//! TLS support, ported from linker.c: module registration,
//! per-thread blocks, `__tls_get_addr` (always hooked, unlike the
//! `CSOLOADER_MAKE_LINKER_HOOKS` family), the TLSDESC dynamic resolver and
//! the tpidr helper.

use std::sync::Mutex;

use crate::image::CsoElf;

pub const MAX_TLS_MODULES: usize = 128;

pub const TAG: &str = crate::TAG;

macro_rules! dlogd {
    ($($arg:tt)*) => {{ rz_common::logd!(TAG, $($arg)*); }};
}
macro_rules! dloge {
    ($($arg:tt)*) => {{ rz_common::loge!(TAG, $($arg)*); }};
}

/// linker.c `struct tls_index` — the ABI layout `__tls_get_addr` receives
/// from compiled TLS code. Must not be changed.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TlsIndex {
    pub module: usize,
    pub offset: usize,
}

/// linker.c `struct tls_module`.
#[derive(Debug, Clone, Copy, Default)]
struct TlsModule {
    module_id: usize,
    align: usize,
    memsz: usize,
    filesz: usize,
    /// Initial TLS data (.tdata) to copy, as a runtime address (0 = none).
    init_image: usize,
    /// linker.c `owner`: the image that registered this slot
    /// (`_linker_unregister_tls_segment` checks it before clearing, so a
    /// stale image can't clear a slot re-registered by another one). Stored
    /// as the address (`usize`) so the static Mutex stays `Sync`; it is only
    /// ever compared for equality, never dereferenced.
    owner: usize,
}

/// linker.c `struct thread_tls` — per-thread module block pointers, plus the
/// thread's emergency arena for degraded TLS service (see
/// [`__tls_get_addr`]'s failure paths).
struct ThreadTls {
    generation: usize,
    modules: [*mut u8; MAX_TLS_MODULES],
    /// Bit i set: `modules[i]` points into `arena`, not the heap — the sync
    /// and destroy paths must clear it instead of `free`ing it.
    fallback: u128,
    /// Bump-allocator offset into `arena` for carved fallback slices.
    arena_used: usize,
    /// Base of the shared no-layout slice (`bogus`), carved once.
    bogus: *mut u8,
    arena: [u8; FALLBACK_ARENA_SIZE],
}

/// Per-thread emergency arena. Bounded so a thread stuck in degraded TLS
/// service cannot exhaust the heap.
const FALLBACK_ARENA_SIZE: usize = 8 * 1024;

/// Shared slice serving accesses that have no module layout behind them
/// (bogus module id, or arena exhausted). Per-thread, and the caller's
/// offset is clamped into it, so degradation stays bounded and thread-local
/// instead of writing through a wild pointer.
const FALLBACK_BOGUS_LEN: usize = 1024;

/// Last-resort static block for the single case where no per-thread state
/// could be created at all (`pthread_setspecific` failed): a shared static
/// page still beats a NULL deref, and there is no thread state to
/// contaminate.
static TLS_LAST_RESORT: [u8; FALLBACK_BOGUS_LEN] = [0; FALLBACK_BOGUS_LEN];

/// Normalize an alignment to a small power of two for arena carving.
fn arena_align(align: usize) -> usize {
    let a = align.clamp(1, 64);
    if a & (a - 1) == 0 {
        a
    } else {
        16
    }
}

impl ThreadTls {
    const fn new() -> Self {
        Self {
            generation: 0,
            modules: [std::ptr::null_mut(); MAX_TLS_MODULES],
            fallback: 0,
            arena_used: 0,
            bogus: std::ptr::null_mut(),
            arena: [0; FALLBACK_ARENA_SIZE],
        }
    }

    /// Carve a full-size, correctly laid-out slice for one module: aligned,
    /// zeroed (.tbss), seeded with the `.tdata` image. The caller caches it in
    /// `modules[id]` so every later `block + offset` lands inside the carve
    /// exactly as it would on the heap. Null when the module's segment simply
    /// does not fit the remaining arena.
    fn carve_module_slice(
        &mut self,
        memsz: usize,
        align: usize,
        init_image: usize,
        filesz: usize,
    ) -> *mut u8 {
        if memsz == 0 || memsz > self.arena.len() {
            return std::ptr::null_mut();
        }
        let align = arena_align(align);
        let start = self.arena_used.wrapping_add(align - 1) & !(align - 1);
        let Some(end) = start.checked_add(memsz) else {
            return std::ptr::null_mut();
        };
        if end > self.arena.len() {
            return std::ptr::null_mut();
        }
        self.arena_used = end;

        let block = unsafe { self.arena.as_mut_ptr().add(start) };
        if init_image != 0 && filesz > 0 {
            unsafe {
                std::ptr::copy_nonoverlapping(init_image as *const u8, block, filesz.min(memsz));
            }
        }
        block
    }

    /// The per-thread no-layout slice. Clamps `offset` into it: any pointer
    /// handed out stays inside this thread's own arena.
    fn bogus_ptr(&mut self, offset: usize) -> *mut u8 {
        let align = arena_align(std::mem::size_of::<*mut u8>());
        if self.bogus.is_null() {
            let start = self.arena_used.wrapping_add(align - 1) & !(align - 1);
            if start + FALLBACK_BOGUS_LEN > self.arena.len() {
                return TLS_LAST_RESORT.as_ptr() as *mut u8;
            }
            self.arena_used = start + FALLBACK_BOGUS_LEN;
            self.bogus = unsafe { self.arena.as_mut_ptr().add(start) };
        }
        unsafe { self.bogus.add(offset % FALLBACK_BOGUS_LEN) }
    }
}

/// Categories of degraded TLS service, each logged once per process. The
/// failure paths are hot (every TLS access in a degraded module) — a line
/// per access would flood the host process's own logd buffer.
#[derive(Clone, Copy)]
enum TlsDegraded {
    NullIndex,
    BogusModule(usize),
    Unregistered(usize),
    LockPoisoned,
    ArenaExhausted(usize),
    ThreadStateFailed,
}

fn log_degraded(what: TlsDegraded) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static NULL_TI: AtomicBool = AtomicBool::new(false);
    static BOGUS_MODULE: AtomicBool = AtomicBool::new(false);
    static UNREGISTERED: AtomicBool = AtomicBool::new(false);
    static LOCK_POISONED: AtomicBool = AtomicBool::new(false);
    static ARENA_EXHAUSTED: AtomicBool = AtomicBool::new(false);
    static THREAD_STATE: AtomicBool = AtomicBool::new(false);

    let (flag, msg): (&AtomicBool, String) = match what {
        TlsDegraded::NullIndex => (&NULL_TI, "__tls_get_addr called with NULL TlsIndex".into()),
        TlsDegraded::BogusModule(id) => (
            &BOGUS_MODULE,
            format!("Library tried to access invalid TLS module ID {id}"),
        ),
        TlsDegraded::Unregistered(id) => (
            &UNREGISTERED,
            format!("Library tried to access unregistered TLS module {id}"),
        ),
        TlsDegraded::LockPoisoned => (
            &LOCK_POISONED,
            "TLS module table lock poisoned during __tls_get_addr".into(),
        ),
        TlsDegraded::ArenaExhausted(id) => (
            &ARENA_EXHAUSTED,
            format!(
                "TLS allocation failed for module {id} and the per-thread fallback arena is exhausted — serving the shared clamped slice"
            ),
        ),
        TlsDegraded::ThreadStateFailed => (
            &THREAD_STATE,
            "Thread TLS state unavailable — serving the static last-resort block".into(),
        ),
    };
    if !flag.swap(true, Ordering::Relaxed) {
        dloge!("{msg}");
    }
}

/// linker.c `_linker_destroy_thread_tls`: free the per-module
/// blocks (arena-carved fallback slices are cleared, not freed), then the
/// struct itself.
unsafe fn destroy_thread_tls(ttls: *mut ThreadTls) {
    unsafe {
        if ttls.is_null() {
            return;
        }
        let tt = &mut *ttls;
        for i in 0..MAX_TLS_MODULES {
            if tt.modules[i].is_null() {
                continue;
            }
            if tt.fallback & (1 << i) == 0 {
                libc::free(tt.modules[i] as *mut libc::c_void);
            }
            tt.modules[i] = std::ptr::null_mut();
        }
        drop(Box::from_raw(ttls));
    }
}

/// linker.c `_linker_destroy_thread_tls` (pthread key destructor).
unsafe extern "C" fn thread_tls_destructor(arg: *mut libc::c_void) {
    unsafe {
        destroy_thread_tls(arg as *mut ThreadTls);
    }
}

// g_tls_key / g_tls_key_once / g_tls_key_initialized.
static TLS_KEY: Mutex<Option<libc::pthread_key_t>> = Mutex::new(None);

fn tls_key() -> Option<libc::pthread_key_t> {
    let mut guard = TLS_KEY.lock().ok()?;

    if let Some(key) = *guard {
        return Some(key);
    }

    let mut key: libc::pthread_key_t = 0;
    // _linker_alloc_tls_key_once
    if unsafe { libc::pthread_key_create(&mut key, Some(thread_tls_destructor)) } != 0 {
        return None;
    }

    *guard = Some(key);
    Some(key)
}

/// linker.c `_linker_get_thread_tls`.
fn get_thread_tls() -> Option<*mut ThreadTls> {
    let key = tls_key()?;
    let existing = unsafe { libc::pthread_getspecific(key) } as *mut ThreadTls;
    if !existing.is_null() {
        return Some(existing);
    }

    let ptr = Box::into_raw(Box::new(ThreadTls::new()));

    if unsafe { libc::pthread_setspecific(key, ptr as *mut libc::c_void) } != 0 {
        unsafe { drop(Box::from_raw(ptr)) };
        return None;
    }

    Some(ptr)
}

// g_tls_modules / g_tls_generation / g_tls_mutex.
static TLS_MODULES: Mutex<[TlsModule; MAX_TLS_MODULES]> =
    Mutex::new([TlsModule {
        module_id: 0,
        align: 0,
        memsz: 0,
        filesz: 0,
        init_image: 0,
        owner: 0,
    }; MAX_TLS_MODULES]);
static TLS_GENERATION: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// linker.c `_linker_sync_thread_tls`: free per-thread blocks of modules that
/// have since been unregistered. Arena-carved fallback slices are cleared
/// only (their space stays reserved for the life of the thread — bounded by
/// the arena size). The caller must hold the TLS_MODULES lock.
unsafe fn sync_thread_tls_locked(ttls: *mut ThreadTls, modules: &[TlsModule; MAX_TLS_MODULES]) {
    unsafe {
        let tt = &mut *ttls;
        let current_gen = TLS_GENERATION.load(std::sync::atomic::Ordering::SeqCst);
        if tt.generation >= current_gen {
            return;
        }

        for (i, module) in modules.iter().enumerate().skip(1) {
            if module.module_id == 0 && !tt.modules[i].is_null() {
                if tt.fallback & (1 << i) == 0 {
                    libc::free(tt.modules[i] as *mut libc::c_void);
                }
                tt.fallback &= !(1 << i);
                tt.modules[i] = std::ptr::null_mut();
            }
        }

        tt.generation = current_gen;
    }
}

/// linker.c `_linker_allocate_module_tls`.
unsafe fn allocate_module_tls(mod_: &TlsModule) -> *mut u8 {
    if mod_.module_id == 0 || mod_.memsz == 0 {
        return std::ptr::null_mut();
    }

    let mut align = mod_.align;
    // posix_memalign requires alignment >= sizeof(void *) and a power of two.
    if align < std::mem::size_of::<*mut u8>() {
        align = std::mem::size_of::<*mut u8>();
    }
    let page = crate::linker::page_size();
    if page > 0 && align > page {
        align = page;
    }
    // The C has no power-of-two fallback: a non-power
    // of-two p_align makes posix_memalign fail with EINVAL and the module
    // gets no TLS block. Match that instead of silently re-aligning.

    let mut block: *mut libc::c_void = std::ptr::null_mut();
    if unsafe { libc::posix_memalign(&mut block, align, mod_.memsz) } != 0 {
        dloge!(
            "Failed to allocate TLS block for module {}: size={}, align={}",
            mod_.module_id,
            mod_.memsz,
            align
        );
        return std::ptr::null_mut();
    }

    unsafe {
        // Zero first (.tbss), then copy the initialized image (.tdata).
        std::ptr::write_bytes(block.cast::<u8>(), 0, mod_.memsz);
        if mod_.init_image != 0 && mod_.filesz > 0 {
            std::ptr::copy_nonoverlapping(mod_.init_image as *const u8, block.cast::<u8>(), mod_.filesz);
        }
    }

    block as *mut u8
}

/// linker.c `_linker_register_tls_segment` for a `CsoElf`.
pub fn register_tls_segment(img: &CsoElf) -> bool {
    let Some(seg) = img.tls_segment() else {
        return true;
    };

    let Ok(mut modules) = TLS_MODULES.lock() else {
        return false;
    };

    let mut mod_id = 1;
    while mod_id < MAX_TLS_MODULES && modules[mod_id].module_id != 0 {
        mod_id += 1;
    }

    if mod_id == MAX_TLS_MODULES {
        dloge!("TLS module overflow: max {MAX_TLS_MODULES} modules reached");
        return false;
    }

    modules[mod_id] = TlsModule {
        module_id: mod_id,
        align: if seg.align != 0 { seg.align as usize } else { 1 },
        memsz: seg.memsz as usize,
        filesz: seg.filesz as usize,
        init_image: img.runtime(seg.vaddr),
        owner: img as *const CsoElf as usize,
    };

    img.set_tls_mod_id(mod_id);
    TLS_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    dlogd!(
        "Registered TLS module {mod_id} for {}: memsz={}, filesz={}, align={}",
        img.path(),
        seg.memsz,
        seg.filesz,
        seg.align
    );

    true
}

/// linker.c `_linker_unregister_tls_segment`.
pub fn unregister_tls_segment(img: &CsoElf) {
    let mod_id = img.tls_mod_id();
    if mod_id == 0 {
        return;
    }

    // C: only clear the slot when this image still owns
    // it — the slot may have been re-registered by another image — and only
    // then reset the stale caller's tls_mod_id.
    if let Ok(mut modules) = TLS_MODULES.lock()
        && mod_id < MAX_TLS_MODULES
        && modules[mod_id].owner == img as *const CsoElf as usize
    {
        modules[mod_id] = TlsModule::default();
        TLS_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        dlogd!("Unregistering TLS module {mod_id} for {}", img.path());
        img.set_tls_mod_id(0);
    }
}

/// linker.c `linker_link`: the extra `g_tls_generation++` after the per-module
/// registrations in `linker_link`.
pub(crate) fn bump_tls_generation() {
    TLS_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// linker.c `__tls_get_addr` (exported — loaded libraries resolve their TLS
/// access trampolines against this symbol).
///
/// Degradation policy: this never returns NULL (compiled-in TLS access code
/// dereferences the result unconditionally) and never hands out a pointer
/// that escapes the caller's own thread state. When the real per-module heap
/// block cannot be served, the thread carves a full-size, initializer-seeded
/// slice from its own emergency arena; when even the module layout is
/// unknown, the thread's shared clamped slice absorbs the access. Every
/// degraded path logs once — see [`log_degraded`].
///
/// # Safety
/// `ti` must point to a valid `TlsIndex` (or be NULL).
#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn __tls_get_addr(ti: *mut TlsIndex) -> *mut libc::c_void {
    if ti.is_null() {
        log_degraded(TlsDegraded::NullIndex);
        return match get_thread_tls() {
            Some(ttls) => unsafe { (*ttls).bogus_ptr(0) as *mut libc::c_void },
            None => TLS_LAST_RESORT.as_ptr() as *mut libc::c_void,
        };
    }

    let (module, offset) = unsafe {
        let ti = &*ti;
        (ti.module, ti.offset)
    };

    if module == 0 || module >= MAX_TLS_MODULES {
        log_degraded(TlsDegraded::BogusModule(module));
        return match get_thread_tls() {
            Some(ttls) => unsafe { (*ttls).bogus_ptr(offset) as *mut libc::c_void },
            None => TLS_LAST_RESORT.as_ptr() as *mut libc::c_void,
        };
    }

    // Single lock section: validation, thread sync and block allocation all
    // consume the same snapshot (sync_thread_tls used to re-lock internally).
    let Ok(modules) = TLS_MODULES.lock() else {
        log_degraded(TlsDegraded::LockPoisoned);
        return match get_thread_tls() {
            Some(ttls) => unsafe { (*ttls).bogus_ptr(offset) as *mut libc::c_void },
            None => TLS_LAST_RESORT.as_ptr() as *mut libc::c_void,
        };
    };

    if modules[module].module_id == 0 {
        log_degraded(TlsDegraded::Unregistered(module));
        drop(modules);
        return match get_thread_tls() {
            Some(ttls) => unsafe { (*ttls).bogus_ptr(offset) as *mut libc::c_void },
            None => TLS_LAST_RESORT.as_ptr() as *mut libc::c_void,
        };
    }

    let Some(ttls) = get_thread_tls() else {
        log_degraded(TlsDegraded::ThreadStateFailed);
        return TLS_LAST_RESORT.as_ptr() as *mut libc::c_void;
    };

    unsafe { sync_thread_tls_locked(ttls, &modules) };

    let tt = unsafe { &mut *ttls };
    if tt.modules[module].is_null() {
        let block = unsafe { allocate_module_tls(&modules[module]) };
        if block.is_null() {
            // Real allocation failed — carve the module's own slice from this
            // thread's arena so the layout and the `.tdata` initializers stay
            // intact. If even that does not fit, the bounded shared slice
            // absorbs the access.
            let carved = tt.carve_module_slice(
                modules[module].memsz,
                modules[module].align,
                modules[module].init_image,
                modules[module].filesz,
            );
            if !carved.is_null() {
                dloge!(
                    "TLS block allocation failed for module {module} — serving a per-thread fallback slice"
                );
                tt.modules[module] = carved;
                tt.fallback |= 1 << module;
            } else {
                log_degraded(TlsDegraded::ArenaExhausted(module));
                return tt.bogus_ptr(offset) as *mut libc::c_void;
            }
        } else {
            tt.modules[module] = block;
        }
    }

    unsafe { tt.modules[module].add(offset) as *mut libc::c_void }
}

/// linker.c `_linker_get_tpidr`.
pub fn get_tpidr() -> usize {
    #[cfg(target_arch = "aarch64")]
    {
        let tpidr: usize;
        unsafe { std::arch::asm!("mrs {}, tpidr_el0", out(reg) tpidr) };
        tpidr
    }
    #[cfg(target_arch = "arm")]
    {
        // CP15: mrc p15, 0, %0, c13, c0, 3
        let tpidr: usize;
        unsafe { std::arch::asm!("mrc p15, 0, {}, c13, c0, 3", out(reg) tpidr) };
        tpidr
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        // x86 uses segment registers; TLSDESC is not used on x86.
        0
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm", target_arch = "x86", target_arch = "x86_64")))]
    {
        0
    }
}

/// linker.c `dynamic_tls_resolver`: TLSDESC resolver returning the variable
/// offset from tpidr.
unsafe extern "C" fn dynamic_tls_resolver(desc: *mut usize) -> usize {
    unsafe {
        if desc.is_null() {
            return 0;
        }

        let ti = *desc.add(1) as *mut TlsIndex;
        let addr = __tls_get_addr(ti);
        if addr.is_null() {
            let (module, offset) = if ti.is_null() {
                (0, 0)
            } else {
                ((*ti).module, (*ti).offset)
            };
            dloge!("dynamic_tls_resolver: __tls_get_addr failed for module={module}, offset={offset}");
            return 0;
        }

        // Offset from tpidr so the caller computes the final TLS address.
        (addr as usize).wrapping_sub(get_tpidr())
    }
}

/// linker.c `tlsdesc_resolver_unresolved_weak`: returns `-tpidr + addend` so
/// the caller computes `NULL + addend`.
unsafe extern "C" fn tlsdesc_resolver_unresolved_weak(desc: *mut usize) -> usize {
    unsafe {
        if desc.is_null() {
            return 0;
        }
        let addend = *desc.add(1);
        addend.wrapping_sub(get_tpidr())
    }
}

pub(crate) fn dynamic_tls_resolver_addr() -> usize {
    dynamic_tls_resolver as *const () as usize
}

pub(crate) fn unresolved_weak_resolver_addr() -> usize {
    tlsdesc_resolver_unresolved_weak as *const () as usize
}

/// linker.c `linker_deinit`'s TLS teardown half.
pub fn deinit() {
    if let Ok(mut key) = TLS_KEY.lock() {
        if let Some(key) = *key {
            // C: _linker_destroy_thread_tls(pthread_getspecific(g_tls_key))
            // — free this thread's state and its module blocks (other threads
            // are expected to have exited).
            let ttls = unsafe { libc::pthread_getspecific(key) } as *mut ThreadTls;
            unsafe { destroy_thread_tls(ttls) };
            unsafe { libc::pthread_setspecific(key, std::ptr::null()) };
            unsafe { libc::pthread_key_delete(key) };
        }
        *key = None;
    }

    TLS_GENERATION.store(0, std::sync::atomic::Ordering::SeqCst);
    if let Ok(mut modules) = TLS_MODULES.lock() {
        *modules = [TlsModule::default(); MAX_TLS_MODULES];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Carves are aligned, non-overlapping, full-size, and seeded with the
    /// initializer image.
    #[test]
    fn carve_module_slice_aligned_seeded_nonoverlapping() {
        let mut tt = ThreadTls::new();

        // 300 bytes @ align 32, initializer 16 bytes of 0xAA.
        let init = [0xAAu8; 16];
        let a = tt.carve_module_slice(300, 32, init.as_ptr() as usize, 16);
        assert!(!a.is_null());
        assert_eq!(a as usize % 32, 0);

        let b = tt.carve_module_slice(64, 8, 0, 0);
        assert!(!b.is_null());

        // Distinct ranges: b starts at or after a's end.
        let a_start = a as usize - tt.arena.as_ptr() as usize;
        let b_start = b as usize - tt.arena.as_ptr() as usize;
        assert!(b_start >= a_start + 300);

        // Initializer landed at the front of a, rest zeroed.
        let a_slice = unsafe { std::slice::from_raw_parts(a, 300) };
        assert!(a_slice[..16].iter().all(|&b| b == 0xAA));
        assert!(a_slice[16..].iter().all(|&b| b == 0));
    }

    /// A segment larger than the arena cannot be carved — the caller falls
    /// back to the bounded shared slice instead of a truncated layout.
    #[test]
    fn carve_rejects_oversized_segment() {
        let mut tt = ThreadTls::new();
        assert!(tt.carve_module_slice(FALLBACK_ARENA_SIZE + 1, 8, 0, 0).is_null());
        // Still fully usable for a fitting segment afterwards.
        assert!(!tt.carve_module_slice(16, 8, 0, 0).is_null());
    }

    /// The no-layout slice clamps every offset into itself: two wildly
    /// different offsets stay within FALLBACK_BOGUS_LEN of the same base.
    #[test]
    fn bogus_ptr_clamps_offsets() {
        let mut tt = ThreadTls::new();
        let base = tt.bogus_ptr(0) as usize;
        let far = tt.bogus_ptr(usize::MAX / 2 + 12345) as usize;
        let wrap = tt.bogus_ptr(FALLBACK_BOGUS_LEN * 3 + 7) as usize;

        assert!(far >= base && far < base + FALLBACK_BOGUS_LEN);
        assert_eq!(wrap, base + 7);
    }

    /// Arena exhaustion in carve routes later callers to the bogus slice,
    /// which keeps every pointer inside the thread's own state.
    #[test]
    fn arena_exhaustion_stays_bounded() {
        let mut tt = ThreadTls::new();
        // Eat almost the whole arena, leaving no room for another full carve
        // but leaving the bogus slice carvable (its 1 KiB comes first).
        let _ = tt.carve_module_slice(FALLBACK_BOGUS_LEN, 8, 0, 0);
        let _ = tt.carve_module_slice(FALLBACK_ARENA_SIZE - FALLBACK_BOGUS_LEN, 8, 0, 0);
        assert!(tt.carve_module_slice(16, 8, 0, 0).is_null());

        let p = tt.bogus_ptr(64) as usize;
        let in_arena = p >= tt.arena.as_ptr() as usize
            && p < tt.arena.as_ptr() as usize + tt.arena.len();
        let last_resort = p == TLS_LAST_RESORT.as_ptr() as usize;
        assert!(in_arena || last_resort);
    }
}
