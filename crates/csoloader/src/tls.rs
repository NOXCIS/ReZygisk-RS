//! TLS support, ported from linker.c lines 972–1264: module registration,
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
}

/// linker.c `struct thread_tls` — per-thread module block pointers.
struct ThreadTls {
    generation: usize,
    modules: [*mut u8; MAX_TLS_MODULES],
}

impl ThreadTls {
    const fn new() -> Self {
        Self {
            generation: 0,
            modules: [std::ptr::null_mut(); MAX_TLS_MODULES],
        }
    }
}

/// linker.c `_linker_destroy_thread_tls` (pthread key destructor).
unsafe extern "C" fn thread_tls_destructor(arg: *mut libc::c_void) {
    unsafe {
        if arg.is_null() {
            return;
        }
        drop(Box::from_raw(arg as *mut ThreadTls));
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
    }; MAX_TLS_MODULES]);
static TLS_GENERATION: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// linker.c `_linker_sync_thread_tls`: free per-thread blocks of modules that
/// have since been unregistered.
unsafe fn sync_thread_tls(ttls: *mut ThreadTls) {
    let Ok(mut modules) = TLS_MODULES.lock() else { return };

    unsafe {
        let tt = &mut *ttls;
        let current_gen = TLS_GENERATION.load(std::sync::atomic::Ordering::SeqCst);
        if tt.generation >= current_gen {
            return;
        }

        for i in 1..MAX_TLS_MODULES {
            if modules[i].module_id == 0 && !tt.modules[i].is_null() {
                libc::free(tt.modules[i] as *mut libc::c_void);
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
    if !align.is_power_of_two() {
        align = 8;
    }

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

    if let Ok(mut modules) = TLS_MODULES.lock() {
        if mod_id < MAX_TLS_MODULES {
            modules[mod_id] = TlsModule::default();
            TLS_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            dlogd!("Unregistering TLS module {mod_id} for {}", img.path());
        }
    }

    img.set_tls_mod_id(0);
}

/// linker.c `__tls_get_addr` (exported — loaded libraries resolve their TLS
/// access trampolines against this symbol).
///
/// # Safety
/// `ti` must point to a valid `TlsIndex` (or be NULL).
#[no_mangle]
pub unsafe extern "C" fn __tls_get_addr(ti: *mut TlsIndex) -> *mut libc::c_void {
    if ti.is_null() {
        return std::ptr::null_mut();
    }

    let (module, offset) = unsafe {
        let ti = &*ti;
        (ti.module, ti.offset)
    };

    dlogd!("__tls_get_addr called: module={module}, offset={offset}");

    if module == 0 || module >= MAX_TLS_MODULES {
        dloge!("Library tried to access invalid TLS module ID {module}");
        return std::ptr::null_mut();
    }

    {
        let Ok(modules) = TLS_MODULES.lock() else {
            return std::ptr::null_mut();
        };
        if modules[module].module_id == 0 {
            dloge!("Library tried to access unregistered TLS module {module}");
            return std::ptr::null_mut();
        }
    }

    let Some(ttls) = get_thread_tls() else {
        dloge!("Library tried to access TLS, but thread TLS allocation failed");
        return std::ptr::null_mut();
    };

    unsafe { sync_thread_tls(ttls) };

    let Ok(mut modules) = TLS_MODULES.lock() else {
        return std::ptr::null_mut();
    };

    let tt = unsafe { &mut *ttls };
    if tt.modules[module].is_null() {
        let block = unsafe { allocate_module_tls(&modules[module]) };
        if block.is_null() {
            dloge!("Failed to allocate TLS block for module {module}");
            return std::ptr::null_mut();
        }
        tt.modules[module] = block;
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
            // Destroy this thread's state (C does the same; other threads are
            // expected to have exited).
            let ttls = unsafe { libc::pthread_getspecific(key) } as *mut ThreadTls;
            if !ttls.is_null() {
                unsafe { drop(Box::from_raw(ttls)) };
            }
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
