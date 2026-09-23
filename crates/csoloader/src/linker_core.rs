//! In-process CSOLoader linker core — port of
//! `loader/src/external/csoloader/src/linker.c` ranges:
//! 124-368 (registration list, ctor/dtor callers, dep lookup, manual
//! constructors, GNU RELRO, `_linker_internal_init`), 506-604
//! (`linker_init`, dependency release, `linker_destroy`, `linker_abandon`),
//! 1122-1150 (`_linker_unregister_tls_segment` — the tracked tls_index
//! cleanup half; the module-table half is `crate::tls`),
//! 1956-2347 (`_linker_is_library_loaded`, `_linker_restore_protections`,
//! `linker_link`, `linker_deinit`).
//!
//! `Linker`/`LoadedDep` are `#[repr(C)]` mirrors of `include/linker.h` —
//! rz-loader's `abi::CsoLib` embeds `Linker` by value, so the layout is the
//! contract. The first two members of `Linker` intentionally match
//! `LoadedDep`: the C casts `(struct loaded_dep *)linker` at the
//! `_linker_process_relocations` and `_linker_unregister_tls_segment` call
//! sites (linker.h's "Do not change this 2 members from order" note).
//!
//! Cross-module contracts (parallel ports, signatures are fixed):
//! - `crate::linker_load::{linker_load_library_manually, linker_find_library_path}`
//! - `crate::linker_reloc::linker_process_relocations`
//! - `crate::tls::{register_tls_segment, unregister_tls_segment, deinit}`

use std::ffi::{c_char, c_int, c_void};

use crate::image::CsoElf;

pub const TAG: &str = rz_common::LOG_TAG;

macro_rules! dlogd {
    ($($arg:tt)*) => {{ rz_common::logd!(TAG, $($arg)*); }};
}
macro_rules! dlogw {
    ($($arg:tt)*) => {{ rz_common::logw!(TAG, $($arg)*); }};
}
macro_rules! dloge {
    ($($arg:tt)*) => {{ rz_common::loge!(TAG, $($arg)*); }};
}

// ---------------------------------------------------------------------------
// linker.h layouts (repr(C) mirrors — layout fidelity is the contract)
// ---------------------------------------------------------------------------

/// linker.h `MAX_DEPS`.
pub const MAX_DEPS: usize = 64;

/// linker.h `struct tls_indices_data`.
#[repr(C)]
#[derive(Debug, Default)]
pub struct TlsIndicesData {
    pub indices: *mut *mut crate::tls::TlsIndex,
    pub count: usize,
    pub capacity: usize,
}

// SAFETY: TlsIndicesData is only accessed while locks are held. The pointers
// point to memory managed by the linker that remains valid for its lifetime.
unsafe impl Send for TlsIndicesData {}
unsafe impl Sync for TlsIndicesData {}

/// linker.h `struct loaded_dep`.
///
/// The first two members must stay in this order: the C reads them through a
/// `struct linker` cast (`(struct loaded_dep *)linker`).
#[repr(C)]
#[derive(Debug, Default)]
pub struct LoadedDep {
    pub img: *mut CsoElf,
    pub tls_indices: TlsIndicesData,
    pub is_manual_load: bool,
    pub load_bias: usize,
    pub map_base: *mut c_void,
    pub map_size: usize,
}

// SAFETY: LoadedDep is only accessed while locks are held.
unsafe impl Send for LoadedDep {}
unsafe impl Sync for LoadedDep {}

/// linker.h `struct linker` — embedded by value in rz-loader's `abi::CsoLib`,
/// so the `#[repr(C)]` layout below must match the C field-for-field.
#[repr(C)]
#[derive(Debug)]
pub struct Linker {
    pub img: *mut CsoElf,
    pub tls_indices: TlsIndicesData,
    pub dependencies: [LoadedDep; MAX_DEPS],
    pub dep_count: i32,
    pub main_map_size: usize,
    pub is_linked: bool,
}

impl Default for Linker {
    fn default() -> Self {
        Self {
            img: std::ptr::null_mut(),
            tls_indices: TlsIndicesData::default(),
            // std only implements Default for arrays up to 32 elements.
            dependencies: std::array::from_fn(|_| LoadedDep::default()),
            dep_count: 0,
            main_map_size: 0,
            is_linked: false,
        }
    }
}

// SAFETY: Linker is only accessed while locks are held.
unsafe impl Send for Linker {}
unsafe impl Sync for Linker {}

// ---------------------------------------------------------------------------
// linker.c globals (1-124): page size cache, active linker list, ctor args
// ---------------------------------------------------------------------------

/// linker.c `system_page_size` + `_linker_internal_init` (118, 356-367).
static SYSTEM_PAGE_SIZE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// linker.c `MAX_ACTIVE_LINKERS` (120).
const MAX_ACTIVE_LINKERS: usize = 16;

/// linker.c `g_active_linkers` / `g_active_linker_count` (121-122).
/// Consolidated into a Mutex-protected struct for sound Rust access.
struct ActiveLinkers {
    linkers: [*mut Linker; MAX_ACTIVE_LINKERS],
    count: usize,
}

impl ActiveLinkers {
    const fn new() -> Self {
        Self {
            linkers: [std::ptr::null_mut(); MAX_ACTIVE_LINKERS],
            count: 0,
        }
    }
}

// SAFETY: Linker pointers are only dereferenced when held; the zygote is
// single-threaded during hook execution, but the Mutex makes this sound
// under Rust's aliasing model.
unsafe impl Send for ActiveLinkers {}
unsafe impl Sync for ActiveLinkers {}

static ACTIVE_LINKERS: std::sync::Mutex<ActiveLinkers> =
    std::sync::Mutex::new(ActiveLinkers::new());

/// linker.c `g_argc` / `g_argv` / `g_envp` (217-219). csoloader never
/// preinits, so these stay at their initializers.
const G_ARGC: c_int = 0;
const G_ARGV: *mut *mut c_char = std::ptr::null_mut();
const G_ENVP: *mut *mut c_char = std::ptr::null_mut();

// ELF p_flags (elf.h PF_*) and p_type (PT_LOAD).
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const PT_LOAD: u32 = 1;

/// <limits.h> `PATH_MAX` (linker.c `char lib_full_path[PATH_MAX]`).
const PATH_MAX: usize = 4096;

/// linker.c `_linker_internal_init` (356-367): the C static page-size cache.
fn internal_init() {
    page_size();
}

/// linker.c `system_page_size` accessor; lazily runs `_linker_internal_init`
/// exactly like the C cache (also re-exported as `crate::linker::page_size`
/// for tls.rs).
pub fn page_size() -> usize {
    let cached = SYSTEM_PAGE_SIZE.load(std::sync::atomic::Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }

    // C: long new_system_page_size = sysconf(_SC_PAGESIZE); (the C keeps the
    // value in a signed long so a -1 failure is checked before the size_t
    // cast).
    let new_system_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if new_system_page_size <= 0 {
        dloge!("Failed to get system page size, assuming 4096 (not cached)");
        return 4096;
    }
    let new_system_page_size = new_system_page_size as usize;

    SYSTEM_PAGE_SIZE.store(new_system_page_size, std::sync::atomic::Ordering::Relaxed);

    dlogd!("System page size: {} bytes", new_system_page_size);

    new_system_page_size
}

/// ALIGN_DOWN(x, system_page_size) (linker.c 110-112).
#[inline]
fn page_start(addr: usize) -> usize {
    addr & !(page_size() - 1)
}

/// ALIGN_DOWN(x + system_page_size - 1, system_page_size).
#[inline]
fn page_end(addr: usize) -> usize {
    (addr.wrapping_add(page_size() - 1)) & !(page_size() - 1)
}

/// linker.c `_linker_register` (124-136). The C aborts on registry saturation
/// in debug builds; here saturation logs and skips registration — the module
/// keeps running without linker-registry services rather than killing the
/// zygote. The no-dangling invariant is guarded by the caller's `try_reserve`.
fn register_linker(linker: &mut Linker) {
    let mut guard = ACTIVE_LINKERS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let active = &mut *guard;

    for i in 0..active.count {
        if std::ptr::eq(active.linkers[i], linker) {
            return;
        }
    }

    if active.count >= MAX_ACTIVE_LINKERS {
        dloge!(
            "Maximum active linker count ({}) exceeded, skipping registration",
            MAX_ACTIVE_LINKERS
        );
        return;
    }

    active.linkers[active.count] = linker;
    active.count += 1;
}

/// linker.c `_linker_unregister` (138-147): swap-with-last, then NULL the
/// vacated slot.
fn unregister_linker(linker: &mut Linker) {
    let mut guard = ACTIVE_LINKERS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let active = &mut *guard;

    for i in 0..active.count {
        if !std::ptr::eq(active.linkers[i], linker) {
            continue;
        }

        active.count -= 1;
        active.linkers[i] = active.linkers[active.count];
        active.linkers[active.count] = std::ptr::null_mut();

        return;
    }
}

// ---------------------------------------------------------------------------
// constructor / destructor callers (236-270)
// ---------------------------------------------------------------------------

/// linker.c `_linker_call_constructors` (236-252).
fn call_constructors(img: &CsoElf) {
    let init_func = img.init_func_addr();
    if init_func != 0 {
        dlogd!("Calling .init function for {} at {:p}", img.path(), init_func as *const c_void);
        let init: unsafe extern "C" fn() = unsafe { std::mem::transmute(init_func) };
        unsafe { init() };
    }

    let (init_array, init_array_count) = img.init_array();
    if init_array != 0 {
        dlogd!("Calling .init_array constructors for {}", img.path());
        for i in 0..init_array_count {
            let ctor_addr = unsafe { (init_array as *const usize).add(i).read_unaligned() };
            let ctor: unsafe extern "C" fn(c_int, *mut *mut c_char, *mut *mut c_char) =
                unsafe { std::mem::transmute(ctor_addr) };

            dlogd!("Calling init_array[{}] at {:p}", i, ctor as *const c_void);

            // C: img->init_array[i](g_argc, g_argv, g_envp);
            unsafe { ctor(G_ARGC, G_ARGV, G_ENVP) };
        }
    }
}

/// linker.c `_linker_call_destructors` (254-270).
fn call_destructors(img: &CsoElf) {
    let (fini_array, fini_array_count) = img.fini_array();
    if fini_array != 0 {
        dlogd!("Calling .fini_array destructors for {}", img.path());
        for i in (0..fini_array_count).rev() {
            let dtor_addr = unsafe { (fini_array as *const usize).add(i).read_unaligned() };
            let dtor: unsafe extern "C" fn() = unsafe { std::mem::transmute(dtor_addr) };

            dlogd!("Calling fini_array[{}] at {:p}", i, dtor as *const c_void);

            unsafe { dtor() };
        }
    }

    let fini_func = img.fini_func_addr();
    if fini_func != 0 {
        dlogd!("Calling .fini function for {} at {:p}", img.path(), fini_func as *const c_void);
        let fini: unsafe extern "C" fn() = unsafe { std::mem::transmute(fini_func) };
        unsafe { fini() };
    }
}

/// linker.c `_path_basename` (272-277).
fn path_basename(path: &str) -> &str {
    match path.rfind('/') {
        Some(slash) => &path[slash + 1..],
        None => path,
    }
}

/// linker.c `_linker_find_dep_index` (279-288): manual deps match on the
/// basename of the loaded path (soname).
fn find_dep_index(linker: &Linker, soname: &str) -> i32 {
    for i in 0..linker.dep_count as usize {
        let dep = &linker.dependencies[i];
        if dep.img.is_null() || !dep.is_manual_load {
            continue;
        }
        let img = unsafe { &*dep.img };
        if path_basename(img.path()) == soname {
            return i as i32;
        }
    }

    -1
}

/// linker.c `_linker_call_manual_constructors` (289-325): DFS over the
/// manual DT_NEEDED graph (`ld-android.so` skipped, like linker_link).
fn call_manual_constructors(
    linker: &mut Linker,
    index: usize,
    constructor_state: &mut [u8; MAX_DEPS],
) -> bool {
    // C: struct loaded_dep *dep = &linker->dependencies[index];
    let (img, is_manual_load) = unsafe {
        let dep = &*linker.dependencies.as_ptr().add(index);
        (dep.img, dep.is_manual_load)
    };
    if img.is_null() || !is_manual_load {
        return true;
    }
    if constructor_state[index] != 0 {
        return constructor_state[index] == 2;
    }

    constructor_state[index] = 1;

    let dep_img = unsafe { &*img };
    // C: if (dep->img->strtab_start) — the Rust image exposes the parsed
    // DT_NEEDED list (empty without a dynstr), same gate in effect.
    for dep_name in dep_img.needed_libraries() {
        if dep_name.is_empty() || dep_name == "ld-android.so" {
            continue;
        }

        let dep_idx = find_dep_index(linker, dep_name);
        if dep_idx < 0 {
            continue;
        }

        if !call_manual_constructors(linker, dep_idx as usize, constructor_state) {
            return false;
        }
    }

    call_constructors(dep_img);
    constructor_state[index] = 2;

    true
}

/// linker.c `_linker_protect_gnu_relro` (327-354). Returns 0 / -1 like the C.
fn protect_gnu_relro(img: &CsoElf) -> i32 {
    let load_bias = img.load_bias();

    for seg in img.gnu_relro_segments() {
        // C: (ElfW(Addr))img->base - img->bias is the load bias; page-aligned
        // over-protective span of the segment (AOSP comment preserved).
        let seg_page_start = page_start((seg.vaddr as usize).wrapping_add(load_bias));
        let seg_page_end = page_end(
            (seg.vaddr as usize)
                .wrapping_add(seg.memsz as usize)
                .wrapping_add(load_bias),
        );
        let seg_size = seg_page_end.wrapping_sub(seg_page_start);

        if seg_size == 0 {
            continue;
        }

        let ret = unsafe { libc::mprotect(seg_page_start as *mut c_void, seg_size, libc::PROT_READ) };
        if ret < 0 {
            dlogw!(
                "Failed to mprotect GNU_RELRO at {:p} (size {}) in {}: {}",
                seg_page_start as *const c_void,
                seg_size,
                img.path(),
                std::io::Error::last_os_error()
            );

            return -1;
        }

        dlogd!(
            "Protected GNU_RELRO region at {:p} (size {}) in {}",
            seg_page_start as *const c_void,
            seg_size,
            img.path()
        );
    }

    0
}

// ---------------------------------------------------------------------------
// linker_init / dependency release / destroy / abandon (506-604)
// ---------------------------------------------------------------------------

/// linker.c `linker_init` (506-520).
pub fn linker_init(linker: &mut Linker, img: *mut CsoElf) -> bool {
    internal_init();

    linker.img = img;
    linker.is_linked = false;
    linker.main_map_size = 0;
    linker.dep_count = 0;
    // C: memset(&linker->tls_indices, 0, ...)
    linker.tls_indices = TlsIndicesData::default();
    // C: memset(linker->dependencies, 0, ...)
    for dep in &mut linker.dependencies {
        *dep = LoadedDep::default();
    }

    register_linker(linker);

    true
}

/// linker.c `_linker_run_dependency_destructors` (524-530).
fn run_dependency_destructors(dep: &LoadedDep) {
    if dep.img.is_null() || !dep.is_manual_load {
        return;
    }

    let img = unsafe { &*dep.img };
    call_destructors(img);
    unregister_eh_frame_for_library(img);
    unregister_custom_library_for_backtrace(img);
}

/// linker.c `_linker_unregister_tls_segment` (1122-1150). The TLS-module
/// unregister lives in `crate::tls::unregister_tls_segment`; this adds the
/// tracked `tls_index` cleanup the C performs in the same function (the
/// tracking itself is linker_sym's `_track_tls_index` writing
/// `dep->tls_indices`).
fn unregister_tls_segment(img: &CsoElf, indices: &mut TlsIndicesData) {
    // C early-returns when the module was never registered; that also skips
    // the tracked-index cleanup below.
    if img.tls_mod_id() == 0 {
        return;
    }

    crate::tls::unregister_tls_segment(img);

    // C: Free all tracked tls_index structures (linker.c 1139-1149).
    crate::linker_sym::free_tls_indices(indices);
}

/// linker.c `_linker_release_dependency` (532-546).
fn release_dependency(linker: &mut Linker, index: usize, unload: bool) {
    let dep = &mut linker.dependencies[index];
    if dep.img.is_null() {
        return;
    }

    let img = unsafe { &*dep.img };
    // C: void *dep_base = dep->img->base; size_t dep_map_size = dep->map_size;
    let dep_base = img.base();
    let dep_map_size = dep.map_size;
    let is_manual_load = dep.is_manual_load;

    // C: _linker_unregister_tls_segment(dep);
    unregister_tls_segment(img, &mut dep.tls_indices);
    // C: csoloader_elf_destroy(dep->img);
    unsafe { drop(Box::from_raw(dep.img)) };
    dep.img = std::ptr::null_mut();
    dep.map_size = 0;

    if unload && is_manual_load && dep_map_size > 0 {
        unsafe { libc::munmap(dep_base as *mut c_void, dep_map_size) };
    }
}

/// linker.c `_linker_release_dependencies` (548-557).
fn release_dependencies(linker: &mut Linker, unload: bool, run_destructors: bool) {
    if run_destructors {
        for i in 0..linker.dep_count as usize {
            run_dependency_destructors(&linker.dependencies[i]);
        }
    }

    // C: for (int i = linker->dep_count - 1; i >= 0; --i) — reverse order.
    for i in (0..linker.dep_count as usize).rev() {
        release_dependency(linker, i, unload);
    }
}

/// linker.c `linker_destroy` (559-583). The C derefs `linker->img`
/// unconditionally; callers guarantee a valid image (crash-parity).
pub fn linker_destroy(linker: &mut Linker) {
    let main_base = unsafe { (*linker.img).base() };
    let main_map_size = linker.main_map_size;

    if linker.is_linked {
        let main_img = unsafe { &*linker.img };
        call_destructors(main_img);
        unregister_eh_frame_for_library(main_img);
        unregister_custom_library_for_backtrace(main_img);
    }

    release_dependencies(linker, true, linker.is_linked);

    unregister_linker(linker);

    // C: _linker_unregister_tls_segment((struct loaded_dep *)linker)
    unregister_tls_segment(
        unsafe { &*linker.img },
        unsafe { &mut *std::ptr::addr_of_mut!(linker.tls_indices) },
    );
    // C: csoloader_elf_destroy(linker->img);
    unsafe { drop(Box::from_raw(linker.img)) };
    linker.img = std::ptr::null_mut();

    if main_base != 0 && main_map_size > 0 {
        unsafe { libc::munmap(main_base as *mut c_void, main_map_size) };
    }

    linker.dep_count = 0;
    linker.is_linked = false;
    linker.main_map_size = 0;
}

/// linker.c `linker_abandon` (586-603): release the bookkeeping without
/// unloading the main image. (`csoloader_elf_destroy(NULL)` is a no-op in the
/// C, so the NULL guards match its behavior.)
pub fn linker_abandon(linker: &mut Linker) {
    release_dependencies(linker, false, false);

    if !linker.img.is_null() && linker.is_linked {
        let main_img = unsafe { &*linker.img };
        unregister_eh_frame_for_library(main_img);
        unregister_custom_library_for_backtrace(main_img);
    }

    unregister_linker(linker);

    if !linker.img.is_null() {
        // C: _linker_unregister_tls_segment((struct loaded_dep *)linker)
        unregister_tls_segment(
            unsafe { &*linker.img },
            unsafe { &mut *std::ptr::addr_of_mut!(linker.tls_indices) },
        );
        // C: csoloader_elf_destroy(linker->img);
        unsafe { drop(Box::from_raw(linker.img)) };
    }
    linker.img = std::ptr::null_mut();

    linker.dep_count = 0;
    linker.is_linked = false;
    linker.main_map_size = 0;
}

// ---------------------------------------------------------------------------
// elf_util.c `csoloader_elf_create` wrappers (heap CsoElf behind the raw
// pointer `struct linker` stores; NULL on failure like the C)
// ---------------------------------------------------------------------------

/// `csoloader_elf_create(name, base)`.
fn elf_create(path: &str, base: usize) -> *mut CsoElf {
    match CsoElf::create(path, base) {
        Ok(img) => Box::into_raw(Box::new(img)),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `csoloader_elf_create(name, NULL)`: base resolved via dl_iterate_phdr
/// (returns NULL when no module matches, like the C).
fn elf_create_loaded(name: &str) -> *mut CsoElf {
    match CsoElf::create_loaded(name) {
        Ok(img) => Box::into_raw(Box::new(img)),
        Err(_) => std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// linker_link pipeline (1956-2332)
// ---------------------------------------------------------------------------

/// linker.c `_linker_is_library_loaded` (1956-1964): `strstr(img->elf,
/// lib_name)` over the main image and every dependency.
fn is_library_loaded(linker: &Linker, lib_name: &str) -> bool {
    let main_img = unsafe { &*linker.img };
    if main_img.path().contains(lib_name) {
        return true;
    }

    for i in 0..linker.dep_count as usize {
        let img = unsafe { &*linker.dependencies[i].img };
        if img.path().contains(lib_name) {
            return true;
        }
    }

    false
}

/// Cache flush for instruction cache coherency after writing executable code.
/// Uses the cacheflush syscall on ARM/AArch64 instead of the external
/// `__clear_cache` symbol which may not be available at runtime.
fn clear_cache(beg: usize, end: usize) {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // On AArch64, use DC CVAU (clean data cache) + IC IVAU (invalidate icache)
        // for each cache line, then DSB + ISB barriers.
        // Cache line size is typically 64 bytes on most ARM64 implementations.
        const CACHE_LINE: usize = 64;
        let mut addr = beg & !(CACHE_LINE - 1);
        while addr < end {
            std::arch::asm!(
                "dc cvau, {addr}",
                addr = in(reg) addr,
                options(nostack, preserves_flags)
            );
            addr += CACHE_LINE;
        }
        std::arch::asm!("dsb ish", options(nostack, preserves_flags));
        addr = beg & !(CACHE_LINE - 1);
        while addr < end {
            std::arch::asm!(
                "ic ivau, {addr}",
                addr = in(reg) addr,
                options(nostack, preserves_flags)
            );
            addr += CACHE_LINE;
        }
        std::arch::asm!("dsb ish", "isb", options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "arm")]
    unsafe {
        // On 32-bit ARM, use the cacheflush syscall (__ARM_NR_cacheflush,
        // 0x000f0002). syscall numbers are c_long-sized, which is i32 here.
        libc::syscall(0xf0002 as libc::c_long, beg as *mut c_void, end as *mut c_void, 0i32);
    }
    #[cfg(target_arch = "riscv64")]
    unsafe {
        // RISC-V uses fence.i for instruction cache synchronization
        std::arch::asm!("fence.i", options(nostack, preserves_flags));
        let _ = (beg, end);
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "arm", target_arch = "riscv64")))]
    let _ = (beg, end);
}

/// linker.c `_linker_restore_protections` (1966-2034): recompute the
/// per-page OR of the PT_LOAD flags and mprotect the whole image span back.
fn restore_protections(image: &CsoElf) {
    // Find the minimum and maximum addresses of all loadable segments.
    let segments = image.load_segments();
    let mut min_addr = usize::MAX;
    let mut max_addr = 0usize;
    for seg in &segments {
        let seg_start_addr = image.runtime(seg.vaddr);
        let seg_end_addr = seg_start_addr.wrapping_add(seg.memsz as usize);

        if seg_start_addr < min_addr {
            min_addr = seg_start_addr;
        }
        if seg_end_addr > max_addr {
            max_addr = seg_end_addr;
        }
    }

    // No loadable segments found, nothing to do.
    if min_addr >= max_addr {
        return;
    }

    let start_page_addr = page_start(min_addr);
    let end_page_addr = page_end(max_addr);
    let num_pages = (end_page_addr - start_page_addr) / page_size();

    if num_pages == 0 {
        return;
    }

    // C: calloc(num_pages, sizeof(int)); a failed calloc logs and returns —
    // Rust allocation failure aborts instead (PORT-NOTE).
    let mut page_protections = vec![0i32; num_pages];

    for seg in &segments {
        let mut seg_prot = 0i32;
        if seg.flags & PF_R != 0 {
            seg_prot |= libc::PROT_READ;
        }
        if seg.flags & PF_W != 0 {
            seg_prot |= libc::PROT_WRITE;
        }
        if seg.flags & PF_X != 0 {
            seg_prot |= libc::PROT_EXEC;
        }

        let seg_start_addr = image.runtime(seg.vaddr);
        let seg_end_addr = seg_start_addr.wrapping_add(seg.memsz as usize);
        let mut current_page = page_start(seg_start_addr);

        while current_page < page_end(seg_end_addr) {
            let page_index = (current_page - start_page_addr) / page_size();
            if page_index < num_pages {
                page_protections[page_index] |= seg_prot;
            } else {
                dloge!(
                    "Calculated page index {} out of bounds (num_pages: {}) for segment in {}, skipping page",
                    page_index,
                    num_pages,
                    image.path()
                );
            }

            current_page += page_size();
        }
    }

    // Restore protections for all pages in the range.
    // page_protections was sized to num_pages above.
    for (i, &final_prot) in page_protections.iter().enumerate() {
        let current_page = start_page_addr + i * page_size();

        if final_prot != 0
            && unsafe { libc::mprotect(current_page as *mut c_void, page_size(), final_prot) } != 0
        {
            dlogw!(
                "mprotect failed to restore prot {} for page {:p} in {}: {}",
                final_prot,
                current_page as *const c_void,
                image.path(),
                std::io::Error::last_os_error()
            );
        } else if (final_prot & libc::PROT_EXEC) != 0 && (final_prot & libc::PROT_READ) != 0 {
            clear_cache(current_page, current_page + page_size());
        }
    }
}

/// linker.c `linker_link` (2045-2332).
pub fn linker_link(linker: &mut Linker) -> bool {
    // C: struct carray *loaded_libs = carray_create(64); (the carray.c port
    // lives in crate::misc; linker_link only needs these semantics — Rust
    // allocation failure aborts instead of returning NULL, PORT-NOTE).
    let Some(mut loaded_libs) = Carray::create(64) else {
        dloge!("Failed to create loaded libraries array");
        return false;
    };

    // C 2053-2084: main image DT_NEEDED scan (ld-android.so skipped).
    {
        let main_img = unsafe { &*linker.img };
        for dep_name in main_img.needed_libraries() {
            if dep_name == "ld-android.so" {
                dlogd!("Skipping internal linker dependency: {}", dep_name);
                continue;
            }

            dlogd!("Found needed dependency in main image: {}", dep_name);

            if !loaded_libs.add(dep_name) {
                dloge!("Failed to add dependency to loaded libraries array");
                return false;
            }
        }
    }

    // C 2086-2203: dependency load loop.
    let mut i: isize = 0;
    while i < loaded_libs.length() as isize {
        let Some(lib_name) = loaded_libs.get(i as usize).map(str::to_string) else {
            dloge!("Loaded library name is NULL");
            return false;
        };

        let mut lib_full_path = [0u8; PATH_MAX];
        if !crate::linker_load::linker_find_library_path(&lib_name, &mut lib_full_path) {
            dlogw!("Could not find required library: {}", lib_name);
            // C: rather than failing, skip missing libraries
            // (carray_remove; i--; continue — net: reprocess this slot).
            loaded_libs.remove(&lib_name);
            continue;
        }

        let path_end = lib_full_path
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(lib_full_path.len());
        let lib_full_path_lossy = String::from_utf8_lossy(&lib_full_path[..path_end]);
        let lib_full_path: &str = lib_full_path_lossy.as_ref();

        if is_library_loaded(linker, lib_full_path) {
            dlogd!("Library already loaded: {}", lib_full_path);
            i += 1;
            continue;
        }

        if linker.dep_count >= MAX_DEPS as i32 {
            dloge!(
                "Maximum dependency count ({}) exceeded while loading: {}",
                MAX_DEPS,
                lib_full_path
            );
            return false;
        }

        // C: struct loaded_dep *current_dep = &linker->dependencies[linker->dep_count];
        let dep_index = linker.dep_count as usize;
        let check_img = elf_create_loaded(&lib_name);

        let is_manual: bool;
        if !check_img.is_null() && unsafe { (*check_img).base() } != 0 {
            // C: already loaded somewhere — reuse it (csoloader_elf_create(lib_name, NULL)).
            let dep = &mut linker.dependencies[dep_index];
            dep.img = check_img;
            dep.is_manual_load = false;
            is_manual = false;
        } else {
            let dep = &mut linker.dependencies[dep_index];
            let base_addr = crate::linker_load::linker_load_library_manually(lib_full_path, dep);
            if base_addr.is_null() {
                dloge!("Failed to manually load library: {}", lib_full_path);
                if !check_img.is_null() {
                    unsafe { drop(Box::from_raw(check_img)) };
                }
                return false;
            }

            dep.img = elf_create(lib_full_path, base_addr as usize);
            if dep.img.is_null() {
                dloge!("Failed to create ELF image for manually loaded library: {}", lib_full_path);
                if !check_img.is_null() {
                    unsafe { drop(Box::from_raw(check_img)) };
                }
                return false;
            }

            dep.is_manual_load = true;
            is_manual = true;

            if !check_img.is_null() {
                unsafe { drop(Box::from_raw(check_img)) };
            }
        }

        if linker.dependencies[dep_index].img.is_null() {
            dloge!("Failed to create ELF image for: {}", lib_full_path);
            return false;
        }

        linker.dep_count += 1;

        // C 2164-2202: transitive DT_NEEDED of the just-loaded manual dep.
        if is_manual {
            let dep_img = unsafe { &*linker.dependencies[dep_index].img };
            for dep_name in dep_img.needed_libraries() {
                if dep_name == "ld-android.so" {
                    dlogd!(
                        "Skipping internal linker dependency in {}: {}",
                        dep_img.path(),
                        dep_name
                    );
                    continue;
                }

                if loaded_libs.exists(dep_name) {
                    dlogd!("Dependency already loaded: {}", dep_name);
                    continue;
                }

                dlogd!("Found needed dependency in {}: {}", dep_img.path(), dep_name);

                if !loaded_libs.add(dep_name) {
                    dloge!("Failed to add dependency to loaded libraries array");
                    return false;
                }
            }
        }

        i += 1;
    }
    // C 2205: carray_destroy(loaded_libs);
    drop(loaded_libs);

    // C 2207-2219: TLS registration + generation bump.
    // Registration failure is fatal here (unlike the C, which ignores the
    // bool): a module whose PT_TLS segment did not register would keep live
    // `__tls_get_addr` trampolines aimed at an unregistered slot, and every
    // access would degrade forever. Failing the link keeps the degradation
    // paths in tls.rs unreachable from a half-loaded module.
    dlogd!("Registering TLS segments for main library and dependencies.");
    {
        let main_img = unsafe { &*linker.img };
        if !crate::tls::register_tls_segment(main_img) {
            dloge!(
                "Failed to register TLS segment for {} — refusing to link",
                main_img.path()
            );
            return false;
        }
    }
    for dep in &linker.dependencies[..linker.dep_count as usize] {
        if !dep.is_manual_load {
            continue;
        }

        let dep_img = unsafe { &*dep.img };
        dlogd!("Registering TLS segment for dependency: {}", dep_img.path());
        if !crate::tls::register_tls_segment(dep_img) {
            dloge!(
                "Failed to register TLS segment for dependency {} — refusing to link",
                dep_img.path()
            );
            return false;
        }
    }
    dlogd!("Bumping TLS generation for all threads");
    // C: g_tls_generation++; (linker.c 2218-2219)
    crate::tls::bump_tls_generation();

    // C 2221-2247: make non-writable PT_LOADs writable for relocations.
    dlogd!("Making memory writable for relocations");
    let page_sz = page_size();
    {
        let main_img = unsafe { &*linker.img };
        for (j, (p_type, seg)) in main_img.all_segments().iter().enumerate() {
            if *p_type != PT_LOAD || seg.flags & PF_W != 0 {
                continue;
            }

            let page_start_addr = (main_img.base() as u64)
                .wrapping_add(seg.vaddr)
                .wrapping_sub(main_img.bias() as u64)
                & !(page_sz as u64 - 1);
            // C quirk kept: page_len is computed in file-vaddr space (no bias).
            let page_len = page_end((seg.vaddr as usize).wrapping_add(seg.memsz as usize))
                - page_start(seg.vaddr as usize);
            let prot = libc::PROT_READ
                | libc::PROT_WRITE
                | if seg.flags & PF_X != 0 { libc::PROT_EXEC } else { 0 };

            if unsafe { libc::mprotect(page_start_addr as *mut c_void, page_len, prot) } != 0 {
                dlogw!(
                    "mprotect failed to make main image segment {} writable: {}",
                    j,
                    std::io::Error::last_os_error()
                );
            }
        }
    }
    for i in 0..linker.dep_count as usize {
        let dep = &linker.dependencies[i];
        if !dep.is_manual_load {
            continue;
        }

        let dep_img = unsafe { &*dep.img };
        for (j, (p_type, seg)) in dep_img.all_segments().iter().enumerate() {
            if *p_type != PT_LOAD || seg.flags & PF_W != 0 {
                continue;
            }

            let page_start_addr = (dep_img.base() as u64)
                .wrapping_add(seg.vaddr)
                .wrapping_sub(dep_img.bias() as u64)
                & !(page_sz as u64 - 1);
            let page_len = page_end((seg.vaddr as usize).wrapping_add(seg.memsz as usize))
                - page_start(seg.vaddr as usize);
            let prot = libc::PROT_READ
                | libc::PROT_WRITE
                | if seg.flags & PF_X != 0 { libc::PROT_EXEC } else { 0 };

            if unsafe { libc::mprotect(page_start_addr as *mut c_void, page_len, prot) } != 0 {
                dlogw!(
                    "mprotect failed for make segment {} in {} writable: {}",
                    j,
                    dep_img.path(),
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    // C 2249-2264: relocations (main first, then manual deps).
    dlogd!("Processing relocations for main library and dependencies.");
    // C: _linker_process_relocations(linker, (struct loaded_dep *)linker) —
    // linker.h keeps the first two members of `struct linker` identical to
    // `struct loaded_dep` so the cast is valid.
    let main_dep: &mut LoadedDep = unsafe { &mut *(linker as *mut Linker as *mut LoadedDep) };
    if !crate::linker_reloc::linker_process_relocations(linker, main_dep) {
        let main_img = unsafe { &*linker.img };
        dloge!("Failed processing relocations for main library: {}", main_img.path());
        return false;
    }
    for i in 0..linker.dep_count as usize {
        if !linker.dependencies[i].is_manual_load {
            continue;
        }

        let dep: &mut LoadedDep = unsafe { &mut *std::ptr::addr_of_mut!(linker.dependencies[i]) };
        if !crate::linker_reloc::linker_process_relocations(linker, dep) {
            let img = unsafe { &*dep.img };
            dloge!("Failed processing relocations for dependency: {}", img.path());
            return false;
        }
    }

    // C 2266-2274: restore the PT_LOAD protections.
    dlogd!("Restoring memory protections after relocations");
    restore_protections(unsafe { &*linker.img });
    for dep in &linker.dependencies[..linker.dep_count as usize] {
        if !dep.is_manual_load {
            continue;
        }
        restore_protections(unsafe { &*dep.img });
    }

    // C 2276-2287: apply GNU RELRO.
    dlogd!("Applying GNU RELRO protection for main library and dependencies.");
    if protect_gnu_relro(unsafe { &*linker.img }) != 0 {
        dlogw!("Failed to apply GNU RELRO protection to main library");
    }
    for dep in &linker.dependencies[..linker.dep_count as usize] {
        if !dep.is_manual_load {
            continue;
        }
        if protect_gnu_relro(unsafe { &*dep.img }) != 0 {
            dlogw!(
                "Failed to apply GNU RELRO protection to {}",
                unsafe { (*dep.img).path() }
            );
        }
    }

    // C 2289-2303: backtrace support registrations.
    {
        let main_img = unsafe { &*linker.img };
        if !register_custom_library_for_backtrace(main_img) {
            dlogw!("Failed to register main library for backtrace support");
        }
        register_eh_frame_for_library(main_img);
    }
    for dep in &linker.dependencies[..linker.dep_count as usize] {
        if !dep.is_manual_load {
            continue;
        }

        let dep_img = unsafe { &*dep.img };
        if !register_custom_library_for_backtrace(dep_img) {
            dlogw!("Failed to register dependency {} for backtrace support", dep_img.path());
        }
        register_eh_frame_for_library(dep_img);
    }

    // C 2305-2307: preinit is for the main EXECUTABLE only — skipped, as in
    // the C (commented out there too).
    // C 2309-2327: constructors — manual deps first (a manual dep runs only
    // after its manual DT_NEEDED deps), then the main elf.
    let mut constructor_state = [0u8; MAX_DEPS];
    for i in 0..linker.dep_count as usize {
        if !linker.dependencies[i].is_manual_load {
            continue;
        }

        call_manual_constructors(linker, i, &mut constructor_state);
    }
    for (i, state) in constructor_state
        .iter_mut()
        .enumerate()
        .take(linker.dep_count as usize)
    {
        if !linker.dependencies[i].is_manual_load || *state == 2 {
            continue;
        }

        call_constructors(unsafe { &*linker.dependencies[i].img });
        *state = 2;
    }
    call_constructors(unsafe { &*linker.img });

    linker.is_linked = true;

    true
}

/// linker.c `linker_deinit` (2334-2348): the TLS teardown half lives in
/// crate::tls (`deinit`), already ported.
pub fn linker_deinit() {
    crate::tls::deinit();
}

// ---------------------------------------------------------------------------
// carray.c `struct carray` — module-local: the carray.c port lives in
// crate::misc, linker_link only needs these exact semantics (slot-based
// storage, first-free-slot add, memmove-compacting remove).
// ---------------------------------------------------------------------------

struct Carray {
    /// `carr->array` — slots are NULL when free (carray_add fills the first
    /// free slot, carray_remove compacts with memmove).
    array: Vec<Option<String>>,
    /// `carr->size` (capacity).
    size: usize,
    /// `carr->length`.
    length: usize,
}

impl Carray {
    /// carray.c `carray_create` (malloc/calloc failure → NULL → the caller's
    /// "Failed to create loaded libraries array" LOGE; Rust aborts on OOM).
    fn create(size: usize) -> Option<Self> {
        Some(Self {
            array: vec![None; size],
            size,
            length: 0,
        })
    }

    /// carray.c `carray_length`.
    fn length(&self) -> usize {
        self.length
    }

    /// carray.c `carray_exists`.
    fn exists(&self, s: &str) -> bool {
        for i in 0..self.size {
            if self.array[i].as_deref() == Some(s) {
                return true;
            }
        }
        false
    }

    /// carray.c `carray_get` (NULL slot / out of bounds → None; the C logs
    /// `"Invalid carray or index out of bounds"` only for `index >= size`).
    fn get(&self, index: usize) -> Option<&str> {
        if index >= self.size {
            dloge!("Invalid carray or index out of bounds");
            return None;
        }
        self.array[index].as_deref()
    }

    /// carray.c `carray_add`.
    fn add(&mut self, s: &str) -> bool {
        for i in 0..self.size {
            if self.array[i].is_none() {
                self.array[i] = Some(s.to_string());
                self.length += 1;
                return true;
            }
        }

        dlogw!("Carray is full, expanding size");

        let new_size = if self.size > 0 { self.size * 2 } else { 1 };
        self.array.resize(new_size, None);
        self.size = new_size;

        self.array[self.length] = Some(s.to_string());
        self.length += 1;

        true
    }

    /// carray.c `carray_remove`.
    fn remove(&mut self, s: &str) -> bool {
        for i in 0..self.size {
            if self.array[i].as_deref() != Some(s) {
                continue;
            }

            self.array[i] = None;
            // C: memmove(&carr->array[i], &carr->array[i + 1],
            //            (carr->size - i - 1) * sizeof(char *));
            for j in i..self.size - 1 {
                let next = self.array[j + 1].take();
                self.array[j] = next;
            }
            self.array[self.size - 1] = None;
            self.length -= 1;

            return true;
        }

        dlogw!("String not found in carray: {}", s);

        false
    }

    // carray.c `carray_destroy`: Rust drop frees the strings + storage.
}

// ---------------------------------------------------------------------------
// backtrace-support.c hooks — owned by the crate::misc port
// (backtrace-support.c). Signatures mirror backtrace-support.c so the calls
// above can move to `crate::misc::*` verbatim once it lands.
// ---------------------------------------------------------------------------

/// backtrace-support.c `register_custom_library_for_backtrace` (434).
fn register_custom_library_for_backtrace(img: &CsoElf) -> bool {
    crate::backtrace::register_custom_library_for_backtrace(img)
}

/// backtrace-support.c `unregister_custom_library_for_backtrace` (489).
fn unregister_custom_library_for_backtrace(img: &CsoElf) -> bool {
    crate::backtrace::unregister_custom_library_for_backtrace(img)
}

/// backtrace-support.c `register_eh_frame_for_library` (518).
fn register_eh_frame_for_library(img: &CsoElf) {
    crate::backtrace::register_eh_frame_for_library(img);
}

/// backtrace-support.c `unregister_eh_frame_for_library` (559).
fn unregister_eh_frame_for_library(img: &CsoElf) {
    crate::backtrace::unregister_eh_frame_for_library(img);
}

