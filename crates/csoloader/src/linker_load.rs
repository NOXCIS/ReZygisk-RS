//! Port of `loader/src/external/csoloader/src/linker.c` manual-loading
//! machinery:
//!
//! - `_linker_find_library_path` (linker.c:369-419) — the DT_NEEDED search
//!   path list.
//! - `phdr_get_load_size` (linker.c:605-620), `_linker_load_one_segment`
//!   (linker.c:622-686) and `linker_load_library_manually`
//!   (linker.c:688-797) — the fd-based segment loader.
//! - `_linker_find_highest_gap_start` (linker.c:183-213) — needed by the
//!   LP64 reservation path of `linker_load_library_manually`; it sits inside
//!   linker_core's line range but is ported here so the loader is
//!   self-contained (linker_core's port may re-home it).
//!
//! Control flow, log messages and error handling mirror the C line for line;
//! no behavior changes.

use std::io::Read;
use std::mem::ManuallyDrop;
use std::os::fd::FromRawFd;
use std::ptr::null_mut;

use libc::c_void;

use rz_elf::{ElfImage, LoadSegment};

use crate::linker_core::{page_size, LoadedDep};

/// Module-local log tag (linker.c logs under the "zygisk" LOG_TAG).
const TAG: &str = rz_common::LOG_TAG;

macro_rules! dlogd {
    ($($arg:tt)*) => {{ rz_common::logd!(TAG, $($arg)*); }};
}
macro_rules! dloge {
    ($($arg:tt)*) => {{ rz_common::loge!(TAG, $($arg)*); }};
}

const PT_LOAD: u32 = 1;

// libc's Android bindings don't export the phdr PF_* flags.
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

// ElfW(Ehdr) / ElfW(Phdr) layouts for the host word size (CSOLoader is
// compiled per-arch, so ElfW matches the target pointer width).
#[cfg(target_pointer_width = "64")]
const EHDR_SIZE: usize = 64;
#[cfg(target_pointer_width = "32")]
const EHDR_SIZE: usize = 52;

#[cfg(target_pointer_width = "64")]
const EHDR_E_PHOFF: usize = 32;
#[cfg(target_pointer_width = "32")]
const EHDR_E_PHOFF: usize = 28;

#[cfg(target_pointer_width = "64")]
const EHDR_E_PHNUM: usize = 56;
#[cfg(target_pointer_width = "32")]
const EHDR_E_PHNUM: usize = 44;

#[cfg(target_pointer_width = "64")]
const PHDR_SIZE: usize = 56;
#[cfg(target_pointer_width = "32")]
const PHDR_SIZE: usize = 32;

// linker.c:370-405: the `__LP64__`/`__ANDROID__` search path table. The C
// appends "/usr/local/lib/" after the compiled-in list, then NULL.
#[cfg(all(target_pointer_width = "64", target_os = "android"))]
const SEARCH_PATHS: &[&str] = &[
    "/apex/com.android.tethering/lib64/",
    "/apex/com.android.runtime/lib64/bionic/",
    "/apex/com.android.runtime/lib64/",
    "/apex/com.android.os.statsd/lib64/",
    "/apex/com.android.i18n/lib64/",
    "/apex/com.android.art/lib64/",
    "/system/lib64/",
    "/vendor/lib64/",
];

#[cfg(all(target_pointer_width = "64", not(target_os = "android")))]
const SEARCH_PATHS: &[&str] = &[
    "/lib64/",
    "/usr/lib64/",
    "/lib/x86_64-linux-gnu/",
    "/usr/lib/x86_64-linux-gnu/",
];

#[cfg(all(target_pointer_width = "32", target_os = "android"))]
const SEARCH_PATHS: &[&str] = &[
    "/apex/com.android.tethering/lib/",
    "/apex/com.android.runtime/lib/bionic/",
    "/apex/com.android.runtime/lib/",
    "/apex/com.android.os.statsd/lib/",
    "/apex/com.android.i18n/lib/",
    "/apex/com.android.art/lib/",
    "/system/lib/",
    "/vendor/lib/",
];

#[cfg(all(target_pointer_width = "32", not(target_os = "android")))]
const SEARCH_PATHS: &[&str] = &["/lib/", "/usr/lib/", "/lib/i386-linux-gnu/"];

/// `_linker_find_library_path` (linker.c:369-419): try each search path with
/// `access(..., F_OK)` on `dir + lib_name`. On success the full path is
/// written NUL-terminated into `full_path` (`char full_path[PATH_MAX]` in
/// the C); on failure it is emptied and the C error is logged.
pub fn linker_find_library_path(lib_name: &str, full_path: &mut [u8]) -> bool {
    let search_paths = SEARCH_PATHS.iter().copied().chain(["/usr/local/lib/"].into_iter());

    // TODO: Read ldconfig

    for dir in search_paths {
        snprintf_full_path(full_path, dir, lib_name);

        if unsafe { libc::access(full_path.as_ptr() as *const libc::c_char, libc::F_OK) } == 0 {
            return true;
        }
    }

    dloge!("Could not find library which shared library depends on: {}", lib_name);
    full_path[0] = 0;

    false
}

/// `snprintf(full_path, full_path_size, "%s%s", dir, lib_name)`: writes the
/// concatenation up to `full_path.len() - 1` bytes and NUL-terminates.
fn snprintf_full_path(full_path: &mut [u8], dir: &str, lib_name: &str) {
    if full_path.is_empty() {
        return;
    }

    let cap = full_path.len() - 1;
    let mut n = 0;
    for &b in dir.as_bytes().iter().chain(lib_name.as_bytes().iter()) {
        if n >= cap {
            break;
        }
        full_path[n] = b;
        n += 1;
    }
    full_path[n] = 0;
}

/// linker.c `_page_start` (linker.c:175-177): ALIGN_DOWN(addr, system_page_size).
fn page_start(addr: usize) -> usize {
    addr & !page_size().wrapping_sub(1)
}

/// linker.c `_page_end` (linker.c:179-181):
/// ALIGN_DOWN(addr + system_page_size - 1, system_page_size).
fn page_end(addr: usize) -> usize {
    addr.wrapping_add(page_size().wrapping_sub(1)) & !page_size().wrapping_sub(1)
}

/// `_linker_find_highest_gap_start` (linker.c:183-213): start of the highest
/// 4GiB+ gap in /proc/self/maps that fits `needed_size`.
///
/// INFO: Pick the start of the highest parsed 4GiB+ gap so the mapping stays
///       high and leaves more free space above it, where the process is more
///       likely to create VMAs later.
#[cfg(target_pointer_width = "64")]
fn find_highest_gap_start(needed_size: usize) -> *mut c_void {
    // C: fopen("/proc/self/maps", "re"); if (!fp) return NULL;
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return null_mut();
    };

    let needed_size = page_end(needed_size);

    let mut prev_end = 0usize;
    let mut hint = 0usize;

    for line in maps.lines() {
        // C: sscanf(line, "%" PRIxPTR "-%" PRIxPTR, &start, &end) != 2
        let Some(range) = line.split_whitespace().next() else {
            continue;
        };
        let Some((start_s, end_s)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (
            usize::from_str_radix(start_s, 16),
            usize::from_str_radix(end_s, 16),
        ) else {
            continue;
        };

        let gap_start = page_end(if prev_end != 0 { prev_end } else { 0x1_0000_0000 });
        if start > gap_start && needed_size <= start - gap_start {
            hint = gap_start;
        }
        if end > prev_end {
            prev_end = end;
        }
    }

    hint as *mut c_void
}

/// `phdr_get_load_size` (linker.c:605-620): page-aligned span of the PT_LOAD
/// segments. `min_vaddr` receives the page-aligned lowest vaddr, exactly like
/// the C out-param (including the C's wrap-around result for an empty phdr
/// table).
fn phdr_get_load_size(phdrs: &[(u32, LoadSegment)], min_vaddr: &mut u64) -> usize {
    // ElfW(Addr) lo = UINTPTR_MAX, hi = 0;
    let mut lo = usize::MAX as u64;
    let mut hi = 0u64;

    for (p_type, seg) in phdrs {
        if *p_type != PT_LOAD {
            continue;
        }

        if seg.vaddr < lo {
            lo = seg.vaddr;
        }
        let end = seg.vaddr.wrapping_add(seg.memsz);
        if end > hi {
            hi = end;
        }
    }

    let lo = page_start(lo as usize) as u64;
    let hi = page_end(hi as usize) as u64;

    *min_vaddr = lo;

    hi.wrapping_sub(lo) as usize
}

/// `_linker_load_one_segment` (linker.c:622-686): map one PT_LOAD into the
/// reserved region — file-backed part, anonymous BSS tail, writable-tail
/// zero-fill, and the W+X mprotect dance. Returns 0 / -1 like the C.
fn load_one_segment(fd: libc::c_int, seg: &LoadSegment, bias: usize, file_off: libc::off_t) -> i32 {
    let seg_start = (seg.vaddr as usize).wrapping_add(bias);
    let seg_end = seg_start.wrapping_add(seg.memsz as usize);
    let file_end = seg_start.wrapping_add(seg.filesz as usize);

    let seg_page_start = page_start(seg_start);
    let seg_page_end = page_end(seg_end);

    let file_page = page_start(seg.offset as usize);
    let file_len = page_end(seg.offset.wrapping_add(seg.filesz) as usize).wrapping_sub(file_page);

    let mut prot = 0;
    if seg.flags & PF_R != 0 {
        prot |= libc::PROT_READ;
    }
    if seg.flags & PF_W != 0 {
        prot |= libc::PROT_WRITE;
    }
    if seg.flags & PF_X != 0 {
        prot |= libc::PROT_EXEC;
    }

    // INFO: If it needs WRITE, then mmap without it, and later add that
    //       permission to avoid issues.
    let mut needs_mprotect = false;
    if prot & libc::PROT_WRITE != 0 && prot & libc::PROT_EXEC != 0 {
        needs_mprotect = true;

        prot &= !libc::PROT_EXEC;
    }

    // INFO: mmap with PROT_WRITE on modern Android gives "Invalid argument" error
    if file_len > 0
        && unsafe {
            libc::mmap(
                seg_page_start as *mut c_void,
                file_len,
                prot,
                libc::MAP_FIXED | libc::MAP_PRIVATE,
                fd,
                file_off.wrapping_add(file_page as libc::off_t),
            )
        } == libc::MAP_FAILED
    {
        rz_common::plog!(TAG, "mmap file-backed segment");

        return -1;
    }

    // INFO: mmap the anonymous BSS portion that extends beyond the file size
    if seg_page_end > seg_page_start.wrapping_add(file_len) {
        let bss_addr = seg_page_start.wrapping_add(file_len) as *mut c_void;
        let bss_size = seg_page_end - seg_page_start.wrapping_add(file_len);

        if unsafe {
            libc::mmap(
                bss_addr,
                bss_size,
                prot,
                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        } == libc::MAP_FAILED
        {
            rz_common::plog!(TAG, "mmap anonymous BSS segment");

            return -1;
        }

        // INFO: Clear the memory to avoid use of unitialized variables and garbage data. This is needed.
        unsafe { libc::memset(bss_addr, 0, bss_size) };
    }

    // INFO: This is needed to avoid access to uninitialized data
    if seg.flags & PF_W != 0 && file_end < seg_start.wrapping_add(seg.memsz as usize) {
        let mut zero_len = page_end(file_end).wrapping_sub(file_end);
        let seg_tail = seg_start.wrapping_add(seg.memsz as usize).wrapping_sub(file_end);
        if zero_len > seg_tail {
            zero_len = seg_tail;
        }

        unsafe { libc::memset(file_end as *mut c_void, 0, zero_len) };
    }

    // INFO: Restore PROT_EXEC if it was removed earlier
    if needs_mprotect
        && unsafe {
            libc::mprotect(
                seg_page_start as *mut c_void,
                seg_page_end.wrapping_sub(seg_page_start),
                prot | libc::PROT_EXEC,
            )
        } != 0
    {
        rz_common::plog!(TAG, "mprotect to add PROT_EXEC");

        return -1;
    }

    0
}

/// `linker_load_library_manually` (linker.c:688-797): open the library,
/// reserve a PROT_NONE region spanning all PT_LOAD segments, map each
/// segment in and return the mapping start. Fills `out` exactly like the C
/// `struct loaded_dep`: `map_size`, `is_manual_load`, `load_bias`.
pub fn linker_load_library_manually(lib_path: &str, out: &mut LoadedDep) -> *mut c_void {
    // C: _linker_internal_init(); — the sysconf(_SC_PAGESIZE) cache and its
    // "System page size" LOGD live in linker_core (linker.c:356-366); this
    // module consumes page_size().

    // C: int fd = open(lib_path, O_RDONLY | O_CLOEXEC);
    let c_path = c_string_upto_nul(lib_path);
    let fd = unsafe { libc::open(c_path.as_ptr() as *const libc::c_char, libc::O_RDONLY | libc::O_CLOEXEC) };
    if fd < 0 {
        rz_common::plog!(TAG, "open {}", lib_path);

        return null_mut();
    }

    // C: ElfW(Ehdr) eh; if (pread(fd, &eh, sizeof eh, 0) != sizeof eh) {
    let mut eh = [0u8; EHDR_SIZE];
    if unsafe { libc::pread(fd, eh.as_mut_ptr() as *mut c_void, EHDR_SIZE, 0) } != EHDR_SIZE as isize {
        dloge!("Failed to read ELF header from {}", lib_path);

        unsafe { libc::close(fd) };

        return null_mut();
    }

    #[cfg(target_pointer_width = "64")]
    let e_phoff = u64::from_le_bytes(eh[EHDR_E_PHOFF..EHDR_E_PHOFF + 8].try_into().unwrap());
    #[cfg(target_pointer_width = "32")]
    let e_phoff = u32::from_le_bytes(eh[EHDR_E_PHOFF..EHDR_E_PHOFF + 4].try_into().unwrap()) as u64;
    let e_phnum = u16::from_le_bytes(eh[EHDR_E_PHNUM..EHDR_E_PHNUM + 2].try_into().unwrap());

    // C: const size_t phdr_sz = eh.e_phnum * sizeof(ElfW(Phdr));
    let phdr_sz = e_phnum as usize * PHDR_SIZE;

    // C: ElfW(Phdr) *phdr = malloc(phdr_sz); if (!phdr) {
    let mut phdr: Vec<u8> = Vec::new();
    if phdr.try_reserve_exact(phdr_sz).is_err() {
        dloge!("Failed to allocate memory for program headers from {}", lib_path);

        unsafe { libc::close(fd) };

        return null_mut();
    }
    phdr.resize(phdr_sz, 0);

    // C: if (pread(fd, phdr, phdr_sz, eh.e_phoff) != (ssize_t)phdr_sz) {
    if unsafe { libc::pread(fd, phdr.as_mut_ptr() as *mut c_void, phdr_sz, e_phoff as libc::off_t) }
        != phdr_sz as isize
    {
        dloge!("Failed to read program headers from {}", lib_path);

        unsafe { libc::close(fd) };

        return null_mut();
    }

    // Segment walk via rz_elf over the file image (the image.rs pattern),
    // read through the same fd so the parse stays on the opened descriptor.
    let mut file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    let mut raw: Vec<u8> = Vec::new();
    if file.read_to_end(&mut raw).is_err() {
        dloge!("Failed to read program headers from {}", lib_path);

        unsafe { libc::close(fd) };

        return null_mut();
    }

    let Ok(img) = ElfImage::parse(&raw) else {
        dloge!("Failed to read program headers from {}", lib_path);

        unsafe { libc::close(fd) };

        return null_mut();
    };

    // Every program header in file order — the phdr index drives the
    // "Failed to load segment %d" message.
    let phdrs = img.all_segments();

    // C: ElfW(Addr) min_vaddr;
    //    out->map_size = phdr_get_load_size(phdr, eh.e_phnum, &min_vaddr);
    let mut min_vaddr = 0u64;
    let map_size = phdr_get_load_size(&phdrs, &mut min_vaddr);
    out.map_size = map_size;
    if map_size == 0 {
        dloge!("No loadable segments found in ELF headers");

        unsafe { libc::close(fd) };

        return null_mut();
    }

    // C: void *hint = _linker_find_highest_gap_start(out->map_size); if (!hint) {
    #[cfg(target_pointer_width = "64")]
    let hint = find_highest_gap_start(map_size);
    #[cfg(target_pointer_width = "64")]
    if hint.is_null() {
        dloge!("Failed to find high mmap hint for {}", lib_path);

        unsafe { libc::close(fd) };

        return null_mut();
    }

    // C: void *base = mmap(hint, out->map_size, PROT_NONE,
    //                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    #[cfg(target_pointer_width = "64")]
    let base = unsafe {
        libc::mmap(
            hint,
            map_size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    // C: void *base = mmap(NULL, out->map_size, PROT_NONE,
    //                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    #[cfg(target_pointer_width = "32")]
    let base = unsafe {
        libc::mmap(null_mut(), map_size, libc::PROT_NONE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS, -1, 0)
    };

    if base == libc::MAP_FAILED {
        #[cfg(target_pointer_width = "64")]
        dloge!(
            "Failed to reserve address space at hint {:p} for {}: {}",
            hint,
            lib_path,
            std::io::Error::last_os_error()
        );
        #[cfg(target_pointer_width = "32")]
        dloge!(
            "Failed to reserve address space for {}: {}",
            lib_path,
            std::io::Error::last_os_error()
        );

        unsafe { libc::close(fd) };

        return null_mut();
    }

    dlogd!(
        "Allocated address space for SO loading at {:p} (size {}): {}",
        base,
        map_size,
        lib_path
    );

    // C: ElfW(Addr) bias = (ElfW(Addr))base - min_vaddr;
    let bias = (base as usize).wrapping_sub(min_vaddr as usize);

    // INFO: Load all segments to the reserved address space
    for (i, (p_type, seg)) in phdrs.iter().enumerate() {
        if *p_type != PT_LOAD {
            continue;
        }

        if load_one_segment(fd, seg, bias, 0) != 0 {
            dloge!("Failed to load segment {} of {}", i, lib_path);

            unsafe { libc::munmap(base, map_size) };
            unsafe { libc::close(fd) };

            return null_mut();
        }
    }

    unsafe { libc::close(fd) };

    // C: out->is_manual_load = true; out->load_bias = bias;
    out.is_manual_load = true;
    out.load_bias = bias;

    base
}

/// `open(lib_path, ...)` C-string semantics: the path stops at the first NUL
/// byte, so mirror that instead of erroring like `CString::new`.
fn c_string_upto_nul(path: &str) -> Vec<u8> {
    let end = path.as_bytes().iter().position(|&b| b == 0).unwrap_or(path.len());

    let mut buf = Vec::with_capacity(end + 1);
    buf.extend_from_slice(&path.as_bytes()[..end]);
    buf.push(0);

    buf
}

// ---------------------------------------------------------------------------
// CSOLOADER_MAKE_LINKER_HOOKS stubs
// ---------------------------------------------------------------------------
// The C builds with the macro UNDEFINED (linker.c 1367-1407 are compiled
// out), so the linker never redirects dlopen/dlsym/dlclose through these.
// The port keeps the same default: inert bodies that are unreachable while
// MAKE_LINKER_HOOKS is false; a faithful port of the real custom_* bodies
// (linker.c 407-505 + backtrace-support.c) is only needed if the build flag
// is ever enabled.

/// Inert until CSOLOADER_MAKE_LINKER_HOOKS is enabled (see module docs).
pub unsafe extern "C" fn custom_dlopen(_filename: *const libc::c_char, _flag: libc::c_int) -> *mut c_void {
    null_mut()
}

/// Inert until CSOLOADER_MAKE_LINKER_HOOKS is enabled (see module docs).
pub unsafe extern "C" fn custom_dlsym(_handle: *mut c_void, _symbol: *const libc::c_char) -> *mut c_void {
    null_mut()
}

/// Inert until CSOLOADER_MAKE_LINKER_HOOKS is enabled (see module docs).
pub unsafe extern "C" fn custom_dlclose(_handle: *mut c_void) -> libc::c_int {
    0
}
