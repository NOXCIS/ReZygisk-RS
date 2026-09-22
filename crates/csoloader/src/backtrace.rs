//! Port of csoloader `backtrace-support.c` registry half (lines 419-570):
//! `g_custom_libs[]`, `copy_program_headers`,
//! `register/unregister_custom_library_for_backtrace` and
//! `register/unregister_eh_frame_for_library`.
//!
//! The registry's *consumers* (`custom_dladdr`, `custom_dl_iterate_phdr`)
//! stay inert exactly like the C build (CSOLOADER_MAKE_LINKER_HOOKS off):
//! the only outside reader of this state is libunwind, through the weak
//! `__register_frame`/`__deregister_frame` hooks. `phdr_copy` and the
//! `dl_phdr_info` fields are maintained so a future MAKE_LINKER_HOOKS build
//! has the same data the C exposes.
//!
//! Uses std::sync::Mutex instead of pthread_mutex_t for sound Rust access.

use std::ffi::c_char;
use std::ffi::c_void;
use std::sync::Mutex;

use crate::image::CsoElf;
use crate::TAG;
#[cfg_attr(target_arch = "arm", allow(unused_imports))] // logw is EH-frame-only; ARM32 uses EHABI
use rz_common::{logd, loge, logw};

macro_rules! dlogd {
    ($($arg:tt)*) => {{ logd!(TAG, $($arg)*); }};
}
#[cfg_attr(target_arch = "arm", allow(unused_macros))] // same EH-frame/EHABI reason
macro_rules! dlogw {
    ($($arg:tt)*) => {{ logw!(TAG, $($arg)*); }};
}
macro_rules! dloge {
    ($($arg:tt)*) => {{ loge!(TAG, $($arg)*); }};
}

/// backtrace-support.c `MAX_CUSTOM_LIBS`.
pub(crate) const MAX_CUSTOM_LIBS: usize = 64;

/// backtrace-support.c `struct custom_lib_info`.
#[derive(Clone, Copy)]
struct CustomLibInfo {
    img: *const CsoElf,
    phdr_info: libc::dl_phdr_info,
    in_use: bool,
    phdr_copy: *mut c_void,

    eh_frame_registered: *mut c_void,
    eh_frame_size: usize,
}

impl CustomLibInfo {
    const fn new() -> Self {
        Self {
            img: std::ptr::null(),
            phdr_info: libc::dl_phdr_info {
                dlpi_addr: 0,
                dlpi_name: std::ptr::null(),
                dlpi_phdr: std::ptr::null(),
                dlpi_phnum: 0,
                dlpi_adds: 0,
                dlpi_subs: 0,
                dlpi_tls_modid: 0,
                dlpi_tls_data: std::ptr::null_mut(),
            },
            in_use: false,
            phdr_copy: std::ptr::null_mut(),
            eh_frame_registered: std::ptr::null_mut(),
            eh_frame_size: 0,
        }
    }
}

// SAFETY: CustomLibInfo contains raw pointers but they are only dereferenced
// while the mutex is held, and the backtrace registry is only accessed from
// the main thread during library load/unload.
unsafe impl Send for CustomLibInfo {}
unsafe impl Sync for CustomLibInfo {}

/// The custom library registry protected by a Mutex for sound Rust access.
/// Consolidates the C's separate pthread_mutex + static array pattern.
static G_CUSTOM_LIBS: Mutex<[CustomLibInfo; MAX_CUSTOM_LIBS]> =
    Mutex::new([CustomLibInfo::new(); MAX_CUSTOM_LIBS]);

/// backtrace-support.c `copy_program_headers` (419): malloc'd copy of the
/// on-disk phdr table, kept alive for the inert `custom_dl_iterate_phdr`
/// consumer.
fn copy_program_headers(img: &CsoElf) -> *mut c_void {
    let (_, phdrs) = img.phdr_table();
    if phdrs.is_empty() {
        dloge!("Empty program header table for {}", img.path());
        return std::ptr::null_mut();
    }

    let ptr = unsafe { libc::malloc(phdrs.len()) as *mut c_void };
    if ptr.is_null() {
        dloge!("Failed to allocate memory for program header copy");
        return std::ptr::null_mut();
    }

    unsafe {
        std::ptr::copy_nonoverlapping(phdrs.as_ptr(), ptr as *mut u8, phdrs.len());
    }
    ptr
}

/// Weak `void __register_frame(void *)` from libunwind (linker-resolved weak
/// import in the C); `dlsym` is the Rust equivalent of that weak reference.
#[cfg_attr(target_arch = "arm", allow(dead_code))] // EHABI: registration skipped
fn resolve_register_frame() -> Option<unsafe extern "C" fn(*const c_void)> {
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__register_frame".as_ptr()) };
    if sym.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn(*const c_void)>(sym) })
    }
}

/// Weak `void __deregister_frame(void *)` (see `resolve_register_frame`).
fn resolve_deregister_frame() -> Option<unsafe extern "C" fn(*const c_void)> {
    let sym = unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"__deregister_frame".as_ptr()) };
    if sym.is_null() {
        None
    } else {
        Some(unsafe { std::mem::transmute::<*mut c_void, unsafe extern "C" fn(*const c_void)>(sym) })
    }
}

/// backtrace-support.c `register_custom_library_for_backtrace` (434).
pub(crate) fn register_custom_library_for_backtrace(img: &CsoElf) -> bool {
    let mut libs = G_CUSTOM_LIBS.lock().unwrap();

    let mut slot = -1i32;
    for i in 0..MAX_CUSTOM_LIBS {
        if libs[i].in_use {
            continue;
        }
        slot = i as i32;
        break;
    }

    if slot == -1 {
        dloge!("No available slots for custom library registration");
        return false;
    }

    let lib_info = &mut libs[slot as usize];
    lib_info.phdr_copy = copy_program_headers(img);
    if lib_info.phdr_copy.is_null() {
        dloge!("Failed to copy program headers for custom library {}", img.path());
        return false;
    }

    // C: (ElfW(Addr))img->base - img->bias.
    lib_info.phdr_info.dlpi_addr = img.base().wrapping_sub(img.bias() as usize) as _;
    lib_info.phdr_info.dlpi_name = img.path().as_ptr() as *const c_char;
    lib_info.phdr_info.dlpi_phdr = lib_info.phdr_copy as *const _;
    lib_info.phdr_info.dlpi_phnum = img.phdr_table().0 as _;
    lib_info.phdr_info.dlpi_adds = 1;
    lib_info.phdr_info.dlpi_subs = 0;

    if img.tls_segment().is_some() {
        lib_info.phdr_info.dlpi_tls_modid = img.tls_mod_id() as _;
        lib_info.phdr_info.dlpi_tls_data = std::ptr::null_mut();
    } else {
        lib_info.phdr_info.dlpi_tls_modid = 0;
        lib_info.phdr_info.dlpi_tls_data = std::ptr::null_mut();
    }

    lib_info.img = img;
    lib_info.in_use = true;
    lib_info.eh_frame_registered = std::ptr::null_mut();
    lib_info.eh_frame_size = 0;

    true
}

/// backtrace-support.c `unregister_custom_library_for_backtrace` (489).
pub(crate) fn unregister_custom_library_for_backtrace(img: &CsoElf) -> bool {
    let mut libs = G_CUSTOM_LIBS.lock().unwrap();

    for i in 0..MAX_CUSTOM_LIBS {
        let lib_info = &mut libs[i];
        if !lib_info.in_use || lib_info.img != img as *const CsoElf {
            continue;
        }

        if !lib_info.eh_frame_registered.is_null() {
            if let Some(deregister_frame) = resolve_deregister_frame() {
                unsafe { deregister_frame(lib_info.eh_frame_registered) };
            }
            // C: LOGD("Deregistered .eh_frame for %s") (backtrace-support.c 498)
            // between the deregister call and the NULL reset.
            dlogd!("Deregistered .eh_frame for {}", img.path());
            lib_info.eh_frame_registered = std::ptr::null_mut();
        }

        if !lib_info.phdr_copy.is_null() {
            unsafe { libc::free(lib_info.phdr_copy) };
        }
        *lib_info = CustomLibInfo::new();

        dlogd!("Unregistered custom library for backtrace support");
        return true;
    }

    false
}

/// backtrace-support.c `register_eh_frame_for_library` (518).
pub(crate) fn register_eh_frame_for_library(img: &CsoElf) {
    // C #ifdef __arm__: EHABI has no .eh_frame to register.
    #[cfg(target_arch = "arm")]
    {
        let _ = img;
        dlogd!("Skipping .eh_frame registration on ARM32 (EHABI)");
        return;
    }

    #[cfg(not(target_arch = "arm"))]
    {
        let Some((eh_frame_ptr, eh_frame_size)) = img.locate_eh_frame() else {
            dlogw!("No .eh_frame found for {}; exceptions may fail", img.path());
            return;
        };

        // C order (backtrace-support.c 534-542): log, then the weak
        // `__register_frame` check (dlsym here), then call + log.
        dlogd!(
            "Registering .eh_frame at {:p} (size ~{eh_frame_size}) for {}",
            eh_frame_ptr as *const c_void,
            img.path()
        );

        let Some(register_frame) = resolve_register_frame() else {
            dlogw!(
                "__register_frame not available; skipping .eh_frame registration for {}",
                img.path()
            );
            return;
        };

        unsafe { register_frame(eh_frame_ptr as *const c_void) };
        dlogd!(
            "Registered .eh_frame at {:p} (size ~{eh_frame_size}) for {}",
            eh_frame_ptr as *const c_void,
            img.path()
        );

        let mut libs = G_CUSTOM_LIBS.lock().unwrap();
        for i in 0..MAX_CUSTOM_LIBS {
            let lib_info = &mut libs[i];
            if !lib_info.in_use || lib_info.img != img as *const CsoElf {
                continue;
            }
            lib_info.eh_frame_registered = eh_frame_ptr as *mut c_void;
            lib_info.eh_frame_size = eh_frame_size;
            break;
        }
    }
}

/// backtrace-support.c `unregister_eh_frame_for_library` (559).
pub(crate) fn unregister_eh_frame_for_library(img: &CsoElf) {
    #[cfg(target_arch = "arm")]
    {
        let _ = img;
    }

    #[cfg(not(target_arch = "arm"))]
    {
        let mut libs = G_CUSTOM_LIBS.lock().unwrap();

        for i in 0..MAX_CUSTOM_LIBS {
            let lib_info = &mut libs[i];
            if !lib_info.in_use
                || lib_info.img != img as *const CsoElf
                || lib_info.eh_frame_registered.is_null()
            {
                continue;
            }

            if let Some(deregister_frame) = resolve_deregister_frame() {
                unsafe { deregister_frame(lib_info.eh_frame_registered) };
            }
            lib_info.eh_frame_registered = std::ptr::null_mut();
            dlogd!("Deregistered .eh_frame for {}", img.path());
            break;
        }
    }
}
