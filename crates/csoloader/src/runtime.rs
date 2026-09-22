//! csoloader.c: the public `csoloader_load/unload/abandon/get_symbol/deinit`
//! API the rz-loader module table drives (`loader/src/load_modules.rs` calls
//! these through the `repr(C)` `CsoLib` mirror defined below).
//!
//! Control flow, log messages and error handling mirror
//! `loader/src/external/csoloader/src/csoloader.c` line for line; no
//! behavior changes.

use std::ffi::{c_char, c_void, CString};

use crate::image::CsoElf;
use crate::linker_core::{
    linker_abandon, linker_deinit, linker_destroy, linker_init, linker_link, Linker, LoadedDep,
};
use crate::linker_load::linker_load_library_manually;

/// Module-local log tag (the C `logging.h` uses LOG_TAG "zygisk").
pub const TAG: &str = rz_common::LOG_TAG;

macro_rules! dloge {
    ($($arg:tt)*) => {{ rz_common::loge!(TAG, $($arg)*); }};
}

/// module.h `struct csoloader` — `{ char *lib_path; struct csoloader_elf *img;
/// struct linker linker; }`.
///
/// Defined here rather than in rz-loader so rz-csoloader has no dependency on
/// rz-loader (the dependency direction is loader → csoloader). NOTE:
/// rz-loader's `abi.rs` currently defines its own copy (`abi::CsoLib`) with
/// the same layout; the integrator should re-point it at
/// `rz_csoloader::runtime::CsoLib` (which requires making this module public
/// in `lib.rs`).
#[repr(C)]
#[derive(Default)]
pub struct CsoLib {
    pub lib_path: *mut c_char,
    pub img: *mut CsoElf,
    pub linker: Linker,
}

// SAFETY: CsoLib is only accessed while the module list mutex is held.
// The raw pointers point to memory owned by this library instance that
// remains valid for its lifetime.
unsafe impl Send for CsoLib {}
unsafe impl Sync for CsoLib {}

/// `csoloader_load`: load a library to memory and link it.
pub fn csoloader_load(lib: &mut CsoLib, lib_path: &str) -> bool {
    // struct loaded_dep dep_info = { 0 };
    let mut dep_info = LoadedDep::default();

    let map_start = linker_load_library_manually(lib_path, &mut dep_info);
    if map_start.is_null() {
        dloge!("Failed to load library: {}", lib_path);
        return false;
    }

    // csoloader_elf_create(lib_path, map_start)
    let elf_image = match CsoElf::create(lib_path, map_start as usize) {
        Ok(img) => Box::into_raw(Box::new(img)),
        Err(_) => {
            dloge!("Failed to create ELF image for {}", lib_path);
            if dep_info.map_size > 0 {
                unsafe { libc::munmap(map_start, dep_info.map_size) };
            }
            return false;
        }
    };

    if !linker_init(&mut lib.linker, elf_image) {
        dloge!("Failed to initialize linker for {}", lib_path);
        // csoloader_elf_destroy(elf_image)
        unsafe { drop(Box::from_raw(elf_image)) };
        if dep_info.map_size > 0 {
            unsafe { libc::munmap(map_start, dep_info.map_size) };
        }
        return false;
    }

    lib.linker.main_map_size = dep_info.map_size;

    if !linker_link(&mut lib.linker) {
        dloge!("Linker failed to link {}", lib_path);
        linker_destroy(&mut lib.linker);
        return false;
    }

    lib.img = elf_image;
    // strdup(lib_path); NULL only on allocation failure — CString::new also
    // rejects interior NUL bytes, which the C loader cannot represent anyway.
    match CString::new(lib_path) {
        Ok(path) => lib.lib_path = path.into_raw(),
        Err(_) => {
            dloge!("Failed to duplicate library path string");
            linker_destroy(&mut lib.linker);
            return false;
        }
    }

    true
}

/// `csoloader_unload`: unload the library and free all related resources.
pub fn csoloader_unload(lib: &mut CsoLib) -> bool {
    linker_destroy(&mut lib.linker);

    // free(lib->lib_path) — free(NULL) is a no-op in C; the Rust
    // CString::from_raw is UB on NULL, so guard it equivalently.
    if !lib.lib_path.is_null() {
        unsafe { drop(CString::from_raw(lib.lib_path)) };
    }

    // memset(lib, 0, sizeof(struct csoloader)) — use Default instead of
    // mem::zeroed for sound Rust access.
    *lib = CsoLib::default();

    true
}

/// `csoloader_abandon`: free resources related to the library without
/// unloading it.
pub fn csoloader_abandon(lib: &mut CsoLib) -> bool {
    linker_abandon(&mut lib.linker);

    // free(lib->lib_path) — see csoloader_unload.
    if !lib.lib_path.is_null() {
        unsafe { drop(CString::from_raw(lib.lib_path)) };
    }

    // memset(lib, 0, sizeof(struct csoloader)) — use Default instead of
    // mem::zeroed for sound Rust access.
    *lib = CsoLib::default();

    true
}

/// `csoloader_get_symbol`: address of a symbol in the loaded library.
///
/// # Safety
/// `lib.img` must be the valid pointer produced by a successful
/// `csoloader_load` (and not yet unloaded/abandoned).
pub unsafe fn csoloader_get_symbol(lib: &CsoLib, symbol_name: &str) -> *mut c_void {
    unsafe { (*lib.img).symb_address(symbol_name) as *mut c_void }
}

/// `csoloader_deinit`: deinitialize all internal global resources.
pub fn csoloader_deinit() {
    linker_deinit();
}
