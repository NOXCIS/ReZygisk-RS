//! `repr(C)` mirrors of the ReZygisk module ABI — loader/src/injector/module.h
//! (REZYGISK_API_VERSION 5). Field order IS the contract: C modules compiled
//! against module.h read and write these structs through raw pointers.
//!
//! Shared spine: the port slices in this crate MUST use these types and not
//! redefine them. `module_calls.rs` holds the `rz_module_call_*` dispatch
//! helpers (the `static inline` bodies at the bottom of module.h).

use std::ffi::c_char;
use std::os::raw::{c_int, c_long, c_void};

use jni::sys::{jarray, jboolean, jint, jlong, jobjectArray, jstring};

/// jni.h `JNINativeMethod` (mirrored: the jni crate does not re-export it).
/// Field order is the JNI contract.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct JNINativeMethod {
    pub name: *mut c_char,
    pub signature: *mut c_char,
    pub fn_ptr: *mut c_void,
}

// SAFETY: JNINativeMethod contains pointers to static strings and function
// pointers that remain valid for the program's lifetime. The struct is only
// accessed while locks are held.
unsafe impl Send for JNINativeMethod {}
unsafe impl Sync for JNINativeMethod {}

/// module.h `REZYGISK_API_VERSION`.
pub const REZYGISK_API_VERSION: c_long = 5;

/// hook.c RZID_MAGIC: every api function receives the module id encoded as
/// `(size_t)impl + RZID_MAGIC` so a stray NULL/0 impl is distinguishable from
/// module 0 (the C logs a warning on out-of-range ids).
pub const RZID_MAGIC: usize = b'R' as usize + b'Z' as usize + b'I' as usize + b'D' as usize;

#[inline]
pub fn encode_id(id: usize) -> *mut c_void {
    (id + RZID_MAGIC) as *mut c_void
}

#[inline]
pub fn decode_id(ptr: *mut c_void) -> usize {
    (ptr as usize).wrapping_sub(RZID_MAGIC)
}

/// `enum rezygisk_options` (module.h).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ReZygiskOptions {
    ForceDenylistUnmount = 0,
    DlcloseModuleLibrary = 1,
}

/// `struct app_specialize_args_v1` — every member is a POINTER to the value
/// in the zygote's own argument block.
#[repr(C)]
pub struct AppSpecializeArgsV1 {
    pub uid: *mut jint,
    pub gid: *mut jint,
    pub gids: *mut jarray,
    pub runtime_flags: *mut jint,
    pub mount_external: *mut jint,
    pub se_info: *mut jstring,
    pub nice_name: *mut jstring,
    pub instruction_set: *mut jstring,
    pub app_data_dir: *mut jstring,
    pub is_child_zygote: *mut jboolean,
    pub is_top_app: *mut jboolean,
    pub pkg_data_info_list: *mut jobjectArray,
    pub whitelisted_data_info_list: *mut jobjectArray,
    pub mount_data_dirs: *mut jboolean,
    pub mount_storage_dirs: *mut jboolean,
}

/// `struct app_specialize_args_v4`.
#[repr(C)]
pub struct AppSpecializeArgsV4 {
    pub uid: *mut jint,
    pub gid: *mut jint,
    pub gids: *mut jarray,
    pub runtime_flags: *mut jint,
    pub rlimits: *mut jobjectArray,
    pub mount_external: *mut jint,
    pub se_info: *mut jstring,
    pub nice_name: *mut jstring,
    pub instruction_set: *mut jstring,
    pub app_data_dir: *mut jstring,
    pub fds_to_ignore: *mut jarray,
    pub is_child_zygote: *mut jboolean,
    pub is_top_app: *mut jboolean,
    pub pkg_data_info_list: *mut jobjectArray,
    pub whitelisted_data_info_list: *mut jobjectArray,
    pub mount_data_dirs: *mut jboolean,
    pub mount_storage_dirs: *mut jboolean,
}

/// `struct app_specialize_args_v5`.
#[repr(C)]
pub struct AppSpecializeArgsV5 {
    pub uid: *mut jint,
    pub gid: *mut jint,
    pub gids: *mut jarray,
    pub runtime_flags: *mut jint,
    pub rlimits: *mut jobjectArray,
    pub mount_external: *mut jint,
    pub se_info: *mut jstring,
    pub nice_name: *mut jstring,
    pub instruction_set: *mut jstring,
    pub app_data_dir: *mut jstring,
    pub fds_to_ignore: *mut jarray,
    pub is_child_zygote: *mut jboolean,
    pub is_top_app: *mut jboolean,
    pub pkg_data_info_list: *mut jobjectArray,
    pub whitelisted_data_info_list: *mut jobjectArray,
    pub mount_data_dirs: *mut jboolean,
    pub mount_storage_dirs: *mut jboolean,
    pub mount_sysprop_overrides: *mut jboolean,
}

/// `struct server_specialize_args_v1`.
#[repr(C)]
pub struct ServerSpecializeArgsV1 {
    pub uid: *mut jint,
    pub gid: *mut jint,
    pub gids: *mut jarray,
    pub runtime_flags: *mut jint,
    pub permitted_capabilities: *mut jlong,
    pub effective_capabilities: *mut jlong,
}

/// `struct rezygisk_abi`.
#[repr(C)]
#[derive(Default)]
pub struct ReZygiskAbi {
    pub api_version: c_long,
    pub impl_: *mut c_void,
    pub pre_app_specialize: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    pub post_app_specialize: Option<unsafe extern "C" fn(*mut c_void, *const c_void)>,
    pub pre_server_specialize: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    pub post_server_specialize: Option<unsafe extern "C" fn(*mut c_void, *const c_void)>,
}

// SAFETY: ReZygiskAbi contains function pointers and a generic impl pointer
// that remain valid for the module's lifetime. Access is mutex-protected.
unsafe impl Send for ReZygiskAbi {}
unsafe impl Sync for ReZygiskAbi {}

/// v3-and-below `plt_hook_register(const char *regex, const char *symbol,
/// void *fn, void **backup)`.
pub type PltRegisterV3Fn =
    unsafe extern "C" fn(*const c_char, *const c_char, *mut c_void, *mut *mut c_void);

/// v4 `plt_hook_register(dev_t dev, ino_t inode, const char *symbol, ...)`.
/// bionic `dev_t` is 32-bit on LP32 (sys/types.h: "historical accident …
/// 32-bit dev_t on 32-bit architectures") and 64-bit on LP64; `ino_t` is
/// 32-bit on LP32 and 64-bit on LP64. A module calling through this slot on
/// armv7 passes a 32-bit `dev_t`, so the LP32 signature must take `u32`.
#[cfg(target_pointer_width = "64")]
pub type PltRegisterV4Fn = unsafe extern "C" fn(u64, u64, *const c_char, *mut c_void, *mut *mut c_void);
#[cfg(target_pointer_width = "32")]
pub type PltRegisterV4Fn = unsafe extern "C" fn(u32, u32, *const c_char, *mut c_void, *mut *mut c_void);

/// module.h union: `plt_hook_register` (v3 and below) / `plt_hook_register_v4`
/// (v4) share one ABI slot.
#[repr(C)]
#[derive(Copy, Clone)]
pub union PltRegisterSlot {
    pub v3: Option<PltRegisterV3Fn>,
    pub v4: Option<PltRegisterV4Fn>,
}

impl Default for PltRegisterSlot {
    fn default() -> Self {
        Self { v3: None }
    }
}

/// module.h union: `plt_hook_exclude` (v3 and below) / `exempt_fd` (v4).
#[repr(C)]
#[derive(Copy, Clone)]
pub union PltExcludeSlot {
    pub plt_hook_exclude: Option<unsafe extern "C" fn(*const c_char, *const c_char)>,
    pub exempt_fd: Option<unsafe extern "C" fn(c_int)>,
}

impl Default for PltExcludeSlot {
    fn default() -> Self {
        Self { plt_hook_exclude: None }
    }
}

/// `struct rezygisk_api`.
#[repr(C)]
#[derive(Default)]
pub struct ReZygiskApi {
    pub impl_: *mut c_void,
    pub register_module: Option<unsafe extern "C" fn(*mut ReZygiskApi, *const ReZygiskAbi) -> bool>,
    pub hook_jni_native_methods: Option<
        unsafe extern "C" fn(
            *mut jni::sys::JNIEnv,
            *const c_char,
            *mut JNINativeMethod,
            c_int,
        ),
    >,
    pub plt_hook_register: PltRegisterSlot,
    pub plt_hook_exclude: PltExcludeSlot,
    pub plt_hook_commit: Option<unsafe extern "C" fn() -> bool>,
    pub connect_companion: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    pub set_option: Option<unsafe extern "C" fn(*mut c_void, c_int)>,
    pub get_module_dir: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    pub get_flags: Option<unsafe extern "C" fn() -> u32>,
}

// SAFETY: ReZygiskApi contains function pointers that remain valid for the
// module's lifetime. Access is mutex-protected.
unsafe impl Send for ReZygiskApi {}
unsafe impl Sync for ReZygiskApi {}

/// module.h `struct csoloader` — `{ char *lib_path; struct csoloader_elf *img;
/// struct linker linker; }`. Defined in rz-csoloader (same crate as `Linker`);
/// re-exported here so `ReZygiskModule` keeps the C field name.
pub use rz_csoloader::runtime::CsoLib;

/// `struct rezygisk_module`.
#[repr(C)]
#[derive(Default)]
pub struct ReZygiskModule {
    pub abi: ReZygiskAbi,
    pub api: ReZygiskApi,
    pub lib: CsoLib,
    pub zygisk_module_entry: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    pub unload: bool,
}

// SAFETY: ReZygiskModule is only accessed while the module list mutex is held.
// All contained types have Send+Sync implemented with the same safety invariant.
unsafe impl Send for ReZygiskModule {}
unsafe impl Sync for ReZygiskModule {}
