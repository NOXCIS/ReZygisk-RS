//! `repr(C)` mirrors of the ReZygisk module ABI (loader/src/injector/module.h,
//! REZYGISK_API_VERSION 5) and the v5 specialize args (loader/src/include).
//! Field order IS the contract — do not reorder or drop fields.

use std::os::raw::{c_long, c_void};

pub const REZYGISK_API_VERSION: c_long = 5;

/// `enum rezygiskd_flags` bits the module may need (subset; see module.h).
#[allow(dead_code)]
pub const PROCESS_GRANTED_ROOT: u32 = 1 << 0;
#[allow(dead_code)]
pub const PROCESS_ON_DENYLIST: u32 = 1 << 1;

/// `enum rezygisk_options` (module.h) — only the value truman needs.
pub const DLCLOSE_MODULE_LIBRARY: u32 = 1;

#[repr(C)]
pub struct ReZygiskAbi {
    pub api_version: c_long,
    pub impl_: *mut c_void,
    pub pre_app_specialize: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    pub post_app_specialize: Option<unsafe extern "C" fn(*mut c_void, *const c_void)>,
    pub pre_server_specialize: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>,
    pub post_server_specialize: Option<unsafe extern "C" fn(*mut c_void, *const c_void)>,
}

#[repr(C)]
pub struct ReZygiskApi {
    pub impl_: *mut c_void,
    pub register_module:
        Option<unsafe extern "C" fn(*mut ReZygiskApi, *const ReZygiskAbi) -> bool>,
    pub hook_jni_native_methods: *mut c_void,
    pub plt_hook_register: *mut c_void,
    pub plt_hook_exclude: *mut c_void,
    pub plt_hook_commit: *mut c_void,
    pub connect_companion: Option<unsafe extern "C" fn(*mut c_void) -> i32>,
    pub set_option: Option<unsafe extern "C" fn(*mut c_void, u32)>,
    pub get_module_dir: *mut c_void,
    pub get_flags: *mut c_void,
}

/// `struct app_specialize_args_v5` — every member is a POINTER to the value
/// (the loader hands us pointers into the zygote's own argument block).
#[repr(C)]
pub struct AppSpecializeArgsV5 {
    pub uid: *mut i32,
    pub gid: *mut i32,
    pub gids: *mut c_void,
    pub runtime_flags: *mut i32,
    pub rlimits: *mut c_void,
    pub mount_external: *mut i32,
    pub se_info: *mut c_void,
    pub nice_name: *mut *mut c_void,
    pub instruction_set: *mut c_void,
    pub app_data_dir: *mut c_void,
    pub fds_to_ignore: *mut c_void,
    pub is_child_zygote: *mut c_void,
    pub is_top_app: *mut c_void,
    pub pkg_data_info_list: *mut c_void,
    pub whitelisted_data_info_list: *mut c_void,
    pub mount_data_dirs: *mut c_void,
    pub mount_storage_dirs: *mut c_void,
    pub mount_sysprop_overrides: *mut c_void,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn abi_layout_is_pointer_sized() {
        // All members are machine-word sized on both LP64 and armeabi-v7a.
        assert_eq!(size_of::<ReZygiskAbi>(), 6 * size_of::<usize>());
        assert_eq!(size_of::<ReZygiskApi>(), 10 * size_of::<usize>());
        assert_eq!(
            size_of::<AppSpecializeArgsV5>(),
            18 * size_of::<usize>()
        );
    }
}
