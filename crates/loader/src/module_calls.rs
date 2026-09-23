//! module.h dispatch helpers: `rz_module_call_on_load`,
//! `rz_module_call_pre/post_app_specialize` (api_version 1-5 dispatch with
//! the v1/v4 narrowing copies), `rz_module_call_pre/post_server_specialize`.
//!
//! Port of loader/src/injector/module.h lines 173-301. NOTE (from the C):
//! the original Zygisk API expects all modules to have all specialize
//! functions; not doing so causes a null pointer dereference in Magisk's
//! Zygisk — hence LOGW-and-skip instead of a call.
//!
//! Every function takes the module as a RAW POINTER, never `&mut`. A module
//! callback may re-enter the loader (`register_module`, `set_option`, ...)
//! and write the very slot being dispatched (see context.rs for the table
//! discipline); an `&mut ReZygiskModule` held across the opaque call is an
//! aliasing violation LLVM may exploit at opt-level="z" + lto=true.

use std::ffi::c_void;
use std::ptr;

use crate::abi::{
    AppSpecializeArgsV1, AppSpecializeArgsV4, AppSpecializeArgsV5, ReZygiskModule,
    ServerSpecializeArgsV1, REZYGISK_API_VERSION,
};

/// module.h `LOG_TAG` (zygisk-core32/64 in the C; the RS port uses "zygisk").
const TAG: &str = rz_common::LOG_TAG;

/// `m->lib.img->path()` for the LOGW messages. C dereferences `img`
/// unconditionally; Rust must null-check first. bionic's printf renders a
/// NULL `%s` as "(null)", which is the closest faithful fallback.
///
/// # Safety
/// `m` must point at a live table slot. The returned `&str` borrows from the
/// module's loaded image, which stays mapped for the process lifetime.
unsafe fn img_path(m: *const ReZygiskModule) -> &'static str {
    let img = unsafe { ptr::addr_of!((*m).lib.img).read() };
    if img.is_null() {
        "(null)"
    } else {
        // The only sound way to hand `path()` a reference derived from a raw
        // pointer while returning the borrowed str.
        let img: &'static rz_csoloader::image::CsoElf = unsafe { &*img };
        img.path()
    }
}

/// module.h `rz_module_call_on_load` (lines 173-175).
///
/// # Safety
/// `m` must point at a live table slot with a valid `zygisk_module_entry`.
pub unsafe fn module_on_load(m: *mut ReZygiskModule, env: *mut c_void) {
    // C calls the entry with no null check (a NULL entry crashes the zygote).
    let entry = unsafe { ptr::addr_of!((*m).zygisk_module_entry).read() };
    // hook.c: zygisk_module_entry(&m->api, env) — the module registers itself
    // through this exact pointer, so it must be the slot's own `api`.
    let api = unsafe { ptr::addr_of_mut!((*m).api) };
    unsafe {
        entry.unwrap_unchecked()(api.cast(), env);
    }
}

/// module.h `rz_module_call_pre_app_specialize` (lines 177-226).
///
/// # Safety
/// `m` must point at a live table slot; `args` at a valid v5 args struct.
pub unsafe fn module_pre_app_specialize(
    m: *mut ReZygiskModule,
    args: *mut AppSpecializeArgsV5,
) {
    let pre_app_specialize = unsafe { ptr::addr_of!((*m).abi.pre_app_specialize).read() };
    let Some(pre_app_specialize) = pre_app_specialize else {
        rz_common::logw!(
            TAG,
            "Module [{}] doesn't have pre_app_specialize. Skipping it.",
            unsafe { img_path(m) }
        );
        return;
    };

    let api_version = unsafe { ptr::addr_of!((*m).abi.api_version).read() };
    let impl_ = unsafe { ptr::addr_of!((*m).abi.impl_).read() };

    match api_version {
        1 | 2 => {
            let a = unsafe { &*args };
            // The C initializer copies the 15 v1 pointers by value.
            let mut versioned_args = AppSpecializeArgsV1 {
                uid: a.uid,
                gid: a.gid,
                gids: a.gids,
                runtime_flags: a.runtime_flags,
                mount_external: a.mount_external,
                se_info: a.se_info,
                nice_name: a.nice_name,
                instruction_set: a.instruction_set,
                app_data_dir: a.app_data_dir,
                is_child_zygote: a.is_child_zygote,
                is_top_app: a.is_top_app,
                pkg_data_info_list: a.pkg_data_info_list,
                whitelisted_data_info_list: a.whitelisted_data_info_list,
                mount_data_dirs: a.mount_data_dirs,
                mount_storage_dirs: a.mount_storage_dirs,
            };
            unsafe {
                pre_app_specialize(
                    impl_,
                    &mut versioned_args as *mut AppSpecializeArgsV1 as *mut c_void,
                );
            }
        }
        3 | 4 => {
            let a = unsafe { &*args };
            // v4 is a strict 17-field prefix of v5: memcpy(sizeof(v4)).
            let mut versioned_args = AppSpecializeArgsV4 {
                uid: a.uid,
                gid: a.gid,
                gids: a.gids,
                runtime_flags: a.runtime_flags,
                rlimits: a.rlimits,
                mount_external: a.mount_external,
                se_info: a.se_info,
                nice_name: a.nice_name,
                instruction_set: a.instruction_set,
                app_data_dir: a.app_data_dir,
                fds_to_ignore: a.fds_to_ignore,
                is_child_zygote: a.is_child_zygote,
                is_top_app: a.is_top_app,
                pkg_data_info_list: a.pkg_data_info_list,
                whitelisted_data_info_list: a.whitelisted_data_info_list,
                mount_data_dirs: a.mount_data_dirs,
                mount_storage_dirs: a.mount_storage_dirs,
            };
            unsafe {
                pre_app_specialize(
                    impl_,
                    &mut versioned_args as *mut AppSpecializeArgsV4 as *mut c_void,
                );
            }
        }
        REZYGISK_API_VERSION => unsafe {
            pre_app_specialize(impl_, args as *mut c_void);
        },
        // C has no default case: unknown versions are silently skipped.
        _ => {}
    }
}

/// module.h `rz_module_call_post_app_specialize` (lines 228-277).
///
/// # Safety
/// `m` must point at a live table slot; `args` at a valid v5 args struct.
pub unsafe fn module_post_app_specialize(
    m: *mut ReZygiskModule,
    args: *const AppSpecializeArgsV5,
) {
    let post_app_specialize = unsafe { ptr::addr_of!((*m).abi.post_app_specialize).read() };
    let Some(post_app_specialize) = post_app_specialize else {
        rz_common::logw!(
            TAG,
            "Module [{}] doesn't have post_app_specialize. Skipping it.",
            unsafe { img_path(m) }
        );
        return;
    };

    let api_version = unsafe { ptr::addr_of!((*m).abi.api_version).read() };
    let impl_ = unsafe { ptr::addr_of!((*m).abi.impl_).read() };

    match api_version {
        1 | 2 => {
            let a = unsafe { &*args };
            // The C initializer copies the 15 v1 pointers by value.
            let versioned_args = AppSpecializeArgsV1 {
                uid: a.uid,
                gid: a.gid,
                gids: a.gids,
                runtime_flags: a.runtime_flags,
                mount_external: a.mount_external,
                se_info: a.se_info,
                nice_name: a.nice_name,
                instruction_set: a.instruction_set,
                app_data_dir: a.app_data_dir,
                is_child_zygote: a.is_child_zygote,
                is_top_app: a.is_top_app,
                pkg_data_info_list: a.pkg_data_info_list,
                whitelisted_data_info_list: a.whitelisted_data_info_list,
                mount_data_dirs: a.mount_data_dirs,
                mount_storage_dirs: a.mount_storage_dirs,
            };
            unsafe {
                post_app_specialize(
                    impl_,
                    &versioned_args as *const AppSpecializeArgsV1 as *const c_void,
                );
            }
        }
        3 | 4 => {
            let a = unsafe { &*args };
            // v4 is a strict 17-field prefix of v5: memcpy(sizeof(v4)).
            let versioned_args = AppSpecializeArgsV4 {
                uid: a.uid,
                gid: a.gid,
                gids: a.gids,
                runtime_flags: a.runtime_flags,
                rlimits: a.rlimits,
                mount_external: a.mount_external,
                se_info: a.se_info,
                nice_name: a.nice_name,
                instruction_set: a.instruction_set,
                app_data_dir: a.app_data_dir,
                fds_to_ignore: a.fds_to_ignore,
                is_child_zygote: a.is_child_zygote,
                is_top_app: a.is_top_app,
                pkg_data_info_list: a.pkg_data_info_list,
                whitelisted_data_info_list: a.whitelisted_data_info_list,
                mount_data_dirs: a.mount_data_dirs,
                mount_storage_dirs: a.mount_storage_dirs,
            };
            unsafe {
                post_app_specialize(
                    impl_,
                    &versioned_args as *const AppSpecializeArgsV4 as *const c_void,
                );
            }
        }
        REZYGISK_API_VERSION => unsafe {
            post_app_specialize(impl_, args as *const c_void);
        },
        // C has no default case: unknown versions are silently skipped.
        _ => {}
    }
}

/// module.h `rz_module_call_pre_server_specialize` (lines 279-289).
///
/// # Safety
/// `m` must point at a live table slot; `args` at a valid args struct.
pub unsafe fn module_pre_server_specialize(
    m: *mut ReZygiskModule,
    args: *mut ServerSpecializeArgsV1,
) {
    let pre_server_specialize = unsafe { ptr::addr_of!((*m).abi.pre_server_specialize).read() };
    let Some(pre_server_specialize) = pre_server_specialize else {
        rz_common::logw!(
            TAG,
            "Module [{}] doesn't have pre_server_specialize. Skipping it.",
            unsafe { img_path(m) }
        );
        return;
    };

    let impl_ = unsafe { ptr::addr_of!((*m).abi.impl_).read() };

    unsafe {
        pre_server_specialize(impl_, args as *mut c_void);
    }
}

/// module.h `rz_module_call_post_server_specialize` (lines 291-301).
///
/// # Safety
/// `m` must point at a live table slot; `args` at a valid args struct.
pub unsafe fn module_post_server_specialize(
    m: *mut ReZygiskModule,
    args: *const ServerSpecializeArgsV1,
) {
    let post_server_specialize = unsafe { ptr::addr_of!((*m).abi.post_server_specialize).read() };
    let Some(post_server_specialize) = post_server_specialize else {
        rz_common::logw!(
            TAG,
            "Module [{}] doesn't have post_server_specialize. Skipping it.",
            unsafe { img_path(m) }
        );
        return;
    };

    let impl_ = unsafe { ptr::addr_of!((*m).abi.impl_).read() };

    unsafe {
        post_server_specialize(impl_, args as *const c_void);
    }
}
