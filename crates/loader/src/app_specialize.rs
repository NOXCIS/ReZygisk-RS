//! hook.c app specialize hooks: `rz_app_specialize_pre` / `_post`
//! (hook.c lines 1041-1160).
//!
//! C-parity notes:
//! - The isolated-service UID fixup uses the raw `JNIEnv` function table
//!   (`GetStringUTFChars` / `ReleaseStringUTFChars`) exactly like the C.
//!   `cpp_strings` is not involved in this slice: the C only reads the
//!   `app_data_dir` jstring here (the pkg_data_info std::string walking
//!   belongs to the fd_sanitize slice).
//! - The C in this range does NOT touch `mount_external`,
//!   `mount_data_dirs` / `mount_storage_dirs`, `fds_to_ignore` or any
//!   truman builtin logic — those are handled by other hook.c slices — so
//!   none of that is ported here.
//! - The `zygisk_context.process` field is a `String` in the RS spine (the C
//!   keeps the raw `GetStringUTFChars` pointer). `rz_app_specialize_post`
//!   therefore re-obtains the pointer with `GetStringUTFChars` before
//!   `ReleaseStringUTFChars`; ART returns the same buffer for a live string,
//!   so the release balances the pre-phase get.
//! - Sibling contracts assumed (implemented by the respective PORT TASKs):
//!   `misc_port::update_mnt_ns(state: rz_ipc::MountNamespaceState, dry_run:
//!   bool) -> bool`, `load_modules::{rz_run_modules_pre, rz_run_modules_post}
//!   (ctx: &mut ZygiskContext)`, `daemon_client::rezygiskd_get_process_flags
//!   (uid: u32, process: &str) -> u32`.

use std::ffi::CStr;

use rz_common::{is_isolated_service, logd, loge, plog};
use rz_ipc::{MountNamespaceState, ProcessFlags};

use crate::context::{
    flag_get, flag_set, set_ctx, APP_SPECIALIZE, DO_REVERT_UNMOUNT, ZygiskContext,
};

const TAG: &str = rz_common::LOG_TAG;

/// `(*env)->GetStringUTFChars(env, s, NULL)`. A missing table entry returns
/// NULL — every caller null-checks — instead of aborting the zygote.
unsafe fn get_string_utf_chars(env: *mut jni::sys::JNIEnv, s: jni::sys::jstring) -> *const libc::c_char {
    match unsafe { (**env).GetStringUTFChars } {
        Some(get) => unsafe { get(env, s, std::ptr::null_mut()) },
        None => {
            loge!(TAG, "JNIEnv::GetStringUTFChars is unavailable");
            std::ptr::null()
        }
    }
}

/// `(*env)->ReleaseStringUTFChars(env, s, chars)`. A missing table entry
/// leaks the chars buffer (harmless in a short-lived app process) instead of
/// aborting the zygote.
unsafe fn release_string_utf_chars(
    env: *mut jni::sys::JNIEnv,
    s: jni::sys::jstring,
    chars: *const libc::c_char,
) {
    match unsafe { (**env).ReleaseStringUTFChars } {
        Some(release) => unsafe { release(env, s, chars) },
        None => loge!(TAG, "JNIEnv::ReleaseStringUTFChars is unavailable"),
    }
}

/// hook.c `rz_app_specialize_pre` (1041-1151).
pub unsafe fn rz_app_specialize_pre(ctx: &mut ZygiskContext) {
    flag_set(ctx, APP_SPECIALIZE);

    // INFO: Isolated services have different UIDs than the main apps. Because
    //         numerous root implementations base themselves in the UID of the
    //         app, we need to ensure that the UID sent to ReZygiskd to search
    //         is the app's and not the isolated service, or else it will be
    //         able to bypass DenyList.
    //
    //      All apps, and isolated processes, of *third-party* applications will
    //        have their app_data_dir set. The system applications might not have
    //        one, however it is unlikely they will create an isolated process,
    //        and even if so, it should not impact in detections, performance or
    //        any area.
    let app = ctx.args.app;
    let mut uid = unsafe { *(*app).uid } as u32;
    let app_data_dir = unsafe { (*app).app_data_dir };
    if is_isolated_service(uid) && !app_data_dir.is_null() {
        // INFO: If the app is an isolated service, we use the UID of the
        //         app's process data directory, which is the UID of the
        //         app itself, which root implementations actually use.
        let jstr = unsafe { *app_data_dir };
        let data_dir = unsafe { get_string_utf_chars(ctx.env, jstr) };
        if data_dir.is_null() {
            loge!(TAG, "Failed to get app data directory");

            return;
        }

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::stat(data_dir, &mut st) } == -1 {
            plog!(
                TAG,
                "Failed to stat app data directory [{}]",
                CStr::from_ptr(data_dir).to_string_lossy()
            );

            unsafe { release_string_utf_chars(ctx.env, jstr, data_dir) };

            return;
        }

        uid = st.st_uid as u32;
        logd!(
            TAG,
            "Isolated service being related to UID {}, app data dir: {}",
            uid,
            CStr::from_ptr(data_dir).to_string_lossy()
        );

        unsafe { release_string_utf_chars(ctx.env, jstr, data_dir) };
    }

    ctx.info_flags = crate::daemon_client::rezygiskd_get_process_flags(uid, &ctx.process);
    let flags = ProcessFlags::from_bits_truncate(ctx.info_flags);

    // INFO: To ensure we are really using a clean mount namespace, we use
    //         the first process it as reference for clean mount namespace,
    //         before it even does something, so that it will be clean yet
    //         with expected mounts.
    //
    //      To avoid duplication, we will bypass this update_mnt_ns if we
    //        are going to execute it later, as the app will be in the
    //        denylist.
    if flags.contains(ProcessFlags::IS_FIRST_STARTED)
        && !flags.contains(ProcessFlags::ON_DENYLIST)
        && !flags.contains(ProcessFlags::IS_MANAGER)
    {
        crate::misc_port::update_mnt_ns(MountNamespaceState::Clean, true);
    }

    if flags.contains(ProcessFlags::IS_MANAGER) {
        logd!(TAG, "Manager process detected. Notifying that Zygisk has been enabled.");

        // INFO: This environment variable is related to Magisk Zygisk/Manager. It
        //         it used by Magisk's Zygisk to communicate to Magisk Manager whether
        //         Zygisk is working or not, allowing Zygisk modules to both work properly
        //         and for the manager to mark Zygisk as enabled.
        //
        //       However, to enhance capabilities of root managers, it is also set for
        //         any other supported manager, so that, if they wish, they can recognize
        //         if Zygisk is enabled.
        unsafe {
            libc::setenv(
                b"ZYGISK_ENABLED\0".as_ptr() as *const libc::c_char,
                b"1\0".as_ptr() as *const libc::c_char,
                1,
            );
        }
    }

    // INFO: Modules only have two "start off" points from Zygisk, preSpecialize and
    //         postSpecialize. In preSpecialize, the process still has privileged
    //         permissions, and therefore can execute mount/umount/setns functions.
    //         If we update the mount namespace AFTER executing them, any mounts made
    //         will be lost, and the process will not have access to them anymore.
    //
    //       In postSpecialize, while still could have its mounts modified with the
    //         assistance of a Zygisk companion, it will already have the mount
    //         namespace switched by then, so there won't be issues.
    //
    //       Knowing this, we update the mns before execution, so that they can still
    //         make changes to mounts in DenyListed processes without being reverted.
    let in_denylist = flags.contains(ProcessFlags::ON_DENYLIST);
    if in_denylist {
        flag_set(ctx, DO_REVERT_UNMOUNT);
        crate::misc_port::update_mnt_ns(MountNamespaceState::Clean, false);
    }

    // INFO: Executed after setns to ensure a module can update the mounts of an
    //         application without worrying about it being overwritten by setns.
    crate::load_modules::rz_run_modules_pre(ctx);

    // INFO: The modules may request that although the process is NOT in
    //         the DenyList, it has its mount namespace switched to the clean
    //         one.
    //
    //         So to ensure this behavior happens, we must also check after the
    //         modules are loaded and executed, so that the modules can have
    //         the chance to request it.
    if !in_denylist && flag_get(ctx, DO_REVERT_UNMOUNT) {
        crate::misc_port::update_mnt_ns(MountNamespaceState::Clean, false);
    }
}

/// hook.c `rz_app_specialize_post` (1153-1160).
pub unsafe fn rz_app_specialize_post(ctx: &mut ZygiskContext) {
    crate::load_modules::rz_run_modules_post(ctx);

    // INFO: Allow the process name string to be released
    let nice_name = unsafe { (*ctx.args.app).nice_name };
    let jstr = unsafe { *nice_name };
    let process = unsafe { get_string_utf_chars(ctx.env, jstr) };
    if !process.is_null() {
        unsafe { release_string_utf_chars(ctx.env, jstr, process) };
    }

    set_ctx(std::ptr::null_mut());
}
