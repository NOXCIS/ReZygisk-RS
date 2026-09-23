//! hook.c app specialize hooks: `rz_app_specialize_pre` / `_post`
//! (hook.c).
//!
//! C-parity notes:
//! - The isolated-service UID fixup uses `JniStringGuard` for safe JNI string
//!   access (the C uses raw `GetStringUTFChars` / `ReleaseStringUTFChars`).
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

use rz_common::{is_isolated_service, logd, loge, plog};
use rz_ipc::{MountNamespaceState, ProcessFlags};

use crate::context::{
    flag_get, flag_set, set_ctx, APP_SPECIALIZE, DO_REVERT_UNMOUNT, ZygiskContext,
};
use crate::jni_utils::JniStringGuard;

const TAG: &str = rz_common::LOG_TAG;

/// hook.c `rz_app_specialize_pre`.
pub unsafe fn app_specialize_pre(ctx: &mut ZygiskContext) {
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
    // SAFETY: ctx.args is a union; caller guarantees it was initialized as .app
    // by the JNI wrapper (jni_tables.rs) for app-specialize paths.
    let app = unsafe { ctx.args.app };
    let mut uid = unsafe { *(*app).uid } as u32;
    let app_data_dir = unsafe { (*app).app_data_dir };
    if is_isolated_service(uid) && !app_data_dir.is_null() {
        // INFO: If the app is an isolated service, we use the UID of the
        //         app's process data directory, which is the UID of the
        //         app itself, which root implementations actually use.
        let jstr = unsafe { *app_data_dir };
        let Some(data_dir_guard) = JniStringGuard::new(ctx.env, jstr) else {
            loge!(TAG, "Failed to get app data directory");
            return;
        };

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::stat(data_dir_guard.as_ptr(), &mut st) } == -1 {
            plog!(
                TAG,
                "Failed to stat app data directory [{}]",
                data_dir_guard.as_cstr().to_string_lossy()
            );
            return;
        }

        uid = st.st_uid as u32;
        logd!(
            TAG,
            "Isolated service being related to UID {}, app data dir: {}",
            uid,
            data_dir_guard.as_cstr().to_string_lossy()
        );
        // data_dir_guard auto-releases on drop
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
    // SAFETY: ctx is valid; modules have been loaded by load_modules_only().
    unsafe { crate::load_modules::run_modules_pre(ctx) };

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

/// hook.c `rz_app_specialize_post`.
pub unsafe fn app_specialize_post(ctx: &mut ZygiskContext) {
    // SAFETY: ctx is valid; called after specialize with module context intact.
    unsafe { crate::load_modules::run_modules_post(ctx) };

    // INFO: Allow the process name string to be released.
    // The C does GetStringUTFChars + ReleaseStringUTFChars; we use JniStringGuard
    // which auto-releases on drop.
    let nice_name = unsafe { (*ctx.args.app).nice_name };
    let jstr = unsafe { *nice_name };
    // Create and immediately drop the guard to trigger release
    let _release_guard = JniStringGuard::new(ctx.env, jstr);

    set_ctx(std::ptr::null_mut());
}
