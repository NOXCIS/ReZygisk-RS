//! hook.c fd sanitization: `mark_fds_allowed` (861-874) + `rz_sanitize_fds`
//! (875-928).
//!
//! The C calls `rz_sanitize_fds` from `rz_nativeSpecializeAppProcess_pre`
//! (after `rz_run_modules_pre`) and from `rz_app_specialize_pre` (after
//! `rz_app_specialize_pre`-side work), both in the zygote child. In the
//! `APP_FORK_AND_SPECIALIZE` case the module-exempted fds are first merged
//! into the zygote's own `fds_to_ignore` jintArray and `SKIP_FD_SANITIZATION`
//! is set (the zygote's native fd sanitization then honors that array), so the
//! `/proc/self/fd` scan only runs when the zygote itself will not sanitize.
//!
//! C-parity notes:
//! - JNI calls go through `JNIEnv::from_raw(ctx.env)` + the jni crate
//!   wrappers. `GetIntArrayElements`/`ReleaseIntArrayElements(JNI_ABORT)`
//!   become `get_array_elements(_, ReleaseMode::NoCopyBack)` + drop (drop
//!   issues `ReleaseIntArrayElements(env, array, ptr, JNI_ABORT)`); the C
//!   passes `is_copy = NULL` while the jni crate fills a local out-param —
//!   the value is discarded either way, no observable difference.
//! - The C derefs `ctx->env` without a NULL check (it is always the
//!   specialize JNIEnv). `JNIEnv::from_raw` fails only on a NULL pointer;
//!   in that unreachable case the port skips the merge instead of crashing.
//! - `GetIntArrayElements` returning NULL (OOM) crashes the C walk; the port
//!   bails out of the same block instead. JNI errors from
//!   `SetIntArrayRegion`/`DeleteLocalRef` are ignored with `let _` exactly
//!   like the C, which never checks.
//! - `NewIntArray` returning NULL maps to the jni crate's `Err` and skips the
//!   `if (newArray) { ... }` body, falling through to the pid check like the
//!   C.
//! - `parse_int` is `misc_port::parse_int(&str)` (common/misc.c 20-33, the
//!   documented home for this call site). The C stops at the NUL terminator;
//!   the Rust port rejects an interior-NUL/non-UTF-8 `d_name` as "" -> 0.
//!   Kernel dirent names never contain NUL or non-ASCII bytes, so behavior
//!   is identical here (noted in misc_port.rs).
//! - `PLOGE`/`LOGW` use the `rz_common` `plog!`/`logw!` macros (the port-wide
//!   convention; `plog!` appends errno as a second line where the C prints
//!   `": %s"` on one line).
//! - `DO_REVERT_UNMOUNT` does not appear in this C slice; it lives in
//!   `module_api::api_set_option`.
//!
//! Audit note (F5, verified — no code change needed): an earlier hypothesis
//! that `allowed_fds` arrives all-zero on the system_server path (closing
//! every zygote fd right after the fork) does NOT hold.
//! `fork_prepost::rz_fork_pre` (hook.c `rz_fork_pre` 824-860 parity) forks
//! before any third-party code runs and seeds `ctx.allowed_fds` from
//! `/proc/self/fd` inside the child (`fork_prepost.rs` 71-103, its own
//! dirfd excluded), so only fds opened AFTER that snapshot — i.e. module
//! loads and module work between the fork and `rz_sanitize_fds` — get
//! closed. This matches `hook.c` 861-928 byte-for-byte in effect. Keep this
//! as the FIRST suspect if system_server ever dies instantly post-fork with
//! "Cannot read /proc/self/fd"-style failures: any code path that forked
//! without passing through `rz_fork_pre` would sanitize against an
//! unseeded (all-zero) allowlist.

use std::ffi::CStr;

use jni::objects::{JIntArray, ReleaseMode};
use jni::JNIEnv;

use crate::context::{
    flag_get, flag_set, ZygiskContext, APP_FORK_AND_SPECIALIZE, MAX_FD_SIZE, SKIP_FD_SANITIZATION,
};
use rz_common::{logw, plog};

/// Module-local log tag (C `LOG_TAG` in logging.h; the loader port uses
/// `"zygisk"`).
const TAG: &str = rz_common::LOG_TAG;

/// hook.c `mark_fds_allowed` (861-874): mark every fd in `fds_array` as
/// allowed so the later sanitization keeps it open.
pub fn mark_fds_allowed(
    ctx: &mut ZygiskContext,
    env: *mut jni::sys::JNIEnv,
    fds_array: jni::sys::jarray,
) {
    if fds_array.is_null() {
        return;
    }

    let mut env = match unsafe { JNIEnv::from_raw(env) } {
        Ok(env) => env,
        Err(_) => return,
    };
    let fds_array = unsafe { JIntArray::from_raw(fds_array) };

    // C: jint *arr = GetIntArrayElements(env, fdsArray, NULL);
    let elems = match unsafe { env.get_array_elements(&fds_array, ReleaseMode::NoCopyBack) } {
        Ok(elems) => elems,
        Err(_) => return,
    };
    // C: jint len = GetArrayLength(env, fdsArray);
    let len = match env.get_array_length(&fds_array) {
        Ok(len) => len,
        Err(_) => return,
    };

    for &fd in elems.iter().take(len as usize) {
        if fd >= 0 && (fd as usize) < MAX_FD_SIZE {
            ctx.allowed_fds[fd as usize] = 1;
        }
    }

    // C: ReleaseIntArrayElements(env, fdsArray, arr, JNI_ABORT);
    // NoCopyBack makes the drop release with JNI_ABORT.
    drop(elems);
}

/// hook.c `rz_sanitize_fds` (875-928): close every fd the zygote child should
/// not keep, honoring the app's `fds_to_ignore` and the module-exempted fds.
pub fn sanitize_fds(ctx: &mut ZygiskContext) {
    if flag_get(ctx, SKIP_FD_SANITIZATION) {
        return;
    }

    if flag_get(ctx, APP_FORK_AND_SPECIALIZE) {
        // C: jintArray fdsToIgnore = ctx->args.app->fds_to_ignore
        //         ? *ctx->args.app->fds_to_ignore : NULL;
        let fds_to_ignore: jni::sys::jarray = unsafe {
            if (*ctx.args.app).fds_to_ignore.is_null() {
                std::ptr::null_mut()
            } else {
                *(*ctx.args.app).fds_to_ignore
            }
        };
        mark_fds_allowed(ctx, ctx.env, fds_to_ignore);

        if ctx.exempted_fds_count > 0 {
            // C: jint len = fdsToIgnore ? GetArrayLength(env, fdsToIgnore) : 0;
            //    jintArray newArray = NewIntArray(env, len + exempted_fds_count);
            //    if (newArray) { ... }   (falls through on NULL)
            if let Ok(mut env) = unsafe { JNIEnv::from_raw(ctx.env) } {
                let fds_array = unsafe { JIntArray::from_raw(fds_to_ignore) };
                let len: jni::sys::jint = if !fds_to_ignore.is_null() {
                    env.get_array_length(&fds_array).unwrap_or(0)
                } else {
                    0
                };

                if let Ok(new_array) = env
                    .new_int_array((len as usize + ctx.exempted_fds_count) as jni::sys::jsize)
                {
                    if !fds_to_ignore.is_null() && len > 0 {
                        // C: GetIntArrayElements + SetIntArrayRegion(newArray,
                        //    0, len, arr) + ReleaseIntArrayElements(..., JNI_ABORT)
                        //    + DeleteLocalRef(fdsToIgnore). The elems guard is
                        //    released (JNI_ABORT) at the end of this block,
                        //    before the DeleteLocalRef below.
                        if let Ok(elems) =
                            unsafe { env.get_array_elements(&fds_array, ReleaseMode::NoCopyBack) }
                        {
                            let _ = env.set_int_array_region(&new_array, 0, &elems);
                        }
                        let _ = env.delete_local_ref(fds_array);
                    }

                    // C: SetIntArrayRegion(newArray, len, exempted_fds_count,
                    //    exempted_fds);
                    let _ = env.set_int_array_region(
                        &new_array,
                        len,
                        &ctx.exempted_fds[..ctx.exempted_fds_count],
                    );
                    for i in 0..ctx.exempted_fds_count {
                        let fd = ctx.exempted_fds[i];
                        if fd >= 0 && (fd as usize) < MAX_FD_SIZE {
                            ctx.allowed_fds[fd as usize] = 1;
                        }
                    }

                    // C: *ctx->args.app->fds_to_ignore = newArray;
                    //    FLAG_SET(ctx, SKIP_FD_SANITIZATION);
                    unsafe { *(*ctx.args.app).fds_to_ignore = new_array.as_raw() };
                    flag_set(ctx, SKIP_FD_SANITIZATION);
                }
            }
        }
    }

    if ctx.pid != 0 {
        return;
    }

    // INFO: Close all forbidden fds to prevent crashing
    let dir = unsafe { libc::opendir(b"/proc/self/fd\0".as_ptr() as *const libc::c_char) };
    if dir.is_null() {
        plog!(TAG, "Failed to open /proc/self/fd");

        return;
    }

    let dfd = unsafe { libc::dirfd(dir) };
    loop {
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }

        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let fd = crate::misc_port::parse_int(name.to_str().unwrap_or_default());
        if fd < 0 || fd as usize >= MAX_FD_SIZE || fd == dfd || ctx.allowed_fds[fd as usize] != 0 {
            continue;
        }

        unsafe { libc::close(fd) };

        logw!(TAG, "Closed leaked fd: {}", fd);
    }

    unsafe { libc::closedir(dir) };
}
