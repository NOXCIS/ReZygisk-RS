//! hook.c native specialize hooks (1161-1216): the six
//! `rz_native*Specialize*_pre/_post` entry points that the JNI method hooks
//! (jni_tables.rs) call around the zygote's own `nativeSpecializeAppProcess`,
//! `nativeForkSystemServer` and `nativeForkAndSpecialize` methods.
//!
//! C-parity notes:
//! - The `native*` hooks do NOT fork themselves. `rz_fork_pre` (hook.c
//!   824-860, fork_prepost.rs) forks and caches the pid in `ctx.pid`; the
//!   zygote's own subsequent `fork` call is answered with that cached pid
//!   by the DCL_HOOK_FUNC(fork) hook (hook.c 231-236 / fork_hooks.rs).
//!   Only the child (`is_zygote_child` -> `ctx.pid == 0` here) runs the
//!   specialize pipeline; the parent returns right after `rz_fork_pre`.
//! - The C keeps the `GetStringUTFChars` buffer alive until
//!   `rz_app_specialize_post` releases it. The Rust spine stores an owned
//!   `String` in `ctx.process`, so the JNI buffer is copied into Rust
//!   memory and released immediately: the bytes are identical and nothing
//!   between pre and post reads the chars pointer except through
//!   `ctx.process`. (The C also leaks this buffer in the parent path,
//!   which never reaches the release.)
//! - `ctx.args.server` is not touched here: the C only reads it inside
//!   `rz_run_modules_pre/post` (load_modules.rs), exactly as ported.
//! - Process names are lossy-decoded from the JNI modified-UTF-8 buffer;
//!   the daemon side already does `String::from_utf8_lossy`
//!   (rezygiskd/src/daemon.rs), so this matches the spine. ASCII package
//!   names (the practical case) are byte-identical to the C.

use jni::sys::JNIEnv;

use crate::context::{
    flag_set, is_zygote_child, ZygiskContext, APP_FORK_AND_SPECIALIZE,
    SERVER_FORK_AND_SPECIALIZE, SKIP_FD_SANITIZATION,
};

const TAG: &str = rz_common::LOG_TAG;

/// hook.c 1162 / 1197: `ctx->process = (*env)->GetStringUTFChars(env,
/// *args.app->nice_name, NULL)` plus the matching `ReleaseStringUTFChars`
/// once the bytes are copied into the owned `ctx.process` String.
///
/// The C never checks the result; the only failure mode is a pending JNI
/// exception / OOM, in which case the C proceeds with a NULL process
/// string. A Rust `String` cannot be NULL, so we store an empty string
/// instead (and skip the release, since no buffer was returned).
fn set_process_from_nice_name(ctx: &mut ZygiskContext) {
    let env: *mut JNIEnv = ctx.env;
    let fns = unsafe { &**env };
    let Some(get_chars) = fns.GetStringUTFChars else {
        rz_common::loge!(TAG, "JNIEnv::GetStringUTFChars is unavailable");
        ctx.process.clear();
        return;
    };
    let chars = unsafe { get_chars(env, *(*ctx.args.app).nice_name, std::ptr::null_mut()) };
    if chars.is_null() {
        ctx.process.clear();
        return;
    }
    ctx.process = unsafe { std::ffi::CStr::from_ptr(chars) }
        .to_string_lossy()
        .into_owned();
    match fns.ReleaseStringUTFChars {
        Some(release) => unsafe { release(env, *(*ctx.args.app).nice_name, chars) },
        None => rz_common::loge!(TAG, "JNIEnv::ReleaseStringUTFChars is unavailable"),
    }
}

/// hook.c `rz_nativeSpecializeAppProcess_pre` (1161-1167).
pub unsafe fn rz_nativeSpecializeAppProcess_pre(ctx: &mut ZygiskContext) {
    set_process_from_nice_name(ctx);
    rz_common::logv!(TAG, "pre specialize [{}]", ctx.process);

    flag_set(ctx, SKIP_FD_SANITIZATION);
    crate::app_specialize::rz_app_specialize_pre(ctx);
}

/// hook.c `rz_nativeSpecializeAppProcess_post` (1169-1172).
pub unsafe fn rz_nativeSpecializeAppProcess_post(ctx: &mut ZygiskContext) {
    rz_common::logv!(TAG, "post specialize [{}]", ctx.process);
    crate::app_specialize::rz_app_specialize_post(ctx);
}

/// hook.c `rz_nativeForkSystemServer_pre` (1174-1184).
pub unsafe fn rz_nativeForkSystemServer_pre(ctx: &mut ZygiskContext) {
    rz_common::logv!(TAG, "pre forkSystemServer");
    flag_set(ctx, SERVER_FORK_AND_SPECIALIZE);

    crate::fork_prepost::rz_fork_pre(ctx);
    if !is_zygote_child(ctx) {
        return;
    }

    crate::load_modules::rz_run_modules_pre(ctx);

    crate::fd_sanitize::rz_sanitize_fds(ctx);
}

/// hook.c `rz_nativeForkSystemServer_post` (1186-1194).
pub unsafe fn rz_nativeForkSystemServer_post(ctx: &mut ZygiskContext) {
    if ctx.pid == 0 {
        rz_common::logv!(TAG, "post forkSystemServer");

        crate::load_modules::rz_run_modules_post(ctx);
    }

    crate::fork_prepost::rz_fork_post(ctx);
}

/// hook.c `rz_nativeForkAndSpecialize_pre` (1196-1206).
pub unsafe fn rz_nativeForkAndSpecialize_pre(ctx: &mut ZygiskContext) {
    set_process_from_nice_name(ctx);
    rz_common::logv!(TAG, "pre forkAndSpecialize [{}]", ctx.process);
    flag_set(ctx, APP_FORK_AND_SPECIALIZE);

    crate::fork_prepost::rz_fork_pre(ctx);
    if !is_zygote_child(ctx) {
        return;
    }

    crate::app_specialize::rz_app_specialize_pre(ctx);
    crate::fd_sanitize::rz_sanitize_fds(ctx);
}

/// hook.c `rz_nativeForkAndSpecialize_post` (1208-1215).
pub unsafe fn rz_nativeForkAndSpecialize_post(ctx: &mut ZygiskContext) {
    if ctx.pid == 0 {
        rz_common::logv!(TAG, "post forkAndSpecialize [{}]", ctx.process);
        // SAFETY: called from the hooked zygote after a successful fork,
        // with the child context in `ctx` (hook.c 1208-1215).
        unsafe { crate::app_specialize::rz_app_specialize_post(ctx) };
    }

    crate::fork_prepost::rz_fork_post(ctx);
}
