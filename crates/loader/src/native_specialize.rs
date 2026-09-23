//! hook.c native specialize hooks: the six
//! `rz_native*Specialize*_pre/_post` entry points that the JNI method hooks
//! (jni_tables.rs) call around the zygote's own `nativeSpecializeAppProcess`,
//! `nativeForkSystemServer` and `nativeForkAndSpecialize` methods.

// Function names follow the C hook.c naming convention for grep-ability.
#![allow(non_snake_case)]
//!
//! C-parity notes:
//! - The `native*` hooks do NOT fork themselves. `rz_fork_pre` (hook.c
//!   824-860, fork_prepost.rs) forks and caches the pid in `ctx.pid`; the
//!   zygote's own subsequent `fork` call is answered with that cached pid
//!   by the DCL_HOOK_FUNC(fork) hook (fork_hooks.rs).
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

use crate::context::{
    flag_set, is_zygote_child, ZygiskContext, APP_FORK_AND_SPECIALIZE,
    SERVER_FORK_AND_SPECIALIZE, SKIP_FD_SANITIZATION,
};
use crate::jni_utils::JniStringGuard;

const TAG: &str = rz_common::LOG_TAG;

/// hook.c: `ctx->process = (*env)->GetStringUTFChars(env,
/// *args.app->nice_name, NULL)` plus the matching `ReleaseStringUTFChars`
/// once the bytes are copied into the owned `ctx.process` String.
///
/// The C never checks the result; the only failure mode is a pending JNI
/// exception / OOM, in which case the C proceeds with a NULL process
/// string. A Rust `String` cannot be NULL, so we store an empty string
/// instead (and skip the release, since no buffer was returned).
fn set_process_from_nice_name(ctx: &mut ZygiskContext) {
    let nice_name = unsafe { *(*ctx.args.app).nice_name };
    let Some(guard) = JniStringGuard::new(ctx.env, nice_name) else {
        ctx.process.clear();
        return;
    };
    ctx.process = guard.as_cstr().to_string_lossy().into_owned();
    // guard auto-releases on drop
}

/// hook.c `rz_nativeSpecializeAppProcess_pre`.
pub unsafe fn rz_nativeSpecializeAppProcess_pre(ctx: &mut ZygiskContext) {
    set_process_from_nice_name(ctx);
    rz_common::logv!(TAG, "pre specialize [{}]", ctx.process);

    flag_set(ctx, SKIP_FD_SANITIZATION);
    // SAFETY: ctx is valid; called from JNI wrapper with proper context.
    unsafe { crate::app_specialize::app_specialize_pre(ctx) };
}

/// hook.c `rz_nativeSpecializeAppProcess_post`.
pub unsafe fn rz_nativeSpecializeAppProcess_post(ctx: &mut ZygiskContext) {
    rz_common::logv!(TAG, "post specialize [{}]", ctx.process);
    // SAFETY: ctx is valid; called from JNI wrapper after specialize.
    unsafe { crate::app_specialize::app_specialize_post(ctx) };
}

/// hook.c `rz_nativeForkSystemServer_pre`.
pub unsafe fn rz_nativeForkSystemServer_pre(ctx: &mut ZygiskContext) {
    rz_common::logv!(TAG, "pre forkSystemServer");
    flag_set(ctx, SERVER_FORK_AND_SPECIALIZE);

    crate::fork_prepost::fork_pre(ctx);
    if !is_zygote_child(ctx) {
        return;
    }

    // SAFETY: ctx is valid; in child process after fork.
    unsafe { crate::load_modules::run_modules_pre(ctx) };

    crate::fd_sanitize::sanitize_fds(ctx);
}

/// hook.c `rz_nativeForkSystemServer_post`.
pub unsafe fn rz_nativeForkSystemServer_post(ctx: &mut ZygiskContext) {
    if ctx.pid == 0 {
        rz_common::logv!(TAG, "post forkSystemServer");

        // SAFETY: ctx is valid; in child process (pid == 0).
        unsafe { crate::load_modules::run_modules_post(ctx) };
    }

    crate::fork_prepost::fork_post(ctx);
}

/// hook.c `rz_nativeForkAndSpecialize_pre`.
pub unsafe fn rz_nativeForkAndSpecialize_pre(ctx: &mut ZygiskContext) {
    set_process_from_nice_name(ctx);
    rz_common::logv!(TAG, "pre forkAndSpecialize [{}]", ctx.process);
    flag_set(ctx, APP_FORK_AND_SPECIALIZE);

    crate::fork_prepost::fork_pre(ctx);
    if !is_zygote_child(ctx) {
        return;
    }

    // SAFETY: ctx is valid; in child process after fork.
    unsafe { crate::app_specialize::app_specialize_pre(ctx) };
    crate::fd_sanitize::sanitize_fds(ctx);
}

/// hook.c `rz_nativeForkAndSpecialize_post`.
pub unsafe fn rz_nativeForkAndSpecialize_post(ctx: &mut ZygiskContext) {
    if ctx.pid == 0 {
        rz_common::logv!(TAG, "post forkAndSpecialize [{}]", ctx.process);
        // SAFETY: called from the hooked zygote after a successful fork,
        // with the child context in `ctx`.
        unsafe { crate::app_specialize::app_specialize_post(ctx) };
    }

    crate::fork_prepost::fork_post(ctx);
}
