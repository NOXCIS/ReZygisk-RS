//! jni_hooks.h port — the generated per-overload JNI wrapper functions plus
//! the static JNI hook table `initialize_jni_hook`/`do_hook_zygote` consume.
//!
//! The C header is emitted by gen_jni_hooks.py: for every
//! `nativeForkAndSpecialize` / `nativeSpecializeAppProcess` /
//! `nativeForkSystemServer` overload there is one
//! `__attribute__((no_stack_protector))` wrapper that
//! 1. snapshots the values into an `app_specialize_args_v5` /
//!    `server_specialize_args_v1` on the stack exactly like the C designated
//!    initializers (only the fields the C sets; the rest stay zeroed),
//! 2. runs `rz_init` / pre-hook / original / post-hook / `rz_cleanup`, and
//! 3. returns `ctx.pid` (fork wrappers only; the specialize wrappers return
//!    void).
//!
//! C-parity notes:
//! - The C orig backups (`static void *nativeForkAndSpecialize_orig`, ...)
//!   are `#[cfg_attr(target_os = "android", unsafe(no_mangle))] pub static mut` here with the EXACT C symbol
//!   names so the hook installer can reach them; in the C they are file-scope
//!   statics, no_mangle exports them (port contract).
//! - The C wrappers are `static`; here they are `#[cfg_attr(target_os = "android", unsafe(no_mangle))] pub` so
//!   the table below and the hook installer can take their addresses by
//!   symbol (port contract).
//! - C default argument promotions: at the variadic call of the original,
//!   `jboolean` (unsigned char) args are widened to `jint` exactly as the C
//!   compiler promotes them through `...`.
//! - The C declares `struct zygisk_context ctx;` uninitialized and rz_init's
//!   memset zeroes it; Rust cannot hold an uninitialized `Vec`/`String`, so
//!   [`new_zygisk_context`] materializes the memset-equivalent zero state.
//!
//! Sibling contracts: crate::lifecycle::{rz_init, rz_cleanup},
//! crate::native_specialize::rz_native*_pre/post. This header has no
//! app_specialize wrappers — `rz_app_specialize_pre/post` are called from
//! within the `rz_native*_pre/post` ports, not from here.

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

use std::ffi::c_void;
use std::mem::transmute;
use std::sync::atomic::{AtomicUsize, Ordering};

use jni::sys::{jarray, jboolean, jclass, jint, jlong, jobjectArray, jstring};

use crate::abi::{AppSpecializeArgsV5, ServerSpecializeArgsV1};
use crate::context::{ZygiskArgs, ZygiskContext, MAX_EXEMPTED_FDS, MAX_FD_SIZE};

/// hook.c `LOG_TAG` (the RS port uses "zygisk"). jni_hooks.h itself never
/// logs; kept per module convention.
pub const TAG: &str = rz_common::LOG_TAG;

// ---------------------------------------------------------------------------
// Orig backups (jni_hooks.h `static void *..._orig = NULL`).
// Uses AtomicUsize for sound access under Rust's aliasing model.
// ---------------------------------------------------------------------------

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub static nativeForkAndSpecialize_orig: AtomicUsize = AtomicUsize::new(0);

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub static nativeSpecializeAppProcess_orig: AtomicUsize = AtomicUsize::new(0);

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub static nativeForkSystemServer_orig: AtomicUsize = AtomicUsize::new(0);

// jni_hooks.h `typedef jint (*nativeForkAndSpecialize_fn)(JNIEnv *, jclass,
// ...)` — variadic so any overload is callable through the same pointer.
type NativeForkAndSpecializeFn =
    unsafe extern "C" fn(env: *mut jni::sys::JNIEnv, clazz: jclass, ...) -> jint;
type NativeSpecializeAppProcessFn =
    unsafe extern "C" fn(env: *mut jni::sys::JNIEnv, clazz: jclass, ...);
type NativeForkSystemServerFn =
    unsafe extern "C" fn(env: *mut jni::sys::JNIEnv, clazz: jclass, ...) -> jint;

/// `struct zygisk_context ctx;` + rz_init's memset in the C wrappers. The C
/// declares the struct uninitialized and rz_init zeroes it before filling;
/// Rust cannot hold an uninitialized `Vec`/`String`, so the wrapper builds
/// the memset-equivalent zero state (exactly what the C sees right after the
/// memset) and rz_init re-fills it as usual.
#[inline]
fn new_zygisk_context() -> ZygiskContext {
    ZygiskContext {
        env: std::ptr::null_mut(),
        args: ZygiskArgs { ptr: std::ptr::null_mut() },
        process: String::new(),
        pid: 0,
        flags: 0,
        info_flags: 0,
        allowed_fds: [0; MAX_FD_SIZE],
        exempted_fds: [0; MAX_EXEMPTED_FDS],
        exempted_fds_count: 0,
        // PTHREAD_MUTEX_INITIALIZER is all-zero on bionic/glibc — the C's
        // memset produces the same bit pattern.
        hook_info_lock: unsafe { std::mem::zeroed() },
        register_info: Vec::new(),
        ignore_info: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// nativeForkAndSpecialize overloads (jni_hooks.h lines 6-191).
// ---------------------------------------------------------------------------

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_l(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, fds_to_close, instruction_set, app_data_dir,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_o(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut fds_to_ignore: jarray,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.fds_to_ignore = &mut fds_to_ignore;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, fds_to_close, fds_to_ignore, instruction_set, app_data_dir,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_p(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut fds_to_ignore: jarray,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.fds_to_ignore = &mut fds_to_ignore;
    args.is_child_zygote = &mut is_child_zygote;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, fds_to_close, fds_to_ignore, is_child_zygote as jint, instruction_set,
            app_data_dir,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_q_alt(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut fds_to_ignore: jarray,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
    mut is_top_app: jboolean,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.fds_to_ignore = &mut fds_to_ignore;
    args.is_child_zygote = &mut is_child_zygote;
    args.is_top_app = &mut is_top_app;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, fds_to_close, fds_to_ignore, is_child_zygote as jint, instruction_set,
            app_data_dir, is_top_app as jint,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_r(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut fds_to_ignore: jarray,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
    mut is_top_app: jboolean,
    mut pkg_data_info_list: jobjectArray,
    mut whitelisted_data_info_list: jobjectArray,
    mut mount_data_dirs: jboolean,
    mut mount_storage_dirs: jboolean,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.fds_to_ignore = &mut fds_to_ignore;
    args.is_child_zygote = &mut is_child_zygote;
    args.is_top_app = &mut is_top_app;
    args.pkg_data_info_list = &mut pkg_data_info_list;
    args.whitelisted_data_info_list = &mut whitelisted_data_info_list;
    args.mount_data_dirs = &mut mount_data_dirs;
    args.mount_storage_dirs = &mut mount_storage_dirs;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, fds_to_close, fds_to_ignore, is_child_zygote as jint, instruction_set,
            app_data_dir, is_top_app as jint, pkg_data_info_list, whitelisted_data_info_list,
            mount_data_dirs as jint, mount_storage_dirs as jint,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_u(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut fds_to_ignore: jarray,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
    mut is_top_app: jboolean,
    mut pkg_data_info_list: jobjectArray,
    mut whitelisted_data_info_list: jobjectArray,
    mut mount_data_dirs: jboolean,
    mut mount_storage_dirs: jboolean,
    mut mount_sysprop_overrides: jboolean,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.fds_to_ignore = &mut fds_to_ignore;
    args.is_child_zygote = &mut is_child_zygote;
    args.is_top_app = &mut is_top_app;
    args.pkg_data_info_list = &mut pkg_data_info_list;
    args.whitelisted_data_info_list = &mut whitelisted_data_info_list;
    args.mount_data_dirs = &mut mount_data_dirs;
    args.mount_storage_dirs = &mut mount_storage_dirs;
    args.mount_sysprop_overrides = &mut mount_sysprop_overrides;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, fds_to_close, fds_to_ignore, is_child_zygote as jint, instruction_set,
            app_data_dir, is_top_app as jint, pkg_data_info_list, whitelisted_data_info_list,
            mount_data_dirs as jint, mount_storage_dirs as jint, mount_sysprop_overrides as jint,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

// A16 QPR shape (device framework.jar ground truth): the `u` overload plus a
// `useFifoUi` boolean between `isTopApp` and `pkgDataInfoList`. Not mapped
// into AppSpecializeArgsV5 (no upstream field); passed through untouched.
#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_v(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut fds_to_ignore: jarray,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
    mut is_top_app: jboolean,
    use_fifo_ui: jboolean,
    mut pkg_data_info_list: jobjectArray,
    mut whitelisted_data_info_list: jobjectArray,
    mut mount_data_dirs: jboolean,
    mut mount_storage_dirs: jboolean,
    mut mount_sysprop_overrides: jboolean,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.fds_to_ignore = &mut fds_to_ignore;
    args.is_child_zygote = &mut is_child_zygote;
    args.is_top_app = &mut is_top_app;
    args.pkg_data_info_list = &mut pkg_data_info_list;
    args.whitelisted_data_info_list = &mut whitelisted_data_info_list;
    args.mount_data_dirs = &mut mount_data_dirs;
    args.mount_storage_dirs = &mut mount_storage_dirs;
    args.mount_sysprop_overrides = &mut mount_sysprop_overrides;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, fds_to_close, fds_to_ignore, is_child_zygote as jint, instruction_set,
            app_data_dir, is_top_app as jint, use_fifo_ui as jint, pkg_data_info_list,
            whitelisted_data_info_list, mount_data_dirs as jint, mount_storage_dirs as jint,
            mount_sysprop_overrides as jint,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_samsung_m(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    _0: jint,
    _1: jint,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info, _0, _1,
            nice_name, fds_to_close, instruction_set, app_data_dir,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_samsung_n(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    _2: jint,
    _3: jint,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
    _4: jint,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info, _2, _3,
            nice_name, fds_to_close, instruction_set, app_data_dir, _4,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_samsung_o(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    _5: jint,
    _6: jint,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut fds_to_ignore: jarray,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.fds_to_ignore = &mut fds_to_ignore;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info, _5, _6,
            nice_name, fds_to_close, fds_to_ignore, instruction_set, app_data_dir,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_samsung_p(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    _7: jint,
    _8: jint,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut fds_to_ignore: jarray,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.fds_to_ignore = &mut fds_to_ignore;
    args.is_child_zygote = &mut is_child_zygote;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info, _7, _8,
            nice_name, fds_to_close, fds_to_ignore, is_child_zygote as jint, instruction_set,
            app_data_dir,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_samsung_b(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut fds_to_ignore: jarray,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
    _9: jboolean,
    mut is_top_app: jboolean,
    mut pkg_data_info_list: jobjectArray,
    mut whitelisted_data_info_list: jobjectArray,
    mut mount_data_dirs: jboolean,
    mut mount_storage_dirs: jboolean,
    mut mount_sysprop_overrides: jboolean,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.fds_to_ignore = &mut fds_to_ignore;
    args.is_child_zygote = &mut is_child_zygote;
    args.is_top_app = &mut is_top_app;
    args.pkg_data_info_list = &mut pkg_data_info_list;
    args.whitelisted_data_info_list = &mut whitelisted_data_info_list;
    args.mount_data_dirs = &mut mount_data_dirs;
    args.mount_storage_dirs = &mut mount_storage_dirs;
    args.mount_sysprop_overrides = &mut mount_sysprop_overrides;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, fds_to_close, fds_to_ignore, is_child_zygote as jint, instruction_set,
            app_data_dir, _9 as jint, is_top_app as jint, pkg_data_info_list,
            whitelisted_data_info_list, mount_data_dirs as jint, mount_storage_dirs as jint,
            mount_sysprop_overrides as jint,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkAndSpecialize_grapheneos_u(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    fds_to_close: jarray,
    mut fds_to_ignore: jarray,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
    mut is_top_app: jboolean,
    mut pkg_data_info_list: jobjectArray,
    mut whitelisted_data_info_list: jobjectArray,
    mut mount_data_dirs: jboolean,
    mut mount_storage_dirs: jboolean,
    mut mount_sysprop_overrides: jboolean,
    _14: jarray,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.fds_to_ignore = &mut fds_to_ignore;
    args.is_child_zygote = &mut is_child_zygote;
    args.is_top_app = &mut is_top_app;
    args.pkg_data_info_list = &mut pkg_data_info_list;
    args.whitelisted_data_info_list = &mut whitelisted_data_info_list;
    args.mount_data_dirs = &mut mount_data_dirs;
    args.mount_storage_dirs = &mut mount_storage_dirs;
    args.mount_sysprop_overrides = &mut mount_sysprop_overrides;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeForkAndSpecialize_pre(&mut ctx);
    let orig: NativeForkAndSpecializeFn = unsafe { transmute(nativeForkAndSpecialize_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, fds_to_close, fds_to_ignore, is_child_zygote as jint, instruction_set,
            app_data_dir, is_top_app as jint, pkg_data_info_list, whitelisted_data_info_list,
            mount_data_dirs as jint, mount_storage_dirs as jint, mount_sysprop_overrides as jint,
            _14,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkAndSpecialize_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

// ---------------------------------------------------------------------------
// nativeSpecializeAppProcess overloads (jni_hooks.h lines 256-380).
// ---------------------------------------------------------------------------

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeSpecializeAppProcess_q(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
) {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.is_child_zygote = &mut is_child_zygote;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeSpecializeAppProcess_pre(&mut ctx);
    let orig: NativeSpecializeAppProcessFn = unsafe { transmute(nativeSpecializeAppProcess_orig.load(Ordering::Relaxed)) };
    unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, is_child_zygote as jint, instruction_set, app_data_dir,
        );
    }
    crate::native_specialize::rz_nativeSpecializeAppProcess_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeSpecializeAppProcess_q_alt(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
    mut is_top_app: jboolean,
) {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.is_child_zygote = &mut is_child_zygote;
    args.is_top_app = &mut is_top_app;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeSpecializeAppProcess_pre(&mut ctx);
    let orig: NativeSpecializeAppProcessFn = unsafe { transmute(nativeSpecializeAppProcess_orig.load(Ordering::Relaxed)) };
    unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, is_child_zygote as jint, instruction_set, app_data_dir, is_top_app as jint,
        );
    }
    crate::native_specialize::rz_nativeSpecializeAppProcess_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeSpecializeAppProcess_r(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
    mut is_top_app: jboolean,
    mut pkg_data_info_list: jobjectArray,
    mut whitelisted_data_info_list: jobjectArray,
    mut mount_data_dirs: jboolean,
    mut mount_storage_dirs: jboolean,
) {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.is_child_zygote = &mut is_child_zygote;
    args.is_top_app = &mut is_top_app;
    args.pkg_data_info_list = &mut pkg_data_info_list;
    args.whitelisted_data_info_list = &mut whitelisted_data_info_list;
    args.mount_data_dirs = &mut mount_data_dirs;
    args.mount_storage_dirs = &mut mount_storage_dirs;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeSpecializeAppProcess_pre(&mut ctx);
    let orig: NativeSpecializeAppProcessFn = unsafe { transmute(nativeSpecializeAppProcess_orig.load(Ordering::Relaxed)) };
    unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, is_child_zygote as jint, instruction_set, app_data_dir, is_top_app as jint,
            pkg_data_info_list, whitelisted_data_info_list, mount_data_dirs as jint,
            mount_storage_dirs as jint,
        );
    }
    crate::native_specialize::rz_nativeSpecializeAppProcess_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeSpecializeAppProcess_u(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
    mut is_top_app: jboolean,
    mut pkg_data_info_list: jobjectArray,
    mut whitelisted_data_info_list: jobjectArray,
    mut mount_data_dirs: jboolean,
    mut mount_storage_dirs: jboolean,
    mut mount_sysprop_overrides: jboolean,
) {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.is_child_zygote = &mut is_child_zygote;
    args.is_top_app = &mut is_top_app;
    args.pkg_data_info_list = &mut pkg_data_info_list;
    args.whitelisted_data_info_list = &mut whitelisted_data_info_list;
    args.mount_data_dirs = &mut mount_data_dirs;
    args.mount_storage_dirs = &mut mount_storage_dirs;
    args.mount_sysprop_overrides = &mut mount_sysprop_overrides;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeSpecializeAppProcess_pre(&mut ctx);
    let orig: NativeSpecializeAppProcessFn = unsafe { transmute(nativeSpecializeAppProcess_orig.load(Ordering::Relaxed)) };
    unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, is_child_zygote as jint, instruction_set, app_data_dir, is_top_app as jint,
            pkg_data_info_list, whitelisted_data_info_list, mount_data_dirs as jint,
            mount_storage_dirs as jint, mount_sysprop_overrides as jint,
        );
    }
    crate::native_specialize::rz_nativeSpecializeAppProcess_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeSpecializeAppProcess_samsung_q(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    _10: jint,
    _11: jint,
    mut nice_name: jstring,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
) {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.is_child_zygote = &mut is_child_zygote;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeSpecializeAppProcess_pre(&mut ctx);
    let orig: NativeSpecializeAppProcessFn = unsafe { transmute(nativeSpecializeAppProcess_orig.load(Ordering::Relaxed)) };
    unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info, _10, _11,
            nice_name, is_child_zygote as jint, instruction_set, app_data_dir,
        );
    }
    crate::native_specialize::rz_nativeSpecializeAppProcess_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeSpecializeAppProcess_grapheneos_u(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    mut rlimits: jobjectArray,
    mut mount_external: jint,
    mut se_info: jstring,
    mut nice_name: jstring,
    mut is_child_zygote: jboolean,
    mut instruction_set: jstring,
    mut app_data_dir: jstring,
    mut is_top_app: jboolean,
    mut pkg_data_info_list: jobjectArray,
    mut whitelisted_data_info_list: jobjectArray,
    mut mount_data_dirs: jboolean,
    mut mount_storage_dirs: jboolean,
    mut mount_sysprop_overrides: jboolean,
    _15: jarray,
) {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: AppSpecializeArgsV5 = unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.rlimits = &mut rlimits;
    args.mount_external = &mut mount_external;
    args.se_info = &mut se_info;
    args.nice_name = &mut nice_name;
    args.instruction_set = &mut instruction_set;
    args.app_data_dir = &mut app_data_dir;
    args.is_child_zygote = &mut is_child_zygote;
    args.is_top_app = &mut is_top_app;
    args.pkg_data_info_list = &mut pkg_data_info_list;
    args.whitelisted_data_info_list = &mut whitelisted_data_info_list;
    args.mount_data_dirs = &mut mount_data_dirs;
    args.mount_storage_dirs = &mut mount_storage_dirs;
    args.mount_sysprop_overrides = &mut mount_sysprop_overrides;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(&mut ctx, env, &mut args as *mut AppSpecializeArgsV5 as *mut c_void);
    crate::native_specialize::rz_nativeSpecializeAppProcess_pre(&mut ctx);
    let orig: NativeSpecializeAppProcessFn = unsafe { transmute(nativeSpecializeAppProcess_orig.load(Ordering::Relaxed)) };
    unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, mount_external, se_info,
            nice_name, is_child_zygote as jint, instruction_set, app_data_dir, is_top_app as jint,
            pkg_data_info_list, whitelisted_data_info_list, mount_data_dirs as jint,
            mount_storage_dirs as jint, mount_sysprop_overrides as jint, _15,
        );
    }
    crate::native_specialize::rz_nativeSpecializeAppProcess_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
}

// ---------------------------------------------------------------------------
// nativeForkSystemServer overloads (jni_hooks.h lines 382-420).
// ---------------------------------------------------------------------------

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkSystemServer_l(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    rlimits: jobjectArray,
    mut permitted_capabilities: jlong,
    mut effective_capabilities: jlong,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: ServerSpecializeArgsV1 =
        unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.permitted_capabilities = &mut permitted_capabilities;
    args.effective_capabilities = &mut effective_capabilities;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(
        &mut ctx,
        env,
        &mut args as *mut ServerSpecializeArgsV1 as *mut c_void,
    );
    crate::native_specialize::rz_nativeForkSystemServer_pre(&mut ctx);
    let orig: NativeForkSystemServerFn = unsafe { transmute(nativeForkSystemServer_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, rlimits, permitted_capabilities,
            effective_capabilities,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkSystemServer_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn nativeForkSystemServer_samsung_q(
    env: *mut jni::sys::JNIEnv,
    clazz: jclass,
    mut uid: jint,
    mut gid: jint,
    mut gids: jarray,
    mut runtime_flags: jint,
    _12: jint,
    _13: jint,
    rlimits: jobjectArray,
    mut permitted_capabilities: jlong,
    mut effective_capabilities: jlong,
) -> jint {
    let _guard = crate::fork_hooks::LoaderGuard::new();

    let mut args: ServerSpecializeArgsV1 =
        unsafe { std::mem::MaybeUninit::zeroed().assume_init() };
    args.uid = &mut uid;
    args.gid = &mut gid;
    args.gids = &mut gids;
    args.runtime_flags = &mut runtime_flags;
    args.permitted_capabilities = &mut permitted_capabilities;
    args.effective_capabilities = &mut effective_capabilities;

    let mut ctx = new_zygisk_context();
    crate::lifecycle::rz_init(
        &mut ctx,
        env,
        &mut args as *mut ServerSpecializeArgsV1 as *mut c_void,
    );
    crate::native_specialize::rz_nativeForkSystemServer_pre(&mut ctx);
    let orig: NativeForkSystemServerFn = unsafe { transmute(nativeForkSystemServer_orig.load(Ordering::Relaxed)) };
    let pid = unsafe {
        orig(
            env, clazz, uid, gid, gids, runtime_flags, _12, _13, rlimits,
            permitted_capabilities, effective_capabilities,
        )
    };
    ctx.pid = pid;
    crate::native_specialize::rz_nativeForkSystemServer_post(&mut ctx);
    crate::lifecycle::rz_cleanup(&mut ctx);
    pid
}

// ---------------------------------------------------------------------------
// JNI_HOOKS — jni_hooks.h's three `JNINativeMethod` arrays flattened into one
// table in C order: nativeForkAndSpecialize_methods (12),
// nativeSpecializeAppProcess_methods (6), nativeForkSystemServer_methods (2).
// ---------------------------------------------------------------------------

pub fn jni_hooks() -> Vec<(&'static str, &'static str, &'static str, usize)> {
    vec![
    // nativeForkAndSpecialize_methods
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;[ILjava/lang/String;Ljava/lang/String;)I",
        nativeForkAndSpecialize_l as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;[I[ILjava/lang/String;Ljava/lang/String;)I",
        nativeForkAndSpecialize_o as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;[I[IZLjava/lang/String;Ljava/lang/String;)I",
        nativeForkAndSpecialize_p as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;[I[IZLjava/lang/String;Ljava/lang/String;Z)I",
        nativeForkAndSpecialize_q_alt as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;[I[IZLjava/lang/String;Ljava/lang/String;Z[Ljava/lang/String;[Ljava/lang/String;ZZ)I",
        nativeForkAndSpecialize_r as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;[I[IZLjava/lang/String;Ljava/lang/String;Z[Ljava/lang/String;[Ljava/lang/String;ZZZ)I",
        nativeForkAndSpecialize_u as usize,
    ),
    // A16 QPR: +useFifoUi (confirmed from device framework.jar classes5.dex).
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;[I[IZLjava/lang/String;Ljava/lang/String;ZZ[Ljava/lang/String;[Ljava/lang/String;ZZZ)I",
        nativeForkAndSpecialize_v as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;IILjava/lang/String;[ILjava/lang/String;Ljava/lang/String;)I",
        nativeForkAndSpecialize_samsung_m as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;IILjava/lang/String;[ILjava/lang/String;Ljava/lang/String;I)I",
        nativeForkAndSpecialize_samsung_n as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;IILjava/lang/String;[I[ILjava/lang/String;Ljava/lang/String;)I",
        nativeForkAndSpecialize_samsung_o as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;IILjava/lang/String;[I[IZLjava/lang/String;Ljava/lang/String;)I",
        nativeForkAndSpecialize_samsung_p as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;[I[IZLjava/lang/String;Ljava/lang/String;ZZ[Ljava/lang/String;[Ljava/lang/String;ZZZ)I",
        nativeForkAndSpecialize_samsung_b as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeForkAndSpecialize",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;[I[IZLjava/lang/String;Ljava/lang/String;Z[Ljava/lang/String;[Ljava/lang/String;ZZZ[J)I",
        nativeForkAndSpecialize_grapheneos_u as usize,
    ),
    // nativeSpecializeAppProcess_methods
    (
        "com/android/internal/os/Zygote",
        "nativeSpecializeAppProcess",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;)V",
        nativeSpecializeAppProcess_q as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeSpecializeAppProcess",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Z)V",
        nativeSpecializeAppProcess_q_alt as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeSpecializeAppProcess",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Z[Ljava/lang/String;[Ljava/lang/String;ZZ)V",
        nativeSpecializeAppProcess_r as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeSpecializeAppProcess",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Z[Ljava/lang/String;[Ljava/lang/String;ZZZ)V",
        nativeSpecializeAppProcess_u as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeSpecializeAppProcess",
        "(II[II[[IILjava/lang/String;IILjava/lang/String;ZLjava/lang/String;Ljava/lang/String;)V",
        nativeSpecializeAppProcess_samsung_q as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeSpecializeAppProcess",
        "(II[II[[IILjava/lang/String;Ljava/lang/String;ZLjava/lang/String;Ljava/lang/String;Z[Ljava/lang/String;[Ljava/lang/String;ZZZ[J)V",
        nativeSpecializeAppProcess_grapheneos_u as usize,
    ),
    // nativeForkSystemServer_methods
    (
        "com/android/internal/os/Zygote",
        "nativeForkSystemServer",
        "(II[II[[IJJ)I",
        nativeForkSystemServer_l as usize,
    ),
    (
        "com/android/internal/os/Zygote",
        "nativeForkSystemServer",
        "(II[IIII[[IJJ)I",
        nativeForkSystemServer_samsung_q as usize,
    ),
    ]
}
