//! hook.c module loading: `load_modules_only` and
//! `rz_run_modules_pre` / `rz_run_modules_post`.
//!
//! Reads the module list from ReZygiskd, loads each lib with csoloader,
//! resolves `zygisk_module_entry`, and installs the api vtable pointer +
//! encoded module id. The per-module SCM_RIGHTS fd is closed immediately
//! after the load (L2 conversion — Android 16's zygote fd allowlist aborts
//! forkSystemServer on any non-allowlisted open path).
//!
//! `rz_run_modules_pre` runs on_load + pre-specialize; `rz_run_modules_post`
//! runs post-specialize then abandons/unloads the libs.

use rz_common::{logd, loge, logi};

use jni::JNIEnv;

use crate::abi::{encode_id, ReZygiskModule};
use crate::context::{
    flag_get, flag_set, module_snapshot, with_module_table, ZygiskContext, APP_SPECIALIZE,
    POST_SPECIALIZE, SERVER_FORK_AND_SPECIALIZE,
};
use crate::jni_utils::cstr_to_owned;

const TAG: &str = rz_common::LOG_TAG;

/// True when a JNI exception is currently pending on `env` (audit F3: the C
/// never checks, so a module leaving a pending exception surfaces as a
/// fork-time abort in the child instead of a named log line).
fn exception_pending(env: *mut jni::sys::JNIEnv) -> bool {
    let Ok(env) = (unsafe { JNIEnv::from_raw(env) }) else {
        return false;
    };
    env.exception_check().unwrap_or(false)
}

/// Report + clear a pending exception left behind by the module callback at
/// `module_idx` / `stage`. `pending_before` must be captured immediately
/// before the callback: a pre-existing pending exception (the zygote's own
/// failure) is never described or cleared — masking it would corrupt the JNI
/// error protocol far worse than one leaked module exception.
fn check_module_exception(
    env: *mut jni::sys::JNIEnv,
    module_idx: usize,
    stage: &str,
    pending_before: bool,
) {
    if pending_before {
        return;
    }
    let Ok(env) = (unsafe { JNIEnv::from_raw(env) }) else {
        return;
    };
    if !env.exception_check().unwrap_or(false) {
        return;
    }
    // Print the exception + Java backtrace to logcat, then clear so the
    // process continues from a clean JNI state.
    let _ = env.exception_describe();
    let _ = env.exception_clear();
    loge!(
        TAG,
        "module [{module_idx}] left a pending JNI exception in {stage} — described and cleared"
    );
}

/// hook.c `load_modules_only`.
pub unsafe fn load_modules_only() -> bool {
    let mut ms = crate::daemon_client::ZygiskModules {
        modules: Vec::new(),
        fds: Vec::new(),
    };
    if !crate::daemon_client::rezygiskd_read_modules(&mut ms) {
        loge!(TAG, "Failed to read modules from ReZygiskd");

        // The daemon's module list stays untouched on purpose: it is the
        // source of truth for the next zygote (re)injection (ZygoteRestart
        // never resets it), so draining it here would permanently disable
        // modules over a transient IPC hiccup.
        return false;
    }

    /* hook.c: mirror the C malloc + failure path; `try_reserve`
       fails (instead of aborting) on OOM so the error branch stays reachable. */
    if with_module_table(|m| m.try_reserve(ms.modules.len())).is_err() {
        loge!(TAG, "Failed to allocate memory for modules");

        crate::daemon_client::free_modules(&mut ms);

        return false;
    }

    // Every daemon-side removal shifts the remaining entries left by one, so
    // a module's daemon index is its original index minus the removals so far.
    let mut removed: usize = 0;

    for i in 0..ms.modules.len() {
        /* hook.c: the C writes into the slot at zygisk_module_length and
           only increments on success. A Vec that pushes on success only is
           observably identical (failed slots are never counted). */
        let lib_path = ms.modules[i].clone();

        /* INFO: The C leaves every field not listed below as malloc garbage;
           none of them is read before rezygisk_module_register (abi/api) or
           csoloader_load (lib) overwrites it. Use Default for sound
           initialization with defined zero values. */
        let mut m = ReZygiskModule::default();
        if !rz_csoloader::runtime::csoloader_load(&mut m.lib, &lib_path) {
            loge!(TAG, "Failed to load module [{}]", lib_path);

            /* INFO: In case a module failed to load, update the list of available modules
                 in ReZygiskd to avoid a mismatch between the loaded modules in ReZygisk
                 Zygote library and the available modules in ReZygiskd. The daemon also
                 re-reports its list to the monitor, keeping state.json truthful. */
            if crate::daemon_client::rezygiskd_remove_module(i - removed) {
                removed += 1;
            }
        } else {
            // SAFETY: m.lib was just successfully loaded by csoloader_load above.
            let entry = unsafe {
                rz_csoloader::runtime::csoloader_get_symbol(&m.lib, "zygisk_module_entry")
            };
            if entry.is_null() {
                loge!(TAG, "Failed to find entry point in module [{}]", lib_path);

                rz_csoloader::runtime::csoloader_unload(&mut m.lib);

                if crate::daemon_client::rezygiskd_remove_module(i - removed) {
                    removed += 1;
                }
            } else {
                m.api.register_module = Some(crate::module_api::rezygisk_module_register);
                m.zygisk_module_entry = Some(unsafe { std::mem::transmute(entry) });

                logd!(TAG, "Loaded module [{}]. Entry: {:p}", lib_path, entry);

                m.unload = false;
                // The C encodes the slot index (zygisk_module_length) the
                // module will land in; read it from the table at push time.
                with_module_table(|modules| {
                    m.api.impl_ = encode_id(modules.len());
                    modules.push(m);
                });
            }
        }

        /* INFO: L2 conversion — the SCM_RIGHTS fd backing /proc/self/fd/N was
               only needed during csoloader_load(). Close it immediately:
               Android 16's zygote fd allowlist (fd_utils.cpp CreateFromFd)
               aborts forkSystemServer on any non-allowlisted open path, so
               no module fd may survive into the fork. */
        // C: `ms.fds && ms.fds[i] >= 0` — skip a missing/consumed fd slot
        // instead of aborting (the Vec index must be bounds-guarded to keep
        // the C's skip semantics).
        if i < ms.fds.len() && ms.fds[i] >= 0 {
            let fd = ms.fds[i];
            logi!(TAG, "closing module fd {} after load", fd);

            unsafe { libc::close(fd) };
            ms.fds[i] = -1;
        }
    }

    crate::daemon_client::free_modules(&mut ms);

    true
}

/// hook.c `rz_run_modules_pre`.
pub unsafe fn run_modules_pre(ctx: &mut ZygiskContext) {
    // Snapshot (base, len) and release the table lock BEFORE any module code
    // runs: module entries re-enter the loader (`register_module`) and must
    // be able to take the lock (audit F1). All element access below is
    // through raw pointers — no reference into the table is alive across a
    // callback.
    let modules = module_snapshot();

    for i in 0..modules.len {
        let m = unsafe { modules.base.add(i) };

        let pending_before = exception_pending(ctx.env);
        unsafe {
            crate::module_calls::module_on_load(m, ctx.env.cast());
        }
        check_module_exception(ctx.env, i, "on_load", pending_before);

        if flag_get(ctx, APP_SPECIALIZE) {
            let pending_before = exception_pending(ctx.env);
            unsafe {
                crate::module_calls::module_pre_app_specialize(m, ctx.args.app);
            }
            check_module_exception(ctx.env, i, "pre_app_specialize", pending_before);
        } else if flag_get(ctx, SERVER_FORK_AND_SPECIALIZE) {
            let pending_before = exception_pending(ctx.env);
            unsafe {
                crate::module_calls::module_pre_server_specialize(m, ctx.args.server);
            }
            check_module_exception(ctx.env, i, "pre_server_specialize", pending_before);
        }
    }
}

/// hook.c `rz_run_modules_post`.
pub unsafe fn run_modules_post(ctx: &mut ZygiskContext) {
    flag_set(ctx, POST_SPECIALIZE);

    // Same snapshot discipline as rz_run_modules_pre: the lock is released
    // before the first callback and never re-taken during the loop.
    let modules = module_snapshot();

    let mut modules_unloaded: usize = 0;
    let total_modules = modules.len;

    for i in 0..modules.len {
        let m = unsafe { modules.base.add(i) };

        if flag_get(ctx, APP_SPECIALIZE) {
            let pending_before = exception_pending(ctx.env);
            unsafe {
                crate::module_calls::module_post_app_specialize(m, ctx.args.app);
            }
            check_module_exception(ctx.env, i, "post_app_specialize", pending_before);
        } else if flag_get(ctx, SERVER_FORK_AND_SPECIALIZE) {
            let pending_before = exception_pending(ctx.env);
            unsafe {
                crate::module_calls::module_post_server_specialize(m, ctx.args.server);
            }
            check_module_exception(ctx.env, i, "post_server_specialize", pending_before);
        }

        let unload = unsafe { std::ptr::addr_of!((*m).unload).read() };
        if !unload {
            logd!(TAG, "Abandoning module library at {:p}", m);
            // Short-lived borrow of the module's own CsoLib; abandon runs no
            // module code and the table lock is not held here.
            let lib = unsafe { std::ptr::addr_of_mut!((*m).lib) };
            rz_csoloader::runtime::csoloader_abandon(unsafe { &mut *lib });

            continue;
        }

        // Capture the on-disk path before unload frees it, so the
        // post-dlclose verification can look for surviving mappings.
        let lib_path = {
            let p = unsafe { std::ptr::addr_of!((*m).lib.lib_path).read() };
            cstr_to_owned(p).unwrap_or_default()
        };

        // dlclose inside linker_destroy can run module destructors; the
        // table lock is free by design, so destructor re-entry cannot
        // deadlock.
        let lib = unsafe { std::ptr::addr_of_mut!((*m).lib) };
        if !rz_csoloader::runtime::csoloader_unload(unsafe { &mut *lib }) {
            loge!(TAG, "Failed to unload module library");

            continue;
        }

        modules_unloaded += 1;

        // dlclose can silently leave resident segments behind (a leaked
        // reference, a TLS block). The "no /data/adb mapping survives
        // into the running app" guarantee is only real if it is checked;
        // log the anomaly, stay silent on success (app-visible logd
        // traffic is itself a detection channel).
        if !lib_path.is_empty()
            && rz_common::parse_maps("self")
                .map(|maps| maps.iter().any(|e| e.path.contains(lib_path.as_str())))
                .unwrap_or(false)
        {
            loge!(TAG, "module library still mapped after dlclose: {lib_path}");
        }
    }

    if total_modules > 0 {
        logd!(
            TAG,
            "Modules unloaded: {}/{}",
            modules_unloaded,
            total_modules
        );
    }
}
