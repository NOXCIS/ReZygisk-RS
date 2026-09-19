//! truman_ref — Truman Phase 7 reflection-spoof Zygisk sub-module.
//!
//! Implements the ReZygisk module ABI in Rust (`zygisk_module_entry` +
//! `rezygisk_abi` vtable, mirroring loader/src/injector/module.h) so the
//! fork's existing `rz_module_call_pre/post_app_specialize` machinery drives
//! it unchanged. In `postAppSpecialize` it rewrites
//! `AssetManager.LINEAGE_APK_PATH` for targeted packages (the Duck Detector
//! canary), pairing with the kernel dome S7 path-spoof published by ksud.
//!
//! Layout: the spoof logic lives in pure-Rust `spoof.rs` (host-testable), the
//! `repr(C)` mirrors in `abi.rs`, and the JNI writer in `jni_glue.rs` — so the
//! crate ports directly into the future ReZygisk-RS daemon.
//!
//! One-shot per process: `preAppSpecialize` sets `DLCLOSE_MODULE_LIBRARY`, so
//! after the specialize pass the loader dlcloses this library — no maps-only
//! `/data/adb` mapping survives into the running app (loader-visibility
//! scans). The rewrite itself persists in the AssetManager static field.

mod abi;
mod jni_glue;
mod spoof;

use std::os::raw::c_void;

use jni::JNIEnv;

use abi::{
    AppSpecializeArgsV5, DLCLOSE_MODULE_LIBRARY, ReZygiskAbi, ReZygiskApi, REZYGISK_API_VERSION,
};

/// State handed back to every callback through the ABI's `impl` pointer —
/// the specialize callbacks carry only (impl, args), and the zygote child
/// keeps the same JNIEnv pointer it inherited at fork (standard Zygisk
/// pattern).
struct ModuleState {
    env: *mut jni::sys::JNIEnv,
    api: *mut ReZygiskApi,
}

// ── logcat (no logging crate — keep the ABI layer thin) ──
const LOG_TAG: &[u8] = b"truman_ref\0";
const ANDROID_LOG_INFO: i32 = 4;

extern "C" {
    fn __android_log_print(prio: i32, tag: *const u8, fmt: *const u8, ...) -> i32;
}

pub(crate) fn truman_log(msg: &str) {
    let fmt = b"%s\0";
    let cmsg = match std::ffi::CString::new(msg.replace('%', "%%")) {
        Ok(s) => s,
        Err(_) => return,
    };
    unsafe {
        __android_log_print(
            ANDROID_LOG_INFO,
            LOG_TAG.as_ptr(),
            fmt.as_ptr(),
            cmsg.as_ptr(),
        );
    }
}

#[no_mangle]
pub unsafe extern "C" fn zygisk_module_entry(api: *mut ReZygiskApi, env: *mut jni::sys::JNIEnv) {
    truman_log("module entry (Phase 7 reflection spoof)");

    let state = Box::new(ModuleState { env, api });
    let abi = ReZygiskAbi {
        api_version: REZYGISK_API_VERSION,
        impl_: Box::into_raw(state) as *mut c_void,
        pre_app_specialize: Some(pre_app_specialize),
        post_app_specialize: Some(post_app_specialize),
        pre_server_specialize: Some(pre_server_specialize),
        post_server_specialize: None,
    };

    match (*api).register_module {
        Some(register) if register(api, &abi) => truman_log("registered (api v5)"),
        _ => truman_log("register_module FAILED — spoof inert this process"),
    }
}

/// One-shot module: ask the loader to dlclose this library once the specialize
/// pass finishes. Safe from every process — the rewrite persists as a Java
/// static field and no truman code is needed after postAppSpecialize returns.
/// The first arg must be the api's `impl` member (the encoded module id, per
/// the loader's RZID_MAGIC contract).
unsafe fn request_self_unload(state: &ModuleState) {
    let api = state.api;
    if api.is_null() {
        return;
    }
    match (*api).set_option {
        Some(set_option) => set_option((*api).impl_, DLCLOSE_MODULE_LIBRARY),
        None => truman_log("set_option unavailable — library stays mapped"),
    }
}

unsafe extern "C" fn pre_app_specialize(impl_: *mut c_void, _args: *mut c_void) {
    let state = &*(impl_ as *const ModuleState);
    request_self_unload(state);
}

unsafe extern "C" fn pre_server_specialize(impl_: *mut c_void, _args: *mut c_void) {
    let state = &*(impl_ as *const ModuleState);
    request_self_unload(state);
}

unsafe extern "C" fn post_app_specialize(impl_: *mut c_void, args: *const c_void) {
    if args.is_null() {
        return;
    }
    let args = args as *const AppSpecializeArgsV5;
    let state = &*(impl_ as *const ModuleState);
    let env_ptr = state.env;

    let nice_name = match (*args).nice_name {
        p if p.is_null() || (*p).is_null() => return,
        p => *p,
    };
    let Some(pkg) = (unsafe {
        if env_ptr.is_null() {
            return;
        }
        let mut env = match JNIEnv::from_raw(env_ptr) {
            Ok(e) => e,
            Err(_) => return,
        };
        let out = jni_glue::borrow_jstring(&mut env, nice_name as *mut jni::sys::_jobject);
        // Do NOT clear exceptions here: this is a borrowed env before we own
        // the reflection phase; just capture the name.
        out
    }) else {
        return;
    };

    let entries = spoof::spoof_entries(&pkg);
    if entries.is_empty() {
        return;
    }

    truman_log(&format!("specializing '{pkg}' — applying {} rewrites", entries.len()));

    if let Ok(mut env) = unsafe { JNIEnv::from_raw(env_ptr) } {
        for entry in entries {
            if let Err(reason) = jni_glue::apply_entry(&mut env, entry) {
                truman_log(&format!("skipped {}.{}: {reason}", entry.class, entry.field));
                if jni_glue::clear_pending(&mut env) {
                    truman_log("pending JNI exception cleared");
                }
            }
        }
        if jni_glue::clear_pending(&mut env) {
            truman_log("pending JNI exception cleared after rewrite pass");
        }
    } else {
        truman_log("JNIEnv::from_raw failed — spoof skipped");
    }
}
