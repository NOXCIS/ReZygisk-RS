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

// ── logging (companion-routed; never the host process's logcat buffer) ──
//
// STEALTH: a zygisk sub-module's stdout/logd output lands in the host
// process's OWN logcat buffer — readable by the app itself without any
// permission — so even dev logging must not go there. With the dev-only
// `truman-log` feature, `preAppSpecialize` (while the child still runs with
// zygote privileges) opens the rezygiskd companion socket, and every `tlog!`
// line is relayed by the module's companion process (root) into
// /data/adb/truman/module.log — the manager's Logs tab reads it next to the
// other root-side truman logs, and the host app sees nothing but an
// unnamed socket fd that dies with the specialize pass. Release builds
// (no feature) compile the whole channel out, so even format strings and
// path literals vanish from the shipped binary.
#[cfg(feature = "truman-log")]
mod logging {
    use std::os::raw::c_void;
    use std::sync::atomic::{AtomicI32, Ordering};

    static LOG_FD: AtomicI32 = AtomicI32::new(-1);

    /// Open the log channel: one companion connection per app child, held
    /// only between the pre- and post-specialize hooks. The companion acks
    /// on this socket before [crate::zygisk_companion_entry] starts serving
    /// it; the loader's `connect_companion` consumes that ack for us.
    pub fn open(api: *mut super::ReZygiskApi, id: *mut c_void) {
        let fd = unsafe {
            match (*api).connect_companion {
                Some(connect) => connect(id),
                None => -1,
            }
        };
        LOG_FD.store(fd, Ordering::Relaxed);
    }

    pub fn close() {
        let fd = LOG_FD.swap(-1, Ordering::Relaxed);
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }

    pub fn emit(msg: &str) {
        let fd = LOG_FD.load(Ordering::Relaxed);
        if fd < 0 {
            return;
        }
        let payload = msg.as_bytes();
        // Native-endian length prefix — the same socket_utils convention as
        // the daemon protocol on this platform.
        let len = (payload.len() as u32).to_ne_bytes();
        let send = |buf: &[u8]| unsafe {
            libc::send(fd, buf.as_ptr().cast(), buf.len(), libc::MSG_NOSIGNAL)
        };
        if send(&len) != 4 {
            close();
            return;
        }
        if !payload.is_empty() && send(payload) != payload.len() as isize {
            close();
        }
    }
}

#[cfg(feature = "truman-log")]
macro_rules! tlog {
    ($($arg:tt)*) => { $crate::logging::emit(&format!($($arg)*)) };
}

#[cfg(not(feature = "truman-log"))]
macro_rules! tlog {
    ($($arg:tt)*) => {{}};
}

pub(crate) use tlog;

/// Root-side log sink, served inside the rezygiskd companion process (one
/// thread per connecting app child). Protocol: a native-endian u32 length
/// followed by that many bytes per line; EOF ends the session. Lines are
/// appended to /data/adb/truman/module.log with a 256 KiB rotate-to-`.old`
/// cap, so growth is bounded and the manager's Logs tab can read it through
/// the root shell like the other truman logs. Only compiled into dev builds
/// together with the `truman-log` feature.
#[cfg(feature = "truman-log")]
#[no_mangle]
pub unsafe extern "C" fn zygisk_companion_entry(fd: i32) {
    const LOG_PATH: &str = "/data/adb/truman/module.log";
    const ROTATE_PATH: &str = "/data/adb/truman/module.log.old";
    const MAX_LOG_BYTES: u64 = 256 * 1024;
    const MAX_LINE: usize = 4096;

    let _ = std::fs::create_dir_all("/data/adb/truman");
    if let Ok(meta) = std::fs::metadata(LOG_PATH) {
        if meta.len() > MAX_LOG_BYTES {
            let _ = std::fs::rename(LOG_PATH, ROTATE_PATH);
        }
    }

    let read_full = |buf: &mut [u8]| -> bool {
        let mut filled = 0;
        while filled < buf.len() {
            let n = unsafe { libc::read(fd, buf[filled..].as_mut_ptr().cast(), buf.len() - filled) };
            if n <= 0 {
                return false;
            }
            filled += n as usize;
        }
        true
    };

    loop {
        let mut len_buf = [0u8; 4];
        if !read_full(&mut len_buf) {
            return;
        }
        let len = u32::from_ne_bytes(len_buf) as usize;
        if len == 0 || len > MAX_LINE {
            return;
        }
        let mut buf = vec![0u8; len];
        if !read_full(&mut buf) {
            return;
        }
        let line = String::from_utf8_lossy(&buf);
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(LOG_PATH)
        else {
            return;
        };
        use std::io::Write;
        let _ = writeln!(file, "[{secs}] {line}");
    }
}

/// # Safety
///
/// Called by the loader after `dlopen`/injection: `api` must point at a live
/// `ReZygiskApi` table published by the daemon for this process, and `env`
/// must be the JNI env of the thread making the `nativeForkAndSpecialize` /
/// `nativeSpecializeAppProcess` call. Both are used for the lifetime of the
/// process (the module keeps `api` for later `pre/post` callbacks).
#[no_mangle]
pub unsafe extern "C" fn zygisk_module_entry(api: *mut ReZygiskApi, env: *mut jni::sys::JNIEnv) {
    tlog!("module entry (Phase 7 reflection spoof)");

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
        Some(register) if register(api, &abi) => tlog!("registered (api v5)"),
        _ => tlog!("register_module FAILED — spoof inert this process"),
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
    if let Some(set_option) = (*api).set_option {
        set_option((*api).impl_, DLCLOSE_MODULE_LIBRARY);
    } else {
        tlog!("set_option unavailable — library stays mapped");
    }
}

/// Dev builds: open the root-side log channel while the child still runs
/// with zygote privileges, so no line ever needs the host's logcat buffer.
#[cfg(feature = "truman-log")]
unsafe fn open_log_channel(state: &ModuleState) {
    let api = state.api;
    if !api.is_null() {
        logging::open(api, (*api).impl_);
    }
}

unsafe extern "C" fn pre_app_specialize(impl_: *mut c_void, _args: *mut c_void) {
    let state = &*(impl_ as *const ModuleState);
    #[cfg(feature = "truman-log")]
    open_log_channel(state);
    request_self_unload(state);
}

/// Closes the companion log channel on every exit path of the specialize
/// pass — the one-shot module is about to be dlclosed, and the fd must not
/// outlive it.
#[cfg(feature = "truman-log")]
struct LogChannelGuard;
#[cfg(feature = "truman-log")]
impl Drop for LogChannelGuard {
    fn drop(&mut self) {
        logging::close();
    }
}

unsafe extern "C" fn pre_server_specialize(impl_: *mut c_void, _args: *mut c_void) {
    let state = &*(impl_ as *const ModuleState);
    request_self_unload(state);
}

#[cfg_attr(not(feature = "truman-log"), allow(unused_variables))]
unsafe extern "C" fn post_app_specialize(impl_: *mut c_void, args: *const c_void) {
    #[cfg(feature = "truman-log")]
    let _log_channel = LogChannelGuard;
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

    tlog!("specializing '{pkg}' — applying {} rewrites", entries.len());

    if let Ok(mut env) = unsafe { JNIEnv::from_raw(env_ptr) } {
        for entry in entries {
            if let Err(reason) = jni_glue::apply_entry(&mut env, entry) {
                tlog!("skipped {}.{}: {reason}", entry.class, entry.field);
                if jni_glue::clear_pending(&mut env) {
                    tlog!("pending JNI exception cleared");
                }
            }
        }
        if jni_glue::clear_pending(&mut env) {
            tlog!("pending JNI exception cleared after rewrite pass");
        }
    } else {
        tlog!("JNIEnv::from_raw failed — spoof skipped");
    }
}
