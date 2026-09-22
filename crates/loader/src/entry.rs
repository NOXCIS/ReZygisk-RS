//! Port of loader/src/injector/entry.c: the `#[no_mangle] extern "C"
//! `entry(addr, size, tango_flag)` export the ptracer calls after injection.
//! Owns the export itself (lib.rs does not).
//!
//! Sets context::{START_ADDR, BLOCK_SIZE}, calls hook_register::hook_functions(),
//! parses the kernel version (rz_common::kversion::KernelVersion), runs
//! ptrace_clear::perform_ptrace_message_clear() on kernel >= 3.8, then checks
//! daemon_client::rezygiskd_zygote_injected(). Returns the hook_functions()
//! status bitmask, like the C.

use std::ffi::c_void;

use rz_common::KernelVersion;

use crate::context;

/// entry.c `LOG_TAG` (zygisk-core32/64 in the C; the RS port uses "zygisk").
pub const TAG: &str = rz_common::LOG_TAG;

/// entry.c `ZKSU_VERSION` (`-DZKSU_VERSION="$(VER_NAME)-$(VER_CODE)-..."`).
const ZKSU_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn entry(addr: *mut c_void, size: usize, tango_flag: i32) -> usize {
    // Self-report before anything else, and logcat-only: if PLT hooking (the
    // 64-bit failure under repair) dies below, the deployed generation is
    // still on record. No manifest cross-check here — the loader runs inside
    // app_process, and its /proc/self/exe is not the module's bin/, so the
    // host script's `assert` is what validates this line.
    //
    // Stays at INFO by design: it is the one line verify_deploy.sh greps for,
    // and it is emitted in the *zygote* (root uid) — invisible to app-side
    // logcat readers.
    rz_common::log_generation(TAG, "loader");

    // Everything from here on is inherited by every app process this zygote
    // forks: drop the floor so the loader cannot fingerprint itself through
    // the app's own logcat buffer (see rz_common::init_app_log_level).
    rz_common::init_app_log_level();

    rz_common::logd!(
        TAG,
        "ReZygisk{} library injected, version {}",
        if tango_flag != 0 { " [TANGO]" } else { "" },
        ZKSU_VERSION
    );

    context::START_ADDR.store(addr as usize, std::sync::atomic::Ordering::Relaxed);
    context::BLOCK_SIZE.store(size, std::sync::atomic::Ordering::Relaxed);

    rz_common::logd!(TAG, "start plt hooking");
    let status = crate::hook_register::hook_functions();

    let version = KernelVersion::current();
    if version.major > 3 || (version.major == 3 && version.minor >= 8) {
        rz_common::logd!(
            TAG,
            "Supported kernel version {}.{}.{}, sending seccomp event",
            version.major,
            version.minor,
            version.patch
        );

        crate::ptrace_clear::perform_ptrace_message_clear();
    }

    if !crate::daemon_client::rezygiskd_zygote_injected() {
        rz_common::loge!(TAG, "ReZygiskd is not running");

        return 0;
    }

    rz_common::logd!(TAG, "Zygisk library execution done, addr: {:p}, size: {}", addr, size);

    status as usize
}
