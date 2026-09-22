//! Shared helpers used by zygiskd, zygisk-ptrace and libzygisk.so:
//! path constants, /proc parsing, kernel version, logging and RAII wrappers.

pub mod consts;
pub mod fdpass;
pub mod generation;
pub mod kversion;
pub mod maps;
pub mod owned_fd;

pub use consts::*;
pub use fdpass::{recv_fd, recv_fd_with_payload, send_fd, send_fd_with_payload};
pub use generation::{
    abi_label, generation_line, log_generation, log_generation_and_check, manifest_generation, manifest_path,
    DeploymentCheck, RZ_GENERATION, RZ_GENERATION_BANNER,
};
pub use kversion::KernelVersion;
pub use maps::{parse_maps, parse_maps_line, parse_maps_safe, MapEntry, MapPerms};
pub use owned_fd::OwnedFd;

/// Mirrors C `LP_SELECT(lp32, lp64)` (loader/src/include/misc.h): picks the
/// first argument on 32-bit builds, the second on 64-bit builds.
#[macro_export]
macro_rules! lp_select {
    ($lp32:expr, $lp64:expr) => {
        if cfg!(target_pointer_width = "64") { $lp64 } else { $lp32 }
    };
}

/// `IS_ISOLATED_SERVICE(uid)` from misc.h.
#[inline]
pub fn is_isolated_service(uid: u32) -> bool {
    (90000..1000000).contains(&uid)
}

// ---------------------------------------------------------------------------
// Logging: __android_log_print on Android, stderr elsewhere (host tests).
// ---------------------------------------------------------------------------

/// Central logcat tags, build-time selectable via the `stealth-tag` feature.
/// The defaults match the C reference ("zygisk*" — C parity, and any
/// logcat-scanning tooling keeps working); the stealth build swaps in
/// neutral tags so a log grep cannot fingerprint the framework.
#[cfg(not(feature = "stealth-tag"))]
pub const LOG_TAG: &str = "zygisk";
#[cfg(feature = "stealth-tag")]
pub const LOG_TAG: &str = "core";

#[cfg(not(feature = "stealth-tag"))]
pub const LOG_TAG_TRACER: &str = if cfg!(target_pointer_width = "64") {
    "zygisk-ptrace64"
} else {
    "zygisk-ptrace32"
};
#[cfg(feature = "stealth-tag")]
pub const LOG_TAG_TRACER: &str = if cfg!(target_pointer_width = "64") {
    "core-trace64"
} else {
    "core-trace32"
};

#[cfg(not(feature = "stealth-tag"))]
pub const LOG_TAG_DAEMON: &str = if cfg!(target_pointer_width = "64") {
    "zygiskd64"
} else {
    "zygiskd32"
};
#[cfg(feature = "stealth-tag")]
pub const LOG_TAG_DAEMON: &str = if cfg!(target_pointer_width = "64") {
    "cored64"
} else {
    "cored32"
};

pub const ANDROID_LOG_VERBOSE: i32 = 2;
pub const ANDROID_LOG_DEBUG: i32 = 3;
pub const ANDROID_LOG_INFO: i32 = 4;
pub const ANDROID_LOG_WARN: i32 = 5;
pub const ANDROID_LOG_ERROR: i32 = 6;
pub const ANDROID_LOG_FATAL: i32 = 7;
/// Not a liblog level: a floor above FATAL, so `log_write` drops every line.
pub const ANDROID_LOG_SILENT: i32 = 8;

/// Central runtime log floor. Defaults to DEBUG (historical behavior); the
/// daemons raise it to WARN when `$TMP_PATH/.quiet` exists (stealth: fewer
/// identifying lines in logcat) or drop it to VERBOSE with `.verbose`.
static MAX_LOG_LEVEL: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(ANDROID_LOG_DEBUG);

/// Apply the `.quiet` / `.verbose` flag files in `$TMP_PATH`, once at daemon
/// startup. Fail-soft: absence of both keeps the default level.
///
/// Deliberately *not* used by the injected loader: `$TMP_PATH` sits in
/// `/data/adb`, which neither the zygote nor an app process may stat — the
/// attempt itself would leave an `avc: denied` trail that is a root-tool
/// fingerprint. The loader's floor is build-time (see `init_app_log_level`).
pub fn init_log_level_from_flags() {
    use std::sync::atomic::Ordering;

    let quiet = std::path::Path::new(TMP_PATH).join(".quiet");
    let verbose = std::path::Path::new(TMP_PATH).join(".verbose");
    if quiet.exists() {
        MAX_LOG_LEVEL.store(ANDROID_LOG_WARN, Ordering::Relaxed);
    } else if verbose.exists() {
        MAX_LOG_LEVEL.store(ANDROID_LOG_VERBOSE, Ordering::Relaxed);
    }
}

/// Log floor for the injected loader (`libzygisk.so`), which ends up running
/// inside app processes.
///
/// logd hands an app only the entries its own uid wrote, so every line the
/// loader prints while running as an app is readable by that app — and by any
/// integrity scanner that greps its own logcat for framework tags (the Duck
/// Detector LSPosed slice flags the `zygisk` tag prefix exactly this way).
/// `MAX_LOG_LEVEL` is one static per process and every `fork` copies it, so
/// this single call in the zygote-side `entry` is what the whole boot's app
/// processes inherit.
///
/// Default ERROR: real failures stay visible, running commentary does not.
/// `loud-loader` (build-time, same mechanism as `stealth-tag`) restores the
/// full trace for bring-up work.
pub fn init_app_log_level() {
    use std::sync::atomic::Ordering;

    let level = if cfg!(feature = "loud-loader") {
        ANDROID_LOG_VERBOSE
    } else {
        ANDROID_LOG_ERROR
    };
    MAX_LOG_LEVEL.store(level, Ordering::Relaxed);
}

#[cfg(target_os = "android")]
pub fn log_write(prio: i32, tag: &str, args: std::fmt::Arguments) {
    use std::ffi::CString;
    use std::sync::atomic::Ordering;

    if prio < MAX_LOG_LEVEL.load(Ordering::Relaxed) {
        return;
    }

    let msg = std::fmt::format(args);
    let tag = CString::new(tag).unwrap_or_default();
    let msg = CString::new(msg).unwrap_or_default();
    unsafe {
        __android_log_print(prio, tag.as_ptr(), c"%s".as_ptr(), msg.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
pub fn log_write(prio: i32, tag: &str, args: std::fmt::Arguments) {
    use std::sync::atomic::Ordering;

    if prio < MAX_LOG_LEVEL.load(Ordering::Relaxed) {
        return;
    }

    let name = match prio {
        ANDROID_LOG_VERBOSE => "V",
        ANDROID_LOG_DEBUG => "D",
        ANDROID_LOG_INFO => "I",
        ANDROID_LOG_WARN => "W",
        ANDROID_LOG_ERROR => "E",
        ANDROID_LOG_FATAL => "F",
        _ => "?",
    };
    eprintln!("[{name}/{tag}] {}", args);
}

#[cfg(target_os = "android")]
unsafe extern "C" {
    fn __android_log_print(prio: i32, tag: *const libc::c_char, fmt: *const libc::c_char, ...) -> i32;
}

#[macro_export]
macro_rules! logd {
    ($tag:expr, $($arg:tt)*) => { $crate::log_write($crate::ANDROID_LOG_DEBUG, $tag, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! logv {
    ($tag:expr, $($arg:tt)*) => { $crate::log_write($crate::ANDROID_LOG_VERBOSE, $tag, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! logi {
    ($tag:expr, $($arg:tt)*) => { $crate::log_write($crate::ANDROID_LOG_INFO, $tag, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! logw {
    ($tag:expr, $($arg:tt)*) => { $crate::log_write($crate::ANDROID_LOG_WARN, $tag, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! loge {
    ($tag:expr, $($arg:tt)*) => { $crate::log_write($crate::ANDROID_LOG_ERROR, $tag, format_args!($($arg)*)) };
}
#[macro_export]
macro_rules! logf {
    ($tag:expr, $($arg:tt)*) => { $crate::log_write($crate::ANDROID_LOG_FATAL, $tag, format_args!($($arg)*)) };
}

/// `PLOGE(fmt, ...)` equivalent: logs the message then appends errno + strerror.
#[macro_export]
macro_rules! plog {
    ($tag:expr, $($arg:tt)*) => {{
        let err = std::io::Error::last_os_error();
        $crate::log_write($crate::ANDROID_LOG_ERROR, $tag, format_args!($($arg)*));
        $crate::log_write($crate::ANDROID_LOG_ERROR, $tag, format_args!(" failed with {}: {}", err.raw_os_error().unwrap_or(0), err));
    }};
}

// ---------------------------------------------------------------------------
// Boot-safe stdio
// ---------------------------------------------------------------------------

/// Daemon-mode binaries must never keep (or block on) the module-script
/// stdout/stderr pipes: the C reference never writes there, but the RS ports
/// emit `println!` diagnostics. Attaching them to `$TMP_PATH/verbose.log`
/// instead keeps a durable per-boot trace (readable from recovery) and leaves
/// the script pipe free to reach EOF.
pub fn redirect_stdio_to_log(tag: &str) {
    use std::ffi::CString;

    let _ = std::fs::create_dir_all(TMP_PATH);
    let cpath = CString::new(format!("{TMP_PATH}/verbose.log")).unwrap_or_default();
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND, 0o666) };
    if fd < 0 {
        // Never keep the module-script stdout pipe: ksud reads it to EOF and
        // a wedged script stalls the boot. Fall back to /dev/null for the
        // println! diagnostics, but say so on logd first — losing the
        // durable trace silently is exactly what makes postmortems
        // impossible.
        log_write(
            ANDROID_LOG_ERROR,
            tag,
            format_args!("cannot open {TMP_PATH}/verbose.log, stdio diagnostics fall back to /dev/null: {}", std::io::Error::last_os_error()),
        );
        let null_fd = unsafe {
            libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_WRONLY)
        };
        if null_fd >= 0 {
            unsafe {
                libc::dup2(null_fd, 1);
                libc::dup2(null_fd, 2);
                if null_fd > 2 {
                    libc::close(null_fd);
                }
            }
        }
        return;
    }

    unsafe {
        libc::dup2(fd, 1);
        libc::dup2(fd, 2);
        if fd > 2 {
            libc::close(fd);
        }
    }

    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!("=== [{tag}] pid={} epoch={epoch} stdio redirected ===", unsafe { libc::getpid() });
}
