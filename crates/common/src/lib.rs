//! Shared helpers used by zygiskd, zygisk-ptrace and libzygisk.so:
//! path constants, /proc parsing, kernel version and logging.

pub mod consts;
pub mod fdpass;
pub mod kversion;
pub mod maps;

pub use consts::*;
pub use fdpass::{recv_fd, send_fd};
pub use kversion::KernelVersion;
pub use maps::{parse_maps, parse_maps_line, parse_maps_safe, MapEntry, MapPerms};

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

pub const ANDROID_LOG_VERBOSE: i32 = 2;
pub const ANDROID_LOG_DEBUG: i32 = 3;
pub const ANDROID_LOG_INFO: i32 = 4;
pub const ANDROID_LOG_WARN: i32 = 5;
pub const ANDROID_LOG_ERROR: i32 = 6;
pub const ANDROID_LOG_FATAL: i32 = 7;

#[cfg(target_os = "android")]
pub fn log_write(prio: i32, tag: &str, args: std::fmt::Arguments) {
    use std::ffi::CString;

    let msg = std::fmt::format(args);
    let tag = CString::new(tag).unwrap_or_default();
    let msg = CString::new(msg).unwrap_or_default();
    unsafe {
        __android_log_print(prio, tag.as_ptr(), c"%s".as_ptr(), msg.as_ptr());
    }
}

#[cfg(not(target_os = "android"))]
pub fn log_write(prio: i32, tag: &str, args: std::fmt::Arguments) {
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
