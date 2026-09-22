//! Port of root_impl/magisk.c: magisk binary probing + --sqlite queries.

use std::io;
use std::sync::Mutex;

use rz_common::{loge, PROCESS_NAME_MAX_LEN};

use super::super::utils::{dloge, exec_command, TAG};
use super::RootImplState;

const SBIN_MAGISK: &str = if cfg!(target_pointer_width = "64") {
    "/sbin/magisk64"
} else {
    "/sbin/magisk32"
};
const BITLESS_SBIN_MAGISK: &str = "/sbin/magisk";
const DEBUG_RAMDISK_MAGISK: &str = if cfg!(target_pointer_width = "64") {
    "/debug_ramdisk/magisk64"
} else {
    "/debug_ramdisk/magisk32"
};
const BITLESS_DEBUG_RAMDISK_MAGISK: &str = "/debug_ramdisk/magisk";

static PATH_TO_MAGISK: Mutex<Option<String>> = Mutex::new(None);

fn path_to_magisk() -> Option<String> {
    PATH_TO_MAGISK.lock().unwrap().clone()
}

/// magisk.c `magisk_get_existence`.
pub fn magisk_get_existence() -> RootImplState {
    let candidates = [
        SBIN_MAGISK,
        BITLESS_SBIN_MAGISK,
        DEBUG_RAMDISK_MAGISK,
        BITLESS_DEBUG_RAMDISK_MAGISK,
    ];

    let mut found: Option<String> = None;
    for candidate in candidates {
        let cpath = std::ffi::CString::new(candidate).unwrap();
        if unsafe { libc::access(cpath.as_ptr(), libc::F_OK) } == 0 {
            found = Some(candidate.to_string());
            break;
        }
    }

    let Some(path) = found else {
        return RootImplState::Inexistent;
    };

    *PATH_TO_MAGISK.lock().unwrap() = Some(path.clone());

    let Some(output) = exec_command(&path, &["magisk", "-V"]) else {
        dloge!("Failed to execute magisk binary: {}", io::Error::last_os_error());
        return RootImplState::Abnormal;
    };

    // C: atoi(output) — parse the leading integer.
    let digits: String = output
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let version: u64 = digits.parse().unwrap_or(0);

    if version >= rz_common::MIN_MAGISK_VERSION {
        RootImplState::Supported
    } else {
        RootImplState::TooOld
    }
}

/// magisk.c `magisk_uid_granted_root`.
pub fn magisk_uid_granted_root(uid: u32) -> bool {
    let Some(path) = path_to_magisk() else {
        return false;
    };

    let sqlite_cmd = format!("select 1 from policies where uid={uid} and policy=2 limit 1");

    let Some(result) = exec_command(&path, &["magisk", "--sqlite", &sqlite_cmd]) else {
        loge!(TAG, "Failed to execute magisk binary: {}", io::Error::last_os_error());
        return false;
    };

    !result.is_empty()
}

/// magisk.c `magisk_uid_should_umount`.
pub fn magisk_uid_should_umount(process: &str) -> bool {
    let Some(path) = path_to_magisk() else {
        return false;
    };

    // Match if the process string starts with any "process" column value.
    let _ = PROCESS_NAME_MAX_LEN;
    let sqlite_cmd =
        format!("SELECT 1 FROM denylist WHERE \"{process}\" LIKE process || '%' LIMIT 1");

    let Some(result) = exec_command(&path, &["magisk", "--sqlite", &sqlite_cmd]) else {
        loge!(TAG, "Failed to execute magisk binary: {}", io::Error::last_os_error());
        return false;
    };

    !result.is_empty()
}

/// magisk.c `magisk_uid_is_manager`.
pub fn magisk_uid_is_manager(uid: u32) -> bool {
    let Some(path) = path_to_magisk() else {
        return false;
    };

    let Some(output) = exec_command(
        &path,
        &["magisk", "--sqlite", "select value from strings where key=\"requester\" limit 1"],
    ) else {
        loge!(TAG, "Failed to execute magisk binary: {}", io::Error::last_os_error());
        return false;
    };

    let mut stat_path = "/data/user_de/0/com.topjohnwu.magisk".to_string();
    if !output.is_empty() {
        // magisk.c 104-105: C unconditionally skips strlen("value=") = 6
        // bytes of the sqlite output ("value=<package>").
        stat_path = format!("/data/user_de/0/{}", output.get(6..).unwrap_or(""));
    }

    let cpath = std::ffi::CString::new(stat_path).unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(cpath.as_ptr(), &mut st) } == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOENT) {
            loge!(TAG, "Failed to stat {}: {err}", cpath.to_string_lossy());
        }
        return false;
    }

    st.st_uid as u32 == uid
}
