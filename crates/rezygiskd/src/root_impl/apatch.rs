//! Port of root_impl/apatch.c: apd -V gate + package_config CSV.

use std::io;

use rz_common::loge;
use rz_common::is_isolated_service;

use super::super::utils::{dloge, exec_command, TAG};
use super::RootImplState;

const APD_PATH: &str = "/data/adb/apd";
const PACKAGE_CONFIG: &str = "/data/adb/ap/package_config";

#[derive(Debug, Clone)]
struct PackageConfig {
    process: String,
    uid: u32,
    root_granted: bool,
    umount_needed: bool,
}

/// apatch.c `apatch_get_existence`.
pub fn apatch_get_existence() -> RootImplState {
    let cpath = std::ffi::CString::new("/data/adb/ap/bin/apd").unwrap();
    if unsafe { libc::access(cpath.as_ptr(), libc::F_OK) } != 0 {
        return RootImplState::Inexistent;
    }

    let Some(path_env) = std::env::var_os("PATH") else {
        dloge!("Failed to get PATH environment variable");
        return RootImplState::Inexistent;
    };
    if !path_env.to_string_lossy().contains("/data/adb/ap/bin") {
        dloge!("APatch's APD binary is not in PATH");
        return RootImplState::Inexistent;
    }

    let Some(output) = exec_command(APD_PATH, &["apd", "-V"]) else {
        dloge!("Failed to execute apd binary: {}", io::Error::last_os_error());
        return RootImplState::Inexistent;
    };

    // C: atoi(output + strlen("apd "))
    let version_str = output.strip_prefix("apd ").unwrap_or(&output);
    let version: u32 = version_str.trim().parse().unwrap_or(0);

    if version == 0 {
        RootImplState::Abnormal
    } else if (rz_common::MIN_APATCH_VERSION as u32..=999999).contains(&version) {
        RootImplState::Supported
    } else if (1..rz_common::MIN_APATCH_VERSION as u32).contains(&version) {
        RootImplState::TooOld
    } else {
        RootImplState::Abnormal
    }
}

/// apatch.c `_apatch_get_package_config`: CSV of
/// `process,exclude,allow,uid,...` with a header line. Re-read on every query
/// like the C implementation.
fn get_package_config() -> Option<Vec<PackageConfig>> {
    let content = std::fs::read_to_string(PACKAGE_CONFIG).ok()?;
    let mut lines = content.lines();
    lines.next()?; // skip CSV header

    let mut configs = Vec::new();
    for line in lines {
        let mut fields = line.split(',');
        let (Some(process), Some(exclude), Some(allow), Some(uid)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };

        configs.push(PackageConfig {
            process: process.to_string(),
            uid: uid.trim().parse().unwrap_or(0),
            root_granted: allow == "1",
            umount_needed: exclude == "1",
        });
    }

    Some(configs)
}

/// apatch.c `apatch_uid_granted_root`.
pub fn apatch_uid_granted_root(uid: u32) -> bool {
    let Some(configs) = get_package_config() else {
        return false;
    };
    configs.iter().any(|c| c.uid == uid && c.root_granted)
}

/// apatch.c `apatch_uid_should_umount`.
pub fn apatch_uid_should_umount(uid: u32, process: &str) -> bool {
    let Some(configs) = get_package_config() else {
        return false;
    };

    if let Some(c) = configs.iter().find(|c| c.uid == uid) {
        return c.umount_needed;
    }

    // Isolated services have different UIDs than the main app; fall back to
    // process-name prefix matching so they don't slip through as Mounted.
    if is_isolated_service(uid) {
        for c in configs {
            let smallest = process.len().min(c.process.len());
            if process.as_bytes()[..smallest] == c.process.as_bytes()[..smallest] {
                return c.umount_needed;
            }
        }
    }

    false
}

/// apatch.c `apatch_uid_is_manager`.
pub fn apatch_uid_is_manager(uid: u32) -> bool {
    let cpath = std::ffi::CString::new("/data/user_de/0/me.bmax.apatch").unwrap();
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::stat(cpath.as_ptr(), &mut st) } == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOENT) {
            loge!(TAG, "Failed to stat APatch manager data directory: {err}");
        }
        return false;
    }
    st.st_uid as u32 == uid
}
