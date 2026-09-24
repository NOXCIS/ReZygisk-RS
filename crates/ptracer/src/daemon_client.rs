//! Port of loader/src/common/daemon.c (client side, subset used by the
//! ptracer CLI): daemon connection, info query, zygote restart.

use rz_common::{loge, logw, plog};
use rz_ipc::{read_u32, read_usize, write_u8};

use crate::utils::TAG;

const CP_SOCKET_NAME: &str = rz_common::cp_socket_abstract_name();

/// daemon.c `rezygiskd_connect`.
pub fn rezygiskd_connect(retry: u8) -> Option<i32> {
    match rz_ipc::connect_abstract(CP_SOCKET_NAME, retry) {
        Ok(fd) => Some(fd),
        Err(e) => {
            if e.raw_os_error() == Some(libc::ENOENT) {
                logw!(TAG, "Failed to connect, socket nonexistent (ReZygiskd not running?)");
            } else {
                plog!(TAG, "connection to ReZygiskd");
            }
            None
        }
    }
}

/// daemon.h `enum root_impl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootImpl {
    None,
    Apatch,
    KernelSU,
    Magisk,
}

/// daemon.c `rezygiskd_get_info` (display names resolved from module.prop).
pub fn rezygiskd_get_info() -> Option<(RootImpl, i32, Vec<String>)> {
    let fd = rezygiskd_connect(1)?;
    let running = true;

    macro_rules! bail {
        () => {{
            unsafe { libc::close(fd) };
            return None;
        }};
    }

    if write_u8(fd, rz_ipc::DaemonSocketAction::GetInfo as u8).is_err() {
        bail!();
    }

    let flags = match read_u32(fd) {
        Ok(v) => v,
        Err(_) => bail!(),
    };

    let root_impl = if flags & (1 << 28) != 0 {
        RootImpl::Apatch
    } else if flags & (1 << 29) != 0 {
        RootImpl::KernelSU
    } else if flags & (1 << 30) != 0 {
        RootImpl::Magisk
    } else {
        RootImpl::None
    };

    let pid = match read_u32(fd) {
        Ok(v) => v as i32,
        Err(_) => bail!(),
    };

    let count = match read_usize(fd) {
        Ok(v) => v,
        Err(_) => bail!(),
    };

    let mut modules = Vec::new();
    for _ in 0..count {
        let module_name = match rz_ipc::read_string(fd) {
            Ok(v) => v,
            Err(_) => bail!(),
        };

        let module_path = format!("{}/{module_name}/module.prop", rz_common::PATH_MODULES_DIR);
        let Some(prop) = std::fs::read_to_string(&module_path).ok() else {
            loge!(TAG, "failed to open module prop file {module_path}");
            bail!();
        };

        let mut display: Option<String> = None;
        for line in prop.split_inclusive('\n') {
            let Some(name) = line.strip_prefix("name=") else {
                continue;
            };

            if name.is_empty() || !name.ends_with('\n') {
                loge!(TAG, "Invalid module name in {module_path}");
                bail!();
            }

            display = Some(name[..name.len() - 1].to_string());
            break;
        }

        match display {
            Some(name) => modules.push(name),
            None => {
                loge!(TAG, "failed to read module name from {module_path}");
                bail!();
            }
        }
    }

    unsafe { libc::close(fd) };
    let _ = running;

    Some((root_impl, pid, modules))
}

/// daemon.c `rezygiskd_zygote_restart`.
pub fn rezygiskd_zygote_restart() {
    let Some(fd) = rezygiskd_connect(1) else {
        return;
    };

    if rz_ipc::write_u8(fd, rz_ipc::DaemonSocketAction::ZygoteRestart as u8).is_err() {
        logw!(TAG, "Failed to write ZygoteRestart action");
    }

    unsafe { libc::close(fd) };
}

/// Truman extension: drop the daemon's cached clean/mounted mount-namespace
/// fds so the next UpdateMountNamespace re-snapshots instead of serving the
/// boot-time snapshot (called from ksud's recapture/arm after republish).
pub fn rezygiskd_invalidate_clean_ns() -> bool {
    let Some(fd) = rezygiskd_connect(1) else {
        return false;
    };

    let ok = rz_ipc::write_u8(fd, rz_ipc::DaemonSocketAction::InvalidateCleanNs as u8).is_ok();
    if !ok {
        logw!(TAG, "Failed to write InvalidateCleanNs action");
    }

    unsafe { libc::close(fd) };

    ok
}
