//! Port of root_impl/kernelsu.c: prctl v1 interface + ioctl (new ksuctl) v3.

use std::io;
use std::os::fd::RawFd;

use rz_common::loge;
use rz_ipc::RootImplKind;

use super::super::utils::{dlogi, dlogw, get_property, TAG};
use super::{K_NEXT, K_OFFICIAL, RootImplState};

const KSU_MANAGER_PATHS: [&str; 2] = [
    "/data/user_de/0/me.weishu.kernelsu",
    "/data/user_de/0/com.rifsxd.ksunext",
];

// (int)0xDEADBEEF / (int)0xCAFEBABE
const KSU_INSTALL_MAGIC1: i32 = -559038737;
const KSU_INSTALL_MAGIC2: i32 = -889275714;

const CMD_GET_VERSION: c_ulong = 2;
const CMD_UID_GRANTED_ROOT: c_ulong = 12;
const CMD_UID_SHOULD_UMOUNT: c_ulong = 13;
const CMD_GET_MANAGER_UID: c_ulong = 16;
const CMD_HOOK_MODE: c_ulong = 0xC0DEAD1A;

#[allow(non_camel_case_types)]
type c_ulong = libc::c_ulong;

// _IOC(dir, type, nr, size) — asm-generic layout shared by arm/arm64/x86.
const fn ioc(dir: u32, ty: u8, nr: u8, size: u16) -> u32 {
    (dir << 30) | ((size as u32) << 16) | ((ty as u32) << 8) | nr as u32
}
const _IOC_WRITE: u32 = 1;
const _IOC_READ: u32 = 2;

const KSU_IOCTL_UID_GRANTED_ROOT: u32 = ioc(_IOC_READ | _IOC_WRITE, b'K', 8, 0);
const KSU_IOCTL_UID_SHOULD_UMOUNT: u32 = ioc(_IOC_READ | _IOC_WRITE, b'K', 9, 0);
const KSU_IOCTL_GET_MANAGER_UID: u32 = ioc(_IOC_READ, b'K', 10, 0);
const KSU_IOCTL_SET_FEATURE: u32 = ioc(_IOC_WRITE, b'K', 14, 0);
/// KernelSU-Next specific
const KSU_IOCTL_GET_HOOK_MODE: u32 = ioc(_IOC_READ, b'K', 98, 0);

#[repr(C)]
struct KsuUidGrantedRootCmd {
    uid: u32,
    granted: u8,
}

#[repr(C)]
struct KsuUidShouldUmountCmd {
    uid: u32,
    should_umount: u8,
}

#[repr(C)]
struct KsuGetManagerUidCmd {
    uid: u32,
}

#[repr(C)]
struct KsuSetFeatureCmd {
    feature_id: u32,
    value: u64,
}

#[repr(C)]
struct KsuGetHookModeCmd {
    mode: [u8; 16],
}

struct KsuState {
    variant: u8,
    ksu_fd: RawFd,
    supports_manager_uid_retrieval: bool,
    ksu_uses_new_ksuctl: bool,
}

static KSU: std::sync::Mutex<Option<KsuState>> = std::sync::Mutex::new(None);

/// Cached variant for root_impl.rs (0 = official, 1 = next).
pub fn ksu_variant() -> u8 {
    KSU.lock().unwrap().as_ref().map(|s| s.variant).unwrap_or(K_OFFICIAL)
}

fn init_state() -> KsuState {
    KsuState {
        variant: K_OFFICIAL,
        ksu_fd: -1,
        supports_manager_uid_retrieval: false,
        ksu_uses_new_ksuctl: false,
    }
}

fn with_ksu<T>(f: impl FnOnce(&mut KsuState) -> T) -> Option<T> {
    let mut guard = KSU.lock().unwrap();
    guard.get_or_insert_with(init_state);
    f(guard.as_mut().unwrap()).into()
}

/// kernelsu.c `ksu_get_existence`.
pub fn ksu_get_existence() -> super::RootImplState {
    // On Waydroid the SYS_reboot probe would die on SIGSYS — skip straight
    // to the prctl interface.
    let is_waydroid = get_property("ro.board.platform")
        .map(|p| p == "waydroid")
        .unwrap_or(false);

    if is_waydroid {
        return ksu_probe_prctl();
    }

    // SYS_reboot probe: KernelSU hijacks this call to hand out an fd.
    let mut ksu_fd: i32 = -1;
    unsafe {
        libc::syscall(
            libc::SYS_reboot,
            KSU_INSTALL_MAGIC1 as i64 as libc::c_ulong,
            KSU_INSTALL_MAGIC2 as i64 as libc::c_ulong,
            0 as libc::c_ulong,
            &mut ksu_fd as *mut i32,
        );
    }

    if ksu_fd == -1 {
        return ksu_probe_prctl();
    }

    // KernelSU v3 (ioctl) interface
    if !access_ok("/data/adb/ksu/bin/ksud") {
        dlogw!("KernelSU (ioctl) detected, but ksud not found.");
        return RootImplState::Inexistent;
    }

    with_ksu(|state| {
        state.ksu_fd = ksu_fd;
        state.ksu_uses_new_ksuctl = true;

        // Tell KernelSU to not umount itself; we handle umounts.
        let mut cmd = KsuSetFeatureCmd { feature_id: 1, value: 0 };
        unsafe {
            if libc::ioctl(state.ksu_fd, KSU_IOCTL_SET_FEATURE as _, &mut cmd as *mut KsuSetFeatureCmd) == -1 {
                dlogw!("Failed to ioctl KSU_IOCTL_SET_FEATURE: {}", io::Error::last_os_error());
            }

            let mut hook_mode_cmd = KsuGetHookModeCmd { mode: [0; 16] };
            libc::ioctl(state.ksu_fd, KSU_IOCTL_GET_HOOK_MODE as _, &mut hook_mode_cmd as *mut KsuGetHookModeCmd);
            state.variant = if hook_mode_cmd.mode[0] != 0 { K_NEXT } else { K_OFFICIAL };
        }

        dlogi!("KernelSU root implementation found (v3 ioctl).");
    })
    .expect("ksu state");

    RootImplState::Supported
}

fn access_ok(path: &str) -> bool {
    let cpath = std::ffi::CString::new(path).unwrap();
    unsafe { libc::access(cpath.as_ptr(), libc::F_OK) == 0 }
}

/// prctl v1 probe (also used on Waydroid).
fn ksu_probe_prctl() -> RootImplState {
    let mut version: i32 = 0;
    let mut reply_ok: i32 = 0;

    unsafe {
        libc::prctl(
            KSU_INSTALL_MAGIC1,
            CMD_GET_VERSION,
            &mut version as *mut i32 as libc::c_ulong,
            0 as libc::c_ulong,
            &mut reply_ok as *mut i32 as libc::c_ulong,
        );
    }

    if version == 0 {
        return RootImplState::Abnormal;
    }
    if version < rz_common::MIN_KSU_KERNEL_VERSION as i32 {
        return RootImplState::TooOld;
    }

    // ksud must exist — custom kernels may pre-install KSU while the user
    // runs Magisk.
    if !access_ok("/data/adb/ksu/bin/ksud") {
        dlogw!("KernelSU {version} detected, but ksud not found.");
        return RootImplState::Inexistent;
    }

    with_ksu(|state| {
        let mut mode = [0u8; 16];
        unsafe {
            libc::prctl(
                KSU_INSTALL_MAGIC1,
                CMD_HOOK_MODE,
                mode.as_mut_ptr() as libc::c_ulong,
                0 as libc::c_ulong,
                &mut reply_ok as *mut i32 as libc::c_ulong,
            );
        }
        state.variant = if mode[0] != 0 { K_NEXT } else { K_OFFICIAL };

        // CMD_GET_MANAGER_UID is KernelSU Next's, but not limited to it.
        let mut reply_ok2: i32 = 0;
        unsafe {
            libc::prctl(
                KSU_INSTALL_MAGIC1,
                CMD_GET_MANAGER_UID,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                &mut reply_ok2 as *mut i32 as libc::c_ulong,
            );
        }
        if reply_ok2 == KSU_INSTALL_MAGIC1 {
            dlogi!("KernelSU implementation supports CMD_GET_MANAGER_UID.");
            state.supports_manager_uid_retrieval = true;
        }
    })
    .expect("ksu state");

    RootImplState::Supported
}

/// kernelsu.c `ksu_uid_granted_root`.
pub fn ksu_uid_granted_root(uid: u32) -> bool {
    let uses_new = with_ksu(|s| s.ksu_uses_new_ksuctl).unwrap_or(false);

    if !uses_new {
        let mut granted: bool = false;
        let mut result: u32 = 0;
        unsafe {
            libc::prctl(
                KSU_INSTALL_MAGIC1,
                CMD_UID_GRANTED_ROOT,
                uid as libc::c_ulong,
                &mut granted as *mut bool as libc::c_ulong,
                &mut result as *mut u32 as libc::c_ulong,
            );
        }
        if result as i32 != KSU_INSTALL_MAGIC1 {
            return false;
        }
        return granted;
    }

    let mut cmd = KsuUidGrantedRootCmd { uid, granted: 0 };
    let fd = with_ksu(|s| s.ksu_fd).unwrap_or(-1);
    unsafe {
        if libc::ioctl(fd, KSU_IOCTL_UID_GRANTED_ROOT as _, &mut cmd as *mut KsuUidGrantedRootCmd) == -1 {
            loge!(TAG, "Failed to ioctl KSU_IOCTL_UID_GRANTED_ROOT: {}", io::Error::last_os_error());
            return false;
        }
    }
    cmd.granted != 0
}

/// kernelsu.c `ksu_uid_should_umount`.
pub fn ksu_uid_should_umount(uid: u32) -> bool {
    let uses_new = with_ksu(|s| s.ksu_uses_new_ksuctl).unwrap_or(false);

    if !uses_new {
        let mut should_umount: bool = false;
        let mut result: u32 = 0;
        unsafe {
            libc::prctl(
                KSU_INSTALL_MAGIC1,
                CMD_UID_SHOULD_UMOUNT,
                uid as libc::c_ulong,
                &mut should_umount as *mut bool as libc::c_ulong,
                &mut result as *mut u32 as libc::c_ulong,
            );
        }
        if result as i32 != KSU_INSTALL_MAGIC1 {
            return false;
        }
        return should_umount;
    }

    let mut cmd = KsuUidShouldUmountCmd { uid, should_umount: 0 };
    let fd = with_ksu(|s| s.ksu_fd).unwrap_or(-1);
    unsafe {
        if libc::ioctl(fd, KSU_IOCTL_UID_SHOULD_UMOUNT as _, &mut cmd as *mut KsuUidShouldUmountCmd) == -1 {
            loge!(TAG, "Failed to ioctl KSU_IOCTL_UID_SHOULD_UMOUNT: {}", io::Error::last_os_error());
            return false;
        }
    }
    cmd.should_umount != 0
}

/// kernelsu.c `ksu_uid_is_manager`.
pub fn ksu_uid_is_manager(uid: u32) -> bool {
    let (uses_new, supports_manager_uid, variant) =
        with_ksu(|s| (s.ksu_uses_new_ksuctl, s.supports_manager_uid_retrieval, s.variant))
            .unwrap_or((false, false, K_OFFICIAL));

    if !uses_new {
        if supports_manager_uid {
            let mut manager_uid: u32 = 0;
            let mut reply_ok: i32 = 0;
            unsafe {
                libc::prctl(
                    KSU_INSTALL_MAGIC1,
                    CMD_GET_MANAGER_UID,
                    &mut manager_uid as *mut u32 as libc::c_ulong,
                    0 as libc::c_ulong,
                    &mut reply_ok as *mut i32 as libc::c_ulong,
                );
            }
            return uid == manager_uid;
        }

        let manager_path = KSU_MANAGER_PATHS[variant as usize % KSU_MANAGER_PATHS.len()];
        let cpath = std::ffi::CString::new(manager_path).unwrap();
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::stat(cpath.as_ptr(), &mut st) } == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                loge!(TAG, "Failed to stat KSU manager data directory: {err}");
            }
            return false;
        }
        return st.st_uid as u32 == uid;
    }

    let mut cmd = KsuGetManagerUidCmd { uid: 0 };
    let fd = with_ksu(|s| s.ksu_fd).unwrap_or(-1);
    unsafe {
        if libc::ioctl(fd, KSU_IOCTL_GET_MANAGER_UID as _, &mut cmd as *mut KsuGetManagerUidCmd) == -1 {
            loge!(TAG, "Failed to ioctl KSU_IOCTL_GET_MANAGER_UID: {}", io::Error::last_os_error());
            return false;
        }
    }

    // Private Space UIDs are 10xxxxx; normalize with modulo.
    uid % 100000 == cmd.uid
}

/// kernelsu.c `ksu_cleanup`.
pub fn ksu_cleanup() {
    with_ksu(|s| {
        if s.ksu_fd != -1 {
            unsafe { libc::close(s.ksu_fd) };
            s.ksu_fd = -1;
        }
    });
}

// Keep RootImplKind referenced for parity with C's root_impl kinds.
const _: Option<RootImplKind> = None;
