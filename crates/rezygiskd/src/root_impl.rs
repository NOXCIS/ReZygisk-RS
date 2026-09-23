//! Port of zygiskd/src/root_impl/: KernelSU (prctl v1 + ioctl v3), APatch
//! (apd -V + package_config CSV) and Magisk (magisk --sqlite) backends.

pub mod apatch;
pub mod kernelsu;
pub mod magisk;

use std::sync::Mutex;

use rz_ipc::RootImplKind;

use super::utils::dlogi;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootImplState {
    Supported,
    TooOld,
    Inexistent,
    Abnormal,
}

/// kernelsu.h variant codes.
pub const K_OFFICIAL: u8 = 0;
pub const K_NEXT: u8 = 1;

/// common.h `struct root_impl` — impl kind plus KernelSU variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootImpl {
    pub kind: RootImplKind,
    /// 0 = KOfficial, 1 = KNext (only meaningful when kind == KernelSU)
    pub variant: u8,
}

/// common.c: the outcome of `root_impls_setup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupKind {
    None,
    Multiple,
    Single(RootImpl),
}

static SETUP: Mutex<Option<SetupKind>> = Mutex::new(None);

/// common.c `root_impls_setup`: probe all three backends exactly once and
/// cache the result (the probes have side effects — KSU fd creation, feature
/// writes — so they must not be repeated).
pub fn root_impls_setup() -> SetupKind {
    if let Some(kind) = *SETUP.lock().unwrap() {
        return kind;
    }

    let state_ksu = kernelsu::ksu_get_existence();
    let state_apatch = apatch::apatch_get_existence();
    let state_magisk = magisk::magisk_get_existence();

    let supported_count = [state_ksu, state_apatch, state_magisk]
        .iter()
        .filter(|s| **s == RootImplState::Supported)
        .count();

    let kind = if supported_count >= 2 {
        dlogi!("Multiple root implementations found.");
        SetupKind::Multiple
    } else if state_ksu == RootImplState::Supported {
        dlogi!("KernelSU root implementation found.");
        SetupKind::Single(RootImpl { kind: RootImplKind::KernelSU, variant: kernelsu::ksu_variant() })
    } else if state_apatch == RootImplState::Supported {
        dlogi!("APatch root implementation found.");
        SetupKind::Single(RootImpl { kind: RootImplKind::APatch, variant: 0 })
    } else if state_magisk == RootImplState::Supported {
        dlogi!("Magisk root implementation found.");
        SetupKind::Single(RootImpl { kind: RootImplKind::Magisk, variant: 0 })
    } else {
        dlogi!("No root implementation found.");
        SetupKind::None
    };

    *SETUP.lock().unwrap() = Some(kind);
    kind
}

fn get_impl() -> RootImpl {
    let setup = SETUP.lock().unwrap();
    match *setup {
        Some(SetupKind::Single(impl_)) => impl_,
        _ => RootImpl { kind: RootImplKind::None, variant: 0 },
    }
}

pub fn stringify_root_impl_name(impl_: RootImpl) -> &'static str {
    match impl_.kind {
        RootImplKind::KernelSU => {
            if impl_.variant == K_NEXT {
                "KernelSU Next"
            } else {
                "KernelSU"
            }
        }
        RootImplKind::APatch => "APatch",
        RootImplKind::Magisk => "Magisk",
        RootImplKind::None => "None",
    }
}

pub fn uid_granted_root(uid: u32) -> bool {
    match get_impl().kind {
        RootImplKind::KernelSU => kernelsu::ksu_uid_granted_root(uid),
        RootImplKind::APatch => apatch::apatch_uid_granted_root(uid),
        RootImplKind::Magisk => magisk::magisk_uid_granted_root(uid),
        _ => false,
    }
}

pub fn uid_should_umount(uid: u32, process: &str) -> bool {
    match get_impl().kind {
        RootImplKind::KernelSU => kernelsu::ksu_uid_should_umount(uid),
        RootImplKind::APatch => apatch::apatch_uid_should_umount(uid, process),
        RootImplKind::Magisk => magisk::magisk_uid_should_umount(process),
        _ => false,
    }
}

pub fn uid_is_manager(uid: u32) -> bool {
    match get_impl().kind {
        RootImplKind::KernelSU => kernelsu::ksu_uid_is_manager(uid),
        RootImplKind::APatch => apatch::apatch_uid_is_manager(uid),
        RootImplKind::Magisk => magisk::magisk_uid_is_manager(uid),
        _ => false,
    }
}

pub fn root_impl_cleanup() {
    if get_impl().kind == RootImplKind::KernelSU {
        kernelsu::ksu_cleanup();
    }
}
