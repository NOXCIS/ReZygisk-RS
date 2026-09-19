//! Action enum, process flags and controller datagram codes.
//! Byte-for-byte mirror of zygiskd/src/constants.h and loader daemon.h.

use bitflags::bitflags;

/// `enum DaemonSocketAction` (constants.h) — discriminants are on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DaemonSocketAction {
    ZygoteInjected = 0,
    GetProcessFlags = 1,
    GetInfo = 2,
    ReadModules = 3,
    RequestCompanionSocket = 4,
    GetModuleDir = 5,
    ZygoteRestart = 6,
    UpdateMountNamespace = 7,
    RemoveModule = 8,
}

impl TryFrom<u8> for DaemonSocketAction {
    type Error = u8;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Ok(match v {
            0 => Self::ZygoteInjected,
            1 => Self::GetProcessFlags,
            2 => Self::GetInfo,
            3 => Self::ReadModules,
            4 => Self::RequestCompanionSocket,
            5 => Self::GetModuleDir,
            6 => Self::ZygoteRestart,
            7 => Self::UpdateMountNamespace,
            8 => Self::RemoveModule,
            other => return Err(other),
        })
    }
}

bitflags! {
    /// `enum ProcessFlags: uint32_t` (constants.h). u32 on the wire.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ProcessFlags: u32 {
        const GRANTED_ROOT = 1 << 0;
        const ON_DENYLIST = 1 << 1;
        const IS_MANAGER = 1 << 27;
        const ROOT_IS_APATCH = 1 << 28;
        const ROOT_IS_KSU = 1 << 29;
        const ROOT_IS_MAGISK = 1 << 30;
        const IS_FIRST_STARTED = 1 << 31;
    }
}

/// `enum MountNamespaceState` (constants.h) — u8 on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MountNamespaceState {
    Clean = 0,
    Mounted = 1,
}

impl TryFrom<u8> for MountNamespaceState {
    type Error = u8;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        Ok(match v {
            0 => Self::Clean,
            1 => Self::Mounted,
            other => return Err(other),
        })
    }
}

/// Root implementation reported by the daemon (daemon.h `enum root_impl`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootImplKind {
    None,
    APatch,
    KernelSU,
    Magisk,
}

impl RootImplKind {
    /// Bit used in GetInfo / GetProcessFlags responses (constants.h flags).
    pub fn flag_bit(self) -> ProcessFlags {
        match self {
            Self::APatch => ProcessFlags::ROOT_IS_APATCH,
            Self::KernelSU => ProcessFlags::ROOT_IS_KSU,
            Self::Magisk => ProcessFlags::ROOT_IS_MAGISK,
            Self::None => ProcessFlags::empty(),
        }
    }

    /// zygiskd.c `stringify_root_impl_name` (KernelSU Next variant name is
    /// decided by the impl, see root_impl).
    pub fn display_name(self) -> &'static str {
        match self {
            Self::None => "None",
            Self::APatch => "APatch",
            Self::KernelSU => "KernelSU",
            Self::Magisk => "Magisk",
        }
    }
}

/// Controller datagram codes (constants.h `ZYGOTE_INJECTED`,
/// `DAEMON_SET_INFO`, `DAEMON_SET_ERROR_INFO`), which are LP_SELECT'ed per
/// bitness so the monitor can tell the 32/64 daemon reports apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ControllerCode {
    ZygoteInjected,
    DaemonSetInfo,
    DaemonSetErrorInfo,
}

pub fn controller_code(code: ControllerCode) -> u8 {
    match code {
        ControllerCode::ZygoteInjected => lp_code(5, 4),
        ControllerCode::DaemonSetInfo => lp_code(7, 6),
        ControllerCode::DaemonSetErrorInfo => lp_code(9, 8),
    }
}

const fn lp_code(on_32: u8, on_64: u8) -> u8 {
    if cfg!(target_pointer_width = "64") { on_64 } else { on_32 }
}

/// zygiskd.c `zygiskd_start` success report: the sequence of datagrams sent
/// to the controller socket. Each element is one sendto() datagram.
pub fn build_set_info_datagrams(impl_name: &str, module_names: &[&str]) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(3 + module_names.len());
    out.push(vec![controller_code(ControllerCode::DaemonSetInfo)]);

    let mut name_frame = (impl_name.len() as u32).to_ne_bytes().to_vec();
    name_frame.extend_from_slice(impl_name.as_bytes());
    out.push(name_frame);

    out.push((module_names.len() as u32).to_ne_bytes().to_vec());

    for name in module_names {
        let mut frame = (name.len() as u32).to_ne_bytes().to_vec();
        frame.extend_from_slice(name.as_bytes());
        out.push(frame);
    }

    out
}

/// zygiskd.c error path report (unknown/multiple root impl).
pub fn build_error_info_datagrams(msg: &str) -> Vec<Vec<u8>> {
    vec![
        vec![controller_code(ControllerCode::DaemonSetErrorInfo)],
        {
            let mut frame = (msg.len() as u32).to_ne_bytes().to_vec();
            frame.extend_from_slice(msg.as_bytes());
            frame
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_discriminants_match_c() {
        for (v, a) in [
            (0u8, DaemonSocketAction::ZygoteInjected),
            (1, DaemonSocketAction::GetProcessFlags),
            (2, DaemonSocketAction::GetInfo),
            (3, DaemonSocketAction::ReadModules),
            (4, DaemonSocketAction::RequestCompanionSocket),
            (5, DaemonSocketAction::GetModuleDir),
            (6, DaemonSocketAction::ZygoteRestart),
            (7, DaemonSocketAction::UpdateMountNamespace),
            (8, DaemonSocketAction::RemoveModule),
        ] {
            assert_eq!(a as u8, v);
            assert_eq!(DaemonSocketAction::try_from(v).unwrap(), a);
        }
        assert!(DaemonSocketAction::try_from(9).is_err());
    }

    #[test]
    fn flag_bits_match_c() {
        assert_eq!(ProcessFlags::GRANTED_ROOT.bits(), 1);
        assert_eq!(ProcessFlags::ON_DENYLIST.bits(), 2);
        assert_eq!(ProcessFlags::IS_MANAGER.bits(), 1 << 27);
        assert_eq!(ProcessFlags::ROOT_IS_APATCH.bits(), 1 << 28);
        assert_eq!(ProcessFlags::ROOT_IS_KSU.bits(), 1 << 29);
        assert_eq!(ProcessFlags::ROOT_IS_MAGISK.bits(), 1 << 30);
        assert_eq!(ProcessFlags::IS_FIRST_STARTED.bits(), 1u32 << 31);
    }

    #[test]
    fn controller_codes_lp_select() {
        let (injected, info, err) = if cfg!(target_pointer_width = "64") { (4, 6, 8) } else { (5, 7, 9) };
        assert_eq!(controller_code(ControllerCode::ZygoteInjected), injected);
        assert_eq!(controller_code(ControllerCode::DaemonSetInfo), info);
        assert_eq!(controller_code(ControllerCode::DaemonSetErrorInfo), err);
    }

    #[test]
    fn set_info_datagrams_golden() {
        let frames = build_set_info_datagrams("KernelSU", &["truman", "playintegrityfix"]);
        assert_eq!(frames.len(), 5);

        assert_eq!(frames[0], vec![controller_code(ControllerCode::DaemonSetInfo)]);

        // u32 length prefix + name (controller protocol uses uint32_t).
        let mut expected_impl = 8u32.to_ne_bytes().to_vec();
        expected_impl.extend_from_slice(b"KernelSU");
        assert_eq!(frames[1], expected_impl);

        assert_eq!(frames[2], 2u32.to_ne_bytes().to_vec());

        let mut expected_m0 = 6u32.to_ne_bytes().to_vec();
        expected_m0.extend_from_slice(b"truman");
        assert_eq!(frames[3], expected_m0);

        let mut expected_m1 = 16u32.to_ne_bytes().to_vec();
        expected_m1.extend_from_slice(b"playintegrityfix");
        assert_eq!(frames[4], expected_m1);
    }

    #[test]
    fn error_info_datagrams_golden() {
        let frames = build_error_info_datagrams("Unsupported environment: Unknown root implementation");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], vec![controller_code(ControllerCode::DaemonSetErrorInfo)]);
        let len = "Unsupported environment: Unknown root implementation".len() as u32;
        let mut expected = len.to_ne_bytes().to_vec();
        expected.extend_from_slice(b"Unsupported environment: Unknown root implementation");
        assert_eq!(frames[1], expected);
    }
}
