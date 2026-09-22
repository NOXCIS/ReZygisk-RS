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

/// zygiskd.c `zygiskd_start` success report, encoded as **one** datagram:
///
/// ```text
/// [cmd][u32 root_impl_len][root_impl][u32 module_count]([u32 name_len][name])*
/// ```
///
/// Why one datagram instead of the C's one-per-`write()`: the controller
/// socket is `SOCK_DGRAM` and every sender shares it, so two daemons reporting
/// at the same moment — which is exactly what happens at boot — interleave
/// their per-field datagrams, and the monitor's field reads then land on the
/// other sender's bytes. Observed on device: both daemons reported in the same
/// millisecond, the monitor logged `malformed DaemonSetInfo32`, and then
/// dispatched the module-count datagram `[u32 2]` as a *command* — byte 0 is 2
/// = Stop — and paused itself (`Stop tracing requested`, status ⛔) with no
/// user involved. A datagram's boundary is preserved by the kernel, so a
/// single-datagram message cannot interleave with anyone.
///
/// (The C is safe only because each daemon wrote to its own *stream*
/// connection; see `recv_datagram` in the monitor for the read side.)
pub fn build_set_info_message(impl_name: &str, module_names: &[&str]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + impl_name.len() + 4 + module_names.len() * 8);
    out.push(controller_code(ControllerCode::DaemonSetInfo));
    out.extend_from_slice(&(impl_name.len() as u32).to_ne_bytes());
    out.extend_from_slice(impl_name.as_bytes());
    out.extend_from_slice(&(module_names.len() as u32).to_ne_bytes());

    for name in module_names {
        out.extend_from_slice(&(name.len() as u32).to_ne_bytes());
        out.extend_from_slice(name.as_bytes());
    }

    out
}

/// zygiskd.c error path report (unknown/multiple root impl), one datagram:
/// `[cmd][u32 msg_len][msg]`.
pub fn build_error_info_message(msg: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 4 + msg.len());
    out.push(controller_code(ControllerCode::DaemonSetErrorInfo));
    out.extend_from_slice(&(msg.len() as u32).to_ne_bytes());
    out.extend_from_slice(msg.as_bytes());

    out
}

/// Upper bound accepted for a report's module count, mirroring the monitor's
/// `MAX_MODULES`, so a corrupt length cannot make the reader allocate wildly.
pub const MAX_MODULES_IN_REPORT: usize = 4096;

/// Strict decoder for [`build_set_info_message`]'s payload — the datagram with
/// its command byte already stripped.
///
/// Strict on purpose: truncated fields, an implausible module count and
/// trailing bytes are all rejected, so neither a desynced sender nor a stray
/// datagram can be mistaken for a valid report.
pub fn parse_set_info(payload: &[u8]) -> Option<(String, Vec<String>)> {
    let mut cur = payload;
    let root_impl = read_str_field(&mut cur)?;
    let count = read_u32(&mut cur)? as usize;
    if count > MAX_MODULES_IN_REPORT {
        return None;
    }

    let mut modules = Vec::with_capacity(count);
    for _ in 0..count {
        modules.push(read_str_field(&mut cur)?);
    }

    if !cur.is_empty() {
        return None;
    }

    Some((root_impl, modules))
}

/// Strict decoder for [`build_error_info_message`]'s payload.
pub fn parse_error_info(payload: &[u8]) -> Option<String> {
    let mut cur = payload;
    let msg = read_str_field(&mut cur)?;
    if !cur.is_empty() {
        return None;
    }

    Some(msg)
}

fn read_u32(cur: &mut &[u8]) -> Option<u32> {
    if cur.len() < 4 {
        return None;
    }

    let (head, rest) = cur.split_at(4);
    *cur = rest;

    Some(u32::from_ne_bytes([head[0], head[1], head[2], head[3]]))
}

fn read_str_field(cur: &mut &[u8]) -> Option<String> {
    let len = read_u32(cur)? as usize;
    if len > cur.len() {
        return None;
    }

    let (head, rest) = cur.split_at(len);
    *cur = rest;

    Some(String::from_utf8_lossy(head).into_owned())
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
    fn set_info_message_single_datagram_golden() {
        // One datagram: anything longer would interleave with the other
        // daemon's report and desync the monitor (see build_set_info_message).
        let msg = build_set_info_message("KernelSU", &["truman", "playintegrityfix"]);

        let mut want = vec![controller_code(ControllerCode::DaemonSetInfo)];
        want.extend_from_slice(&8u32.to_ne_bytes());
        want.extend_from_slice(b"KernelSU");
        want.extend_from_slice(&2u32.to_ne_bytes());
        want.extend_from_slice(&6u32.to_ne_bytes());
        want.extend_from_slice(b"truman");
        want.extend_from_slice(&16u32.to_ne_bytes());
        want.extend_from_slice(b"playintegrityfix");

        assert_eq!(msg, want);
    }

    #[test]
    fn set_info_round_trips() {
        let names = ["truman", "playintegrityfix"];
        let msg = build_set_info_message("KernelSU", &names);
        let (root, modules) = parse_set_info(&msg[1..]).expect("round trip");
        assert_eq!(root, "KernelSU");
        assert_eq!(modules, names);
    }

    #[test]
    fn set_info_parser_rejects_malformed_payloads() {
        let msg = build_set_info_message("KernelSU", &["truman"]);

        // Truncated at every prefix length: none may parse.
        assert!(parse_set_info(&[]).is_none());
        for cut in 1..msg.len() {
            assert!(parse_set_info(&msg[1..cut]).is_none(), "cut {cut} parsed");
        }

        // Trailing garbage (the shape a desynced sender produces).
        let mut trailing = msg[1..].to_vec();
        trailing.push(0);
        assert!(parse_set_info(&trailing).is_none());

        // Implausible module count.
        let mut huge = vec![0u8; 8];
        huge[0..4].copy_from_slice(&8u32.to_ne_bytes());
        huge[4..8].copy_from_slice(&(MAX_MODULES_IN_REPORT as u32 + 1).to_ne_bytes());
        assert!(parse_set_info(&huge).is_none());
    }

    #[test]
    fn error_info_message_golden() {
        let msg = "Unsupported environment: Unknown root implementation";
        let frame = build_error_info_message(msg);

        let mut want = vec![controller_code(ControllerCode::DaemonSetErrorInfo)];
        want.extend_from_slice(&(msg.len() as u32).to_ne_bytes());
        want.extend_from_slice(msg.as_bytes());

        assert_eq!(frame, want);
        assert_eq!(parse_error_info(&frame[1..]).as_deref(), Some(msg));
        assert!(parse_error_info(&frame[1..frame.len() - 1]).is_none());
    }
}
