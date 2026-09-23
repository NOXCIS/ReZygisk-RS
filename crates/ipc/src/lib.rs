//! Wire protocol shared by libzygisk.so, rezygiskd, and zygisk-ptrace.
//!
//! # RS-canonical wire
//! The types in this crate define the protocol. Deliberate divergences from
//! the original C:
//! - Daemon reports use one datagram per message (not per-field writes) —
//!   documented in `action.rs`
//! - Mount-ns fd passed from the daemon instead of `/proc` access — see the
//!   loader's `misc_port::update_mnt_ns`
//!
//! See `docs/CONTRACTS.md` for frozen surfaces.

pub mod action;
pub mod socket;
pub mod stream;

pub use action::{
    build_error_info_message, build_set_info_message, controller_code, parse_error_info,
    parse_set_info, ControllerCode, DaemonSocketAction, MountNamespaceState, ProcessFlags,
    RootImplKind, MAX_MODULES_IN_REPORT,
};
pub use rz_common::{recv_fd, recv_fd_with_payload, send_fd, send_fd_with_payload};
pub use socket::{connect_abstract, datagram_sendto, listen_abstract};
pub use stream::{
    read_exact, read_string, read_string_bounded, read_u8, read_u32, read_usize, write_all,
    write_string, write_u8, write_u32, write_usize, WriteFrame,
};
