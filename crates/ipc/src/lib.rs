//! Wire protocol shared by libzygisk.so, zygiskd and zygisk-ptrace.
//!
//! Everything here must stay byte-compatible with the C fork:
//! - action enum + flags: [out/ReZygisk/zygiskd/src/constants.h](../../../out/ReZygisk/zygiskd/src/constants.h)
//! - client frames: [out/ReZygisk/loader/src/common/daemon.c](../../../out/ReZygisk/loader/src/common/daemon.c)
//! - server frames: [out/ReZygisk/zygiskd/src/zygiskd.c](../../../out/ReZygisk/zygiskd/src/zygiskd.c)
//! - socket helpers: loader/src/common/socket_utils.c and zygiskd/src/utils.c
//!
//! One deliberate exception: the daemon→monitor reports (`DaemonSetInfo` /
//! `DaemonSetErrorInfo`) are **one datagram per message** here instead of the
//! C's one `write()` per field. The C can afford per-field writes because each
//! daemon owns its own *stream* connection; this port reports over a single
//! shared `SOCK_DGRAM` socket, where two daemons reporting at once (boot)
//! interleave their datagrams and desync the reader — which once dispatched a
//! module-count field as a `Stop` command. See `action.rs` for the layout and
//! the monitor's `rezygiskd_listener_callback` for the read side.

pub mod action;
pub mod socket;
pub mod stream;

pub use action::{
    build_error_info_message, build_set_info_message, controller_code, parse_error_info,
    parse_set_info, ControllerCode, DaemonSocketAction, MountNamespaceState, ProcessFlags,
    RootImplKind, MAX_MODULES_IN_REPORT,
};
pub use rz_common::{recv_fd, send_fd};
pub use socket::{connect_abstract, datagram_sendto, listen_abstract};
pub use stream::{
    read_exact, read_string, read_string_bounded, read_u8, read_u32, read_usize, write_all,
    write_string, write_u8, write_u32, write_usize, WriteFrame,
};
