//! Wire protocol shared by libzygisk.so, zygiskd and zygisk-ptrace.
//!
//! Everything here must stay byte-compatible with the C fork:
//! - action enum + flags: [out/ReZygisk/zygiskd/src/constants.h](../../../out/ReZygisk/zygiskd/src/constants.h)
//! - client frames: [out/ReZygisk/loader/src/common/daemon.c](../../../out/ReZygisk/loader/src/common/daemon.c)
//! - server frames: [out/ReZygisk/zygiskd/src/zygiskd.c](../../../out/ReZygisk/zygiskd/src/zygiskd.c)
//! - socket helpers: loader/src/common/socket_utils.c and zygiskd/src/utils.c

pub mod action;
pub mod socket;
pub mod stream;

pub use action::{
    build_error_info_datagrams, build_set_info_datagrams, controller_code,
    ControllerCode, DaemonSocketAction, MountNamespaceState, ProcessFlags, RootImplKind,
};
pub use rz_common::{recv_fd, send_fd};
pub use socket::{connect_abstract, datagram_sendto, listen_abstract};
pub use stream::{
    read_exact, read_string, read_string_bounded, read_u8, read_u32, read_usize, write_all,
    write_string, write_u8, write_u32, write_usize, WriteFrame,
};
