//! Client side of the ReZygiskd cp socket protocol — port of
//! loader/src/common/daemon.c and its `include/daemon.h`.
//!
//! Wire format (daemon.c is authoritative): every call opens a fresh
//! connection to the abstract-namespace socket
//! `rz_common::cp_socket_abstract_name()` ("rezygisk-cp32"/"rezygisk-cp64"),
//! writes one `DaemonSocketAction` byte, then per-action frames. Integers are
//! native-endian fixed-size (socket_utils.c), strings are a `size_t` length
//! prefix + raw bytes without NUL, and fds travel as SCM_RIGHTS on a
//! 1-byte payload (`rz_common::recv_fd`).
//!
//! C-parity notes:
//! - `rezygiskd_connect(retry)` performs exactly `retry` attempts (the C's
//!   `retry++; while (--retry)` loop). After a failed attempt it logs
//!   "retrying..." and sleeps 1s only when another attempt remains (the C's
//!   `if (retry)` guard — daemon.c 45-49), so the final failure is silent and
//!   returns immediately. It does NOT use rz_ipc::connect_abstract, which
//!   performs exactly `retry` attempts with a 1s sleep only between
//!   attempts but does not emit the "retrying..." log (callers log instead).
//! - `PLOGE` sites use the workspace `plog!` macro, reading
//!   `io::Error::last_os_error()` exactly where the C reads the errno
//!   global (the macro emits the C's one "msg failed with %d: %s" line as
//!   two log lines — the established RS convention).

use rz_common::{logd, loge, logi, plog};
use rz_ipc::{
    read_string, read_u8, read_u32, read_usize, recv_fd, recv_fd_with_payload, write_string,
    write_u8, write_u32, write_usize, DaemonSocketAction, MountNamespaceState, ProcessFlags,
    RootImplKind,
};

/// daemon.c `LOG_TAG` ("zygisk" in the RS port).
const TAG: &str = rz_common::LOG_TAG;

/// daemon.h `CP_SOCKET_ABSTRACT_NAME` — abstract-namespace cp socket.
const CP_SOCKET_NAME: &str = rz_common::cp_socket_abstract_name();

/// daemon.h `struct zygisk_modules` (`modules` + `modules_count` + `fds`).
pub struct ZygiskModules {
    pub modules: Vec<String>,
    /// Raw SCM_RIGHTS fds backing the `/proc/self/fd/N` paths in `modules`;
    /// kept open until the libs are loaded.
    pub fds: Vec<i32>,
}

/// daemon.h `struct rezygisk_info`.
pub struct ReZygiskInfo {
    pub modules: ZygiskModules,
    /// daemon.h `enum root_impl`.
    pub root_impl: RootImplKind,
    pub pid: i32,
    pub running: bool,
}

/// daemon.c `safe_write`: on write failure, log, close and return.
macro_rules! safe_write {
    ($fd:expr, $write:expr, $name:expr, $ret:expr) => {
        if $write.is_err() {
            loge!(TAG, "Failed to write {} to ReZygiskd", $name);
            unsafe { libc::close($fd) };
            return $ret;
        }
    };
}

/// daemon.c `safe_read`: on read failure, log, close and return.
macro_rules! safe_read {
    ($fd:expr, $read:expr, $name:expr, $ret:expr) => {
        match $read {
            Ok(v) => v,
            Err(_) => {
                loge!(TAG, "Failed to read {} from ReZygiskd", $name);
                unsafe { libc::close($fd) };
                return $ret;
            }
        }
    };
}

/// daemon.c `rezygiskd_connect`: abstract-namespace connect with exactly
/// `retry` attempts; log + 1s sleep only when a retry remains after a
/// failure (the C's `if (retry)` guard skips both on the final attempt).
pub fn rezygiskd_connect(retry: u8) -> i32 {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    // Abstract namespace: sun_path[0] stays NUL, the name follows.
    let name = CP_SOCKET_NAME.as_bytes();
    let dst = unsafe { std::slice::from_raw_parts_mut(addr.sun_path.as_mut_ptr() as *mut u8, 108) };
    dst[1..1 + name.len()].copy_from_slice(name);
    // offsetof(sun_path) == 2 (u16 family) + 1 (leading NUL) + name.
    let socklen = (2 + 1 + name.len()) as libc::socklen_t;

    // C 31-32: retry++; while (--retry) — exactly `retry` attempts in total.
    let mut attempts = retry as u32;
    while attempts > 0 {
        attempts -= 1;

        let fd = unsafe { libc::socket(libc::PF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        if fd == -1 {
            plog!(TAG, "socket create");

            return -1;
        }

        let ret = unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), socklen) };
        if ret == 0 {
            return fd;
        }

        unsafe { libc::close(fd) };

        // daemon.c 45-49: the log + 1s sleep sit inside `if (retry)` — they
        // happen only when another attempt remains, never after the final
        // failure. `attempts` here is the C's post-decrement `retry`.
        if attempts > 0 {
            plog!(TAG, "Failed to connect to ReZygiskd, retrying...");

            unsafe { libc::sleep(1) };
        }
    }

    -1
}

/// daemon.c `rezygiskd_zygote_injected`: fire-and-forget ZygoteInjected.
pub fn rezygiskd_zygote_injected() -> bool {    let fd = rezygiskd_connect(5);
    if fd == -1 {
        plog!(TAG, "connection to ReZygiskd");

        return false;
    }

    safe_write!(fd, write_u8(fd, DaemonSocketAction::ZygoteInjected as u8), "ZygoteInjected action", false);

    unsafe { libc::close(fd) };

    true
}

/// daemon.c `rezygiskd_get_process_flags`: uid + process name in, flags out.
pub fn rezygiskd_get_process_flags(uid: u32, process: &str) -> u32 {
    let fd = rezygiskd_connect(1);
    if fd == -1 {
        plog!(TAG, "connection to ReZygiskd");

        return 0;
    }

    safe_write!(fd, write_u8(fd, DaemonSocketAction::GetProcessFlags as u8), "GetProcessFlags action", 0);
    safe_write!(fd, write_u32(fd, uid), "uid", 0);
    safe_write!(fd, write_string(fd, process), "process name", 0);

    let res = safe_read!(fd, read_u32(fd), "process flags", 0);

    unsafe { libc::close(fd) };

    res
}

/// daemon.c `rezygiskd_get_info`: flags/pid + per-module display names read
/// from each module's `/data/adb/modules/<name>/module.prop` `name=` line.
pub fn rezygiskd_get_info(info: &mut ReZygiskInfo) {
    let fd = rezygiskd_connect(1);
    if fd == -1 {
        plog!(TAG, "connection to ReZygiskd");

        info.running = false;

        return;
    }

    info.running = true;
    info.modules.fds.clear(); // C: info->modules.fds = NULL

    safe_write!(fd, write_u8(fd, DaemonSocketAction::GetInfo as u8), "GetInfo action", ());

    let flags: u32 = safe_read!(fd, read_u32(fd), "info flags", ());
    info.root_impl = if flags & ProcessFlags::ROOT_IS_APATCH.bits() != 0 {
        RootImplKind::APatch
    } else if flags & ProcessFlags::ROOT_IS_KSU.bits() != 0 {
        RootImplKind::KernelSU
    } else if flags & ProcessFlags::ROOT_IS_MAGISK.bits() != 0 {
        RootImplKind::Magisk
    } else {
        RootImplKind::None
    };

    info.pid = safe_read!(fd, read_u32(fd), "pid", ()) as i32;

    let count = safe_read!(fd, read_usize(fd), "modules count", ());
    if count == 0 {
        info.modules.modules.clear(); // C: info->modules.modules = NULL

        unsafe { libc::close(fd) };

        return;
    }

    // C: modules = malloc(count * sizeof(char *)). A failed malloc logs and
    // bails (info_cleanup); try_reserve_exact reproduces that fail-soft path
    // instead of aborting the zygote on a daemon-supplied garbage count.
    if info.modules.modules.try_reserve_exact(count).is_err() {
        loge!(TAG, "Failed to allocate memory for modules");

        unsafe { libc::close(fd) };

        return;
    }

    'outer: for _ in 0..count {
        let module_name = match read_string(fd) {
            Ok(v) => v,
            Err(_) => {
                plog!(TAG, "reading module name");

                info.modules.modules.clear();

                break 'outer; // info_cleanup
            }
        };

        let module_path = format!("{}/{}/module.prop", rz_common::PATH_MODULES_DIR, module_name);

        let prop = match std::fs::File::open(&module_path) {
            Ok(f) => f,
            Err(_) => {
                plog!(TAG, "failed to open module prop file {}", module_path);

                info.modules.modules.clear();

                break 'outer;
            }
        };

        let mut display: Option<String> = None;
        let mut reader = std::io::BufReader::new(prop);
        while let Some(line) = fgets_1024(&mut reader) {
            let Some(rest) = line.strip_prefix("name=") else {
                continue;
            };

            // C: name_len == 0 || line[name_len + 4] != '\n' (the last byte
            // of the line must be the newline; fgets truncates at 1023 so a
            // longer line cannot pass either).
            if rest.is_empty() || !rest.ends_with('\n') {
                loge!(TAG, "Invalid module name in {}", module_path);

                info.modules.modules.clear();

                break 'outer;
            }

            display = Some(rest[..rest.len() - 1].to_string());

            break;
        }

        match display {
            Some(name) => info.modules.modules.push(name),
            None => {
                plog!(TAG, "failed to read module name from {}", module_path);

                info.modules.modules.clear();

                break 'outer;
            }
        }
    }

    unsafe { libc::close(fd) };
}

/// daemon.c `free_rezygisk_info`. The C does not touch `modules.fds` here
/// (get_info always NULLs it) — mirrored.
pub fn free_rezygisk_info(info: &mut ReZygiskInfo) {
    info.modules.modules.clear();
}

/// daemon.c `rezygiskd_read_modules`: module count + per-module
/// (path string, SCM_RIGHTS fd); paths are rewritten to /proc/self/fd/N.
pub fn rezygiskd_read_modules(modules: &mut ZygiskModules) -> bool {
    let fd = rezygiskd_connect(1);
    if fd == -1 {
        plog!(TAG, "connection to ReZygiskd");

        return false;
    }

    safe_write!(fd, write_u8(fd, DaemonSocketAction::ReadModules as u8), "ReadModules action", false);

    // Fail-soft deadline: never block the zygote on a hung/stale broker
    // (e.g. a stock daemon that does not send fds).
    let timeout = libc::timeval { tv_sec: 1, tv_usec: 0 };
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast::<libc::c_void>(),
            size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    modules.fds.clear(); // C: modules->fds = NULL

    let len = safe_read!(fd, read_usize(fd), "modules count", false);

    // C mallocs both arrays (with OOM error paths that log and bail);
    // try_reserve_exact keeps that fail-soft bail instead of aborting the
    // zygote on a daemon-supplied garbage count.
    if modules.modules.try_reserve_exact(len).is_err()
        || modules.fds.try_reserve_exact(len).is_err()
    {
        plog!(TAG, "allocating module arrays");

        unsafe { libc::close(fd) };

        return false;
    }

    for i in 0..len {
        let lib_path = match read_string(fd) {
            Ok(v) => v,
            Err(_) => {
                plog!(TAG, "reading module lib_path");

                free_modules(modules);

                unsafe { libc::close(fd) };

                return false;
            }
        };

        let lib_fd = read_fd_c(fd);
        if lib_fd < 0 {
            plog!(TAG, "reading module lib fd (no SCM_RIGHTS from daemon?)");

            free_modules(modules);

            unsafe { libc::close(fd) };

            return false;
        }

        logi!(TAG, "ReadModules[{i}]: path={lib_path} fd={lib_fd}");

        // L2 conversion: replace the daemon-sent path with the received fd's
        // /proc/self/fd/N form so csoloader re-opens the fd instead of
        // walking /data/adb/modules/<name>/... (the fd path is strictly
        // shorter, so C reuses the buffer in place).
        let buf_size = lib_path.len() + 1;
        let fd_path = format!("/proc/self/fd/{lib_fd}");
        let written = fd_path.len() as i32;

        logi!(TAG, "ReadModules[{i}]: fd path written={written} buf={buf_size} -> {fd_path}");

        modules.modules.push(fd_path);
        modules.fds.push(lib_fd);
    }

    unsafe { libc::close(fd) };

    true
}

/// daemon.c `free_modules`: drop the names and close the backing fds.
pub fn free_modules(modules: &mut ZygiskModules) {
    modules.modules.clear();

    for fd in modules.fds.drain(..) {
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
    }
}

/// daemon.c `rezygiskd_connect_companion`: returns the open socket fd on
/// success (u8 reply == 1), -1 otherwise.
pub fn rezygiskd_connect_companion(index: usize) -> i32 {
    let fd = rezygiskd_connect(1);
    if fd == -1 {
        plog!(TAG, "connection to ReZygiskd");

        return -1;
    }

    safe_write!(fd, write_u8(fd, DaemonSocketAction::RequestCompanionSocket as u8), "RequestCompanionSocket action", -1);
    safe_write!(fd, write_usize(fd, index), "companion index", -1);

    let res = safe_read!(fd, read_u8(fd), "companion socket result", -1);

    if res == 1 {
        fd
    } else {
        unsafe { libc::close(fd) };

        -1
    }
}

/// daemon.c `rezygiskd_get_module_dir`: receive the module dir fd over
/// SCM_RIGHTS (-1 on failure, like the C).
pub fn rezygiskd_get_module_dir(index: usize) -> i32 {
    let fd = rezygiskd_connect(1);
    if fd == -1 {
        plog!(TAG, "connection to ReZygiskd");

        return -1;
    }

    safe_write!(fd, write_u8(fd, DaemonSocketAction::GetModuleDir as u8), "GetModuleDir action", -1);
    safe_write!(fd, write_usize(fd, index), "module index", -1);

    let dirfd = read_fd_c(fd);

    unsafe { libc::close(fd) };

    dirfd
}

/// daemon.c `rezygiskd_zygote_restart` (including the C's ENOENT wording
/// quirk: "Failed to connect to connect, ...").
pub fn rezygiskd_zygote_restart() {
    let fd = rezygiskd_connect(1);
    if fd == -1 {
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            logd!(TAG, "Failed to connect to connect, file nonexistent (ReZygiskd not running?)");
        } else {
            plog!(TAG, "connection to ReZygiskd");
        }

        return;
    }

    safe_write!(fd, write_u8(fd, DaemonSocketAction::ZygoteRestart as u8), "ZygoteRestart action", ());

    unsafe { libc::close(fd) };
}

/// daemon.c `rezygiskd_update_mns`: report the mount namespace state, get
/// the target `/proc/<pid>/fd/<fd>` path back (snprintf semantics into buf).
///
/// RS extension over the C reply: the daemon also attaches the namespace fd
/// itself as `SCM_RIGHTS`, and `ns_fd_out` receives it (`-1` when absent).
/// The path is still filled in either way, so two peers that disagree about
/// the extension both work — the fd is an optimization the caller may ignore,
/// not a replacement framing:
/// - a daemon that predates it (or a stock C `rezygiskd`) sends only the two
///   integers and the non-blocking receive reports "nothing queued", which the
///   caller answers with the C's own `/proc/<pid>/fd/<n>` open;
/// - our callers against a C daemon behave exactly like the C loader did.
pub fn rezygiskd_update_mns(
    nms_state: MountNamespaceState,
    buf: &mut [u8],
    buf_size: usize,
    ns_fd_out: &mut i32,
) -> bool {
    *ns_fd_out = -1;

    let fd = rezygiskd_connect(1);
    if fd == -1 {
        plog!(TAG, "connection to ReZygiskd");

        return false;
    }

    safe_write!(fd, write_u8(fd, DaemonSocketAction::UpdateMountNamespace as u8), "UpdateMountNamespace action", false);
    safe_write!(fd, write_u32(fd, unsafe { libc::getpid() } as u32), "pid", false);
    safe_write!(fd, write_u8(fd, nms_state as u8), "mount namespace state", false);

    let target_pid = match read_u32_capture_fd(fd, ns_fd_out) {
        Ok(v) => v,
        Err(_) => {
            loge!(TAG, "Failed to read target pid from ReZygiskd");

            unsafe { libc::close(fd) };

            return false;
        }
    };

    let target_fd = match read_u32_capture_fd(fd, ns_fd_out) {
        Ok(v) => v,
        Err(_) => {
            loge!(TAG, "Failed to read target fd from ReZygiskd");

            unsafe { libc::close(fd) };

            release_captured_fd(ns_fd_out);

            return false;
        }
    };

    if target_fd == 0 {
        loge!(TAG, "Failed to get target fd");

        unsafe { libc::close(fd) };

        release_captured_fd(ns_fd_out);

        return false;
    }

    // C: snprintf(buf, buf_size, "/proc/%u/fd/%u", target_pid, target_fd) —
    // at most buf_size - 1 bytes + NUL.
    let path = format!("/proc/{target_pid}/fd/{target_fd}");
    let n = path
        .len()
        .min(buf_size.saturating_sub(1))
        .min(buf.len().saturating_sub(1));
    buf[..n].copy_from_slice(&path.as_bytes()[..n]);
    if n < buf.len() {
        buf[n] = 0;
    }

    unsafe { libc::close(fd) };

    true
}

/// `read_u32` that also collects an fd from the same message.
///
/// The daemon attaches its mount-namespace fd to one of the two words in this
/// reply (see `rezygiskd_update_mns`), so both reads have to offer a control
/// buffer: a plain `read` would let the kernel drop the ancillary data on the
/// floor, and which word carries it is an implementation detail of the sender
/// rather than something this side should assume. `slot` holds the first fd
/// seen; a second one cannot legitimately appear, so it is closed instead of
/// being leaked or silently replacing the first.
fn read_u32_capture_fd(fd: i32, slot: &mut i32) -> std::io::Result<u32> {
    let mut buf = [0u8; 4];
    if let Some(received) = recv_fd_with_payload(fd, &mut buf)? {
        if *slot >= 0 {
            unsafe { libc::close(received) };
        } else {
            *slot = received;
        }
    }

    Ok(u32::from_ne_bytes(buf))
}

/// Drop an fd captured before the request turned out to be unusable.
fn release_captured_fd(slot: &mut i32) {
    if *slot >= 0 {
        unsafe { libc::close(*slot) };
        *slot = -1;
    }
}

/// daemon.c `rezygiskd_remove_module`: u8 reply == 1 means removed.
pub fn rezygiskd_remove_module(index: usize) -> bool {
    let fd = rezygiskd_connect(1);
    if fd == -1 {
        plog!(TAG, "connection to ReZygiskd");

        return false;
    }

    safe_write!(fd, write_u8(fd, DaemonSocketAction::RemoveModule as u8), "RemoveModule action", false);
    safe_write!(fd, write_usize(fd, index), "module index", false);

    let res = safe_read!(fd, read_u8(fd), "remove module result", false);

    unsafe { libc::close(fd) };

    res == 1
}

/// socket_utils.c `read_fd`: SCM_RIGHTS on a 1-byte payload, with the C's
/// two error messages (-1 on failure).
fn read_fd_c(fd: i32) -> i32 {
    match recv_fd(fd) {
        Ok(f) => f,
        Err(e) => {
            match e.kind() {
                // C treats recvmsg EOF / missing cmsg as "no valid fd"
                // (read_fd scans the cmsgs and bails with this message).
                std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::InvalidData => {
                    loge!(TAG, "Failed to receive fd: No valid fd found in ancillary data.");
                }
                _ => plog!(TAG, "recvmsg"),
            }

            -1
        }
    }
}

/// `fgets(line, sizeof(line) = 1024, f)` for the module.prop parsing in
/// rezygiskd_get_info: up to 1023 bytes or until '\n'. None at EOF/error
/// (fgets returns NULL on both, so the C does not distinguish either).
fn fgets_1024(reader: &mut impl std::io::BufRead) -> Option<String> {
    let mut line = Vec::with_capacity(128);
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).ok()?;
        if n == 0 {
            if line.is_empty() {
                return None;
            }

            break;
        }

        line.push(byte[0]);

        if byte[0] == b'\n' || line.len() == 1023 {
            break;
        }
    }

    Some(String::from_utf8_lossy(&line).into_owned())
}
