//! Port of zygiskd/src/utils.c: mount-ns switching, SELinux sockcreate dance,
//! controller datagram send, exec helpers, mountinfo parsing / umount.

use std::io;
use std::os::fd::RawFd;
use std::sync::Mutex;

use rz_common::plog;

pub const TAG: &str = rz_common::LOG_TAG_DAEMON;

/// utils.h LOGx macros write to logcat AND stdout.
macro_rules! dlogi {
    ($($arg:tt)*) => {{ rz_common::logi!(crate::utils::TAG, $($arg)*); println!($($arg)*); }};
}
macro_rules! dlogw {
    ($($arg:tt)*) => {{ rz_common::logw!(crate::utils::TAG, $($arg)*); println!($($arg)*); }};
}
macro_rules! dloge {
    ($($arg:tt)*) => {{ rz_common::loge!(crate::utils::TAG, $($arg)*); println!($($arg)*); }};
}
pub(crate) use {dlogi, dlogw, dloge};

/// utils.c `switch_mount_namespace`.
pub fn switch_mount_namespace(pid: i32) -> bool {
    let path = std::ffi::CString::new(format!("/proc/{pid}/ns/mnt")).unwrap();
    let nsfd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if nsfd == -1 {
        plog!(TAG, "Failed to open nsfd");
        return false;
    }

    if unsafe { libc::setns(nsfd, libc::CLONE_NEWNS) } == -1 {
        plog!(TAG, "Failed to setns");
        unsafe { libc::close(nsfd) };
        return false;
    }

    unsafe { libc::close(nsfd) };
    true
}

/// utils.c `get_property` via __system_property_get.
pub fn get_property(name: &str) -> Option<String> {
    #[cfg(target_os = "android")]
    unsafe {
        unsafe extern "C" {
            fn __system_property_get(name: *const libc::c_char, value: *mut libc::c_char) -> libc::c_int;
        }
        let cname = std::ffi::CString::new(name).ok()?;
        let mut buf = [0 as libc::c_char; 92]; // PROP_VALUE_MAX
        let len = __system_property_get(cname.as_ptr(), buf.as_mut_ptr());
        if len <= 0 {
            return None;
        }
        let bytes: Vec<u8> = buf.iter().copied().map(|c| c as u8).take_while(|&c| c != 0).take(len as usize).collect();
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = name;
        None
    }
}

/// utils.c `set_socket_create_context`.
pub fn set_socket_create_context(context: &str) {
    let write_to = |path: &std::ffi::CString| -> bool {
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_WRONLY) };
        if fd == -1 {
            return false;
        }
        let ret = unsafe { libc::write(fd, context.as_ptr() as *const libc::c_void, context.len()) };
        unsafe { libc::close(fd) };
        ret == context.len() as isize
    };

    if write_to(&std::ffi::CString::new("/proc/thread-self/attr/sockcreate").unwrap()) {
        return;
    }

    let path = std::ffi::CString::new(format!(
        "/proc/self/task/{}/attr/sockcreate",
        unsafe { libc::gettid() }
    ))
    .unwrap();
    if !write_to(&path) {
        dloge!("Failed to set socket create context");
    }
}

fn get_current_attr() -> Option<String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open("/proc/self/attr/current").ok()?.read_to_end(&mut bytes).ok()?;
    let s = String::from_utf8_lossy(&bytes);
    let trimmed = s.trim_end_matches(['\n', '\0']).to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

/// utils.c `unix_datagram_sendto`: keeps the socket in the daemon's own
/// context by re-writing sockcreate before/after (the L2 fork dropped the
/// sock_file/chcon approach for filesystem sockets, keeping this dance).
pub fn unix_datagram_sendto(path: &str, buf: &[u8]) {
    let Some(current_attr) = get_current_attr() else {
        dloge!("Failed to get current attribute");
        return;
    };

    set_socket_create_context(&current_attr);

    let result = rz_ipc::datagram_sendto(path, buf);

    set_socket_create_context("u:r:zygote:s0");

    if let Err(e) = result {
        match e.raw_os_error() {
            Some(libc::EPIPE) | Some(libc::ENOENT) | Some(libc::ECONNREFUSED) => {
                // Controller socket not up yet — same as C, silently dropped
                // by callers; log only at the call sites that care.
                dlogw!("sendto {}: {}", path, e);
            }
            _ => {
                dloge!("sendto {}: {}", path, e);
            }
        }
    }
}

/// utils.c `exec_command`: run `file` with `argv`, capture stdout into a
/// bounded string (last byte truncated like C's `buf[nbytes - 1] = '\0'`).
pub fn exec_command(file: &str, argv: &[&str]) -> Option<String> {
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
        plog!(TAG, "pipe");
        return None;
    }

    let pid = unsafe { libc::fork() };
    if pid == -1 {
        plog!(TAG, "fork");
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
        return None;
    }

    if pid == 0 {
        unsafe {
            libc::dup2(fds[1], libc::STDOUT_FILENO);
            libc::close(fds[0]);
            libc::close(fds[1]);

            let cfile = std::ffi::CString::new(file).unwrap();
            let cargs: Vec<std::ffi::CString> =
                argv.iter().map(|s| std::ffi::CString::new(*s).unwrap()).collect();
            let mut argp: Vec<*const libc::c_char> =
                cargs.iter().map(|c| c.as_ptr()).collect();
            argp.push(std::ptr::null());
            libc::execv(cfile.as_ptr(), argp.as_ptr() as *const *const libc::c_char);

            dloge!("execv failed: {}", io::Error::last_os_error());
            libc::_exit(1);
        }
    }

    unsafe {
        libc::close(fds[1]);
        let mut buf = vec![0u8; 4096];
        let n = loop {
            let n = libc::read(fds[0], buf.as_mut_ptr() as _, buf.len());
            if n == -1 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                libc::close(fds[0]);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
                return None;
            }
            break n as usize;
        };
        libc::close(fds[0]);
        libc::waitpid(pid, std::ptr::null_mut(), 0);

        buf.truncate(n);
        if !buf.is_empty() {
            // C replaces the last byte read with '\0' (drops trailing '\n').
            buf.pop();
        }
        while buf.last() == Some(&b'\0') {
            buf.pop();
        }
        Some(String::from_utf8_lossy(&buf).into_owned())
    }
}

/// utils.c `check_unix_socket`: poll(2) POLLIN with 0ms (non-block) or
/// infinite (block) timeout; false when error events are pending.
pub fn check_unix_socket(fd: RawFd, block: bool) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let timeout = if block { -1 } else { 0 };
    if unsafe { libc::poll(&mut pfd, 1, timeout) } == -1 {
        dloge!("poll: {}", io::Error::last_os_error());
        return false;
    }
    pfd.revents & !libc::POLLIN == 0
}

/// utils.c `non_blocking_execv`: fork+exec with stdout redirected into a
/// pipe whose read end is returned.
#[allow(dead_code)]
pub fn non_blocking_execv(file: &str, argv: &[&str]) -> Option<RawFd> {
    let mut fds = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
        plog!(TAG, "pipe");
        return None;
    }

    let pid = unsafe { libc::fork() };
    if pid == -1 {
        plog!(TAG, "fork");
        return None;
    }

    if pid == 0 {
        unsafe {
            libc::dup2(fds[1], libc::STDOUT_FILENO);
            libc::close(fds[0]);
            libc::close(fds[1]);

            let cfile = std::ffi::CString::new(file).unwrap();
            let cargs: Vec<std::ffi::CString> =
                argv.iter().map(|s| std::ffi::CString::new(*s).unwrap()).collect();
            let mut argp: Vec<*const libc::c_char> =
                cargs.iter().map(|c| c.as_ptr()).collect();
            argp.push(std::ptr::null());
            libc::execv(cfile.as_ptr(), argp.as_ptr() as *const *const libc::c_char);
            libc::_exit(1);
        }
    }

    unsafe { libc::close(fds[1]) };
    Some(fds[0])
}

// ---------------------------------------------------------------------------
// mountinfo parsing + denylist umount
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
#[allow(dead_code)]
pub struct MountInfo {
    pub id: u32,
    pub parent: u32,
    pub device: (u32, u32),
    pub root: String,
    pub target: String,
    pub vfs_option: String,
    pub shared: u32,
    pub master: u32,
    pub propagate_from: u32,
    pub fs_type: String,
    pub source: String,
    pub fs_option: String,
}

/// utils.c `parse_mountinfo`.
pub fn parse_mountinfo(pid: &str) -> Option<Vec<MountInfo>> {
    let content = std::fs::read_to_string(format!("/proc/{pid}/mountinfo")).ok()?;

    let mut mounts = Vec::new();
    for line in content.lines() {
        let mut it = line.split_whitespace();
        let id: u32 = it.next()?.parse().ok()?;
        let parent: u32 = it.next()?.parse().ok()?;
        let dev = it.next()?;
        let (maj, min) = dev.split_once(':')?;
        let (maj, min) = (maj.parse().ok()?, min.parse().ok()?);
        let root = it.next()?.to_string();
        let target = it.next()?.to_string();
        let vfs_option = it.next()?.to_string();

        // Optional fields until " - "
        let (mut shared, mut master, mut propagate_from) = (0, 0, 0);
        for field in it.by_ref() {
            if field == "-" {
                break;
            }
            if let Some(v) = field.strip_prefix("shared:") {
                shared = v.parse().unwrap_or(0);
            } else if let Some(v) = field.strip_prefix("master:") {
                master = v.parse().unwrap_or(0);
            } else if let Some(v) = field.strip_prefix("propagate_from:") {
                propagate_from = v.parse().unwrap_or(0);
            }
        }

        let fs_type = it.next()?.to_string();
        let source = it.next().unwrap_or("").to_string();
        let fs_option = it.next().unwrap_or("").to_string();

        mounts.push(MountInfo {
            id,
            parent,
            device: (maj, min),
            root,
            target,
            vfs_option,
            shared,
            master,
            propagate_from,
            fs_type,
            source,
            fs_option,
        });
    }

    Some(mounts)
}

/// utils.c `umount_root`: unmount everything the current root implementation
/// mounted into this (already-switched) mount namespace.
pub fn umount_root(kind: rz_ipc::RootImplKind) -> bool {
    let Some(mounts) = parse_mountinfo("self") else {
        dloge!("Failed to parse mountinfo");
        return false;
    };

    let source_name = match kind {
        rz_ipc::RootImplKind::KernelSU => "KSU",
        rz_ipc::RootImplKind::APatch => "APatch",
        _ => "magisk",
    };

    dlogi!("[{source_name}] Unmounting root");

    let mut targets = Vec::new();
    for mount in &mounts {
        let mut should_unmount = false;
        if mount.source == source_name || (kind == rz_ipc::RootImplKind::Magisk && mount.source == "worker") {
            should_unmount = true;
        }
        if mount.target.starts_with("/data/adb/modules") {
            should_unmount = true;
        }
        if mount.root.starts_with("/adb/modules/") {
            should_unmount = true;
        }

        if should_unmount {
            targets.push(mount.target.clone());
        }
    }

    for target in targets.iter().rev() {
        let ctarget = std::ffi::CString::new(target.as_str()).unwrap();
        if unsafe { libc::umount2(ctarget.as_ptr(), libc::MNT_DETACH) } == -1 {
            dloge!("[{source_name}] Failed to unmount {target}: {}", io::Error::last_os_error());
            continue;
        }
        dlogi!("[{source_name}] Unmounted {target}");
    }

    true
}

// ---------------------------------------------------------------------------
// save_mns_fd: cached mount-namespace fds for clean/mounted states
// ---------------------------------------------------------------------------

struct NsFdCache {
    clean: RawFd,
    mounted: RawFd,
}

static NS_FD_CACHE: Mutex<NsFdCache> = Mutex::new(NsFdCache { clean: -1, mounted: -1 });

/// utils.c `save_mns_fd`: return a cached fd referring to a clean/mounted
/// mount namespace derived from `pid`, creating it in a forked child if
/// needed. `state` is the raw wire byte (Clean=0 / Mounted=1); any other
/// value behaves exactly like the C enum cast in utils.c 773-901: no
/// unshare, no caching.
pub fn save_mns_fd(pid: i32, state: u8, kind: rz_ipc::RootImplKind) -> RawFd {
    let clean = rz_ipc::MountNamespaceState::Clean as u8;
    let mounted = rz_ipc::MountNamespaceState::Mounted as u8;

    {
        let cache = NS_FD_CACHE.lock().unwrap();
        // utils.c 777-778
        if state == clean && cache.clean != -1 {
            return cache.clean;
        }
        if state == mounted && cache.mounted != -1 {
            return cache.mounted;
        }
    }

    let mut sockets = [0 as libc::c_int; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr()) } == -1 {
        plog!(TAG, "socketpair");
        return -1;
    }
    let (parent_sock, child_sock) = (sockets[0], sockets[1]);

    let fork_pid = unsafe { libc::fork() };
    if fork_pid < 0 {
        plog!(TAG, "fork");
        unsafe {
            libc::close(parent_sock);
            libc::close(child_sock);
        }
        return -1;
    }

    if fork_pid == 0 {
        unsafe {
            libc::close(parent_sock);

            if !switch_mount_namespace(pid) {
                dloge!("Failed to switch mount namespace");
                rz_ipc::write_u8(child_sock, 0).ok();
                libc::close(child_sock);
                libc::_exit(0);
            }

            if state == clean {
                libc::unshare(libc::CLONE_NEWNS);
                if !umount_root(kind) {
                    dloge!("Failed to umount root");
                    rz_ipc::write_u8(child_sock, 0).ok();
                    libc::close(child_sock);
                    libc::_exit(0);
                }
            }

            if rz_ipc::write_u8(child_sock, 1).is_err() {
                libc::close(child_sock);
                libc::_exit(1);
            }

            // Parent signals it opened the ns fd; wait for its ack, then exit.
            let _ = rz_ipc::read_u8(child_sock);

            libc::close(child_sock);
            libc::_exit(0);
        }
    }

    unsafe {
        libc::close(child_sock);

        let has_succeeded = match rz_ipc::read_u8(parent_sock) {
            Ok(v) => v,
            Err(_) => {
                dloge!("Failed to read from socket_parent");
                libc::close(parent_sock);
                return -1;
            }
        };

        if has_succeeded == 0 {
            dloge!("Failed to umount root");
            libc::close(parent_sock);
            return -1;
        }

        let ns_path = std::ffi::CString::new(format!("/proc/{fork_pid}/ns/mnt")).unwrap();
        let ns_fd = libc::open(ns_path.as_ptr(), libc::O_RDONLY);
        if ns_fd == -1 {
            dloge!("open: {}", io::Error::last_os_error());
            libc::close(parent_sock);
            return -1;
        }

        if rz_ipc::write_u8(parent_sock, 1).is_err() {
            dloge!("Failed to write to socket_parent");
            libc::close(ns_fd);
            libc::close(parent_sock);
            return -1;
        }

        libc::close(parent_sock);
        // utils.c 892-896: C treats a failed waitpid as failure (and leaks
        // ns_fd); close it here instead.
        if libc::waitpid(fork_pid, std::ptr::null_mut(), 0) == -1 {
            dloge!("waitpid: {}", io::Error::last_os_error());
            libc::close(ns_fd);
            return -1;
        }

        {
            let mut cache = NS_FD_CACHE.lock().unwrap();
            if state == clean {
                cache.clean = ns_fd;
            } else if state == mounted {
                cache.mounted = ns_fd;
            }
        }

        ns_fd
    }
}

/// main.c: switch to pid 1's mount namespace before starting.
#[allow(dead_code)]
pub fn init_mount_namespace() -> bool {
    switch_mount_namespace(1)
}
