//! /proc/<pid>/maps parsing (misc.c `parse_maps`).

use std::{fs::File, io::Read as _};

/// PROT_* bits matching sys/mman.h, as stored by the C parser.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MapPerms(pub u8);

impl MapPerms {
    pub const READ: u8 = 1;
    pub const WRITE: u8 = 2;
    pub const EXEC: u8 = 4;

    pub fn read(&self) -> bool { self.0 & Self::READ != 0 }
    pub fn write(&self) -> bool { self.0 & Self::WRITE != 0 }
    pub fn exec(&self) -> bool { self.0 & Self::EXEC != 0 }
}

#[derive(Debug, Clone)]
pub struct MapEntry {
    pub start: usize,
    pub end: usize,
    pub perms: MapPerms,
    pub is_private: bool,
    pub offset: usize,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub inode: u64,
    pub path: String,
}

/// Split off the next whitespace-delimited field, returning it and the rest.
fn next_field(r: &str) -> Option<(&str, &str)> {
    let idx = r.find(char::is_whitespace)?;
    let (field, remainder) = r.split_at(idx);
    Some((field, remainder.trim_start()))
}

/// Parse a single maps line:
/// `start-end perms offset devmaj:devmin inode [path...]`
pub fn parse_maps_line(line: &str) -> Option<MapEntry> {
    let line = line.trim_end_matches(['\n', '\r']);
    if line.is_empty() {
        return None;
    }

    let rest = line;

    let (addr, r) = next_field(rest)?;
    let (perms, r) = next_field(r)?;
    let (offset, r) = next_field(r)?;
    let (dev, r) = next_field(r)?;
    let (inode, path) = next_field(r).map_or((r, ""), |(i, p)| (i, p));

    let (start, end) = addr.split_once('-')?;
    let start = usize::from_str_radix(start, 16).ok()?;
    let end = usize::from_str_radix(end, 16).ok()?;

    let perms_bytes = perms.as_bytes();
    if perms_bytes.len() < 4 {
        return None;
    }
    let mut perms_bit = 0u8;
    if perms_bytes[0] == b'r' { perms_bit |= MapPerms::READ; }
    if perms_bytes[1] == b'w' { perms_bit |= MapPerms::WRITE; }
    if perms_bytes[2] == b'x' { perms_bit |= MapPerms::EXEC; }

    let offset = usize::from_str_radix(offset, 16).ok()?;

    let (dev_major, dev_minor) = dev.split_once(':')?;
    let dev_major = u32::from_str_radix(dev_major, 16).ok()?;
    let dev_minor = u32::from_str_radix(dev_minor, 16).ok()?;

    let inode = u64::parse_linux(inode)?;

    Some(MapEntry {
        start,
        end,
        perms: MapPerms(perms_bit),
        is_private: perms_bytes[3] == b'p',
        offset,
        dev_major,
        dev_minor,
        inode,
        path: path.to_string(),
    })
}

trait ParseLinux {
    fn parse_linux(s: &str) -> Option<Self>
    where
        Self: Sized;
}

impl ParseLinux for u64 {
    fn parse_linux(s: &str) -> Option<Self> {
        s.parse().ok()
    }
}

/// Parse /proc/<pid>/maps (misc.c `parse_maps`).
pub fn parse_maps(pid: &str) -> Option<Vec<MapEntry>> {
    let path = format!("/proc/{pid}/maps");
    let content = std::fs::read_to_string(&path).ok()?;
    Some(content.lines().filter_map(parse_maps_line).collect())
}

/// Parse /proc/<pid>/maps from a forked child (misc.c `parse_maps_safe`):
/// opening maps updates its access time, which is detectable via stat();
/// doing the open from a forked child keeps the parent's maps atime clean.
pub fn parse_maps_safe(pid: &str) -> Option<Vec<MapEntry>> {
    let mut sockets = [0 as libc::c_int; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr()) } < 0 {
        return None;
    }
    let (parent_sock, child_sock) = (sockets[0], sockets[1]);

    // C uses clone(NULL, NULL, SIGCHLD, NULL); fork() has SIGCHLD as its
    // default child exit signal, which is equivalent here.
    let child = unsafe { libc::fork() };
    if child == -1 {
        unsafe {
            libc::close(parent_sock);
            libc::close(child_sock);
        }
        return None;
    }

    if child == 0 {
        // Child: open maps, send fd, wait for the parent to finish reading.
        unsafe {
            libc::close(parent_sock);
            let path = std::ffi::CString::new(format!("/proc/{pid}/maps")).unwrap();
            let maps_file = libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
            if maps_file < 0 {
                let can_kill_myself: u8 = 0;
                libc::write(child_sock, (&can_kill_myself) as *const u8 as _, 1);
                libc::close(child_sock);
                libc::_exit(1);
            }

            if super::fdpass::send_fd(child_sock, maps_file).is_err() {
                libc::close(maps_file);
                libc::close(child_sock);
                libc::_exit(1);
            }
            libc::close(maps_file);

            let mut can_kill_myself: u8 = 1;
            loop {
                let ret = libc::read(child_sock, (&mut can_kill_myself) as *mut u8 as _, 1);
                if ret == 1 { break; }
                if ret == 0 { break; }
                if errno_is_retry() { continue; }
                break;
            }

            libc::close(child_sock);
            libc::_exit(0);
        }
    }

    unsafe {
        libc::close(child_sock);
        let fd = match super::fdpass::recv_fd(parent_sock) {
            Ok(fd) => fd,
            Err(_) => {
                libc::close(parent_sock);
                let mut status = 0;
                libc::waitpid(child, &mut status, 0);
                return None;
            }
        };

        use std::os::fd::FromRawFd;
        let mut file = File::from_raw_fd(fd);
        let mut content = String::new();
        let read_ok = file.read_to_string(&mut content).is_ok();
        drop(file);

        // Notify the child that we are done reading.
        let can_kill_itself: u8 = 1;
        libc::write(parent_sock, (&can_kill_itself) as *const u8 as _, 1);
        libc::close(parent_sock);

        let mut status = 0;
        libc::waitpid(child, &mut status, 0);

        if !read_ok {
            return None;
        }
        Some(content.lines().filter_map(parse_maps_line).collect())
    }
}

fn errno_is_retry() -> bool {
    #[cfg(target_os = "android")]
    unsafe {
        let e = *libc::__errno();
        e == libc::EINTR || e == libc::EAGAIN
    }
    #[cfg(not(target_os = "android"))]
    unsafe {
        let e = *libc::__errno_location();
        e == libc::EINTR || e == libc::EAGAIN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_line_with_path() {
        let line = "7f8b0a400000-7f8b0c000000 r--p 00000000 fe:01 123456    /data/app/base.apk\n";
        let m = parse_maps_line(line).unwrap();
        assert_eq!(m.start, 0x7f8b0a400000);
        assert_eq!(m.end, 0x7f8b0c000000);
        assert_eq!(m.perms.read(), true);
        assert_eq!(m.perms.write(), false);
        assert_eq!(m.perms.exec(), false);
        assert!(m.is_private);
        assert_eq!(m.offset, 0);
        assert_eq!(m.dev_major, 0xfe);
        assert_eq!(m.dev_minor, 1);
        assert_eq!(m.inode, 123456);
        assert_eq!(m.path, "/data/app/base.apk");
    }

    #[test]
    fn parses_anon_line_without_path() {
        let line = "7ffd1a200000-7ffd1a210000 rw-p 00000000 00:00 0                          [stack]";
        let m = parse_maps_line(line).unwrap();
        assert_eq!(m.perms.exec(), false);
        assert_eq!(m.inode, 0);
        assert_eq!(m.path, "[stack]");
    }

    #[test]
    fn parses_line_with_spaces_in_path() {
        // C keeps trailing whitespace of the path (only the newline is stripped).
        let line = "7000000000-7000010000 r-xp 00001000 fe:01 42   /path/with space/lib.so   ";
        let m = parse_maps_line(line).unwrap();
        assert_eq!(m.path, "/path/with space/lib.so   ");
        assert!(m.perms.exec());
        assert_eq!(m.offset, 0x1000);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_maps_line("not a maps line").is_none());
        assert!(parse_maps_line("").is_none());
    }
}
