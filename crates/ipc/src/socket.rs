//! Unix socket helpers: abstract-namespace cp socket (connect/listen) and
//! filesystem datagram sendto for the controller socket.

use std::io;

pub const SUN_PATH_MAX: usize = 108;

fn set_abstract_name(addr: &mut libc::sockaddr_un, name: &str) -> io::Result<libc::socklen_t> {
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if name.len() + 1 > SUN_PATH_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "abstract name too long"));
    }
    // sun_path[0] must be NUL for the abstract namespace; the name follows.
    let dst = unsafe { std::slice::from_raw_parts_mut(addr.sun_path.as_mut_ptr() as *mut u8, SUN_PATH_MAX) };
    dst[1..1 + name.len()].copy_from_slice(name.as_bytes());
    // offsetof(sun_path) == 2 on Linux (sa_family_t u16)
    Ok((2 + 1 + name.len()) as libc::socklen_t)
}

fn set_path_name(addr: &mut libc::sockaddr_un, path: &str) -> io::Result<()> {
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    if path.len() >= SUN_PATH_MAX {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
    }
    let dst = unsafe { std::slice::from_raw_parts_mut(addr.sun_path.as_mut_ptr() as *mut u8, SUN_PATH_MAX) };
    dst[..path.len()].copy_from_slice(path.as_bytes());
    Ok(())
}

/// Connect to an abstract-namespace Unix stream socket (daemon.c
/// `rezygiskd_connect`): exactly `retry` attempts, 1s sleep only while
/// another attempt remains (the C `if (retry)` guard — the final failed
/// attempt returns immediately, without sleeping).
pub fn connect_abstract(name: &str, retry: u8) -> io::Result<i32> {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let addr_len = set_abstract_name(&mut addr, name)?;

    // daemon.c: exactly `retry` attempts in total.
    let mut attempts = retry as u32;
    while attempts > 0 {
        attempts -= 1;
        let fd = unsafe {
            libc::socket(
                libc::PF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if fd == -1 {
            return Err(io::Error::last_os_error());
        }

        let ret = unsafe {
            libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), addr_len)
        };
        if ret == 0 {
            return Ok(fd);
        }

        unsafe { libc::close(fd) };

        // daemon.c: log + 1s sleep only when a retry remains; the
        // final failure returns immediately. (The log lives in the callers,
        // which tag it per binary.)
        if attempts > 0 {
            unsafe { libc::sleep(1) };
        }
    }

    Err(io::Error::new(io::ErrorKind::TimedOut, "connect_abstract: exhausted retries"))
}

/// Bind + listen on an abstract-namespace Unix stream socket
/// (utils.c `unix_listener_from_abstract`, backlog 2).
pub fn listen_abstract(name: &str) -> io::Result<i32> {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let addr_len = set_abstract_name(&mut addr, name)?;

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }

    if unsafe { libc::bind(fd, (&addr as *const libc::sockaddr_un).cast(), addr_len) } == -1 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    if unsafe { libc::listen(fd, 2) } == -1 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    Ok(fd)
}

/// Single datagram sendto a filesystem-path Unix socket
/// (utils.c `unix_datagram_sendto` minus the sockcreate dance, which is
/// daemon-policy and handled by the caller).
pub fn datagram_sendto(path: &str, buf: &[u8]) -> io::Result<()> {
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    set_path_name(&mut addr, path)?;

    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_DGRAM, 0) };
    if fd == -1 {
        return Err(io::Error::last_os_error());
    }

    let result = unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), size_of::<libc::sockaddr_un>() as libc::socklen_t) };
    if result == -1 {
        let err = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let sent_ok = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
            (&addr as *const libc::sockaddr_un).cast(),
            size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    } != -1;
    let ret = if sent_ok {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    };

    unsafe { libc::close(fd) };
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstract_listen_connect_roundtrip() {
        // Unique per-process name to avoid collisions with parallel tests.
        let name = format!("rz-test-{:x}", std::process::id());
        let listener = listen_abstract(&name).expect("listen");

        let client = connect_abstract(&name, 1).expect("connect");
        let server = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
        assert!(server >= 0);

        crate::stream::write_string(client, "hello").unwrap();
        assert_eq!(crate::stream::read_string(server).unwrap(), "hello");

        unsafe {
            libc::close(client);
            libc::close(server);
            libc::close(listener);
        }
    }

    #[test]
    fn connect_refused_errors() {
        let name = format!("rz-absent-{:x}", std::process::id());
        assert!(connect_abstract(&name, 1).is_err());
    }
}
