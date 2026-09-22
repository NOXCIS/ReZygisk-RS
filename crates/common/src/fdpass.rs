//! SCM_RIGHTS fd passing (socket_utils.c `write_fd` / `read_fd`).
//!
//! Wire compatibility note: the C side sends a 1-byte payload with the fd
//! attached, and receives with a 4-byte MSG_WAITALL read that relies on the
//! kernel returning as soon as the cmsg-bearing skb is consumed. Here the
//! receiver reads exactly the 1 payload byte that is atomically sent with the
//! control message, which never over-consumes stream bytes regardless of
//! kernel skb coalescing, and stays byte-compatible with the C implementation
//! on both ends.
//!
//! [`send_fd_with_payload`] / [`recv_fd_with_payload`] are the extension the
//! daemon's mount-namespace reply needs: an fd attached to bytes the receiver
//! is *already* blocked on, so "was an fd sent?" is answered by the same
//! message that carries the data and cannot depend on timing.

use std::io;
use std::os::fd::RawFd;

pub fn send_fd(fd: RawFd, sendfd: RawFd) -> io::Result<()> {
    send_fd_with_payload(fd, &[0u8; 1], sendfd)
}

/// `send_fd` with a caller-chosen payload in the message that carries the fd.
///
/// The 1-byte payload of [`send_fd`] is only enough when the fd *is* the whole
/// message. A reply that already has a byte stream in it must attach the fd to
/// bytes the receiver is already reading: sending it as a second message leaves
/// a window in which the receiver finishes its reads, asks once whether an fd
/// follows, and answers "none" before the sender gets there. Riding along with
/// a word the receiver blocks on removes that window entirely.
pub fn send_fd_with_payload(fd: RawFd, payload: &[u8], sendfd: RawFd) -> io::Result<()> {
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as libc::c_uint) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut iov = libc::iovec {
        iov_base: payload.as_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::new(io::ErrorKind::Other, "CMSG_FIRSTHDR failed"));
        }
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as libc::c_uint) as usize;
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        std::ptr::copy_nonoverlapping(
            (&sendfd) as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            size_of::<libc::c_int>(),
        );
    }

    let ret = unsafe { libc::sendmsg(fd, &msg, 0) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// `recv_fd` for a caller that requires the fd: a missing `SCM_RIGHTS` is an
/// error, like the C's `read_fd`.
pub fn recv_fd(fd: RawFd) -> io::Result<RawFd> {
    match recv_fd_with_payload(fd, &mut [0u8; 1])? {
        Some(received) => Ok(received),
        None => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Failed to receive fd: No valid fd found in ancillary data.",
        )),
    }
}

/// Receive exactly `buf.len()` bytes, reporting an fd if the message carrying
/// them had one attached.
///
/// Reads in a loop until the buffer is full, because a stream peer may split
/// the payload across messages, and keeps the fd from whichever message
/// carried it — for the caller that means [`None`] is a definite "this peer
/// does not send fds", not "it had not sent one yet". Bytes are copied before
/// the fd is examined, so a message whose length straddles the requested
/// buffer still yields its fd rather than dropping it, which a plain `read`
/// would do silently.
pub fn recv_fd_with_payload(fd: RawFd, buf: &mut [u8]) -> io::Result<Option<RawFd>> {
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as libc::c_uint) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut received: Option<RawFd> = None;
    let mut filled = 0usize;

    while filled < buf.len() {
        let mut iov = libc::iovec {
            iov_base: buf[filled..].as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len() - filled,
        };

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len();

        let ret = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if ret == -1 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if ret == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "recv_fd: eof"));
        }

        received = match received {
            Some(kept) => {
                // Only one fd is ever sent; a second one would be a protocol
                // violation, so close it instead of leaking it here.
                if let Some(extra) = fd_from_cmsgs(&msg) {
                    unsafe { libc::close(extra) };
                }

                Some(kept)
            }
            None => fd_from_cmsgs(&msg),
        };

        filled += ret as usize;
    }

    Ok(received)
}

/// Scan one message's control data for a usable `SCM_RIGHTS` fd.
fn fd_from_cmsgs(msg: &libc::msghdr) -> Option<RawFd> {
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            let c = &*cmsg;
            if c.cmsg_level == libc::SOL_SOCKET
                && c.cmsg_type == libc::SCM_RIGHTS
                && c.cmsg_len as usize
                    >= libc::CMSG_LEN(size_of::<libc::c_int>() as libc::c_uint) as usize
            {
                let mut out_fd: RawFd = -1;
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    (&mut out_fd) as *mut RawFd as *mut u8,
                    size_of::<libc::c_int>(),
                );
                if out_fd >= 0 {
                    return Some(out_fd);
                }
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socketpair() -> (RawFd, RawFd) {
        let mut fds = [0 as RawFd; 2];
        assert_ne!(
            unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) },
            -1
        );
        (fds[0], fds[1])
    }

    fn close(fd: RawFd) {
        unsafe { libc::close(fd) };
    }

    fn open_null() -> RawFd {
        use std::os::fd::AsRawFd;
        let file = std::fs::File::open("/dev/null").expect("/dev/null");
        let fd = file.as_raw_fd();
        std::mem::forget(file);
        fd
    }

    fn write_u32(fd: RawFd, v: u32) {
        let bytes = v.to_ne_bytes();
        assert_eq!(unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) }, 4);
    }

    /// The mount-namespace reply: `daemon_pid`, then `ns_fd` **with the fd
    /// attached to it**. The receiver learns both the integer and the fd from a
    /// read it was blocked on anyway.
    #[test]
    fn payload_receive_yields_word_and_fd_together() {
        let (a, b) = socketpair();
        let target = open_null();

        write_u32(b, 1071);
        send_fd_with_payload(b, &11u32.to_ne_bytes(), target).expect("send_fd_with_payload");

        let mut word = [0u8; 4];
        assert_eq!(recv_fd_with_payload(a, &mut word).expect("pid"), None);
        assert_eq!(u32::from_ne_bytes(word), 1071);

        let received = recv_fd_with_payload(a, &mut word)
            .expect("ns word")
            .expect("fd must ride with the integer");
        assert_eq!(u32::from_ne_bytes(word), 11);

        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(received, &mut st) }, 0);

        close(received);
        close(target);
        close(a);
        close(b);
    }

    /// A peer that only sends the path leaves the queue empty: `None` is the
    /// definitive answer that sends the loader to the C open fallback.
    #[test]
    fn payload_receive_reports_legacy_peer() {
        let (a, b) = socketpair();

        write_u32(b, 1071);
        write_u32(b, 11);

        let mut word = [0u8; 4];
        assert_eq!(recv_fd_with_payload(a, &mut word).expect("pid"), None);
        assert_eq!(recv_fd_with_payload(a, &mut word).expect("ns word"), None);
        assert_eq!(u32::from_ne_bytes(word), 11);

        close(a);
        close(b);
    }

    /// The fd must survive a payload split across two messages, and a message
    /// that overfills the requested buffer must not lose it either.
    #[test]
    fn payload_receive_keeps_fd_across_splits() {
        let (a, b) = socketpair();
        let target = open_null();

        // Two bytes plain, then the remaining two with the fd attached.
        let word = 0x11223344u32.to_ne_bytes();
        assert_eq!(unsafe { libc::write(b, word.as_ptr().cast(), 2) }, 2);
        send_fd_with_payload(b, &word[2..], target).expect("tail with fd");

        let mut buf = [0u8; 4];
        let received = recv_fd_with_payload(a, &mut buf)
            .expect("split word")
            .expect("fd from the second message");
        assert_eq!(buf, word);

        close(received);
        close(target);
        close(a);
        close(b);
    }

    /// `recv_fd` keeps its C contract: no fd is an error, not an empty answer.
    #[test]
    fn recv_fd_requires_the_fd() {
        let (a, b) = socketpair();
        assert_eq!(unsafe { libc::write(b, [0u8].as_ptr().cast(), 1) }, 1);
        assert_eq!(
            recv_fd(a).expect_err("no cmsg").kind(),
            io::ErrorKind::InvalidData
        );
        close(a);
        close(b);
    }
}
