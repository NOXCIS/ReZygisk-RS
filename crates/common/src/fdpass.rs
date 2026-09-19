//! SCM_RIGHTS fd passing (socket_utils.c `write_fd` / `read_fd`).
//!
//! Wire compatibility note: the C side sends a 1-byte payload with the fd
//! attached, and receives with a 4-byte MSG_WAITALL read that relies on the
//! kernel returning as soon as the cmsg-bearing skb is consumed. Here the
//! receiver reads exactly the 1 payload byte that is atomically sent with the
//! control message, which never over-consumes stream bytes regardless of
//! kernel skb coalescing, and stays byte-compatible with the C implementation
//! on both ends.

use std::io;
use std::os::fd::RawFd;

pub fn send_fd(fd: RawFd, sendfd: RawFd) -> io::Result<()> {
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as libc::c_uint) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let payload = [0u8; 1];
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

pub fn recv_fd(fd: RawFd) -> io::Result<RawFd> {
    let cmsg_space =
        unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as libc::c_uint) } as usize;
    let mut cmsg_buf = vec![0u8; cmsg_space];

    let mut payload = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: payload.as_mut_ptr() as *mut libc::c_void,
        iov_len: payload.len(),
    };

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_buf.len();

    loop {
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
        break;
    }

    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            let c = &*cmsg;
            if c.cmsg_level == libc::SOL_SOCKET
                && c.cmsg_type == libc::SCM_RIGHTS
                && c.cmsg_len as usize >= libc::CMSG_LEN(size_of::<libc::c_int>() as libc::c_uint) as usize
            {
                let mut out_fd: RawFd = -1;
                std::ptr::copy_nonoverlapping(
                    libc::CMSG_DATA(cmsg),
                    (&mut out_fd) as *mut RawFd as *mut u8,
                    size_of::<libc::c_int>(),
                );
                if out_fd >= 0 {
                    return Ok(out_fd);
                }
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "Failed to receive fd: No valid fd found in ancillary data.",
    ))
}
