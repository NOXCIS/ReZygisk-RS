//! Stream read/write primitives over raw fds.
//!
//! Byte-for-byte mirror of loader/src/common/socket_utils.c (loader side) and
//! zygiskd/src/utils.c (daemon side): fixed-size integers native-endian,
//! strings as `size_t` length prefix + raw bytes (no NUL). `usize` matches C
//! `size_t` for the same bitness, and a cp socket only ever connects
//! same-bitness peers (rezygisk-cp64 <-> 64-bit zygote loader).

use std::io;

/// write_loop: retries EINTR; sleeps 1ms on EAGAIN (socket_utils.c).
pub fn write_all(fd: i32, mut buf: &[u8]) -> io::Result<usize> {
    let total = buf.len();
    let mut written = 0usize;
    while written < total {
        let ret = unsafe {
            libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len())
        };
        if ret == -1 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EAGAIN) => {
                    unsafe { libc::usleep(1000) };
                    continue;
                }
                Some(libc::EINTR) => continue,
                _ => return Err(err),
            }
        }
        if ret == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write: 0 bytes written"));
        }
        written += ret as usize;
        buf = &buf[ret as usize..];
    }
    Ok(written)
}

/// read_loop: retries EINTR/EAGAIN (socket_utils.c).
pub fn read_exact(fd: i32, mut buf: &mut [u8]) -> io::Result<usize> {
    let total = buf.len();
    let mut read_bytes = 0usize;
    while read_bytes < total {
        let ret = unsafe {
            libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
        };
        if ret == -1 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) | Some(libc::EAGAIN) => continue,
                _ => return Err(err),
            }
        }
        if ret == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read: 0 bytes read"));
        }
        read_bytes += ret as usize;
        buf = &mut buf[ret as usize..];
    }
    Ok(read_bytes)
}

pub fn write_u8(fd: i32, val: u8) -> io::Result<usize> {
    write_all(fd, &[val])
}

pub fn write_u32(fd: i32, val: u32) -> io::Result<usize> {
    write_all(fd, &val.to_ne_bytes())
}

pub fn write_usize(fd: i32, val: usize) -> io::Result<usize> {
    write_all(fd, &val.to_ne_bytes())
}

pub fn read_u8(fd: i32) -> io::Result<u8> {
    let mut buf = [0u8; 1];
    read_exact(fd, &mut buf)?;
    Ok(buf[0])
}

pub fn read_u32(fd: i32) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    read_exact(fd, &mut buf)?;
    Ok(u32::from_ne_bytes(buf))
}

pub fn read_usize(fd: i32) -> io::Result<usize> {
    let mut buf = [0u8; size_of::<usize>()];
    read_exact(fd, &mut buf)?;
    Ok(usize::from_ne_bytes(buf))
}

/// write_string (socket_utils.c): size_t length prefix + bytes, no NUL.
pub fn write_string(fd: i32, s: &str) -> io::Result<usize> {
    let mut written = write_usize(fd, s.len())?;
    written += write_all(fd, s.as_bytes())?;
    Ok(written)
}

/// read_string (socket_utils.c): size_t length prefix + bytes.
/// The C client bounds the length by a fixed buffer; here an absurd length is
/// simply an error (the stream is then discarded by the caller).
pub fn read_string(fd: i32) -> io::Result<String> {
    let len = read_usize(fd)?;
    if len > 1 << 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "read_string: implausible length",
        ));
    }
    let mut buf = vec![0u8; len];
    read_exact(fd, &mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// read_string into a fixed-size buffer like zygiskd.c `read_string(fd, buf, buf_size)`.
/// Returns the number of payload bytes read (excluding NUL).
pub fn read_string_bounded(fd: i32, buf: &mut [u8]) -> io::Result<usize> {
    let len = read_usize(fd)?;
    if buf.is_empty() || len > buf.len() - 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "read_string: buffer too small",
        ));
    }
    read_exact(fd, &mut buf[..len])?;
    buf[len] = 0;
    Ok(len)
}

/// Fixed-int/string frame writer over a raw fd, used by the daemon handlers.
pub struct WriteFrame {
    pub fd: i32,
}

impl WriteFrame {
    pub fn new(fd: i32) -> Self {
        Self { fd }
    }

    pub fn u8(&mut self, v: u8) -> io::Result<()> {
        write_u8(self.fd, v)?;
        Ok(())
    }

    pub fn u32(&mut self, v: u32) -> io::Result<()> {
        write_u32(self.fd, v)?;
        Ok(())
    }

    pub fn usize(&mut self, v: usize) -> io::Result<()> {
        write_usize(self.fd, v)?;
        Ok(())
    }

    pub fn string(&mut self, s: &str) -> io::Result<()> {
        write_string(self.fd, s)?;
        Ok(())
    }

    pub fn fd(&mut self, fd: i32) -> io::Result<()> {
        rz_common::send_fd(self.fd, fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_roundtrip_socketpair() {
        let mut fds = [0 as libc::c_int; 2];
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        let (a, b) = (fds[0], fds[1]);

        write_string(a, "truman").unwrap();
        assert_eq!(read_string(b).unwrap(), "truman");

        unsafe {
            libc::close(a);
            libc::close(b);
        }
    }

    #[test]
    fn string_golden_bytes() {
        // "truman": size_t (8 bytes on this target) length + bytes, no NUL.
        let mut fds = [0 as libc::c_int; 2];
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        let (a, b) = (fds[0], fds[1]);

        write_string(a, "truman").unwrap();

        let mut expected = (6usize).to_ne_bytes().to_vec();
        expected.extend_from_slice(b"truman");
        let mut buf = vec![0u8; expected.len()];
        unsafe { libc::read(b, buf.as_mut_ptr() as _, buf.len()) };
        assert_eq!(buf, expected);

        unsafe {
            libc::close(a);
            libc::close(b);
        }
    }

    #[test]
    fn int_roundtrip_socketpair() {
        let mut fds = [0 as libc::c_int; 2];
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        let (a, b) = (fds[0], fds[1]);

        write_u8(a, 3).unwrap();
        write_u32(a, 0xdeadbeef).unwrap();
        write_usize(a, 0x1122334455667788 & usize::MAX).unwrap();

        assert_eq!(read_u8(b).unwrap(), 3);
        assert_eq!(read_u32(b).unwrap(), 0xdeadbeef);
        assert_eq!(read_usize(b).unwrap(), 0x1122334455667788 & usize::MAX);

        unsafe {
            libc::close(a);
            libc::close(b);
        }
    }

    #[test]
    fn fd_passing_socketpair() {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom, Write};
        use std::os::fd::{AsRawFd, FromRawFd};
        use rz_common::{recv_fd, send_fd};

        let mut fds = [0 as libc::c_int; 2];
        unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        let (a, b) = (fds[0], fds[1]);

        let path = std::env::temp_dir().join(format!("rz_ipc_test_{}", std::process::id()));
        {
            let mut tmp = File::create(&path).unwrap();
            tmp.write_all(b"rezygisk").unwrap();
            tmp.flush().unwrap();
        }
        // Pass an O_RDONLY fd like the daemon does for module libs.
        let ro = File::open(&path).unwrap();
        let raw_fd = ro.as_raw_fd();
        send_fd(a, raw_fd).unwrap();
        drop(ro);

        let mut received = [0u8; 8];
        {
            let fd = recv_fd(b).unwrap();
            let mut f = unsafe { File::from_raw_fd(fd) };
            f.seek(SeekFrom::Start(0)).unwrap();
            f.read_exact(&mut received).unwrap();
        }
        assert_eq!(&received, b"rezygisk");

        std::fs::remove_file(&path).ok();
        unsafe {
            libc::close(a);
            libc::close(b);
        }
    }
}
