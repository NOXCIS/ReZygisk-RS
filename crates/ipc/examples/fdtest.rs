//! Standalone debug harness for SCM_RIGHTS fd passing (`rz_common::send_fd` /
//! `recv_fd`) plus stream framing, mirroring the byte-level concerns from
//! socket_utils.c `write_fd` / `read_fd`:
//!
//! 1. fd roundtrip over a socketpair, contents readable through the received fd
//! 2. the receiver consumes exactly the 1-byte cmsg payload (stream stays in sync)
//! 3. a string frame written after the fd arrives intact (no skb coalescing loss)
//! 4. repeated fd passing on the same connection
//!
//! Run: `cargo run -p rz-ipc --example fdtest`

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

use rz_ipc::{read_string, recv_fd, send_fd, write_string};

fn step(msg: &str) {
    println!("[fdtest] {msg}");
}

fn bail(context: &str, err: std::io::Error) -> ! {
    eprintln!("[fdtest] FAIL at {context}: {err}");
    std::process::exit(1);
}

fn main() {
    let mut fds: [RawFd; 2] = [0; 2];
    let ret = unsafe {
        libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0, fds.as_mut_ptr())
    };
    if ret == -1 {
        bail("socketpair", std::io::Error::last_os_error());
    }
    let (a, b) = (fds[0], fds[1]);
    step(&format!("socketpair ok: a={a} b={b}"));

    let path = std::env::temp_dir().join(format!("rz_fdtest_{}", std::process::id()));
    {
        let mut tmp = match File::create(&path) {
            Ok(f) => f,
            Err(e) => bail("create temp file", e),
        };
        tmp.write_all(b"rezygisk-fdtest-0000").unwrap();
        tmp.flush().unwrap();
    }

    // Pass 1: open O_RDONLY like the daemon does for module libs, send, then
    // close our copy so only the transferred fd keeps the file alive.
    let ro = match File::open(&path) {
        Ok(f) => f,
        Err(e) => bail("open temp file", e),
    };
    let sent_fd = ro.as_raw_fd();
    step(&format!("pass 1: sending fd {sent_fd} ({:?})", path));

    if let Err(e) = send_fd(a, sent_fd) {
        bail("send_fd #1", e);
    }
    drop(ro);
    step("pass 1: send_fd ok, sender copy closed");

    // recv_fd consumes exactly the 1-byte cmsg payload; the stream-sync check
    // below is the observable proof (a swallowed or over-read byte would
    // corrupt the next frame).
    let new_fd = match recv_fd(b) {
        Ok(fd) => fd,
        Err(e) => bail("recv_fd #1", e),
    };
    step(&format!("pass 1: recv_fd ok -> new fd {new_fd}"));

    let mut received = [0u8; 20];
    {
        let mut f = unsafe { File::from_raw_fd(new_fd) };
        if let Err(e) = f.seek(SeekFrom::Start(0)) {
            bail("seek received fd", e);
        }
        if let Err(e) = f.read_exact(&mut received) {
            bail("read received fd", e);
        }
    }
    step(&format!(
        "pass 1: read through received fd: {:?}",
        String::from_utf8_lossy(&received)
    ));
    if &received != b"rezygisk-fdtest-0000" {
        eprintln!("[fdtest] FAIL: received fd content mismatch");
        std::process::exit(1);
    }

    // Stream sync: exactly the 1-byte cmsg payload was consumed, so a string
    // frame sent after the fd must arrive intact (no skb coalescing loss).
    if let Err(e) = write_string(a, "after-fd-marker") {
        bail("write_string after fd", e);
    }
    match read_string(b) {
        Ok(s) => {
            step(&format!("stream sync: got frame {s:?} after fd pass"));
            if s != "after-fd-marker" {
                eprintln!("[fdtest] FAIL: stream desync after fd pass");
                std::process::exit(1);
            }
        }
        Err(e) => bail("read_string after fd", e),
    }

    // Pass 2: repeated fd passing on the same connection (daemon reuses the
    // connection for multiple module libs).
    let ro2 = match File::open(&path) {
        Ok(f) => f,
        Err(e) => bail("reopen temp file", e),
    };
    if let Err(e) = send_fd(a, ro2.as_raw_fd()) {
        bail("send_fd #2", e);
    }
    drop(ro2);
    let fd2 = match recv_fd(b) {
        Ok(fd) => fd,
        Err(e) => bail("recv_fd #2", e),
    };
    let mut buf2 = [0u8; 8];
    {
        let mut f = unsafe { File::from_raw_fd(fd2) };
        if let Err(e) = f.read_exact(&mut buf2) {
            bail("read fd #2", e);
        }
    }
    step(&format!(
        "pass 2: recv_fd ok -> fd {fd2}, head {:?}",
        String::from_utf8_lossy(&buf2)
    ));
    if &buf2 != b"rezygisk" {
        eprintln!("[fdtest] FAIL: second fd content mismatch");
        std::process::exit(1);
    }

    unsafe {
        libc::close(new_fd);
        libc::close(fd2);
        libc::close(a);
        libc::close(b);
    }
    std::fs::remove_file(&path).ok();

    println!("[fdtest] PASS: fd roundtrip, payload sync, post-fd frame, repeat pass all ok");
}
