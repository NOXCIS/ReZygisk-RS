//! Host integration tests for the IPC wire protocol:
//!
//! - golden-byte frames written with the public stream API, derived from
//!   loader/src/common/daemon.c (`rezygiskd_get_process_flags`) and
//!   common/socket_utils.c `write_uint8_t`/`write_uint32_t`/`write_string`;
//! - `read_string` / `read_string_bounded` receiver semantics vs
//!   zygiskd/src/zygiskd.c (`read_string(fd, buf, buf_size)`);
//! - `connect_abstract` retry/timing semantics vs daemon.c
//!   (`rezygiskd_connect`: exactly `retry` attempts, 1s after each failure);
//! - filesystem datagram delivery via `datagram_sendto` with the
//!   controller report messages (zygiskd.c `zygiskd_start`).

use std::os::unix::net::UnixDatagram;
use std::time::Instant;

use rz_ipc::{
    build_set_info_message, connect_abstract, datagram_sendto, listen_abstract, parse_set_info,
    read_string, read_string_bounded, read_u32, read_u8, read_usize, write_string, write_u32,
    write_u8, write_usize, DaemonSocketAction, WriteFrame,
};

fn socketpair() -> (i32, i32) {
    let mut fds = [0 as libc::c_int; 2];
    let r = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    assert_eq!(r, 0, "socketpair failed");
    (fds[0], fds[1])
}

fn close(a: i32, b: i32) {
    unsafe {
        libc::close(a);
        libc::close(b);
    }
}

/// Raw single-read of up to `n` bytes (read() on a stream socket may return
/// less, so this is only used with small frames).
fn read_some(fd: i32, n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    let r = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, n) };
    assert!(r >= 0, "read failed");
    buf.truncate(r as usize);
    buf
}

// ---------------------------------------------------------------------------
// Golden wire frames (daemon.c, socket_utils.c write_*)
// ---------------------------------------------------------------------------

#[test]
fn get_process_flags_request_frame_is_daemon_c_golden() {
    let (a, b) = socketpair();
    let mut f = WriteFrame::new(a);
    f.u8(DaemonSocketAction::GetProcessFlags as u8).unwrap();
    f.u32(0xdead_beef).unwrap();
    let proc = "com.android.systemui";
    f.string(proc).unwrap();

    let mut expected = Vec::new();
    expected.push(DaemonSocketAction::GetProcessFlags as u8); // daemon.c
    expected.extend_from_slice(&0xdead_beefu32.to_ne_bytes()); // daemon.c
    expected.extend_from_slice(&proc.len().to_ne_bytes()); // string len (size_t)
    expected.extend_from_slice(proc.as_bytes()); // no NUL

    assert_eq!(read_some(b, expected.len()), expected);
    close(a, b);
}

#[test]
fn fixed_int_writes_are_exact_width() {
    let (a, b) = socketpair();
    assert_eq!(write_u8(a, 0x42).unwrap(), 1);
    assert_eq!(write_u32(a, 0x0102_0304).unwrap(), 4);
    assert_eq!(write_usize(a, 0x0809_0a0b_0c0d_0e0f).unwrap(), 8);

    let mut expected = vec![0x42u8];
    expected.extend_from_slice(&0x0102_0304u32.to_ne_bytes());
    expected.extend_from_slice(&0x0809_0a0b_0c0d_0e0fusize.to_ne_bytes());
    assert_eq!(read_some(b, expected.len()), expected);
    close(a, b);
}

#[test]
fn string_write_is_size_t_len_plus_bytes_no_nul() {
    let (a, b) = socketpair();
    write_string(a, "").unwrap();
    write_string(a, "a").unwrap();
    write_string(a, "truman").unwrap();

    let mut expected = Vec::new();
    expected.extend_from_slice(&0usize.to_ne_bytes());
    expected.extend_from_slice(&1usize.to_ne_bytes());
    expected.push(b'a');
    expected.extend_from_slice(&6usize.to_ne_bytes());
    expected.extend_from_slice(b"truman");
    assert_eq!(read_some(b, expected.len()), expected);
    close(a, b);
}

// ---------------------------------------------------------------------------
// Receiver semantics (zygiskd.c read_string(fd, buf, buf_size))
// ---------------------------------------------------------------------------

#[test]
fn read_string_bounded_matches_zygiskd_semantics() {
    // Exact fit: len == buf.len() - 1 must succeed and NUL-terminate.
    let (a, b) = socketpair();
    write_string(a, "truman").unwrap(); // len 6
    let mut buf = [0u8; 7];
    let n = read_string_bounded(b, &mut buf).unwrap();
    assert_eq!(n, 6);
    assert_eq!(&buf[..7], b"truman\0");
    close(a, b);

    // One byte too small: rejected with InvalidData (zygiskd.c checks
    // len + 1 > buf_size before reading the payload). The C breaks out of
    // the handler on the -1 return (payload left unread → connection
    // dropped), so each case runs on a fresh socketpair.
    let (a, b) = socketpair();
    write_string(a, "truman").unwrap(); // len 6 into buf of 6
    let mut small = [0u8; 6];
    let err = read_string_bounded(b, &mut small).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    close(a, b);

    // Empty payload: len 0 fits any buffer and writes only the NUL.
    let (a, b) = socketpair();
    write_string(a, "").unwrap();
    let mut buf2 = [0xffu8; 8];
    let n = read_string_bounded(b, &mut buf2).unwrap();
    assert_eq!(n, 0);
    assert_eq!(buf2[0], 0);
    close(a, b);
}

#[test]
fn read_string_rejects_implausible_length() {
    let (a, b) = socketpair();
    // (1 << 20) + 1: over the C client's fixed buffer ceiling — the stream
    // is unusable and must error instead of allocating 1MB+.
    write_usize(a, (1 << 20) + 1).unwrap();
    let err = read_string(b).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);

    // Exactly 1 << 20 is accepted. The 1MB payload exceeds the socketpair
    // buffer, so the writer runs in a thread while the reader drains.
    // (Payload is ASCII: from_utf8_lossy must round-trip 1:1.)
    let payload = vec![b'A'; 1 << 20];
    let writer_payload = payload.clone();
    let writer = std::thread::spawn(move || {
        write_usize(a, 1 << 20).unwrap();
        rz_ipc::write_all(a, &writer_payload).unwrap();
    });
    let got = read_string(b).unwrap();
    assert_eq!(got.len(), 1 << 20);
    assert_eq!(got.as_bytes(), &payload[..]);
    writer.join().unwrap();
    close(a, b);
}

// ---------------------------------------------------------------------------
// Round-trip symmetry
// ---------------------------------------------------------------------------

#[test]
fn stream_roundtrip_symmetry() {
    let (a, b) = socketpair();
    let mut f = WriteFrame::new(a);
    f.u8(0x7f).unwrap();
    f.u32(0xcafe_babe).unwrap();
    f.usize(0xfeed_beef_dead_f00d).unwrap();
    f.string("rezygisk").unwrap();
    f.string("").unwrap();
    f.string("naïve 日本語 🦊").unwrap();

    assert_eq!(read_u8(b).unwrap(), 0x7f);
    assert_eq!(read_u32(b).unwrap(), 0xcafe_babe);
    assert_eq!(read_usize(b).unwrap(), 0xfeed_beef_dead_f00d);
    assert_eq!(read_string(b).unwrap(), "rezygisk");
    assert_eq!(read_string(b).unwrap(), "");
    assert_eq!(read_string(b).unwrap(), "naïve 日本語 🦊");
    close(a, b);
}

// ---------------------------------------------------------------------------
// connect_abstract retry semantics (daemon.c rezygiskd_connect)
// ---------------------------------------------------------------------------

#[test]
fn connect_abstract_zero_retries_fails_fast() {
    // daemon.c: `while (--retry) ...` with retry == 0 → zero attempts, no
    // sleep. Must not take ~1s.
    let name = format!("rz-absent-zero-{:x}", std::process::id());
    let start = Instant::now();
    assert!(connect_abstract(&name, 0).is_err());
    assert!(start.elapsed() < std::time::Duration::from_millis(900));
}

#[test]
fn connect_abstract_sleeps_only_between_attempts() {
    // retry == 2 → attempt, 1s sleep (retry remains), attempt, no sleep on
    // the final failure → error. Elapsed covers one sleep.
    let name = format!("rz-absent-two-{:x}", std::process::id());
    let start = Instant::now();
    assert!(connect_abstract(&name, 2).is_err());
    let elapsed = start.elapsed();
    assert!(
        elapsed >= std::time::Duration::from_millis(900),
        "expected >= 0.9s for 2 attempts with 1 sleep, got {elapsed:?}"
    );
    // Sanity upper bound so a hang fails the test instead of blocking CI.
    assert!(elapsed < std::time::Duration::from_secs(10));
}

#[test]
fn connect_abstract_rejects_overlong_name() {
    // sun_path is 108 bytes; an abstract name of 108+ chars needs
    // len + 1 > SUN_PATH_MAX → InvalidInput without touching the network.
    let name = "x".repeat(108);
    let start = Instant::now();
    let err = connect_abstract(&name, 0).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert!(start.elapsed() < std::time::Duration::from_millis(900));
    assert!(listen_abstract(&name).is_err());
}

#[test]
fn abstract_listen_connect_roundtrip_with_retry() {
    let name = format!("rz-live-{:x}", std::process::id());
    let listener = listen_abstract(&name).unwrap();
    let client = connect_abstract(&name, 1).unwrap();
    let server = unsafe { libc::accept(listener, std::ptr::null_mut(), std::ptr::null_mut()) };
    assert!(server >= 0);
    write_string(client, "ping").unwrap();
    assert_eq!(read_string(server).unwrap(), "ping");
    unsafe {
        libc::close(client);
        libc::close(server);
        libc::close(listener);
    }
}

// ---------------------------------------------------------------------------
// Datagram controller reports (zygiskd.c zygiskd_start sendto sequence)
// ---------------------------------------------------------------------------

fn temp_socket_path(tag: &str) -> String {
    std::env::temp_dir()
        .join(format!("rz_ipc_it_{}_{}", tag, std::process::id()))
        .to_string_lossy()
        .into_owned()
}

#[test]
fn datagram_sendto_delivers_exact_bytes() {
    let path = temp_socket_path("dgram");
    let _ = std::fs::remove_file(&path);
    let sock = UnixDatagram::bind(&path).unwrap();

    datagram_sendto(&path, b"hello-datagram").unwrap();
    let mut buf = [0u8; 64];
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"hello-datagram");

    // Datagram boundaries are preserved: two sends = two reads.
    datagram_sendto(&path, b"one").unwrap();
    datagram_sendto(&path, b"two").unwrap();
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"one");
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"two");

    drop(sock);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn datagram_sendto_missing_socket_errors() {
    let path = temp_socket_path("absent");
    let _ = std::fs::remove_file(&path);
    assert!(datagram_sendto(&path, b"x").is_err());
}

#[test]
fn set_info_report_is_one_datagram_and_decodes() {
    // One datagram per report, so two daemons reporting at the same moment
    // cannot interleave their fields. The old one-datagram-per-field framing
    // did interleave at boot and ended with the monitor dispatching a
    // module-count field as a Stop command.
    let msg = build_set_info_message("KernelSU", &["truman", "playintegrityfix"]);

    let path = temp_socket_path("ctrl");
    let _ = std::fs::remove_file(&path);
    let sock = UnixDatagram::bind(&path).unwrap();

    datagram_sendto(&path, &msg).unwrap();

    let mut buf = vec![0u8; 256];
    let (n, _) = sock.recv_from(&mut buf).unwrap();
    assert_eq!(&buf[..n], &msg[..], "report must arrive as a single datagram");

    // And nothing else is queued behind it.
    assert!(sock.set_nonblocking(true).is_ok());
    assert!(sock.recv_from(&mut buf).is_err(), "unexpected extra datagram");

    drop(sock);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn interleaved_reports_do_not_corrupt_each_other() {
    // Two daemons reporting simultaneously: with single-datagram reports the
    // reader can always resolve each one, in either order.
    let a = build_set_info_message("KernelSU", &["truman"]);
    let b = build_set_info_message("KernelSU", &["playintegrityfix", "truman"]);

    let path = temp_socket_path("ctrl");
    let _ = std::fs::remove_file(&path);
    let sock = UnixDatagram::bind(&path).unwrap();

    datagram_sendto(&path, &b).unwrap();
    datagram_sendto(&path, &a).unwrap();

    let mut buf = vec![0u8; 256];
    let mut parsed = Vec::new();
    for _ in 0..2 {
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        let (root, modules) = parse_set_info(&buf[1..n]).expect("each report decodes");
        assert_eq!(root, "KernelSU");
        parsed.push(modules);
    }

    assert!(parsed.contains(&vec!["truman".to_string()]));
    assert!(parsed.contains(&vec!["playintegrityfix".to_string(), "truman".to_string()]));

    drop(sock);
    let _ = std::fs::remove_file(&path);
}
