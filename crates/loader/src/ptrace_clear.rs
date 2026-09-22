//! ptrace_clear.c port: `perform_ptrace_message_clear` — the seccomp-BPF
//! "exit_group with random args" trick that forces a PTRACE_EVENT_SECCOMP so
//! the tracer can scrub the ptrace status.
//!
//! C-parity notes:
//! - libc 0.2.189 exports the `BPF_*` / `SECCOMP_RET_*` constants, `prctl`,
//!   `PR_SET_SECCOMP` and `SECCOMP_MODE_FILTER`, but not the
//!   `sock_filter` / `sock_fprog` / `seccomp_data` structs (linux/filter.h,
//!   linux/seccomp.h) nor the `BPF_STMT` / `BPF_JUMP` macros — `repr(C)`
//!   mirrors and const helpers below replicate them exactly.
//! - C `fopen` / `fgets(line, 256)` on /proc/self/status becomes
//!   `std::fs::File` + a module-local `fgets_256` that mirrors fgets
//!   byte-for-byte (255-byte truncation, "NULL" at EOF/error). Status lines
//!   are far shorter than 256 bytes, so reads are identical.
//! - `/dev/urandom` is read with `libc::read` into a `[u32; 4]` — the same
//!   16 raw bytes as the C `uint32_t args[4]` (all supported targets are
//!   little-endian).
//! - The final `syscall(__NR_exit_group, ...)` becomes
//!   `libc::syscall(libc::SYS_exit_group, ...)` (`__NR_` / `SYS_` numbering
//!   is identical per arch; args are widened to `c_ulong` exactly like the
//!   register slots the kernel reads them back from).

use std::io::BufRead;
use std::mem::{offset_of, size_of, size_of_val};

use rz_common::{logd, plog};

/// ptrace_clear.c uses the injector LOG_TAG; the RS port logs under "zygisk".
const TAG: &str = rz_common::LOG_TAG;

/// linux/filter.h `struct sock_filter` — not exported by libc.
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)] // fields are written by the helpers and handed to prctl
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// linux/filter.h `struct sock_fprog` — not exported by libc.
#[repr(C)]
#[allow(dead_code)]
struct SockFprog {
    len: u16,
    filter: *mut SockFilter,
}

/// linux/seccomp.h `struct seccomp_data` — not exported by libc. The uapi
/// layout is fixed (identical on LP32 and LP64): nr, arch, then the 64-bit
/// instruction pointer and args.
#[repr(C)]
#[allow(dead_code)] // only touched through offset_of! (the C's offsetof)
struct SeccompData {
    nr: libc::c_int,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

static_assertions::const_assert_eq!(size_of::<SeccompData>(), 64);

/// linux/filter.h `BPF_STMT(code, k)`: `{ (unsigned short)(code), 0, 0, k }`.
const fn bpf_stmt(code: u32, k: u32) -> SockFilter {
    SockFilter {
        code: code as u16,
        jt: 0,
        jf: 0,
        k,
    }
}

/// linux/filter.h `BPF_JUMP(code, k, jt, jf)`: `{ (unsigned short)(code), jt, jf, k }`.
const fn bpf_jump(code: u32, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter {
        code: code as u16,
        jt,
        jf,
        k,
    }
}

/// `fgets(line, sizeof(line) = 256, f)`: up to 255 bytes or until '\n'.
/// `None` at EOF/error (fgets returns NULL on both, so the C does not
/// distinguish either).
fn fgets_256(reader: &mut impl BufRead) -> Option<Vec<u8>> {
    let mut line = Vec::with_capacity(64);
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

        if byte[0] == b'\n' || line.len() == 255 {
            break;
        }
    }

    Some(line)
}

fn seccomp_filters_visible() -> bool {
    let Ok(status_file) = std::fs::File::open("/proc/self/status") else {
        plog!(TAG, "open /proc/self/status");

        return true;
    };

    let mut reader = std::io::BufReader::new(status_file);
    while let Some(line) = fgets_256(&mut reader) {
        // C: strncmp(line, "Seccomp_filters:", strlen("Seccomp_filters:")) != 0
        if !line.starts_with(b"Seccomp_filters:") {
            continue;
        }

        return true;
    }

    false
}

pub fn perform_ptrace_message_clear() {
    // INFO: Since kernel 5.10, Seccomp filters are visible, making hiding via seccomp event unusable
    if seccomp_filters_visible() {
        logd!(TAG, "Seccomp filters are visible, skipping using hiding via seccomp event");

        return;
    }

    let rnd_fd = unsafe {
        libc::open(b"/dev/urandom\0".as_ptr() as *const libc::c_char, libc::O_RDONLY)
    };
    if rnd_fd == -1 {
        plog!(TAG, "open /dev/urandom");

        return;
    }

    let mut args: [u32; 4] = [0; 4];
    let n = unsafe { libc::read(rnd_fd, args.as_mut_ptr() as *mut libc::c_void, size_of_val(&args)) };
    if n != size_of_val(&args) as isize {
        plog!(TAG, "read /dev/urandom");

        unsafe { libc::close(rnd_fd) };

        return;
    }

    unsafe { libc::close(rnd_fd) };

    args[0] |= 0x10000;

    // linux/bpf_common.h + linux/filter.h constants (the libc crate does not
    // expose BPF_* for bionic targets, so mirror them locally — values are
    // ABI-stable in the kernel UAPI).
    const BPF_LD: u32 = 0x00;
    const BPF_W: u32 = 0x00;
    const BPF_ABS: u32 = 0x20;
    const BPF_JMP: u32 = 0x05;
    const BPF_JEQ: u32 = 0x10;
    const BPF_K: u32 = 0x00;
    const BPF_RET: u32 = 0x06;

    // C: offsetof(struct seccomp_data, args[i]) — Rust's offset_of! cannot
    // index arrays, so compute the base offset + i * element size.
    let args_base = offset_of!(SeccompData, args);
    let args_off = |i: usize| (args_base + i * size_of::<u64>()) as u32;

    let mut filter = [
        // INFO: Check syscall number
        bpf_stmt(BPF_LD | BPF_W | BPF_ABS, offset_of!(SeccompData, nr) as u32),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, libc::SYS_exit_group as u32, 0, 9),
        // INFO: Load and check arg0 (lower 32 bits)
        bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            args_off(0),
        ),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, args[0], 0, 7),
        // INFO: Load and check arg1 (lower 32 bits)
        bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            args_off(1),
        ),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, args[1], 0, 5),
        // INFO: Load and check arg2 (lower 32 bits)
        bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            args_off(2),
        ),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, args[2], 0, 3),
        // INFO: Load and check arg3 (lower 32 bits)
        bpf_stmt(
            BPF_LD | BPF_W | BPF_ABS,
            args_off(3),
        ),
        bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, args[3], 0, 1),
    // INFO: All match: return TRACE => will trigger PTRACE_EVENT_SECCOMP
    bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_TRACE),
    // INFO: Default: allow
    bpf_stmt(BPF_RET | BPF_K, libc::SECCOMP_RET_ALLOW),
    ];

    let prog = SockFprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };

    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &prog) } != 0 {
        plog!(TAG, "prctl(SECCOMP)");

        return;
    }

    // INFO: This will trigger a ptrace event, syscall will not execute due to tracee_skip_syscall
    unsafe {
        libc::syscall(
            libc::SYS_exit_group,
            args[0] as libc::c_ulong,
            args[1] as libc::c_ulong,
            args[2] as libc::c_ulong,
            args[3] as libc::c_ulong,
        );
    }
}
