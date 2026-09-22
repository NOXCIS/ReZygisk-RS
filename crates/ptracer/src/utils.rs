//! Port of loader/src/ptracer/utils.c: remote memory access, per-arch register
//! handling, remote calls/syscalls, gadget scanning, wait-status helpers.

use std::io;
use std::mem::size_of;
use std::time::{Duration, Instant};

use rz_common::plog;
use thiserror::Error;

/// Errors that can occur during ptrace register operations.
#[derive(Debug, Error)]
pub enum RegsError {
    #[error("GETREGS ptrace call failed")]
    GetRegsFailed,
    #[error("SETREGS ptrace call failed")]
    SetRegsFailed,
}

pub const TAG: &str = rz_common::LOG_TAG_TRACER;

// libc's android bindings don't export the PTRACE_SEIZE group (kernel 3.4+)
// nor NT_PRSTATUS; glibc's ptrace takes a c_uint request, bionic a c_int.
#[cfg(target_os = "android")]
pub const PTRACE_SEIZE: libc::c_int = 0x4206;
#[cfg(not(target_os = "android"))]
pub const PTRACE_SEIZE: libc::c_uint = 0x4206;
#[cfg(target_os = "android")]
pub const PTRACE_INTERRUPT: libc::c_int = 0x4207;
#[cfg(not(target_os = "android"))]
pub const PTRACE_INTERRUPT: libc::c_uint = 0x4207;
// NT_PRSTATUS is only referenced from the aarch64/arm GET/SETREGSET paths.
#[cfg(target_os = "android")]
#[cfg_attr(not(any(target_arch = "aarch64", target_arch = "arm")), allow(dead_code))]
pub const NT_PRSTATUS: libc::c_int = 1;
#[cfg(not(target_os = "android"))]
#[cfg_attr(not(any(target_arch = "aarch64", target_arch = "arm")), allow(dead_code))]
pub const NT_PRSTATUS: libc::c_int = libc::NT_PRSTATUS;
// arm's PTRACE_SET_SYSCALL is 23 (arch/arm uapi); it commits the kernel-side
// syscall number, which is what actually makes a seccomp trap skip (the
// NT_PRSTATUS write alone doesn't).
#[cfg(target_arch = "aarch64")]
pub const NT_ARM_SYSTEM_CALL: libc::c_int = 0x404;
#[cfg(target_arch = "arm")]
pub const PTRACE_SET_SYSCALL: libc::c_int = 23;

macro_rules! dlogv {
    ($($arg:tt)*) => {{ rz_common::logv!(crate::utils::TAG, $($arg)*); }};
}
macro_rules! dlogd {
    ($($arg:tt)*) => {{ rz_common::logd!(crate::utils::TAG, $($arg)*); }};
}
macro_rules! dlogi {
    ($($arg:tt)*) => {{ rz_common::logi!(crate::utils::TAG, $($arg)*); println!($($arg)*); }};
}
macro_rules! dlogw {
    ($($arg:tt)*) => {{ rz_common::logw!(crate::utils::TAG, $($arg)*); println!($($arg)*); }};
}
macro_rules! dloge {
    ($($arg:tt)*) => {{ rz_common::loge!(crate::utils::TAG, $($arg)*); println!($($arg)*); }};
}
pub(crate) use {dlogd, dloge, dlogi, dlogv, dlogw};

// ---------------------------------------------------------------------------
// wait status helpers (wait.h macros + utils.h WPTEVENT / STOPPED_WITH)
// ---------------------------------------------------------------------------

pub fn wifstopped(status: i32) -> bool {
    (status & 0xff) == 0x7f
}

pub fn wstopsig(status: i32) -> i32 {
    (status >> 8) & 0xff
}

pub fn wptevent(status: i32) -> i32 {
    status >> 16
}

/// monitor.c / utils.h `STOPPED_WITH(sig, event)`.
pub fn stopped_with(status: i32, sig: i32, event: i32) -> bool {
    wifstopped(status) && (status >> 8) == (sig | (event << 8))
}

pub fn wifexited(status: i32) -> bool {
    (status & 0x7f) == 0
}

pub fn wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xff
}

pub fn wifsignaled(status: i32) -> bool {
    let s = status & 0x7f;
    s != 0 && s != 0x7f
}

pub fn wtermsig(status: i32) -> i32 {
    status & 0x7f
}

/// utils.h `parse_ptrace_event`.
pub fn parse_ptrace_event(status: i32) -> &'static str {
    match wptevent(status) {
        libc::PTRACE_EVENT_FORK => "PTRACE_EVENT_FORK",
        libc::PTRACE_EVENT_VFORK => "PTRACE_EVENT_VFORK",
        libc::PTRACE_EVENT_CLONE => "PTRACE_EVENT_CLONE",
        libc::PTRACE_EVENT_EXEC => "PTRACE_EVENT_EXEC",
        libc::PTRACE_EVENT_VFORK_DONE => "PTRACE_EVENT_VFORK_DONE",
        libc::PTRACE_EVENT_EXIT => "PTRACE_EVENT_EXIT",
        libc::PTRACE_EVENT_SECCOMP => "PTRACE_EVENT_SECCOMP",
        libc::PTRACE_EVENT_STOP => "PTRACE_EVENT_STOP",
        _ => "(no event)",
    }
}

/// utils.h `sigabbrev_np` (bionic sys_signame).
pub fn sigabbrev_np(sig: i32) -> &'static str {
    match sig {
        libc::SIGHUP => "HUP",
        libc::SIGINT => "INT",
        libc::SIGQUIT => "QUIT",
        libc::SIGILL => "ILL",
        libc::SIGTRAP => "TRAP",
        libc::SIGABRT => "ABRT",
        libc::SIGBUS => "BUS",
        libc::SIGFPE => "FPE",
        libc::SIGKILL => "KILL",
        libc::SIGUSR1 => "USR1",
        libc::SIGSEGV => "SEGV",
        libc::SIGUSR2 => "USR2",
        libc::SIGPIPE => "PIPE",
        libc::SIGALRM => "ALRM",
        libc::SIGTERM => "TERM",
        libc::SIGCHLD => "CHLD",
        libc::SIGCONT => "CONT",
        libc::SIGSTOP => "STOP",
        libc::SIGTSTP => "TSTP",
        libc::SIGTTIN => "TTIN",
        libc::SIGTTOU => "TTOU",
        libc::SIGURG => "URG",
        libc::SIGXCPU => "XCPU",
        libc::SIGXFSZ => "XFSZ",
        libc::SIGVTALRM => "VTALRM",
        libc::SIGPROF => "PROF",
        libc::SIGWINCH => "WINCH",
        libc::SIGIO => "IO",
        libc::SIGSYS => "SYS",
        _ => "(unknown)",
    }
}

/// utils.c `parse_status`: "0x%x exited with %d" / "signaled with ..." /
/// "stopped by signal=%s(%d),event=%s".
pub fn parse_status(status: i32) -> String {
    let mut buf = format!("0x{status:x} ");

    if wifexited(status) {
        buf.push_str(&format!("exited with {}", wexitstatus(status)));
    } else if wifsignaled(status) {
        let sig = wtermsig(status);
        buf.push_str(&format!("signaled with {}({})", sigabbrev_np(sig), sig));
    } else if wifstopped(status) {
        let stop_sig = wstopsig(status);
        buf.push_str("stopped by ");
        buf.push_str(&format!("signal={}({}),", sigabbrev_np(stop_sig), stop_sig));
        buf.push_str(&format!("event={}", parse_ptrace_event(status)));
    } else {
        buf.push_str("unknown");
    }

    buf
}

/// utils.c `get_program`: readlink /proc/<pid>/exe.
pub fn get_program(pid: i32) -> io::Result<String> {
    let path = std::ffi::CString::new(format!("/proc/{pid}/exe")).unwrap();
    let mut buf = [0u8; libc::PATH_MAX as usize];
    let sz = unsafe { libc::readlink(path.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if sz == -1 {
        return Err(io::Error::last_os_error());
    }

    Ok(String::from_utf8_lossy(&buf[..sz as usize]).into_owned())
}

/// Best-effort `/proc/<pid>/cmdline`, argv joined with single spaces. Empty on
/// any failure — diagnostics only.
pub fn get_cmdline(pid: i32) -> String {
    let path = std::ffi::CString::new(format!("/proc/{pid}/cmdline")).unwrap();
    let mut buf = [0u8; 4096];
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return String::new();
    }
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    unsafe { libc::close(fd) };
    if n <= 0 {
        return String::new();
    }

    buf[..n as usize]
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(String::from_utf8_lossy)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Best-effort parent pid from `/proc/<pid>/stat` (field 4, after the parenthesized
/// comm which may contain spaces). None on any failure.
pub fn get_ppid(pid: i32) -> Option<i32> {
    let path = std::ffi::CString::new(format!("/proc/{pid}/stat")).unwrap();
    let mut buf = [0u8; 1024];
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return None;
    }
    let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    unsafe { libc::close(fd) };
    if n <= 0 {
        return None;
    }

    let s = String::from_utf8_lossy(&buf[..n as usize]);
    let after_comm = s.rfind(')')? + 1;
    s[after_comm..].split_whitespace().nth(1)?.parse().ok()
}

/// utils.c `fork_dont_care`: double fork so the grandchild is reparented away
/// from the tracer (no SIGCHLD back to us). Returns 0 in the grandchild, the
/// intermediate pid in the parent, or -1 when the chain could not be started.
pub fn fork_dont_care() -> i32 {
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        plog!(TAG, "fork 1");
    } else if pid == 0 {
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            plog!(TAG, "fork 2");
            // Never fall through: this child must not run caller (monitor)
            // code as a duplicate — that forked a second monitor competing
            // for the same signalfd/epoll while the original blocked forever
            // in waitpid below.
            unsafe { libc::_exit(127) };
        } else if pid > 0 {
            // _exit, not exit: no atexit/stdio machinery in a forked child.
            unsafe { libc::_exit(0) };
        }
    } else {
        // The intermediate must exit immediately; blocking here forever would
        // stall the monitor's only thread (SIGCHLD drain, watchdog and all).
        // Bound the wait and escalate to SIGKILL if it misbehaves.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut status = 0;
        loop {
            let r = unsafe { libc::waitpid(pid, &mut status, libc::__WALL | libc::WNOHANG) };
            if r == pid {
                if !wifexited(status) || wexitstatus(status) != 0 {
                    return -1;
                }
                break;
            }
            if r == -1 {
                plog!(TAG, "waitpid fork_dont_care");
                return -1;
            }
            if std::time::Instant::now() > deadline {
                dlogw!("fork_dont_care: intermediate {pid} did not exit cleanly, killing");
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, std::ptr::null_mut(), libc::__WALL);
                }
                return -1;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    pid
}

// ---------------------------------------------------------------------------
// Remote memory access (process_vm_readv/writev)
// ---------------------------------------------------------------------------

/// utils.c `write_proc`.
pub fn write_proc(pid: i32, remote_addr: usize, buf: &[u8]) -> isize {
    dlogv!("write to remote addr {remote_addr:x} size {}", buf.len());

    let len = buf.len();
    let local = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: remote_addr as *mut libc::c_void,
        iov_len: len,
    };

    let l = unsafe { libc::process_vm_writev(pid, &local, 1, &remote, 1, 0) };
    if l == -1 {
        plog!(TAG, "process_vm_writev");
    } else if l as usize != len {
        dlogw!("not fully written: {l}, excepted {len}");
    }

    l
}

/// utils.c `read_proc`.
pub fn read_proc(pid: i32, remote_addr: usize, buf: &mut [u8]) -> isize {
    let len = buf.len();
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: len,
    };
    let remote = libc::iovec {
        iov_base: remote_addr as *mut libc::c_void,
        iov_len: len,
    };

    let l = unsafe { libc::process_vm_readv(pid, &local, 1, &remote, 1, 0) };
    if l == -1 {
        plog!(TAG, "process_vm_readv");
    } else if l as usize != len {
        dlogw!("not fully read: {l}, excepted {len}");
    }

    l
}

// ---------------------------------------------------------------------------
// Registers (per-arch; REG_* macros from utils.h)
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserRegs {
    pub regs: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[cfg(target_arch = "arm")]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserRegs {
    pub uregs: [u32; 18],
}

#[cfg(target_arch = "x86_64")]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserRegs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

#[cfg(target_arch = "x86")]
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UserRegs {
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub esi: u32,
    pub edi: u32,
    pub ebp: u32,
    pub eax: u32,
    pub xds: u32,
    pub xes: u32,
    pub xfs: u32,
    pub xgs: u32,
    pub orig_eax: u32,
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub ss: u32,
}

#[cfg(target_arch = "aarch64")]
impl UserRegs {
    pub fn reg_sp(&self) -> u64 { self.sp }
    pub fn set_reg_sp(&mut self, v: u64) { self.sp = v; }
    pub fn reg_ip(&self) -> u64 { self.pc }
    pub fn set_reg_ip(&mut self, v: u64) { self.pc = v; }
    pub fn reg_ret(&self) -> u64 { self.regs[0] }
    pub fn set_reg_sysnr(&mut self, v: i64) { self.regs[8] = v as u64; }
}

#[cfg(target_arch = "arm")]
impl UserRegs {
    pub fn reg_sp(&self) -> u64 { u64::from(self.uregs[13]) }
    pub fn set_reg_sp(&mut self, v: u64) { self.uregs[13] = v as u32; }
    pub fn reg_ip(&self) -> u64 { u64::from(self.uregs[15]) }
    pub fn set_reg_ip(&mut self, v: u64) { self.uregs[15] = v as u32; }
    pub fn reg_ret(&self) -> u64 { u64::from(self.uregs[0]) }
    pub fn set_reg_sysnr(&mut self, v: i64) { self.uregs[7] = v as u32; }
}

#[cfg(target_arch = "x86_64")]
impl UserRegs {
    pub fn reg_sp(&self) -> u64 { self.rsp }
    pub fn set_reg_sp(&mut self, v: u64) { self.rsp = v; }
    pub fn reg_ip(&self) -> u64 { self.rip }
    pub fn set_reg_ip(&mut self, v: u64) { self.rip = v; }
    pub fn reg_ret(&self) -> u64 { self.rax }
    pub fn set_reg_sysnr(&mut self, v: i64) { self.orig_rax = v as u64; }
}

#[cfg(target_arch = "x86")]
impl UserRegs {
    pub fn reg_sp(&self) -> u64 { u64::from(self.esp) }
    pub fn set_reg_sp(&mut self, v: u64) { self.esp = v as u32; }
    pub fn reg_ip(&self) -> u64 { u64::from(self.eip) }
    pub fn set_reg_ip(&mut self, v: u64) { self.eip = v as u32; }
    pub fn reg_ret(&self) -> u64 { u64::from(self.eax) }
    pub fn set_reg_sysnr(&mut self, v: i64) { self.orig_eax = v as u32; }
}

/// utils.c `get_regs` - Result-returning version.
pub fn try_get_regs(pid: i32, regs: &mut UserRegs) -> Result<(), RegsError> {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    unsafe {
        if libc::ptrace(libc::PTRACE_GETREGS, pid, 0, regs as *mut UserRegs as libc::c_long) == -1 {
            plog!(TAG, "getregs");
            return Err(RegsError::GetRegsFailed);
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    unsafe {
        let mut iov = libc::iovec {
            iov_base: regs as *mut UserRegs as *mut libc::c_void,
            iov_len: size_of::<UserRegs>(),
        };

        if libc::ptrace(libc::PTRACE_GETREGSET, pid, crate::utils::NT_PRSTATUS as libc::c_long, &mut iov as *mut libc::iovec as libc::c_long) == -1 {
            plog!(TAG, "GETREGSET failed, trying GETREGS");

            if libc::ptrace(12, pid, 0, regs as *mut UserRegs as libc::c_long) == -1 {
                plog!(TAG, "GETREGS");
                return Err(RegsError::GetRegsFailed);
            }

            return Ok(());
        }
    }

    Ok(())
}

/// utils.c `get_regs` - bool-returning version for backward compatibility.
pub fn get_regs(pid: i32, regs: &mut UserRegs) -> bool {
    try_get_regs(pid, regs).is_ok()
}

/// utils.c `set_regs` - Result-returning version.
pub fn try_set_regs(pid: i32, regs: &mut UserRegs) -> Result<(), RegsError> {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    unsafe {
        if libc::ptrace(libc::PTRACE_SETREGS, pid, 0, regs as *mut UserRegs as libc::c_long) == -1 {
            plog!(TAG, "setregs");
            return Err(RegsError::SetRegsFailed);
        }
    }

    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    unsafe {
        let mut iov = libc::iovec {
            iov_base: regs as *mut UserRegs as *mut libc::c_void,
            iov_len: size_of::<UserRegs>(),
        };

        if libc::ptrace(libc::PTRACE_SETREGSET, pid, crate::utils::NT_PRSTATUS as libc::c_long, &mut iov as *mut libc::iovec as libc::c_long) == -1 {
            plog!(TAG, "SETREGSET failed, trying SETREGS");

            if libc::ptrace(13, pid, 0, regs as *mut UserRegs as libc::c_long) == -1 {
                plog!(TAG, "SETREGS");
                return Err(RegsError::SetRegsFailed);
            }

            return Ok(());
        }
    }

    Ok(())
}

/// utils.c `set_regs` - bool-returning version for backward compatibility.
pub fn set_regs(pid: i32, regs: &mut UserRegs) -> bool {
    try_set_regs(pid, regs).is_ok()
}

/// utils.c `align_stack` (~0xf is negative; cast through signed).
pub fn align_stack(regs: &mut UserRegs, preserve: i64) {
    let sp = regs.reg_sp() as i64;
    regs.set_reg_sp(((sp - preserve) & !0xf) as u64);
}

// ---------------------------------------------------------------------------
// Remote calls
// ---------------------------------------------------------------------------

/// utils.c `remote_call`: run a remote function, return its return value.
/// Returns 0 on failure (matching the C sentinel).
pub fn remote_call(pid: i32, regs: &mut UserRegs, func_addr: u64, return_addr: u64, args: &[i64]) -> u64 {
    align_stack(regs, 0);

    dlogv!("calling remote function {func_addr:x} args {}", args.len());
    for arg in args {
        dlogv!("arg {arg:#x}");
    }

    #[cfg(target_arch = "x86_64")]
    {
        if !args.is_empty() { regs.rdi = args[0] as u64; }
        if args.len() >= 2 { regs.rsi = args[1] as u64; }
        if args.len() >= 3 { regs.rdx = args[2] as u64; }
        if args.len() >= 4 { regs.rcx = args[3] as u64; }
        if args.len() >= 5 { regs.r8 = args[4] as u64; }
        if args.len() >= 6 { regs.r9 = args[5] as u64; }
        if args.len() > 6 {
            let remain = (args.len() - 6) as i64 * size_of::<i64>() as i64;
            align_stack(regs, remain);

            let bytes: Vec<u8> = args[6..].iter().flat_map(|a| a.to_ne_bytes()).collect();
            if write_proc(pid, regs.reg_sp() as usize, &bytes) as usize != bytes.len() {
                dloge!("failed to push arguments");
            }
        }

        regs.set_reg_sp(regs.reg_sp() - size_of::<i64>() as u64);

        let ra = return_addr.to_ne_bytes();
        if write_proc(pid, regs.reg_sp() as usize, &ra) != ra.len() as isize {
            dloge!("failed to write return addr");
        }

        regs.set_reg_ip(func_addr);
    }

    #[cfg(target_arch = "x86")]
    {
        if !args.is_empty() {
            // C: `long remain = args_size * sizeof(long);` — i386 `long` is
            // 4 bytes, so each pushed arg occupies a 4-byte stack slot.
            let remain = args.len() as i64 * size_of::<u32>() as i64;
            align_stack(regs, remain);

            let bytes: Vec<u8> = args.iter().flat_map(|a| (*a as u32).to_ne_bytes()).collect();
            if write_proc(pid, regs.reg_sp() as usize, &bytes) as usize != bytes.len() {
                dloge!("failed to push arguments");
            }
        }

        // C: `regs->REG_SP -= sizeof(long);` — 4 bytes on i386.
        regs.set_reg_sp(regs.reg_sp() - size_of::<u32>() as u64);

        let ra = (return_addr as u32).to_ne_bytes();
        if write_proc(pid, regs.reg_sp() as usize, &ra) != ra.len() as isize {
            dloge!("failed to write return addr");
        }

        regs.set_reg_ip(func_addr);
    }

    #[cfg(target_arch = "aarch64")]
    {
        for (i, arg) in args.iter().enumerate().take(8) {
            regs.regs[i] = *arg as u64;
        }

        if args.len() > 8 {
            let remain = (args.len() - 8) as i64 * size_of::<i64>() as i64;
            align_stack(regs, remain);

            let bytes: Vec<u8> = args[8..].iter().flat_map(|a| a.to_ne_bytes()).collect();
            write_proc(pid, regs.reg_sp() as usize, &bytes);
        }

        regs.regs[30] = return_addr;
        regs.set_reg_ip(func_addr);
    }

    #[cfg(target_arch = "arm")]
    {
        for (i, arg) in args.iter().enumerate().take(4) {
            regs.uregs[i] = *arg as u32;
        }

        if args.len() > 4 {
            // C: `long remain = (args_size - 4) * sizeof(long);` — arm32
            // `long` is 4 bytes, so each stack arg is a 4-byte slot.
            let remain = (args.len() - 4) as i64 * size_of::<u32>() as i64;
            align_stack(regs, remain);

            let bytes: Vec<u8> = args[4..].iter().flat_map(|a| (*a as u32).to_ne_bytes()).collect();
            write_proc(pid, regs.reg_sp() as usize, &bytes);
        }

        regs.uregs[14] = return_addr as u32;
        regs.set_reg_ip(func_addr);

        let cpsr_t_mask: u32 = 1 << 5;
        if regs.reg_ip() & 1 != 0 {
            regs.set_reg_ip(regs.reg_ip() & !1);
            regs.uregs[16] |= cpsr_t_mask;
        } else {
            regs.uregs[16] &= !cpsr_t_mask;
        }
    }

    if !set_regs(pid, regs) {
        dloge!("failed to set regs");
        return 0;
    }

    unsafe {
        libc::ptrace(libc::PTRACE_CONT, pid, 0, 0);
    }

    let mut status = 0;
    if !wait_for_trace_deadline(pid, &mut status, libc::__WALL, Duration::from_secs(30)) {
        dloge!("remote call to {func_addr:#x} did not regain control in time");
        return 0;
    }

    if !get_regs(pid, regs) {
        dloge!("failed to get regs after call");
        return 0;
    }

    if wstopsig(status) == libc::SIGSEGV && wifstopped(status) {
        if regs.reg_ip() != return_addr {
            dloge!("wrong return addr {:#x}", regs.reg_ip());
            return 0;
        }

        regs.reg_ret()
    } else {
        dloge!("stopped by other reason {} at addr {:#x}", parse_status(status), regs.reg_ip());
        0
    }
}

/// utils.c `find_syscall_gadget`: scan executable regions (vdso first) for an
/// svc/syscall instruction.
pub fn find_syscall_gadget(pid: i32, remote_map: &[rz_common::MapEntry]) -> u64 {
    #[cfg(target_arch = "aarch64")]
    let (svc_insn, insn_size): ([u8; 4], usize) = (0xD4000001u32.to_ne_bytes(), 4);
    #[cfg(target_arch = "x86_64")]
    let (svc_insn, insn_size): ([u8; 2], usize) = (0x050Fu16.to_ne_bytes(), 2);
    #[cfg(target_arch = "x86")]
    let (svc_insn, insn_size): ([u8; 2], usize) = (0x80CDu16.to_ne_bytes(), 2);
    #[cfg(target_arch = "arm")]
    let thumb_svc_insn: [u8; 2] = 0xDF00u16.to_ne_bytes();
    #[cfg(target_arch = "arm")]
    let arm_svc_insn: [u8; 4] = 0xEF000000u32.to_ne_bytes();

    for (pass, vdso_only) in [true, false].into_iter().enumerate() {
        let _ = pass;
        for m in remote_map {
            let is_vdso = m.path.contains("[vdso]");
            if !m.perms.exec() || is_vdso != vdso_only {
                continue;
            }

            let mut region_size = m.end - m.start;
            region_size = region_size.min(if vdso_only { 0x10000 } else { 0x100000 });

            let mut buf = vec![0u8; region_size];
            if read_proc(pid, m.start, &mut buf) as usize != region_size {
                continue;
            }

            #[cfg(target_arch = "arm")]
            {
                let mut j = 0;
                while j + arm_svc_insn.len() <= region_size {
                    if buf[j..j + 4] == arm_svc_insn {
                        dlogd!(
                            "found ARM syscall gadget in {} at offset {j:#x}",
                            if vdso_only { "vdso" } else { m.path.as_str() }
                        );
                        return m.start as u64 + j as u64;
                    }
                    j += 4;
                }

                let mut j = 0;
                while j + 2 <= region_size {
                    if buf[j..j + 2] == thumb_svc_insn {
                        dlogd!(
                            "found Thumb syscall gadget in {} at offset {j:#x}",
                            if vdso_only { "vdso" } else { m.path.as_str() }
                        );
                        return m.start as u64 + j as u64 + 1;
                    }
                    j += 2;
                }
            }

            #[cfg(not(target_arch = "arm"))]
            {
                let mut j = 0;
                while j + insn_size <= region_size {
                    if buf[j..j + insn_size] == svc_insn {
                        dlogd!(
                            "found syscall gadget in {} at offset {j:#x}",
                            if vdso_only { "vdso" } else { m.path.as_str() }
                        );
                        return m.start as u64 + j as u64;
                    }
                    j += insn_size;
                }
            }
        }
    }

    dloge!("Failed to find syscall gadget in remote process");

    0
}

/// utils.c `tracee_skip_syscall`: set syscall number to -1 so the seccomp
/// trap becomes a no-op. On arm/arm64 the NT_PRSTATUS write alone doesn't
/// commit the syscall number -- the kernel-side override is required, or the
/// trapped syscall (the loader's exit_group seccomp probe) executes for real.
pub fn tracee_skip_syscall(pid: i32) {
    let mut regs = UserRegs::default();
    if !get_regs(pid, &mut regs) {
        dloge!("Failed to get seccomp regs");
        unsafe { libc::exit(1) };
    }

    regs.set_reg_sysnr(-1);
    if !set_regs(pid, &mut regs) {
        dloge!("Failed to set seccomp regs");
        unsafe { libc::exit(1) };
    }

    // INFO: It might not work, don't check for error (as in C)
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let sysnr: libc::c_int = -1;
        let iov = libc::iovec {
            iov_base: &sysnr as *const libc::c_int as *mut libc::c_void,
            iov_len: size_of::<libc::c_int>(),
        };
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            pid,
            NT_ARM_SYSTEM_CALL as libc::c_long,
            &iov as *const libc::iovec as libc::c_long,
        );
    }
    #[cfg(target_arch = "arm")]
    unsafe {
        libc::ptrace(PTRACE_SET_SYSCALL, pid, 0, -1);
    }
}

/// utils.c `wait_for_trace`: wait a tracee, swallowing SIGCHLD group noise and
/// seccomp traps. On wait failure sets status to `255 << 8` (WIFEXITED=255).
pub fn wait_for_trace(pid: i32, status: &mut i32, flags: i32) {
    loop {
        let result = unsafe { libc::waitpid(pid, status, flags) };
        if result == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }

            dloge!("wait {pid} failed");
            *status = 255 << 8;
            return;
        }

        if wifstopped(*status) && wstopsig(*status) == libc::SIGCHLD {
            dlogi!("process {pid} stopped by SIGCHLD, continue");
            unsafe {
                libc::ptrace(libc::PTRACE_CONT, pid, 0, 0);
            }
            continue;
        } else if *status >> 8 == (libc::SIGTRAP | (libc::PTRACE_EVENT_SECCOMP << 8)) {
            tracee_skip_syscall(pid);
            unsafe {
                libc::ptrace(libc::PTRACE_CONT, pid, 0, 0);
            }
            continue;
        } else if !wifstopped(*status) {
            dloge!("process {pid} not stopped for trace: {}", parse_status(*status));
            return;
        }

        return;
    }
}

/// `wait_for_trace` with a hard deadline. A tracer that blocks forever keeps
/// the zygote frozen and wedges the boot; on expiry the status is set to the
/// same `255 << 8` failure sentinel and `false` is returned so callers take
/// their failure paths (detach / kill + restart cycle).
pub fn wait_for_trace_deadline(pid: i32, status: &mut i32, flags: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let result = unsafe { libc::waitpid(pid, status, flags | libc::WNOHANG) };
        if result == pid {
            // Same filtering as wait_for_trace.
            if wifstopped(*status) && wstopsig(*status) == libc::SIGCHLD {
                dlogi!("process {pid} stopped by SIGCHLD, continue");
                unsafe {
                    libc::ptrace(libc::PTRACE_CONT, pid, 0, 0);
                }
                continue;
            } else if *status >> 8 == (libc::SIGTRAP | (libc::PTRACE_EVENT_SECCOMP << 8)) {
                tracee_skip_syscall(pid);
                unsafe {
                    libc::ptrace(libc::PTRACE_CONT, pid, 0, 0);
                }
                continue;
            } else if !wifstopped(*status) {
                dloge!("process {pid} not stopped for trace: {}", parse_status(*status));
                return false;
            }

            return true;
        }

        if result == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }

            dloge!("wait {pid} failed");
            *status = 255 << 8;
            return false;
        }

        if Instant::now() > deadline {
            dloge!("wait {pid} timed out after {timeout:?}");
            *status = 255 << 8;
            return false;
        }

        std::thread::sleep(Duration::from_millis(10));
    }
}

/// utils.c `wait_for_event_stop`: drain stops until PTRACE_EVENT_STOP.
pub fn wait_for_event_stop(pid: i32) -> bool {
    loop {
        let mut status = 0;
        wait_for_trace(pid, &mut status, libc::__WALL);

        if wifstopped(status) && wstopsig(status) == libc::SIGTRAP && wptevent(status) == libc::PTRACE_EVENT_STOP {
            return true;
        }

        if !wifstopped(status) {
            return false;
        }

        let deliver = if wptevent(status) != 0 { 0 } else { wstopsig(status) };
        if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, deliver) } == -1 {
            plog!(TAG, "PTRACE_CONT while draining to EVENT_STOP");
            return false;
        }
    }
}

/// utils.c `wait_for_ptrace_syscall_stop`.
pub fn wait_for_ptrace_syscall_stop(pid: i32, status: &mut i32) -> bool {
    let mut step_retries = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid, status, libc::__WALL) };
        if waited == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }

            plog!(TAG, "waitpid");
            return false;
        }

        if waited != pid {
            continue;
        }

        if !wifstopped(*status) {
            dloge!("Remote syscall stop is not ptrace-stop: {}", parse_status(*status));
            return false;
        }

        let stop_sig = wstopsig(*status);
        let stop_event = (wptevent(*status)) & 0xff;
        let is_syscall_stop = stop_event == 0 && (stop_sig == libc::SIGTRAP || stop_sig == (libc::SIGTRAP | 0x80));

        if (stop_sig == libc::SIGSTOP || stop_sig == libc::SIGTRAP) && stop_event == libc::PTRACE_EVENT_STOP {
            if step_retries >= 4 {
                dloge!("Remote syscall stuck in ptrace-stop: {}", parse_status(*status));
                return false;
            }
            step_retries += 1;

            dlogv!("Remote syscall got pending ptrace-stop, retrying (retry {step_retries})");

            if unsafe { libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0) } == -1 {
                plog!(TAG, "PTRACE_SYSCALL retry");
                return false;
            }

            continue;
        }

        if is_syscall_stop {
            return true;
        }

        dloge!("Remote syscall unexpected stop: {}", parse_status(*status));
        return false;
    }
}

/// `wait_for_ptrace_syscall_stop` with a hard deadline on the whole wait.
pub fn wait_for_ptrace_syscall_stop_deadline(pid: i32, status: &mut i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut step_retries = 0;
    loop {
        let waited = unsafe { libc::waitpid(pid, status, libc::__WALL | libc::WNOHANG) };
        if waited == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }

            plog!(TAG, "waitpid");
            return false;
        }

        if waited == 0 {
            if Instant::now() > deadline {
                dloge!("Remote syscall wait timed out after {timeout:?}");
                return false;
            }

            std::thread::sleep(Duration::from_millis(10));
            continue;
        }

        if waited != pid {
            continue;
        }

        if !wifstopped(*status) {
            dloge!("Remote syscall stop is not ptrace-stop: {}", parse_status(*status));
            return false;
        }

        let stop_sig = wstopsig(*status);
        let stop_event = (wptevent(*status)) & 0xff;
        let is_syscall_stop = stop_event == 0 && (stop_sig == libc::SIGTRAP || stop_sig == (libc::SIGTRAP | 0x80));

        if (stop_sig == libc::SIGSTOP || stop_sig == libc::SIGTRAP) && stop_event == libc::PTRACE_EVENT_STOP {
            if step_retries >= 4 {
                dloge!("Remote syscall stuck in ptrace-stop: {}", parse_status(*status));
                return false;
            }
            step_retries += 1;

            dlogv!("Remote syscall got pending ptrace-stop, retrying (retry {step_retries})");

            if unsafe { libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0) } == -1 {
                plog!(TAG, "PTRACE_SYSCALL retry");
                return false;
            }

            continue;
        }

        if is_syscall_stop {
            return true;
        }

        dloge!("Remote syscall unexpected stop: {}", parse_status(*status));
        return false;
    }
}

/// utils.c `remote_syscall`: run a syscall in the tracee via a syscall gadget.
pub fn remote_syscall(pid: i32, regs: &mut UserRegs, syscall_gadget: u64, sysnr: i64, args: &[i64]) -> i64 {
    dlogv!("Remote syscall {sysnr} args {} at gadget {syscall_gadget:#x}", args.len());

    // Save the tracee's current register state.
    let mut saved_regs = UserRegs::default();
    if !get_regs(pid, &mut saved_regs) {
        dloge!("Failed to get regs for save");
        return -1;
    }

    #[cfg(target_arch = "aarch64")]
    {
        regs.regs[8] = sysnr as u64;
        for r in regs.regs.iter_mut().take(6) {
            *r = 0;
        }
        for (i, arg) in args.iter().enumerate().take(6) {
            regs.regs[i] = *arg as u64;
        }
        regs.set_reg_ip(syscall_gadget);
        regs.pstate &= !(3u64 << 10); // AARCH64_PSTATE_BTYPE_MASK
    }

    #[cfg(target_arch = "arm")]
    {
        regs.uregs[7] = sysnr as u32;
        for r in regs.uregs.iter_mut().take(6) {
            *r = 0;
        }
        for (i, arg) in args.iter().enumerate().take(6) {
            regs.uregs[i] = *arg as u32;
        }
        regs.set_reg_ip(syscall_gadget);

        let cpsr_t_mask: u32 = 1 << 5;
        if syscall_gadget & 1 != 0 {
            regs.set_reg_ip(syscall_gadget & !1);
            regs.uregs[16] |= cpsr_t_mask;
        } else {
            regs.uregs[16] &= !cpsr_t_mask;
        }
    }

    #[cfg(target_arch = "x86_64")]
    {
        regs.set_reg_sysnr(sysnr);
        regs.rax = sysnr as u64;
        regs.rdi = 0;
        regs.rsi = 0;
        regs.rdx = 0;
        regs.r10 = 0;
        regs.r8 = 0;
        regs.r9 = 0;

        if !args.is_empty() { regs.rdi = args[0] as u64; }
        if args.len() >= 2 { regs.rsi = args[1] as u64; }
        if args.len() >= 3 { regs.rdx = args[2] as u64; }
        if args.len() >= 4 { regs.r10 = args[3] as u64; }
        if args.len() >= 5 { regs.r8 = args[4] as u64; }
        if args.len() >= 6 { regs.r9 = args[5] as u64; }
        regs.set_reg_ip(syscall_gadget);
    }

    #[cfg(target_arch = "x86")]
    {
        regs.set_reg_sysnr(sysnr);
        regs.eax = sysnr as u32;
        regs.ebx = 0;
        regs.ecx = 0;
        regs.edx = 0;
        regs.esi = 0;
        regs.edi = 0;
        regs.ebp = 0;

        if !args.is_empty() { regs.ebx = args[0] as u32; }
        if args.len() >= 2 { regs.ecx = args[1] as u32; }
        if args.len() >= 3 { regs.edx = args[2] as u32; }
        if args.len() >= 4 { regs.esi = args[3] as u32; }
        if args.len() >= 5 { regs.edi = args[4] as u32; }
        if args.len() >= 6 { regs.ebp = args[5] as u32; }
        regs.set_reg_ip(syscall_gadget);
    }

    let mut ret = -1i64;

    'restore: {
        if !set_regs(pid, regs) {
            dloge!("Failed to set regs for syscall");
            break 'restore;
        }

        // Step into the syscall entry, then out of the syscall exit.
        for i in 0..2 {
            if unsafe { libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0) } == -1 {
                plog!(TAG, "PTRACE_SYSCALL");
                ret = -1;
                break 'restore;
            }

            let mut status = 0;
            if !wait_for_ptrace_syscall_stop_deadline(pid, &mut status, Duration::from_secs(15)) {
                break 'restore;
            }

            if i == 0 {
                dlogv!("Remote syscall {sysnr} got PTRACE_SYSCALL entry-stop, continuing to exit-stop");
            }
        }

        if !get_regs(pid, regs) {
            dloge!("Failed to get regs after PTRACE_SYSCALL");
            ret = -1;
            break 'restore;
        }

        ret = regs.reg_ret() as i64;
        dlogv!("Remote syscall {sysnr} succeeded: {ret}");
    }

    *regs = saved_regs;
    if !set_regs(pid, regs) {
        dloge!("Failed to restore regs after syscall");
    }

    ret
}

// ---------------------------------------------------------------------------
// Module / symbol locating on maps
// ---------------------------------------------------------------------------

/// utils.c `position_after`: strrchr + 1 without modifying the string.
pub fn position_after(s: &str, needle: char) -> &str {
    match s.rfind(needle) {
        Some(pos) => &s[pos + needle.len_utf8()..],
        None => s,
    }
}

/// utils.c `find_module_return_addr`: first non-exec mapping whose file name
/// starts with `suffix`.
pub fn find_module_return_addr(map: &[rz_common::MapEntry], suffix: &str) -> usize {
    for m in map {
        if m.path.is_empty() || m.perms.exec() {
            continue;
        }

        let file_name = position_after(&m.path, '/');
        if file_name.len() < suffix.len() || !file_name.starts_with(suffix) {
            continue;
        }

        return m.start;
    }

    0
}

/// utils.c `find_module_base`: first mapping of `file` with offset 0.
pub fn find_module_base(map: &[rz_common::MapEntry], file: &str) -> usize {
    for m in map {
        if m.path.is_empty() || m.offset != 0 {
            continue;
        }
        if m.path != file {
            continue;
        }

        return m.start;
    }

    0
}

/// elf_util.c `handle_indirect_symbol`: execute the IFUNC resolver in this
/// (tracer) process with the arch-correct arguments and return the selected
/// implementation's local address. The tracer maps the same libc file as the
/// tracee, so the returned local offset translates to the remote space.
///
/// # Safety
/// `resolver_addr` must point at executable code inside this process (the
/// local base + a file-relative st_value of an IFUNC resolver).
#[cfg(any(target_arch = "arm", target_arch = "aarch64", target_arch = "x86", target_arch = "x86_64", target_arch = "riscv64"))]
unsafe fn call_ifunc_resolver(resolver_addr: usize) -> usize {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        // AOSP sys/ifunc.h __ifunc_arg_t; linkers pass hwcap | _IFUNC_ARG_HWCAP.
        #[repr(C)]
        struct IfuncArg {
            size: u64,
            hwcap: u64,
            hwcap2: u64,
        }
        const IFUNC_ARG_HWCAP: u64 = 1u64 << 62;
        type Resolver = unsafe extern "C" fn(u64, *mut IfuncArg) -> u64;

        let mut args = IfuncArg {
            size: size_of::<IfuncArg>() as u64,
            hwcap: libc::getauxval(libc::AT_HWCAP),
            hwcap2: libc::getauxval(libc::AT_HWCAP2),
        };
        let resolver: Resolver = std::mem::transmute(resolver_addr);
        resolver(args.hwcap | IFUNC_ARG_HWCAP, &mut args) as usize
    }
    #[cfg(target_arch = "arm")]
    unsafe {
        // arm32: resolver takes unsigned long (AT_HWCAP), returns Elf32_Addr.
        type Resolver = unsafe extern "C" fn(libc::c_ulong) -> u32;

        let resolver: Resolver = std::mem::transmute(resolver_addr);
        resolver(libc::getauxval(libc::AT_HWCAP)) as usize
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "riscv64"))]
    unsafe {
        // x86/x86_64/riscv64: resolver takes no arguments.
        type Resolver = unsafe extern "C" fn() -> usize;

        let resolver: Resolver = std::mem::transmute(resolver_addr);
        resolver()
    }
}

/// utils.c `find_func_addr`: resolve `func` in `module` via the local file,
/// then translate to the remote address space through the two bases.
pub fn find_func_addr(
    local_info: &[rz_common::MapEntry],
    remote_info: &[rz_common::MapEntry],
    module: &str,
    func: &str,
) -> u64 {
    let local_base = find_module_base(local_info, module);
    if local_base == 0 {
        dlogd!("failed to find local base for module {module}");
        return 0;
    }

    let remote_base = find_module_base(remote_info, module);
    if remote_base == 0 {
        dlogd!("failed to find remote base for module {module}");
        return 0;
    }

    dlogd!("found local base {local_base:#x} remote base {remote_base:#x}");

    let Ok(raw) = std::fs::read(module) else {
        dlogw!("failed to create elf img {module}");
        return 0;
    };
    let Ok(img) = rz_elf::ElfImage::parse(&raw) else {
        dlogw!("failed to create elf img {module}");
        return 0;
    };

    let Some(sym) = img.symbol_by_name(func) else {
        dlogd!("failed to find symbol {func} in {module}");
        return 0;
    };

    dlogd!("found symbol {func} in {module}: {:#x}", sym.value);

    // getSymbAddress: an IFUNC's st_value is its resolver, not the
    // implementation — run the resolver locally to pick the real body
    // (bionic arm32/arm64 ship strlen/memcpy/... as IFUNCs).
    let local_rel: i64 = if sym.info & 0xf == rz_elf::STT_GNU_IFUNC {
        dlogd!("Resolving STT_GNU_IFUNC symbol {func}");

        let resolver_addr = (local_base as i64 + sym.value as i64 - img.bias()) as usize;
        let impl_local = unsafe { call_ifunc_resolver(resolver_addr) };
        if impl_local == 0 {
            return 0;
        }

        (impl_local as i64 - local_base as i64) as i64
    } else {
        sym.value as i64 - img.bias()
    };

    let addr = local_rel + remote_base as i64;
    dlogd!("addr {addr:#x}");

    addr as u64
}

/// utils.c `get_addr_mem_region`.
pub fn get_addr_mem_region(map: &[rz_common::MapEntry], addr: usize) -> String {
    for m in map {
        if m.start <= addr && m.end > addr {
            let path = if m.path.is_empty() { "<anonymous>" } else { m.path.as_str() };
            return format!(
                "{path} {}{}{}",
                if m.perms.read() { "r" } else { "-" },
                if m.perms.write() { "w" } else { "-" },
                if m.perms.exec() { "x" } else { "-" },
            );
        }
    }

    "<unknown>".to_string()
}

/// utils.c `ptrace_poke_u32`: POKEDATA lane write, bypasses RELRO.
/// Live only in the arm32 tango path; exercised by tests on other targets.
#[cfg_attr(not(target_arch = "arm"), allow(dead_code))]
pub fn ptrace_poke_u32(pid: i32, addr: u64, value: u32) -> bool {
    let word_mask = size_of::<libc::c_ulong>() as u64 - 1;
    let aligned = addr & !word_mask;
    let shift = (addr & word_mask) * 8;

    #[cfg(target_os = "android")]
    unsafe {
        *libc::__errno() = 0;
        let data = libc::ptrace(libc::PTRACE_PEEKDATA, pid, aligned as *mut libc::c_void, 0) as u64;
        if *libc::__errno() != 0 {
            plog!(TAG, "ptrace peekdata at {addr:#x}");
            return false;
        }

        let lane_mask64 = 0xFFFFFFFFu64 << shift;
        let masked = data & !lane_mask64;
        let patched = masked | ((u64::from(value)) << shift);
        if libc::ptrace(libc::PTRACE_POKEDATA, pid, aligned as *mut libc::c_void, patched as *mut libc::c_void) == -1 {
            plog!(TAG, "ptrace pokedata at {addr:#x}");
            return false;
        }
    }

    #[cfg(not(target_os = "android"))]
    unsafe {
        *libc::__errno_location() = 0;
        let data = libc::ptrace(libc::PTRACE_PEEKDATA, pid, aligned as *mut libc::c_void, 0) as u64;
        if *libc::__errno_location() != 0 {
            plog!(TAG, "ptrace peekdata at {addr:#x}");
            return false;
        }

        let lane_mask64 = 0xFFFFFFFFu64 << shift;
        let masked = data & !lane_mask64;
        let patched = masked | ((u64::from(value)) << shift);
        if libc::ptrace(libc::PTRACE_POKEDATA, pid, aligned as *mut libc::c_void, patched as *mut libc::c_void) == -1 {
            plog!(TAG, "ptrace pokedata at {addr:#x}");
            return false;
        }
    }

    true
}

/// utils.c `find_arm32_ret_gadget`: scan 32-bit guest regions for a Thumb
/// `BX LR` (returns the address WITH the Thumb bit, like the C).
/// Unused in the C reference as well; kept for parity.
#[allow(dead_code)]
pub fn find_arm32_ret_gadget(pid: i32, remote_map: &[rz_common::MapEntry]) -> u64 {
    let bx_lr: [u8; 2] = 0x4770u16.to_ne_bytes();

    for m in remote_map {
        if !m.perms.exec() || m.start as u64 >= 0x1_0000_0000 {
            continue;
        }

        let region_size = (m.end - m.start).min(0x10000);

        let mut buf = vec![0u8; region_size];
        if read_proc(pid, m.start, &mut buf) as usize != region_size {
            continue;
        }

        let mut j = 0;
        while j + 2 <= region_size {
            if buf[j..j + 2] == bx_lr {
                let addr = m.start as u64 + j as u64 + 1;
                dlogd!(
                    "found arm32 ret gadget (BX LR) at {:#x} in {}",
                    addr - 1,
                    if m.path.is_empty() { "<anon>" } else { m.path.as_str() }
                );
                return addr;
            }
            j += 2;
        }
    }

    dloge!("Failed to find arm32 ret gadget in 32-bit guest regions");

    0
}

/// utils.c `find_tramp_padding`: find `needed` bytes of zero padding at the
/// tail of an RX region (up to 8 pages), 4-byte aligned.
/// Live only in the arm32 tango path; exercised by tests on other targets.
#[cfg_attr(not(target_arch = "arm"), allow(dead_code))]
pub fn find_tramp_padding(pid: i32, rx_start: u32, rx_end: u32, needed: usize) -> u32 {
    let map_size = rx_end - rx_start;
    let mut page_count = (map_size / 0x1000) as i32;
    if page_count > 8 {
        page_count = 8;
    }

    let scan_start = rx_end - page_count as u32 * 0x1000;
    let mut zero_run_end = rx_end;

    for page in 0..page_count {
        let page_addr = rx_end - (page + 1) as u32 * 0x1000;
        let mut buf = [0u8; 0x1000];
        if read_proc(pid, page_addr as usize, &mut buf) as usize != buf.len() {
            break;
        }

        for off in (0..buf.len()).rev() {
            if buf[off] == 0 {
                continue;
            }

            let candidate = (page_addr + off as u32 + 1 + 3) & !3;
            if zero_run_end >= candidate && (zero_run_end - candidate) as usize >= needed {
                return candidate;
            }

            zero_run_end = page_addr + off as u32;
        }
    }

    let candidate = (scan_start + 3) & !3;
    if zero_run_end >= candidate && (zero_run_end - candidate) as usize >= needed {
        return candidate;
    }

    dlogd!("Failed to find {needed}-byte trampoline padding in {rx_start:#x}-{rx_end:#x}");

    0
}

// --- Tango linker watch (utils.c tango_wait_linker_ready) ---

/// utils.h `struct tango_linker_watch`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TangoLinkerWatch {
    pub libc_init_got_slot: u32,
    pub libc_init_initial: u32,
    pub libc_init_resolved: u32,
}

/// utils.c `find_jump_slot_got_offset_elf32`: locate `symbol`'s JUMP_SLOT GOT
/// offset in an ELF32 file. Returns (min PT_LOAD vaddr, GOT slot offset).
pub fn find_jump_slot_got_offset_elf32(elf_path: &str, symbol: &str) -> Option<(u32, u32)> {
    let raw = std::fs::read(elf_path).ok()?;
    let img = rz_elf::ElfImage::parse(&raw).ok()?;

    // min_vaddr over PT_LOADs (C elf32 scan); bias() is the same for .so files.
    let min_vaddr = img.bias();

    for rel in img.relocations().ok()? {
        if rel.rtype != rz_elf::arch::types::arm::JUMP_SLOT {
            continue;
        }

        let Some(sym) = img.symbol_at(rel.sym_idx as usize) else {
            continue;
        };
        if sym.name == symbol {
            return Some((min_vaddr as u32, rel.offset as u32));
        }
    }

    None
}

/// utils.c `tango_wait_linker_ready`: step the tracee with PTRACE_SYSCALL until
/// the `__libc_init` GOT slot in app_process32 is resolved by the linker.
pub fn tango_wait_linker_ready(pid: i32, watch: &mut TangoLinkerWatch) -> bool {
    loop {
        if watch.libc_init_got_slot == 0 {
            let pid_str = pid.to_string();
            let Some(remote_map) = rz_common::parse_maps(&pid_str) else {
                dloge!("Failed to parse remote maps for pid {pid}");
                return false;
            };

            *watch = TangoLinkerWatch::default();
            for m in &remote_map {
                if m.path.is_empty()
                    || m.start as u64 >= 0x1_0000_0000
                    || m.offset != 0
                    || !m.path.contains("app_process32")
                {
                    continue;
                }

                let Some((bias, got_off)) = find_jump_slot_got_offset_elf32(&m.path, "__libc_init")
                else {
                    dlogd!("Failed to find __libc_init in JMPREL of '{}'", m.path);
                    continue;
                };

                // utils.c:694: ((uint32_t)(uintptr_t)m->start - bias) + got_off
                // is unsigned wrapping arithmetic on the 32-bit values.
                watch.libc_init_got_slot = (m.start as u32).wrapping_sub(bias).wrapping_add(got_off);

                break;
            }

            if watch.libc_init_got_slot != 0 {
                let mut initial = [0u8; 4];
                if read_proc(pid, watch.libc_init_got_slot as usize, &mut initial) == 4 {
                    watch.libc_init_initial = u32::from_le_bytes(initial);
                    dlogi!(
                        "Found __libc_init GOT@{:x} (initial={:x}), waiting for linker",
                        watch.libc_init_got_slot,
                        watch.libc_init_initial
                    );
                } else {
                    dlogd!("Failed to read __libc_init GOT@{:x}", watch.libc_init_got_slot);
                    *watch = TangoLinkerWatch::default();
                }
            }
        } else {
            let mut cur = [0u8; 4];
            if read_proc(pid, watch.libc_init_got_slot as usize, &mut cur) == 4 {
                let got_current = u32::from_le_bytes(cur);
                if got_current != 0 && got_current != watch.libc_init_initial {
                    watch.libc_init_resolved = got_current;
                    dlogi!(
                        "Resolved __libc_init ({:x} -> {:x}, pid {})",
                        watch.libc_init_initial,
                        got_current,
                        pid
                    );
                    return true;
                }
            }
        }

        if unsafe { libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0) } == -1 {
            plog!(TAG, "Failed to step syscall");
            return false;
        }

        let mut status = 0;
        if !wait_for_ptrace_syscall_stop(pid, &mut status) {
            dloge!("Process {pid} died while waiting for injection point");
            return false;
        }
    }
}
