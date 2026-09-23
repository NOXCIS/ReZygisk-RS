//! Port of loader/src/ptracer/ptracer.c: PTRACE_SEIZE machinery, the
//! inject-on-main entry-rewrite trick, and the tango arm32 GOT-hook path.

use std::mem::size_of;

use rz_common::plog;
use thiserror::Error;

use crate::remote_csoloader::remote_csoloader_load_and_resolve_entry;
use crate::utils::{
    dlogd, dloge, dlogi, dlogv, dlogw, find_module_return_addr, get_addr_mem_region, get_regs,
    parse_status, read_proc, remote_call, set_regs, tango_wait_linker_ready, wait_for_event_stop,
    wait_for_trace_deadline, write_proc, TangoLinkerWatch, UserRegs, PTRACE_INTERRUPT,
    PTRACE_SEIZE, TAG,
};

/// Errors that can occur during injection operations.
#[allow(
    dead_code,
    reason = "reserved error surface for the injector; the current call sites \
              log and return sentinel values instead"
)]
#[derive(Debug, Error)]
pub enum InjectError {
    #[error("failed to parse remote maps")]
    MapsParseFailed,
    #[error("failed to get registers")]
    GetRegsFailed,
    #[error("failed to set registers")]
    SetRegsFailed,
    #[error("AT_ENTRY not found in auxv")]
    AtEntryNotFound,
    #[error("failed to load library: {0}")]
    LoadLibraryFailed(String),
    #[error("remote call failed")]
    RemoteCallFailed,
    #[error("ptrace operation failed: {0}")]
    PtraceFailed(&'static str),
    #[error("timeout waiting for trace event")]
    TraceTimeout,
    #[error("unexpected stop status: {0}")]
    UnexpectedStopStatus(String),
}

// Blocking wait used only by the arm32 tango path.
#[cfg(target_arch = "arm")]
use crate::utils::wait_for_trace;

#[cfg_attr(not(target_arch = "arm"), allow(unused_imports))]
use std::time::Duration;

/// Blocking wait budget for each zygote-trace step: exceeding it fails the
/// injection (kill + restart cycle) instead of freezing the zygote forever.
const TRACE_STEP_TIMEOUT: Duration = Duration::from_secs(15);

// auxv type ids are c_int-sized on 32-bit targets.
#[allow(clippy::unnecessary_cast)]
const AT_ENTRY: u64 = libc::AT_ENTRY as u64;
#[allow(clippy::unnecessary_cast)]
const AT_NULL: u64 = libc::AT_NULL as u64;

const LIB_PATH_64: &str = "/data/adb/modules/rezygisk/lib64/libzygisk.so";
const LIB_PATH_32: &str = "/data/adb/modules/rezygisk/lib/libzygisk.so";
const TANGO_LIB_PATH: &str = "/data/adb/modules/rezygisk/lib/libzygisk.so";

/// ptracer.c `STOPPED_WITH(sig, event)` on `status`.
fn stopped_with(status: i32, sig: i32, event: i32) -> bool {
    crate::utils::stopped_with(status, sig, event)
}

/// ptracer.c inject_on_main's post-CONT check: `WIFSTOPPED && WSTOPSIG == sig`.
fn stopped_sig(status: i32, sig: i32) -> bool {
    crate::utils::wifstopped(status) && crate::utils::wstopsig(status) == sig
}

#[cfg(target_arch = "arm")]
mod tango {
    use super::*;
    use crate::utils::{dlogw, find_tramp_padding, ptrace_poke_u32, wait_for_ptrace_syscall_stop};

    /// ptracer.c `inject_tango`: the tango translator intercepts BKPT/UDF in
    /// userspace, so injection runs a thumb trampoline written into executable
    /// padding that mprotects the payload RWX, calls `entry(1)`, then raises
    /// SIGTRAP via kill(getpid(), SIGTRAP) to hand control back to the tracer.
    pub(super) fn inject_tango(
        pid: i32,
        lib_path: &str,
        libc_init_target: u32,
        libc_init_got_slot: u32,
    ) -> bool {
        let mut regs = UserRegs::default();
        if !get_regs(pid, &mut regs) {
            plog!(TAG, "Failed to get registers");
            return false;
        }

        let backup = regs;

        let pid_str = pid.to_string();
        let Some(remote_map) = rz_common::parse_maps(&pid_str) else {
            dloge!("Failed to parse remote maps for pid {pid}");
            return false;
        };

        let Some(local_map) = rz_common::parse_maps("self") else {
            dloge!("Failed to parse local maps");
            return false;
        };

        let mut ok = false;
        let mut need_restore = true;

        'tango_done: {
            let Some(mapped) = remote_csoloader_load_and_resolve_entry(
                pid,
                &mut regs,
                &remote_map,
                &local_map,
                lib_path,
            ) else {
                dloge!("Failed to load {lib_path}");
                break 'tango_done;
            };

            let lib_base = mapped.base as u32;
            let lib_size = mapped.total_size as u32;
            let lib_entry = mapped.entry as u32;

            dlogd!("Mapped {lib_path} at {lib_base:#x} (size: {lib_size:#x}, entry={lib_entry:#x})");

            if lib_entry == 0 {
                dloge!("Failed to find 'entry' symbol in {lib_path}");
                break 'tango_done;
            }

            // mprotect(lib_base, lib_size, RWX); entry(lib_base, lib_size, 1);
            // getpid(); kill(getpid(), SIGTRAP). See ptracer.c for the encoding.
            // ptracer.c:83-104: the C array carries a trailing 0 placeholder
            // word, so sizeof(code) is 48 bytes — the trampoline reservation
            // must cover the tail-call stub written at tramp+32..tramp+48.
            let code: [u32; 12] = [
                0x4807B5FF, 0x22074907, 0xDF00277D, 0x49054804, 0x4B052201, 0x27144798,
                0x2105DF00, 0xDF002725, lib_base, lib_size, lib_entry, 0,
            ];

            let mut tramp = 0u32;
            for m in &remote_map {
                if tramp != 0 {
                    break;
                }
                if m.path.is_empty() || !m.perms.exec() || m.start as u64 >= 0x1_0000_0000 {
                    continue;
                }

                tramp = find_tramp_padding(pid, m.start as u32, m.end as u32, size_of_val(&code));
            }

            if tramp == 0 {
                dloge!(
                    "Failed to find enough executable padding for trampoline ({} bytes)",
                    size_of_val(&code)
                );
                break 'tango_done;
            }

            for (i, word) in code.iter().enumerate() {
                if ptrace_poke_u32(pid, (tramp + i as u32 * 4) as u64, *word) {
                    continue;
                }

                dloge!("Failed to write trampoline word {i}");
                break 'tango_done;
            }

            dlogd!(
                "GOT hook __libc_init in app_process32 ({libc_init_target:#x} to trampoline {:#x})",
                tramp | 1
            );

            let tramp_thumb = tramp | 1;
            let thumb_bytes = tramp_thumb.to_le_bytes();
            if write_proc(pid, libc_init_got_slot as usize, &thumb_bytes) != 4
                && !ptrace_poke_u32(pid, libc_init_got_slot as u64, tramp_thumb)
            {
                plog!(TAG, "Patch GOT entry at {libc_init_got_slot:#x}");
                break 'tango_done;
            }

            let mut run = backup;
            if !set_regs(pid, &mut run) {
                dloge!("Failed to restore regs before trampoline run");
                break 'tango_done;
            }

            need_restore = false;

            if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) } == -1 {
                plog!(TAG, "PTRACE_CONT for trampoline execution");
                break 'tango_done;
            }

            // Wait for the SIGTRAP raised by the trampoline's kill().
            loop {
                let mut status = 0;
                wait_for_trace(pid, &mut status, libc::__WALL);

                if !crate::utils::wifstopped(status) {
                    dloge!("Process {pid} exited during trampoline (status {status:#x})");
                    break 'tango_done;
                }

                let sig = crate::utils::wstopsig(status);
                let event = (status >> 16) & 0xFF;
                if sig == libc::SIGTRAP && event == 0 {
                    break;
                }

                let cont_sig = if event != 0 { 0 } else { sig };
                if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, cont_sig) } == -1 {
                    plog!(TAG, "PTRACE_CONT while waiting trampoline SIGTRAP");
                    break 'tango_done;
                }
            }

            dlogd!("Caught trampoline SIGTRAP");

            // Clean the trampoline after catching the SIGTRAP to avoid detections.
            for i in 0..code.len() {
                ptrace_poke_u32(pid, (tramp + i as u32 * 4) as u64, 0);
            }

            // Also clean the GOT entry.
            if !ptrace_poke_u32(pid, libc_init_got_slot as u64, libc_init_target) {
                dlogw!("Failed to restore GOT at {libc_init_got_slot:#x}");
            }

            dlogd!("Restored __libc_init GOT entry and zeroed trampoline");

            // Tango keeps memory-side state that would desync if we rewound
            // via set_regs, so write a tiny tail-call stub jumping into
            // __libc_init instead.
            ptrace_poke_u32(pid, (tramp + 32) as u64, 0x40FFE8BD); // POP.W {r0-r7,lr}
            ptrace_poke_u32(pid, (tramp + 36) as u64, 0xC004F8DF); // LDR.W r12,[PC,#4]
            ptrace_poke_u32(pid, (tramp + 40) as u64, 0x00004760); // BX r12 ; padding
            ptrace_poke_u32(pid, (tramp + 44) as u64, libc_init_target);

            if unsafe { libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0) } == -1 {
                plog!(TAG, "PTRACE_SYSCALL for tail-call stub");
                ok = true;
                break 'tango_done;
            }

            let mut post_stub_status = 0;
            if !wait_for_ptrace_syscall_stop(pid, &mut post_stub_status) {
                dloge!("Process {pid} died waiting for post-stub syscall");
                break 'tango_done;
            }

            // Zero the stub.
            for i in 0..4 {
                ptrace_poke_u32(pid, (tramp + 32 + i as u32 * 4) as u64, 0);
            }

            ok = true;
        }

        if need_restore {
            let mut restore = backup;
            if let Err(err) = crate::utils::try_set_regs(pid, &mut restore) {
                dloge!(
                    "failed to restore tracee registers after trampoline: {err:?} — zygote left with mangled register state"
                );
            }
        }

        ok
    }
}

/// ptracer.c `inject_on_main`: let the linker initialize by replacing AT_ENTRY
/// with a poisoned address, catching the SIGSEGV, mapping libzygisk.so
/// remotely, calling its `entry` via remote_call, then rewinding to entry.
fn inject_on_main(pid: i32, lib_path: &str) -> bool {
    dlogi!("injecting {lib_path} to zygote {pid}");

    // Parsing KernelArgumentBlock:
    // https://cs.android.com/android/platform/superproject/main/+/main:bionic/libc/private/KernelArgumentBlock.h
    let pid_str = pid.to_string();

    let Some(map) = rz_common::parse_maps(&pid_str) else {
        dloge!("failed to parse remote maps");
        return false;
    };

    let mut regs = UserRegs::default();
    if !get_regs(pid, &mut regs) {
        return false;
    }

    let arg = regs.reg_sp() as usize;
    dlogv!("kernel argument {arg:x} {}", get_addr_mem_region(&map, arg));

    let ptr_size = size_of::<usize>();

    // argc lives at sp; argv is sp + 1 pointer.
    let mut argc_buf = [0u8; 4];
    read_proc(pid, arg, &mut argc_buf);
    let argc = i32::from_le_bytes(argc_buf);
    dlogv!("argc {argc}");

    let argv = arg + ptr_size;
    let envp = argv + (argc as usize + 1) * ptr_size;
    dlogv!("envp {envp:#x}");

    // Walk envp until the NULL terminator.
    let mut p = envp;
    loop {
        let mut buf = [0u8; size_of::<usize>()];
        if read_proc(pid, p, &mut buf) as usize != buf.len() {
            break;
        }

        if usize::from_le_bytes(buf) == 0 {
            break;
        }

        p += ptr_size;
    }

    p += ptr_size;

    // auxv starts here.
    let auxv = p;
    dlogv!("auxv {auxv:#x} {}", get_addr_mem_region(&map, auxv));

    let auxv_entsize = size_of::<usize>() * 2;
    let mut v = auxv;
    let mut entry_addr = 0usize;
    let mut addr_of_entry_addr = 0usize;

    loop {
        let mut buf = [0u8; size_of::<usize>() * 2];
        if read_proc(pid, v, &mut buf) as usize != buf.len() {
            break;
        }

        let (a_type, a_val) = if cfg!(target_pointer_width = "64") {
            (
                u64::from_le_bytes(buf[0..8].try_into().unwrap()),
                u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            )
        } else {
            (
                u32::from_le_bytes(buf[0..4].try_into().unwrap()) as u64,
                u32::from_le_bytes(buf[4..8].try_into().unwrap()) as u64,
            )
        };

        if a_type == AT_ENTRY {
            entry_addr = a_val as usize;
            addr_of_entry_addr = v + size_of::<usize>();

            dlogv!(
                "entry address {entry_addr:x} {} (entry={auxv:#x}, entry_addr={addr_of_entry_addr:#x})",
                get_addr_mem_region(&map, entry_addr)
            );

            break;
        }

        if a_type == AT_NULL {
            break;
        }

        v += auxv_entsize;
    }

    if entry_addr == 0 {
        dloge!("failed to get entry");
        return false;
    }

    // Replace the program entry with an invalid address. For arm32
    // compatibility, keep the entry address's thumb bit.
    let break_addr = ((-0x0Fisize & !1isize) as usize) | (entry_addr & 1usize);
    let break_bytes = break_addr.to_le_bytes();
    if write_proc(pid, addr_of_entry_addr, &break_bytes) as usize != break_bytes.len() {
        return false;
    }

    unsafe {
        libc::ptrace(libc::PTRACE_CONT, pid, 0, 0);
    }

    let mut status = 0;
    if !wait_for_trace_deadline(pid, &mut status, libc::__WALL, Duration::from_secs(30)) {
        dloge!("zygote never hit the poisoned entry");
        return false;
    }
    if stopped_sig(status, libc::SIGSEGV) {
        if !get_regs(pid, &mut regs) {
            return false;
        }

        if (regs.reg_ip() as usize & !1) != (break_addr & !1) {
            dloge!("stopped at unknown addr {:#x}", regs.reg_ip());
            return false;
        }

        // The linker has been initialized now, we can do dlopen.
        dlogd!("stopped at entry");

        // Restore entry address.
        let entry_bytes = entry_addr.to_le_bytes();
        if write_proc(pid, addr_of_entry_addr, &entry_bytes) as usize != entry_bytes.len() {
            return false;
        }

        let backup = regs;

        let Some(map) = rz_common::parse_maps(&pid_str) else {
            dloge!("failed to parse remote maps");
            return false;
        };

        let Some(local_map) = rz_common::parse_maps("self") else {
            dloge!("failed to parse local maps");
            return false;
        };

        let libc_return_addr = find_module_return_addr(&map, "libc.so");
        dlogd!("libc return addr {libc_return_addr:#x}");

        let Some(mapped) =
            remote_csoloader_load_and_resolve_entry(pid, &mut regs, &map, &local_map, lib_path)
        else {
            dloge!("remote CSOLoader mapping failed");
            return false;
        };

        let args = [mapped.base as i64, mapped.total_size as i64, 0 /* tango_flag */];
        let ret = remote_call(pid, &mut regs, mapped.entry as u64, libc_return_addr as u64, &args);
        dlogi!("client entry call returned {ret:#x}");

        // remote_call uses a deliberate SIGSEGV on an invalid return address
        // to regain control. If the call faults elsewhere (e.g., inside
        // injector code), REG_IP won't match.
        #[cfg(target_arch = "arm")]
        let injector_ok = (regs.reg_ip() as usize & !1) == (libc_return_addr & !1);
        #[cfg(not(target_arch = "arm"))]
        let injector_ok = regs.reg_ip() as usize == libc_return_addr;
        if !injector_ok {
            let stopped_region = rz_common::parse_maps(&pid_str)
                .map(|m| get_addr_mem_region(&m, regs.reg_ip() as usize))
                .unwrap_or_else(|| "<maps unavailable>".to_string());

            dloge!("injector entry faulted at {:#x} ({})", regs.reg_ip(), stopped_region);

            // Restore registers before reporting failure. A failed restore
            // leaves the tracee mangled — surface it loudly instead of
            // silently continuing with a corrupted zygote.
            let mut restore = backup;
            restore.set_reg_ip(entry_addr as u64);
            if let Err(err) = crate::utils::try_set_regs(pid, &mut restore) {
                dloge!(
                    "failed to restore tracee registers after injector fault: {err:?} — zygote left with mangled register state"
                );
            }

            return false;
        }

        // Reset pc to entry.
        let mut restore = backup;
        restore.set_reg_ip(entry_addr as u64);
        dlogi!("invoke entry");

        // Restore registers.
        if !set_regs(pid, &mut restore) {
            return false;
        }

        true
    } else {
        dloge!("stopped by other reason: {}", parse_status(status));

        false
    }
}

/// ptracer.c `trace_zygote`.
pub fn trace_zygote(pid: i32, tango_flag: bool) -> bool {
    dlogi!("start tracing {pid} (tracer {})", unsafe { libc::getpid() });

    let mut status = 0;

    let version = rz_common::KernelVersion::current();
    if version.major > 3 || (version.major == 3 && version.minor >= 8) {
        #[cfg(target_arch = "aarch64")]
        {
            if tango_flag {
                // Seize with PTRACE_O_TRACESYSGOOD to reliably catch the
                // translator's entry point.
                if unsafe {
                    libc::ptrace(
                        PTRACE_SEIZE,
                        pid,
                        0,
                        libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACESECCOMP,
                    )
                } == -1
                {
                    plog!(TAG, "seize for tango");
                    return false;
                }
            } else {
                if unsafe {
                    libc::ptrace(PTRACE_SEIZE, pid, 0, libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACESECCOMP)
                } == -1
                {
                    plog!(TAG, "seize");
                    return false;
                }

                if !wait_for_trace_deadline(pid, &mut status, libc::__WALL, TRACE_STEP_TIMEOUT) {
                    dloge!("seized zygote never reported its stop");
                    return false;
                }
            }
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut seize_opts = libc::PTRACE_O_EXITKILL | libc::PTRACE_O_TRACESECCOMP;
            if tango_flag {
                seize_opts |= libc::PTRACE_O_TRACESYSGOOD;
            }

            if unsafe { libc::ptrace(PTRACE_SEIZE, pid, 0, seize_opts) } == -1 {
                if tango_flag {
                    plog!(TAG, "seize for tango");
                } else {
                    plog!(TAG, "seize");
                }
                return false;
            }

            if !tango_flag && !wait_for_trace_deadline(pid, &mut status, libc::__WALL, TRACE_STEP_TIMEOUT) {
                dloge!("seized zygote never reported its stop");
                return false;
            }
        }
    } else {
        if unsafe { libc::ptrace(PTRACE_SEIZE, pid, 0, 0) } == -1 {
            plog!(TAG, "seize");
            return false;
        }

        if !wait_for_trace_deadline(pid, &mut status, libc::__WALL, TRACE_STEP_TIMEOUT) {
            dloge!("seized zygote never reported its stop");
            return false;
        }
    }

    if tango_flag {
        if unsafe { libc::ptrace(PTRACE_INTERRUPT, pid, 0, 0) } == -1 {
            plog!(TAG, "interrupt");
            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
            }
            return false;
        }

        // Drain to INTERRUPT's SIGTRAP + EVENT_STOP.
        if !wait_for_event_stop(pid) {
            dloge!("Failed to drain to event stop for tango injection");
            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, pid, 0, libc::SIGCONT);
            }
            return false;
        }

        let mut watch = TangoLinkerWatch::default();
        if !tango_wait_linker_ready(pid, &mut watch) {
            dloge!("Failed to wait for linker ready for injection");
            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, pid, 0, libc::SIGCONT);
            }
            return false;
        }

        // Leave syscall-stop state before injection.
        unsafe {
            libc::ptrace(libc::PTRACE_CONT, pid, 0, 0);
        }
        if unsafe { libc::ptrace(PTRACE_INTERRUPT, pid, 0, 0) } == -1 {
            plog!(TAG, "Failed to interrupt process for injection");
            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, pid, 0, libc::SIGCONT);
            }
            return false;
        }

        if !wait_for_event_stop(pid) {
            dloge!("Failed to drain to event stop for injection");
            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, pid, 0, libc::SIGCONT);
            }
            return false;
        }

        let result = tango_inject(
            pid,
            TANGO_LIB_PATH,
            watch.libc_init_resolved,
            watch.libc_init_got_slot,
        );
        if !result {
            dloge!("Failed to inject tango");
        }

        unsafe {
            libc::ptrace(libc::PTRACE_DETACH, pid, 0, libc::SIGCONT);
        }

        return result;
    }

    if stopped_with(status, libc::SIGSTOP, libc::PTRACE_EVENT_STOP) {
        let lib_path = if cfg!(target_pointer_width = "64") {
            LIB_PATH_64
        } else {
            LIB_PATH_32
        };
        if !inject_on_main(pid, lib_path) {
            dloge!("failed to inject");
            return false;
        }

        dlogi!("inject done, continuing process");
        if unsafe { libc::kill(pid, libc::SIGCONT) } != 0 {
            plog!(TAG, "kill");
            return false;
        }

        // CONT_OR_DIE / WAIT_OR_DIE
        if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) } == -1 {
            plog!(TAG, "cont");
            return false;
        }
        if !wait_for_trace_deadline(pid, &mut status, libc::__WALL, TRACE_STEP_TIMEOUT) {
            dloge!("no stop after post-injection CONT");
            return false;
        }

        if stopped_with(status, libc::SIGTRAP, libc::PTRACE_EVENT_STOP) {
            if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) } == -1 {
                plog!(TAG, "cont");
                return false;
            }
            if !wait_for_trace_deadline(pid, &mut status, libc::__WALL, TRACE_STEP_TIMEOUT) {
                dloge!("no stop while draining group-stop exit");
                return false;
            }

            if stopped_with(status, libc::SIGCONT, 0) {
                dlogi!("received SIGCONT, detaching zygote");

                // Kernel bugs fixed in 5.16+ may leave a stale
                // ptrace_message; PTRACE_SYSCALL resets it to the normal
                // state before we detach.
                unsafe {
                    libc::ptrace(libc::PTRACE_SYSCALL, pid, 0, 0);
                }

                if !wait_for_trace_deadline(pid, &mut status, libc::__WALL, TRACE_STEP_TIMEOUT) {
                    dloge!("no syscall-stop before detach");
                    return false;
                }

                unsafe {
                    libc::ptrace(libc::PTRACE_DETACH, pid, 0, libc::SIGCONT);
                }
            } else {
                // ptracer.c:574-588: when the expected SIGCONT delivery never
                // arrives, C returns success WITHOUT detaching — tracer exit
                // then triggers PTRACE_O_EXITKILL, killing the zygote so init
                // restarts it and the monitor re-injects (fail-closed).
                dlogw!(
                    "expected SIGCONT delivery, got {} — leaving zygote for EXITKILL restart",
                    parse_status(status)
                );
            }
        } else {
            dloge!(
                "unknown state {}, not SIGTRAP + EVENT_STOP",
                parse_status(status)
            );

            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
            }

            return false;
        }
    } else {
        dloge!(
            "unknown state {}, not SIGSTOP + EVENT_STOP",
            parse_status(status)
        );

        unsafe {
            libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
        }

        return false;
    }

    dlogi!("trace complete, zygote {pid} released");

    true
}

#[cfg(target_arch = "arm")]
use tango::inject_tango as tango_inject;

#[cfg(not(target_arch = "arm"))]
fn tango_inject(pid: i32, lib_path: &str, libc_init_target: u32, libc_init_got_slot: u32) -> bool {
    let _ = (pid, lib_path, libc_init_target, libc_init_got_slot);
    dloge!("tango injection is only supported on arm32");
    false
}
