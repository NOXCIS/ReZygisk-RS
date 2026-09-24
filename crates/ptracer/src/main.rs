//! zygisk-ptrace: monitor + tracer (port of loader/src/ptracer/main.c).

mod daemon_client;
mod monitor;
mod remote_csoloader;
mod trace;
mod utils;

#[cfg(test)]
mod tests;

use rz_common::loge;
use utils::{dloge, dlogi, TAG};

const ZKSU_VERSION: &str = env!("CARGO_PKG_VERSION");

/// main.c `strtol(argv[2], 0, 0)`: optional sign, 0x-prefixed hex,
/// 0-prefixed octal, otherwise decimal. Unlike strtol, trailing garbage
/// is rejected instead of being silently ignored.
fn parse_pid(s: &str) -> Option<i32> {
    let s = s.trim();
    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };

    let (radix, digits) = if let Some(hex) = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")) {
        (16, hex)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };

    let magnitude = i64::from_str_radix(digits, radix).ok()?;
    i32::try_from(if neg { -magnitude } else { magnitude }).ok()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    println!("tracer {ZKSU_VERSION} online\n");

    if args.len() >= 2 && args[1] == "monitor" {
        rz_common::init_log_level_from_flags();
        rz_common::redirect_stdio_to_log("zygisk-ptrace monitor");
        monitor::init_monitor();
        return;
    } else if args.len() >= 3 && args[1] == "trace" {
        rz_common::init_log_level_from_flags();
        rz_common::redirect_stdio_to_log("zygisk-ptrace trace");

        // Same self-report + manifest cross-check as the monitor path; the
        // tracer is a fresh exec of the same binary, so a mixed deployment
        // shows up as one of the two roles logging a different generation.
        println!("{}", rz_common::log_generation_and_check(TAG, "tracer"));

        let mut is_tango = false;
        let mut do_restart = false;

        for arg in &args[3..] {
            if arg == "--restart" {
                do_restart = true;
            } else if arg == "--tango" {
                is_tango = true;
            }
        }

        // We need to be fast enough to not miss Tango's injection point, so
        // the restart nudge is deferred until after the trace for Tango.
        if do_restart && !is_tango {
            daemon_client::rezygiskd_zygote_restart();
        }

        let Some(pid) = args.get(2).and_then(|s| parse_pid(s)) else {
            loge!(TAG, "invalid pid {}", args[2]);
            std::process::exit(1);
        };

        if !trace::trace_zygote(pid, is_tango) {
            // The monitor reaps tracers through `fork_dont_care`, so a tracer
            // that dies is invisible to it: this line is the only durable
            // record that an ABI's injection failed. Never downgrade it.
            dloge!(
                "tracer: injection into {pid} failed, killing it so init restarts it and the monitor can hand off the fresh exec"
            );

            unsafe {
                libc::kill(pid, libc::SIGKILL);
            }

            std::process::exit(1);
        }

        dlogi!("tracer: injection into {pid} succeeded, exiting");

        if do_restart && is_tango {
            daemon_client::rezygiskd_zygote_restart();
        }

        return;
    } else if args.len() >= 2 && args[1] == "ctl" {
        let command = match args.get(2).map(String::as_str) {
            Some("start") => monitor::RezygiskdCommand::Start,
            Some("stop") => monitor::RezygiskdCommand::Stop,
            Some("exit") => monitor::RezygiskdCommand::Exit,
            _ => {
                println!("[ReZygisk]: Usage: {} ctl <start|stop|exit>", args[0]);
                std::process::exit(1);
            }
        };

        if monitor::send_control_command(command).is_err() {
            println!("[ReZygisk]: Failed to send the command, is the daemon running?");
            std::process::exit(1);
        }

        println!("[ReZygisk]: command sent");

        return;
    } else if args.len() >= 2 && args[1] == "version" {
        // Noop
        return;
    } else if args.len() >= 2 && args[1] == "invalidate-ns" {
        // Truman extension: drop the daemon's cached clean/mounted ns fds so
        // post-publish mounts are re-snapshotted (ksud calls this from
        // truman recapture/arm).
        if !daemon_client::rezygiskd_invalidate_clean_ns() {
            eprintln!("[ReZygisk]: Failed to invalidate the ns cache, is the daemon running?");
            std::process::exit(1);
        }

        println!("[ReZygisk]: ns cache invalidated");

        return;
    } else if args.len() >= 2 && args[1] == "info" {
        let Some((root_impl, pid, modules)) = daemon_client::rezygiskd_get_info() else {
            std::process::exit(1);
        };

        println!("Daemon process PID: {pid}");

        println!(
            "Root implementation: {}",
            match root_impl {
                daemon_client::RootImpl::None => "none",
                daemon_client::RootImpl::Apatch => "APatch",
                daemon_client::RootImpl::KernelSU => "KernelSU",
                daemon_client::RootImpl::Magisk => "Magisk",
            }
        );

        if !modules.is_empty() {
            println!("Modules: {}", modules.len());
            for m in &modules {
                println!(" - {m}");
            }
        } else {
            println!("Modules: N/A");
        }

        return;
    }

    dlogi!(
        "Available commands:
 - monitor
 - trace <pid> [--restart]
 - ctl <start|stop|exit>
 - invalidate-ns: Drops the daemon's cached mount-namespace fds (Truman).
 - version: Shows the version of ReZygisk.
 - info: Shows information about the created daemon/injection.

<...>: Obligatory
[...]: Optional"
    );

    std::process::exit(1);
}
