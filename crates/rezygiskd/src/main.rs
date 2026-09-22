//! Port of zygiskd/src/main.c: CLI dispatch.

mod companion;
mod daemon;
mod root_impl;
mod utils;

use crate::root_impl::{stringify_root_impl_name, root_impls_setup, SetupKind};
use crate::utils::{dlogi, switch_mount_namespace, TAG};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    dlogi!("Service online (lp{})", rz_common::lp_select!("32", "64"));

    if args.len() > 1 {
        match args[1].as_str() {
            "companion" => {
                if args.len() < 3 {
                    dlogi!("Usage: zygiskd companion <fd>");
                    std::process::exit(1);
                }
                // main.c 21: C parses the fd with atoi, which yields 0 for
                // a non-numeric argument.
                let fd: i32 = args[2].parse().unwrap_or(0);
                companion::companion_entry(fd);
            }
            "version" => {
                dlogi!("ReZygisk Daemon {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "root" => {
                let setup = root_impls_setup();
                let name = match setup {
                    SetupKind::Single(impl_) => stringify_root_impl_name(impl_),
                    SetupKind::Multiple => "Multiple",
                    SetupKind::None => "None",
                };
                dlogi!("Root implementation: {name}");
                std::process::exit(0);
            }
            other => {
                dlogi!("Usage: zygiskd [companion|version|root] (got \"{other}\")");
                std::process::exit(0);
            }
        }
    }

    // Daemon mode only: keep CLI helpers (version/root) writing to real stdout.
    rz_common::init_log_level_from_flags();
    rz_common::redirect_stdio_to_log("rezygiskd");

    println!("{}", rz_common::log_generation_and_check(TAG, "daemon"));

    if !switch_mount_namespace(1) {
        dlogi!("Failed to switch mount namespace");
        std::process::exit(1);
    }
    root_impls_setup();
    daemon::zygiskd_start(&args[0]);
}
