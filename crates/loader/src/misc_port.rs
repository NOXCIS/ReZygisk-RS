//! hook.c misc helpers: `update_mnt_ns` plus the gap
//! audit of loader/src/common/misc.c against rz_common / rz-ptracer.
//!
//! # Gap audit of common/misc.c
//!
//! | misc.c symbol                    | status            | existing Rust impl |
//! |----------------------------------|-------------------|--------------------|
//! | `parse_int`                      | GAP — ported here | [`parse_int`] below |
//! | `parse_kversion`                 | already available | `rz_common::KernelVersion::{parse,current}` — `crates/common/src/kversion.rs` |
//! | `parse_maps_safe`                | already available | `rz_common::parse_maps_safe` — `crates/common/src/maps.rs` |
//! | `parse_maps`                     | already available | `rz_common::parse_maps` — `crates/common/src/maps.rs` |
//! | `free_maps`                      | N/A               | ownership: `Vec<MapEntry>` `drop` (no port needed) |
//! | `IS_ISOLATED_SERVICE` (misc.h)   | already available | `rz_common::is_isolated_service` — `crates/common/src/lib.rs` |
//! | `LP_SELECT` (misc.h)             | already available | `rz_common::lp_select!` — `crates/common/src/lib.rs` |
//! | `struct kernel_version` (misc.h) | already available | `rz_common::KernelVersion` — `crates/common/src/kversion.rs` |
//! | `struct map_entry` (misc.h)      | already available | `rz_common::MapEntry` — `crates/common/src/maps.rs` |
//! | `struct maps_info` (misc.h)      | already available | `Vec<rz_common::MapEntry>` (same file) |
//! | `write_fd`/`read_fd` (socket_utils.h, used inside parse_maps_safe) | already available | `rz_common::{send_fd,recv_fd}` — `crates/common/src/fdpass.rs` |
//!
//! No other helpers exist in misc.c. The only gaps ported into this module are
//! `parse_int` and, from hook.c, `update_mnt_ns`.
//!
//! # `MapEntry` field parity (loader call sites)
//!
//! `rz_common::MapEntry` has `start`, `end`, `perms`, `is_private`, `offset`,
//! `dev_major`, `dev_minor`, `inode`, `path`. The C `struct map_entry` stores
//! `dev` as `makedev(major, minor)` (`dev_t`) instead of the raw pair. The
//! loader call sites are satisfied:
//! - `plt_commit.rs` (C `api_plt_hook_commit`) needs
//!   `offset == 0`, `is_private`, `perms & PROT_READ` and `path` — all present.
//! - `plt_commit_v4.rs` (C `api_plt_hook_register_v4`) compares
//!   `dev`/`inode` per entry against the module-supplied pair; the raw
//!   `dev_major`+`dev_minor` pair is recombined there with the full bionic
//!   `makedev` formula (sys/sysmacros.h), including the LP32 `dev_t`
//!   truncation.
//!
//! # Deviations (C → Rust)
//!
//! - `parse_kversion`: C uses `sscanf("%hhu.%u.%u")` from the start of the
//!   release string; `rz_common::KernelVersion::parse` splits on non-digits and
//!   takes the first three numeric tokens. Identical for every real kernel
//!   release (`"5.4.302-..."` etc.). Differences only on malformed input:
//!   leading non-digit garbage parses in Rust but fails in C; a major > 255
//!   truncates (wraps) in C `%hhu` but fails in Rust. C logs
//!   `PLOGE("uname")` / `LOGE("Failed to parse kernel version")` on failure;
//!   the Rust impl is silent.
//! - `parse_maps`/`parse_maps_safe`: C logs every failure path (`PLOGE
//!   "Failed to open %s"`, allocation errors); `rz_common` is silent. C reads
//!   with `fgets`(1024) so lines > 1023 bytes are split into bogus entries;
//!   Rust reads the whole file and parses long lines correctly. C keeps the
//!   original array on realloc failure (truncated success); Rust `Vec` growth
//!   aborts on OOM. C `%4s` perms rejects a > 4-char perms field; `rz_common`
//!   accepts it (unrealistic input). C strips exactly one trailing char
//!   (assumed `\n`); Rust trims trailing `\r`/`\n` — identical for real maps.
//! - `parse_maps` inode: C `ino_t` is parsed with `%lu` (32-bit on LP32);
//!   `rz_common` always uses `u64` (a superset; kernel inode values fit).
//! - `parse_int`: C stops at the NUL terminator; the Rust port takes `&str`
//!   and would reject an interior-NUL input with -1. All call sites
//!   (`fd_sanitize.rs`, hook.c fork/sanitize paths) pass NUL-free `d_name`
//!   strings, so behavior is identical there.
//! - `update_mnt_ns` depends on the daemon_client sibling
//!   `crate::daemon_client::rezygiskd_update_mns(state, buf: &mut [u8],
//!   buf_size: usize, ns_fd_out: &mut i32) -> bool` (C
//!   `rezygiskd_update_mns`) filling `buf` with the
//!   `snprintf`'d `"/proc/%u/fd/%u"` ns path — always NUL-terminated. The
//!   defensive no-NUL failure below cannot trigger against a C-parity sibling.
//!   `ns_fd_out` is an RS extension: the daemon also attaches the namespace
//!   fd itself, and this port uses it in place of the C's `open` (which needs
//!   ptrace access to the daemon and silently fails in app processes). The
//!   path is still produced, so a peer that does not send the fd keeps the C
//!   behavior.
//! - C computes `mns_state_str` with an `"unknown"` default reachable only via
//!   an out-of-range enum cast; the Rust helper keeps the same default in a
//!   wildcard arm (unreachable today: `MountNamespaceState` has exactly
//!   `Clean`/`Mounted`).
//! - C `LOGD` is compiled out in `NDEBUG` builds; the Rust `logd!` always
//!   emits (existing port-wide convention).

use std::ffi::CStr;

use rz_common::{logd, loge, plog};

/// Module-local log tag (C `LOG_TAG` in logging.h; the loader port uses
/// `"zygisk"`).
pub const TAG: &str = rz_common::LOG_TAG;

/// misc.c `parse_int`: decimal parse with C-parity semantics.
///
/// - Empty input parses to 0 (the C loop body never runs).
/// - Any non-digit character returns -1.
/// - Overflow wraps like the C's two's-complement `val * 10 + c - '0'`.
pub fn parse_int(s: &str) -> i32 {
    let mut val: i32 = 0;
    for &c in s.as_bytes() {
        if !c.is_ascii_digit() {
            return -1;
        }

        val = val.wrapping_mul(10).wrapping_add((c - b'0') as i32);
    }

    val
}

/// hook.c `update_mnt_ns`: ask ReZygiskd for the target mount
/// namespace, optionally only `dry_run` it, then `open`/`setns(CLONE_NEWNS)`/
/// `close` with the exact C messages and clean/mounted string mapping.
///
/// Where the C opens the daemon's `/proc/<daemon pid>/fd/<n>` link, this
/// prefers the namespace fd the daemon hands over on the same reply. The open
/// is not a formality: it asks the kernel to ptrace a root process, and the
/// caller is a zygote child that may already be running as the app uid, so it
/// comes back EACCES and the clean-namespace switch simply never happens (C
/// reference behavior, not a port difference). A received fd needs no access to
/// the daemon at all, so the `setns` below is what decides the outcome.
pub fn update_mnt_ns(mns_state: rz_ipc::MountNamespaceState, dry_run: bool) -> bool {
    // C: char ns_path[PATH_MAX]; snprintf'd by the daemon call.
    let mut ns_path = [0u8; libc::PATH_MAX as usize];
    let ns_len = ns_path.len();
    // RS extension: the daemon's own duplicate of the namespace fd, or -1.
    let mut ns_fd: i32 = -1;
    if !crate::daemon_client::rezygiskd_update_mns(mns_state, &mut ns_path, ns_len, &mut ns_fd) {
        plog!(TAG, "Failed to update mount namespace");

        return false;
    }

    if dry_run {
        // The fd is a real resource even when the namespace is only being
        // prepared: a dry run must not leave it open in the zygote.
        if ns_fd >= 0 {
            unsafe { libc::close(ns_fd) };
        }

        return true;
    }

    // C: snprintf always NUL-terminates; fail rather than hand open() an
    // unterminated buffer (defensive — unreachable with a C-parity sibling).
    let ns_cstr = match CStr::from_bytes_until_nul(&ns_path) {
        Ok(c) => c,
        Err(_) => {
            loge!(TAG, "mount namespace path is not NUL-terminated");

            if ns_fd >= 0 {
                unsafe { libc::close(ns_fd) };
            }

            return false;
        }
    };
    let ns_path_str = ns_cstr.to_string_lossy();

    let updated_ns = if ns_fd >= 0 {
        logd!(TAG, "Using the daemon-passed mount namespace fd [{}]", ns_fd);

        ns_fd
    } else {
        let opened = unsafe { libc::open(ns_cstr.as_ptr(), libc::O_RDONLY) };
        if opened == -1 {
            // C parity here is PLOGE (ERROR), but the failure is routine in
            // this deployment, not exceptional: an app process cannot open
            // the daemon's `/proc/<pid>/fd/<n>` link, because ptrace access
            // to a different-uid process is denied (EACCES) — so this fires
            // in every app process that asks for the clean namespace and says
            // nothing about the app itself.
            //
            // It must not stay at ERROR: logd shows an app only the entries
            // its own uid wrote, so an `E/<tag>` line is a framework
            // fingerprint in exactly the buffer an integrity scanner greps
            // (the Duck Detector LSPosed slice flags the `zygisk` tag prefix).
            // Debug level keeps it visible in a `loud-loader` build without
            // leaking in a deployment one. Reaching it means the daemon sent
            // no fd, i.e. the peer is a stock C `rezygiskd`.
            logd!(
                TAG,
                "Failed to open mount namespace [{}]: {}",
                ns_path_str,
                std::io::Error::last_os_error()
            );

            return false;
        }

        opened
    };

    let mns_state_str = mns_state_str(mns_state);

    logd!(TAG, "set mount namespace to [{}] fd=[{}]: {}", ns_path_str, updated_ns, mns_state_str);

    if unsafe { libc::setns(updated_ns, libc::CLONE_NEWNS) } == -1 {
        // Also debug, and for a second reason on top of the fingerprint one
        // above: joining a namespace owned by the initial user namespace needs
        // CAP_SYS_ADMIN, so a caller that is already the app uid is refused by
        // the kernel here no matter how the fd arrived. That is a property of
        // *who* is asking, not of this call, and an `E/` line per app launch
        // would say nothing the daemon's own request record does not.
        logd!(
            TAG,
            "Failed to set mount namespace [{}]: {}",
            ns_path_str,
            std::io::Error::last_os_error()
        );

        unsafe { libc::close(updated_ns) };

        return false;
    }

    unsafe { libc::close(updated_ns) };

    true
}

/// hook.c inline `mns_state_str` mapping. The `"unknown"` default matches the
/// C and is unreachable today (`MountNamespaceState` has exactly `Clean` /
/// `Mounted`); it stays as the fallback if the enum ever grows.
fn mns_state_str(state: rz_ipc::MountNamespaceState) -> &'static str {
    match state {
        rz_ipc::MountNamespaceState::Clean => "clean",
        rz_ipc::MountNamespaceState::Mounted => "mounted",
        #[allow(unreachable_patterns)]
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_int_plain() {
        assert_eq!(parse_int("123"), 123);
        assert_eq!(parse_int("0"), 0);
        assert_eq!(parse_int("007"), 7);
    }

    #[test]
    fn parse_int_empty_is_zero_like_c() {
        assert_eq!(parse_int(""), 0);
    }

    #[test]
    fn parse_int_non_digit_is_minus_one() {
        assert_eq!(parse_int("12a"), -1);
        assert_eq!(parse_int("abc"), -1);
        assert_eq!(parse_int("-5"), -1);
        assert_eq!(parse_int("1.5"), -1);
    }

    #[test]
    fn parse_int_wraps_like_c() {
        // Two's-complement wrap of the C `val * 10 + digit` accumulation.
        assert_eq!(parse_int("2147483648"), i32::MIN);
        assert_eq!(parse_int("4294967296"), 0);
        assert_eq!(parse_int("9999999999"), 1_410_065_407);
    }

    #[test]
    fn mns_state_str_matches_c() {
        assert_eq!(mns_state_str(rz_ipc::MountNamespaceState::Clean), "clean");
        assert_eq!(mns_state_str(rz_ipc::MountNamespaceState::Mounted), "mounted");
    }
}
