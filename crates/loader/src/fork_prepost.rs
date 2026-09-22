//! hook.c `sigmask` helper + `rz_fork_pre` / `rz_fork_post`.
//!
//! PORT TASK: hook.c lines 814-823 (sigmask), 824-860 (rz_fork_pre) and
//! 929-933 (rz_fork_post).
//!
//! C-parity notes:
//! - The C forks via `old_fork()` (the PLT backup, bypassing the `fork`
//!   hook). The Rust call goes through `libc::fork()`; libzygisk.so's own
//!   PLT is never hooked (only libandroid_runtime.so is), so this resolves
//!   to the real fork exactly like `old_fork()`.
//! - `rz_fork_pre` is where the zygote-side fork actually happens: the pid
//!   is cached in `ctx.pid` so the later `nativeForkAndSpecialize` /
//!   `nativeForkSystemServer` hooks reuse it instead of forking again.
//! - `rz_fork_pre` does NOT call `update_mnt_ns`, `rz_sanitize_fds` or
//!   `rz_run_modules_pre/post` in the C — those belong to the
//!   `nativeFork*`/`app_specialize` wrappers, not to this slice.
//! - `rz_fork_post` does NOT call `rz_cleanup` — the C only unblocks
//!   SIGCHLD and clears `g_ctx` here.
//! - `parse_int` is a local port of common/misc.c lines 20-33 (it is also
//!   needed by fd_sanitize.rs); misc_port.rs is the intended home when that
//!   slice gets ported.

use libc::c_char;

use crate::context::{flag_get, set_ctx, ZygiskContext, MAX_FD_SIZE, SKIP_FD_SANITIZATION};
use rz_common::plog;

const TAG: &str = rz_common::LOG_TAG;

/// common/misc.c `parse_int`: decimal digits only, -1 on any other byte.
/// Like the C, an empty string yields 0 (dirent names are never empty).
fn parse_int(str: *const c_char) -> i32 {
    let mut val: i32 = 0;
    let mut c = str;
    loop {
        let ch = unsafe { *c } as u8;
        if ch == 0 {
            break;
        }
        if ch > b'9' || ch < b'0' {
            return -1;
        }
        val = val.wrapping_mul(10).wrapping_add((ch - b'0') as i32);
        c = unsafe { c.add(1) };
    }
    val
}

/// hook.c `sigmask` (814-823): sigprocmask over a single signum.
pub fn sigmask(how: i32, signum: i32) -> i32 {
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, signum);
        libc::sigprocmask(how, &set, std::ptr::null_mut())
    }
}

/// hook.c `rz_fork_pre` (824-860). Do our own fork before loading any 3rd
/// party code: block SIGCHLD, fork, and in the child record all currently
/// open fds into `allowed_fds` so the later sanitization keeps them.
pub fn rz_fork_pre(ctx: &mut ZygiskContext) {
    // INFO: Do our own fork before loading any 3rd party code.
    //         First block SIGCHLD, unblock after original fork is done.
    sigmask(libc::SIG_BLOCK, libc::SIGCHLD);
    ctx.pid = unsafe { libc::fork() };
    if ctx.pid != 0 || flag_get(ctx, SKIP_FD_SANITIZATION) {
        return;
    }

    // INFO: Record all open fds
    let dir = unsafe { libc::opendir(b"/proc/self/fd\0".as_ptr() as *const libc::c_char) };
    if dir.is_null() {
        plog!(TAG, "Failed to open /proc/self/fd");
        return;
    }

    loop {
        let entry = unsafe { libc::readdir(dir) };
        if entry.is_null() {
            break;
        }

        let fd = parse_int(unsafe { (*entry).d_name.as_ptr() });
        if fd == -1 {
            continue;
        }

        if fd as usize >= MAX_FD_SIZE {
            unsafe { libc::close(fd) };
            continue;
        }

        ctx.allowed_fds[fd as usize] = 1;
    }

    // INFO: The dirfd should not be allowed
    let dfd = unsafe { libc::dirfd(dir) };
    if dfd >= 0 && (dfd as usize) < MAX_FD_SIZE {
        ctx.allowed_fds[dfd as usize] = 0;
    }

    unsafe { libc::closedir(dir) };
}

/// hook.c `rz_fork_post` (929-933): unblock SIGCHLD and drop the current
/// context (`g_ctx = NULL`). The C marks `ctx` unused here too.
pub fn rz_fork_post(_ctx: &mut ZygiskContext) {
    sigmask(libc::SIG_UNBLOCK, libc::SIGCHLD);
    set_ctx(std::ptr::null_mut());
}
