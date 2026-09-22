//! Port of zygiskd/src/zygiskd.c: module loading, companion spawning and the
//! abstract-socket accept loop dispatching all 9 DaemonSocketActions.

use std::io;
use std::os::fd::RawFd;

use rz_common::{
    builtin_truman_so_path, cp_socket_abstract_name, module_so_path, plog, zygiskd_path,
    CONTROLLER_SOCKET, PATH_MODULES_DIR,
};
use rz_ipc::{
    build_error_info_message, build_set_info_message, controller_code, read_string_bounded, read_u8,
    read_u32, read_usize, send_fd, write_u8, write_u32, write_usize, write_string, ControllerCode,
    DaemonSocketAction, MountNamespaceState, ProcessFlags,
};

use crate::root_impl::{self, SetupKind};
use crate::utils::{
    check_unix_socket, dlogi, dloge, save_mns_fd, unix_datagram_sendto, TAG,
};

const ZYGISKD_PATH: &str = zygiskd_path();

struct Module {
    name: String,
    so_path: String,
    lib_fd: RawFd,
    companion: RawFd,
}

struct Context {
    modules: Vec<Module>,
}

/// zygiskd.c `free_modules`: close the per-module fds. Strings/vec memory is
/// managed by Rust, but `process::exit` below skips drops, so the fds are
/// closed explicitly like the C.
fn free_modules(context: &Context) {
    for module in &context.modules {
        if module.companion >= 0 {
            unsafe { libc::close(module.companion) };
        }
        if module.lib_fd >= 0 {
            unsafe { libc::close(module.lib_fd) };
        }
    }
}

/// zygiskd.c `load_modules`: built-in truman prepend, then every enabled
/// module with a per-ARCH so file.
fn load_modules() -> Context {
    let mut modules: Vec<Module> = Vec::new();

    // zygiskd.c 56-63: the modules directory handle is opened first; when
    // that fails the context stays empty (the built-in truman module is
    // skipped too).
    let Ok(dir) = std::fs::read_dir(PATH_MODULES_DIR) else {
        dloge!("Failed opening modules directory: {PATH_MODULES_DIR}.");
        return Context { modules };
    };

    dlogi!("Loading modules for architecture: {}", rz_common::arch_str());

    // Built-in truman sub-module (fork addition) ahead of third-party modules.
    let truman_path = builtin_truman_so_path();
    let ctruman = std::ffi::CString::new(truman_path.clone()).unwrap();
    if unsafe { libc::access(ctruman.as_ptr(), libc::R_OK) } == 0 {
        let cpath = std::ffi::CString::new(truman_path.clone()).unwrap();
        let lib_fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if lib_fd == -1 {
            dloge!("Built-in truman module open failed: {}", io::Error::last_os_error());
        } else {
            dlogi!("Built-in module [truman] loaded: {truman_path}");
            modules.push(Module {
                name: "truman".to_string(),
                so_path: truman_path,
                lib_fd,
                companion: -1,
            });
        }
    } else {
        dlogi!("No built-in truman module at {truman_path} (skipping)");
    }

    for entry in dir.flatten() {
        let Ok(ftype) = entry.file_type() else { continue };
        if !ftype.is_dir() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "." || name == ".." || name == "rezygisk" {
            continue;
        }

        let so_path = module_so_path(&name);
        let cso = std::ffi::CString::new(so_path.clone()).unwrap();
        if unsafe { libc::access(cso.as_ptr(), libc::R_OK) } == -1 {
            continue;
        }

        let disabled = format!("{PATH_MODULES_DIR}/{name}/disable");
        let cdisabled = std::ffi::CString::new(disabled).unwrap();
        if unsafe { libc::access(cdisabled.as_ptr(), libc::F_OK) } == 0 {
            continue;
        }

        let lib_fd = unsafe { libc::open(cso.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if lib_fd == -1 {
            dloge!("Failed loading module \"{name}\"");
            continue;
        }

        modules.push(Module { name, so_path, lib_fd, companion: -1 });
    }

    Context { modules }
}

/// zygiskd.c `spawn_companion`: double-fork + exec of this binary with
/// `companion <fd>`; returns the daemon-side fd of the socketpair, -1 on
/// failure, -2 when the module has no companion entry.
fn spawn_companion(argv0: &str, name: &str, lib_fd: RawFd) -> RawFd {
    let mut sockets = [0 as libc::c_int; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sockets.as_mut_ptr()) } == -1 {
        dloge!("Failed creating socket pair.");
        return -1;
    }
    let (daemon_fd, companion_fd) = (sockets[0], sockets[1]);

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        dloge!("Failed forking companion: {}", io::Error::last_os_error());
        unsafe {
            libc::close(companion_fd);
            libc::close(daemon_fd);
        }
        return -1;
    }

    if pid > 0 {
        unsafe { libc::close(companion_fd) };

        let mut status = 0;
        // zygiskd.c 223-224: waitpid's return value is not checked; a
        // failure leaves status 0, which reads as "exited 0" and proceeds.
        unsafe { libc::waitpid(pid, &mut status, 0) };
        if !libc_wifexited(status) || libc_wexitstatus(status) != 0 {
            dloge!("Exited with status {status}");
            unsafe { libc::close(daemon_fd) };
            return -1;
        }

        if write_string(daemon_fd, name).is_err() {
            dloge!("Failed writing module name.");
            unsafe { libc::close(daemon_fd) };
            return -1;
        }

        if send_fd(daemon_fd, lib_fd).is_err() {
            dloge!("Failed sending library fd.");
            unsafe { libc::close(daemon_fd) };
            return -1;
        }

        let response = match read_u8(daemon_fd) {
            Ok(r) => r,
            Err(_) => {
                dloge!("Failed reading companion response.");
                unsafe { libc::close(daemon_fd) };
                return -1;
            }
        };

        return match response {
            // Even without any entry, we should still just deal with it
            0 => {
                unsafe { libc::close(daemon_fd) };
                -2
            }
            1 => daemon_fd,
            _ => {
                unsafe { libc::close(daemon_fd) };
                -1
            }
        };
    }

    // Child of the daemon.
    unsafe {
        libc::close(daemon_fd);

        // Remove FD_CLOEXEC so the fd survives exec.
        if libc::fcntl(companion_fd, libc::F_SETFD, 0) == -1 {
            dloge!("Failed removing FD_CLOEXEC flag: {}", io::Error::last_os_error());
            libc::close(companion_fd);
            libc::_exit(1);
        }

        let nice_name = match argv0.rsplit_once('/') {
            Some((_, last)) => last,
            None => argv0,
        };
        let process_name = format!("{nice_name}-{name}");
        let companion_fd_str = companion_fd.to_string();

        // non_blocking_execv: fork a grandchild that execs, exit immediately
        // so the daemon's waitpid unblocks.
        let gpid = libc::fork();
        if gpid == 0 {
            // The C version dup2'd a pipe write-end here whose read end was
            // never held by anyone: the exec'd companion's first println!
            // hit EPIPE and aborted it (Rust ignores SIGPIPE). Point stdout
            // at the verbose log (fd 2) instead.
            libc::dup2(2, libc::STDOUT_FILENO);

            let cfile = std::ffi::CString::new(ZYGISKD_PATH).unwrap();
            let cargs: Vec<std::ffi::CString> = [
                process_name.as_str(),
                "companion",
                companion_fd_str.as_str(),
            ]
            .iter()
            .map(|s| std::ffi::CString::new(*s).unwrap())
            .collect();
            let mut argp: Vec<*const libc::c_char> = cargs.iter().map(|c| c.as_ptr()).collect();
            argp.push(std::ptr::null());
            libc::execv(cfile.as_ptr(), argp.as_ptr() as *const *const libc::c_char);

            libc::_exit(1);
        }
        libc::_exit(0);
    }
}

fn libc_wifexited(status: i32) -> bool {
    (status & 0x7f) == 0
}

fn libc_wexitstatus(status: i32) -> i32 {
    (status >> 8) & 0xff
}

/// zygiskd.c error taxonomy for one cp client:
/// - the action-byte read failure (`len == -1` / `len == 0` in C) breaks the
///   accept loop and ends the daemon (the monitor restarts it);
/// - any mid-frame failure (safe_read / ASSURE_SIZE_* `return`/`break` in C)
///   only drops the offending client and the loop keeps serving.
enum ClientError {
    Fatal,
    MidFrame,
}

fn handle_client(client_fd: RawFd, context: &mut Context, impl_: root_impl::RootImpl, first_process: &mut bool) -> Result<(), ClientError> {
    // C (zygiskd.c 389-400): a failure reading the action byte — transport
    // error or client disconnect before sending anything — breaks the
    // accept loop. Mid-frame failures only drop this client (safe_read's
    // `return` / ASSURE_SIZE_*'s `break`), so they map to ClientError::MidFrame.
    let action8 = read_u8(client_fd).map_err(|_| ClientError::Fatal)?;
    dlogi!("cp request: action={action8}");

    let Ok(action) = DaemonSocketAction::try_from(action8) else {
        return Ok(());
    };

    match action {
        DaemonSocketAction::ZygoteInjected => {
            unix_datagram_sendto(
                CONTROLLER_SOCKET,
                &[controller_code(ControllerCode::ZygoteInjected)],
            );
        }
        DaemonSocketAction::ZygoteRestart => {
            for module in &mut context.modules {
                if module.companion > -1 {
                    unsafe { libc::close(module.companion) };
                    module.companion = -1;
                }
            }
        }
        DaemonSocketAction::GetProcessFlags => {
            let uid = read_u32(client_fd).map_err(|_| ClientError::MidFrame)?;

            let mut process = [0u8; rz_common::PROCESS_NAME_MAX_LEN];
            let ret = read_string_bounded(client_fd, &mut process).map_err(|_| ClientError::MidFrame)?;
            let process = String::from_utf8_lossy(&process[..ret]).into_owned();

            let mut flags = ProcessFlags::empty();
            if *first_process {
                flags |= ProcessFlags::IS_FIRST_STARTED;
                *first_process = false;
            }

            if root_impl::uid_is_manager(uid) {
                flags |= ProcessFlags::IS_MANAGER;
            } else {
                if root_impl::uid_granted_root(uid) {
                    flags |= ProcessFlags::GRANTED_ROOT;
                }
                if root_impl::uid_should_umount(uid, &process) {
                    flags |= ProcessFlags::ON_DENYLIST;
                }
            }

            flags |= impl_.kind.flag_bit();

            write_u32(client_fd, flags.bits()).map_err(|_| ClientError::MidFrame)?;
        }
        DaemonSocketAction::GetInfo => {
            let mut flags = ProcessFlags::empty();
            flags |= impl_.kind.flag_bit();

            write_u32(client_fd, flags.bits()).map_err(|_| ClientError::MidFrame)?;
            write_u32(client_fd, unsafe { libc::getpid() } as u32).map_err(|_| ClientError::MidFrame)?;
            write_usize(client_fd, context.modules.len()).map_err(|_| ClientError::MidFrame)?;

            for module in &context.modules {
                write_string(client_fd, &module.name).map_err(|_| ClientError::MidFrame)?;
            }
        }
        DaemonSocketAction::ReadModules => {
            write_usize(client_fd, context.modules.len()).map_err(|_| ClientError::MidFrame)?;

            for module in &context.modules {
                write_string(client_fd, &module.so_path).map_err(|_| ClientError::MidFrame)?;
                // zygiskd.c 544-550: the pre-opened lib fd is only attached
                // when it is open; attach it so the zygote can load via
                // /proc/self/fd/N (no path walk).
                if module.lib_fd >= 0 {
                    send_fd(client_fd, module.lib_fd).map_err(|_| ClientError::MidFrame)?;
                }
            }
        }
        DaemonSocketAction::RequestCompanionSocket => {
            let index = read_usize(client_fd).map_err(|_| ClientError::MidFrame)?;

            if index >= context.modules.len() {
                dloge!("Invalid module index: {index}");
                write_u8(client_fd, 0).map_err(|_| ClientError::MidFrame)?;
                return Ok(());
            }

            let module = &mut context.modules[index];
            if module.companion >= 0 && !check_unix_socket(module.companion, false) {
                dloge!(" - Companion for module \"{}\" crashed", module.name);
                unsafe { libc::close(module.companion) };
                module.companion = -1;
            }

            if module.companion <= -1 {
                module.companion = spawn_companion(ARGV0.with(|a| a.borrow().clone()).as_deref().unwrap_or(ZYGISKD_PATH), &module.name, module.lib_fd);

                if module.companion >= 0 {
                    dlogi!(" - Spawned companion for \"{}\": {}", module.name, module.companion);
                } else if module.companion == -2 {
                    dloge!(" - No companion spawned for \"{}\" because it has no entry.", module.name);
                } else {
                    dloge!(" - Failed to spawn companion for \"{}\": {}", module.name, io::Error::last_os_error());
                }
            }

            // The companion is serving; hand the client connection over.
            if module.companion >= 0 {
                dlogi!(" - Sending companion fd socket of module \"{}\"", module.name);

                if send_fd(module.companion, client_fd).is_err() {
                    dloge!(" - Failed to send companion fd socket of module \"{}\"", module.name);
                    write_u8(client_fd, 0).map_err(|_| ClientError::MidFrame)?;

                    unsafe { libc::close(module.companion) };
                    module.companion = -1;
                }
            } else {
                dloge!(" - Failed to spawn companion for module \"{}\"", module.name);
                write_u8(client_fd, 0).map_err(|_| ClientError::MidFrame)?;
            }
        }
        DaemonSocketAction::GetModuleDir => {
            let index = read_usize(client_fd).map_err(|_| ClientError::MidFrame)?;

            if index >= context.modules.len() {
                dloge!("Invalid module index: {index}");
                write_u8(client_fd, 0).map_err(|_| ClientError::MidFrame)?;
                return Ok(());
            }

            let module_dir = format!("{PATH_MODULES_DIR}/{}", context.modules[index].name);
            let cdir = std::ffi::CString::new(module_dir.clone()).unwrap();
            let fd = unsafe { libc::open(cdir.as_ptr(), libc::O_RDONLY) };
            if fd == -1 {
                dloge!("Failed opening module directory \"{module_dir}\": {}", io::Error::last_os_error());
                return Ok(());
            }

            if send_fd(client_fd, fd).is_err() {
                dloge!("Failed sending module directory \"{module_dir}\" fd: {}", io::Error::last_os_error());
                unsafe { libc::close(fd) };
                return Ok(());
            }
            unsafe { libc::close(fd) };
        }
        DaemonSocketAction::UpdateMountNamespace => {
            let pid = read_u32(client_fd).map_err(|_| ClientError::MidFrame)?;
            let mns_state = read_u8(client_fd).map_err(|_| ClientError::MidFrame)?;

            write_u32(client_fd, unsafe { libc::getpid() } as u32).map_err(|_| ClientError::MidFrame)?;

            // zygiskd.c 665-666: building the clean ns also needs the mounted
            // ns fd. The raw byte is compared (not enum-validated) exactly
            // like the C cast: any non-zero value skips the warm-up.
            if mns_state == MountNamespaceState::Clean as u8 {
                save_mns_fd(pid as i32, MountNamespaceState::Mounted as u8, impl_.kind);
            }

            let ns_fd = save_mns_fd(pid as i32, mns_state, impl_.kind);
            if ns_fd == -1 {
                dloge!("Failed to save mount namespace fd for pid {pid}: {}", io::Error::last_os_error());
                write_u32(client_fd, 0).map_err(|_| ClientError::MidFrame)?;
                return Ok(());
            }

            write_u32(client_fd, ns_fd as u32).map_err(|_| ClientError::MidFrame)?;
        }
        DaemonSocketAction::RemoveModule => {
            let index = read_usize(client_fd).map_err(|_| ClientError::MidFrame)?;

            if index >= context.modules.len() {
                dloge!("Invalid module index: {index}");
                write_u8(client_fd, 0).map_err(|_| ClientError::MidFrame)?;
                return Ok(());
            }

            let module = &mut context.modules[index];
            if module.companion >= 0 {
                unsafe { libc::close(module.companion) };
                module.companion = -1;
            }
            if module.lib_fd >= 0 {
                unsafe { libc::close(module.lib_fd) };
                module.lib_fd = -1;
            }
            context.modules.remove(index);

            // Keep the monitor's state.json / WebUI module list truthful:
            // re-report the shrunken list. The monitor's SetInfo handler is
            // idempotent (replaces env.modules, re-renders status), so a
            // re-send needs no new protocol. One datagram per report: two
            // reports in flight used to interleave and desync the monitor.
            let module_names: Vec<&str> = context.modules.iter().map(|m| m.name.as_str()).collect();
            let impl_name = root_impl::stringify_root_impl_name(impl_);
            let report = build_set_info_message(impl_name, &module_names);
            unix_datagram_sendto(CONTROLLER_SOCKET, &report);

            write_u8(client_fd, 1).map_err(|_| ClientError::MidFrame)?;
        }
    }

    Ok(())
}

thread_local! {
    static ARGV0: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// zygiskd.c `zygiskd_start`: report status to the controller, open the
/// abstract cp socket and serve forever.
pub fn zygiskd_start(argv0: &str) -> ! {
    ARGV0.with(|a| *a.borrow_mut() = Some(argv0.to_string()));

    // Probe once (idempotent). Builders already include the cmd datagram —
    // do not send the code byte again (double-send desyncs the monitor).
    let setup = root_impl::root_impls_setup();

    let context = match setup {
        SetupKind::None => {
            let msg = "Unsupported environment: Unknown root implementation";
            dloge!("{msg}");
            unix_datagram_sendto(CONTROLLER_SOCKET, &build_error_info_message(msg));
            std::process::exit(1);
        }
        SetupKind::Multiple => {
            let msg = "Unsupported environment: Multiple root implementations found";
            dloge!("{msg}");
            unix_datagram_sendto(CONTROLLER_SOCKET, &build_error_info_message(msg));
            std::process::exit(1);
        }
        SetupKind::Single(impl_) => {
            let ctx = load_modules();

            let impl_name = root_impl::stringify_root_impl_name(impl_);
            let module_names: Vec<&str> = ctx.modules.iter().map(|m| m.name.as_str()).collect();
            let report = build_set_info_message(impl_name, &module_names);
            unix_datagram_sendto(CONTROLLER_SOCKET, &report);

            dlogi!("Sent root implementation and modules information to controller socket");
            (ctx, impl_)
        }
    };

    let (mut context, impl_) = context;

    let socket_fd = match rz_ipc::listen_abstract(cp_socket_abstract_name()) {
        Ok(fd) => fd,
        Err(e) => {
            dloge!("Failed creating daemon socket");
            plog!(TAG, "listen_abstract: {e}");
            free_modules(&context);
            root_impl::root_impl_cleanup();
            // zygiskd.c 366-373: C cleans up and returns; main.c 62 then
            // exits with status 0.
            std::process::exit(0);
        }
    };

    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }

    let mut first_process = true;
    loop {
        let client_fd = unsafe { libc::accept4(socket_fd, std::ptr::null_mut(), std::ptr::null_mut(), libc::SOCK_CLOEXEC) };
        if client_fd == -1 {
            dloge!("accept: {}", io::Error::last_os_error());
            break;
        }

        match handle_client(client_fd, &mut context, impl_, &mut first_process) {
            Ok(()) => {}
            // C closes the client and keeps accepting on mid-frame errors.
            Err(ClientError::MidFrame) => {
                dloge!("cp client mid-frame error, dropping connection");
            }
            // C breaks out of the accept loop when the action byte cannot
            // be read (transport error or early disconnect); the monitor's
            // crash handling restarts us.
            Err(ClientError::Fatal) => {
                dloge!("cp client error, shutting down");
                unsafe { libc::close(client_fd) };
                break;
            }
        }

        unsafe { libc::close(client_fd) };
    }

    unsafe { libc::close(socket_fd) };
    free_modules(&context);
    root_impl::root_impl_cleanup();
    std::process::exit(0);
}

