//! Port of zygiskd/src/companion.c: per-module companion process entry.

use std::io;
use std::os::fd::RawFd;

use rz_ipc::{read_string_bounded, recv_fd, write_u8};

use crate::utils::{check_unix_socket, dlogi, dloge};

type ZygiskCompanionEntry = unsafe extern "C" fn(i32);

/// companion.c `load_module`: dlopen /proc/self/fd/<fd>, dlsym entry.
unsafe fn load_module(lib_fd: RawFd) -> Option<ZygiskCompanionEntry> {
    let path = std::ffi::CString::new(format!("/proc/self/fd/{lib_fd}")).unwrap();

    let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW) };
    if handle.is_null() {
        let err = unsafe { libc::dlerror() };
        let msg = if err.is_null() {
            "unknown".to_string()
        } else {
            unsafe { std::ffi::CStr::from_ptr(err) }.to_string_lossy().into_owned()
        };
        dloge!("Failed to dlopen module: {msg}");
        return None;
    }

    let sym = unsafe { libc::dlsym(handle, c"zygisk_companion_entry".as_ptr()) };
    if sym.is_null() {
        let err = unsafe { libc::dlerror() };
        let msg = if err.is_null() {
            "unknown".to_string()
        } else {
            unsafe { std::ffi::CStr::from_ptr(err) }.to_string_lossy().into_owned()
        };
        dloge!("Failed to dlsym zygisk_companion_entry: {msg}");
        unsafe { libc::dlclose(handle) };
        return None;
    }

    Some(unsafe { std::mem::transmute::<*mut libc::c_void, ZygiskCompanionEntry>(sym) })
}

/// companion.c `entry_thread`: run the module entry, then close the client
/// fd only if it still refers to the same file (double-close guard).
fn entry_thread(fd: RawFd, module_entry: ZygiskCompanionEntry) {
    unsafe {
        let mut st0: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st0) == -1 {
            dloge!(" - Failed to get initial client fd stats: {}", io::Error::last_os_error());
            return;
        }

        module_entry(fd);

        let mut st1: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut st1) != -1 && st0.st_ino == st1.st_ino {
            dlogi!(" - Client fd changed after module entry");
            libc::close(fd);
        }
    }
}

/// companion.c `companion_entry`: serve one module's companion requests until
/// the socket dies. Never returns normally (exits the process like C).
pub fn companion_entry(fd: RawFd) -> ! {
    dlogi!("New companion entry.\n - Client fd: {fd}\n");

    'cleanup: {
        let mut name_buf = [0u8; 256 + 1];
        let ret = read_string_bounded(fd, &mut name_buf);
        if ret.is_err() {
            dloge!("Failed to read module name");
            break 'cleanup;
        }
        let name = String::from_utf8_lossy(&name_buf[..ret.unwrap()]).into_owned();

        dlogi!(" - Module name: \"{name}\"");

        let library_fd = match recv_fd(fd) {
            Ok(fd) => fd,
            Err(_) => {
                dloge!("Failed to receive library fd");
                break 'cleanup;
            }
        };

        dlogi!(" - Library fd: {library_fd}");

        let module_entry = unsafe { load_module(library_fd) };
        unsafe { libc::close(library_fd) };

        if module_entry.is_none() {
            dloge!(" - No companion module entry for module: {name}");
            if write_u8(fd, 0).is_err() {
                dloge!("Failed to write module_entry response");
            }
            break 'cleanup;
        }
        let module_entry = module_entry.unwrap();

        dlogi!(" - Module entry found");

        // C companion.c: ack success so spawn_companion's read_u8 unblocks.
        if write_u8(fd, 1).is_err() {
            dloge!("Failed to write companion success ack");
            break 'cleanup;
        }

        // Ignore SIGPIPE like C.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }

        loop {
            if !check_unix_socket(fd, true) {
                dloge!("Something went wrong in companion. Bye!");
                break 'cleanup;
            }

            let client_fd = match recv_fd(fd) {
                Ok(fd) => fd,
                Err(_) => {
                    dloge!("Failed to receive client fd");
                    break 'cleanup;
                }
            };

            dlogi!("New companion request.\n - Module name: {name}\n - Client fd: {client_fd}\n");

            if write_u8(client_fd, 1).is_err() {
                dloge!("Failed to send client_fd ack in ZygiskdCompanion");
                unsafe { libc::close(client_fd) };
                break 'cleanup;
            }

            // companion.c 164-172: a failed pthread_create breaks the serve
            // loop (after closing the client fd) and exits the companion.
            if std::thread::Builder::new()
                .name("companion-req".into())
                .spawn(move || entry_thread(client_fd, module_entry))
                .is_err()
            {
                dloge!(" - Failed to create thread for companion module");
                unsafe { libc::close(client_fd) };
                break 'cleanup;
            }
        }
    }

    unsafe { libc::close(fd) };
    dloge!("Companion thread exited");
    std::process::exit(0);
}
