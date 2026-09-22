//! Port of loader/src/ptracer/monitor.c: the init-monitor process. Seizes
//! init, watches for app_process execve handoffs, spawns/tracks the per-ABI
//! ReZygiskd daemons and tracers, rewrites module.prop + state.json.

use std::io;
use std::mem::size_of;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
// Note: waitpid, WaitPidFlag, WaitStatus may be used in a future full nix refactor
use nix::unistd::{fork, ForkResult, Pid};

use rz_common::{plog, CONTROLLER_SOCKET, MODULE_PROP, PATH_MODULES_DIR, TMP_PATH};

use crate::utils::{self, dlogd, dloge, dlogi, dlogw, dlogv, fork_dont_care, parse_status, TAG};

const ZKSU_VERSION: &str = env!("CARGO_PKG_VERSION");

/// monitor.h `enum rezygiskd_command` — datagram command codes. Values 4–9
/// arrive as raw bytes from the daemons (see the byte-level match in
/// `rezygiskd_listener_callback`), so they're never constructed directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum RezygiskdCommand {
    Start = 1,
    Stop = 2,
    Exit = 3,
    Zygote64Injected = 4,
    Zygote32Injected = 5,
    Daemon64SetInfo = 6,
    Daemon32SetInfo = 7,
    Daemon64SetErrorInfo = 8,
    Daemon32SetErrorInfo = 9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TracingState {
    Tracing,
    Stopping,
    Stopped,
    Exiting,
}

pub(crate) struct RezygiskdStatus {
    pub(crate) supported: bool,
    pub(crate) zygote_injected: bool,
    pub(crate) daemon_running: bool,
    daemon_pid: i32,
    pub(crate) daemon_error_info: Option<String>,
}

impl Default for RezygiskdStatus {
    fn default() -> Self {
        Self {
            supported: false,
            zygote_injected: false,
            daemon_running: false,
            daemon_pid: -1,
            daemon_error_info: None,
        }
    }
}

#[derive(Default)]
pub(crate) struct EnvironmentInformation {
    pub(crate) root_impl: Option<String>,
    pub(crate) modules: Vec<String>,
}

/// monitor.c `CREATE_ZYGOTE_START_COUNTER`: restarts within a 30s window count
/// toward MAX_RETRY_COUNT (5).
pub(crate) struct ZygoteStartCounter {
    last: Option<Instant>,
    pub(crate) count: i32,
}

impl ZygoteStartCounter {
    const MAX_RETRY_COUNT: i32 = 5;

    pub(crate) fn new() -> Self {
        Self { last: None, count: 0 }
    }

    pub(crate) fn should_stop_inject(&mut self) -> bool {
        let now = Instant::now();
        match self.last {
            Some(last) if now.duration_since(last) < Duration::from_secs(30) => self.count += 1,
            _ => self.count = 0,
        }

        self.last = Some(now);

        self.count >= Self::MAX_RETRY_COUNT
    }
}

const APP_PROCESS_64: &str = "/system/bin/app_process64";
const APP_PROCESS_32: &str = "/system/bin/app_process32";
const TANGO_TRANSLATOR: &str = "/system_ext/bin/tango_translator";

pub struct Monitor {
    pub(crate) tracing_state: TracingState,
    pub(crate) stop_reason: Option<&'static str>,
    epfd: i32,
    sock_fd: i32,
    sig_fd: i32,
    events_running: bool,
    pub(crate) status64: RezygiskdStatus,
    pub(crate) status32: RezygiskdStatus,
    pub(crate) env64: EnvironmentInformation,
    pub(crate) env32: EnvironmentInformation,
    counter64: ZygoteStartCounter,
    counter32: ZygoteStartCounter,
    /// PIDs handed to tracer exec, waiting for their exec-stop. 0 = free slot.
    tracked: Vec<i32>,
    pub(crate) pre_section: String,
    pub(crate) post_section: String,
}

impl Monitor {
    pub(crate) fn new() -> Self {
        Self {
            tracing_state: TracingState::Tracing,
            stop_reason: None,
            epfd: -1,
            sock_fd: -1,
            sig_fd: -1,
            events_running: true,
            status64: RezygiskdStatus::default(),
            status32: RezygiskdStatus::default(),
            env64: EnvironmentInformation::default(),
            env32: EnvironmentInformation::default(),
            counter64: ZygoteStartCounter::new(),
            counter32: ZygoteStartCounter::new(),
            tracked: Vec::new(),
            pre_section: String::new(),
            post_section: String::new(),
        }
    }

    // -----------------------------------------------------------------------
    // monitor.c prepare_environment / update_status
    // -----------------------------------------------------------------------

    fn prepare_environment(&mut self) -> bool {
        let Ok(orig) = std::fs::read_to_string(format!("{PATH_MODULES_DIR}/rezygisk/{MODULE_PROP}")) else {
            plog!(TAG, "failed to open orig prop");
            return false;
        };

        (self.pre_section, self.post_section) = split_module_prop(&orig);

        true
    }

    pub(crate) fn status_text(&self) -> String {
        let mut status_text = String::from("Monitor: ");
        match self.tracing_state {
            TracingState::Tracing => status_text.push('✅'),
            TracingState::Stopping | TracingState::Stopped => status_text.push('⛔'),
            TracingState::Exiting => status_text.push('❌'),
        }

        for (suffix, status) in [("64", &self.status64), ("32", &self.status32)] {
            if !status.supported {
                continue;
            }

            status_text.push_str(&format!(", ReZygisk {suffix}-bit: "));

            if self.tracing_state != TracingState::Tracing {
                status_text.push('❌');
            } else if status.zygote_injected && status.daemon_running {
                status_text.push('✅');
            } else {
                status_text.push_str("⚠️");
            }

            if !status.daemon_running {
                match &status.daemon_error_info {
                    Some(info) => status_text.push_str(&format!("(ReZygiskd: {info})")),
                    None => status_text.push_str("(ReZygiskd: not running)"),
                }
            }
        }

        status_text
    }

    fn update_status(&mut self, message: Option<&str>) -> bool {
        let prop_path = format!("{PATH_MODULES_DIR}/rezygisk/{MODULE_PROP}");
        let Some(prop) = write_file_start(&prop_path) else {
            plog!(TAG, "failed to open prop");
            return false;
        };

        let payload = match message {
            Some(message) => format!("{}[{message}] {}", self.pre_section, self.post_section),
            None => {
                let status_text = self.status_text();
                dlogi!("status updated: {status_text}");
                format!("{}[{status_text}] {}", self.pre_section, self.post_section)
            }
        };

        if write_file_finish(prop, &payload).is_err() {
            plog!(TAG, "failed to write prop");
            return false;
        }

        if message.is_some() {
            return true;
        }

        if self.env64.root_impl.is_some() || self.env32.root_impl.is_some() {
            let json = self.build_state_json();
            let json_path = format!("{TMP_PATH}/state.json");
            let Some(fd) = write_file_start(&json_path) else {
                plog!(TAG, "failed to open state.json");
                return false;
            };
            if write_file_finish(fd, &json).is_err() {
                plog!(TAG, "failed to write state.json");
                return false;
            }
        } else if unsafe { libc::remove(format!("{TMP_PATH}/state.json\0").as_ptr() as *const libc::c_char) } == -1 {
            plog!(TAG, "failed to remove state.json");
        }

        true
    }

    /// monitor.c `update_status` state.json writer, byte-for-byte.
    pub(crate) fn build_state_json(&self) -> String {
        let mut json = String::from("{\n");
        let root = self
            .env64
            .root_impl
            .as_ref()
            .or(self.env32.root_impl.as_ref())
            .map(String::as_str)
            .unwrap_or("");
        json.push_str(&format!("  \"root\": \"{root}\",\n"));

        json.push_str("  \"monitor\": {\n");
        json.push_str(&format!("    \"state\": \"{}\"", self.tracing_state as i32));
        if let Some(reason) = self.stop_reason {
            json.push_str(&format!(",\n    \"reason\": \"{reason}\",\n"));
        } else {
            json.push('\n');
        }

        if self.status64.supported || self.status32.supported {
            json.push_str("  },\n");
        } else {
            json.push_str("  }\n");
        }

        if self.status64.supported || self.status32.supported {
            json.push_str("  \"rezygiskd\": {\n");
            if self.status64.supported {
                json.push_str("    \"64\": {\n");
                json.push_str(&format!("      \"state\": {},\n", self.status64.daemon_running as i32));
                if let Some(info) = &self.status64.daemon_error_info {
                    json.push_str(&format!("      \"reason\": \"{info}\",\n"));
                }
                json.push_str("      \"modules\": [");
                for (i, m) in self.env64.modules.iter().enumerate() {
                    if i > 0 {
                        json.push_str(", ");
                    }
                    json.push_str(&format!("\"{m}\""));
                }
                json.push_str("]\n");
                json.push_str("    }");
                if self.status32.supported {
                    json.push_str(",\n");
                } else {
                    json.push('\n');
                }
            }

            if self.status32.supported {
                json.push_str("    \"32\": {\n");
                json.push_str(&format!("      \"state\": {},\n", self.status32.daemon_running as i32));
                if let Some(info) = &self.status32.daemon_error_info {
                    json.push_str(&format!("      \"reason\": \"{info}\",\n"));
                }
                json.push_str("      \"modules\": [");
                for (i, m) in self.env32.modules.iter().enumerate() {
                    if i > 0 {
                        json.push_str(", ");
                    }
                    json.push_str(&format!("\"{m}\""));
                }
                json.push_str("]\n");
                json.push_str("    }\n");
            }

            json.push_str("  },\n");

            json.push_str("  \"zygote\": {\n");
            if self.status64.supported {
                json.push_str(&format!("    \"64\": {}", self.status64.zygote_injected as i32));
                if self.status32.supported && self.status32.zygote_injected {
                    json.push_str(",\n");
                } else {
                    json.push('\n');
                }
            }
            if self.status32.supported && self.status32.zygote_injected {
                json.push_str(&format!("    \"32\": {}\n", self.status32.zygote_injected as i32));
            }
            json.push_str("  }\n");
        }

        json.push_str("}\n");

        json
    }

    // -----------------------------------------------------------------------
    // monitor.c epoll plumbing
    // -----------------------------------------------------------------------

    fn events_init(&mut self) -> bool {
        self.epfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        if self.epfd == -1 {
            plog!(TAG, "epoll_create");
            return false;
        }

        true
    }

    fn events_register(&self, fd: i32) -> bool {
        let mut ev = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLET) as u32,
            u64: fd as u64,
        };

        if unsafe { libc::epoll_ctl(self.epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) } == -1 {
            plog!(TAG, "epoll_ctl");
            return false;
        }

        true
    }

    fn events_loop(&mut self) {
        let mut events: [libc::epoll_event; 2] = unsafe { std::mem::zeroed() };
        let mut idle_ticks: u32 = 0;
        while self.events_running {
            let nfds = unsafe { libc::epoll_wait(self.epfd, events.as_mut_ptr(), 2, 2000) };
            if nfds == 0 {
                idle_ticks = idle_ticks.saturating_add(1);
                if idle_ticks % 15 == 0 {
                    // Liveness heartbeat: a wedged monitor produces silence;
                    // this line proves the loop is turning (and how much is
                    // pending) when nothing else logs.
                    dlogi!(
                        "idle: {:?}, tracked pids: {}",
                        self.tracing_state,
                        self.tracked.iter().filter(|&&p| p > 0).count()
                    );
                }
                self.watchdog_check_init();
                continue;
            }
            idle_ticks = 0;

            if nfds == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }

                plog!(TAG, "epoll_wait");
                self.events_running = false;
                break;
            }

            for event in &events[..nfds as usize] {
                if event.events as i32 & (libc::EPOLLERR | libc::EPOLLHUP) != 0 {
                    dloge!("Failed event on fd {}: {}", event.u64 as i32, io::Error::last_os_error());
                    self.events_running = false;
                    break;
                }

                if event.u64 == self.sock_fd as u64 {
                    self.rezygiskd_listener_callback();
                } else if event.u64 == self.sig_fd as u64 {
                    self.sigchld_listener_callback();
                }

                if !self.events_running {
                    break;
                }
            }
        }

        if self.epfd >= 0 {
            unsafe { libc::close(self.epfd) };
        }
        self.epfd = -1;
    }

    // -----------------------------------------------------------------------
    // Controller datagram socket (daemon -> monitor reports)
    // -----------------------------------------------------------------------

    fn rezygiskd_listener_init(&mut self) -> bool {
        self.sock_fd = unsafe {
            libc::socket(libc::PF_UNIX, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK, 0)
        };
        if self.sock_fd == -1 {
            plog!(TAG, "socket create");
            return false;
        }

        let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path = CONTROLLER_SOCKET;
        let bytes = path.as_bytes();
        if bytes.len() >= addr.sun_path.len() {
            dloge!("controller socket path too long");
            return false;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytes.as_ptr() as *const libc::c_char,
                addr.sun_path.as_mut_ptr(),
                bytes.len(),
            );
        }

        let socklen = std::mem::size_of::<libc::sa_family_t>() as libc::socklen_t + bytes.len() as libc::socklen_t;
        if unsafe { libc::bind(self.sock_fd, &addr as *const libc::sockaddr_un as *const libc::sockaddr, socklen) } == -1 {
            plog!(TAG, "bind socket");
            return false;
        }

        true
    }

    fn rezygiskd_listener_stop(&mut self) {
        if self.sock_fd >= 0 {
            unsafe { libc::close(self.sock_fd) };
        }
        self.sock_fd = -1;
    }

    fn rezygiskd_listener_callback(&mut self) {
        loop {
            let mut cmd = 0u8;
            let nread = unsafe {
                libc::read(self.sock_fd, (&mut cmd as *mut u8).cast(), 1)
            };
            if nread == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) || err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    break;
                }

                // A persistent error must not turn this loop into a spin.
                plog!(TAG, "read socket");
                break;
            }
            if nread == 0 {
                break;
            }

            match cmd {
                1 => self.handle_start(),
                2 => self.handle_stop(),
                3 => self.handle_exit(),
                4 | 5 => self.handle_zygote_injected(cmd),
                6 | 7 => self.handle_set_info(cmd),
                8 | 9 => self.handle_set_error_info(cmd),
                _ => {}
            }
        }
    }

    fn handle_start(&mut self) {
        match self.tracing_state {
            TracingState::Stopping => {
                dlogi!("Continue tracing init");
                self.tracing_state = TracingState::Tracing;
            }
            TracingState::Stopped => {
                dlogi!("Start tracing init");
                unsafe {
                    libc::ptrace(utils::PTRACE_SEIZE, 1, 0, libc::PTRACE_O_TRACEFORK);
                }
                self.tracing_state = TracingState::Tracing;
            }
            _ => {}
        }

        self.update_status(None);
    }

    fn handle_stop(&mut self) {
        if self.tracing_state == TracingState::Tracing {
            dlogi!("Stop tracing requested");

            self.tracing_state = TracingState::Stopping;
            self.stop_reason = Some("user requested");

            unsafe {
                libc::ptrace(utils::PTRACE_INTERRUPT, 1, 0, 0);
            }
            self.update_status(None);
        }
    }

    fn handle_exit(&mut self) {
        dlogi!("Prepare for exit ...");

        self.tracing_state = TracingState::Exiting;
        self.stop_reason = Some("user requested");

        self.update_status(None);
        self.events_running = false;
    }

    fn handle_zygote_injected(&mut self, cmd: u8) {
        dlogi!("Received Zygote{} injected command", if cmd == 4 { "64" } else { "32" });

        let status = if cmd == 4 { &mut self.status64 } else { &mut self.status32 };
        status.zygote_injected = true;

        self.update_status(None);
    }

    fn handle_set_info(&mut self, cmd: u8) {
        let which = if cmd == 6 { "64" } else { "32" };
        dlogd!("Received ReZygiskd{which} info");

        // One field per datagram (C zygiskd.c `zygiskd_start`). Any framing
        // violation aborts the message and drains the queue: the old
        // stream-style reads busy-spun on EAGAIN forever inside the epoll
        // callback, wedging the whole monitor (boot-killing).
        let Some(root_impl_buf) = recv_bytes_field(self.sock_fd) else {
            dloge!("malformed DaemonSetInfo{which} (root impl), draining controller socket");
            drain_controller_socket(self.sock_fd);
            return;
        };
        let root_impl = String::from_utf8_lossy(&root_impl_buf).into_owned();
        dlogd!("ReZygiskd{which} root impl: {root_impl}");

        let Some(modules_len) = recv_u32_field(self.sock_fd) else {
            dloge!("malformed DaemonSetInfo{which} (modules len), draining controller socket");
            drain_controller_socket(self.sock_fd);
            return;
        };
        if modules_len > MAX_MODULES {
            dloge!("DaemonSetInfo{which}: implausible module count {modules_len}, draining");
            drain_controller_socket(self.sock_fd);
            return;
        }

        let mut modules = Vec::with_capacity(modules_len as usize);
        for i in 0..modules_len {
            let Some(name_buf) = recv_bytes_field(self.sock_fd) else {
                dloge!("malformed DaemonSetInfo{which} (module {i} name), draining controller socket");
                drain_controller_socket(self.sock_fd);
                return;
            };
            modules.push(String::from_utf8_lossy(&name_buf).into_owned());
        }

        let env = if cmd == 6 { &mut self.env64 } else { &mut self.env32 };
        env.root_impl = Some(root_impl);
        env.modules = modules;

        self.update_status(None);
    }

    fn handle_set_error_info(&mut self, cmd: u8) {
        let which = if cmd == 8 { "64" } else { "32" };
        dlogd!("Received ReZygiskd{which} error info");

        let Some(buf) = recv_bytes_field(self.sock_fd) else {
            dloge!("malformed DaemonSetErrorInfo{which}, draining controller socket");
            drain_controller_socket(self.sock_fd);
            return;
        };

        let status = if cmd == 8 { &mut self.status64 } else { &mut self.status32 };
        status.daemon_error_info = Some(String::from_utf8_lossy(&buf).into_owned());

        self.update_status(None);
    }

    // -----------------------------------------------------------------------
    // Daemon lifecycle
    // -----------------------------------------------------------------------

    fn ensure_daemon_created(&mut self, is_64bit: bool) -> bool {
        {
            let status = if is_64bit { &mut self.status64 } else { &mut self.status32 };
            if status.daemon_pid != -1 {
                dlogi!("ReZygiskd{} already running", if is_64bit { "64" } else { "32" });
                return status.daemon_running;
            }
        }

        let pid = match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                let daemon_name = if is_64bit { "./bin/zygiskd64" } else { "./bin/zygiskd32" };
                execv_or_die(daemon_name, &[daemon_name], None);
                // execv_or_die doesn't return, but make the type checker happy
                unreachable!()
            }
            Ok(ForkResult::Parent { child }) => child.as_raw(),
            Err(_) => {
                plog!(TAG, "create ReZygiskd{}", if is_64bit { "64" } else { "32" });
                return false;
            }
        };

        let status = if is_64bit { &mut self.status64 } else { &mut self.status32 };
        status.supported = true;
        status.daemon_pid = pid;
        status.daemon_running = true;

        true
    }

    fn check_daemon_exit(&mut self, pid: i32, status: i32) -> bool {
        // Returns true if the pid was one of the daemons (handled).
        for is_64 in [true, false] {
            let supported = if is_64 { self.status64.supported } else { self.status32.supported };
            let daemon_pid = if is_64 { self.status64.daemon_pid } else { self.status32.daemon_pid };
            if !supported || pid != daemon_pid {
                continue;
            }

            // Only an actual termination is a daemon exit. A stop report for
            // this pid (kernel pid reuse after the daemon died) must fall
            // through to normal attach handling, or the victim is frozen in
            // ptrace-stop forever.
            if !(utils::wifexited(status) || utils::wifsignaled(status)) {
                continue;
            }

            let status_str = parse_status(status);
            dlogw!("daemon{} pid {pid} exited: {status_str}", if is_64 { "64" } else { "32" });

            let status_slot = if is_64 { &mut self.status64 } else { &mut self.status32 };
            status_slot.daemon_running = false;
            // Clear the pid so `ensure_daemon_created` can re-fork instead of
            // reporting a stale "not running" forever after.
            status_slot.daemon_pid = -1;
            if status_slot.daemon_error_info.is_none() {
                status_slot.daemon_error_info = Some(status_str);
            }

            self.update_status(None);
            return true;
        }

        false
    }

    // -----------------------------------------------------------------------
    // Boot watchdog: init must never stay frozen, whatever happens elsewhere.
    // -----------------------------------------------------------------------

    /// True when pid 1 is currently in a stop state ('T' job-control stop or
    /// 't' ptrace-stop) according to /proc/1/stat.
    fn init_stopped() -> bool {
        let Ok(stat) = std::fs::read_to_string("/proc/1/stat") else {
            return false;
        };

        // comm can contain spaces/parens; the state char follows the last ')'.
        let Some(close) = stat.rfind(')') else {
            return false;
        };

        match stat[close + 1..].split_whitespace().next() {
            Some("T") | Some("t") => true,
            _ => false,
        }
    }

    /// Fires on every idle epoll tick. If init was seized by us and left in a
    /// stop for a full tick, resume it. A buggy handler can then only stall
    /// boot by at most one tick instead of forever.
    fn watchdog_check_init(&mut self) {
        if self.tracing_state != TracingState::Tracing || !Self::init_stopped() {
            return;
        }

        dloge!("WATCHDOG: init is stopped with no pending event, resuming it");
        if unsafe { libc::ptrace(libc::PTRACE_CONT, 1, 0, 0) } == -1 {
            plog!(TAG, "WATCHDOG: PTRACE_CONT init");
        }
    }

    // -----------------------------------------------------------------------
    // SIGCHLD handling
    // -----------------------------------------------------------------------

    fn sigchld_listener_init(&mut self) -> bool {
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGCHLD);

            if libc::sigprocmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut()) == -1 {
                plog!(TAG, "set sigprocmask");
                return false;
            }

            self.sig_fd = libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC);
            if self.sig_fd == -1 {
                plog!(TAG, "create signalfd");
                return false;
            }
        }

        true
    }

    fn sigchld_listener_stop(&mut self) {
        if self.sig_fd >= 0 {
            unsafe { libc::close(self.sig_fd) };
        }
        self.sig_fd = -1;

        self.tracked.clear();
    }

    fn sigchld_listener_callback(&mut self) {
        loop {
            let mut fdsi: libc::signalfd_siginfo = unsafe { std::mem::zeroed() };
            let s = unsafe { libc::read(self.sig_fd, (&mut fdsi as *mut libc::signalfd_siginfo).cast(), size_of::<libc::signalfd_siginfo>()) };
            if s == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EAGAIN) {
                    break;
                }

                plog!(TAG, "read signalfd");
                continue;
            }

            if s as usize != size_of::<libc::signalfd_siginfo>() {
                dlogw!("read {s} != {}", size_of::<libc::signalfd_siginfo>());
                continue;
            }

            if fdsi.ssi_signo as i32 != libc::SIGCHLD {
                dlogw!("no sigchld received");
                continue;
            }

            loop {
                let mut status = 0;
                let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
                if pid == 0 {
                    break;
                }
                if pid == -1 {
                    let err = io::Error::last_os_error();
                    if self.tracing_state == TracingState::Stopped && err.raw_os_error() == Some(libc::ECHILD) {
                        break;
                    }
                    plog!(TAG, "waitpid");
                    // Never dispatch a waitpid error sentinel as a child
                    // report: it used to poison `tracked` with -1.
                    continue;
                }

                self.handle_sigchld_child(pid, status);
            }
        }
    }

    fn handle_sigchld_child(&mut self, pid: i32, mut status: i32) {
        if pid == 1 {
            if utils::stopped_with(status, libc::SIGTRAP, libc::PTRACE_EVENT_FORK) {
                let mut child_pid: i64 = 0;
                unsafe {
                    libc::ptrace(libc::PTRACE_GETEVENTMSG, pid, 0, &mut child_pid as *mut i64 as *mut libc::c_void);
                }
                dlogv!("forked {child_pid}");
            } else if utils::stopped_with(status, libc::SIGTRAP, libc::PTRACE_EVENT_STOP)
                && self.tracing_state == TracingState::Stopping
            {
                if unsafe { libc::ptrace(libc::PTRACE_DETACH, 1, 0, 0) } == -1 {
                    plog!(TAG, "failed to detach init");
                }

                self.tracing_state = TracingState::Stopped;
                dlogi!("stop tracing init");

                // monitor.c:624-632: after detaching init, C `continue`s the
                // SIGCHLD loop — the generic stopped-handling below must not
                // PTRACE_CONT an already-detached tracee.
                return;
            }

            if utils::wifstopped(status) {
                if utils::wptevent(status) == 0 {
                    let stop_sig = utils::wstopsig(status);
                    if stop_sig != libc::SIGSTOP
                        && stop_sig != libc::SIGTSTP
                        && stop_sig != libc::SIGTTIN
                        && stop_sig != libc::SIGTTOU
                    {
                        dlogw!(
                            "inject signal sent to init: {} {stop_sig}",
                            utils::sigabbrev_np(stop_sig)
                        );

                        unsafe {
                            libc::ptrace(libc::PTRACE_CONT, pid, 0, stop_sig);
                        }
                        return;
                    } else {
                        dlogw!(
                            "suppress stopping signal sent to init: {} {stop_sig}",
                            utils::sigabbrev_np(stop_sig)
                        );
                    }
                }

                unsafe {
                    libc::ptrace(libc::PTRACE_CONT, pid, 0, 0);
                }
            }

            return;
        }

        if self.check_daemon_exit(pid, status) {
            return;
        }

        let tracked_index = self.tracked.iter().position(|&p| p == pid);
        match tracked_index {
            None => {
                // Only a stop report introduces a new tracee. Exit reports of
                // monitor children reaped elsewhere (and error sentinels,
                // gated above) must not enter `tracked`: a stale slot later
                // misroutes a pid-reused init child into the "unknown
                // sigchld_status" blind-detach path.
                if pid > 0 && utils::wifstopped(status) {
                    dlogv!("new process {pid} attached");

                    if let Some(slot) = self.tracked.iter_mut().find(|p| **p == 0) {
                        *slot = pid;
                    } else {
                        self.tracked.push(pid);
                    }

                    unsafe {
                        libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, libc::PTRACE_O_TRACEEXEC);
                        libc::ptrace(libc::PTRACE_CONT, pid, 0, 0);
                    }
                }
            }
            Some(_) => {
                if utils::stopped_with(status, libc::SIGTRAP, libc::PTRACE_EVENT_EXEC) {
                    let Ok(program) = utils::get_program(pid) else {
                        dlogw!("failed to get program {pid}");
                        self.clear_tracked(pid);
                        return;
                    };

                    dlogv!("{pid} program {program}");

                    self.consider_handoff(pid, &program, &mut status);
                } else {
                    let program = utils::get_program(pid).unwrap_or_else(|_| "<unreadable>".to_string());
                    let cmdline = utils::get_cmdline(pid);
                    dlogw!(
                        "process {pid} (program={program}, cmdline=\"{cmdline}\") received unknown sigchld_status {}",
                        parse_status(status)
                    );
                }

                self.clear_tracked(pid);

                if utils::wifstopped(status) {
                    dlogv!("detach process {pid}");

                    unsafe {
                        libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
                    }
                }
            }
        }
    }

    fn clear_tracked(&mut self, pid: i32) {
        if let Some(slot) = self.tracked.iter_mut().find(|p| **p == pid) {
            *slot = 0;
        }
    }

    /// monitor.c PRE_INJECT / PRE_INJECT_TANGO / handoff block.
    fn consider_handoff(&mut self, pid: i32, program: &str, status: &mut i32) {
        let (tracer, is_tango, is_64) = if program == APP_PROCESS_64 {
            ("./bin/zygisk-ptrace64", false, true)
        } else if program == APP_PROCESS_32 {
            ("./bin/zygisk-ptrace32", false, false)
        } else if program == TANGO_TRANSLATOR {
            ("./bin/zygisk-ptrace32", true, false)
        } else {
            return;
        };

        // Next-gen hardening: an app_process exec only wins a handoff if it is
        // genuinely a zygote. Other app_process users (TEE simulators, cmd
        // wrappers, translation runtimes racing a zygote restart) must never
        // receive libzygisk. Fail-open when /proc is unreadable so a blocked
        // read can never wedge the boot — the positive matches below still
        // filter every normally-readable process.
        if !is_tango {
            let cmdline = utils::get_cmdline(pid);
            if !cmdline.is_empty() && !cmdline.split(' ').any(|arg| arg == "--zygote") {
                dlogw!("not handing off {pid}: app_process exec without --zygote (cmdline: \"{cmdline}\")");
                return;
            }
            if let Some(ppid) = utils::get_ppid(pid) {
                if ppid != 1 {
                    dlogw!("not handing off {pid}: parent is {ppid}, not init (program={program})");
                    return;
                }
            }
        }

        if self.tracing_state != TracingState::Tracing {
            dlogw!("stop injecting {pid} because not tracing");
            return;
        }

        // Restart counters + daemon readiness gate.
        if !is_64 {
            if self.counter32.should_stop_inject() {
                dlogw!(
                    "{} restart {} times, stop injecting",
                    if is_tango { "Tango" } else { "Zygote32" },
                    if is_tango { "too many" } else { "too much" }
                );

                self.tracing_state = TracingState::Stopping;
                self.stop_reason = Some("Zygote crashed");
                unsafe {
                    libc::ptrace(utils::PTRACE_INTERRUPT, 1, 0, 0);
                }
                return;
            }
        } else if self.counter64.should_stop_inject() {
            dlogw!("Zygote64 restart too much times, stop injecting");

            self.tracing_state = TracingState::Stopping;
            self.stop_reason = Some("Zygote crashed");
            unsafe {
                libc::ptrace(utils::PTRACE_INTERRUPT, 1, 0, 0);
            }
            return;
        }

        if !self.ensure_daemon_created(is_64) {
            dlogw!("ReZygiskd {}-bit not running, stop injecting", if is_64 { "64" } else { "32" });

            self.tracing_state = TracingState::Stopping;
            self.stop_reason = Some("ReZygiskd not running");
            unsafe {
                libc::ptrace(utils::PTRACE_INTERRUPT, 1, 0, 0);
            }
            return;
        }

        dlogi!(
            "handoff tracer: pid={pid} program={program} tracer={tracer} tango={}",
            if is_tango { "yes" } else { "no" }
        );

        if is_tango {
            // Stopping tango during init causes an unrecoverable SIGSEGV on resume.
            dlogd!("tango deferred: detaching {pid} without stop");
            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, pid, 0, 0);
            }
        } else {
            dlogd!("stopping {pid}");

            let _ = kill(Pid::from_raw(pid), Signal::SIGSTOP);
            unsafe {
                libc::ptrace(libc::PTRACE_CONT, pid, 0, 0);
            }

            // Bounded wait for the group-stop: blocking forever here would
            // hold init (seized by us) stopped on every event queued behind
            // it, wedging the whole boot.
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut handoff_status = 0;
            let stopped_ok = loop {
                let r = unsafe { libc::waitpid(pid, &mut handoff_status, libc::__WALL | libc::WNOHANG) };
                if r == pid {
                    break utils::stopped_with(handoff_status, libc::SIGSTOP, 0);
                }
                if r == -1 || Instant::now() > deadline {
                    break false;
                }
                std::thread::sleep(Duration::from_millis(20));
            };

            if !stopped_ok {
                dloge!("handoff: pid {pid} did not group-stop as expected ({}), aborting handoff", parse_status(handoff_status));

                unsafe {
                    libc::ptrace(libc::PTRACE_DETACH, pid, 0, libc::SIGCONT);
                }
                let _ = kill(Pid::from_raw(pid), Signal::SIGCONT);

                self.clear_tracked(pid);
                return;
            }

            dlogd!("detaching {pid}");
            unsafe {
                libc::ptrace(libc::PTRACE_DETACH, pid, 0, libc::SIGSTOP);
            }
        }

        // monitor.c:745 `sigchld_status = 0`: the handoff above already
        // detached the process; clearing the status keeps the outer SIGCHLD
        // handler from PTRACE_DETACH-ing it a second time.
        *status = 0;

        // Only restart companions if it's not the first time.
        let do_restart = if is_tango {
            self.counter32.count > 1
        } else if is_64 {
            self.counter64.count > 1
        } else {
            self.counter32.count > 1
        };

        let p = fork_dont_care();
        if p == 0 {
            let pid_str = pid.to_string();
            dlogi!(
                "exec tracer command: {tracer} trace {pid_str} --restart{}",
                if is_tango { " --tango" } else { "" }
            );

            let base = tracer.rsplit('/').next().unwrap_or(tracer);
            let mut args: Vec<&str> = vec![base, "trace", &pid_str];
            if do_restart {
                args.push("--restart");
            }
            if is_tango {
                args.push("--tango");
            }

            execv_or_die(tracer, &args, Some(pid));
        } else if p == -1 {
            plog!(TAG, "failed to fork, kill");
            let _ = kill(Pid::from_raw(pid), Signal::SIGKILL);
        }
    }
}

/// exec helper for the forked children: mirrors `execl(...)` + PLOGE/exit(1).
/// When `kill_target` is set (tracer handoff), the C monitor kills the parked
/// zygote on exec failure — otherwise it stays group-stopped forever.
fn execv_or_die(path: &str, args: &[&str], kill_target: Option<i32>) -> ! {
    let cpath = std::ffi::CString::new(path).unwrap();
    let argp: Vec<std::ffi::CString> = args.iter().map(|a| std::ffi::CString::new(*a).unwrap()).collect();
    let mut argp: Vec<*const libc::c_char> = argp.iter().map(|a| a.as_ptr()).collect();
    argp.push(std::ptr::null());

    unsafe {
        libc::execv(cpath.as_ptr(), argp.as_ptr());
    }

    plog!(TAG, "failed to exec, kill");
    if let Some(target) = kill_target {
        let _ = kill(Pid::from_raw(target), Signal::SIGKILL);
    }
    std::process::exit(1);
}

// ---------------------------------------------------------------------------
// Controller-socket datagram discipline
// ---------------------------------------------------------------------------

/// Sanity bound for a controller string field (root impl name, module name,
/// error message). A garbled length must never become a giant allocation.
const MAX_FIELD_LEN: u32 = 1 << 20;

/// Sanity bound for the module count in DaemonSetInfo.
const MAX_MODULES: u32 = 4096;

/// Read one controller field: the daemon (C and Rust) sends each field as its
/// own `SOCK_DGRAM` datagram. A datagram shorter than the field, an oversized
/// datagram (MSG_TRUNC reports the true length), or an empty queue
/// mid-message (EWOULDBLOCK — sender died or sequences interleaved) is a
/// framing violation: return false so the caller logs, drains and resyncs.
/// This must never loop on EAGAIN like `read_exact` did — that spin wedged
/// the monitor's only thread inside the epoll callback and killed boots.
fn recv_field(fd: i32, buf: &mut [u8]) -> bool {
    loop {
        let n = unsafe {
            libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), libc::MSG_DONTWAIT | libc::MSG_TRUNC)
        };
        if n == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return false;
        }
        return n as usize == buf.len();
    }
}

/// A `u32` field datagram.
fn recv_u32_field(fd: i32) -> Option<u32> {
    let mut bytes = [0u8; 4];
    if !recv_field(fd, &mut bytes) {
        return None;
    }
    Some(u32::from_ne_bytes(bytes))
}

/// A length-prefixed string field: `[u32 len]` datagram followed by a
/// `len`-byte datagram, both bounds-checked.
fn recv_bytes_field(fd: i32) -> Option<Vec<u8>> {
    let len = recv_u32_field(fd)?;
    if len > MAX_FIELD_LEN {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    if !recv_field(fd, &mut buf) {
        return None;
    }
    Some(buf)
}

/// After a framing violation, discard everything currently queued so the
/// next command byte starts a fresh message.
fn drain_controller_socket(fd: i32) {
    let mut scratch = [0u8; 4096];
    loop {
        let n = unsafe {
            libc::recv(fd, scratch.as_mut_ptr() as *mut libc::c_void, scratch.len(), libc::MSG_DONTWAIT)
        };
        if n <= 0 {
            break;
        }
    }
}

/// C fopen(..., "w") equivalent: create/truncate, returning the raw fd.
fn write_file_start(path: &str) -> Option<i32> {
    let cpath = std::ffi::CString::new(path).ok()?;
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    if fd == -1 {
        None
    } else {
        Some(fd)
    }
}

fn write_file_finish(fd: i32, payload: &str) -> io::Result<()> {
    let bytes = payload.as_bytes();
    let mut written = 0;
    while written < bytes.len() {
        let n = unsafe { libc::write(fd, bytes[written..].as_ptr() as *const libc::c_void, bytes.len() - written) };
        if n == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            unsafe { libc::close(fd) };
            return Err(err);
        }
        written += n as usize;
    }

    unsafe { libc::close(fd) };
    Ok(())
}

/// monitor.c `prepare_environment` line splitting: everything up to and
/// including the `description=` prefix goes to `pre`; the description value and
/// everything after goes to `post`.
///
/// `update_status` formats as `pre + "[status] " + post`, so any status
/// bracket already present in the stored description would be preserved
/// forever as stale history (a prop in the wild can carry several fossilized
/// "[Monitor: … ⚠️]" groups). Leading status brackets are therefore stripped
/// here — but only genuine ones ("Monitor:" prefix), since a description may
/// legitimately begin with its own bracketed text.
pub(crate) fn split_module_prop(orig: &str) -> (String, String) {
    let mut pre = String::new();
    let mut post = String::new();
    let mut after_description = false;

    for line in orig.split_inclusive('\n') {
        if let Some(value) = line.strip_prefix("description=") {
            pre.push_str("description=");
            post.push_str(strip_status_brackets(value));
            after_description = true;
            continue;
        }

        if after_description {
            post.push_str(line);
        } else {
            pre.push_str(line);
        }
    }

    (pre, post)
}

fn strip_status_brackets(mut value: &str) -> &str {
    loop {
        let trimmed = value.trim_start();
        let Some(rest) = trimmed.strip_prefix("[Monitor: ") else {
            break;
        };
        let Some(end) = rest.find(']') else {
            break;
        };
        value = rest[end + 1..].trim_start();
    }
    value
}

/// monitor.c `claim_init_tracer`.
fn claim_init_tracer(monitor: &mut Monitor) -> bool {
    if unsafe { libc::ptrace(utils::PTRACE_SEIZE, 1, 0, libc::PTRACE_O_TRACEFORK) } == -1 {
        // A second ReZygisk cannot seize init (single-tracer limitation): exit
        // quietly instead of fighting over it.
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) {
            dlogw!("Another process is already tracing init");

            // monitor.c:553: a second Zygisk instance was started — surface
            // it in module.prop so the user can see why injection stopped.
            monitor.update_status(Some("❌ Multiple Zygisks functioning"));
        } else {
            plog!(TAG, "failed to seize init");
        }

        return false;
    }

    true
}

/// monitor.c `init_monitor` — the monitor main body; never returns normally.
pub fn init_monitor() {
    dlogi!("ReZygisk {ZKSU_VERSION}");

    let mut monitor = Monitor::new();

    if !monitor.prepare_environment() {
        std::process::exit(1);
    }

    if !claim_init_tracer(&mut monitor) {
        std::process::exit(1);
    }

    monitor.events_init();

    if !monitor.rezygiskd_listener_init() {
        dloge!("failed to create socket");
        unsafe { libc::close(monitor.epfd) };
        std::process::exit(1);
    }

    monitor.events_register(monitor.sock_fd);

    if !monitor.sigchld_listener_init() {
        dloge!("failed to create signalfd");

        monitor.rezygiskd_listener_stop();
        unsafe { libc::close(monitor.epfd) };

        std::process::exit(1);
    }

    monitor.events_register(monitor.sig_fd);

    monitor.events_loop();

    monitor.rezygiskd_listener_stop();
    monitor.sigchld_listener_stop();

    dlogi!("Terminating ReZygisk monitor");
}

/// monitor.c `send_control_command`.
pub fn send_control_command(cmd: RezygiskdCommand) -> io::Result<()> {
    // datagram_sendto opens its own socket; the C code's manual socket here
    // exists only to copy a string into the message payload, which a single
    // byte command does not need.
    rz_ipc::datagram_sendto(CONTROLLER_SOCKET, &[cmd as u8])
}

