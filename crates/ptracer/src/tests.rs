//! Host tests for the monitor port: state.json golden bytes, module.prop
//! splitting, wait-status helpers, and the zygote restart counter.

use crate::monitor::{split_module_prop, Monitor, RezygiskdCommand, TracingState, ZygoteStartCounter};
use crate::utils::{parse_status, sigabbrev_np, stopped_with, wifstopped, wptevent, wstopsig};

fn monitor_with_status() -> Monitor {
    let mut m = Monitor::new();
    m.env64.root_impl = Some("KernelSU".into());
    m.env64.modules = vec!["truman".into(), "playintegrityfix".into()];
    m.status64.supported = true;
    m.status64.daemon_running = true;
    m.status64.zygote_injected = true;
    m
}

/// Byte-for-byte against monitor.c update_status fprintf sequence
/// (64-bit daemon only, everything healthy).
#[test]
fn state_json_64bit_healthy() {
    let m = monitor_with_status();
    assert_eq!(
        m.build_state_json(),
        "{\n\
         \x20 \"root\": \"KernelSU\",\n\
         \x20 \"monitor\": {\n\
         \x20   \"state\": \"0\"\n\
         \x20 },\n\
         \x20 \"rezygiskd\": {\n\
         \x20   \"64\": {\n\
         \x20     \"state\": 1,\n\
         \x20     \"modules\": [\"truman\", \"playintegrityfix\"]\n\
         \x20   }\n\
         \x20 },\n\
         \x20 \"zygote\": {\n\
         \x20   \"64\": 1\n\
         \x20 }\n\
         }\n"
    );
}

/// Both ABIs, daemon error info, tango-style stop reason (trailing comma
/// quirk preserved from the C fprintf).
#[test]
fn state_json_both_abis_with_errors() {
    let mut m = monitor_with_status();
    m.env32.root_impl = Some("Magisk".into());
    m.env32.modules = vec!["truman".into()];
    m.status32.supported = true;
    m.status32.daemon_running = false;
    m.status32.daemon_error_info = Some("exec failed".into());
    m.status32.zygote_injected = true;
    m.tracing_state = TracingState::Stopping;
    m.stop_reason = Some("Zygote crashed");

    let json = m.build_state_json();
    assert_eq!(
        json,
        "{\n\
         \x20 \"root\": \"KernelSU\",\n\
         \x20 \"monitor\": {\n\
         \x20   \"state\": \"1\",\n\
         \x20   \"reason\": \"Zygote crashed\",\n\
         \x20 },\n\
         \x20 \"rezygiskd\": {\n\
         \x20   \"64\": {\n\
         \x20     \"state\": 1,\n\
         \x20     \"modules\": [\"truman\", \"playintegrityfix\"]\n\
         \x20   },\n\
         \x20   \"32\": {\n\
         \x20     \"state\": 0,\n\
         \x20     \"reason\": \"exec failed\",\n\
         \x20     \"modules\": [\"truman\"]\n\
         \x20   }\n\
         \x20 },\n\
         \x20 \"zygote\": {\n\
         \x20   \"64\": 1,\n\
         \x20   \"32\": 1\n\
         \x20 }\n\
         }\n"
    );
}

/// No environment info yet → no rezygiskd/zygote sections.
#[test]
fn state_json_empty_environment() {
    let m = Monitor::new();
    assert_eq!(
        m.build_state_json(),
        "{\n\
         \x20 \"root\": \"\",\n\
         \x20 \"monitor\": {\n\
         \x20   \"state\": \"0\"\n\
         \x20 }\n\
         }\n"
    );
}

#[test]
fn module_prop_split() {
    // Leading status brackets are stripped: update_status prepends a fresh
    // "[Monitor: …] " on every write, so a stored bracket is stale history.
    let orig = "id=rezygisk\nname=ReZygisk\ndescription=[Monitor: ✅] tracer\nversion=v1\nextra=1\n";
    let (pre, post) = split_module_prop(orig);
    assert_eq!(pre, "id=rezygisk\nname=ReZygisk\ndescription=");
    assert_eq!(post, "tracer\nversion=v1\nextra=1\n");

    // Fossilized bracket pileup from older monitors self-heals: only the
    // fresh bracket written by update_status remains.
    let dirty = "description=[Monitor: ✅, ReZygisk 64-bit: ✅, ReZygisk 32-bit: ✅] \
                 [Monitor: ✅, ReZygisk 64-bit: ✅, ReZygisk 32-bit: ⚠️] Standalone implementation of Zygisk.\n\
                 versionCode=1\n";
    let (pre, post) = split_module_prop(dirty);
    assert_eq!(post, "Standalone implementation of Zygisk.\nversionCode=1\n");
    assert_eq!(
        format!("{}[Monitor: ✅] {}", pre, post),
        "description=[Monitor: ✅] Standalone implementation of Zygisk.\nversionCode=1\n"
    );

    // Non-status leading brackets are left untouched.
    let (_, post) = split_module_prop("description=[TIP] friendly text\n");
    assert_eq!(post, "[TIP] friendly text\n");

    // No trailing newline on the last line.
    let (pre, post) = split_module_prop("a=1\ndescription=d\nb=2");
    assert_eq!(pre, "a=1\ndescription=");
    assert_eq!(post, "d\nb=2");
}

/// module.prop rewrite payload shape: pre[status] post.
#[test]
fn status_text_and_payload_shape() {
    let mut m = monitor_with_status();
    let pre = "id=rezygisk\ndescription=";
    let post = "original\n";
    m.pre_section = pre.into();
    m.post_section = post.into();

    let text = m.status_text();
    assert_eq!(text, "Monitor: ✅, ReZygisk 64-bit: ✅");
    assert_eq!(format!("{}[{text}] {}", m.pre_section, m.post_section),
               "id=rezygisk\ndescription=[Monitor: ✅, ReZygisk 64-bit: ✅] original\n");

    m.status64.daemon_running = false;
    m.status64.zygote_injected = false;
    assert_eq!(m.status_text(), "Monitor: ✅, ReZygisk 64-bit: ⚠️(ReZygiskd: not running)");
}

/// wait-status helper behavior on synthetic status words.
#[test]
fn wait_status_helpers() {
    // group-stop: SIGTRAP|0x80 (0x85) with no event. Wait status low byte is
    // 0x7f for stops; the stop signal lives in bits 8..15, the ptrace event
    // in bits 16..23.
    let syscall_stop = 0x7f | ((libc::SIGTRAP | 0x80) << 8);
    assert!(wifstopped(syscall_stop));
    assert_eq!(wstopsig(syscall_stop), libc::SIGTRAP | 0x80);
    assert_eq!(wptevent(syscall_stop), 0);
    assert!(!stopped_with(syscall_stop, libc::SIGTRAP, libc::PTRACE_EVENT_STOP));

    // PTRACE_EVENT_EXEC(4) report.
    let exec_stop = 0x7f | (libc::SIGTRAP << 8) | (4 << 16);
    assert_eq!(wptevent(exec_stop), libc::PTRACE_EVENT_EXEC);
    assert!(stopped_with(exec_stop, libc::SIGTRAP, libc::PTRACE_EVENT_EXEC));

    // plain SIGSTOP group stop.
    let group_stop = 0x7f | (libc::SIGSTOP << 8);
    assert!(stopped_with(group_stop, libc::SIGSTOP, 0));

    assert_eq!(sigabbrev_np(libc::SIGSEGV), "SEGV");

    let s = parse_status(group_stop);
    assert!(s.contains("stopped by signal=STOP(19)"), "{s}");
}

/// Counter semantics mirror the C macro: first call never trips, five rapid
/// restarts within 30s trip on the sixth call.
#[test]
fn zygote_counter_first_call_clears() {
    let mut c = ZygoteStartCounter::new();
    assert!(!c.should_stop_inject());
    assert_eq!(c.count, 0);
}

/// ctl command wire values (monitor.h enum rezygiskd_command).
#[test]
fn control_command_values() {
    assert_eq!(RezygiskdCommand::Start as u8, 1);
    assert_eq!(RezygiskdCommand::Stop as u8, 2);
    assert_eq!(RezygiskdCommand::Exit as u8, 3);
    assert_eq!(RezygiskdCommand::Zygote64Injected as u8, 4);
    assert_eq!(RezygiskdCommand::Zygote32Injected as u8, 5);
    assert_eq!(RezygiskdCommand::Daemon64SetInfo as u8, 6);
    assert_eq!(RezygiskdCommand::Daemon32SetInfo as u8, 7);
    assert_eq!(RezygiskdCommand::Daemon64SetErrorInfo as u8, 8);
    assert_eq!(RezygiskdCommand::Daemon32SetErrorInfo as u8, 9);
}

/// find_func_addr must execute an IFUNC resolver locally instead of using the
/// resolver's st_value (elf_util.c handle_indirect_symbol). This is the root
/// cause of the zygote32 fortify-abort bootloop: GOT[0x14050] got the resolver
/// address, so strlen() "returned" the implementation pointer.
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
#[test]
fn ifunc_resolver_translation() {
    use std::ffi::CString;

    let dir = std::env::temp_dir().join(format!("rz-ifunc-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let src = dir.join("ifunc_fixture.c");
    let so = dir.join("ifunc_fixture.so");
    std::fs::write(
        &src,
        "static void *impl_fn(void) { return (void *)0x1234abcd; }\n\
         static void *resolver_fn(void) { return (void *)impl_fn; }\n\
         void *ifunc_sym(void) __attribute__((ifunc(\"resolver_fn\")));\n\
         long plain_fn(void) { return 42; }\n",
    )
    .unwrap();

    let status = std::process::Command::new("gcc")
        .args(["-shared", "-fPIC", "-o"])
        .arg(&so)
        .arg(&src)
        .status()
        .expect("gcc");
    assert!(status.success(), "failed to build fixture");

    let so_path = so.canonicalize().unwrap();
    let cpath = CString::new(so_path.as_os_str().as_encoded_bytes()).unwrap();
    let handle = unsafe { libc::dlopen(cpath.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
    assert!(!handle.is_null(), "dlopen failed");

    // Local maps for this process; "remote" is the same mapping, so the
    // base translation must be the identity.
    let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
    let entries: Vec<rz_common::MapEntry> =
        maps.lines().filter_map(rz_common::parse_maps_line).collect();
    let mine: Vec<rz_common::MapEntry> = entries
        .iter()
        .filter(|m| m.path == so_path.as_os_str().to_string_lossy())
        .cloned()
        .collect();
    assert!(!mine.is_empty(), "fixture not found in maps");

    let expected_ifunc =
        unsafe { libc::dlsym(handle, b"ifunc_sym\0".as_ptr() as *const libc::c_char) } as usize;
    let expected_plain =
        unsafe { libc::dlsym(handle, b"plain_fn\0".as_ptr() as *const libc::c_char) } as usize;
    assert_ne!(expected_ifunc, 0);
    assert_ne!(expected_plain, 0);

    let got_ifunc = crate::utils::find_func_addr(&mine, &mine, &so_path.to_string_lossy(), "ifunc_sym");
    let got_plain = crate::utils::find_func_addr(&mine, &mine, &so_path.to_string_lossy(), "plain_fn");

    assert_eq!(got_ifunc as usize, expected_ifunc, "IFUNC must resolve via local resolver");
    assert_eq!(got_plain as usize, expected_plain, "plain symbol must resolve via st_value");

    unsafe { libc::dlclose(handle) };
    let _ = std::fs::remove_dir_all(&dir);
}
