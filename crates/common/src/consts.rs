//! Path / name constants. Wire-compatible with the C fork:
//! daemon.h, zygiskd/src/zygiskd.c and common.mk.

/// Non-const helper mirroring `LP_SELECT(a, b)`: usable in `const fn` bodies
/// because `cfg!` is a compile-time bool literal.
macro_rules! lp_select_impl {
    ($lp32:expr, $lp64:expr) => {
        if cfg!(target_pointer_width = "64") { $lp64 } else { $lp32 }
    };
}

pub const TMP_PATH: &str = "/data/adb/rezygisk";
pub const PATH_MODULES_DIR: &str = "/data/adb/modules";
pub const CONTROLLER_SOCKET: &str = "/data/adb/rezygisk/init_monitor";
pub const MODULE_PROP: &str = "module.prop";

/// daemon.h `CP_SOCKET_ABSTRACT_NAME` — abstract-namespace cp socket (L2).
pub const fn cp_socket_abstract_name() -> &'static str {
    lp_select_impl!("rezygisk-cp32", "rezygisk-cp64")
}

/// zygiskd.c `ZYGISKD_PATH`.
pub const fn zygiskd_path() -> &'static str {
    lp_select_impl!(
        "/data/adb/modules/rezygisk/bin/zygiskd32",
        "/data/adb/modules/rezygisk/bin/zygiskd64"
    )
}

/// zygiskd.c `ARCH_STR` — the module .so subdirectory for this build.
pub const fn arch_str() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    { "arm64-v8a" }
    #[cfg(target_arch = "arm")]
    { "armeabi-v7a" }
    #[cfg(target_arch = "x86_64")]
    { "x86_64" }
    #[cfg(target_arch = "x86")]
    { "x86" }
}

/// `/data/adb/modules/<name>/zygisk/<ARCH>.so`
pub fn module_so_path(name: &str) -> String {
    format!("{PATH_MODULES_DIR}/{name}/zygisk/{}.so", arch_str())
}

/// Built-in truman sub-module path (fork addition).
pub fn builtin_truman_so_path() -> String {
    format!("{PATH_MODULES_DIR}/rezygisk/zygisk/truman/{}.so", arch_str())
}

/// PROCESS_NAME_MAX_LEN from constants.h.
pub const PROCESS_NAME_MAX_LEN: usize = 256 + 1;

/// Version gates from common.mk / root_impl version minimums.
pub const MIN_APATCH_VERSION: u64 = 10655;
pub const MIN_KSU_KERNEL_VERSION: u64 = 10940;
pub const MIN_KSU_KSUD_VERSION: u64 = 11425;
pub const MIN_MAGISK_VERSION: u64 = 26402;
