//! Zygisk loader injected into the zygote (`libzygisk.so`).
//!
//! # Frozen contracts (do not break)
//! - `entry(addr, size, tango_flag)` — ptracer calls this after injection
//! - `abi.rs` — `repr(C)` module API (REZYGISK_API_VERSION 5)
//! - `jni_tables.rs` — zygote JNI overload hooks (Android/ART surface)
//! - PLT hook symbols: `fork`, `strdup`, `pthread_attr_setstacksize`,
//!   `property_get`, `ReopenOrDetach`
//!
//! See `docs/CONTRACTS.md` for the full list and the verification rules.
//!
//! # Layout
//! - `abi.rs` / `context.rs`: shared spine (module ABI + zygote-side state)
//! - `entry.rs`: `#[no_mangle] entry` export
//! - `fork_hooks.rs`: PLT hooks + self-unmap trampoline
//! - `jni_tables.rs` / `jni_hooks.rs`: JNI overload wrappers
//! - `ifunc_shim.rs` (arm32): hidden mem*/str* for Tango

// Lint policy: no crate-level suppressions except dead_code for host builds.
// Per-file or per-item allows only where required by external contracts
// (JNI symbols, C++ mangled names, ABI exports).
//
// `dead_code` (non-android builds only): rustc roots the full live graph
// only on the shipping android targets; host/qemu builds cfg out the
// entry chain and fake mass dead code, so the lint is relaxed there.
#![cfg_attr(not(target_os = "android"), allow(dead_code))]

pub mod abi;
pub mod context;

mod app_specialize;
mod art_method;
mod cpp_strings;
mod daemon_client;
mod entry;
mod fd_sanitize;
mod fork_hooks;
mod fork_prepost;
mod hook_register;
mod ifunc_shim;
mod jni_hooks;
mod jni_tables;
mod jni_utils;
mod lifecycle;
mod load_modules;
mod misc_port;
mod module_api;
mod module_calls;
mod native_specialize;
mod plt_commit;
mod plt_commit_v4;
mod ptrace_clear;
#[cfg(all(
    test,
    not(target_os = "android"),
    any(target_arch = "aarch64", target_arch = "arm")
))]
mod trampoline_test;
