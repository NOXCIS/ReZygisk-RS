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

// Required allows — reasons:
// - `dead_code`: the live graph hangs off the extern `entry` (the ptracer
//   calls it by scanning `.dynsym`; PLTI and modules call hook tables by
//   pointer), so rustc sees most of the crate as unreachable
// - `non_snake_case` / `non_upper_case_globals`: JNI symbols (`nativeForkAndSpecialize_l`,
//   `OLD_...`) are the Android contract; their spelling is not ours to change
// - `unsafe_op_in_unsafe_fn`: hot paths; per-op unsafe blocks would obscure
//   control flow without adding safety the signatures don't already state
// - `static_mut_refs`: context.rs / jni_tables.rs globals (migration to
//   atomics/Mutex planned)
// - `function_casts_as_integer`: `JNINativeMethod.fn_ptr` and the PLTI
//   backup slots store addresses as `usize` — the storage types are fixed
//   by the module ABI / PLTI interface
#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(static_mut_refs)]
#![allow(function_casts_as_integer)]

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
