//! Zygisk loader injected into the zygote (libzygisk.so).
//!
//! Port of loader/src/injector/* (hook.c, entry.c, module.h, jni_hooks.h,
//! art_method.h, cpp_strings.c, ptrace_clear.c) plus the in-process
//! CSOLoader client (loader/src/common/daemon.c).
//!
//! Layout:
//! - `abi.rs` / `context.rs`: the shared spine (`repr(C)` module ABI mirrors
//!   and the zygote-side global state). Every other module writes against
//!   these — do not redefine the types.
//! - one module per C source/function group, mirroring hook.c's layout.
//! - `entry` owns the `#[no_mangle] entry` export the ptracer calls.
//! - `ifunc_shim` (arm32-only) provides the hidden mem*/str* shims for
//!   Tango; `exports.map` localizes them like the C `-fvisibility=hidden`.

#![allow(static_mut_refs)]
// C-parity allowances:
// - the whole live graph hangs off the extern `entry` (the ptracer calls it
//   by scanning `.dynsym`; PLTI/modules call the hook tables by pointer), so
//   rustc sees most of the crate as unreachable — `dead_code`.
// - C identifiers (`nativeForkAndSpecialize_l`, `OLD_...`, ...) keep their
//   upstream names for diff-ability — `non_snake_case`/`non_upper_case_globals`.
// - the `unsafe fn` bodies are line-by-line transcriptions of C functions;
//   wrapping every raw-pointer op in an `unsafe {}` block would bury the
//   diff against hook.c — `unsafe_op_in_unsafe_fn`.
// - JNI wrapper / hook addresses are stored as `usize` in the C-parity
//   tables (`JNINativeMethod.fn_ptr`, PLTI registrations) —
//   `function_casts_as_integer`.

#![allow(dead_code)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unsafe_op_in_unsafe_fn)]
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
