//! Emulated tests for the `pthread_attr_setstacksize` trampoline.
//!
//! The trampoline is *naked* code: what runs on the device is exactly the
//! instruction sequence written in `fork_hooks.rs`, so the interesting
//! question is not what the compiler made of it (nothing) but how it behaves
//! at run time — in particular that the tail-branch into `munmap` returns to
//! the *app's* caller, with the app's callee-saved registers and stack intact,
//! and that no instruction of this library is fetched after the mapping dies.
//!
//! These tests instantiate the *same* `macro_rules!` that builds the shipped
//! hook (so the instruction sequence cannot drift) around a **stub body** that
//! fills the `UnmapPlan` with a mapping the test owns. That lets the unmap path
//! run to completion without a zygote: the hook unmaps the test's mapping
//! instead of its own image.
//!
//! They only run off-device, under qemu-user:
//!
//! ```text
//! CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER="qemu-aarch64 -L /usr/aarch64-linux-gnu" \
//!     cargo test -p rz-loader --target aarch64-unknown-linux-gnu -- --test-threads=1
//! CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_RUNNER="qemu-arm -L /usr/arm-linux-gnueabihf" \
//!     cargo test -p rz-loader --target armv7-unknown-linux-gnueabihf -- --test-threads=1
//! ```
//!
//! The cross linkers come from `.cargo/config.toml` (`aarch64-linux-gnu-gcc` /
//! `arm-linux-gnueabihf-gcc`); without them the link fails before a test runs.
//!
//! `--test-threads=1` matters: the unmap path is gated on nothing here, but the
//! assertions below assume no other test is holding loader code.

#![cfg(all(
    test,
    not(target_os = "android"),
    any(target_arch = "aarch64", target_arch = "arm")
))]

use core::ffi::c_void;
use std::io::Error as IoError;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::fork_hooks::UnmapPlan;

/// What the stub body reports when the caller keeps the library mapped.
const KEEP_MAPPED_SENTINEL: i32 = 0x5A5A;

/// Mapping the stub body asks the trampoline to unmap; `0` means "keep mapped".
static PLAN_ADDR: AtomicUsize = AtomicUsize::new(0);
static PLAN_LEN: AtomicUsize = AtomicUsize::new(0);

/// Stub replacement for `pthread_attr_setstacksize_inner`: same ABI (including
/// the `plan` out-parameter), no device state.
unsafe extern "C" fn stub_inner(_target: *mut c_void, _size: usize, plan: *mut UnmapPlan) -> i32 {
    let addr = PLAN_ADDR.load(Ordering::Relaxed);
    let len = PLAN_LEN.load(Ordering::Relaxed);

    unsafe {
        (*plan).addr = addr as *mut c_void;
        (*plan).len = len;
    }

    KEEP_MAPPED_SENTINEL
}

#[cfg(target_arch = "aarch64")]
crate::fork_hooks::aarch64_trampoline!(test_trampoline, stub_inner);

#[cfg(target_arch = "arm")]
crate::fork_hooks::arm_trampoline!(test_trampoline, stub_inner);

/// The trampoline as a value, so calls go through a register (`blr`/`blx`)
/// like the hooked ART code does, and can never be inlined.
fn trampoline() -> unsafe extern "C" fn(*mut c_void, usize) -> i32 {
    test_trampoline
}

/// One writable, private, anonymous mapping of two pages, touched so the
/// kernel has actually populated it.
unsafe fn map_two_pages() -> *mut c_void {
    let len = 2 * 4096;
    let addr = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };

    assert_ne!(addr, libc::MAP_FAILED, "mmap failed: {}", IoError::last_os_error());

    unsafe { core::ptr::write_volatile(addr.cast::<u8>(), 0xA5) };
    unsafe { core::ptr::write_volatile((addr.cast::<u8>()).add(len - 1), 0x5A) };

    addr
}

/// Is the whole range still resident? `mincore` fails with `ENOMEM` as soon as
/// any page of the range is unmapped.
fn is_mapped(addr: *mut c_void, len: usize) -> bool {
    let pages = len.div_ceil(4096);
    let mut vec = vec![0u8; pages];
    let ret = unsafe { libc::mincore(addr, len, vec.as_mut_ptr().cast()) };

    if ret == 0 {
        return true;
    }

    let err = IoError::last_os_error();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::ENOMEM),
        "mincore({:p}) failed unexpectedly: {err}",
        addr
    );

    false
}

/// The unmap path: the trampoline must unmap what the body asked for, return
/// `munmap`'s result (not the body's), and hand control back to us — nothing of
/// the trampoline's own frame is left behind.
#[test]
fn unmap_path_returns_munmap_result_and_keeps_running() {
    let region = unsafe { map_two_pages() };
    let len = 2 * 4096;
    assert!(is_mapped(region, len), "region should start mapped");

    PLAN_ADDR.store(region as usize, Ordering::Relaxed);
    PLAN_LEN.store(len, Ordering::Relaxed);

    let ret = unsafe { trampoline()(core::ptr::null_mut(), 4096) };

    // munmap(2) returns 0 on success; the stub body's sentinel must NOT be what
    // the app sees — that would mean the body's `ret` was used instead of the
    // tail branch.
    assert_eq!(ret, 0, "expected munmap's result, got the body's: {ret:#x}");
    assert!(!is_mapped(region, len), "region should be unmapped now");

    // Proving we are still executing: allocating and writing through the heap
    // would fault immediately if we had returned into the dead mapping.
    let probe = vec![0x5Au8; 64 * 1024];
    assert_eq!(probe[0], 0x5A);
    assert_eq!(probe[probe.len() - 1], 0x5A);
    println!("continued after unmap; heap allocation intact");
}

/// The keep-mapped path (what the hook does on any failure gate): the body's
/// result is passed through untouched and the mapping survives.
#[test]
fn keep_mapped_path_passes_body_result_through() {
    let region = unsafe { map_two_pages() };
    let len = 2 * 4096;

    PLAN_ADDR.store(0, Ordering::Relaxed);
    PLAN_LEN.store(0, Ordering::Relaxed);

    let ret = unsafe { trampoline()(core::ptr::null_mut(), 4096) };

    assert_eq!(
        ret, KEEP_MAPPED_SENTINEL,
        "keep-mapped path must return the body's result"
    );
    assert!(is_mapped(region, len), "region must stay mapped");

    unsafe { libc::munmap(region, len) };
}

// ---------------------------------------------------------------------------
// Callee-saved register discipline
// ---------------------------------------------------------------------------

/// Calls the trampoline with every callee-saved register loaded with a magic
/// value and writes what came back into `out` (7 entries).
///
/// This has to be naked: a compiler-generated caller is free to keep nothing in
/// those registers, so only hand-written code can pin the contract. The tramp
/// uses `x19`/`x20` (arm64) / `r4`-`r6` (arm) as scratch, so this is what proves
/// it saves and restores them on the unmap path — where `munmap` returns to the
/// *app* with those registers already restored.
///
/// aarch64: checks `x19`-`x24`, `x29`.
#[cfg(target_arch = "aarch64")]
#[unsafe(naked)]
unsafe extern "C" fn call_with_magic_registers(
    f: *const c_void,
    target: *mut c_void,
    size: usize,
    out: *mut usize,
) -> i32 {
    core::arch::naked_asm!(
        "bti c",
        // Save the caller's frame record *and* every callee-saved register this
        // helper repurposes: the values are pinned for the call, but the caller
        // still needs its originals back.
        "stp x29, x30, [sp, #-16]!",
        "stp x19, x20, [sp, #-16]!",
        "stp x21, x22, [sp, #-16]!",
        "stp x23, x24, [sp, #-16]!",
        "sub sp, sp, #16",
        "str x3, [sp]",                // out, kept across the call
        "mov x19, #0x1111",
        "mov x20, #0x2222",
        "mov x21, #0x3333",
        "mov x22, #0x4444",
        "mov x23, #0x5555",
        "mov x24, #0x6666",
        "mov x29, #0x7777",
        "mov x9, x0",                  // f
        "mov x0, x1",                  // target
        "mov x1, x2",                  // size
        "blr x9",
        "ldr x10, [sp]",               // out
        "str x19, [x10]",
        "str x20, [x10, #8]",
        "str x21, [x10, #16]",
        "str x22, [x10, #24]",
        "str x23, [x10, #32]",
        "str x24, [x10, #40]",
        "str x29, [x10, #48]",
        "add sp, sp, #16",
        "ldp x23, x24, [sp], #16",
        "ldp x21, x22, [sp], #16",
        "ldp x19, x20, [sp], #16",
        "ldp x29, x30, [sp], #16",
        "ret",
    )
}

/// arm counterpart: checks `r4`-`r10`. `r9` is in the set on purpose — it is
/// callee-saved on the Android arm ABI (LLVM pushes it in every prologue that
/// touches it), and an earlier revision of the tramp used it as scratch.
#[cfg(target_arch = "arm")]
#[unsafe(naked)]
unsafe extern "C" fn call_with_magic_registers(
    f: *const c_void,
    target: *mut c_void,
    size: usize,
    out: *mut usize,
) -> i32 {
    core::arch::naked_asm!(
        "push {{r4, r5, r6, r7, r8, r9, r10, lr}}",
        "sub sp, #16",                 // keeps the call 16-byte aligned
        "str r3, [sp]",                // out, kept across the call
        "mov r4, #0x41",
        "mov r5, #0x52",
        "mov r6, #0x63",
        "mov r7, #0x74",
        "mov r8, #0x85",
        "mov r9, #0x96",
        "mov r10, #0xa7",
        "mov r12, r0",                 // f (r12 is caller-saved scratch)
        "mov r0, r1",                  // target
        "mov r1, r2",                  // size
        "blx r12",
        "ldr r3, [sp]",                // out
        "str r4, [r3]",
        "str r5, [r3, #4]",
        "str r6, [r3, #8]",
        "str r7, [r3, #12]",
        "str r8, [r3, #16]",
        "str r9, [r3, #20]",
        "str r10, [r3, #24]",
        "add sp, #16",
        "pop {{r4, r5, r6, r7, r8, r9, r10, lr}}",
        "bx lr",
    )
}

/// The magic values `call_with_magic_registers` loads, in the order it stores
/// them.
#[cfg(target_arch = "aarch64")]
const MAGICS: [usize; 7] = [
    0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777,
];

#[cfg(target_arch = "arm")]
const MAGICS: [usize; 7] = [0x41, 0x52, 0x63, 0x74, 0x85, 0x96, 0xa7];

#[test]
fn unmap_path_preserves_callee_saved_registers() {
    let region = unsafe { map_two_pages() };
    let len = 2 * 4096;

    PLAN_ADDR.store(region as usize, Ordering::Relaxed);
    PLAN_LEN.store(len, Ordering::Relaxed);

    let mut out = [0usize; 7];
    let ret = unsafe {
        call_with_magic_registers(
            trampoline() as *const c_void,
            core::ptr::null_mut(),
            4096,
            out.as_mut_ptr(),
        )
    };

    assert_eq!(ret, 0, "expected munmap's result from the unmap path");
    assert!(!is_mapped(region, len), "region should be unmapped");
    assert_eq!(
        out,
        MAGICS,
        "trampoline clobbered callee-saved registers: {:#x?}",
        out
    );
}

#[test]
fn keep_mapped_path_preserves_callee_saved_registers() {
    let region = unsafe { map_two_pages() };
    let len = 2 * 4096;

    PLAN_ADDR.store(0, Ordering::Relaxed);
    PLAN_LEN.store(0, Ordering::Relaxed);

    let mut out = [0usize; 7];
    let ret = unsafe {
        call_with_magic_registers(
            trampoline() as *const c_void,
            core::ptr::null_mut(),
            4096,
            out.as_mut_ptr(),
        )
    };

    assert_eq!(ret, KEEP_MAPPED_SENTINEL);
    assert!(is_mapped(region, len), "region must stay mapped");
    assert_eq!(
        out,
        MAGICS,
        "trampoline clobbered callee-saved registers: {:#x?}",
        out
    );

    unsafe { libc::munmap(region, len) };
}
