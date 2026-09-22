//! hook.c DCL_HOOK_FUNC hooks (lines 237-380): `fork`,
//! `FileDescriptorInfo::ReopenOrDetach` (`_ZNK18FileDescriptorInfo14ReopenOrDetach`),
//! `pthread_attr_setstacksize`, `strdup`, `property_get`.
//!
//! Each hook keeps its own `OLD_*` static (the C `old_##func` file-scope
//! pointer, exported with C linkage and resolved through the PLT hooker).
//! The statics are `pub(crate)` so `hook_register::hook_functions` can hand
//! their addresses to PLTI as the backup slots — in C they live in the same
//! translation unit, here the two module slices share the crate.
//!
//! These use AtomicPtr for soundness under Rust's aliasing model. PLTI writes
//! through the raw pointer (via as_ptr()), and hooks read via load().

use std::ffi::{c_char, c_int, c_void, CStr};
use std::mem::{offset_of, transmute};
use std::sync::atomic::{AtomicPtr, Ordering};

// ---------------------------------------------------------------------------
// Logging (hook.c LOGD/LOGV/LOGW with tag "zygisk")
// ---------------------------------------------------------------------------

const TAG: &str = rz_common::LOG_TAG;

macro_rules! dlogv {
    ($($arg:tt)*) => {{ rz_common::logv!(TAG, $($arg)*); }};
}
macro_rules! dlogd {
    ($($arg:tt)*) => {{ rz_common::logd!(TAG, $($arg)*); }};
}
macro_rules! dlogw {
    ($($arg:tt)*) => {{ rz_common::logw!(TAG, $($arg)*); }};
}
macro_rules! dlogi {
    ($($arg:tt)*) => {{ rz_common::logi!(TAG, $($arg)*); }};
}

// ---------------------------------------------------------------------------
// Self-unload quiescence (audit F4)
// ---------------------------------------------------------------------------
//
// The tail-called munmap races with any other thread still executing loader
// code: unmapping libzygisk.so under such a thread arms a deferred SIGSEGV
// in it. The C accepts this; these counters only narrow the window — an
// in-process self-unmap cannot be made fully race-free (a thread can enter
// between the last check and the jump), which is why ENABLE_UNLOADER stays
// opt-in exactly as in the C.
//
// Relaxed ordering is sufficient: a stale low count can only unmap in the
// same window the C always had; a stale high count conservatively keeps the
// library mapped.

/// Threads currently inside a hooked entry point / specialize wrapper.
pub(crate) static IN_LOADER: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Set while the unloader is between its final decision and the munmap jump.
pub(crate) static UNLOADING: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Enables the in-process self-unmap (`[[clang::musttail]] return munmap(...)`
/// in hook.c, reached from the `pthread_attr_setstacksize` hook).
///
/// It is **off** because the tail call is not real yet, and a not-real one
/// kills the process: `tail_call_munmap` below jumps to `munmap` without
/// running an epilogue, so x30 still holds a return address *inside*
/// libzygisk.so. `munmap` then returns into the region it just unmapped.
/// Observed on device (system_server child, 5 restarts, then the monitor's
/// restart guard disabled injection):
///
/// ```text
/// signal 11 (SIGSEGV), code 1 (SEGV_MAPERR), fault addr 0x00000001000affb4
/// esr: Instruction Abort                      <- executing unmapped memory
/// x19 0000000100000000   <- libzygisk base    (tracer: "mapped ... at 0x100000000")
/// x20 0000000000183000   <- libzygisk size    ("size 0x183000")
/// lr  00000001000affb4   pc 00000001000affb4  <- pc == lr: `ret` to a stale LR
/// ```
///
/// C gets this right because `[[clang::musttail]]` makes the compiler emit the
/// full epilogue (restore callee-saved registers, sp, and x30 = the app's
/// return address) before branching. Rust has no `musttail`, so the hook is
/// exported as a **naked wrapper** (`pthread_attr_setstacksize`) whose only job
/// is to call the real body and then, on the unmap path, tear its own frame
/// down and branch straight into `munmap` with x30 (lr) already holding the
/// app's return address. `munmap` then returns to the app, and no instruction
/// of this library runs after the mapping is gone.
///
/// Enabled on the two ABIs this project tests on hardware (aarch64, arm and
/// their hooks below). x86/x86_64 keep the fail-closed path: the same wrapper
/// is straightforward there, but with no device to exercise it, an untested
/// self-unmap is not worth the crash risk. The cost of staying mapped is
/// stealth only — `unhook_functions()` has already restored every PLT slot, so
/// nothing branches into the mapping.
const SELF_UNMAP_ENABLED: bool = cfg!(any(target_arch = "aarch64", target_arch = "arm"));

/// Filled by the hook body, read by the naked wrapper: where the library is
/// mapped and how much of it to unmap.
///
/// `addr == null` means "keep libzygisk.so mapped" (the fail-closed default,
/// and also the answer whenever the quiescence gate declines). Per call, never
/// shared, so a second thread in the hook can never pick up another thread's
/// decision.
#[repr(C)]
pub struct UnmapPlan {
    pub addr: *mut c_void,
    pub len: usize,
}

impl UnmapPlan {
    #[inline]
    const fn keep_mapped() -> Self {
        UnmapPlan {
            addr: std::ptr::null_mut(),
            len: 0,
        }
    }
}


/// RAII marker for "this thread is executing loader code". Held across the
/// original-call forwarding in every exported hook and across the
/// nativeFork/Specialize wrappers.
pub(crate) struct LoaderGuard;

impl LoaderGuard {
    #[inline]
    pub(crate) fn new() -> Self {
        IN_LOADER.fetch_add(1, Ordering::Relaxed);
        LoaderGuard
    }
}

impl Drop for LoaderGuard {
    #[inline]
    fn drop(&mut self) {
        IN_LOADER.fetch_sub(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// DCL_HOOK_FUNC backups (hook.c `old_##func` file-scope statics)
// Uses AtomicPtr for sound access. PLTI writes via as_ptr(), hooks read via load().
// ---------------------------------------------------------------------------

/// hook.c `old_fork`.
pub(crate) static OLD_FORK: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
/// hook.c `old__ZNK18FileDescriptorInfo14ReopenOrDetach`.
pub(crate) static OLD__ZNK18FileDescriptorInfo14ReopenOrDetach: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
/// hook.c `old_pthread_attr_setstacksize`.
pub(crate) static OLD_PTHREAD_ATTR_SETSTACKSIZE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
/// hook.c `old_strdup`.
pub(crate) static OLD_STRDUP: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
/// hook.c `old_property_get`.
pub(crate) static OLD_PROPERTY_GET: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

// ---------------------------------------------------------------------------
// fork (hook.c lines 232-239)
// ---------------------------------------------------------------------------

type OldForkFn = unsafe extern "C" fn() -> c_int;

#[inline]
unsafe fn old_fork() -> c_int {
    let f: OldForkFn = unsafe { transmute(OLD_FORK.load(Ordering::Relaxed)) };
    unsafe { f() }
}

// INFO: ReZygisk already performs a fork in `fork_pre`. Because of that, we
// avoid a duplicate fork in nativeForkAndSpecialize and nativeForkSystemServer
// by caching the pid in fork_pre and only performing a real fork if the pid
// is non-0 — in other words, if we (libzygisk.so) already forked. While a
// context is live (`pid >= 0`) the cached pid is returned instead.
/// # Safety
/// The PLT hooker guarantees `OLD_FORK` holds the original `fork` before this
/// can be reached from the zygote; `ctx_ref` performs the `g_ctx` null check.
#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn fork() -> c_int {
    let _guard = LoaderGuard::new();

    if let Some(ctx) = crate::context::ctx_ref() {
        if ctx.pid >= 0 {
            return ctx.pid;
        }
    }

    let pid = unsafe { old_fork() };
    if pid == 0 {
        // Child: the parent's other threads (and their in-flight loader
        // entries) are gone, but their counter slots were inherited. Reset to
        // exactly this thread's guard or the F4 gate would keep the library
        // mapped forever in this child.
        IN_LOADER.store(1, Ordering::Relaxed);
        UNLOADING.store(false, Ordering::Relaxed);
    }
    pid
}

// ---------------------------------------------------------------------------
// _ZNK18FileDescriptorInfo14ReopenOrDetach (hook.c lines 241-290)
// ---------------------------------------------------------------------------

// INFO: file_path is a std::string in the actual class. We represent it as
// opaque bytes.
#[cfg(target_pointer_width = "64")]
const STD_STRING_SIZE: usize = 24;
#[cfg(target_pointer_width = "32")]
const STD_STRING_SIZE: usize = 12;

// hook.c `struct FileDescriptorInfo`: a layout mirror of the libnativehelper
// class with identical field order, so `offset_of!` yields the C++ object's
// member offsets exactly like the C's `offsetof`. `file_path` is really a
// std::string whose storage is read through crate::cpp_strings. `libc::stat`
// matches the bionic `struct stat` the C mirror was compiled against.
#[repr(C)]
#[allow(dead_code)] // fields are only used through offset_of!
struct FileDescriptorInfo {
    fd: c_int,
    stat: libc::stat,
    file_path_storage: [c_char; STD_STRING_SIZE],
    open_flags: c_int,
    fd_flags: c_int,
    fs_flags: c_int,
    offset: libc::off_t,
    is_sock: bool,
}

const MEMFD_BOOT_IMAGE_METHODS_ART: &CStr = c"/memfd:/boot-image-methods.art";

type OldReopenOrDetachFn = unsafe extern "C" fn(*mut c_void, *mut c_void);

#[inline]
unsafe fn old_reopen_or_detach() -> OldReopenOrDetachFn {
    unsafe { transmute(OLD__ZNK18FileDescriptorInfo14ReopenOrDetach.load(Ordering::Relaxed)) }
}

// INFO: This hook avoids that unmounted overlays made by root modules lead
// Zygote to abort its operation as it cannot open anymore.
///
/// # Safety
/// `this` must point to a live `FileDescriptorInfo` and `OLD__ZNK18...` must
/// hold the original method (guaranteed by the PLT hooker before the zygote
/// runs); the std::string invariants come from libc++.
#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn _ZNK18FileDescriptorInfo14ReopenOrDetach(
    this: *mut c_void,
    fail_fn: *mut c_void,
) {
    let _guard = LoaderGuard::new();

    let fd = unsafe {
        std::ptr::read((this as *const u8).add(offset_of!(FileDescriptorInfo, fd)) as *const c_int)
    };
    let file_path_std_string = unsafe {
        (this as *const u8).add(offset_of!(FileDescriptorInfo, file_path_storage))
    };
    let file_path = unsafe { crate::cpp_strings::read_std_string(file_path_std_string) };
    let file_path: *const c_char = file_path.map_or(std::ptr::null(), |s| s.as_ptr().cast());
    let is_sock = unsafe {
        std::ptr::read(
            (this as *const u8).add(offset_of!(FileDescriptorInfo, is_sock)) as *const bool,
        )
    };

    // C: `if (is_sock) goto bypass_fd_check;` /
    // `if (strncmp(file_path, "/memfd:/boot-image-methods.art", ...) == 0)
    //  goto bypass_fd_check;`
    if is_sock
        || unsafe {
            libc::strncmp(
                file_path,
                MEMFD_BOOT_IMAGE_METHODS_ART.as_ptr(),
                MEMFD_BOOT_IMAGE_METHODS_ART.to_bytes().len(),
            )
        } == 0
    {
        unsafe { old_reopen_or_detach()(this, fail_fn) };
        return;
    }

    if unsafe { libc::access(file_path, libc::F_OK) } == -1 {
        dlogd!(
            "Failed to open file {}, detaching it",
            unsafe { CStr::from_ptr(file_path) }.to_string_lossy()
        );

        unsafe { libc::close(fd) };

        return;
    }

    unsafe { old_reopen_or_detach()(this, fail_fn) };
}

// ---------------------------------------------------------------------------
// pthread_attr_setstacksize (hook.c lines 292-342)
// ---------------------------------------------------------------------------

type OldPthreadAttrSetStacksizeFn = unsafe extern "C" fn(*mut c_void, usize) -> c_int;

#[inline]
unsafe fn old_pthread_attr_setstacksize() -> OldPthreadAttrSetStacksizeFn {
    unsafe { transmute(OLD_PTHREAD_ATTR_SETSTACKSIZE.load(Ordering::Relaxed)) }
}


// INFO: Self-unloading is not a direct task; it requires the utilization of
// tail optimization, which requires the signature to be the same as munmap,
// or else munmap will be executed and will try to reach our code, leading to
// a segmentation fault.
//
// To counter that, we hook pthread_attr_setstacksize, which is called around
// when the VM daemon starts, to allow this to happen before the app can
// execute code.
///
/// The real body of the `pthread_attr_setstacksize` hook.
///
/// Called only by the naked wrapper below, which supplies `plan` on the stack
/// and performs the actual tail branch into `munmap` when the body asks for
/// one. Returning `addr == null` in `*plan` means "keep libzygisk.so mapped".
///
/// # Safety
/// `target`/`size` come straight from the hooked caller; `plan` must be a
/// valid, writable, per-call `UnmapPlan`; `OLD_...` is set by the PLT hooker
/// before ART runs.
pub unsafe extern "C" fn pthread_attr_setstacksize_inner(
    target: *mut c_void,
    size: usize,
    plan: *mut UnmapPlan,
) -> c_int {
    use std::sync::atomic::Ordering;

    let _guard = LoaderGuard::new();

    unsafe { *plan = UnmapPlan::keep_mapped() };

    let res = unsafe { old_pthread_attr_setstacksize()(target, size) };

    if !crate::context::ENABLE_UNLOADER.load(Ordering::Relaxed) {
        return res;
    }

    // INFO: Only perform unloading on the main thread.
    if unsafe { libc::gettid() != libc::getpid() } {
        return res;
    }

    if crate::context::SHOULD_UNMAP_ZYGISK.load(Ordering::Relaxed) {
        // Any PLT slot that failed to restore still points into
        // libzygisk.so. Munmapping now arms a deferred SIGSEGV in this app
        // on the next fork/strdup — keep the library mapped instead.
        if !crate::hook_register::unhook_functions() {
            dlogw!("PLT unhook incomplete — keeping libzygisk.so mapped");
            crate::context::SHOULD_UNMAP_ZYGISK.store(false, Ordering::Relaxed);
        }

        // C 314: csoloader_deinit() → linker_deinit().
        rz_csoloader::runtime::csoloader_deinit();

        if !crate::context::SHOULD_UNMAP_ZYGISK.load(Ordering::Relaxed) {
            dlogw!("Failed to unmap libzygisk.so, skipping munmap");

            crate::context::ENABLE_UNLOADER.store(false, Ordering::Relaxed);

            // C: free(zygisk_modules); zygisk_modules = NULL;
            crate::context::clear_zygisk_modules();

            // C: plti_deinit(&plti_ctx);
            if let Some(p) = crate::context::take_plti() {
                p.deinit();
            }

            return res;
        }

        // INFO: Modules might use libzygisk.so after postAppSpecialize. We can
        // only free it when we are really before our unmap.
        crate::context::clear_zygisk_modules();
        if let Some(p) = crate::context::take_plti() {
            p.deinit();
        }

        if SELF_UNMAP_ENABLED {
            let start_addr = crate::context::START_ADDR.load(Ordering::Relaxed);
            let block_size = crate::context::BLOCK_SIZE.load(Ordering::Relaxed);

            // F4 quiescence gate: every other thread must be outside loader
            // code (this hook holds the only legitimate in-flight entry, so
            // the count must be exactly 1 — this thread's own guard). Skipping
            // keeps the library mapped and disarms the unloader, the safe
            // direction. It narrows the window but cannot close it: a thread
            // can still enter loader code between this check and the branch —
            // the same window the C always had.
            if IN_LOADER.load(Ordering::Relaxed) != 1 {
                dlogw!(
                    "loader code in flight on another thread — keeping libzygisk.so mapped"
                );
                UNLOADING.store(false, Ordering::Relaxed);
                crate::context::ENABLE_UNLOADER.store(false, Ordering::Relaxed);
                return res;
            }

            dlogd!(
                "unmap libzygisk.so loaded at {:p} with size {}",
                start_addr as *const c_void,
                block_size,
            );

            // C: [[clang::musttail]] return munmap(start_addr, block_size);
            // The naked wrapper branches into munmap with this frame already
            // torn down, so nothing of this library runs afterwards.
            unsafe {
                (*plan).addr = start_addr as *mut c_void;
                (*plan).len = block_size;
            };

            return res;
        }

        // Fail closed (see SELF_UNMAP_ENABLED): without a real tail call the
        // jump above would return into the unmapped image. Keeping the library
        // mapped is harmless — `unhook_functions()` already put every PLT slot
        // back, so nothing branches into it any more — and it costs stealth
        // only, where a wrong unmap kills the process.
        dlogi!("self-unmap disabled — keeping libzygisk.so mapped");
        UNLOADING.store(false, Ordering::Relaxed);
        crate::context::ENABLE_UNLOADER.store(false, Ordering::Relaxed);
    }

    res
}

/// Emits the aarch64 trampoline for `$name` around the body `$inner`.
///
/// `$inner` decides whether an unmap is wanted by filling the `UnmapPlan` it
/// is handed; production passes the real body, the emulated tests (see
/// `trampoline_test`) pass a stub so the *same* instruction sequence can be
/// driven against a controlled plan under qemu-user.
///
/// Frame discipline: `x19`/`x20` are the only callee-saved registers touched,
/// and both are saved before use and restored on *both* exits. The unmap path
/// tears the frame down, so `x30` (the app's return address) and the app's
/// `x19`/`x20` are live when the tail branch enters `munmap`, which returns
/// straight to the app. Nothing of this library runs after the mapping is
/// gone — that is the whole point of the tail call.
#[cfg(target_arch = "aarch64")]
macro_rules! aarch64_trampoline {
    ($(#[$meta:meta])* $name:ident, $inner:path) => {
        $(#[$meta])*
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(
            target: *mut ::core::ffi::c_void,
            size: usize,
        ) -> ::libc::c_int {
            core::arch::naked_asm!(
                "bti c",
                "stp x29, x30, [sp, #-16]!",
                "mov x29, sp",
                "stp x19, x20, [sp, #-16]!",
                "mov x19, x0",             // target
                "mov x20, x1",             // size
                "sub sp, sp, #16",         // UnmapPlan { addr, len }
                "mov x2, sp",
                "mov x0, x19",
                "mov x1, x20",
                "bl {inner}",
                "ldr x9, [sp]",            // plan.addr: null => keep mapped
                "ldr x1, [sp, #8]",        // plan.len
                "add sp, sp, #16",
                "cbz x9, 2f",
                "ldp x19, x20, [sp], #16",
                "ldp x29, x30, [sp], #16", // x30 = the app's return address
                "mov x0, x9",
                "b {munmap}",              // tail call: returns straight to the app
                "2:",
                "ldp x19, x20, [sp], #16",
                "ldp x29, x30, [sp], #16",
                "ret",
                inner = sym $inner,
                munmap = sym libc::munmap,
            )
        }
    };
}

#[cfg(all(test, target_arch = "aarch64"))]
pub(crate) use aarch64_trampoline;

/// arm (Thumb-2) counterpart. `r4`/`r5` carry the arguments across the call;
/// `r12` (`ip`, caller-saved) carries the plan once the frame is off, because
/// `r9` — the obvious scratch — is callee-saved on the Android arm ABI (LLVM
/// saves it in every prologue that touches it), and clobbering it would corrupt
/// the app's register state on the keep-mapped path.
#[cfg(target_arch = "arm")]
macro_rules! arm_trampoline {
    ($(#[$meta:meta])* $name:ident, $inner:path) => {
        $(#[$meta])*
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name(
            target: *mut ::core::ffi::c_void,
            size: usize,
        ) -> ::libc::c_int {
            core::arch::naked_asm!(
                "push {{r4, r5, r6, lr}}", // 16-byte frame record
                "mov r4, r0",              // target
                "mov r5, r1",              // size
                "sub sp, #16",             // UnmapPlan { addr, len } + 8B pad, so
                                           // the call below is 16-byte aligned
                "mov r2, sp",
                "mov r0, r4",
                "mov r1, r5",
                "bl {inner}",
                "ldr r12, [sp]",           // plan.addr: null => keep mapped
                "ldr r1, [sp, #4]",        // plan.len
                "add sp, #16",
                "cmp r12, #0",
                "beq 2f",
                "pop {{r4, r5, r6, lr}}",
                "mov r0, r12",
                "b {munmap}",              // tail call: returns straight to the app
                "2:",
                "pop {{r4, r5, r6, lr}}",
                "bx lr",
                inner = sym $inner,
                munmap = sym libc::munmap,
            )
        }
    };
}

#[cfg(all(test, target_arch = "arm"))]
pub(crate) use arm_trampoline;

// The exported hook. On the ABIs with a verified wrapper this is naked code
// that owns the frame discipline described above `SELF_UNMAP_ENABLED`; `x29`
// (arm64) / frame-pointer-less (arm) is a plain record, and the unmap path
// restores `sp`/`x30` (arm: `sp`/`lr`) before branching into `munmap` so that
// nothing of this library runs after the mapping is gone. `bti c` makes the
// entry a valid indirect-branch target where BTI is enforced (a HINT
// elsewhere).
#[cfg(target_arch = "aarch64")]
aarch64_trampoline!(
    #[cfg_attr(target_os = "android", unsafe(no_mangle))]
    pthread_attr_setstacksize,
    pthread_attr_setstacksize_inner
);

#[cfg(target_arch = "arm")]
arm_trampoline!(
    #[cfg_attr(target_os = "android", unsafe(no_mangle))]
    pthread_attr_setstacksize,
    pthread_attr_setstacksize_inner
);

/// x86/x86_64 keep the plain export: `SELF_UNMAP_ENABLED` is false there, so
/// the plan is never filled and the body logs the fail-closed path.
#[cfg(not(any(target_arch = "aarch64", target_arch = "arm")))]
#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn pthread_attr_setstacksize(target: *mut c_void, size: usize) -> c_int {
    let mut plan = UnmapPlan::keep_mapped();

    unsafe { pthread_attr_setstacksize_inner(target, size, &mut plan) }
}

// ---------------------------------------------------------------------------
// strdup (hook.c lines 345-353)
// ---------------------------------------------------------------------------

type OldStrdupFn = unsafe extern "C" fn(*const c_char) -> *mut c_char;

#[inline]
unsafe fn old_strdup() -> OldStrdupFn {
    unsafe { transmute(OLD_STRDUP.load(Ordering::Relaxed)) }
}

/// # Safety
/// `str` must be a valid NUL-terminated string (like the C `strcmp` call);
/// `OLD_STRDUP` is set by the PLT hooker before the zygote runs.
#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn strdup(str: *const c_char) -> *mut c_char {
    let _guard = LoaderGuard::new();

    if unsafe { libc::strcmp(str, c"com.android.internal.os.ZygoteInit".as_ptr()) } == 0 {
        dlogv!("strdup {}", unsafe { CStr::from_ptr(str) }.to_string_lossy());

        crate::jni_hooks::initialize_jni_hook();
    }

    unsafe { old_strdup()(str) }
}

// ---------------------------------------------------------------------------
// property_get (hook.c lines 355-373)
// ---------------------------------------------------------------------------

type OldPropertyGetFn =
    unsafe extern "C" fn(*const c_char, *mut c_char, *const c_char) -> c_int;

#[inline]
unsafe fn old_property_get() -> OldPropertyGetFn {
    unsafe { transmute(OLD_PROPERTY_GET.load(Ordering::Relaxed)) }
}

// INFO: Our goal is to get called after libart.so is loaded, but before ART
// actually starts running. If we are too early, we won't find libart.so in
// maps, and if we are too late, we could make other threads crash if they try
// to use the PLT while we are in the process of hooking it. For this task,
// hooking property_get was chosen as there are lots of calls to this, so it's
// relatively unlikely to break.
//
// After we succeed in getting called at a point where libart.so is already
// loaded, we will ignore the rest of the property_get calls.
///
/// # Safety
/// Arguments mirror the libc `property_get` contract; `OLD_PROPERTY_GET` is
/// set by the PLT hooker before the zygote runs.
#[cfg_attr(target_os = "android", unsafe(no_mangle))]
pub unsafe extern "C" fn property_get(
    key: *const c_char,
    value: *mut c_char,
    default_value: *const c_char,
) -> c_int {
    let _guard = LoaderGuard::new();

    crate::hook_register::hook_unloader();

    unsafe { old_property_get()(key, value, default_value) }
}

