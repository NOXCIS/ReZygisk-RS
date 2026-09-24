//! Zygote-side global state: flags, [`ZygiskContext`], hook lists, and the
//! `is_zygote_child` helper.
//!
//! Shared spine: every module in this crate uses these globals/types instead
//! of redefining them. Rust-idiomatic notes:
//! - Primitive globals use atomics (`AtomicUsize`, `AtomicBool`, `AtomicPtr`)
//!   instead of `static mut` to be sound under Rust's aliasing model.
//! - Container globals use `Mutex<Option<T>>` to allow take() semantics while
//!   remaining sound.
//! - Module `exclude`/`include` patterns are `regex::Regex`. The regex
//!   crate's syntax covers every pattern module authors use in practice
//!   (BRE vs Rust-regex differ only on constructs nobody ships: backrefs).

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use crate::abi::JNINativeMethod;
use regex::Regex;
use rz_plti::Plti;

use crate::abi::{AppSpecializeArgsV5, ServerSpecializeArgsV1};

// hook.c globals `start_addr` / `block_size` (set by entry(), read by the
// hook teardown path). Relaxed ordering is sufficient — single-threaded access.
pub static START_ADDR: AtomicUsize = AtomicUsize::new(0);
pub static BLOCK_SIZE: AtomicUsize = AtomicUsize::new(0);

// hook.c `should_unmap_zygisk` / `enable_unloader`.
pub static SHOULD_UNMAP_ZYGISK: AtomicBool = AtomicBool::new(false);
pub static ENABLE_UNLOADER: AtomicBool = AtomicBool::new(false);

/// Module-table self-heal: the first ReadModules can legitimately report an
/// empty table when the daemon is still re-reading its module dir
/// (mid-respawn). `MODULE_TABLE_EMPTY` flags that state; the fork hook
/// retries the read on subsequent forks, bounded by
/// `MODULE_TABLE_MAX_RETRIES` so a genuinely module-less boot does not
/// turn every fork into an IPC round-trip forever.
pub static MODULE_TABLE_EMPTY: AtomicBool = AtomicBool::new(false);
pub static MODULE_TABLE_RETRIES: AtomicU32 = AtomicU32::new(0);
pub const MODULE_TABLE_MAX_RETRIES: u32 = 3;

// ---------------------------------------------------------------------------
// Flag indices (hook.c `enum { POST_SPECIALIZE, ... }`). `FLAG_SET/GET` shift
// by the index — these are INDICES, not bits.
// ---------------------------------------------------------------------------
pub const POST_SPECIALIZE: u32 = 0;
pub const APP_FORK_AND_SPECIALIZE: u32 = 1;
pub const APP_SPECIALIZE: u32 = 2;
pub const SERVER_FORK_AND_SPECIALIZE: u32 = 3;
pub const DO_REVERT_UNMOUNT: u32 = 4;
pub const SKIP_FD_SANITIZATION: u32 = 5;
pub const FLAG_MAX: u32 = 6;

#[inline]
pub fn flag_set(ctx: &mut ZygiskContext, flag: u32) {
    ctx.flags |= 1u32 << flag;
}

#[inline]
pub fn flag_get(ctx: &ZygiskContext, flag: u32) -> bool {
    (ctx.flags & (1u32 << flag)) != 0
}

// hook.c limits.
pub const MAX_FD_SIZE: usize = 1024;
pub const MAX_REGISTER_INFO: usize = 64;
pub const MAX_IGNORE_INFO: usize = 64;
pub const MAX_EXEMPTED_FDS: usize = 128;

/// hook.c `struct register_info` (PLT hook registration from modules).
pub struct RegisterInfo {
    pub regex: Regex,
    pub symbol: String,
    pub callback: *mut c_void,
    pub backup: *mut *mut c_void,
}

/// hook.c `struct ignore_info` (PLT hook exclusion).
pub struct IgnoreInfo {
    pub regex: Regex,
    pub symbol: Option<String>,
}

/// hook.c `struct plt_hook_entry`: the module v4 queue only — the loader's
/// own hooks register directly (as the C's `PLT_HOOK_REGISTER` does) and
/// never enter this list.
pub struct PltHookEntry {
    pub lib_path: String,
    pub symbol: String,
    pub new_func: *mut c_void,
    pub backup: *mut *mut c_void,
}

// SAFETY: PltHookEntry is only accessed while the Mutex is held, and the
// raw pointers are module-provided callback addresses that remain valid
// for the duration of the hook's lifetime.
unsafe impl Send for PltHookEntry {}
unsafe impl Sync for PltHookEntry {}

/// hook.c `struct jni_hook_entry` (loader's own JNI method hooks).
pub struct JniHookEntry {
    pub class_name: String,
    pub methods: Vec<JNINativeMethod>,
}

// SAFETY: JniHookEntry is only accessed while the Mutex is held. The
// JNINativeMethod raw pointers are static strings and function pointers
// that remain valid for the program's lifetime.
unsafe impl Send for JniHookEntry {}
unsafe impl Sync for JniHookEntry {}

/// hook.c `struct zygisk_context`: the state handed through the specialize
/// pipeline. The `args` union mirrors the C (the zygote casts one pointer).
#[repr(C)]
pub union ZygiskArgs {
    pub ptr: *mut c_void,
    pub app: *mut AppSpecializeArgsV5,
    pub server: *mut ServerSpecializeArgsV1,
}

pub struct ZygiskContext {
    pub env: *mut jni::sys::JNIEnv,
    pub args: ZygiskArgs,
    pub process: String,
    pub pid: i32,
    pub flags: u32,
    pub info_flags: u32,
    pub allowed_fds: [u8; MAX_FD_SIZE],
    pub exempted_fds: [i32; MAX_EXEMPTED_FDS],
    pub exempted_fds_count: usize,
    pub hook_info_lock: libc::pthread_mutex_t,
    pub register_info: Vec<RegisterInfo>,
    pub ignore_info: Vec<IgnoreInfo>,
}

/// hook.c `g_ctx` — the current context. Null outside a specialize pass.
/// Uses AtomicPtr for sound access without `static mut`.
pub static G_CTX: AtomicPtr<ZygiskContext> = AtomicPtr::new(std::ptr::null_mut());

pub fn set_ctx(ctx: *mut ZygiskContext) {
    G_CTX.store(ctx, Ordering::Release);
}

/// Borrow the current context (hook.c `if (g_ctx) ...` guard).
/// # Safety
/// Caller must ensure no mutable aliases exist. In practice, the zygote
/// is single-threaded during hook execution, so this is safe.
pub fn ctx_ref() -> Option<&'static ZygiskContext> {
    let ptr = G_CTX.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &*ptr })
    }
}

pub fn ctx_mut() -> Option<&'static mut ZygiskContext> {
    let ptr = G_CTX.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { &mut *ptr })
    }
}

/// hook.c `is_zygote_child`: pid <= 0 means we are still the (pre-fork)
/// zygote process; the hook implementations branch on this.
#[inline]
pub fn is_zygote_child(ctx: &ZygiskContext) -> bool {
    ctx.pid <= 0
}

// ---------------------------------------------------------------------------
// hook.c file-scope globals. Use Mutex<Option<T>> to allow take() semantics
// while remaining sound under Rust's aliasing model. The zygote is single-
// threaded during hook execution, so contention is not a concern.
// ---------------------------------------------------------------------------

/// hook.c `struct plti plti_ctx`.
static PLTI: Mutex<Option<Plti>> = Mutex::new(None);

/// hook.c `plt_hook_list` (module-queued v4 hooks, drained by
/// api_plt_hook_commit_v4).
static PLT_HOOK_LIST: Mutex<Option<Vec<PltHookEntry>>> = Mutex::new(None);

/// hook.c `jni_hook_list`.
static JNI_HOOK_LIST: Mutex<Option<Vec<JniHookEntry>>> = Mutex::new(None);

/// hook.c `zygisk_modules` / `zygisk_module_length`: the loaded module table.
///
/// Access discipline (this replaces both the C's plain unlocked global and
/// the removed TLS-flag reentrancy bypass):
/// - The lock guards only the table's own memory (header + element slots).
///   It is taken briefly, for accesses the loader performs itself, and is
///   NEVER held across a module callback. Module entries call back into the
///   loader by contract (`register_module` from `zygisk_module_entry`,
///   `set_option`/`connect_companion`/... from the specialize hooks), and
///   every one of those re-enters these accessors — a non-reentrant std
///   Mutex held across a callback self-deadlocks the fork on a futex.
/// - The removed bypass "fixed" that deadlock by aliasing the table: the
///   outer loop's `&mut Vec` (and its `&mut` element) stayed live while the
///   callback took a second `&mut` to the same slot. Under
///   opt-level="z" + lto=true + codegen-units=1 LLVM may assume those
///   references do not alias and miscompile; that is why reentrancy must be
///   impossible to hit, not bypassed.
/// - `module_snapshot()` copies (base, len) out under the lock and drops the
///   guard; the caller iterates through RAW POINTERS so no reference to the
///   table or to any element is alive while module code runs.
/// - `with_module()` borrows one element for a loader-side field write only
///   (register / set-option / cleanup-style accesses that run no module code).
/// - Single-threaded during hook execution (the C relies on the same
///   property; a forked child is single-threaded by definition), so the
///   brief locks never contend in practice.
///
/// The `UnsafeCell` stays: the mutex-guarded aliasing discipline above is
/// sound and covered by the loader test suite, so this is not a bug to
/// rewrite. A future alternative, if the accessors ever grow a hot path or
/// the lock ordering gets harder to audit, is an epoch-style table (publish
/// a generation, retire the old table when no reader holds it) — noted as a
/// possible design, not pending work.
struct ModuleTable {
    lock: Mutex<()>,
    data: std::cell::UnsafeCell<Option<Vec<crate::abi::ReZygiskModule>>>,
}
unsafe impl Sync for ModuleTable {}
static ZYGISK_MODULES: ModuleTable = ModuleTable {
    lock: Mutex::new(()),
    data: std::cell::UnsafeCell::new(None),
};

/// Poison recovery: these mutexes live in the zygote, where a panic while
/// holding one must not abort every later fork. The guarded data is
/// self-healing (Option/Vec accessors), so continuing past a poison is safe.
fn lock_ok<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Access the PLT interceptor, initializing on first use.
pub fn with_plti<F, R>(f: F) -> R
where
    F: FnOnce(&mut Plti) -> R,
{
    let mut guard = lock_ok(&PLTI);
    let plti = guard.get_or_insert_with(Plti::new);
    f(plti)
}

/// Take the PLT interceptor for cleanup.
pub fn take_plti() -> Option<Plti> {
    lock_ok(&PLTI).take()
}

/// Access the PLT hook list, initializing on first use.
pub fn with_plt_hook_list<F, R>(f: F) -> R
where
    F: FnOnce(&mut Vec<PltHookEntry>) -> R,
{
    let mut guard = lock_ok(&PLT_HOOK_LIST);
    let list = guard.get_or_insert_with(Vec::new);
    f(list)
}

/// Take the PLT hook list for commit (leaves None behind).
pub fn take_plt_hook_list() -> Option<Vec<PltHookEntry>> {
    lock_ok(&PLT_HOOK_LIST).take()
}

/// Access the JNI hook list, initializing on first use.
pub fn with_jni_hook_list<F, R>(f: F) -> R
where
    F: FnOnce(&mut Vec<JniHookEntry>) -> R,
{
    let mut guard = lock_ok(&JNI_HOOK_LIST);
    let list = guard.get_or_insert_with(Vec::new);
    f(list)
}

/// Base pointer + element count of the module table, copied out under the
/// lock. The guard is released before returning: module callbacks are invoked
/// through `base` afterwards, and every one of them must be able to take the
/// lock again (`register_module`, `set_option`, ...). The snapshot is valid
/// for the lifetime of the table — elements are only pushed during
/// `load_modules_only` and the whole table is dropped by
/// `clear_zygisk_modules`, neither of which runs concurrently with a
/// callback pass.
#[derive(Copy, Clone)]
pub struct ModuleSnapshot {
    pub base: *mut crate::abi::ReZygiskModule,
    pub len: usize,
}

impl ModuleSnapshot {
    /// Returns a reference to the module at index `i`, or `None` if out of bounds.
    ///
    /// # Safety
    /// The snapshot must be valid (base points to allocated memory, len is accurate).
    /// This is guaranteed by `module_snapshot()`.
    #[inline]
    pub fn get(&self, i: usize) -> Option<&crate::abi::ReZygiskModule> {
        if i >= self.len || self.base.is_null() {
            return None;
        }
        // SAFETY: bounds checked above, base is valid per snapshot discipline
        Some(unsafe { &*self.base.add(i) })
    }

    /// Returns a mutable reference to the module at index `i`, or `None` if out of bounds.
    ///
    /// # Safety
    /// The snapshot must be valid (base points to allocated memory, len is accurate).
    /// This is guaranteed by `module_snapshot()`.
    #[inline]
    pub fn get_mut(&mut self, i: usize) -> Option<&mut crate::abi::ReZygiskModule> {
        if i >= self.len || self.base.is_null() {
            return None;
        }
        // SAFETY: bounds checked above, base is valid per snapshot discipline
        Some(unsafe { &mut *self.base.add(i) })
    }

    /// Returns an iterator over references to all modules in the snapshot.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &crate::abi::ReZygiskModule> {
        (0..self.len).filter_map(|i| self.get(i))
    }

    /// Returns an iterator over mutable references to all modules in the snapshot.
    ///
    /// Note: This creates multiple mutable references, but they point to different
    /// elements so there's no aliasing. Use with care.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut crate::abi::ReZygiskModule> {
        let base = self.base;
        let len = self.len;
        (0..len).filter_map(move |i| {
            if base.is_null() {
                return None;
            }
            // SAFETY: bounds checked, base is valid, each index yields a distinct element
            Some(unsafe { &mut *base.add(i) })
        })
    }

    /// Returns `true` if the snapshot is empty or invalid.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0 || self.base.is_null()
    }
}

pub fn module_snapshot() -> ModuleSnapshot {
    let _guard = lock_ok(&ZYGISK_MODULES.lock);
    // SAFETY: the guard gives exclusive access to the table; the reference
    // ends before this function returns.
    match unsafe { &mut *ZYGISK_MODULES.data.get() } {
        Some(modules) => ModuleSnapshot { base: modules.as_mut_ptr(), len: modules.len() },
        None => ModuleSnapshot { base: std::ptr::null_mut(), len: 0 },
    }
}

/// Borrow module `idx` for a loader-side field access that runs no module
/// code (`rezygisk_module_register`, `api_set_option`, cleanup zeroing).
/// Returns None when `idx` is out of range — the C indexes blindly because
/// the loader itself minted the id; the bounds check is free hardening.
pub fn with_module<R>(
    idx: usize,
    f: impl FnOnce(&mut crate::abi::ReZygiskModule) -> R,
) -> Option<R> {
    let _guard = lock_ok(&ZYGISK_MODULES.lock);
    // SAFETY: the guard gives exclusive access to the table.
    let data = unsafe { &mut *ZYGISK_MODULES.data.get() };
    let modules = data.as_mut()?;
    modules.get_mut(idx).map(f)
}

/// Mutate the table itself (try_reserve / push while loading modules).
/// Only called from `load_modules_only`, before any module can run — no
/// module callback may execute inside `f`.
pub fn with_module_table<R>(f: impl FnOnce(&mut Vec<crate::abi::ReZygiskModule>) -> R) -> R {
    let _guard = lock_ok(&ZYGISK_MODULES.lock);
    // SAFETY: the guard gives exclusive access to the table.
    let data = unsafe { &mut *ZYGISK_MODULES.data.get() };
    f(data.get_or_insert_with(Vec::new))
}

/// Clear the module list (for cleanup).
pub fn clear_zygisk_modules() {
    let _guard = lock_ok(&ZYGISK_MODULES.lock);
    unsafe { *ZYGISK_MODULES.data.get() = None };
}

/// hook.c `zygisk_module_length`.
#[inline]
pub fn zygisk_module_length() -> usize {
    module_snapshot().len
}

#[cfg(test)]
mod module_table_tests {
    use super::*;

    /// Audit F1 regression test, mirrors the truman_ref re-entry shape: a
    /// "module callback" is a raw-pointer iteration over a snapshot (exactly
    /// like rz_run_modules_pre/post) that calls back into the loader from
    /// inside the pass — `register_module` lands in `with_module`, and the
    /// DlcloseModuleLibrary option lands there too. With the removed TLS
    /// bypass this test deadlocks (lock held across the callback) and with
    /// the old `&mut Vec` iteration it aliased; under the snapshot design it
    /// must pass with every write visible through the raw slots.
    #[test]
    fn snapshot_callback_reentry_is_deadlock_and_alias_free() {
        clear_zygisk_modules();

        // Load-time mutation (load_modules_only shape).
        with_module_table(|modules| {
            modules.push(crate::abi::ReZygiskModule::default());
            modules.push(crate::abi::ReZygiskModule::default());
        });

        // The accessor sees the pushes through its own short lock.
        assert_eq!(zygisk_module_length(), 2);

        // Snapshot like rz_run_modules_pre, then simulate each module's
        // on_load calling api->register_module + set_option: full
        // lock/unlock cycles *inside* the snapshot pass.
        let snap = module_snapshot();
        assert_eq!(snap.len, 2);
        assert!(!snap.base.is_null());

        for i in 0..snap.len {
            let m = unsafe { snap.base.add(i) };

            // Re-entrant register (rezygisk_module_register shape).
            let wrote = with_module(i, |slot| {
                slot.abi.api_version = crate::abi::REZYGISK_API_VERSION;
                slot.api.impl_ = std::ptr::null_mut();
            });
            assert!(wrote.is_some(), "with_module({i}) must be in range");

            // Re-entrant set_option(DlcloseModuleLibrary) shape.
            assert!(with_module(i, |slot| slot.unload = true).is_some());

            // Both writes must be observable through the raw snapshot slot —
            // with_module mutated the same memory, not a copy (the aliasing
            // regression would make this read stale zero/false).
            let version = unsafe { std::ptr::addr_of!((*m).abi.api_version).read() };
            assert_eq!(version, crate::abi::REZYGISK_API_VERSION);
            let unload = unsafe { std::ptr::addr_of!((*m).unload).read() };
            assert!(unload);
        }

        // Out-of-range ids must be rejected, not panic (module_api logs).
        assert!(with_module(2, |_| ()).is_none());

        // Cleanup shape (rz_cleanup): zero over the snapshot.
        let snap = module_snapshot();
        for i in 0..snap.len {
            unsafe { *snap.base.add(i) = crate::abi::ReZygiskModule::default() };
        }
        assert_eq!(zygisk_module_length(), 2);

        clear_zygisk_modules();
        assert_eq!(zygisk_module_length(), 0);
        assert!(module_snapshot().base.is_null());
    }
}
