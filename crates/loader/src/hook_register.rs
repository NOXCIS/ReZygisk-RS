//! hook.c hook installation/teardown: `hook_register`, `hook_unregister`,
//! `hook_functions`, `hook_unloader`, `unhook_functions` (hook.c 1291-1362).
//!
//! Sibling contract (fork_hooks): the hook bodies and the `OLD_*` backup
//! statics live in fork_hooks (the C's `new_*`/`old_*` file statics), and
//! registration goes straight to PLTI through [`hook_register`] — the exact
//! expansion of the C's `PLT_HOOK_REGISTER` macros. The loader's own hooks
//! never touch `context::PLT_HOOK_LIST`, which stays the module-only v4
//! queue (hook.c 128-129 semantics).
//!
//! Deviations vs the C, by design:
//! - JNI native-method hooking happens only in `do_hook_zygote` (triggered
//!   by the strdup hook via `initialize_jni_hook`); that path owns the
//!   `_orig` backups and the unhook list.
//! - The `[[clang::musttail]] return munmap(...)` self-unload is re-emitted
//!   as a per-arch asm tail jump (`fork_hooks::tail_call_munmap`), called
//!   directly from the pthread_attr_setstacksize hook body together with the
//!   rest of the hook.c 313-338 teardown.

use std::ffi::c_void;

use crate::context;

/// hook.c LOG_TAG; the RS port uses "zygisk" everywhere (see entry.rs).
const TAG: &str = rz_common::LOG_TAG;

macro_rules! dlogd {
    ($($arg:tt)*) => {{ rz_common::logd!(crate::hook_register::TAG, $($arg)*); }};
}
macro_rules! dloge {
    ($($arg:tt)*) => {{ rz_common::loge!(crate::hook_register::TAG, $($arg)*); }};
}

/// hook.c `hook_register` (1291-1301): forward one PLT hook to PLTI.
///
/// `backup` is the address of the old_* static (NULL when the caller does
/// not keep a backup); plti writes it only while the slot is still 0,
/// exactly like the C (`if (backup && *backup == NULL) *backup = ...`).
pub unsafe fn hook_register(
    lib_name: &str,
    symbol: &str,
    is_prefix: bool,
    new_func: *mut c_void,
    backup: *mut *mut c_void,
) -> bool {
    let backup_slot = if backup.is_null() {
        None
    } else {
        Some(unsafe { &mut *backup.cast::<usize>() })
    };

    let ok = context::with_plti(|plti| {
        if is_prefix {
            plti.add_hook_by_prefix(lib_name, symbol, new_func as usize, backup_slot)
        } else {
            plti.add_hook(lib_name, symbol, new_func as usize, backup_slot)
        }
    });

    if !ok {
        dloge!("Failed to register plt_hook \"{symbol}\" with PLTI");
        return false;
    }

    dlogd!("Registered plt_hook for symbol \"{symbol}\" in library \"{lib_name}\"");
    true
}

/// hook.c `hook_unregister` (1303-1313): remove one PLT hook from PLTI.
///
/// The C `plti_remove_hook` reads the original callback out of `*backup`
/// and rejects NULL (logged by the plti crate); a NULL `backup` slot
/// therefore behaves identically to an unfilled one.
pub unsafe fn hook_unregister(
    lib_name: &str,
    symbol: &str,
    is_prefix: bool,
    backup: *mut *mut c_void,
) -> bool {
    let original = if backup.is_null() {
        0
    } else {
        unsafe { *backup.cast::<usize>() }
    };

    let ok = context::with_plti(|plti| {
        if is_prefix {
            plti.remove_hook_by_prefix(lib_name, symbol, original)
        } else {
            plti.remove_hook(lib_name, symbol, original)
        }
    });

    if !ok {
        dloge!("Failed to unregister plt_hook \"{symbol}\" with PLTI");
        return false;
    }

    dlogd!("Unregistered plt_hook for symbol \"{symbol}\" in library \"{lib_name}\"");
    true
}

/// hook.c `hook_functions` (1327-1336): init PLTI, add libandroid_runtime.so
/// and register the four core loader hooks.
pub fn hook_functions() -> u32 {
    // Status bitmask — 0 = all four hooks registered.
    let mut status: u32 = 0;
    // C: plti_init(&plti_ctx) — with_plti constructs on first use
    // (Plti::new == the zeroed struct).
    // C: plti_add_lib(&plti_ctx, "libandroid_runtime.so"); — result ignored.
    let lib_ok = context::with_plti(|plti| plti.add_lib("libandroid_runtime.so"));
    if !lib_ok {
        status |= 0x1;
    }

    // C 1332-1335: PLT_HOOK_REGISTER x3 + PLT_HOOK_REGISTER_SYM (the
    // ReopenOrDetach dynsym entry carries a longer `...Ev` suffix, hence the
    // prefix match); fork_hooks owns the new_*/old_* equivalents.
    // AtomicPtr::as_ptr() gives PLTI a raw pointer to write the backup.
    unsafe {
        if !hook_register(
            "libandroid_runtime.so",
            "fork",
            false,
            crate::fork_hooks::fork as usize as *mut c_void,
            crate::fork_hooks::OLD_FORK.as_ptr() as *mut *mut c_void,
        ) {
            status |= 0x2;
        }
        if !hook_register(
            "libandroid_runtime.so",
            "strdup",
            false,
            crate::fork_hooks::strdup as usize as *mut c_void,
            crate::fork_hooks::OLD_STRDUP.as_ptr() as *mut *mut c_void,
        ) {
            status |= 0x4;
        }
        if !hook_register(
            "libandroid_runtime.so",
            "property_get",
            false,
            crate::fork_hooks::property_get as usize as *mut c_void,
            crate::fork_hooks::OLD_PROPERTY_GET.as_ptr() as *mut *mut c_void,
        ) {
            status |= 0x8;
        }
        if !hook_register(
            "libandroid_runtime.so",
            "_ZNK18FileDescriptorInfo14ReopenOrDetach",
            true,
            crate::fork_hooks::_ZNK18FileDescriptorInfo14ReopenOrDetach as usize as *mut c_void,
            crate::fork_hooks::OLD__ZNK18FileDescriptorInfo14ReopenOrDetach.as_ptr() as *mut *mut c_void,
        ) {
            status |= 0x10;
        }
    }

    status
}

/// hook.c `hook_unloader` (1338-1355): once libart.so is mapped, hook
/// pthread_attr_setstacksize, drop the property_get hook that got us here,
/// then load modules early (before the system server fork) to spread them
/// through all Zygotes.
pub fn hook_unloader() {
    if !context::with_plti(|plti| plti.add_lib("libart.so")) {
        dloge!("Failed to add libart.so to PLTI");
        return;
    }

    // C 1345: PLT_HOOK_REGISTER("libart.so", pthread_attr_setstacksize, false);
    unsafe {
        hook_register(
            "libart.so",
            "pthread_attr_setstacksize",
            false,
            crate::fork_hooks::pthread_attr_setstacksize as usize as *mut c_void,
            crate::fork_hooks::OLD_PTHREAD_ATTR_SETSTACKSIZE.as_ptr() as *mut *mut c_void,
        );
    }

    // C 1347: PLT_HOOK_UNREGISTER("libandroid_runtime.so", property_get, false);
    unsafe {
        hook_unregister(
            "libandroid_runtime.so",
            "property_get",
            false,
            crate::fork_hooks::OLD_PROPERTY_GET.as_ptr() as *mut *mut c_void,
        );
    }

    if !unsafe { crate::load_modules::load_modules_only() } {
        dloge!("Failed to load modules in hook_unloader");
    }

    dlogd!("ReZygisk unloader hooked successfully");
}

/// hook.c `unhook_functions` (1357-1362): restore the four loader hooks the
/// C unhooks (property_get was already unregistered by `hook_unloader`).
///
/// The self-unload teardown the C runs right after this call inside the
/// pthread_attr_setstacksize hook (csoloader_deinit, the defensive
/// should_unmap_zygisk re-check, module table free, plti_deinit, and the
/// tail-called munmap of libzygisk.so) lives in the hook body itself — see
/// `fork_hooks::pthread_attr_setstacksize`.
/// Restore every core PLT hook. Returns true only when all four slots were
/// restored: a failed slot still points into libzygisk.so, so unmapping the
/// library behind it would leave a dangling GOT target that crashes the app
/// on its next `fork`/`strdup` — itself a detection signal.
pub fn unhook_functions() -> bool {
    let mut all_ok = true;
    unsafe {
        all_ok &= hook_unregister(
            "libandroid_runtime.so",
            "fork",
            false,
            crate::fork_hooks::OLD_FORK.as_ptr() as *mut *mut c_void,
        );
        all_ok &= hook_unregister(
            "libandroid_runtime.so",
            "strdup",
            false,
            crate::fork_hooks::OLD_STRDUP.as_ptr() as *mut *mut c_void,
        );
        all_ok &= hook_unregister(
            "libandroid_runtime.so",
            "_ZNK18FileDescriptorInfo14ReopenOrDetach",
            true,
            crate::fork_hooks::OLD__ZNK18FileDescriptorInfo14ReopenOrDetach.as_ptr() as *mut *mut c_void,
        );
        all_ok &= hook_unregister(
            "libart.so",
            "pthread_attr_setstacksize",
            false,
            crate::fork_hooks::OLD_PTHREAD_ATTR_SETSTACKSIZE.as_ptr() as *mut *mut c_void,
        );
    }

    all_ok
}
