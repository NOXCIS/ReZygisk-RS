//! hook.c module api: `api_exempt_fd` (683-694), `api_connect_companion`
//! (728-739), `api_set_option` (740-763), `api_get_module_dir` (764-775),
//! `api_get_flags` (776-781), `rezygisk_module_register` (782-813).
//!
//! Every api entry receives the module id encoded as `impl + RZID_MAGIC`
//! (`abi::{RZID_MAGIC, decode_id}`); the range check against
//! `zygisk_module_length()` and the "Invalid (encoded) module id" error are
//! copied verbatim from the C (the RZID_MAGIC scheme exists so a stray
//! NULL/0 impl is distinguishable from module 0). `rezygisk_module_register`
//! byte-copies the module's `ReZygiskAbi`/`ReZygiskApi` into the module
//! table, then patches the loader-owned vtable entries (v3/v4/v5 union slots
//! per api_version) on the module's `api` pointer.
//!
//! C-parity notes:
//! - `g_ctx` access goes through context::{ctx_ref, ctx_mut} (the raw static
//!   `G_CTX` pointer, exactly like the C `if (!g_ctx) ...` guards).
//! - `rezygisk_module_register` bounds-checks the decoded id (the C indexes
//!   `zygisk_modules[DECODE_ID(api->impl)]` blindly; the loader does mint the
//!   id via `encode_id`, but a module hand-crafting an id must not write out
//!   of bounds). Runs from inside a module entry callback, so it takes the
//!   table lock briefly via `with_module` — deadlock-free because the
//!   snapshot in `rz_run_modules_pre` released the lock before the callback.
//! - `m->abi = *abi` / `m->api = *api` become `ptr::read` byte copies; the
//!   module's own `register_module` therefore survives in `m->api` exactly
//!   like the C, which only overwrites the loader-owned fields afterwards.
//! - Sibling contracts: `jni_hooks::hook_jni_methods`, `plt_commit::{..}`
//!   (v3) and `plt_commit_v4::{..}` (v4) own their union slots; this module
//!   only installs them into the vtable here.

use std::os::raw::{c_int, c_void};

use rz_common::{logd, loge};

use crate::abi::{
    decode_id, PltExcludeSlot, PltRegisterSlot, REZYGISK_API_VERSION, RZID_MAGIC, ReZygiskAbi,
    ReZygiskApi, ReZygiskOptions,
};
use crate::context::{
    ctx_mut, ctx_ref, flag_get, flag_set, with_module, zygisk_module_length, APP_FORK_AND_SPECIALIZE,
    DO_REVERT_UNMOUNT, MAX_EXEMPTED_FDS, POST_SPECIALIZE, SKIP_FD_SANITIZATION,
};

/// hook.c `LOG_TAG` (zygisk-core32/64 in the C; the RS port uses "zygisk").
const TAG: &str = rz_common::LOG_TAG;

/// module.h `PRIVATE_MASK` (= PROCESS_IS_FIRST_STARTED, bit 31), stripped by
/// `api_get_flags`. Belongs with the rezygiskd flags in daemon_client.rs once
/// that slice lands; kept local until then.
const PRIVATE_MASK: u32 = 1u32 << 31;

/// hook.c `api_exempt_fd` (683-694): record an fd the zygote must keep open
/// during fd sanitization. Only meaningful during forkAndSpecialize, before
/// post-specialize, when sanitization was not already skipped.
pub unsafe extern "C" fn api_exempt_fd(fd: c_int) {
    let Some(ctx) = ctx_mut() else { return };
    if flag_get(ctx, POST_SPECIALIZE) || flag_get(ctx, SKIP_FD_SANITIZATION) {
        return;
    }
    if !flag_get(ctx, APP_FORK_AND_SPECIALIZE) {
        return;
    }
    if ctx.exempted_fds_count >= MAX_EXEMPTED_FDS {
        return;
    }

    ctx.exempted_fds[ctx.exempted_fds_count] = fd;
    ctx.exempted_fds_count += 1;
}

/// hook.c `api_connect_companion` (728-739).
pub unsafe extern "C" fn api_connect_companion(id: *mut c_void) -> c_int {
    if ctx_ref().is_none() {
        return -1;
    }

    let raw = id as usize;
    if raw < RZID_MAGIC || raw >= RZID_MAGIC + zygisk_module_length() {
        loge!(TAG, "Invalid (encoded) module id {}", raw);
        return -1;
    }

    crate::daemon_client::rezygiskd_connect_companion(decode_id(id))
}

/// hook.c `api_set_option` (740-763).
pub unsafe extern "C" fn api_set_option(id: *mut c_void, opt: c_int) {
    let Some(ctx) = ctx_mut() else { return };

    let raw = id as usize;
    if raw < RZID_MAGIC || raw >= RZID_MAGIC + zygisk_module_length() {
        loge!(TAG, "Invalid (encoded) module id {}", raw);
        return;
    }

    match opt {
        o if o == ReZygiskOptions::ForceDenylistUnmount as c_int => {
            flag_set(ctx, DO_REVERT_UNMOUNT);
        }
        o if o == ReZygiskOptions::DlcloseModuleLibrary as c_int => {
            // The old path called zygisk_module_length() from inside a module
            // callback while the table lock was held — the deadlock. The
            // bounds check above already validated the id; with_module takes
            // the (now free) lock briefly.
            if with_module(decode_id(id), |m| m.unload = true).is_none() {
                loge!(TAG, "Invalid (encoded) module id {}", raw);
            }
        }
        _ => {}
    }
}

/// hook.c `api_get_module_dir` (764-775).
pub unsafe extern "C" fn api_get_module_dir(id: *mut c_void) -> c_int {
    if ctx_ref().is_none() {
        return -1;
    }

    let raw = id as usize;
    if raw < RZID_MAGIC || raw >= RZID_MAGIC + zygisk_module_length() {
        loge!(TAG, "Invalid (encoded) module id {}", raw);
        return -1;
    }

    crate::daemon_client::rezygiskd_get_module_dir(decode_id(id))
}

/// hook.c `api_get_flags` (776-781): the process info flags with the private
/// bit stripped.
pub unsafe extern "C" fn api_get_flags() -> u32 {
    let Some(ctx) = ctx_ref() else { return 0 };

    ctx.info_flags & !PRIVATE_MASK
}

/// hook.c `rezygisk_module_register` (782-813).
pub unsafe extern "C" fn rezygisk_module_register(
    api: *mut ReZygiskApi,
    abi: *const ReZygiskAbi,
) -> bool {
    if ctx_ref().is_none()
        || api.is_null()
        || abi.is_null()
        || (*abi).api_version > REZYGISK_API_VERSION
    {
        return false;
    }

    logd!(TAG, "Registering module with API version {}", (*abi).api_version);

    // Called from inside a module entry (on_load): the table lock is free by
    // design (module_snapshot released it before the callback ran), so this
    // short borrow cannot deadlock. Bounds-checked instead of the C's blind
    // index.
    let idx = decode_id((*api).impl_);
    if with_module(idx, |m| {
        m.abi = std::ptr::read(abi);
        m.api = std::ptr::read(api);
    })
    .is_none()
    {
        loge!(TAG, "Invalid (encoded) module id {}", idx.wrapping_add(RZID_MAGIC));
        return false;
    }

    (*api).hook_jni_native_methods = Some(crate::jni_hooks::hook_jni_methods);
    if (*abi).api_version >= 4 {
        (*api).plt_hook_register = PltRegisterSlot {
            v4: Some(crate::plt_commit_v4::api_plt_hook_register_v4),
        };
        (*api).plt_hook_exclude = PltExcludeSlot { exempt_fd: Some(api_exempt_fd) };
        (*api).plt_hook_commit = Some(crate::plt_commit_v4::api_plt_hook_commit_v4);
    } else {
        (*api).plt_hook_register = PltRegisterSlot {
            v3: Some(crate::plt_commit::api_plt_hook_register),
        };
        (*api).plt_hook_exclude = PltExcludeSlot {
            plt_hook_exclude: Some(crate::plt_commit::api_plt_hook_exclude),
        };
        (*api).plt_hook_commit = Some(crate::plt_commit::api_plt_hook_commit);
    }

    (*api).connect_companion = Some(api_connect_companion);
    (*api).set_option = Some(api_set_option);

    if (*abi).api_version >= 2 {
        (*api).get_module_dir = Some(api_get_module_dir);
        (*api).get_flags = Some(api_get_flags);
    }

    true
}
