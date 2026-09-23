//! hook.c PLT hook commit (v3 api): `api_plt_hook_register`,
//! `api_plt_hook_exclude`, `api_plt_hook_commit`.
//!
//! C-parity notes:
//! - `regcomp(regex, REG_NOSUB)` becomes `regex::Regex::new`; a compile
//!   failure returns silently exactly like `if (regcomp(...) != 0) return;`.
//! - `strdup(symbol)` becomes an owned `String` (dropping it == `free`).
//! - `g_ctx->hook_info_lock` is `libc::pthread_mutex_t`; locked/unlocked via
//!   `libc::pthread_mutex_lock/unlock` at exactly the C lock points.
//! - The commit walk mirrors the C double loop: maps → register_info with an
//!   unanchored regex match on the map path, ignore_info checked with the
//!   symbol equality rule (`ign->symbol == NULL` matches any symbol), then
//!   `rz_plti::Plti::add_hook` per (map, symbol) and full cleanup of both
//!   lists (dropping `Regex` == `regfree`, dropping `String` == `free`).

use std::ffi::{c_char, c_void};

use regex::Regex;

use crate::context::{
    ctx_mut, with_plti, IgnoreInfo, RegisterInfo, MAX_IGNORE_INFO, MAX_REGISTER_INFO,
};
use crate::jni_utils::cstr_to_owned;

const TAG: &str = rz_common::LOG_TAG;

/// hook.c `api_plt_hook_register`: queue a PLT hook for a
/// regex-matched library path.
pub unsafe extern "C" fn api_plt_hook_register(
    regex: *const c_char,
    symbol: *const c_char,
    fn_ptr: *mut c_void,
    backup: *mut *mut c_void,
) {
    let Some(ctx) = ctx_mut() else { return };
    if regex.is_null() || symbol.is_null() || fn_ptr.is_null() {
        return;
    }
    if ctx.register_info.len() >= MAX_REGISTER_INFO {
        return;
    }

    // hook.c regcomp(&re, regex, REG_NOSUB): compile before locking, and a
    // failure returns silently.
    let Some(regex_str) = cstr_to_owned(regex) else {
        return;
    };
    let Ok(re) = Regex::new(&regex_str) else { return };

    unsafe {
        libc::pthread_mutex_lock(&mut ctx.hook_info_lock);
    }

    // hook.c strdup(symbol): take ownership of the module's copy.
    let symbol = cstr_to_owned(symbol).unwrap_or_default();

    ctx.register_info.push(RegisterInfo {
        regex: re,
        symbol,
        callback: fn_ptr,
        backup,
    });

    unsafe {
        libc::pthread_mutex_unlock(&mut ctx.hook_info_lock);
    }
}

/// hook.c `api_plt_hook_exclude`: queue a PLT hook exclusion;
/// `symbol == NULL` excludes every symbol in the regex-matched library.
pub unsafe extern "C" fn api_plt_hook_exclude(regex: *const c_char, symbol: *const c_char) {
    let Some(ctx) = ctx_mut() else { return };
    if regex.is_null() {
        return;
    }
    if ctx.ignore_info.len() >= MAX_IGNORE_INFO {
        return;
    }

    // hook.c regcomp(&re, regex, REG_NOSUB): compile before locking, and a
    // failure returns silently.
    let Some(regex_str) = cstr_to_owned(regex) else {
        return;
    };
    let Ok(re) = Regex::new(&regex_str) else { return };

    // hook.c `symbol ? strdup(symbol) : NULL`.
    let symbol = cstr_to_owned(symbol);

    unsafe {
        libc::pthread_mutex_lock(&mut ctx.hook_info_lock);
    }

    ctx.ignore_info.push(IgnoreInfo { regex: re, symbol });

    unsafe {
        libc::pthread_mutex_unlock(&mut ctx.hook_info_lock);
    }
}

/// hook.c `api_plt_hook_commit`: scan /proc/self/maps and apply
/// every queued register/ignore pair.
pub unsafe extern "C" fn api_plt_hook_commit() -> bool {
    let Some(ctx) = ctx_mut() else { return false };
    if ctx.register_info.is_empty() {
        return false;
    }

    unsafe {
        libc::pthread_mutex_lock(&mut ctx.hook_info_lock);
    }

    let Some(map_infos) = rz_common::parse_maps_safe("self") else {
        rz_common::loge!(TAG, "Failed to scan maps for self");

        unsafe {
            libc::pthread_mutex_unlock(&mut ctx.hook_info_lock);
        }

        return false;
    };

    let mut any_failed = false;
    for map in &map_infos {
        if map.offset != 0 || !map.is_private || !map.perms.read() {
            continue;
        }

        for reg in &ctx.register_info {
            if !reg.regex.is_match(&map.path) {
                continue;
            }

            let mut ignored = false;
            for ign in &ctx.ignore_info {
                if !ign.regex.is_match(&map.path) {
                    continue;
                }
                if let Some(ign_symbol) = &ign.symbol {
                    if ign_symbol != &reg.symbol {
                        continue;
                    }
                }

                ignored = true;

                break;
            }

            if !ignored {
                let backup = if reg.backup.is_null() {
                    None
                } else {
                    // SAFETY: `backup` is the module-provided backup slot
                    // for this hook (hook.c plt_hook_register path).
                    Some(unsafe { &mut *(reg.backup as *mut usize) })
                };

                let hook_ok = with_plti(|plti| {
                    plti.add_hook(&map.path, &reg.symbol, reg.callback as usize, backup)
                });
                if !hook_ok {
                    rz_common::loge!(
                        TAG,
                        "Failed to register PLT hook for {} in {}",
                        reg.symbol,
                        map.path
                    );

                    any_failed = true;
                }
            }
        }
    }

    // hook.c free_maps(map_infos): the owned Vec drops here.

    // Clear register_info and ignore_info: dropping Regex == regfree,
    // dropping String == free(symbol), and the counts reset with the Vecs.
    ctx.register_info.clear();
    ctx.ignore_info.clear();

    unsafe {
        libc::pthread_mutex_unlock(&mut ctx.hook_info_lock);
    }

    !any_failed
}
