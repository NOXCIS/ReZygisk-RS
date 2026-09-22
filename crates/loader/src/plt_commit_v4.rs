//! hook.c PLT hook commit v4: `api_plt_hook_register_v4` (hook.c 615-681)
//! and `api_plt_hook_commit_v4` (hook.c 695-720). Modules using api version
//! >= 4 register hooks by (dev_t, ino_t) instead of a regex: register
//! resolves the pair to the first matching self-maps entry up front, adds
//! that library to PLTI as a manual lib, and queues a `PltHookEntry` on the
//! module v4 queue; commit drains the queue through
//! `rz_plti::Plti::add_hook`, frees it, and returns `!any_failed`.
//!
//! C-parity notes:
//! - The C's file-static `plt_hook_list` / `struct plt_hook_entry` live in
//!   the shared spine as `context::{PLT_HOOK_LIST, PltHookEntry}` (the
//!   context.rs mirror of hook.c lines 128-129). A Rust `Vec` aborts on OOM
//!   where the C realloc fails, so the C's `strdup`/realloc failure branches
//!   below are unreachable (existing port-wide convention).
//! - `entry->dev` is `makedev(dev_major, dev_minor)` (misc.c); the raw
//!   major/minor pair is recombined with the sys/sysmacros.h formula so
//!   `entry->dev != dev` stays a direct `dev_t` comparison.
//! - Neither function takes `hook_info_lock` (the C doesn't lock here).

use std::ffi::{c_char, c_void, CStr};

use crate::context::{ctx_mut, take_plt_hook_list, with_plti, with_plt_hook_list, PltHookEntry};

const TAG: &str = rz_common::LOG_TAG;

/// hook.c `ino_t`: 32-bit on LP32, 64-bit on LP64 — the same cfg as the
/// second `abi::PltRegisterV4Fn` parameter, which this function's signature
/// must match exactly (module_api.rs stores it into the v4 union slot).
#[cfg(target_pointer_width = "64")]
#[allow(non_camel_case_types)]
type ino_ty = u64;
#[cfg(target_pointer_width = "32")]
#[allow(non_camel_case_types)]
type ino_ty = u32;

/// hook.c `dev_t`: 64-bit on LP64, 32-bit on LP32 (bionic sys/types.h
/// "historical accident"). Mirrors the first `abi::PltRegisterV4Fn`
/// parameter so the v4 union slot assignment stays type-exact.
#[cfg(target_pointer_width = "64")]
#[allow(non_camel_case_types)]
type dev_ty = u64;
#[cfg(target_pointer_width = "32")]
#[allow(non_camel_case_types)]
type dev_ty = u32;

/// hook.c `makedev` (bionic sys/sysmacros.h), the dev_t layout bionic uses:
/// misc.c stores `entry->dev` as `makedev(dev_major, dev_minor)`. The 64-bit
/// formula is truncated on the `dev_ty` store, exactly like the C assigns
/// the macro result into a `dev_t` field.
fn makedev(major: u32, minor: u32) -> dev_ty {
    let major = major as u64;
    let minor = minor as u64;

    let dev = ((major & 0xfff) << 8)
        | (minor & 0xff)
        | ((minor & 0xffff_ff00) << 12)
        | ((major & 0xffff_f000) << 32);

    dev as dev_ty
}

/// hook.c `api_plt_hook_register_v4` (615-681): resolve the module-supplied
/// (dev, inode) pair to the first matching self-maps entry, add that library
/// to PLTI as a manual lib, and queue the hook on the shared PLT hook list.
pub unsafe extern "C" fn api_plt_hook_register_v4(
    dev: dev_ty,
    ino: ino_ty,
    symbol: *const c_char,
    fn_ptr: *mut c_void,
    backup: *mut *mut c_void,
) {
    // hook.c `if (!g_ctx || !symbol || !fn) return;` — g_ctx is only
    // checked here, never dereferenced.
    if ctx_mut().is_none() || symbol.is_null() || fn_ptr.is_null() {
        return;
    }

    let symbol_str = unsafe { CStr::from_ptr(symbol) }.to_string_lossy();

    let Some(maps) = rz_common::parse_maps_safe("self") else {
        rz_common::loge!(TAG, "Failed to scan maps for plt_hook_register_v4");

        return;
    };

    let mut lib_start: usize = 0;
    let mut found_path: Option<&str> = None;
    for entry in &maps {
        // hook.c `if (entry->dev != dev || entry->inode != inode) continue;`
        // — the `as ino_ty` cast reproduces the C's ino_t-width truncation
        // of the parsed inode on LP32.
        if makedev(entry.dev_major, entry.dev_minor) != dev || entry.inode as ino_ty != ino {
            continue;
        }

        lib_start = entry.start;
        found_path = Some(entry.path.as_str());

        break;
    }

    let Some(found_path) = found_path else {
        // hook.c logs `(size_t)dev` / `(size_t)inode`: the `as usize`
        // casts truncate on LP32 exactly like the C.
        rz_common::loge!(
            TAG,
            "Failed to find library with dev {} and inode {} for hook {}",
            dev as usize,
            ino as usize,
            symbol_str
        );

        // maps drops here == hook.c free_maps(maps)

        return;
    };

    // hook.c strdup(lib_path) cannot fail in Rust (a String allocation
    // aborts on OOM), so the C "Failed to duplicate library path" branch
    // (hook.c 646-652) is dropped.
    let lib_path = found_path.to_string();
    // hook.c free_maps(maps)
    drop(maps);

    let add_ok = with_plti(|plti| plti.add_manual_lib(&lib_path, lib_start));
    if !add_ok {
        rz_common::loge!(
            TAG,
            "Failed to add manual library for hook {}: {}",
            symbol_str,
            lib_path
        );

        // lib_path drops here == hook.c free(lib_path_copy)

        return;
    }

    // hook.c strdup(symbol) + plt_hook_list_add are infallible in Rust, so
    // the C "Failed to duplicate symbol name" (hook.c 665-671) and
    // "Failed to add plt_hook entry" (hook.c 674-680) branches are dropped.
    with_plt_hook_list(|list| {
        list.push(PltHookEntry {
            lib_path,
            symbol: symbol_str.into_owned(),
            new_func: fn_ptr,
            backup,
        })
    });
}

/// hook.c `api_plt_hook_commit_v4` (695-720): apply every queued v4 PLT
/// hook through PLTI, then free the list and reset it to NULL.
pub unsafe extern "C" fn api_plt_hook_commit_v4() -> bool {
    if ctx_mut().is_none() {
        return false;
    }

    let mut any_failed = false;

    // hook.c `for (i = 0; i < plt_hook_list_count; i++)` — a NULL list
    // iterates zero times. `take_plt_hook_list` leaves PLT_HOOK_LIST = None
    // (the C `plt_hook_list = NULL`), and the moved Vec's drop frees the
    // strdup'd lib_path/symbol of every entry plus the list itself
    // (hook.c 708-717).
    if let Some(list) = take_plt_hook_list() {
        for entry in &list {
            let backup = if entry.backup.is_null() {
                None
            } else {
                unsafe { Some(&mut *(entry.backup as *mut usize)) }
            };

            let hook_ok = with_plti(|plti| {
                plti.add_hook(&entry.lib_path, &entry.symbol, entry.new_func as usize, backup)
            });
            if !hook_ok {
                rz_common::loge!(
                    TAG,
                    "Failed to register plt_hook \"{}\" in {} with PLTI",
                    entry.symbol,
                    entry.lib_path
                );

                any_failed = true;
            }
        }
    }

    !any_failed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn makedev_matches_bionic_formula() {
        // bionic sys/sysmacros.h:
        // (major & 0xfffff000) << 32 | (major & 0xfff) << 8
        //   | (minor & 0xffffff00) << 12 | (minor & 0xff)
        assert_eq!(makedev(0xfe, 0x1), 0xfe01);
        assert_eq!(makedev(0x103, 0xab), 0x103ab);
        #[cfg(target_pointer_width = "64")]
        assert_eq!(makedev(0xabcd, 0xef), 0x0000_a000_000b_cdef);
        // dev_t truncation drops the (major & 0xfffff000) << 32 term on LP32
        #[cfg(target_pointer_width = "32")]
        assert_eq!(makedev(0xabcd, 0xef), 0x0000_bcdef);
    }

    #[test]
    fn makedev_encodes_minor_high_bits_at_bit_12() {
        // bionic keeps minor bits >= 0x100 at offset 12 (kernel encode_dev
        // layout): the C `entry->dev != dev` relies on this, so a maps
        // minor like 0x100 (e.g. loop16+) must not collapse to 0.
        assert_eq!(makedev(0xfe, 0x100), 0x10fe00);
        assert_eq!(makedev(0xfe, 0x2ff), 0x20feff);
    }
}
