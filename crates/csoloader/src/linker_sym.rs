//! Port of linker.c `_linker_find_symbol_in_linker_scope` (the global-group
//! symbol resolution), the `tls_index` bookkeeping that `crate::tls` does
//! not cover, and elf_util.c's `handle_indirect_symbol` — the IFUNC resolver
//! execution. linker.c carries a second copy of `handle_indirect_symbol`
//! taking a raw resolver address; that is the shape `image.rs` calls, so it
//! is the one ported here.
//!
//! Reused from `crate::tls` (already ported, NOT duplicated here):
//! `register_tls_segment`, `unregister_tls_segment`, the pthread key
//! allocation (`_linker_alloc_tls_key_once`), per-thread block alloc/sync
//! (`_linker_allocate_module_tls` / `_linker_sync_thread_tls`),
//! `__tls_get_addr`, the TLSDESC resolvers and `get_tpidr`.
//!
//! # Assumed `crate::linker_core` API (owned by the linker_core port)
//!
//! This module only needs the C-parity shape of linker.h — plain `#[repr(C)]`
//! structs with public fields mirroring the C member names:
//!
//! ```ignore
//! #[repr(C)]
//! pub struct TlsIndicesData {
//!     pub indices: *mut *mut crate::tls::TlsIndex,
//!     pub count: usize,
//!     pub capacity: usize,
//! }
//!
//! #[repr(C)]
//! pub struct LoadedDep {
//!     pub img: *mut CsoElf,
//!     pub tls_indices: TlsIndicesData,
//!     pub is_manual_load: bool,
//!     pub load_bias: usize,
//!     pub map_base: *mut libc::c_void,
//!     pub map_size: usize,
//! }
//!
//! #[repr(C)]
//! pub struct Linker {
//!     pub img: *mut CsoElf,
//!     pub tls_indices: TlsIndicesData,
//!     pub dependencies: [LoadedDep; MAX_DEPS],
//!     pub dep_count: libc::c_int,
//!     pub main_map_size: usize,
//!     pub is_linked: bool,
//! }
//! ```

use crate::image::CsoElf;
use crate::linker_core::{Linker, TlsIndicesData};
use crate::tls::TlsIndex;

pub const TAG: &str = crate::TAG;

macro_rules! dlogd {
    ($($arg:tt)*) => {{ rz_common::logd!(TAG, $($arg)*); }};
}
macro_rules! dlogw {
    ($($arg:tt)*) => {{ rz_common::logw!(TAG, $($arg)*); }};
}
macro_rules! dloge {
    ($($arg:tt)*) => {{ rz_common::loge!(TAG, $($arg)*); }};
}

// ---------------------------------------------------------------------------
// IFUNC resolver execution — elf_util.c `handle_indirect_symbol`
// (the `(resolver_addr)` variant also duplicated in linker.c).
// ---------------------------------------------------------------------------

/// elf_util.c `struct __ifunc_arg_t` (aarch64 only).
#[cfg(target_arch = "aarch64")]
#[repr(C)]
struct IfuncArg {
    /// `_size`
    size: usize,
    /// `_hwcap`
    hwcap: usize,
    /// `_hwcap2`
    hwcap2: usize,
}

/// elf_util.c `_IFUNC_ARG_HWCAP` — flags the first resolver argument as
/// carrying hardware capability bits (aarch64 only).
#[cfg(target_arch = "aarch64")]
const IFUNC_ARG_HWCAP: u64 = 1u64 << 62;

/// elf_util.c `struct riscv_hwprobe` (riscv only).
#[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
#[repr(C)]
struct RiscvHwprobe {
    key: i64,
    value: u64,
}

/// elf_util.c `__riscv_hwprobe_t`.
#[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
type RiscvHwprobeFn =
    unsafe extern "C" fn(*mut RiscvHwprobe, usize, usize, *mut usize, u32) -> i32;

/// `<elf.h>` `AT_HWCAP` (riscv only; libc only declares it on Android).
#[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
const AT_HWCAP: libc::c_ulong = 16;

/// `<asm/unistd.h>` `__NR_riscv_hwprobe` (riscv only).
#[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
const SYS_RISCV_HWPROBE: isize = 258;

/// elf_util.c `__riscv_hwprobe`: raw `__NR_riscv_hwprobe` syscall. The kernel
/// leaves `-errno` in a0 on failure; like the C (`return -a0;`) this negates
/// it back to bionic's positive-errno convention (0 on success).
#[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
unsafe extern "C" fn riscv_hwprobe(
    pairs: *mut RiscvHwprobe,
    pair_count: usize,
    cpu_count: usize,
    cpus: *mut usize,
    flags: u32,
) -> i32 {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") pairs as isize => ret,
            in("a1") pair_count,
            in("a2") cpu_count,
            in("a3") cpus as isize,
            in("a4") flags,
            in("a7") SYS_RISCV_HWPROBE,
            options(nostack),
        );
    }

    ret.wrapping_neg() as i32
}

/// elf_util.c `handle_indirect_symbol` (the linker.c raw-address form):
/// execute the GNU IFUNC resolver at the runtime address `addr` with the
/// per-arch calling convention and return the selected implementation.
///
/// - aarch64: 2-arg `__ifunc_arg_t` protocol — `hwcap | _IFUNC_ARG_HWCAP`
///   plus a pointer to the `_size`/`_hwcap`/`_hwcap2` argument block.
/// - arm: 1-arg `AT_HWCAP`.
/// - riscv: 3-arg — `AT_HWCAP`, `__riscv_hwprobe`, `NULL`.
/// - everything else: 0-arg.
///
/// The C logs nothing here; the callers (`csoloader_elf_symb_address`,
/// `csoloader_elf_symb_address_exported`) log "Resolving STT_GNU_IFUNC
/// symbol %s" first — image.rs already does the same.
///
/// # Safety
/// `addr` must point at executable resolver code (image.rs passes a runtime
/// address derived from a mapped image, like the C).
pub fn handle_indirect_symbol(addr: usize) -> usize {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        type IfuncResolver = unsafe extern "C" fn(u64, *mut IfuncArg) -> usize;

        let mut args = IfuncArg {
            size: std::mem::size_of::<IfuncArg>(),
            hwcap: libc::getauxval(libc::AT_HWCAP) as usize,
            hwcap2: libc::getauxval(libc::AT_HWCAP2) as usize,
        };
        let resolver: IfuncResolver = std::mem::transmute(addr);
        resolver((args.hwcap as u64) | IFUNC_ARG_HWCAP, &mut args)
    }
    #[cfg(target_arch = "arm")]
    unsafe {
        type IfuncResolver = unsafe extern "C" fn(libc::c_ulong) -> usize;

        let resolver: IfuncResolver = std::mem::transmute(addr);
        resolver(libc::getauxval(libc::AT_HWCAP))
    }
    #[cfg(any(target_arch = "riscv64", target_arch = "riscv32"))]
    unsafe {
        type IfuncResolver = unsafe extern "C" fn(u64, RiscvHwprobeFn, *mut libc::c_void) -> usize;

        let resolver: IfuncResolver = std::mem::transmute(addr);
        resolver(
            libc::getauxval(AT_HWCAP) as u64,
            riscv_hwprobe,
            std::ptr::null_mut(),
        )
    }
    #[cfg(not(any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
        target_arch = "riscv32"
    )))]
    unsafe {
        type IfuncResolver = unsafe extern "C" fn() -> usize;

        let resolver: IfuncResolver = std::mem::transmute(addr);
        resolver()
    }
}

// ---------------------------------------------------------------------------
// Global-group symbol resolution — linker.c `_linker_find_symbol_in_linker_scope`.
// ---------------------------------------------------------------------------

/// linker.c `struct linker_symbol_info`.
#[derive(Clone, Copy)]
pub(crate) struct LinkerSymbolInfo {
    pub addr: usize,
    /// Image that owns the symbol (NULL when unresolved). Relocation callers
    /// use the NULL case for the STB_WEAK fallback.
    pub img: *mut CsoElf,
    /// `tls_indices` of the module the symbol belongs to.
    pub tls_indices: *mut TlsIndicesData,
}

/// linker.c `_linker_find_symbol_in_linker_scope`: resolve `sym_name` for
/// `requester` in the loader's global group — the requester's own dynamic
/// tables first, then the main image's exported symbols, then every loaded
/// dependency's exported symbols. The C takes a possibly-NULL `requester`;
/// this signature takes `&CsoElf` (all callers pass `dep->img`).
pub(crate) fn find_symbol_in_linker_scope_info(
    linker: &Linker,
    requester: &CsoElf,
    sym_name: &str,
) -> LinkerSymbolInfo {
    // Phase 1: the requester's own dynamic symbol tables.
    let addr = requester.symb_address(sym_name);
    if addr != 0 {
        if std::ptr::eq(requester, linker.img) {
            dlogd!(
                "Found symbol '{sym_name}' in main image: {} via Elf Utils: {addr:#x}",
                requester.path()
            );

            return LinkerSymbolInfo {
                addr,
                img: linker.img,
                tls_indices: &linker.tls_indices as *const TlsIndicesData as *mut TlsIndicesData,
            };
        }

        for i in 0..linker.dep_count as usize {
            let dep = &linker.dependencies[i];
            if !std::ptr::eq(dep.img, requester) {
                continue;
            }

            dlogd!(
                "Found symbol '{sym_name}' in requester dependency {i}: {} via Elf Utils: {addr:#x}",
                requester.path()
            );

            return LinkerSymbolInfo {
                addr,
                img: dep.img,
                tls_indices: &dep.tls_indices as *const TlsIndicesData as *mut TlsIndicesData,
            };
        }
    }

    // Phase 2: the main image's exported symbols.
    if !std::ptr::eq(linker.img, requester) {
        let main_img = unsafe { &*linker.img };
        let addr = main_img.symb_address_exported(sym_name);
        if addr != 0 {
            dlogd!(
                "Found exported symbol '{sym_name}' in main image: {} via Elf Utils: {addr:#x}",
                main_img.path()
            );

            return LinkerSymbolInfo {
                addr,
                img: linker.img,
                tls_indices: &linker.tls_indices as *const TlsIndicesData as *mut TlsIndicesData,
            };
        }
    }

    // Phase 3: the loaded dependencies' exported symbols.
    for i in 0..linker.dep_count as usize {
        let candidate = &linker.dependencies[i];
        if candidate.img.is_null() || std::ptr::eq(candidate.img, requester) {
            continue;
        }

        let candidate_img = unsafe { &*candidate.img };
        let addr = candidate_img.symb_address_exported(sym_name);
        if addr == 0 {
            continue;
        }

        dlogd!(
            "Found exported symbol '{sym_name}' in dependency {i}: {} via Elf Utils: {addr:#x}",
            candidate_img.path()
        );

        return LinkerSymbolInfo {
            addr,
            img: candidate.img,
            tls_indices: &candidate.tls_indices as *const TlsIndicesData as *mut TlsIndicesData,
        };
    }

    dloge!("Symbol '{sym_name}' not found in any loaded image");

    LinkerSymbolInfo {
        addr: 0,
        img: std::ptr::null_mut(),
        tls_indices: std::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// TLS index bookkeeping — linker.c `_track_tls_index`,
// `allocate_tls_index_for_symbol` and the `tls_indices` teardown
// half of `_linker_unregister_tls_segment` (1139-1149). Everything else from
// this block (module registration, per-thread blocks, `__tls_get_addr`)
// already lives in `crate::tls`.
// ---------------------------------------------------------------------------

/// linker.c `_track_tls_index`: grow the tracking array when full (8 → ×2,
/// C's `realloc` semantics — the old array survives a failed grow) and append
/// `ti`, which stays owned by the `allocate_tls_index_for_symbol` caller.
pub(crate) fn track_tls_index(tls_indices: &mut TlsIndicesData, ti: *mut TlsIndex) -> bool {
    if ti.is_null() {
        return false;
    }

    if tls_indices.count >= tls_indices.capacity {
        let new_cap = if tls_indices.capacity == 0 {
            8
        } else {
            tls_indices.capacity * 2
        };
        let new_arr = unsafe {
            libc::realloc(
                tls_indices.indices as *mut libc::c_void,
                new_cap * std::mem::size_of::<*mut TlsIndex>(),
            )
        } as *mut *mut TlsIndex;
        if new_arr.is_null() {
            dloge!("Failed to grow tls_indices array");

            return false;
        }

        tls_indices.indices = new_arr;
        tls_indices.capacity = new_cap;
    }

    unsafe {
        *tls_indices.indices.add(tls_indices.count) = ti;
    }
    tls_indices.count += 1;

    true
}

/// linker.c `allocate_tls_index_for_symbol`: heap-allocate a `tls_index`
/// (`module` = `img->tls_mod_id`, `offset` = the relocating image's dynsym
/// `st_value` + `addend`) and track it for cleanup.
///
/// The C takes `(img, tls_indices, dynsym, sym_idx, addend)` where `dynsym`
/// is the *relocating* image's table (`dep->img`), not `img`'s — hence the
/// separate `dynsym_img`/`sym_idx` pair here (`CsoElf::symbol_at` plays the
/// `dynsym` role).
pub(crate) fn allocate_tls_index_for_symbol(
    img: &CsoElf,
    tls_indices: &mut TlsIndicesData,
    dynsym_img: &CsoElf,
    sym_idx: usize,
    addend: u64,
) -> *mut TlsIndex {
    let ti = unsafe { libc::malloc(std::mem::size_of::<TlsIndex>()) } as *mut TlsIndex;
    if ti.is_null() {
        dloge!("Failed to allocate memory for tls_index");

        return std::ptr::null_mut();
    }

    unsafe {
        (*ti).module = img.tls_mod_id();
        // C: sym = &dynsym[sym_idx]; ti->offset = sym->st_value + addend;
        let st_value = dynsym_img.symbol_at(sym_idx).map(|sym| sym.value).unwrap_or(0);
        (*ti).offset = (st_value as usize).wrapping_add(addend as usize);
    }

    if !track_tls_index(tls_indices, ti) {
        dlogw!("Failed to track tls_index for cleanup - potential memory leak");
    }

    ti
}

/// The `tls_indices` teardown of linker.c `_linker_unregister_tls_segment`:
/// free every tracked `tls_index`, then the array itself,
/// and reset the bookkeeping. The module-table half is
/// `crate::tls::unregister_tls_segment`; callers unregistering a `LoadedDep`
/// run both.
pub(crate) fn free_tls_indices(tls_indices: &mut TlsIndicesData) {
    if tls_indices.count == 0 {
        return;
    }

    unsafe {
        for i in 0..tls_indices.count {
            libc::free(*tls_indices.indices.add(i) as *mut libc::c_void);
        }
        libc::free(tls_indices.indices as *mut libc::c_void);
    }

    tls_indices.indices = std::ptr::null_mut();
    tls_indices.count = 0;
    tls_indices.capacity = 0;
}
