//! Port of linker.c relocation processing:
//! - `_linker_process_unified_relocation` (linker.c 1303-1651)
//! - `_linker_process_relocations` (linker.c 1653-1954)
//!
//! Processing order matches the C exactly: RELR first, then DT_RELA and
//! DT_REL, then the Android packed (APS2) table, then DT_JMPREL (PLT).
//! RELR semantics are "`*target += load_bias`"; REL (non-RELA) addends are
//! read from the target word at runtime.
//!
//! Why this file walks the tables itself instead of using
//! `CsoElf::relocations_grouped()`/`relr_offsets()`: `relocations_grouped()`
//! decodes all tables eagerly, so one bad decode loses the RELA/REL/PLT
//! tables too, and `relr_offsets()` flattens the RELR bitmap so the C's
//! per-entry messages cannot be reproduced. (The historic initial-r_offset
//! bug in rz_elf::decode_android_packed is fixed; eager decoding and log
//! parity remain the reasons for this port.) Decoding from the image's own
//! file copy is byte-identical to reading the mapped image: relocation tables
//! live in file-backed PT_LOAD segments and are never relocation targets
//! themselves.
//!
//! C parity: the C declares `= NULL`-initialized locals and assigns them in
//! conditional branches (`struct elf *tls_img = NULL; if (...) tls_img =
//! sym.img;`). Rust requires the initializer to keep definite-assignment
//! happy on the paths that skip the branch, hence the allow.
#![allow(unused_assignments)]

// C parity: hook addresses are written into `ElfW(Word)` relocation targets
// (numeric by nature); the lint's pointer-route cast would bury the C diff.
#![allow(function_casts_as_integer)]

//!
//! Expected cross-module API (ported by the linker_core / linker_sym /
//! linker_load / misc agents; this file is written against these exact
//! signatures):
//!
//! ```ignore
//! // linker_core.rs (linker.h struct loaded_dep / struct tls_indices_data)
//! pub struct TlsIndicesData {
//!     pub indices: *mut *mut crate::tls::TlsIndex, // C `void **indices`
//!     pub count: usize,
//!     pub capacity: usize,
//! }
//! pub struct LoadedDep {
//!     pub img: *mut CsoElf,         // C `struct csoloader_elf *img`
//!     pub tls_indices: TlsIndicesData,
//!     pub is_manual_load: bool,
//!     pub load_bias: usize,
//!     pub map_base: *mut c_void,
//!     pub map_size: usize,
//! }
//! // linker_sym.rs (linker.c 805-869, 1173-1191)
//! pub(crate) struct LinkerSymbolInfo {
//!     pub addr: usize,
//!     pub img: *mut CsoElf,         // NULL like the C
//!     pub tls_indices: *mut TlsIndicesData,
//! }
//! pub(crate) fn find_symbol_in_linker_scope_info(
//!     linker: &Linker, requester: &CsoElf, sym_name: &str) -> LinkerSymbolInfo;
//! pub(crate) fn allocate_tls_index_for_symbol(
//!     img: &CsoElf, tls_indices: &mut TlsIndicesData, dynsym_img: &CsoElf,
//!     sym_idx: usize, addend: u64) -> *mut crate::tls::TlsIndex;
//! // linker_load.rs (linker.c 421-502, CSOLOADER_MAKE_LINKER_HOOKS)
//! pub unsafe extern "C" fn custom_dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
//! pub unsafe extern "C" fn custom_dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
//! pub unsafe extern "C" fn custom_dlclose(handle: *mut c_void) -> c_int;
//! // misc.rs (backtrace-support.c, CSOLOADER_MAKE_LINKER_HOOKS)
//! pub unsafe extern "C" fn custom_dl_iterate_phdr(...) -> c_int;
//! pub unsafe extern "C" fn custom_dladdr(...) -> c_int;
//! ```

use std::ptr;

use rz_elf::arch::GenericReloc;
use rz_elf::{
    sym_bind, ElfImage, APS2_MAGIC, DT_ANDROID_REL, DT_ANDROID_RELA, DT_ANDROID_RELASZ,
    DT_ANDROID_RELRENT, DT_ANDROID_RELR, DT_ANDROID_RELRSZ, DT_ANDROID_RELSZ, DT_RELR,
    DT_RELRSZ, STB_LOCAL, STB_WEAK,
};

use crate::image::CsoElf;
use crate::linker_core::{Linker, LoadedDep, TlsIndicesData};
use crate::linker_sym::{
    allocate_tls_index_for_symbol, find_symbol_in_linker_scope_info, handle_indirect_symbol,
    LinkerSymbolInfo,
};

pub const TAG: &str = rz_common::LOG_TAG;

macro_rules! dlogd {
    ($($arg:tt)*) => {{ rz_common::logd!(TAG, $($arg)*); }};
}
macro_rules! dlogw {
    ($($arg:tt)*) => {{ rz_common::logw!(TAG, $($arg)*); }};
}
macro_rules! dloge {
    ($($arg:tt)*) => {{ rz_common::loge!(TAG, $($arg)*); }};
}

// Dynamic tags consumed by _linker_process_relocations (linker.c 1702-1738).
// The classic DT_* numbers; the Android/RELR ones come from rz_elf.
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_PLTRELSZ: u64 = 2;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_REL: u64 = 17;
const DT_RELSZ: u64 = 18;
const DT_RELENT: u64 = 19;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;

/// PT_DYNAMIC program-header type (elf.h).
const PT_DYNAMIC: u32 = 2;

/// e_machine of riscv (elf.h EM_RISCV); the C compiles a riscv R_GENERIC_*
/// branch too (linker.c 68-78) which rz_elf's classifier does not cover.
const EM_RISCV: u16 = 243;

/// linker.c `CSOLOADER_MAKE_LINKER_HOOKS` (1367-1407). The C build leaves
/// the macro undefined (csoloader/CMakeLists.txt only adds CSOLOADER_DEBUG
/// for Debug), so the dl-family hooks are compiled out — mirrored here.
/// Flip to `true` only if the Rust build adopts the macro.
/// `__tls_get_addr` is hooked ALWAYS (linker.c 1409-1419), regardless.
const MAKE_LINKER_HOOKS: bool = false;

// Relocation group flags (linker.c 1853-1856 / AOSP packed format).
const RELOCATION_GROUPED_BY_INFO_FLAG: u64 = 1;
const RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG: u64 = 2;
const RELOCATION_GROUPED_BY_ADDEND_FLAG: u64 = 4;
const RELOCATION_GROUP_HAS_ADDEND_FLAG: u64 = 8;

/// linker.c `_linker_unified_r` (1266-1271).
///
/// `addend` is the raw table value: for RELA entries the explicit addend
/// (two's-complement bits of `r_addend`), for REL entries 0 (the addend is
/// read from the target word at apply time, linker.c 1818 / 1432).
#[derive(Debug, Clone, Copy)]
struct UnifiedReloc {
    sym_idx: u32,
    rtype: u32,
    offset: u64,
    addend: u64,
}

/// ELF64/ELF32_R_SYM and _R_TYPE (linker.c 98-104). The C decodes `r_info`
/// into `ElfW(Addr)` first, so the 32-bit split truncates to 32 bits.
fn split_r_info(r_info: u64, is_64: bool) -> (u32, u32) {
    if is_64 {
        ((r_info >> 32) as u32, (r_info & 0xffff_ffff) as u32)
    } else {
        let r = r_info as u32;
        (r >> 8, r & 0xff)
    }
}

/// linker.c per-arch R_GENERIC_* mapping (33-90). The C relies on the host
/// arch matching the loaded image (compile-time switch); in-process loading
/// guarantees that, and classifying by the image's own `e_machine` keeps the
/// crate host-testable like the rest of rz_elf.
fn classify_reloc(img: &CsoElf, rtype: u32) -> GenericReloc {
    if img.machine() == EM_RISCV {
        return classify_riscv(rtype);
    }
    // linker.c 1334-1336/1440-1446 handle R_X86_64_32 (10) in the x86_64
    // branch; rz_elf's x86_64 classifier table omits it (its GenericReloc
    // has the variant but no mapping), so map it here instead of LOGF.
    if img.machine() == rz_elf::arch::EM_X86_64 && rtype == 10 {
        return GenericReloc::X86_64_32;
    }
    img.classify(rtype)
}

/// linker.c 68-78 riscv branch. NOTE: the C maps GLOB_DAT and ABSOLUTE to
/// the same number (R_RISCV_64), producing a duplicate case label that would
/// not compile; the ABSOLUTE semantics used here are identical for the
/// RELA-only riscv ABI.
fn classify_riscv(t: u32) -> GenericReloc {
    match t {
        0 => GenericReloc::None, // R_RISCV_NONE
        2 => GenericReloc::Absolute, // R_RISCV_64 (= GLOB_DAT)
        3 => GenericReloc::Relative, // R_RISCV_RELATIVE
        4 => GenericReloc::Copy, // R_RISCV_COPY
        5 => GenericReloc::JumpSlot, // R_RISCV_JUMP_SLOT
        9 => GenericReloc::TlsDtpmod, // R_RISCV_TLS_DTPMOD64
        11 => GenericReloc::TlsDtprel, // R_RISCV_TLS_DTPREL64
        12 => GenericReloc::TlsTprel, // R_RISCV_TLS_TPREL64
        13 => GenericReloc::TlsDesc, // R_RISCV_TLSDESC
        58 => GenericReloc::IRelative, // R_RISCV_IRELATIVE
        other => GenericReloc::Other(other),
    }
}

/// sleb128.c `sleb128_decoder` + `sleb128_decode`: signed LEB128 with the
/// same bit pattern as rz_elf::sleb128_decode. The pure `decode` lets tests
/// exercise the state machine; `decode_or_zero` logs (not aborts — we run
/// inside the zygote) and returns 0 on buffer overrun, matching C release
/// semantics where LOGF only logs.
struct CSleb128<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> CSleb128<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn decode(&mut self) -> crate::Result<u64> {
        let (value, pos) = rz_elf::sleb128_decode(self.buf, self.pos)?;
        self.pos = pos;
        Ok(value)
    }

    fn decode_or_zero(&mut self) -> u64 {
        match self.decode() {
            Ok(v) => v,
            Err(_) => {
                dloge!("Failed to decode SLEB128: buffer overrun, using addend 0");
                0
            }
        }
    }
}

/// One ElfW(Rela) entry: (r_offset, r_info, r_addend). The addend keeps the
/// two's-complement bits exactly like the C's `ElfW(Sxword) -> ElfW(Addr)`
/// truncating assignment (32-bit reads zero-extend into the u64 like the
/// C's u32 `r_addend` field).
fn read_rela_entry(entry: &[u8], is_64: bool) -> (u64, u64, u64) {
    if is_64 {
        let offset = u64::from_le_bytes(entry[0..8].try_into().unwrap());
        let info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        let addend = i64::from_le_bytes(entry[16..24].try_into().unwrap()) as u64;
        (offset, info, addend)
    } else {
        let offset = u32::from_le_bytes(entry[0..4].try_into().unwrap()) as u64;
        let info = u32::from_le_bytes(entry[4..8].try_into().unwrap()) as u64;
        let addend = u32::from_le_bytes(entry[8..12].try_into().unwrap()) as u64;
        (offset, info, addend)
    }
}

/// One ElfW(Rel) entry: (r_offset, r_info). No addend (linker.c 1818).
fn read_rel_entry(entry: &[u8], is_64: bool) -> (u64, u64) {
    if is_64 {
        let offset = u64::from_le_bytes(entry[0..8].try_into().unwrap());
        let info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        (offset, info)
    } else {
        let offset = u32::from_le_bytes(entry[0..4].try_into().unwrap()) as u64;
        let info = u32::from_le_bytes(entry[4..8].try_into().unwrap()) as u64;
        (offset, info)
    }
}

/// File bytes backing a dynamic pointer tag (vaddr → file offset → slice).
/// `None` when the vaddr is not file-backed (malformed input).
fn table_bytes<'a>(elf: &'a ElfImage, vaddr: u64, size: u64) -> Option<&'a [u8]> {
    let off = elf.vaddr_to_file_offset(vaddr)? as usize;
    let end = off.checked_add(size as usize)?;
    elf.raw().get(off..end)
}

/// RELR entry walk in the C's exact structure (1746-1785): even words are
/// explicit offsets, odd words are bitmaps of the next `bits_per_entry - 1`
/// words; `base_offset` accumulates identically. Returns `(offset, direct)`
/// pairs in walk order so the caller can apply and log like the C.
fn decode_relr_entries(entries: &[u8], word_size: usize) -> Vec<(u64, bool)> {
    let bits_per_entry = word_size * 8;
    let relr_count = entries.len() / word_size;
    let mut out = Vec::new();
    let mut base_offset: u64 = 0;

    for i in 0..relr_count {
        let at = i * word_size;
        let entry = if word_size == 8 {
            u64::from_le_bytes(entries[at..at + 8].try_into().unwrap())
        } else {
            u32::from_le_bytes(entries[at..at + 4].try_into().unwrap()) as u64
        };

        if entry & 1 == 0 {
            // INFO: Even entries encode an explicit address
            out.push((entry, true));
            base_offset = entry.wrapping_add(word_size as u64);
            continue;
        }

        // INFO: Odd entries encode a bitmap of up to (bits_per_entry - 1) following words
        let mut bitmap = entry >> 1;
        let mut bit = 0u64;
        while bitmap != 0 && bit < (bits_per_entry - 1) as u64 {
            if bitmap & 1 != 0 {
                out.push((base_offset.wrapping_add(bit * word_size as u64), false));
            }
            bitmap >>= 1;
            bit += 1;
        }

        base_offset = base_offset.wrapping_add((word_size * (bits_per_entry - 1)) as u64);
    }

    out
}

/// C-exact Android packed (APS2) walk (linker.c 1835-1912), including the
/// group log lines (the per-reloc r_info log uses `j`, the group logs `i`,
/// exactly like the C). `apply` consumes each decoded relocation; production
/// applies it, tests collect entries. The caller verifies the APS2 magic and
/// logs "Processing Android ..." first (linker.c 1827-1833).
fn walk_android_packed(
    table: &[u8],
    is_rela: bool,
    is_64: bool,
    apply: &mut dyn FnMut(&UnifiedReloc) -> bool,
) -> bool {
    let packed = &table[4..];
    let mut decoder = CSleb128::new(packed);

    let num_relocs = decoder.decode_or_zero();

    // The first post-count value is the ABSOLUTE initial r_offset
    // (linker.c 1843-1845); group offsets are deltas on top of it.
    let mut unified = UnifiedReloc {
        sym_idx: 0,
        rtype: 0,
        offset: decoder.decode_or_zero(),
        addend: 0,
    };

    let mut i: u64 = 0;
    while i < num_relocs {
        let group_size = decoder.decode_or_zero();
        let group_flags = decoder.decode_or_zero();

        let mut group_r_offset_delta: u64 = 0;

        if group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG != 0 {
            group_r_offset_delta = decoder.decode_or_zero();

            dlogd!("Group {}: Offset delta: {}", i, group_r_offset_delta);
        }

        if group_flags & RELOCATION_GROUPED_BY_INFO_FLAG != 0 {
            let r_info = decoder.decode_or_zero();
            let (sym_idx, rtype) = split_r_info(r_info, is_64);
            unified.sym_idx = sym_idx;
            unified.rtype = rtype;

            dlogd!(
                "Group {}: r_info: {}, sym_idx: {}, type: {}",
                i,
                r_info,
                unified.sym_idx,
                unified.rtype
            );
        }

        let group_flags_reloc = if is_rela {
            group_flags & (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG)
        } else {
            0
        };

        if group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG {
            // INFO: Each relocation has an addend. This is the default
            //       situation with lld's current encoder.
        } else if group_flags_reloc
            == RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG
        {
            unified.addend = unified.addend.wrapping_add(decoder.decode_or_zero());
        } else {
            unified.addend = 0;
        }

        if !is_rela && group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG != 0 {
            dlogw!(
                "REL relocations should not have addends, but found one in group {}",
                i
            );
        }

        for j in 0..group_size {
            if group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG != 0 {
                unified.offset = unified.offset.wrapping_add(group_r_offset_delta);
            } else {
                unified.offset = unified.offset.wrapping_add(decoder.decode_or_zero());
            }
            if group_flags & RELOCATION_GROUPED_BY_INFO_FLAG == 0 {
                let r_info = decoder.decode_or_zero();
                let (sym_idx, rtype) = split_r_info(r_info, is_64);
                unified.sym_idx = sym_idx;
                unified.rtype = rtype;

                dlogd!(
                    "Group {}: r_info: {}, sym_idx: {}, type: {}",
                    j,
                    r_info,
                    unified.sym_idx,
                    unified.rtype
                );
            }

            if is_rela && group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG {
                unified.addend = unified.addend.wrapping_add(decoder.decode_or_zero());
            }

            if !apply(&unified) {
                return false;
            }
        }

        i += group_size;

        dlogd!("Processed group {}: size {}, flags {:#x}", i, group_size, group_flags);
    }

    true
}

/// linker.c `_linker_process_unified_relocation` (1303-1651).
///
/// Writes use unaligned accesses (the C dereferences `ElfW(Addr) *` which is
/// UB for unaligned offsets; the values written are identical).
fn linker_process_unified_relocation(
    linker: &mut Linker,
    dep: &mut LoadedDep,
    r: &UnifiedReloc,
    load_bias: usize,
    is_rela: bool,
) -> bool {
    let img: &CsoElf = unsafe { &*dep.img };
    let target_addr = (load_bias.wrapping_add(r.offset as usize)) as *mut usize;
    let class = classify_reloc(img, r.rtype);

    match class {
        GenericReloc::None => {
            dlogd!(
                "Skipping R_GENERIC_NONE relocation at {:p} in {}",
                target_addr,
                img.path()
            );
        }
        GenericReloc::Copy => {
            dlogw!(
                "R_GENERIC_COPY relocation at {:p} in {}: This relocation type is not supported yet",
                target_addr,
                img.path()
            );
        }
        GenericReloc::IRelative => {
            let resolver = load_bias.wrapping_add(if is_rela {
                r.addend as usize
            } else {
                // SAFETY: target_addr points into the mapped image (linker.c
                // reads the embedded addend the same way).
                unsafe { target_addr.read_unaligned() }
            });
            // SAFETY: write to the mapped image, mirroring the C.
            unsafe {
                target_addr.write_unaligned(handle_indirect_symbol(resolver));
            }

            dlogd!(
                "R_GENERIC_IRELATIVE relocation at {:p} in {}: Resolved to {:#x}",
                target_addr,
                img.path(),
                // SAFETY: re-read of the word just written (the C logs the
                // same dereference).
                unsafe { target_addr.read_unaligned() }
            );
        }
        GenericReloc::Relative => {
            let value = load_bias.wrapping_add(if is_rela {
                r.addend as usize
            } else {
                // SAFETY: embedded addend read, like the C.
                unsafe { target_addr.read_unaligned() }
            });
            // SAFETY: write to the mapped image.
            unsafe {
                target_addr.write_unaligned(value);
            }

            dlogd!(
                "R_GENERIC_RELATIVE relocation at {:p} in {}: Resolved to {:#x}",
                target_addr,
                img.path(),
                value
            );
        }
        GenericReloc::GlobDat
        | GenericReloc::Absolute
        | GenericReloc::JumpSlot
        | GenericReloc::X86_64_32
        | GenericReloc::X86_64_PC32
        | GenericReloc::X86_PC32 => {
            let sym_ent = img.symbol_at(r.sym_idx as usize);
            let sym_name = sym_ent.as_ref().map_or("", |s| s.name.as_str());
            let sym_bind = sym_ent.as_ref().map_or(0, |s| sym_bind(s.info));
            let sym: LinkerSymbolInfo = find_symbol_in_linker_scope_info(linker, img, sym_name);

            if sym.addr == 0 {
                if sym_bind == STB_WEAK {
                    let mut weak_value: usize = 0;
                    if class == GenericReloc::Absolute {
                        weak_value = if is_rela {
                            r.addend as usize
                        } else {
                            // SAFETY: embedded addend read, like the C.
                            unsafe { target_addr.read_unaligned() }
                        };
                    } else if is_rela {
                        weak_value = r.addend as usize;
                    }

                    // SAFETY: write to the mapped image.
                    unsafe {
                        target_addr.write_unaligned(weak_value);
                    }

                    dlogd!(
                        "Weak symbol '{}' unresolved in {}, using fallback value {:#x}",
                        sym_name,
                        img.path(),
                        weak_value
                    );

                    return true;
                }

                dloge!("Symbol '{}' not found for relocation in {}", sym_name, img.path());

                return false;
            }

            /* INFO: If CSOLoader is unloaded, or for whatever reason, isn't in the same memory location, and a
                     library loaded by it calls any of those functions (with the macro defined), it will try
                     to call an address that is no longer valid, resulting in an undefined behavior, which
                     most of the time, in most devices, will result in a segmentation fault. */
            if MAKE_LINKER_HOOKS {
                match sym_name {
                    "dl_iterate_phdr" => {
                        dlogd!("Special case for dl_iterate_phdr: using custom implementation");
                        // SAFETY: write to the mapped image.
                        unsafe {
                            target_addr.write_unaligned(crate::misc::custom_dl_iterate_phdr as usize);
                        }
                        return true;
                    }
                    "dladdr" => {
                        dlogd!("Special case for dladdr: using custom implementation");
                        // SAFETY: write to the mapped image.
                        unsafe {
                            target_addr.write_unaligned(crate::misc::custom_dladdr as usize);
                        }
                        return true;
                    }
                    "dlopen" => {
                        dlogd!("Special case for dlopen: using custom implementation");
                        // SAFETY: write to the mapped image.
                        unsafe {
                            target_addr.write_unaligned(crate::linker_load::custom_dlopen as usize);
                        }
                        return true;
                    }
                    "dlsym" => {
                        dlogd!("Special case for dlsym: using custom implementation");
                        // SAFETY: write to the mapped image.
                        unsafe {
                            target_addr.write_unaligned(crate::linker_load::custom_dlsym as usize);
                        }
                        return true;
                    }
                    "dlclose" => {
                        dlogd!("Special case for dlclose: using custom implementation");
                        // SAFETY: write to the mapped image.
                        unsafe {
                            target_addr.write_unaligned(crate::linker_load::custom_dlclose as usize);
                        }
                        return true;
                    }
                    _ => {}
                }
            }

            /* INFO: While the comment for other hooks is still valid for this one, it is a critical
                     component of the TLS system from CSOLoader, and if not hooked, will also result
                     in improper TLS handling. So, because of that, it will always be hooked,
                     regardless of the CSOLOADER_MAKE_LINKER_HOOKS macro. */
            if sym_name == "__tls_get_addr" {
                dlogd!("Special case for __tls_get_addr: using custom TLS implementation");
                // SAFETY: write to the mapped image.
                unsafe {
                    target_addr.write_unaligned(crate::tls::__tls_get_addr as usize);
                }
                return true;
            }

            match class {
                GenericReloc::GlobDat | GenericReloc::JumpSlot => {
                    let addend: u64 = if is_rela { r.addend } else { 0 };
                    let value = sym.addr.wrapping_add(addend as usize);
                    // SAFETY: write to the mapped image.
                    unsafe {
                        target_addr.write_unaligned(value);
                    }

                    dlogd!(
                        "{} relocation at {:p} in {}: symbol '{}' resolved to {:#x}",
                        if class == GenericReloc::GlobDat {
                            "R_GENERIC_GLOB_DAT"
                        } else {
                            "R_GENERIC_JUMP_SLOT"
                        },
                        target_addr,
                        img.path(),
                        sym_name,
                        value
                    );
                }
                GenericReloc::Absolute => {
                    let addend: u64 = if is_rela {
                        r.addend
                    } else {
                        // SAFETY: embedded addend read, like the C.
                        unsafe { target_addr.read_unaligned() as u64 }
                    };
                    let value = sym.addr.wrapping_add(addend as usize);
                    // SAFETY: write to the mapped image.
                    unsafe {
                        target_addr.write_unaligned(value);
                    }

                    dlogd!(
                        "R_GENERIC_ABSOLUTE relocation at {:p} in {}: symbol '{}' resolved to {:#x}",
                        target_addr,
                        img.path(),
                        sym_name,
                        value
                    );
                }
                GenericReloc::X86_64_32 => {
                    let value = sym.addr.wrapping_add(r.addend as usize);
                    // SAFETY: write to the mapped image (the C writes a full
                    // ElfW(Addr) word here, no 32-bit truncation).
                    unsafe {
                        target_addr.write_unaligned(value);
                    }

                    dlogd!(
                        "R_X86_64_32 relocation at {:p} in {}: symbol '{}' resolved to {:#x}",
                        target_addr,
                        img.path(),
                        sym_name,
                        value
                    );
                }
                GenericReloc::X86_64_PC32 => {
                    let value = sym
                        .addr
                        .wrapping_add(r.addend as usize)
                        .wrapping_sub(target_addr as usize);
                    // SAFETY: write to the mapped image.
                    unsafe {
                        target_addr.write_unaligned(value);
                    }

                    dlogd!(
                        "R_X86_64_PC32 relocation at {:p} in {}: symbol '{}' resolved to {:#x}",
                        target_addr,
                        img.path(),
                        sym_name,
                        value
                    );
                }
                GenericReloc::X86_PC32 => {
                    let addend: u64 = if is_rela {
                        r.addend
                    } else {
                        // SAFETY: embedded addend read, like the C.
                        unsafe { target_addr.read_unaligned() as u64 }
                    };
                    let value = sym
                        .addr
                        .wrapping_add(addend as usize)
                        .wrapping_sub(target_addr as usize);
                    // SAFETY: write to the mapped image.
                    unsafe {
                        target_addr.write_unaligned(value);
                    }

                    dlogd!(
                        "R_386_PC32 relocation at {:p} in {}: symbol '{}' resolved to {:#x}",
                        target_addr,
                        img.path(),
                        sym_name,
                        value
                    );
                }
                _ => unreachable!("outer match arm already covers every symbol-group class"),
            }
        }
        GenericReloc::TlsDtpmod => {
            let mut tls_img: *mut CsoElf = ptr::null_mut();
            let mut module_id: usize = 0;

            if r.sym_idx == 0 {
                // INFO: If not referenced, assume current module
                tls_img = img as *const CsoElf as *mut CsoElf;
            } else {
                let sym_ent = img.symbol_at(r.sym_idx as usize);
                let bind = sym_ent.as_ref().map_or(0, |s| sym_bind(s.info));

                if bind == STB_LOCAL {
                    dloge!(
                        "Unexpected TLS reference to STB_LOCAL symbol in {}",
                        img.path()
                    );
                    return false;
                }

                let sym_name = sym_ent.as_ref().map_or("", |s| s.name.as_str());
                let sym = find_symbol_in_linker_scope_info(linker, img, sym_name);

                if sym.img.is_null() && bind != STB_WEAK {
                    dloge!("TLS symbol '{}' not found in {}", sym_name, img.path());
                    return false;
                }

                // INFO: NULLs are allowed for unresolved WEAKs
                tls_img = sym.img;
            }

            // SAFETY: tls_img is a live image pointer (dep's own image or a
            // linker-scope one).
            if !tls_img.is_null() && unsafe { (*tls_img).tls_segment().is_some() } {
                module_id = unsafe { (*tls_img).tls_mod_id() };
            }
            // SAFETY: write to the mapped image.
            unsafe {
                target_addr.write_unaligned(module_id);
            }

            dlogd!(
                "TLS: R_GENERIC_TLS_DTPMOD at {:p} in {}: module_id={}",
                target_addr,
                img.path(),
                module_id
            );
        }
        GenericReloc::TlsDtprel => {
            let sym_ent = img.symbol_at(r.sym_idx as usize);
            let offset = sym_ent
                .as_ref()
                .map_or(0, |s| s.value)
                .wrapping_add(r.addend);
            // SAFETY: write to the mapped image.
            unsafe {
                target_addr.write_unaligned(offset as usize);
            }

            dlogd!(
                "TLS: R_GENERIC_TLS_DTPREL at {:p} in {}: offset={}",
                target_addr,
                img.path(),
                offset
            );
        }
        GenericReloc::TlsDesc => {
            let mut tls_img: *mut CsoElf = ptr::null_mut();
            let mut target_tls_indices: *mut TlsIndicesData = ptr::null_mut();
            let desc = target_addr;

            if r.sym_idx == 0 {
                // INFO: If not referenced, assume current module
                tls_img = img as *const CsoElf as *mut CsoElf;
                target_tls_indices = &mut dep.tls_indices as *mut TlsIndicesData;
            } else {
                let sym_ent = img.symbol_at(r.sym_idx as usize);
                let bind = sym_ent.as_ref().map_or(0, |s| sym_bind(s.info));

                if bind == STB_LOCAL {
                    dloge!(
                        "Unexpected TLS reference to STB_LOCAL symbol in {}",
                        img.path()
                    );
                    return false;
                }

                let sym_name = sym_ent.as_ref().map_or("", |s| s.name.as_str());
                let sym = find_symbol_in_linker_scope_info(linker, img, sym_name);
                if sym.img.is_null() {
                    if bind != STB_WEAK {
                        dloge!(
                            "TLS symbol '{}' not found for TLSDESC in {}",
                            sym_name,
                            img.path()
                        );
                        return false;
                    }

                    // INFO: Unresolved weak. Setup resolver that returns -tpidr + addend
                    //       so result is NULL + addend
                    // SAFETY: writes to the mapped image (the C `break`s out
                    // of the switch here and returns true at the end).
                    unsafe {
                        desc.write_unaligned(crate::tls::unresolved_weak_resolver_addr());
                        desc.add(1).write_unaligned(r.addend as usize);
                    }

                    dlogd!(
                        "TLS: R_GENERIC_TLSDESC at {:p} in {}: unresolved weak, addend={}",
                        target_addr,
                        img.path(),
                        r.addend
                    );

                    return true;
                }

                tls_img = sym.img;
                target_tls_indices = sym.tls_indices;
            }

            // SAFETY: tls_img is a live image pointer.
            if tls_img.is_null() || unsafe { (*tls_img).tls_segment().is_none() } {
                dloge!(
                    "TLSDESC refers to module with no TLS segment in {}",
                    img.path()
                );
                return false;
            }

            // SAFETY: tls_img is non-null and live here.
            let ti = allocate_tls_index_for_symbol(
                unsafe { &*tls_img },
                unsafe { &mut *target_tls_indices },
                img,
                r.sym_idx as usize,
                r.addend,
            );
            if ti.is_null() {
                dloge!("Failed to allocate tls_index for TLSDESC in {}", img.path());
                return false;
            }

            // SAFETY: writes to the mapped image.
            unsafe {
                desc.write_unaligned(crate::tls::dynamic_tls_resolver_addr());
                desc.add(1).write_unaligned(ti as usize);
            }

            // SAFETY: ti is the allocation returned above.
            let (ti_mod, ti_off) = unsafe { ((*ti).module, (*ti).offset) };

            dlogd!(
                "TLS: R_GENERIC_TLSDESC at {:p} in {}: resolver={:#x}, ti={{mod={},off={}}}",
                target_addr,
                img.path(),
                crate::tls::dynamic_tls_resolver_addr(),
                ti_mod,
                ti_off
            );
        }
        GenericReloc::TlsTprel => {
            // AOSP INFO: TLS symbol in dlopened library referenced using IE access model.
            //
            // INFO: Since CSOLoader only handles dlopen'd libraries, we cannot support
            //       true static TLS. However, we can emulate by computing offset from tpidr.
            let mut tls_img: *mut CsoElf = ptr::null_mut();

            if r.sym_idx == 0 {
                // INFO: If not referenced, assume current module
                tls_img = img as *const CsoElf as *mut CsoElf;
            } else {
                let sym_ent = img.symbol_at(r.sym_idx as usize);
                let bind = sym_ent.as_ref().map_or(0, |s| sym_bind(s.info));

                if bind == STB_LOCAL {
                    dloge!(
                        "Unexpected TLS reference to STB_LOCAL symbol in {}",
                        img.path()
                    );
                    return false;
                }

                let sym_name = sym_ent.as_ref().map_or("", |s| s.name.as_str());
                let sym = find_symbol_in_linker_scope_info(linker, img, sym_name);
                if sym.img.is_null() {
                    if bind != STB_WEAK {
                        dloge!("TLS symbol '{}' not found for TPREL in {}", sym_name, img.path());
                        return false;
                    }

                    // INFO: Unresolved weak. tpoff=0 so &symbol resolves to tpidr (thread pointer)
                    // SAFETY: write to the mapped image.
                    unsafe {
                        target_addr.write_unaligned(0);
                    }

                    dlogd!(
                        "TLS: R_GENERIC_TLS_TPREL at {:p} in {}: unresolved weak, tpoff=0",
                        target_addr,
                        img.path()
                    );

                    return true;
                }

                tls_img = sym.img;
            }

            // SAFETY: tls_img is a live image pointer.
            if tls_img.is_null() || unsafe { (*tls_img).tls_segment().is_none() } {
                dloge!(
                    "TLS_TPREL refers to module with no TLS segment in {}",
                    img.path()
                );
                return false;
            }

            let sym_ent = img.symbol_at(r.sym_idx as usize);
            // SAFETY: tls_img is non-null and live here.
            let mut ti = crate::tls::TlsIndex {
                module: unsafe { (*tls_img).tls_mod_id() },
                offset: sym_ent
                    .as_ref()
                    .map_or(0, |s| s.value)
                    .wrapping_add(r.addend) as usize,
            };

            // SAFETY: TLS index pointer valid for the duration of the call.
            let var_addr =
                unsafe { crate::tls::__tls_get_addr(&mut ti as *mut crate::tls::TlsIndex) };
            if var_addr.is_null() {
                dloge!("TLS: Failed to get TLS address for TPREL in {}", img.path());
                return false;
            }

            // INFO: Store offset from tpidr so that tpidr + offset = var_addr
            let tpidr = crate::tls::get_tpidr();
            let tpoff = (var_addr as usize).wrapping_sub(tpidr);
            // SAFETY: write to the mapped image.
            unsafe {
                target_addr.write_unaligned(tpoff);
            }

            dlogd!(
                "TLS: R_GENERIC_TLS_TPREL at {:p} in {}: tpoff={:#x} (addr={:p}, tpidr={:#x})",
                target_addr,
                img.path(),
                tpoff,
                var_addr,
                tpidr
            );
        }
        GenericReloc::Other(t) => {
            // Unsupported relocation: fail this relocation (and the module
            // load) rather than writing garbage — but never abort the zygote.
            dloge!(
                "Unsupported relocation type: {} in {}.\n - Symbol index: {}\n - Symbol name: {}\n - Offset: {:p}\n - Addend: {:#x}",
                t,
                img.path(),
                r.sym_idx,
                img.symbol_at(r.sym_idx as usize)
                    .as_ref()
                    .map_or("", |s| s.name.as_str()),
                target_addr,
                r.addend
            );
            return false;
        }
    }

    true
}

/// linker.c `_linker_process_relocations` (1653-1954).
pub fn linker_process_relocations(linker: &mut Linker, dep: &mut LoadedDep) -> bool {
    let img_ptr = dep.img;
    let img = unsafe { &*img_ptr };
    let load_bias = img.load_bias();
    // Copy the path once: the relocation loops reborrow `dep` mutably.
    let path = img.path().to_string();

    // The C walks the mapped dynamic section; the parsed file copy is
    // byte-identical for the file-backed PT_LOAD segments that hold the
    // relocation tables (and using the image's own copy avoids a disk
    // re-read, so deleted/fd-based files keep working).
    let elf = img.image();
    let is_64 = elf.is_64();
    let word_size = if is_64 { 8 } else { 4 };

    // linker.c 1653-1668: bail out early only when there is no PT_DYNAMIC
    // segment at all. A PT_DYNAMIC that is present but empty falls through
    // to the DT_SYMTAB error below (the C fails closed).
    if !elf
        .all_segments()
        .iter()
        .any(|(p_type, _)| *p_type == PT_DYNAMIC)
    {
        dlogd!("No DYNAMIC section found in {}", path);
        return true;
    }

    // Dynamic scan (linker.c 1702-1738); only the DT_ANDROID_RELRENT check
    // has an observable effect beyond collecting the table locations.
    if let Some(rent) = elf.dynamic_find(DT_ANDROID_RELRENT) {
        if rent != word_size as u64 {
            dloge!("Unsupported DT_ANDROID_RELRENT size {} in {}", rent, path);
        }
    }

    if elf.dynamic_find(DT_SYMTAB).is_none() || elf.dynamic_find(DT_STRTAB).is_none() {
        dloge!("Could not find DT_SYMTAB or DT_STRTAB in {}", path);
        return false;
    }

    // 1. RELR first (linker.c 1746-1785): *target += load_bias. The C maps
    // both DT_RELR and DT_ANDROID_RELR onto one variable (last tag wins); lld
    // emits only one of them, so prefer-DT_RELR matches every real input.
    let relr_vaddr = elf.dynamic_find(DT_RELR).or_else(|| elf.dynamic_find(DT_ANDROID_RELR));
    if let Some(relr_vaddr) = relr_vaddr {
        let relr_sz = elf
            .dynamic_find(DT_RELRSZ)
            .or_else(|| elf.dynamic_find(DT_ANDROID_RELRSZ))
            .unwrap_or(0) as usize;
        let relr_bytes = table_bytes(&elf, relr_vaddr, relr_sz as u64).unwrap_or(&[]);

        dlogd!("Processing RELR relocations for {}", path);
        for (reloc_offset, direct) in decode_relr_entries(relr_bytes, word_size) {
            let target_addr = (load_bias.wrapping_add(reloc_offset as usize)) as *mut usize;
            // SAFETY: RELR targets point into the mapped image.
            unsafe {
                target_addr.write_unaligned(target_addr.read_unaligned().wrapping_add(load_bias));
            }

            if direct {
                dlogd!("RELR direct relocation at offset {:#x}", reloc_offset);
            } else {
                dlogd!("RELR bitmap relocation at offset {:#x}", reloc_offset);
            }
        }
    }

    // 2. DT_RELA then DT_REL (linker.c 1787-1823) — both processed when both
    // present, exactly like the C (no else between them).
    if let Some(rela_vaddr) = elf.dynamic_find(DT_RELA) {
        dlogd!("Processing RELA relocations for {}", path);

        let rela_sz = elf.dynamic_find(DT_RELASZ).unwrap_or(0);
        let mut rela_ent = elf.dynamic_find(DT_RELAENT).unwrap_or(0);
        if rela_ent == 0 {
            rela_ent = if is_64 { 24 } else { 12 };
        }
        let bytes = table_bytes(&elf, rela_vaddr, rela_sz).unwrap_or(&[]);
        let entsize = if is_64 { 24 } else { 12 };

        for i in 0..(rela_sz / rela_ent) {
            let at = i as usize * entsize;
            let Some(entry) = bytes.get(at..at + entsize) else { break };
            let (offset, info, addend) = read_rela_entry(entry, is_64);
            let (sym_idx, rtype) = split_r_info(info, is_64);
            let unified = UnifiedReloc {
                sym_idx,
                rtype,
                offset,
                addend,
            };

            if !linker_process_unified_relocation(linker, dep, &unified, load_bias, true) {
                return false;
            }
        }
    }

    if let Some(rel_vaddr) = elf.dynamic_find(DT_REL) {
        dlogd!("Processing REL relocations for {}", path);

        let rel_sz = elf.dynamic_find(DT_RELSZ).unwrap_or(0);
        let mut rel_ent = elf.dynamic_find(DT_RELENT).unwrap_or(0);
        if rel_ent == 0 {
            rel_ent = if is_64 { 16 } else { 8 };
        }
        let bytes = table_bytes(&elf, rel_vaddr, rel_sz).unwrap_or(&[]);
        let entsize = if is_64 { 16 } else { 8 };

        for i in 0..(rel_sz / rel_ent) {
            let at = i as usize * entsize;
            let Some(entry) = bytes.get(at..at + entsize) else { break };
            let (offset, info) = read_rel_entry(entry, is_64);
            let (sym_idx, rtype) = split_r_info(info, is_64);
            let unified = UnifiedReloc {
                sym_idx,
                rtype,
                offset,
                addend: 0,
            };

            if !linker_process_unified_relocation(linker, dep, &unified, load_bias, false) {
                return false;
            }
        }
    }

    // 3. Android packed relocations (linker.c 1825-1914). NOTE: the C maps
    // DT_ANDROID_RELA and DT_ANDROID_REL onto one variable and DT_ANDROID_REL
    // does NOT reset is_rela; lld never emits both, so prefer-RELA matches
    // every real input.
    let android_vaddr =
        elf.dynamic_find(DT_ANDROID_RELA).or_else(|| elf.dynamic_find(DT_ANDROID_REL));
    if let Some(android_vaddr) = android_vaddr {
        let is_rela = elf.dynamic_find(DT_ANDROID_RELA).is_some();
        let android_sz = if is_rela {
            elf.dynamic_find(DT_ANDROID_RELASZ)
        } else {
            elf.dynamic_find(DT_ANDROID_RELSZ)
        }
        .unwrap_or(0) as usize;
        let table = table_bytes(&elf, android_vaddr, android_sz as u64).unwrap_or(&[]);

        dlogd!(
            "Processing Android {} relocations for {}",
            if is_rela { "RELA" } else { "REL" },
            path
        );

        if table.len() < 4 || &table[..4] != APS2_MAGIC {
            dloge!(
                "Invalid Android {} magic in {}",
                if is_rela { "RELA" } else { "REL" },
                path
            );
            return false;
        }

        if !walk_android_packed(table, is_rela, is_64, &mut |r| {
            linker_process_unified_relocation(linker, dep, r, load_bias, is_rela)
        }) {
            return false;
        }
    }

    // 4. PLT relocations (linker.c 1916-1951).
    if let Some(jmprel_vaddr) = elf.dynamic_find(DT_JMPREL) {
        let jmprel_sz = elf.dynamic_find(DT_PLTRELSZ).unwrap_or(0);
        let is_rela = elf.dynamic_find(DT_PLTREL) == Some(DT_RELA);

        dlogd!(
            "Processing {} PLT relocations for {}",
            if is_rela { "RELA" } else { "REL" },
            path
        );

        let entsize: usize = if is_rela {
            if is_64 { 24 } else { 12 }
        } else {
            if is_64 { 16 } else { 8 }
        };
        let bytes = table_bytes(&elf, jmprel_vaddr, jmprel_sz).unwrap_or(&[]);
        let count = (jmprel_sz / entsize as u64) as usize;

        for i in 0..count {
            let at = i * entsize;
            let Some(entry) = bytes.get(at..at + entsize) else { break };

            let unified = if is_rela {
                let (offset, info, addend) = read_rela_entry(entry, is_64);
                let (sym_idx, rtype) = split_r_info(info, is_64);
                UnifiedReloc {
                    sym_idx,
                    rtype,
                    offset,
                    addend,
                }
            } else {
                let (offset, info) = read_rel_entry(entry, is_64);
                let (sym_idx, rtype) = split_r_info(info, is_64);
                UnifiedReloc {
                    sym_idx,
                    rtype,
                    offset,
                    addend: 0,
                }
            };

            dlogd!("Processing PLT relocation of type {} for {}", unified.rtype, path);

            if !linker_process_unified_relocation(linker, dep, &unified, load_bias, is_rela) {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standard SLEB128 encoder (mirrors lld's encodeSLEB128).
    fn push_sleb(out: &mut Vec<u8>, value: i64) {
        let mut v = value;
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0) {
                out.push(byte);
                break;
            }
            byte |= 0x80;
            out.push(byte);
        }
    }

    #[test]
    fn sleb128_signed_roundtrip() {
        for v in [0i64, 1, -1, 63, 64, -64, -65, 624485, -123456, i64::MIN, i64::MAX] {
            let mut buf = Vec::new();
            push_sleb(&mut buf, v);

            let mut d = CSleb128::new(&buf);
            assert_eq!(d.decode().unwrap(), v as u64);
            // One byte past the end: overrun like the C's buffer check.
            assert!(d.decode().is_err());
        }
    }

    #[test]
    fn r_info_split_matches_elf_macros() {
        assert_eq!(split_r_info(0x0000_0003_0000_0401, true), (3, 1025));
        assert_eq!(split_r_info(0x0000_0502, false), (5, 2));
    }

    /// APS2 stream byte-identical to lld's `AndroidPackedRelocationSection`
    /// writeTo for a 64-bit RELA table:
    ///
    /// - R_AARCH64_RELATIVE (type 1027, sym 0) at 0x108 (+0x30)
    /// - R_AARCH64_RELATIVE at 0x110 (+0x40)
    /// - R_AARCH64_GLOB_DAT (type 1025, sym 3) at 0x200 (+0)
    ///
    /// lld writes num_relocs, then the initial r_offset (always 0, "the
    /// first relocation group will perform the initial adjustment"), then the
    /// ungrouped relatives (GROUPED_BY_INFO | HAS_ADDEND) followed by the
    /// ungrouped non-relative (HAS_ADDEND). This is the fixture a dump of a
    /// real Android .so would slot into; it was reproduced from lld's
    /// SyntheticSections.cpp because no device/lib with APS2 was available
    /// on this host.
    #[test]
    fn android_packed_decodes_lld_style_rela_stream() {
        let mut t = b"APS2".to_vec();
        push_sleb(&mut t, 3); // num_relocs
        push_sleb(&mut t, 0); // initial r_offset (lld: 0)
        // Ungrouped relatives (< 8 in a row): GROUPED_BY_INFO | HAS_ADDEND.
        push_sleb(&mut t, 2);
        push_sleb(&mut t, RELOCATION_GROUPED_BY_INFO_FLAG as i64 | RELOCATION_GROUP_HAS_ADDEND_FLAG as i64);
        push_sleb(&mut t, 1027); // R_AARCH64_RELATIVE
        push_sleb(&mut t, 0x108); // offset delta from 0
        push_sleb(&mut t, 0x30); // addend delta from 0
        push_sleb(&mut t, 8); // next offset delta
        push_sleb(&mut t, 0x10); // next addend delta
        // Ungrouped non-relative: HAS_ADDEND.
        push_sleb(&mut t, 1);
        push_sleb(&mut t, RELOCATION_GROUP_HAS_ADDEND_FLAG as i64);
        push_sleb(&mut t, 0xf0); // offset delta from 0x110
        push_sleb(&mut t, (3i64 << 32) | 1025); // r_info
        push_sleb(&mut t, -0x40); // addend delta (addend accumulator carries over groups)

        let mut got = Vec::new();
        assert!(walk_android_packed(&t, true, true, &mut |r| {
            got.push(*r);
            true
        }));

        assert_eq!(got.len(), 3);
        assert_eq!(got[0].offset, 0x108);
        assert_eq!(got[0].sym_idx, 0);
        assert_eq!(got[0].rtype, 1027);
        assert_eq!(got[0].addend, 0x30);
        assert_eq!(got[1].offset, 0x110);
        assert_eq!(got[1].sym_idx, 0);
        assert_eq!(got[1].rtype, 1027);
        assert_eq!(got[1].addend, 0x40);
        assert_eq!(got[2].offset, 0x200);
        assert_eq!(got[2].sym_idx, 3);
        assert_eq!(got[2].rtype, 1025);
        assert_eq!(got[2].addend, 0);
    }

    /// The audit's diverging case, kept as this walker's own regression: the
    /// C decodes the first post-count value as an ABSOLUTE initial r_offset
    /// (linker.c 1843-1845) and every group field is a delta on top of it.
    /// lld emits 0 there; non-lld packers emit nonzero and the offsets below
    /// prove the accumulator starts from the absolute value.
    #[test]
    fn android_packed_decodes_absolute_nonzero_initial_offset() {
        let mut t = b"APS2".to_vec();
        push_sleb(&mut t, 2); // num_relocs
        push_sleb(&mut t, 0x3e0); // ABSOLUTE initial r_offset
        push_sleb(&mut t, 2); // group size
        push_sleb(&mut t, 0); // flags: nothing grouped
        push_sleb(&mut t, 8); // offset delta
        push_sleb(&mut t, (1i64 << 32) | 1025); // r_info (sym 1, type 1025)
        push_sleb(&mut t, 0x10); // offset delta
        push_sleb(&mut t, (2i64 << 32) | 1025); // r_info (sym 2, type 1025)

        let mut got = Vec::new();
        assert!(walk_android_packed(&t, true, true, &mut |r| {
            got.push(*r);
            true
        }));

        assert_eq!(got.len(), 2);
        assert_eq!(got[0].offset, 0x3e8);
        assert_eq!(got[0].sym_idx, 1);
        assert_eq!(got[0].rtype, 1025);
        assert_eq!(got[1].offset, 0x3f8);
        assert_eq!(got[1].sym_idx, 2);
        assert_eq!(got[1].rtype, 1025);
    }

    /// GROUPED_BY_ADDEND accumulates across groups: the C never resets
    /// r_addend unless the flags demand it (linker.c 1880-1883).
    #[test]
    fn android_packed_grouped_addend_accumulates_across_groups() {
        let flags = RELOCATION_GROUPED_BY_INFO_FLAG
            | RELOCATION_GROUPED_BY_ADDEND_FLAG
            | RELOCATION_GROUP_HAS_ADDEND_FLAG;

        let mut t = b"APS2".to_vec();
        push_sleb(&mut t, 2); // num_relocs
        push_sleb(&mut t, 0x200); // initial r_offset
        push_sleb(&mut t, 1); // group size
        push_sleb(&mut t, flags as i64);
        push_sleb(&mut t, 1027); // grouped r_info
        push_sleb(&mut t, 0x20); // group addend delta
        push_sleb(&mut t, 8); // offset delta
        push_sleb(&mut t, 1); // group size
        push_sleb(&mut t, flags as i64);
        push_sleb(&mut t, 1027); // grouped r_info
        push_sleb(&mut t, 0x10); // group addend delta (carries 0x20 -> 0x30)
        push_sleb(&mut t, 0x10); // offset delta

        let mut got = Vec::new();
        assert!(walk_android_packed(&t, true, true, &mut |r| {
            got.push(*r);
            true
        }));

        assert_eq!(got.len(), 2);
        assert_eq!(got[0].offset, 0x208);
        assert_eq!(got[0].rtype, 1027);
        assert_eq!(got[0].addend, 0x20);
        assert_eq!(got[1].offset, 0x218);
        assert_eq!(got[1].rtype, 1027);
        assert_eq!(got[1].addend, 0x30);
    }

    /// REL (32-bit) table with grouped r_info: no addends, 32-bit
    /// ELF32_R_SYM / ELF32_R_TYPE split.
    #[test]
    fn android_packed_rel_table_32bit_info_split() {
        let mut t = b"APS2".to_vec();
        push_sleb(&mut t, 2); // num_relocs
        push_sleb(&mut t, 0); // initial r_offset
        push_sleb(&mut t, 2); // group size
        push_sleb(&mut t, RELOCATION_GROUPED_BY_INFO_FLAG as i64);
        push_sleb(&mut t, (5 << 8) | 2); // 32-bit r_info: sym 5, type 2
        push_sleb(&mut t, 0x10); // offset delta
        push_sleb(&mut t, 0x20); // offset delta

        let mut got = Vec::new();
        assert!(walk_android_packed(&t, false, false, &mut |r| {
            got.push(*r);
            true
        }));

        assert_eq!(got.len(), 2);
        assert_eq!(got[0].offset, 0x10);
        assert_eq!(got[0].sym_idx, 5);
        assert_eq!(got[0].rtype, 2);
        assert_eq!(got[0].addend, 0);
        assert_eq!(got[1].offset, 0x30);
        assert_eq!(got[1].sym_idx, 5);
        assert_eq!(got[1].rtype, 2);
        assert_eq!(got[1].addend, 0);
    }

    /// RELR: even word = direct offset, odd word = bitmap over the next
    /// `bits_per_entry - 1` words; base_offset advances identically to the C
    /// (linker.c 1746-1785).
    #[test]
    fn relr_walk_matches_c_structure() {
        let words = [0x108u64, 7, 0x300];
        let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();

        assert_eq!(
            decode_relr_entries(&bytes, 8),
            vec![(0x108, true), (0x110, false), (0x118, false), (0x300, true)]
        );
    }
}
