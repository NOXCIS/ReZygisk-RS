//! PLTI: PLT/GOT hooking inside the current process.
//!
//! Hooks function calls by patching the Global Offset Table (GOT) entries
//! that the Procedure Linkage Table (PLT) stubs indirect through. Works on
//! any mapped ELF image — filesystem-backed, memfd-backed, or csoloader-loaded.
//!
//! # Key concepts
//! - `bias_addr = base_addr - load0.p_vaddr`: the runtime load bias
//! - GOT entries hold runtime addresses; PLT stubs jump through them
//! - Hooking replaces the GOT entry with a callback, saving the original
//!
//! # Design
//! Parses ELF headers directly from the mapped image (no filesystem access),
//! using `rz_elf` for parsing. GOT writes use `mprotect`/`mremap` to handle
//! read-only and RELRO-protected pages.

#![allow(clippy::missing_safety_doc)]

use std::ffi::CStr;
use std::ops::Range;
use std::ptr::NonNull;

// ---------------------------------------------------------------------------
// MappedElf: bounds-checked access to memory-mapped ELF images
// ---------------------------------------------------------------------------

/// Safe abstraction for accessing memory-mapped ELF images with bounds checking.
///
/// All accesses go through methods that verify the requested range fits within
/// the mapped region, preventing out-of-bounds reads on malformed ELF files.
pub struct MappedElf {
    base: NonNull<u8>,
    len: usize,
}

impl MappedElf {
    /// Create a MappedElf from a base pointer and length.
    ///
    /// # Safety
    /// - `base` must point to a valid, readable memory region of at least `len` bytes.
    /// - The memory must remain valid for the lifetime of the MappedElf.
    pub const unsafe fn new(base: NonNull<u8>, len: usize) -> Self {
        Self { base, len }
    }

    /// Create a MappedElf from a raw address and length.
    ///
    /// Returns None if the address is null.
    ///
    /// # Safety
    /// - The address must point to valid, readable memory of at least `len` bytes.
    pub unsafe fn from_raw(base: usize, len: usize) -> Option<Self> {
        NonNull::new(base as *mut u8).map(|base| Self { base, len })
    }

    /// The base address of the mapped region.
    pub fn base(&self) -> usize {
        self.base.as_ptr() as usize
    }

    /// The length of the mapped region in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the mapped region is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Get a slice of the mapped region, with bounds checking.
    ///
    /// Returns None if the range extends beyond the mapped region.
    pub fn slice(&self, range: Range<usize>) -> Option<&[u8]> {
        if range.start <= range.end && range.end <= self.len {
            Some(unsafe {
                std::slice::from_raw_parts(self.base.as_ptr().add(range.start), range.len())
            })
        } else {
            None
        }
    }

    /// Get a pointer to an offset within the mapped region, with bounds checking.
    ///
    /// Returns None if offset + size would exceed the mapped region.
    pub fn ptr_at(&self, offset: usize, size: usize) -> Option<*const u8> {
        if offset.checked_add(size).map_or(false, |end| end <= self.len) {
            Some(unsafe { self.base.as_ptr().add(offset) })
        } else {
            None
        }
    }

    /// Read a value of type T at the given offset, with bounds checking.
    ///
    /// Returns None if the offset + size_of::<T>() would exceed the mapped region.
    ///
    /// # Safety
    /// The memory at offset must be properly aligned for T and contain a valid T.
    pub unsafe fn read_at<T: Copy>(&self, offset: usize) -> Option<T> {
        self.ptr_at(offset, std::mem::size_of::<T>())
            .map(|ptr| unsafe { (ptr as *const T).read_unaligned() })
    }
}

// ---------------------------------------------------------------------------
// ProtectedPage: RAII wrapper for mprotect sequences
// ---------------------------------------------------------------------------

/// RAII wrapper for temporarily changing memory protection.
///
/// Automatically restores the original protection on drop, preventing
/// pages from being left writable after a GOT write sequence.
pub struct ProtectedPage {
    addr: *mut std::ffi::c_void,
    len: usize,
    restore_prot: i32,
}

impl ProtectedPage {
    /// Make a page range writable, returning a guard that restores the
    /// original protection on drop.
    ///
    /// # Safety
    /// - `addr` must be page-aligned.
    /// - The memory range must be valid for the current process.
    /// - `original_prot` must be the actual current protection of the pages.
    pub unsafe fn make_writable(
        addr: *mut std::ffi::c_void,
        len: usize,
        original_prot: i32,
    ) -> std::io::Result<Self> {
        let new_prot = original_prot | libc::PROT_WRITE;
        // SAFETY: Caller guarantees addr is page-aligned and the range is valid
        if unsafe { libc::mprotect(addr, len, new_prot) } == -1 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            addr,
            len,
            restore_prot: original_prot,
        })
    }

    /// Create a ProtectedPage guard without changing protection.
    ///
    /// Useful when the page is already writable but you want to ensure
    /// protection is restored on all exit paths.
    pub const fn already_writable(
        addr: *mut std::ffi::c_void,
        len: usize,
        restore_prot: i32,
    ) -> Self {
        Self {
            addr,
            len,
            restore_prot,
        }
    }

    /// Prevent the protection from being restored on drop.
    ///
    /// Use this when the write failed and you don't want to touch the
    /// page protections at all.
    pub fn forget(self) {
        std::mem::forget(self);
    }
}

impl Drop for ProtectedPage {
    fn drop(&mut self) {
        unsafe {
            libc::mprotect(self.addr, self.len, self.restore_prot);
        }
    }
}

pub const TAG: &str = rz_common::LOG_TAG;

macro_rules! dlogd {
    ($($arg:tt)*) => {{ rz_common::logd!(TAG, $($arg)*); }};
}
macro_rules! dloge {
    ($($arg:tt)*) => {{ rz_common::loge!(TAG, $($arg)*); }};
}

// Relocation families are classified through rz_elf::arch::generic_reloc_type
// (the per-arch ELF_R_GENERIC_* sets of PLTI's elf_util.c): JUMP_SLOT for the
// PLT table, ABS + GLOB_DAT for the non-PLT tables.

// PF_* / PROT_* bits (libc lacks the PF_ constants on Android).
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

// ET_* (elf_util.c checks; the Android libc crate doesn't export them).
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

// PT_DYNAMIC / DT_* tags for the elfutil_init gates in `add_manual_lib`
// (elf_util.c 99-113, 148-159, 161-165, 265-272; libc doesn't export them).
const PT_DYNAMIC: u32 = 2;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_JMPREL: u64 = 23;
const DT_REL: u64 = 17;
const DT_RELA: u64 = 7;

const PROT_READ: i32 = libc::PROT_READ;
const PROT_WRITE: i32 = libc::PROT_WRITE;
const PROT_EXEC: i32 = libc::PROT_EXEC;

// MREMAP_* bits and the call itself: libc declares them for gnu/musl only.
// Bionic ships the same symbol (variadic there; integer-only call sites are
// ABI-equivalent declared fixed), so Android gets a local declaration.
#[cfg(target_os = "android")]
mod mremap {
    pub const MAYMOVE: libc::c_int = 1;
    pub const FIXED: libc::c_int = 2;

    unsafe extern "C" {
        pub fn mremap(
            old_address: *mut libc::c_void,
            old_size: libc::size_t,
            new_size: libc::size_t,
            flags: libc::c_int,
            new_address: *mut libc::c_void,
        ) -> *mut libc::c_void;
    }
}

/// The only mremap form this crate uses (VMA stash/restore):
/// `mremap(old, len, len, MREMAP_FIXED | MREMAP_MAYMOVE, new)`.
unsafe fn mremap_relocate(
    old_addr: *mut libc::c_void,
    len: usize,
    new_addr: *mut libc::c_void,
) -> *mut libc::c_void {
    #[cfg(target_os = "android")]
    unsafe {
        mremap::mremap(old_addr, len, len, mremap::MAYMOVE | mremap::FIXED, new_addr)
    }
    #[cfg(not(target_os = "android"))]
    unsafe {
        libc::mremap(
            old_addr,
            len,
            len,
            libc::MREMAP_FIXED | libc::MREMAP_MAYMOVE,
            new_addr,
        )
    }
}

// ---------------------------------------------------------------------------
// Pure ELF helpers (host-testable): bias/protection/VMA/PLT discovery.
// ---------------------------------------------------------------------------

/// `elfutil_init`: bias = base_addr - p_vaddr of the **last** PT_LOAD with
/// p_offset == 0 that the base can reach. elf_util.c 148-159 scans every
/// phdr without breaking, so a later matching LOAD overwrites earlier ones;
/// when nothing matches, `base_addr` is returned (bias 0 relative to the
/// image start). Must agree with [`read_mapped_image`]'s bias computation.
pub fn bias_addr_for(img: &rz_elf::ElfImage, base_addr: usize) -> usize {
    let mut bias = base_addr;

    for seg in img.load_segments() {
        if seg.offset == 0 && base_addr >= seg.vaddr as usize {
            bias = base_addr.wrapping_sub(seg.vaddr as usize);
        }
    }

    bias
}

/// `elfutil_get_addr_protection`: PT_LOAD prot of the segment containing
/// `addr`, with PROT_WRITE cleared when `addr` falls inside PT_GNU_RELRO.
pub fn get_addr_protection(img: &rz_elf::ElfImage, bias_addr: usize, addr: usize) -> Option<i32> {
    let mut prot = 0;
    let mut found = false;

    for seg in img.load_segments() {
        if seg.memsz == 0 {
            continue;
        }

        let seg_start = bias_addr.wrapping_add(seg.vaddr as usize);
        let seg_end = seg_start.wrapping_add(seg.memsz as usize);
        if seg_end <= seg_start || addr < seg_start || addr >= seg_end {
            continue;
        }

        if seg.flags & PF_R != 0 {
            prot |= PROT_READ;
        }
        if seg.flags & PF_W != 0 {
            prot |= PROT_WRITE;
        }
        if seg.flags & PF_X != 0 {
            prot |= PROT_EXEC;
        }
        found = true;

        break;
    }

    if !found || prot == 0 {
        return None;
    }

    for seg in img.gnu_relro_segments() {
        if seg.memsz == 0 {
            continue;
        }

        let relro_start = bias_addr.wrapping_add(seg.vaddr as usize);
        let relro_end = relro_start.wrapping_add(seg.memsz as usize);
        if relro_end <= relro_start || addr < relro_start || addr >= relro_end {
            continue;
        }

        prot &= !PROT_WRITE;

        break;
    }

    Some(prot)
}

/// `elfutil_get_vma_boundaries`: page-aligned bounds of the RELRO (preferred)
/// or LOAD segment containing `addr`. The C walks the phdrs **in file order**
/// and only `break`s on the RELRO match, so a later matching PT_LOAD
/// overwrites earlier results — kept as-is.
pub fn get_vma_boundaries(img: &rz_elf::ElfImage, bias_addr: usize, addr: usize) -> Option<(usize, usize)> {
    let page_size = page_size();
    const PT_LOAD: u32 = 1;
    const PT_GNU_RELRO: u32 = 0x6474_e552;

    let mut result: Option<(usize, usize)> = None;

    for (ptype, seg) in img.all_segments() {
        if ptype != PT_GNU_RELRO && ptype != PT_LOAD {
            continue;
        }
        if seg.memsz == 0 {
            continue;
        }

        let s = bias_addr.wrapping_add(seg.vaddr as usize) & !(page_size - 1);
        let e = (bias_addr.wrapping_add(seg.vaddr as usize) + seg.memsz as usize + page_size - 1)
            & !(page_size - 1);

        if addr < s || addr >= e {
            continue;
        }

        result = Some((s, e - s));

        if ptype == PT_GNU_RELRO {
            break;
        }
    }

    // elf_util.c 618-638: the C fails the lookup when the matched segment's
    // page-aligned start is 0 (`return (vma_start && *vma_start != 0);`).
    // The check applies to the final written value — a later PT_LOAD match
    // may overwrite an earlier zero before the RELRO break.
    match result {
        Some((0, _)) => None,
        other => other,
    }
}

#[allow(clippy::too_many_arguments)]
fn collect_relocs(
    img: &rz_elf::ElfImage,
    bias_addr: usize,
    base_addr: usize,
    match_by_prefix: Option<&str>,
    sym_idx: Option<u32>,
    table: &[rz_elf::Reloc],
    is_plt: bool,
    stop_on_first_match: bool,
    out: &mut Vec<usize>,
    ) {        for rel in table {
            let matches = if let Some(prefix) = match_by_prefix {
                // elf_util.c 523-531: prefix matching skips st_name == 0
                // symbols outright, then strncmp's `prefix_len` bytes. An
                // empty prefix therefore matches every *named* symbol.
                img.symbol_at(rel.sym_idx as usize)
                    .is_some_and(|s| !s.name.is_empty() && s.name.starts_with(prefix))
            } else {
                rel.sym_idx == sym_idx.unwrap_or(u32::MAX)
            };
            if !matches {
                continue;
            }

            use rz_elf::arch::{generic_reloc_type, GenericReloc};
            let generic = generic_reloc_type(img.machine(), rel.rtype);
            let type_ok = if is_plt {
                generic == GenericReloc::JumpSlot
            } else {
                matches!(generic, GenericReloc::Absolute | GenericReloc::GlobDat)
            };
            if !type_ok {
                continue;
            }

            let addr = bias_addr.wrapping_add(rel.offset as usize);
            if addr <= base_addr {
                continue;
            }

            out.push(addr);
            if stop_on_first_match {
                break;
            }
        }
    }

/// `elfutil_internal_find_plt_addr`: PLT table (JMPREL, JUMP_SLOT only, stop
/// on first when matching by exact name) then the non-PLT tables (REL/RELA +
/// Android packed) filtered to ABS/GLOB_DAT.
pub fn find_plt_addrs(img: &rz_elf::ElfImage, bias_addr: usize, base_addr: usize, name: &str, by_prefix: bool) -> Vec<usize> {
    let mut out = Vec::new();

    let tables = match img.relocations_grouped() {
        Ok(t) => t,
        Err(e) => {
            dloge!("Failed to collect relocation tables: {e}");
            return out;
        }
    };

    let (match_by_prefix, sym_idx) = if by_prefix {
        (Some(name), None)
    } else {
        match img.dynsym_index_by_name(name) {
            Some(idx) => (None, Some(idx as u32)),
            // C returns 0 entries when the symbol is not in dynsym.
            None => return out,
        }
    };

    collect_relocs(
        img,
        bias_addr,
        base_addr,
        match_by_prefix,
        sym_idx,
        &tables.plt,
        true,
        !by_prefix,
        &mut out,
    );

    collect_relocs(
        img,
        bias_addr,
        base_addr,
        match_by_prefix,
        sym_idx,
        &tables.rel,
        false,
        false,
        &mut out,
    );

    collect_relocs(
        img,
        bias_addr,
        base_addr,
        match_by_prefix,
        sym_idx,
        &tables.android,
        false,
        false,
        &mut out,
    );

    out
}

// ---------------------------------------------------------------------------
// Runtime state
// ---------------------------------------------------------------------------

struct StashedVma {
    original_addr: usize,
    backup_addr: usize,
    len: usize,
    /// Protection to restore when the VMA is moved back (kept from the C).
    #[allow(dead_code)]
    original_prot: i32,
}

pub struct ElfInfo {
    pub path: String,
    /// ELF header address (`base_addr_` in the C).
    pub base_addr: usize,
    /// `base_addr_ - load0.p_vaddr` (`bias_addr_` in the C).
    pub bias_addr: usize,
    /// Sparse per-PT_LOAD snapshot of the mapped image window, copied once
    /// at add time (`read_mapped_image`); parsed on demand as a file image
    /// (avoids self-referential borrows).
    file: Vec<u8>,
    stashed_vmas: Vec<StashedVma>,
}

impl ElfInfo {
    fn parse(&self) -> Option<rz_elf::ElfImage<'_>> {
        rz_elf::ElfImage::parse(&self.file).ok()
    }
}

#[derive(Clone)]
pub struct Hook {
    pub lib_name: String,
    pub name: String,
    /// GOT slot address.
    pub address: usize,
    /// GOT target captured before this slot was hooked. Slots matched by a
    /// single (lib, name) pair can legitimately differ, so rollback and
    /// removal must restore per-slot values, never a shared one.
    pub original: usize,
}

pub struct Plti {
    pub elf_infos: Vec<ElfInfo>,
    pub hooks: Vec<Hook>,
}

impl Default for Plti {
    fn default() -> Self {
        Self::new()
    }
}

/// ELF class of the build target (elf_util.c `ELF_CLASS`).
#[cfg(target_pointer_width = "64")]
const TARGET_ELF_CLASS: u8 = 2;
#[cfg(target_pointer_width = "32")]
const TARGET_ELF_CLASS: u8 = 1;

#[cfg(target_arch = "aarch64")]
const TARGET_ELF_MACHINE: u16 = rz_elf::arch::EM_AARCH64;
#[cfg(target_arch = "x86_64")]
const TARGET_ELF_MACHINE: u16 = rz_elf::arch::EM_X86_64;
#[cfg(target_arch = "x86")]
const TARGET_ELF_MACHINE: u16 = rz_elf::arch::EM_386;
#[cfg(target_arch = "arm")]
const TARGET_ELF_MACHINE: u16 = rz_elf::arch::EM_ARM;

/// `elfutil_init`'s acquisition half (elf_util.c 115-159): validate the ELF
/// header at `base_addr` and snapshot the mapped image as a sparse,
/// per-PT_LOAD window, returning `(window, bias)`.
///
/// The C parses headers straight out of the mapping with raw pointers and
/// keeps no copy; the port copies the same ground truth once at add time so
/// `ElfInfo` can own its bytes while `rz_elf` parses them as a file image —
/// the file system is never involved, so csoloader in-memory images,
/// memfd-backed libs and since-deleted files all behave like the C.
///
/// The snapshot is NOT one contiguous span: real Android libraries leave
/// UNMAPPED holes between their PT_LOADs (segment-alignment gaps). The C
/// walks pointers lazily and never dereferences those holes — every walk
/// starts from a dynamic-table entry that lives inside a mapped segment — so
/// a single `[base_addr, bias + max(p_vaddr + p_memsz))` copy would fault
/// where the C works. Instead each PT_LOAD's mapped range
/// `[bias + p_vaddr, bias + p_vaddr + p_memsz)` is copied into its window
/// slot and the holes stay zero, which `rz_elf` never reads anyway
/// (`vaddr_to_file_offset` only resolves addresses inside a LOAD's
/// `[p_vaddr, p_vaddr + p_filesz)`).
///
/// `window[k]` equals file-offset-`k` content: the winning base LOAD has
/// `p_offset == 0`, so `base_addr` (= `bias + B`) maps to file offset 0 and
/// its slot is 0; for every other LOAD the usual ELF congruence
/// `p_vaddr - p_offset == B` makes the slot `p_vaddr - B` equal `p_offset`,
/// so goblin's file-offset reads (phdrs, PT_DYNAMIC table, hash/reloc
/// tables) land on the right bytes.
///
/// The returned bias is what `add_manual_lib` stores as `ElfInfo::bias_addr`
/// — the same last-match-wins `base_addr - p_vaddr` the C computes.
///
/// # Safety
/// `base_addr` must point at an ELF header in mapped memory (the C's own
/// contract from `plti_add_manual_lib`); unmapped or short mappings fault
/// here just as they would in the C.
unsafe fn read_mapped_image(base_addr: usize) -> Option<(Vec<u8>, usize)> {
    // SAFETY: forwarded contract; the ABI gates are this build's own target,
    // exactly elf_util.c's `ELF_CLASS` / `EM_*` check.
    unsafe { read_mapped_image_abi(base_addr, TARGET_ELF_CLASS, TARGET_ELF_MACHINE) }
}

/// [`read_mapped_image`] with the ABI gates supplied by the caller.
///
/// Production always passes this build's own class/machine; the window itself
/// is ABI-independent byte surgery, so tests drive other ABIs here to check it
/// against fixtures from another architecture (the device's arm64 library on
/// an x86-64 host).
///
/// # Safety
/// Same contract as [`read_mapped_image`].
unsafe fn read_mapped_image_abi(base_addr: usize, elf_class: u8, machine: u16) -> Option<(Vec<u8>, usize)> {
    if base_addr == 0 {
        return None;
    }

    let ehdr_size: usize = if elf_class == 2 { 64 } else { 52 };
    let hdr = unsafe { std::slice::from_raw_parts(base_addr as *const u8, ehdr_size) }.to_vec();

    // elf_util.c 121-137: magic, class, endianness, ident version, type and
    // machine all gate silently except the late version check.
    if hdr[0..4] != [0x7f, b'E', b'L', b'F'] {
        return None;
    }
    if hdr[4] != elf_class || hdr[5] != 1 || hdr[6] != 1 {
        return None;
    }

    let (e_type, e_machine, e_version, e_phoff, e_phentsize, e_phnum) = if elf_class == 2 {
        (
            u16::from_le_bytes(hdr[16..18].try_into().unwrap()),
            u16::from_le_bytes(hdr[18..20].try_into().unwrap()),
            u32::from_le_bytes(hdr[20..24].try_into().unwrap()),
            u64::from_le_bytes(hdr[32..40].try_into().unwrap()) as usize,
            u16::from_le_bytes(hdr[54..56].try_into().unwrap()),
            u16::from_le_bytes(hdr[56..58].try_into().unwrap()),
        )
    } else {
        (
            u16::from_le_bytes(hdr[16..18].try_into().unwrap()),
            u16::from_le_bytes(hdr[18..20].try_into().unwrap()),
            u32::from_le_bytes(hdr[20..24].try_into().unwrap()),
            u32::from_le_bytes(hdr[28..32].try_into().unwrap()) as usize,
            u16::from_le_bytes(hdr[42..44].try_into().unwrap()),
            u16::from_le_bytes(hdr[44..46].try_into().unwrap()),
        )
    };

    if e_type != ET_EXEC && e_type != ET_DYN {
        return None;
    }
    if e_machine != machine {
        return None;
    }
    if e_version != 1 {
        // C 139-143: "Unsupported ELF version".
        dloge!("Unsupported ELF version: {e_version}");
        return None;
    }

    let phdr_len = e_phnum as usize * e_phentsize as usize;
    if phdr_len == 0 {
        return None;
    }
    let phdrs =
        unsafe { std::slice::from_raw_parts((base_addr + e_phoff) as *const u8, phdr_len) }
            .to_vec();

    // elf_util.c 147-159: bias from the last p_offset == 0 PT_LOAD the base
    // can reach (the C's branch has no break, so later matches overwrite
    // earlier ones). B is that LOAD's p_vaddr; the snapshot window starts at
    // base_addr = bias + B, so window[k] holds the mapped byte at
    // base_addr + k.
    let mut bias: Option<(usize, usize)> = None;
    // (p_offset, p_vaddr, p_filesz) — the window is laid out by FILE offset,
    // matching what Elf::parse expects. On modern linkers p_offset and
    // p_vaddr diverge (per-segment page alignment), so a vaddr-layout window
    // feeds parse garbage even though every byte was copied faithfully.
    let mut loads: Vec<(usize, usize, usize)> = Vec::new();
    for i in 0..e_phnum as usize {
        let p = &phdrs[i * e_phentsize as usize..];
        let (p_type, p_offset, p_vaddr, p_memsz) = if elf_class == 2 {
            (
                u32::from_le_bytes(p[0..4].try_into().unwrap()),
                u64::from_le_bytes(p[8..16].try_into().unwrap()) as usize,
                u64::from_le_bytes(p[16..24].try_into().unwrap()) as usize,
                u64::from_le_bytes(p[40..48].try_into().unwrap()) as usize,
            )
        } else {
            (
                u32::from_le_bytes(p[0..4].try_into().unwrap()),
                u32::from_le_bytes(p[4..8].try_into().unwrap()) as usize,
                u32::from_le_bytes(p[8..12].try_into().unwrap()) as usize,
                u32::from_le_bytes(p[20..24].try_into().unwrap()) as usize,
            )
        };

        if p_type != libc::PT_LOAD {
            continue;
        }

        loads.push((p_offset, p_vaddr, p_memsz));

        if p_offset == 0 && base_addr >= p_vaddr {
            bias = Some((base_addr - p_vaddr, p_vaddr));
        }
    }

    let (bias, _load0_vaddr) = bias?;

    // Window end = the furthest file extent across the LOADs.
    // i128 keeps unchecked sums from wrapping: p_offset/p_memsz come straight
    // from the file (checked math; equivalent to the old `end <= base_addr`
    // sanity for every non-pathological image).
    let mut window_len: i128 = 0;
    for &(p_offset, _, p_memsz) in &loads {
        window_len = window_len.max(p_offset as i128 + p_memsz as i128);
    }
    if window_len <= 0 || window_len > usize::MAX as i128 {
        return None;
    }
    let window_len = window_len as usize;

    // Copy each PT_LOAD's mapped range into its FILE-offset window slot. Only
    // PT_LOADs are touched, so the alignment holes between segments stay zero
    // instead of being dereferenced (real Android libraries leave those gaps
    // unmapped; the C's lazy pointer walks never read them).
    //
    // Use try_reserve_exact to avoid panicking on allocation failure (could
    // be triggered by a malformed ELF with extreme vaddr spans).
    let mut window = Vec::new();
    if window.try_reserve_exact(window_len).is_err() {
        dloge!("Failed to allocate ELF window of size {window_len}");
        return None;
    }
    window.resize(window_len, 0);
    for &(p_offset, p_vaddr, p_memsz) in &loads {
        if p_offset >= window_len || p_memsz == 0 {
            continue;
        }

        let copy_len = p_memsz.min(window_len - p_offset);
        let src = bias.wrapping_add(p_vaddr as usize);
        unsafe {
            std::ptr::copy_nonoverlapping(
                src as *const u8,
                window.as_mut_ptr().add(p_offset),
                copy_len,
            );
        }
    }

    // `rz_elf` parses the window as a *file* image, and a file image must carry
    // its section header table; a mapped one does not (the table lies outside
    // every PT_LOAD). Reconcile the two before handing the window over.
    canonicalize_section_table(&mut window, elf_class);

    Some((window, bias))
}

/// Make a mapped-image window's header honest about the section table it
/// actually contains.
///
/// goblin parses `e_shnum` section headers of `e_shentsize` bytes at `e_shoff`
/// and rejects the whole image ("bad offset <e_shoff>" from scroll) when that
/// span leaves the buffer. A file image always holds the table; a *mapped*
/// image normally does not — the table sits past the last PT_LOAD, so neither
/// the mapping nor the window has those bytes — while `elf_util.c` never reads
/// sections at all (PLTI walks phdrs, the dynamic table, dynsym/dynstr and the
/// reloc tables).
///
/// So a window that does not cover the whole table is canonicalized to the
/// standard "no section header table" header (`e_shoff`/`e_shentsize`/
/// `e_shnum`/`e_shstrndx` = 0). A window that does cover it keeps the real
/// fields, preserving the section-based fast paths in `rz_elf` (exact
/// `.dynsym` count, `section_by_name`) for images whose table is inside the
/// window. Nothing PLTI consumes is altered: phdrs, the dynamic segment and
/// every table they point at stay byte-identical to the mapping.
fn canonicalize_section_table(window: &mut [u8], elf_class: u8) {
    // (e_shoff offset, e_shoff width, e_shentsize offset, e_shnum offset,
    // e_shstrndx offset, standard section-header size) — elf.h for both
    // classes; goblin uses the class-standard size, not `e_shentsize`.
    let (shoff_at, shoff_w, shentsize_at, shnum_at, shstrndx_at, shdr_size): (usize, usize, usize, usize, usize, u64) = if elf_class == 2 {
        (0x28, 8, 0x3a, 0x3c, 0x3e, 64)
    } else {
        (0x20, 4, 0x2e, 0x30, 0x32, 40)
    };

    if window.len() < shoff_at + shoff_w || window.len() < shstrndx_at + 2 {
        return;
    }

    let shoff = if shoff_w == 8 {
        u64::from_le_bytes(window[shoff_at..shoff_at + 8].try_into().unwrap())
    } else {
        u32::from_le_bytes(window[shoff_at..shoff_at + 4].try_into().unwrap()) as u64
    };
    let shentsize = u16::from_le_bytes(window[shentsize_at..shentsize_at + 2].try_into().unwrap());
    let shnum = u16::from_le_bytes(window[shnum_at..shnum_at + 2].try_into().unwrap());

    let representable = shentsize as u64 == shdr_size
        && shnum != 0
        && shoff
            .checked_add(shnum as u64 * shdr_size)
            .is_some_and(|end| end <= window.len() as u64);

    if !representable {
        window[shoff_at..shoff_at + shoff_w].fill(0);
        window[shentsize_at..shentsize_at + 2].fill(0);
        window[shnum_at..shnum_at + 2].fill(0);
        window[shstrndx_at..shstrndx_at + 2].fill(0);
    }
}

impl Plti {
    /// `plti_init`.
    pub fn new() -> Self {
        Self {
            elf_infos: Vec::new(),
            hooks: Vec::new(),
        }
    }

    /// `plti_add_manual_lib`.
    pub fn add_manual_lib(&mut self, lib_path: &str, base_addr: usize) -> bool {
        // Prevent adding the same library twice.
        if self.elf_infos.iter().any(|i| i.base_addr == base_addr) {
            return true;
        }

        // The C initializes its ELF image from the mapping at base_addr; the
        // port copies that same window instead of reading the file from
        // disk, so nothing touches the file system (C-parity for csoloader
        // in-memory images, memfd-backed libs and since-deleted files
        // alike). The bias computed while building the window is the image's
        // load bias — the value `elfutil_init` derives from its phdr scan
        // and the one stored as `ElfInfo::bias_addr`.
        let Some((file, bias_addr)) = (unsafe { read_mapped_image(base_addr) }) else {
            dloge!("Failed to initialize ELF image for library: {lib_path}");
            return false;
        };

        let img = match rz_elf::ElfImage::parse(&file) {
            Ok(img) => img,
            Err(_) => {
                dloge!("Failed to initialize ELF image for library: {lib_path}");
                return false;
            }
        };

        // elf_util.c 155-165: `dynamic_` holds the LAST PT_DYNAMIC phdr's
        // p_vaddr (the scan has no break) and init fails when that value is
        // 0 — a zero-vaddr PT_DYNAMIC is not saved by an earlier one, and a
        // later PT_DYNAMIC with p_vaddr != 0 wins over an earlier zero.
        if !img
            .all_segments()
            .iter()
            .rev()
            .find(|(pt, _)| *pt == PT_DYNAMIC)
            .is_some_and(|(_, seg)| seg.vaddr != 0)
        {
            dloge!("Failed to find dynamic section or bias address in ELF header");
            return false;
        }

        // elf_util.c 99-113 (`set_by_offset`) parity: every tag the C turns
        // into a runtime pointer must satisfy `bias + value >= base` (the
        // C's wrap-around ElfW(Addr) arithmetic, reproduced exactly). Only
        // tags actually present in the dynamic table are checked, exactly
        // like the C's switch.
        for &(tag, value) in img.dynamic_entries() {
            let checked = matches!(
                tag,
                DT_STRTAB
                    | DT_SYMTAB
                    | DT_JMPREL
                    | DT_REL
                    | DT_RELA
                    | rz_elf::DT_ANDROID_REL
                    | rz_elf::DT_ANDROID_RELA
            );
            if checked && bias_addr.wrapping_add(value as usize) < base_addr {
                dloge!(
                    "Failed to set pointer: base={base_addr:#x}, bias={bias_addr:#x}, off={value:#x}, val={:#x}",
                    bias_addr.wrapping_add(value as usize)
                );
                return false;
            }
        }

        // elf_util.c 219-236 + 265-272: `rel_android_` is the LAST
        // DT_ANDROID_REL/DT_ANDROID_RELA occurrence and `rel_android_size_`
        // the last of the two size tags — the C's flat assignments pair the
        // two fields independently, so the winning pair can cross tags. A
        // table pointer that fails `set_by_offset` (bias + d_ptr < base) or
        // lands exactly on 0 is left at 0 and never checked; otherwise the
        // runtime pointer must hold at least 4 bytes starting with "APS2".
        // When d_ptr == 0 and the load0 segment has p_vaddr == 0 the check
        // resolves to the ELF header itself and fails, exactly like the C.
        let android_table = img
            .dynamic_entries()
            .iter()
            .rev()
            .find(|(t, _)| {
                *t == rz_elf::DT_ANDROID_REL || *t == rz_elf::DT_ANDROID_RELA
            })
            .copied();
        let android_size = img
            .dynamic_entries()
            .iter()
            .rev()
            .find(|(t, _)| {
                *t == rz_elf::DT_ANDROID_RELSZ || *t == rz_elf::DT_ANDROID_RELASZ
            })
            .map(|(_, v)| *v);

        if let Some((_, table_vaddr)) = android_table {
            let runtime_ptr = bias_addr.wrapping_add(table_vaddr as usize);
            if runtime_ptr != 0 && runtime_ptr >= base_addr {
                let size = android_size.unwrap_or(0);
                let Some(off) = img.vaddr_to_file_offset(table_vaddr) else {
                    dloge!("Invalid Android packed reloc table");
                    return false;
                };
                let (Ok(start), Ok(size)) = (
                    usize::try_from(off),
                    usize::try_from(size),
                ) else {
                    dloge!("Invalid Android packed reloc table");
                    return false;
                };
                let Some(bytes) = img.raw().get(start..start.checked_add(size).unwrap_or(usize::MAX))
                else {
                    dloge!("Invalid Android packed reloc table");
                    return false;
                };
                if bytes.len() < 4 || !bytes.starts_with(rz_elf::APS2_MAGIC) {
                    dloge!("Invalid Android packed reloc table");
                    return false;
                }
            }
        }

        self.elf_infos.push(ElfInfo {
            path: lib_path.to_string(),
            base_addr,
            bias_addr,
            file,
            stashed_vmas: Vec::new(),
        });

        dlogd!("Added library: {lib_path}");

        true
    }

    /// `plti_add_lib` via `dl_iterate_phdr`: first entry whose name contains
    /// `lib_name` gets added through [`add_manual_lib`].
    pub fn add_lib(&mut self, lib_name: &str) -> bool {
        struct Ctx<'a> {
            lib_name: &'a str,
            found: Option<(String, usize)>,
        }

        unsafe extern "C" fn callback(
            info: *mut libc::dl_phdr_info,
            _size: usize,
            data: *mut libc::c_void,
        ) -> i32 {
            let ctx = unsafe { &mut *(data as *mut Ctx) };
            let info = unsafe { &*info };

            let name = if info.dlpi_name.is_null() {
                String::new()
            } else {
                let raw = unsafe { CStr::from_ptr(info.dlpi_name) };
                raw.to_string_lossy().into_owned()
            };
            if !name.contains(ctx.lib_name) {
                return 0;
            }

            // C plti.c: first PT_LOAD with p_offset == 0 holds the ELF header.
            // When that LOAD has p_vaddr != 0, ehdr sits at dlpi_addr + p_vaddr.
            let mut ehdr_addr = info.dlpi_addr as usize;
            for i in 0..info.dlpi_phnum as usize {
                let ph = unsafe { *info.dlpi_phdr.add(i) };
                if ph.p_type != libc::PT_LOAD || ph.p_offset != 0 {
                    continue;
                }

                ehdr_addr = ehdr_addr.wrapping_add(ph.p_vaddr as usize);

                break;
            }

            ctx.found = Some((name.to_string(), ehdr_addr));

            // Stop iterating, we only want the first match.
            1
        }

        let mut ctx = Ctx {
            lib_name,
            found: None,
        };

        let ret = unsafe { libc::dl_iterate_phdr(Some(callback), (&mut ctx as *mut Ctx).cast()) };
        if ret != 1 {
            dloge!("Failed to find ELF image for library: {lib_name}");
            return false;
        }

        let Some((name, ehdr_addr)) = ctx.found else {
            dloge!("Failed to find ELF image for library: {lib_name}");
            return false;
        };

        let ok = self.add_manual_lib(&name, ehdr_addr);
        ok
    }

    /// `plti_internal_set_got_entry`.
    fn set_got_entry(info: &mut ElfInfo, got_addr: usize, new_val: usize) -> bool {
        let Some(img) = info.parse() else {
            dloge!("Failed to infer memory protection for GOT entry at {got_addr:#x}");
            return false;
        };

        let Some(restore_prot) = get_addr_protection(&img, info.bias_addr, got_addr) else {
            dloge!("Failed to infer memory protection for GOT entry at {got_addr:#x}");
            return false;
        };

        if is_self_elf(&img, info.bias_addr) {
            return apply_hook(got_addr, new_val, restore_prot);
        }

        // For writable segments (data), modify directly and exit early.
        if restore_prot & PROT_WRITE != 0 {
            if unsafe { libc::mprotect(page_start(got_addr), page_size(), restore_prot | PROT_WRITE) } == -1 {
                dloge!("Failed to make GOT entry writable at {got_addr:#x}");
                return false;
            }

            return apply_hook(got_addr, new_val, restore_prot);
        }

        // For read-only segments, replace the whole VMA with an anonymous
        // mapping and stash the original to avoid Private Dirty CoW growth.
        let Some((vma_start, vma_len)) = get_vma_boundaries(&img, info.bias_addr, got_addr) else {
            dloge!("Failed to find VMA boundaries for GOT entry at {got_addr:#x}");
            return false;
        };

        // Already stashed (or anonymous): the VMA is process-private RW now.
        if info.stashed_vmas.iter().any(|v| v.original_addr == vma_start) {
            return apply_hook(got_addr, new_val, restore_prot);
        }

        // Early exit if the VMA is already anonymous (msync fails with ENOMEM).
        if unsafe { libc::msync(vma_start as *mut libc::c_void, vma_len, libc::MS_ASYNC) } == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOMEM)
        {
            return apply_hook(got_addr, new_val, restore_prot);
        }

        // Don't log while the VMA is being swapped: the logger itself may be
        // a hook target.
        let Some(backup_addr) = stash_vma(vma_start, vma_len) else {
            dloge!("Failed to stash VMA for library: {}", info.path);
            return false;
        };

        info.stashed_vmas.push(StashedVma {
            original_addr: vma_start,
            backup_addr,
            len: vma_len,
            original_prot: restore_prot,
        });

        apply_hook(got_addr, new_val, restore_prot)
    }

    /// `plti_internal_add_hook`.
    fn add_hook_internal(
        &mut self,
        lib_name: &str,
        name: &str,
        by_prefix: bool,
        new_callback: usize,
        backup: Option<&mut usize>,
    ) -> bool {
        let Some(info_idx) = self
            .elf_infos
            .iter()
            .position(|i| i.path.contains(lib_name))
        else {
            dloge!("Failed to find ELF image for library for hook {name}: {lib_name}");
            return false;
        };

        let img = match self.elf_infos[info_idx].parse() {
            Some(img) => img,
            None => {
                dloge!("Failed to find PLT address for hook {name} in library {lib_name}");
                return false;
            }
        };

        let info = &self.elf_infos[info_idx];
        let plt_addrs = find_plt_addrs(&img, info.bias_addr, info.base_addr, name, by_prefix);
        if plt_addrs.is_empty() {
            dloge!("Failed to find PLT address for hook {name} in library {lib_name}");
            return false;
        }

        let mut backup = backup;

        for plt_addr in plt_addrs {
            if plt_addr == 0 {
                continue;
            }

            // Capture original target before any modification. Backup is only
            // written once (first slot) — sufficient for single-symbol hooks.
            let original_callback = unsafe { *(plt_addr as *const usize) };
            if let Some(backup) = backup.as_deref_mut()
                && *backup == 0
            {
                *backup = original_callback;
            }

            // Modify GOT first. If this fails, no metadata is committed; roll
            // back only the slots already hooked in this call, each to its
            // own captured original.
            if !Self::set_got_entry(&mut self.elf_infos[info_idx], plt_addr, new_callback) {
                dloge!("Failed to set GOT entry for PLT hook at {plt_addr:#x}");

                for h in self.hooks.iter().rev() {
                    if h.lib_name != lib_name || h.name != name || h.address == 0 {
                        continue;
                    }

                    // Best-effort rollback with the slot's own original.
                    Self::set_got_entry(&mut self.elf_infos[info_idx], h.address, h.original);
                }

                return false;
            }

            self.hooks.push(Hook {
                lib_name: lib_name.to_string(),
                name: name.to_string(),
                address: plt_addr,
                original: original_callback,
            });
        }

        true
    }

    /// `plti_add_hook`.
    pub fn add_hook(&mut self, lib_name: &str, name: &str, new_callback: usize, backup: Option<&mut usize>) -> bool {
        self.add_hook_internal(lib_name, name, false, new_callback, backup)
    }

    /// `plti_add_hook_by_prefix`. Only one hook per prefix: multiple hooks
    /// would lose at least one original address.
    pub fn add_hook_by_prefix(
        &mut self,
        lib_name: &str,
        name_prefix: &str,
        new_callback: usize,
        backup: Option<&mut usize>,
    ) -> bool {
        self.add_hook_internal(lib_name, name_prefix, true, new_callback, backup)
    }

    /// `plti_internal_remove_hook`.
    fn remove_hook_internal(&mut self, lib_name: &str, name: &str, original_callback: usize) -> bool {
        let Some(info_idx) = self
            .elf_infos
            .iter()
            .position(|i| i.path.contains(lib_name))
        else {
            dloge!("Failed to find ELF image for library for removing hook {name}: {lib_name}");
            return false;
        };

        let matching = self.hooks.iter().filter(|h| h.lib_name == lib_name && h.name == name).count();
        if matching == 0 {
            dloge!("No matching hook found for {name} in library {lib_name}");
            return false;
        }

        let mut hooks = std::mem::take(&mut self.hooks);

        // Restore every matching GOT slot to its own captured original (the
        // API-level `original_callback` is only a fallback for legacy entries
        // recorded without one). On the first failure, keep the hook list
        // unchanged (partially restored, like the C) and bail.
        for hook in hooks.iter() {
            if hook.lib_name != lib_name || hook.name != name || hook.address == 0 {
                continue;
            }

            let original = if hook.original != 0 { hook.original } else { original_callback };
            if !Self::set_got_entry(&mut self.elf_infos[info_idx], hook.address, original) {
                dloge!("Failed to restore GOT entry for PLT hook at {:#x}", hook.address);
                self.hooks = hooks;

                return false;
            }
        }

        hooks.retain(|h| h.lib_name != lib_name || h.name != name);
        self.hooks = hooks;

        true
    }

    /// `plti_remove_hook`.
    pub fn remove_hook(&mut self, lib_name: &str, name: &str, original_callback: usize) -> bool {
        if original_callback == 0 {
            dloge!("Original callback pointer is NULL for hook {name} in library {lib_name}");
            return false;
        }

        self.remove_hook_internal(lib_name, name, original_callback)
    }

    /// `plti_remove_hook_by_prefix`.
    pub fn remove_hook_by_prefix(&mut self, lib_name: &str, name_prefix: &str, original_callback: usize) -> bool {
        if original_callback == 0 {
            dloge!("Original callback pointer is NULL for hook with prefix {name_prefix} in library {lib_name}");
            return false;
        }

        self.remove_hook_internal(lib_name, name_prefix, original_callback)
    }

    /// `plti_deinit`: move every stashed VMA back and drop state.
    pub fn deinit(mut self) -> bool {
        for info in &mut self.elf_infos {
            for vma in info.stashed_vmas.drain(..) {
                let restored = unsafe {
                    mremap_relocate(
                        vma.backup_addr as *mut libc::c_void,
                        vma.len,
                        vma.original_addr as *mut libc::c_void,
                    )
                };

                // plti.c 556-560: the C's `if (!mremap(...))` negates the
                // MAP_FAILED sentinel, so the branch is dead code and every
                // restore is silently accepted. The port keeps the intended
                // failure handling (log + free the backup) but, like the C's
                // plti_deinit, the restore result never changes the return.
                if restored as usize != vma.original_addr {
                    dloge!("Failed to restore original VMA for library {}", info.path);
                    unsafe {
                        libc::munmap(vma.backup_addr as *mut libc::c_void, vma.len);
                    }
                }
            }
        }

        self.elf_infos.clear();
        self.hooks.clear();

        // plti.c 580: plti_deinit returns true unconditionally.
        true
    }
}

// ---------------------------------------------------------------------------
// Raw-memory helpers (mirror plti.c)
// ---------------------------------------------------------------------------

fn page_size() -> usize {
    let ps = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if ps <= 0 {
        4096
    } else {
        ps as usize
    }
}

fn page_start(addr: usize) -> *mut libc::c_void {
    (addr & !(page_size() - 1)) as *mut libc::c_void
}

/// `is_self_elf`: is our own executing PC inside this image's PT_LOADs?
fn is_self_elf(img: &rz_elf::ElfImage, bias_addr: usize) -> bool {
    let pc = is_self_elf as *const () as usize;

    img.load_segments().iter().any(|seg| {
        let start = bias_addr.wrapping_add(seg.vaddr as usize);
        let end = start.wrapping_add(seg.memsz as usize);
        pc >= start && pc < end
    })
}

fn apply_hook(got_addr: usize, new_val: usize, restore_prot: i32) -> bool {
    // Always ensure the page is writable first: previous hooks may have
    // restored R permissions.
    if unsafe { libc::mprotect(page_start(got_addr), page_size(), PROT_READ | PROT_WRITE) } == -1 {
        dloge!("Failed to make GOT entry writable at {got_addr:#x}");
        return false;
    }

    unsafe {
        *(got_addr as *mut usize) = new_val;
    }

    if unsafe { libc::mprotect(page_start(got_addr), page_size(), restore_prot) } == -1 {
        dloge!("Failed to restore memory protection for GOT entry at {got_addr:#x}");
        return false;
    }

    true
}

/// `find_high_backup_hint`: fork a child that scans /proc/self/maps for a gap
/// large enough for `needed_size`, reporting the gap start over a pipe. Kept
/// in a child because scanning maps from within a hooked process is unsafe.
fn find_high_backup_hint(needed_size: usize) -> usize {
    let mut pfd = [0 as libc::c_int; 2];
    if unsafe { libc::pipe(pfd.as_mut_ptr()) } == -1 {
        dloge!("Failed to create pipe for backup hint scan");
        return 0;
    }

    let pid = unsafe { libc::fork() };
    if pid == -1 {
        dloge!("Failed to fork for backup hint scan");

        unsafe {
            libc::close(pfd[0]);
            libc::close(pfd[1]);
        }

        return 0;
    }

    if pid == 0 {
        unsafe {
            libc::close(pfd[0]);

            let mut hint: usize = 0;

            if let Ok(maps) = std::fs::read_to_string("/proc/self/maps") {
                let page = page_size();
                let size = needed_size.div_ceil(page) * page;

                let mut prev_end: usize = 0;
                let mut best: usize = 0;

                for line in maps.lines() {
                    let Some((start, end)) = parse_map_range(line) else {
                        continue;
                    };

                    if prev_end != 0 && start > prev_end && start - prev_end >= size {
                        best = prev_end;
                    }

                    if end > prev_end {
                        prev_end = end;
                    }
                }

                if best != 0 {
                    hint = (best + page - 1) & !(page - 1);
                }
            }

            let bytes = hint.to_ne_bytes();
            let mut written = 0;
            while written < bytes.len() {
                let n = libc::write(pfd[1], bytes.as_ptr().add(written) as *const libc::c_void, bytes.len() - written);
                if n <= 0 {
                    break;
                }
                written += n as usize;
            }

            libc::close(pfd[1]);
            libc::_exit(0);
        }
    }

    unsafe {
        libc::close(pfd[1]);
    }

    let mut hint_bytes = [0u8; size_of::<usize>()];
    let mut read_total = 0;
    while read_total < hint_bytes.len() {
        let n = unsafe {
            libc::read(
                pfd[0],
                hint_bytes.as_mut_ptr().add(read_total) as *mut libc::c_void,
                hint_bytes.len() - read_total,
            )
        };
        if n <= 0 {
            break;
        }
        read_total += n as usize;
    }

    unsafe {
        libc::close(pfd[0]);
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
    }

    if read_total != hint_bytes.len() {
        dloge!("Failed to read backup hint from child");
        return 0;
    }

    usize::from_ne_bytes(hint_bytes)
}

fn parse_map_range(line: &str) -> Option<(usize, usize)> {
    let mut split = line.splitn(2, ' ');
    let range = split.next()?;

    let mut parts = range.splitn(2, '-');
    let start = usize::from_str_radix(parts.next()?, 16).ok()?;
    let end = usize::from_str_radix(parts.next()?, 16).ok()?;

    Some((start, end))
}

/// The read-only VMA replacement dance from `plti_internal_set_got_entry`:
/// 1. reserve a backup region (prefer a high address found by the child scan),
/// 2. `mremap` the original VMA there,
/// 3. map anonymous RW memory at the original address,
/// 4. copy the contents over.
///
/// Returns the backup address on success.
fn stash_vma(vma_start: usize, vma_len: usize) -> Option<usize> {
    let hint = find_high_backup_hint(vma_len);

    let backup_addr = unsafe {
        libc::mmap(
            hint as *mut libc::c_void,
            vma_len,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    };
    let backup_addr = if backup_addr as isize == -1 {
        unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                vma_len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        }
    } else {
        backup_addr
    };

    if backup_addr as isize == -1 {
        return None;
    }

    let backup = backup_addr as usize;

    if unsafe { mremap_relocate(vma_start as *mut libc::c_void, vma_len, backup_addr) } as isize
        == -1
    {
        unsafe {
            libc::munmap(backup_addr, vma_len);
        }
        return None;
    }

    if unsafe {
        libc::mmap(
            vma_start as *mut libc::c_void,
            vma_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
            -1,
            0,
        )
    } as isize
        == -1
    {
        unsafe {
            mremap_relocate(backup_addr, vma_len, vma_start as *mut libc::c_void);
            libc::munmap(backup_addr, vma_len);
        }
        return None;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(backup as *const u8, vma_start as *mut u8, vma_len);
    }

    Some(backup)
}

#[cfg(test)]
mod tests;
