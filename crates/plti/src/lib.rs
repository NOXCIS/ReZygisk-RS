//! PLTI (Pure Library Hooking) port: PLT/GOT hooking inside the current
//! process, mirroring `loader/src/external/plti/src/{plti.c, elf_util.c}`.
//!
//! The C parses ELF headers straight out of the mapped image; here the file
//! image is read once per library (via `rz_elf`) and runtime addresses are
//! computed as `bias_addr + vaddr` where `bias_addr = base_addr -
//! load0.p_vaddr` exactly like `elfutil_init`. Everything that only touches
//! program headers / relocation tables is host-testable; the GOT write
//! helpers mirror the C mprotect/mremap dances 1:1.

#![allow(clippy::missing_safety_doc)]

use std::ffi::CStr;

pub const TAG: &str = "zygisk";

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

/// `elfutil_init`: bias = base_addr - p_vaddr of the first PT_LOAD with
/// p_offset == 0 (the mapping that holds the ELF header).
pub fn bias_addr_for(img: &rz_elf::ElfImage, base_addr: usize) -> usize {
    let load0 = img
        .load_segments()
        .into_iter()
        .find(|s| s.offset == 0);

    match load0 {
        Some(seg) => base_addr.wrapping_sub(seg.vaddr as usize),
        None => base_addr,
    }
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

    result
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
                img.symbol_at(rel.sym_idx as usize).is_some_and(|s| s.name.starts_with(prefix))
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
    /// File image, parsed on demand (avoids self-referential borrows).
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

        let Ok(file) = std::fs::read(lib_path) else {
            dloge!("Failed to read ELF image for library: {lib_path}");
            return false;
        };

        let Ok(img) = rz_elf::ElfImage::parse(&file) else {
            dloge!("Failed to initialize ELF image for library: {lib_path}");
            return false;
        };

        let bias_addr = bias_addr_for(&img, base_addr);

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

            // When the first p_offset==0 PT_LOAD has p_vaddr != 0, the ELF
            // header sits at dlpi_addr + p_vaddr.
            let mut ehdr_addr = info.dlpi_addr as usize;
            for i in 0..info.dlpi_phnum as usize {
                let ph = unsafe { *info.dlpi_phdr.add(i) };
                if ph.p_type != libc::PT_LOAD || ph.p_offset == 0 {
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

        self.add_manual_lib(&name, ehdr_addr)
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
            // back only the slots already hooked in this call.
            if !Self::set_got_entry(&mut self.elf_infos[info_idx], plt_addr, new_callback) {
                dloge!("Failed to set GOT entry for PLT hook at {plt_addr:#x}");

                for h in self.hooks.iter().rev() {
                    if h.lib_name != lib_name || h.name != name || h.address == 0 {
                        continue;
                    }

                    // Best-effort rollback.
                    Self::set_got_entry(&mut self.elf_infos[info_idx], h.address, original_callback);
                }

                return false;
            }

            self.hooks.push(Hook {
                lib_name: lib_name.to_string(),
                name: name.to_string(),
                address: plt_addr,
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

        // Restore every matching GOT slot; on the first failure, keep the
        // hook list unchanged (partially restored, like the C) and bail.
        for hook in hooks.iter() {
            if hook.lib_name != lib_name || hook.name != name || hook.address == 0 {
                continue;
            }

            if !Self::set_got_entry(&mut self.elf_infos[info_idx], hook.address, original_callback) {
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
        let mut ok = true;

        for info in &mut self.elf_infos {
            for vma in info.stashed_vmas.drain(..) {
                let restored = unsafe {
                    mremap_relocate(
                        vma.backup_addr as *mut libc::c_void,
                        vma.len,
                        vma.original_addr as *mut libc::c_void,
                    )
                };

                if restored as usize != vma.original_addr {
                    dloge!("Failed to restore original VMA for library {}", info.path);
                    unsafe {
                        libc::munmap(vma.backup_addr as *mut libc::c_void, vma.len);
                    }
                    ok = false;
                }
            }
        }

        self.elf_infos.clear();
        self.hooks.clear();

        ok
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
