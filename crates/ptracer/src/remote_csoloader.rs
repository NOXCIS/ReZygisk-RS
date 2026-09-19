//! Port of loader/src/ptracer/remote_csoloader.c: map libzygisk.so into the
//! tracee via remote mmap + process_vm_writev, apply relocations in the
//! tracee's address space, then resolve the `entry` symbol. Relocation and
//! symbol parsing are shared with csoloader via the rz-elf crate.

use rz_common::MapEntry;
#[cfg(target_arch = "aarch64")]
use rz_elf::arch::types::aarch64;
#[cfg(target_arch = "arm")]
use rz_elf::arch::types::arm;
#[cfg(target_arch = "x86")]
use rz_elf::arch::types::x86;
#[cfg(target_arch = "x86_64")]
use rz_elf::arch::types::x86_64;
use rz_elf::{ElfImage, LoadSegment};

use crate::utils::{
    dlogd, dloge, dlogi, dlogw, find_func_addr, find_syscall_gadget, read_proc, remote_syscall,
    write_proc, UserRegs, TAG,
};

#[cfg(target_pointer_width = "32")]
const SYS_MMAP: i64 = libc::SYS_mmap2 as i64;
#[cfg(target_pointer_width = "64")]
const SYS_MMAP: i64 = libc::SYS_mmap;

// libc's android bindings don't export the PT_FLAGS PF_* constants.
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

// SYS_* are i32 on 32-bit targets.
#[allow(clippy::unnecessary_cast)]
const SYS_MUNMAP: i64 = libc::SYS_munmap as i64;
#[allow(clippy::unnecessary_cast)]
const SYS_MPROTECT: i64 = libc::SYS_mprotect as i64;

fn page_start(addr: usize, page_size: usize) -> usize {
    addr & !(page_size - 1)
}

fn page_end(addr: usize, page_size: usize) -> usize {
    (addr + page_size - 1) & !(page_size - 1)
}

pub struct RemoteLoadResult {
    pub base: usize,
    pub total_size: usize,
    pub entry: usize,
}

/// remote_csoloader.c `compute_load_layout`: page-aligned vaddr range across
/// all PT_LOAD segments.
fn compute_load_layout(img: &ElfImage, page_size: usize) -> Option<(u64, usize)> {
    let mut lo = u64::MAX;
    let mut hi = 0;

    for seg in img.load_segments() {
        if seg.vaddr < lo {
            lo = seg.vaddr;
        }

        let end = seg.vaddr + seg.memsz;
        if end > hi {
            hi = end;
        }
    }

    if hi <= lo {
        dloge!("Invalid PT_LOAD segments");
        return None;
    }

    let lo = page_start(lo as usize, page_size) as u64;
    let hi = page_end(hi as usize, page_size) as u64;

    Some((lo, (hi - lo) as usize))
}

/// remote_csoloader.c `find_remote_module_path`: full path of a loaded module
/// by its soname (basename match on offset-0 maps).
fn find_remote_module_path<'a>(remote_map: &'a [MapEntry], soname: &str) -> Option<&'a str> {
    for m in remote_map {
        if m.path.is_empty() || m.offset != 0 {
            continue;
        }

        let filename = crate::utils::position_after(&m.path, '/');
        if filename == soname {
            return Some(&m.path);
        }
    }

    None
}

/// remote_csoloader.c `find_dynsym_value`: name → st_value, skipping SHN_UNDEF.
fn find_dynsym_value(img: &ElfImage, sym_name: &str) -> Option<u64> {
    for i in 0..img.dynsym_count() {
        let Some(sym) = img.symbol_at(i) else { break };
        if sym.shndx == 0 {
            continue;
        }

        if sym.name == sym_name {
            return Some(sym.value);
        }
    }

    dloge!("Symbol not found in dynsym: {sym_name}");

    None
}

/// remote_csoloader.c `resolve_symbol_addr`: defined symbols resolve to
/// `load_bias + st_value`; undefined ones are searched through the DT_NEEDED
/// libraries' on-disk images, with a dlopen-family fallback resolved from the
/// linker's own exported `__dl_*` symbols.
fn resolve_symbol_addr(
    img: &ElfImage,
    local_map: &[MapEntry],
    remote_map: &[MapEntry],
    needed_paths: &[Option<&str>],
    load_bias: usize,
    sym_idx: u32,
) -> Option<usize> {
    let sym = img.symbol_at(sym_idx as usize)?;

    // Defined symbol: use load_bias + value.
    if sym.shndx != 0 {
        return Some(load_bias.wrapping_add(sym.value as usize));
    }

    // Undefined symbol: resolve from external libraries.
    let name = &sym.name;
    if name.is_empty() {
        return None;
    }

    // Optional in CSOLoader; unresolvable here, bypassed like the C does.
    if name == "__register_frame" || name == "__deregister_frame" {
        dlogw!("Bypassing resolution of EH frame function: {name}");
        return Some(0);
    }

    for path in needed_paths.iter().flatten() {
        let addr = find_func_addr(local_map, remote_map, path, name);
        if addr != 0 {
            return Some(addr as usize);
        }
    }

    if matches!(
        name.as_str(),
        "dlopen" | "dlsym" | "dlerror" | "dl_iterate_phdr" | "dlclose"
    ) {
        let linker_dl_symbol = match name.as_str() {
            "dlsym" => "__dl_dlsym",
            "dlerror" => "__dl_dlerror",
            "dl_iterate_phdr" => "__dl_dl_iterate_phdr",
            "dlclose" => "__dl_dlclose",
            _ => "__dl_dlopen",
        };

        #[cfg(target_pointer_width = "64")]
        let linker_path = "/system/bin/linker64";
        #[cfg(target_pointer_width = "32")]
        let linker_path = "/system/bin/linker";

        dlogd!("Trying to resolve {name} from main executable as: {linker_dl_symbol}");

        let addr = find_func_addr(local_map, remote_map, linker_path, linker_dl_symbol);
        if addr != 0 {
            return Some(addr as usize);
        }
    }

    dloge!("Failed to resolve external symbol {name}");

    None
}

/// Apply one RELA-style relocation (has explicit addend). Mirrors the
/// per-arch branches of remote_csoloader.c `apply_rela_section`.
#[allow(unused_variables)]
fn apply_rela_reloc(
    pid: i32,
    rel: &rz_elf::Reloc,
    target: usize,
    load_bias: usize,
    resolver: &dyn Fn(u32) -> Option<usize>,
) -> Option<u64> {
    let value: u64 = match rel.rtype {
        #[cfg(target_arch = "aarch64")]
        aarch64::RELATIVE => load_bias as u64 + rel.addend,
        #[cfg(target_arch = "aarch64")]
        aarch64::GLOB_DAT | aarch64::JUMP_SLOT | aarch64::ABS64 => {
            let sym_addr = resolver(rel.sym_idx)?;
            if sym_addr != 0 { sym_addr as u64 + rel.addend } else { 0 }
        }
        #[cfg(target_arch = "x86_64")]
        x86_64::RELATIVE => load_bias as u64 + rel.addend,
        #[cfg(target_arch = "x86_64")]
        x86_64::GLOB_DAT | x86_64::JUMP_SLOT | x86_64::R_64 => {
            let sym_addr = resolver(rel.sym_idx)?;
            if sym_addr != 0 { sym_addr as u64 + rel.addend } else { 0 }
        }
        // The C only handles the implicit-addend case on the REL arches.
        #[cfg(any(target_arch = "arm", target_arch = "x86"))]
        0 => load_bias as u64 + rel.addend,
        _ => {
            dloge!("Unsupported RELA type {}", rel.rtype);
            return None;
        }
    };

    let buf = value.to_le_bytes();
    (write_proc(pid, target, &buf) as usize == buf.len()).then_some(value)
}

/// Apply one REL-style relocation (addend read from the target). Mirrors
/// remote_csoloader.c `apply_rel_section`.
#[allow(unused_variables)]
fn apply_rel_reloc(
    pid: i32,
    rel: &rz_elf::Reloc,
    target: usize,
    load_bias: usize,
    resolver: &dyn Fn(u32) -> Option<usize>,
) -> Option<u64> {
    let read_remote = |target: usize| -> Option<u64> {
        let mut buf = [0u8; 4];
        if read_proc(pid, target, &mut buf) as usize != buf.len() {
            return None;
        }
        Some(u32::from_le_bytes(buf) as u64)
    };

    let value: u64 = match rel.rtype {
        #[cfg(target_arch = "arm")]
        arm::RELATIVE => load_bias as u64 + read_remote(target)?,
        #[cfg(target_arch = "arm")]
        arm::GLOB_DAT | arm::JUMP_SLOT | arm::ABS32 => {
            let sym_addr = resolver(rel.sym_idx)?;
            if sym_addr == 0 {
                0
            } else if rel.rtype == arm::ABS32 {
                sym_addr as u64 + read_remote(target)?
            } else {
                sym_addr as u64
            }
        }
        #[cfg(target_arch = "x86")]
        x86::RELATIVE => load_bias as u64 + read_remote(target)?,
        #[cfg(target_arch = "x86")]
        x86::GLOB_DAT | x86::JMP_SLOT | x86::ABS32 => {
            let sym_addr = resolver(rel.sym_idx)?;
            if sym_addr == 0 {
                0
            } else if rel.rtype == x86::ABS32 {
                sym_addr as u64 + read_remote(target)?
            } else {
                sym_addr as u64
            }
        }
        _ => {
            dloge!("Unsupported REL relocation on this arch");
            return None;
        }
    };

    #[allow(unreachable_code)]
    {
        let buf = value.to_le_bytes();
        (write_proc(pid, target, &buf) as usize == buf.len()).then_some(value)
    }
}

/// remote_csoloader.c `apply_relocations`.
fn apply_relocations(
    pid: i32,
    img: &ElfImage,
    local_map: &[MapEntry],
    remote_map: &[MapEntry],
    needed_paths: &[Option<&str>],
    load_bias: usize,
) -> bool {
    let resolver = |sym_idx: u32| -> Option<usize> {
        resolve_symbol_addr(img, local_map, remote_map, needed_paths, load_bias, sym_idx)
    };

    // Covers DT_RELA/DT_REL/DT_JMPREL plus the Android packed variants the
    // rz-elf core decodes; the C remote loader handles the first three.
    for rel in img.relocations().unwrap_or_default() {
        let target = load_bias.wrapping_add(rel.offset as usize);

        let ok = if rel.has_addend {
            apply_rela_reloc(pid, &rel, target, load_bias, &resolver)
        } else {
            apply_rel_reloc(pid, &rel, target, load_bias, &resolver)
        };

        if ok.is_none() {
            return false;
        }
    }

    true
}

/// remote_csoloader.c `remote_csoloader_load_and_resolve_entry`.
pub fn remote_csoloader_load_and_resolve_entry(
    pid: i32,
    regs: &mut UserRegs,
    remote_map: &[MapEntry],
    local_map: &[MapEntry],
    lib_path: &str,
) -> Option<RemoteLoadResult> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        dloge!("sysconf(_SC_PAGESIZE) failed");
        return None;
    }
    let page_size = page_size as usize;

    // The C reads via a fd + pread; a whole-file read is equivalent here and
    // keeps every access local.
    let Ok(raw) = std::fs::read(lib_path) else {
        rz_common::plog!(TAG, "open {lib_path}");
        return None;
    };

    let img = match ElfImage::parse(&raw) {
        Ok(img) => img,
        Err(e) => {
            dloge!("Failed to parse ELF phdrs for {lib_path}: {e}");
            return None;
        }
    };

    let Some((min_vaddr, map_size)) = compute_load_layout(&img, page_size) else {
        dloge!("Failed to parse ELF phdrs for {lib_path}");
        return None;
    };

    // Raw syscalls only: IBT/GCS enforcement on new Android versions makes
    // libc's functions unreliable in this context.
    let syscall_gadget = find_syscall_gadget(pid, remote_map);
    if syscall_gadget == 0 {
        dloge!("Failed to find syscall gadget");
        return None;
    }

    // Reserve high (LP64: 4GiB+) so later VMAs stay away from the mapping.
    #[cfg(target_pointer_width = "64")]
    let min_addr: usize = 0x1_0000_0000;
    #[cfg(target_pointer_width = "32")]
    let min_addr: usize = 0;
    let args = [
        min_addr as i64,
        map_size as i64,
        libc::PROT_NONE as i64,
        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as i64,
        -1,
        0,
    ];
    let remote_base = remote_syscall(pid, regs, syscall_gadget, SYS_MMAP, &args) as usize;
    if remote_base == 0 || remote_base == usize::MAX {
        dloge!("remote mmap reserve failed: {remote_base:#x}");
        return None;
    }

    #[cfg(target_pointer_width = "64")]
    if remote_base < min_addr {
        dloge!("remote mmap reserve returned low base {remote_base:#x} (< {min_addr:#x})");
        let args = [remote_base as i64, map_size as i64];
        remote_syscall(pid, regs, syscall_gadget, SYS_MUNMAP, &args);
        return None;
    }

    let load_bias = remote_base - min_vaddr as usize;

    let munmap_reserve = |regs: &mut UserRegs| {
        let args = [remote_base as i64, map_size as i64];
        remote_syscall(pid, regs, syscall_gadget, SYS_MUNMAP, &args);
    };

    // Map every PT_LOAD as anonymous writable memory and copy the file image
    // in via process_vm_writev. No fd is ever opened in the tracee, so no
    // /data/adb path is walked in the zygote context.
    let mut segs: Vec<(usize, usize, i32)> = Vec::new();

    for (idx, seg) in img.load_segments().into_iter().enumerate() {
        let seg: LoadSegment = seg;
        let seg_start = load_bias + seg.vaddr as usize;
        let seg_page = page_start(seg_start, page_size);
        let seg_end = load_bias + (seg.vaddr + seg.memsz) as usize;
        let seg_page_end = page_end(seg_end, page_size);
        let seg_page_len = seg_page_end - seg_page;

        let args = [
            seg_page as i64,
            seg_page_len as i64,
            (libc::PROT_READ | libc::PROT_WRITE) as i64,
            (libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as i64,
            -1,
            0,
        ];
        let seg_map = remote_syscall(pid, regs, syscall_gadget, SYS_MMAP, &args) as usize;
        if seg_map == 0 || seg_map == usize::MAX {
            dloge!("remote mmap anonymous segment failed for phdr {idx}");
            munmap_reserve(regs);
            return None;
        }

        // Anonymous memory is zero-filled, so the BSS tail needs no clearing.
        if seg.filesz > 0 {
            let at = seg.offset as usize;
            let Some(data) = raw.get(at..at + seg.filesz as usize) else {
                dloge!("Failed to read segment data of phdr {idx}");
                munmap_reserve(regs);
                return None;
            };

            if write_proc(pid, seg_start, data) as usize != data.len() {
                dloge!("Failed to copy segment data of phdr {idx} to remote");
                munmap_reserve(regs);
                return None;
            }
        }

        let mut prot = 0;
        if seg.flags & PF_R != 0 {
            prot |= libc::PROT_READ;
        }
        if seg.flags & PF_W != 0 {
            prot |= libc::PROT_WRITE;
        }
        if seg.flags & PF_X != 0 {
            prot |= libc::PROT_EXEC;
        }

        segs.push((seg_page, seg_page_len, prot));
    }

    let needed = img.needed_libraries();
    let needed_paths: Vec<Option<&str>> = needed
        .iter()
        .map(|soname| find_remote_module_path(remote_map, soname))
        .collect();

    if !apply_relocations(pid, &img, local_map, remote_map, &needed_paths, load_bias) {
        dloge!("Failed to apply relocations");
        munmap_reserve(regs);
        return None;
    }

    // Finalize segment protections after relocations.
    for (addr, len, prot) in &segs {
        let args = [*addr as i64, *len as i64, *prot as i64];
        let mp_ret = remote_syscall(pid, regs, syscall_gadget, SYS_MPROTECT, &args);
        if mp_ret < 0 {
            dloge!("Failed to set final protections for segment at {addr:#x}: {mp_ret}");
            munmap_reserve(regs);
            return None;
        }
    }

    let Some(entry_value) = find_dynsym_value(&img, "entry") else {
        dloge!("Failed to resolve entry from ELF dynsym");
        munmap_reserve(regs);
        return None;
    };

    let remote_entry = load_bias + entry_value as usize;

    dlogi!(
        "remote mapped {lib_path} at {remote_base:#x} (size {map_size:#x}), entry {remote_entry:#x}"
    );

    Some(RemoteLoadResult {
        base: remote_base,
        total_size: map_size,
        entry: remote_entry,
    })
}
