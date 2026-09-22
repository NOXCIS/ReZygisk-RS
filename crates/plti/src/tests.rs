use super::*;
use rz_elf::ElfImage;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_GNU_RELRO: u32 = 0x6474_e552;

const DT_NULL: u64 = 0;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;
const DT_PLTRELSZ: u64 = 2;
const DT_ANDROID_RELA: u64 = 0x6000_001f;
const DT_ANDROID_RELASZ: u64 = 0x6000_0020;

const R_X86_64_GLOB_DAT: u64 = 6;
const R_X86_64_JUMP_SLOT: u64 = 7;

const GOT_BASE: u64 = 0x1000; // RW LOAD region
const RELRO_SZ: u64 = 0x40;
const RW_LOAD_SZ: u64 = 0x2000; // spans two pages so RELRO/LOAD bounds differ

struct Builder {
    data: Vec<u8>,
}

/// One ELF64 section header. `link` is sh_link, `entsize` sh_entsize.
fn shdr64(name: u32, stype: u32, off: u64, vaddr: u64, size: u64, link: u32, entsize: u64) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend(le_u32(name));
    s.extend(le_u32(stype));
    s.extend(le_u64(0)); // sh_flags
    s.extend(le_u64(vaddr));
    s.extend(le_u64(off));
    s.extend(le_u64(size));
    s.extend(le_u32(link));
    s.extend(le_u32(0)); // sh_info
    s.extend(le_u64(1)); // sh_addralign
    s.extend(le_u64(entsize));
    assert_eq!(s.len(), 64);
    s
}

impl Builder {
    fn new() -> Self {
        // ehdr (0x40) + 4 phdrs (0xe0) must fit before content starts.
        Self { data: vec![0u8; 0x180] }
    }

    fn append(&mut self, bytes: &[u8]) -> u64 {
        let off = self.data.len() as u64;
        self.data.extend_from_slice(bytes);
        off
    }

    fn append_align(&mut self, align: u64) -> u64 {
        while !(self.data.len() as u64).is_multiple_of(align) {
            self.data.push(0);
        }
        self.append(&[])
    }
}

fn le_u16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}

fn le_u32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}

fn le_u64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

fn phdr64(ptype: u32, flags: u32, off: u64, vaddr: u64, filesz: u64, memsz: u64) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend(le_u32(ptype));
    p.extend(le_u32(flags));
    p.extend(le_u64(off));
    p.extend(le_u64(vaddr));
    p.extend(le_u64(vaddr)); // paddr
    p.extend(le_u64(filesz));
    p.extend(le_u64(memsz));
    p.extend(le_u64(0x1000)); // align
    p
}

/// Layout (vaddr == file offset for the R region; the RW region is file-backed
/// up to rw_p_offset+0x100):
///   phdr order: LOAD R, LOAD RW, GNU_RELRO, DYNAMIC (RELRO after LOAD RW, so
///   it wins the VMA-boundary break).
///   LOAD R   [load0_vaddr, load0_vaddr+r_load_sz)  ehdr/phdr/dynamic/strtab/symtab/rela/plt/hash
///   LOAD RW  [rw_vaddr, rw_vaddr+rw_memsz)         GOT slots
///   RELRO    [rw_vaddr, rw_vaddr+RELRO_SZ)         first GOT page area
/// Symbols: 0 null, 1 "hook_me" (func), 2 "glob" (object), 3 "imported_fn" UNDEF.
///
/// DT_RELAENT is deliberately omitted: elf_util.c has no DT_RELAENT case
/// (169-262), and leaving it out keeps the table region ≤ 0x300 so the
/// gapped fixture's R LOAD is exactly filesz 0x300.
struct SoSpec {
    /// p_vaddr of the first PT_LOAD (which keeps p_offset == 0).
    load0_vaddr: u64,
    /// p_vaddr of the RW/GOT PT_LOAD.
    rw_vaddr: u64,
    /// p_offset of the RW/GOT PT_LOAD.
    rw_p_offset: u64,
    /// p_memsz of the RW/GOT PT_LOAD.
    rw_memsz: u64,
    /// Emit the PT_DYNAMIC phdr (the dynamic-table bytes are always built).
    with_dynamic_phdr: bool,
    /// When set, DT_STRTAB is emitted with this value instead of the strtab
    /// vaddr (drives the out-of-window pointer rejection test).
    strtab_override: Option<u64>,
    /// Emit DT_ANDROID_RELA/DT_ANDROID_RELASZ pointing at the strtab with
    /// size 4 before DT_NULL (drives the APS2 magic rejection test).
    android_tags: bool,
    /// When set, emit a real section header table (NULL + `.dynsym` +
    /// `.shstrtab`) with `e_shoff` at this file offset. Normal shared objects
    /// put it past the last PT_LOAD; an offset inside a LOAD's mapped slot
    /// builds the unusual image whose table the window *does* cover.
    shdr_at: Option<u64>,
}

fn build_so_spec(spec: SoSpec) -> Vec<u8> {
    let mut b = Builder::new();

    // ---- dynstr ------------------------------------------------------
    let _ = b.append_align(16);
    let strtab_file_off = b.data.len() as u64;
    let strtab_vaddr = spec.load0_vaddr + strtab_file_off;
    let mut names: Vec<(u64, &str)> = Vec::new();
    let mut add_name = |s: &'static str| {
        let off = b.data.len() as u64 - strtab_file_off;
        names.push((off, s));
        b.data.extend_from_slice(s.as_bytes());
        b.data.push(0);
    };
    add_name("");
    add_name("hook_me");
    add_name("glob");
    add_name("imported_fn");

    // ---- dynsym ------------------------------------------------------
    let _ = b.append_align(8);
    let dynsym_off = b.data.len() as u64;
    let dynsym_vaddr = spec.load0_vaddr + dynsym_off;
    let dynsym_size = 4 * 24u64; // 4 symbols × Elf64_Sym
    let mut sym = |info: u8, shndx: u16, name_off: u64, value: u64, size: u64| {
        let mut e = Vec::new();
        e.extend(le_u32(name_off as u32));
        e.push(info);
        e.push(0);
        e.extend(le_u16(shndx));
        e.extend(le_u64(value));
        e.extend(le_u64(size));
        b.data.extend_from_slice(&e);
    };
    sym(0, 0, 0, 0, 0);
    sym(0x12, 1, names[1].0, spec.load0_vaddr + 0x60, 32); // GLOBAL FUNC hook_me
    sym(0x11, 1, names[2].0, spec.load0_vaddr + 0x80, 8); // GLOBAL OBJECT glob
    sym(0x11, 0, names[3].0, 0, 0); // UNDEF imported_fn
    let dynsym_count = 4u32;

    // ---- SysV hash (DT_HASH): single bucket chain 1 → 2 → 0 ----------
    let _ = b.append_align(8);
    let hash_vaddr = spec.load0_vaddr + b.data.len() as u64;
    let mut hash = Vec::new();
    hash.extend(le_u32(1)); // nbucket
    hash.extend(le_u32(dynsym_count)); // nchain = 4
    hash.extend(le_u32(1)); // bucket[0] = 1
    hash.extend(le_u32(0)); // chain[0] (unused slot, C: chain_ = bucket_ + nbucket)
    hash.extend(le_u32(2)); // chain[1] → 2 (hook_me → glob)
    hash.extend(le_u32(0)); // chain[2] → end
    hash.extend(le_u32(0)); // chain[3] → end
    b.data.extend_from_slice(&hash);

    // ---- DT_RELA: one GLOB_DAT for "glob" ----------------------------
    let _ = b.append_align(8);
    let rela_vaddr = spec.load0_vaddr + b.data.len() as u64;
    let mut rela = Vec::new();
    rela.extend(le_u64(spec.rw_vaddr)); // r_offset -> GOT slot inside RELRO
    rela.extend(le_u64((2 << 32) | R_X86_64_GLOB_DAT));
    rela.extend(le_u64(0));
    b.data.extend_from_slice(&rela);

    // ---- DT_JMPREL: two JUMP_SLOTs for "hook_me" ---------------------
    let _ = b.append_align(8);
    let jmprel_vaddr = spec.load0_vaddr + b.data.len() as u64;
    let mut plt = Vec::new();
    for got in [spec.rw_vaddr + 0x10, spec.rw_vaddr + 0x18] {
        plt.extend(le_u64(got));
        plt.extend(le_u64((1 << 32) | R_X86_64_JUMP_SLOT));
        plt.extend(le_u64(0));
    }
    b.data.extend_from_slice(&plt);

    // ---- dynamic -----------------------------------------------------
    let _ = b.append_align(8);
    let dyn_file_off = b.data.len() as u64;
    let dyn_vaddr = spec.load0_vaddr + dyn_file_off;
    let mut dyns = Vec::new();
    let mut d = |tag: u64, val: u64| {
        dyns.extend(le_u64(tag));
        dyns.extend(le_u64(val));
    };
    d(DT_HASH, hash_vaddr);
    d(DT_STRTAB, spec.strtab_override.unwrap_or(strtab_vaddr));
    d(DT_SYMTAB, dynsym_vaddr);
    d(DT_RELA, rela_vaddr);
    d(DT_RELASZ, 24);
    d(DT_PLTREL, DT_RELA);
    d(DT_JMPREL, jmprel_vaddr);
    d(DT_PLTRELSZ, 48);
    if spec.android_tags {
        d(DT_ANDROID_RELA, strtab_vaddr);
        d(DT_ANDROID_RELASZ, 4);
    }
    d(DT_NULL, 0);
    b.data.extend_from_slice(&dyns);
    let dyn_end = b.data.len() as u64;

    // ---- ehdr + phdrs ------------------------------------------------
    const PHOFF: u64 = 0x40;
    let phnum = 3u16 + u16::from(spec.with_dynamic_phdr);
    // NULL + .dynsym + .shstrtab; e_shstrndx points at .shstrtab (index 2).
    let (shoff, shentsize, shnum, shstrndx) = match spec.shdr_at {
        Some(at) => (at, 64u16, 3u16, 2u16),
        None => (0, 0, 0, 0),
    };
    let ehdr = {
        let mut e = Vec::new();
        e.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        e.push(2); // ELFCLASS64
        e.push(1); // little endian
        e.push(1); // version
        e.push(0); // SYSV
        e.extend(&[0u8; 8]); // padding
        e.extend(le_u16(3)); // ET_DYN
        e.extend(le_u16(62)); // EM_X86_64
        e.extend(le_u32(1));
        e.extend(le_u64(0)); // entry
        e.extend(le_u64(PHOFF));
        e.extend(le_u64(shoff));
        e.extend(le_u32(0)); // flags
        e.extend(le_u16(64)); // ehsize
        e.extend(le_u16(56)); // phentsize
        e.extend(le_u16(phnum));
        e.extend(le_u16(shentsize));
        e.extend(le_u16(shnum));
        e.extend(le_u16(shstrndx));
        e
    };
    assert_eq!(ehdr.len(), 64);
    for (i, byte) in ehdr.into_iter().enumerate() {
        b.data[i] = byte;
    }

    let mut phs = Vec::new();
    // LOAD R: covers all parsed tables (p_offset 0, so bias = base - load0_vaddr).
    let r_load_sz = (dyn_end + 0xf) & !0xf;
    phs.extend(phdr64(PT_LOAD, PF_R, 0, spec.load0_vaddr, r_load_sz, r_load_sz));
    // LOAD RW: the GOT region, file-backed up to rw_p_offset+0x100.
    phs.extend(phdr64(PT_LOAD, PF_R | PF_W, spec.rw_p_offset, spec.rw_vaddr, 0x100, spec.rw_memsz));
    // GNU_RELRO over the first GOT bytes (after the RW LOAD → wins by break)
    phs.extend(phdr64(PT_GNU_RELRO, PF_R, spec.rw_p_offset, spec.rw_vaddr, RELRO_SZ, RELRO_SZ));
    // DYNAMIC
    if spec.with_dynamic_phdr {
        let dyn_size = dyn_end - dyn_file_off;
        phs.extend(phdr64(PT_DYNAMIC, PF_R | PF_W, dyn_file_off, dyn_vaddr, dyn_size, dyn_size));
    }
    assert_eq!(phs.len(), phnum as usize * 56);
    // Write into the reserved head only: the gap between the last table byte
    // and rw_p_offset must stay zero so the sparse window copy (holes zero)
    // matches the file bytes 1:1.
    for (i, byte) in phs.into_iter().enumerate() {
        b.data[0x40 + i] = byte;
    }

    // Pad the file out to cover the RW LOAD's file-backed part.
    while (b.data.len() as u64) < spec.rw_p_offset + 0x100 {
        b.data.push(0);
    }

    b.data
}

fn build_so() -> Vec<u8> {
    build_so_spec(SoSpec {
        load0_vaddr: 0,
        rw_vaddr: GOT_BASE,
        rw_p_offset: GOT_BASE,
        rw_memsz: RW_LOAD_SZ,
        with_dynamic_phdr: true,
        strtab_override: None,
        android_tags: false,
        shdr_at: None,
    })
}

// Gapped fixture (finding #3): RW/GOT LOAD at vaddr 0x3000 with only 0x100
// file bytes at p_offset 0x300, so the file covers 0..0x400 while the
// runtime window must cover 0..0x4000.
const GAP_RW_VADDR: u64 = 0x3000;
const GAP_RW_POFF: u64 = 0x300;
const GAP_RW_MEMSZ: u64 = 0x1000;

// Shifted fixture (finding #2): load0 has p_vaddr 0x1000 (p_offset 0) and
// each LOAD keeps p_offset == p_vaddr - 0x1000, so file offsets stay compact.
const SHIFT: u64 = 0x1000;

/// build_so variant for finding #3 (gap between the two LOADs' runtime ranges).
fn build_so_gapped() -> Vec<u8> {
    build_so_spec(SoSpec {
        load0_vaddr: 0,
        rw_vaddr: GAP_RW_VADDR,
        rw_p_offset: GAP_RW_POFF,
        rw_memsz: GAP_RW_MEMSZ,
        with_dynamic_phdr: true,
        strtab_override: None,
        android_tags: false,
        shdr_at: None,
    })
}

/// build_so variant for finding #2 (nonzero load0 p_vaddr → bias < base).
fn build_so_shifted() -> Vec<u8> {
    build_so_spec(SoSpec {
        load0_vaddr: SHIFT,
        rw_vaddr: SHIFT + GOT_BASE,
        rw_p_offset: GOT_BASE,
        rw_memsz: RW_LOAD_SZ,
        with_dynamic_phdr: true,
        strtab_override: None,
        android_tags: false,
        shdr_at: None,
    })
}

const BASE: usize = 0x7000_0000;

fn parsed() -> ElfImage<'static> {
    // Leak the fixture so it can be parsed without lifetime plumbing; each
    // test parses its own copy once.
    let data: &'static Vec<u8> = Box::leak(Box::new(build_so()));
    ElfImage::parse(data).unwrap()
}

#[test]
fn bias_addr_from_load0() {
    let img = parsed();
    // First PT_LOAD with p_offset == 0 has p_vaddr == 0 → bias == base.
    assert_eq!(bias_addr_for(&img, BASE), BASE);
}

#[test]
fn addr_protection_honors_relro() {
    let img = parsed();
    let bias = BASE;

    // GOT_BASE is inside LOAD RW but also inside RELRO → read-only.
    assert_eq!(get_addr_protection(&img, bias, BASE + GOT_BASE as usize), Some(libc::PROT_READ));
    // Past the RELRO end → RW.
    assert_eq!(
        get_addr_protection(&img, bias, BASE + GOT_BASE as usize + 0x80),
        Some(libc::PROT_READ | libc::PROT_WRITE)
    );
    // In the R-only LOAD.
    assert_eq!(get_addr_protection(&img, bias, BASE + 0x60), Some(libc::PROT_READ));
    // Outside any segment.
    assert_eq!(get_addr_protection(&img, bias, BASE + 0x5000), None);
}

#[test]
fn vma_boundaries_prefer_relro() {
    let img = parsed();
    let page = page_size();

    // Address inside both LOAD RW and RELRO: LOAD RW comes first but RELRO
    // breaks after overwriting → RELRO page range wins.
    let (start, len) = get_vma_boundaries(&img, BASE, BASE + GOT_BASE as usize + 0x10).expect("vma");
    assert_eq!(start, (BASE + GOT_BASE as usize) & !(page - 1));
    assert_eq!(start + len, (BASE + GOT_BASE as usize + RELRO_SZ as usize + page - 1) & !(page - 1));

    // Address in the second RW page (outside the RELRO page span) → LOAD RW
    // bounds (two pages).
    let (start, len) = get_vma_boundaries(&img, BASE, BASE + GOT_BASE as usize + 0x1080).expect("vma");
    assert_eq!(start, (BASE + GOT_BASE as usize) & !(page - 1));
    assert_eq!(start + len, (BASE + GOT_BASE as usize + RW_LOAD_SZ as usize + page - 1) & !(page - 1));

    // R-only LOAD region.
    let (start, _len) = get_vma_boundaries(&img, BASE, BASE + 0x60).expect("vma");
    assert_eq!(start, BASE & !(page - 1));
}

#[test]
fn plt_addrs_exact_and_prefix() {
    let img = parsed();
    let bias = BASE;
    let got = BASE + GOT_BASE as usize;

    // Exact name stops at the first JUMP_SLOT for "hook_me" (sym idx 1).
    let addrs = find_plt_addrs(&img, bias, BASE, "hook_me", false);
    assert_eq!(addrs, vec![got + 0x10]);

    // Prefix matching collects every JUMP_SLOT (and the GLOB_DAT is filtered
    // out of the non-PLT pass since it references "glob").
    let addrs = find_plt_addrs(&img, bias, BASE, "hook_me", true);
    assert_eq!(addrs, vec![got + 0x10, got + 0x18]);

    // "glob" has a GLOB_DAT in DT_RELA but no JUMP_SLOT → one address.
    let addrs = find_plt_addrs(&img, bias, BASE, "glob", false);
    assert_eq!(addrs, vec![got]);

    // Unknown symbol → empty.
    let addrs = find_plt_addrs(&img, bias, BASE, "nope", false);
    assert!(addrs.is_empty());

    // Defined-but-unreferenced UNDEF symbol → empty.
    let addrs = find_plt_addrs(&img, bias, BASE, "imported_fn", false);
    assert!(addrs.is_empty());
}

#[test]
fn map_range_parser() {
    assert_eq!(parse_map_range("7000000-7100000 r--p 00000000"), Some((0x7000000, 0x7100000)));
    assert_eq!(parse_map_range("garbage"), None);
}

/// Map `build_so()` at a kernel-chosen address and hand the mapping's base to
/// `add_manual_lib` — the C's acquisition model (elf_util.c parses the
/// mapped image; no file system involved).
#[test]
fn add_manual_lib_reads_mapped_image() {
    let mut so = build_so();
    // The fixture stamps EM_X86_64; make it match this build's target so the
    // machine gate passes on any host.
    so[18..20].copy_from_slice(&TARGET_ELF_MACHINE.to_le_bytes());

    let total = GOT_BASE as usize + RW_LOAD_SZ as usize;
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            total,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if addr as isize == -1 {
        eprintln!("mmap failed; skipping");
        return;
    }
    let base = addr as usize;
    unsafe {
        std::ptr::copy_nonoverlapping(so.as_ptr(), addr.cast::<u8>(), so.len());
    }

    let mut plti = Plti::new();
    assert!(plti.add_manual_lib("mapped_fixture.so", base));
    assert_eq!(plti.elf_infos.len(), 1);
    assert_eq!(plti.elf_infos[0].base_addr, base);
    assert_eq!(plti.elf_infos[0].bias_addr, base);
    // Window = bias + max(p_vaddr + p_memsz) = GOT_BASE + RW_LOAD_SZ.
    assert_eq!(plti.elf_infos[0].file.len(), total);
    assert_eq!(&plti.elf_infos[0].file[..so.len()], &so[..]);

    // Re-adding the same base is a no-op (elf_util.c 62-64).
    assert!(plti.add_manual_lib("mapped_fixture.so", base));
    assert_eq!(plti.elf_infos.len(), 1);

    // Hook discovery works straight off the mapped snapshot.
    let img = plti.elf_infos[0].parse().expect("parse mapped");
    let got = base + GOT_BASE as usize;
    let addrs = find_plt_addrs(&img, base, base, "hook_me", true);
    assert_eq!(addrs, vec![got + 0x10, got + 0x18]);

    unsafe { libc::munmap(addr, total) };
}

/// Header validation gates: no ELF magic, and a machine mismatch against the
/// build target (elf_util.c 121-137).
#[test]
fn add_manual_lib_rejects_garbage_and_machine_mismatch() {
    let mut so = build_so();
    // Always one past the target machine.
    so[18..20].copy_from_slice(&TARGET_ELF_MACHINE.wrapping_add(1).to_le_bytes());

    let total = 0x2000;
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            total,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if addr as isize == -1 {
        eprintln!("mmap failed; skipping");
        return;
    }
    let base = addr as usize;

    let mut plti = Plti::new();

    // Zeroed mapping: no ELF magic.
    assert!(!plti.add_manual_lib("junk.so", base));
    assert!(plti.elf_infos.is_empty());

    // Valid header, wrong machine.
    unsafe {
        std::ptr::copy_nonoverlapping(so.as_ptr(), addr.cast::<u8>(), so.len());
    }
    assert!(!plti.add_manual_lib("wrong_machine.so", base));
    assert!(plti.elf_infos.is_empty());

    unsafe { libc::munmap(addr, total) };
}

fn stamp_machine(so: &mut [u8]) {
    so[18..20].copy_from_slice(&TARGET_ELF_MACHINE.to_le_bytes());
}

/// mmap `size` RW anonymous bytes; on failure eprintln + return None (same
/// skip pattern as the existing mapping tests).
fn mmap_anon(size: usize) -> Option<usize> {
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if addr as isize == -1 {
        eprintln!("mmap failed; skipping");
        return None;
    }
    Some(addr as usize)
}

/// Minimal ELF with exactly the given program headers and no tables: enough
/// for phdr-only walks (bias_addr_for).
fn build_phdrs_only(phdrs: &[Vec<u8>]) -> Vec<u8> {
    let mut b = Builder::new();

    let ehdr = {
        let mut e = Vec::new();
        e.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        e.push(2); // ELFCLASS64
        e.push(1); // little endian
        e.push(1); // version
        e.push(0); // SYSV
        e.extend(&[0u8; 8]); // padding
        e.extend(le_u16(3)); // ET_DYN
        e.extend(le_u16(62)); // EM_X86_64
        e.extend(le_u32(1));
        e.extend(le_u64(0)); // entry
        e.extend(le_u64(0x40)); // phoff
        e.extend(le_u64(0)); // shoff
        e.extend(le_u32(0)); // flags
        e.extend(le_u16(64)); // ehsize
        e.extend(le_u16(56)); // phentsize
        e.extend(le_u16(phdrs.len() as u16));
        e.extend(le_u16(0)); // shentsize
        e.extend(le_u16(0)); // shnum
        e.extend(le_u16(0)); // shstrndx
        e
    };
    for (i, byte) in ehdr.into_iter().enumerate() {
        b.data[i] = byte;
    }
    for (i, ph) in phdrs.iter().enumerate() {
        let at = 0x40 + i * 56;
        b.data[at..at + 56].copy_from_slice(ph);
    }

    b.data
}

/// Finding #3 (add_manual_lib window walk, elf_util.c 115-159): the snapshot
/// window spans `bias + max(p_vaddr + p_memsz)` over PT_LOADs, so a gap
/// between two LOADs' runtime ranges is inside the window even though it is
/// not backed by the file. The C only ever dereferences pointers that lie in
/// file-backed LOAD spans; the port must not copy the raw
/// [base, bias + image_end) range or it faults on the unmapped hole.
///
/// Fixture: LOAD R [vaddr 0, filesz 0x300, p_offset 0], LOAD RW [vaddr 0x3000,
/// memsz 0x1000, p_offset 0x300]. The window is laid out by *file* offset (see
/// `read_mapped_image`), so it must reach p_offset + p_memsz = 0x1300 while
/// never touching the runtime hole at vaddr 0x1000..0x3000.
#[test]
fn add_manual_lib_skips_unmapped_hole_between_loads() {
    let mut so = build_so_gapped();
    stamp_machine(&mut so);

    const WINDOW: usize = 0x4000;
    let Some(base) = mmap_anon(WINDOW) else { return; };
    unsafe {
        std::ptr::copy_nonoverlapping(so.as_ptr(), base as *mut u8, so.len());
        // Hole between the two LOADs' runtime ranges: keep the R pages
        // (base..base+0x1000) and the RW page (base+0x3000..base+0x4000)
        // mapped, unmapping the middle.
        libc::munmap((base + 0x1000) as *mut libc::c_void, 0x2000);
    }

    let mut plti = Plti::new();
    assert!(plti.add_manual_lib("gapped.so", base));
    assert_eq!(plti.elf_infos.len(), 1);
    // Window end = max(p_offset + p_memsz) over the LOADs = the RW LOAD's end
    // by file offset. The R LOAD only contributes 0x300.
    assert_eq!(
        plti.elf_infos[0].file.len(),
        GAP_RW_POFF as usize + GAP_RW_MEMSZ as usize
    );

    let img = plti.elf_infos[0].parse().expect("parse gapped window");
    let addrs = find_plt_addrs(&img, base, base, "hook_me", true);
    assert_eq!(addrs, vec![base + 0x3010, base + 0x3018]);

    unsafe {
        libc::munmap(base as *mut libc::c_void, 0x1000);
        libc::munmap((base + 0x3000) as *mut libc::c_void, 0x1000);
    }
}

/// Finding #2/#3 (bias for a nonzero load0 p_vaddr, elf_util.c 147-154):
/// ehdr lives at file offset 0 ↔ vaddr 0x1000, so bias = base - 0x1000 and
/// every runtime address is bias + vaddr. p_offset == p_vaddr - 0x1000 keeps
/// the file offsets compact.
#[test]
fn add_manual_lib_nonzero_load0_vaddr() {
    let mut so = build_so_shifted();
    stamp_machine(&mut so);

    // Window end = bias + max(p_vaddr + p_memsz) = base - 0x1000 + 0x4000.
    const TOTAL: usize = 0x3000;
    let Some(base) = mmap_anon(TOTAL) else { return; };
    unsafe {
        std::ptr::copy_nonoverlapping(so.as_ptr(), base as *mut u8, so.len());
    }

    let mut plti = Plti::new();
    assert!(plti.add_manual_lib("shifted.so", base));
    assert_eq!(plti.elf_infos.len(), 1);

    let bias = base - 0x1000;
    assert_eq!(plti.elf_infos[0].bias_addr, bias);

    let got_vaddr = SHIFT + GOT_BASE;
    let img = plti.elf_infos[0].parse().expect("parse shifted window");
    let addrs = find_plt_addrs(&img, bias, base, "hook_me", true);
    assert_eq!(
        addrs,
        vec![bias + got_vaddr as usize + 0x10, bias + got_vaddr as usize + 0x18]
    );

    unsafe { libc::munmap(base as *mut libc::c_void, TOTAL) };
}

/// Finding #4 (elf_util.c 155-165): without a PT_DYNAMIC phdr elfutil_init
/// logs "Failed to find dynamic section or bias address in ELF header" and
/// returns false, so the library is not added.
#[test]
fn add_manual_lib_rejects_missing_pt_dynamic() {
    let mut so = build_so_spec(SoSpec {
        load0_vaddr: 0,
        rw_vaddr: GOT_BASE,
        rw_p_offset: GOT_BASE,
        rw_memsz: RW_LOAD_SZ,
        with_dynamic_phdr: false,
        strtab_override: None,
        android_tags: false,
        shdr_at: None,
    });
    stamp_machine(&mut so);

    let total = GOT_BASE as usize + RW_LOAD_SZ as usize;
    let Some(base) = mmap_anon(total) else { return; };
    unsafe {
        std::ptr::copy_nonoverlapping(so.as_ptr(), base as *mut u8, so.len());
    }

    let mut plti = Plti::new();
    assert!(!plti.add_manual_lib("no_dynamic.so", base));
    assert!(plti.elf_infos.is_empty());

    unsafe { libc::munmap(base as *mut libc::c_void, total) };
}

/// Finding #4 (set_by_offset gate, elf_util.c 99-113 + 176-177): DT_STRTAB = 0
/// is below load0.p_vaddr (0x1000), so bias + 0 < base and elfutil_init
/// fails instead of accepting an out-of-window pointer.
#[test]
fn add_manual_lib_rejects_out_of_window_dyn_ptr() {
    let mut so = build_so_spec(SoSpec {
        load0_vaddr: SHIFT,
        rw_vaddr: SHIFT + GOT_BASE,
        rw_p_offset: GOT_BASE,
        rw_memsz: RW_LOAD_SZ,
        with_dynamic_phdr: true,
        strtab_override: Some(0),
        android_tags: false,
        shdr_at: None,
    });
    stamp_machine(&mut so);

    const TOTAL: usize = 0x3000;
    let Some(base) = mmap_anon(TOTAL) else { return; };
    unsafe {
        std::ptr::copy_nonoverlapping(so.as_ptr(), base as *mut u8, so.len());
    }

    let mut plti = Plti::new();
    assert!(!plti.add_manual_lib("bad_strtab.so", base));
    assert!(plti.elf_infos.is_empty());

    unsafe { libc::munmap(base as *mut libc::c_void, TOTAL) };
}

/// Finding #4 (APS2 magic check, elf_util.c 265-272): DT_ANDROID_RELA/RELASZ
/// pointing at the strtab (size 4, first byte '\0' ≠ 'A') must fail
/// elfutil_init.
#[test]
fn add_manual_lib_rejects_bad_aps2_magic() {
    let mut so = build_so_spec(SoSpec {
        load0_vaddr: 0,
        rw_vaddr: GOT_BASE,
        rw_p_offset: GOT_BASE,
        rw_memsz: RW_LOAD_SZ,
        with_dynamic_phdr: true,
        strtab_override: None,
        android_tags: true,
        shdr_at: None,
    });
    stamp_machine(&mut so);

    let total = GOT_BASE as usize + RW_LOAD_SZ as usize;
    let Some(base) = mmap_anon(total) else { return; };
    unsafe {
        std::ptr::copy_nonoverlapping(so.as_ptr(), base as *mut u8, so.len());
    }

    let mut plti = Plti::new();
    assert!(!plti.add_manual_lib("bad_aps2.so", base));
    assert!(plti.elf_infos.is_empty());

    unsafe { libc::munmap(base as *mut libc::c_void, total) };
}

/// Finding #6b (elf_util.c 148-159): the bias scan has no `break` — with two
/// PT_LOADs both at p_offset == 0 (vaddrs 0 and 0x1000) the LAST match wins,
/// so bias_addr_for must return base - 0x1000, not base.
#[test]
fn bias_addr_for_last_load0_wins() {
    let so = build_phdrs_only(&[
        phdr64(PT_LOAD, PF_R, 0, 0, 0x100, 0x100),
        phdr64(PT_LOAD, PF_R, 0, 0x1000, 0x100, 0x100),
    ]);
    let img = ElfImage::parse(so.as_slice()).unwrap();

    assert_eq!(bias_addr_for(&img, BASE), BASE - 0x1000);
}

/// Finding #6c (elf_util.c 618-638): get_vma_boundaries returns false when
/// the page-aligned start is 0 (`return vma_start && *vma_start != 0`) —
/// an address inside a LOAD whose aligned start is 0 (build_so's R LOAD with
/// bias 0) yields None even though the segment bounds are valid.
#[test]
fn vma_boundaries_zero_start_returns_none() {
    let img = parsed();

    assert_eq!(get_vma_boundaries(&img, 0, 0x60), None);
}
