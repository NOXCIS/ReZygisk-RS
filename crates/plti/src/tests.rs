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
const DT_RELAENT: u64 = 9;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;
const DT_PLTRELSZ: u64 = 2;

const R_X86_64_GLOB_DAT: u64 = 6;
const R_X86_64_JUMP_SLOT: u64 = 7;

const GOT_BASE: u64 = 0x1000; // RW LOAD region
const RELRO_SZ: u64 = 0x40;
const RW_LOAD_SZ: u64 = 0x2000; // spans two pages so RELRO/LOAD bounds differ

struct Builder {
    data: Vec<u8>,
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
/// up to GOT_BASE+0x100):
///   phdr order: LOAD R, LOAD RW, GNU_RELRO, DYNAMIC (RELRO after LOAD RW, so
///   it wins the VMA-boundary break).
///   LOAD R   [0, 0x300)        ehdr/phdr/dynamic/strtab/symtab/rela/plt/hash
///   LOAD RW  [0x1000, 0x3000)  GOT slots
///   RELRO    [0x1000, 0x1040)  first GOT page area
/// Symbols: 0 null, 1 "hook_me" (func), 2 "glob" (object), 3 "imported_fn" UNDEF.
fn build_so() -> Vec<u8> {
    let mut b = Builder::new();

    // ---- dynstr ------------------------------------------------------
    let _ = b.append_align(16);
    let strtab_vaddr = b.data.len() as u64;
    let mut names: Vec<(u64, &str)> = Vec::new();
    let mut add_name = |s: &'static str| {
        let off = b.data.len() as u64 - strtab_vaddr;
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
    let dynsym_vaddr = b.data.len() as u64;
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
    sym(0x12, 1, names[1].0, 0x60, 32); // GLOBAL FUNC hook_me
    sym(0x11, 1, names[2].0, 0x80, 8); // GLOBAL OBJECT glob
    sym(0x11, 0, names[3].0, 0, 0); // UNDEF imported_fn
    let dynsym_count = 4u32;

    // ---- SysV hash (DT_HASH): single bucket chain 1 → 2 → 0 ----------
    let _ = b.append_align(8);
    let hash_vaddr = b.data.len() as u64;
    let mut hash = Vec::new();
    hash.extend(le_u32(1)); // nbucket
    hash.extend(le_u32(dynsym_count)); // nchain
    hash.extend(le_u32(1)); // bucket[0] = 1
    for _ in 0..dynsym_count {
        hash.extend(le_u32(0)); // chains
    }
    b.data.extend_from_slice(&hash);

    // ---- DT_RELA: one GLOB_DAT for "glob" ----------------------------
    let _ = b.append_align(8);
    let rela_vaddr = b.data.len() as u64;
    let mut rela = Vec::new();
    rela.extend(le_u64(GOT_BASE)); // r_offset -> GOT slot inside RELRO
    rela.extend(le_u64((2 << 32) | R_X86_64_GLOB_DAT));
    rela.extend(le_u64(0));
    b.data.extend_from_slice(&rela);

    // ---- DT_JMPREL: two JUMP_SLOTs for "hook_me" ---------------------
    let _ = b.append_align(8);
    let jmprel_vaddr = b.data.len() as u64;
    let mut plt = Vec::new();
    for got in [GOT_BASE + 0x10, GOT_BASE + 0x18] {
        plt.extend(le_u64(got));
        plt.extend(le_u64((1 << 32) | R_X86_64_JUMP_SLOT));
        plt.extend(le_u64(0));
    }
    b.data.extend_from_slice(&plt);

    // ---- dynamic -----------------------------------------------------
    let _ = b.append_align(8);
    let dyn_vaddr = b.data.len() as u64;
    let mut dyns = Vec::new();
    let mut d = |tag: u64, val: u64| {
        dyns.extend(le_u64(tag));
        dyns.extend(le_u64(val));
    };
    d(DT_HASH, hash_vaddr);
    d(DT_STRTAB, strtab_vaddr);
    d(DT_SYMTAB, dynsym_vaddr);
    d(DT_RELA, rela_vaddr);
    d(DT_RELASZ, 24);
    d(DT_RELAENT, 24);
    d(DT_PLTREL, DT_RELA);
    d(DT_JMPREL, jmprel_vaddr);
    d(DT_PLTRELSZ, 48);
    d(DT_NULL, 0);
    b.data.extend_from_slice(&dyns);
    let dyn_end = b.data.len() as u64;

    // ---- ehdr + phdrs ------------------------------------------------
    const PHOFF: u64 = 0x40;
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
        e.extend(le_u64(0)); // shoff
        e.extend(le_u32(0)); // flags
        e.extend(le_u16(64)); // ehsize
        e.extend(le_u16(56)); // phentsize
        e.extend(le_u16(4)); // phnum
        e.extend(le_u16(0)); // shentsize
        e.extend(le_u16(0)); // shnum
        e.extend(le_u16(0)); // shstrndx
        e
    };
    assert_eq!(ehdr.len(), 64);
    for (i, byte) in ehdr.into_iter().enumerate() {
        b.data[i] = byte;
    }

    let mut phs = Vec::new();
    // LOAD R: covers all parsed tables
    phs.extend(phdr64(PT_LOAD, PF_R, 0, 0, dyn_end, dyn_end));
    // LOAD RW: the GOT region, spanning two pages
    phs.extend(phdr64(PT_LOAD, PF_R | PF_W, GOT_BASE, GOT_BASE, 0x100, RW_LOAD_SZ));
    // GNU_RELRO over the first GOT bytes (after the RW LOAD → wins by break)
    phs.extend(phdr64(PT_GNU_RELRO, PF_R, GOT_BASE, GOT_BASE, RELRO_SZ, RELRO_SZ));
    // DYNAMIC
    phs.extend(phdr64(PT_DYNAMIC, PF_R | PF_W, dyn_vaddr, dyn_vaddr, dyn_end - dyn_vaddr, dyn_end - dyn_vaddr));
    assert_eq!(phs.len(), 4 * 56);
    b.data.extend_from_slice(&phs);
    for (i, byte) in phs.into_iter().enumerate() {
        b.data[0x40 + i] = byte;
    }

    // Pad the file out to cover the RW LOAD's file-backed part.
    while (b.data.len() as u64) < GOT_BASE + 0x100 {
        b.data.push(0);
    }

    b.data
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
