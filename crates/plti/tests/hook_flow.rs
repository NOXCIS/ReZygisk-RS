//! Host integration tests for the PLTI hook discovery flow.
//!
//! Covers `find_plt_addrs` end-to-end against
//! `loader/src/external/plti/src/elf_util.c` `elfutil_internal_find_plt_addr`
//! (PLT pass: DT_JMPREL, JUMP_SLOT only, stop-on-first for exact names; then
//! DT_REL/DT_RELA + the Android packed table, filtered to
//! ABS/GLOB_DAT; addresses computed as bias + r_offset and rejected when
//! <= base_addr), plus the PLTI dynsym-index resolution chain it depends on
//! (elfutil_gnu_lookup → elfutil_elf_lookup → elfutil_linear_lookup).
//!
//! `add_hook` / `remove_hook` / commit are public but intentionally NOT
//! exercised here: they patch live mapped memory (write trampolines into
//! RWX buffers and overwrite the resolved GOT/PLT slots via mprotect), which
//! needs a real mapped module in a process — the synthetic fixtures used
//! here are unmapped bytes, and their resolution step is exactly what the
//! tests below verify against the C truth. (In-crate tests cover the
//! `add_manual_lib` mapping/snapshot machinery; commit semantics need an
//! Android process.)

use rz_elf::ElfImage;
use rz_plti::find_plt_addrs;

// --- fixture builder (single PT_LOAD, vaddr == file offset) -----------------

const DT_NULL: u64 = 0;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_STRSZ: u64 = 10;
const DT_SYMENT: u64 = 11;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;
const DT_PLTRELSZ: u64 = 2;
const DT_ANDROID_RELA: u64 = 0x6000_001f;
const DT_ANDROID_RELASZ: u64 = 0x6000_0020;

const R_X86_64_64: u64 = 1;
const R_X86_64_GLOB_DAT: u64 = 6;
const R_X86_64_JUMP_SLOT: u64 = 7;
const R_X86_64_RELATIVE: u64 = 8;

const GOT_BASE: u64 = 0x1000;
const BASE: usize = 0x7000_0000;

fn le_u16(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn le_u32(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}
fn le_u64(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

fn push_sleb(out: &mut Vec<u8>, mut v: i64) {
    loop {
        let mut b = (v & 0x7f) as u8;
        v >>= 7;
        let done = (v == 0 && b & 0x40 == 0) || (v == -1 && b & 0x40 != 0);
        if !done {
            b |= 0x80;
        }
        out.push(b);
        if done {
            break;
        }
    }
}

fn sleb(v: i64) -> Vec<u8> {
    let mut o = Vec::new();
    push_sleb(&mut o, v);
    o
}

fn rela(off: u64, sym_type: u64) -> [u8; 24] {
    let mut r = [0u8; 24];
    r[0..8].copy_from_slice(&le_u64(off));
    r[8..16].copy_from_slice(&le_u64(sym_type));
    r
}

fn dyn_entry(tag: u64, val: u64) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[0..8].copy_from_slice(&le_u64(tag));
    e[8..16].copy_from_slice(&le_u64(val));
    e
}

/// Symbols: 0 null, 1 hook_me (GLOBAL FUNC), 2 glob (GLOBAL OBJECT),
/// 3 undef (GLOBAL FUNC, shndx 0 — IN the SysV chain), 4 other (FUNC),
/// 5 hook_other (FUNC). SysV chain: 1 → 2 → 3 → 4 → 5 → 0.
fn build_fixture() -> Vec<u8> {
    // ---- dynstr ----
    let mut dynstr = vec![0u8];
    let mut name_off = Vec::new();
    for s in ["nullsym", "hook_me", "glob", "undef", "other", "hook_other"] {
        name_off.push(dynstr.len() as u32);
        dynstr.extend_from_slice(s.as_bytes());
        dynstr.push(0);
    }

    // ---- dynsym ----
    let mut dynsym = Vec::new();
    let mut sym = |off: u32, info: u8, shndx: u16, value: u64, size: u64| {
        let mut e = [0u8; 24];
        e[0..4].copy_from_slice(&le_u32(off));
        e[4] = info;
        e[6..8].copy_from_slice(&le_u16(shndx));
        e[8..16].copy_from_slice(&le_u64(value));
        e[16..24].copy_from_slice(&le_u64(size));
        dynsym.extend_from_slice(&e);
    };
    sym(0, 0, 0, 0, 0);
    sym(name_off[1], 0x12, 1, 0x1000, 32); // hook_me FUNC GLOBAL
    sym(name_off[2], 0x11, 1, 0x2000, 8); // glob OBJECT GLOBAL
    sym(name_off[3], 0x12, 0, 0, 0); // undef FUNC GLOBAL (UNDEF)
    sym(name_off[4], 0x12, 1, 0x3000, 32); // other
    sym(name_off[5], 0x12, 1, 0x4000, 32); // hook_other

    // ---- DT_HASH: nbucket 1, nchain 6, bucket[0] = 1, chain 1→2→3→4→5→0
    let mut hash = Vec::new();
    hash.extend(le_u32(1));
    hash.extend(le_u32(6));
    hash.extend(le_u32(1));
    hash.extend(le_u32(0)); // chain[0]
    hash.extend(le_u32(2)); // chain[1]
    hash.extend(le_u32(3)); // chain[2] → undef IS reachable via SysV
    hash.extend(le_u32(4)); // chain[3]
    hash.extend(le_u32(5)); // chain[4]
    hash.extend(le_u32(0)); // chain[5]

    // ---- DT_RELA (4 entries) ----
    let mut rela_tab = Vec::new();
    rela_tab.extend(rela(GOT_BASE + 0x00, (2 << 32) | R_X86_64_GLOB_DAT));
    rela_tab.extend(rela(GOT_BASE + 0x08, (1 << 32) | R_X86_64_64));
    rela_tab.extend(rela(GOT_BASE + 0x09, (1 << 32) | R_X86_64_RELATIVE)); // sym 1, RELATIVE type
    rela_tab.extend(rela(GOT_BASE + 0x10, (1 << 32) | R_X86_64_GLOB_DAT));

    // ---- DT_JMPREL (6 entries) ----
    let mut jmprel = Vec::new();
    jmprel.extend(rela(GOT_BASE + 0x18, (1 << 32) | R_X86_64_JUMP_SLOT));
    jmprel.extend(rela(GOT_BASE + 0x20, (1 << 32) | R_X86_64_JUMP_SLOT));
    jmprel.extend(rela(GOT_BASE + 0x28, (4 << 32) | R_X86_64_JUMP_SLOT));
    jmprel.extend(rela(0x0000, (1 << 32) | R_X86_64_JUMP_SLOT)); // addr <= base
    jmprel.extend(rela(GOT_BASE + 0x30, (5 << 32) | R_X86_64_JUMP_SLOT));
    jmprel.extend(rela(GOT_BASE + 0x38, (1 << 32) | R_X86_64_64)); // ABS64 in PLT table

    // ---- Android packed (APS2, RELA, 64-bit): 3 relocs ----
    let mut aps2 = b"APS2".to_vec();
    aps2.extend(sleb(3)); // num_relocs
    aps2.extend(sleb((GOT_BASE + 0x40) as i64)); // absolute initial offset
    aps2.extend(sleb(2)); // group size
    aps2.extend(sleb(1)); // GROUPED_BY_INFO
    aps2.extend(sleb(((1u64 << 32) | R_X86_64_GLOB_DAT) as i64));
    aps2.extend(sleb(0)); // offset delta
    aps2.extend(sleb(8)); // offset delta
    aps2.extend(sleb(1)); // group size
    aps2.extend(sleb(0)); // flags: per-reloc info + delta
    aps2.extend(sleb(8)); // offset delta
    aps2.extend(sleb(((3u64 << 32) | R_X86_64_GLOB_DAT) as i64));

    // ---- layout: ehdr(64) + phdrs(112) | dynsym | dynstr | hash | rela |
    //      jmprel | aps2 | dynamic ----
    let align8 = |v: usize| (v + 7) & !7;
    let sym_off = 64 + 112;
    let str_off = align8(sym_off + dynsym.len());
    let hash_off = align8(str_off + dynstr.len());
    let rela_off = align8(hash_off + hash.len());
    let jmprel_off = align8(rela_off + rela_tab.len());
    let aps2_off = align8(jmprel_off + jmprel.len());
    let dyn_off = align8(aps2_off + aps2.len());

    let mut dt: Vec<[u8; 16]> = Vec::new();
    dt.push(dyn_entry(DT_HASH, hash_off as u64));
    dt.push(dyn_entry(DT_STRTAB, str_off as u64));
    dt.push(dyn_entry(DT_SYMTAB, sym_off as u64));
    dt.push(dyn_entry(DT_STRSZ, dynstr.len() as u64));
    dt.push(dyn_entry(DT_SYMENT, 24));
    dt.push(dyn_entry(DT_RELA, rela_off as u64));
    dt.push(dyn_entry(DT_RELASZ, rela_tab.len() as u64));
    dt.push(dyn_entry(DT_PLTREL, DT_RELA)); // value 7 == DT_RELA
    dt.push(dyn_entry(DT_JMPREL, jmprel_off as u64));
    dt.push(dyn_entry(DT_PLTRELSZ, jmprel.len() as u64));
    dt.push(dyn_entry(DT_ANDROID_RELA, aps2_off as u64));
    dt.push(dyn_entry(DT_ANDROID_RELASZ, aps2.len() as u64));
    let dyn_size = (dt.len() + 1) * 16;
    let total = align8(dyn_off + dyn_size) as u64;

    let mut out = Vec::with_capacity(total as usize);
    let mut ehdr = [0u8; 64];
    ehdr[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    ehdr[4] = 2;
    ehdr[5] = 1;
    ehdr[6] = 1;
    ehdr[0x10..0x12].copy_from_slice(&le_u16(3)); // ET_DYN
    ehdr[0x12..0x14].copy_from_slice(&le_u16(62)); // EM_X86_64
    ehdr[0x14..0x18].copy_from_slice(&le_u32(1));
    ehdr[0x20..0x28].copy_from_slice(&le_u64(64)); // e_phoff
    ehdr[0x34..0x36].copy_from_slice(&le_u16(64));
    ehdr[0x36..0x38].copy_from_slice(&le_u16(56));
    ehdr[0x38..0x3a].copy_from_slice(&le_u16(2)); // e_phnum
    out.extend_from_slice(&ehdr);

    let mut phdr = |ptype: u32, flags: u32, off: u64, vaddr: u64, filesz: u64, memsz: u64| {
        let mut p = [0u8; 56];
        p[0..4].copy_from_slice(&le_u32(ptype));
        p[4..8].copy_from_slice(&le_u32(flags));
        p[8..16].copy_from_slice(&le_u64(off));
        p[16..24].copy_from_slice(&le_u64(vaddr));
        p[32..40].copy_from_slice(&le_u64(filesz));
        p[40..48].copy_from_slice(&le_u64(memsz));
        p[48..56].copy_from_slice(&le_u64(0x1000));
        out.extend_from_slice(&p);
    };
    phdr(1, 4, 0, 0, total, total); // PT_LOAD PF_R
    phdr(2, 4, dyn_off as u64, dyn_off as u64, dyn_size as u64, dyn_size as u64); // PT_DYNAMIC

    out.resize(sym_off, 0);
    out.extend_from_slice(&dynsym);
    out.resize(str_off, 0);
    out.extend_from_slice(&dynstr);
    out.resize(hash_off, 0);
    out.extend_from_slice(&hash);
    out.resize(rela_off, 0);
    out.extend_from_slice(&rela_tab);
    out.resize(jmprel_off, 0);
    out.extend_from_slice(&jmprel);
    out.resize(aps2_off, 0);
    out.extend_from_slice(&aps2);
    out.resize(dyn_off, 0);
    for e in dt {
        out.extend_from_slice(&e);
    }
    out.extend_from_slice(&dyn_entry(DT_NULL, 0));
    out.resize(total as usize, 0);

    out
}

fn fixture_image() -> ElfImage<'static> {
    let data: &'static Vec<u8> = Box::leak(Box::new(build_fixture()));
    ElfImage::parse(data).expect("synthetic PLTI fixture must parse")
}

fn got() -> usize {
    BASE + GOT_BASE as usize
}

// --- hook discovery flow ------------------------------------------------------

#[test]
fn exact_symbol_collects_plt_then_rel_then_android() {
    // elfutil_internal_find_plt_addr: for an exact name the PLT pass stops at
    // the FIRST matching JUMP_SLOT; then DT_RELA (ABS/GLOB_DAT only, table
    // order); then the Android packed table.
    let img = fixture_image();
    let addrs = find_plt_addrs(&img, BASE, BASE, "hook_me", false);
    assert_eq!(
        addrs,
        vec![
            got() + 0x18, // first JUMP_SLOT (stop-on-first; +0x20 not collected)
            got() + 0x08, // DT_RELA R_X86_64_64
            got() + 0x10, // DT_RELA GLOB_DAT (RELATIVE at +0x09 filtered by type)
            got() + 0x40, // APS2 GLOB_DAT
            got() + 0x48, // APS2 GLOB_DAT
        ]
    );
}

#[test]
fn prefix_symbol_collects_all_matches_across_tables() {
    let img = fixture_image();
    let addrs = find_plt_addrs(&img, BASE, BASE, "hook_", true);
    assert_eq!(
        addrs,
        vec![
            got() + 0x18, // JUMP_SLOT hook_me
            got() + 0x20, // JUMP_SLOT hook_me (no stop-on-first for prefixes)
            got() + 0x30, // JUMP_SLOT hook_other
            got() + 0x08, // DT_RELA ABS
            got() + 0x10, // DT_RELA GLOB_DAT
            got() + 0x40, // APS2
            got() + 0x48, // APS2
        ]
    );
}

#[test]
fn relocation_type_filter_matches_c() {
    let img = fixture_image();

    // R_X86_64_RELATIVE (sym 1) in DT_RELA is neither Absolute nor GlobDat.
    // R_X86_64_64 inside DT_JMPREL is not JUMP_SLOT, so the PLT pass skips
    // it (it is not a hookable PLT entry).
    let addrs = find_plt_addrs(&img, BASE, BASE, "hook_me", false);
    assert!(!addrs.contains(&(got() + 0x09))); // RELATIVE in DT_RELA
    assert!(!addrs.contains(&(got() + 0x38))); // ABS64 in DT_JMPREL

    // "glob" only has its GLOB_DAT.
    assert_eq!(find_plt_addrs(&img, BASE, BASE, "glob", false), vec![got() + 0x00]);
    // "other" only has its JUMP_SLOT.
    assert_eq!(find_plt_addrs(&img, BASE, BASE, "other", false), vec![got() + 0x28]);
    // "hook_other" resolves its own JUMP_SLOT by exact name.
    assert_eq!(find_plt_addrs(&img, BASE, BASE, "hook_other", false), vec![got() + 0x30]);
}

#[test]
fn zero_offset_reloc_is_below_base_filter() {
    // r_offset 0 → addr = bias + 0 = base_addr → rejected by the
    // `addr <= base_addr` guard in both exact and prefix passes.
    let img = fixture_image();
    let exact = find_plt_addrs(&img, BASE, BASE, "hook_me", false);
    assert!(!exact.contains(&BASE));
    let prefix = find_plt_addrs(&img, BASE, BASE, "hook_", true);
    assert!(!prefix.contains(&BASE));
}

#[test]
fn undef_symbol_resolves_in_plti_chain() {
    // elfutil_elf_lookup compares raw names with NO shndx/visibility filter:
    // an UNDEF import referenced by relocations must resolve (its APS2
    // GLOB_DAT at +0x50 is collectable). The Rust PLTI chain mirrors this.
    let img = fixture_image();
    assert_eq!(img.dynsym_index_by_name("undef"), Some(3));
    assert_eq!(find_plt_addrs(&img, BASE, BASE, "undef", false), vec![got() + 0x50]);
}

#[test]
fn unknown_symbol_yields_empty() {
    let img = fixture_image();
    assert!(find_plt_addrs(&img, BASE, BASE, "nope", false).is_empty());
    assert!(find_plt_addrs(&img, BASE, BASE, "nope", true).is_empty());
}

#[test]
fn dynsym_chain_sysv_only_reaches_all_chained_symbols() {
    // Sanity on the resolution layer the hook flow depends on: every symbol
    // in the SysV chain resolves, "nullsym" (index 0) never does.
    let img = fixture_image();
    for (name, idx) in
        [("hook_me", 1usize), ("glob", 2), ("undef", 3), ("other", 4), ("hook_other", 5)]
    {
        assert_eq!(img.dynsym_index_by_name(name), Some(idx), "{name}");
    }
    assert_eq!(img.dynsym_index_by_name("nullsym"), None);
}
