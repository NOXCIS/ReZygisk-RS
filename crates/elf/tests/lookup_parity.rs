//! Host integration tests: symbol-lookup chain parity between `ElfImage` and
//! the C references.
//!
//! Two C lookup chains are exercised against synthetic ELF64 dynsym fixtures
//! (no section headers — DT_HASH/DT_GNU_HASH drive everything, exactly like a
//! stripped Android image):
//!
//! - PLTI chain `dynsym_index_by_name`
//!   (`external/plti/src/elf_util.c` elfutil_gnu_lookup 422-471 →
//!    elfutil_elf_lookup 473-495 → elfutil_linear_lookup 496-520)
//! - csoloader chain `symbol_by_name` / `symbol_by_name_ex`
//!   (`external/csoloader/src/elf_util.c` GnuLookup → ElfLookup →
//!    LinearLookup + is_dynamic_symbol_visible)
//!
//! GNU hash buckets are computed AT TEST TIME with an independent in-test
//! implementation of the DJB2 GNU hash (elf_util.c), and `nbucket` is chosen
//! collision-free, so the fixtures encode real hash semantics without
//! hardcoded tables.

use rz_elf::{
    ElfImage, STB_LOCAL, STT_FUNC, STT_NOTYPE, STV_HIDDEN, SHN_UNDEF,
};

// --- in-test hash implementations (elf_util.c: gnu_hash 231-239, elf_hash 219-229)

fn gnu_hash_c(name: &str) -> u32 {
    let mut h: u32 = 5381;
    for &b in name.as_bytes() {
        h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(b as u32);
    }
    h
}

fn elf_hash_c(name: &str) -> u32 {
    let mut h: u32 = 0;
    for &b in name.as_bytes() {
        h = h.wrapping_shl(4).wrapping_add(b as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

#[test]
fn in_test_hash_helpers_match_c() {
    // Ground the helpers against the C algorithm before they are used to
    // build fixtures (elf_util.c: h = 5381; h = (h << 5) + h + c for GNU;
    // h = (h << 4) + c, h ^= g >> 24, h &= ~g for SysV).
    assert_eq!(gnu_hash_c(""), 5381);
    assert_eq!(gnu_hash_c("foo"), 193_491_849);
    assert_eq!(elf_hash_c(""), 0);
    assert_eq!(elf_hash_c("foo"), 27_999);
}

// --- fixture builder -------------------------------------------------------

#[derive(Clone)]
struct SymDef {
    name: &'static str,
    info: u8,
    other: u8,
    shndx: u16,
    value: u64,
    size: u64,
}

impl SymDef {
    fn func(name: &'static str, shndx: u16, value: u64) -> Self {
        SymDef { name, info: (1 << 4) | STT_FUNC, other: 0, shndx, value, size: 4 }
    }
}

struct Fixture {
    bytes: Vec<u8>,
}

const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_GNU_HASH: i64 = 0x6fff_fef5;

fn u16le(v: u16) -> [u8; 2] {
    v.to_le_bytes()
}
fn u32le(v: u32) -> [u8; 4] {
    v.to_le_bytes()
}
fn u64le(v: u64) -> [u8; 8] {
    v.to_le_bytes()
}

/// ELF64 header: no sections, 2 phdrs (LOAD + DYNAMIC), little-endian DYN.
fn elf64_header() -> [u8; 64] {
    let mut h = [0u8; 64];
    h[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    h[4] = 2; // ELFCLASS64
    h[5] = 1; // ELFDATA2LSB
    h[6] = 1; // EV_CURRENT
    h[0x10..0x12].copy_from_slice(&u16le(3)); // e_type = ET_DYN
    h[0x12..0x14].copy_from_slice(&u16le(62)); // e_machine = EM_X86_64
    h[0x14..0x18].copy_from_slice(&u32le(1)); // e_version
    h[0x20..0x28].copy_from_slice(&u64le(64)); // e_phoff
    h[0x34..0x36].copy_from_slice(&u16le(64)); // e_ehsize
    h[0x36..0x38].copy_from_slice(&u16le(56)); // e_phentsize
    h[0x38..0x3a].copy_from_slice(&u16le(2)); // e_phnum
    h[0x3e..0x40].copy_from_slice(&u16le(0)); // e_shstrndx
    h
}

fn phdr64(ptype: u32, flags: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64, align: u64) -> [u8; 56] {
    let mut p = [0u8; 56];
    p[0..4].copy_from_slice(&u32le(ptype));
    p[4..8].copy_from_slice(&u32le(flags));
    p[8..16].copy_from_slice(&u64le(offset));
    p[16..24].copy_from_slice(&u64le(vaddr));
    p[24..32].copy_from_slice(&u64le(0)); // p_paddr
    p[32..40].copy_from_slice(&u64le(filesz));
    p[40..48].copy_from_slice(&u64le(memsz));
    p[48..56].copy_from_slice(&u64le(align));
    p
}

fn dynsym64(name_off: u32, info: u8, other: u8, shndx: u16, value: u64, size: u64) -> [u8; 24] {
    let mut s = [0u8; 24];
    s[0..4].copy_from_slice(&u32le(name_off));
    s[4] = info;
    s[5] = other;
    s[6..8].copy_from_slice(&u16le(shndx));
    s[8..16].copy_from_slice(&u64le(value));
    s[16..24].copy_from_slice(&u64le(size));
    s
}

fn dyn_entry(tag: i64, val: u64) -> [u8; 16] {
    let mut e = [0u8; 16];
    e[0..8].copy_from_slice(&u64le(tag as u64));
    e[8..16].copy_from_slice(&u64le(val));
    e
}

fn align8(v: usize) -> usize {
    (v + 7) & !7
}

/// Pick a collision-free nbucket for the given GNU-hash symbol indexes.
fn pick_nbucket(hashes: &[u32]) -> u32 {
    let mut nb = 1u32;
    loop {
        let mut seen = Vec::new();
        let mut ok = true;
        for &h in hashes {
            if seen.contains(&(h % nb)) {
                ok = false;
                break;
            }
            seen.push(h % nb);
        }
        if ok {
            return nb;
        }
        nb += 1;
    }
}

/// Build a synthetic ELF64: single PT_LOAD over everything (vaddr == file
/// offset), no section headers. `gnu_idxs` lists dynsym indexes that get GNU
/// hash entries; `sysv_chain` is the DT_HASH chain array (indexes). All
/// symbols use STT_FUNC except where specified (no IFUNCs — those would need
/// resolvers on host).
fn build(syms: &[SymDef], sysv_chain: &[u32], gnu_idxs: &[u32], with_gnu: bool) -> Fixture {
    // 1. dynstr
    let mut dynstr = vec![0u8];
    let mut name_offs = Vec::new();
    for s in syms {
        name_offs.push(dynstr.len() as u32);
        dynstr.extend_from_slice(s.name.as_bytes());
        dynstr.push(0);
    }

    // 2. dynsym
    let mut dynsym = Vec::new();
    for (i, s) in syms.iter().enumerate() {
        dynsym.extend_from_slice(&dynsym64(name_offs[i], s.info, s.other, s.shndx, s.value, s.size));
    }
    let n = syms.len() as u32;

    // 3. DT_HASH: nbucket=1, nchain=n
    let mut hash = Vec::new();
    hash.extend_from_slice(&u32le(1));
    hash.extend_from_slice(&u32le(n));
    hash.extend_from_slice(&u32le(sysv_chain[0]));
    for &c in sysv_chain {
        hash.extend_from_slice(&u32le(c));
    }

    // 4. DT_GNU_HASH (optional) — computed dynamically at test time
    let mut gnu = Vec::new();
    let symoffset = gnu_idxs.iter().copied().min().unwrap_or(0);
    if with_gnu {
        let hashes: Vec<u32> = gnu_idxs.iter().map(|&i| gnu_hash_c(syms[i as usize].name)).collect();
        let nbucket = pick_nbucket(&hashes);
        let bloom_shift = 5u32;
        let mut bloom: u64 = 0;
        for &h in &hashes {
            bloom |= 1u64 << (h % 64) | 1u64 << ((h >> bloom_shift) % 64);
        }
        gnu.extend_from_slice(&u32le(nbucket));
        gnu.extend_from_slice(&u32le(symoffset));
        gnu.extend_from_slice(&u32le(1)); // bloom_size
        gnu.extend_from_slice(&u32le(bloom_shift));
        gnu.extend_from_slice(&u64le(bloom));
        let mut buckets = vec![0u32; nbucket as usize];
        for (i, &h) in gnu_idxs.iter().zip(&hashes) {
            buckets[(h % nbucket) as usize] = *i;
        }
        for b in buckets {
            gnu.extend_from_slice(&u32le(b));
        }
        let nchain = n - symoffset;
        let mut chains = vec![0u32; nchain as usize];
        for (i, &h) in gnu_idxs.iter().zip(&hashes) {
            chains[(*i - symoffset) as usize] = h | 1; // end bit (no collisions)
        }
        for c in chains {
            gnu.extend_from_slice(&u32le(c));
        }
    }

    // 5. layout: ehdr | phdrs | dynsym | dynstr | hash | gnu | dynamic
    let ehdr = 64usize;
    let phdrs = 2 * 56;
    let sym_off = align8(ehdr + phdrs);
    let str_off = align8(sym_off + dynsym.len());
    let hash_off = align8(str_off + dynstr.len());
    let gnu_off = if with_gnu { align8(hash_off + hash.len()) } else { hash_off + hash.len() };
    let dyn_off = align8(gnu_off + gnu.len());

    let mut dt: Vec<[u8; 16]> = Vec::new();
    dt.push(dyn_entry(DT_HASH, hash_off as u64));
    dt.push(dyn_entry(DT_STRTAB, str_off as u64));
    dt.push(dyn_entry(DT_SYMTAB, sym_off as u64));
    dt.push(dyn_entry(DT_STRSZ, dynstr.len() as u64));
    dt.push(dyn_entry(DT_SYMENT, 24));
    if with_gnu {
        dt.push(dyn_entry(DT_GNU_HASH, gnu_off as u64));
    }
    let dyn_size = (dt.len() + 1) * 16; // + DT_NULL
    let total = align8(dyn_off + dyn_size) as u64;

    let mut out = Vec::with_capacity(total as usize);
    out.extend_from_slice(&elf64_header());
    out.extend_from_slice(&phdr64(1, 4, 0, 0, total, total, 0x1000)); // PT_LOAD PF_R
    out.extend_from_slice(&phdr64(2, 4, dyn_off as u64, dyn_off as u64, dyn_size as u64, dyn_size as u64, 8)); // PT_DYNAMIC
    out.resize(sym_off, 0);
    out.extend_from_slice(&dynsym);
    out.resize(str_off, 0);
    out.extend_from_slice(&dynstr);
    out.resize(hash_off, 0);
    out.extend_from_slice(&hash);
    out.resize(gnu_off, 0);
    out.extend_from_slice(&gnu);
    out.resize(dyn_off, 0);
    for e in dt {
        out.extend_from_slice(&e);
    }
    out.extend_from_slice(&dyn_entry(DT_NULL, 0));
    out.resize(total as usize, 0);

    Fixture { bytes: out }
}

impl Fixture {
    fn image(&self) -> ElfImage<'_> {
        ElfImage::parse(&self.bytes).expect("synthetic ELF must parse")
    }
}

// --- fixtures --------------------------------------------------------------

/// GNU-present fixture.
///
/// - 0 nullsym: UNDEF, NOTYPE — below symoffset; SysV chain starts at 1, so
///   it is unreachable everywhere (and 0 is the not-found sentinel).
/// - 1 alpha: GLOBAL FUNC, shndx 1 — below symoffset: reachable ONLY by the
///   PLTI linear fallback (which scans [1, symoffset)).
/// - 2 beta, 3 undefsym, 6 local_hidden: GNU table members.
/// - 4 notinbloom, 5 sysvfar, 7 hidden_global: not in GNU table;
///   sysvfar/hidden_global are in the SysV chain.
fn gnu_fixture() -> Fixture {
    let syms = vec![
        SymDef { name: "nullsym", info: STT_NOTYPE, other: 0, shndx: SHN_UNDEF, value: 0, size: 0 },
        SymDef::func("alpha", 1, 0x100),
        SymDef::func("beta", 1, 0x200),
        SymDef::func("undefsym", SHN_UNDEF, 0),
        SymDef::func("notinbloom", 1, 0x400),
        SymDef::func("sysvfar", 1, 0x500),
        SymDef {
            name: "local_hidden",
            info: (STB_LOCAL << 4) | STT_FUNC,
            other: STV_HIDDEN,
            shndx: 1,
            value: 0x600,
            size: 4,
        },
        SymDef {
            name: "hidden_global",
            info: (1 << 4) | STT_FUNC,
            other: STV_HIDDEN,
            shndx: 1,
            value: 0x700,
            size: 4,
        },
    ];
    // SysV chain: 1 → 2 → 5 → 6 → 7 → 0
    let sysv_chain = [1, 2, 5, 6, 7, 6, 7, 0];
    build(&syms, &sysv_chain, &[2, 3, 6], true)
}

/// SysV-only fixture: no DT_GNU_HASH at all.
///
/// - 0 nullsym (UNDEF), 1 alpha, 2 beta in the chain; 3 sigma NOT in any
///   chain (the PLTI linear fallback never runs without DT_GNU_HASH).
fn sysv_fixture() -> Fixture {
    let syms = vec![
        SymDef { name: "nullsym", info: STT_NOTYPE, other: 0, shndx: SHN_UNDEF, value: 0, size: 0 },
        SymDef::func("alpha", 1, 0x100),
        SymDef::func("beta", 1, 0x200),
        SymDef::func("sigma", 1, 0x300),
    ];
    let sysv_chain = [1, 2, 0, 0];
    build(&syms, &sysv_chain, &[], false)
}

// --- PLTI chain (external/plti/src/elf_util.c 422-520) ---------------------

#[test]
fn plti_chain_gnu_present_matches_c() {
    let fixture = gnu_fixture();
    let img = fixture.image();

    // elfutil_gnu_lookup: bloom + bucket + chain walk (dynamic tables).
    assert_eq!(img.dynsym_index_by_name("beta"), Some(2));
    // Raw name match only: LOCAL binding and HIDDEN visibility are invisible
    // to the PLTI chain (elfutil_gnu_lookup has no bind/vis check).
    assert_eq!(img.dynsym_index_by_name("local_hidden"), Some(6));
    // No SHN_UNDEF filter either: imports referenced by relocations must
    // resolve (elf_util.c 422-471 compares raw names).
    assert_eq!(img.dynsym_index_by_name("undefsym"), Some(3));
    // Below symoffset and outside the GNU table: found by the linear scan
    // over [1, symoffset).
    assert_eq!(img.dynsym_index_by_name("alpha"), Some(1));
    // In the SysV chain only: the SysV path is skipped entirely when
    // DT_GNU_HASH is present (elfutil_elf_lookup returns 0 when bloom_ set).
    assert_eq!(img.dynsym_index_by_name("sysvfar"), None);
    // Not in any table: None.
    assert_eq!(img.dynsym_index_by_name("notinbloom"), None);
    // Index 0 is the not-found sentinel and can never be returned.
    assert_eq!(img.dynsym_index_by_name("nullsym"), None);
    assert_eq!(img.dynsym_index_by_name("definitely_not_there"), None);
}

#[test]
fn plti_chain_sysv_only_matches_c() {
    let fx = sysv_fixture();
    let img = fx.image();

    assert_eq!(img.dynsym_index_by_name("beta"), Some(2));
    assert_eq!(img.dynsym_index_by_name("alpha"), Some(1));
    // Without DT_GNU_HASH the linear fallback never runs (sym_offset_ is
    // GNU-only in C), so symbols outside the SysV chain are unreachable.
    assert_eq!(img.dynsym_index_by_name("sigma"), None);
    assert_eq!(img.dynsym_index_by_name("nullsym"), None);
}

// --- csoloader chain (external/csoloader/src/elf_util.c) --------------------

#[test]
fn csoloader_chain_matches_c() {
    let fx = gnu_fixture();
    let img = fx.image();

    // GnuLookup succeeds.
    let beta = img.symbol_by_name("beta").expect("beta");
    assert_eq!(beta.value, 0x200);
    assert_eq!(beta.type_(), STT_FUNC);

    // GnuLookup misses (not in the GNU table): ElfLookup via the SysV chain
    // still finds it — the csoloader chain has no "skip SysV when GNU
    // present" quirk, unlike the PLTI chain.
    let sysvfar = img.symbol_by_name("sysvfar").expect("sysvfar");
    assert_eq!(sysvfar.value, 0x500);

    // The SysV chain contains index 1, so alpha resolves here too.
    let alpha = img.symbol_by_name("alpha").expect("alpha");
    assert_eq!(alpha.value, 0x100);

    // UNDEF is filtered in BOTH the GNU and SysV paths of the csoloader
    // chain (is_dynamic_symbol_visible: SHN_UNDEF never resolves).
    assert_eq!(img.symbol_by_name("undefsym"), None);

    assert_eq!(img.symbol_by_name("definitely_not_there"), None);
}

#[test]
fn exported_only_filter_matches_c_csoloader() {
    let fx = gnu_fixture();
    let img = fx.image();

    // Plain global: exported.
    assert_eq!(img.symbol_by_name_ex("beta", true).map(|s| s.value), Some(0x200));
    // HIDDEN visibility: not exported, but visible when the filter is off.
    assert_eq!(img.symbol_by_name_ex("hidden_global", false).map(|s| s.value), Some(0x700));
    assert_eq!(img.symbol_by_name_ex("hidden_global", true), None);
    // LOCAL binding: not exported; visible when the filter is off.
    assert_eq!(img.symbol_by_name_ex("local_hidden", false).map(|s| s.value), Some(0x600));
    assert_eq!(img.symbol_by_name_ex("local_hidden", true), None);
    // UNDEF: filtered even when exported_only is false.
    assert_eq!(img.symbol_by_name_ex("undefsym", false), None);
    assert_eq!(img.symbol_by_name_ex("undefsym", true), None);
    // SysV-only exported global: GnuLookup misses, ElfLookup finds it.
    assert_eq!(img.symbol_by_name_ex("sysvfar", true).map(|s| s.value), Some(0x500));
}

// --- real-world sanity -------------------------------------------------------

#[test]
fn real_libc_lookup_parity() {
    let candidates = [
        "/lib/x86_64-linux-gnu/libc.so.6",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/lib64/libc.so.6",
    ];
    let path = candidates.iter().find(|p| std::path::Path::new(p).exists());
    let Some(path) = path else {
        eprintln!("skipping: no libc.so.6 found on this host");
        return;
    };
    let bytes = std::fs::read(path).expect("read libc");
    let img = ElfImage::parse(&bytes).expect("parse libc");
    assert!(img.is_64());

    let malloc = img.symbol_by_name("malloc").expect("libc malloc via csoloader chain");
    assert_eq!(malloc.type_(), STT_FUNC);

    let idx = img.dynsym_index_by_name("malloc").expect("libc malloc via PLTI chain");
    assert_eq!(img.symbol_at(idx).expect("symbol_at").name, "malloc");

    assert!(img.symbol_by_name("rz_nonexistent_sym_9f8e7d6c").is_none());
    assert!(img.dynsym_index_by_name("rz_nonexistent_sym_9f8e7d6c").is_none());
}
