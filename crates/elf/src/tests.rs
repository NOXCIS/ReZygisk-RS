use crate::arch::{generic_reloc_type, types, GenericReloc, EM_AARCH64, EM_ARM, EM_X86_64};
use crate::image::{elf_hash, gnu_hash, ElfImage};
use crate::reloc::{decode_android_packed, decode_relr, sleb128_decode};

// DT_* tags used by the fixture builder.
const DT_NULL: u64 = 0;
const DT_HASH: u64 = 4;
const DT_STRTAB: u64 = 5;
const DT_SYMTAB: u64 = 6;
const DT_RELA: u64 = 7;
const DT_RELASZ: u64 = 8;
const DT_RELAENT: u64 = 9;
const DT_SYMENT: u64 = 11;
const DT_PLTREL: u64 = 20;
const DT_JMPREL: u64 = 23;
const DT_PLTRELSZ: u64 = 2;
const DT_GNU_HASH: u64 = 0x6fff_fef5;
const DT_ANDROID_RELA: u64 = 0x6000_001f;
const DT_ANDROID_RELASZ: u64 = 0x6000_0020;
const DT_RELR: u64 = 36;
const DT_RELRSZ: u64 = 35;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;

const R_AARCH64_RELATIVE: u64 = 1027;
const R_AARCH64_GLOB_DAT: u64 = 1025;
const R_AARCH64_JUMP_SLOT: u64 = 1026;

// ---------------------------------------------------------------------------
// Minimal hand-crafted ELF64 aarch64 shared object
// ---------------------------------------------------------------------------

struct Builder {
    data: Vec<u8>,
}

impl Builder {
    fn new() -> Self {
        Self { data: vec![0u8; 0x100] }
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

/// Layout (all vaddrs == file offsets, so bias = 0):
///   0x000 ehdr, 0x040 phdr[2], 0x0b0 dynamic, 0x130 dynstr,
///   0x1a0 dynsym (3 entries), 0x1c8 sysv hash, 0x1e0 gnu hash,
///   0x210 rela[2], 0x230 jmprel[1], 0x250 android packed, 0x2a0 relr
fn build_elf64() -> Vec<u8> {
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
    add_name(""); // st_name 0 is ""
    add_name("exported_fn");
    add_name("imported_fn");
    add_name("local_data");
    b.data.push(0); // padding so tables start aligned

    // ---- dynsym: 3 entries (index 0 is the UNDEF null) ---------------
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
    sym(0, 0, 0, 0, 0); // null
    sym(0x12, 1, names[1].0, 0x5000, 64); // GLOBAL FUNC "exported_fn"
    sym(0x11, 1, names[2].0, 0, 0); // GLOBAL NOTYPE UNDEF "imported_fn"
    sym(0x11, 1, names[3].0, 0x6000, 32); // GLOBAL OBJECT "local_data"
    let dynsym_count = 4u32;

    // ---- SysV hash table (DT_HASH) -----------------------------------
    let _ = b.append_align(8);
    let sysv_hash_vaddr = b.data.len() as u64;
    let nbucket = 1u32;
    let nchain = dynsym_count;
    b.data.extend(le_u32(nbucket));
    b.data.extend(le_u32(nchain));
            // bucket[0] -> 1 (exported_fn)
            b.data.extend(le_u32(1));
            // chains indexed by symbol: 1 -> 3 -> 0 (exported_fn walks to
            // local_data, then UNDEF)
            b.data.extend(le_u32(0));
            b.data.extend(le_u32(3));
            b.data.extend(le_u32(0));
            b.data.extend(le_u32(0));

    // ---- GNU hash table (DT_GNU_HASH) --------------------------------
    let _ = b.append_align(8);
    let gnu_hash_vaddr = b.data.len() as u64;
    let gnu_nbucket = 1u32;
    let gnu_symoffset = 1u32;
    let bloom_size = 1u32;
    let bloom_shift = 0u32;
    b.data.extend(le_u32(gnu_nbucket));
    b.data.extend(le_u32(gnu_symoffset));
    b.data.extend(le_u32(bloom_size));
    b.data.extend(le_u32(bloom_shift));
    // bloom: all-ones word accepts everything
    b.data.extend(le_u64(u64::MAX));
    // bucket[0] -> sym 1
    b.data.extend(le_u32(1));
    // chain for sym 1: hash("exported_fn") | 1
    let h1 = gnu_hash("exported_fn");
    b.data.extend(le_u32(h1 | 1));
    // chains for syms 2..3: mark end-of-chain with bit 0
    b.data.extend(le_u32(gnu_hash("imported_fn") | 1));
    b.data.extend(le_u32(gnu_hash("local_data") | 1));

    // ---- RELA: RELATIVE + GLOB_DAT ------------------------------------
    let _ = b.append_align(8);
    let rela_vaddr = b.data.len() as u64;
    let mut rela = |offset: u64, info: u64, addend: i64| {
        b.data.extend(le_u64(offset));
        b.data.extend(le_u64(info));
        b.data.extend(le_u64(addend as u64));
    };
    rela(0x1000, R_AARCH64_RELATIVE, 0x2000);
    rela(0x1008, R_AARCH64_GLOB_DAT | (1 << 32), 0);
    let rela_count = 2u64;
    let rela_entsize = 24u64;

    // ---- JMPREL: JUMP_SLOT --------------------------------------------
    let _ = b.append_align(8);
    let jmprel_vaddr = b.data.len() as u64;
    b.data.extend(le_u64(0x1010));
    b.data.extend(le_u64(R_AARCH64_JUMP_SLOT | (2 << 32)));
    b.data.extend(le_u64(0));
    let jmprel_count = 1u64;
    let jmprel_entsize = 24u64;

    // ---- Android packed APS2 table -------------------------------------
    let _ = b.append_align(8);
    let android_vaddr = b.data.len() as u64;
    let mut packed = Vec::new();
    packed.extend_from_slice(b"APS2");
    let sleb_push = |v: u64, out: &mut Vec<u8>| {
        let mut v = v as i64;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0) {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    };
    // 1 reloc, one group: size=1, flags=HAS_ADDEND, offset delta=0x800,
    // r_info=RELATIVE, addend=0x4000
    sleb_push(1, &mut packed);
    sleb_push(1, &mut packed);
    sleb_push(8, &mut packed); // RELOCATION_GROUP_HAS_ADDEND_FLAG
    sleb_push(0x800, &mut packed);
    sleb_push(R_AARCH64_RELATIVE, &mut packed);
    sleb_push(0x4000, &mut packed);
    b.data.extend_from_slice(&packed);
    let android_size = packed.len() as u64;

    // ---- RELR table -----------------------------------------------------
    let _ = b.append_align(8);
    let relr_vaddr = b.data.len() as u64;
    // word 0: explicit 0x3000; word 1: bitmap bits 0 and 2 set
    b.data.extend(le_u64(0x3000));
    b.data.extend(le_u64(0b101 << 1 | 1));
    let relr_size = 16u64;

    // ---- dynamic ---------------------------------------------------------
    let _ = b.append_align(8);
    let dynamic_vaddr = b.data.len() as u64;
    let mut dyn_entry = |tag: u64, val: u64| {
        b.data.extend(le_u64(tag));
        b.data.extend(le_u64(val));
    };
    dyn_entry(DT_HASH, sysv_hash_vaddr);
    dyn_entry(DT_GNU_HASH, gnu_hash_vaddr);
    dyn_entry(DT_STRTAB, strtab_vaddr);
    dyn_entry(DT_SYMTAB, dynsym_vaddr);
    dyn_entry(DT_SYMENT, 24);
    dyn_entry(DT_RELA, rela_vaddr);
    dyn_entry(DT_RELASZ, rela_count * rela_entsize);
    dyn_entry(DT_RELAENT, rela_entsize);
    dyn_entry(DT_JMPREL, jmprel_vaddr);
    dyn_entry(DT_PLTRELSZ, jmprel_count * jmprel_entsize);
    dyn_entry(DT_PLTREL, DT_RELA);
    dyn_entry(DT_ANDROID_RELA, android_vaddr);
    dyn_entry(DT_ANDROID_RELASZ, android_size);
    dyn_entry(DT_RELR, relr_vaddr);
    dyn_entry(DT_RELRSZ, relr_size);
    dyn_entry(DT_NULL, 0);
    let dynamic_size = b.data.len() as u64 - dynamic_vaddr;

    // ---- headers ---------------------------------------------------------
    let ehdr_size = 64usize;
    let phdr_size = 56usize;
    let phoff = ehdr_size;
    let total = b.data.len() as u64;

    // PT_LOAD covering the whole file at vaddr 0 (bias 0), then PT_DYNAMIC.
    let mut phdr = Vec::new();
    phdr.extend(le_u32(PT_LOAD));
    phdr.extend(le_u32(5)); // R|X
    phdr.extend(le_u64(0)); // offset
    phdr.extend(le_u64(0)); // vaddr
    phdr.extend(le_u64(0)); // paddr
    phdr.extend(le_u64(total)); // filesz
    phdr.extend(le_u64(total)); // memsz
    phdr.extend(le_u64(0x1000)); // align
    phdr.extend(le_u32(PT_DYNAMIC));
    phdr.extend(le_u32(4)); // R
    phdr.extend(le_u64(dynamic_vaddr));
    phdr.extend(le_u64(dynamic_vaddr));
    phdr.extend(le_u64(dynamic_vaddr));
    phdr.extend(le_u64(dynamic_size));
    phdr.extend(le_u64(dynamic_size));
    phdr.extend(le_u64(8));
    assert_eq!(phdr.len(), phdr_size * 2);

    // Patch ehdr into place.
    let mut ehdr = Vec::new();
    ehdr.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    ehdr.extend_from_slice(&[2, 1, 1, 0]); // 64-bit, LE, v1, SysV
    ehdr.extend_from_slice(&[0u8; 8]);
    ehdr.extend(le_u16(3)); // ET_DYN
    ehdr.extend(le_u16(EM_AARCH64));
    ehdr.extend(le_u32(1)); // version
    ehdr.extend(le_u64(0)); // entry
    ehdr.extend(le_u64(phoff as u64));
    ehdr.extend(le_u64(0)); // shoff
    ehdr.extend(le_u32(0)); // flags
    ehdr.extend(le_u16(ehdr_size as u16));
    ehdr.extend(le_u16(phdr_size as u16));
    ehdr.extend(le_u16(2)); // phnum
    ehdr.extend(le_u16(0)); // shentsize
    ehdr.extend(le_u16(0)); // shnum
    ehdr.extend(le_u16(0)); // shstrndx
    assert_eq!(ehdr.len(), ehdr_size);
    b.data[0..ehdr_size].copy_from_slice(&ehdr);
    b.data[phoff..phoff + phdr.len()].copy_from_slice(&phdr);

    b.data
}

#[test]
fn sleb128_roundtrip() {
    let mut buf = Vec::new();
    for v in [0u64, 1, 63, 64, 127, 128, 0x1000, u64::from(u32::MAX), u64::MAX / 2] {
        let mut out = Vec::new();
        let mut v2 = v as i64;
        loop {
            let byte = (v2 & 0x7f) as u8;
            v2 >>= 7;
            if (v2 == 0 && byte & 0x40 == 0) || (v2 == -1 && byte & 0x40 != 0) {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
        buf.extend_from_slice(&out);
    }

    let mut pos = 0;
    for v in [0u64, 1, 63, 64, 127, 128, 0x1000, u64::from(u32::MAX), u64::MAX / 2] {
        let (got, p) = sleb128_decode(&buf, pos).unwrap();
        assert_eq!(got, v, "sleb128 value mismatch");
        pos = p;
    }
}

#[test]
#[ignore]
fn dump_fixture() {
    std::fs::write("/tmp/fixture.so", build_elf64()).unwrap();
}

#[test]
fn fixture_parse_and_lookup() {
    let data = build_elf64();
    let img = ElfImage::parse(&data).unwrap();

    assert!(img.is_64());
    assert_eq!(img.machine(), EM_AARCH64);
    assert_eq!(img.bias(), 0);
    assert_eq!(img.dynsym_count(), 4);

    // Hash lookups.
    let s = img.symbol_by_name("exported_fn").expect("exported_fn via hash");
    assert_eq!(s.value, 0x5000);
    assert_eq!(s.type_(), crate::STT_FUNC);

    // SysV path directly exercised because the GNU table only contains
    // exported_fn: this must go through ElfLookup.
    let s2 = img.symbol_by_name("local_data").expect("local_data via sysv");
    assert_eq!(s2.value, 0x6000);
    assert_eq!(s2.type_(), crate::STT_OBJECT);

    assert!(img.symbol_by_name("missing_fn").is_none());
    assert!(img.symbol_by_name("imported_fn").is_none()); // SHN_UNDEF skipped

    // Dynamic segment round trip: DT_SYMTAB points into the file and the
    // symbols are readable through it (no section headers in the fixture).
    let symtab_vaddr = img.dynamic_find(DT_SYMTAB).expect("DT_SYMTAB present");
    assert!(img.vaddr_to_file_offset(symtab_vaddr).is_some());
    let s = img.symbol_at(1).expect("dynsym[1]");
    assert_eq!(s.name, "exported_fn");
}

#[test]
fn fixture_relocations_in_c_order() {
    let data = build_elf64();
    let img = ElfImage::parse(&data).unwrap();

    let relocs = img.relocations().unwrap();
    // 2 RELA + 1 packed + 1 JMPREL
    assert_eq!(relocs.len(), 4);

    assert_eq!(relocs[0].offset, 0x1000);
    assert_eq!(relocs[0].rtype as u64, R_AARCH64_RELATIVE);
    assert!(relocs[0].has_addend);
    assert_eq!(relocs[0].addend, 0x2000);

    assert_eq!(relocs[1].rtype as u64, R_AARCH64_GLOB_DAT);
    assert_eq!(relocs[1].sym_idx, 1);

    // packed APS2 entry: offset = 0x800, RELATIVE, addend 0x4000
    assert_eq!(relocs[2].offset, 0x800);
    assert_eq!(relocs[2].rtype as u64, R_AARCH64_RELATIVE);
    assert_eq!(relocs[2].addend, 0x4000);

    // jmprel: JUMP_SLOT sym 2
    assert_eq!(relocs[3].rtype as u64, R_AARCH64_JUMP_SLOT);
    assert_eq!(relocs[3].sym_idx, 2);

    // RELR: explicit 0x3000, bitmap words 0x3008 and 0x3018
    let relr = img.relr_offsets().unwrap();
    assert_eq!(relr, vec![0x3000, 0x3008, 0x3018]);
}

#[test]
fn generic_reloc_mapping() {
    // aarch64
    assert_eq!(generic_reloc_type(EM_AARCH64, 1027), GenericReloc::Relative);
    assert_eq!(generic_reloc_type(EM_AARCH64, types::aarch64::JUMP_SLOT), GenericReloc::JumpSlot);
    assert_eq!(generic_reloc_type(EM_AARCH64, types::aarch64::IRELATIVE), GenericReloc::IRelative);
    // arm
    assert_eq!(generic_reloc_type(EM_ARM, types::arm::ABS32), GenericReloc::Absolute);
    assert_eq!(generic_reloc_type(EM_ARM, types::arm::IRELATIVE), GenericReloc::IRelative);
    // x86_64
    assert_eq!(generic_reloc_type(EM_X86_64, types::x86_64::PC32), GenericReloc::X86_64_PC32);
    assert_eq!(generic_reloc_type(EM_X86_64, types::x86_64::DTPMOD64), GenericReloc::TlsDtpmod);
    // unknown machine
    assert_eq!(generic_reloc_type(999, 42), GenericReloc::Other(42));
}

#[test]
fn relr_word32_and_packed_rel() {
    // RELR 32-bit: explicit 0x100, then bitmap setting bits 0,1
    let mut table = Vec::new();
    table.extend(0x100u32.to_le_bytes());
    table.extend(((0b11u32 << 1) | 1).to_le_bytes());
    let offs = decode_relr(&table, 4).unwrap();
    assert_eq!(offs, vec![0x100, 0x104, 0x108]);

    // packed REL (no addend flag): 2 relocs RELATIVE at deltas
    let mut packed = Vec::new();
    packed.extend_from_slice(b"APS2");
    let push = |v: u64, out: &mut Vec<u8>| {
        let mut v = v as i64;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if (v == 0 && byte & 0x40 == 0) || (v == -1 && byte & 0x40 != 0) {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    };
    push(2, &mut packed); // 2 relocs
    push(2, &mut packed); // group size
    push(2, &mut packed); // flags: GROUPED_BY_OFFSET_DELTA only
    push(0x10, &mut packed); // offset delta
    push(23, &mut packed); // r_info: R_ARM_RELATIVE
    push(23, &mut packed); // second reloc r_info (info grouping is off)
    let relocs = decode_android_packed(&packed, false, false).unwrap();
    assert_eq!(relocs.len(), 2);
    assert!(!relocs[0].has_addend);
    assert_eq!(relocs[0].addend, 0);
    assert_eq!(relocs[0].rtype, 23);
    assert_eq!(relocs[0].sym_idx, 0);
    assert_eq!(relocs[1].offset, relocs[0].offset + 0x10);
}

#[test]
fn elf_hash_matches_sysv_spec() {
    // Reference values computed independently in Python.
    assert_eq!(elf_hash(""), 0);
    assert_eq!(elf_hash("printf"), 0x0779_05a6);
    assert_eq!(gnu_hash(""), 5381);
    assert_eq!(gnu_hash("a"), (5381u32 << 5).wrapping_add(5381) + 97);
    assert_eq!(gnu_hash("exported_fn"), 0x324f_a963);
}

#[test]
fn real_lib_zygisk_lookup() {
    // Real-world check against the C fork's arm64 libzygisk.so (GNU hash,
    // RELA relocations, stripped sections aside from dynamic ones).
    let path = concat!(
        "/home/nemo/MIX_4_ODIN/out/ReZygisk/build/obj/release/loader/",
        "arm64-v8a/stripped/libzygisk.so"
    );
    let Ok(data) = std::fs::read(path) else {
        eprintln!("libzygisk.so not present; skipping");
        return;
    };

    let img = ElfImage::parse(&data).unwrap();
    assert_eq!(img.machine(), EM_AARCH64);

    // Every zygisk .so exports its module entry via the companion ABI.
    let relocs = img.relocations().unwrap();
    assert!(
        relocs.iter().any(|r| generic_reloc_type(EM_AARCH64, r.rtype) == GenericReloc::Relative),
        "libzygisk.so has no RELATIVE relocs"
    );

    // zygisk_companion_entry is exported by the companion side of the fork.
    if let Some(s) = img.symbol_by_name("zygisk_companion_entry") {
        assert_eq!(s.type_(), crate::STT_FUNC);
        assert_ne!(s.value, 0);
    } else {
        eprintln!("zygisk_companion_entry not exported in this build");
    }
}
