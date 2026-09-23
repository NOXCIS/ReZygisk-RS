//! Host integration tests for the APS2 / RELR / SLEB128 decoders.
//!
//! Expected values are derived from the C reference:
//! - sleb128: loader/src/external/csoloader/src/sleb128.c (also duplicated in
//!   external/plti/src/elf_util.c)
//! - APS2: loader/src/external/csoloader/src/linker.c
//!   (`_linker_process_relocations` Android packed handling)
//! - RELR: loader/src/external/csoloader/src/linker.c
//!
//! These complement the in-crate unit tests (src/tests.rs) which already
//! cover the absolute-initial-offset consumption, zero-group and
//! REL-with-addend guards.

use rz_elf::{decode_android_packed, decode_relr, sleb128_decode, Reloc};

// Android packed-relocation group flags (lld/reloc.h RELOCATION_GROUP*_FLAG;
// linker.c interprets these exact bits). The rz-elf reloc module is
// private, so the format constants are spelled out here.
const RELOCATION_GROUPED_BY_INFO_FLAG: i64 = 1;
const RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG: i64 = 2;
const RELOCATION_GROUPED_BY_ADDEND_FLAG: i64 = 4;
const RELOCATION_GROUP_HAS_ADDEND_FLAG: i64 = 8;

/// Encode a signed LEB128 value (mirrors lld's encoder).
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

/// Encode one encoded-value vector for use in APS2 tables.
fn sleb(v: i64) -> Vec<u8> {
    let mut out = Vec::new();
    push_sleb(&mut out, v);
    out
}

fn aps2(table: &[u8], is_rela: bool, is_64: bool) -> Result<Vec<Reloc>, rz_elf::Error> {
    decode_android_packed(table, is_rela, is_64)
}

/// ELF64 r_info helper: (sym << 32) | type.
fn r_info64(sym: u32, rtype: u32) -> i64 {
    ((sym as u64) << 32 | rtype as u64) as i64
}

/// ELF32 r_info helper: (sym << 8) | type.
fn r_info32(sym: u32, rtype: u32) -> i64 {
    ((sym << 8) | rtype) as i64
}

fn rel(offset: u64, sym_idx: u32, rtype: u32, addend: u64, has_addend: bool) -> Reloc {
    Reloc { offset, sym_idx, rtype, addend, has_addend }
}

// ---------------------------------------------------------------------------
// SLEB128 (sleb128.c)
// ---------------------------------------------------------------------------

#[test]
fn sleb128_edges_match_sleb128_c() {
    // (encoded bytes, expected decoded value as u64) — the C decoder returns
    // int64_t; all of these are well-formed ≤10-byte encodings where the C
    // shift is never >= 64 (no UB), so the Rust result must match exactly.
    let cases: &[(i64, &[u8])] = &[
        (0, &[0x00]),
        (1, &[0x01]),
        (-1, &[0x7f]),
        (63, &[0x3f]),
        (-64, &[0x40]),
        (64, &[0xc0, 0x00]),
        (-65, &[0xbf, 0x7f]),
        (127, &[0xff, 0x00]),
        (128, &[0x80, 0x01]),
        (-128, &[0x80, 0x7f]),
        (300, &[0xac, 0x02]),
        (
            i64::MAX,
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00],
        ),
        (
            i64::MIN,
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f],
        ),
    ];

    for (val, enc) in cases {
        assert_eq!(
            sleb128_decode(enc, 0).unwrap(),
            (*val as u64, enc.len()),
            "decode of {enc:02x?} -> {val}"
        );
    }

    // Decoding at a nonzero position must return positions relative to the
    // caller's `pos`, not to the buffer start.
    let mut prefixed = vec![0xab, 0xcd];
    prefixed.extend_from_slice(&[0xc0, 0x00]); // 64
    assert_eq!(sleb128_decode(&prefixed, 2).unwrap(), (64u64, 4));

    // Truncated continuation byte: the C LOGFs on buffer overrun; the Rust
    // port must surface an error instead.
    assert!(sleb128_decode(&[0x80], 0).is_err());
    assert!(sleb128_decode(&[], 0).is_err());
    assert!(sleb128_decode(&[0xff, 0xff], 1).is_err());
}

// ---------------------------------------------------------------------------
// APS2 (linker.c)
// ---------------------------------------------------------------------------

#[test]
fn aps2_32bit_r_info_split_and_absolute_initial_offset() {
    // ELF32 layout (linker.c: ELF_R_SYM(info) = info >> 8 for 32-bit): the
    // same encoded r_info splits differently than on 64-bit. Initial offset
    // is ABSOLUTE (unified_r.r_offset = next sleb, per linker.c).
    let mut t = b"APS2".to_vec();
    t.extend(sleb(2)); // num_relocs
    t.extend(sleb(0x100)); // absolute initial r_offset
    t.extend(sleb(2)); // group_size
    t.extend(sleb(0)); // flags: per-reloc deltas and r_infos
    t.extend(sleb(4)); // offset delta
    t.extend(sleb(r_info32(0x1234, 7))); // sym 0x1234, type 7
    t.extend(sleb(4)); // offset delta
    t.extend(sleb(r_info32(0xab, 0x16))); // sym 0xab, type 0x16

    assert_eq!(
        aps2(&t, false, false).unwrap(),
        vec![
            rel(0x104, 0x1234, 7, 0, false),
            rel(0x108, 0xab, 0x16, 0, false),
        ]
    );

    // The same stream decoded as 64-bit splits r_info at bit 32 instead.
    assert_eq!(
        aps2(&t, false, true).unwrap(),
        vec![
            rel(0x104, 0, 0x123407, 0, false),
            rel(0x108, 0, 0xab16, 0, false),
        ]
    );
}

#[test]
fn aps2_negative_deltas() {
    // Offset deltas are signed sleb values added to the running absolute
    // offset (unified_r.r_offset += sleb128_decode(), per linker.c).
    let mut t = b"APS2".to_vec();
    t.extend(sleb(3));
    t.extend(sleb(0x2000));
    t.extend(sleb(3));
    t.extend(sleb(0));
    t.extend(sleb(0)); // first reloc stays at the initial offset
    t.extend(sleb(r_info64(1, 1026)));
    t.extend(sleb(-8)); // 0x1ff8
    t.extend(sleb(r_info64(1, 1026)));
    t.extend(sleb(-16)); // 0x1fe8
    t.extend(sleb(r_info64(1, 1026)));

    assert_eq!(
        aps2(&t, true, true).unwrap(),
        vec![
            rel(0x2000, 1, 1026, 0, true),
            rel(0x1ff8, 1, 1026, 0, true),
            rel(0x1fe8, 1, 1026, 0, true),
        ]
    );
}

#[test]
fn aps2_offset_wrap_around() {
    // The C accumulates into ElfW(Addr) (unsigned) — overflow wraps, it does
    // not saturate or fail.
    let mut t = b"APS2".to_vec();
    t.extend(sleb(3));
    t.extend(sleb(i64::MAX - 2)); // initial offset near u64::MAX
    t.extend(sleb(3));
    t.extend(sleb(0));
    t.extend(sleb(1));
    t.extend(sleb(r_info64(0, 1027)));
    t.extend(sleb(1));
    t.extend(sleb(r_info64(0, 1027)));
    t.extend(sleb(2)); // MAX + 2 wraps to 1
    t.extend(sleb(r_info64(0, 1027)));

    let got = aps2(&t, false, true).unwrap();
    let offsets: Vec<u64> = got.iter().map(|r| r.offset).collect();
    assert_eq!(
        offsets,
        vec![
            (i64::MAX - 1) as u64, // 0x7fff_ffff_ffff_fffe
            i64::MAX as u64,       // 0x7fff_ffff_ffff_ffff
            0x8000_0000_0000_0001, // wrapped
        ]
    );
}

#[test]
fn aps2_grouped_info_with_group_offset_delta() {
    // flags = GROUPED_BY_INFO | GROUPED_BY_OFFSET_DELTA (linker.c): one
    // r_info and one delta per group, applied to every reloc
    // in that group; sym/type carry into later groups only when a new r_info
    // is present.
    let mut t = b"APS2".to_vec();
    t.extend(sleb(4));
    t.extend(sleb(0x1000));
    // group 1: 2 relocs, delta 8, r_info sym 1 JUMP_SLOT
    t.extend(sleb(2));
    t.extend(sleb(RELOCATION_GROUPED_BY_INFO_FLAG | RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG));
    t.extend(sleb(8)); // group offset delta
    t.extend(sleb(r_info64(1, 1026)));
    // group 2: 2 relocs, delta 4, r_info sym 2 GLOB_DAT
    t.extend(sleb(2));
    t.extend(sleb(RELOCATION_GROUPED_BY_INFO_FLAG | RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG));
    t.extend(sleb(4));
    t.extend(sleb(r_info64(2, 1025)));

    assert_eq!(
        aps2(&t, true, true).unwrap(),
        vec![
            rel(0x1008, 1, 1026, 0, true),
            rel(0x1010, 1, 1026, 0, true),
            rel(0x1014, 2, 1025, 0, true),
            rel(0x1018, 2, 1025, 0, true),
        ]
    );
}

#[test]
fn aps2_addend_accumulation_across_groups() {
    // linker.c addend state machine:
    // - HAS_ADDEND|GROUPED_BY_ADDEND: r_addend += one group delta; r_addend is
    //   NOT reset between groups, so groups accumulate.
    // - HAS_ADDEND alone: per-reloc deltas accumulate onto the running
    //   r_addend.
    // - neither flag: r_addend = 0 (reset).
    let mut t = b"APS2".to_vec();
    t.extend(sleb(7));
    t.extend(sleb(0x1000));
    // group 1: grouped addend delta 10 → addends 10, 10
    t.extend(sleb(2));
    t.extend(sleb(RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG));
    t.extend(sleb(10));
    t.extend(sleb(0));
    t.extend(sleb(r_info64(1, 1026)));
    t.extend(sleb(4));
    t.extend(sleb(r_info64(1, 1026)));
    // group 2: grouped addend delta 20 → addends 30, 30 (10 + 20)
    t.extend(sleb(2));
    t.extend(sleb(RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG));
    t.extend(sleb(20));
    t.extend(sleb(0));
    t.extend(sleb(r_info64(1, 1026)));
    t.extend(sleb(4));
    t.extend(sleb(r_info64(1, 1026)));
    // group 3: per-reloc addends 1, 2 → 31, 33 (continue from 30)
    t.extend(sleb(2));
    t.extend(sleb(RELOCATION_GROUP_HAS_ADDEND_FLAG));
    t.extend(sleb(0));
    t.extend(sleb(r_info64(1, 1026)));
    t.extend(sleb(1));
    t.extend(sleb(4));
    t.extend(sleb(r_info64(1, 1026)));
    t.extend(sleb(2));
    // group 4: no addend flags → reset to 0
    t.extend(sleb(1));
    t.extend(sleb(0));
    t.extend(sleb(0));
    t.extend(sleb(r_info64(1, 1026)));

    assert_eq!(
        aps2(&t, true, true).unwrap(),
        vec![
            rel(0x1000, 1, 1026, 10, true),
            rel(0x1004, 1, 1026, 10, true),
            rel(0x1004, 1, 1026, 30, true),
            rel(0x1008, 1, 1026, 30, true),
            rel(0x1008, 1, 1026, 31, true),
            rel(0x100c, 1, 1026, 33, true),
            rel(0x100c, 1, 1026, 0, true),
        ]
    );
}

#[test]
fn aps2_error_paths() {
    // Bad magic (linker.c returns false on non-"APS2").
    assert!(aps2(b"XPS2", true, true).is_err());
    // Truncated: num_relocs present but the stream ends mid-group.
    let mut t = b"APS2".to_vec();
    t.extend(sleb(3));
    t.extend(sleb(0x100));
    t.extend(sleb(3));
    t.extend(sleb(0));
    t.extend(sleb(0));
    t.extend(sleb(r_info64(1, 1026)));
    assert!(aps2(&t, false, true).is_err());
    // Truncated to just the magic: even num_relocs is missing.
    assert!(aps2(b"APS2", false, true).is_err());
    // Zero-sized group: the C `i += group_size` would loop forever
    // (infinite loop in the C); the Rust port rejects the malformed stream.
    let mut t = b"APS2".to_vec();
    t.extend(sleb(1));
    t.extend(sleb(0));
    t.extend(sleb(0)); // group_size == 0
    t.extend(sleb(0));
    assert!(aps2(&t, false, true).is_err());
    // REL table with HAS_ADDEND: the C LOGFs "REL relocations should not
    // have addends"; the Rust port errors.
    let mut t = b"APS2".to_vec();
    t.extend(sleb(1));
    t.extend(sleb(0));
    t.extend(sleb(1));
    t.extend(sleb(RELOCATION_GROUP_HAS_ADDEND_FLAG));
    t.extend(sleb(0x10));
    t.extend(sleb(r_info64(0, 1027)));
    assert!(aps2(&t, false, true).is_err());
}

// ---------------------------------------------------------------------------
// RELR (linker.c)
// ---------------------------------------------------------------------------

#[test]
fn relr_64_walker_matches_linker_c() {
    // entries: [0x1000 direct, 5 bitmap, 0x1208 direct, 3 bitmap]
    // i0: even → reloc @0x1000; base = 0x1000 + 8 = 0x1008
    // i1: odd, bitmap = 0b10 → bit 1 → reloc @0x1008 + 8 = 0x1010;
    //     base += 8 * (64 - 1) → 0x1008 + 0x1f8 = 0x1200
    // i2: even → reloc @0x1208; base = 0x1210
    // i3: odd, bitmap = 1 → bit 0 → reloc @0x1210
    let entries: Vec<u8> = [0x1000u64, 0x5, 0x1208, 0x3]
        .iter()
        .flat_map(|e| e.to_le_bytes())
        .collect();
    assert_eq!(
        decode_relr(&entries, 8).unwrap(),
        vec![0x1000, 0x1010, 0x1208, 0x1210]
    );
}

#[test]
fn relr_64_top_entry_bit_is_last_bitmap_bit() {
    // Entry with the marker and bit 63 set: after `entry >> 1` that top bit
    // becomes bitmap bit 62, which the C walker (`bit < bits_per_entry - 1`)
    // DOES process as the last relocation bit —
    // it is not ignored. Relocation lands at base + 62 * 8.
    let entry: u64 = 1 | (1 << 63);
    let entries: Vec<u8> = entry.to_le_bytes().to_vec();
    assert_eq!(decode_relr(&entries, 8).unwrap(), vec![62 * 8]);
}

#[test]
fn relr_32_walker_matches_linker_c() {
    // Same walker with 4-byte words (linker.c: sizeof(ElfW(Addr)) == 4):
    // i0: 0x1000 even → reloc; base = 0x1004
    // i1: 5 → bitmap 0b10 → bit 1 → 0x1004 + 4 = 0x1008; base += 4 * 31 → 0x1080
    // i2: 0x1084 even → reloc; base = 0x1088
    // i3: 3 → bit 0 → 0x1088
    let entries: Vec<u8> = [0x1000u32, 0x5, 0x1084, 0x3]
        .iter()
        .flat_map(|e| e.to_le_bytes())
        .collect();
    assert_eq!(
        decode_relr(&entries, 4).unwrap(),
        vec![0x1000, 0x1008, 0x1084, 0x1088]
    );

    // 32-bit top entry bit: bitmap bit 30 → base + 30 * 4.
    let entry: u32 = 1 | (1 << 31);
    let entries: Vec<u8> = entry.to_le_bytes().to_vec();
    assert_eq!(decode_relr(&entries, 4).unwrap(), vec![30 * 4]);
}
