//! linker.c `_linker_process_relocations` decoding: unified relocation entries
//! from DT_RELA/REL, DT_JMPREL, Android packed (APS2) tables and RELR, plus the
//! SLEB128 primitives those tables are built on.

pub const APS2_MAGIC: &[u8; 4] = b"APS2";

#[inline]
fn split_r_info(r_info: u64, is_64: bool, sym: &mut u32, rtype: &mut u32) {
    if is_64 {
        *sym = (r_info >> 32) as u32;
        *rtype = (r_info & 0xffff_ffff) as u32;
    } else {
        *sym = ((r_info & 0xffff_ffff) >> 8) as u32;
        *rtype = (r_info & 0xff) as u32;
    }
}

// Android packed-reloc dynamic tags.
pub const DT_ANDROID_REL: u64 = 0x6000_000f;
pub const DT_ANDROID_RELSZ: u64 = 0x6000_0010;
pub const DT_ANDROID_RELA: u64 = 0x6000_001f;
pub const DT_ANDROID_RELASZ: u64 = 0x6000_0020;
pub const DT_ANDROID_RELR: u64 = 0x06ff_e000;
pub const DT_ANDROID_RELRSZ: u64 = 0x06ff_e001;
pub const DT_ANDROID_RELRENT: u64 = 0x06ff_e003;

// Standard RELR tags.
pub const DT_RELRSZ: u64 = 35;
pub const DT_RELR: u64 = 36;
pub const DT_RELRENT: u64 = 37;

// Relocation group flags (Android packed format).
pub const RELOCATION_GROUPED_BY_INFO_FLAG: u64 = 1;
pub const RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG: u64 = 2;
pub const RELOCATION_GROUPED_BY_ADDEND_FLAG: u64 = 4;
pub const RELOCATION_GROUP_HAS_ADDEND_FLAG: u64 = 8;

/// A unified relocation entry (linker.c `_linker_unified_r`).
///
/// `has_addend` mirrors the C `is_rela` flag: when false the addend is read
/// from the target word at runtime instead of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reloc {
    pub offset: u64,
    pub sym_idx: u32,
    pub rtype: u32,
    pub addend: u64,
    pub has_addend: bool,
}

/// Decode one signed LEB128 value at `pos`, returning (value, new_pos).
pub fn sleb128_decode(buf: &[u8], pos: usize) -> crate::Result<(u64, usize)> {
    let mut value: i64 = 0;
    let mut shift: u32 = 0;
    let mut p = pos;
    let byte = loop {
        let b = *buf
            .get(p)
            .ok_or(crate::Error::OutOfBounds("sleb128 byte", p))?;
        p += 1;
        // The C payload shift (`(int64_t)(byte & 0x7f) << shift`,
        // sleb128.c) is UB for shift >= 64; arm64/x86_64 hardware masks the
        // shift to 6 bits, so mask here too (mirrors
        // csoloader/src/misc.rs sleb128_decode).
        value |= ((b & 0x7f) as i64).wrapping_shl(shift & 63);
        shift += 7;
        if b & 0x80 == 0 {
            break b;
        }
    };
    if shift < 64 && byte & 0x40 != 0 {
        value |= -1i64 << shift;
    }
    Ok((value as u64, p))
}

/// Decode an Android packed relocation table ("APS2") exactly like linker.c:
/// `is_rela` selects RELA vs REL semantics for addends; `is_64` selects the
/// ELF64 (sym = info >> 32) vs ELF32 (sym = info >> 8) r_info layout.
pub fn decode_android_packed(table: &[u8], is_rela: bool, is_64: bool) -> crate::Result<Vec<Reloc>> {
    if table.len() < 4 || &table[..4] != APS2_MAGIC {
        return Err(crate::Error::Other("Invalid Android packed reloc magic".into()));
    }

    let mut out = Vec::new();
    let mut pos = 4;

    let (num_relocs, p) = sleb128_decode(table, pos)?;
    pos = p;

    // linker.c: the value right after num_relocs is the ABSOLUTE
    // initial r_offset — group fields are deltas on top of it. Skipping this
    // desyncs the whole stream on real lld output (the initial offset gets
    // read as the first group's size).
    let (initial_offset, p) = sleb128_decode(table, pos)?;
    pos = p;
    let mut r_offset: u64 = initial_offset;
    let mut sym_idx: u32 = 0;
    let mut rtype: u32 = 0;
    let mut r_addend: u64 = 0;

    let mut i: u64 = 0;
    while i < num_relocs {
        let (group_size, p) = sleb128_decode(table, pos)?;
        pos = p;
        if group_size == 0 {
            // C hangs here (`for (i = 0; i < num_relocs; ) { ... i += 0; }`);
            // the stream is malformed, so fail instead of looping forever.
            return Err(crate::Error::Other(
                "APS2: zero-sized relocation group".into(),
            ));
        }
        let (group_flags, p) = sleb128_decode(table, pos)?;
        pos = p;

        let mut group_r_offset_delta = 0u64;
        if group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG != 0 {
            let (d, p) = sleb128_decode(table, pos)?;
            group_r_offset_delta = d;
            pos = p;
        }

        if group_flags & RELOCATION_GROUPED_BY_INFO_FLAG != 0 {
            let (r_info, p) = sleb128_decode(table, pos)?;
            pos = p;
            split_r_info(r_info, is_64, &mut sym_idx, &mut rtype);
        }

        if !is_rela && group_flags & RELOCATION_GROUP_HAS_ADDEND_FLAG != 0 {
            // C LOGFs here ("REL relocations should not have addends"); the
            // per-reloc addend bytes would otherwise desync the stream.
            return Err(crate::Error::Other(
                "APS2: REL relocation group carries addends".into(),
            ));
        }

        let group_flags_reloc = if is_rela {
            group_flags & (RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG)
        } else {
            0
        };

        if group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG {
            // Per-relocation addends (lld default): nothing now.
        } else if group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG | RELOCATION_GROUPED_BY_ADDEND_FLAG {
            let (delta, p) = sleb128_decode(table, pos)?;
            pos = p;
            r_addend = r_addend.wrapping_add(delta);
        } else {
            r_addend = 0;
        }

        for _ in 0..group_size {
            if group_flags & RELOCATION_GROUPED_BY_OFFSET_DELTA_FLAG != 0 {
                r_offset = r_offset.wrapping_add(group_r_offset_delta);
            } else {
                let (delta, p) = sleb128_decode(table, pos)?;
                pos = p;
                r_offset = r_offset.wrapping_add(delta);
            }

            if group_flags & RELOCATION_GROUPED_BY_INFO_FLAG == 0 {
                let (r_info, p) = sleb128_decode(table, pos)?;
                pos = p;
                split_r_info(r_info, is_64, &mut sym_idx, &mut rtype);
            }

            if is_rela && group_flags_reloc == RELOCATION_GROUP_HAS_ADDEND_FLAG {
                let (delta, p) = sleb128_decode(table, pos)?;
                pos = p;
                r_addend = r_addend.wrapping_add(delta);
            }

            out.push(Reloc {
                offset: r_offset,
                sym_idx,
                rtype,
                addend: r_addend,
                has_addend: is_rela,
            });
        }

        i += group_size;
    }

    Ok(out)
}

/// RELR is not a list of relocations: each entry means "add the load bias to
/// the word at this offset". Returns the offsets the caller must fix up.
pub fn decode_relr(entries: &[u8], word_size: usize) -> crate::Result<Vec<u64>> {
    debug_assert!(word_size == 8 || word_size == 4);
    let bits_per_entry = word_size * 8;
    let count = entries.len() / word_size;
    let mut out = Vec::new();
    let mut base_offset = 0u64;

    for i in 0..count {
        let off = i * word_size;
        let entry = if word_size == 8 {
            u64::from_le_bytes(entries[off..off + 8].try_into().unwrap())
        } else {
            u32::from_le_bytes(entries[off..off + 4].try_into().unwrap()) as u64
        };

        if entry & 1 == 0 {
            // Even entries encode an explicit address.
            out.push(entry);
            base_offset = entry.wrapping_add(word_size as u64);
            continue;
        }

        // Odd entries encode a bitmap of following words.
        let mut bitmap = entry >> 1;
        let mut bit = 0usize;
        while bitmap != 0 && bit < bits_per_entry - 1 {
            if bitmap & 1 != 0 {
                out.push(base_offset.wrapping_add((bit * word_size) as u64));
            }
            bitmap >>= 1;
            bit += 1;
        }

        base_offset = base_offset.wrapping_add((word_size * (bits_per_entry - 1)) as u64);
    }

    Ok(out)
}
