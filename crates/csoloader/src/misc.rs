//! Ports of `loader/src/external/csoloader`:
//! - `src/carray.c` (+ `include/carray.h`): the `struct carray` string array
//!   used by `linker_link` to queue DT_NEEDED
//!   dependencies.
//! - `src/sleb128.c` (+ `include/sleb128.h`): the signed LEB128 decoder used
//!   by the Android packed-relocation path.
//! - `src/backtrace-support.c`: a documented minimal subset — see the
//!   "backtrace subset" section below.
//!
//! Port notes (C-parity decisions):
//! - `carray_create`/`strdup`/`realloc` failure paths cannot occur with
//!   `Vec`; the corresponding C `LOGE`s have no Rust equivalent and are
//!   dropped. `carray_destroy` is Rust's `Drop` (the C header declares it
//!   `void` but the implementation returns `bool`; following the impl, there
//!   is nothing to return here).
//! - `carray_add` does NOT dedupe (C parity); call sites dedupe via
//!   `carray_exists` first.
//! - `sleb128_decode` is redundant for the linker fan-out: `rz_elf`'s
//!   `RelocTables.android` already returns fully decoded relocs via
//!   `decode_android_packed`, so `linker_reloc` consumes pre-decoded tables.
//!   It is ported anyway for C-parity completeness and is host-tested here.
//!
//! Everything below is exercised by host unit tests but unreferenced by the
//! lib build itself (the linker fan-out consumes `rz_elf`'s decoded tables
//! directly), so the module carries an `allow(dead_code)` to keep the C
//! surface available for future callers.

#![allow(dead_code)]

use rz_elf::LoadSegment;

pub const TAG: &str = rz_common::LOG_TAG;

macro_rules! dlogw {
    ($($arg:tt)*) => {{ rz_common::logw!(TAG, $($arg)*); }};
}
macro_rules! dloge {
    ($($arg:tt)*) => {{ rz_common::loge!(TAG, $($arg)*); }};
}

// ---------------------------------------------------------------------------
// carray.c (+ include/carray.h)
// ---------------------------------------------------------------------------

/// `struct carray` (carray.c): a growable array of owned items.
///
/// C stores `char *` slots (`strdup`-ed); here the items are moved into the
/// `Vec` by value, so no duplication step exists. Expansion is automatic
/// (`Vec` doubles like the C `realloc` path) and cannot fail.
pub struct CArray<T> {
    items: Vec<T>,
}

impl<T> CArray<T> {
    /// `carray_create(size)`.
    pub fn new(capacity: usize) -> Self {
        Self {
            items: Vec::with_capacity(capacity),
        }
    }

    /// `carray_add`: append `item`; logs the C's expansion warning when the
    /// array is full. Always succeeds — the C's `strdup`/`realloc` failure
    /// paths (`false` return) cannot happen with `Vec`. No dedupe, like C.
    pub fn add(&mut self, item: T) -> bool {
        if self.items.len() == self.items.capacity() {
            dlogw!("Carray is full, expanding size");
        }
        self.items.push(item);
        true
    }

    /// `carray_exists`. The C scans all `size` (capacity) slots skipping
    /// NULLs; because `carray_remove` compacts, that is exactly the live
    /// items `Vec` holds.
    pub fn exists(&self, item: &T) -> bool
    where
        T: PartialEq,
    {
        self.items.iter().any(|x| x == item)
    }

    /// `carray_length`.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// `carray_get`: C returns NULL without logging for an index in
    /// `[length, size)` (a hole freed by remove-then-memmove) and logs
    /// `"Invalid carray or index out of bounds"` only for `index >= size`.
    /// Mirrored via `capacity()`.
    pub fn get(&self, idx: usize) -> Option<&T> {
        if idx >= self.items.capacity() {
            dloge!("Invalid carray or index out of bounds");
            return None;
        }
        self.items.get(idx)
    }

    /// `carray_remove`: remove the first occurrence by value — the C scans
    /// all `size` slots and frees the first strcmp match, then memmove-
    /// compacts (same as `Vec::remove`). Logs the C's `"String not found in
    /// carray"` warning when the value is absent.
    pub fn remove(&mut self, item: &T) -> bool
    where
        T: PartialEq + std::fmt::Debug,
    {
        let Some(pos) = self.items.iter().position(|x| x == item) else {
            dlogw!("String not found in carray: {item:?}");
            return false;
        };
        self.items.remove(pos);
        true
    }
}

// ---------------------------------------------------------------------------
// sleb128.c (+ include/sleb128.h)
// ---------------------------------------------------------------------------

/// `sleb128_decode` (sleb128.c): decode one signed LEB128 value at `index`,
/// advancing it past the consumed bytes.
///
/// Parity notes:
/// - Overrun is `LOGF` in C (fatal log + `abort`); mirrored exactly.
/// - The C payload shift `(int64_t)(byte & 0x7f) << shift` is UB when
///   `shift >= 64`; on arm64/x86_64 the variable shift is masked to 6 bits,
///   so the shift is masked here to reproduce real-hardware behavior.
pub fn sleb128_decode(bytes: &[u8], index: &mut usize) -> i64 {
    let mut value: i64 = 0;
    let mut shift: u32 = 0;
    let mut byte: u8;

    loop {
        if *index >= bytes.len() {
            rz_common::logf!(TAG, "Failed to decode SLEB128: buffer overrun");
            std::process::abort();
        }

        byte = bytes[*index];
        *index += 1;
        value |= ((byte & 0x7f) as i64).wrapping_shl(shift & 63);
        shift += 7;
        if byte & 0x80 == 0 {
            break;
        }
    }

    if shift < 64 && (byte & 0x40) != 0 {
        // C: `value |= -((int64_t)1 << shift)` — same bit pattern.
        value |= (-1i64).wrapping_shl(shift);
    }

    value
}

// ---------------------------------------------------------------------------
// backtrace-support.c — minimal ported subset
// ---------------------------------------------------------------------------
//
// Ported (pure, byte-level or rz_elf-derivable pieces the linker's custom-lib
// registry needs):
// - `read_uleb128` (backtrace-support.c): ULEB128 reader used by the
//   `.eh_frame_hdr` decode. Overrun stops silently and returns the partial
//   value, exactly like the C.
// - `read_u16` / `read_u32` / `read_u64`: bounds-checked
//   little-endian readers; the C's `-1` overrun return maps to `None`.
// - `addr_in_load_segments`: the PT_LOAD range scan from `custom_dladdr`
//   over rz_elf-derived segments, per the audit: CsoElf does not
//   expose raw program headers, so derive them from `ElfImage::all_segments()`
//   on the file bytes.
//
// OMITTED and why:
// - `custom_dl_iterate_phdr` / `custom_dladdr`: both
//   resolve the real libdl.so symbols via `csoloader_elf_symb_address` and
//   chain over the custom-lib registry. linker.c consumes them only as raw
//   addresses for the libc PLT redirection table, which
//   belongs to the linker port. The symbol half of `custom_dladdr` reuses the
//   already-present `CsoElf::get_symbol_at`; its segment scan is ported here
//   as `addr_in_load_segments`.
// - `register_custom_library_for_backtrace` / `unregister_...`:
//   the MAX_CUSTOM_LIBS slot table + pthread mutex + `copy_program_headers`.
//   Call sites are in the linker port. When ported, the
//   `dl_phdr_info` phdr copies must come from `rz_elf::ElfImage::all_segments()`
//   over the file bytes (raw phdrs are not exposed on `CsoElf`).
// - `register_eh_frame_for_library` / `unregister_...`: weak
//   `__register_frame`/`__deregister_frame` + the registry. The address
//   computation half (`locate_eh_frame_ptr`) is already ported as
//   `CsoElf::locate_eh_frame` + `decode_eh_frame_ptr` in image.rs.
// - `decode_eh_value`: its DW_EH_PE_indirect case dereferences a
//   pointer-sized word at a *runtime* address, which a file-byte/slice API
//   cannot represent; the runtime C-parity version is image.rs
//   `decode_eh_frame_ptr`. Its slice-level primitives are ported below.
// - `copy_program_headers`: superseded by `ElfImage::all_segments()`.

const PT_LOAD: u32 = 1;

/// backtrace-support.c `read_uleb128`.
pub fn read_uleb128(bytes: &[u8], p: &mut usize) -> u64 {
    let mut r: u64 = 0;
    let mut shift: u32 = 0;
    while *p < bytes.len() {
        let b = bytes[*p];
        *p += 1;
        r |= ((b & 0x7f) as u64).wrapping_shl(shift);
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            break;
        }
    }
    r
}

/// backtrace-support.c `read_u16` (C returns -1 on overrun → `None`).
pub fn read_u16(bytes: &[u8], p: &mut usize) -> Option<u16> {
    let end = *p + 2;
    if end > bytes.len() {
        return None;
    }
    let v = u16::from_le_bytes([bytes[*p], bytes[*p + 1]]);
    *p = end;
    Some(v)
}

/// backtrace-support.c `read_u32` (C returns -1 on overrun → `None`).
pub fn read_u32(bytes: &[u8], p: &mut usize) -> Option<u32> {
    let end = *p + 4;
    if end > bytes.len() {
        return None;
    }
    let v = u32::from_le_bytes([bytes[*p], bytes[*p + 1], bytes[*p + 2], bytes[*p + 3]]);
    *p = end;
    Some(v)
}

/// backtrace-support.c `read_u64` (C returns -1 on overrun → `None`).
pub fn read_u64(bytes: &[u8], p: &mut usize) -> Option<u64> {
    let end = *p + 8;
    if end > bytes.len() {
        return None;
    }
    let mut b = [0u8; 8];
    b.copy_from_slice(&bytes[*p..end]);
    *p = end;
    Some(u64::from_le_bytes(b))
}

/// The PT_LOAD scan of `custom_dladdr` (backtrace-support.c): does
/// `addr` fall inside any PT_LOAD segment of a library loaded at
/// `dlpi_addr`? Non-PT_LOAD entries in `segments` are skipped, as in C.
///
/// `segments` is `ElfImage::all_segments()` output derived from the file
/// bytes — the C's `dlpi_phdr` copy is not exposed on `CsoElf`.
pub fn addr_in_load_segments(
    dlpi_addr: usize,
    segments: &[(u32, LoadSegment)],
    addr: usize,
) -> bool {
    let mut in_range = false;
    for (p_type, phdr) in segments {
        if *p_type != PT_LOAD {
            continue;
        }
        let seg_start = dlpi_addr.wrapping_add(phdr.vaddr as usize);
        let seg_end = seg_start.wrapping_add(phdr.memsz as usize);
        if addr >= seg_start && addr < seg_end {
            in_range = true;
        }
    }
    in_range
}

#[cfg(test)]
mod tests {
    use super::*;

    // The C has no encoder (sleb128.h declares only init + decode); this
    // test-local encoder exists purely for round-trip coverage.
    fn sleb128_encode(mut value: i64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7f) as u8;
            value >>= 7;
            let done = (value == 0 && byte & 0x40 == 0) || (value == -1 && byte & 0x40 != 0);
            out.push(byte | if done { 0 } else { 0x80 });
            if done {
                break;
            }
        }
        out
    }

    #[test]
    fn carray_add_get_exists_len() {
        let mut arr: CArray<String> = CArray::new(2);
        assert_eq!(arr.len(), 0);

        assert!(arr.add("liba.so".into()));
        assert!(arr.add("libb.so".into()));
        assert_eq!(arr.len(), 2);

        // Third add exercises the C's "Carray is full, expanding size" path.
        assert!(arr.add("libc.so".into()));
        assert_eq!(arr.len(), 3);

        assert!(arr.exists(&"liba.so".to_string()));
        assert!(arr.exists(&"libc.so".to_string()));
        assert!(!arr.exists(&"libd.so".to_string()));

        assert_eq!(arr.get(0).map(String::as_str), Some("liba.so"));
        assert_eq!(arr.get(1).map(String::as_str), Some("libb.so"));
        assert_eq!(arr.get(2).map(String::as_str), Some("libc.so"));
        // [len, capacity) hole → silent NULL, >= capacity → logged NULL (C).
        assert!(arr.get(3).is_none());
        assert!(arr.get(usize::MAX).is_none());
    }

    #[test]
    fn carray_add_does_not_dedupe() {
        // C's carray_add never dedupes; linker.c calls carray_exists first.
        let mut arr: CArray<&str> = CArray::new(4);
        assert!(arr.add("dup"));
        assert!(arr.add("dup"));
        assert_eq!(arr.len(), 2);
        assert_eq!(arr.get(0), Some(&"dup"));
        assert_eq!(arr.get(1), Some(&"dup"));
    }

    #[test]
    fn carray_remove_compacts() {
        let mut arr: CArray<i32> = CArray::new(8);
        for i in 0..5 {
            assert!(arr.add(i));
        }

        // C removes the first match by value, then memmove-compacts.
        assert!(arr.remove(&1));
        assert_eq!(arr.len(), 4);
        assert_eq!(arr.get(0), Some(&0));
        assert_eq!(arr.get(1), Some(&2));
        assert_eq!(arr.get(2), Some(&3));
        assert_eq!(arr.get(3), Some(&4));
        assert!(arr.get(4).is_none());

        assert!(!arr.remove(&7));
        assert_eq!(arr.len(), 4);
    }

    #[test]
    fn sleb128_known_vectors() {
        let cases: &[(i64, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (-1, &[0x7f]),
            (63, &[0x3f]),
            (-64, &[0x40]),
            (64, &[0xc0, 0x00]),
            (-65, &[0xbf, 0x7f]),
            (128, &[0x80, 0x01]),
            (-128, &[0x80, 0x7f]),
            (624485, &[0xe5, 0x8e, 0x26]),
            (-624485, &[0x9b, 0xf1, 0x59]),
            (i64::MIN, &[0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f]),
            (i64::MAX, &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]),
        ];
        for (value, encoded) in cases {
            let mut idx = 0;
            assert_eq!(sleb128_decode(encoded, &mut idx), *value, "decode {value}");
            assert_eq!(idx, encoded.len(), "full consumption of {value}");
        }
    }

    #[test]
    fn sleb128_round_trip() {
        let values = [
            0,
            1,
            -1,
            2,
            -2,
            63,
            -63,
            64,
            -64,
            65,
            -65,
            127,
            -127,
            128,
            -128,
            129,
            -129,
            624485,
            -624485,
            123_456_789,
            -123_456_789,
            0x1234_5678_9abc_def,
            -0x1234_5678_9abc_def,
            -1 << 62,
            (1 << 62) - 1,
            i64::MAX,
            i64::MIN,
        ];
        for value in values {
            let encoded = sleb128_encode(value);
            let mut idx = 0;
            assert_eq!(sleb128_decode(&encoded, &mut idx), value, "round-trip {value}");
            assert_eq!(idx, encoded.len(), "consumed exactly {value}");

            // Re-encoding the decoded stream reproduces the same bytes.
            let mut idx = 0;
            assert_eq!(sleb128_encode(sleb128_decode(&encoded, &mut idx)), encoded);
        }
    }

    #[test]
    fn sleb128_stream_decode() {
        let mut stream = Vec::new();
        stream.extend_from_slice(&sleb128_encode(1));
        stream.extend_from_slice(&sleb128_encode(-1));
        stream.extend_from_slice(&sleb128_encode(624485));

        let mut idx = 0;
        assert_eq!(sleb128_decode(&stream, &mut idx), 1);
        assert_eq!(sleb128_decode(&stream, &mut idx), -1);
        assert_eq!(sleb128_decode(&stream, &mut idx), 624485);
        assert_eq!(idx, stream.len());
    }

    #[test]
    fn read_scalars_le_and_overrun() {
        let b = [
            0x34u8, 0x12, // u16 = 0x1234
            0x78, 0x56, 0x34, 0x12, // u32 = 0x12345678
            0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12, // u64
        ];
        let mut p = 0;
        assert_eq!(read_u16(&b, &mut p), Some(0x1234));
        assert_eq!(p, 2);
        assert_eq!(read_u32(&b, &mut p), Some(0x1234_5678));
        assert_eq!(p, 6);
        assert_eq!(read_u64(&b, &mut p), Some(0x1234_5678_9abc_def0));
        assert_eq!(p, 14);

        // C returns -1 and leaves the cursor untouched on overrun.
        assert_eq!(read_u16(&b, &mut p), None);
        assert_eq!(p, 14);
    }

    #[test]
    fn uleb128_known_and_truncated() {
        let b = [0xe5u8, 0x8e, 0x26];
        let mut p = 0;
        assert_eq!(read_uleb128(&b, &mut p), 624485);
        assert_eq!(p, 3);

        // C stops silently at the end and returns the partial value.
        let truncated = [0xe5u8];
        let mut p = 0;
        assert_eq!(read_uleb128(&truncated, &mut p), 0x65);
        assert_eq!(p, 1);

        let truncated = [0x80u8, 0x80];
        let mut p = 0;
        assert_eq!(read_uleb128(&truncated, &mut p), 0);
        assert_eq!(p, 2);

        let empty: [u8; 0] = [];
        let mut p = 0;
        assert_eq!(read_uleb128(&empty, &mut p), 0);
        assert_eq!(p, 0);
    }

    #[test]
    fn addr_in_load_segments_ranges() {
        const PT_DYNAMIC: u32 = 2;
        let seg = LoadSegment {
            vaddr: 0x1000,
            memsz: 0x2000,
            filesz: 0x2000,
            offset: 0,
            flags: 5,
        };
        let base = 0x7000_0000_0000usize;
        let segments = [(PT_LOAD, seg)];

        assert!(addr_in_load_segments(base, &segments, base + 0x1000));
        assert!(addr_in_load_segments(base, &segments, base + 0x2fff));
        // seg_end is exclusive (`addr < seg_end` in C).
        assert!(!addr_in_load_segments(base, &segments, base + 0x3000));
        assert!(!addr_in_load_segments(base, &segments, base + 0xfff));

        // Non-PT_LOAD entries are skipped even if they cover the address.
        let mixed = [(PT_DYNAMIC, seg)];
        assert!(!addr_in_load_segments(base, &mixed, base + 0x2000));
    }
}

// ---------------------------------------------------------------------------
// CSOLOADER_MAKE_LINKER_HOOKS stubs
// ---------------------------------------------------------------------------
// See linker_load.rs: the C compiles these out (macro undefined), and the
// port keeps the same default. Inert until the build flag is ever enabled.

/// Inert until CSOLOADER_MAKE_LINKER_HOOKS is enabled (see linker_load.rs).
pub unsafe extern "C" fn custom_dladdr(
    _addr: *const libc::c_void,
    _info: *mut libc::Dl_info,
) -> libc::c_int {
    0
}

/// Inert until CSOLOADER_MAKE_LINKER_HOOKS is enabled (see linker_load.rs).
pub unsafe extern "C" fn custom_dl_iterate_phdr(
    _callback: unsafe extern "C" fn(*mut libc::c_void, usize, *mut libc::c_void) -> libc::c_int,
    _data: *mut libc::c_void,
) -> libc::c_int {
    0
}
