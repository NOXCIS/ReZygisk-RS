//! Port of loader/src/common/elf_util.c (`ElfImg`) plus the dynamic-table
//! decoding csoloader's linker.c needs, over an in-memory file image.
//!
//! All addresses are file-relative (st_value etc.); the caller combines them
//! with its own base/bias when the image is mapped.

use goblin::elf::{program_header::PT_DYNAMIC, program_header::PT_GNU_RELRO, program_header::PT_LOAD, Elf};

use goblin::elf::dynamic as d;
use d::{DT_GNU_HASH, DT_HASH, DT_JMPREL, DT_NULL, DT_PLTREL, DT_PLTRELSZ, DT_RELA, DT_RELASZ,
        DT_REL, DT_RELSZ, DT_STRTAB, DT_SYMTAB};
use crate::reloc::Reloc;

use crate::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
}

/// Flattened PT_LOAD segment (remote_csoloader's mapping input).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadSegment {
    pub vaddr: u64,
    pub memsz: u64,
    pub filesz: u64,
    pub offset: u64,
    pub flags: u32,
}

/// Relocation tables split by origin ([`ElfImage::relocations_grouped`]).
#[derive(Debug, Clone, Default)]
pub struct RelocTables {
    pub plt: Vec<Reloc>,
    pub plt_is_rela: bool,
    pub rel: Vec<Reloc>,
    pub rel_is_rela: bool,
    pub android: Vec<Reloc>,
    pub android_is_rela: bool,
}

impl Symbol {
    pub fn type_(&self) -> u8 {
        crate::sym_type(self.info)
    }

    pub fn bind(&self) -> u8 {
        crate::sym_bind(self.info)
    }
}

/// Which symbol filter a lookup applies. PLTI's elf_util.c
/// (`elfutil_gnu_lookup` / `elfutil_elf_lookup`)
/// compares raw names with NO shndx/visibility filter — even SHN_UNDEF
/// imports resolve, since relocations reference them directly. The
/// common/csoloader chains (`GnuLookup`/`ElfLookup` + `is_dynamic_symbol_visible`)
/// always drop SHN_UNDEF and optionally filter binding/visibility.
#[derive(Clone, Copy)]
enum SymbolFilter {
    None,
    Dynamic { exported_only: bool },
}

pub struct ElfImage<'a> {
    raw: &'a [u8],
    elf: Elf<'a>,
    is_64: bool,
    dyn_entries: Vec<(u64, u64)>,
}

impl<'a> ElfImage<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        let elf = Elf::parse(raw).map_err(|e| Error::Parse(e.to_string()))?;

        let ident = &elf.header.e_ident;
        let ei_data = ident[5];
        if ei_data != 1 {
            return Err(Error::Other("big-endian ELF images are not supported".into()));
        }
        let is_64 = elf.is_64;

        let mut dyn_entries = Vec::new();
        // C: the phdr scan has no `break`, so the LAST
        // PT_DYNAMIC wins, and the dynamic-table entry count comes from
        // `p_memsz` (`dynamic_size_`), not `p_filesz`.
        if let Some(ph) = elf
            .program_headers
            .iter()
            .rev()
            .find(|ph| ph.p_type == PT_DYNAMIC)
        {
            let file_off = ph.p_offset as usize;
            let entsize = if is_64 { 16 } else { 8 };
            let count = ph.p_memsz as usize / entsize;
            for i in 0..count {
                let at = file_off + i * entsize;
                let (tag, val) = if is_64 {
                    let tag = u64::from_le_bytes(raw[at..at + 8].try_into().unwrap());
                    let val = u64::from_le_bytes(raw[at + 8..at + 16].try_into().unwrap());
                    (tag, val)
                } else {
                    let tag = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) as u64;
                    let val = u32::from_le_bytes(raw[at + 4..at + 8].try_into().unwrap()) as u64;
                    (tag, val)
                };
                if tag == DT_NULL {
                    break;
                }
                dyn_entries.push((tag, val));
            }
        }

        Ok(Self { raw, elf, is_64, dyn_entries })
    }

    pub fn is_64(&self) -> bool {
        self.is_64
    }

    pub fn machine(&self) -> u16 {
        self.elf.header.e_machine
    }

    pub fn raw(&self) -> &'a [u8] {
        self.raw
    }

    /// elf_util.c: bias = p_vaddr - p_offset of the PT_LOAD with p_offset == 0,
    /// falling back to the first PT_LOAD. Signed like the C `off_t` so a
    /// pre-linked executable image yields a usable negative bias.
    pub fn bias(&self) -> i64 {
        let loads: Vec<_> = self
            .elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .collect();
        let pick = loads.iter().find(|ph| ph.p_offset == 0).or_else(|| loads.first());
        match pick {
            Some(ph) => ph.p_vaddr as i64 - ph.p_offset as i64,
            None => 0,
        }
    }

    pub fn dynamic_find(&self, tag: u64) -> Option<u64> {
        self.dyn_entries.iter().find(|(t, _)| *t == tag).map(|(_, v)| *v)
    }

    /// The C dynamic-table scans assign scalar fields per occurrence, so the LAST occurrence of a
    /// tag in the table is the one that sticks. `dynamic_find` keeps the
    /// first-wins lookup for consumers that expect it; this is the C-faithful
    /// variant.
    fn dynamic_find_last(&self, tag: u64) -> Option<u64> {
        self.dyn_entries.iter().rev().find(|(t, _)| *t == tag).map(|(_, v)| *v)
    }

    pub fn dynamic_entries(&self) -> &[(u64, u64)] {
        &self.dyn_entries
    }

    pub fn needed_libraries(&self) -> Vec<&'a str> {
        self.elf.libraries.clone()
    }

    pub fn soname(&self) -> Option<&'a str> {
        self.elf.soname
    }

    /// Map a virtual address to a file offset via the PT_LOAD segments.
    pub fn vaddr_to_file_offset(&self, vaddr: u64) -> Option<u64> {
        self.elf.program_headers.iter().find_map(|ph| {
            if ph.p_type != PT_LOAD {
                return None;
            }
            let lo = ph.p_vaddr;
            let hi = lo + ph.p_filesz;
            if vaddr >= lo && vaddr < hi {
                Some(vaddr - lo + ph.p_offset)
            } else {
                None
            }
        })
    }

    /// PT_LOAD segment view used by the remote loader (remote_csoloader).
    pub fn load_segments(&self) -> Vec<LoadSegment> {
        self.elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_LOAD)
            .map(|ph| LoadSegment {
                vaddr: ph.p_vaddr,
                memsz: ph.p_memsz,
                filesz: ph.p_filesz,
                offset: ph.p_offset,
                flags: ph.p_flags,
            })
            .collect()
    }

    /// PT_GNU_RELRO segments (PLTI `elfutil_get_vma_boundaries` / CSOLoader
    /// `protect_gnu_relro`).
    pub fn gnu_relro_segments(&self) -> Vec<LoadSegment> {
        self.elf
            .program_headers
            .iter()
            .filter(|ph| ph.p_type == PT_GNU_RELRO)
            .map(|ph| LoadSegment {
                vaddr: ph.p_vaddr,
                memsz: ph.p_memsz,
                filesz: ph.p_filesz,
                offset: ph.p_offset,
                flags: ph.p_flags,
            })
            .collect()
    }

    /// PT_TLS segment with p_align (CSOLoader TLS registration).
    pub fn tls_segment(&self) -> Option<(u64, u64, u64, u64)> {
        self.elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == goblin::elf::program_header::PT_TLS)
            .map(|ph| (ph.p_vaddr, ph.p_memsz, ph.p_filesz, ph.p_align))
    }

    /// PT_GNU_EH_FRAME segment (vaddr, memsz) for backtrace registration.
    pub fn gnu_eh_frame_segment(&self) -> Option<(u64, u64)> {
        self.elf
            .program_headers
            .iter()
            .find(|ph| ph.p_type == goblin::elf::program_header::PT_GNU_EH_FRAME)
            .map(|ph| (ph.p_vaddr, ph.p_memsz))
    }

    /// Section by name via .shstrtab: (sh_addr, sh_size).
    pub fn section_by_name(&self, name: &str) -> Option<(u64, u64)> {
        let sh = self
            .elf
            .section_headers
            .iter()
            .find(|sh| self.elf.shdr_strtab.get_at(sh.sh_name) == Some(name))?;
        Some((sh.sh_addr, sh.sh_size))
    }

    pub fn e_type(&self) -> u16 {
        self.elf.header.e_type
    }

    /// Every program header as (p_type, flattened segment) in **file order** —
    /// PLTI's VMA-boundary scan depends on the phdr iteration order.
    /// Raw on-disk program-header table (`img->header` + `e_phoff`, `e_phnum`
    /// entries) — backtrace-support.c `copy_program_headers` input. Returns
    /// `(count, bytes)` in file order.
    pub fn phdr_table(&self) -> (usize, &[u8]) {
        let ent_size = if self.is_64 { 56 } else { 32 };
        let off = self.elf.header.e_phoff as usize;
        let count = self.elf.header.e_phnum as usize;
        let bytes = &self.raw[off..off + count * ent_size];
        (count, bytes)
    }

    pub fn all_segments(&self) -> Vec<(u32, LoadSegment)> {
        self.elf
            .program_headers
            .iter()
            .map(|ph| {
                (
                    ph.p_type,
                    LoadSegment {
                        vaddr: ph.p_vaddr,
                        memsz: ph.p_memsz,
                        filesz: ph.p_filesz,
                        offset: ph.p_offset,
                        flags: ph.p_flags,
                    },
                )
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // Dynamic symbol tables
    // ------------------------------------------------------------------

    /// Locate (file offset, entry size, entry count) of the dynsym table.
    fn dynsym_table(&self) -> Option<(usize, usize, usize)> {
        let entsize = if self.is_64 { 24 } else { 16 };

        // Prefer the .dynsym section header like elf_util.c.
        for sh in &self.elf.section_headers {
            if sh.sh_type == crate::SHT_DYNSYM {
                let count = (sh.sh_size / if sh.sh_entsize > 0 { sh.sh_entsize } else { entsize as u64 }) as usize;
                return Some((sh.sh_offset as usize, entsize, count));
            }
        }

        // Fall back to DT_SYMTAB/DT_STRTAB (last
        // occurrence of each tag wins). The C never bounds the table
        // (`dyn_sym_` is a raw pointer), so the count here is only a safety
        // bound: DT_HASH nchain when present, otherwise the bytes remaining
        // in the PT_LOAD that holds the symtab — GNU-hash-only images (and
        // mapped snapshots, which have no section headers) resolve through
        // DT_SYMTAB alone in the C.
        let symtab = self.dynamic_find_last(DT_SYMTAB)?;
        let symtab_off = self.vaddr_to_file_offset(symtab)? as usize;
        if let Some(hash) = self.dynamic_find_last(DT_HASH) {
            let hash_off = self.vaddr_to_file_offset(hash)? as usize;
            let nchain = u32::from_le_bytes(self.raw.get(hash_off + 4..hash_off + 8)?.try_into().ok()?);
            return Some((symtab_off, entsize, nchain as usize));
        }
        let seg = self.elf.program_headers.iter().find(|ph| {
            ph.p_type == PT_LOAD && symtab >= ph.p_vaddr && symtab < ph.p_vaddr + ph.p_filesz
        })?;
        let available = (seg.p_vaddr + seg.p_filesz).saturating_sub(symtab) as usize;
        Some((symtab_off, entsize, available / entsize))
    }

    pub fn dynsym_count(&self) -> usize {
        self.dynsym_table().map(|(_, _, c)| c).unwrap_or(0)
    }

    pub fn symbol_at(&self, index: usize) -> Option<Symbol> {
        let (off, entsize, count) = self.dynsym_table()?;
        if index >= count {
            return None;
        }
        self.read_symbol(off + index * entsize, None)
    }

    /// dynstr via DT_STRTAB (works even with no section headers).
    pub fn dynstr_at(&self, offset: u64) -> Option<&'a str> {
        let strtab = self.dynamic_find_last(DT_STRTAB)?;
        let base = self.vaddr_to_file_offset(strtab)? as usize;
        self.cstr_at(base + offset as usize)
    }

    fn cstr_at(&self, at: usize) -> Option<&'a str> {
        let rest = self.raw.get(at..)?;
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        std::str::from_utf8(&rest[..end]).ok()
    }

    fn read_symbol(&self, at: usize, strtab_hint: Option<u64>) -> Option<Symbol> {
        let raw = self.raw;
        let name_off: u64;
        let info: u8;
        let other: u8;
        let shndx: u16;
        let value: u64;
        let size: u64;

        if self.is_64 {
            name_off = u32::from_le_bytes(raw.get(at..at + 4)?.try_into().ok()?) as u64;
            info = *raw.get(at + 4)?;
            other = *raw.get(at + 5)?;
            shndx = u16::from_le_bytes(raw.get(at + 6..at + 8)?.try_into().ok()?);
            value = u64::from_le_bytes(raw.get(at + 8..at + 16)?.try_into().ok()?);
            size = u64::from_le_bytes(raw.get(at + 16..at + 24)?.try_into().ok()?);
        } else {
            name_off = u32::from_le_bytes(raw.get(at..at + 4)?.try_into().ok()?) as u64;
            value = u32::from_le_bytes(raw.get(at + 4..at + 8)?.try_into().ok()?) as u64;
            size = u32::from_le_bytes(raw.get(at + 8..at + 12)?.try_into().ok()?) as u64;
            info = *raw.get(at + 12)?;
            other = *raw.get(at + 13)?;
            shndx = u16::from_le_bytes(raw.get(at + 14..at + 16)?.try_into().ok()?);
        }

        let name = if name_off != 0 {
            match strtab_hint {
                Some(strtab_vaddr) => {
                    let base = self.vaddr_to_file_offset(strtab_vaddr)? as usize;
                    self.cstr_at(base + name_off as usize)?
                }
                None => self.dynstr_at(name_off)?,
            }
        } else {
            ""
        };

        Some(Symbol { name: name.to_string(), value, size, info, other, shndx })
    }

    // ------------------------------------------------------------------
    // Hash tables + lookups (elf_util.c GnuLookup / ElfLookup / LinearLookup)
    // ------------------------------------------------------------------

    /// GNU hash table parsed from DT_GNU_HASH:
    /// (nbucket, symoffset, bloom_size, bloom_shift, bloom_off, bucket_off, chain_off)
    fn gnu_hash_table(&self) -> Option<(u32, u32, u32, u32, usize, usize, usize)> {
        let tag = self.dynamic_find_last(DT_GNU_HASH)?;
        let off = self.vaddr_to_file_offset(tag)? as usize;
        let r = &self.raw;
        let nbucket = u32::from_le_bytes(r.get(off..off + 4)?.try_into().ok()?);
        let symoffset = u32::from_le_bytes(r.get(off + 4..off + 8)?.try_into().ok()?);
        let bloom_size = u32::from_le_bytes(r.get(off + 8..off + 12)?.try_into().ok()?);
        let bloom_shift = u32::from_le_bytes(r.get(off + 12..off + 16)?.try_into().ok()?);
        let bloom_word = if self.is_64 { 8 } else { 4 };
        let bloom_off = off + 16;
        let bucket_off = bloom_off + bloom_size as usize * bloom_word;
        let chain_off = bucket_off + nbucket as usize * 4;
        Some((nbucket, symoffset, bloom_size, bloom_shift, bloom_off, bucket_off, chain_off))
    }

    fn gnu_lookup(&self, name: &str, hash: u32) -> Option<Symbol> {
        self.gnu_lookup_index(name, hash).and_then(|i| self.symbol_at(i))
    }

    /// common/csoloader `GnuLookup` index (SHN_UNDEF filtered, no binding/
    /// visibility filter) — `symbol_by_name` chain.
    fn gnu_lookup_index(&self, name: &str, hash: u32) -> Option<usize> {
        self.gnu_lookup_index_filtered(name, hash, SymbolFilter::Dynamic { exported_only: false })
    }

    fn symbol_matches(&self, sym: &Symbol, name: &str, filter: SymbolFilter) -> bool {
        if sym.name != name {
            return false;
        }
        match filter {
            SymbolFilter::None => true,
            SymbolFilter::Dynamic { exported_only } => crate::symbol_is_visible(sym, exported_only),
        }
    }

    fn gnu_lookup_index_filtered(
        &self,
        name: &str,
        hash: u32,
        filter: SymbolFilter,
    ) -> Option<usize> {
        let (nbucket, symoffset, bloom_size, bloom_shift, bloom_off, bucket_off, chain_off) =
            self.gnu_hash_table()?;
        if nbucket == 0 || bloom_size == 0 {
            return None;
        }

        let bloom_mask_bits = if self.is_64 { 64usize } else { 32 };
        let bloom_word_size = if self.is_64 { 8usize } else { 4 };
        let bloom_idx = (hash as usize / bloom_mask_bits) % bloom_size as usize;
        let at = bloom_off + bloom_idx * bloom_word_size;
        let bloom_word = if self.is_64 {
            u64::from_le_bytes(self.raw.get(at..at + 8)?.try_into().ok()?)
        } else {
            u32::from_le_bytes(self.raw.get(at..at + 4)?.try_into().ok()?) as u64
        };

        let c = bloom_mask_bits as u32;
        let mask = (1u64 << (hash % c)) | (1u64 << ((hash >> bloom_shift) % c));
        if mask & bloom_word != mask {
            return None;
        }

        let bucket_at = bucket_off + (hash % nbucket) as usize * 4;
        let mut sym_index = u32::from_le_bytes(self.raw.get(bucket_at..bucket_at + 4)?.try_into().ok()?);
        if sym_index < symoffset {
            return None;
        }

        let dynsym_count = self.dynsym_count() as u32;
        let (sym_off, sym_ent, _) = self.dynsym_table()?;

        loop {
            if sym_index >= dynsym_count {
                return None;
            }

            let chain_at = chain_off + (sym_index - symoffset) as usize * 4;
            let chain_val = u32::from_le_bytes(self.raw.get(chain_at..chain_at + 4)?.try_into().ok()?);

            let sym = self.read_symbol(sym_off + sym_index as usize * sym_ent, None);
            let matches = (chain_val ^ hash) >> 1 == 0
                && sym.is_some_and(|s| self.symbol_matches(&s, name, filter));

            if matches {
                return Some(sym_index as usize);
            }

            if chain_val & 1 != 0 {
                return None;
            }
            sym_index += 1;
        }
    }

    fn elf_lookup(&self, name: &str, hash: u32) -> Option<Symbol> {
        self.elf_lookup_index(name, hash).and_then(|i| self.symbol_at(i))
    }

    /// common/csoloader `ElfLookup` index (SHN_UNDEF filtered, no binding/
    /// visibility filter) — `symbol_by_name` chain.
    fn elf_lookup_index(&self, name: &str, hash: u32) -> Option<usize> {
        self.elf_lookup_index_filtered(name, hash, SymbolFilter::Dynamic { exported_only: false })
    }

    fn elf_lookup_index_filtered(&self, name: &str, hash: u32, filter: SymbolFilter) -> Option<usize> {
        let tag = self.dynamic_find_last(DT_HASH)?;
        let off = self.vaddr_to_file_offset(tag)? as usize;
        let nbucket = u32::from_le_bytes(self.raw.get(off..off + 4)?.try_into().ok()?);
        if nbucket == 0 {
            return None;
        }
        let bucket_at = off + 8;
        let chain_at = bucket_at + nbucket as usize * 4;

        let mut n = u32::from_le_bytes(
            self.raw
                .get(bucket_at + (hash % nbucket) as usize * 4..bucket_at + (hash % nbucket) as usize * 4 + 4)?
                .try_into()
                .ok()?,
        ) as usize;
        while n != 0 {
            // STN_UNDEF == 0
            let sym = self.symbol_at(n)?;
            if self.symbol_matches(&sym, name, filter) {
                return Some(n);
            }
            n = u32::from_le_bytes(
                self.raw
                    .get(chain_at + n * 4..chain_at + n * 4 + 4)?
                    .try_into()
                    .ok()?,
            ) as usize;
        }
        None
    }

    /// elf_util.c `getSymbOffset`: GNU hash → SysV hash → full symtab scan.
    pub fn symbol_by_name(&self, name: &str) -> Option<Symbol> {
        if let Some(s) = self.gnu_lookup(name, gnu_hash(name)) {
            return Some(s);
        }
        if let Some(s) = self.elf_lookup(name, elf_hash(name)) {
            return Some(s);
        }
        self.linear_lookup(name, None)
    }

    /// csoloader elf_util.c lookup chain with the exported-only filter of
    /// `gnu_symbol_lookup`/`elf_symbol_lookup` (csoloader_elf_symb_address_exported).
    pub fn symbol_by_name_ex(&self, name: &str, exported_only: bool) -> Option<Symbol> {
        let filter = SymbolFilter::Dynamic { exported_only };
        if let Some(i) = self.gnu_lookup_index_filtered(name, gnu_hash(name), filter) {
            return self.symbol_at(i);
        }
        if let Some(i) = self.elf_lookup_index_filtered(name, elf_hash(name), filter) {
            return self.symbol_at(i);
        }
        None
    }

    /// PLTI `elfutil_gnu_lookup` → `elfutil_elf_lookup` → `elfutil_linear_lookup`:
    /// dynsym *index* of the first symbol matching `name`.
    ///
    /// Mirrors the C lookup-chain quirks exactly:
    /// - raw name match only — no SHN_UNDEF/visibility filter (imports
    ///   referenced by relocations must resolve);
    /// - with a GNU hash table (DT_GNU_HASH) the SysV lookup is skipped
    ///   entirely (`elfutil_elf_lookup` returns 0 when `bloom_` is set);
    /// - `elfutil_linear_lookup` only runs when DT_GNU_HASH was parsed
    ///   (`sym_offset_` is GNU-only) and scans only indexes in
    ///   `[0, sym_offset)`; index 0 is the not-found sentinel, so it can
    ///   never be returned;
    /// - without a GNU hash table only the SysV lookup can match.
    pub fn dynsym_index_by_name(&self, name: &str) -> Option<usize> {
        let has_gnu = self.gnu_hash_table().is_some();

        if has_gnu {
            if let Some(i) = self.gnu_lookup_index_filtered(name, gnu_hash(name), SymbolFilter::None)
            {
                return Some(i);
            }
            // C quirk: the SysV path is skipped when GNU hash exists, and the
            // linear fallback runs only then (sym_offset_ comes from
            // DT_GNU_HASH), scanning [1, sym_offset) — 0 is the not-found
            // sentinel in C.
            let symoffset = self.gnu_hash_table()?.1;
            for i in 1..symoffset as usize {
                if self.symbol_at(i).is_some_and(|s| s.name == name) {
                    return Some(i);
                }
            }
            return None;
        }

        // No GNU hash: only the SysV lookup can match (the C chain's linear
        // lookup returns 0 without sym_offset_).
        if let Some(i) = self.elf_lookup_index_filtered(name, elf_hash(name), SymbolFilter::None) {
            return Some(i);
        }

        None
    }

    /// PLTI prefix matching support: all dynsym indexes whose name starts
    /// with `prefix`.
    pub fn dynsym_indices_by_prefix(&self, prefix: &str) -> Vec<usize> {
        (0..self.dynsym_count())
            .filter(|&i| {
                self.symbol_at(i)
                    .is_some_and(|s| s.name.starts_with(prefix))
            })
            .collect()
    }

    /// Valid `.symtab` symbols (STT_FUNC/STT_OBJECT, size > 0, named) —
    /// the `calculate_valid_symtabs_amount` filter of elf_util.c.
    pub fn symtab_symbols(&self) -> Vec<Symbol> {
        self.symtab_symbols_iter().collect()
    }

    fn symtab_symbols_iter(&self) -> impl Iterator<Item = Symbol> + '_ {
        // .symtab via section headers (stripped images yield nothing here).
        let symtab = self.elf.section_headers.iter().find(|sh| sh.sh_type == crate::SHT_SYMTAB);
        let strtab = symtab.and_then(|st| {
            self.elf
                .section_headers
                .get(st.sh_link as usize)
                .filter(|l| l.sh_type == crate::SHT_STRTAB)
        });
        let (st_off, st_entsize, st_count, str_off) = match (symtab, strtab) {
            (Some(st), Some(lt)) => (
                st.sh_offset as usize,
                if st.sh_entsize > 0 { st.sh_entsize as usize } else { if self.is_64 { 24 } else { 16 } },
                (st.sh_size / st.sh_entsize.max(1)) as usize,
                lt.sh_offset,
            ),
            _ => (0, 0, 0, 0),
        };

        let raw = self.raw;
        let is_64 = self.is_64;
        (0..st_count).filter_map(move |i| {
            if st_entsize == 0 || raw.is_empty() {
                return None;
            }
            Self::read_symbol_static(raw, is_64, st_off + i * st_entsize, Some(str_off))
        })
    }

    fn linear_lookup(&self, name: &str, prefix_len: Option<usize>) -> Option<Symbol> {
        for sym in self.symtab_symbols_iter() {
            // calculate_valid_symtabs_amount filter.
            if sym.size == 0 || sym.name.is_empty() {
                continue;
            }
            let ty = crate::sym_type(sym.info);
            if ty != crate::STT_FUNC && ty != crate::STT_OBJECT {
                continue;
            }
            if sym.shndx == crate::SHN_UNDEF {
                continue;
            }
            let matched = if let Some(plen) = prefix_len {
                sym.name.len() >= plen && sym.name.as_bytes()[..plen] == *name.as_bytes()
            } else {
                sym.name == name
            };
            if matched {
                return Some(sym);
            }
        }
        None
    }

    /// elf_util.c `LinearLookupByPrefix` over the full symtab.
    pub fn symbol_by_prefix(&self, prefix: &str) -> Option<Symbol> {
        if prefix.is_empty() {
            return None;
        }
        self.linear_lookup(prefix, Some(prefix.len()))
    }

    // ------------------------------------------------------------------
    // Relocation tables (linker.c _linker_process_relocations)
    // ------------------------------------------------------------------

    fn read_rela_table(&self, bytes: &[u8]) -> Vec<Reloc> {
        let entsize = if self.is_64 { 24 } else { 12 };
        let mut out = Vec::with_capacity(bytes.len() / entsize);
        for i in 0..bytes.len() / entsize {
            let at = i * entsize;
            if self.is_64 {
                let offset = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
                let info = u64::from_le_bytes(bytes[at + 8..at + 16].try_into().unwrap());
                let addend = i64::from_le_bytes(bytes[at + 16..at + 24].try_into().unwrap()) as u64;
                out.push(Reloc {
                    offset,
                    sym_idx: (info >> 32) as u32,
                    rtype: (info & 0xffff_ffff) as u32,
                    addend,
                    has_addend: true,
                });
            } else {
                let offset = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as u64;
                let info = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap());
                let addend = i32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()) as u64;
                out.push(Reloc {
                    offset,
                    sym_idx: info >> 8,
                    rtype: info & 0xff,
                    addend,
                    has_addend: true,
                });
            }
        }
        out
    }

    fn read_rel_table(&self, bytes: &[u8]) -> Vec<Reloc> {
        let entsize = if self.is_64 { 16 } else { 8 };
        let mut out = Vec::with_capacity(bytes.len() / entsize);
        for i in 0..bytes.len() / entsize {
            let at = i * entsize;
            if self.is_64 {
                let offset = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
                let info = u64::from_le_bytes(bytes[at + 8..at + 16].try_into().unwrap());
                out.push(Reloc {
                    offset,
                    sym_idx: (info >> 32) as u32,
                    rtype: (info & 0xffff_ffff) as u32,
                    addend: 0,
                    has_addend: false,
                });
            } else {
                let offset = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as u64;
                let info = u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap());
                out.push(Reloc {
                    offset,
                    sym_idx: info >> 8,
                    rtype: info & 0xff,
                    addend: 0,
                    has_addend: false,
                });
            }
        }
        out
    }

    /// All relocations in linker.c processing order: DT_RELA, DT_REL, the
    /// Android packed table (the last DT_ANDROID_REL/RELA occurrence wins),
    /// then DT_JMPREL. RELR is separate (see
    /// [`relr_offsets`]) because its effect is "add bias to target", not a
    /// value write. Scalar tags use last-wins like the C's flat assignments.
    pub fn relocations(&self) -> Result<Vec<Reloc>> {
        let mut out = Vec::new();

        if let Some(vaddr) = self.dynamic_find_last(DT_RELA)
            && let Some(sz) = self.dynamic_find_last(DT_RELASZ)
            && let Some(b) = self.table_bytes(vaddr, sz)
        {
            out.extend(self.read_rela_table(b));
        }
        if let Some(vaddr) = self.dynamic_find_last(DT_REL)
            && let Some(sz) = self.dynamic_find_last(DT_RELSZ)
            && let Some(b) = self.table_bytes(vaddr, sz)
        {
            out.extend(self.read_rel_table(b));
        }
        // linker.c: only ONE android table is processed — whichever
        // of DT_ANDROID_REL/DT_ANDROID_RELA occurs last (the C pointer is
        // overwritten per occurrence). The sticky `is_rela` of linker.c
        // (DT_ANDROID_REL never resets it) is NOT copied: the winning tag
        // decides, like plti's elf_util.c.
        let android_vaddr = self
            .dyn_entries
            .iter()
            .rev()
            .find(|(t, _)| *t == crate::reloc::DT_ANDROID_RELA || *t == crate::reloc::DT_ANDROID_REL)
            .copied();
        let android_size = self
            .dyn_entries
            .iter()
            .rev()
            .find(|(t, _)| *t == crate::reloc::DT_ANDROID_RELASZ || *t == crate::reloc::DT_ANDROID_RELSZ)
            .map(|(_, v)| *v);
        if let Some((tag, vaddr)) = android_vaddr
            && let Some(sz) = android_size
            && let Some(b) = self.table_bytes(vaddr, sz)
        {
            out.extend(crate::reloc::decode_android_packed(
                b,
                tag == crate::reloc::DT_ANDROID_RELA,
                self.is_64,
            )?);
        }

        if let (Some(jmprel), Some(sz)) = (
            self.dynamic_find_last(DT_JMPREL),
            self.dynamic_find_last(DT_PLTRELSZ),
        )
            && let Some(off) = self.vaddr_to_file_offset(jmprel) {
                let pltrel = self.dynamic_find_last(DT_PLTREL);
                let is_rela = pltrel == Some(DT_RELA);
                let bytes = self
                    .raw
                    .get(off as usize..off as usize + sz as usize)
                    .ok_or(Error::OutOfBounds("jmprel", off as usize))?;
                if is_rela {
                    out.extend(self.read_rela_table(bytes));
                } else {
                    out.extend(self.read_rel_table(bytes));
                }
            }

        Ok(out)
    }

    /// Relocations split by dynamic-table origin, in the order PLTI /
    /// CSOLoader process them: DT_JMPREL (PLT), then DT_REL/DT_RELA, then the
    /// Android packed table. Order inside each table is preserved. Scalar tags
    /// use the C's last-wins assignments; REL/RELA and
    /// the two Android tables pair the last table tag with the last size tag,
    /// exactly like the C's flat `rel_dyn_`/`rel_dyn_size_` fields.
    pub fn relocations_grouped(&self) -> Result<RelocTables> {
        let mut tables = RelocTables::default();

        if let (Some(jmprel), Some(sz)) = (
            self.dynamic_find_last(DT_JMPREL),
            self.dynamic_find_last(DT_PLTRELSZ),
        )
            && let Some(off) = self.vaddr_to_file_offset(jmprel)
        {
            let pltrel = self.dynamic_find_last(DT_PLTREL);
            let is_rela = pltrel == Some(DT_RELA);
            let bytes = self
                .raw
                .get(off as usize..off as usize + sz as usize)
                .ok_or(Error::OutOfBounds("jmprel", off as usize))?;
            tables.plt_is_rela = is_rela;
            if is_rela {
                tables.plt = self.read_rela_table(bytes);
            } else {
                tables.plt = self.read_rel_table(bytes);
            }
        }

        let rel_tag = self
            .dyn_entries
            .iter()
            .rev()
            .find(|(t, _)| *t == DT_RELA || *t == DT_REL)
            .copied();
        let rel_size = self
            .dyn_entries
            .iter()
            .rev()
            .find(|(t, _)| *t == DT_RELASZ || *t == DT_RELSZ)
            .map(|(_, v)| *v);
        if let Some((tag, vaddr)) = rel_tag
            && let Some(sz) = rel_size
            && let Some(b) = self.table_bytes(vaddr, sz)
        {
            tables.rel_is_rela = tag == DT_RELA;
            if tables.rel_is_rela {
                tables.rel = self.read_rela_table(b);
            } else {
                tables.rel = self.read_rel_table(b);
            }
        }

        let android_tag = self
            .dyn_entries
            .iter()
            .rev()
            .find(|(t, _)| *t == crate::reloc::DT_ANDROID_RELA || *t == crate::reloc::DT_ANDROID_REL)
            .copied();
        let android_size = self
            .dyn_entries
            .iter()
            .rev()
            .find(|(t, _)| *t == crate::reloc::DT_ANDROID_RELASZ || *t == crate::reloc::DT_ANDROID_RELSZ)
            .map(|(_, v)| *v);
        if let Some((tag, vaddr)) = android_tag
            && let Some(sz) = android_size
            && let Some(b) = self.table_bytes(vaddr, sz)
        {
            tables.android_is_rela = tag == crate::reloc::DT_ANDROID_RELA;
            tables.android = crate::reloc::decode_android_packed(b, tables.android_is_rela, self.is_64)?;
        }

        Ok(tables)
    }

    /// Bytes of a vaddr+size dynamic-table pair, or None when either tag is
    /// missing or the range does not fall inside the file image.
    fn table_bytes(&self, vaddr: u64, size: u64) -> Option<&'a [u8]> {
        let off = self.vaddr_to_file_offset(vaddr)? as usize;
        self.raw.get(off..off.checked_add(size as usize)?)
    }

    pub fn relr_offsets(&self) -> Result<Vec<u64>> {
        let word_size = if self.is_64 { 8 } else { 4 };

        // linker.c: one `relr` pointer, overwritten by whichever of
        // DT_RELR/DT_ANDROID_RELR comes last, sized by the last of the two
        // size tags (cross-paired, like the C's flat assignments).
        let relr_vaddr = self
            .dyn_entries
            .iter()
            .rev()
            .find(|(t, _)| *t == crate::reloc::DT_RELR || *t == crate::reloc::DT_ANDROID_RELR)
            .map(|(_, v)| *v);
        let relr_size = self
            .dyn_entries
            .iter()
            .rev()
            .find(|(t, _)| *t == crate::reloc::DT_RELRSZ || *t == crate::reloc::DT_ANDROID_RELRSZ)
            .map(|(_, v)| *v);

        if let (Some(vaddr), Some(sz)) = (relr_vaddr, relr_size)
            && let Some(b) = self.table_bytes(vaddr, sz)
        {
            return crate::reloc::decode_relr(b, word_size);
        }

        Ok(Vec::new())
    }

    fn read_symbol_static(
        raw: &[u8],
        is_64: bool,
        at: usize,
        strtab_file_off: Option<u64>,
    ) -> Option<Symbol> {
        // Mirrors read_symbol without borrowing self (used by the symtab
        // iterator to avoid closure borrow issues).
        let name_off: u64;
        let info: u8;
        let other: u8;
        let shndx: u16;
        let value: u64;
        let size: u64;

        if is_64 {
            name_off = u32::from_le_bytes(raw.get(at..at + 4)?.try_into().ok()?) as u64;
            info = *raw.get(at + 4)?;
            other = *raw.get(at + 5)?;
            shndx = u16::from_le_bytes(raw.get(at + 6..at + 8)?.try_into().ok()?);
            value = u64::from_le_bytes(raw.get(at + 8..at + 16)?.try_into().ok()?);
            size = u64::from_le_bytes(raw.get(at + 16..at + 24)?.try_into().ok()?);
        } else {
            name_off = u32::from_le_bytes(raw.get(at..at + 4)?.try_into().ok()?) as u64;
            value = u32::from_le_bytes(raw.get(at + 4..at + 8)?.try_into().ok()?) as u64;
            size = u32::from_le_bytes(raw.get(at + 8..at + 12)?.try_into().ok()?) as u64;
            info = *raw.get(at + 12)?;
            other = *raw.get(at + 13)?;
            shndx = u16::from_le_bytes(raw.get(at + 14..at + 16)?.try_into().ok()?);
        }

        let name = if name_off != 0 {
            let base = strtab_file_off? as usize;
            let rest = raw.get(base + name_off as usize..)?;
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            std::str::from_utf8(&rest[..end]).ok()?
        } else {
            ""
        };

        Some(Symbol { name: name.to_string(), value, size, info, other, shndx })
    }
}


/// elf_util.c `ElfHash` (SysV).
pub fn elf_hash(name: &str) -> u32 {
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

/// elf_util.c `GnuHash` (DJB2 variant).
pub fn gnu_hash(name: &str) -> u32 {
    let mut h: u32 = 5381;
    for &b in name.as_bytes() {
        h = h.wrapping_shl(5).wrapping_add(h).wrapping_add(b as u32);
    }
    h
}
