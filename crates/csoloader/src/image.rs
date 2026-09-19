//! Port of `loader/src/external/csoloader/src/elf_util.c` (`struct
//! csoloader_elf` and the `csoloader_elf_*` function family).
//!
//! The C image owns a full copy of the file (`img->header`) and parses
//! section/program headers out of it; runtime addresses are computed as
//! `base + offset - bias` where `bias` is the file `p_vaddr - p_offset` of
//! the first PT_LOAD (0 for ordinary prelinked `.so`s). Here the file copy
//! lives in a `Box<[u8]>` parsed once via `rz_elf::ElfImage`, and the runtime
//! arithmetic mirrors the C exactly (wrapping; truncating on 32-bit).

use rz_elf::arch::generic_reloc_type;
use rz_elf::{ElfImage, GenericReloc, RelocTables, STT_GNU_IFUNC};

use crate::{Error, Result};

pub const TAG: &str = "zygisk";

macro_rules! dlogd {
    ($($arg:tt)*) => {{ rz_common::logd!(TAG, $($arg)*); }};
}
macro_rules! dlogw {
    ($($arg:tt)*) => {{ rz_common::logw!(TAG, $($arg)*); }};
}
macro_rules! dloge {
    ($($arg:tt)*) => {{ rz_common::loge!(TAG, $($arg)*); }};
}

// DT_* tags consumed during the dynamic scan.
const DT_NEEDED: u64 = 1;
const DT_INIT: u64 = 12;
const DT_FINI: u64 = 13;
const DT_SONAME: u64 = 14;
const DT_INIT_ARRAY: u64 = 25;
const DT_FINI_ARRAY: u64 = 26;
const DT_INIT_ARRAYSZ: u64 = 27;
const DT_FINI_ARRAYSZ: u64 = 28;

/// The per-image TLS segment description (`csoloader_elf.tls_segment`).
#[derive(Debug, Clone, Copy, Default)]
pub struct TlsSegment {
    pub vaddr: u64,
    pub memsz: u64,
    pub filesz: u64,
    pub align: u64,
}

/// Result of `csoloader_elf_get_symbol`: address-scoped symtab lookup.
#[derive(Debug, Clone, Default)]
pub struct SymInfo {
    pub name: String,
    pub address: usize,
}

/// A parsed shared object tied to a runtime base address. Owns the file copy
/// the way the C `csoloader_elf` owns `img->header`.
pub struct CsoElf {
    /// Path as passed to `csoloader_elf_create` (`img->elf`); may be
    /// `/proc/self/fd/N` for fd-based loads.
    path: String,
    /// `img->base`: mapping start (`map_start` for manual loads, `dlpi_addr`
    /// for preloaded ones).
    base: usize,
    /// `img->bias`: file `p_vaddr - p_offset` of the first PT_LOAD with
    /// `p_offset == 0`, falling back to the first PT_LOAD (signed `off_t`).
    bias: i64,
    /// Owning file copy; `img` borrows from its heap buffer.
    raw: Box<[u8]>,
    /// SAFETY: borrows `raw`'s heap buffer. `Box<[u8]>` never reallocates or
    /// moves its data, and struct fields drop in declaration order, so `img`
    /// drops before `raw` does.
    img: ElfImage<'static>,

    tls_segment: Option<TlsSegment>,
    pub(crate) tls_mod_id: usize,

    init_func_vaddr: u64,
    init_array_vaddr: u64,
    init_array_count: usize,
    fini_func_vaddr: u64,
    fini_array_vaddr: u64,
    fini_array_count: usize,

    needed: Vec<String>,
    soname: Option<String>,
    is_et_dyn: bool,

    /// (.eh_frame sh_addr, sh_size) for backtrace registration.
    eh_frame: Option<(u64, u64)>,
}

impl CsoElf {
    /// `csoloader_elf_create(elf, base)` with a pre-known base (manual loads
    /// pass `map_start`).
    pub fn create(path: &str, base: usize) -> Result<Self> {
        let raw: Box<[u8]> = std::fs::read(path)
            .map_err(|e| Error::Other(format!("failed to read {path}: {e}")))?
            .into_boxed_slice();
        Self::from_raw(path.to_string(), base, raw)
    }

    /// `csoloader_elf_create(elf, NULL)`: resolve the base of an already
    /// loaded library via `dl_iterate_phdr` (substring match on the soname,
    /// like the C `dl_cb`).
    pub fn create_loaded(path: &str) -> Result<Self> {
        let base = find_loaded_base(path)
            .ok_or_else(|| Error::Other(format!("no loaded module base for {path}")))?;
        Self::create(path, base)
    }

    fn from_raw(path: String, base: usize, raw: Box<[u8]>) -> Result<Self> {
        if raw.len() <= 64 {
            return Err(Error::Other(format!("invalid file size {} for {}", raw.len(), path)));
        }

        let img: ElfImage<'static> = {
            let ptr = raw.as_ptr();
            let len = raw.len();
            // SAFETY: see struct doc — aliases the stable heap buffer of `raw`.
            let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
            ElfImage::parse(slice)?
        };

        let bias = img.bias();
        let is_et_dyn = img.e_type() == 3; // ET_DYN

        let mut elf = Self {
            path,
            base,
            bias,
            raw,
            img,
            tls_segment: None,
            tls_mod_id: 0,
            init_func_vaddr: 0,
            init_array_vaddr: 0,
            init_array_count: 0,
            fini_func_vaddr: 0,
            fini_array_vaddr: 0,
            fini_array_count: 0,
            needed: Vec::new(),
            soname: None,
            is_et_dyn,
            eh_frame: None,
        };

        elf.scan_program_headers();
        elf.scan_dynamic();
        elf.scan_sections();

        if elf.img.dynsym_count() == 0 {
            if elf.is_et_dyn {
                dloge!("Failed to find .dynsym or its string table (.dynstr) in {}", elf.path);
            } else {
                dlogw!("No .dynsym or .dynstr found in {} (might be expected for ET_EXEC)", elf.path);
            }
        }

        Ok(elf)
    }

    fn scan_program_headers(&mut self) {
        if let Some((vaddr, memsz, filesz, align)) = self.img.tls_segment() {
            self.tls_segment = Some(TlsSegment { vaddr, memsz, filesz, align });
        }
    }

    /// .dynamic scan for the init/fini machinery, DT_NEEDED and DT_SONAME
    /// (elf_util.c's PT_DYNAMIC walk). String references are file-relative
    /// and resolved through the parsed file image.
    fn scan_dynamic(&mut self) {
        let addr_size = if self.img.is_64() { 8 } else { 4 };
        let mut needed = Vec::new();
        let mut soname_off: Option<u64> = None;
        let mut init_array_size = 0u64;
        let mut fini_array_size = 0u64;

        for &(tag, val) in self.img.dynamic_entries() {
            match tag {
                DT_NEEDED => {
                    if let Some(name) = self.img.dynstr_at(val) {
                        needed.push(name.to_string());
                    }
                }
                DT_INIT => self.init_func_vaddr = val,
                DT_FINI => self.fini_func_vaddr = val,
                DT_INIT_ARRAY => self.init_array_vaddr = val,
                DT_INIT_ARRAYSZ => init_array_size = val,
                DT_FINI_ARRAY => self.fini_array_vaddr = val,
                DT_FINI_ARRAYSZ => fini_array_size = val,
                DT_SONAME => soname_off = Some(val),
                _ => {}
            }
        }

        self.needed = needed;
        self.soname = soname_off.and_then(|off| self.img.dynstr_at(off).map(str::to_string));
        self.init_array_count = (init_array_size / addr_size) as usize;
        self.fini_array_count = (fini_array_size / addr_size) as usize;
    }

    /// Section scan for .eh_frame (elf_util.c's EH region population).
    fn scan_sections(&mut self) {
        self.eh_frame = self.img.section_by_name(".eh_frame");
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn base(&self) -> usize {
        self.base
    }

    /// `img->bias` (file offset correction, signed like the C `off_t`).
    pub fn bias(&self) -> i64 {
        self.bias
    }

    /// Runtime address of a file vaddr: `base + vaddr - bias`.
    pub fn runtime(&self, vaddr: u64) -> usize {
        (self.base as u64).wrapping_add(vaddr).wrapping_sub(self.bias as u64) as usize
    }

    /// linker.c's `load_bias` for relocations: `base - bias` — the runtime
    /// address that file vaddr 0 lands on.
    pub fn load_bias(&self) -> usize {
        (self.base as u64).wrapping_sub(self.bias as u64) as usize
    }

    pub fn tls_segment(&self) -> Option<TlsSegment> {
        self.tls_segment
    }

    pub(crate) fn tls_mod_id(&self) -> usize {
        self.tls_mod_id
    }

    pub(crate) fn set_tls_mod_id(&self, id: usize) {
        // C mutates img->tls_mod_id through the struct pointer; interior
        // mutability keeps the Rust API usable while images are shared.
        unsafe {
            let me = self as *const Self as *mut Self;
            (*me).tls_mod_id = id;
        }
    }

    pub fn needed_libraries(&self) -> &[String] {
        &self.needed
    }

    pub fn soname(&self) -> Option<&str> {
        self.soname.as_deref()
    }

    pub fn is_et_dyn(&self) -> bool {
        self.is_et_dyn
    }

    // ------------------------------------------------------------------
    // Relocation tables (delegated to the shared rz_elf parser)
    // ------------------------------------------------------------------

    pub fn relocations_grouped(&self) -> Result<RelocTables> {
        self.img.relocations_grouped()
    }

    pub fn relr_offsets(&self) -> Result<Vec<u64>> {
        self.img.relr_offsets()
    }

    pub fn machine(&self) -> u16 {
        self.img.machine()
    }

    pub fn classify(&self, rtype: u32) -> GenericReloc {
        generic_reloc_type(self.machine(), rtype)
    }

    /// Symbol entry backing a relocation (`&dynsym[r->sym_idx]`).
    pub fn symbol_at(&self, index: usize) -> Option<rz_elf::Symbol> {
        self.img.symbol_at(index)
    }

    // ------------------------------------------------------------------
    // Symbol lookup (csoloader_elf_symb_* family)
    // ------------------------------------------------------------------

    /// `csoloader_elf_symb_offset`: GNU hash → SysV hash over the dynamic
    /// tables, no visibility filter, no .symtab fallback (the C keeps a
    /// comment forbidding it for dynamic linker resolution). Returns
    /// `(st_value, st_type)`.
    pub fn symb_offset(&self, name: &str) -> Option<(u64, u8)> {
        let sym = self.img.symbol_by_name_ex(name, false)?;
        Some((sym.value, sym.type_()))
    }

    fn resolve_runtime(&self, name: &str, exported_only: bool) -> Option<usize> {
        let sym = self.img.symbol_by_name_ex(name, exported_only)?;
        let addr = self.runtime(sym.value);

        if sym.type_() == STT_GNU_IFUNC {
            dlogd!("Resolving STT_GNU_IFUNC symbol {}", name);
            return Some(crate::linker::handle_indirect_symbol(addr));
        }

        Some(addr)
    }

    /// `csoloader_elf_symb_address`: any dynsym match, runtime address.
    pub fn symb_address(&self, name: &str) -> usize {
        if name.is_empty() {
            return 0;
        }
        self.resolve_runtime(name, false).unwrap_or(0)
    }

    /// `csoloader_elf_symb_address_exported`: visibility-filtered lookup.
    pub fn symb_address_exported(&self, name: &str) -> usize {
        if name.is_empty() {
            return 0;
        }
        self.resolve_runtime(name, true).unwrap_or(0)
    }

    /// `csoloader_elf_symb_address_by_prefix`: .symtab linear prefix scan.
    pub fn symb_address_by_prefix(&self, prefix: &str) -> usize {
        if prefix.is_empty() {
            return 0;
        }

        let Some(sym) = self.img.symbol_by_prefix(prefix) else {
            return 0;
        };
        let addr = self.runtime(sym.value);

        if sym.type_() == STT_GNU_IFUNC {
            return crate::linker::handle_indirect_symbol(addr);
        }

        addr
    }

    /// `csoloader_elf_symb_value_by_prefix`: deref of the prefix symbol.
    ///
    /// # Safety
    /// The symbol must point to readable (mapped) memory.
    pub unsafe fn symb_value_by_prefix(&self, prefix: &str) -> usize {
        let addr = self.symb_address_by_prefix(prefix);
        if addr == 0 {
            return 0;
        }
        unsafe { (addr as *const usize).read_unaligned() }
    }

    /// `csoloader_elf_get_symbol`: symtab reverse lookup for `addr`.
    pub fn get_symbol_at(&self, addr: usize) -> Option<SymInfo> {
        for sym in self.img.symtab_symbols() {
            if sym.value == 0 || sym.size == 0 {
                continue;
            }

            let sym_start = self.runtime(sym.value);
            let sym_end = sym_start.wrapping_add(sym.size as usize);

            if addr >= sym_start && addr < sym_end {
                return Some(SymInfo { name: sym.name, address: sym_start });
            }
        }
        None
    }

    // ------------------------------------------------------------------
    // Constructors / destructors
    // ------------------------------------------------------------------

    pub(crate) fn init_func_addr(&self) -> usize {
        if self.init_func_vaddr != 0 {
            self.runtime(self.init_func_vaddr)
        } else {
            0
        }
    }

    pub(crate) fn init_array(&self) -> (usize, usize) {
        if self.init_array_vaddr != 0 && self.init_array_count > 0 {
            (self.runtime(self.init_array_vaddr), self.init_array_count)
        } else {
            (0, 0)
        }
    }

    pub(crate) fn fini_array(&self) -> (usize, usize) {
        if self.fini_array_vaddr != 0 && self.fini_array_count > 0 {
            (self.runtime(self.fini_array_vaddr), self.fini_array_count)
        } else {
            (0, 0)
        }
    }

    pub(crate) fn fini_func_addr(&self) -> usize {
        if self.fini_func_vaddr != 0 {
            self.runtime(self.fini_func_vaddr)
        } else {
            0
        }
    }

    // ------------------------------------------------------------------
    // EH frame location for backtrace registration
    // ------------------------------------------------------------------

    /// backtrace-support.c `locate_eh_frame`: .eh_frame section first, then
    /// decode .eh_frame_hdr via PT_GNU_EH_FRAME.
    pub(crate) fn locate_eh_frame(&self) -> Option<usize> {
        if let Some((vaddr, _)) = self.eh_frame {
            let addr = self.runtime(vaddr);
            if addr != 0 {
                return Some(addr);
            }
        }

        let (vaddr, memsz) = self.img.gnu_eh_frame_segment()?;
        let hdr = self.runtime(vaddr);
        decode_eh_frame_ptr(hdr, memsz as usize)
    }
}

/// Decode a `.eh_frame_hdr` (version 1) into the .eh_frame pointer it
/// encodes (backtrace-support.c `decode_eh_value` for eh_frame_ptr_enc).
fn decode_eh_frame_ptr(hdr: usize, hdr_size: usize) -> Option<usize> {
    if hdr == 0 || hdr_size < 8 {
        dlogw!("PT_GNU_EH_FRAME too small");
        return None;
    }

    let base = hdr as *const u8;
    let get = |i: usize| -> Option<u8> { Some(unsafe { base.add(i).read() }) };
    let u16_at = |i: usize| -> Option<u16> { Some(get(i)? as u16 | ((get(i + 1)? as u16) << 8)) };
    let u32_at = |i: usize| -> Option<u32> {
        Some(get(i)? as u32 | ((get(i + 1)? as u32) << 8) | ((get(i + 2)? as u32) << 16) | ((get(i + 3)? as u32) << 24))
    };
    let u64_at = |i: usize| -> Option<u64> { Some(u32_at(i)? as u64 | ((u32_at(i + 4)? as u64) << 32)) };

    let version = get(0)?;
    if version != 1 {
        dlogw!(".eh_frame_hdr version {version} not supported");
        return None;
    }

    let enc = get(1)?;
    if enc == 0xff {
        // DW_EH_PE_omit
        return None;
    }

    let fmt = enc & 0x0f;
    let app = enc & 0x70;
    let at = 4usize; // header is version + 3 enc bytes

    let value: usize = match fmt {
        0x00 => {
            // DW_EH_PE_ptr
            #[cfg(target_pointer_width = "64")]
            {
                u64_at(at)? as usize
            }
            #[cfg(target_pointer_width = "32")]
            {
                u32_at(at)? as usize
            }
        }
        0x01 => {
            // DW_EH_PE_uleb128
            let mut v = 0usize;
            let mut shift = 0u32;
            let mut i = at;
            loop {
                let b = get(i)?;
                v |= ((b & 0x7f) as usize) << shift;
                i += 1;
                if b & 0x80 == 0 || shift >= 64 {
                    break;
                }
                shift += 7;
            }
            v
        }
        0x02 => u16_at(at)? as usize,
        0x03 => u32_at(at)? as usize,
        0x04 => u64_at(at)? as usize,
        0x0a => (u16_at(at)? as i16) as isize as usize, // sdata2
        0x0b => (u32_at(at)? as i32) as isize as usize, // sdata4
        0x0c => (u64_at(at)? as i64) as isize as usize, // sdata8
        _ => return None,
    };

    // pcrel base is the address of the encoded field; datarel is the hdr.
    let value = match app {
        0x00 => value,
        0x10 => value.wrapping_add(hdr.wrapping_add(4)),
        0x30 => value.wrapping_add(hdr),
        _ => return None,
    };

    // DW_EH_PE_indirect: resolve through the pointer (C does this; kept for
    // parity but guarded against NULL).
    if enc & 0x80 != 0 {
        if value == 0 {
            return None;
        }
        unsafe {
            return Some((value as *const usize).read_unaligned());
        }
    }

    Some(value)
}

/// `csoloader_elf_create(name, NULL)`'s `find_module_base`:
/// `dl_iterate_phdr` substring match returning `dlpi_addr`.
pub fn find_loaded_base(name: &str) -> Option<usize> {
    let Ok(name_c) = std::ffi::CString::new(name) else {
        return None;
    };

    FOUND.with(|f| f.set(0));

    unsafe extern "C" fn callback(
        info: *mut libc::dl_phdr_info,
        _size: usize,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        unsafe {
            let dlpi = &*info;
            let want = data as *const libc::c_char;
            if dlpi.dlpi_name.is_null() || libc::strstr(dlpi.dlpi_name, want).is_null() {
                return 0;
            }
            FOUND.with(|f| f.set(dlpi.dlpi_addr as usize));
            1
        }
    }

    let ret = unsafe { libc::dl_iterate_phdr(Some(callback), name_c.as_ptr() as *mut libc::c_void) };
    if ret == 0 {
        return None;
    }

    FOUND.with(|f| {
        let base = f.get();
        if base != 0 { Some(base) } else { None }
    })
}

thread_local! {
    static FOUND: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
