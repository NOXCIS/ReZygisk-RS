//! goblin-based ELF/relocation core shared by csoloader, plti and the remote
//! loader. Pure parsing over byte buffers — host-testable and free of unsafe.
//!
//! Semantics mirror the C fork:
//! - symbol lookup: [out/ReZygisk/loader/src/common/elf_util.c](../../../out/ReZygisk/loader/src/common/elf_util.c)
//!   (GnuLookup → ElfLookup → LinearLookup, valid-symtab filtering, prefix scan)
//! - relocation iteration: [out/ReZygisk/loader/src/external/csoloader/src/linker.c](../../../out/ReZygisk/loader/src/external/csoloader/src/linker.c)
//!   `_linker_process_relocations` (DT_RELA/REL, DT_JMPREL, Android packed
//!   APS2, RELR incl. the Android variants)

pub mod arch;
mod image;
mod reloc;

pub use arch::{generic_reloc_type, GenericReloc};
pub use image::{ElfImage, LoadSegment, RelocTables, Symbol};
pub use reloc::{
    decode_android_packed, decode_relr, sleb128_decode, Reloc, APS2_MAGIC, DT_ANDROID_REL,
    DT_ANDROID_RELA, DT_ANDROID_RELASZ, DT_ANDROID_RELRENT, DT_ANDROID_RELR, DT_ANDROID_RELSZ,
    DT_ANDROID_RELRSZ, DT_RELRENT, DT_RELR, DT_RELRSZ,
};

#[cfg(test)]
mod tests;

use thiserror::Error;

pub const SHT_SYMTAB: u32 = 2;
pub const SHT_STRTAB: u32 = 3;
pub const SHT_DYNSYM: u32 = 11;
pub const SHT_GNU_HASH: u32 = 0x6fff_fff6;

pub const SHN_UNDEF: u16 = 0;

pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_GNU_IFUNC: u8 = 10;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const STB_GNU_UNIQUE: u8 = 10;

// ELF_ST_VISIBILITY values (st_other & 0x3).
pub const STV_DEFAULT: u8 = 0;
pub const STV_INTERNAL: u8 = 1;
pub const STV_HIDDEN: u8 = 2;
pub const STV_PROTECTED: u8 = 3;

/// csoloader elf_util.c `is_dynamic_symbol_visible`: UNDEF symbols never
/// resolve; the exported-only filter additionally demands GLOBAL/WEAK/GNU_UNIQUE
/// binding with DEFAULT/PROTECTED visibility.
pub fn symbol_is_visible(sym: &Symbol, exported_only: bool) -> bool {
    if sym.shndx == SHN_UNDEF {
        return false;
    }
    if !exported_only {
        return true;
    }

    let bind = sym_bind(sym.info);
    let vis = sym.other & 0x3;

    if bind != STB_GLOBAL && bind != STB_WEAK && bind != STB_GNU_UNIQUE {
        return false;
    }

    vis == STV_DEFAULT || vis == STV_PROTECTED
}

pub fn sym_type(st_info: u8) -> u8 {
    st_info & 0xf
}

pub fn sym_bind(st_info: u8) -> u8 {
    st_info >> 4
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("goblin parse error: {0}")]
    Parse(String),
    #[error("field {0} out of bounds (size {1})")]
    OutOfBounds(&'static str, usize),
    #[error("missing {0}")]
    Missing(&'static str),
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
