//! fd-based custom ELF loader (port of CSOLoader).
//!
//! - `image`: ELF image parser (csoloader_elf) — ported.
//! - `tls`: TLS segment machinery — ported.
//! - `linker_*` / `runtime`: in-process linker port (linker.c, csoloader.c).
//! - `backtrace`: `g_custom_libs` registry + `__register_frame` hooks
//!   (backtrace-support.c registry half).
//! - `misc`: carray + sleb128 + backtrace-support ports.
//! - `linker`: the small cross-module shim image.rs/tls.rs were written
//!   against (`page_size`, `handle_indirect_symbol`).

// The C keeps `g_custom_libs`/its mutex as file-scope globals; the Rust port
// uses `static Mutex<[T; N]>` for sound interior mutability (see `backtrace.rs`).

pub const TAG: &str = rz_common::LOG_TAG;

/// csoloader error type (image parsing, loading).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<rz_elf::Error> for Error {
    fn from(e: rz_elf::Error) -> Self {
        Error::Other(e.to_string())
    }
}

pub mod image;
pub mod tls;

mod backtrace;
pub mod linker_core;
mod linker_load;
mod linker_reloc;
mod linker_sym;
mod misc;
pub mod runtime;

/// Cross-module shim referenced by `image`/`tls`.
pub mod linker {
    pub use super::linker_core::page_size;
    pub use super::linker_sym::handle_indirect_symbol;
}
