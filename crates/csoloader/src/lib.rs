//! fd-based custom ELF loader.
//!
//! Loads shared libraries from file descriptors (including memfd) without
//! touching the filesystem, enabling injection of Zygisk modules into the
//! zygote process where the original ELF may be deleted or inaccessible.
//!
//! # Modules
//! - `image`: ELF image parser
//! - `tls`: TLS segment allocation and management
//! - `linker_*` / `runtime`: in-process dynamic linker (symbol resolution,
//!   relocation, initialization)
//! - `backtrace`: custom library registry for unwinder integration
//! - `misc`: helper utilities (sleb128 encoding, arrays)

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
