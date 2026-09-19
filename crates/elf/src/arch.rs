//! linker.c `R_GENERIC_*` mapping, for all four ABIs regardless of the build
//! target so one classification table can drive any tracee.

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenericReloc {
    None,
    Copy,
    IRelative,
    Relative,
    GlobDat,
    Absolute,
    JumpSlot,
    /// R_X86_64_32
    X86_64_32,
    /// R_X86_64_PC32
    X86_64_PC32,
    /// R_386_PC32
    X86_PC32,
    TlsDtpmod,
    TlsDtprel,
    TlsTprel,
    TlsDesc,
    Other(u32),
}

// EM_* e_machine values.
pub const EM_386: u16 = 3;
pub const EM_ARM: u16 = 40;
pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;

/// Generic relocation type numbers per machine (linker.c's per-arch defines).
pub mod types {
    pub mod aarch64 {
        pub const ABS64: u32 = 257;
        pub const COPY: u32 = 1024;
        pub const GLOB_DAT: u32 = 1025;
        pub const JUMP_SLOT: u32 = 1026;
        pub const RELATIVE: u32 = 1027;
        pub const TLS_DTPMOD: u32 = 1028;
        pub const TLS_DTPREL: u32 = 1029;
        pub const TLS_TPREL: u32 = 1030;
        pub const TLSDESC: u32 = 1031;
        pub const IRELATIVE: u32 = 1032;
    }

    pub mod arm {
        pub const ABS32: u32 = 2;
        pub const TLS_DTPMOD32: u32 = 17;
        pub const TLS_DTPOFF32: u32 = 18;
        pub const TLS_TPOFF32: u32 = 19;
        pub const COPY: u32 = 20;
        pub const GLOB_DAT: u32 = 21;
        pub const JUMP_SLOT: u32 = 22;
        pub const RELATIVE: u32 = 23;
        pub const IRELATIVE: u32 = 160;
        pub const TLS_DESC: u32 = 163;
    }

    pub mod x86 {
        pub const PC32: u32 = 2;
        pub const ABS32: u32 = 1;
        pub const COPY: u32 = 5;
        pub const GLOB_DAT: u32 = 6;
        pub const JMP_SLOT: u32 = 7;
        pub const RELATIVE: u32 = 8;
        pub const TLS_TPOFF: u32 = 14;
        pub const TLS_DTPMOD32: u32 = 35;
        pub const TLS_DTPOFF32: u32 = 36;
        pub const TLS_DESC: u32 = 43;
        pub const IRELATIVE: u32 = 42;
    }

    pub mod x86_64 {
        pub const PC32: u32 = 2;
        pub const R_64: u32 = 1;
        pub const COPY: u32 = 5;
        pub const GLOB_DAT: u32 = 6;
        pub const JUMP_SLOT: u32 = 7;
        pub const RELATIVE: u32 = 8;
        pub const DTPMOD64: u32 = 16;
        pub const DTPOFF64: u32 = 17;
        pub const TPOFF64: u32 = 18;
        pub const TLSDESC: u32 = 36;
        pub const IRELATIVE: u32 = 37;
    }
}

fn aarch64(t: u32) -> GenericReloc {
    use types::aarch64::*;
    match t {
        0 => GenericReloc::None,
        COPY => GenericReloc::Copy,
        GLOB_DAT => GenericReloc::GlobDat,
        JUMP_SLOT => GenericReloc::JumpSlot,
        RELATIVE => GenericReloc::Relative,
        TLS_DTPMOD => GenericReloc::TlsDtpmod,
        TLS_DTPREL => GenericReloc::TlsDtprel,
        TLS_TPREL => GenericReloc::TlsTprel,
        TLSDESC => GenericReloc::TlsDesc,
        IRELATIVE => GenericReloc::IRelative,
        ABS64 => GenericReloc::Absolute,
        other => GenericReloc::Other(other),
    }
}

fn arm(t: u32) -> GenericReloc {
    use types::arm::*;
    match t {
        0 => GenericReloc::None,
        ABS32 => GenericReloc::Absolute,
        GLOB_DAT => GenericReloc::GlobDat,
        JUMP_SLOT => GenericReloc::JumpSlot,
        RELATIVE => GenericReloc::Relative,
        IRELATIVE => GenericReloc::IRelative,
        COPY => GenericReloc::Copy,
        TLS_DTPMOD32 => GenericReloc::TlsDtpmod,
        TLS_DTPOFF32 => GenericReloc::TlsDtprel,
        TLS_TPOFF32 => GenericReloc::TlsTprel,
        TLS_DESC => GenericReloc::TlsDesc,
        other => GenericReloc::Other(other),
    }
}

fn x86(t: u32) -> GenericReloc {
    use types::x86::*;
    match t {
        0 => GenericReloc::None,
        ABS32 => GenericReloc::Absolute,
        GLOB_DAT => GenericReloc::GlobDat,
        JMP_SLOT => GenericReloc::JumpSlot,
        RELATIVE => GenericReloc::Relative,
        IRELATIVE => GenericReloc::IRelative,
        COPY => GenericReloc::Copy,
        TLS_DTPMOD32 => GenericReloc::TlsDtpmod,
        TLS_DTPOFF32 => GenericReloc::TlsDtprel,
        TLS_TPOFF => GenericReloc::TlsTprel,
        TLS_DESC => GenericReloc::TlsDesc,
        PC32 => GenericReloc::X86_PC32,
        other => GenericReloc::Other(other),
    }
}

fn x86_64(t: u32) -> GenericReloc {
    use types::x86_64::*;
    match t {
        0 => GenericReloc::None,
        R_64 => GenericReloc::Absolute,
        GLOB_DAT => GenericReloc::GlobDat,
        JUMP_SLOT => GenericReloc::JumpSlot,
        RELATIVE => GenericReloc::Relative,
        IRELATIVE => GenericReloc::IRelative,
        COPY => GenericReloc::Copy,
        DTPMOD64 => GenericReloc::TlsDtpmod,
        DTPOFF64 => GenericReloc::TlsDtprel,
        TPOFF64 => GenericReloc::TlsTprel,
        TLSDESC => GenericReloc::TlsDesc,
        PC32 => GenericReloc::X86_64_PC32,
        other => GenericReloc::Other(other),
    }
}

/// Classify a raw relocation type for `e_machine`. linker.c only ever runs on
/// the tracee's architecture, but exposing all four keeps the crate
/// host-testable and lets the ptracer pick by tracee machine.
pub fn generic_reloc_type(machine: u16, rtype: u32) -> GenericReloc {
    match machine {
        EM_AARCH64 => aarch64(rtype),
        EM_ARM => arm(rtype),
        EM_386 => x86(rtype),
        EM_X86_64 => x86_64(rtype),
        _ => GenericReloc::Other(rtype),
    }
}
