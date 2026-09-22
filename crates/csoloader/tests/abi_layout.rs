//! ABI-layout parity tests: the public `#[repr(C)]` csoloader structs must
//! match the C `include/linker.h` layouts field-for-field on x86_64 LP64.
//! rz-loader embeds `Linker` by value in its `abi::CsoLib`, and the C casts
//! `(struct loaded_dep *)linker` — so any layout drift is a real crash bug,
//! not a compile-time concern.
//!
//! Expected values derive from
//! `loader/src/external/csoloader/include/linker.h` (and `module.h` for
//! `struct csoloader`) on LP64 (pointers/size_t = 8 bytes, int = 4,
//! bool = 1, alignment 8):
//!
//! - `struct tls_indices_data`: indices@0, count@8, capacity@16, size 24.
//! - `struct loaded_dep`: img@0, tls_indices@8, is_manual_load@32,
//!   load_bias@40, map_base@48, map_size@56, size 64.
//! - `struct linker`: img@0, tls_indices@8, dependencies@32 (64 × 64),
//!   dep_count@4128, main_map_size@4136, is_linked@4144, size 4152.
//! - `struct csoloader`: lib_path@0, img@8, linker@16, size 4168.

use std::mem::{align_of, offset_of, size_of};

use rz_csoloader::linker_core::{Linker, LoadedDep, TlsIndicesData, MAX_DEPS};
use rz_csoloader::runtime::CsoLib;

fn require_lp64() {
    assert_eq!(
        std::mem::size_of::<usize>(),
        8,
        "layout expectations below are LP64-only"
    );
}

#[test]
fn tls_indices_data_matches_linker_h() {
    require_lp64();
    // struct tls_indices_data { void **indices; size_t count; size_t capacity; };
    assert_eq!(size_of::<TlsIndicesData>(), 24);
    assert_eq!(align_of::<TlsIndicesData>(), 8);
    assert_eq!(offset_of!(TlsIndicesData, indices), 0);
    assert_eq!(offset_of!(TlsIndicesData, count), 8);
    assert_eq!(offset_of!(TlsIndicesData, capacity), 16);
}

#[test]
fn loaded_dep_matches_linker_h() {
    require_lp64();
    // struct loaded_dep { img; tls_indices; bool is_manual_load;
    //                     uintptr_t load_bias; void *map_base; size_t map_size; };
    assert_eq!(size_of::<LoadedDep>(), 64);
    assert_eq!(align_of::<LoadedDep>(), 8);
    assert_eq!(offset_of!(LoadedDep, img), 0);
    assert_eq!(offset_of!(LoadedDep, tls_indices), 8);
    assert_eq!(offset_of!(LoadedDep, is_manual_load), 32);
    assert_eq!(offset_of!(LoadedDep, load_bias), 40);
    assert_eq!(offset_of!(LoadedDep, map_base), 48);
    assert_eq!(offset_of!(LoadedDep, map_size), 56);
}

#[test]
fn linker_matches_linker_h() {
    require_lp64();
    assert_eq!(MAX_DEPS, 64);
    // struct linker { img; tls_indices; struct loaded_dep dependencies[64];
    //                 int dep_count; size_t main_map_size; bool is_linked; };
    assert_eq!(size_of::<Linker>(), 4152);
    assert_eq!(align_of::<Linker>(), 8);
    assert_eq!(offset_of!(Linker, img), 0);
    assert_eq!(offset_of!(Linker, tls_indices), 8);
    assert_eq!(offset_of!(Linker, dependencies), 32);
    assert_eq!(offset_of!(Linker, dep_count), 32 + 64 * 64); // 4128
    assert_eq!(offset_of!(Linker, main_map_size), 4136);
    assert_eq!(offset_of!(Linker, is_linked), 4144);
}

#[test]
fn linker_and_loaded_dep_prefix_overlap_matches_c_cast() {
    require_lp64();
    // linker.h: "DO NOT change this 2 members from order. Keep consistent
    // with loaded_dep structure" — the C does `(struct loaded_dep *)linker`.
    // The two members must sit at identical offsets with identical size.
    assert_eq!(offset_of!(Linker, img), offset_of!(LoadedDep, img));
    assert_eq!(offset_of!(Linker, tls_indices), offset_of!(LoadedDep, tls_indices));
    assert_eq!(size_of::<TlsIndicesData>(), 24);
}

#[test]
fn cso_lib_matches_module_h() {
    require_lp64();
    // module.h: struct csoloader { char *lib_path; struct csoloader_elf *img;
    //                            struct linker linker; };
    assert_eq!(size_of::<CsoLib>(), 16 + 4152); // 4168
    assert_eq!(offset_of!(CsoLib, lib_path), 0);
    assert_eq!(offset_of!(CsoLib, img), 8);
    assert_eq!(offset_of!(CsoLib, linker), 16);
}
