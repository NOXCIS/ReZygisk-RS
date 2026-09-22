//! Link-time export policy for `libzygisk.so`.
//!
//! The C loader builds with `-fvisibility=hidden` and marks only `entry`
//! `visibility("default")` — the ptracer finds `entry` by scanning the
//! file's dynamic symbol table (`find_dynsym_value`), so it must stay in
//! `.dynsym`. Every other symbol (`fork`/`strdup`/`property_get` hooks, the
//! JNI wrapper tables, `__tls_get_addr`, the arm32 ifunc shims) is local to
//! the shared object, matching the C.
//!
//! Localization is what keeps the arm32 `memcpy`/`memmove`/... shims
//! preemptible-proof: intra-object references bind to them instead of
//! resolving to libc's IFUNC symbols under Tango.

use std::path::Path;

fn main() {
    println!("cargo::rerun-if-changed=exports.map");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        let map = Path::new(env!("CARGO_MANIFEST_DIR")).join("exports.map");
        println!("cargo::rustc-link-arg=-Wl,--version-script={}", map.display());
    }
}
