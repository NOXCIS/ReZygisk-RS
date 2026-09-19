//! Truman Phase 7 spoof configuration, embedded at build time.
//!
//! Pure-Rust, host-testable: no JNI, no platform types. The ABI layer
//! (`abi.rs`) and JNI glue (`jni_glue.rs`) call into `should_spoof()` /
//! `spoof_entries()` only, so this whole file ports into the future
//! ReZygisk-RS daemon unchanged.

/// Packages whose processes get the reflection rewrite. The Duck Detector
/// canary is the initial target; append freely (applies at next rebuild).
pub const TARGET_PKGS: &[&str] = &["com.eltavine.duckdetector"];

/// One reflection rewrite: set `field` on `class` (static `String`) to
/// `value` in every targeted process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpoofEntry {
    pub class: &'static str,
    pub field: &'static str,
    pub value: &'static str,
}

/// The rewrite pairs with the kernel dome S7 path-spoof: the fake value MUST
/// match the fake basename ksud publishes (see ksud
/// src/truman/data/spoof_paths.txt), so the spoofed path both renders AND
/// resolves for enrolled UIDs.
pub const SPOOF_ENTRIES: &[SpoofEntry] = &[SpoofEntry {
    class: "android/content/res/AssetManager",
    field: "LINEAGE_APK_PATH",
    value: "com.google.android.platform-res.apk",
}];

/// Entries to apply for `pkg`, or an empty slice when the package is not
/// targeted (the common case — every zygote fork pays one strcmp loop).
pub fn spoof_entries(pkg: &str) -> &'static [SpoofEntry] {
    if TARGET_PKGS.contains(&pkg) {
        SPOOF_ENTRIES
    } else {
        &[]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canary_is_targeted() {
        assert_eq!(spoof_entries("com.eltavine.duckdetector"), SPOOF_ENTRIES);
    }

    #[test]
    fn gms_and_unknown_are_not() {
        assert!(spoof_entries("com.google.android.gms").is_empty());
        assert!(spoof_entries("com.android.systemui").is_empty());
        assert!(spoof_entries("").is_empty());
    }

    #[test]
    fn entries_pair_with_kernel_spoof_map() {
        // The fake basename here must equal the fake basename ksud publishes
        // for /system/framework/org.lineageos.platform-res.apk.
        assert_eq!(SPOOF_ENTRIES[0].value, "com.google.android.platform-res.apk");
        assert!(SPOOF_ENTRIES[0].value.find('/').is_none());
    }
}
