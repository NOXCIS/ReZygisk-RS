//! Deployment generation: the build id every component carries, plus the
//! runtime cross-check against the manifest written by the host.
//!
//! The id itself is baked in by `build.rs` (see that file for the derivation).
//! What matters here is that the value is reachable as `&'static str` from
//! every binary: each component logs it at startup, so the deployed set can be
//! validated with one grep instead of by trusting each component to describe
//! itself. A stale binary cannot self-report, which is exactly why the host
//! script also reads the id out of the installed bytes.

use std::path::{Path, PathBuf};

/// Build-time generation id, e.g. `RZGEN-1.0.0+g6e282a7-dirty.w1a2b3c4`.
/// `build.rs` always sets it; the fallback only exists so a directly-invoked
/// rustc cannot silently produce an unguarded binary.
pub const RZ_GENERATION: &str = match option_env!("RZ_GENERATION") {
    Some(id) => id,
    None => "RZGEN-0.0.0+unknown-nobuildscript",
};

/// The same id, bracketed, as a single rodata constant. Rust string constants
/// are not NUL-terminated, so an unbracketed id could run into adjacent
/// printable rodata when extracted from a stripped binary; the delimiters make
/// `<<RZGEN:...>>` an exact, greppable token in both logcat and the file bytes.
pub const RZ_GENERATION_BANNER: &str = concat!("<<RZGEN:", env!("RZ_GENERATION"), ">>");

/// Manifest file name, written host-side next to the module's `bin/`+`lib*/`.
pub const MANIFEST_FILE: &str = ".generation.json";

/// Documented fallback for components whose `/proc/self/exe` is not inside the
/// module directory — the loader runs inside `app_process64`, so it cannot
/// derive the module root from its own image. Tracks `consts::PATH_MODULES_DIR`
/// + the module name.
pub const FALLBACK_MANIFEST: &str = "/data/adb/modules/rezygisk/.generation.json";

/// Top-level key of the manifest holding the generation id of the staged
/// build. Deliberately distinct from the per-component `"generation"` keys so
/// the reader below needs no JSON parser (nor a serde dependency in the
/// injected loader).
const MANIFEST_KEY: &str = "\"deployment_generation\"";

/// `lp64` / `lp32`, matching the daemon's existing "Service online (lp64)" line.
pub fn abi_label() -> &'static str {
    if cfg!(target_pointer_width = "64") { "lp64" } else { "lp32" }
}

/// `generation: <<RZGEN:id>> (lp64 monitor)` — one stable, greppable format for
/// every component and role.
pub fn generation_line(role: &str) -> String {
    format!("generation: {RZ_GENERATION_BANNER} ({} {role})", abi_label())
}

/// Where `stage` wrote the manifest: the module root derived from the running
/// image (`<mod>/bin/...` or `<mod>/lib64/...`), else the fixed module path.
pub fn manifest_path() -> PathBuf {
    if let Ok(exe) = std::fs::read_link("/proc/self/exe") {
        if let Some(root) = exe.parent().and_then(Path::parent) {
            let candidate = root.join(MANIFEST_FILE);
            if candidate.is_file() {
                return candidate;
            }
        }
    }

    PathBuf::from(FALLBACK_MANIFEST)
}

/// Result of comparing this component's id against the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentCheck {
    Match,
    /// The manifest names a different generation: this process is a different
    /// build than the one that was staged.
    Mismatch(String),
    /// No manifest at the resolved path (pre-guard deployment, or the module
    /// was installed without the host script).
    Missing,
    /// Present but not parseable / not readable.
    Unreadable,
}

/// First `"<key>": "value"` string in `text`. The manifest is machine-written
/// with a fixed shape, so this stays a scan, not a parser.
fn json_string(text: &str, key: &str) -> Option<String> {
    let rest = &text[text.find(key)? + key.len()..];
    let rest = rest[rest.find(':')? + 1..].trim_start();
    let rest = rest.strip_prefix('"')?;
    let value = &rest[..rest.find('"')?];
    if value.is_empty() || value.chars().any(char::is_control) {
        return None;
    }

    Some(value.to_string())
}

/// Read the generation the host recorded for the staged deployment.
pub fn manifest_generation() -> DeploymentCheck {
    match std::fs::read_to_string(manifest_path()) {
        Ok(text) => match json_string(&text, MANIFEST_KEY) {
            Some(id) => {
                if id == RZ_GENERATION { DeploymentCheck::Match } else { DeploymentCheck::Mismatch(id) }
            }
            None => DeploymentCheck::Unreadable,
        },
        Err(_) => DeploymentCheck::Missing,
    }
}

/// Log this component's generation to logcat. INFO is deliberately below the
/// daemon's `.quiet` floor: a quiet deployment hides this line, so
/// `verify_deploy.sh assert` refuses to report PASS while `.quiet` exists.
/// Returns the line so a component with a durable stdout can mirror it into
/// `verbose.log` without logging twice to logcat.
pub fn log_generation(tag: &str, role: &str) -> String {
    let line = generation_line(role);
    crate::logi!(tag, "{line}");
    line
}

/// `log_generation` plus the cross-check that makes a mixed deployment loud:
/// on mismatch the *current* components scream with both ids, because the
/// stale one cannot. Infallible: a missing or unreadable manifest is a debug
/// note, never a crash — the guard must not be able to break a boot.
pub fn log_generation_and_check(tag: &str, role: &str) -> String {
    let line = log_generation(tag, role);

    match manifest_generation() {
        DeploymentCheck::Match => {
            crate::logd!(tag, "generation matches manifest {}", manifest_path().display());
        }
        DeploymentCheck::Mismatch(manifest) => {
            crate::loge!(
                tag,
                "generation MISMATCH: {} is {} but {} records {} — mixed-generation deployment, re-run scripts/verify_deploy.sh stage",
                role,
                RZ_GENERATION_BANNER,
                manifest_path().display(),
                manifest
            );
        }
        DeploymentCheck::Missing => {
            crate::logd!(
                tag,
                "no deployment manifest at {} (generation cross-check skipped)",
                manifest_path().display()
            );
        }
        DeploymentCheck::Unreadable => {
            crate::logd!(
                tag,
                "deployment manifest at {} is not readable (generation cross-check skipped)",
                manifest_path().display()
            );
        }
    }

    line
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_reads_the_top_level_key_only() {
        let text = r#"{
  "schema": 1,
  "deployment_generation": "RZGEN-1.0.0+gabc-dirty.w1234",
  "components": { "bin/zygiskd64": { "generation": "other" } }
}"#;
        assert_eq!(json_string(text, MANIFEST_KEY).as_deref(), Some("RZGEN-1.0.0+gabc-dirty.w1234"));
    }

    #[test]
    fn json_string_rejects_garbage() {
        assert_eq!(json_string("{}", MANIFEST_KEY), None);
        assert_eq!(json_string(r#""deployment_generation": ""}"#, MANIFEST_KEY), None);
        assert_eq!(json_string("\"deployment_generation\": \"bad\nvalue\"}", MANIFEST_KEY), None);
    }
}
