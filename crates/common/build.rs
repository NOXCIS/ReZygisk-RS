//! Build-time deployment generation id, baked into every component.
//!
//! Why: a stale component cannot report anything about itself. The field
//! failure this guards against was a 64-bit monitor left behind by an older
//! build — it predated the very diagnostics that would have named it, so
//! "the line is missing" read as "the code path never ran" and cost a full
//! debug cycle. The generation id moves that fact out of the component's own
//! (possibly stale) code: it is baked into every binary of one build, recorded
//! in the module manifest by scripts/verify_deploy.sh, and read back by the
//! host script from the bytes actually installed on the device.
//!
//! Derivation is reproducible for a given tree — no clock, no network:
//!   RZGEN-<version>+g<short-sha>[-dirty[.w<digest>]]
//!   RZGEN-<version>+unknown            (no git, or no commit yet)
//!
//! `-dirty` tracks the whole worktree (any uncommitted change), while `.w<hex>`
//! digests only the *build inputs* (`git diff HEAD` + porcelain status + the
//! contents of untracked inputs, under the paths below). So two different dirty
//! trees do not share one id — which is how "same commit, uncommitted changes"
//! staleness stays detectable — while a concurrent edit to a doc or a helper
//! script cannot make the two target builds of one run look mixed.
//!
//! RZ_GENERATION overrides the whole value (CI / source tarball builds).

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Paths whose content can end up in a shipped artifact. Everything else (docs,
/// diagnostics, helper scripts) is deliberately outside the digest.
const BUILD_INPUTS: &[&str] = &[
    "crates",
    "truman_ref",
    "module",
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo",
];

/// Cap on a single untracked input read into the digest.
const MAX_DIGESTED_FILE: usize = 4 << 20;

/// Chars allowed in a generation id: it appears in one log token, in the
/// manifest JSON and in a `grep -o` extraction pattern.
fn sanitize(value: &str) -> String {
    let cleaned: String = value
        .trim()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-') { c } else { '-' })
        .collect();
    if cleaned.is_empty() { "unknown".to_string() } else { cleaned }
}

fn git_stdout(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git").arg("-C").arg(root).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(out.stdout)
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = git_stdout(root, args)?;
    Some(String::from_utf8_lossy(&out).trim_end().to_string())
}

/// Digest of the working-tree state of the build inputs. `git hash-object
/// --stdin` hashes the stream without `-w`, so nothing is written and no git
/// state is touched.
fn worktree_digest(root: &Path, input_status: &str) -> Option<String> {
    let mut feed: Vec<u8> = Vec::new();
    feed.extend_from_slice(&git_stdout(root, &paths_args(&["diff", "HEAD", "--"]))?);
    feed.extend_from_slice(input_status.as_bytes());

    // Untracked inputs never reach `git diff`; their contents are build inputs
    // all the same (a fresh module that is not `git add`ed yet still compiles).
    if let Some(list) = git(root, &paths_args(&["ls-files", "--others", "--exclude-standard"])) {
        for rel in list.lines().filter(|l| !l.is_empty()) {
            feed.extend_from_slice(rel.as_bytes());
            match std::fs::read(root.join(rel)) {
                Ok(bytes) if bytes.len() <= MAX_DIGESTED_FILE => feed.extend_from_slice(&bytes),
                _ => {}
            }
        }
    }

    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["hash-object", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    {
        let mut stdin = child.stdin.take()?;
        stdin.write_all(&feed).ok()?;
    }

    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }

    let hash = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!hash.is_empty()).then(|| hash[..hash.len().min(8)].to_string())
}

fn paths_args<'a>(base: &'a [&'a str]) -> Vec<&'a str> {
    let mut args = base.to_vec();
    args.extend_from_slice(BUILD_INPUTS);
    args
}

/// Nearest ancestor (including `start`) holding a `.git` entry; `.git` may be
/// a directory or a file (worktree / submodule checkout).
fn repo_root(start: &Path) -> Option<PathBuf> {
    let mut dir = Some(start);
    for _ in 0..6 {
        let candidate = dir?;
        if candidate.join(".git").exists() {
            return Some(candidate.to_path_buf());
        }
        dir = candidate.parent();
    }
    None
}

fn compute_generation() -> (String, Option<PathBuf>) {
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let root = repo_root(&PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default()));

    if let Ok(over) = std::env::var("RZ_GENERATION") {
        let over = over.trim().to_string();
        if !over.is_empty() {
            let id = sanitize(&over);
            if id != over {
                println!("cargo::warning=RZ_GENERATION contained characters outside [A-Za-z0-9._+-]; using {id}");
            }
            return (id, root);
        }
    }

    let Some(root) = root else {
        println!("cargo::warning=no .git found above this crate: generation has no provenance (set RZ_GENERATION for reproducible builds)");
        return (format!("RZGEN-{version}+unknown"), None);
    };

    // Whole-repo status decides `-dirty`; the digest below is narrower so that
    // editing this script does not make two builds look like different
    // generations.
    let status = git(&root, &["status", "--porcelain"]);
    // An unknown status counts as dirty: a falsely clean id is the one a reader
    // would trust.
    let dirty = status.as_deref().map(|s| !s.trim().is_empty()).unwrap_or(true);
    let input_status = git(&root, &paths_args(&["status", "--porcelain"])).unwrap_or_default();

    let head = git(&root, &["rev-parse", "--short", "HEAD"]).filter(|h| !h.is_empty());
    let Some(head) = head else {
        let mut id = format!("RZGEN-{version}+unknown");
        if dirty {
            id.push_str("-dirty");
        }
        return (id, Some(root));
    };

    let mut id = format!("RZGEN-{version}+g{head}");
    if dirty {
        id.push_str("-dirty");
        if let Some(digest) = worktree_digest(&root, &input_status) {
            id.push_str(&format!(".w{digest}"));
        }
    }

    (id, Some(root))
}

fn main() {
    let (generation, root) = compute_generation();
    println!("cargo::rustc-env=RZ_GENERATION={generation}");

    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src");
    println!("cargo::rerun-if-env-changed=RZ_GENERATION");

    // The watch list must cover exactly what the digest covers. Without this,
    // editing a crate that does not depend on this build script (e.g. plti)
    // rebuilds that crate but never re-runs this script, and two different
    // source states end up sharing one id — the hole this whole design closes.
    if let Some(root) = &root {
        for input in BUILD_INPUTS {
            let path = root.join(input);
            if path.exists() {
                println!("cargo::rerun-if-changed={}", path.display());
            }
        }
    }

    // Anything that can change HEAD, the index or a branch tip must re-run this
    // script, or the id goes stale and stops describing the tree.
    if let Some(root) = root {
        for watched in [".git/HEAD", ".git/index", ".git/refs/heads", ".git/packed-refs"] {
            let path = root.join(watched);
            if path.exists() {
                println!("cargo::rerun-if-changed={}", path.display());
            }
        }
    }
}
