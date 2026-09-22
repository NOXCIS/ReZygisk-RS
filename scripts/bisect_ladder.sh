#!/usr/bin/env bash
# F4->F3->F1 loader bisect ladder (runnable, self-verifying harness).
#
# Why: the arm64 loader from the L2+ tree (commit b2697c7, "F1-F5") crashes
# zygote64 with a stack-canary abort, while the 18:45 lib ("pre-F1/F3/F4") is
# device-verified stable. The ladder peels the newest fix set off first and
# re-tests after a reboot, one rung per boot.
#
# HOW A RUNG IS BUILT: the tree has no cargo feature gate for F1/F3/F4 (the
# only feature is rz-common's stealth-tag), so a rung is a *source state*. This
# script copies the working tree into diag/bisect/scratch, applies its own
# BISECT-RUNG replacements there, and drives verify_deploy.sh *from the scratch
# copy*: the real tree, its target/ artifacts and its git state are untouched.
# Every replacement is exact-string (no fuzz) and `show <rung>` prints all of
# them; if an anchor no longer matches exactly once, the rung is REFUSED.
#
# DECISION RULE
#   D0 all-on       F1+F3+F4 on  (F4 restored: the pre-bisect candidate)
#   D1 f4off        F4 off       (== tree as committed; NEGATIVE CONTROL)
#   D2 f4f3off      F4+F3 off
#   D3 f4f3f1off    F4+F3+F1 off (pre-F1/F3/F4 shape; 18:45-stable equivalent)
#   * OK at Dn but CRASHED at D(n-1) => the fix set removed in between causes
#     the crash (D0->D1: F4, D1->D2: F3, D2->D3: F1).
#   * CRASHED at D3 as well => none of F1/F3/F4 alone explains it.
#   * INJECTED_NO_HOOKS is NOT a rung signal: it is the known 64-bit ELF-image
#     blocker ("Failed to initialize ELF image for library: .../libandroid_runtime.so")
#     owned by another agent. Until that fix lands, expect INJECTED_NO_HOOKS on
#     64-bit at every rung; the ladder signal is CRASHED vs OK.
#
# VERDICTS (one VERDICT line per ABI, plus the exact evidence lines)
#   CRASHED            crash evidence for that ABI's zygote (tombstone / Fatal
#                      signal / stack corruption) — wins over everything else
#   OK                 injected + hooking + execution done + zero hook/ELF errors
#   INJECTED_NO_HOOKS  injected, but >=1 "Failed to register plt_hook" or
#                      "Failed to initialize ELF image for library"
#   NOT_INJECTED       handoff/tracer ran, no loader "injected" line, no crash
#   UNKNOWN            no handoff line (monitor/daemon problem, out of scope),
#                      or injected but execution never completed (possible hang)
#
# Subcommands:
#   rungs               ladder table + decision rule
#   show <rung>         rung definition + exact source replacements + dry check
#   build <rung>        patch scratch + build both ABIs (no device needed)
#   stage <rung>        build + stage via verify_deploy.sh + provenance check
#   assert <rung>       post-reboot assertions -> VERDICT per ABI (device)
#   classify <log> [r]  classify a saved logcat dump (offline, no device)
#   probe               read-only: what loader generation is live on the device
#   selftest [--with-build]
#                       prove the harness itself: rung table, patch anchors,
#                       control artifacts, classifier on recorded fixtures,
#                       no-device fast fail, no bare adb calls
#   next                which rung to run next, from ladder-results.tsv
#
# Env: ADB, ADB_TIMEOUT=25 (every adb call), BUILD_TIMEOUT=2400,
#      STAGE_TIMEOUT=2400, ASSERT_TIMEOUT=600, MOD=/data/adb/modules/rezygisk,
#      RZ_FEATURES="" (e.g. rz-common/stealth-tag), RZ_ASSERT_LOG=<file>,
#      RZ_BISECT_32_ARTIFACT=<path> (control-crash 32-bit slot override).
# Exit: 0 ok, 1 unexpected/control mismatch, 2 usage|no-device|refused,
#       3 mixed-or-stale generation, 4 timeout.
# ==== end of usage ====
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SELF="$(readlink -f "${BASH_SOURCE[0]}")"
RESULTS="$REPO/diag/bisect"
SCRATCH="$RESULTS/scratch"
TSV="$RESULTS/ladder-results.tsv"
STATE="$RESULTS/staged.env"
PATCHES="$RESULTS/patches"

ADB_TIMEOUT="${ADB_TIMEOUT:-25}"
BUILD_TIMEOUT="${BUILD_TIMEOUT:-2400}"
STAGE_TIMEOUT="${STAGE_TIMEOUT:-2400}"
ASSERT_TIMEOUT="${ASSERT_TIMEOUT:-600}"
MOD="${MOD:-/data/adb/modules/rezygisk}"
FEATURES="${RZ_FEATURES:-}"
T64=aarch64-linux-android
T32=armv7-linux-androideabi
BAD64="$REPO/badlibs/lib64-libzygisk-20260921-1809-crashing.so"

if [[ -z "${ADB:-}" ]]; then
    if ss -H -tln 2>/dev/null | grep -q ':15037'; then
        ADB="env ADB_SERVER_SOCKET=tcp:localhost:15037 adb"
    else
        ADB="adb"
    fi
fi

say()  { printf '%s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }
die()  { local code="$1"; shift; printf 'ERROR: %s\n' "$*" >&2; exit "$code"; }

# ---------------------------------------------------------------------------
# Ladder definition. F1..F5 are named in b2697c7's message; F2 (remove rz_dbg/
# rz_ping instrumentation) and F5 (fd_sanitize parity doc) are inert for the
# crash, so the bisectable units are F4, F3, F1 - the ladder order.
# ---------------------------------------------------------------------------
RUNG_ORDER=(all-on f4off f4f3off f4f3f1off control-crash)
declare -A RUNG_PATCHES=(
    [all-on]="f4-enable"
    [f4off]=""
    [f4f3off]="f3-disable"
    [f4f3f1off]="f3-disable f1-disable"
    [control-crash]=""
)
declare -A RUNG_DESC=(
    [all-on]="F1+F3+F4 active (F4 restored: pre-bisect candidate)"
    [f4off]="F4 off, F3+F1 on (== tree as committed; NEGATIVE CONTROL)"
    [f4f3off]="F4+F3 off, F1 on"
    [f4f3f1off]="F4+F3+F1 off (pre-F1/F3/F4 shape; 18:45-stable equivalent)"
    [control-crash]="POSITIVE CONTROL: badlibs 18:09 crashing 64-bit lib"
)
declare -A RUNG_EXPECT_HARD=(
    [all-on]="64:CRASHED"
    [control-crash]="64:CRASHED"
)
declare -A RUNG_EXPECT_SOFT=(
    [f4off]="64:INJECTED_NO_HOOKS"
)
declare -A RUNG_PREDICT=(
    [all-on]="64:CRASHED"
    [f4off]="64:CRASHED if F4 is not the cause"
    [f4f3off]="64:CRASHED if F1 is the cause"
    [f4f3f1off]="64:OK (stable shape)"
    [control-crash]="64:CRASHED (stack corruption)"
)
declare -A RUNG_ALIAS=(
    [tree]=f4off [base]=f4off [neg]=f4off [negcontrol]=f4off
    [control]=control-crash [pos]=control-crash [poscontrol]=control-crash
)
ALL_ABIS=(64 32)
declare -A VERDICT_ABI=() VERDICT_PID=() VERDICT_TAG=() VERDICT_SHA=()

resolve_rung() {
    local r="${1:-}"
    [[ -n "$r" ]] || die 2 "missing rung (see: bisect_ladder.sh rungs)"
    r="${RUNG_ALIAS[$r]:-$r}"
    [[ -n "${RUNG_DESC[$r]:-}" ]] || die 2 "unknown rung '$1' (known: ${RUNG_ORDER[*]}; aliases: tree base neg control pos)"
    printf '%s' "$r"
}

# ---------------------------------------------------------------------------
# adb plumbing: every call carries a timeout; missing device = one clear error
# ---------------------------------------------------------------------------
RC_TIMEOUT=0
run_adb() {
    timeout "$ADB_TIMEOUT" $ADB "$@" 2>&1
    local rc=$?
    [[ $rc -eq 124 ]] && return 124
    return $rc
}

require_tools() {
    command -v timeout  >/dev/null || die 2 "timeout(1) not found"
    command -v sha256sum >/dev/null || die 2 "sha256sum not found"
    command -v python3  >/dev/null || die 2 "python3 not found (patch applier)"
    local bin="${ADB##* }"
    command -v "$bin" >/dev/null || die 2 "adb not found (tried '$bin'); set ADB=<cmd>"
}

probe_device() {
    require_tools
    local state rc
    state="$(run_adb get-state)"; rc=$?
    if [[ $rc -eq 124 ]]; then
        die 2 "adb timed out after ${ADB_TIMEOUT}s (ADB='$ADB'); no device — nothing was staged"
    fi
    if [[ $rc -ne 0 || "$state" != *device* ]]; then
        die 2 "no adb device: get-state -> '${state:-<empty>}' (rc=$rc, ADB='$ADB'); connect the device or start the localhost:15037 tunnel — nothing was staged"
    fi
}

# ---------------------------------------------------------------------------
# scratch tree / patch application
# ---------------------------------------------------------------------------
scratch_prepare() {
    mkdir -p "$RESULTS" "$PATCHES"
    if [[ ! -f "$SCRATCH/Cargo.toml" ]]; then
        say "== creating scratch tree (rsync; target/, .git/, diag/ excluded) =="
    fi
    # Refresh from the real tree so a rung is built from the *current* sources.
    # target/ is excluded, so the scratch's warm build cache survives.
    rsync -a --exclude '.git/' --exclude 'target/' --exclude 'build/' \
          --exclude 'diag/' --exclude 'webroot/' "$REPO/" "$SCRATCH/" \
        || die 2 "rsync $REPO -> $SCRATCH failed"
}

src_digest() {
    ( cd "$SCRATCH" 2>/dev/null && find crates/loader -type f -print0 | sort -z \
        | xargs -0 sha256sum | sha256sum | awk '{print $1}' ) 2>/dev/null || echo -
}

dc5()       { head -c 5 "$1" | od -An -tu1 | awk '{print $5}'; }
sha256_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }
short()     { printf '%s' "${1:0:16}"; }

write_patches() {
    mkdir -p "$PATCHES"

    cat >"$PATCHES/f4-enable.txt" <<'PATCH'
REPL
FILE crates/loader/src/fork_hooks.rs
OLD
        // BISECT-EXPERIMENT: F4 neutered — no counter tracking.
        LoaderGuard
END-OLD
NEW
        // BISECT-RUNG(F4 on): counter tracking restored (the F4 design).
        IN_LOADER.fetch_add(1, Ordering::Relaxed);
        LoaderGuard
END-NEW
REPL
FILE crates/loader/src/fork_hooks.rs
OLD
        // BISECT-EXPERIMENT: F4 neutered.
END-OLD
NEW
        IN_LOADER.fetch_sub(1, Ordering::Relaxed);
END-NEW
REPL
FILE crates/loader/src/fork_hooks.rs
OLD
        // BISECT-EXPERIMENT: gate disabled — always take the munmap path.
        if false {
            if IN_LOADER.load(Ordering::Relaxed) != 1 {
                dlogw!(
                    "loader code in flight on another thread — keeping libzygisk.so mapped"
                );
                UNLOADING.store(false, Ordering::Relaxed);
                crate::context::ENABLE_UNLOADER.store(false, Ordering::Relaxed);
                return res;
            }
        }
END-OLD
NEW
        // BISECT-RUNG(F4 on): quiescence gate active again (F4 design).
        if IN_LOADER.load(Ordering::Relaxed) != 1 {
            dlogw!(
                "loader code in flight on another thread — keeping libzygisk.so mapped"
            );
            UNLOADING.store(false, Ordering::Relaxed);
            crate::context::ENABLE_UNLOADER.store(false, Ordering::Relaxed);
            return res;
        }
END-NEW
PATCH

    cat >"$PATCHES/f3-disable.txt" <<'PATCH'
REPL
FILE crates/loader/src/load_modules.rs
OLD
fn exception_pending(env: *mut jni::sys::JNIEnv) -> bool {
    let Ok(env) = (unsafe { JNIEnv::from_raw(env) }) else {
END-OLD
NEW
#[allow(unreachable_code)] // BISECT-RUNG(F3 off)
fn exception_pending(env: *mut jni::sys::JNIEnv) -> bool {
    // BISECT-RUNG(F3 off): the C reference never inspects pending exceptions.
    let _ = env;
    return false;
    let Ok(env) = (unsafe { JNIEnv::from_raw(env) }) else {
END-NEW
REPL
FILE crates/loader/src/load_modules.rs
OLD
fn check_module_exception(
    env: *mut jni::sys::JNIEnv,
    module_idx: usize,
    stage: &str,
    pending_before: bool,
) {
END-OLD
NEW
#[allow(unreachable_code)] // BISECT-RUNG(F3 off)
fn check_module_exception(
    env: *mut jni::sys::JNIEnv,
    module_idx: usize,
    stage: &str,
    pending_before: bool,
) {
    // BISECT-RUNG(F3 off): the C reference never inspects pending exceptions.
    let _ = (env, module_idx, stage, pending_before);
    return;
END-NEW
PATCH

    # F1 off: DERIVED rung. F1 replaced a TLS re-entrancy bypass + lock-free
    # table access; the pre-F1 source is not in git (b2697c7 introduced the
    # whole loader crate), so this re-creates the removed shape: a thread-local
    # bypass that makes the module-table accessors skip their lock while a
    # callback pass is live, so module re-entry inside a pass is unguarded.
    cat >"$PATCHES/f1-disable.txt" <<'PATCH'
REPL
FILE crates/loader/src/context.rs
OLD
static ZYGISK_MODULES: ModuleTable = ModuleTable {
    lock: Mutex::new(()),
    data: std::cell::UnsafeCell::new(None),
};
END-OLD
NEW
static ZYGISK_MODULES: ModuleTable = ModuleTable {
    lock: Mutex::new(()),
    data: std::cell::UnsafeCell::new(None),
};

// BISECT-RUNG(F1 off): the pre-F1 re-entrancy bypass that F1 removed. While a
// callback pass is live the accessors below skip the table lock, so a module
// re-entering the loader from inside a callback is unguarded (DERIVED repro).
thread_local! {
    static MODULE_TABLE_BYPASS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// BISECT-RUNG(F1 off): arm/disarm the pre-F1 module-table re-entrancy bypass.
pub fn bisect_set_module_table_bypass(on: bool) {
    MODULE_TABLE_BYPASS.with(|b| b.set(on));
}

#[inline]
fn module_table_bypass() -> bool {
    MODULE_TABLE_BYPASS.with(|b| b.get())
}
END-NEW
REPL
FILE crates/loader/src/context.rs
OLD
pub fn module_snapshot() -> ModuleSnapshot {
    let _guard = lock_ok(&ZYGISK_MODULES.lock);
END-OLD
NEW
pub fn module_snapshot() -> ModuleSnapshot {
    // BISECT-RUNG(F1 off): skip the lock while a callback pass is live.
    let _guard = (!module_table_bypass()).then(|| lock_ok(&ZYGISK_MODULES.lock));
END-NEW
REPL
FILE crates/loader/src/context.rs
OLD
) -> Option<R> {
    let _guard = lock_ok(&ZYGISK_MODULES.lock);
END-OLD
NEW
) -> Option<R> {
    // BISECT-RUNG(F1 off): skip the lock while a callback pass is live.
    let _guard = (!module_table_bypass()).then(|| lock_ok(&ZYGISK_MODULES.lock));
END-NEW
REPL
FILE crates/loader/src/context.rs
OLD
pub fn with_module_table<R>(f: impl FnOnce(&mut Vec<crate::abi::ReZygiskModule>) -> R) -> R {
    let _guard = lock_ok(&ZYGISK_MODULES.lock);
END-OLD
NEW
pub fn with_module_table<R>(f: impl FnOnce(&mut Vec<crate::abi::ReZygiskModule>) -> R) -> R {
    // BISECT-RUNG(F1 off): skip the lock while a callback pass is live.
    let _guard = (!module_table_bypass()).then(|| lock_ok(&ZYGISK_MODULES.lock));
END-NEW
REPL
FILE crates/loader/src/load_modules.rs
OLD
    // Snapshot (base, len) and release the table lock BEFORE any module code
    // runs: module entries re-enter the loader (`register_module`) and must
    // be able to take the lock (audit F1). All element access below is
    // through raw pointers — no reference into the table is alive across a
    // callback.
    let modules = module_snapshot();
END-OLD
NEW
    // BISECT-RUNG(F1 off): pre-F1 shape — arm the bypass for the whole pass.
    crate::context::bisect_set_module_table_bypass(true);
    let modules = module_snapshot();
END-NEW
REPL
FILE crates/loader/src/load_modules.rs
OLD
            check_module_exception(ctx.env, i, "pre_server_specialize", pending_before);
        }
    }
}
END-OLD
NEW
            check_module_exception(ctx.env, i, "pre_server_specialize", pending_before);
        }
    }
    // BISECT-RUNG(F1 off): disarm the bypass after the pass.
    crate::context::bisect_set_module_table_bypass(false);
}
END-NEW
REPL
FILE crates/loader/src/load_modules.rs
OLD
    // Same snapshot discipline as rz_run_modules_pre: the lock is released
    // before the first callback and never re-taken during the loop.
    let modules = module_snapshot();
END-OLD
NEW
    // BISECT-RUNG(F1 off): pre-F1 shape — arm the bypass for the whole pass.
    crate::context::bisect_set_module_table_bypass(true);
    let modules = module_snapshot();
END-NEW
REPL
FILE crates/loader/src/load_modules.rs
OLD
    if total_modules > 0 {
        logd!(
            TAG,
            "Modules unloaded: {}/{}",
            modules_unloaded,
            total_modules
        );
    }
}
END-OLD
NEW
    // BISECT-RUNG(F1 off): disarm the bypass after the pass.
    crate::context::bisect_set_module_table_bypass(false);

    if total_modules > 0 {
        logd!(
            TAG,
            "Modules unloaded: {}/{}",
            modules_unloaded,
            total_modules
        );
    }
}
END-NEW
PATCH
}

# Exact-string applier. argv: <patch-file> <root> [check]
apply_patch_file() {
    python3 - "$1" "$2" "${3:-apply}" "$$" <<'PY'
import pathlib, sys

patch = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
mode = sys.argv[3]
want_write = mode != "check"

repls, cur, field = [], None, None
for raw in patch.read_text(encoding="utf-8").splitlines(True):
    line = raw.rstrip("\n")
    if field is not None:                       # inside OLD/NEW: verbatim
        cur[field].append(raw if raw.endswith("\n") else raw + "\n")
        if line == ("END-OLD" if field == "old" else "END-NEW"):
            cur[field].pop()
            if field == "new":
                repls.append(cur)
            field = None
        continue
    if line == "REPL":
        cur = {"file": None, "old": [], "new": []}
    elif line.startswith("FILE "):
        if cur is None:
            raise SystemExit(f"{patch.name}: FILE before REPL")
        cur["file"] = line[5:].strip()
    elif line in ("OLD", "NEW"):
        field = "old" if line == "OLD" else "new"
    elif line.strip():
        raise SystemExit(f"{patch.name}: unexpected directive {line!r}")

if not repls:
    raise SystemExit(f"{patch.name}: no REPL blocks")

bad = 0
for i, r in enumerate(repls, 1):
    p = root / r["file"]
    if not p.is_file():
        print(f"    REFUSED {r['file']}: not found under {root}")
        bad = 1
        continue
    src = p.read_text(encoding="utf-8")
    old, new = "".join(r["old"]), "".join(r["new"])
    n = src.count(old)
    if n != 1:
        print(f"    REFUSED {r['file']} anchor {i}: {n} matches (need exactly 1) — patch spec is stale for this tree; re-derive the rung (show <rung> prints every replacement)")
        bad = 1
        continue
    if want_write:
        p.write_text(src.replace(old, new, 1), encoding="utf-8")
    print(f"    {'applied' if want_write else 'anchor ok'} {r['file']} #{i}")
sys.exit(bad)
PY
}

verify_rung_state() {
    local rung="$1" f ldr="$SCRATCH/crates/loader/src" bad=0
    if [[ "$rung" == "all-on" ]]; then
        grep -q 'IN_LOADER.fetch_add(1, Ordering::Relaxed);' "$ldr/fork_hooks.rs" || { printf 'ERROR: F4 fetch_add missing\n' >&2; bad=1; }
        grep -q 'if false {' "$ldr/fork_hooks.rs" && { printf 'ERROR: F4 gate still neutered\n' >&2; bad=1; }
    else
        grep -q 'if false {' "$ldr/fork_hooks.rs" || { printf 'ERROR: F4 gate not neutered (expected if false)\n' >&2; bad=1; }
        grep -q 'BISECT-EXPERIMENT: F4 neutered' "$ldr/fork_hooks.rs" || { printf 'ERROR: F4 neuter marker missing\n' >&2; bad=1; }
    fi
    if [[ " ${RUNG_PATCHES[$rung]} " == *" f3-disable "* ]]; then
        f=$(grep -c 'BISECT-RUNG(F3 off)' "$ldr/load_modules.rs")
        [[ "$f" == "2" ]] || { printf 'ERROR: F3-off markers %s (want 2)\n' "$f" >&2; bad=1; }
    else
        grep -q 'BISECT-RUNG(F3 off)' "$ldr/load_modules.rs" && { printf 'ERROR: unexpected F3-off marker\n' >&2; bad=1; }
    fi
    if [[ " ${RUNG_PATCHES[$rung]} " == *" f1-disable "* ]]; then
        f=$(grep -c 'BISECT-RUNG(F1 off)' "$ldr/context.rs")
        [[ "$f" == "4" ]] || { printf 'ERROR: F1-off context markers %s (want 4)\n' "$f" >&2; bad=1; }
        f=$(grep -c 'BISECT-RUNG(F1 off)' "$ldr/load_modules.rs")
        [[ "$f" == "4" ]] || { printf 'ERROR: F1-off load_modules markers %s (want 4)\n' "$f" >&2; bad=1; }
    else
        grep -rq 'BISECT-RUNG(F1 off)' "$ldr" && { printf 'ERROR: unexpected F1-off marker\n' >&2; bad=1; }
    fi
    [[ "$bad" == "0" ]] || die 2 "REFUSED: scratch tree is not rung '$rung' (marker check failed)"
    say "  rung state verified: $rung (F4=${rung:+}$( [[ " ${RUNG_PATCHES[$rung]} " == *" f4-enable "* ]] && echo on || echo off ))"
}

feature_preflight() {
    local fargs=()
    [[ -n "$FEATURES" ]] && fargs=(--features "$FEATURES")
    ( cd "$SCRATCH" && timeout "$BUILD_TIMEOUT" cargo tree -p rz-loader -p rz-ptracer -p rezygiskd \
        "${fargs[@]+"${fargs[@]}"}" -e features --target "$T32" ) >/dev/null 2>"$RESULTS/.features.err"
    local rc=$?
    if [[ $rc -eq 124 ]]; then die 4 "cargo feature pre-flight timed out"; fi
    if [[ $rc -ne 0 ]]; then
        err "RZ_FEATURES='$FEATURES' is not a valid feature set for rz-loader/rz-ptracer/rezygiskd:"
        sed 's/^/    /' "$RESULTS/.features.err" >&2
        say "hint: the only feature in the tree is rz-common's 'stealth-tag'; pass it qualified" >&2
        say "      (RZ_FEATURES=rz-common/stealth-tag) — rz-loader declares no features of its own," >&2
        say "      so the bare 'stealth-tag' form fails." >&2
        exit 2
    fi
}

prepare_rung() {
    local rung="$1" p
    scratch_prepare
    feature_preflight
    write_patches
    say "== rung $rung: ${RUNG_DESC[$rung]} (features: ${FEATURES:-<none>}) =="
    for p in ${RUNG_PATCHES[$rung]}; do
        say "  applying $p"
        apply_patch_file "$PATCHES/$p.txt" "$SCRATCH" apply || die 2 "patch $p refused for rung $rung"
    done
    verify_rung_state "$rung"
}

build_rung() {
    local rung="$1" t0 t1
    prepare_rung "$rung"
    t0="$(date +%s)"
    say "== build (scratch, features: ${FEATURES:-<none>}) =="
    ( cd "$SCRATCH" && RZ_STAGE=loaders RZ_FEATURES="$FEATURES" \
        timeout "$BUILD_TIMEOUT" ./scripts/verify_deploy.sh build )
    local rc=$?
    if [[ $rc -eq 124 ]]; then die 4 "build timed out after ${BUILD_TIMEOUT}s"; fi
    [[ $rc -eq 0 ]] || die 1 "build failed for rung $rung"
    t1="$(date +%s)"

    local a64="$SCRATCH/target/$T64/release/libzygisk.so" a32="$SCRATCH/target/$T32/release/libzygisk.so"
    [[ -f "$a64" && -f "$a32" ]] || die 1 "build did not produce both loaders"
    local m64 m32 c64 c32
    m64="$(stat -c %Y "$a64")"; m32="$(stat -c %Y "$a32")"
    if (( m64 < t0 - 5 || m64 > t1 + 5 || m32 < t0 - 5 || m32 > t1 + 5 )); then
        die 3 "REFUSED: an artifact is outside this build window (64=$m64 32=$m32 window=$t0..$t1) — mixed generation"
    fi
    c64="$(dc5 "$a64")"; c32="$(dc5 "$a32")"
    [[ "$c64" == "2" ]] || die 3 "REFUSED: $a64 ELF class $c64 (want 2)"
    [[ "$c32" == "1" ]] || die 3 "REFUSED: $a32 ELF class $c32 (want 1)"
    say "  lib64/libzygisk.so $(sha256_of "$a64") $(stat -c %s "$a64")B class=$c64"
    say "  lib/libzygisk.so   $(sha256_of "$a32") $(stat -c %s "$a32")B class=$c32"
    say "  loader src digest  $(src_digest)"
    tsv_append BUILD "$rung" - BUILT - - - - "features=${FEATURES:-none} src=$(src_digest)"
}

# ---------------------------------------------------------------------------
# stage
# ---------------------------------------------------------------------------
stage_rung() {
    local rung="$1"
    probe_device                      # fail fast: no device => no build, no push
    build_rung "$rung"

    local a64="$SCRATCH/target/$T64/release/libzygisk.so" a32="$SCRATCH/target/$T32/release/libzygisk.so"
    local p64="$a64" p32="$a32"

    if [[ "$rung" == "control-crash" ]]; then
        [[ -f "$BAD64" ]] || die 2 "positive-control fixture missing: $BAD64"
        p64="$BAD64"
        if [[ -n "${RZ_BISECT_32_ARTIFACT:-}" ]]; then
            [[ -f "$RZ_BISECT_32_ARTIFACT" ]] || die 2 "RZ_BISECT_32_ARTIFACT is not a file"
            p32="$RZ_BISECT_32_ARTIFACT"
        fi
        say "== POSITIVE CONTROL: 64-bit slot = $(basename "$BAD64") (known-bad 18:09 build) =="
        if [[ "$p32" == "$a32" ]]; then
            say "  32-bit slot = the current tree build: the repo contains NO 32-bit counterpart"
            say "  of the 18:09 fixture (checked badlibs/, diag/, build/), so the 32-bit verdict is"
            say "  a REFERENCE, not part of the control. Override with RZ_BISECT_32_ARTIFACT=<path>."
        else
            say "  32-bit slot = $p32 (RZ_BISECT_32_ARTIFACT)"
        fi
        cp -f "$BAD64" "$a64" || die 1 "cannot place the control fixture"
    fi

    say "== staging via verify_deploy.sh (RZ_STAGE=loaders) =="
    local out="$RESULTS/.stage.out"
    ( cd "$SCRATCH" && RZ_STAGE=loaders RZ_FEATURES="$FEATURES" \
        timeout "$STAGE_TIMEOUT" ./scripts/verify_deploy.sh stage ) >"$out" 2>&1
    local rc=$?
    if [[ $rc -eq 124 ]]; then sed 's/^/    /' "$out" >&2; die 4 "staging timed out after ${STAGE_TIMEOUT}s"; fi
    if [[ $rc -ne 0 ]]; then sed 's/^/    /' "$out" >&2; die 1 "verify_deploy.sh stage failed for rung $rung"; fi
    grep -E '^  (PASS|FAIL)' "$out" | sed 's/^/  /'
    if grep -qE '^  FAIL' "$out"; then
        die 3 "REFUSED: verify_deploy.sh reported FAIL — device hashes/ELF classes are not the local rung artifacts"
    fi

    # Independent anti-mix check: each slot must hold exactly the intended file.
    local d64 d32 w64 w32
    d64="$(device_sha lib64/libzygisk.so)"; d32="$(device_sha lib/libzygisk.so)"
    w64="$(sha256_of "$p64")"; w32="$(sha256_of "$p32")"
    [[ -n "$d64" && -n "$d32" ]] || die 3 "REFUSED: cannot read staged hashes from the device (su/sha256sum) — generation unverified"
    if [[ "$d64" != "$w64" || "$d32" != "$w32" ]]; then
        err "device lib64/libzygisk.so = $d64 (wanted $w64)"
        err "device lib/libzygisk.so   = $d32 (wanted $w32)"
        die 3 "REFUSED: staged generation is MIXED or STALE (device != intended rung artifact)"
    fi
    [[ "$d64" != "$d32" ]] || die 3 "REFUSED: both slots hold the same file — mixed generation"

    cat >"$STATE" <<EOF
RUNG=$rung
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
FEATURES=${FEATURES:-}
GIT_HEAD=$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)
SRC_DIGEST=$(src_digest)
PATH64=$p64
PATH32=$p32
SHA64=$w64
SHA32=$w32
EOF
    say "== staged (record: $STATE) =="
    say "  lib64/libzygisk.so $(short "$w64")…  <- $p64"
    say "  lib/libzygisk.so   $(short "$w32")…  <- $p32"
    say "  features: ${FEATURES:-<none>}   rung: $rung"
    tsv_append STAGED "$rung" - STAGED - - - "$w64/$w32" "features=${FEATURES:-none}"
    say ""
    say "NEXT: reboot, then: scripts/bisect_ladder.sh assert $rung"
}

device_sha() { run_adb shell "su -c 'sha256sum $MOD/$1 2>/dev/null'" | awk '{print $1}'; }
device_size() { run_adb shell "su -c 'stat -c%s $MOD/$1 2>/dev/null'" | tr -dc '0-9'; }

# ---------------------------------------------------------------------------
# probe — read-only: what generation is live on the device right now?
# ---------------------------------------------------------------------------
cmd_probe() {
    probe_device
    say "== device (read-only; nothing staged, nothing rebooted) =="
    local abi f sha size
    for abi in "${ALL_ABIS[@]}"; do
        if [[ "$abi" == "64" ]]; then f=lib64/libzygisk.so; else f=lib/libzygisk.so; fi
        sha="$(device_sha "$f")"; size="$(device_size "$f")"
        say "  $f ${sha:-<missing>} ${size:-?}B"
        printf '%s\n' "${sha:-missing}" >"$RESULTS/.probe.sha$abi"
    done

    local genjson
    genjson="$(run_adb shell "su -c 'cat $MOD/.generation.json'" 2>/dev/null)"
    if [[ -n "$genjson" ]]; then
        say "== deployed generation ($MOD/.generation.json) =="
        local line
        while IFS= read -r line; do say "  $line"; done < <(printf '%s\n' "$genjson" | grep -oE '"(deployment_generation|lib64/libzygisk.so|lib/libzygisk.so|bin/zygisk-ptrace64|bin/zygisk-ptrace32)"[^}]*' | head -8)
    fi

    # MIXED detection for the two loader slots: their recorded generations must agree.
    local g64 g32
    g64="$(printf '%s\n' "$genjson" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("components",{}).get("lib64/libzygisk.so",{}).get("generation",""))' 2>/dev/null)"
    g32="$(printf '%s\n' "$genjson" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("components",{}).get("lib/libzygisk.so",{}).get("generation",""))' 2>/dev/null)"
    if [[ -n "$g64$g32" ]]; then
        if [[ "$g64" == "$g32" ]]; then say "  loader generation: both ABIs = $g64 (not mixed)"
        else say "  WARNING: MIXED loader generation: lib64='$g64' lib='$g32' — stage a rung before asserting"; fi
    fi
    if [[ -f "$STATE" ]]; then
        local sr s64 s32
        sr="$(awk -F= '$1=="RUNG"{print $2}' "$STATE")"
        s64="$(awk -F= '$1=="SHA64"{print $2}' "$STATE")"; s32="$(awk -F= '$1=="SHA32"{print $2}' "$STATE")"
        if [[ "$(cat "$RESULTS/.probe.sha64")" == "$s64" && "$(cat "$RESULTS/.probe.sha32")" == "$s32" ]]; then
            say "  matches the last staged rung '$sr' -> 'assert $sr' is valid now"
        else
            say "  does NOT match the last staged rung '$sr' ($(short "$s64")…/$(short "$s32")…) -> re-stage before asserting"
        fi
    fi
    # Which local build does the device hold? (identifies stale vs current)
    local a
    for a in "$REPO/target/$T64/release/libzygisk.so:64" "$REPO/target/$T32/release/libzygisk.so:32" \
             "$SCRATCH/target/$T64/release/libzygisk.so:64" "$SCRATCH/target/$T32/release/libzygisk.so:32"; do
        local p="${a%:*}" ab="${a##*:}"
        [[ -f "$p" ]] || continue
        if [[ "$(sha256_of "$p")" == "$(cat "$RESULTS/.probe.sha$ab")" ]]; then
            say "  device lib$ab loader == $p"
        fi
    done
    rm -f "$RESULTS/.probe.sha64" "$RESULTS/.probe.sha32"
}

# ---------------------------------------------------------------------------
# log classification
# ---------------------------------------------------------------------------
BOOT_ANCHOR=""

# Current-boot window. The snapshot is append-only across boots, so the stale
# lines of earlier boots must be excluded; every candidate below is logged once
# per boot and before the zygote handoffs, so the EARLIEST of their last
# occurrences is the current boot's start (a superset of it). Note the
# "--------- beginning of <buffer>" markers are per logcat BUFFER (main, events,
# system, radio), not per boot, so they are only a last-resort fallback.
# RZ_CLASSIFY_ALL=1 disables the window (post-mortem forensics on a dump).
boot_window() {
    local log="$1" cands=() n
    if [[ "${RZ_CLASSIFY_ALL:-0}" == "1" ]]; then
        BOOT_ANCHOR="whole file (RZ_CLASSIFY_ALL=1)"
        cat "$log"; return
    fi
    local pat
    for pat in 'exec /data/adb/modules/rezygisk/post-fs-data.sh' 'Service online' \
               'ReZygisk 1.0.0' 'deployed monitor:'; do
        n="$(grep -anF -- "$pat" "$log" | tail -1 | cut -d: -f1)"
        [[ -n "$n" ]] && cands+=("$n")
    done
    if (( ${#cands[@]} > 0 )); then
        n="$(printf '%s\n' "${cands[@]}" | sort -n | head -1)"
        BOOT_ANCHOR="line $n (earliest last-once-per-boot marker)"
        tail -n +"$n" "$log"
        return
    fi
    n="$(grep -an -- '--------- beginning of' "$log" | tail -1 | cut -d: -f1)"
    if [[ -n "$n" ]]; then
        BOOT_ANCHOR="line $n (last 'beginning of' buffer marker; no per-boot marker found)"
        tail -n +"$n" "$log"
        return
    fi
    BOOT_ANCHOR="whole file (no boot marker found)"
    cat "$log"
}

# "<tag>|<line>" for lines of <pid>; handles logcat threadtime and the
# "PID: L tag: msg" dump form, then falls back to a loose pid grep.
pid_lines() {
    local out
    out="$(awk -v pid="$2" '
        { tag = ""
          if ($3 == pid) tag = $6
          else if ($1 == pid ":") tag = $3
          if (tag != "") { sub(/:$/, "", tag); print tag "|" $0 } }' "$1")"
    if [[ -z "$out" ]]; then
        out="$(grep -a "\b$2\b" "$1" | sed 's/^/|/')"
    fi
    printf '%s\n' "$out"
}

count_match() { printf '%s\n' "$1" | grep -cF -- "$2" 2>/dev/null; }

handoff_pids() { # <win> <abi>
    grep -aoE "handoff tracer: pid=[0-9]+ program=/system/bin/app_process$2" "$1" \
        | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u | tr '\n' ' '
}

crashed_pids() { # <win> — zygote pids named in tombstone bodies / libc aborts
    { grep -aE '>>> zygote(64|32) <<<' "$1" | grep -aoE 'pid: ?[0-9]+' | grep -oE '[0-9]+'
      grep -a 'Fatal signal' "$1" | grep -aoE 'pid [0-9]+ \(' | grep -oE '[0-9]+'
      grep -aE 'Cmdline: zygote(64|32)' "$1" | grep -aoE 'pid: ?[0-9]+' | grep -oE '[0-9]+'
    } 2>/dev/null | sort -u | tr '\n' ' '
}

decide_verdict() { # injected hooking done hook_fail elf_fail crash tracer_fail ack have_handoff -> "VERDICT:reason"
    local injected="$1" hooking="$2" done="$3" hook_fail="$4" elf_fail="$5" crash="$6"
    local tracer_fail="$7" ack="$8" have_handoff="$9"
    if [[ -n "$crash" ]]; then
        printf 'CRASHED:%s' "$crash"; return
    fi
    if (( injected >= 1 )); then
        if (( done >= 1 && hook_fail == 0 && elf_fail == 0 )); then printf 'OK:HOOKS_REGISTERED'; return; fi
        if (( hook_fail >= 1 )); then printf 'INJECTED_NO_HOOKS:HOOK_REGISTER_FAILED'; return; fi
        if (( elf_fail >= 1 )); then printf 'INJECTED_NO_HOOKS:ELF_IMAGE_FAILED'; return; fi
        printf 'UNKNOWN:NO_COMPLETION'; return
    fi
    if (( hooking >= 1 )); then printf 'UNKNOWN:NO_INJECTION_LINE_BUT_HOOKING'; return; fi
    # NOT_INJECTED needs positive evidence: the tracer saying it failed, or a
    # handoff for this ABI with no injection at all. Missing evidence in a
    # partial/corrupt window stays UNKNOWN (absence of evidence is not evidence).
    if (( tracer_fail >= 1 )); then printf 'NOT_INJECTED:TRACER_INJECT_FAILED'; return; fi
    if (( ack >= 1 )); then printf 'UNKNOWN:INJECT_ACK_BUT_NO_LOADER_LINE'; return; fi
    if (( have_handoff == 1 )); then printf 'NOT_INJECTED:NO_INJECTION_LINE'; return; fi
    printf 'UNKNOWN:NO_HANDOFF_OR_EVIDENCE'
}

# Monitor/tracer lines for one ABI: they carry the monitor's pid, not the
# zygote's, so they are matched by message text or by the abi-suffixed tag
# (zygisk-ptrace64 / zygiskd64 / zygiskd / core ...).
abi_aux_lines() { # <win> <abi> <pid>
    { grep -aF "handoff tracer: pid=$3 " "$1"
      grep -aF "start tracing $3 (tracer " "$1"
      grep -aF "tracer: injection into $3 " "$1"
      grep -aF "Received Zygote$2 injected command" "$1"
      grep -aE "(zygiskd|zygisk-ptrace)$2: Service online" "$1"
    } 2>/dev/null
}

verdict_rank() {
    case "$1" in
        CRASHED) echo 4 ;; INJECTED_NO_HOOKS) echo 3 ;; NOT_INJECTED) echo 2 ;; UNKNOWN) echo 1 ;; OK) echo 0 ;; *) echo 1 ;;
    esac
}

classify_log() { # <log> <rung-label>
    local log="$1" want_rung="${2:--}" win
    win="$(mktemp)"
    boot_window "$log" >"$win"
    say "== classify: window = $BOOT_ANCHOR; $(wc -l <"$win") lines; log = $log =="

    local pids64 pids32 crash_pids
    pids64="$(handoff_pids "$win" 64)"
    pids32="$(handoff_pids "$win" 32)"
    crash_pids="$(crashed_pids "$win")"
    local coarse=0
    [[ -z "$pids64$pids32" ]] && coarse=1

    local abi
    local -A chosen_counts=()
    for abi in "${ALL_ABIS[@]}"; do
        local pids; [[ "$abi" == "64" ]] && pids="$pids64" || pids="$pids32"
        [[ -n "$pids" ]] || pids="none"
        local worst="UNKNOWN" worst_reason="NO_HANDOFF" worst_pid="-" worst_ev="" worst_tag="?" report=""
        local pid
        for pid in $pids; do
            local L=""
            if [[ "$coarse" == "1" ]]; then
                L="$(grep -aE 'ReZygisk library injected, version|start plt hooking|Failed to initialize ELF image|Failed to find ELF image|Failed to register plt_hook|Zygisk library execution done|Registered plt_hook' "$win" | sed 's/^/|/')"
            else
                L="$(pid_lines "$win" "$pid")"
            fi
            local injected hooking done elf_fail hook_fail hook_ok tracer_ok tracer_fail ack aux
            injected=$(count_match "$L" 'ReZygisk library injected, version')
            hooking=$(count_match "$L" 'start plt hooking')
            done=$(count_match "$L" 'Zygisk library execution done')
            elf_fail=$(count_match "$L" 'Failed to initialize ELF image for library')
            hook_fail=$(count_match "$L" 'Failed to register plt_hook "')
            hook_ok=$(count_match "$L" 'Registered plt_hook for symbol')
            aux="$(abi_aux_lines "$win" "$abi" "$pid")"
            tracer_ok=$(count_match "$aux" "tracer: injection into $pid succeeded")
            tracer_fail=$(count_match "$aux" "tracer: injection into $pid failed")
            ack=$(count_match "$aux" "Received Zygote$abi injected command")
            if [[ "$coarse" == "1" ]]; then
                tracer_ok=$(count_match "$win" 'tracer: injection into .* succeeded')
                tracer_fail=$(count_match "$win" 'tracer: injection into .* failed')
                ack=$(count_match "$win" "Received Zygote$abi injected command")
            fi
            local tag; tag="$(printf '%s\n' "$L" | grep -a 'library injected' | head -1 | cut -d'|' -f1)"; tag="${tag:-?}"

            local crash_hit=""
            local p
            for p in $crash_pids; do [[ "$p" == "$pid" ]] && crash_hit="TOMBSTONE_OR_FATAL_PID_$p"; done
            if [[ -z "$crash_hit" && "$coarse" == "1" ]]; then
                grep -aqE ">>> zygote$abi <<<|Cmdline: zygote$abi" "$win" && crash_hit="TOMBSTONE_NAME_zygote$abi"
            fi

            local dec v reason have_handoff=0
            [[ "$pid" != "none" ]] && have_handoff=1
            dec="$(decide_verdict "$injected" "$hooking" "$done" "$hook_fail" "$elf_fail" "$crash_hit" "$tracer_fail" "$ack" "$have_handoff")"
            v="${dec%%:*}"; reason="${dec#*:}"

            report="$report
  abi=$abi pid=$pid tag=$tag injected=$injected hooking=$hooking done=$done hook_ok=$hook_ok hook_fail=$hook_fail elf_fail=$elf_fail tracer_ok=$tracer_ok tracer_fail=$tracer_fail ack=$ack crash=${crash_hit:-0}"

            if [[ "$worst_pid" == "-" ]] || (( $(verdict_rank "$v") > $(verdict_rank "$worst") )); then
                worst="$v"; worst_reason="$reason"; worst_pid="$pid"; worst_tag="$tag"
                worst_ev="$(printf '%s\n' "$L" | grep -aE 'ReZygisk library injected, version|start plt hooking|Failed to initialize ELF image|Failed to find ELF image|Failed to register plt_hook|Zygisk library execution done|Registered plt_hook' | head -20)"
                worst_ev="$worst_ev
$(printf '%s\n' "$aux" | grep -aE "handoff tracer: pid=$pid|start tracing $pid|tracer: injection into $pid|Received Zygote$abi injected command" | head -4)"
                if [[ -n "$crash_hit" ]]; then
                    worst_ev="$worst_ev
$(grep -aE 'Fatal signal|stack corruption detected|Abort message:|>>> zygote(64|32) <<<' "$win" | grep -aE "pid[ :]+$pid|zygote$abi" | head -6)"
                fi
            fi
            chosen_counts["$abi:$pid"]="$report"
        done
        local cout=""
        [[ "$worst_pid" != "-" ]] && cout="${chosen_counts[$abi:$worst_pid]:-}"
        [[ -n "$cout" ]] || cout="
  abi=$abi pid=none: no handoff line in this window"
        printf '%s\n' "$cout" | sed '/^$/d' | sed 's/^/  counts:/'
        VERDICT_ABI[$abi]="$worst"; VERDICT_PID[$abi]="$worst_pid"; VERDICT_TAG[$abi]="$worst_tag"
        local ssha; ssha="$(staged_sha_for "$abi")"
        VERDICT_SHA[$abi]="$ssha"
        say "VERDICT rung=$want_rung abi=$abi verdict=$worst pid=$worst_pid reason=$worst_reason tag=$worst_tag sha256=${ssha:--}"
        printf '%s\n' "$worst_ev" | sed '/^$/d' | sed "s/^/  evidence[$abi]: /"
    done

    if [[ -n "${VERDICT_TAG[64]:-}" && -n "${VERDICT_TAG[32]:-}" \
          && "${VERDICT_TAG[64]}" != "?" && "${VERDICT_TAG[32]}" != "?" \
          && "${VERDICT_TAG[64]}" != "${VERDICT_TAG[32]}" ]]; then
        say "SKEW abi=64 tag=${VERDICT_TAG[64]} abi=32 tag=${VERDICT_TAG[32]} (per-ABI feature difference: stealth-tag moves the loader tag to 'core')"
    fi
    if [[ "$coarse" == "1" ]]; then
        say "NOTE: no handoff line in this window — verdicts are coarse (both ABIs share the same evidence)."
    fi
    rm -f "$win"
}

staged_sha_for() { # <abi> from the stage record, if any
    [[ -f "$STATE" ]] || { echo -n ""; return; }
    local key=SHA$1
    awk -F= -v k="$key" '$1==k{print $2}' "$STATE"
}

# ---------------------------------------------------------------------------
# assert
# ---------------------------------------------------------------------------
assert_rung() {
    local rung="$1" force="${2:-}"
    local allow_force=0; [[ "$force" == "--force" ]] && allow_force=1
    probe_device

    local d64 d32
    d64="$(device_sha lib64/libzygisk.so)"; d32="$(device_sha lib/libzygisk.so)"
    if [[ -f "$STATE" ]]; then
        local s_rung s_ts s64 s32
        s_rung="$(awk -F= '$1=="RUNG"{print $2}' "$STATE")"
        s_ts="$(awk -F= '$1=="TS"{print $2}' "$STATE")"
        s64="$(awk -F= '$1=="SHA64"{print $2}' "$STATE")"
        s32="$(awk -F= '$1=="SHA32"{print $2}' "$STATE")"
        if [[ "$s_rung" != "$rung" ]]; then
            warn "last staged rung is '$s_rung' ($s_ts), not '$rung'"
            (( allow_force )) || die 3 "REFUSED: assert '$rung' but the device holds rung '$s_rung' — stage '$rung' first (or pass --force)"
        fi
        if [[ "$d64" != "$s64" || "$d32" != "$s32" ]]; then
            warn "device loaders differ from the staged record (device 64=$(short "$d64") 32=$(short "$d32") | record 64=$(short "$s64") 32=$(short "$s32"))"
            (( allow_force )) || die 3 "REFUSED: STALE/MIXED generation on device — stage '$rung' again (or pass --force)"
        fi
        FEATURES="$(awk -F= '$1=="FEATURES"{print $2}' "$STATE")"
    else
        warn "no stage record at $STATE — the device generation is unverified"
        (( allow_force )) || die 3 "REFUSED: assert without a stage record (pass --force to accept)"
    fi

    # Coarse gate via verify_deploy.sh's own assert; reuse its log snapshot.
    local vout="$RESULTS/.assert.out" vrc
    ( cd "$REPO" && RZ_STAGE=loaders timeout "$ASSERT_TIMEOUT" ./scripts/verify_deploy.sh assert ) >"$vout" 2>&1
    vrc=$?
    [[ $vrc -eq 124 ]] && die 4 "verify_deploy.sh assert timed out after ${ASSERT_TIMEOUT}s"
    say "== verify_deploy.sh assert: $(grep -cE '^  PASS' "$vout") pass / $(grep -cE '^  FAIL' "$vout") fail (rc=$vrc) =="
    grep -E '^  FAIL' "$vout" | sed 's/^/  /'

    local log="${RZ_ASSERT_LOG:-}"
    [[ -n "$log" ]] || log="$(sed -n 's/^== assert boot outcome (log: \(.*\)) ==$/\1/p' "$vout" | tail -1)"
    if [[ -z "$log" || ! -f "$log" ]]; then
        log="$RESULTS/logcat.$(date -u +%Y%m%dT%H%M%SZ)"
        say "  (no log path from verify_deploy.sh; taking my own snapshot)"
        if run_adb shell "su -c 'test -f /data/adb/ksu/log/logcat.log'" >/dev/null 2>&1; then
            run_adb shell "su -c 'cat /data/adb/ksu/log/logcat.log'" >"$log"
        else
            run_adb logcat -d -b all >"$log" 2>&1
        fi
    fi
    say "  log: $log"

    local tdir="$RESULTS/tombstones.$(date -u +%Y%m%dT%H%M%SZ)" tlist
    tlist="$(run_adb shell "su -c 'ls -t /data/tombstones 2>/dev/null | head -5'" | tr -d '\r')"
    if [[ -n "$tlist" && "$tlist" != *"No such"* && "$tlist" != *"Permission"* ]]; then
        mkdir -p "$tdir"; local f
        for f in $tlist; do run_adb shell "su -c 'cat /data/tombstones/$f 2>/dev/null'" >"$tdir/$f.txt" 2>/dev/null; done
        say "  tombstones: $(printf '%s ' $tlist)(saved under $tdir)"
        cat "$tdir"/*.txt >>"$log" 2>/dev/null
    else
        say "  tombstones: none readable"
    fi

    classify_log "$log" "$rung"

    local abi v exp result rc=0
    for abi in "${ALL_ABIS[@]}"; do
        v="${VERDICT_ABI[$abi]:-UNKNOWN}"
        exp="${RUNG_EXPECT_HARD[$rung]:-}"; result="no-expectation"
        if [[ "$exp" == "$abi:"* ]]; then
            if [[ "$v" == "${exp#*:}" ]]; then result="MATCH(hard)"; else result="MISMATCH(hard)"; rc=1; fi
        fi
        exp="${RUNG_EXPECT_SOFT[$rung]:-}"
        if [[ "$exp" == "$abi:"* ]]; then
            if [[ "$v" == "${exp#*:}" ]]; then result="MATCH(soft)"
            else result="MISMATCH(soft)"; warn "soft expectation for abi=$abi was ${exp#*:}, got $v (the ELF-image fix may have landed — that is progress, not a harness failure)"
            fi
        fi
        say "EXPECT rung=$rung abi=$abi ${RUNG_EXPECT_HARD[$rung]:-${RUNG_EXPECT_SOFT[$rung]:-ANY}} result=$result"
        tsv_append ASSERT "$rung" "$abi" "$v" \
            "${RUNG_EXPECT_HARD[$rung]:-${RUNG_EXPECT_SOFT[$rung]:-ANY}}" "$result" \
            "${VERDICT_PID[$abi]:--}" "${VERDICT_SHA[$abi]:--}" "log=$log"
    done
    if [[ "$rung" == "control-crash" ]]; then
        if [[ "${VERDICT_ABI[64]}" == "CRASHED" ]]; then
            say "CONTROL PASS: positive control is CRASHED on 64-bit — the harness detects the known-bad lib"
        else
            say "CONTROL FAIL: positive control should be CRASHED on 64-bit, got ${VERDICT_ABI[64]:-UNKNOWN}"
            rc=1
        fi
    fi
    say "results: $TSV"
    return $rc
}

# ---------------------------------------------------------------------------
# results / next
# ---------------------------------------------------------------------------
tsv_append() { # event rung abi verdict expect result pid sha notes
    mkdir -p "$RESULTS"
    if [[ ! -f "$TSV" ]]; then
        printf '%s\n' "event	ts	rung	abi	verdict	expectation	result	pid	staged_sha256	features	git_head	src_digest	notes" >"$TSV"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$2" "$3" "$4" "$5" "$6" "$7" "$8" \
        "${FEATURES:-}" "$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo -)" \
        "$(src_digest)" "$9" >>"$TSV"
}

decision_rule() {
    say "DECISION RULE"
    say "  D0 all-on CRASHED + D1 f4off OK       -> F4 is the cause"
    say "  D1 CRASHED + D2 f4f3off OK            -> F3 is the cause"
    say "  D2 CRASHED + D3 f4f3f1off OK          -> F1 is the cause"
    say "  D3 CRASHED                            -> none of F1/F3/F4 alone; look outside this ladder"
    say "  any rung INJECTED_NO_HOOKS on 64      -> the ELF-image blocker (not a ladder signal)"
    say "  verdict by agreement on BOTH ABIs: 64 is the crashing ABI, 32 is the control"
}

cmd_next() {
    [[ -f "$TSV" ]] || { say "no results yet: 'stage <rung>' then reboot then 'assert <rung>'"; return 0; }
    say "== ladder state ($TSV) =="
    local r v64 v32
    for r in "${RUNG_ORDER[@]}"; do
        v64="$(awk -F'\t' -v r="$r" '$1=="ASSERT" && $3==r && $4=="64"{v=$5} END{print v}' "$TSV")"
        v32="$(awk -F'\t' -v r="$r" '$1=="ASSERT" && $3==r && $4=="32"{v=$5} END{print v}' "$TSV")"
        if [[ -z "$v64$v32" ]]; then printf '  %-14s not run yet\n' "$r"
        else printf '  %-14s 64=%-18s 32=%s\n' "$r" "${v64:-?}" "${v32:-?}"; fi
    done
    say ""
    decision_rule
    say ""
    for r in "${RUNG_ORDER[@]}"; do
        if ! awk -F'\t' -v r="$r" '$1=="ASSERT" && $3==r{f=1} END{exit !f}' "$TSV"; then
            say "NEXT: no verdict for '$r' -> scripts/bisect_ladder.sh stage $r  (then reboot, then assert $r)"
            return 0
        fi
    done
    say "NEXT: all rungs have verdicts — apply the rule above (or re-run a rung after a code change)."
}

# ---------------------------------------------------------------------------
# selftest — prove the harness itself, without a device
# ---------------------------------------------------------------------------
SELFTEST_FAILS=0
st_ok()   { printf '  PASS  %s\n' "$*"; }
st_bad()  { printf '  FAIL  %s\n' "$*"; SELFTEST_FAILS=$((SELFTEST_FAILS + 1)); }
st_skip() { printf '  SKIP  %s\n' "$*"; }

cmd_selftest() {
    local with_build="${1:-}" r p
    say "== selftest: ladder table =="
    for r in "${RUNG_ORDER[@]}"; do
        if [[ -n "${RUNG_DESC[$r]:-}" ]]; then st_ok "rung '$r' = ${RUNG_DESC[$r]}"
        else st_bad "rung '$r' has no description"; fi
    done

    say "== selftest: patch anchors against the pristine tree ($REPO) =="
    write_patches
    for r in "${RUNG_ORDER[@]}"; do
        local bad=0
        for p in ${RUNG_PATCHES[$r]}; do
            apply_patch_file "$PATCHES/$p.txt" "$REPO" check >/dev/null 2>&1 || bad=1
        done
        if (( bad == 0 )); then st_ok "anchors match exactly once: $r"
        else st_bad "anchor mismatch for rung '$r' (inspect: bisect_ladder.sh show $r)"; fi
    done

    say "== selftest: positive control artifact =="
    if [[ ! -f "$BAD64" ]]; then
        st_bad "missing positive control: $BAD64"
    else
        local c; c="$(dc5 "$BAD64")"
        if [[ "$c" == "2" ]]; then st_ok "control 64-bit lib is ELF64, sha256=$(short "$(sha256_of "$BAD64")")"
        else st_bad "control 64-bit lib has ELF class '$c' (want 2 for ELF64): $BAD64"; fi
    fi
    if [[ -n "${RZ_BISECT_32_ARTIFACT:-}" ]]; then
        if [[ ! -f "$RZ_BISECT_32_ARTIFACT" ]]; then st_bad "RZ_BISECT_32_ARTIFACT is not a file: $RZ_BISECT_32_ARTIFACT"
        else
            local c32; c32="$(dc5 "$RZ_BISECT_32_ARTIFACT")"
            if [[ "$c32" == "1" ]]; then st_ok "32-bit control artifact is ELF32"
            else st_bad "32-bit control artifact has ELF class '$c32' (want 1 for ELF32)"; fi
        fi
    else
        st_skip "no 32-bit control artifact found in badlibs/ or diag/ -> control-crash stages the 64-bit slot only (pass RZ_BISECT_32_ARTIFACT=<file> to add one)"
    fi

    say "== selftest: every device call is timeout-guarded (no bare adb) =="
    local bare
    bare="$(sed 's/#.*$//' "$SELF" \
            | grep -nE '(^|[[:space:]])(env )?adb[[:space:]]+(devices|shell|push|pull|get-state|reboot|root|wait-for-device|exec-out|start-server|kill-server|install|logcat|forward|reverse|connect|disconnect|tcpip|remount|sync)\b' \
            | grep -vE 'run_adb|ADB=|ADB_SERVER_SOCKET|ADB_TIMEOUT' || true)"
    if [[ -n "$bare" ]]; then st_bad "bare adb call(s) found:"; printf '%s\n' "$bare" | sed 's/^/        /'
    else st_ok "all adb calls go through run_adb (ADB_TIMEOUT=${ADB_TIMEOUT}s)"; fi

    say "== selftest: device probe =="
    local t0 t1 rc out
    t0="$(date +%s)"; out="$( (probe_device) 2>&1 )"; rc=$?; t1="$(date +%s)"
    if (( rc != 0 )); then
        if printf '%s' "$out" | grep -qi 'no device'; then st_ok "no device: exits $rc in $((t1 - t0))s: $out"
        else st_bad "no device: exits $rc but the message is unclear: $out"; fi
    else
        st_ok "device reachable via ADB='$ADB' in $((t1 - t0))s (device runs are possible now)"
    fi
    # Simulated missing device: the guard must fail fast with one clear message
    # and a non-zero exit, whatever the real device state is.
    t0="$(date +%s)"; out="$( (ADB=false; probe_device) 2>&1 )"; rc=$?; t1="$(date +%s)"
    if (( rc != 0 )) && printf '%s' "$out" | grep -qi 'no adb device'; then
        st_ok "simulated missing device: exits $rc in $((t1 - t0))s, one clear error, nothing staged"
    else
        st_bad "simulated missing device: rc=$rc out='$out' (want non-zero + 'no adb device')"
    fi

    say "== selftest: classifier against recorded evidence =="
    local boot="${RZ_SELFTEST_BOOT_LOG:-/tmp/rz-this-boot.log}"
    local crash="$REPO/diag/zygote64-crash-audit/logcat-crash.txt"
    local t
    for t in "$boot:64:INJECTED_NO_HOOKS" "$boot:32:INJECTED_NO_HOOKS" "$crash:64:CRASHED"; do
        local log="${t%%:*}" rest="${t#*:}" abi="${t#*:}"; abi="${abi%%:*}"
        local want="${t##*:}" got
        if [[ ! -f "$log" ]]; then st_skip "fixture missing: $log (want $want on abi $abi)"; continue; fi
        classify_log "$log" selftest >/dev/null 2>&1
        got="${VERDICT_ABI[$abi]:-UNKNOWN}"
        if [[ "$got" == "$want" ]]; then st_ok "$(basename "$log") abi=$abi -> $got"
        else st_bad "$(basename "$log") abi=$abi -> $got (want $want)"; fi
    done

    if [[ "$with_build" == "--with-build" ]]; then
        say "== selftest: build the most-patched rung, both ABIs (slow) =="
        if (build_rung f4f3f1off) >"$RESULTS/.selftest-build.log" 2>&1; then
            st_ok "rung f4f3f1off builds (log: $RESULTS/.selftest-build.log)"
            local abi trip tdir want_c so c
            for trip in "64:$T64:2" "32:$T32:1"; do
                abi="${trip%%:*}"; rest="${trip#*:}"; tdir="${rest%%:*}"; want_c="${rest##*:}"
                so="$SCRATCH/target/$tdir/release/libzygisk.so"
                if [[ ! -f "$so" ]]; then st_bad "no artifact for abi=$abi: $so"; continue; fi
                c="$(dc5 "$so")"
                if [[ "$c" == "$want_c" ]]; then st_ok "abi=$abi artifact is ELF class $c, sha256=$(short "$(sha256_of "$so")")"
                else st_bad "abi=$abi artifact ELF class $c (want $want_c): $so"; fi
            done
        else
            st_bad "rung f4f3f1off failed to build (log: $RESULTS/.selftest-build.log)"
        fi
    else
        st_skip "build check (re-run with: bisect_ladder.sh selftest --with-build)"
    fi

    say ""
    if (( SELFTEST_FAILS == 0 )); then
        say "SELFTEST: PASS — harness verified without a device"
        return 0
    fi
    say "SELFTEST: FAIL — $SELFTEST_FAILS check(s) failed"
    return 1
}

# ---------------------------------------------------------------------------
usage() {
    awk 'NR>1 && /^# ==== end of usage ====/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"
    say ""
    say "RUNGS"
    local r
    for r in "${RUNG_ORDER[@]}"; do
        printf '  %-14s %s\n' "$r" "${RUNG_DESC[$r]}"
        printf '  %-14s   patches=%s | predict=%s | hard-expect=%s%s\n' "" \
            "${RUNG_PATCHES[$r]:-none}" "${RUNG_PREDICT[$r]}" \
            "${RUNG_EXPECT_HARD[$r]:-none}" "${RUNG_EXPECT_SOFT[$r]:+ | soft-expect=${RUNG_EXPECT_SOFT[$r]}}"
    done
    say ""
    decision_rule
    say ""
    say "RUN: stage <rung>  ->  reboot  ->  assert <rung>  ->  next"
}

main() {
    local cmd="${1:-}" rc=0 r
    case "$cmd" in
        rungs)
            usage
            ;;
        show)
            r="$(resolve_rung "${2:-}")"
            say "rung:    $r"
            say "state:   ${RUNG_DESC[$r]}"
            say "patches: ${RUNG_PATCHES[$r]:-<none: the tree as committed>}"
            say "predict: ${RUNG_PREDICT[$r]}"
            write_patches
            local p
            for p in ${RUNG_PATCHES[$r]}; do
                say ""
                say "--- replacement set: $PATCHES/$p.txt ---"
                sed 's/^/  /' "$PATCHES/$p.txt"
            done
            say ""
            say "== anchor dry-check against the pristine working tree ($REPO) =="
            for p in ${RUNG_PATCHES[$r]}; do
                apply_patch_file "$PATCHES/$p.txt" "$REPO" check || rc=2
            done
            [[ $rc -eq 0 ]] && say "  all anchors match exactly once: rung '$r' is buildable now"
            ;;
        build)    r="$(resolve_rung "${2:-}")"; build_rung "$r" ;;
        stage)    r="$(resolve_rung "${2:-}")"; stage_rung "$r" ;;
        assert)   r="$(resolve_rung "${2:-}")"; assert_rung "$r" "${3:-}"; rc=$? ;;
        classify)
            [[ -n "${2:-}" && -f "${2:-}" ]] || die 2 "usage: bisect_ladder.sh classify <logfile> [rung]"
            r="${3:-offline}"
            [[ "$r" != "offline" ]] && r="$(resolve_rung "$r")"
            classify_log "$2" "$r"
            local abi
            for abi in "${ALL_ABIS[@]}"; do
                tsv_append CLASSIFY "$r" "$abi" "${VERDICT_ABI[$abi]:-UNKNOWN}" - - \
                    "${VERDICT_PID[$abi]:--}" "${VERDICT_SHA[$abi]:--}" "log=$2"
            done
            ;;
        next) cmd_next ;;
        probe) cmd_probe ;;
        selftest) cmd_selftest "${2:-}"; rc=$? ;;
        ""|-h|--help|help) usage; rc=2 ;;
        *) usage >&2; die 2 "unknown command '$cmd'" ;;
    esac
    return $rc
}

main "$@"
exit $?
