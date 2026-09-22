#!/usr/bin/env bash
# Single-generation deploy + verification for the rezygisk module.
#
# Why this exists: the 64-bit monitor/tracer was once left behind by an older
# build while every other component was current. A stale ptracer does not fail
# loudly — it simply lacks newer diagnostics, so the *missing lines* read as
# "that code path never ran" and cost a full debug cycle chasing a ptracer
# regression that did not exist. Mixed ABIs also produce two different mapping
# and logging signatures for the same success, which breaks any log grep.
#
# So this script refuses to trust the deployment:
#   1. builds both ABIs from the working tree with one feature set,
#   2. stages one generation into the module dir, fail-closed,
#   3. writes a generation manifest next to the module's binaries, then asserts
#      on-device sha256 + ELF class + embedded generation for every component,
#   4. after reboot, asserts that BOTH ABIs actually got handed off + injected
#      AND that every component's startup `generation:` line matches the
#      manifest.
#
# The generation id (crates/common/build.rs) is baked into every binary of one
# build. That is what makes the guard non-circular: a stale component cannot
# self-report, so the *host* reads the id out of the installed bytes while the
# *current* components log an ERROR when the manifest disagrees with them.
#
# Usage:
#   scripts/verify_deploy.sh build     # build only
#   scripts/verify_deploy.sh stage     # build + push + manifest + verify hashes
#   scripts/verify_deploy.sh verify    # manifest vs installed sha256/ELF/generation
#   scripts/verify_deploy.sh assert [log]  # post-reboot log assertions
#   scripts/verify_deploy.sh all       # build + stage + verify
#
# Env knobs:
#   ADB="adb"                adb command (defaults to the Mac-tunnel form when
#                            localhost:15037 is listening, matching ~/.bashrc)
#   MOD=/data/adb/modules/rezygisk
#   RZ_STAGE=all             which groups to stage+verify: all | ptracer |
#                            daemons | loaders (comma-separated to combine).
#                            A bisect varies one component at a time, so use
#                            RZ_STAGE=ptracer to fix the tracers without
#                            touching the loader rung under test. Anything not
#                            selected is reported as NOT VERIFIED, never as OK.
#   RZ_FEATURES=""           cargo features applied to EVERY component. Build
#                            all ABIs with the same value: a per-ABI feature
#                            difference is the other half of the skew trap
#                            (stealth-tag moves the loader's log tag to `core`,
#                            which silently drops it from `grep -i zygisk`).
#   RZ_GENERATION=<id>       build override forwarded to cargo (CI / tarball).
#   RZ_ALLOW_MIX=1           downgrade a *deliberate* generation mix (one that
#                            RZ_STAGE excluded) from FAIL to MIXED. The mix is
#                            still printed; it is never reported as OK.
#   RZ_ADB_TIMEOUT=10        seconds before a device probe is declared dead.
#   RZ_MANIFEST_LOCAL=<path> read the manifest from this file instead of the
#                            device (offline rehearsal / postmortem of a saved
#                            deployment; the boot log path is argv[2]).
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT64="$REPO/target/aarch64-linux-android/release"
OUT32="$REPO/target/armv7-linux-androideabi/release"
MOD="${MOD:-/data/adb/modules/rezygisk}"
FEATURES="${RZ_FEATURES:-}"
STAGING=/data/local/tmp/rz-stage
MANIFEST_NAME=.generation.json
MANIFEST_LOCAL="${RZ_MANIFEST_LOCAL:-}"
ALLOW_MIX="${RZ_ALLOW_MIX:-0}"
ADB_TIMEOUT="${RZ_ADB_TIMEOUT:-10}"
TMP_PATH=/data/adb/rezygisk

if [[ -z "${ADB:-}" ]]; then
    if ss -H -tln 2>/dev/null | grep -q ':15037'; then
        ADB="env ADB_SERVER_SOCKET=tcp:localhost:15037 adb"
    else
        ADB="adb"
    fi
fi

# "installed-path:local-artifact" pairs — one generation on both sides.
PAIRS=(
    "bin/zygisk-ptrace64:$OUT64/zygisk-ptrace"
    "bin/zygiskd64:$OUT64/rezygiskd"
    "lib64/libzygisk.so:$OUT64/libzygisk.so"
    "bin/zygisk-ptrace32:$OUT32/zygisk-ptrace"
    "bin/zygiskd32:$OUT32/rezygiskd"
    "lib/libzygisk.so:$OUT32/libzygisk.so"
)

# Which groups to stage/verify. A bisect varies exactly one component at a
# time, so "all" is the wrong default there: RZ_STAGE=ptracer stages only the
# tracers and leaves the loader rung under test untouched. Anything not
# selected is reported as unverified rather than silently assumed good.
STAGE_SET="${RZ_STAGE:-all}"
group_of() {
    case "$1" in
        bin/zygisk-ptrace*) echo ptracer ;;
        bin/zygiskd*) echo daemons ;;
        *libzygisk.so) echo loaders ;;
        *) echo other ;;
    esac
}
selected_pairs() {
    local pair group
    for pair in "${PAIRS[@]}"; do
        group="$(group_of "${pair%%:*}")"
        if [[ "$STAGE_SET" == "all" || ",$STAGE_SET," == *",$group,"* ]]; then
            printf '%s\n' "$pair"
        fi
    done
}
mapfile -t SEL < <(selected_pairs)

is_selected() {
    local pair
    for pair in "${SEL[@]}"; do
        [[ "${pair%%:*}" == "$1" ]] && return 0
    done
    return 1
}

PASS=0
FAIL=0
MIXED=0
check() { # check <ok:0|1> <label>
    if [[ "$1" == "0" ]]; then
        printf '  PASS  %s\n' "$2"
        PASS=$((PASS + 1))
    else
        printf '  FAIL  %s\n' "$2"
        FAIL=$((FAIL + 1))
    fi
}
mixed() { # mixed <label> — reported, never counted as OK
    printf '  MIXED %s\n' "$1"
    MIXED=$((MIXED + 1))
}

sha256_of() { sha256sum "$1" 2>/dev/null | awk '{ print $1 }'; }

elf_class_of() { # 2 = ELF64, 1 = ELF32, ? = not readable/not ELF
    head -c 5 "$1" 2>/dev/null | od -An -tu1 | awk '{ print $5 }'
}

# Stage names must not collide: both loaders are `libzygisk.so` on the way in.
stage_name() { printf '%s' "${1//\//_}"; }

# ---------------------------------------------------------------------------
# Generation id plumbing
# ---------------------------------------------------------------------------
#
# One token, `<<RZGEN:<id>>`, is baked into every binary of one build and
# printed by every component at startup. The `<<`/`>>` delimiters are not
# decoration: Rust string constants are not NUL-terminated, so an unbracketed
# id would run into adjacent printable rodata and extract as a different id.

gen_token_re='<<RZGEN:[^>]*>>'

gen_token_of_file() { # host-side; binary safe, exact thanks to the delimiters
    LC_ALL=C grep -aoE "$gen_token_re" "$1" 2>/dev/null | head -n1
}
gen_token_count_of_file() {
    LC_ALL=C grep -aoE "$gen_token_re" "$1" 2>/dev/null | sort -u | wc -l
}
gen_id_of_token() {
    local token="$1"
    token="${token#<<RZGEN:}"
    printf '%s' "${token%>>}"
}
gen_id_of_file() { gen_id_of_token "$(gen_token_of_file "$1")"; }

# Single generation shared by all six local artifacts, or an error on stderr.
local_generation() {
    local pair src token first="" count
    for pair in "${PAIRS[@]}"; do
        src="${pair#*:}"
        if [[ ! -f "$src" ]]; then
            echo "missing local artifact: $src" >&2
            return 1
        fi
        count="$(gen_token_count_of_file "$src")"
        if [[ "$count" != "1" ]]; then
            echo "$src carries ${count} distinct generation tokens (expected 1) — rebuild it" >&2
            return 1
        fi
        token="$(gen_token_of_file "$src")"
        if [[ -z "$first" ]]; then
            first="$token"
        elif [[ "$token" != "$first" ]]; then
            echo "generation skew: ${pair%%:*} is $token, expected $first" >&2
            return 1
        fi
    done
    gen_id_of_token "$first"
}

# Device-side extraction. Validated on toybox grep (API 25+): `-a`, `-o` and
# `-E` are all supported, which keeps the check reading the installed bytes
# instead of trusting a host-side copy.
dev_gen_token() {
    $ADB shell "su -c \"grep -aoE '$gen_token_re' $MOD/$1 2>/dev/null | head -n1\"" 2>/dev/null \
        | tr -d '\r' | sed -n "s/.*\($gen_token_re\).*/\1/p" | head -n1
}
dev_gen_id() { gen_id_of_token "$(dev_gen_token "$1")"; }
dev_sha() { $ADB shell "su -c 'sha256sum $MOD/$1 2>/dev/null'" 2>/dev/null | awk '{ print $1 }'; }
dev_class() {
    $ADB shell "su -c 'head -c 5 $MOD/$1 2>/dev/null | od -An -tu1 | awk \"{print \\\$5}\"'" 2>/dev/null \
        | tr -d ' \r\n'
}
dev_size() { $ADB shell "su -c 'stat -c %s $MOD/$1 2>/dev/null'" 2>/dev/null | tr -d ' \r\n'; }

manifest_id_of_stream() { awk -F'"' '/"deployment_generation"/ { print $4; exit }'; }
manifest_id_of_file() { awk -F'"' '/"deployment_generation"/ { print $4; exit }' "$1" 2>/dev/null; }

dev_manifest_id() {
    if [[ -n "$MANIFEST_LOCAL" ]]; then
        manifest_id_of_file "$MANIFEST_LOCAL"
        return
    fi
    $ADB shell "su -c 'cat $MOD/$MANIFEST_NAME 2>/dev/null'" 2>/dev/null | tr -d '\r' | manifest_id_of_stream
}
manifest_present() {
    if [[ -n "$MANIFEST_LOCAL" ]]; then
        [[ -s "$MANIFEST_LOCAL" ]]
        return
    fi
    $ADB shell "su -c 'test -s $MOD/$MANIFEST_NAME'" >/dev/null 2>&1
}

want_class() {
    case "$1" in
        bin/zygisk-ptrace64|bin/zygiskd64|lib64/*) echo 2 ;;
        *) echo 1 ;;
    esac
}

# adb fails fast without a device on modern platform-tools, but a dead
# ADB_SERVER_SOCKET tunnel accepts the connection and then stalls every
# command. Probe with a bounded round trip so verify/assert degrade with a
# clear message instead of hanging.
require_device() {
    if [[ -n "$MANIFEST_LOCAL" ]]; then
        return 0
    fi
    local probe
    probe="$(timeout "$ADB_TIMEOUT" $ADB shell 'echo RZ-PROBE-OK' 2>&1 | tr -d '\r')"
    if [[ "$probe" != *RZ-PROBE-OK* ]]; then
        printf 'no usable adb device (ADB="%s", timeout %ss)\n' "$ADB" "$ADB_TIMEOUT" >&2
        printf '  probe output: %s\n' "${probe:-<empty>}" >&2
        printf '  this step needs the device; nothing was changed on it\n' >&2
        return 1
    fi
    return 0
}

do_build() {
    echo "== build (features: ${FEATURES:-<none>}) =="
    local feats=()
    [[ -n "$FEATURES" ]] && feats=(--features "$FEATURES")
    local target
    for target in aarch64-linux-android armv7-linux-androideabi; do
        echo "-- $target"
        (cd "$REPO" && cargo build --release -p rz-ptracer -p rezygiskd -p rz-loader \
            --target "$target" ${feats[@]+"${feats[@]}"}) || return 1
    done

    # The build itself is the first thing that can be mixed (one ABI refreshed,
    # the other not), so the six local artifacts must agree before anything is
    # staged. This is the check that would have caught the original bug on the
    # host instead of on the device.
    local gen
    if ! gen="$(local_generation)"; then
        echo "  refusing to continue: the build output is not one generation (see above)" >&2
        return 1
    fi
    case "$gen" in
        *+unknown*)
            if [[ -z "${RZ_GENERATION:-}" ]]; then
                echo "  refusing to continue: '$gen' has no git provenance, so a stale" >&2
                echo "  artifact cannot be told apart from a current one. Set RZ_GENERATION=<id>." >&2
                return 1
            fi
            ;;
    esac
    GEN="$gen"
    echo "  generation: $GEN"
    echo
}

do_scope() {
    echo "== scope: RZ_STAGE=$STAGE_SET (groups: ptracer|daemons|loaders|all) =="
    [[ -n "${GEN:-}" ]] && printf '  generation: %s\n' "$GEN"
    local pair group staged=()
    for pair in "${PAIRS[@]}"; do
        group="$(group_of "${pair%%:*}")"
        [[ "$STAGE_SET" == "all" || ",$STAGE_SET," == *",$group,"* ]] && staged+=("$group")
    done
    printf '  selected: %s\n' "$(printf '%s\n' "${staged[@]}" | sort -u | tr '\n' ' ')"
    local group
    for group in ptracer daemons loaders; do
        if [[ "$STAGE_SET" != "all" && ",$STAGE_SET," != *",$group,"* ]]; then
            printf '  NOT VERIFIED (left as installed): %s\n' "$group"
        fi
    done
    echo
}

# ---------------------------------------------------------------------------
# Manifest: the host's record of what is installed, rewritten once per stage.
# Runtime components read only `deployment_generation` from it; the per-path
# entries are the audit trail and are checked against the device by verify.
# Never written from the device side.
# ---------------------------------------------------------------------------
manifest_json() { # manifest_json <local-out>
    local out="$1" pair dest src first=1 staged sha cls size gen
    {
        printf '{\n'
        printf '  "schema": 1,\n'
        printf '  "deployment_generation": "%s",\n' "$GEN"
        printf '  "created_epoch": %s,\n' "$(date +%s)"
        printf '  "module": "%s",\n' "$MOD"
        printf '  "staged": "%s",\n' "$STAGE_SET"
        printf '  "components": {\n'
        for pair in "${PAIRS[@]}"; do
            dest="${pair%%:*}"; src="${pair#*:}"
            if is_selected "$dest"; then
                staged=true
                sha="$(sha256_of "$src")"
                cls="$(elf_class_of "$src")"
                size="$(stat -c %s "$src" 2>/dev/null)"
                gen="$(gen_id_of_file "$src")"
            else
                # Not staged in this run: record what is installed right now, so
                # a deliberately mixed deployment is visible in the manifest
                # instead of being implied by its absence.
                staged=false
                sha="$(dev_sha "$dest")"
                cls="$(dev_class "$dest")"
                size="$(dev_size "$dest")"
                gen="$(dev_gen_id "$dest")"
            fi
            [[ $first -eq 0 ]] && printf ',\n'
            first=0
            printf '    "%s": {"generation": "%s", "sha256": "%s", "elf_class": %s, "size": %s, "staged": %s}' \
                "$dest" "${gen:-unknown}" "${sha:-}" "${cls:-0}" "${size:-0}" "$staged"
        done
        printf '\n  }\n}\n'
    } >"$out"
}

do_stage() {
    echo "== stage into $MOD =="
    require_device || return 1
    if [[ -z "${GEN:-}" ]]; then
        GEN="$(local_generation)" || return 1
    fi
    echo "  generation: $GEN"

    $ADB shell "rm -rf $STAGING" >/dev/null 2>&1
    $ADB shell "mkdir -p $STAGING" >/dev/null || return 1

    local pair dest src name want got
    for pair in "${SEL[@]}"; do
        dest="${pair%%:*}"; src="${pair#*:}"
        if [[ ! -f "$src" ]]; then
            echo "  missing local artifact: $src" >&2
            return 1
        fi
        name="$(stage_name "$dest")"
        $ADB push "$src" "$STAGING/$name" >/dev/null || return 1

        # A truncated push must never reach the module dir.
        want="$(sha256_of "$src")"
        got="$($ADB shell "su -c 'sha256sum $STAGING/$name 2>/dev/null'" | awk '{ print $1 }')"
        if [[ -z "$want" || "$want" != "$got" ]]; then
            printf '  stage aborted: push of %s did not survive the transfer (local %s, device %s)\n' \
                "$dest" "${want:0:16}" "${got:0:16}" >&2
            return 1
        fi
    done

    $ADB shell "su -c 'mkdir -p $MOD/bin $MOD/lib $MOD/lib64'" || return 1

    # Move the selection into place, then verify each copy before the next one:
    # a half-applied set is exactly the state this script exists to prevent, so
    # a mismatch aborts loudly and names the component. The module dir is then
    # in a mixed state — re-run after fixing; the manifest will describe it.
    local want_sha want_cls got_cls
    for pair in "${SEL[@]}"; do
        dest="${pair%%:*}"; src="${pair#*:}"; name="$(stage_name "$dest")"
        $ADB shell "su -c 'cp -f $STAGING/$name $MOD/$dest'" || return 1

        want_sha="$(sha256_of "$src")"
        got="$(dev_sha "$dest")"
        if [[ -z "$want_sha" || "$want_sha" != "$got" ]]; then
            printf '  stage aborted: %s sha256 mismatch after copy (local %s, device %s)\n' \
                "$dest" "${want_sha:0:16}" "${got:0:16}" >&2
            printf '  %s is now in a MIXED state; re-run stage after fixing the cause\n' "$MOD" >&2
            return 1
        fi

        want_cls="$(elf_class_of "$src")"
        got_cls="$(dev_class "$dest")"
        if [[ -z "$want_cls" || "$want_cls" == "?" || "$want_cls" != "$got_cls" ]]; then
            printf '  stage aborted: %s ELF class mismatch after copy (local %s, device %s)\n' \
                "$dest" "${want_cls:-?}" "${got_cls:-?}" >&2
            return 1
        fi
        printf '  installed %s (%s, ELF class %s, sha256 %s…)\n' \
            "$dest" "$(gen_id_of_file "$src")" "$want_cls" "${want_sha:0:16}"
    done

    # Ownership/mode hygiene is not part of the guard (sha256 + ELF class are
    # already verified above), so a failure here warns: aborting would hide the
    # manifest and leave exactly the unverifiable mixed state this guards against.
    $ADB shell "su -c '
        chown 0:0 $MOD/bin/zygisk-ptrace64 $MOD/bin/zygisk-ptrace32 $MOD/bin/zygiskd64 $MOD/bin/zygiskd32 $MOD/lib64/libzygisk.so $MOD/lib/libzygisk.so 2>/dev/null
        chmod 755 $MOD/bin/zygisk-ptrace64 $MOD/bin/zygisk-ptrace32 $MOD/bin/zygiskd64 $MOD/bin/zygiskd32
        chmod 644 $MOD/lib64/libzygisk.so $MOD/lib/libzygisk.so
    '" >/dev/null 2>&1 || printf '  WARNING: could not set root ownership/mode on the staged files; content is verified, fix ownership before rebooting\n' >&2

    # Manifest last, so it describes the finished set.
    local local_manifest
    local_manifest="$(mktemp /tmp/rz-manifest.XXXXXX)"
    manifest_json "$local_manifest" || return 1
    $ADB push "$local_manifest" "$STAGING/$MANIFEST_NAME" >/dev/null || return 1
    rm -f "$local_manifest"
    if ! $ADB shell "su -c 'cp -f $STAGING/$MANIFEST_NAME $MOD/$MANIFEST_NAME && chmod 644 $MOD/$MANIFEST_NAME'"; then
        printf '  stage aborted: could not install the manifest into %s\n' "$MOD" >&2
        return 1
    fi
    $ADB shell "su -c 'chown 0:0 $MOD/$MANIFEST_NAME 2>/dev/null'" >/dev/null 2>&1 || true
    $ADB shell "rm -rf $STAGING" >/dev/null 2>&1

    got="$(dev_manifest_id)"
    if [[ "$got" != "$GEN" ]]; then
        printf '  stage aborted: manifest on device reads "%s", expected "%s"\n' "${got:-<absent>}" "$GEN" >&2
        return 1
    fi
    echo "  wrote $MOD/$MANIFEST_NAME (generation $GEN)"
    echo
}

do_verify() {
    echo "== verify installed generation =="
    require_device || return 1

    local want_gen
    want_gen="$(dev_manifest_id)"
    if ! manifest_present || [[ -z "$want_gen" ]]; then
        if [[ -n "$MANIFEST_LOCAL" ]]; then
            printf '  no manifest at %s (offline manifest missing)\n' "$MANIFEST_LOCAL" >&2
        else
            printf '  no usable %s/%s on the device: this deployment predates\n' "$MOD" "$MANIFEST_NAME" >&2
            printf '  the generation guard, and a stale binary cannot report anything about\n' >&2
            printf '  itself. Re-run stage to install the guard.\n' >&2
        fi
        local pair token
        for pair in "${PAIRS[@]}"; do
            token="$(dev_gen_token "${pair%%:*}")"
            printf '  %s embedded generation: %s\n' "${pair%%:*}" "${token:-<none>}"
        done
        check 1 "manifest $MANIFEST_NAME present and readable"
        echo
        return 0
    fi
    check 0 "manifest generation on device: $want_gen"

    # The working tree is a second opinion, not the judge: `verify` must work
    # against an install that this checkout no longer builds.
    local local_gen
    if local_gen="$(local_generation)"; then
        if [[ "$local_gen" == "$want_gen" ]]; then
            printf '  NOTE  working-tree artifacts are the installed generation\n'
        else
            printf '  NOTE  working-tree artifacts are generation %s, installed is %s\n' "$local_gen" "$want_gen"
            printf '        (the installed set is not what this checkout builds right now)\n'
        fi
    else
        printf '  NOTE  local artifacts are not one generation; device checks continue\n'
    fi
    echo

    local pair dest src want got gotclass gen staged
    for pair in "${PAIRS[@]}"; do
        dest="${pair%%:*}"; src="${pair#*:}"
        staged=0; is_selected "$dest" && staged=1

        if [[ "$staged" == "1" ]]; then
            want="$(sha256_of "$src")"
            got="$(dev_sha "$dest")"
            check "$([[ -n "$want" && "$want" == "$got" ]] && echo 0 || echo 1)" \
                "$dest sha256 == ${want:0:16}…  (device: ${got:0:16}…)"
        fi

        gotclass="$(dev_class "$dest")"
        check "$([[ "$(want_class "$dest")" == "$gotclass" ]] && echo 0 || echo 1)" \
            "$dest ELF class == $(want_class "$dest")  (device: ${gotclass:-?})"

        gen="$(dev_gen_id "$dest")"
        if [[ "$gen" == "$want_gen" ]]; then
            check 0 "$dest embedded generation == manifest"
        elif [[ "$staged" == "1" ]]; then
            check 1 "$dest embedded generation is ${gen:-ABSENT}, manifest says $want_gen (stale or pre-guard binary)"
        elif [[ "$ALLOW_MIX" == "1" ]]; then
            mixed "$dest embedded generation is ${gen:-ABSENT} != manifest $want_gen (not staged: RZ_STAGE=$STAGE_SET, deliberate)"
        else
            check 1 "$dest embedded generation is ${gen:-ABSENT} != manifest $want_gen (MIXED: not in RZ_STAGE=$STAGE_SET)"
        fi
    done
    echo
}

# The durable log is KernelSU's persistent logcat: the live ring buffer wraps
# within minutes and loses the whole boot window, which is how the original
# misdiagnosis survived.
snapshot_log() {
    local out="$1"
    if $ADB shell "su -c 'test -f /data/adb/ksu/log/logcat.log'" >/dev/null 2>&1; then
        $ADB shell "su -c 'cat /data/adb/ksu/log/logcat.log'" >"$out" 2>/dev/null
    else
        $ADB logcat -d -b all >"$out" 2>&1
    fi
}

# "<abi>|<role>|<installed path>|<what runs it>"
EXPECT_LINES=(
    "lp64|monitor|bin/zygisk-ptrace64|monitor process"
    "lp64|tracer|bin/zygisk-ptrace64|64-bit tracer exec"
    "lp32|tracer|bin/zygisk-ptrace32|32-bit tracer exec"
    "lp64|daemon|bin/zygiskd64|daemon"
    "lp32|daemon|bin/zygiskd32|daemon"
    "lp64|loader|lib64/libzygisk.so|injected 64-bit library"
)
# The 32-bit loader only runs if a 32-bit app starts inside the log window, so
# its absence is reported, never failed.
OPTIONAL_LINES=(
    "lp32|loader|lib/libzygisk.so|injected 32-bit library"
)

# check one component's startup line against the manifest generation
assert_component_line() { # <log> <want id> <abi> <role> <path> <origin> <required:0|1>
    local log="$1" want="$2" abi="$3" role="$4" path="$5" origin="$6" required="$7"
    local expected="generation: <<RZGEN:${want}>> (${abi} ${role})"
    local found
    found="$(LC_ALL=C grep -aoE "generation: <<RZGEN:[^>]*>> \($abi $role\)" "$log" 2>/dev/null | head -n1)"

    if [[ "$found" == "$expected" ]]; then
        check 0 "$role ($abi) from $path reported generation $want"
    elif [[ -n "$found" ]]; then
        check 1 "$role ($abi) from $path reported '$found', manifest says '$expected' (MIXED generation)"
    elif [[ "$required" == "1" ]]; then
        check 1 "$role ($abi) from $path has NO generation line (stale/pre-guard binary, or $origin did not run)"
    else
        printf '  INFO  %s (%s) from %s: no generation line (only expected if no %s ran)\n' \
            "$role" "$abi" "$path" "$origin"
    fi
}

do_assert() {
    local log="${1:-}"
    [[ -n "$log" ]] || log="$(mktemp /tmp/rz-logcat.XXXXXX)"
    echo "== assert boot outcome (log: $log) =="
    require_device || return 1
    if [[ -n "$MANIFEST_LOCAL" ]]; then
        # Offline postmortem: the log must be supplied, never overwritten.
        if [[ ! -s "$log" ]]; then
            printf 'offline assert needs a boot log: %s scripts/verify_deploy.sh assert <log>\n' "$0" >&2
            return 1
        fi
    else
        snapshot_log "$log"
    fi
    echo "  ($(wc -l <"$log") log lines)"

    local want_gen
    want_gen="$(dev_manifest_id)"
    if [[ -z "$want_gen" ]]; then
        check 1 "manifest $MANIFEST_NAME readable (no manifest: deployment predates the guard — run stage, reboot, assert again)"
    else
        check 0 "manifest generation: $want_gen"

        # .quiet raises the daemon's log floor to WARN, which hides the INFO
        # self-reports; refusing to say PASS beats reporting an absence that is
        # really a log filter.
        if [[ -n "$MANIFEST_LOCAL" ]]; then
            :
        elif $ADB shell "su -c 'test -f $TMP_PATH/.quiet'" >/dev/null 2>&1; then
            check 1 "generation self-reports are observable ($TMP_PATH/.quiet hides INFO lines; remove it and reboot)"
        else
            check 0 "no $TMP_PATH/.quiet, so INFO self-reports are not filtered"
        fi

        local spec abi role path origin
        for spec in "${EXPECT_LINES[@]}"; do
            IFS='|' read -r abi role path origin <<<"$spec"
            assert_component_line "$log" "$want_gen" "$abi" "$role" "$path" "$origin" 1
        done
        for spec in "${OPTIONAL_LINES[@]}"; do
            IFS='|' read -r abi role path origin <<<"$spec"
            assert_component_line "$log" "$want_gen" "$abi" "$role" "$path" "$origin" 0
        done

        # A current component that finds the manifest disagreeing with itself
        # logs ERROR (rz_common::log_generation_and_check). A uniform deployment
        # must have none.
        local mism
        mism="$(LC_ALL=C grep -ac 'generation MISMATCH' "$log" 2>/dev/null)"
        mism="${mism:-0}"
        if [[ "$mism" != "0" && "$ALLOW_MIX" == "1" ]]; then
            mixed "$mism component line(s) logged 'generation MISMATCH' (allowed by RZ_ALLOW_MIX=1)"
        else
            check "$([[ "$mism" -eq 0 ]] && echo 0 || echo 1)" \
                "no component logged 'generation MISMATCH' (found $mism)"
        fi
    fi

    check "$(grep -qa 'deployed monitor:' "$log" && echo 0 || echo 1)" \
        "running monitor logged its build stamp (stale binary ruled out)"

    local abi
    for abi in 64 32; do
        check "$(grep -qaE "handoff tracer: pid=[0-9]+ program=/system/bin/app_process$abi" "$log" && echo 0 || echo 1)" \
            "Zygote$abi was handed off to a tracer"
        check "$(grep -qa "Received Zygote$abi injected command" "$log" && echo 0 || echo 1)" \
            "Zygote$abi reported injection success"
    done

    # A healthy boot must not contain any of the give-up paths.
    local bad
    for bad in 'did not park as expected' 'not handing off' 'stop injecting because not tracing'; do
        check "$(grep -qa -- "$bad" "$log" && echo 1 || echo 0)" \
            "no '$bad' in this boot"
    done
    check "$(grep -qaE 'tracer: injection into [0-9]+ failed' "$log" && echo 1 || echo 0)" \
        "no failed tracer in this boot"

    # Controller-socket framing: the daemons report over one shared SOCK_DGRAM
    # socket, so a report that is not exactly one datagram tears under the
    # other daemon's report. When that happened the monitor logged 'malformed
    # DaemonSetInfo', then dispatched a module-count datagram as a command and
    # stopped itself ('Stop tracing requested' with reason 'user requested',
    # status ⛔, no user involved). Boot must show neither.
    check "$(grep -qaE 'malformed DaemonSet(Info|ErrorInfo)' "$log" && echo 1 || echo 0)" \
        "no malformed daemon report in this boot"
    check "$(grep -qaE 'ignoring control datagram with unexpected shape' "$log" && echo 1 || echo 0)" \
        "no mis-shaped control datagram in this boot"
    check "$(grep -qa 'Stop tracing requested' "$log" && echo 1 || echo 0)" \
        "monitor did not stop itself during boot"

    # The status line is what the WebUI shows: it must end the boot all-green.
    check "$(grep -qa 'status updated: Monitor: ✅, ReZygisk 64-bit: ✅, ReZygisk 32-bit: ✅' "$log" && echo 0 || echo 1)" \
        "monitor reported an all-green status during boot"

    # Per-ABI tracer outcomes, counted only inside the current monitor's
    # section: verbose.log is append-only across boots, so a stale line from an
    # earlier boot must not be able to satisfy this. Skipped for an offline log.
    if [[ -z "$MANIFEST_LOCAL" ]]; then
        local verbose="$log.verbose"
        $ADB shell "su -c 'cat $TMP_PATH/verbose.log'" >"$verbose" 2>/dev/null
        local outcomes
        outcomes="$(awk '/^=== \[zygisk-ptrace monitor\]/ { buf = "" } { buf = buf $0 "\n" } END { printf "%s", buf }' "$verbose" \
            | grep -ac 'tracer: injection into' 2>/dev/null)"
        outcomes="${outcomes:-0}"
        check "$([[ "$outcomes" -ge 2 ]] && echo 0 || echo 1)" \
            "current monitor's verbose.log section records both ABI tracer outcomes (found $outcomes)"
    fi
    echo
}

summary() {
    printf '== %s passed, %s failed' "$PASS" "$FAIL"
    [[ "$MIXED" -ne 0 ]] && printf ', %s mixed (deliberate, not OK)' "$MIXED"
    printf ' ==\n'
    [[ "$FAIL" -eq 0 ]]
}

case "${1:-all}" in
    build) do_build ;;
    stage) do_build && do_scope && do_stage && do_verify && summary ;;
    verify) do_scope && do_verify && summary ;;
    assert) do_assert "${2:-}" && summary ;;
    all)
        do_build && do_scope && do_stage && do_verify || exit 1
        summary || exit 1
        echo "Next: reboot, then run '$0 assert' — the boot must show a generation line"
        echo "for the monitor, both tracers, both daemons and the 64-bit loader (all"
        echo "equal to the manifest) plus a handoff AND an injection for both zygotes."
        ;;
    *)
        awk 'NR > 1 && /^set -uo/ { exit } NR > 1 { print }' "${BASH_SOURCE[0]}"
        exit 1
        ;;
esac
