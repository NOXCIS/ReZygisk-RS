#!/usr/bin/env bash
# ReZygisk-RS stability soak.
#
# Usage: scripts/soak.sh [minutes] [label]
#   RZ_SOAK_SERIAL=<serial>   device (default 1c487e6b)
#
# Samples the live device once a minute and periodically starts an app so that
# the per-process loader path (module load -> REGISTER_MODULE -> unload) is
# exercised, not just the boot-time injection. Read-only on device apart from
# those app starts. Output: diag/<UTC ts>_<label>/ (samples.tsv, SUMMARY.txt)
# plus a full device_diag.sh bundle.
#
# PASS requires, for the whole window:
#   * monitor state stayed Tracing (state.json "state": "0", never "2")
#   * zygote64/32 pids never changed (a change means a zygote crash)
#   * the crash buffer stayed empty
#   * no new tombstones
#   * no controller-framing / give-up / self-stop lines
#   * every app start produced loader + module evidence for the new pid

set -u

SERIAL="${RZ_SOAK_SERIAL:-1c487e6b}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MINUTES="${1:-45}"
LABEL="${2:-soak}"
TS="$(date -u +%Y%m%d_%H%M%S)"
OUT="$REPO_ROOT/diag/${TS}_${LABEL}"
mkdir -p "$OUT"

S=""
adb_dev() { ADB_SERVER_SOCKET=tcp:localhost:15037 command adb -s "$SERIAL" "$@"; }
# KernelSU: run the command string through the device shell first, else su can
# silently drop to the plain shell domain.
root() { adb_dev shell "su -c '$1'" 2>/dev/null; }

SCOPE="/data/adb/rezygisk"
STATE_JSON="$OUT/state_first.json"
: >"$OUT/samples.tsv"
: >"$OUT/app_starts.tsv"

echo "=== ReZygisk-RS soak: ${MINUTES}m into $OUT (device $SERIAL) ==="
adb_dev wait-for-device >/dev/null 2>&1

z64_start="$(adb_dev shell pidof zygote64 | tr -d '\r')"
# On this device the 32-bit zygote's comm is plain "zygote" (its 64-bit
# sibling is "zygote64"); "app_process32" only appears in its argv.
z32_start="$(adb_dev shell pidof zygote | tr -d '\r')"
tomb_start="$(root 'ls /data/tombstones 2>/dev/null | wc -l' | tr -d '\r')"
echo "start: zygote64=$z64_start zygote32=$z32_start tombstones=$tomb_start"

printf 'elapsed_s\tstate\tstate_reason\tmods64\tmods32\tzygote64\tzygote32\tcrash_lines\ttombstones\n' >>"$OUT/samples.tsv"

# Apps that exist on virtually every device; started in rotation.
APPS=(com.android.settings com.android.documentsui com.android.dialer com.android.calendar)

fail_lines() {
    # Lines that must not appear during a healthy soak.
    grep -aE \
        'malformed DaemonSet|ignoring control datagram|Stop tracing requested|not handing off|did not park as expected|stop injecting because not tracing|tracer: injection into [0-9]+ failed' \
        "$FULL_LOG" | wc -l | tr -d ' \r'
}

snapshot() {
    local elapsed="$1"
    root "cat $SCOPE/state.json" >"$OUT/state.json" 2>/dev/null
    local state reason m64 m32 z64 z32 crashes tombs
    state="$(sed -n 's/.*"state": *"\([0-9]*\)".*/\1/p' "$OUT/state.json" | head -1)"
    reason="$(sed -n 's/.*"reason": *"\([^"]*\)".*/\1/p' "$OUT/state.json" | head -1)"
    m64="$(tr -d ' \n' <"$OUT/state.json" | sed -n 's/.*"64":{"state":\([0-9]*\),"modules":\[\([^]]*\)\].*/\2/p')"
    m32="$(tr -d ' \n' <"$OUT/state.json" | sed -n 's/.*"32":{"state":\([0-9]*\),"modules":\[\([^]]*\)\].*/\2/p')"
    z64="$(adb_dev shell pidof zygote64 | tr -d '\r')"
    z32="$(adb_dev shell pidof zygote | tr -d '\r')"
    crashes="$(adb_dev logcat -d -b crash 2>/dev/null | grep -ac 'Fatal signal' | tr -d '\r')"
    tombs="$(root 'ls /data/tombstones 2>/dev/null | wc -l' | tr -d '\r')"
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$elapsed" "${state:-?}" "${reason:--}" "${m64:--}" "${m32:--}" \
        "${z64:--}" "${z32:--}" "${crashes:-0}" "${tombs:-?}" >>"$OUT/samples.tsv"
    [[ "${z64:-}" != "$z64_start" ]] && echo "!! zygote64 pid changed: $z64_start -> $z64"
    [[ "${z32:-}" != "$z32_start" ]] && echo "!! zygote32 pid changed: $z32_start -> $z32"
    return 0
}

exercise() {
    local app="$1" elapsed="$2"
    # Force-stop first: bringing an already-running app to the front produces
    # no new process and therefore no loader activity to observe. No
    # logcat -c — the crash buffer and the boot window are evidence we keep.
    adb_dev shell "am force-stop $app" >/dev/null 2>&1
    sleep 2
    adb_dev shell "am start -n $app/.MainActivity >/dev/null 2>&1 || \
        monkey -p $app -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1" >/dev/null 2>&1
    sleep 14
    local log="$OUT/applog_${elapsed}s.txt"
    adb_dev logcat -d 2>/dev/null >"$log"
    local pid loaded registered unmap
    pid="$(adb_dev shell pidof "$app" 2>/dev/null | tr -d '\r' | awk '{print $1}')"
    if [[ -z "$pid" ]]; then
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$elapsed" "$app" "no-pid" 0 0 0 >>"$OUT/app_starts.tsv"
        echo "  app $app: not running after start (no pid)"
        return 0
    fi
    local mine
    mine="$(grep -aE "[[:space:]]${pid}[[:space:]]+[0-9]+[[:space:]]+[A-Z][[:space:]]+zygisk" "$log")"
    loaded="$(grep -ac 'Loaded module \[' <<<"$mine")"
    registered="$(grep -ac 'Registering module with API version' <<<"$mine")"
    unmap="$(grep -ac 'self-unmap disabled' <<<"$mine")"
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$elapsed" "$app" "$pid" "$loaded" "$registered" "$unmap" >>"$OUT/app_starts.tsv"
    echo "  app $app (pid $pid): module loads=$loaded register=$registered loader-marker=$unmap"
}

total_s=$((MINUTES * 60))
next_app=0
i=0
while [[ "$i" -lt "$total_s" ]]; do
    snapshot "$i"
    if [[ "$i" -ge "$next_app" ]]; then
        exercise "${APPS[$(( (i / 480) % ${#APPS[@]} ))]}" "$i"
        next_app=$((i + 480))
    fi
    sleep 60
    i=$((i + 60))
done
snapshot "$total_s"

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
FULL_LOG="$OUT/logcat_full.txt"
adb_dev logcat -d >"$FULL_LOG" 2>/dev/null
CRASH_LOG="$OUT/logcat_crash.txt"
adb_dev logcat -d -b crash >"$CRASH_LOG" 2>/dev/null

report="$OUT/SUMMARY.txt"
{
    echo "=== ReZygisk-RS soak: ${MINUTES}m, device $SERIAL, out $OUT ==="
    echo "start zygote64=$z64_start zygote32=$z32_start tombstones=$tomb_start"
    echo
    echo "--- samples.tsv ---"
    cat "$OUT/samples.tsv"
    echo
    echo "--- app starts (module callbacks per fresh process) ---"
    cat "$OUT/app_starts.tsv"
    echo
    echo "--- forbidden lines seen during soak ---"
    grep -aE \
        'malformed DaemonSet|ignoring control datagram|Stop tracing requested|not handing off|did not park as expected|stop injecting because not tracing|tracer: injection into [0-9]+ failed' \
        "$FULL_LOG"
    echo "(end)"
    echo
    echo "--- status update history (verbose.log) ---"
    root "cat $SCOPE/verbose.log" 2>/dev/null | grep -a 'status updated' | tail -10
    echo
    echo "--- crash buffer ---"
    grep -a 'Fatal signal' "$CRASH_LOG" | tail -5
    echo "(end)"
} >>"$report" 2>&1

rc=0
FAILS=()
fail() { echo "FAIL: $*"; FAILS+=("$*"); rc=1; }

# 1. monitor stayed tracing
bad_states="$(awk -F'\t' 'NR>1 && $2 != "0" {print $1": state="$2" reason="$3}' "$OUT/samples.tsv")"
[[ -n "$bad_states" ]] && fail "monitor left Tracing: $(echo "$bad_states" | tr '\n' ';')"
# 2. zygote pids stable
z64_end="$(adb_dev shell pidof zygote64 | tr -d '\r')"
z32_end="$(adb_dev shell pidof zygote | tr -d '\r')"
[[ "$z64_end" != "$z64_start" ]] && fail "zygote64 restarted ($z64_start -> $z64_end)"
[[ "$z32_end" != "$z32_start" ]] && fail "zygote32 restarted ($z32_start -> $z32_end)"
# 3. crash buffer empty
grep -aq 'Fatal signal' "$CRASH_LOG" && fail "crash buffer is not empty"
# 4. no new tombstones
tomb_end="$(root 'ls /data/tombstones 2>/dev/null | wc -l' | tr -d '\r')"
[[ "${tomb_end:-0}" -gt "${tomb_start:-0}" ]] && fail "new tombstones ($tomb_start -> $tomb_end)"
# 5. forbidden lines
fl="$(fail_lines)"
[[ "${fl:-0}" != "0" ]] && fail "$fl forbidden line(s) in logcat"
# 6. every app start produced loader + module evidence in the fresh process
while IFS=$'\t' read -r el app pid loaded reg unmap; do
    if [[ "${loaded:-0}" -lt 1 && "${reg:-0}" -lt 1 && "${unmap:-0}" -lt 1 ]]; then
        fail "app start at ${el}s ($app pid $pid) showed no loader/module evidence (loads=$loaded register=$reg marker=$unmap)"
    fi
done <"$OUT/app_starts.tsv"

{
    echo
    if [[ "$rc" -eq 0 ]]; then
        echo "VERDICT: PASS"
    else
        echo "VERDICT: FAIL"
        for f in "${FAILS[@]}"; do echo "  - $f"; done
    fi
} >>"$report"
echo
sed -n '/--- samples.tsv ---/,$p' "$report" | head -30
if [[ "$rc" -eq 0 ]]; then echo "SOAK PASS ($OUT)"; else echo "SOAK FAIL ($OUT)"; fi
exit "$rc"
