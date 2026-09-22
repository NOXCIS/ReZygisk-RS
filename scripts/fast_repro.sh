#!/usr/bin/env bash
# Fast repro loop for the loader crash, without a reboot.
#
# The crash we chase happens on the *fork path of a freshly injected zygote*:
# the child runs the loader's cleanup (module unload + JNI hook restore) inside
# `nativeForkSystemServer` and then dies at the next JNI boundary if the restore
# left a pending exception. So the shortest faithful repro is:
#
#   1. `zygisk-ptrace64 ctl start` — re-seize init so the monitor injects again
#      (the failure guard stops injection after too many zygote restarts; the
#      monitor's `handle_start` re-runs PTRACE_SEIZE on pid 1 and both ABIs get
#      injected on their next fork — no reboot needed).
#   2. kill zygote64 / zygote — init respawns it with the same argv, so it
#      re-forks system_server, which is exactly the process that died before.
#
# Evidence lands in diag/repro/<UTC stamp>/ so a run can be diffed against the
# previous one; the verdict is printed last.
#
# Usage:
#   scripts/fast_repro.sh [64|32|both] [wait_seconds]
#
# Env: ADB (defaults to the tunnel form when localhost:15037 is listening,
#      matching ~/.bashrc), MOD=/data/adb/modules/rezygisk

set -uo pipefail

WHICH="${1:-64}"
WAIT="${2:-45}"

MOD="${MOD:-/data/adb/modules/rezygisk}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -z "${ADB:-}" ]]; then
    if (exec 3<>/dev/tcp/localhost/15037) 2>/dev/null; then
        ADB="adb"
        export ADB_SERVER_SOCKET=tcp:localhost:15037
    else
        ADB="adb"
    fi
fi

case "$WHICH" in
    64 | 32 | both) ;;
    *)
        echo "usage: $0 [64|32|both] [wait_seconds]" >&2
        exit 2
        ;;
esac

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$REPO/diag/repro/$STAMP"
mkdir -p "$OUT"

sh() { "$ADB" shell "$@" 2>&1; }
# `su -c '<cmd>'` (quoted this way, like verify_deploy.sh) is what can read
# /data/adb/rezygisk/*; `su 0 -c` gets EACCES on that directory.
root() { "$ADB" shell "su -c '$1'" 2>&1; }

echo "== fast repro $STAMP (target: $WHICH, wait ${WAIT}s) =="

if [[ "$("$ADB" get-state 2>&1)" != "device" ]]; then
    echo "FAIL: no device (adb get-state != device)" >&2
    exit 1
fi

# Remember where the monitor's own log file currently ends so the evidence
# below only contains this run.
VERBOSE_OFF="$(root "wc -l < /data/adb/rezygisk/verbose.log 2>/dev/null" | tr -dc 0-9)"
VERBOSE_OFF="${VERBOSE_OFF:-0}"

# Clear the buffers *before* re-arming: the monitor's own "Start tracing init"
# line is part of the evidence, and a clear after it would hide whether the
# re-arm was accepted. Tombstones are not cleared (they carry timestamps).
"$ADB" logcat -b all -c 2>/dev/null

echo "-- re-arm monitor"
root "cat /data/adb/rezygisk/state.json 2>/dev/null" >"$OUT/state.before.json"
ARM="$(root "$MOD/bin/zygisk-ptrace64 ctl start")"
echo "   ctl start -> ${ARM:-<no output>}"

echo "-- kill zygote(s)"
if [[ "$WHICH" == "64" || "$WHICH" == "both" ]]; then
    root 'kill -9 $(pidof zygote64)'
fi
if [[ "$WHICH" == "32" || "$WHICH" == "both" ]]; then
    root 'kill -9 $(pidof zygote)'
fi

echo "-- waiting ${WAIT}s for init -> zygote -> fork system_server"
sleep "$WAIT"

echo "-- collecting evidence into ${OUT#"$REPO"/}"
"$ADB" logcat -b all -d >"$OUT/logcat-all.txt" 2>&1
root "tail -n +$((VERBOSE_OFF + 1)) /data/adb/rezygisk/verbose.log" >"$OUT/verbose.log" 2>&1
sh "ps -A -o PID,PPID,ARGS" >"$OUT/ps.txt"
root "cat /data/adb/rezygisk/state.json" >"$OUT/state.after.json" 2>/dev/null
root "ls -la /data/tombstones/ | tail -6" >"$OUT/tombstones.txt" 2>&1

# ---- verdict ---------------------------------------------------------------
echo
echo "== verdict =="

inj() { grep -aE "tracer: injection into [0-9]+ (succeeded|failed)" "$OUT/verbose.log" "$OUT/logcat-all.txt" 2>/dev/null | sort -u; }
NOSUCH="$(grep -ac 'NoSuchMethodError' "$OUT/logcat-all.txt")"
CORRUPT="$(grep -ac 'stack corruption detected' "$OUT/logcat-all.txt")"
REGF=0
grep -aq 'Failed to register native method' "$OUT/logcat-all.txt" && REGF=1
RESTORE_FAIL="$(grep -ac 'Failed to restore JNI hook' "$OUT/logcat-all.txt")"
# A spurious self-stop (a control datagram misread as a command) and a monitor
# that is not Tracing afterwards are failures in their own right: injection can
# succeed and the module still end up reporting not-working.
SELFSTOP="$(grep -ac 'Stop tracing requested' "$OUT/logcat-all.txt")"
MSTATE="$(sed -n 's/.*"state": *"\([0-9]*\)".*/\1/p' "$OUT/state.after.json" | head -1)"

echo "zygote64 pid: $(grep -a ' zygote64$' "$OUT/ps.txt" | awk '{print $1}' | tr '\n' ' ')"
echo "zygote32 pid: $(grep -aE ' [0-9]+ zygote$' "$OUT/ps.txt" | awk '{print $1}' | tr '\n' ' ')"
echo "system_server: $(grep -ac ' system_server' "$OUT/ps.txt")"
echo "guard/tracing: $(grep -aoE 'Stop tracing|restart too much|Start tracing init|Continue tracing init|stop injecting' "$OUT/logcat-all.txt" | sort -u | tr '\n' '/')"
echo "injection:"
inj | sed 's/^/   /'
echo "   NoSuchMethodError=$NOSUCH  Failed-to-register=$REGF  Failed-to-restore=$RESTORE_FAIL  stack-corruption=$CORRUPT"
echo "   monitor state after=${MSTATE:-?}  spurious-self-stops=$SELFSTOP"

if [[ "$NOSUCH" -gt 0 || "$CORRUPT" -gt 0 || "$REGF" -gt 0 || "$RESTORE_FAIL" -gt 0 ]]; then
    echo "RESULT: FAIL — loader crash signature present (see $OUT)"
    exit 1
fi
if [[ "$SELFSTOP" -gt 0 || "${MSTATE:-0}" != "0" ]]; then
    echo "RESULT: FAIL — monitor did not stay in Tracing (spurious stop / state ${MSTATE:-?}) (see $OUT)"
    exit 1
fi
if ! inj | grep -aq 'succeeded'; then
    echo "RESULT: INCONCLUSIVE — no successful injection observed (see $OUT)"
    exit 2
fi
echo "RESULT: PASS — injected, forked, no crash signature, monitor still Tracing (see $OUT)"
