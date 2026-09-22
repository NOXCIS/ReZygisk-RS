#!/usr/bin/env bash
# ReZygisk-RS device diagnostics bundle capture.
#
# Usage: scripts/device_diag.sh [label]
#   RADB_SERIAL=<serial> overrides the device (default: 1c487e6b).
#
# Pulls everything relevant for postmortem of "boots but background weirdness":
# rezygisk verbose.log / state.json / boot.log (opt-in boot logger), module
# statuses, full logcat buffers, tombstones, dropbox, avc denials, process
# tree, tricky_store (TEE sim) logs/tee_status, kernel-side truman logs.
#
# Output: diag/<UTC timestamp>_<label>/ in the repo root. Read-only on device.

set -u

SERIAL="${RADB_SERIAL:-1c487e6b}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABEL="${1:-}"
TS="$(date -u +%Y%m%d_%H%M%S)"
OUT="$REPO_ROOT/diag/${TS}${LABEL:+_$LABEL}"
mkdir -p "$OUT"

R() { radb -s "$SERIAL" "$@"; }

# Replicate the interactive radb helper (bash function; not visible to scripts):
# adb server lives on a forwarded tunnel at localhost:15037.
radb() {
  ADB_SERVER_SOCKET=tcp:localhost:15037 command adb "$@"
}

# KernelSU flakiness note: `adb shell su -c "cmd"` can drop through to the
# plain shell domain (avc denials look like file "protection"). Running the
# command string through the device shell first ("su -c 'cmd'") elevates
# reliably — commands must therefore avoid single quotes.
as_root() {
  R shell "su -c '$1'" >"$OUT/$2" 2>"$OUT/.err_$2"
}

echo "=== ReZygisk-RS diag bundle: $OUT (device $SERIAL) ==="

R get-state >"$OUT/device_state.txt" 2>&1

# --- ReZygisk runtime state -------------------------------------------------
as_root "cat /data/adb/rezygisk/verbose.log" verbose.log
as_root "cat /data/adb/rezygisk/state.json" state.json
as_root "cat /data/adb/rezygisk/boot.log" boot.log
as_root "cat /data/adb/modules/rezygisk/module.prop" module.prop
as_root "cat /data/adb/rezygisk/module.prop" tmp_module_prop
as_root "ls -la /data/adb/rezygisk" listing_rezygisk.txt
as_root "ls -la /data/adb/modules" listing_modules.txt
as_root "ls -la /data/adb/modules/rezygisk" listing_rezygisk_module.txt

# Per-module enable/disable/remove markers.
{
  R shell "su -c 'for m in /data/adb/modules/*; do printf \"%s : \" \$m; if [ -f \$m/disable ]; then echo DISABLED; elif [ -f \$m/remove ]; then echo REMOVE; else echo enabled; fi; done'"
} >"$OUT/module_status.txt" 2>&1

# --- Logcat buffers (host side; shell can read logcat) ----------------------
for buf in main system crash events; do
  R logcat -d -b "$buf" -v threadtime >"$OUT/logcat_$buf.txt" 2>&1
done

# --- Tombstones / dropbox (most recent only) --------------------------------
as_root "ls -t /data/tombstones | head -24" tombstone_list.txt
n=0
while IFS= read -r t; do
  case "$t" in ''|*.pb|*':') continue ;; esac
  n=$((n + 1))
  [ "$n" -gt 12 ] && break
  as_root "head -c 262144 /data/tombstones/$t" "tombstone_$t.txt"
done <"$OUT/tombstone_list.txt"

as_root "ls -t /data/system/dropbox 2>/dev/null | head -40" dropbox_list.txt
n=0
while IFS= read -r d; do
  case "$d" in ''|*.tmp) continue ;; esac
  n=$((n + 1))
  [ "$n" -gt 15 ] && break
  as_root "head -c 131072 /data/system/dropbox/$d" "dropbox_${d//\//_}.txt"
done <"$OUT/dropbox_list.txt"

# --- Kernel / SELinux --------------------------------------------------------
as_root "dmesg" dmesg.txt
as_root "logcat -d -b kernel -v threadtime 2>/dev/null | tail -c 524288" logcat_kernel.txt
{
  grep -i "avc.*denied" "$OUT/dmesg.txt" 2>/dev/null | tail -200
  grep -i "avc.*denied" "$OUT/logcat_kernel.txt" 2>/dev/null | tail -200
} >"$OUT/avc_denials.txt"

# --- Process tree ------------------------------------------------------------
R shell "ps -A -o PID,PPID,USER,STIME,NAME" >"$OUT/ps_all.txt" 2>&1
R shell "ps -A -o PID,PPID,USER,STIME,ARGS | grep -E 'zygisk|ptrace|truman|TEESim|inject|supervisor|keystore' | grep -v grep" >"$OUT/ps_relevant.txt" 2>&1

# --- tricky_store (TEE simulator) ---------------------------------------------
as_root "cat /data/adb/tricky_store/tee_status" tricky_tee_status.txt
as_root "cat /data/adb/tricky_store/target.txt" tricky_target.txt
as_root "tail -c 131072 /data/adb/tricky_store/logs/certgen.log" tricky_certgen.log
as_root "ls -la /data/adb/tricky_store /data/adb/tricky_store/logs /data/adb/modules/tricky_store" tricky_listing.txt

# --- Kernel-side truman (ksud) -----------------------------------------------
as_root "cat /data/adb/truman.log" truman.log
as_root "cat /data/adb/truman_watch.log" truman_watch.log

# --- Device identity / boot timing --------------------------------------------
R shell getprop >"$OUT/getprop.txt" 2>&1
{
  R shell uptime
  R shell "getprop sys.boot_completed; getprop ro.boottime.init; getprop ro.boottime.zygote"
} >"$OUT/boot_timing.txt" 2>&1

# --- Quick summary ------------------------------------------------------------
{
  echo "=== unknown sigchld_status lines in verbose.log ==="
  grep -c "unknown sigchld_status" "$OUT/verbose.log" 2>/dev/null || true
  grep "unknown sigchld_status" "$OUT/verbose.log" 2>/dev/null || true
  echo
  echo "=== status updates ==="
  grep "status updated" "$OUT/verbose.log" 2>/dev/null || true
  echo
  echo "=== tracer / inject lines ==="
  grep -E "inject|handoff|trace complete|restart" "$OUT/verbose.log" 2>/dev/null | head -40 || true
} >"$OUT/SUMMARY.txt"

echo "=== done: $OUT ==="
ls -la "$OUT" | head -50
