#!/bin/bash
# Cargo linker wrapper for Android targets.
#
# rustc generates its own --version-script for cdylibs that exports every
# #[no_mangle] / #[export_name] symbol.  ld.lld MERGES version scripts: a
# symbol stays global if ANY script declares it global.  That neutralizes
# crates/loader/exports.map (local: *, global: entry), which is what gives
# libzygisk.so its C-parity `visibility("hidden")` export policy.
#
# So: when the loader's exports.map is on the command line, drop rustc's
# temporary version script and keep only ours.  Every other link (all other
# crates) is passed through untouched.
#
# Invoked via per-target symlinks (link-aarch64, link-armv7, ...) whose name
# selects the real NDK clang below.
NDK=/home/nemo/Android/Sdk/ndk/29.0.13113456/toolchains/llvm/prebuilt/linux-x86_64/bin

case "$(basename "$0")" in
  link-aarch64) real="$NDK/aarch64-linux-android25-clang" ;;
  link-armv7)   real="$NDK/armv7a-linux-androideabi25-clang" ;;
  link-x86_64)  real="$NDK/x86_64-linux-android25-clang" ;;
  link-i686)    real="$NDK/i686-linux-android25-clang" ;;
  *)
    echo "ndk-link-wrapper.sh: invoked via unknown name: $0" >&2
    exit 1
    ;;
esac

has_ours=0
for a in "$@"; do
  case "$a" in
    -Wl,--version-script=*exports.map) has_ours=1 ;;
  esac
done

if [ "$has_ours" = 1 ]; then
  out=()
  for a in "$@"; do
    case "$a" in
      -Wl,--version-script=*exports.map) out+=("$a") ;;
      -Wl,--version-script=*) : ;; # rustc's temporary export script: drop
      *) out+=("$a") ;;
    esac
  done
  exec "$real" "${out[@]}"
fi

exec "$real" "$@"
