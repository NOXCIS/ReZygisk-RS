# ReZygisk-RS Frozen Contracts

Surfaces that must not change without versioning or migration. Everything
else in this repository is RS-owned: correctness is decided by device
evidence (soak / `fast_repro`, maps residue, duck detector, tombstones),
not by parity with any other implementation.

## 1. Ptracer entry point

- Symbol: `entry` (`crates/loader/src/entry.rs`, `#[no_mangle]`)
- Signature: `unsafe extern "C" fn(addr: *mut c_void, size: usize, tango_flag: i32) -> usize`
- Called by the ptracer after injecting `libzygisk.so`; `addr`/`size` are the
  library's mapping, and the returned usize is the `hook_functions()` status
  bitmask the tracer reads back.

## 2. Module ABI (`crates/loader/src/abi.rs`)

- `REZYGISK_API_VERSION = 5` (`c_long`)
- `repr(C)` structs: `AppSpecializeArgsV5`, `ServerSpecializeArgsV1`,
  `JNINativeMethod`
- Field order IS the contract: C Zygisk modules were compiled against these
  layouts and read/write them through raw pointers.

## 3. Zygote JNI overloads (`crates/loader/src/jni_tables.rs`)

- `nativeForkAndSpecialize` variants (Android 5–16+)
- `nativeSpecializeAppProcess` variants
- `nativeForkSystemServer` variants
- Symbol names match Android's `com_android_internal_os_Zygote.cpp`; the
  per-overload spelling (`_l`, `_samsung_q`, ...) is the ART/Android
  contract and is not ours to change.

## 4. PLT hook symbols

Exported with `#[no_mangle]` from `fork_hooks.rs`, installed via PLTI
(`hook_register.rs`):

| Symbol | Backup static | Note |
|--------|---------------|------|
| `fork` | `OLD_FORK` | libandroid_runtime.so |
| `strdup` | `OLD_STRDUP` | libandroid_runtime.so; triggers JNI hook init on `ZygoteInit` |
| `property_get` | `OLD_PROPERTY_GET` | libandroid_runtime.so; unhooked once libart.so appears |
| `pthread_attr_setstacksize` | `OLD_PTHREAD_ATTR_SETSTACKSIZE` | libart.so; self-unmap trigger |
| `_ZNK18FileDescriptorInfo14ReopenOrDetach` | `OLD__ZNK18FileDescriptorInfo14ReopenOrDetach` | C++ mangled; prefix match |

Invariant: `unhook_functions()` returns true only when **all four** restores
succeeded; the self-unmap gate refuses to unmap otherwise (a dangling GOT
entry into an unmapped library is a deferred SIGSEGV and a detection signal).

## 5. Daemon IPC (`crates/ipc`)

- `DaemonSocketAction` enum values (u8 wire discriminants)
- Frame helpers in `stream.rs` (native-endian fixed-size integers, length-
  prefixed strings, fds as SCM_RIGHTS)
- **RS divergences from the original wire:**
  - daemon→monitor reports are one datagram per message (see
    `action.rs::build_set_info_message` for the interleaving failure that
    forced this)
  - mount-ns fd is handed over from the daemon on the reply (see the loader's
    `misc_port::update_mnt_ns`)

## Verification

Any change to a frozen surface requires:

1. Bump `REZYGISK_API_VERSION` if the module ABI changes incompatibly.
2. Device test: `scripts/fast_repro.sh` + `scripts/soak.sh` (libzygisk.so
   unmapped in app processes, no zygote crash loop, quiet logcat).
3. C module compatibility check, if the module ABI was touched.
4. For the trampoline: qemu ABI tests (`trampoline_test.rs`) on both
   aarch64 and armv7 must pass before any device run.
