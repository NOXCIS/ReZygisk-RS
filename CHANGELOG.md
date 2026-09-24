# Changelog

## v1.0.1-rs (516)

- Mount-ns cache invalidation: drop cached clean/mounted ns fds on
  ZygoteRestart and via new Truman action `InvalidateCleanNs`
  (`zygisk-ptrace invalidate-ns`, for ksud recapture/arm after republish)
- Ptracer monitor respawns a dead daemon immediately (bounded 5/30s),
  instead of waiting for the next zygote restart
- Module-table self-heal: empty ReadModules mid-daemon-respawn is retried
  on subsequent forks (bounded), not cached for the zygote lifetime
- GetProcessFlags: one short retry covers a daemon mid-restart so a root
  process is not presented as unmanaged for a whole specialize round
- RS owns its behavior: device evidence (fast_repro / soak / duck detector)
  is the correctness oracle, not parity with the original C implementation
- `docs/CONTRACTS.md`: frozen surfaces (ptracer entry, module ABI v5, zygote
  JNI overloads, PLT hook symbols, daemon wire) plus their verification rules
- Self-unmap trampoline and PLT-restore invariant documented as RS design
- Crate roots and hook-file banners state RS-owned behavior; stale C
  line-number references and `rz_`-prefixed internals dropped
- Safe FFI wrappers (`jni_utils::{JniStringGuard, cstr_to_owned}`,
  `ModuleSnapshot::{get,get_mut,iter,iter_mut}`) replace ~37 raw `unsafe`
  blocks with audited, behavior-identical helpers
- CI: workspace tests + cross-arch check; clippy `-D warnings` clean

## v1.0.0-rs-trumanrs (515)

- Standalone Rust ReZygisk loader + daemon packaging
- Built-in truman_ref reflection-spoof sub-module
- WebUI credits: Noxcis (module), PerformanC (original ReZygisk)
