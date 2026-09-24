# ReZygisk-RS

This repository was a **working proof of concept**: a Rust port of ReZygisk that actually ran on device.

That said, the code is **unholy and cursed**. It was written to prove the idea, not to be maintainable. Do not copy its architecture.

## Why it's unholy

- **C with a Rust accent.** Large parts are a faithful reshape of the original C/C++ ReZygisk surface — `repr(C)` ABI mirrors, PLT symbol names, zygote JNI overload tables spanning Android 5–16+ (plus vendor spellings) — not a design that starts from Rust's strengths.
- **Unsafe is the product.** The loader lives inside zygote via PLT interposition (`fork`, `strdup`, `property_get`, `pthread_attr_setstacksize`, a mangled C++ method), function-pointer `transmute`s, and a **naked assembly trampoline** that unmaps `libzygisk.so` from under its own return path.
- **It pokes C++ memory by hand.** Hooks walk `FileDescriptorInfo` with `offset_of!` and parse libc++ `std::string` SSO layouts in Rust (`cpp_strings`) because there is no safe boundary to stand behind.
- **A linker inside the process.** `csoloader` is a custom in-process ELF loader/relocator so modules can be brought up (and torn down) without a normal `dlopen` story. That is a second operating system living in the zygote address space.
- **Correctness is soak-or-die.** Frozen contracts are whatever the device still boots after (`fast_repro` / soak / maps residue / duck detector). The type system is not the oracle; a quiet logcat is.

It works. That does not make it holy.

## What comes next

The lessons learned from this experiment are being used to develop a proper Rust Zygisk implementation in [`zygisk-rs`](../zygisk-rs).

Treat this tree as historical / reference material. New work belongs there.
