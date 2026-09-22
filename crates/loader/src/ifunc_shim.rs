//! Port of loader/src/common/ifunc_shim.c — arm32-only (Tango) hidden
//! implementations of the libc string/memory primitives.
//!
//! Tango (a binary translator) runs 32-bit ARM app_process on aarch64-only
//! devices. During injection into that 32-bit process, IFUNC symbols cannot
//! be resolved from the 64-bit ptrace host, because that would require
//! executing the ARM32 IFUNC resolver. The C shim lets the linker resolve
//! `memcpy` & co. locally — without importing them from libc.so — so the
//! remote CSOLoader never has to handle IFUNC resolution for these symbols.
//! The `_chk` variants are shimmed for the same reason (`_FORTIFY_SOURCE`
//! rewrites calls to them in the C build).
//!
//! The `#[unsafe(no_mangle)]` wrappers are compiled only for
//! `armv7-linux-androideabi`; `exports.map` then localizes them (the C marks
//! them `visibility("hidden")`), which is what makes intra-object references
//! bind to these definitions instead of libc's preemptible IFUNC symbols.
//!
//! Recursion note: LLVM's loop-idiom pass will not turn byte-copy loops into
//! `memcpy`/`memmove`/`memset` calls inside functions carrying those exact
//! names, so the `memcpy`/`memmove` wrappers below stay self-contained. The
//! `__memset_chk` loop lowering to a `memset` call is harmless — that
//! resolves to compiler-builtins' local `memset`, not `__memset_chk` itself.

use std::ffi::{c_char, c_int};
#[cfg(all(target_os = "android", target_arch = "arm"))]
use std::ffi::c_void;

// ---------------------------------------------------------------------------
// Implementations (kept on every target so host tests exercise the exact
// C loop semantics; the C-ABI wrappers below are arm32-only).
// ---------------------------------------------------------------------------

#[cfg_attr(not(all(target_os = "android", target_arch = "arm")), allow(dead_code))]
fn memcpy_impl(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            *dst.add(i) = *src.add(i);
        }
    }
    dst
}

#[cfg_attr(not(all(target_os = "android", target_arch = "arm")), allow(dead_code))]
fn memmove_impl(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // C compares `d < s` on the raw pointers; the usize cast reproduces that
    // numeric comparison.
    let d = dst as usize;
    let s = src as usize;
    if d < s {
        for i in 0..n {
            unsafe {
                *dst.add(i) = *src.add(i);
            }
        }
    } else if d > s {
        for i in (0..n).rev() {
            unsafe {
                *dst.add(i) = *src.add(i);
            }
        }
    }
    dst
}

#[cfg_attr(not(all(target_os = "android", target_arch = "arm")), allow(dead_code))]
fn strcpy_impl(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    let mut d = dst;
    let mut s = src;
    loop {
        unsafe {
            *d = *s;
            if *s == 0 {
                break;
            }
        }
        d = unsafe { d.add(1) };
        s = unsafe { s.add(1) };
    }
    dst
}

#[cfg_attr(not(all(target_os = "android", target_arch = "arm")), allow(dead_code))]
fn memset_chk_impl(dst: *mut u8, c: c_int, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            *dst.add(i) = c as u8;
        }
    }
    dst
}

#[cfg_attr(not(all(target_os = "android", target_arch = "arm")), allow(dead_code))]
fn strcmp_impl(s1: *const u8, s2: *const u8) -> c_int {
    let mut p1 = s1;
    let mut p2 = s2;
    loop {
        let a = unsafe { *p1 };
        let b = unsafe { *p2 };
        if a == 0 || a != b {
            return a as c_int - b as c_int;
        }
        p1 = unsafe { p1.add(1) };
        p2 = unsafe { p2.add(1) };
    }
}

#[cfg_attr(not(all(target_os = "android", target_arch = "arm")), allow(dead_code))]
fn strncmp_impl(s1: *const u8, s2: *const u8, n: usize) -> c_int {
    for i in 0..n {
        let a = unsafe { *s1.add(i) };
        let b = unsafe { *s2.add(i) };
        if a != b {
            return a as c_int - b as c_int;
        }
        if a == 0 {
            return 0;
        }
    }
    0
}

#[cfg_attr(not(all(target_os = "android", target_arch = "arm")), allow(dead_code))]
fn memcmp_impl(s1: *const u8, s2: *const u8, n: usize) -> c_int {
    for i in 0..n {
        let a = unsafe { *s1.add(i) };
        let b = unsafe { *s2.add(i) };
        if a != b {
            return a as c_int - b as c_int;
        }
    }
    0
}

#[cfg_attr(not(all(target_os = "android", target_arch = "arm")), allow(dead_code))]
fn strstr_impl(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    if unsafe { *needle } == 0 {
        return haystack as *mut c_char;
    }

    let mut h = haystack;
    while unsafe { *h } != 0 {
        let mut hi = h;
        let mut n = needle;
        loop {
            let hc = unsafe { *hi };
            let nc = unsafe { *n };
            if hc == 0 || nc == 0 || hc != nc {
                break;
            }
            hi = unsafe { hi.add(1) };
            n = unsafe { n.add(1) };
        }
        if unsafe { *n } == 0 {
            return h as *mut c_char;
        }
        h = unsafe { h.add(1) };
    }
    std::ptr::null_mut()
}

// ---------------------------------------------------------------------------
// C-ABI shims (arm32 Android only; localized by exports.map).
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "android", target_arch = "arm"))]
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    memcpy_impl(dst as *mut u8, src as *const u8, n) as *mut c_void
}

#[cfg(all(target_os = "android", target_arch = "arm"))]
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut c_void, src: *const c_void, n: usize) -> *mut c_void {
    memmove_impl(dst as *mut u8, src as *const u8, n) as *mut c_void
}

#[cfg(all(target_os = "android", target_arch = "arm"))]
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcpy(dst: *mut c_char, src: *const c_char) -> *mut c_char {
    strcpy_impl(dst, src)
}

#[cfg(all(target_os = "android", target_arch = "arm"))]
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __strcpy_chk(
    dst: *mut c_char,
    src: *const c_char,
    _dst_len: usize,
) -> *mut c_char {
    strcpy_impl(dst, src)
}

#[cfg(all(target_os = "android", target_arch = "arm"))]
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __memset_chk(
    dst: *mut c_void,
    c: c_int,
    n: usize,
    _dst_len: usize,
) -> *mut c_void {
    memset_chk_impl(dst as *mut u8, c, n) as *mut c_void
}

#[cfg(all(target_os = "android", target_arch = "arm"))]
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcmp(s1: *const c_char, s2: *const c_char) -> c_int {
    strcmp_impl(s1 as *const u8, s2 as *const u8)
}

#[cfg(all(target_os = "android", target_arch = "arm"))]
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncmp(s1: *const c_char, s2: *const c_char, n: usize) -> c_int {
    strncmp_impl(s1 as *const u8, s2 as *const u8, n)
}

#[cfg(all(target_os = "android", target_arch = "arm"))]
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(s1: *const c_void, s2: *const c_void, n: usize) -> c_int {
    memcmp_impl(s1 as *const u8, s2 as *const u8, n)
}

#[cfg(all(target_os = "android", target_arch = "arm"))]
#[inline(never)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strstr(haystack: *const c_char, needle: *const c_char) -> *mut c_char {
    strstr_impl(haystack, needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cstr(s: &[u8]) -> Vec<u8> {
        let mut v = s.to_vec();
        v.push(0);
        v
    }

    #[test]
    fn memcpy_basic() {
        let src = cstr(b"hello world");
        let mut dst = vec![0u8; src.len()];
        memcpy_impl(dst.as_mut_ptr(), src.as_ptr(), src.len());
        assert_eq!(&dst[..src.len() - 1], b"hello world");
        assert_eq!(&dst[src.len() - 1..], &[0]);
    }

    #[test]
    fn memcpy_zero_len() {
        let src = [1u8, 2, 3];
        let mut dst = [9u8; 3];
        memcpy_impl(dst.as_mut_ptr(), src.as_ptr(), 0);
        assert_eq!(dst, [9, 9, 9]);
    }

    #[test]
    fn memmove_overlap_forward() {
        // dst < src: forward copy keeps earlier bytes intact.
        let mut buf = [1u8, 2, 3, 4, 5];
        let src = unsafe { buf.as_ptr().add(1) };
        memmove_impl(buf.as_mut_ptr(), src, 4);
        assert_eq!(buf, [2, 3, 4, 5, 5]);
    }

    #[test]
    fn memmove_overlap_backward() {
        // dst > src: backward copy avoids clobbering the source.
        let mut buf = [1u8, 2, 3, 4, 5];
        let dst = unsafe { buf.as_mut_ptr().add(1) };
        memmove_impl(dst, buf.as_ptr(), 4);
        assert_eq!(buf, [1, 1, 2, 3, 4]);
    }

    #[test]
    fn strcpy_full() {
        let src = cstr(b"zygisk");
        let mut dst = vec![0u8; src.len() + 4];
        strcpy_impl(dst.as_mut_ptr() as *mut c_char, src.as_ptr() as *const c_char);
        assert_eq!(&dst[..7], b"zygisk\0");
    }

    #[test]
    fn strcpy_empty() {
        let src = [0u8];
        let mut dst = [b'x' as c_char; 2];
        strcpy_impl(dst.as_mut_ptr(), src.as_ptr() as *const c_char);
        assert_eq!(dst[0], 0);
    }

    #[test]
    fn memset_chk_ignores_dst_len() {
        let mut buf = [1u8; 5];
        memset_chk_impl(buf.as_mut_ptr(), 0xab, 3);
        assert_eq!(buf, [0xab, 0xab, 0xab, 1, 1]);
    }

    #[test]
    fn strcmp_ordering() {
        let a = cstr(b"abc");
        let b = cstr(b"abd");
        let c = cstr(b"abc");
        assert!(strcmp_impl(a.as_ptr(), b.as_ptr()) < 0);
        assert!(strcmp_impl(b.as_ptr(), a.as_ptr()) > 0);
        assert_eq!(strcmp_impl(a.as_ptr(), c.as_ptr()), 0);
    }

    #[test]
    fn strcmp_prefix_is_less() {
        let a = cstr(b"ab");
        let b = cstr(b"abc");
        assert!(strcmp_impl(a.as_ptr(), b.as_ptr()) < 0);
    }

    #[test]
    fn strncmp_limits_and_early_nul() {
        let a = cstr(b"abz");
        let b = cstr(b"aby");
        assert_eq!(strncmp_impl(a.as_ptr(), b.as_ptr(), 2), 0);
        assert!(strncmp_impl(a.as_ptr(), b.as_ptr(), 3) > 0);
        // Both strings end at index 2: the C returns 0 once a shared NUL is
        // reached, even when `n` extends past it.
        let c = cstr(b"ab");
        assert_eq!(strncmp_impl(c.as_ptr(), c.as_ptr(), 5), 0);
        // A NUL vs a non-NUL differs (C: *p1 - *p2 = -'y').
        let d = cstr(b"aby");
        assert_eq!(strncmp_impl(c.as_ptr(), d.as_ptr(), 5), -(b'y' as c_int));
    }

    #[test]
    fn memcmp_vectors() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 4];
        assert!(memcmp_impl(a.as_ptr(), b.as_ptr(), 3) < 0);
        assert!(memcmp_impl(b.as_ptr(), a.as_ptr(), 3) > 0);
        assert_eq!(memcmp_impl(a.as_ptr(), a.as_ptr(), 3), 0);
        assert_eq!(memcmp_impl(a.as_ptr(), b.as_ptr(), 2), 0);
    }

    #[test]
    fn strstr_finds_and_empties() {
        let h = cstr(b"the zygisk module");
        let n = cstr(b"zygisk");
        let found = strstr_impl(h.as_ptr() as *const c_char, n.as_ptr() as *const c_char);
        assert_eq!(found, unsafe { h.as_ptr().add(4) } as *mut c_char);

        let miss = cstr(b"zygote");
        assert!(
            strstr_impl(h.as_ptr() as *const c_char, miss.as_ptr() as *const c_char).is_null()
        );

        // Empty needle matches at the start (C: return haystack).
        let empty = [0u8];
        let at_start = strstr_impl(h.as_ptr() as *const c_char, empty.as_ptr() as *const c_char);
        assert_eq!(at_start, h.as_ptr() as *mut c_char);
    }

    #[test]
    fn strstr_needle_longer_than_haystack() {
        let h = cstr(b"ab");
        let n = cstr(b"abcd");
        assert!(
            strstr_impl(h.as_ptr() as *const c_char, n.as_ptr() as *const c_char).is_null()
        );
    }
}
