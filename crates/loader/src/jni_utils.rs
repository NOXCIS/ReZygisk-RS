//! Safe wrappers for the raw-pointer FFI boundaries the loader crosses:
//! JNI string access ([`JniStringGuard`]) and C string pointers
//! ([`cstr_to_owned`]).
//!
//! These wrappers encapsulate unsafe FFI calls behind safe Rust APIs,
//! centralizing the safety invariants in one audited location.

use std::ffi::CStr;

use libc::c_char;

const TAG: &str = rz_common::LOG_TAG;

/// Copies a nullable C string pointer into an owned `String`.
///
/// Returns `None` for a null pointer. Unlike `CStr::from_ptr` the borrow ends
/// inside this function — the result is owned — so callers need no `unsafe`
/// block and cannot outlive the pointer's storage.
pub fn cstr_to_owned(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }

    // SAFETY: FFI boundary contract — the C callers pass NULL or a
    // NUL-terminated string that stays valid for the duration of this call.
    // The reference never escapes (`to_string_lossy` borrows only until
    // `into_owned` copies).
    Some(unsafe { CStr::from_ptr(ptr) }.to_string_lossy().into_owned())
}

/// RAII guard for JNI string access via GetStringUTFChars/ReleaseStringUTFChars.
///
/// Automatically releases the string buffer when dropped, preventing leaks
/// and ensuring the get/release calls are always balanced.
///
/// # Example
/// ```ignore
/// let Some(guard) = JniStringGuard::new(env, jstr) else {
///     return; // GetStringUTFChars failed
/// };
/// let path = guard.as_cstr().to_string_lossy();
/// // guard auto-releases on drop
/// ```
pub struct JniStringGuard {
    env: *mut jni::sys::JNIEnv,
    jstr: jni::sys::jstring,
    chars: *const c_char,
}

impl JniStringGuard {
    /// Creates a new guard by calling GetStringUTFChars.
    ///
    /// Returns `None` if:
    /// - The JNIEnv vtable entry for GetStringUTFChars is missing
    /// - GetStringUTFChars returns NULL (OOM or pending exception)
    ///
    /// # Safety
    /// The caller must ensure:
    /// - `env` is a valid JNIEnv pointer from the Android runtime
    /// - `jstr` is a valid jstring (may be null, which returns None)
    pub fn new(env: *mut jni::sys::JNIEnv, jstr: jni::sys::jstring) -> Option<Self> {
        if env.is_null() || jstr.is_null() {
            return None;
        }

        // SAFETY: env is valid per caller contract; we check the vtable entry
        let get_chars = unsafe { (**env).GetStringUTFChars }?;

        // SAFETY: env and jstr are valid, get_chars is a valid function pointer
        let chars = unsafe { get_chars(env, jstr, std::ptr::null_mut()) };
        if chars.is_null() {
            return None;
        }

        Some(Self { env, jstr, chars })
    }

    /// Returns the string as a CStr reference.
    ///
    /// The returned reference is valid for the lifetime of this guard.
    pub fn as_cstr(&self) -> &CStr {
        // SAFETY: chars is a valid NUL-terminated string from GetStringUTFChars,
        // and remains valid until ReleaseStringUTFChars is called in drop()
        unsafe { CStr::from_ptr(self.chars) }
    }

    /// Returns the raw pointer to the string data.
    ///
    /// Useful for passing to C APIs that expect `const char*`.
    pub fn as_ptr(&self) -> *const c_char {
        self.chars
    }
}

impl Drop for JniStringGuard {
    fn drop(&mut self) {
        // SAFETY: env, jstr, chars are all valid from new().
        // This balances the GetStringUTFChars call.
        let release = unsafe { (**self.env).ReleaseStringUTFChars };
        match release {
            Some(release_fn) => unsafe { release_fn(self.env, self.jstr, self.chars) },
            None => rz_common::loge!(TAG, "JNIEnv::ReleaseStringUTFChars is unavailable"),
        }
    }
}

// SAFETY: JniStringGuard is not Send/Sync because:
// - JNIEnv pointers are thread-local in Android
// - The jstring may be a local reference that's thread-bound
// These are intentionally NOT implemented.

#[cfg(test)]
mod tests {
    // JNI tests would require an actual Android runtime, so we just
    // verify the struct is the expected size and alignment.
    use super::*;

    #[test]
    fn guard_size() {
        assert_eq!(
            std::mem::size_of::<JniStringGuard>(),
            3 * std::mem::size_of::<*const ()>()
        );
    }
}
