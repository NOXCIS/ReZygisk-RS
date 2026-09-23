//! cpp_strings.c port: read C++ std::string (libc++ SSO layout) from raw
//! memory — injector/cpp_strings.c + cpp_strings.h.
//! Host-testable; the #[cfg(test)] suite covers short/long modes.
//!
//! libc++ layout:
//! - Short mode (LSB of first byte == 0): size = byte0 >> 1, data at byte 1
//! - Long mode: capacity/size/pointer at platform-specific offsets

/// cpp_strings.c `LONG_SIZE_OFFSET`: byte offset of the size word in a
/// long-mode std::string (`__LP64__`: +8, LP32: +4).
const LONG_SIZE_OFFSET: usize = if cfg!(target_pointer_width = "64") { 8 } else { 4 };

/// cpp_strings.c `LONG_DATA_OFFSET`: byte offset of the data pointer in a
/// long-mode std::string (`__LP64__`: +16, LP32: +8).
const LONG_DATA_OFFSET: usize = if cfg!(target_pointer_width = "64") { 16 } else { 8 };

/// cpp_strings.c `is_short_string`: in libc++ little-endian, the LSB of the
/// first byte is 0 for short (SSO) mode and 1 for long mode. Callers
/// null-check first, like the C.
#[inline]
unsafe fn is_short_string(bytes: *const u8) -> bool {
    unsafe { (*bytes & 1) == 0 }
}

/// cpp_strings.c `get_std_string_length`: size of the std::string (not
/// including any null terminator). Null input returns 0, like the C.
pub fn get_std_string_length(ptr: *const u8) -> usize {
    if ptr.is_null() {
        return 0;
    }

    unsafe {
        if is_short_string(ptr) {
            (*ptr >> 1) as usize
        } else {
            *(ptr.add(LONG_SIZE_OFFSET) as *const usize)
        }
    }
}

/// cpp_strings.c `read_std_string`: the string data. Null input returns
/// `None` (the C returns NULL); the returned slice is valid only as long as
/// the std::string object exists.
///
/// # Safety
/// `ptr` must be null or point to a live libc++ std::string object for `'a`.
pub unsafe fn read_std_string<'a>(ptr: *const u8) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }

    unsafe {
        let data = if is_short_string(ptr) {
            ptr.add(1)
        } else {
            *(ptr.add(LONG_DATA_OFFSET) as *const *const u8)
        };

        // `from_raw_parts` requires a non-null pointer even for an empty
        // slice; the C returns the long-mode pointer field as-is.
        if data.is_null() {
            return None;
        }

        Some(std::slice::from_raw_parts(data, get_std_string_length(ptr)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // libc++ sizeof(std::string): hook.c `STD_STRING_SIZE`.
    const STD_STRING_BYTES: usize = if cfg!(target_pointer_width = "64") { 24 } else { 12 };

    #[test]
    fn null_string() {
        assert_eq!(get_std_string_length(std::ptr::null()), 0);
        assert!(unsafe { read_std_string(std::ptr::null()) }.is_none());
    }

    #[test]
    fn empty_short_string() {
        // libc++ empty string: first byte 0 (size 0 << 1, short mode).
        let obj = vec![0u8; STD_STRING_BYTES];
        assert_eq!(get_std_string_length(obj.as_ptr()), 0);

        let s = unsafe { read_std_string(obj.as_ptr()) }.unwrap();
        assert_eq!(s, b"");
    }

    #[test]
    fn short_string_with_data() {
        let data = b"hello";
        let mut obj = vec![0u8; STD_STRING_BYTES];
        obj[0] = (data.len() << 1) as u8;
        obj[1..1 + data.len()].copy_from_slice(data);

        assert_eq!(get_std_string_length(obj.as_ptr()), data.len());

        let s = unsafe { read_std_string(obj.as_ptr()) }.unwrap();
        assert_eq!(s.as_ptr(), unsafe { obj.as_ptr().add(1) });
        assert_eq!(s, data);
    }

    #[test]
    fn long_string_layout() {
        let data = b"this is a long-mode std::string";

        // Vec<usize> keeps the fake object usize-aligned so the size word and
        // data-pointer reads at LONG_SIZE/LONG_DATA offsets stay aligned.
        let mut obj = vec![0usize; 4];
        let ptr = obj.as_mut_ptr() as *mut u8;
        unsafe {
            *ptr = 1; // long-mode flag bit
            *(ptr.add(LONG_SIZE_OFFSET) as *mut usize) = data.len();
            *(ptr.add(LONG_DATA_OFFSET) as *mut *const u8) = data.as_ptr();
        }

        assert_eq!(get_std_string_length(ptr), data.len());

        let s = unsafe { read_std_string(ptr) }.unwrap();
        assert_eq!(s.as_ptr(), data.as_ptr());
        assert_eq!(s, data);
    }
}
