//! RAII wrapper for file descriptors.
//!
//! Provides automatic close-on-drop semantics for raw file descriptors,
//! eliminating manual close() calls and preventing leaks on early returns.

use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, RawFd};

/// RAII wrapper for file descriptors that closes on drop.
///
/// This is similar to `std::os::unix::io::OwnedFd` but available on older
/// Rust versions and works with the raw i32 fd pattern used throughout
/// the codebase.
///
/// # Example
/// ```ignore
/// let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
/// // use fd...
/// // fd automatically closed when it goes out of scope
/// ```
pub struct OwnedFd {
    fd: RawFd,
}

impl OwnedFd {
    /// Create an OwnedFd from a raw file descriptor.
    ///
    /// # Safety
    /// The fd must be a valid, open file descriptor that this OwnedFd
    /// will take ownership of. The fd should not be closed elsewhere.
    pub const unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self { fd }
    }

    /// Create an OwnedFd from a raw fd, returning None if fd is -1.
    ///
    /// This is a convenience for the common pattern where -1 indicates
    /// an error.
    ///
    /// # Safety
    /// If fd >= 0, it must be a valid, open file descriptor.
    pub unsafe fn from_raw_fd_checked(fd: RawFd) -> Option<Self> {
        if fd >= 0 {
            Some(Self { fd })
        } else {
            None
        }
    }

    /// Returns the raw file descriptor without consuming the OwnedFd.
    ///
    /// The caller must ensure not to close the fd while OwnedFd still
    /// owns it.
    pub const fn as_raw_fd(&self) -> RawFd {
        self.fd
    }

    /// Consumes the OwnedFd and returns the raw file descriptor
    /// without closing it.
    ///
    /// After calling this, the caller is responsible for closing the fd.
    pub fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        std::mem::forget(self);
        fd
    }
}

impl AsRawFd for OwnedFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl FromRawFd for OwnedFd {
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self { fd }
    }
}

impl IntoRawFd for OwnedFd {
    fn into_raw_fd(self) -> RawFd {
        let fd = self.fd;
        std::mem::forget(self);
        fd
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_owned_fd_closes_on_drop() {
        let mut fds: [libc::c_int; 2] = [0; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };

        {
            let _owned = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            // fds[0] should still be valid here
            let mut buf = [0u8; 1];
            // Write to fds[1], should work since fds[0] is open
            unsafe { libc::write(fds[1], b"x".as_ptr() as *const _, 1) };
            let n = unsafe { libc::read(fds[0], buf.as_mut_ptr() as *mut _, 1) };
            assert_eq!(n, 1);
        }
        // fds[0] should be closed now

        unsafe { libc::close(fds[1]) };
    }

    #[test]
    fn test_into_raw_fd_prevents_close() {
        let mut fds: [libc::c_int; 2] = [0; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };

        let fd = {
            let owned = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            owned.into_raw_fd()
        };

        // fd should still be valid since into_raw_fd was called
        assert_eq!(fd, fds[0]);

        // Clean up
        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
