//! Kernel version parsing (misc.c `parse_kversion`).

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct KernelVersion {
    pub major: u8,
    pub minor: u32,
    pub patch: u32,
}

impl KernelVersion {
    pub fn parse(release: &str) -> Option<Self> {
        let mut it = release.split(|c: char| !c.is_ascii_digit());
        // C `%hhu` converts via mod-256 truncation on overflow; parse as u32
        // then cast to u8 to reproduce that instead of failing the parse.
        let major: u8 = it.next()?.parse::<u32>().ok()? as u8;
        let minor: u32 = it.next()?.parse().ok()?;
        let patch: u32 = it.next()?.parse().ok()?;
        Some(Self { major, minor, patch })
    }

    /// Current kernel version via uname(2); zeroed on failure like C.
    pub fn current() -> Self {
        let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
        if unsafe { libc::uname(&mut uts) } == -1 {
            return Self::default();
        }

        let release_bytes: Vec<u8> = uts
            .release
            .iter()
            .copied()
            .map(|c| c as u8)
            .take_while(|&c| c != 0)
            .collect();
        let release = String::from_utf8_lossy(&release_bytes);
        Self::parse(&release).unwrap_or_default()
    }

    /// C comparison used by entry.c: kernel >= major.minor.patch
    pub fn at_least(&self, major: u8, minor: u32, patch: u32) -> bool {
        (self.major, self.minor, self.patch) >= (major, minor, patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_release() {
        let v = KernelVersion::parse("5.4.302-android13-...").unwrap();
        assert_eq!((v.major, v.minor, v.patch), (5, 4, 302));
    }

    #[test]
    fn at_least_semantics() {
        let v = KernelVersion { major: 5, minor: 4, patch: 302 };
        assert!(v.at_least(3, 8, 0));
        assert!(!v.at_least(5, 5, 0));
        assert!(v.at_least(5, 4, 302));
    }
}
