use std::fs;

/// Check if a password is present in a blacklist file.
///
/// The file is read as raw bytes so non-UTF-8 passwords compare correctly.
/// Each line is matched against the password as exact bytes. Empty lines
/// and lines starting with `#` are ignored. CRLF line endings are tolerated.
pub fn is_blacklisted(password: &[u8], blacklist_file: &str) -> bool {
    let contents = match fs::read(blacklist_file) {
        Ok(c) => c,
        Err(_) => return false,
    };
    contents
        .split(|&b| b == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .filter(|line| !line.is_empty() && !line.starts_with(b"#"))
        .any(|line| line == password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn matches_exact_entry() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "password").unwrap();
        writeln!(f, "123456").unwrap();
        writeln!(f, "qwerty").unwrap();
        let path = f.path().to_str().unwrap();
        assert!(is_blacklisted(b"password", path));
        assert!(is_blacklisted(b"123456", path));
        assert!(is_blacklisted(b"qwerty", path));
    }

    #[test]
    fn non_matching_password_returns_false() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "password").unwrap();
        let path = f.path().to_str().unwrap();
        assert!(!is_blacklisted(b"unique-passphrase", path));
    }

    #[test]
    fn missing_file_returns_false() {
        assert!(!is_blacklisted(b"password", "/nonexistent/blacklist.txt"));
    }

    #[test]
    fn empty_file_returns_false() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        assert!(!is_blacklisted(b"password", path));
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "# common passwords").unwrap();
        writeln!(f).unwrap();
        writeln!(f, "password").unwrap();
        writeln!(f, "# another comment").unwrap();
        writeln!(f).unwrap();
        let path = f.path().to_str().unwrap();
        assert!(is_blacklisted(b"password", path));
        assert!(!is_blacklisted(b"# common passwords", path));
        assert!(!is_blacklisted(b"", path));
    }

    #[test]
    fn case_sensitive_match() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "password").unwrap();
        let path = f.path().to_str().unwrap();
        assert!(is_blacklisted(b"password", path));
        assert!(!is_blacklisted(b"Password", path));
        assert!(!is_blacklisted(b"PASSWORD", path));
    }

    #[test]
    fn crlf_line_endings_tolerated() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "password\r\n123456\r\n").unwrap();
        let path = f.path().to_str().unwrap();
        assert!(is_blacklisted(b"password", path));
        assert!(is_blacklisted(b"123456", path));
    }

    #[test]
    fn no_trailing_newline() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        write!(f, "password\n123456").unwrap();
        let path = f.path().to_str().unwrap();
        assert!(is_blacklisted(b"123456", path));
    }

    #[test]
    fn non_utf8_password_compared_byte_exact() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0xff, 0xfe, b'a', b'b', b'\n']).unwrap();
        f.write_all(b"password\n").unwrap();
        let path = f.path().to_str().unwrap();
        assert!(is_blacklisted(&[0xff, 0xfe, b'a', b'b'], path));
        assert!(!is_blacklisted(&[0xff, 0xfe, b'a', b'c'], path));
    }

    #[test]
    fn whitespace_in_entry_is_significant() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, " padded ").unwrap();
        let path = f.path().to_str().unwrap();
        assert!(is_blacklisted(b" padded ", path));
        assert!(!is_blacklisted(b"padded", path));
    }

    #[test]
    fn path_is_directory_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        assert!(!is_blacklisted(b"password", path));
    }

    #[test]
    fn empty_password_does_not_match_empty_line() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f).unwrap();
        writeln!(f, "password").unwrap();
        let path = f.path().to_str().unwrap();
        // An empty line is treated as no entry, so an empty password should
        // never match a blank line.
        assert!(!is_blacklisted(b"", path));
    }
}
