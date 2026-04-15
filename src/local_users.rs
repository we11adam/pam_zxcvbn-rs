use std::fs;

/// Check if a username exists in a passwd-style file.
/// Each line format: username:x:uid:gid:gecos:home:shell
pub fn is_local_user(username: &str, passwd_file: &str) -> bool {
    match fs::read_to_string(passwd_file) {
        Ok(contents) => contents
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .any(|line| line.split(':').next() == Some(username)),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_is_local_user() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "root:x:0:0:root:/root:/bin/bash").unwrap();
        writeln!(tmpfile, "testuser:x:1000:1000:Test:/home/test:/bin/bash").unwrap();
        writeln!(tmpfile, "# comment line").unwrap();

        let path = tmpfile.path().to_str().unwrap();
        assert!(is_local_user("root", path));
        assert!(is_local_user("testuser", path));
        assert!(!is_local_user("nobody", path));
    }

    #[test]
    fn test_missing_file() {
        assert!(!is_local_user("root", "/nonexistent/file"));
    }

    #[test]
    fn test_empty_file() {
        let tmpfile = tempfile::NamedTempFile::new().unwrap();
        let path = tmpfile.path().to_str().unwrap();
        assert!(!is_local_user("root", path));
    }

    #[test]
    fn test_empty_lines_ignored() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "").unwrap();
        writeln!(tmpfile, "root:x:0:0:root:/root:/bin/bash").unwrap();
        writeln!(tmpfile, "").unwrap();

        let path = tmpfile.path().to_str().unwrap();
        assert!(is_local_user("root", path));
    }

    #[test]
    fn test_prefix_username_no_false_positive() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "testuser:x:1000:1000:Test:/home/test:/bin/bash").unwrap();

        let path = tmpfile.path().to_str().unwrap();
        // "test" is a prefix of "testuser" but should NOT match
        assert!(!is_local_user("test", path));
        assert!(is_local_user("testuser", path));
    }

    #[test]
    fn test_username_in_other_fields_no_match() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "alice:x:1000:1000:bob:/home/bob:/bin/bash").unwrap();

        let path = tmpfile.path().to_str().unwrap();
        // "bob" appears in gecos and home but not as the username
        assert!(!is_local_user("bob", path));
        assert!(is_local_user("alice", path));
    }

    #[test]
    fn test_comment_only_file() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "# This is a comment").unwrap();
        writeln!(tmpfile, "# Another comment").unwrap();

        let path = tmpfile.path().to_str().unwrap();
        assert!(!is_local_user("root", path));
    }

    #[test]
    fn test_no_colon_in_line() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "malformed_line_without_colons").unwrap();

        let path = tmpfile.path().to_str().unwrap();
        // split(':').next() returns the whole line as "username"
        assert!(is_local_user("malformed_line_without_colons", path));
        assert!(!is_local_user("root", path));
    }

    #[test]
    fn test_username_with_leading_hash_treated_as_comment() {
        let mut tmpfile = tempfile::NamedTempFile::new().unwrap();
        writeln!(tmpfile, "#disabled:x:1000:1000::/home/dis:/bin/bash").unwrap();

        let path = tmpfile.path().to_str().unwrap();
        // Line starting with # is treated as comment
        assert!(!is_local_user("#disabled", path));
    }
}
