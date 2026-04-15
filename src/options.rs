/// PAM module configuration options parsed from the module arguments.
pub struct Options {
    pub debug: bool,
    pub tries: u32,
    pub min_score: u8,
    pub min_entropy: Option<f64>,
    pub use_inputs: Vec<String>,
    pub enforce_for_root: bool,
    pub local_users_only: bool,
    pub local_users_file: String,
    pub authtok_type: String,
    pub try_first_pass: bool,
    pub use_first_pass: bool,
    pub use_authtok: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            debug: false,
            tries: 1,
            min_score: 3,
            min_entropy: None,
            use_inputs: vec![],
            enforce_for_root: false,
            local_users_only: false,
            local_users_file: "/etc/passwd".to_string(),
            authtok_type: String::new(),
            try_first_pass: false,
            use_first_pass: false,
            use_authtok: false,
        }
    }
}

impl Options {
    pub fn parse(args: &[String]) -> Self {
        let mut opts = Self::default();

        for arg in args {
            if let Some((key, value)) = arg.split_once('=') {
                match key {
                    "tries" | "retry" => {
                        if let Ok(n) = value.parse::<u32>() {
                            opts.tries = n.max(1);
                        }
                    }
                    "min_score" => {
                        if let Ok(n) = value.parse::<u8>() {
                            opts.min_score = n.min(4);
                        }
                    }
                    "min_entropy" => {
                        if let Ok(f) = value.parse::<f64>() {
                            if f.is_finite() && f >= 0.0 {
                                opts.min_entropy = Some(f);
                            }
                        }
                    }
                    "user_inputs" => {
                        opts.use_inputs = value
                            .split(",")
                            .map(|input| input.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect();
                    }
                    "local_users_file" => {
                        opts.local_users_file = value.to_string();
                    }
                    "authtok_type" => {
                        opts.authtok_type = value.to_string();
                    }
                    _ => {}
                }
            } else {
                match arg.as_str() {
                    "debug" => opts.debug = true,
                    "enforce_for_root" => opts.enforce_for_root = true,
                    "local_users_only" => opts.local_users_only = true,
                    "try_first_pass" => opts.try_first_pass = true,
                    "use_first_pass" => opts.use_first_pass = true,
                    "use_authtok" => opts.use_authtok = true,
                    _ => {}
                }
            }
        }

        opts
    }

    /// Build the password prompt string.
    /// e.g. "New UNIX password: " or "New password: " if authtok_type is empty.
    pub fn new_password_prompt(&self) -> String {
        if self.authtok_type.is_empty() {
            "New password: ".to_string()
        } else {
            format!("New {} password: ", self.authtok_type)
        }
    }

    /// Build the retype prompt string.
    pub fn retype_password_prompt(&self) -> String {
        if self.authtok_type.is_empty() {
            "Retype new password: ".to_string()
        } else {
            format!("Retype new {} password: ", self.authtok_type)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let opts = Options::default();
        assert!(!opts.debug);
        assert_eq!(opts.tries, 1);
        assert_eq!(opts.min_score, 3);
        assert!(opts.min_entropy.is_none());
        assert!(!opts.enforce_for_root);
        assert!(!opts.local_users_only);
        assert_eq!(opts.local_users_file, "/etc/passwd");
        assert!(opts.authtok_type.is_empty());
        assert!(!opts.try_first_pass);
        assert!(!opts.use_first_pass);
        assert!(!opts.use_authtok);
    }

    #[test]
    fn test_parse() {
        let args: Vec<String> = vec![
            "debug".into(),
            "tries=3".into(),
            "min_score=2".into(),
            "min_entropy=8.5".into(),
            "enforce_for_root".into(),
            "local_users_only".into(),
            "local_users_file=/etc/passwd.local".into(),
            "authtok_type=UNIX".into(),
            "use_authtok".into(),
        ];
        let opts = Options::parse(&args);
        assert!(opts.debug);
        assert_eq!(opts.tries, 3);
        assert_eq!(opts.min_score, 2);
        assert_eq!(opts.min_entropy, Some(8.5));
        assert!(opts.enforce_for_root);
        assert!(opts.local_users_only);
        assert_eq!(opts.local_users_file, "/etc/passwd.local");
        assert_eq!(opts.authtok_type, "UNIX");
        assert!(opts.use_authtok);
    }

    #[test]
    fn test_retry_alias() {
        let args: Vec<String> = vec!["retry=5".into()];
        let opts = Options::parse(&args);
        assert_eq!(opts.tries, 5);
    }

    #[test]
    fn test_tries_zero_clamped_to_one() {
        let args: Vec<String> = vec!["tries=0".into()];
        let opts = Options::parse(&args);
        assert_eq!(opts.tries, 1);
    }

    #[test]
    fn test_min_score_clamped_to_four() {
        let args: Vec<String> = vec!["min_score=5".into()];
        let opts = Options::parse(&args);
        assert_eq!(opts.min_score, 4);

        let args: Vec<String> = vec!["min_score=255".into()];
        let opts = Options::parse(&args);
        assert_eq!(opts.min_score, 4);
    }

    #[test]
    fn test_min_score_zero_allowed() {
        let args: Vec<String> = vec!["min_score=0".into()];
        let opts = Options::parse(&args);
        assert_eq!(opts.min_score, 0);
    }

    #[test]
    fn test_min_entropy_negative_rejected() {
        let args: Vec<String> = vec!["min_entropy=-1.0".into()];
        let opts = Options::parse(&args);
        assert!(opts.min_entropy.is_none());
    }

    #[test]
    fn test_min_entropy_nan_rejected() {
        let args: Vec<String> = vec!["min_entropy=NaN".into()];
        let opts = Options::parse(&args);
        assert!(opts.min_entropy.is_none());
    }

    #[test]
    fn test_min_entropy_infinity_rejected() {
        let args: Vec<String> = vec!["min_entropy=inf".into()];
        let opts = Options::parse(&args);
        assert!(opts.min_entropy.is_none());
    }

    #[test]
    fn test_min_entropy_zero_allowed() {
        let args: Vec<String> = vec!["min_entropy=0.0".into()];
        let opts = Options::parse(&args);
        assert_eq!(opts.min_entropy, Some(0.0));
    }

    #[test]
    fn test_user_inputs_parse_and_trim() {
        let args: Vec<String> = vec!["user_inputs=company, hostname ,service".into()];
        let opts = Options::parse(&args);
        assert_eq!(opts.use_inputs, vec!["company", "hostname", "service"]);
    }

    #[test]
    fn test_user_inputs_empty_entries_filtered() {
        let args: Vec<String> = vec!["user_inputs=, company, ,hostname,, ".into()];
        let opts = Options::parse(&args);
        assert_eq!(opts.use_inputs, vec!["company", "hostname"]);
    }

    #[test]
    fn test_user_inputs_only_commas_becomes_empty() {
        let args: Vec<String> = vec!["user_inputs=,,,".into()];
        let opts = Options::parse(&args);
        assert!(opts.use_inputs.is_empty());
    }

    #[test]
    fn test_invalid_numeric_values_ignored() {
        let args: Vec<String> = vec![
            "tries=abc".into(),
            "min_score=xyz".into(),
            "min_entropy=not_a_number".into(),
        ];
        let opts = Options::parse(&args);
        assert_eq!(opts.tries, 1); // default
        assert_eq!(opts.min_score, 3); // default
        assert!(opts.min_entropy.is_none()); // default
    }

    #[test]
    fn test_unknown_options_ignored() {
        let args: Vec<String> = vec!["unknown_flag".into(), "unknown_key=value".into()];
        let opts = Options::parse(&args);
        // Should still have defaults
        assert_eq!(opts.tries, 1);
        assert!(!opts.debug);
    }

    #[test]
    fn test_empty_args() {
        let args: Vec<String> = vec![];
        let opts = Options::parse(&args);
        assert_eq!(opts.tries, 1);
        assert_eq!(opts.min_score, 3);
    }

    #[test]
    fn test_try_first_pass_and_use_first_pass() {
        let args: Vec<String> = vec!["try_first_pass".into(), "use_first_pass".into()];
        let opts = Options::parse(&args);
        assert!(opts.try_first_pass);
        assert!(opts.use_first_pass);
    }

    #[test]
    fn test_prompts() {
        let opts = Options::default();
        assert_eq!(opts.new_password_prompt(), "New password: ");
        assert_eq!(opts.retype_password_prompt(), "Retype new password: ");

        let mut opts = Options::default();
        opts.authtok_type = "UNIX".into();
        assert_eq!(opts.new_password_prompt(), "New UNIX password: ");
        assert_eq!(opts.retype_password_prompt(), "Retype new UNIX password: ");
    }

    #[test]
    fn test_authtok_type_with_spaces() {
        let args: Vec<String> = vec!["authtok_type=LDAP AUTH".into()];
        let opts = Options::parse(&args);
        assert_eq!(opts.authtok_type, "LDAP AUTH");
        assert_eq!(opts.new_password_prompt(), "New LDAP AUTH password: ");
    }

    #[test]
    fn test_last_value_wins() {
        let args: Vec<String> = vec!["tries=3".into(), "tries=5".into()];
        let opts = Options::parse(&args);
        assert_eq!(opts.tries, 5);
    }
}
