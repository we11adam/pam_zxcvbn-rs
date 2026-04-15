use crate::options::Options;

pub struct CheckResult {
    pub passed: bool,
    pub score: u8,
    pub guesses_log10: f64,
    pub feedback_warning: Option<String>,
    pub feedback_suggestions: Vec<String>,
}

pub fn evaluate(password: &str, user_inputs: &[&str], opts: &Options) -> CheckResult {
    let entropy = zxcvbn::zxcvbn(password, user_inputs);

    let score = entropy.score() as u8;
    let guesses_log10 = entropy.guesses_log10();

    let passed = if let Some(min_e) = opts.min_entropy {
        guesses_log10 >= min_e
    } else {
        score >= opts.min_score
    };

    let (warning, suggestions) = match entropy.feedback() {
        Some(fb) => (
            fb.warning().map(|w| w.to_string()),
            fb.suggestions().iter().map(|s| s.to_string()).collect(),
        ),
        None => (None, vec![]),
    };

    CheckResult {
        passed,
        score,
        guesses_log10,
        feedback_warning: warning,
        feedback_suggestions: suggestions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_password() {
        let opts = Options::default();
        let result = evaluate("password", &[], &opts);
        assert!(!result.passed);
        assert!(result.score < 3);
    }

    #[test]
    fn test_strong_password() {
        let opts = Options::default();
        let result = evaluate("correct horse battery staple xkcd", &[], &opts);
        assert!(result.passed);
    }

    #[test]
    fn test_min_entropy_override() {
        let mut opts = Options::default();
        opts.min_entropy = Some(20.0);
        let result = evaluate("correct horse battery staple xkcd", &[], &opts);
        assert!(!result.passed);
    }

    #[test]
    fn test_min_score_zero_passes_everything() {
        let mut opts = Options::default();
        opts.min_score = 0;
        let result = evaluate("a", &[], &opts);
        assert!(result.passed);
    }

    #[test]
    fn test_min_score_four_rejects_mediocre() {
        let mut opts = Options::default();
        opts.min_score = 4;
        let result = evaluate("password123", &[], &opts);
        assert!(!result.passed);
    }

    #[test]
    fn test_min_entropy_zero_passes_everything() {
        let mut opts = Options::default();
        opts.min_entropy = Some(0.0);
        let result = evaluate("a", &[], &opts);
        assert!(result.passed);
        assert!(result.guesses_log10 >= 0.0);
    }

    #[test]
    fn test_min_entropy_overrides_min_score() {
        // "sunshine123" has score < 4 but guesses_log10 > 4.0
        let mut opts = Options::default();
        opts.min_score = 4; // strict score requirement
        opts.min_entropy = Some(4.0); // lenient entropy requirement

        let result_score_only = evaluate("sunshine123", &[], &{
            let mut o = Options::default();
            o.min_score = 4;
            o
        });
        let result_entropy = evaluate("sunshine123", &[], &opts);

        // With score-only at 4, it should fail (password isn't perfect)
        // With min_entropy at 4.0, it should pass (guesses_log10 > 4)
        // This demonstrates min_entropy takes precedence over min_score
        assert!(!result_score_only.passed, "Should fail score=4 check");
        assert!(result_entropy.passed, "Should pass low entropy threshold");
    }

    #[test]
    fn test_user_inputs_weaken_score() {
        let opts = Options::default();
        let without_inputs = evaluate("adam2024secure!", &[], &opts);
        let with_inputs = evaluate("adam2024secure!", &["adam"], &opts);
        // Username as input should reduce the guesses estimate
        assert!(with_inputs.guesses_log10 <= without_inputs.guesses_log10);
    }

    #[test]
    fn test_feedback_present_for_weak_password() {
        let opts = Options::default();
        let result = evaluate("password", &[], &opts);
        assert!(!result.passed);
        // Weak passwords should have feedback
        assert!(
            result.feedback_warning.is_some() || !result.feedback_suggestions.is_empty(),
            "Expected feedback for weak password"
        );
    }

    #[test]
    fn test_score_range() {
        let opts = Options::default();
        let result = evaluate("a", &[], &opts);
        assert!(result.score <= 4);

        let result = evaluate("correct horse battery staple xkcd", &[], &opts);
        assert!(result.score <= 4);
    }

    #[test]
    fn test_single_char_password() {
        let opts = Options::default();
        let result = evaluate("a", &[], &opts);
        assert!(!result.passed);
        assert_eq!(result.score, 0);
    }
}
