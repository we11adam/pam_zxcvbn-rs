use pamsm::{pam_module, Pam, PamError, PamFlags, PamServiceModule};
use std::ffi::CString;
use zeroize::Zeroizing;

mod local_users;
mod options;
mod pam_io;
mod strength;

use options::Options;
use pam_io::{LogLevel, PamIo, RealPamIo};

/// PAM_PRELIM_CHECK flag (0x4000) - not exposed by pamsm.
const PAM_PRELIM_CHECK: i32 = 0x4000;
/// PAM_UPDATE_AUTHTOK flag (0x2000) - not exposed by pamsm.
const PAM_UPDATE_AUTHTOK: i32 = 0x2000;

struct PamZxcvbn;

fn log_debug<P: PamIo>(pam: &P, opts: &Options, msg: &str) {
    if opts.debug {
        pam.syslog(LogLevel::Debug, &format!("pam_zxcvbn: {}", msg));
    }
}

fn log_error<P: PamIo>(pam: &P, msg: &str) {
    pam.syslog(LogLevel::Error, &format!("pam_zxcvbn: {}", msg));
}

fn conv_prompt<P: PamIo>(pam: &P, msg: &str) -> Result<Zeroizing<CString>, PamError> {
    match pam.prompt_password(msg)? {
        Some(cstr) => Ok(Zeroizing::new(cstr)),
        None => Err(PamError::CONV_ERR),
    }
}

fn conv_error<P: PamIo>(pam: &P, silent: bool, msg: &str) {
    if !silent {
        pam.show_error(msg);
    }
}

fn conv_info<P: PamIo>(pam: &P, silent: bool, msg: &str) {
    if !silent {
        pam.show_info(msg);
    }
}

/// Prompt the user for a new password and confirm it.
fn prompt_new_password<P: PamIo>(
    pam: &P,
    opts: &Options,
    silent: bool,
) -> Result<Zeroizing<CString>, PamError> {
    let pass1 = conv_prompt(pam, &opts.new_password_prompt())?;
    let pass2 = conv_prompt(pam, &opts.retype_password_prompt())?;

    if pass1 != pass2 {
        conv_error(pam, silent, "Sorry, passwords do not match.");
        return Err(PamError::AUTHTOK_ERR);
    }

    if pass1.as_bytes().is_empty() {
        conv_error(pam, silent, "No password supplied.");
        return Err(PamError::AUTHTOK_ERR);
    }

    Ok(pass1)
}

/// Get the new password from a stacked module's cached authtok.
fn get_cached_password<P: PamIo>(pam: &P) -> Result<Zeroizing<CString>, PamError> {
    match pam.get_cached_authtok() {
        Ok(Some(cstr)) => {
            if cstr.as_bytes().is_empty() {
                Err(PamError::AUTHTOK_ERR)
            } else {
                Ok(Zeroizing::new(cstr))
            }
        }
        Ok(None) => Err(PamError::AUTHTOK_ERR),
        Err(e) => Err(e),
    }
}

/// Score description for debug/info messages.
fn score_description(score: u8) -> &'static str {
    match score {
        0 => "Too guessable: risky password (guesses < 10^3)",
        1 => "Very guessable: protection from throttled online attacks (guesses < 10^6)",
        2 => "Somewhat guessable: protection from unthrottled online attacks (guesses < 10^8)",
        3 => "Safely unguessable: moderate protection from offline slow-hash scenario (guesses < 10^10)",
        4 => "Very unguessable: strong protection from offline slow-hash scenario (guesses >= 10^10)",
        _ => "Unknown score",
    }
}

fn do_chauthtok<P: PamIo>(pam: &P, raw_flags: i32, silent: bool, opts: &Options) -> PamError {
    // On PRELIM_CHECK pass, we have nothing to do.
    if raw_flags & PAM_PRELIM_CHECK != 0 {
        log_debug(pam, opts, "PRELIM_CHECK phase, returning SUCCESS");
        return PamError::SUCCESS;
    }

    // We only act on UPDATE_AUTHTOK.
    if raw_flags & PAM_UPDATE_AUTHTOK == 0 {
        log_debug(
            pam,
            opts,
            "neither PRELIM_CHECK nor UPDATE_AUTHTOK, returning SERVICE_ERR",
        );
        return PamError::SERVICE_ERR;
    }

    log_debug(pam, opts, "UPDATE_AUTHTOK phase");

    // Get the username.
    let username = match pam.get_user() {
        Ok(Some(u)) => u.to_string_lossy().into_owned(),
        Ok(None) => {
            log_error(pam, "cannot determine username");
            return PamError::USER_UNKNOWN;
        }
        Err(e) => {
            log_error(pam, "cannot determine username");
            return e;
        }
    };

    log_debug(pam, opts, &format!("user={}", username));

    // local_users_only: skip strength check for non-local users,
    // but still prompt for password so downstream modules can use use_authtok.
    if opts.local_users_only && !local_users::is_local_user(&username, &opts.local_users_file) {
        log_debug(
            pam,
            opts,
            &format!(
                "user '{}' not found in {}, skipping strength check",
                username, opts.local_users_file
            ),
        );
        // Still obtain and set the password for downstream modules.
        let pass = if opts.use_authtok || opts.use_first_pass {
            match get_cached_password(pam) {
                Ok(p) => p,
                Err(e) => return e,
            }
        } else {
            let cached = if opts.try_first_pass {
                get_cached_password(pam).ok()
            } else {
                None
            };
            match cached {
                Some(p) => p,
                None => {
                    let mut attempt = 0u32;
                    loop {
                        attempt += 1;
                        match prompt_new_password(pam, opts, silent) {
                            Ok(p) => break p,
                            Err(e) => {
                                if attempt >= opts.tries {
                                    return e;
                                }
                                conv_info(pam, silent, "Please try again.");
                            }
                        }
                    }
                }
            }
        };
        match pam.set_authtok(&pass) {
            Ok(()) => return PamError::SUCCESS,
            Err(e) => return e,
        }
    }

    // Determine if we should enforce or just warn.
    let is_root = pam.is_root();
    let enforce = !is_root || opts.enforce_for_root;

    if is_root && !opts.enforce_for_root {
        log_debug(
            pam,
            opts,
            "running as root without enforce_for_root, failures will be warnings",
        );
    }

    // Retry loop.
    let mut attempt = 0u32;
    loop {
        attempt += 1;

        log_debug(pam, opts, &format!("attempt {}/{}", attempt, opts.tries));

        // Obtain the new password.
        let new_pass = if opts.use_authtok {
            // Must use token from a previously stacked module.
            match get_cached_password(pam) {
                Ok(p) => p,
                Err(e) => {
                    log_error(pam, "use_authtok set but no password available");
                    return e;
                }
            }
        } else if opts.use_first_pass {
            // Force use of a previous module's password.
            match get_cached_password(pam) {
                Ok(p) => p,
                Err(e) => {
                    log_debug(pam, opts, "use_first_pass set but no password available");
                    return e;
                }
            }
        } else if opts.try_first_pass && attempt == 1 {
            // Try cached password first, fall back to prompting.
            match get_cached_password(pam) {
                Ok(p) => {
                    log_debug(pam, opts, "using cached password from try_first_pass");
                    p
                }
                Err(_) => {
                    log_debug(pam, opts, "no cached password, prompting user");
                    match prompt_new_password(pam, opts, silent) {
                        Ok(p) => p,
                        Err(e) => {
                            if attempt >= opts.tries {
                                return e;
                            }
                            continue;
                        }
                    }
                }
            }
        } else {
            // Prompt the user.
            match prompt_new_password(pam, opts, silent) {
                Ok(p) => p,
                Err(e) => {
                    if attempt >= opts.tries {
                        return e;
                    }
                    continue;
                }
            }
        };

        // Evaluate password strength. Use a lossy UTF-8 view only for
        // zxcvbn; the original bytes are preserved for set_authtok.
        let mut user_inputs: Vec<&str> = opts
            .user_inputs
            .iter()
            .map(|input| input.as_str())
            .collect();
        user_inputs.push(username.as_str());
        let pw_lossy = Zeroizing::new(String::from_utf8_lossy(new_pass.as_bytes()).into_owned());
        let result = strength::evaluate(&pw_lossy, &user_inputs, opts);

        log_debug(
            pam,
            opts,
            &format!(
                "score={} guesses_log10={:.2} passed={}",
                result.score, result.guesses_log10, result.passed
            ),
        );

        if result.passed {
            log_debug(pam, opts, "password strength check passed");
            // Store the new password for downstream modules.
            match pam.set_authtok(&new_pass) {
                Ok(()) => return PamError::SUCCESS,
                Err(e) => {
                    log_error(pam, "failed to set authtok");
                    return e;
                }
            }
        }

        // Password is too weak.
        let strength_msg = format!(
            "BAD PASSWORD: {} (score={}, log10(guesses)={:.2})",
            score_description(result.score),
            result.score,
            result.guesses_log10,
        );

        if !enforce {
            // Root without enforce_for_root: warn but succeed.
            log_debug(
                pam,
                opts,
                &format!("weak password accepted for root: {}", strength_msg),
            );
            conv_info(pam, silent, &format!("WARNING: {}", strength_msg));
            match pam.set_authtok(&new_pass) {
                Ok(()) => return PamError::SUCCESS,
                Err(e) => return e,
            }
        }

        // Show feedback to the user.
        conv_error(pam, silent, &strength_msg);
        if let Some(warning) = &result.feedback_warning {
            conv_error(pam, silent, &format!("Warning: {}", warning));
        }
        for suggestion in &result.feedback_suggestions {
            conv_info(pam, silent, &format!("Suggestion: {}", suggestion));
        }

        // If we can't retry (use_first_pass/use_authtok), fail immediately.
        if opts.use_first_pass || opts.use_authtok {
            return PamError::AUTHTOK_ERR;
        }

        if attempt >= opts.tries {
            log_debug(
                pam,
                opts,
                &format!("max tries ({}) reached, rejecting", opts.tries),
            );
            return PamError::MAXTRIES;
        }

        conv_info(pam, silent, "Please try again.");
    }
}

impl PamServiceModule for PamZxcvbn {
    fn chauthtok(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        let opts = Options::parse(&args);
        let raw_flags = flags.bits();
        let silent = flags.contains(PamFlags::SILENT);
        let io = RealPamIo::new(&pamh);
        do_chauthtok(&io, raw_flags, silent, &opts)
    }
}

pam_module!(PamZxcvbn);

#[cfg(test)]
mod tests {
    use super::score_description;

    #[test]
    fn score_description_known_values() {
        assert!(score_description(0).contains("Too guessable"));
        assert!(score_description(1).contains("Very guessable"));
        assert!(score_description(2).contains("Somewhat guessable"));
        assert!(score_description(3).contains("Safely unguessable"));
        assert!(score_description(4).contains("Very unguessable"));
    }

    #[test]
    fn score_description_out_of_range() {
        assert_eq!(score_description(5), "Unknown score");
        assert_eq!(score_description(255), "Unknown score");
    }
}

#[cfg(test)]
mod flow_tests {
    use super::pam_io::{LogLevel, PamIo};
    use super::{do_chauthtok, Options, PamError, PAM_PRELIM_CHECK, PAM_UPDATE_AUTHTOK};
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::ffi::CString;
    use std::io::Write;

    const STRONG_PW: &str = "correct horse battery staple xkcd";

    enum UserBehavior {
        Name(CString),
        None,
        Err(PamError),
    }

    struct MockPam {
        user: RefCell<UserBehavior>,
        cached_authtok: RefCell<Option<CString>>,
        prompt_responses: RefCell<VecDeque<Result<Option<CString>, PamError>>>,
        is_root: bool,
        set_authtok_result: RefCell<Result<(), PamError>>,

        syslog: RefCell<Vec<(LogLevel, String)>>,
        prompts: RefCell<Vec<String>>,
        infos: RefCell<Vec<String>>,
        errors: RefCell<Vec<String>>,
        set_authtok_calls: RefCell<Vec<CString>>,
    }

    impl MockPam {
        fn new(username: &str) -> Self {
            Self {
                user: RefCell::new(UserBehavior::Name(CString::new(username).unwrap())),
                cached_authtok: RefCell::new(None),
                prompt_responses: RefCell::new(VecDeque::new()),
                is_root: false,
                set_authtok_result: RefCell::new(Ok(())),
                syslog: RefCell::new(vec![]),
                prompts: RefCell::new(vec![]),
                infos: RefCell::new(vec![]),
                errors: RefCell::new(vec![]),
                set_authtok_calls: RefCell::new(vec![]),
            }
        }

        fn push_password(&self, pw: &str) {
            self.prompt_responses
                .borrow_mut()
                .push_back(Ok(Some(CString::new(pw).unwrap())));
        }

        fn push_password_bytes(&self, pw: &[u8]) {
            self.prompt_responses
                .borrow_mut()
                .push_back(Ok(Some(CString::new(pw).unwrap())));
        }

        fn push_password_pair(&self, pw: &str) {
            self.push_password(pw);
            self.push_password(pw);
        }

        fn push_prompt_err(&self, err: PamError) {
            self.prompt_responses.borrow_mut().push_back(Err(err));
        }

        fn set_cached(&self, pw: &str) {
            *self.cached_authtok.borrow_mut() = Some(CString::new(pw).unwrap());
        }

        fn as_root(mut self) -> Self {
            self.is_root = true;
            self
        }

        fn with_user(self, b: UserBehavior) -> Self {
            *self.user.borrow_mut() = b;
            self
        }
    }

    impl PamIo for MockPam {
        fn syslog(&self, level: LogLevel, msg: &str) {
            self.syslog.borrow_mut().push((level, msg.to_string()));
        }

        fn prompt_password(&self, msg: &str) -> Result<Option<CString>, PamError> {
            self.prompts.borrow_mut().push(msg.to_string());
            self.prompt_responses
                .borrow_mut()
                .pop_front()
                .unwrap_or(Err(PamError::CONV_ERR))
        }

        fn show_info(&self, msg: &str) {
            self.infos.borrow_mut().push(msg.to_string());
        }

        fn show_error(&self, msg: &str) {
            self.errors.borrow_mut().push(msg.to_string());
        }

        fn get_user(&self) -> Result<Option<CString>, PamError> {
            match &*self.user.borrow() {
                UserBehavior::Name(c) => Ok(Some(c.clone())),
                UserBehavior::None => Ok(None),
                UserBehavior::Err(e) => Err(*e),
            }
        }

        fn get_cached_authtok(&self) -> Result<Option<CString>, PamError> {
            Ok(self.cached_authtok.borrow().clone())
        }

        fn set_authtok(&self, authtok: &CString) -> Result<(), PamError> {
            self.set_authtok_calls.borrow_mut().push(authtok.clone());
            *self.set_authtok_result.borrow()
        }

        fn is_root(&self) -> bool {
            self.is_root
        }
    }

    fn passwd_file(users: &[&str]) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for u in users {
            writeln!(f, "{}:x:1000:1000::/home/{}:/bin/bash", u, u).unwrap();
        }
        f
    }

    // -- Flag handling -----------------------------------------------------

    #[test]
    fn prelim_check_returns_success_without_interacting() {
        let mock = MockPam::new("alice");
        let opts = Options::default();
        let rc = do_chauthtok(&mock, PAM_PRELIM_CHECK, false, &opts);
        assert_eq!(rc, PamError::SUCCESS);
        assert!(mock.prompts.borrow().is_empty());
        assert!(mock.set_authtok_calls.borrow().is_empty());
    }

    #[test]
    fn no_update_flag_returns_service_err() {
        let mock = MockPam::new("alice");
        let opts = Options::default();
        let rc = do_chauthtok(&mock, 0, false, &opts);
        assert_eq!(rc, PamError::SERVICE_ERR);
        assert!(mock.prompts.borrow().is_empty());
    }

    #[test]
    fn user_unknown_returns_user_unknown() {
        let mock = MockPam::new("x").with_user(UserBehavior::None);
        let opts = Options::default();
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::USER_UNKNOWN);
    }

    #[test]
    fn get_user_error_is_propagated() {
        let mock = MockPam::new("x").with_user(UserBehavior::Err(PamError::BUF_ERR));
        let opts = Options::default();
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::BUF_ERR);
    }

    // -- Happy / unhappy paths --------------------------------------------

    #[test]
    fn strong_password_accepted_and_authtok_set() {
        let mock = MockPam::new("alice");
        mock.push_password_pair(STRONG_PW);

        let opts = Options::default();
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::SUCCESS);

        let calls = mock.set_authtok_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].as_bytes(), STRONG_PW.as_bytes());
        assert_eq!(mock.prompts.borrow().len(), 2);
    }

    #[test]
    fn weak_password_exhausts_retries_returns_maxtries() {
        let mock = MockPam::new("alice");
        mock.push_password_pair("password");
        mock.push_password_pair("123456");

        let mut opts = Options::default();
        opts.tries = 2;
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::MAXTRIES);
        assert!(mock.set_authtok_calls.borrow().is_empty());
    }

    #[test]
    fn weak_then_strong_retries_and_succeeds() {
        let mock = MockPam::new("alice");
        mock.push_password_pair("password");
        mock.push_password_pair(STRONG_PW);

        let mut opts = Options::default();
        opts.tries = 2;
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::SUCCESS);
        assert_eq!(mock.set_authtok_calls.borrow().len(), 1);
    }

    #[test]
    fn password_mismatch_retries_and_succeeds() {
        let mock = MockPam::new("alice");
        // First attempt: mismatch.
        mock.push_password("typo1");
        mock.push_password("typo2");
        // Second attempt: match + strong.
        mock.push_password_pair(STRONG_PW);

        let mut opts = Options::default();
        opts.tries = 2;
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::SUCCESS);
    }

    #[test]
    fn password_mismatch_exhausts_returns_authtok_err() {
        let mock = MockPam::new("alice");
        mock.push_password("a");
        mock.push_password("b");

        let opts = Options::default(); // tries=1
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::AUTHTOK_ERR);
    }

    #[test]
    fn empty_password_is_rejected() {
        let mock = MockPam::new("alice");
        mock.push_password("");
        mock.push_password("");

        let opts = Options::default();
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::AUTHTOK_ERR);
    }

    // -- use_authtok / use_first_pass / try_first_pass --------------------

    #[test]
    fn use_authtok_reuses_cached_password() {
        let mock = MockPam::new("alice");
        mock.set_cached(STRONG_PW);

        let mut opts = Options::default();
        opts.use_authtok = true;
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::SUCCESS);
        // No prompts when use_authtok is set.
        assert!(mock.prompts.borrow().is_empty());
        assert_eq!(
            mock.set_authtok_calls.borrow()[0].as_bytes(),
            STRONG_PW.as_bytes()
        );
    }

    #[test]
    fn use_authtok_without_cached_fails() {
        let mock = MockPam::new("alice");
        let mut opts = Options::default();
        opts.use_authtok = true;
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::AUTHTOK_ERR);
    }

    #[test]
    fn use_authtok_with_weak_cached_fails_without_retry() {
        let mock = MockPam::new("alice");
        mock.set_cached("password");
        let mut opts = Options::default();
        opts.use_authtok = true;
        opts.tries = 5; // ignored in this path
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::AUTHTOK_ERR);
        // No prompts — can't change the cached token.
        assert!(mock.prompts.borrow().is_empty());
    }

    #[test]
    fn use_first_pass_requires_cached() {
        let mock = MockPam::new("alice");
        let mut opts = Options::default();
        opts.use_first_pass = true;
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::AUTHTOK_ERR);
        assert!(mock.prompts.borrow().is_empty());
    }

    #[test]
    fn try_first_pass_uses_cached_when_available() {
        let mock = MockPam::new("alice");
        mock.set_cached(STRONG_PW);
        let mut opts = Options::default();
        opts.try_first_pass = true;
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::SUCCESS);
        assert!(mock.prompts.borrow().is_empty());
    }

    #[test]
    fn try_first_pass_without_cached_prompts() {
        let mock = MockPam::new("alice");
        mock.push_password_pair(STRONG_PW);
        let mut opts = Options::default();
        opts.try_first_pass = true;
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::SUCCESS);
        assert_eq!(mock.prompts.borrow().len(), 2);
    }

    /// Regression: try_first_pass with no cached token used to return on
    /// the first prompt mismatch regardless of opts.tries.
    #[test]
    fn try_first_pass_retries_prompt_mismatch() {
        let mock = MockPam::new("alice");
        // No cached token. Prompt 1: mismatch. Prompt 2: match + strong.
        mock.push_password("typo1");
        mock.push_password("typo2");
        mock.push_password_pair(STRONG_PW);

        let mut opts = Options::default();
        opts.try_first_pass = true;
        opts.tries = 2;
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::SUCCESS);
    }

    // -- local_users_only --------------------------------------------------

    #[test]
    fn local_users_only_skips_strength_check_for_nonlocal_user() {
        let file = passwd_file(&["root", "otheruser"]);
        let mock = MockPam::new("alice");
        // "password" is weak, but strength check is skipped.
        mock.push_password_pair("password");

        let mut opts = Options::default();
        opts.local_users_only = true;
        opts.local_users_file = file.path().to_string_lossy().into_owned();
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::SUCCESS);
        assert_eq!(mock.set_authtok_calls.borrow()[0].as_bytes(), b"password");
    }

    /// Regression: the local_users_only skip path used to return on the
    /// first prompt mismatch regardless of opts.tries.
    #[test]
    fn local_users_only_nonlocal_retries_prompt_mismatch() {
        let file = passwd_file(&["root"]);
        let mock = MockPam::new("alice");
        mock.push_password("typo1");
        mock.push_password("typo2");
        mock.push_password_pair("whatever");

        let mut opts = Options::default();
        opts.local_users_only = true;
        opts.local_users_file = file.path().to_string_lossy().into_owned();
        opts.tries = 2;
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::SUCCESS);
    }

    #[test]
    fn local_users_only_runs_strength_check_for_local_user() {
        let file = passwd_file(&["alice"]);
        let mock = MockPam::new("alice");
        mock.push_password_pair("password");

        let mut opts = Options::default();
        opts.local_users_only = true;
        opts.local_users_file = file.path().to_string_lossy().into_owned();
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::MAXTRIES);
    }

    // -- root / enforce_for_root ------------------------------------------

    #[test]
    fn root_without_enforce_warns_and_succeeds_on_weak_password() {
        let mock = MockPam::new("alice").as_root();
        mock.push_password_pair("password");

        let opts = Options::default(); // enforce_for_root=false by default
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::SUCCESS);

        let infos = mock.infos.borrow();
        assert!(
            infos.iter().any(|m| m.starts_with("WARNING:")),
            "expected a WARNING info message, got {:?}",
            *infos
        );
        assert_eq!(mock.set_authtok_calls.borrow().len(), 1);
    }

    #[test]
    fn root_with_enforce_rejects_weak_password() {
        let mock = MockPam::new("alice").as_root();
        mock.push_password_pair("password");

        let mut opts = Options::default();
        opts.enforce_for_root = true;
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::MAXTRIES);
    }

    // -- Silent mode ------------------------------------------------------

    #[test]
    fn silent_flag_suppresses_conv_messages() {
        let mock = MockPam::new("alice");
        mock.push_password_pair("password");

        let opts = Options::default();
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, true, &opts);
        assert_eq!(rc, PamError::MAXTRIES);
        assert!(
            mock.infos.borrow().is_empty(),
            "infos leaked under silent: {:?}",
            mock.infos.borrow()
        );
        assert!(
            mock.errors.borrow().is_empty(),
            "errors leaked under silent: {:?}",
            mock.errors.borrow()
        );
    }

    // -- Byte preservation ------------------------------------------------

    /// Regression: non-UTF-8 password bytes used to be replaced with U+FFFD
    /// via to_string_lossy before being written back to set_authtok.
    #[test]
    fn non_utf8_password_bytes_passed_through_to_authtok() {
        let bytes: &[u8] = &[0xff, 0xfe, 0xfd, b'a', b'b', b'c', b'd'];
        let mock = MockPam::new("alice");
        mock.push_password_bytes(bytes);
        mock.push_password_bytes(bytes);

        let mut opts = Options::default();
        // Accept any non-empty password so the strength check doesn't block us.
        opts.min_score = 0;
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::SUCCESS);

        let calls = mock.set_authtok_calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].as_bytes(), bytes);
    }

    // -- Prompt cancelation -----------------------------------------------

    #[test]
    fn conv_error_propagates_from_prompt() {
        let mock = MockPam::new("alice");
        mock.push_prompt_err(PamError::CONV_ERR);

        let opts = Options::default();
        let rc = do_chauthtok(&mock, PAM_UPDATE_AUTHTOK, false, &opts);
        assert_eq!(rc, PamError::CONV_ERR);
    }
}
