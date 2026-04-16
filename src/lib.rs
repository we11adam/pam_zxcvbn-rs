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
        let mut user_inputs: Vec<&str> =
            opts.user_inputs.iter().map(|input| input.as_str()).collect();
        user_inputs.push(username.as_str());
        let pw_lossy =
            Zeroizing::new(String::from_utf8_lossy(new_pass.as_bytes()).into_owned());
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
