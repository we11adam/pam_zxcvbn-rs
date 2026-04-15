use pamsm::{
    pam_module, LogLvl, Pam, PamError, PamFlags, PamLibExt, PamMsgStyle, PamServiceModule,
};
use std::ffi::CString;

mod local_users;
mod options;
mod strength;

use options::Options;

/// PAM_PRELIM_CHECK flag (0x4000) - not exposed by pamsm.
const PAM_PRELIM_CHECK: i32 = 0x4000;
/// PAM_UPDATE_AUTHTOK flag (0x2000) - not exposed by pamsm.
const PAM_UPDATE_AUTHTOK: i32 = 0x2000;

struct PamZxcvbn;

fn log_debug(pamh: &Pam, opts: &Options, msg: &str) {
    if opts.debug {
        let _ = pamh.syslog(LogLvl::DEBUG, msg);
    }
}

fn log_err(pamh: &Pam, msg: &str) {
    let _ = pamh.syslog(LogLvl::ERR, msg);
}

fn conv_prompt(pamh: &Pam, msg: &str) -> Result<String, PamError> {
    match pamh.conv(Some(msg), PamMsgStyle::PROMPT_ECHO_OFF) {
        Ok(Some(cstr)) => Ok(cstr.to_string_lossy().into_owned()),
        Ok(None) => Err(PamError::CONV_ERR),
        Err(e) => Err(e),
    }
}

fn conv_error(pamh: &Pam, silent: bool, msg: &str) {
    if !silent {
        let _ = pamh.conv(Some(msg), PamMsgStyle::ERROR_MSG);
    }
}

fn conv_info(pamh: &Pam, silent: bool, msg: &str) {
    if !silent {
        let _ = pamh.conv(Some(msg), PamMsgStyle::TEXT_INFO);
    }
}

/// Prompt the user for a new password and confirm it.
fn prompt_new_password(pamh: &Pam, opts: &Options, silent: bool) -> Result<String, PamError> {
    let pass1 = conv_prompt(pamh, &opts.new_password_prompt())?;
    let pass2 = conv_prompt(pamh, &opts.retype_password_prompt())?;

    if pass1 != pass2 {
        conv_error(pamh, silent, "Sorry, passwords do not match.");
        return Err(PamError::AUTHTOK_ERR);
    }

    if pass1.is_empty() {
        conv_error(pamh, silent, "No password supplied.");
        return Err(PamError::AUTHTOK_ERR);
    }

    Ok(pass1)
}

/// Get the new password from a stacked module's cached authtok.
fn get_cached_password(pamh: &Pam) -> Result<String, PamError> {
    match pamh.get_cached_authtok() {
        Ok(Some(cstr)) => {
            let s = cstr.to_string_lossy().into_owned();
            if s.is_empty() {
                Err(PamError::AUTHTOK_ERR)
            } else {
                Ok(s)
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

impl PamServiceModule for PamZxcvbn {
    fn chauthtok(pamh: Pam, flags: PamFlags, args: Vec<String>) -> PamError {
        let opts = Options::parse(&args);
        let raw_flags = flags.bits();
        let silent = flags.contains(PamFlags::SILENT);

        // On PRELIM_CHECK pass, we have nothing to do.
        if raw_flags & PAM_PRELIM_CHECK != 0 {
            log_debug(
                &pamh,
                &opts,
                "pam_zxcvbn: PRELIM_CHECK phase, returning SUCCESS",
            );
            return PamError::SUCCESS;
        }

        // We only act on UPDATE_AUTHTOK.
        if raw_flags & PAM_UPDATE_AUTHTOK == 0 {
            log_debug(
                &pamh,
                &opts,
                "pam_zxcvbn: neither PRELIM_CHECK nor UPDATE_AUTHTOK, returning SERVICE_ERR",
            );
            return PamError::SERVICE_ERR;
        }

        log_debug(&pamh, &opts, "pam_zxcvbn: UPDATE_AUTHTOK phase");

        // Get the username.
        let username = match pamh.get_user(None) {
            Ok(Some(u)) => u.to_string_lossy().into_owned(),
            Ok(None) => {
                log_err(&pamh, "pam_zxcvbn: cannot determine username");
                return PamError::USER_UNKNOWN;
            }
            Err(e) => {
                log_err(&pamh, "pam_zxcvbn: cannot determine username");
                return e;
            }
        };

        log_debug(&pamh, &opts, &format!("pam_zxcvbn: user={}", username));

        // local_users_only: skip strength check for non-local users,
        // but still prompt for password so downstream modules can use use_authtok.
        if opts.local_users_only && !local_users::is_local_user(&username, &opts.local_users_file) {
            log_debug(
                &pamh,
                &opts,
                &format!(
                    "pam_zxcvbn: user '{}' not found in {}, skipping strength check",
                    username, opts.local_users_file
                ),
            );
            // Still obtain and set the password for downstream modules.
            let pass = if opts.use_authtok || opts.use_first_pass {
                match get_cached_password(&pamh) {
                    Ok(p) => p,
                    Err(e) => return e,
                }
            } else if opts.try_first_pass {
                match get_cached_password(&pamh) {
                    Ok(p) => p,
                    Err(_) => match prompt_new_password(&pamh, &opts, silent) {
                        Ok(p) => p,
                        Err(e) => return e,
                    },
                }
            } else {
                match prompt_new_password(&pamh, &opts, silent) {
                    Ok(p) => p,
                    Err(e) => return e,
                }
            };
            match CString::new(pass) {
                Ok(cpass) => match pamh.set_authtok(&cpass) {
                    Ok(()) => return PamError::SUCCESS,
                    Err(e) => return e,
                },
                Err(_) => return PamError::AUTHTOK_ERR,
            }
        }

        // Determine if we should enforce or just warn.
        let is_root = unsafe { libc::getuid() } == 0;
        let enforce = !is_root || opts.enforce_for_root;

        if is_root && !opts.enforce_for_root {
            log_debug(
                &pamh,
                &opts,
                "pam_zxcvbn: running as root without enforce_for_root, failures will be warnings",
            );
        }

        // Retry loop.
        let mut attempt = 0u32;
        loop {
            attempt += 1;

            log_debug(
                &pamh,
                &opts,
                &format!("pam_zxcvbn: attempt {}/{}", attempt, opts.tries),
            );

            // Obtain the new password.
            let new_pass = if opts.use_authtok {
                // Must use token from a previously stacked module.
                match get_cached_password(&pamh) {
                    Ok(p) => p,
                    Err(e) => {
                        log_err(
                            &pamh,
                            "pam_zxcvbn: use_authtok set but no password available",
                        );
                        return e;
                    }
                }
            } else if opts.use_first_pass {
                // Force use of a previous module's password.
                match get_cached_password(&pamh) {
                    Ok(p) => p,
                    Err(e) => {
                        log_debug(
                            &pamh,
                            &opts,
                            "pam_zxcvbn: use_first_pass set but no password available",
                        );
                        return e;
                    }
                }
            } else if opts.try_first_pass && attempt == 1 {
                // Try cached password first, fall back to prompting.
                match get_cached_password(&pamh) {
                    Ok(p) => {
                        log_debug(
                            &pamh,
                            &opts,
                            "pam_zxcvbn: using cached password from try_first_pass",
                        );
                        p
                    }
                    Err(_) => {
                        log_debug(
                            &pamh,
                            &opts,
                            "pam_zxcvbn: no cached password, prompting user",
                        );
                        match prompt_new_password(&pamh, &opts, silent) {
                            Ok(p) => p,
                            Err(e) => return e,
                        }
                    }
                }
            } else {
                // Prompt the user.
                match prompt_new_password(&pamh, &opts, silent) {
                    Ok(p) => p,
                    Err(e) => {
                        if attempt >= opts.tries {
                            return e;
                        }
                        continue;
                    }
                }
            };

            // Evaluate password strength.
            let mut user_inputs: Vec<&str> =
                opts.use_inputs.iter().map(|input| input.as_str()).collect();
            user_inputs.push(username.as_str());
            let result = strength::evaluate(&new_pass, &user_inputs, &opts);

            log_debug(
                &pamh,
                &opts,
                &format!(
                    "pam_zxcvbn: score={} guesses_log10={:.2} passed={}",
                    result.score, result.guesses_log10, result.passed
                ),
            );

            if result.passed {
                log_debug(&pamh, &opts, "pam_zxcvbn: password strength check passed");
                // Store the new password for downstream modules.
                match CString::new(new_pass) {
                    Ok(cpass) => match pamh.set_authtok(&cpass) {
                        Ok(()) => return PamError::SUCCESS,
                        Err(e) => {
                            log_err(&pamh, "pam_zxcvbn: failed to set authtok");
                            return e;
                        }
                    },
                    Err(_) => {
                        log_err(&pamh, "pam_zxcvbn: password contains null byte");
                        return PamError::AUTHTOK_ERR;
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
                    &pamh,
                    &opts,
                    &format!(
                        "pam_zxcvbn: weak password accepted for root: {}",
                        strength_msg
                    ),
                );
                conv_info(&pamh, silent, &format!("WARNING: {}", strength_msg));
                match CString::new(new_pass) {
                    Ok(cpass) => match pamh.set_authtok(&cpass) {
                        Ok(()) => return PamError::SUCCESS,
                        Err(e) => return e,
                    },
                    Err(_) => return PamError::AUTHTOK_ERR,
                }
            }

            // Show feedback to the user.
            conv_error(&pamh, silent, &strength_msg);
            if let Some(warning) = &result.feedback_warning {
                conv_error(&pamh, silent, &format!("Warning: {}", warning));
            }
            for suggestion in &result.feedback_suggestions {
                conv_info(&pamh, silent, &format!("Suggestion: {}", suggestion));
            }

            // If we can't retry (use_first_pass/use_authtok), fail immediately.
            if opts.use_first_pass || opts.use_authtok {
                return PamError::AUTHTOK_ERR;
            }

            if attempt >= opts.tries {
                log_debug(
                    &pamh,
                    &opts,
                    &format!("pam_zxcvbn: max tries ({}) reached, rejecting", opts.tries),
                );
                return PamError::MAXTRIES;
            }

            conv_info(&pamh, silent, "Please try again.");
        }
    }
}

pam_module!(PamZxcvbn);
