//! Abstraction over the PAM side-effects used by this module.
//!
//! Keeping the PAM interaction behind a trait lets the core chauthtok
//! logic be exercised by tests without a real PAM stack or root check.

use pamsm::{LogLvl, Pam, PamError, PamLibExt, PamMsgStyle};
use std::ffi::CString;

#[derive(Clone, Copy, Debug)]
pub enum LogLevel {
    Debug,
    Error,
}

pub trait PamIo {
    fn syslog(&self, level: LogLevel, msg: &str);
    fn prompt_password(&self, msg: &str) -> Result<Option<CString>, PamError>;
    fn show_info(&self, msg: &str);
    fn show_error(&self, msg: &str);
    fn get_user(&self) -> Result<Option<CString>, PamError>;
    fn get_cached_authtok(&self) -> Result<Option<CString>, PamError>;
    fn set_authtok(&self, authtok: &CString) -> Result<(), PamError>;
    fn is_root(&self) -> bool;
}

pub struct RealPamIo<'a> {
    pam: &'a Pam,
}

impl<'a> RealPamIo<'a> {
    pub fn new(pam: &'a Pam) -> Self {
        Self { pam }
    }
}

impl PamIo for RealPamIo<'_> {
    fn syslog(&self, level: LogLevel, msg: &str) {
        let lvl = match level {
            LogLevel::Debug => LogLvl::DEBUG,
            LogLevel::Error => LogLvl::ERR,
        };
        let _ = self.pam.syslog(lvl, msg);
    }

    fn prompt_password(&self, msg: &str) -> Result<Option<CString>, PamError> {
        match self.pam.conv(Some(msg), PamMsgStyle::PROMPT_ECHO_OFF)? {
            Some(cstr) => Ok(Some(cstr.to_owned())),
            None => Ok(None),
        }
    }

    fn show_info(&self, msg: &str) {
        let _ = self.pam.conv(Some(msg), PamMsgStyle::TEXT_INFO);
    }

    fn show_error(&self, msg: &str) {
        let _ = self.pam.conv(Some(msg), PamMsgStyle::ERROR_MSG);
    }

    fn get_user(&self) -> Result<Option<CString>, PamError> {
        match self.pam.get_user(None)? {
            Some(cstr) => Ok(Some(cstr.to_owned())),
            None => Ok(None),
        }
    }

    fn get_cached_authtok(&self) -> Result<Option<CString>, PamError> {
        match self.pam.get_cached_authtok()? {
            Some(cstr) => Ok(Some(cstr.to_owned())),
            None => Ok(None),
        }
    }

    fn set_authtok(&self, authtok: &CString) -> Result<(), PamError> {
        self.pam.set_authtok(authtok)
    }

    fn is_root(&self) -> bool {
        unsafe { libc::getuid() == 0 }
    }
}
