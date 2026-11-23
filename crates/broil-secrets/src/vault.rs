// Copyright 2026 Broil contributors
// SPDX-License-Identifier: Apache-2.0

pub mod api;
pub mod json;
pub mod session;
pub mod transport;

pub use api::Client;
pub use session::Session;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Class {
    Runtime,
    IdentityDecrypt,
    AppRoleRejected,
    Unavailable,
}

#[derive(Clone, Copy, Debug)]
pub struct Error {
    pub class: Class,
    pub fallback: bool,
    pub cleanup_failed: bool,
    message: &'static str,
}
pub type Result<T> = std::result::Result<T, Error>;
impl Error {
    pub fn runtime(message: &'static str) -> Self {
        Self {
            class: Class::Runtime,
            fallback: false,
            cleanup_failed: false,
            message,
        }
    }
    pub(crate) fn unavailable() -> Self {
        Self {
            class: Class::Unavailable,
            fallback: true,
            ..Self::runtime("vault unavailable or deadline exceeded")
        }
    }
    pub(crate) fn identity() -> Self {
        Self {
            class: Class::IdentityDecrypt,
            ..Self::runtime("identity unlock or credential decryption failed")
        }
    }
    pub(crate) fn rejected() -> Self {
        Self {
            class: Class::AppRoleRejected,
            ..Self::runtime("AppRole login rejected or no usable token")
        }
    }
    pub(crate) fn setup(message: &'static str, status: u16) -> Self {
        Self {
            class: if status >= 500 {
                Class::Unavailable
            } else {
                Class::Runtime
            },
            ..Self::runtime(message)
        }
    }
    pub fn failure_class(self) -> &'static str {
        match self.class {
            Class::Runtime => "runtime",
            Class::IdentityDecrypt => "identity-decrypt",
            Class::AppRoleRejected => "approle-rejected",
            Class::Unavailable => "vault-unreachable",
        }
    }
    pub fn login_status(self) -> i32 {
        match self.class {
            Class::AppRoleRejected => 3,
            Class::Unavailable => 4,
            _ => 1,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)?;
        if self.cleanup_failed {
            f.write_str("; owned token revocation failed")?;
        }
        Ok(())
    }
}
impl std::error::Error for Error {}

impl From<crate::read::Error> for Error {
    fn from(_: crate::read::Error) -> Self {
        Self::runtime("vault value or output preparation failed")
    }
}
