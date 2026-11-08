//! The error of reading configuration.

use std::fmt;

/// A configuration that cannot be used. The whole document fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    class: &'static str,
    message: String,
}

impl Error {
    /// The class: `syntax`, `duplicate_key`, `unknown_member`, `type`, `range`, `table`,
    /// `scope`, `conflict`, `reference`, `unreachable`, `cycle`, `zero_delay_cycle`,
    /// `no_default`, `no_candidate` or `size`.
    #[must_use]
    pub fn class(&self) -> &'static str {
        self.class
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.class, self.message)
    }
}

impl std::error::Error for Error {}

pub(crate) fn err(class: &'static str, message: impl Into<String>) -> Error {
    Error {
        class,
        message: message.into(),
    }
}
