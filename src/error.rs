//! The errors of the drivers' compound operations. Every other operation
//! returns the session's errors unchanged ([`crate::SessionError`],
//! [`crate::StreamError`], [`crate::OpenError`], [`crate::DatagramError`],
//! [`crate::PipeError`]; see `proto::session::error`); these add only what
//! the compound operation itself can fail with.

use std::fmt;
use std::io;
use std::sync::Arc;

use crate::proto::session::{SessionError, StreamError};

/// Why establishing a session failed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ConnectError {
    /// The session ended during establishment: among others
    /// [`SessionError::HandshakeTimeout`] when the peer's parameters did not
    /// arrive in time.
    Closed(SessionError),
    /// The carrier failed, or the driver could not start its I/O.
    Io(Arc<io::Error>),
    /// The configuration is invalid.
    InvalidConfig(&'static str),
    /// A blocking `connect` was refused on a thread that drives sessions
    /// (std driver only); nothing was started.
    OnDriverThread,
}

impl ConnectError {
    /// Whether establishing may succeed if repeated on a new carrier: only
    /// after [`SessionError::EarlyDataRejected`], without early data.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Closed(e) if e.is_retryable())
    }
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Closed(e) => write!(f, "session closed during establishment: {e}"),
            Self::Io(e) => write!(f, "carrier error: {e}"),
            Self::InvalidConfig(e) => write!(f, "invalid configuration: {e}"),
            Self::OnDriverThread => f.write_str(crate::proto::session::ON_DRIVER_THREAD),
        }
    }
}

impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Closed(e) => Some(e),
            Self::Io(e) => Some(&**e),
            _ => None,
        }
    }
}

impl From<ConnectError> for io::Error {
    fn from(e: ConnectError) -> Self {
        let kind = match &e {
            ConnectError::Closed(s) => io::Error::from(s.clone()).kind(),
            ConnectError::Io(io) => io.kind(),
            ConnectError::InvalidConfig(_) => io::ErrorKind::InvalidInput,
            ConnectError::OnDriverThread => io::ErrorKind::Deadlock,
        };
        io::Error::new(kind, e)
    }
}

/// Why `read_exact` failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadExactError {
    /// The stream ended after this many bytes.
    FinishedEarly(usize),
    /// A read failed.
    Read(StreamError),
}

impl ReadExactError {
    /// Whether the stream may be retried ([`StreamError::is_retryable`]).
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Read(e) if e.is_retryable())
    }
}

impl fmt::Display for ReadExactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FinishedEarly(n) => write!(f, "stream finished after {n} bytes"),
            Self::Read(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ReadExactError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(e) => Some(e),
            Self::FinishedEarly(_) => None,
        }
    }
}

impl From<ReadExactError> for io::Error {
    fn from(e: ReadExactError) -> Self {
        match e {
            ReadExactError::FinishedEarly(_) => io::Error::new(io::ErrorKind::UnexpectedEof, e),
            ReadExactError::Read(r) => r.into(),
        }
    }
}

/// Why `read_to_end` failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadToEndError {
    /// The stream is longer than the limit.
    TooLong,
    /// A read failed.
    Read(StreamError),
}

impl ReadToEndError {
    /// Whether the stream may be retried ([`StreamError::is_retryable`]).
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Read(e) if e.is_retryable())
    }
}

impl fmt::Display for ReadToEndError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("stream longer than the limit"),
            Self::Read(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for ReadToEndError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read(e) => Some(e),
            Self::TooLong => None,
        }
    }
}

impl From<ReadToEndError> for io::Error {
    fn from(e: ReadToEndError) -> Self {
        match e {
            ReadToEndError::TooLong => io::Error::new(io::ErrorKind::InvalidData, e),
            ReadToEndError::Read(r) => r.into(),
        }
    }
}
