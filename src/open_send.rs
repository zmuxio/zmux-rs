use crate::config::OpenOptions;
use crate::error::{Error, Result};
use std::borrow::Cow;
use std::io::IoSlice;
use std::time::Duration;

/// Request parameters for opening a stream.
///
/// Open metadata is carried inside `OpenOptions` and is opaque binary data.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenRequest {
    options: OpenOptions,
    timeout: Option<Duration>,
}

impl OpenRequest {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn with_options(mut self, options: OpenOptions) -> Self {
        self.options = options;
        self
    }

    #[inline]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    #[inline]
    pub fn options(&self) -> &OpenOptions {
        &self.options
    }

    #[inline]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    #[inline]
    pub fn into_parts(self) -> (OpenOptions, Option<Duration>) {
        (self.options, self.timeout)
    }
}

impl From<OpenOptions> for OpenRequest {
    #[inline]
    fn from(options: OpenOptions) -> Self {
        Self::new().with_options(options)
    }
}

/// Binary payload for write operations.
///
/// Byte buffers can be borrowed or owned. Borrowed `&[u8]` / `&Vec<u8>` values
/// stay borrowed until the operation returns; owned `Vec<u8>` values move into
/// the write request and let concrete runtimes avoid an internal queue copy
/// when the transport framing can use the buffer directly. Vectored payloads
/// are opt-in through `WritePayload::vectored(...)` / `OpenSend::vectored(...)`
/// so ordinary byte-buffer calls keep the same shape as `Write::write(&[u8])`.
#[derive(Debug, Clone)]
pub enum WritePayload<'a> {
    Bytes(Cow<'a, [u8]>),
    Vectored(&'a [IoSlice<'a>]),
}

impl<'a> WritePayload<'a> {
    #[inline]
    pub fn bytes(data: &'a [u8]) -> Self {
        Self::Bytes(Cow::Borrowed(data))
    }

    #[inline]
    pub fn vectored(parts: &'a [IoSlice<'a>]) -> Self {
        Self::Vectored(parts)
    }

    #[inline]
    pub fn checked_len(&self) -> Result<usize> {
        match self {
            Self::Bytes(data) => Ok(data.len()),
            Self::Vectored(parts) => parts.iter().try_fold(0usize, |total, part| {
                total
                    .checked_add(part.len())
                    .ok_or_else(|| Error::local("zmux: vectored write length overflow"))
            }),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Bytes(data) => data.is_empty(),
            Self::Vectored(parts) => parts.iter().all(|part| part.is_empty()),
        }
    }
}

impl<'a> From<&'a [u8]> for WritePayload<'a> {
    #[inline]
    fn from(data: &'a [u8]) -> Self {
        Self::bytes(data)
    }
}

impl<'a> From<&'a Vec<u8>> for WritePayload<'a> {
    #[inline]
    fn from(data: &'a Vec<u8>) -> Self {
        Self::bytes(data.as_slice())
    }
}

impl<'a> From<&'a mut Vec<u8>> for WritePayload<'a> {
    #[inline]
    fn from(data: &'a mut Vec<u8>) -> Self {
        Self::bytes(data.as_slice())
    }
}

impl<'a> From<Vec<u8>> for WritePayload<'a> {
    #[inline]
    fn from(data: Vec<u8>) -> Self {
        Self::Bytes(Cow::Owned(data))
    }
}

impl<'a> From<Cow<'a, [u8]>> for WritePayload<'a> {
    #[inline]
    fn from(data: Cow<'a, [u8]>) -> Self {
        Self::Bytes(data)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for WritePayload<'a> {
    #[inline]
    fn from(data: &'a [u8; N]) -> Self {
        Self::bytes(data.as_slice())
    }
}

impl<'a, const N: usize> From<[u8; N]> for WritePayload<'a> {
    #[inline]
    fn from(data: [u8; N]) -> Self {
        Self::Bytes(Cow::Owned(Vec::from(data)))
    }
}

impl<'a> From<&'a [IoSlice<'a>]> for WritePayload<'a> {
    #[inline]
    fn from(parts: &'a [IoSlice<'a>]) -> Self {
        Self::vectored(parts)
    }
}

/// Complete request for opening a stream and immediately sending binary data.
#[derive(Debug, Clone)]
pub struct OpenSend<'a> {
    options: OpenOptions,
    payload: WritePayload<'a>,
    timeout: Option<Duration>,
}

impl<'a> OpenSend<'a> {
    #[inline]
    pub fn new(payload: impl Into<WritePayload<'a>>) -> Self {
        Self {
            options: OpenOptions::default(),
            payload: payload.into(),
            timeout: None,
        }
    }

    #[inline]
    pub fn vectored(parts: &'a [IoSlice<'a>]) -> Self {
        Self::new(WritePayload::vectored(parts))
    }

    #[inline]
    pub fn with_options(mut self, options: OpenOptions) -> Self {
        self.options = options;
        self
    }

    #[inline]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    #[inline]
    pub fn options(&self) -> &OpenOptions {
        &self.options
    }

    #[inline]
    pub fn payload(&self) -> &WritePayload<'a> {
        &self.payload
    }

    #[inline]
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    #[inline]
    pub fn into_parts(self) -> (OpenOptions, WritePayload<'a>, Option<Duration>) {
        (self.options, self.payload, self.timeout)
    }
}

impl<'a> From<&'a [u8]> for OpenSend<'a> {
    #[inline]
    fn from(data: &'a [u8]) -> Self {
        Self::new(data)
    }
}

impl<'a> From<&'a Vec<u8>> for OpenSend<'a> {
    #[inline]
    fn from(data: &'a Vec<u8>) -> Self {
        Self::new(data.as_slice())
    }
}

impl<'a> From<&'a mut Vec<u8>> for OpenSend<'a> {
    #[inline]
    fn from(data: &'a mut Vec<u8>) -> Self {
        Self::new(data.as_slice())
    }
}

impl<'a> From<Vec<u8>> for OpenSend<'a> {
    #[inline]
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl<'a> From<Cow<'a, [u8]>> for OpenSend<'a> {
    #[inline]
    fn from(data: Cow<'a, [u8]>) -> Self {
        Self::new(data)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for OpenSend<'a> {
    #[inline]
    fn from(data: &'a [u8; N]) -> Self {
        Self::new(data.as_slice())
    }
}

impl<'a, const N: usize> From<[u8; N]> for OpenSend<'a> {
    #[inline]
    fn from(data: [u8; N]) -> Self {
        Self::new(data)
    }
}

impl<'a> From<&'a [IoSlice<'a>]> for OpenSend<'a> {
    #[inline]
    fn from(parts: &'a [IoSlice<'a>]) -> Self {
        Self::vectored(parts)
    }
}

impl<'a> From<WritePayload<'a>> for OpenSend<'a> {
    #[inline]
    fn from(payload: WritePayload<'a>) -> Self {
        Self::new(payload)
    }
}
