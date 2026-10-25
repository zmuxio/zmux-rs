//! Error codes of the transport and application spaces (SPEC.md Section 10,
//! EXTENSIONS.md Section 7, REGISTRY.md Section 6) and the error types of the
//! wire layer.

use std::fmt;

macro_rules! codes {
    (
        $(#[$meta:meta])*
        $ty:ident, $table:ident, $entry:ty;
        $( $(#[$cmeta:meta])* $name:ident = $value:expr, $extra:expr; )*
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $ty(pub u64);

        impl $ty {
            $( $(#[$cmeta])* pub const $name: Self = Self($value); )*

            /// Returns the registry name of a known code.
            pub const fn name(self) -> Option<&'static str> {
                match self.0 {
                    $( $value => Some(stringify!($name)), )*
                    _ => None,
                }
            }
        }

        /// Every code of this space in the registry, in registry order, with
        /// its name and extra registry column.
        pub const $table: &[($ty, &str, $entry)] = &[
            $( ($ty::$name, stringify!($name), $extra), )*
        ];

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.name() {
                    Some(name) => f.write_str(name),
                    None => write!(f, "{}({:#x})", stringify!($ty), self.0),
                }
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Debug::fmt(self, f)
            }
        }
    };
}

codes! {
    /// A transport error code, carried in CONNECTION_CLOSE (type 0x1c) and
    /// PIPE_ABANDON.
    TransportErrorCode, TRANSPORT_ERRORS, bool;
    /// No error.
    NO_ERROR = 0x00, true;
    /// Implementation error.
    INTERNAL_ERROR = 0x01, true;
    /// The endpoint refuses the session.
    CONNECTION_REFUSED = 0x02, true;
    /// Stream or session data beyond an advertised limit.
    FLOW_CONTROL_ERROR = 0x03, true;
    /// A stream opened beyond the advertised stream limit.
    STREAM_LIMIT_ERROR = 0x04, true;
    /// A frame for a stream in a state that does not allow it.
    STREAM_STATE_ERROR = 0x05, true;
    /// A final size changed or was exceeded.
    FINAL_SIZE_ERROR = 0x06, true;
    /// A malformed, unknown, prohibited or not-in-use frame.
    FRAME_ENCODING_ERROR = 0x07, true;
    /// Malformed or inconsistent transport parameters.
    TRANSPORT_PARAMETER_ERROR = 0x08, true;
    /// Any other protocol violation.
    PROTOCOL_VIOLATION = 0x0a, true;
    /// A multipath session lost every pipe in a direction.
    NO_VIABLE_PATH = 0x10, true;
    /// The peer exhausted the no-effect budget (SPEC.md Section 9.4).
    ZMUX_EXCESSIVE_LOAD = 0x25ff_75ef, true;
    /// Role negotiation failed (EXTENSIONS.md Section 2).
    ZMUX_ROLE_CONFLICT = 0x277d_b2c3, true;
    /// The resume grace period expired (RESUME.md Section 8).
    ZMUX_RESUME_TIMEOUT = 0x0eb8_7167, true;
    /// A resume could not be completed safely (RESUME.md Section 7).
    ZMUX_RESUME_FAILED = 0x0f05_f74e, true;
    /// PIPE_ABANDON reason: the pipe failed or was removed abruptly.
    ZMUX_PIPE_FAILED = 0x296a_5bf5, true;
    /// PIPE_ABANDON reason: the endpoint cannot keep the pipe.
    ZMUX_PIPE_RESOURCE_LIMIT = 0x0b4f_a113, true;
    /// A join failed authentication; reported locally, never sent.
    ZMUX_PIPE_AUTH_FAILED = 0x0961_3938, false;
    /// The sender's idle timer expired in a multipath session (SPEC.md
    /// Section 6.4).
    ZMUX_IDLE_TIMEOUT = 0x2736_d55c, true;
}

impl TransportErrorCode {
    /// Whether this code may appear on the wire. Unknown codes are treated as
    /// sendable; only [`Self::ZMUX_PIPE_AUTH_FAILED`] is local-only.
    pub const fn is_sent_on_wire(self) -> bool {
        self.0 != Self::ZMUX_PIPE_AUTH_FAILED.0
    }
}

codes! {
    /// An application error code, carried in CONNECTION_CLOSE (type 0x1d),
    /// RESET_STREAM, RESET_STREAM_AT, STOP_SENDING and GOAWAY. The block
    /// 0x5a4d0000 to 0x5a4d0fff holds the zmux conventions; the extra table
    /// column is the matching SOCKS5 reply code.
    ApplicationErrorCode, APPLICATION_ERRORS, Option<u8>;
    /// No error; for STOP_SENDING, "no more data wanted".
    NO_ERROR = 0x00, None;
    /// The endpoint abandoned the stream or operation.
    ZMUX_CANCELLED = 0x5a4d_0001, None;
    /// The stream was not processed and may be retried.
    ZMUX_REJECTED = 0x5a4d_0002, None;
    /// The stream carried something that failed: a pipe of a nested
    /// session that the nested session failed or aborted, or one hop of a
    /// relayed stream whose other side was lost (EXTENSIONS.md Section 10).
    /// Data already delivered stands; the stream is not safe to retry
    /// blindly.
    ZMUX_CARRIER_FAILED = 0x5a4d_0003, None;
    /// Proxy open failure: general failure.
    ZMUX_PROXY_GENERAL_FAILURE = 0x5a4d_0101, Some(0x01);
    /// Proxy open failure: not allowed by ruleset.
    ZMUX_PROXY_NOT_ALLOWED = 0x5a4d_0102, Some(0x02);
    /// Proxy open failure: network unreachable.
    ZMUX_PROXY_NETWORK_UNREACHABLE = 0x5a4d_0103, Some(0x03);
    /// Proxy open failure: host unreachable.
    ZMUX_PROXY_HOST_UNREACHABLE = 0x5a4d_0104, Some(0x04);
    /// Proxy open failure: connection refused.
    ZMUX_PROXY_CONNECTION_REFUSED = 0x5a4d_0105, Some(0x05);
    /// Proxy open failure: TTL expired.
    ZMUX_PROXY_TTL_EXPIRED = 0x5a4d_0106, Some(0x06);
    /// Proxy open failure: command not supported.
    ZMUX_PROXY_COMMAND_NOT_SUPPORTED = 0x5a4d_0107, Some(0x07);
    /// Proxy open failure: address type not supported.
    ZMUX_PROXY_ADDRESS_TYPE_NOT_SUPPORTED = 0x5a4d_0108, Some(0x08);
    /// Proxy open failure: the target name did not resolve.
    ZMUX_PROXY_DNS_FAILURE = 0x5a4d_0110, Some(0x04);
    /// Proxy open failure: connecting to the target timed out.
    ZMUX_PROXY_CONNECT_TIMEOUT = 0x5a4d_0111, Some(0x06);
}

impl ApplicationErrorCode {
    /// The first code of the block reserved for zmux conventions.
    pub const ZMUX_BLOCK_FIRST: u64 = 0x5a4d_0000;
    /// The last code of the block reserved for zmux conventions.
    pub const ZMUX_BLOCK_LAST: u64 = 0x5a4d_0fff;

    /// The SOCKS5 reply code (RFC 1928 Section 6) that a proxy open-failure
    /// code maps to.
    pub fn socks5_reply(self) -> Option<u8> {
        APPLICATION_ERRORS
            .iter()
            .find(|e| e.0 == self)
            .and_then(|e| e.2)
    }

    /// The proxy open-failure code for a SOCKS5 reply code 0x01 to 0x08.
    pub const fn from_socks5_reply(rep: u8) -> Option<Self> {
        match rep {
            0x01..=0x08 => Some(Self(0x5a4d_0100 + rep as u64)),
            _ => None,
        }
    }
}

/// A key of the diagnostic line of a Reason Phrase (SPEC.md Section 4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DetailKey {
    /// `stream`: a stream ID.
    Stream,
    /// `pipe`: a pipe number.
    Pipe,
    /// `offset`: a stream offset.
    Offset,
    /// `length`: a length.
    Length,
    /// `limit`: the limit that was exceeded.
    Limit,
    /// `value`: the offending value of a field.
    Value,
    /// `pos`: a byte position in a pipe (MULTIPATH.md Section 2.3).
    Pos,
    /// `rec`: a byte position in a record.
    Rec,
}

impl DetailKey {
    const ALL: [Self; 8] = [
        Self::Stream,
        Self::Pipe,
        Self::Offset,
        Self::Length,
        Self::Limit,
        Self::Value,
        Self::Pos,
        Self::Rec,
    ];

    /// The key as it appears in the diagnostic line.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stream => "stream",
            Self::Pipe => "pipe",
            Self::Offset => "offset",
            Self::Length => "length",
            Self::Limit => "limit",
            Self::Value => "value",
            Self::Pos => "pos",
            Self::Rec => "rec",
        }
    }

    /// The defined key of that name.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

/// The most `key=value` pairs an [`Error`] carries.
const MAX_DETAILS: usize = 4;

/// A violation found while decoding peer input. A session that encounters
/// one closes with CONNECTION_CLOSE carrying [`Error::code`] (SPEC.md Section
/// 9.3), its reason and, after a line feed, its [`Error::details`] (SPEC.md
/// Section 4.3).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Error {
    code: TransportErrorCode,
    frame_type: u64,
    reason: &'static str,
    keys: [DetailKey; MAX_DETAILS],
    values: [u64; MAX_DETAILS],
    details: u8,
}

impl Error {
    /// Creates an error with a transport code, the type of the offending
    /// frame (0 when there is none) and a short reason.
    pub const fn new(code: TransportErrorCode, frame_type: u64, reason: &'static str) -> Self {
        Self {
            code,
            frame_type,
            reason,
            keys: [DetailKey::Value; MAX_DETAILS],
            values: [0; MAX_DETAILS],
            details: 0,
        }
    }

    /// Adds a `key=value` pair to the diagnostic line (SPEC.md Section
    /// 4.3); pairs beyond the fourth are left out.
    #[must_use]
    pub const fn detail(mut self, key: DetailKey, value: u64) -> Self {
        let i = self.details as usize;
        if i < MAX_DETAILS {
            self.keys[i] = key;
            self.values[i] = value;
            self.details += 1;
        }
        self
    }

    pub(crate) const fn frame_encoding(frame_type: u64, reason: &'static str) -> Self {
        Self::new(TransportErrorCode::FRAME_ENCODING_ERROR, frame_type, reason)
    }

    pub(crate) const fn protocol_violation(frame_type: u64, reason: &'static str) -> Self {
        Self::new(TransportErrorCode::PROTOCOL_VIOLATION, frame_type, reason)
    }

    pub(crate) const fn transport_parameter(reason: &'static str) -> Self {
        Self::new(TransportErrorCode::TRANSPORT_PARAMETER_ERROR, 0, reason)
    }

    /// The transport error code to close the session with.
    pub const fn code(&self) -> TransportErrorCode {
        self.code
    }

    /// The Frame Type field of CONNECTION_CLOSE: the type of the frame that
    /// caused the error, or 0.
    pub const fn frame_type(&self) -> u64 {
        self.frame_type
    }

    /// A short description, the human-readable part of the Reason Phrase.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// The `key=value` pairs of the diagnostic line, in order.
    pub fn details(&self) -> impl ExactSizeIterator<Item = (DetailKey, u64)> + '_ {
        let n = usize::from(self.details);
        self.keys[..n]
            .iter()
            .copied()
            .zip(self.values[..n].iter().copied())
    }

    /// The Reason Phrase: the reason, then a line feed and the pairs when
    /// there are any (SPEC.md Section 4.3).
    pub fn reason_phrase(&self) -> String {
        use fmt::Write as _;
        let mut s = String::from(self.reason);
        for (i, (k, v)) in self.details().enumerate() {
            let sep = if i == 0 { '\n' } else { ' ' };
            let _ = write!(s, "{sep}{}={v}", k.name());
        }
        s
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.code, self.reason)?;
        for (k, v) in self.details() {
            write!(f, " {}={v}", k.name())?;
        }
        if self.frame_type != 0 {
            write!(f, " (frame type {:#x})", self.frame_type)?;
        }
        Ok(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl std::error::Error for Error {}

/// An encoder could not write a frame or value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The output buffer is shorter than the encoding.
    BufferTooShort,
    /// A field holds a value that cannot be encoded: above 2^62 - 1, or
    /// outside the range the field's definition allows.
    ValueOutOfRange,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BufferTooShort => "output buffer too short",
            Self::ValueOutOfRange => "value out of range for its field",
        })
    }
}

impl std::error::Error for EncodeError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_socks_mapping() {
        assert_eq!(TransportErrorCode(0x0a).name(), Some("PROTOCOL_VIOLATION"));
        assert_eq!(
            format!("{:?}", TransportErrorCode(0x99)),
            "TransportErrorCode(0x99)"
        );
        assert!(!TransportErrorCode::ZMUX_PIPE_AUTH_FAILED.is_sent_on_wire());
        for rep in 1..=8 {
            let code = ApplicationErrorCode::from_socks5_reply(rep).unwrap();
            assert_eq!(code.socks5_reply(), Some(rep));
        }
        assert_eq!(
            ApplicationErrorCode::ZMUX_PROXY_DNS_FAILURE.socks5_reply(),
            Some(4)
        );
        assert_eq!(ApplicationErrorCode::from_socks5_reply(9), None);
    }
}
