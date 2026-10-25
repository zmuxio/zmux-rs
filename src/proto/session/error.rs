//! Errors of the session (STATE_MACHINE.md Section
//! 2.5): one type per kind of operation, shared by the sans-IO core and the
//! drivers, which return them unchanged.
//!
//! | type | returned by |
//! |---|---|
//! | [`SessionError`] | why a session ended; session-wide waits (accept, datagram receive, `closed`, `shutdown`) |
//! | [`StreamError`] | every operation on a stream's sending or receiving part |
//! | [`OpenError`] | opening a stream |
//! | [`DatagramError`] | sending a datagram |
//! | [`PipeError`] | adding, reserving and changing pipes |
//!
//! Every type is `#[non_exhaustive]`, tells whether the operation may be
//! retried ([`StreamError::is_retryable`] and its siblings) and converts
//! into an [`io::Error`] of a matching [`io::ErrorKind`] that wraps it.
//!
//! `is_retryable` means one thing on every type: the peer did not act on
//! the operation, so repeating it cannot duplicate anything. Where it must
//! be repeated depends on the error: on the same session (credit,
//! ZMUX_REJECTED, a pipe operation before establishment) or on a new one
//! (GOAWAY, and [`SessionError::EarlyDataRejected`], where the new session
//! must not send early data). A session that ended for any other reason is
//! not retryable: the peer may have processed some of its data.
//!
//! Through [`io::Error`], a rejection of early data has no kind of its own
//! ([`io::ErrorKind::Other`]); [`SessionError::in_io`] finds the session
//! error inside an [`io::Error`] made from any of these types, so
//! `SessionError::in_io(&e).is_some_and(SessionError::is_early_data_rejected)`
//! tells a caller that only sees [`io::Error`]s to retry without early
//! data.
//!
//! A few variants belong to the drivers only, and the core never returns
//! them: `OnDriverThread` of the operation errors (a blocking call of the
//! std driver refused on a thread that drives sessions, mapped to
//! [`io::ErrorKind::Deadlock`]; never a
//! [`SessionError`], which only says why a session ended),
//! [`StreamError::TimedOut`] (a blocking stream's timeout),
//! [`PipeError::Io`] (the std driver could not start a pipe's threads),
//! [`PipeError::CarrierLoop`] (a stream carrier that runs over the session
//! it is for) and [`PipeError::Failed`] (a pipe's join failed).

use std::fmt;
use std::io;

use bytes::Bytes;

use crate::proto::{DetailKey, TransportErrorCode, VarInt};

/// Why a session ended. The first cause wins (SPEC.md Section 6.5).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionError {
    /// CONNECTION_CLOSE type 0x1d, sent by either application.
    ApplicationClosed {
        /// The application error code.
        code: VarInt,
        /// The reason phrase.
        reason: Bytes,
        /// Whether the peer closed.
        remote: bool,
    },
    /// CONNECTION_CLOSE type 0x1c: a protocol error found by either side.
    TransportClosed {
        /// The transport error code.
        code: TransportErrorCode,
        /// The Frame Type field.
        frame_type: u64,
        /// The reason phrase; when it ends with a diagnostic line, the text
        /// before that line (SPEC.md Section 4.3).
        reason: Bytes,
        /// The defined `key=value` pairs of the diagnostic line, in order;
        /// empty without one. Unknown keys are left out.
        details: Vec<(DetailKey, u64)>,
        /// Whether the peer detected the error.
        remote: bool,
    },
    /// The idle timer expired; `remote` when the peer ended the session by
    /// shutting down its pipe without CONNECTION_CLOSE (SPEC.md Section 6.4).
    IdleTimeout {
        /// Caused by the peer.
        remote: bool,
    },
    /// The peer's parameters did not arrive in time.
    HandshakeTimeout,
    /// The endpoint sent early data and the peer's parameters show that it
    /// cannot take it (not a zmux endpoint, or no bidirectional streams
    /// accepted): the peer processed none of it. The streams may be opened
    /// again on a new session without early data; this is the one
    /// termination that [`SessionError::is_retryable`] reports. Through
    /// [`io::Error`] it is [`io::ErrorKind::Other`]: see
    /// [`SessionError::in_io`].
    EarlyDataRejected,
    /// The resume grace period expired while the session was suspended
    /// (RESUME.md Section 8), or a listener limit ended the suspended
    /// session: CONNECTION_CLOSE(ZMUX_RESUME_TIMEOUT) when a pipe remains.
    /// A peer's ZMUX_RESUME_TIMEOUT is [`SessionError::TransportClosed`].
    ResumeTimeout {
        /// The most recent pipe failure of the session, when a pipe failed.
        last: Option<PipeFailure>,
    },
    /// Every pipe in a direction was lost without resume, or the single
    /// carrier failed or ended inside a record (MULTIPATH.md Section 8.5,
    /// SPEC.md Section 6.6).
    PipesLost {
        /// The most recent pipe failure of the session, when a pipe failed
        /// (`None` when none did: the last pipe was removed gracefully).
        last: Option<PipeFailure>,
    },
}

/// Why a pipe failed (MULTIPATH.md Section 7): reported with the session's
/// end ([`SessionError::PipesLost`], [`SessionError::ResumeTimeout`]) and
/// by a pipe's statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PipeFailure {
    /// The carrier failed: a read or write error of this kind, or
    /// [`io::ErrorKind::UnexpectedEof`] for an end where the pipe may not
    /// end (inside a record, or without its removal).
    Carrier(io::ErrorKind),
    /// No acknowledgement, write progress or input in time, or a drain
    /// that did not complete (MULTIPATH.md Sections 7.1 and 8.2).
    Stalled,
    /// The join was not confirmed within `handshake_timeout`: the peer
    /// refused it or never saw it (MULTIPATH.md Section 5.4).
    JoinTimedOut,
    /// The peer abandoned the pipe with this error code (PIPE_ABANDON).
    Abandoned(VarInt),
    /// This endpoint removed it abruptly: [`Pipe::abort`](crate::Pipe#method.abort), a resource
    /// limit, or room for a new join (MULTIPATH.md Sections 5.4 and 8.3).
    Aborted,
    /// The carrier broke the protocol for its state (MULTIPATH.md Section
    /// 5.4).
    Protocol,
}

impl fmt::Display for PipeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Carrier(kind) => write!(f, "carrier failed: {kind}"),
            Self::Stalled => f.write_str("pipe stalled"),
            Self::JoinTimedOut => f.write_str("join not confirmed in time"),
            Self::Abandoned(code) => write!(f, "abandoned by the peer with code {code}"),
            Self::Aborted => f.write_str("aborted locally"),
            Self::Protocol => f.write_str("protocol violation on the carrier"),
        }
    }
}

impl SessionError {
    /// Whether the peer caused the termination.
    pub fn is_remote(&self) -> bool {
        match self {
            Self::ApplicationClosed { remote, .. }
            | Self::TransportClosed { remote, .. }
            | Self::IdleTimeout { remote } => *remote,
            Self::HandshakeTimeout
            | Self::EarlyDataRejected
            | Self::ResumeTimeout { .. }
            | Self::PipesLost { .. } => false,
        }
    }

    /// The peer could not take this session's early data and processed
    /// none of it: the same streams may be opened again on a new session
    /// without early data.
    pub fn is_early_data_rejected(&self) -> bool {
        matches!(self, Self::EarlyDataRejected)
    }

    /// Whether what was in flight may be repeated on a new session: only
    /// for [`SessionError::EarlyDataRejected`] (without early data then),
    /// since after any other end the peer may have processed some of it.
    pub fn is_retryable(&self) -> bool {
        self.is_early_data_rejected()
    }

    /// The session error inside an [`io::Error`] converted from a
    /// [`SessionError`], [`StreamError`], [`OpenError`], [`DatagramError`],
    /// [`PipeError`] or [`ConnectError`](crate::ConnectError), when it holds
    /// one: how a caller that only sees [`io::Error`]s tells, for example,
    /// a rejection of early data ([`SessionError::is_early_data_rejected`])
    /// from other failures.
    pub fn in_io(e: &io::Error) -> Option<&SessionError> {
        let inner = e.get_ref()?;
        if let Some(s) = inner.downcast_ref::<SessionError>() {
            return Some(s);
        }
        if let Some(StreamError::SessionLost(s)) = inner.downcast_ref() {
            return Some(s);
        }
        if let Some(OpenError::SessionLost(s)) = inner.downcast_ref() {
            return Some(s);
        }
        if let Some(DatagramError::SessionLost(s)) = inner.downcast_ref() {
            return Some(s);
        }
        if let Some(PipeError::SessionLost(s)) = inner.downcast_ref() {
            return Some(s);
        }
        if let Some(crate::ConnectError::Closed(s)) = inner.downcast_ref() {
            return Some(s);
        }
        None
    }

    /// The [`io::ErrorKind`] of the termination.
    fn kind(&self) -> io::ErrorKind {
        match self {
            Self::ApplicationClosed { .. } | Self::TransportClosed { .. } => {
                io::ErrorKind::ConnectionAborted
            }
            Self::IdleTimeout { .. } | Self::HandshakeTimeout | Self::ResumeTimeout { .. } => {
                io::ErrorKind::TimedOut
            }
            Self::PipesLost { .. } => io::ErrorKind::ConnectionReset,
            // Not "refused": the peer is there and closed cleanly.
            Self::EarlyDataRejected => io::ErrorKind::Other,
        }
    }
}

pub(crate) const ON_DRIVER_THREAD: &str = "blocking call on a thread that drives sessions";

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let side = |remote: bool| if remote { "peer" } else { "local" };
        match self {
            Self::ApplicationClosed {
                code,
                reason,
                remote,
            } => write!(
                f,
                "closed by {} application with code {code} ({})",
                side(*remote),
                String::from_utf8_lossy(reason)
            ),
            Self::TransportClosed {
                code,
                reason,
                details,
                remote,
                ..
            } => {
                write!(
                    f,
                    "{} protocol error {code:?} ({}",
                    side(*remote),
                    String::from_utf8_lossy(reason)
                )?;
                for (k, v) in details {
                    write!(f, " {}={v}", k.name())?;
                }
                f.write_str(")")
            }
            Self::IdleTimeout { remote } => write!(f, "idle timeout ({})", side(*remote)),
            Self::HandshakeTimeout => f.write_str("handshake timeout"),
            Self::EarlyDataRejected => f.write_str(
                "early data rejected: the peer processed none of it; retry on a new session without early data",
            ),
            Self::ResumeTimeout { last } => {
                f.write_str("resume timeout")?;
                last.map_or(Ok(()), |l| write!(f, " (last pipe: {l})"))
            }
            Self::PipesLost { last } => {
                f.write_str("pipes lost")?;
                last.map_or(Ok(()), |l| write!(f, " (last pipe: {l})"))
            }
        }
    }
}

impl std::error::Error for SessionError {}

/// The most `key=value` pairs kept from a received diagnostic line: one
/// of each key (SPEC.md Section 4.3), whatever the peer sends.
const MAX_DETAILS: usize = 8;

/// Splits a transport Reason Phrase into its text and the defined pairs of
/// its diagnostic line (SPEC.md Section 4.3): a last line of space-separated
/// `key=value` pairs, keys lower-case ASCII, values decimal or `0x`
/// hexadecimal. A last line that does not parse leaves the phrase plain
/// text; unknown keys are ignored. Only reported, never acted upon.
pub(crate) fn split_reason(phrase: Bytes) -> (Bytes, Vec<(DetailKey, u64)>) {
    let Some(nl) = phrase.iter().rposition(|&b| b == b'\n') else {
        return (phrase, Vec::new());
    };
    let mut details = Vec::new();
    for pair in phrase[nl + 1..].split(|&b| b == b' ') {
        let Some((key, value)) = parse_pair(pair) else {
            return (phrase, Vec::new());
        };
        if let Some(key) = std::str::from_utf8(key).ok().and_then(DetailKey::from_name)
            && details.len() < MAX_DETAILS
        {
            details.push((key, value));
        }
    }
    (phrase.slice(..nl), details)
}

/// One `key=value` pair of a diagnostic line.
fn parse_pair(pair: &[u8]) -> Option<(&[u8], u64)> {
    let eq = pair.iter().position(|&b| b == b'=')?;
    let (key, value) = (&pair[..eq], &pair[eq + 1..]);
    if key.is_empty()
        || !key
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
    {
        return None;
    }
    let (digits, radix) = match value.strip_prefix(b"0x") {
        Some(hex) => (hex, 16),
        None => (value, 10),
    };
    if digits.is_empty() || !digits.iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let value = u64::from_str_radix(std::str::from_utf8(digits).ok()?, radix).ok()?;
    Some((key, value))
}

impl From<SessionError> for io::Error {
    fn from(e: SessionError) -> Self {
        io::Error::new(e.kind(), e)
    }
}

/// Why an operation on a stream's sending or receiving part failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StreamError {
    /// The peer reset its sending part (reads): its code and the Reliable
    /// Size in application bytes (0 for RESET_STREAM). Data below it was
    /// delivered first; a reset stream never reads as complete.
    Reset {
        /// The application error code.
        code: VarInt,
        /// Application bytes delivered before the reset took effect.
        reliable_size: u64,
    },
    /// The peer sent STOP_SENDING (writes).
    Stopped(VarInt),
    /// The stream was not processed by the peer and may be retried: the peer
    /// rejected it, or it is above a GOAWAY watermark.
    Rejected,
    /// The peer sent GOAWAY before the stream emitted its first frame: it
    /// never opened and may be retried on another session (EXTENSIONS.md
    /// Section 3.5).
    GoingAway,
    /// This direction was already closed locally (finished, reset or
    /// stopped).
    ClosedLocally,
    /// The operation needs a feature the peer did not negotiate (for
    /// example peer priorities with a plain QMux peer).
    NotNegotiated,
    /// The session is not established yet, so the stream has no
    /// identifier.
    NotEstablished,
    /// The stream was opened before establishment beyond the peer's stream
    /// limit; its identifier follows a MAX_STREAMS.
    Blocked,
    /// The session ended.
    SessionLost(SessionError),
    /// The read or write timeout of a blocking stream expired (drivers
    /// only).
    TimedOut,
    /// A blocking call was refused on a thread that drives sessions
    /// (drivers only).
    OnDriverThread,
}

impl StreamError {
    /// Whether the stream may be opened again, its data unprocessed by the
    /// peer: ZMUX_REJECTED, a GOAWAY (on another session), or a session
    /// lost to [`SessionError::EarlyDataRejected`] (on a new session
    /// without early data).
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Rejected | Self::GoingAway => true,
            Self::SessionLost(e) => e.is_retryable(),
            _ => false,
        }
    }

    fn kind(&self) -> io::ErrorKind {
        match self {
            Self::Reset { .. } | Self::Stopped(_) => io::ErrorKind::ConnectionReset,
            Self::Rejected | Self::GoingAway => io::ErrorKind::ConnectionRefused,
            Self::ClosedLocally | Self::NotEstablished => io::ErrorKind::NotConnected,
            Self::NotNegotiated => io::ErrorKind::Unsupported,
            Self::Blocked => io::ErrorKind::WouldBlock,
            Self::SessionLost(e) => e.kind(),
            Self::TimedOut => io::ErrorKind::TimedOut,
            Self::OnDriverThread => io::ErrorKind::Deadlock,
        }
    }
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reset { code, .. } => write!(f, "stream reset by peer with code {code}"),
            Self::Stopped(code) => write!(f, "stream stopped by peer with code {code}"),
            Self::Rejected => f.write_str("stream rejected; retryable"),
            Self::GoingAway => f.write_str("the peer is going away; retryable"),
            Self::ClosedLocally => f.write_str("stream direction closed locally"),
            Self::NotNegotiated => f.write_str("not negotiated with the peer"),
            Self::NotEstablished => f.write_str("session not established"),
            Self::Blocked => f.write_str("waiting for stream credit"),
            Self::SessionLost(e) => write!(f, "session lost: {e}"),
            Self::TimedOut => f.write_str("stream operation timed out"),
            Self::OnDriverThread => f.write_str(ON_DRIVER_THREAD),
        }
    }
}

impl std::error::Error for StreamError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SessionLost(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StreamError> for io::Error {
    fn from(e: StreamError) -> Self {
        io::Error::new(e.kind(), e)
    }
}

/// Why opening a stream failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenError {
    /// No stream credit now; wait for [`super::CoreEvent::StreamsAvailable`]
    /// (the drivers' waiting opens do), or try later.
    Blocked,
    /// The peer sent GOAWAY, or the session is shutting down; the stream
    /// may be opened on another session.
    GoingAway,
    /// The session is not established yet.
    NotEstablished,
    /// The preamble needs the peer's `zmux_preamble`, which a plain QMux
    /// peer does not send (EXTENSIONS.md Section 4).
    NotNegotiated,
    /// The preamble is larger than the peer accepts (its Maximum Preamble
    /// Size) or than one record.
    TooLarge,
    /// The preamble is not valid for the stream: a TLV type outside the
    /// application range (0x1000 to 0x3fff) or a GREASE value, or
    /// PIPE_CARRIER on a unidirectional stream.
    InvalidArgument,
    /// The session ended.
    SessionLost(SessionError),
    /// A blocking call was refused on a thread that drives sessions
    /// (drivers only).
    OnDriverThread,
}

impl OpenError {
    /// Whether opening may succeed later (credit), on another session
    /// (GOAWAY), or on a new session without early data
    /// ([`SessionError::EarlyDataRejected`]).
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Blocked | Self::GoingAway => true,
            Self::SessionLost(e) => e.is_retryable(),
            _ => false,
        }
    }
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Blocked => f.write_str("no stream credit"),
            Self::GoingAway => f.write_str("the peer is going away; retryable"),
            Self::NotEstablished => f.write_str("session not established"),
            Self::NotNegotiated => f.write_str("preambles not negotiated with the peer"),
            Self::TooLarge => f.write_str("preamble too large for the peer"),
            Self::InvalidArgument => f.write_str("preamble not valid for this stream"),
            Self::SessionLost(e) => write!(f, "session lost: {e}"),
            Self::OnDriverThread => f.write_str(ON_DRIVER_THREAD),
        }
    }
}

impl std::error::Error for OpenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SessionLost(e) => Some(e),
            _ => None,
        }
    }
}

impl From<OpenError> for io::Error {
    fn from(e: OpenError) -> Self {
        let kind = match &e {
            OpenError::Blocked => io::ErrorKind::WouldBlock,
            OpenError::GoingAway => io::ErrorKind::ConnectionRefused,
            OpenError::NotEstablished => io::ErrorKind::NotConnected,
            OpenError::NotNegotiated => io::ErrorKind::Unsupported,
            OpenError::TooLarge | OpenError::InvalidArgument => io::ErrorKind::InvalidInput,
            OpenError::SessionLost(s) => s.kind(),
            OpenError::OnDriverThread => io::ErrorKind::Deadlock,
        };
        io::Error::new(kind, e)
    }
}

/// Why sending a datagram failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DatagramError {
    /// The peer does not accept datagrams, or datagram flows are not in use
    /// for a stream datagram.
    NotNegotiated,
    /// The datagram does not fit in one DATAGRAM frame; `max` is the largest
    /// payload that does.
    TooLarge {
        /// The largest payload.
        max: usize,
    },
    /// The stream cannot carry datagrams (unidirectional or closed).
    ClosedStream,
    /// The session ended.
    SessionLost(SessionError),
    /// A blocking call was refused on a thread that drives sessions
    /// (drivers only).
    OnDriverThread,
}

impl DatagramError {
    /// Whether sending may succeed if retried: never (the queue drops the
    /// oldest datagram instead of refusing a new one).
    pub fn is_retryable(&self) -> bool {
        false
    }
}

impl fmt::Display for DatagramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNegotiated => f.write_str("datagrams not negotiated with the peer"),
            Self::TooLarge { max } => write!(f, "datagram larger than {max} bytes"),
            Self::ClosedStream => f.write_str("stream cannot carry datagrams"),
            Self::SessionLost(e) => write!(f, "session lost: {e}"),
            Self::OnDriverThread => f.write_str(ON_DRIVER_THREAD),
        }
    }
}

impl std::error::Error for DatagramError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SessionLost(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DatagramError> for io::Error {
    fn from(e: DatagramError) -> Self {
        let kind = match &e {
            DatagramError::NotNegotiated => io::ErrorKind::Unsupported,
            DatagramError::TooLarge { .. } => io::ErrorKind::InvalidInput,
            DatagramError::ClosedStream => io::ErrorKind::NotConnected,
            DatagramError::SessionLost(s) => s.kind(),
            DatagramError::OnDriverThread => io::ErrorKind::Deadlock,
        };
        io::Error::new(kind, e)
    }
}

/// Why a pipe operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PipeError {
    /// Multipath is not in use in this session.
    NotNegotiated,
    /// The session is not established yet.
    NotEstablished,
    /// The endpoint may not join now: it has max_pipes + H unretired
    /// attachments of its own, or a join was refused recently (MULTIPATH.md
    /// Sections 5.4 step 9 and 5.7 step 1). An out-of-band reservation needs
    /// its join at once; retry later.
    Deferred,
    /// No such pipe (it was retired).
    UnknownPipe,
    /// The carrier cannot be used so: a pipe added in band needs an
    /// outbound half.
    InvalidArgument,
    /// The pipe failed ([`Pipe::joined`](crate::Pipe#method.joined)).
    Failed(PipeFailure),
    /// A blocking call was refused on a thread that drives sessions
    /// (drivers only).
    OnDriverThread,
    /// A blocking wait's timeout expired (drivers only).
    TimedOut,
    /// The session ended.
    SessionLost(SessionError),
    /// The std driver could not start the pipe's threads (drivers only);
    /// the pipe failed.
    Io(io::ErrorKind),
    /// The carrier is a stream of a session that runs, directly or through
    /// other sessions of the process, over a pipe of this session
    /// (EXTENSIONS.md Section 10.2; drivers only).
    CarrierLoop,
}

impl PipeError {
    /// Whether the operation may succeed if retried: once the session is
    /// established ([`PipeError::NotEstablished`]).
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::NotEstablished | Self::Deferred)
    }
}

impl fmt::Display for PipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNegotiated => f.write_str("multipath not in use"),
            Self::NotEstablished => f.write_str("session not established"),
            Self::Deferred => f.write_str("joining is deferred"),
            Self::UnknownPipe => f.write_str("unknown pipe"),
            Self::InvalidArgument => f.write_str("carrier not usable as this pipe"),
            Self::Failed(e) => write!(f, "pipe failed: {e}"),
            Self::OnDriverThread => f.write_str(ON_DRIVER_THREAD),
            Self::TimedOut => f.write_str("pipe wait timed out"),
            Self::SessionLost(e) => write!(f, "session lost: {e}"),
            Self::Io(kind) => write!(f, "starting the pipe's I/O failed: {kind}"),
            Self::CarrierLoop => f.write_str("the carrier runs over this session"),
        }
    }
}

impl std::error::Error for PipeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SessionLost(e) => Some(e),
            _ => None,
        }
    }
}

impl From<PipeError> for io::Error {
    fn from(e: PipeError) -> Self {
        let kind = match &e {
            PipeError::NotNegotiated => io::ErrorKind::Unsupported,
            PipeError::NotEstablished => io::ErrorKind::NotConnected,
            PipeError::Deferred => io::ErrorKind::WouldBlock,
            PipeError::UnknownPipe => io::ErrorKind::NotFound,
            PipeError::InvalidArgument => io::ErrorKind::InvalidInput,
            PipeError::Failed(_) => io::ErrorKind::ConnectionReset,
            PipeError::OnDriverThread => io::ErrorKind::Deadlock,
            PipeError::TimedOut => io::ErrorKind::TimedOut,
            PipeError::SessionLost(s) => s.kind(),
            PipeError::Io(kind) => *kind,
            PipeError::CarrierLoop => io::ErrorKind::InvalidInput,
        };
        io::Error::new(kind, e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Error;

    /// A rejection of early data is retryable on every error type and found
    /// again inside the [`io::Error`]s they convert into.
    #[test]
    fn early_data_rejected_is_retryable_through_io() {
        let rejected = SessionError::EarlyDataRejected;
        assert!(rejected.is_retryable());
        assert!(!SessionError::HandshakeTimeout.is_retryable());
        assert!(StreamError::SessionLost(rejected.clone()).is_retryable());
        assert!(OpenError::SessionLost(rejected.clone()).is_retryable());
        assert!(crate::ConnectError::Closed(rejected.clone()).is_retryable());
        for e in [
            io::Error::from(rejected.clone()),
            io::Error::from(StreamError::SessionLost(rejected.clone())),
            io::Error::from(OpenError::SessionLost(rejected.clone())),
            io::Error::from(crate::ConnectError::Closed(rejected.clone())),
        ] {
            assert!(SessionError::in_io(&e).is_some_and(SessionError::is_early_data_rejected));
        }
        assert!(SessionError::in_io(&io::Error::other("x")).is_none());
    }

    /// SPEC.md Section 4.3: the diagnostic line is split off when it parses;
    /// unknown keys are ignored, and a last line that does not parse leaves
    /// the phrase plain text.
    #[test]
    fn reason_phrase_details() {
        let split = |s: &'static str| split_reason(Bytes::from_static(s.as_bytes()));
        let (reason, details) =
            split("data beyond the limit\nstream=4 offset=0x800 x_y=7 limit=2048");
        assert_eq!(&reason[..], b"data beyond the limit");
        assert_eq!(
            details,
            [
                (DetailKey::Stream, 4),
                (DetailKey::Offset, 2048),
                (DetailKey::Limit, 2048)
            ]
        );
        for plain in [
            "no line",
            "text\nstream=0 offset=2048 x=",
            "text\nStream=1",
            "text\nstream=0x",
            "text\nstream=1  pos=2",
            "text\n",
        ] {
            let (reason, details) = split(plain);
            assert_eq!(&reason[..], plain.as_bytes());
            assert!(details.is_empty(), "{plain:?}");
        }
        // The sender's side: the reason, a line feed and the pairs.
        let e = Error::protocol_violation(0x08, "out of order")
            .detail(DetailKey::Stream, 4)
            .detail(DetailKey::Offset, 7);
        assert_eq!(e.reason_phrase(), "out of order\nstream=4 offset=7");
        let (reason, details) = split_reason(Bytes::from(e.reason_phrase()));
        assert_eq!(&reason[..], b"out of order");
        assert_eq!(details, e.details().collect::<Vec<_>>());
    }
}
