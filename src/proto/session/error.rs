//! Errors of the session: one type per kind of operation, shared by the sans-IO core and the
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

/// A setting that cannot work as given: a value outside its range, a
/// combination that is excluded, or a feature enabled without what it
/// needs. It names the setting ([`InvalidConfig::field`]) and says why
/// ([`InvalidConfig::reason`]); nothing was changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct InvalidConfig {
    field: &'static str,
    reason: &'static str,
}

impl InvalidConfig {
    /// The error for the setting `field`, invalid for `reason`. Carrier
    /// adapters and helpers report their own options with it.
    pub const fn new(field: &'static str, reason: &'static str) -> Self {
        Self { field, reason }
    }

    /// The setting, by its field or option name (`max_pipes`,
    /// `ListenerConfig::instance_id`, ...).
    pub const fn field(&self) -> &'static str {
        self.field
    }

    /// Why the value cannot be used.
    pub const fn reason(&self) -> &'static str {
        self.reason
    }
}

impl fmt::Display for InvalidConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}: {}", self.field, self.reason)
    }
}

impl std::error::Error for InvalidConfig {}

impl From<InvalidConfig> for io::Error {
    fn from(e: InvalidConfig) -> Self {
        io::Error::new(io::ErrorKind::InvalidInput, e)
    }
}

/// Why a session ended. The first cause wins.
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
        /// before that line.
        reason: Bytes,
        /// The defined `key=value` pairs of the diagnostic line, in order;
        /// empty without one. Unknown keys are left out.
        details: Vec<(DetailKey, u64)>,
        /// Whether the peer detected the error.
        remote: bool,
    },
    /// The idle timer expired; `remote` when the peer ended the session by
    /// shutting down its pipe without CONNECTION_CLOSE.
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
    /// The resume grace period expired while the session was suspended, or a listener limit ended
    /// the suspended session: CONNECTION_CLOSE(ZMUX_RESUME_TIMEOUT) when a pipe remains.
    /// A peer's ZMUX_RESUME_TIMEOUT is [`SessionError::TransportClosed`].
    ResumeTimeout {
        /// The most recent pipe failure of the session, when a pipe failed.
        last: Option<PipeFailure>,
    },
    /// Every pipe in a direction was lost without resume, or the single
    /// carrier failed or ended inside a record.
    PipesLost {
        /// The most recent pipe failure of the session, when a pipe failed
        /// (`None` when none did: the last pipe was removed gracefully).
        last: Option<PipeFailure>,
    },
    /// Resume could not continue safely: the two endpoints' states
    /// diverged, so the data in flight is in an unknown state
    /// (CONNECTION_CLOSE with ZMUX_RESUME_FAILED, sent or received).
    ResumeFailed {
        /// The reason phrase.
        reason: Bytes,
        /// Whether the peer detected it.
        remote: bool,
    },
}

/// Why a pipe failed: reported with the session's
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
    /// that did not complete.
    Stalled,
    /// The join was not confirmed within `handshake_timeout`: the peer
    /// refused it or never saw it.
    JoinTimedOut,
    /// The peer abandoned the pipe with this error code (PIPE_ABANDON).
    Abandoned(VarInt),
    /// This endpoint removed it abruptly: [`Pipe::abort`](crate::Pipe#method.abort), a resource
    /// limit, or room for a new join.
    Aborted,
    /// The carrier broke the protocol for its state.
    Protocol,
    /// The acceptor closed the carrier of this endpoint's join before
    /// confirming it, with a CONNECTION_CLOSE of this error code; ZMUX_RESUME_FAILED: it has no
    /// session for the locator.
    JoinFailed,
    /// The peer refused the join in its Reply.
    JoinRefused,
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
            Self::JoinFailed => f.write_str("join failed"),
            Self::JoinRefused => f.write_str("join refused"),
        }
    }
}

impl SessionError {
    /// Whether the peer caused the termination.
    pub fn is_remote(&self) -> bool {
        match self {
            Self::ApplicationClosed { remote, .. }
            | Self::TransportClosed { remote, .. }
            | Self::IdleTimeout { remote }
            | Self::ResumeFailed { remote, .. } => *remote,
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
        if let Some(crate::ConnectError::SessionLost(s)) = inner.downcast_ref() {
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
            Self::PipesLost { .. } | Self::ResumeFailed { .. } => io::ErrorKind::ConnectionReset,
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
            Self::ResumeFailed { reason, remote } => write!(
                f,
                "resume failed ({}: {}): the data in flight is in an unknown state",
                side(*remote),
                String::from_utf8_lossy(reason)
            ),
        }
    }
}

impl std::error::Error for SessionError {
    /// The last pipe failure of [`SessionError::ResumeTimeout`] and
    /// [`SessionError::PipesLost`].
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ResumeTimeout { last: Some(l) } | Self::PipesLost { last: Some(l) } => Some(l),
            _ => None,
        }
    }
}

impl std::error::Error for PipeFailure {}

/// The most `key=value` pairs kept from a received diagnostic line: one
/// of each key, whatever the peer sends.
const MAX_DETAILS: usize = 8;

/// Splits a transport Reason Phrase into its text and the defined pairs of
/// its diagnostic line: a last line of space-separated
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
    /// never opened and may be retried on another session.
    GoingAway,
    /// The stream's preamble did not fit the peer's Maximum Preamble Size
    /// known when its identifier was due (the peer's parameters arrived
    /// after the open, below the limit assumed then): nothing was sent and
    /// the stream never opened; the session is unaffected.
    PreambleTooLarge,
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
            Self::PreambleTooLarge => io::ErrorKind::InvalidInput,
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
            Self::PreambleTooLarge => f.write_str("preamble too large for the peer"),
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
    /// peer does not send.
    NotNegotiated,
    /// The preamble, with room for a PRIORITY and a GREASE TLV, is larger
    /// than the limit known now: the peer's Maximum Preamble Size (before
    /// its parameters, the remembered one or the 1024-byte floor), at most
    /// 4096 bytes and one record.
    PreambleTooLarge,
    /// The preamble is not valid for the stream: a TLV type outside the
    /// application range (0x1000 to 0x3fff) or a GREASE value, or
    /// PIPE_CARRIER on a unidirectional stream.
    InvalidArgument,
    /// The session ended.
    SessionLost(SessionError),
    /// A blocking call was refused on a thread that drives sessions
    /// (drivers only).
    OnDriverThread,
    /// A blocking wait's timeout expired (drivers only).
    TimedOut,
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
            Self::PreambleTooLarge => f.write_str("preamble too large for the peer"),
            Self::InvalidArgument => f.write_str("preamble not valid for this stream"),
            Self::SessionLost(e) => write!(f, "session lost: {e}"),
            Self::OnDriverThread => f.write_str(ON_DRIVER_THREAD),
            Self::TimedOut => f.write_str("open wait timed out"),
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
            OpenError::PreambleTooLarge | OpenError::InvalidArgument => io::ErrorKind::InvalidInput,
            OpenError::SessionLost(s) => s.kind(),
            OpenError::OnDriverThread => io::ErrorKind::Deadlock,
            OpenError::TimedOut => io::ErrorKind::TimedOut,
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
    /// A blocking wait's timeout expired (drivers only).
    TimedOut,
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
            Self::TimedOut => f.write_str("datagram wait timed out"),
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
            DatagramError::TimedOut => io::ErrorKind::TimedOut,
        };
        io::Error::new(kind, e)
    }
}

/// What a join-pending session still waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JoinMissing {
    /// The end-to-end declaration (`declare_end_to_end`, or
    /// [`PipeAuth::with_end_to_end`](crate::PipeAuth::with_end_to_end)).
    EndToEnd,
    /// The deferred pre-shared key (`set_join_secret`).
    DeferredPsk,
    /// Both.
    Both,
}

impl fmt::Display for JoinMissing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EndToEnd => {
                "the end-to-end declaration of pipe 0 is missing (declare_end_to_end)"
            }
            Self::DeferredPsk => "the deferred pre-shared key is missing (set_join_secret)",
            Self::Both => {
                "the end-to-end declaration of pipe 0 and the deferred pre-shared key are missing"
            }
        })
    }
}

/// Why a pipe operation failed. Errors compare by variant and value, an
/// [`PipeError::Io`] by identity.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PipeError {
    /// Multipath is not in use in this session.
    NotNegotiated,
    /// The session is not established yet.
    NotEstablished,
    /// The endpoint may not join now: it has max_pipes + H unretired
    /// attachments of its own, or a join was refused recently; retry later.
    Deferred,
    /// No such pipe (it was retired).
    UnknownPipe,
    /// The carrier cannot be used so: a join needs both of its directions, and Bound a
    /// `Secure` declaration and an exporter on one connection.
    InvalidArgument,
    /// The [`PipeOptions`](crate::PipeOptions) are not valid: an idle-probe
    /// interval above 0 and below 1 s or a jitter outside \[0, 1); or a
    /// [`QualityBand`](crate::QualityBand) or
    /// [`CapacityFloor`](crate::CapacityFloor) is not valid.
    InvalidOptions(InvalidConfig),
    /// The pipe failed ([`Pipe::joined`](crate::Pipe#method.joined)).
    Failed(PipeFailure),
    /// The peer refused the join in its Reply: the carrier was closed and
    /// the join backoff started; the session goes on.
    JoinRefused,
    /// The session is join pending: it has no join keys until what this
    /// names is in place.
    JoinPending(JoinMissing),
    /// The deferred pre-shared key was given already.
    JoinSecretSet,
    /// A blocking call was refused on a thread that drives sessions
    /// (drivers only).
    OnDriverThread,
    /// A blocking wait's timeout expired (drivers only).
    TimedOut,
    /// The session ended.
    SessionLost(SessionError),
    /// Dialling or starting the pipe's I/O failed (drivers only): the
    /// carrier's dial, or the std driver's threads; the pipe failed.
    Io(std::sync::Arc<io::Error>),
    /// The carrier is a stream of a session that runs, directly or through
    /// other sessions of the process, over a pipe of this session
    /// (drivers only).
    CarrierLoop,
}

impl PartialEq for PipeError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::InvalidOptions(a), Self::InvalidOptions(b)) => a == b,
            (Self::Failed(a), Self::Failed(b)) => a == b,
            (Self::JoinPending(a), Self::JoinPending(b)) => a == b,
            (Self::SessionLost(a), Self::SessionLost(b)) => a == b,
            (Self::Io(a), Self::Io(b)) => std::sync::Arc::ptr_eq(a, b),
            // The other variants carry nothing.
            (a, b) => std::mem::discriminant(a) == std::mem::discriminant(b),
        }
    }
}

impl Eq for PipeError {}

impl PipeError {
    /// Whether the operation may succeed if retried: once the session is
    /// established ([`PipeError::NotEstablished`]).
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::NotEstablished | Self::Deferred | Self::JoinPending(_)
        )
    }

    /// The error of a failed pipe: [`PipeError::JoinRefused`] for a refused
    /// join, else [`PipeError::Failed`].
    pub(crate) fn failed(f: PipeFailure) -> Self {
        match f {
            PipeFailure::JoinRefused => Self::JoinRefused,
            f => Self::Failed(f),
        }
    }
}

impl fmt::Display for PipeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotNegotiated => f.write_str("multipath not in use"),
            Self::JoinPending(m) => write!(f, "join pending: {m}"),
            Self::JoinSecretSet => f.write_str("join secret already set"),
            Self::NotEstablished => f.write_str("session not established"),
            Self::Deferred => f.write_str("joining is deferred"),
            Self::UnknownPipe => f.write_str("unknown pipe"),
            Self::InvalidArgument => f.write_str("carrier not usable as this pipe"),
            Self::InvalidOptions(e) => write!(f, "pipe options not valid: {e}"),
            Self::Failed(e) => write!(f, "pipe failed: {e}"),
            Self::JoinRefused => f.write_str("join refused by the peer"),
            Self::OnDriverThread => f.write_str(ON_DRIVER_THREAD),
            Self::TimedOut => f.write_str("pipe wait timed out"),
            Self::SessionLost(e) => write!(f, "session lost: {e}"),
            Self::Io(e) => write!(f, "the pipe's I/O failed: {e}"),
            Self::CarrierLoop => f.write_str("the carrier runs over this session"),
        }
    }
}

impl std::error::Error for PipeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SessionLost(e) => Some(e),
            Self::InvalidOptions(e) => Some(e),
            Self::Io(e) => Some(&**e),
            _ => None,
        }
    }
}

impl From<PipeError> for io::Error {
    fn from(e: PipeError) -> Self {
        let kind = match &e {
            PipeError::NotNegotiated => io::ErrorKind::Unsupported,
            PipeError::NotEstablished => io::ErrorKind::NotConnected,
            PipeError::Deferred | PipeError::JoinPending(_) => io::ErrorKind::WouldBlock,
            PipeError::JoinSecretSet => io::ErrorKind::AlreadyExists,
            PipeError::UnknownPipe => io::ErrorKind::NotFound,
            PipeError::InvalidArgument | PipeError::InvalidOptions(_) | PipeError::CarrierLoop => {
                io::ErrorKind::InvalidInput
            }
            PipeError::Failed(_) => io::ErrorKind::ConnectionReset,
            PipeError::JoinRefused => io::ErrorKind::ConnectionRefused,
            PipeError::OnDriverThread => io::ErrorKind::Deadlock,
            PipeError::TimedOut => io::ErrorKind::TimedOut,
            PipeError::SessionLost(s) => s.kind(),
            PipeError::Io(e) => e.kind(),
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
        assert!(crate::ConnectError::SessionLost(rejected.clone()).is_retryable());
        for e in [
            io::Error::from(rejected.clone()),
            io::Error::from(StreamError::SessionLost(rejected.clone())),
            io::Error::from(OpenError::SessionLost(rejected.clone())),
            io::Error::from(crate::ConnectError::SessionLost(rejected)),
        ] {
            assert!(SessionError::in_io(&e).is_some_and(SessionError::is_early_data_rejected));
        }
        assert!(SessionError::in_io(&io::Error::other("x")).is_none());
    }

    /// A Reason Phrase's diagnostic line is split off when it parses;
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
