use std::borrow::Cow;
use std::error::Error as StdError;
use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

const OPEN_INFO_UNAVAILABLE_MESSAGE: &str = "zmux: open_info requires negotiated open_metadata";
const OPEN_METADATA_TOO_LARGE_MESSAGE: &str =
    "zmux: opening metadata exceeds peer max_frame_payload";
const EMPTY_METADATA_UPDATE_MESSAGE: &str = "zmux: metadata update has no fields";
const PRIORITY_UPDATE_UNAVAILABLE_MESSAGE: &str =
    "metadata update requires negotiated priority_update";
const PRIORITY_UPDATE_TOO_LARGE_MESSAGE: &str =
    "zmux: priority update exceeds peer max_extension_payload_bytes";
const KEEPALIVE_TIMEOUT_MESSAGE: &str = "zmux: keepalive timeout";
const GRACEFUL_CLOSE_TIMEOUT_MESSAGE: &str = "zmux: graceful close drain timed out";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ErrorScope {
    #[default]
    Unknown,
    Session,
    Stream,
}

impl ErrorScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Session => "session",
            Self::Stream => "stream",
        }
    }
}

impl fmt::Display for ErrorScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for ErrorScope {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ErrorOperation {
    #[default]
    Unknown,
    Open,
    Accept,
    Read,
    Write,
    Close,
}

impl ErrorOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Open => "open",
            Self::Accept => "accept",
            Self::Read => "read",
            Self::Write => "write",
            Self::Close => "close",
        }
    }
}

impl fmt::Display for ErrorOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for ErrorOperation {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ErrorSource {
    #[default]
    Unknown,
    Local,
    Remote,
    Transport,
}

impl ErrorSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Transport => "transport",
        }
    }
}

impl fmt::Display for ErrorSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for ErrorSource {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ErrorDirection {
    #[default]
    Unknown,
    Read,
    Write,
    Both,
}

impl ErrorDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Read => "read",
            Self::Write => "write",
            Self::Both => "both",
        }
    }
}

impl fmt::Display for ErrorDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for ErrorDirection {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum TerminationKind {
    #[default]
    Unknown,
    Graceful,
    Stopped,
    Reset,
    Abort,
    SessionTermination,
    Timeout,
    Interrupted,
}

impl TerminationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Graceful => "graceful",
            Self::Stopped => "stopped",
            Self::Reset => "reset",
            Self::Abort => "abort",
            Self::SessionTermination => "session_termination",
            Self::Timeout => "timeout",
            Self::Interrupted => "interrupted",
        }
    }
}

impl fmt::Display for TerminationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for TerminationKind {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum ErrorCode {
    NoError = 0,
    Protocol = 1,
    FlowControl = 2,
    StreamLimit = 3,
    RefusedStream = 4,
    StreamState = 5,
    StreamClosed = 6,
    SessionClosing = 7,
    Cancelled = 8,
    IdleTimeout = 9,
    FrameSize = 10,
    UnsupportedVersion = 11,
    RoleConflict = 12,
    Internal = 13,
}

impl ErrorCode {
    pub fn from_code(code: u64) -> Option<Self> {
        Self::from_u64(code)
    }

    pub fn from_u64(v: u64) -> Option<Self> {
        Self::try_from(v).ok()
    }

    pub fn as_u64(self) -> u64 {
        self as u64
    }

    pub fn as_str(self) -> &'static str {
        self.name()
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::NoError => "NO_ERROR",
            Self::Protocol => "PROTOCOL",
            Self::FlowControl => "FLOW_CONTROL",
            Self::StreamLimit => "STREAM_LIMIT",
            Self::RefusedStream => "REFUSED_STREAM",
            Self::StreamState => "STREAM_STATE",
            Self::StreamClosed => "STREAM_CLOSED",
            Self::SessionClosing => "SESSION_CLOSING",
            Self::Cancelled => "CANCELLED",
            Self::IdleTimeout => "IDLE_TIMEOUT",
            Self::FrameSize => "FRAME_SIZE",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::RoleConflict => "ROLE_CONFLICT",
            Self::Internal => "INTERNAL",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl AsRef<str> for ErrorCode {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl TryFrom<u64> for ErrorCode {
    type Error = u64;

    fn try_from(value: u64) -> std::result::Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::NoError,
            1 => Self::Protocol,
            2 => Self::FlowControl,
            3 => Self::StreamLimit,
            4 => Self::RefusedStream,
            5 => Self::StreamState,
            6 => Self::StreamClosed,
            7 => Self::SessionClosing,
            8 => Self::Cancelled,
            9 => Self::IdleTimeout,
            10 => Self::FrameSize,
            11 => Self::UnsupportedVersion,
            12 => Self::RoleConflict,
            13 => Self::Internal,
            _ => return Err(value),
        })
    }
}

impl From<ErrorCode> for u64 {
    fn from(value: ErrorCode) -> Self {
        value.as_u64()
    }
}

#[derive(Debug, Clone)]
pub struct Error {
    code: Option<ErrorCode>,
    application_code: Option<u64>,
    reason: Option<String>,
    io_kind: Option<io::ErrorKind>,
    scope: ErrorScope,
    operation: ErrorOperation,
    source: ErrorSource,
    direction: ErrorDirection,
    termination_kind: TerminationKind,
    message: Cow<'static, str>,
}

impl Error {
    const SESSION_CLOSED_MESSAGE: &'static str = "zmux: session closed";

    fn default_termination_kind(code: Option<ErrorCode>) -> TerminationKind {
        match code {
            Some(ErrorCode::IdleTimeout) => TerminationKind::Timeout,
            _ => TerminationKind::Unknown,
        }
    }

    pub fn new(code: ErrorCode, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code: Some(code),
            application_code: None,
            reason: None,
            io_kind: None,
            scope: ErrorScope::Unknown,
            operation: ErrorOperation::Unknown,
            source: ErrorSource::Unknown,
            direction: ErrorDirection::Unknown,
            termination_kind: Self::default_termination_kind(Some(code)),
            message: message.into(),
        }
    }

    pub fn local(message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            code: None,
            application_code: None,
            reason: None,
            io_kind: None,
            scope: ErrorScope::Unknown,
            operation: ErrorOperation::Unknown,
            source: ErrorSource::Local,
            direction: ErrorDirection::Unknown,
            termination_kind: TerminationKind::Unknown,
            message: message.into(),
        }
    }

    pub fn code(&self) -> Option<ErrorCode> {
        self.code
            .or_else(|| self.application_code.and_then(ErrorCode::from_u64))
    }

    pub fn application_code(&self) -> Option<u64> {
        self.application_code
    }

    pub fn numeric_code(&self) -> Option<u64> {
        self.application_code
            .or_else(|| self.code.map(ErrorCode::as_u64))
    }

    pub fn reason(&self) -> Option<&str> {
        self.reason.as_deref()
    }

    pub fn message(&self) -> &str {
        self.message.as_ref()
    }

    pub fn source_io_error_kind(&self) -> Option<io::ErrorKind> {
        self.io_kind
    }

    pub fn scope(&self) -> ErrorScope {
        self.scope
    }

    pub fn operation(&self) -> ErrorOperation {
        self.operation
    }

    pub fn source(&self) -> ErrorSource {
        self.source
    }

    pub fn direction(&self) -> ErrorDirection {
        self.direction
    }

    pub fn termination_kind(&self) -> TerminationKind {
        self.termination_kind
    }

    pub fn is_error_code(&self, code: ErrorCode) -> bool {
        self.code() == Some(code)
    }

    pub fn is_application_code(&self, code: u64) -> bool {
        self.application_code == Some(code)
    }

    pub fn is_session_closed(&self) -> bool {
        self.code() == Some(ErrorCode::SessionClosing)
            || self.message.as_ref() == Self::SESSION_CLOSED_MESSAGE
    }

    pub fn is_timeout(&self) -> bool {
        let message = self.message.as_ref();
        self.termination_kind == TerminationKind::Timeout
            || self.code() == Some(ErrorCode::IdleTimeout)
            || self.io_kind == Some(io::ErrorKind::TimedOut)
            || (message.starts_with("zmux: ") && message.ends_with(" timed out"))
    }

    pub fn is_interrupted(&self) -> bool {
        self.termination_kind == TerminationKind::Interrupted
            || self.io_kind == Some(io::ErrorKind::Interrupted)
    }

    pub fn io_error_kind(&self) -> io::ErrorKind {
        if let Some(kind) = self.io_kind {
            return kind;
        }
        if self.code() == Some(ErrorCode::IdleTimeout) {
            return io::ErrorKind::TimedOut;
        }
        match self.termination_kind {
            TerminationKind::Timeout => io::ErrorKind::TimedOut,
            TerminationKind::Interrupted => io::ErrorKind::Interrupted,
            _ => io::ErrorKind::Other,
        }
    }

    pub fn is_stream_not_readable(&self) -> bool {
        self.message.as_ref() == "zmux: stream is not readable"
    }

    pub fn is_stream_not_writable(&self) -> bool {
        self.message.as_ref() == "zmux: stream is not writable"
    }

    pub fn is_read_closed(&self) -> bool {
        self.message.as_ref() == "zmux: read side closed"
    }

    pub fn is_write_closed(&self) -> bool {
        self.message.as_ref() == "zmux: write side closed"
    }

    pub fn is_open_limited(&self) -> bool {
        let message = self.message.as_ref();
        message.contains("local open limited by session memory cap")
            || message.contains("provisional open limit reached")
    }

    pub fn is_open_expired(&self) -> bool {
        self.message
            .as_ref()
            .contains("provisional local open expired")
    }

    pub fn is_open_info_unavailable(&self) -> bool {
        self.message.as_ref() == OPEN_INFO_UNAVAILABLE_MESSAGE
    }

    pub fn is_open_metadata_too_large(&self) -> bool {
        self.message.as_ref() == OPEN_METADATA_TOO_LARGE_MESSAGE
    }

    pub fn is_adapter_unsupported(&self) -> bool {
        self.message
            .as_ref()
            .contains("feature not supported by adapter")
    }

    pub fn is_priority_update_unavailable(&self) -> bool {
        self.message
            .as_ref()
            .contains(PRIORITY_UPDATE_UNAVAILABLE_MESSAGE)
    }

    pub fn is_priority_update_too_large(&self) -> bool {
        self.message.as_ref() == PRIORITY_UPDATE_TOO_LARGE_MESSAGE
    }

    pub fn is_empty_metadata_update(&self) -> bool {
        self.message.as_ref() == EMPTY_METADATA_UPDATE_MESSAGE
    }

    pub fn is_keepalive_timeout(&self) -> bool {
        self.code() == Some(ErrorCode::IdleTimeout)
            && (self.message.as_ref() == KEEPALIVE_TIMEOUT_MESSAGE
                || self.reason() == Some(KEEPALIVE_TIMEOUT_MESSAGE))
    }

    pub fn is_graceful_close_timeout(&self) -> bool {
        self.message.as_ref() == GRACEFUL_CLOSE_TIMEOUT_MESSAGE
    }

    pub(crate) fn is_urgent_writer_queue_full(&self) -> bool {
        self.code == Some(ErrorCode::Internal)
            && self.message.as_ref() == "zmux: urgent writer queue full"
    }

    pub(crate) fn is_protocol_message(&self, message: &str) -> bool {
        self.code == Some(ErrorCode::Protocol) && self.message.as_ref() == message
    }

    pub(crate) fn is_frame_size_message(&self, message: &str) -> bool {
        self.code == Some(ErrorCode::FrameSize) && self.message.as_ref() == message
    }

    pub fn with_scope(mut self, scope: ErrorScope) -> Self {
        if scope != ErrorScope::Unknown {
            self.scope = scope;
        }
        self
    }

    pub fn with_operation(mut self, operation: ErrorOperation) -> Self {
        if operation != ErrorOperation::Unknown {
            self.operation = operation;
        }
        self
    }

    pub fn with_source(mut self, source: ErrorSource) -> Self {
        if source != ErrorSource::Unknown {
            self.source = source;
        }
        self
    }

    pub fn with_direction(mut self, direction: ErrorDirection) -> Self {
        if direction != ErrorDirection::Unknown {
            self.direction = direction;
        }
        self
    }

    pub fn with_termination_kind(mut self, termination_kind: TerminationKind) -> Self {
        if termination_kind != TerminationKind::Unknown {
            self.termination_kind = termination_kind;
        }
        self
    }

    pub fn with_session_context(mut self, operation: ErrorOperation) -> Self {
        let is_terminal = self.termination_kind == TerminationKind::Unknown
            && (self.is_session_closed()
                || (self.application_code.is_some()
                    && matches!(self.scope, ErrorScope::Unknown | ErrorScope::Session)));
        self.scope = ErrorScope::Session;
        if operation != ErrorOperation::Unknown {
            self.operation = operation;
        }
        if self.direction == ErrorDirection::Unknown {
            self.direction = ErrorDirection::Both;
        }
        if is_terminal {
            self.termination_kind = TerminationKind::SessionTermination;
        }
        self
    }

    pub fn with_stream_context(
        mut self,
        operation: ErrorOperation,
        direction: ErrorDirection,
    ) -> Self {
        let is_terminal_session_error =
            self.termination_kind == TerminationKind::Unknown && self.is_session_closed();
        self.scope = ErrorScope::Stream;
        if operation != ErrorOperation::Unknown {
            self.operation = operation;
        }
        if direction != ErrorDirection::Unknown {
            self.direction = direction;
        }
        if is_terminal_session_error {
            self.termination_kind = TerminationKind::SessionTermination;
        }
        self
    }

    pub fn protocol(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::Protocol, message)
    }

    pub fn frame_size(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::FrameSize, message)
    }

    pub fn unsupported_version(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::UnsupportedVersion, message)
    }

    pub fn role_conflict(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::RoleConflict, message)
    }

    pub fn flow_control(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::FlowControl, message)
    }

    pub fn stream_state(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorCode::StreamState, message)
    }

    pub fn stream_closed() -> Self {
        Self::new(ErrorCode::StreamClosed, "zmux: stream closed")
    }

    pub fn read_closed() -> Self {
        Self::local("zmux: read side closed").with_termination_kind(TerminationKind::Stopped)
    }

    pub fn write_closed() -> Self {
        Self::local("zmux: write side closed")
    }

    pub fn session_closed() -> Self {
        Self::local(Self::SESSION_CLOSED_MESSAGE)
    }

    pub fn application(code: u64, reason: impl Into<String>) -> Self {
        Self::try_application(code, reason).unwrap_or_else(|err| err)
    }

    pub fn try_application(code: u64, reason: impl Into<String>) -> Result<Self> {
        if code > crate::varint::MAX_VARINT62 {
            return Err(Self::protocol(
                "zmux: application error code exceeds varint62 range",
            ));
        }
        Ok(Self::application_unchecked(code, reason))
    }

    pub(crate) fn application_unchecked(code: u64, reason: impl Into<String>) -> Self {
        debug_assert!(code <= crate::varint::MAX_VARINT62);
        let reason = reason.into();
        let known_code = ErrorCode::from_u64(code);
        Self {
            code: None,
            application_code: Some(code),
            reason: (!reason.is_empty()).then_some(reason),
            io_kind: None,
            scope: ErrorScope::Unknown,
            operation: ErrorOperation::Unknown,
            source: ErrorSource::Unknown,
            direction: ErrorDirection::Unknown,
            termination_kind: Self::default_termination_kind(known_code),
            message: Cow::Borrowed(""),
        }
    }

    pub fn io(err: io::Error) -> Self {
        let kind = err.kind();
        let mut error =
            Self::new(ErrorCode::Internal, err.to_string()).with_source(ErrorSource::Transport);
        error.io_kind = Some(kind);
        match kind {
            io::ErrorKind::Interrupted => {
                error = error.with_termination_kind(TerminationKind::Interrupted);
            }
            io::ErrorKind::TimedOut => {
                error = error.with_termination_kind(TerminationKind::Timeout);
            }
            _ => {}
        }
        error
    }

    pub fn timeout(operation: impl AsRef<str>) -> Self {
        Self::local(format!("zmux: {} timed out", operation.as_ref()))
            .with_termination_kind(TerminationKind::Timeout)
    }

    pub fn graceful_close_timeout() -> Self {
        Self::local(GRACEFUL_CLOSE_TIMEOUT_MESSAGE).with_termination_kind(TerminationKind::Timeout)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.application_code {
            if let Some(reason) = self.reason.as_deref() {
                return write!(f, "zmux application error {code}: {reason}");
            }
            return write!(f, "zmux application error {code}");
        }
        match self.code {
            Some(code) => write!(f, "{code}: {}", self.message.as_ref()),
            None => f.write_str(self.message.as_ref()),
        }
    }
}

impl StdError for Error {}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::io(value)
    }
}

impl From<Error> for io::Error {
    fn from(value: Error) -> Self {
        io::Error::new(value.io_error_kind(), value)
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{
        Error, ErrorCode, ErrorDirection, ErrorOperation, ErrorScope, ErrorSource, TerminationKind,
    };

    #[test]
    fn standard_application_codes_map_to_core_error_codes() {
        let standard = Error::application(ErrorCode::Cancelled.as_u64(), "stop");
        assert_eq!(standard.code(), Some(ErrorCode::Cancelled));
        assert_eq!(
            standard.application_code(),
            Some(ErrorCode::Cancelled.as_u64())
        );
        assert_eq!(standard.numeric_code(), Some(ErrorCode::Cancelled.as_u64()));
        assert!(standard.is_error_code(ErrorCode::Cancelled));

        let non_core = Error::application(256, "extension");
        assert_eq!(non_core.code(), None);
        assert_eq!(non_core.application_code(), Some(256));
        assert_eq!(non_core.numeric_code(), Some(256));
        assert!(non_core.is_application_code(256));
    }

    #[test]
    fn application_error_survives_io_error_wrapping() {
        let err = Error::application(ErrorCode::Cancelled.as_u64(), "stop");
        assert_eq!(err.code(), Some(ErrorCode::Cancelled));
        assert_eq!(err.reason(), Some("stop"));
        assert!(err.is_error_code(ErrorCode::Cancelled));

        let wrapped: std::io::Error = err.into();
        assert_eq!(wrapped.kind(), std::io::ErrorKind::Other);

        let preserved = wrapped
            .get_ref()
            .and_then(|source| source.downcast_ref::<Error>())
            .expect("structured application error should be preserved inside io::Error");
        assert_eq!(preserved.code(), Some(ErrorCode::Cancelled));
        assert_eq!(
            preserved.application_code(),
            Some(ErrorCode::Cancelled.as_u64())
        );
        assert_eq!(preserved.reason(), Some("stop"));
        assert!(preserved.is_error_code(ErrorCode::Cancelled));
    }

    #[test]
    fn application_code_construction_enforces_varint62_range() {
        let max = Error::try_application(crate::varint::MAX_VARINT62, "").unwrap();
        assert_eq!(max.application_code(), Some(crate::varint::MAX_VARINT62));

        let err =
            Error::try_application(crate::varint::MAX_VARINT62 + 1, "out of range").unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert_eq!(err.application_code(), None);

        let fallback = Error::application(crate::varint::MAX_VARINT62 + 1, "out of range");
        assert_eq!(fallback.code(), Some(ErrorCode::Protocol));
        assert_eq!(fallback.application_code(), None);
    }

    #[test]
    fn static_error_messages_are_borrowed() {
        let closed = Error::session_closed();
        assert!(matches!(
            closed.message,
            Cow::Borrowed(Error::SESSION_CLOSED_MESSAGE)
        ));
        assert_eq!(closed.message(), Error::SESSION_CLOSED_MESSAGE);

        let application = Error::application(77, "bye");
        assert!(matches!(application.message, Cow::Borrowed("")));
        assert_eq!(application.to_string(), "zmux application error 77: bye");

        let application_without_reason = Error::application(78, "");
        assert!(matches!(
            application_without_reason.message,
            Cow::Borrowed("")
        ));
        assert_eq!(
            application_without_reason.to_string(),
            "zmux application error 78"
        );

        let dynamic = Error::timeout("read");
        assert!(matches!(dynamic.message, Cow::Owned(_)));
    }

    #[test]
    fn structured_error_enums_are_displayable_and_string_borrowable() {
        assert_eq!(ErrorScope::Session.to_string(), "session");
        assert_eq!(ErrorOperation::Write.as_ref(), "write");
        assert_eq!(ErrorSource::Transport.to_string(), "transport");
        assert_eq!(ErrorDirection::Both.as_ref(), "both");
        assert_eq!(TerminationKind::Timeout.to_string(), "timeout");
        assert_eq!(ErrorCode::Cancelled.as_str(), "CANCELLED");
        assert_eq!(ErrorCode::Cancelled.as_ref(), "CANCELLED");
    }

    #[test]
    fn error_code_converts_from_and_into_wire_numbers() {
        assert_eq!(ErrorCode::try_from(1), Ok(ErrorCode::Protocol));
        assert_eq!(ErrorCode::from_u64(13), Some(ErrorCode::Internal));
        assert_eq!(ErrorCode::try_from(999), Err(999));
        assert_eq!(
            u64::from(ErrorCode::Cancelled),
            ErrorCode::Cancelled.as_u64()
        );
    }

    #[test]
    fn session_context_marks_only_terminal_session_errors() {
        let closed = Error::session_closed().with_session_context(ErrorOperation::Accept);
        assert_eq!(closed.scope(), ErrorScope::Session);
        assert_eq!(closed.operation(), ErrorOperation::Accept);
        assert_eq!(closed.direction(), ErrorDirection::Both);
        assert_eq!(
            closed.termination_kind(),
            TerminationKind::SessionTermination
        );

        let peer_close = Error::application(77, "bye")
            .with_source(ErrorSource::Remote)
            .with_session_context(ErrorOperation::Open);
        assert_eq!(
            peer_close.termination_kind(),
            TerminationKind::SessionTermination
        );

        let standard_session_close = Error::application(ErrorCode::SessionClosing.as_u64(), "");
        assert!(standard_session_close.is_session_closed());

        let open_limit = Error::local("zmux: provisional open limit reached")
            .with_session_context(ErrorOperation::Open);
        assert_eq!(open_limit.scope(), ErrorScope::Session);
        assert_eq!(open_limit.operation(), ErrorOperation::Open);
        assert_eq!(open_limit.termination_kind(), TerminationKind::Unknown);
    }

    #[test]
    fn stream_context_marks_session_closed_as_session_termination() {
        let closed = Error::session_closed()
            .with_source(ErrorSource::Local)
            .with_stream_context(ErrorOperation::Write, ErrorDirection::Write);
        assert_eq!(closed.scope(), ErrorScope::Stream);
        assert_eq!(closed.operation(), ErrorOperation::Write);
        assert_eq!(closed.direction(), ErrorDirection::Write);
        assert_eq!(closed.source(), ErrorSource::Local);
        assert_eq!(
            closed.termination_kind(),
            TerminationKind::SessionTermination
        );

        let stopped =
            Error::read_closed().with_stream_context(ErrorOperation::Read, ErrorDirection::Read);
        assert_eq!(stopped.termination_kind(), TerminationKind::Stopped);

        let ordinary = Error::local("zmux: stream is not writable")
            .with_stream_context(ErrorOperation::Write, ErrorDirection::Write);
        assert_eq!(ordinary.termination_kind(), TerminationKind::Unknown);
    }

    #[test]
    fn timeout_errors_keep_timeout_termination_kind() {
        let err = Error::timeout("accept").with_session_context(ErrorOperation::Accept);
        assert_eq!(err.scope(), ErrorScope::Session);
        assert_eq!(err.operation(), ErrorOperation::Accept);
        assert_eq!(err.source(), ErrorSource::Local);
        assert_eq!(err.direction(), ErrorDirection::Both);
        assert_eq!(err.termination_kind(), TerminationKind::Timeout);
        assert!(err.is_timeout());

        let drain = Error::graceful_close_timeout().with_session_context(ErrorOperation::Close);
        assert_eq!(drain.termination_kind(), TerminationKind::Timeout);
        assert!(drain.is_timeout());
        assert!(drain.is_graceful_close_timeout());
    }

    #[test]
    fn cross_language_error_helpers_cover_public_sentinel_conditions() {
        assert!(Error::local("zmux: metadata update has no fields").is_empty_metadata_update());
        assert!(
            Error::protocol("zmux: open_info requires negotiated open_metadata")
                .is_open_info_unavailable()
        );
        assert!(
            Error::protocol("zmux: opening metadata exceeds peer max_frame_payload")
                .is_open_metadata_too_large()
        );
        assert!(
            Error::local("zmux: priority update exceeds peer max_extension_payload_bytes")
                .is_priority_update_too_large()
        );
        assert!(Error::protocol(
            "zmux: metadata update requires negotiated priority_update and matching semantic capability",
        )
            .is_priority_update_unavailable());
        assert!(Error::local(
            "zmux: feature not supported by adapter: metadata update requires negotiated priority_update",
        )
            .is_adapter_unsupported());
        assert!(Error::local(
            "zmux: feature not supported by adapter: metadata update requires negotiated priority_update",
        )
            .is_priority_update_unavailable());
        assert!(Error::local("zmux: provisional open limit reached").is_open_limited());
        assert!(Error::local("zmux: local open limited by session memory cap").is_open_limited());
    }

    #[test]
    fn interrupted_io_errors_keep_interrupted_termination_kind() {
        let err = Error::io(std::io::Error::from(std::io::ErrorKind::Interrupted))
            .with_session_context(ErrorOperation::Read);
        assert_eq!(err.source(), ErrorSource::Transport);
        assert_eq!(err.termination_kind(), TerminationKind::Interrupted);
        assert!(err.is_interrupted());
    }

    #[test]
    fn io_error_conversion_preserves_timeout_and_interrupted_kinds() {
        let timeout = Error::timeout("read");
        let io_timeout: std::io::Error = timeout.into();
        assert_eq!(io_timeout.kind(), std::io::ErrorKind::TimedOut);

        let interrupted = Error::io(std::io::Error::from(std::io::ErrorKind::Interrupted));
        assert_eq!(
            interrupted.source_io_error_kind(),
            Some(std::io::ErrorKind::Interrupted)
        );
        let io_interrupted: std::io::Error = interrupted.into();
        assert_eq!(io_interrupted.kind(), std::io::ErrorKind::Interrupted);

        let transport_timeout = Error::io(std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert_eq!(
            transport_timeout.source_io_error_kind(),
            Some(std::io::ErrorKind::TimedOut)
        );
        assert_eq!(transport_timeout.source(), ErrorSource::Transport);
        assert_eq!(
            transport_timeout.termination_kind(),
            TerminationKind::Timeout
        );
        assert!(transport_timeout.is_timeout());

        let broken_pipe = Error::io(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
        assert_eq!(
            broken_pipe.source_io_error_kind(),
            Some(std::io::ErrorKind::BrokenPipe)
        );
        let io_broken_pipe: std::io::Error = broken_pipe.into();
        assert_eq!(io_broken_pipe.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn idle_timeout_code_is_typed_as_timeout() {
        let core = Error::new(ErrorCode::IdleTimeout, "zmux: keepalive timeout");
        assert_eq!(core.termination_kind(), TerminationKind::Timeout);
        assert!(core.is_timeout());
        assert!(core.is_keepalive_timeout());
        let io_core: std::io::Error = core.into();
        assert_eq!(io_core.kind(), std::io::ErrorKind::TimedOut);

        let application =
            Error::application(ErrorCode::IdleTimeout.as_u64(), "zmux: keepalive timeout");
        assert_eq!(application.code(), Some(ErrorCode::IdleTimeout));
        assert_eq!(application.termination_kind(), TerminationKind::Timeout);
        assert!(application.is_timeout());
        assert!(application.is_keepalive_timeout());
        let io_application: std::io::Error = application.into();
        assert_eq!(io_application.kind(), std::io::ErrorKind::TimedOut);
    }
}
