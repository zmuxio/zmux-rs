use crate::error::Error;
use crate::payload::StreamMetadata;
use crate::session::SessionState;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    StreamOpened,
    StreamAccepted,
    SessionClosed,
}

impl EventType {
    #[inline]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StreamOpened => "stream_opened",
            Self::StreamAccepted => "stream_accepted",
            Self::SessionClosed => "session_closed",
        }
    }
}

impl fmt::Display for EventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl AsRef<str> for EventType {
    #[inline]
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamEventInfo {
    pub stream_id: u64,
    pub metadata: StreamMetadata,
    pub local: bool,
    pub bidirectional: bool,
    pub application_visible: bool,
}

impl StreamEventInfo {
    #[inline]
    pub fn open_info(&self) -> &[u8] {
        &self.metadata.open_info
    }

    #[inline]
    pub fn open_info_len(&self) -> usize {
        self.metadata.open_info.len()
    }

    #[inline]
    pub fn has_open_info(&self) -> bool {
        !self.metadata.open_info.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub event_type: EventType,
    pub session_state: SessionState,
    pub stream_id: u64,
    pub stream: Option<StreamEventInfo>,
    pub local: bool,
    pub bidirectional: bool,
    pub time: SystemTime,
    pub error: Option<Error>,
    pub application_visible: bool,
}

pub type EventHandler = Arc<dyn Fn(Event) + Send + Sync + 'static>;

#[inline]
pub(crate) fn dispatch_event(handler: &EventHandler, event: Event) {
    let _ = catch_unwind(AssertUnwindSafe(|| handler(event)));
}

#[cfg(test)]
mod tests {
    use super::EventType;

    #[test]
    fn event_type_is_displayable_and_string_borrowable() {
        assert_eq!(EventType::StreamOpened.as_str(), "stream_opened");
        assert_eq!(EventType::StreamAccepted.to_string(), "stream_accepted");
        assert_eq!(EventType::SessionClosed.as_ref(), "session_closed");
    }
}
