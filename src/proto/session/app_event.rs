//! The application's view of a session's events: what
//! [`Session::next_event`](crate::Session#method.next_event) returns and a
//! [`Tracer`] observes.

use std::fmt;

use super::{PipeFailure, PipeHalf, PipeId, PrioritySource, SessionError};

/// The GOAWAY watermarks the peer sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoAway {
    /// Bidirectional streams with a lower index were or may be processed.
    pub max_bidi: u64,
    /// Unidirectional streams with a lower index were or may be processed.
    pub max_uni: u64,
    /// The peer's application error code.
    pub code: u64,
}

/// Support of a protocol extension at each side, a negotiation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Support {
    /// The local endpoint announced it.
    pub local: bool,
    /// The peer announced it (false until its parameters were processed).
    pub peer: bool,
}

/// A kind of carrier a dial in a carrier mode chooses among: its name is the one events, statistics
/// and caches use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum CarrierKind {
    /// A WebSocket.
    WebSocket,
    /// A bidirectional streaming HTTP request.
    Streaming,
    /// A split bootstrap: an uplink `POST` and a downlink `GET`.
    Split,
    /// The exchange carrier.
    Exchange,
    /// A QUIC connection.
    Quic,
    /// An HTTP/3 request.
    Http3,
    /// A WebTransport session.
    WebTransport,
}

impl CarrierKind {
    /// Every kind.
    pub const ALL: [Self; 7] = [
        Self::WebSocket,
        Self::Streaming,
        Self::Split,
        Self::Exchange,
        Self::Quic,
        Self::Http3,
        Self::WebTransport,
    ];

    /// The kind's name: `websocket`, `streaming`, `split`, `exchange`,
    /// `quic`, `http3`, `webtransport`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::WebSocket => "websocket",
            Self::Streaming => "streaming",
            Self::Split => "split",
            Self::Exchange => "exchange",
            Self::Quic => "quic",
            Self::Http3 => "http3",
            Self::WebTransport => "webtransport",
        }
    }

    /// The kind of a name ([`CarrierKind::name`]).
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }
}

impl fmt::Display for CarrierKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// How one try of a candidate carrier fared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CandidateOutcome {
    /// The peer's transport parameters arrived on it in time (or, for a
    /// further pipe, its join was confirmed in time).
    Usable,
    /// Not within the candidate's timer.
    TimedOut,
    /// The server or an intermediary refused it: an HTTP status, a refused
    /// upgrade or connection.
    Refused,
    /// It failed otherwise: the network, TLS, a carrier error.
    Failed,
}

impl CandidateOutcome {
    /// The outcome's name: `usable`, `timed_out`, `refused`, `failed`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Usable => "usable",
            Self::TimedOut => "timed_out",
            Self::Refused => "refused",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for CandidateOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// One try of a candidate carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CandidateResult {
    /// The candidate's kind.
    pub kind: CarrierKind,
    /// The candidate's variant.
    pub variant: Option<std::sync::Arc<str>>,
    /// How it fared.
    pub outcome: CandidateOutcome,
    /// Tried as a further pipe of the established session.
    pub joined: bool,
    /// The failure, unless usable.
    pub error: Option<String>,
}

/// A session event: pipe state changes,
/// pipe quality and priority reports, and the session's own events
/// (GOAWAY, suspension, capacity), read with
/// [`Session::next_event`](crate::Session#method.next_event).
///
/// The queue is bounded however many pipes a session goes through: unread
/// events coalesce (a pipe direction reports its latest state event among
/// `PipeJoined`, `PipeSuspect`, `PipeRecovered`, `PipeFailed` and
/// `PipeClosed`, a pipe its `PipeAdded`, latest priority change and quality
/// report, a tier its latest saturation, the session its latest GOAWAY,
/// suspension and capacity state; failed join authentications are
/// counted), a terminal event ([`SessionEvent::is_terminal`]: `PipeFailed`,
/// `PipeClosed`) is never replaced, and the unread events of a
/// pipe that is retired fold into one [`SessionEvent::PipesRetired`]. After the
/// session ended, the queued events are still delivered before the end of
/// the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEvent {
    /// A local outbound pipe direction appeared (a join began, or pipe 0).
    PipeAdded {
        /// The pipe.
        pipe: PipeId,
        /// The pipe's carrier kind (`PipeIo::with_carrier`).
        carrier: Option<CarrierKind>,
    },
    /// An outbound pipe direction became active.
    PipeJoined {
        /// The pipe.
        pipe: PipeId,
        /// The pipe's carrier kind.
        carrier: Option<CarrierKind>,
    },
    /// An outbound pipe direction stopped making progress.
    PipeSuspect {
        /// The pipe.
        pipe: PipeId,
        /// The pipe's carrier kind.
        carrier: Option<CarrierKind>,
    },
    /// A suspect outbound pipe direction is active again.
    PipeRecovered {
        /// The pipe.
        pipe: PipeId,
        /// The pipe's carrier kind.
        carrier: Option<CarrierKind>,
    },
    /// An outbound pipe direction failed. Terminal.
    PipeFailed {
        /// The pipe.
        pipe: PipeId,
        /// Why it failed.
        failure: Option<PipeFailure>,
        /// The pipe's carrier kind.
        carrier: Option<CarrierKind>,
    },
    /// A pipe direction ended: the outbound one closed, or the inbound one
    /// ended. Terminal. Retirement is reported by
    /// [`SessionEvent::PipesRetired`] instead.
    PipeClosed {
        /// The pipe.
        pipe: PipeId,
        /// The direction that ended.
        half: PipeHalf,
        /// The pipe's carrier kind.
        carrier: Option<CarrierKind>,
    },
    /// A Hello did not verify at this endpoint (a secret mismatch, or in Bound an
    /// intermediary that terminates the carrier).
    JoinAuthFailed {
        /// The error class, `auth`.
        reason: &'static str,
        /// How many joins failed since the last such event was read.
        count: u64,
    },
    /// The effective priority, standby flag or weight of a pipe's outbound
    /// direction changed, by a local setting or the peer's request.
    PipePriorityChanged {
        /// The pipe.
        pipe: PipeId,
        /// The effective priority (lower preferred).
        send_priority: u64,
        /// The effective standby flag.
        standby: bool,
        /// The weight.
        weight: u64,
        /// Where the priority comes from.
        source: PrioritySource,
    },
    /// An outbound pipe's estimates left its quality band
    /// ([`crate::QualityBand`]): the band now centres
    /// on these values. At most one per pipe per `min_interval`.
    PipeQualityChanged {
        /// The pipe.
        pipe: PipeId,
        /// The smoothed RTT; `None` before the first sample.
        smoothed_rtt: Option<std::time::Duration>,
        /// The delivery rate R_p in bytes per second; `None` before it was
        /// measured, or without pipe acknowledgement.
        delivery_rate: Option<u64>,
    },
    /// A tier of the local outbound direction entered or left saturation; at
    /// most one event per tier per second.
    TierSaturation {
        /// The tier's priority.
        priority: u64,
        /// Saturated now.
        saturated: bool,
    },
    /// The session's outbound capacity fell below its floor
    /// ([`crate::CapacityFloor`]): the sum of the delivery rates of the
    /// usable non-standby outbound pipes, in bytes per second. zmux only
    /// reports it.
    CapacityBelow {
        /// The capacity in bytes per second.
        rate: u64,
    },
    /// The outbound capacity rose to the floor times its ratio again.
    CapacityRestored {
        /// The capacity in bytes per second.
        rate: u64,
    },
    /// The peer sent GOAWAY.
    GoAwayReceived(GoAway),
    /// Every pipe in a direction was lost; the session is suspended.
    SessionSuspended,
    /// The session left SUSPENDED.
    SessionResumed,
    /// The session, which can rejoin (the peer announced a Session
    /// Locator), suspended while it has neither a
    /// [`redial`](crate::Config#structfield.redial) hook nor a running pipe
    /// pool: nothing in the library will dial, and the session ends at the
    /// grace period unless the application adds a pipe. It follows
    /// [`SessionEvent::SessionSuspended`]
    /// and is also logged as a warning. An application that resumes by its
    /// own `add_pipe` calls can ignore it.
    ResumeUnattended,
    /// A carrier mode tried a candidate: the latest
    /// try of a kind, as the session or as a further pipe, when several
    /// were not read.
    CarrierCandidate {
        /// The candidate's kind.
        kind: CarrierKind,
        /// The candidate's variant.
        variant: Option<std::sync::Arc<str>>,
        /// How it fared.
        outcome: CandidateOutcome,
        /// Tried as a further pipe of the established session.
        joined: bool,
    },
    /// A carrier mode chose the session's carrier kind, first when the
    /// session was established and again on every switch: the latest when
    /// several were not read.
    CarrierChosen(CarrierKind, Option<std::sync::Arc<str>>),
    /// Pipes were retired since the last such event was read (at least
    /// one): their unread events left the queue (only unretired pipes hold
    /// events), and their unread terminal states are counted here. It is
    /// queued at the first such retirement.
    PipesRetired {
        /// Pipes retired.
        retired: u64,
        /// Of those, pipes with an unread failure (a direction FAILED).
        failed: u64,
        /// Of those, pipes with an unread end (CLOSED or ENDED) and no
        /// unread failure.
        closed: u64,
        /// Non-terminal events dropped because more pipes were live than
        /// the session allows (a defence; the core bounds them), since the
        /// last such event was read. Terminal states are never dropped.
        dropped: u64,
        /// The last retired pipes, oldest first (at most 4).
        last: Vec<PipeId>,
    },
    /// The session committed an epoch: its secret is known, and joins of it are
    /// accepted ([`Session`](crate::Session)`::advance_epoch`). The latest
    /// when several were not read.
    EpochCommitted {
        /// The epoch.
        epoch: u64,
    },
    /// An epoch, its keys and its Locators were deleted. The latest when several were
    /// not read.
    EpochDeleted {
        /// The epoch.
        epoch: u64,
    },
}

/// Observes a session (the `tracer` hook): its events,
/// whether or not the application reads them with `next_event`, and its
/// end. Called outside every lock, serially and in order on the session's
/// hook context, `closed` last; a slow
/// tracer never holds the session back: past a bounded backlog, events
/// other than the end are dropped and counted ([`Tracer::dropped`]). A
/// panic in a call is caught and ignored. Every method does nothing by
/// default.
pub trait Tracer: Send + Sync + 'static {
    /// The session was established.
    fn established(&self) {}

    /// A session event.
    fn event(&self, event: &SessionEvent) {
        let _ = event;
    }

    /// Events dropped since the previous call, before the next delivered.
    fn dropped(&self, count: u64) {
        let _ = count;
    }

    /// The session ended, with the reason; nothing follows.
    fn closed(&self, reason: &SessionError) {
        let _ = reason;
    }
}

impl fmt::Debug for dyn Tracer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tracer(..)")
    }
}

impl SessionEvent {
    /// The pipe a pipe event is about.
    #[must_use]
    pub const fn pipe(&self) -> Option<PipeId> {
        match self {
            Self::PipeAdded { pipe, .. }
            | Self::PipeJoined { pipe, .. }
            | Self::PipeSuspect { pipe, .. }
            | Self::PipeRecovered { pipe, .. }
            | Self::PipeFailed { pipe, .. }
            | Self::PipeClosed { pipe, .. }
            | Self::PipePriorityChanged { pipe, .. }
            | Self::PipeQualityChanged { pipe, .. } => Some(*pipe),
            _ => None,
        }
    }

    /// Whether it is a pipe direction's terminal event: [`SessionEvent::PipeFailed`]
    /// or [`SessionEvent::PipeClosed`].
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::PipeFailed { .. } | Self::PipeClosed { .. })
    }
}
