//! The application's view of a session's events: what
//! [`Session::next_event`](crate::Session#method.next_event) returns and a
//! [`Tracer`] observes.

use std::fmt;

use super::{PipeFailure, PipeHalf, PipeId, PrioritySource, SessionError};

/// The GOAWAY watermarks the peer sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
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
    #[must_use]
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
    #[must_use]
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
    /// Another candidate satisfied the race before this attempt completed.
    Cancelled,
}

impl CandidateOutcome {
    /// The outcome's name: `usable`, `timed_out`, `refused`, `failed`.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Usable => "usable",
            Self::TimedOut => "timed_out",
            Self::Refused => "refused",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
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
#[cfg_attr(
    feature = "tokio",
    doc = " [`Session::next_event`](crate::Session#method.next_event)."
)]
#[cfg_attr(not(feature = "tokio"), doc = " `Session::next_event`.")]
///
/// The queue is keyed and never drops an event: each event has a key (its
/// kind, and for a pipe event the pipe and direction, for a tier its
/// priority, for a failed join its reason, for a carrier candidate its
/// kind and variant), and an event whose key has one unread updates it
/// (the latest replaces, failed joins are counted, a terminal event stays)
/// and moves it to the tail, so events are read in the order of their keys'
/// latest occurrences. The keys are those of what the session holds, so the
/// queue is bounded however many pipes the session goes through: the unread
/// events of a pipe that is retired leave with it and its unread end is
/// counted in one [`SessionEvent::PipesRetired`]. A
/// [`SessionEvent::SessionResumed`] removes an unread
/// [`SessionEvent::ResumeUnattended`]. After the session ended nothing more
/// is queued; the queued events are still delivered before the end of the
/// stream. The queue retains the most recent 256 controller events.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEvent {
    /// The session owner installed a controller or updated its target.
    TargetChanged {
        /// Current binding generation.
        generation: u64,
        /// Installed target revision.
        revision: u64,
        /// This commit installed a new binding.
        initial: bool,
        /// Previous binding generation for an atomic takeover.
        predecessor: Option<u64>,
    },
    /// A controller reserved a capacity batch.
    BatchReserved {
        /// Originating binding generation.
        generation: u64,
        /// Target revision of the batch.
        revision: u64,
        /// Session-local batch identity.
        batch: u64,
    },
    /// A controller batch rolled back its outstanding work.
    BatchRolledBack {
        /// Originating binding generation.
        generation: u64,
        /// Session-local batch identity.
        batch: u64,
    },
    /// A controller committed the member's retirement.
    DrainCommitted {
        /// Originating binding generation.
        generation: u64,
        /// Session-local batch identity.
        batch: u64,
        /// Retiring member.
        member: super::MemberId,
    },
    /// A controller started a host opener.
    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    AttemptStarted {
        /// Originating binding generation.
        generation: u64,
        /// Session-local batch identity.
        batch: u64,
        /// Attempt assigned at opener entry.
        attempt: crate::AttemptId,
    },
    /// A controller settled an attempt.
    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    AttemptFinished {
        /// Originating binding generation.
        generation: u64,
        /// Session-local batch identity.
        batch: u64,
        /// Attempt identity, or zero for a refusal before opener entry.
        attempt: crate::AttemptId,
        /// Immutable terminal reason.
        reason: crate::AttemptReason,
    },
    /// Cover acceptance, rejection or carrier completion.
    Shaping(Box<super::shaping::Event>),
    /// A committed directional health transition. Sequence gaps indicate coalescing.
    PipeHealthChanged(Box<super::PipeHealthChange>),
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
        /// The error class: `auth`, `kex`, or that of a payload that does not
        /// parse.
        reason: &'static str,
        /// How many joins failed with this reason since the last such
        /// event was read (at least 1; a [`Tracer`] gets one event per
        /// failure, with 1).
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
        /// The delivery rate `R_p` in bytes per second; `None` before it was
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
    /// The largest session datagram payload that leaves as one datagram of
    /// the carrier instead of in a record changed
    #[cfg_attr(
        feature = "tokio",
        doc = " ([`Session::path_datagram_size`](crate::Session#method.path_datagram_size)):"
    )]
    #[cfg_attr(not(feature = "tokio"), doc = " (`Session::path_datagram_size`):")]
    /// the carrier's datagram size changed (path MTU discovery), another
    /// pipe carries the datagrams, or they moved between the carrier's
    /// datagrams and records. It is noticed when the session sends or its
    /// pipes change. The latest when several were not read.
    DatagramPathChanged {
        /// Updated original-copy payload capacities.
        path: super::DatagramPath,
    },
    /// Pipes were retired since the last such event was read (at least
    /// one): their unread events left the queue (only unretired pipes hold
    /// events), and the pipes whose terminal state the application had not
    /// read are counted here. It is queued at the first such retirement and
    /// moves to the tail at each one. A [`Tracer`] gets one per retired
    /// pipe, with `retired` 1 and the pipe in `failed` or in `closed`.
    PipesRetired {
        /// Pipes retired.
        retired: u64,
        /// Of those, pipes that ended failed (a direction FAILED), the
        /// application not having read a `PipeFailed` or `PipeClosed` of
        /// them; a terminal event never queued counts as unread.
        failed: u64,
        /// Of those, the other pipes (CLOSED or ENDED) whose terminal state
        /// the application had not read.
        closed: u64,
        /// The last retired pipes, oldest first (at most 4).
        last: Vec<PipeId>,
    },
    /// The session committed an epoch: its secret is known, and joins of it are
    #[cfg_attr(
        feature = "tokio",
        doc = " accepted ([`Session`](crate::Session)`::advance_epoch`). The latest"
    )]
    #[cfg_attr(
        not(feature = "tokio"),
        doc = " accepted (`Session``::advance_epoch`). The latest"
    )]
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

/// A session's identity within this process: distinct for every session
/// the process makes (a counter, never reused), so that the hooks shared by
/// the sessions of one configuration ([`Tracer`], [`HostEvents`]) tell them
/// apart. `Session::id` gives a session's. Not sent to the peer.
///
/// [`HostEvents`]: crate::HostEvents
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl SessionId {
    /// Restores a process-local identity previously obtained from [`Self::get`].
    /// Returns `None` for zero. A nonzero value need not name an existing session.
    #[must_use]
    pub const fn from_raw(id: u64) -> Option<Self> {
        if id == 0 { None } else { Some(Self(id)) }
    }

    /// A new identity, distinct from every other of the process.
    #[cfg(any(all(any(feature = "tokio", feature = "blocking"), not(loom)), test))]
    pub(crate) fn next() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self(NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
    }

    /// The number (at least 1).
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "session #{}", self.0)
    }
}

/// What a [`Tracer`] is told of a session, in order: `Established` once
/// it is, its events (each occurrence, before the event queue merges it),
/// `Dropped` where its backlog overflowed, and `Closed` last.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TraceRecord {
    /// The session was established.
    Established,
    /// A session event.
    Event(SessionEvent),
    /// This many of the session's events were dropped here: the session's
    /// backlog of 256 events was full. It stands before the next event
    /// accepted, or before `Closed`.
    Dropped(u64),
    /// The session ended; nothing of it follows.
    Closed(SessionError),
}

/// Observes sessions (the `tracer` hook): each session's events, whether or
/// not the application reads them with `next_event`, and its end, as
/// [`TraceRecord`]s with the session's [`SessionId`] (the sessions of one
/// configuration share its tracer). Called outside every lock, serially and
/// in order on each session's hook context, [`TraceRecord::Closed`] last
/// (nothing that happens after the session is closed is traced); a
/// slow tracer never holds a session back: a session has a backlog of 256
/// events (fixed), and an event that arrives when it is full is dropped and
/// counted ([`TraceRecord::Dropped`], where it would have stood: before the
/// next event accepted, or before `Closed`). `Established`, `Dropped` and
/// `Closed` take no room from the backlog and are never dropped. A
/// panic in a call is caught and ignored. The hook context is a task of the
/// runtime (a thread of the std driver): a tracer must not block it; one
/// that would subscribes with [`Config::events`](crate::Config::events)
/// instead.
pub trait Tracer: Send + Sync + 'static {
    /// A record of session `session`.
    fn trace(&self, session: SessionId, record: &TraceRecord);
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
            Self::Shaping(event) => Some(event.pipe),
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
