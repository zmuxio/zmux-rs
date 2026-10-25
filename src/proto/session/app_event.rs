//! The application's view of a session's events: what
//! [`Session::next_event`](crate::Session#method.next_event) returns and a
//! [`Tracer`] observes.

use std::fmt;

use super::{PipeFailure, PipeHalf, PipeId, PipeState, PrioritySource, SessionError};

/// The GOAWAY watermarks the peer sent (EXTENSIONS.md Section 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoAway {
    /// Bidirectional streams with a lower index were or may be processed.
    pub max_bidi: u64,
    /// Unidirectional streams with a lower index were or may be processed.
    pub max_uni: u64,
    /// The peer's application error code.
    pub code: u64,
}

/// A session event: pipe state changes,
/// pipe quality and priority reports, and the session's own events
/// (GOAWAY, suspension, capacity), read with [`Session::next_event`](crate::Session#method.next_event).
///
/// The queue is bounded however many pipes a session goes through: unread
/// events coalesce (a pipe direction reports its latest state, a pipe its
/// latest priority change and quality report, a tier its latest
/// saturation, the session its latest GOAWAY, suspension and capacity
/// state; failed join authentications are counted), a terminal state
/// (outbound [`PipeState::Failed`] or [`PipeState::Closed`], inbound
/// [`PipeState::Ended`]) is never replaced, and the unread events of a
/// pipe that is retired fold into one [`SessionEvent::PipesRetired`]. After the
/// session ended, the queued events are still delivered before the end of
/// the stream.
///
/// [`PipeState::Failed`]: crate::PipeState::Failed
/// [`PipeState::Closed`]: crate::PipeState::Closed
/// [`PipeState::Ended`]: crate::PipeState::Ended
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionEvent {
    /// A pipe direction changed state: its latest state when several
    /// changes were not read. Retirement is reported by
    /// [`SessionEvent::PipesRetired`] instead.
    PipeState {
        /// The pipe.
        pipe: PipeId,
        /// Which of its directions.
        half: PipeHalf,
        /// The new state.
        state: PipeState,
        /// Why the pipe failed, with [`crate::PipeState::Failed`].
        failure: Option<PipeFailure>,
    },
    /// A join's token did not verify at this endpoint (a secret mismatch,
    /// or a TLS-terminating intermediary when the secret is the exporter).
    JoinAuthFailed {
        /// The token was carrier-bound.
        carrier_bound: bool,
        /// How many joins failed since the last such event was read.
        count: u64,
    },
    /// Both endpoints offered multipath but no secret source of
    /// `pipe_auth` matched: the session runs on one pipe
    /// ([`crate::Multipath::JoinSecurityUnavailable`]).
    JoinSecurityUnavailable,
    /// The effective priority, standby flag or weight of a pipe's outbound
    /// direction changed, by a local setting or the peer's request
    /// (MULTIPATH.md Section 9).
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
    /// The peer sent GOAWAY (EXTENSIONS.md Section 3).
    GoAway(GoAway),
    /// Every pipe in a direction was lost; the session is suspended.
    Suspended,
    /// The session left SUSPENDED.
    Resumed,
    /// Pipes were retired since the last such event was read: their unread
    /// events left the queue (only unretired pipes hold events), and their
    /// unread terminal states are counted here.
    PipesRetired {
        /// Pipes retired.
        retired: u64,
        /// Of those, pipes with an unread failure (a direction FAILED), and
        /// pipes failed beyond the queue's limit.
        failed: u64,
        /// Of those, pipes with an unread end (CLOSED or ENDED) and no
        /// failure, and pipes ended beyond the queue's limit.
        closed: u64,
        /// Non-terminal events dropped because more pipes were live than
        /// the session allows (a defence; the core bounds them).
        dropped: u64,
        /// The last retired pipes, oldest first (at most 4).
        last: Vec<PipeId>,
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
