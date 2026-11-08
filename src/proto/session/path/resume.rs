//! Resume: the SUSPENDED state and the grace timer. Positions after a
//! rejoin travel in PIPE_ACK snapshots (`ack.rs`).

use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::proto::TransportErrorCode as T;
use crate::proto::session::{CloseFrame, CoreEvent, SessionCore, SessionError, State};

/// The SUSPENDED state of a multipath session.
#[derive(Debug)]
pub(crate) struct Suspension {
    /// The grace period.
    grace: Duration,
    /// When the session entered SUSPENDED, and whether it was DRAINING.
    since: Option<Instant>,
    was_draining: bool,
    /// When the grace period ends.
    deadline: Option<Instant>,
}

impl Suspension {
    pub(in crate::proto::session) fn new(grace: Duration) -> Self {
        Self {
            grace,
            since: None,
            was_draining: false,
            deadline: None,
        }
    }

    /// When the session entered SUSPENDED, while it is.
    pub(in crate::proto::session) fn since(&self) -> Option<Instant> {
        self.since
    }

    /// When the grace period ends, while it runs.
    pub(in crate::proto::session) fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// A shutdown or GOAWAY while SUSPENDED: the session resumes into
    /// DRAINING.
    pub(in crate::proto::session) fn drain_after(&mut self) {
        self.was_draining = true;
    }

    /// The session is closing: the grace timer stops.
    pub(in crate::proto::session) fn closing(&mut self) {
        self.deadline = None;
    }
}

impl SessionCore {
    // ---- the SUSPENDED state --------------------------------------------------------

    /// Enters SUSPENDED: no live pipe in a direction, resume in use.
    pub(in crate::proto::session) fn suspend(&mut self, now: Instant) {
        if self.state >= State::Closing || self.state == State::Suspended {
            return;
        }
        let draining = self.state == State::Draining;
        self.state = State::Suspended;
        self.idle_deadline = None;
        self.keep_alive_deadline = None;
        self.stats.suspensions += 1;
        let s = self.mp_mut().suspension_mut();
        s.was_draining = draining;
        s.since = Some(now);
        s.deadline = now.checked_add(s.grace);
        self.push_event(CoreEvent::Suspended);
    }

    /// Leaves SUSPENDED once an ACTIVE outbound pipe and an OPEN inbound
    /// pipe exist.
    pub(in crate::proto::session) fn check_resume(&mut self, now: Instant) {
        if self.state != State::Suspended {
            return;
        }
        let active_out = self
            .atts
            .outs()
            .any(|o| o.state() == crate::proto::session::OutState::Active && !o.out_closed());
        let open_in = self.atts.iter().any(|a| {
            a.inp()
                .is_some_and(|p| p.state() == crate::proto::session::InState::Open)
        });
        if !active_out || !open_in {
            return;
        }
        let mp = self.mp_mut();
        mp.resumed(now);
        let s = mp.suspension_mut();
        let draining = s.was_draining;
        let since = s.since.take();
        s.deadline = None;
        self.state = if draining || self.goaway_announced() {
            State::Draining
        } else {
            State::Active
        };
        if let Some(t) = since {
            self.stats.suspended_time += now.saturating_duration_since(t);
        }
        self.restart_idle(now);
        self.push_event(CoreEvent::Resumed);
        self.epoch_after_resume(now);
    }

    /// The grace timer expired. Returns whether the session ended.
    pub(in crate::proto::session) fn resume_timeout_fired(&mut self, now: Instant) -> bool {
        let Some(t) = self.mp.as_deref().and_then(|m| m.suspension().deadline) else {
            return false;
        };
        if now < t || self.state != State::Suspended {
            return false;
        }
        self.mp_mut().suspension_mut().deadline = None;
        self.close_resume(T::ZMUX_RESUME_TIMEOUT, "resume grace period expired", now);
        true
    }

    /// Ends a suspended session for a listener limit: ZMUX_RESUME_TIMEOUT, as
    /// at grace expiry.
    pub fn close_suspended(&mut self, now: Instant) {
        self.tick(now);
        if self.state == State::Suspended {
            self.close_resume(T::ZMUX_RESUME_TIMEOUT, "suspended session limit", now);
        }
    }

    /// When the session entered SUSPENDED, while it is.
    pub fn suspended_since(&self) -> Option<Instant> {
        self.mp.as_deref().and_then(|m| m.suspension().since)
    }

    /// Closes with ZMUX_RESUME_FAILED or ZMUX_RESUME_TIMEOUT: CONNECTION_CLOSE
    /// on any live outbound pipe, otherwise locally.
    pub(in crate::proto::session) fn close_resume(
        &mut self,
        code: T,
        reason: &'static str,
        now: Instant,
    ) {
        if self.state >= State::Closing {
            return;
        }
        self.set_error(if code == T::ZMUX_RESUME_TIMEOUT {
            SessionError::ResumeTimeout {
                last: self.mp.as_deref().and_then(|m| m.last_failure),
            }
        } else {
            SessionError::ResumeFailed {
                reason: Bytes::from_static(reason.as_bytes()),
                remote: false,
            }
        });
        if self.atts.iter().any(|a| a.out_live()) {
            self.enter_closing(
                Some(CloseFrame::Transport {
                    code: code.0,
                    frame_type: 0,
                    reason: Bytes::from_static(reason.as_bytes()),
                }),
                now,
            );
        } else {
            self.closed_now();
        }
    }
}
