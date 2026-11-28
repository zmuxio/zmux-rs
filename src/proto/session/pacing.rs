//! Pacing: the session's side of the carrier
//! queue limiter, which pipes it paces, and the limiter's inputs from the
//! sends and acknowledgements of a pipe.

use std::time::{Duration, Instant};

use super::SessionCore;
use super::estimator::AckSample;
use super::limiter::{AckEvent, Params};
use super::pipes::OutPipe;
use crate::proto::params::{DEFAULT_ACK_THRESHOLD, DEFAULT_MAX_ACK_DELAY_MS};

impl SessionCore {
    /// The limiter's view of the session: B, the peer's acknowledgement
    /// threshold and delay, `spread_chunk`.
    pub(super) fn pacing_params(&self) -> Params {
        let (threshold, max_ack_delay) = match (self.pipe_ack_state(), self.peer_tp.as_ref()) {
            (Some(pa), _) => (pa.peer_threshold, pa.peer_mad),
            (None, Some(t)) => (t.ack_threshold(), Duration::from_millis(t.max_ack_delay())),
            (None, None) => (
                DEFAULT_ACK_THRESHOLD,
                Duration::from_millis(DEFAULT_MAX_ACK_DELAY_MS),
            ),
        };
        Params {
            budget: self.config.latency_budget,
            threshold,
            max_ack_delay,
            chunk: self.config.spread_chunk as u64,
        }
    }

    /// Whether the limiter paces a pipe: in a multipath session, or on the
    /// single pipe with pipe acknowledgement,
    /// when its carrier has neither a low-water mark nor an unsent count.
    pub(super) fn paced(&self, o: &OutPipe) -> bool {
        self.acknowledged() && !o.carrier_signals_queue() && !self.config.hooks.unpaced
    }

    /// The bytes of stream data, reinjection and copies the limiter lets
    /// pipe `id` take now; `None` when the pipe is not paced. A pipe that
    /// is paced gets its limiter here.
    pub(super) fn pacing_room(&mut self, id: u64, now: Instant) -> Option<u64> {
        let paced = self.out_ref(id).is_some_and(|o| self.paced(o));
        if !paced {
            if let Some(out) = self.out_mut(id)
                && out.limiter().is_some()
            {
                out.set_paced(false, now);
                self.set_pacing_deadline(id, None);
            }
            return None;
        }
        self.out_mut(id)?.set_paced(true, now);
        let o = self.out_ref(id)?;
        let p = self.pacing_params();
        Some(
            o.limiter()?
                .room(now, o.limiter_in_flight(now), o.est(), &p),
        )
    }

    /// Feeds an acknowledgement of pipe `id` to its limiter, after the
    /// estimator took the samples: the one call per acknowledgement, from
    /// a multipath session's `PIPE_ACK` and from the single pipe's; then the
    /// quality reports judge the new estimates.
    pub(super) fn pace_ack(&mut self, id: u64, sample: &AckSample, now: Instant) {
        let p = self.pacing_params();
        let Some(i) = self.att_index(id) else {
            return;
        };
        let out = self.atts.at(i).out();
        if out.is_some_and(|o| self.paced(o) && !o.writes_ended()) {
            let out = self.atts.at_mut(i).out_mut().expect("paced pipe");
            let ev = AckEvent {
                sample,
                acked: out.acked(),
                sent: out.eliciting_end().max(out.acked()),
                held: out.held_out(now),
            };
            out.set_paced(true, now);
            let deadline = out
                .limiter_parts()
                .and_then(|(limiter, est)| limiter.on_ack(now, &ev, est, &p));
            self.set_pacing_deadline(id, deadline);
        }
        // The estimators and the limiter's rate bound took the
        // acknowledgement.
        self.quality_sample(id, now);
    }

    /// `bytes` were handed to pipe `id`'s carrier: the bucket pays for
    /// them, and whether the pipe is held back now is decided.
    pub(super) fn pace_sent(&mut self, id: u64, bytes: u64, now: Instant) {
        let p = self.pacing_params();
        let Some(i) = self.att_index(id) else {
            return;
        };
        let out = self.atts.at(i).out();
        if out.is_some_and(|o| self.paced(o) && !o.writes_ended()) {
            let out = self.atts.at_mut(i).out_mut().expect("paced pipe");
            out.set_paced(true, now);
            let in_flight = out.limiter_in_flight(now);
            let deadline = out.limiter_parts().and_then(|(limiter, est)| {
                limiter.on_sent(now, bytes, est, &p);
                limiter.refresh(now, in_flight, est, &p)
            });
            self.set_pacing_deadline(id, deadline);
        }
    }

    /// Updates the pipe's only pacing appointment.
    pub(super) fn set_pacing_deadline(&mut self, id: u64, at: Option<Instant>) {
        if at.is_some() {
            self.pacing_timers.get_or_insert_default().set(id, at);
        } else if let Some(timers) = &mut self.pacing_timers {
            timers.set(id, None);
        }
    }

    /// The earliest moment a held pipe may send again.
    pub(super) fn pacing_deadline(&self) -> Option<Instant> {
        self.pacing_timers.as_deref()?.next()
    }

    /// Updates only pipes whose bucket was due for a refill.
    pub(super) fn pacing_timeout(&mut self, now: Instant) {
        if self.pacing_deadline().is_none_or(|at| at > now) {
            return;
        }
        let params = self.pacing_params();
        while let Some((_, id)) = self.pacing_timers.as_mut().and_then(|q| q.take_due(now)) {
            let deadline = self
                .out_mut(id)
                .filter(|out| !out.writes_ended())
                .and_then(|out| {
                    let in_flight = out.limiter_in_flight(now);
                    let (limiter, est) = out.limiter_parts()?;
                    limiter.refresh(now, in_flight, est, &params)
                });
            debug_assert!(deadline.is_none_or(|at| at > now));
            self.set_pacing_deadline(id, deadline);
        }
    }
}
