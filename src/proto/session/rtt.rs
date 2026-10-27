//! The RTT that receive-window auto-tuning uses. On a single pipe the core
//! takes no RTT samples of its own: it uses
//! the carrier's estimate when the driver provides one (TCP_INFO), else the
//! windowed minimum of QX_PING samples, never a smoothed mean (queueing
//! behind bulk data would inflate it and grow windows without end). A
//! window never grows before a real sample exists; auto-tuning asks for a
//! QX_PING instead.

use std::time::{Duration, Instant};

use super::{SessionCore, State};

/// How often auto-tuning asks for a QX_PING sample, at most.
const PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// The smallest limit of one write call (and the limit before the first
/// rate measurement).
pub const WRITE_CALL_MIN: usize = 16 * 1024;
/// The largest limit of one write call.
const WRITE_CALL_MAX: u64 = 64 * 1024;
/// The floor of a batch taken while input is pending.
const BATCH_UNDER_INPUT_MIN: u64 = 64 * 1024;
/// The floor of a multipath write call.
const MP_WRITE_CALL_MIN: u64 = 4 * 1024;
/// The time a multipath write call is bounded by at the pipe's rate.
const MP_WRITE_CALL_SPAN: Duration = Duration::from_millis(50);

impl SessionCore {
    /// Gives the core the carrier's own RTT estimate (for example the
    /// kernel's from TCP_INFO), which receive-window auto-tuning prefers to
    /// QX_PING samples; `None` when unknown.
    pub fn set_carrier_rtt(&mut self, rtt: Option<Duration>) {
        self.carrier_rtt = rtt.filter(|r| !r.is_zero());
        if self.mp.is_none() {
            self.quality_sample(0, self.now);
        }
    }

    /// Gives the core a pipe's carrier RTT estimate (for example the
    /// kernel's from TCP_INFO); in a multipath session auto-tuning prefers
    /// it to the pipe's own samples. `None` when unknown.
    pub fn set_pipe_carrier_rtt(&mut self, pipe: super::PipeId, rtt: Option<Duration>) {
        if let Some(o) = self.out_mut(pipe.0) {
            o.set_carrier_rtt(rtt);
            self.quality_sample(pipe.0, self.now);
        }
    }

    /// pipe_min_rtt of an attachment: its
    /// carrier minimum when the carrier reports one, else the 300 s minimum
    /// of its PIPE_ACK samples; an attachment without a local outbound
    /// direction takes the largest of the other attachments of its fate
    /// group, or without one the largest in the session. Never the
    /// credit-loop minimum.
    pub(super) fn pipe_min_rtt(&self, id: u64) -> Option<Duration> {
        let own = |a: &super::pipes::Attachment| a.out()?.min_rtt();
        let a = self.att(id)?;
        if a.out().is_some() {
            return own(a);
        }
        if a.fate_group() != 0 {
            let g = self
                .atts
                .iter()
                .filter(|b| b.id() != id && b.fate() == a.fate())
                .filter_map(own)
                .max();
            if g.is_some() {
                return g;
            }
        }
        self.atts.iter().filter_map(own).max()
    }

    /// The TCP_NOTSENT_LOWAT a pipe's carrier should use now: on a single pipe max(128 KiB, send
    /// rate x RTT_min / 8), in a multipath session max(32 KiB, R_p x
    /// RTT_min_p / 8) per pipe. Without an RTT_min the floor. The driver
    /// applies it at most every 20 ms and only when it changes by more than
    /// 25 %, never above the carrier's send buffer.
    pub fn notsent_lowat(&self, pipe: super::PipeId) -> u64 {
        const SINGLE: u64 = 128 * 1024;
        const MULTI: u64 = 32 * 1024;
        if self.mp.is_some() {
            let Some(o) = self.out_ref(pipe.0) else {
                return MULTI;
            };
            let Some(rtt) = o.min_rtt() else {
                return MULTI;
            };
            let term = (o.est().rate as f64 * rtt.as_secs_f64() / 8.0) as u64;
            return MULTI.max(term);
        }
        let Some(rtt) = self.carrier_rtt.or(self.loop_min.get()) else {
            return SINGLE;
        };
        let term = (self.send_rate.get().unwrap_or(0) as f64 * rtt.as_secs_f64() / 8.0) as u64;
        SINGLE.max(term)
    }

    /// Asks for a QX_PING sample when auto-tuning would grow a window but
    /// has no RTT: one at a time, at most once per [`PROBE_INTERVAL`].
    pub(super) fn probe_rtt(&mut self, now: Instant) {
        if self.mp.is_some()
            || self.state != State::Active
            || self.ping.outstanding.is_some()
            || self.ping.request_pending
            || self
                .last_rtt_probe
                .is_some_and(|t| now.saturating_duration_since(t) < PROBE_INTERVAL)
        {
            return;
        }
        self.last_rtt_probe = Some(now);
        self.ping.request_pending = true;
    }
}

impl SessionCore {
    /// The sending rate of a pipe in bytes per second: its delivery-rate
    /// estimate in a multipath session, else the rate the session hands
    /// bytes to its carrier; 0 before the first measurement.
    fn pipe_send_rate(&self, pipe: super::PipeId) -> u64 {
        if self.mp.is_some() {
            self.out_ref(pipe.0).map_or(0, |o| o.est().rate)
        } else {
            self.send_rate.get().unwrap_or(0)
        }
    }

    /// The configured latency budget: how long a driver may reuse a
    /// [`SessionCore::write_call_limit`] for the calls of a batch that follow.
    #[cfg(any(feature = "tokio", feature = "blocking"))]
    pub(crate) fn latency_budget(&self) -> Duration {
        self.config.latency_budget
    }

    /// The most bytes a driver hands a pipe's carrier in the write call it
    /// is about to make, of a batch (or what is left of one) of `batch`
    /// bytes: the whole of it, except while
    /// latency-sensitive work waits ([`SessionCore`]'s own state, and
    /// `input_pending`: bytes the driver received and has not handed to the
    /// core yet), when the bound clamp(R x B / 2, 16 KiB, 64 KiB) lets a
    /// request, an acknowledgement or credit wait for at most one short
    /// call. A `blocking` write in a multipath session also holds at most
    /// max(4 KiB, R_p x 50 ms), so that no call is
    /// expected to take much longer than 50 ms. Independent of the
    /// carrier: any carrier works with it, whatever signals it offers.
    pub fn write_call_limit(
        &self,
        pipe: super::PipeId,
        batch: usize,
        blocking: bool,
        input_pending: bool,
        now: Instant,
    ) -> usize {
        let rate = self.pipe_send_rate(pipe);
        let mut limit = batch as u64;
        if self.latency_work(pipe.0, input_pending, now) {
            let budget = self.config.latency_budget.as_secs_f64();
            let bound =
                ((rate as f64 * budget / 2.0) as u64).clamp(WRITE_CALL_MIN as u64, WRITE_CALL_MAX);
            limit = limit.min(bound);
        }
        if blocking && self.mp.is_some() {
            let mp = ((rate as f64 * MP_WRITE_CALL_SPAN.as_secs_f64()) as u64)
                .clamp(MP_WRITE_CALL_MIN, (batch as u64).max(MP_WRITE_CALL_MIN));
            limit = limit.min(mp);
        }
        usize::try_from(limit).unwrap_or(usize::MAX).max(1)
    }

    /// The size of a new batch for a pipe: `full`, or while input is
    /// pending min(full, max(64 KiB, R x B)), so that a large batch does not
    /// hold the reads back when the carrier is fast enough to take it in
    /// smaller ones.
    pub fn batch_limit(&self, pipe: super::PipeId, full: usize, input_pending: bool) -> usize {
        if !input_pending {
            return full;
        }
        let rate = self.pipe_send_rate(pipe);
        let r_b = (rate as f64 * self.config.latency_budget.as_secs_f64()) as u64;
        usize::try_from(r_b.max(BATCH_UNDER_INPUT_MIN))
            .unwrap_or(usize::MAX)
            .min(full)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_calls_are_bounded_only_while_latency_sensitive_work_waits() {
        let now = Instant::now();
        let config = super::super::Config::default();
        let role = super::super::RoleConfig::Initiator;
        let mut s = SessionCore::new(config, role, None, now).unwrap();
        let pipe = super::super::PipeId(0);
        let batch = 256 * 1024;
        // Bulk alone: the whole batch in one call.
        assert_eq!(s.write_call_limit(pipe, batch, false, false, now), batch);
        // Input waiting for the core: the 16 KiB floor until a rate is known.
        assert_eq!(
            s.write_call_limit(pipe, batch, false, true, now),
            WRITE_CALL_MIN
        );
        // An exchange just happened: bounded for max(10 x B, RTT_min).
        s.exchange_at = Some(now);
        let soon = now + Duration::from_micros(900);
        assert_eq!(
            s.write_call_limit(pipe, batch, false, false, soon),
            WRITE_CALL_MIN
        );
        let later = now + Duration::from_millis(1);
        assert_eq!(s.write_call_limit(pipe, batch, false, false, later), batch);
        // A queued credit update goes ahead of bulk data.
        let window = s.streams.recv_flow().window;
        s.streams.set_session_window(window * 2);
        assert!(s.streams.recv_flow().update_pending);
        assert_eq!(
            s.write_call_limit(pipe, batch, false, false, later),
            WRITE_CALL_MIN
        );
    }
}
