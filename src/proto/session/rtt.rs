//! The RTT that receive-window auto-tuning uses. On a single pipe the core
//! takes no RTT samples of its own: it uses
//! the carrier's estimate when the driver provides one (TCP_INFO), else the
//! windowed minimum of QX_PING samples, never a smoothed mean (queueing
//! behind bulk data would inflate it and grow windows without end). A
//! window never grows before a real sample exists; auto-tuning asks for a
//! QX_PING instead.

use std::time::Duration;

use super::SessionCore;

/// How often auto-tuning asks for a QX_PING sample, at most.
pub(super) const PROBE_INTERVAL: Duration = Duration::from_secs(1);

/// The smallest limit of one write call (and the limit before the first
/// rate measurement).
pub(crate) const WRITE_CALL_MIN: usize = 16 * 1024;
/// The largest limit of one write call.
pub(super) const WRITE_CALL_MAX: u64 = 64 * 1024;
/// The floor of a batch taken while input is pending.
const BATCH_UNDER_INPUT_MIN: u64 = 64 * 1024;
/// The floor of a multipath write call.
pub(super) const MP_WRITE_CALL_MIN: u64 = 4 * 1024;
/// The time a multipath write call is bounded by at the pipe's rate.
pub(super) const MP_WRITE_CALL_SPAN: Duration = Duration::from_millis(50);

impl SessionCore {
    /// Gives the core the carrier's own RTT estimate (for example the
    /// kernel's from TCP_INFO), which receive-window auto-tuning prefers to
    /// QX_PING samples; `None` when unknown.
    pub fn set_carrier_rtt(&mut self, rtt: Option<Duration>) {
        self.carrier_rtt = rtt.filter(|r| !r.is_zero());
        self.session_rtt_sampled(self.now);
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
}

impl SessionCore {
    /// The configured latency budget: how long a driver may reuse a
    /// [`SessionCore::write_call_limit`] for the calls of a batch that follow.
    #[cfg(any(feature = "tokio", feature = "blocking"))]
    pub(crate) fn latency_budget(&self) -> Duration {
        self.config.latency_budget
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
    use std::time::Instant;

    use super::*;

    #[test]
    fn write_calls_are_bounded_only_while_latency_sensitive_work_waits() {
        let now = Instant::now();
        let config = super::super::Config::default();
        let role = super::super::Role::Client;
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
