//! Credit of the stream layer: stream counts per type (SPEC.md Section
//! 8.5) and session flow control (Sections 8.2 to 8.4).
//!
//! The types are read through [`Streams`] and changed only by it:
//! their fields are visible to the session for reading, and no mutable
//! reference to them leaves the stream layer.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::super::stream::{RecvState, StreamKey};
use super::super::tuner::Tuner;
use super::Streams;

/// The regular update floor.
const UPDATE_FLOOR: u64 = 256 * 1024;

/// SPEC.md Section 8.3 rules 2 and 3: whether released credit `unsent`
/// (C - L > 0) must be sent now, given the window, the peer's remaining
/// credit and whether it reported BLOCKED at the current limit.
fn credit_due(unsent: u64, window: u64, remaining: u64, blocked_reported: bool) -> bool {
    let quarter = window / 4;
    // Rule 2, sent early as SPEC.md Section 8.3 rule 2 allows: min(W/4,
    // max(W/16, 256 KiB)) released. Rule 3:
    // a blocked peer gets any credit at once; a nearly blocked one from a
    // minimum increment on.
    unsent >= quarter.min((window / 16).max(UPDATE_FLOOR))
        || remaining == 0
        || blocked_reported
        || (remaining < quarter && unsent >= quarter.min(32 * 1024))
}

/// State of one stream type for streams this endpoint opens.
#[derive(Debug, Default)]
pub(in super::super) struct LocalDir {
    /// Identifiers allocated (next stream index).
    pub(in super::super) next_index: u64,
    /// Streams opened by the application, with or without an identifier.
    pub(in super::super) reserved: u64,
    /// The peer's MAX_STREAMS.
    pub(in super::super) peer_max: u64,
    /// STREAMS_BLOCKED limit already reported.
    pub(in super::super) blocked_reported: Option<u64>,
    /// STREAMS_BLOCKED to send.
    pub(in super::super) blocked_pending: bool,
    /// Whether an opener waits for credit.
    pub(in super::super) waiting: bool,
    /// STREAMS_BLOCKED was lost with a pipe and is still true.
    pub(in super::super) blocked_resend: bool,
    /// Minimum GOAWAY watermark received.
    pub(in super::super) goaway: Option<u64>,
}

impl LocalDir {
    /// Takes stream credit for a new stream: `false`, with the opener
    /// noted as waiting and STREAMS_BLOCKED owed, when an established
    /// session has none left.
    pub(super) fn reserve(&mut self, established: bool) -> bool {
        if established && self.reserved >= self.peer_max {
            self.waiting = true;
            self.report_blocked();
            return false;
        }
        self.reserved += 1;
        true
    }

    /// Owes STREAMS_BLOCKED at the current limit, unless it was reported.
    pub(super) fn report_blocked(&mut self) {
        if self.blocked_reported != Some(self.peer_max) {
            self.blocked_pending = true;
        }
    }

    /// MAX_STREAMS raised the limit to `max`; `false` when it did not.
    pub(super) fn raise(&mut self, max: u64) -> bool {
        if max <= self.peer_max {
            return false;
        }
        self.peer_max = max;
        self.blocked_pending = false;
        self.blocked_resend = false;
        true
    }

    /// STREAMS_BLOCKED was written at `limit`.
    pub(super) fn blocked_written(&mut self, limit: u64) {
        self.blocked_reported = Some(limit);
        self.blocked_pending = false;
    }

    /// STREAMS_BLOCKED is no longer owed.
    pub(super) fn blocked_settled(&mut self) {
        self.blocked_pending = false;
        self.blocked_resend = false;
    }

    /// STREAMS_BLOCKED was lost with a pipe: sent again while still true.
    pub(super) fn blocked_lost(&mut self) {
        if self.blocked_reported == Some(self.peer_max) && self.reserved >= self.peer_max {
            self.blocked_resend = true;
        }
    }

    /// A GOAWAY watermark: `true` when it lowered the minimum.
    pub(super) fn goaway(&mut self, watermark: u64) -> bool {
        if self.goaway.is_none_or(|c| watermark < c) {
            self.goaway = Some(watermark);
            return true;
        }
        false
    }
}

/// State of one stream type for streams the peer opens.
#[derive(Debug, Default)]
pub(in super::super) struct RemoteDir {
    /// Streams opened so far (highest index + 1).
    pub(in super::super) opened: u64,
    /// The initial limit (our transport parameter).
    pub(in super::super) initial: u64,
    /// The limit written in MAX_STREAMS (or the initial one).
    pub(in super::super) limit_sent: u64,
    /// Streams discarded so far.
    pub(in super::super) discarded: u64,
    /// MAX_STREAMS to send.
    pub(in super::super) update_pending: bool,
    /// Streams ready for accept, in identifier order.
    pub(in super::super) accept: VecDeque<StreamKey>,
    /// Highest index offered to the application, plus one.
    pub(in super::super) offered: u64,
    /// Largest STREAMS_BLOCKED limit reported (NE-4).
    pub(in super::super) blocked_seen: Option<u64>,
    /// Lowest GOAWAY watermark sent.
    pub(in super::super) goaway_sent: Option<u64>,
    /// More credit is granted on the first accept (staged unidirectional
    /// credit, SPEC.md Section 8.5 rule 4).
    pub(in super::super) staged: bool,
    /// MAX_STREAMS was lost with a pipe: send the current limit again.
    pub(in super::super) resend: bool,
}

impl RemoteDir {
    /// A stream type whose initial limit is `limit`.
    pub(super) fn new(limit: u64) -> Self {
        Self {
            initial: limit,
            limit_sent: limit,
            ..Self::default()
        }
    }

    /// The limit MAX_STREAMS would carry now: the initial one plus the
    /// streams discarded, within the encodable count.
    pub(in super::super) fn limit_due(&self, max_count: u64) -> u64 {
        (self.initial + self.discarded).min(max_count)
    }

    /// A stream at index `index` would open beyond a GOAWAY watermark
    /// sent.
    pub(super) fn above_goaway(&self, index: u64) -> bool {
        self.goaway_sent.is_some_and(|w| index >= w)
    }

    /// MAX_STREAMS was written with `value`: whether the peer was blocked
    /// at the previous limit (a bottleneck, copied in a multipath session).
    pub(super) fn update_written(&mut self, value: u64) -> bool {
        let bottleneck = self.blocked_seen == Some(self.limit_sent);
        self.limit_sent = value;
        bottleneck
    }

    /// MAX_STREAMS is no longer owed.
    pub(super) fn update_settled(&mut self) {
        self.update_pending = false;
        self.resend = false;
    }
}

/// Session-level receive flow control (SPEC.md Section 8.2).
#[derive(Debug)]
pub(in super::super) struct RecvFlow {
    /// The MAX_DATA value last written (or the initial one): L.
    pub(in super::super) limit_sent: u64,
    /// The session window W (auto-tuned).
    pub(in super::super) window: u64,
    /// Sum over streams of max(received, final size).
    pub(in super::super) used: u64,
    /// Credit released (SPEC.md Section 8.3 rule 4).
    pub(in super::super) released: u64,
    /// Bytes received at or above the buffer cap, not released yet.
    pub(in super::super) held: u64,
    /// The buffer cap was reached; window growth stops until the buffered
    /// bytes fall below half of it.
    pub(in super::super) at_cap: bool,
    pub(in super::super) tuner: Tuner,
    pub(in super::super) update_pending: bool,
    /// Largest DATA_BLOCKED limit reported (NE-4).
    pub(in super::super) blocked_seen: Option<u64>,
    /// Unread bytes buffered in streams.
    pub(in super::super) buffered: u64,
    /// MAX_DATA was lost with a pipe: send the current limit again.
    pub(in super::super) resend: bool,
}

impl RecvFlow {
    /// The session receive window `window`, all of it advertised.
    pub(super) fn new(window: u64) -> Self {
        Self {
            limit_sent: window,
            window,
            used: 0,
            released: 0,
            held: 0,
            at_cap: false,
            tuner: Tuner::default(),
            update_pending: false,
            blocked_seen: None,
            buffered: 0,
            resend: false,
        }
    }

    /// The credit MAX_DATA would carry now (C).
    #[inline]
    pub(in super::super) fn credit(&self) -> u64 {
        self.released + self.window
    }

    /// Whether `increase` more bytes counted against the session stay
    /// within the advertised limit.
    #[inline]
    pub(in super::super) fn admits(&self, increase: u64) -> bool {
        self.used + increase <= self.limit_sent
    }

    /// Bytes received on streams, `cap` the session receive buffer cap.
    /// `buffered` bytes went into stream buffers; of the bytes whose credit
    /// was not handled before, `fresh_buffered` were buffered and
    /// `fresh_consumed` will never be.
    pub(super) fn received(
        &mut self,
        cap: u64,
        buffered: u64,
        fresh_buffered: u64,
        fresh_consumed: u64,
    ) {
        if fresh_buffered > 0 {
            if self.buffered < cap {
                self.released += fresh_buffered;
            } else {
                self.held += fresh_buffered;
            }
        }
        self.buffered += buffered;
        if self.buffered >= cap {
            self.at_cap = true;
        }
        self.released += fresh_consumed;
        self.check_credit();
    }

    /// `n` bytes left stream buffers; under memory `pressure` held credit
    /// is released only as it is consumed.
    pub(super) fn consumed(&mut self, cap: u64, n: u64, pressure: bool) {
        self.buffered = self.buffered.saturating_sub(n);
        let from_held = n.min(self.held);
        self.held -= from_held;
        self.released += from_held;
        if self.buffered < cap && self.held > 0 && !pressure {
            self.released += self.held;
            self.held = 0;
        }
        if self.buffered < cap / 2 {
            self.at_cap = false;
        }
        self.check_credit();
    }

    /// Decides whether MAX_DATA is due (SPEC.md Section 8.3 rules 2 and 3).
    pub(super) fn check_credit(&mut self) {
        let c = self.credit();
        if c <= self.limit_sent {
            return;
        }
        let remaining = self.limit_sent.saturating_sub(self.used);
        if credit_due(
            c - self.limit_sent,
            self.window,
            remaining,
            self.blocked_seen == Some(self.limit_sent),
        ) {
            self.update_pending = true;
        }
    }

    /// MAX_DATA was written with `value`: the credit loop's entry when it
    /// raised the limit, and whether the peer was (nearly) blocked at the
    /// previous limit (a bottleneck, copied in a multipath session).
    pub(super) fn update_written(&mut self, value: u64, now: Instant) -> bool {
        let remaining = self.limit_sent.saturating_sub(self.used);
        let bottleneck = remaining < self.window / 4 || self.blocked_seen == Some(self.limit_sent);
        let old = self.limit_sent;
        self.limit_sent = value;
        if value > old {
            self.tuner.sent(old, self.used, now);
        }
        bottleneck
    }

    /// MAX_DATA is no longer owed.
    pub(super) fn update_settled(&mut self) {
        self.update_pending = false;
        self.resend = false;
    }

    /// The session data arrived up to `used`: the rate and credit-loop
    /// sample of the session.
    pub(super) fn on_data(
        &mut self,
        now: Instant,
        rtt: Option<Duration>,
        pipe_rtt: Option<Duration>,
    ) -> Option<Duration> {
        let used = self.used;
        self.tuner.on_data(used, now, rtt, pipe_rtt)
    }
}

/// Session-level send flow control.
#[derive(Debug, Default)]
pub(in super::super) struct SendFlow {
    /// The peer's MAX_DATA.
    pub(in super::super) max: u64,
    /// Bytes counted against it.
    pub(in super::super) used: u64,
    /// DATA_BLOCKED limit already reported.
    pub(in super::super) blocked_reported: Option<u64>,
    pub(in super::super) blocked_pending: bool,
    /// DATA_BLOCKED was lost with a pipe and is still true.
    pub(in super::super) blocked_resend: bool,
    /// Bytes written by the application and not yet sent.
    pub(in super::super) buffered: u64,
    /// When MAX_DATA last raised the limit after the session was stalled
    /// on it (the age test).
    pub(in super::super) credit_at: Option<Instant>,
}

impl SendFlow {
    /// Session credit left.
    #[inline]
    pub(in super::super) fn room(&self) -> u64 {
        self.max.saturating_sub(self.used)
    }

    /// No session credit is left.
    #[inline]
    pub(in super::super) fn exhausted(&self) -> bool {
        self.used >= self.max
    }

    /// MAX_DATA raised the limit to `max` (`stalled`: data waited for it,
    /// dated `now`); `false` when it did not.
    pub(super) fn raise(&mut self, max: u64, stalled: bool, now: Instant) -> bool {
        if max <= self.max {
            return false;
        }
        if stalled || self.exhausted() {
            self.credit_at = Some(now);
        }
        self.max = max;
        self.blocked_pending = false;
        self.blocked_resend = false;
        true
    }

    /// The limit to report in DATA_BLOCKED when it was not reported yet
    /// (it is then owed).
    pub(super) fn report_blocked(&mut self) -> Option<u64> {
        if self.blocked_reported == Some(self.max) {
            return None;
        }
        self.blocked_pending = true;
        Some(self.max)
    }

    /// DATA_BLOCKED was written at `limit`.
    pub(super) fn blocked_written(&mut self, limit: u64) {
        self.blocked_reported = Some(limit);
        self.blocked_pending = false;
    }

    /// DATA_BLOCKED is no longer owed.
    pub(super) fn blocked_settled(&mut self) {
        self.blocked_pending = false;
        self.blocked_resend = false;
    }

    /// DATA_BLOCKED was lost with a pipe: sent again while still true.
    pub(super) fn blocked_lost(&mut self) {
        if self.blocked_reported == Some(self.max) {
            self.blocked_resend = true;
        }
    }
}

/// What [`Streams::stop_recv`] did to a receiving part.
pub(in super::super) struct Stopped {
    /// The stream is a local one.
    pub(in super::super) local: bool,
    /// Buffered bytes dropped (consumed).
    pub(in super::super) dropped: u64,
    /// STOP_SENDING is owed.
    pub(in super::super) stop_pending: bool,
}

impl Streams {
    // ---- credit frames -------------------------------------------------------

    /// MAX_DATA was written with `value` at `now`: whether the limit it
    /// raised was a bottleneck.
    pub(in super::super) fn max_data_written(&mut self, value: u64, now: Instant) -> bool {
        self.recv_flow.update_written(value, now)
    }

    /// MAX_DATA is no longer owed.
    pub(in super::super) fn max_data_settled(&mut self) {
        self.recv_flow.update_settled();
    }

    /// MAX_DATA was lost with a pipe.
    pub(in super::super) fn max_data_lost(&mut self) {
        self.recv_flow.resend = true;
    }

    /// MAX_STREAMS of type `d` was written with `value`: whether the limit
    /// it raised was a bottleneck.
    pub(in super::super) fn max_streams_written(&mut self, d: usize, value: u64) -> bool {
        self.remote_dirs[d].update_written(value)
    }

    /// MAX_STREAMS of type `d` is no longer owed.
    pub(in super::super) fn max_streams_settled(&mut self, d: usize) {
        self.remote_dirs[d].update_settled();
    }

    /// MAX_STREAMS of type `d` was lost with a pipe.
    pub(in super::super) fn max_streams_lost(&mut self, d: usize) {
        self.remote_dirs[d].resend = true;
    }

    /// The limit to report in DATA_BLOCKED when it was not reported yet
    /// (it is then owed).
    pub(in super::super) fn report_data_blocked(&mut self) -> Option<u64> {
        self.send_flow.report_blocked()
    }

    /// DATA_BLOCKED was written at `limit`.
    pub(in super::super) fn data_blocked_written(&mut self, limit: u64) {
        self.send_flow.blocked_written(limit);
    }

    /// DATA_BLOCKED is no longer owed.
    pub(in super::super) fn data_blocked_settled(&mut self) {
        self.send_flow.blocked_settled();
    }

    /// DATA_BLOCKED was lost with a pipe.
    pub(in super::super) fn data_blocked_lost(&mut self) {
        self.send_flow.blocked_lost();
    }

    /// STREAMS_BLOCKED of type `d` was written at `limit`.
    pub(in super::super) fn streams_blocked_written(&mut self, d: usize, limit: u64) {
        self.local_dirs[d].blocked_written(limit);
    }

    /// STREAMS_BLOCKED of type `d` is no longer owed.
    pub(in super::super) fn streams_blocked_settled(&mut self, d: usize) {
        self.local_dirs[d].blocked_settled();
    }

    /// STREAMS_BLOCKED of type `d` was lost with a pipe.
    pub(in super::super) fn streams_blocked_lost(&mut self, d: usize) {
        self.local_dirs[d].blocked_lost();
    }

    /// Sets a stream's MAX_STREAM_DATA update as owed or not, counting the
    /// owed ones.
    pub(in super::super) fn mark_stream_update(&mut self, key: StreamKey, on: bool) {
        let Some(r) = self.recv_mut(key) else {
            return;
        };
        if r.update_pending != on {
            r.update_pending = on;
            if on {
                self.stream_updates += 1;
            } else {
                self.stream_updates -= 1;
            }
        }
    }

    // ---- session flow control ------------------------------------------------

    /// Bytes received on streams (see [`RecvFlow::received`]), `cap` the
    /// session receive buffer cap.
    pub(in super::super) fn credit_received(
        &mut self,
        cap: u64,
        buffered: u64,
        fresh_buffered: u64,
        fresh_consumed: u64,
    ) {
        self.recv_flow
            .received(cap, buffered, fresh_buffered, fresh_consumed);
    }

    /// `n` bytes left stream buffers (read, or discarded by a stop or
    /// release), `cap` the session receive buffer cap.
    pub(in super::super) fn credit_consumed(&mut self, cap: u64, n: u64) {
        let pressure = self.memory_pressure;
        self.recv_flow.consumed(cap, n, pressure);
    }

    /// Decides whether MAX_DATA is due (SPEC.md Section 8.3 rules 2 and 3).
    pub(in super::super) fn check_session_credit(&mut self) {
        self.recv_flow.check_credit();
    }

    /// The session receive window becomes `window`.
    pub(in super::super) fn set_session_window(&mut self, window: u64) {
        self.recv_flow.window = window;
        self.check_session_credit();
    }

    /// Whether auto-tuning is paused: at the buffer cap until the buffered
    /// bytes fall below half of it (SPEC.md Section 8.3 rule 4), or under
    /// the listener's memory pressure.
    pub(in super::super) fn growth_paused(&self) -> bool {
        self.recv_flow.at_cap || self.memory_pressure
    }

    /// `increase` more bytes count against the session's receive credit.
    #[inline]
    pub(in super::super) fn count_received(&mut self, increase: u64) {
        self.recv_flow.used += increase;
    }

    /// DATA_BLOCKED from the peer at `limit`, new: auto-tuning learns of
    /// it and credit may be due.
    pub(in super::super) fn data_blocked_received(&mut self, limit: u64) {
        self.recv_flow.blocked_seen = Some(limit);
        self.recv_flow.tuner.on_blocked(limit);
        self.check_session_credit();
    }

    /// Stream data arrived on `key` (its highest received offset `off`):
    /// the arrival rates and credit-loop samples of the stream and of the
    /// session, with their RTT inputs and the receiving pipe's.
    pub(in super::super) fn autotune_data(
        &mut self,
        key: StreamKey,
        off: u64,
        now: Instant,
        rtts: (Option<Duration>, Option<Duration>),
        pipe_rtt: Option<Duration>,
    ) -> [Option<Duration>; 2] {
        let mut samples = [None, None];
        if let Some(r) = self.slab.get_mut(key).and_then(|s| s.recv.as_mut()) {
            if r.tuner.is_empty() {
                r.tuner.install(self.spare.tuner());
            }
            samples[0] = r.tuner.on_data(off, now, rtts.0, pipe_rtt);
        }
        samples[1] = self.recv_flow.on_data(now, rtts.1, pipe_rtt);
        samples
    }

    /// A stream's credit-loop entry for an update that raised its limit.
    pub(in super::super) fn autotune_sent_stream(
        &mut self,
        key: StreamKey,
        old: u64,
        now: Instant,
    ) {
        if let Some(r) = self.slab.get_mut(key).and_then(|s| s.recv.as_mut()) {
            if r.tuner.is_empty() {
                r.tuner.install(self.spare.tuner());
            }
            let highest = r.received;
            r.tuner.sent(old, highest, now);
        }
    }

    /// STREAM_DATA_BLOCKED at `limit` for a stream.
    pub(in super::super) fn autotune_blocked(&mut self, key: StreamKey, limit: u64) {
        if let Some(r) = self.recv_mut(key) {
            r.tuner.on_blocked(limit);
        }
    }

    /// Decides whether MAX_STREAM_DATA is due for a stream and queues it.
    pub(in super::super) fn check_stream_credit(&mut self, key: StreamKey) {
        let Some(r) = self.recv_mut(key) else {
            return;
        };
        if r.state != RecvState::Recv || r.cold().stopped.is_some() || r.update_pending {
            return;
        }
        let c = r.read_offset + r.window;
        if c <= r.limit {
            return;
        }
        let remaining = r.limit.saturating_sub(r.received);
        if credit_due(
            c - r.limit,
            r.window,
            remaining,
            r.cold().blocked_seen == Some(r.limit),
        ) {
            self.mark_stream_update(key, true);
            self.queue_ctrl(key);
        }
    }

    /// STOP_SENDING on the local receiving part: data still buffered is
    /// discarded and counts as consumed, and an owed update is owed no
    /// more. `None` when the part is gone, stopped or terminal already.
    pub(in super::super) fn stop_recv(&mut self, key: StreamKey, code: u64) -> Option<Stopped> {
        let s = self.slab.get_mut(key)?;
        let local = s.local;
        let r = s.recv.as_mut()?;
        if r.cold().stopped.is_some() || r.state.is_terminal() {
            return None;
        }
        r.cold_mut().stopped = Some(code);
        let dropped = r.drop_all();
        r.read_offset = r.received.max(r.read_offset);
        r.contig = r.contig.max(r.read_offset);
        let was = std::mem::replace(&mut r.update_pending, false);
        match r.state {
            RecvState::DataRecvd => r.state = RecvState::DataRead,
            RecvState::ResetRecvd => r.state = RecvState::ResetRead,
            // The peer sent everything already or will reset: STOP_SENDING
            // is useful only while it may still send (RFC 9000 3.5).
            _ => r.stop_pending = true,
        }
        let stop_pending = r.stop_pending;
        if was {
            self.stream_updates -= 1;
        }
        Some(Stopped {
            local,
            dropped,
            stop_pending,
        })
    }

    /// MAX_DATA from the peer raised the limit to `max` at `now`; `false`
    /// when it did not. Streams waiting for session credit (and pinned
    /// openings) may send again.
    pub(in super::super) fn max_data_received(&mut self, max: u64, now: Instant) -> bool {
        if !self.send_flow.raise(max, self.session_stalled, now) {
            return false;
        }
        self.session_stalled = false;
        true
    }

    /// `n` bytes counted against the peer's session credit.
    #[inline]
    pub(in super::super) fn spend(&mut self, n: u64) {
        self.send_flow.used += n;
    }

    /// `n` bytes of stream data were sent, `app` of them written by the
    /// application (the rest a preamble).
    #[inline]
    pub(in super::super) fn sent(&mut self, n: u64, app: u64) {
        self.send_flow.used += n;
        self.send_flow.buffered -= app;
    }

    /// `n` written bytes were dropped unsent (a reset or a failure).
    #[inline]
    pub(in super::super) fn drop_unsent(&mut self, n: u64) {
        self.send_flow.buffered -= n;
    }

    /// Writes `data` to a stream's sending part, copied into its buffer.
    #[inline]
    pub(in super::super) fn write_slice(&mut self, key: StreamKey, data: &[u8]) -> Option<()> {
        let send = self.slab.get_mut(key)?.send.as_mut()?;
        send.buf.push_slice(data, &mut self.chunks);
        send.written += data.len() as u64;
        self.send_flow.buffered += data.len() as u64;
        Some(())
    }

    /// Writes `data` to a stream's sending part without copying it.
    #[inline]
    pub(in super::super) fn write_bytes(
        &mut self,
        key: StreamKey,
        data: bytes::Bytes,
    ) -> Option<()> {
        let n = data.len() as u64;
        let send = self.slab.get_mut(key)?.send.as_mut()?;
        send.buf.push_bytes(data);
        send.written += n;
        self.send_flow.buffered += n;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regular_updates_at_a_sixteenth_of_large_windows() {
        let w = 64 << 20;
        assert!(!credit_due(3 << 20, w, w, false));
        assert!(credit_due(4 << 20, w, w, false));
        // Small windows keep the quarter.
        assert!(!credit_due(63 << 10, 256 << 10, 256 << 10, false));
        assert!(credit_due(64 << 10, 256 << 10, 256 << 10, false));
    }
}
