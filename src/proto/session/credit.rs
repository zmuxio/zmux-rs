//! Receive-side flow control: releasing and issuing credit (SPEC.md
//! Section 8.3) and window auto-tuning.

use std::time::{Duration, Instant};

use super::SessionCore;
use super::config::{Cap, DEFAULT_SEND_BUFFER_MAX, SESSION_WINDOW_FLOOR, STREAM_WINDOW_FLOOR};
use super::stream::StreamKey;

/// The largest window an automatic cap lets grow: what keeps every limit
/// (released bytes plus the window) encodable as a variable-length integer.
const MAX_WINDOW: u64 = crate::proto::varint::MAX / 2;

/// The `allow_connection_window_increase` proposal state: at most one proposal outstanding;
/// growth meanwhile only raises the wanted window.
#[derive(Debug, Default)]
pub(super) struct IncreaseState {
    /// The outstanding proposal: generation and increase.
    pub(super) proposal: Option<(u64, u64)>,
    /// Handed to the driver.
    pub(super) offered: bool,
    pub(super) generation: u64,
    /// The window auto-tuning wants meanwhile.
    pub(super) wanted: u64,
    /// Refused proposals (refusals and panics).
    pub(super) refused: u64,
}

impl SessionCore {
    /// The session receive buffer cap (SPEC.md Section 8.3 rule 4).
    pub(super) fn buffer_cap(&self) -> u64 {
        let tp = self.local_tp();
        // The stream counts the peer may have open (constant once granted;
        // unidirectional credit may be granted lazily).
        let s = self
            .streams
            .remote_dir(super::BIDI)
            .initial
            .saturating_mul(tp.window_bidi_remote)
            .saturating_add(
                self.streams
                    .remote_dir(super::UNI)
                    .initial
                    .saturating_mul(tp.window_uni),
            )
            .saturating_add(
                self.streams
                    .local_recv_open()
                    .saturating_mul(tp.window_bidi_local),
            );
        s.max(self.config.session_window_base())
    }

    /// Bytes received on streams. `buffered` bytes went into stream
    /// buffers; of the bytes whose credit was not handled before,
    /// `fresh_buffered` were buffered and `fresh_consumed` will never be
    /// (discarded data, preamble bytes, final sizes beyond the data).
    pub(super) fn credit_received(
        &mut self,
        buffered: u64,
        fresh_buffered: u64,
        fresh_consumed: u64,
    ) {
        let cap = self.buffer_cap();
        self.streams
            .credit_received(cap, buffered, fresh_buffered, fresh_consumed);
    }

    /// Bytes left stream buffers (read, or discarded by a stop or release).
    pub(super) fn credit_consumed(&mut self, n: u64) {
        if self.recv_refs.consumed(n) {
            // What is left may keep old read buffers alive beyond the
            // bound now.
            self.settle_recv_refs();
        }
        let cap = self.buffer_cap();
        self.streams.credit_consumed(cap, n);
    }

    /// The MAX_DATA value to send now, after auto-tuning (rule RB).
    pub(super) fn session_credit_value(&mut self, now: Instant) -> u64 {
        let paused = self.streams.growth_paused();
        if !paused {
            let rtt = self.autotune_rtt(None);
            let b = self.config.latency_budget;
            if let Some(target) = self.streams.recv_flow().tuner.target(rtt, b) {
                self.grow_session_window(target);
            }
            if rtt.is_none() && self.streams.recv_flow().tuner.rate().is_some() {
                self.probe_rtt(now);
            }
        }
        self.streams.recv_flow().credit()
    }

    /// What the session holds that its memory budget counts, in constant
    /// time: buffered receive data, retained data (which includes what a
    /// suspended session keeps) and the session window's growth.
    pub(super) fn budget_used(&self) -> u64 {
        let retained = self.mp.as_deref().map_or(0, super::mpath::Mp::retained);
        self.streams.recv_flow().buffered + retained + self.window_growth() + self.carrier_memory
    }

    /// What the memory budget has left for the session to grow by: the
    /// listener's allowance less what the session took since, or its own
    /// `memory_budget` less what it holds; `None` is unlimited.
    pub(super) fn budget_left(&self) -> Option<u64> {
        let used = self.budget_used();
        match self.memory_allowance {
            Some((left, at)) => left.map(|l| l.saturating_sub(used.saturating_sub(at))),
            None => (self.config.memory_budget > 0)
                .then(|| self.config.memory_budget.saturating_sub(used)),
        }
    }

    /// The largest session window the memory budget allows.
    fn session_allowance(&self) -> u64 {
        self.budget_left().map_or(u64::MAX, |l| {
            self.streams.recv_flow().window.saturating_add(l)
        })
    }

    /// The largest session window now: a fixed cap within the memory
    /// allowance, or the automatic cap, the 96 MiB floor and above it the
    /// allowance (SPEC.md Section 8.3 rule 4).
    fn session_window_limit(&self) -> u64 {
        let allowance = self.session_allowance();
        match self.config.max_connection_receive_window {
            Cap::Fixed(v) => v.min(allowance),
            Cap::Auto => SESSION_WINDOW_FLOOR.max(allowance).min(MAX_WINDOW),
        }
    }

    /// The largest stream window the memory budget allows now, through the
    /// session window: with the automatic cap, at least the 64 MiB floor.
    fn stream_window_limit(&self) -> u64 {
        let allowance = self.session_allowance();
        match self.config.max_stream_receive_window {
            Cap::Fixed(_) => allowance,
            Cap::Auto => STREAM_WINDOW_FLOOR.max(allowance).min(MAX_WINDOW),
        }
    }

    /// Raises the session window toward `target`, within its cap and the
    /// memory allowance; through `allow_connection_window_increase` when
    /// set (one proposal outstanding at a time).
    pub(super) fn grow_session_window(&mut self, target: u64) {
        let target = target.min(self.session_window_limit());
        if target <= self.streams.recv_flow().window {
            return;
        }
        if self.config.allow_connection_window_increase.is_some() {
            let w = &mut self.window_increase;
            w.wanted = w.wanted.max(target);
            if w.proposal.is_none() {
                let delta = target - self.streams.recv_flow().window;
                w.generation += 1;
                w.proposal = Some((w.generation, delta));
                w.offered = false;
                self.events.push_back(super::CoreEvent::WindowIncrease);
            }
            return;
        }
        self.streams.set_session_window(target);
    }

    /// The proposed session window increase the driver should put to
    /// `allow_connection_window_increase` (outside every lock): its
    /// generation and the increase. Each proposal is handed out once.
    pub fn take_window_increase(&mut self) -> Option<(u64, u64)> {
        let w = &mut self.window_increase;
        let p = w.proposal.filter(|_| !w.offered)?;
        w.offered = true;
        Some(p)
    }

    /// The predicate's answer to the proposal of `generation`: an approval
    /// raises the session window by up to the approved increase (within the
    /// caps and the memory allowance) unless the session has closed; then,
    /// if the wanted window has moved on, the rest is proposed. A refusal
    /// leaves the window until the next growth decision.
    pub fn answer_window_increase(&mut self, generation: u64, approved: bool) {
        let w = &mut self.window_increase;
        let Some((g, delta)) = w.proposal else {
            return;
        };
        if g != generation {
            return;
        }
        w.proposal = None;
        w.offered = false;
        if !approved {
            w.wanted = 0;
            w.refused += 1;
            return;
        }
        if self.error.is_some() {
            return;
        }
        let wanted = std::mem::take(&mut self.window_increase.wanted);
        let target = (self.streams.recv_flow().window + delta).min(self.session_window_limit());
        if target > self.streams.recv_flow().window {
            self.streams.set_session_window(target);
        }
        if wanted > self.streams.recv_flow().window {
            self.grow_session_window(wanted);
        }
    }

    /// A listener's memory budget has `bytes` left (`None`: it is
    /// unlimited): the session grows its windows and retained data by at
    /// most that much from now on, until the listener says again. From the first call
    /// the listener's budget replaces the session's own `memory_budget`.
    pub fn set_memory_allowance(&mut self, bytes: Option<u64>) {
        self.memory_allowance = Some((bytes, self.budget_used()));
    }

    /// Counts `bytes` that a carrier holds for the session (a QUIC
    /// connection's receive window) in
    /// its memory budget until [`SessionCore::release_carrier_memory`]: window
    /// growth stops that much earlier.
    pub fn charge_carrier_memory(&mut self, bytes: u64) {
        self.carrier_memory = self.carrier_memory.saturating_add(bytes);
    }

    /// Releases a charge of [`SessionCore::charge_carrier_memory`]: the
    /// carrier holds those bytes for the session no more.
    pub fn release_carrier_memory(&mut self, bytes: u64) {
        self.carrier_memory = self.carrier_memory.saturating_sub(bytes);
    }

    /// Whether the session grew what the memory budget charges since its
    /// last allowance: the listener shares what is left between the
    /// sessions that grow.
    pub fn grew_since_allowance(&self) -> bool {
        self.memory_allowance
            .is_some_and(|(_, at)| self.budget_used() > at)
    }

    /// The largest send buffer, which also caps the retransmit budget: a fixed
    /// `max`, or the 64 MiB floor and
    /// above it the retained data plus what the memory budget has left.
    pub(super) fn send_buffer_limit(&self) -> u64 {
        match self.config.send_buffer_max {
            Cap::Fixed(v) => v,
            Cap::Auto => {
                let retained = self.mp.as_deref().map_or(0, super::mpath::Mp::retained);
                let grant = self
                    .budget_left()
                    .map_or(u64::MAX, |l| retained.saturating_add(l));
                DEFAULT_SEND_BUFFER_MAX.max(grant)
            }
        }
    }

    /// How far the session window grew above its initial size: what the
    /// listener's memory budget charges for it.
    pub fn window_growth(&self) -> u64 {
        self.streams
            .recv_flow()
            .window
            .saturating_sub(self.config.initial_connection_receive_window)
    }

    /// The RTT input of auto-tuning for a scope (`key` a stream, `None` the
    /// session): on a single pipe the
    /// carrier's minimum RTT, else the credit-loop minimum (300 s, QX_PING
    /// samples included); in a multipath session the largest pipe_min_rtt
    /// of the pipes the scope's data arrived on in the last 4 intervals.
    pub(super) fn autotune_rtt(&self, key: Option<StreamKey>) -> Option<Duration> {
        if let Some(r) = self.config.hooks.rtt {
            return Some(r);
        }
        if self.mp.is_some() {
            return match key {
                Some(k) => self.streams.recv(k).and_then(|r| r.tuner.rtt_seen()),
                None => self.streams.recv_flow().tuner.rtt_seen(),
            };
        }
        self.carrier_rtt.or(self.loop_min.get())
    }

    /// Stream data arrived: the arrival rates and credit-loop samples of
    /// the stream (whose highest received offset is `off`) and of the
    /// session.
    pub(super) fn autotune_data(&mut self, key: StreamKey, off: u64, now: Instant) {
        let pipe_rtt = if self.mp.is_some() {
            self.pipe_min_rtt(self.rx)
        } else {
            None
        };
        let rtt = self.autotune_rtt(Some(key));
        let session_rtt = self.autotune_rtt(None);
        let samples = self
            .streams
            .autotune_data(key, off, now, (rtt, session_rtt), pipe_rtt);
        for s in samples.into_iter().flatten() {
            self.loop_min.sample(now, s, super::filter::LOOP_SPAN);
        }
    }

    /// The MAX_STREAM_DATA value to send now for a stream, after
    /// auto-tuning (rule RB); a grown stream window raises the session
    /// window to 1.5 times it.
    pub(super) fn stream_credit_value(&mut self, key: StreamKey, now: Instant) -> Option<u64> {
        let paused = self.streams.growth_paused();
        let rtt = self.autotune_rtt(Some(key));
        let b = self.config.latency_budget;
        // A stream window is bounded through the session window by the
        // memory allowance as well.
        let allowance = self.stream_window_limit();
        let r = self.streams.recv_mut(key)?;
        let mut grew = None;
        let mut no_rtt = false;
        if !paused && let Some(target) = r.tuner.target(rtt, b) {
            no_rtt = rtt.is_none();
            if target > r.window {
                let w = target.min(r.max_window).min(allowance).max(r.window);
                if w > r.window {
                    r.window = w;
                    grew = Some(w);
                }
            }
        }
        let value = r.read_offset + r.window;
        if no_rtt {
            self.probe_rtt(now);
        }
        if let Some(w) = grew {
            self.grow_session_window(w.saturating_add(w / 2));
        }
        Some(value)
    }

    /// MAX_STREAMS for a discarded peer stream (SPEC.md Section 8.5).
    pub(super) fn stream_count_credit(&mut self, d: usize) {
        // An endpoint that sent GOAWAY raises MAX_STREAMS no more
        // (EXTENSIONS.md Section 3.3).
        let raise = !self.goaway_announced();
        self.streams.count_discarded(d, raise);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SPEC.md Section 8.3: every reset releases the session credit of
    /// the bytes in [Reliable Size, final size) that never arrived, each
    /// byte once, also after a FIN and when the Reliable Size is lowered;
    /// late copies release nothing, and bytes below the Reliable Size are
    /// released on arrival or when the part is discarded.
    #[test]
    fn resets_release_lost_bytes_once() {
        use super::super::stream::RecvPart;
        let part = || RecvPart::with_buf(2048, 2048, bytes::BytesMut::new());
        // 2 bytes arrived; RESET_STREAM_AT(1500) then RESET_STREAM.
        let mut r = part();
        assert_eq!(r.arrive(0, 2), 2);
        r.final_size = Some(2048);
        assert_eq!(r.credit_reset(1500, 2048), 548);
        assert_eq!(r.credit_reset(1500, 2048), 0, "a repeat releases nothing");
        // Bytes below the Reliable Size still arrive and release on arrival;
        // a late copy at or above it releases nothing.
        assert_eq!(r.arrive(2, 1000), 998);
        assert_eq!(r.arrive(1000, 2048), 500);
        assert_eq!(r.arrive(0, 2048), 0);
        assert_eq!(r.credit_owed(), 0);
        // Lowering to 0 releases what lies between, once.
        let mut r = part();
        assert_eq!(r.arrive(0, 2), 2);
        r.final_size = Some(2048);
        assert_eq!(r.credit_reset(1500, 2048), 548);
        assert_eq!(r.credit_reset(0, 2048), 1498);
        assert_eq!(r.credit_reset(0, 2048), 0);
        assert_eq!(r.arrive(0, 2048), 0, "late copies release nothing");
        // After a FIN every byte arrived.
        let mut r = part();
        assert_eq!(r.arrive(0, 2048), 2048);
        r.final_size = Some(2048);
        assert_eq!(r.credit_reset(0, 2048), 0);
        // Discarding a part owes the bytes below the Reliable Size that
        // never arrived.
        let mut r = part();
        r.final_size = Some(2048);
        assert_eq!(r.credit_reset(1500, 2048), 548);
        assert_eq!(r.credit_owed(), 1500);
    }

    /// SPEC.md Section 8.3: bytes beyond a gap (multipath) release credit
    /// when they arrive, never before; the gap releases its own bytes when
    /// they arrive, and a reset releases the gap's bytes at or above the
    /// Reliable Size that never arrived.
    #[test]
    fn gaps_release_credit_on_arrival_only() {
        use super::super::stream::RecvPart;
        let mut r = RecvPart::with_buf(4096, 4096, bytes::BytesMut::new());
        assert_eq!(r.arrive(1000, 1100), 100, "only the frame's own bytes");
        assert_eq!(r.arrive(1050, 1200), 100);
        assert_eq!(r.arrive(0, 500), 500);
        assert_eq!(r.arrived_in(0, 4096), 700);
        assert_eq!(r.arrive(400, 1000), 500, "the gap's bytes, once");
        assert_eq!(r.arrived_to, 1200);
        assert_eq!(r.arrived_in(0, u64::MAX), r.arrived_to);
        // A gap at a reset: [1300, 1400) arrived, the rest of [1200, 2000)
        // did not; RESET_STREAM releases those 700 bytes.
        assert_eq!(r.arrive(1300, 1400), 100);
        r.final_size = Some(2000);
        assert_eq!(r.credit_reset(0, 2000), 700);
        assert_eq!(r.arrive(1200, 2000), 0);
        assert_eq!(r.credit_owed(), 0);
    }

    fn session(c: super::super::Config) -> SessionCore {
        let role = super::super::RoleConfig::Initiator;
        SessionCore::new(c, role, None, Instant::now()).unwrap()
    }

    #[test]
    fn automatic_caps_grow_beyond_the_floors_within_the_budget() {
        const MIB: u64 = 1 << 20;
        let mut c = super::super::Config {
            memory_budget: 256 * MIB,
            ..Default::default()
        };
        let mut s = session(c.clone());
        s.grow_session_window(1 << 40);
        // The window's growth counts against the budget.
        assert_eq!(s.streams.recv_flow().window, 257 * MIB);
        assert_eq!(s.stream_window_limit(), 257 * MIB);
        // The receive buffer cap stays at the floor: the DoS bound does not
        // grow with the window.
        assert_eq!(s.buffer_cap(), 96 * MIB);
        // A budget below the floors leaves the floors.
        c.memory_budget = MIB;
        let mut s = session(c.clone());
        s.grow_session_window(1 << 40);
        assert_eq!(s.streams.recv_flow().window, 96 * MIB);
        assert_eq!(s.send_buffer_limit(), 64 * MIB);
        // A listener's budget replaces the session's own.
        s.set_memory_allowance(Some(500 * MIB));
        s.grow_session_window(1 << 40);
        assert_eq!(s.streams.recv_flow().window, 596 * MIB);
        // The window took what the listener had left.
        assert_eq!(s.send_buffer_limit(), 64 * MIB);
        // Fixed caps are fixed, whatever the budget.
        c.memory_budget = 0;
        c.max_connection_receive_window = Cap::Fixed(8 * MIB);
        c.send_buffer_max = Cap::Fixed(2 * MIB);
        let mut s = session(c);
        s.grow_session_window(1 << 40);
        assert_eq!(s.streams.recv_flow().window, 8 * MIB);
        assert_eq!(s.buffer_cap(), 68 * MIB);
        assert_eq!(s.send_buffer_limit(), 2 * MIB);
    }
}
