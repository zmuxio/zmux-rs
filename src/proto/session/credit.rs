//! Receive-side flow control: releasing and issuing credit and window auto-tuning.

use std::time::Instant;

use super::SessionCore;
use super::config::{Cap, STREAM_WINDOW_FLOOR};
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
    /// The session receive buffer cap.
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
        let window = match self.config.max_connection_receive_window {
            Cap::Fixed(cap) => cap,
            Cap::Auto => self.streams.recv_flow().window,
        };
        s.max(window)
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
        if self.streams.memory_pressure() {
            self.reclaim_receive_space(false);
        }
    }

    /// The `MAX_DATA` value to send now, after auto-tuning.
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

    /// The largest receive window that could be backed at this instant.
    fn session_allowance(&self) -> u64 {
        self.receive_credit
            .as_ref()
            .map_or(u64::MAX, super::memory::ReceiveCredit::possible)
    }

    fn session_window_limit(&self) -> u64 {
        let allowance = self
            .session_allowance()
            .min(super::recv_store::ReceiveStore::MAX_POSITIONS);
        match self.config.max_connection_receive_window {
            Cap::Fixed(value) => value.min(allowance),
            Cap::Auto => allowance.min(MAX_WINDOW),
        }
    }

    fn stream_window_limit(&self, automatic_cap: bool) -> u64 {
        let allowance = self.session_allowance();
        if automatic_cap {
            STREAM_WINDOW_FLOOR.max(allowance).min(MAX_WINDOW)
        } else {
            allowance
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

    /// The per-session cap on send buffering and retransmit retention.
    pub(super) fn send_buffer_limit(&self) -> u64 {
        match self.config.send_buffer_max {
            Cap::Fixed(v) => v,
            Cap::Auto => u64::MAX,
        }
    }

    /// How far the tuned session window grew from the advertised initial window.
    pub fn window_growth(&self) -> u64 {
        let flow = self.streams.recv_flow();
        flow.window.saturating_sub(flow.initial_window)
    }

    /// The `MAX_STREAM_DATA` value to send now for a stream, after
    /// auto-tuning; a grown stream window raises the session
    /// window to 1.5 times it.
    pub(super) fn stream_credit_value(&mut self, key: StreamKey, now: Instant) -> Option<u64> {
        let paused = self.streams.growth_paused();
        let rtt = self.autotune_rtt(Some(key));
        let b = self.config.latency_budget;
        // A stream window is bounded through the session window by the
        // memory allowance as well.
        let automatic_cap = self.streams.recv(key)?.automatic_cap();
        let allowance = self.stream_window_limit(automatic_cap);
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

    /// `MAX_STREAMS` for a discarded peer stream.
    pub(super) fn stream_count_credit(&mut self, d: usize) {
        // An endpoint that sent GOAWAY raises MAX_STREAMS no more.
        let raise = !self.goaway_announced();
        self.streams.count_discarded(d, raise);
        self.release_peer_receive(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StreamError;

    /// Every reset releases the session credit of
    /// the bytes in [Reliable Size, final size) that never arrived, each
    /// byte once, also after a FIN and when the Reliable Size is lowered;
    /// late copies release nothing, and bytes below the Reliable Size are
    /// released on arrival or when the part is discarded.
    #[test]
    fn resets_release_lost_bytes_once() {
        use super::super::stream::RecvPart;
        let part = || RecvPart::new(2048, 2048);
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

    /// Bytes beyond a gap (multipath) release credit
    /// when they arrive, never before; the gap releases its own bytes when
    /// they arrive, and a reset releases the gap's bytes at or above the
    /// Reliable Size that never arrived.
    #[test]
    fn gaps_release_credit_on_arrival_only() {
        use super::super::stream::RecvPart;
        let mut r = RecvPart::new(4096, 4096);
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

    #[test]
    fn discard_keeps_only_missing_offsets_and_reset_preserves_statistics() {
        use super::super::stream::RecvPart;

        let mut r = RecvPart::new(8192, 8192);
        for offset in (1..8192).step_by(2) {
            assert_eq!(r.arrive(offset, offset + 1), 1);
        }
        assert_eq!(r.arrive(2, 8192), 4095);
        r.received = 8192;
        assert!(r.memory() >= 1024);
        r.discard_arrival_data();
        assert!(r.memory() < 256);
        assert_eq!(r.arrived_from(0), 8191);
        assert_eq!(r.arrive(0, 3), 1);
        assert_eq!(r.arrived_from(0), 8192);

        let mut r = RecvPart::new(8192, 8192);
        assert_eq!(r.arrive(16, 64), 48);
        assert_eq!(r.credit_reset(32, 128), 64);
        assert_eq!(r.credit_reset(8, 128), 8);
        assert_eq!(r.arrived_from(0), 48);
        assert_eq!(r.arrive(0, 128), 8);
        assert_eq!(r.arrived_from(0), 56);
    }

    #[test]
    fn stop_then_out_of_order_arrival_extends_the_known_extent_without_filling_holes() {
        use super::super::stream::RecvPart;

        let mut r = RecvPart::new(8192, 8192);
        assert_eq!(r.arrive(0, 10), 10);
        assert_eq!(r.arrive(20, 30), 10);
        r.received = 30;
        r.cold_mut().stopped = Some(0);
        r.discard_arrival_data();
        assert_eq!(r.arrive(40, 50), 10);
        assert_eq!(r.arrived_to, 10);
        assert_eq!(r.arrived_in(10, 20), 0);
        assert_eq!(r.arrived_in(30, 40), 0);
        assert_eq!(r.arrive(40, 50), 0);
        assert_eq!(r.arrive(35, 45), 5);
        assert_eq!(r.arrive(10, 35), 15);
        assert_eq!(r.arrived_to, 50);
        assert_eq!(r.arrived_from(0), 50);
    }

    #[test]
    fn stop_and_reliable_reset_settle_only_their_own_offsets() {
        use super::super::stream::RecvPart;

        for stop_first in [false, true] {
            let mut r = RecvPart::new(8192, 8192);
            assert_eq!(r.arrive(0, 10), 10);
            assert_eq!(r.arrive(25, 30), 5);
            r.received = 30;
            r.final_size = Some(60);
            let stop = |r: &mut RecvPart| {
                r.cold_mut().stopped = Some(0);
                r.discard_arrival_data();
            };
            if stop_first {
                stop(&mut r);
            }
            assert_eq!(r.credit_reset(40, 60), 20);
            if !stop_first {
                stop(&mut r);
            }
            assert_eq!(r.arrive(35, 50), 5);
            assert_eq!(r.credit_owed(), 20);
            assert_eq!(r.credit_reset(20, 60), 10);
            assert_eq!(r.arrived_from(0), 20);
            assert_eq!(r.credit_owed(), 10);
            assert_eq!(r.arrive(10, 60), 10);
            assert_eq!(r.credit_owed(), 0);
        }
    }

    fn session(c: super::super::Config) -> SessionCore {
        let role = super::super::Role::Client;
        SessionCore::new(c, role, None, Instant::now()).unwrap()
    }

    #[test]
    fn automatic_connection_window_cannot_exceed_its_committable_positions() {
        const MIB: u64 = 1 << 20;
        let mut config = super::super::Config {
            memory_budget: Some(256 * MIB),
            ..Default::default()
        };
        let mut core = session(config.clone());
        let affordable = core.session_allowance();
        assert!(affordable >= 8 * MIB, "{affordable} bytes can be committed");
        core.grow_session_window(1 << 40);
        assert_eq!(core.streams.recv_flow().window, affordable);
        assert!(core.buffer_cap() >= affordable);
        config.memory_budget = None;
        config.max_connection_receive_window = Cap::Fixed(8 * MIB);
        config.send_buffer_max = Cap::Fixed(2 * MIB);
        config.send_buffer = 2 * MIB;
        let mut core = session(config);
        core.grow_session_window(1 << 40);
        assert_eq!(core.streams.recv_flow().window, 8 * MIB);
        assert_eq!(core.send_buffer_limit(), 2 * MIB);
    }

    #[test]
    fn receive_window_getter_reads_the_setting_not_the_tuned_window() {
        let c = super::super::Config::default();
        let initial = c.initial_stream_receive_window;
        let mut s = session(c);
        let k = s.open(super::super::Dir::Bidi).unwrap();
        // The session's initial window; the automatic cap reads 0.
        assert_eq!(s.receive_window(k), Some((initial, 0)));
        // What auto-tuning does to a stream: the window grows.
        let r = s.streams.recv_mut(k).unwrap();
        r.window = 8 * initial;
        assert_eq!(s.streams.recv(k).unwrap().window, 8 * initial);
        assert_eq!(s.receive_window(k), Some((initial, 0)));
        // A raised initial window and a cap read as set, and tuning does
        // not move them either.
        s.set_receive_window(k, 2 * initial, 16 * initial).unwrap();
        assert_eq!(s.receive_window(k), Some((2 * initial, 16 * initial)));
        s.streams.recv_mut(k).unwrap().window = 12 * initial;
        assert_eq!(s.receive_window(k), Some((2 * initial, 16 * initial)));
        assert_eq!(
            s.stream_settings(k).unwrap().receive_window,
            (2 * initial, 16 * initial)
        );
        // A fixed cap in the configuration reads as configured.
        let c = super::super::Config {
            max_stream_receive_window: Cap::Fixed(4 * initial),
            ..Default::default()
        };
        let mut s = session(c);
        let k = s.open(super::super::Dir::Bidi).unwrap();
        assert_eq!(s.receive_window(k), Some((initial, 4 * initial)));
    }

    #[test]
    fn set_receive_window_zero_max_is_automatic() {
        let initial = super::super::Config::default().initial_stream_receive_window;
        let c = super::super::Config {
            max_stream_receive_window: Cap::Fixed(4 * initial),
            ..Default::default()
        };
        let mut s = session(c);
        let k = s.open(super::super::Dir::Bidi).unwrap();
        assert_eq!(s.receive_window(k), Some((initial, 4 * initial)));
        // A fixed cap above the session's, as set.
        s.set_receive_window(k, initial, 8 * initial).unwrap();
        assert_eq!(s.receive_window(k), Some((initial, 8 * initial)));
        // 0 is the automatic cap: not the previous cap, not the initial
        // window, not the session's fixed cap.
        s.set_receive_window(k, initial, 0).unwrap();
        assert_eq!(s.receive_window(k), Some((initial, 0)));
        assert_eq!(
            s.streams.recv(k).unwrap().max_window,
            crate::proto::varint::MAX
        );
        // A cap equal to initial is valid.
        s.set_receive_window(k, 2 * initial, 2 * initial).unwrap();
        assert_eq!(s.receive_window(k), Some((2 * initial, 2 * initial)));
    }

    /// A stream made automatic with a `max` of 0 under a session that fixes
    /// the cap gets the automatic cap's 64 MiB floor, not the session's cap;
    /// a stream with a fixed cap does not.
    #[test]
    fn a_stream_automatic_under_a_fixed_session_cap_gets_the_floor() {
        let initial = super::super::Config::default().initial_stream_receive_window;
        let c = super::super::Config {
            max_stream_receive_window: Cap::Fixed(4 * initial),
            memory_budget: Some(32 << 20),
            ..Default::default()
        };
        let mut s = session(c);
        let k = s.open(super::super::Dir::Bidi).unwrap();
        let limit = |s: &SessionCore| {
            let auto = s.streams.recv(k).unwrap().automatic_cap();
            s.stream_window_limit(auto)
        };
        assert!(s.stream_window_limit(false) < STREAM_WINDOW_FLOOR);
        assert_eq!(limit(&s), s.stream_window_limit(false));
        s.set_receive_window(k, initial, 0).unwrap();
        assert_eq!(limit(&s), STREAM_WINDOW_FLOOR);
        s.set_receive_window(k, initial, 2 * initial).unwrap();
        assert_eq!(limit(&s), s.stream_window_limit(false));
    }

    /// A window above the largest varint is refused, not cut to it.
    #[test]
    fn set_receive_window_rejects_values_above_the_largest_varint() {
        let initial = super::super::Config::default().initial_stream_receive_window;
        let mut s = session(super::super::Config::default());
        let k = s.open(super::super::Dir::Bidi).unwrap();
        let big = crate::proto::varint::MAX + 1;
        for (i, m) in [(big, 0), (initial, big), (big, big)] {
            assert_eq!(
                s.set_receive_window(k, i, m),
                Err(StreamError::InvalidArgument)
            );
        }
        assert_eq!(s.receive_window(k), Some((initial, 0)));
        // The largest varint itself is accepted and reads back as set (as
        // a cap it is the automatic one).
        let max = crate::proto::varint::MAX;
        s.set_receive_window(k, max, max - 1).unwrap_err();
        s.set_receive_window(k, max - 1, max).unwrap();
        assert_eq!(s.receive_window(k), Some((max - 1, 0)));
    }

    #[test]
    fn set_receive_window_rejects_a_max_below_initial() {
        let initial = super::super::Config::default().initial_stream_receive_window;
        let mut s = session(super::super::Config::default());
        let k = s.open(super::super::Dir::Bidi).unwrap();
        s.set_receive_window(k, 2 * initial, 4 * initial).unwrap();
        let window = s.streams.recv(k).unwrap().window;
        for (i, m) in [
            (8 * initial, 4 * initial),
            (1 << 20, 1),
            (3 * initial, 2 * initial),
        ] {
            assert_eq!(
                s.set_receive_window(k, i, m),
                Err(StreamError::InvalidArgument)
            );
        }
        // Nothing changed: the setting, the cap and the window in force.
        assert_eq!(s.receive_window(k), Some((2 * initial, 4 * initial)));
        assert_eq!(s.streams.recv(k).unwrap().window, window);
    }

    #[test]
    fn set_receive_window_never_withdraws_credit() {
        let initial = super::super::Config::default().initial_stream_receive_window;
        let mut s = session(super::super::Config::default());
        let k = s.open(super::super::Dir::Bidi).unwrap();
        // Above the window in force: raised at once.
        s.set_receive_window(k, 8 * initial, 0).unwrap();
        assert_eq!(s.streams.recv(k).unwrap().window, 8 * initial);
        // Below it: only the setting read back changes; the floor is 16 KiB.
        s.set_receive_window(k, 2 * initial, 4 * initial).unwrap();
        assert_eq!(s.streams.recv(k).unwrap().window, 8 * initial);
        assert_eq!(s.receive_window(k), Some((2 * initial, 4 * initial)));
        s.set_receive_window(k, 4096, 0).unwrap();
        assert_eq!(s.streams.recv(k).unwrap().window, 8 * initial);
        assert_eq!(s.receive_window(k), Some((4096, 0)));
    }

    #[test]
    fn set_receive_window_rejects_an_initial_below_4_kib() {
        let initial = super::super::Config::default().initial_stream_receive_window;
        let mut s = session(super::super::Config::default());
        let k = s.open(super::super::Dir::Bidi).unwrap();
        s.set_receive_window(k, 2 * initial, 4 * initial).unwrap();
        let window = s.streams.recv(k).unwrap().window;
        for i in [0, 1, 4095] {
            assert_eq!(
                s.set_receive_window(k, i, 0),
                Err(StreamError::InvalidArgument)
            );
        }
        assert_eq!(s.receive_window(k), Some((2 * initial, 4 * initial)));
        assert_eq!(s.streams.recv(k).unwrap().window, window);
        s.set_receive_window(k, 4096, 0).unwrap();
        assert_eq!(s.receive_window(k), Some((4096, 0)));
        s.set_receive_window(k, 4096, 4096).unwrap();
        assert_eq!(s.receive_window(k), Some((4096, 4096)));
    }
}
