//! Behaviour of the sans-IO core that the traces do not cover: two cores
//! connected in memory.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use zmux::Limiter;
use zmux::proto::VarInt;
use zmux::proto::frame::Dir;
use zmux::proto::session::{Config, CoreEvent, Preamble, SessionCore, State, StreamError};

#[path = "common/core_pair.rs"]
mod core_pair;

use core_pair::{CorePair as Pair, P0};

#[test]
fn memory_pressure_rejects_new_streams_and_keeps_credit_flowing() {
    let mut cfg = Config::default();
    cfg.max_incoming_streams = 4;
    let mut p = Pair::with_events(Config::default(), cfg);
    p.b.set_memory_pressure(true);
    let mut keys = Vec::new();
    for _ in 0..4 {
        let k = p.a.open(Dir::Bidi).unwrap();
        p.a.write(k, b"request").unwrap();
        keys.push(k);
    }
    p.pump();
    // Nothing was offered, every stream was rejected and retryable.
    assert_eq!(p.b.accept(Dir::Bidi).unwrap(), None);
    for &k in &keys {
        assert_eq!(p.a.write(k, b"more"), Err(StreamError::Rejected));
        let mut buf = [0u8; 16];
        assert_eq!(p.a.read(k, &mut buf), Err(StreamError::Rejected));
        p.a.release(k);
    }
    p.pump();
    // The rejected streams returned their credit: four more can open.
    // Released before their first frame, they consume no identifier and
    // give their credit back at once.
    for _ in 0..4 {
        let k = p.a.open(Dir::Bidi).expect("credit returned");
        p.a.release(k);
    }
    p.b.set_memory_pressure(false);
    let mut tries = 0;
    let k = loop {
        match p.a.open(Dir::Bidi) {
            Ok(k) => break k,
            Err(e) => {
                tries += 1;
                assert!(tries < 10, "{e:?}");
                p.pump();
            }
        }
    };
    p.a.write(k, b"after").unwrap();
    p.pump();
    let s =
        p.b.accept(Dir::Bidi)
            .unwrap()
            .expect("offered without pressure");
    assert_eq!(p.b.peek_stream_id(s), Some(16));
}

#[test]
fn keep_alive_counts_sent_records_as_activity() {
    let mut cfg = Config::default();
    cfg.max_idle_timeout = Duration::from_secs(10);
    cfg.keep_alive_period = Some(Duration::from_secs(4));
    cfg.max_incoming_uni_streams = Some(4);
    let mut p = Pair::with_events(cfg.clone(), cfg);
    // A only sends: its own records postpone its keep-alive as they
    // restart its idle timer.
    let start = p.now;
    let k = p.a.open(Dir::Uni).unwrap();
    for i in 1..=6 {
        p.now = start + Duration::from_secs(3 * i);
        p.a.handle_timeout(p.now);
        p.b.handle_timeout(p.now);
        p.a.write(k, b"tick").unwrap();
        p.pump();
    }
    assert_eq!(p.a.state(), State::Active);
    assert_eq!(p.b.state(), State::Active);
    assert_eq!(p.a.stats().records_sent, p.b.stats().records_received);
}

#[test]
fn idle_sessions_time_out_without_keep_alive() {
    let mut cfg = Config::default();
    cfg.max_idle_timeout = Duration::from_secs(5);
    let mut p = Pair::with_events(cfg.clone(), cfg);
    p.now += Duration::from_secs(6);
    p.a.handle_timeout(p.now);
    assert_eq!(p.a.state(), State::Closing);
    assert!(matches!(
        p.a.error(),
        Some(zmux::SessionError::IdleTimeout { remote: false })
    ));
}

/// A budget of bytes that never refills (a limiter).
struct Budget(AtomicUsize);

impl Limiter for Budget {
    fn poll_ready(&self, _: &mut Context<'_>, _: usize, max: usize) -> Poll<usize> {
        Poll::Ready(self.try_ready(max))
    }

    fn try_ready(&self, max: usize) -> usize {
        self.0.load(Ordering::Relaxed).min(max)
    }

    fn charge(&self, n: usize) {
        self.0.fetch_sub(n, Ordering::Relaxed);
    }
}

/// Received datagrams waiting for the receive limiter, the ones the driver
/// took to police included, count in the session's datagram bytes with
/// the queued ones (EXTENSIONS.md Section 6.5): the oldest waiting ones
/// make room, and the session never holds more than 1 MiB of them.
#[test]
fn datagrams_waiting_for_the_limiter_stay_within_the_session_bytes() {
    const LIMIT: u64 = 1024 * 1024;
    let mut a_cfg = Config::default();
    a_cfg.enable_datagrams = true;
    let mut b_cfg = Config::default();
    b_cfg.enable_datagrams = true;
    b_cfg.datagram_limiter.receive = Some(Arc::new(Budget(AtomicUsize::new(usize::MAX))));
    let mut p = Pair::with_events(a_cfg, b_cfg);
    let send = |p: &mut Pair, n: usize| {
        for _ in 0..n {
            for _ in 0..50 {
                p.a.send_datagram(Bytes::from(vec![9u8; 1000]), true)
                    .unwrap();
            }
            p.pump();
            assert!(p.b.held_bytes() <= LIMIT, "{} held", p.b.held_bytes());
        }
    };
    // 600 KB arrive and the driver takes them to the limiter.
    send(&mut p, 12);
    let mut staged = Vec::new();
    p.b.take_received_datagrams(&mut staged);
    assert_eq!(staged.len(), 600);
    // 600 KB more: only what fits beside the staged ones is kept.
    send(&mut p, 12);
    assert!(p.b.held_bytes() <= LIMIT);
    assert!(p.b.held_bytes() > LIMIT - 2000);
    for d in &mut staged {
        d.set_allowed(true);
    }
    p.b.admit_datagrams(&mut staged);
    let mut rest = Vec::new();
    p.b.take_received_datagrams(&mut rest);
    for d in &mut rest {
        d.set_allowed(true);
    }
    p.b.admit_datagrams(&mut rest);
    assert!(p.b.held_bytes() <= LIMIT);
    let mut n = 0;
    while p.b.recv_datagram().unwrap().is_some() {
        n += 1;
    }
    // The session queue keeps its newest 128.
    assert_eq!(n, 128);
    assert_eq!(p.b.held_bytes(), 0);
}

#[test]
fn application_bytes_count_payload_once_and_never_what_was_discarded() {
    let send_budget = Arc::new(Budget(AtomicUsize::new(1000)));
    let receive_budget = Arc::new(Budget(AtomicUsize::new(600)));
    let mut a_cfg = Config::default();
    a_cfg.enable_datagrams = true;
    a_cfg.datagram_limiter.send = Some(send_budget.clone());
    let mut b_cfg = Config::default();
    b_cfg.enable_datagrams = true;
    b_cfg.datagram_limiter.receive = Some(receive_budget.clone());
    let mut p = Pair::with_events(a_cfg, b_cfg);

    // A preamble, then data the reader stops reading midway.
    let s1 =
        p.a.open_with(Dir::Bidi, &Preamble::new().with_info(&b"open info"[..]))
            .unwrap();
    assert_eq!(p.a.write(s1, &[1; 5000]).unwrap(), 5000);
    p.a.finish(s1).unwrap();
    // Written, then lost to a reset: still written.
    let s2 = p.a.open(Dir::Bidi).unwrap();
    assert_eq!(p.a.write(s2, &[2; 3000]).unwrap(), 3000);
    p.pump();
    p.a.reset(s2, VarInt::from_u32(7)).unwrap();
    // Datagrams: the third exceeds the send budget, the second the receive
    // budget.
    // The core never calls a limiter: the caller asks
    // the send limiter before and charges after, and polices received
    // datagrams the core holds.
    for _ in 0..3 {
        let allowed = send_budget.try_ready(400) >= 400;
        if p.a
            .send_datagram(Bytes::from_static(&[3; 400]), allowed)
            .unwrap()
        {
            send_budget.charge(400);
        }
    }
    p.pump();
    let mut held = Vec::new();
    p.b.take_received_datagrams(&mut held);
    assert_eq!(held.len(), 2, "held for the limiter");
    assert_eq!(p.b.recv_datagram().unwrap(), None, "not queued before it");
    for d in &mut held {
        d.set_allowed(zmux::proto::limit::police(
            &*receive_budget,
            d.payload_len(),
        ));
    }
    p.b.admit_datagrams(&mut held);
    assert!(held.is_empty() && !p.b.has_received_datagrams());

    let r1 = p.b.accept(Dir::Bidi).unwrap().expect("stream");
    let meter = p.b.stream_meter(r1).unwrap();
    let mut buf = [0u8; 2000];
    assert_eq!(p.b.read(r1, &mut buf).unwrap(), Some((2000, false)));
    p.b.stop(r1, VarInt::from_u32(0)).unwrap();
    assert_eq!(p.b.recv_datagram().unwrap().map(|d| d.len()), Some(400));
    assert_eq!(p.b.recv_datagram().unwrap(), None);
    p.pump();

    assert_eq!(meter.bytes_read(), 2000, "the discarded rest is not read");
    assert_eq!(p.b.stream_stats(r1).map(|s| s.bytes_read), Some(2000));
    let a = p.a.meter().get();
    assert_eq!((a.bytes_written, a.datagram_bytes_sent), (8000, 800));
    let b = p.b.meter().get();
    assert_eq!((b.bytes_read, b.datagram_bytes_received), (2000, 400));
    assert_eq!(p.a.stats().datagrams_dropped_limit, 1);
    assert_eq!(p.b.stats().datagrams_dropped_limit, 1);
    let st = p.a.stream_stats(s1).unwrap();
    assert_eq!((st.bytes_written, st.bytes_sent), (5000, 5000));
}

#[test]
fn send_capacity_is_credit_left_minus_unsent_and_session_credit_wakes_it() {
    let mut b_cfg = Config::default();
    b_cfg.initial_connection_receive_window = 20_000;
    b_cfg.max_connection_receive_window = zmux::Cap::Fixed(20_000);
    let mut p = Pair::with_events(Config::default(), b_cfg);
    let s = p.a.open(Dir::Bidi).unwrap();
    // The session's credit is the smaller.
    assert_eq!(p.a.send_capacity(s).unwrap().capacity, 20_000);
    assert_eq!(p.a.write(s, &[0; 15_000]).unwrap(), 15_000);
    let c = p.a.send_capacity(s).unwrap();
    assert_eq!((c.capacity, c.unsent), (5000, 15_000));
    assert_eq!(p.a.write(s, &[0; 15_000]).unwrap(), 15_000);
    assert_eq!(p.a.send_capacity(s).unwrap().capacity, 0);
    p.a.wait_send_capacity(s, 1);
    p.events_a.clear();
    // The peer's MAX_DATA as the data arrives.
    p.pump();
    assert!(
        p.events_a
            .iter()
            .any(|e| matches!(e, CoreEvent::StreamWritable(k) if *k == s)),
        "MAX_DATA wakes a part waiting for capacity"
    );
    assert!(p.a.send_capacity(s).unwrap().capacity > 0);
    p.a.reset(s, VarInt::from_u32(1)).unwrap();
    assert!(p.a.send_capacity(s).is_err(), "a part that ended has none");
}

/// A capacity wait is ready with any capacity once
/// the part holds nothing unsent. Sending changes no credit, and 3 KiB
/// read of a 16 KiB window earns no MAX_STREAM_DATA (the W/4 rule), so
/// the drain of the send buffer itself must wake the wait.
#[test]
fn send_capacity_wait_wakes_when_the_unsent_bytes_drain() {
    let mut b_cfg = Config::default();
    b_cfg.initial_stream_receive_window = 16 * 1024;
    b_cfg.max_stream_receive_window = zmux::Cap::Fixed(16 * 1024);
    let mut p = Pair::with_events(Config::default(), b_cfg);
    let s = p.a.open(Dir::Bidi).unwrap();
    assert_eq!(p.a.write(s, &[7; 3 * 1024]).unwrap(), 3 * 1024);
    let c = p.a.send_capacity(s).unwrap();
    assert_eq!((c.capacity, c.unsent), (13 * 1024, 3 * 1024));
    // Not ready for a full window: 0 < capacity < min with bytes unsent.
    p.a.wait_send_capacity(s, 16 * 1024);
    p.events_a.clear();
    p.pump();
    let c = p.a.send_capacity(s).unwrap();
    assert!(c.capacity > 12 * 1024 && c.capacity < 16 * 1024, "{c:?}");
    assert_eq!(c.unsent, 0);
    assert!(
        p.events_a
            .iter()
            .any(|e| matches!(e, CoreEvent::StreamWritable(k) if *k == s)),
        "the drained send buffer wakes the capacity wait"
    );
}

/// A capacity wait is woken only once it is over,
/// not on every change of credit. Credit that leaves the capacity below
/// `min` while bytes are unsent wakes nothing; a wait for less is woken by
/// the same credit; the drain of the unsent bytes ends the larger wait.
#[test]
fn send_capacity_wait_is_woken_only_once_its_minimum_is_reached() {
    let mut b_cfg = Config::default();
    b_cfg.initial_stream_receive_window = 16 * 1024;
    b_cfg.max_stream_receive_window = zmux::Cap::Fixed(16 * 1024);
    let mut p = Pair::with_events(Config::default(), b_cfg);
    let s = p.a.open(Dir::Bidi).unwrap();
    let small = p.a.open(Dir::Bidi).unwrap();
    for k in [s, small] {
        assert_eq!(p.a.write(k, &[7; 16 * 1024]).unwrap(), 16 * 1024);
    }
    p.pump();
    for k in [s, small] {
        assert_eq!(p.a.write(k, &[7; 2 * 1024]).unwrap(), 2 * 1024);
        assert_eq!(p.a.send_capacity(k).unwrap().capacity, 0);
    }
    p.a.wait_send_capacity(s, 16 * 1024);
    p.a.wait_send_capacity(small, 4 * 1024);
    // The reader takes half of each window: MAX_STREAM_DATA (and MAX_DATA)
    // come back, delivered before `a` sends anything.
    let mut buf = [0u8; 8 * 1024];
    for _ in [s, small] {
        let r = p.b.accept(Dir::Bidi).unwrap().expect("stream");
        assert_eq!(p.b.read(r, &mut buf).unwrap(), Some((8 * 1024, false)));
    }
    let mut wire = Vec::new();
    while p.b.wants_write(P0) {
        p.b.poll_transmit(P0, p.now, &mut p.out);
        if p.out.is_empty() {
            break;
        }
        wire.clear();
        p.out.copy_to_vec(&mut wire);
        p.a.receive(P0, &wire, p.now);
    }
    let c = p.a.send_capacity(s).unwrap();
    assert!(c.capacity == 6 * 1024 && c.unsent >= 2 * 1024, "{c:?}");
    let woken = |events: &mut Vec<CoreEvent>, a: &mut SessionCore, k| {
        events.clear();
        while let Some(e) = a.poll_event() {
            events.push(e);
        }
        events
            .iter()
            .any(|e| matches!(e, CoreEvent::StreamWritable(w) if *w == k))
    };
    let mut events = Vec::new();
    assert!(
        woken(&mut events, &mut p.a, small),
        "credit that reaches min wakes"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, CoreEvent::StreamWritable(w) if *w == s)),
        "credit below min with bytes unsent wakes nothing"
    );
    // Once the unsent bytes are out (after the pacing timer), any capacity
    // ends the wait.
    p.events_a.clear();
    if let Some(t) = p.a.poll_timeout() {
        p.now = p.now.max(t);
        p.a.handle_timeout(p.now);
    }
    p.pump();
    let c = p.a.send_capacity(s).unwrap();
    assert!(c.capacity > 0 && c.unsent == 0, "{c:?}");
    assert!(
        p.events_a
            .iter()
            .any(|e| matches!(e, CoreEvent::StreamWritable(w) if *w == s)),
        "the drain ends the wait"
    );
}

/// SPEC.md Section 4.5: a request whose response is later than its
/// timeout, max(1 s, 3 x SRTT), stops being outstanding, and its late
/// response matches nothing; a ping still waiting asks again, so it is
/// answered.
#[test]
fn a_ping_whose_response_is_late_asks_again() {
    let mut p = Pair::with_events(Config::default(), Config::default());
    let ticket = p.a.ping().unwrap();
    // The request leaves A and stays on the wire for 1.5 s.
    let mut wire = Vec::new();
    while p.a.wants_write(P0) {
        p.a.poll_transmit(P0, p.now, &mut p.out);
        if p.out.is_empty() {
            break;
        }
        p.out.copy_to_vec(&mut wire);
    }
    assert!(!wire.is_empty());
    p.now += Duration::from_millis(1500);
    p.a.handle_timeout(p.now);
    p.b.handle_timeout(p.now);
    p.b.receive(P0, &wire, p.now);
    p.pump();
    assert!(
        p.a.ping_rtt(ticket).is_some(),
        "the ping is answered by a new request"
    );
}

/// EXTENSIONS.md Section 6.6: a single-pipe
/// session reports pipe 0 like any pipe; its RTT comes from QX_PING with a
/// plain QMux peer, which gives no acknowledgements and so no rates or
/// acknowledged positions; `ping` measures a fresh RTT; the largest
/// datagram is the peer's limit.
#[test]
fn single_pipe_sessions_report_pipe_zero() {
    use zmux::proto::params::TransportParameters;
    use zmux::proto::session::{PipeState, RttSource};
    let p = Pair::with_events(Config::default(), Config::default());
    let pipes = p.a.pipes();
    assert_eq!(pipes.len(), 1);
    let i = &pipes[0];
    assert_eq!(i.pipe, P0);
    assert_eq!(i.outbound, Some(PipeState::Active));
    assert!(i.eligible && !i.saturated);
    assert_eq!((i.send_priority, i.standby, i.weight), (0, false, 1));
    assert_eq!((i.bytes_reinjected, i.bytes_opportunistic), (0, 0));
    assert!(i.rtt_source.is_some() && i.smoothed_rtt.is_some());
    assert!(i.bytes_acked.is_some());

    // A plain QMux peer: no zmux parameter, the default record size.
    let mut a = Config::default();
    a.enable_datagrams = true;
    let mut qmux = Config::default();
    qmux.test_hooks().transport_parameters = Some(TransportParameters {
        initial_max_data: Some(1 << 20),
        initial_max_stream_data_bidi_local: Some(1 << 18),
        initial_max_stream_data_bidi_remote: Some(1 << 18),
        initial_max_stream_data_uni: Some(1 << 18),
        initial_max_streams_bidi: Some(16),
        initial_max_streams_uni: Some(16),
        max_datagram_frame_size: Some(65535),
        ..TransportParameters::default()
    });
    let mut p = Pair::with_events(a, qmux);
    assert_eq!(p.a.max_datagram_size(), Some(16381));
    let i = p.a.pipes().remove(0);
    assert_eq!(
        i.rtt_source,
        Some(RttSource::Ping),
        "the first record's QX_PING"
    );
    assert_eq!(
        (i.delivery_rate, i.bytes_acked, i.bytes_in_flight),
        (None, None, None)
    );
    let ticket = p.a.ping().unwrap();
    assert_eq!(p.a.ping_rtt(ticket), None);
    // A second call joins the outstanding request.
    assert_eq!(p.a.ping().unwrap(), ticket);
    // The request goes out now, its response arrives 20 ms later.
    let mut wire = Vec::new();
    p.a.poll_transmit(P0, p.now, &mut p.out);
    p.out.copy_to_vec(&mut wire);
    p.b.receive(P0, &wire, p.now);
    wire.clear();
    p.b.poll_transmit(P0, p.now, &mut p.out);
    p.out.copy_to_vec(&mut wire);
    p.now += Duration::from_millis(20);
    p.a.receive(P0, &wire, p.now);
    assert_eq!(p.a.ping_rtt(ticket), Some(Duration::from_millis(20)));
    assert_eq!(p.a.stats().latest_rtt, Some(Duration::from_millis(20)));
}
