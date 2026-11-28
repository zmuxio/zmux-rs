//! Datagrams on a carrier's datagram channel,
//! in the sans-IO core: the per-frame choice between the channel and a
//! record, what a receiver does with channel datagrams, and the datagrams
//! held for streams that have not opened yet, in records and on channels.

use std::time::Duration;

use bytes::Bytes;
use zmux::proto::TransportErrorCode;
use zmux::proto::frame::{Dir, channel};
use zmux::proto::session::shaping::{
    Caps, DatagramPlan, DatagramView, Effects, Event, EventKind, Shaper,
};
use zmux::proto::session::{Config, NativeDatagramResult, PipeId, SessionCore, State};

#[path = "common/core_pair.rs"]
mod core_pair;

use core_pair::{CorePair as Pair, P0};

/// The Pipe Stream IDs of the two ends' channels (a QUIC stream's ID).
const ID: u64 = 4;
const MAX: usize = 1200;

fn dgram_config() -> Config {
    let mut c = Config::default();
    c.enable_datagrams = true;
    c
}

/// A pair whose ends' carriers have channels as given (`None`: no
/// channel), established.
fn pair(a: Option<usize>, b: Option<usize>) -> Pair {
    let mut p = Pair::attached(dgram_config(), dgram_config());
    if let Some(max) = a {
        p.a.set_pipe_channel(P0, Some(ID), max, max);
    }
    if let Some(max) = b {
        p.b.set_pipe_channel(P0, Some(ID), max, max);
    }
    p.pump();
    assert!(p.a.is_established() && p.b.is_established());
    p
}

/// Takes `from`'s channel datagrams and hands each to `to` as its carrier
/// would, the Pipe Stream ID removed; returns how many moved.
fn move_channel(from: &mut SessionCore, to: &mut SessionCore, now: std::time::Instant) -> usize {
    let mut out = Vec::new();
    assert!(from.poll_channel(P0, &mut out, now), "channel live");
    let count = out.len();
    for d in out {
        let (id, frame) = channel::split(&d.bytes).expect("Pipe Stream ID");
        assert_eq!(id, ID);
        to.receive_channel_datagram(P0, frame, now);
        from.channel_done(P0, d.outcome, NativeDatagramResult::Accepted, now);
    }
    count
}

#[test]
fn negotiated_datagrams_go_on_the_channel() {
    let mut p = pair(Some(MAX), Some(MAX));
    assert!(p.a.features().carrier_datagrams && p.b.features().carrier_datagrams);
    assert!(p.a.local_parameters().zmux_carrier_datagrams);
    let records = p.a.stats().records_sent;
    p.a.send_datagram(Bytes::from_static(b"hello"), true, p.now)
        .unwrap();
    // Not in a record: the pipe has nothing to write for it.
    assert!(!p.a.wants_write(P0));
    let now = p.now;
    let before = p.b.stats().records_received;
    assert_eq!(move_channel(&mut p.a, &mut p.b, now), 1);
    assert_eq!(
        p.b.recv_datagram(p.now).unwrap().as_deref(),
        Some(&b"hello"[..])
    );
    p.pump();
    assert_eq!(p.a.stats().records_sent, records, "no record");
    assert_eq!(p.b.stats().records_received, before);
    let (sa, sb) = (p.a.stats(), p.b.stats());
    assert_eq!((sa.datagrams_sent, sa.datagrams_sent_channel), (1, 1));
    assert_eq!(
        (sb.datagrams_received, sb.datagrams_received_channel),
        (1, 1)
    );
}

#[test]
fn records_without_a_negotiated_channel() {
    // The peer's carrier has no channel: it does not send the parameter.
    let mut p = pair(Some(MAX), None);
    assert!(!p.b.local_parameters().zmux_carrier_datagrams);
    assert!(!p.a.features().carrier_datagrams);
    p.a.send_datagram(Bytes::from_static(b"x"), true, p.now)
        .unwrap();
    let mut out = Vec::new();
    assert!(
        !p.a.poll_channel(P0, &mut out, p.now),
        "the channel's task ends"
    );
    assert!(out.is_empty());
    p.pump();
    assert_eq!(
        p.b.recv_datagram(p.now).unwrap().as_deref(),
        Some(&b"x"[..])
    );
    assert_eq!(p.a.stats().datagrams_sent_channel, 0);
    // No channel at all on this end.
    let mut p = pair(None, Some(MAX));
    assert!(!p.b.features().carrier_datagrams);
    p.b.send_datagram(Bytes::from_static(b"y"), true, p.now)
        .unwrap();
    p.pump();
    assert_eq!(
        p.a.recv_datagram(p.now).unwrap().as_deref(),
        Some(&b"y"[..])
    );
    // Without datagrams the parameter is never sent.
    let mut p = Pair::attached(Config::default(), Config::default());
    p.a.set_pipe_channel(P0, Some(ID), MAX, MAX);
    assert!(!p.a.local_parameters().zmux_carrier_datagrams);
}

#[test]
fn the_choice_is_per_frame() {
    let mut p = pair(Some(100), Some(100));
    // One byte each for Pipe Stream ID, type, Sequence and Flow.
    p.a.send_datagram(Bytes::from(vec![1u8; 96]), true, p.now)
        .unwrap();
    p.a.send_datagram(Bytes::from(vec![2u8; 97]), true, p.now)
        .unwrap();
    let now = p.now;
    assert_eq!(move_channel(&mut p.a, &mut p.b, now), 1);
    assert!(p.a.wants_write(P0), "the larger one goes in a record");
    p.pump();
    let mut got = Vec::new();
    while let Some(d) = p.b.recv_datagram(p.now).unwrap() {
        got.push(d.len());
    }
    got.sort_unstable();
    assert_eq!(got, [96, 97]);
    assert_eq!(p.a.stats().datagrams_sent_channel, 1);
    assert_eq!(p.a.stats().datagrams_sent, 2);
    // A channel that takes nothing now (0): records.
    p.a.set_pipe_channel(P0, Some(ID), 0, 0);
    p.a.send_datagram(Bytes::from_static(b"z"), true, p.now)
        .unwrap();
    assert!(p.a.wants_write(P0));
    p.pump();
    assert_eq!(
        p.b.recv_datagram(p.now).unwrap().as_deref(),
        Some(&b"z"[..])
    );
}

struct NativeShaper(std::sync::Arc<std::sync::Mutex<Vec<Event>>>);

impl Shaper for NativeShaper {
    fn capabilities(&self) -> Caps {
        Caps::DATAGRAM_PLAN | Caps::OUTBOUND
    }

    fn plan_datagram(&mut self, _: &DatagramView, plan: &mut DatagramPlan) {
        plan.unit.pad_to = 10;
        plan.unit.delay = Duration::from_micros(20);
    }

    fn on_event(&mut self, event: &Event, _: &mut Effects) {
        self.0.lock().unwrap().push(*event);
    }
}

#[test]
fn native_shaping_waits_trims_and_reports_at_completion() {
    let mut p = pair(Some(MAX), Some(MAX));
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    assert!(p.a.set_pipe_shaper(P0, Some(Box::new(NativeShaper(events.clone())))));
    p.a.send_datagram(Bytes::from_static(b"a\0"), true, p.now)
        .unwrap();
    let initial_limit = p.a.datagram_path().native_payload;
    let mut out = Vec::new();
    assert!(p.a.poll_channel(P0, &mut out, p.now));
    assert!(out.is_empty());
    let release = p.now + Duration::from_micros(20);
    p.a.set_pipe_channel(P0, Some(ID), MAX, 8);
    assert_eq!(p.a.datagram_path().native_payload, initial_limit);
    assert!(p.a.poll_channel(
        P0,
        &mut out,
        release.checked_sub(Duration::from_micros(1)).unwrap()
    ));
    assert!(out.is_empty());
    p.a.handle_timeout(release);
    assert!(p.a.poll_channel(P0, &mut out, release));
    let d = out.pop().unwrap();
    assert_eq!(d.bytes[..], [4, 0, 0, 0x30, 0, 0, b'a', 0]);
    assert_eq!(p.a.stats().datagrams_sent_channel, 0);
    assert!(
        !events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.kind == EventKind::Outbound)
    );
    let (_, frame) = channel::split(&d.bytes).unwrap();
    p.b.receive_channel_datagram(P0, frame, release);
    assert_eq!(
        p.b.recv_datagram(release).unwrap().as_deref(),
        Some(&b"a\0"[..])
    );
    p.a.channel_done(P0, d.outcome, NativeDatagramResult::Accepted, release);
    assert_eq!(p.a.stats().datagrams_sent_channel, 1);
    let events = events.lock().unwrap();
    let [outbound]: [&Event; 1] = events
        .iter()
        .filter(|e| e.kind == EventKind::Outbound)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    assert_eq!(outbound.len, 8);
    assert!(outbound.data);
}

#[test]
fn temporary_channel_room_waits_without_record_fallback() {
    let mut p = pair(Some(MAX), Some(MAX));
    p.a.set_pipe_channel(P0, Some(ID), MAX, 0);
    p.a.send_datagram(Bytes::from_static(b"native"), true, p.now)
        .unwrap();
    assert!(!p.a.wants_write(P0));
    let now = p.now;
    assert_eq!(move_channel(&mut p.a, &mut p.b, now), 0);
    p.a.set_pipe_channel(P0, Some(ID), MAX, MAX);
    assert_eq!(move_channel(&mut p.a, &mut p.b, now), 1);
}

#[test]
fn failed_channel_sends_count_as_dropped() {
    use zmux::DatagramChannelKind;

    let mut p = pair(Some(MAX), Some(MAX));
    for _ in 0..3 {
        p.a.send_datagram(Bytes::from_static(b"d"), true, p.now)
            .unwrap();
    }
    let mut out = Vec::new();
    assert!(p.a.poll_channel(P0, &mut out, p.now));
    assert_eq!(out.len(), 3);
    // Give the matched ACK a positive RTT; dispatch and delivery are synchronous in this fixture.
    p.now += Duration::from_millis(1);
    for d in &out {
        let (_, frame) = channel::split(&d.bytes).unwrap();
        p.b.receive_channel_datagram(P0, frame, p.now);
    }
    // The return path can deliver its report before the local send completes.
    p.send(false);
    assert_eq!(p.a.datagram_feedback(P0, DatagramChannelKind::Native), None);
    for (i, d) in out.into_iter().enumerate() {
        let result = if i == 2 {
            NativeDatagramResult::Accepted
        } else {
            NativeDatagramResult::Rejected
        };
        p.a.channel_done(P0, d.outcome, result, p.now);
    }
    let s = p.a.stats();
    assert_eq!((s.datagrams_sent, s.datagrams_sent_channel), (1, 1));
    assert_eq!(s.datagrams_dropped_send, 2);
    let detailed = p.a.datagram_stats();
    assert_eq!(detailed.drops.carrier_rejected, 2);
    assert_eq!(
        detailed.replica_degradation,
        zmux::DatagramReplicaDegradation::default()
    );
    assert_eq!(detailed.native.originals, 3);
    assert_eq!(detailed.native.originals_accepted, 1);
    assert_eq!(detailed.native.originals_failed, 2);
    assert_eq!(detailed.native.original_bytes_accepted, 1);
    let arrivals =
        p.b.datagram_arrivals(P0, DatagramChannelKind::Native)
            .unwrap();
    assert_eq!(
        (arrivals.frames, arrivals.bytes, arrivals.last_at),
        (3, 3, p.now)
    );
    let evidence =
        p.a.datagram_feedback(P0, DatagramChannelKind::Native)
            .unwrap();
    assert_eq!(
        (evidence.tracking, evidence.arrived, evidence.samples),
        (1, 1, 1)
    );
}

#[test]
fn received_channel_datagrams_that_name_no_pipe_or_session_are_dropped() {
    let mut p = pair(Some(MAX), Some(MAX));
    let now = p.now;
    let frame = channel::encode(None, &[0, b'x']);
    p.b.receive_channel_datagram(PipeId::new(7), &frame, now);
    assert_eq!(p.b.stats().datagrams_dropped_recv, 1);
    assert_eq!(p.b.stats().datagrams_received_channel, 0);
    // A session that did not negotiate the channel drops what arrives.
    let mut q = pair(None, Some(MAX));
    q.b.receive_channel_datagram(P0, &frame, now);
    assert_eq!(q.b.stats().datagrams_dropped_recv, 1);
    assert_eq!(q.b.recv_datagram(q.now).unwrap(), None);
    assert_eq!(q.b.state(), State::Active);
}

#[test]
fn malformed_channel_datagrams_are_a_protocol_violation() {
    for bad in [
        &[0x31, 0x02, 0, b'x'][..],
        &[0x00, 0x30, 0][..],
        &[][..],
        &[0x30][..],
    ] {
        let mut p = pair(Some(MAX), Some(MAX));
        let now = p.now;
        p.b.receive_channel_datagram(P0, bad, now);
        assert_eq!(p.b.state(), State::Closing, "{bad:x?}");
        match p.b.error() {
            Some(zmux::SessionError::TransportClosed { code, remote, .. }) => {
                assert!(!remote);
                // An empty Flow is the flow prefix's violation; the others
                // the channel's.
                assert_eq!(*code, TransportErrorCode::PROTOCOL_VIOLATION, "{bad:x?}");
            }
            e => panic!("{bad:x?}: {e:?}"),
        }
    }
}

#[test]
fn channel_datagrams_are_not_records() {
    let mut cfg = dgram_config();
    cfg.max_idle_timeout = Some(Duration::from_secs(5));
    let mut p = Pair::attached(cfg.clone(), cfg);
    p.a.set_pipe_channel(P0, Some(ID), MAX, MAX);
    p.b.set_pipe_channel(P0, Some(ID), MAX, MAX);
    p.pump();
    let start = p.now;
    // Channel datagrams alone for longer than the idle timeout: the
    // receiver's idle timer is not restarted by them.
    for i in 1..=6 {
        p.now = start + Duration::from_secs(i);
        let now = p.now;
        p.a.handle_timeout(now);
        p.b.handle_timeout(now);
        if p.a
            .send_datagram(Bytes::from_static(b"tick"), true, p.now)
            .is_err()
        {
            // The sender timed out first: neither do its own channel
            // datagrams count as activity.
            break;
        }
        move_channel(&mut p.a, &mut p.b, now);
        assert_eq!(
            p.b.recv_datagram(p.now).unwrap().as_deref(),
            Some(&b"tick"[..])
        );
    }
    p.b.handle_timeout(start + Duration::from_secs(6));
    assert!(matches!(
        p.b.error(),
        Some(zmux::SessionError::IdleTimeout { remote: false })
    ));
}

#[test]
fn a_stream_datagram_that_overtakes_the_opening_frame_is_held_until_it_opens() {
    let mut p = pair(Some(MAX), Some(MAX));
    for i in 0..5u8 {
        let k = p.a.open(Dir::Bidi).unwrap();
        p.a.write(k, &[i]).unwrap();
        p.a.send_stream_datagram(k, 0, Bytes::from(vec![i]), true, p.now)
            .unwrap();
        p.a.send_stream_datagram(k, 2, Bytes::from(vec![i, i]), true, p.now)
            .unwrap();
        // The channel first: the opening frame is still to be written.
        let now = p.now;
        assert_eq!(move_channel(&mut p.a, &mut p.b, now), 2);
        assert_eq!(p.b.accept(Dir::Bidi).unwrap(), None);
        p.pump();
        let s = p.b.accept(Dir::Bidi).unwrap().expect("opened");
        assert_eq!(
            p.b.recv_stream_datagram(s, p.now).unwrap(),
            Some((0, Bytes::from(vec![i])))
        );
        assert_eq!(
            p.b.recv_stream_datagram(s, p.now).unwrap(),
            Some((2, Bytes::from(vec![i, i]))),
            "in arrival order"
        );
    }
    let st = p.b.stats();
    assert_eq!(st.datagrams_dropped_recv, 0);
    assert_eq!(st.datagrams_received_channel, 10);
    assert!(st.datagrams_received_channel <= st.datagrams_received);
}

#[test]
fn held_datagrams_expire_after_one_smoothed_rtt() {
    let mut p = pair(Some(MAX), Some(MAX));
    let k = p.a.open(Dir::Bidi).unwrap();
    p.a.write(k, b"o").unwrap();
    p.a.send_stream_datagram(k, 0, Bytes::from_static(b"late"), true, p.now)
        .unwrap();
    let now = p.now;
    move_channel(&mut p.a, &mut p.b, now);
    let due = now + Duration::from_millis(333);
    p.now = due;
    p.b.handle_timeout(due);
    assert_eq!(p.b.stats().datagrams_dropped_recv, 1);
    // Dropped only: a held datagram counts as received once delivered.
    let st = p.b.stats();
    assert_eq!(
        (st.datagrams_received, st.datagrams_received_channel),
        (0, 0)
    );
    p.pump();
    let s = p.b.accept(Dir::Bidi).unwrap().expect("opened");
    assert_eq!(p.b.recv_stream_datagram(s, p.now).unwrap(), None);
}

#[test]
fn held_datagrams_count_in_the_session_bytes_and_go_first() {
    let mut cfg = dgram_config();
    cfg.max_incoming_streams = 1000;
    let mut p = Pair::attached(dgram_config(), cfg);
    p.a.set_pipe_channel(P0, Some(ID), 70_000, 70_000);
    p.b.set_pipe_channel(P0, Some(ID), 70_000, 70_000);
    p.pump();
    let now = p.now;
    // 40 streams not opened at B, 60000 bytes each: more than the 1 MiB
    // of the session's datagram bytes.
    let mut keys = Vec::new();
    for _ in 0..40 {
        let k = p.a.open(Dir::Bidi).unwrap();
        p.a.write(k, b"o").unwrap();
        p.a.send_stream_datagram(k, 0, Bytes::from(vec![7u8; 60_000]), true, p.now)
            .unwrap();
        move_channel(&mut p.a, &mut p.b, now);
        keys.push(k);
    }
    let dropped = p.b.stats().datagrams_dropped_recv;
    assert_eq!(dropped, 40 - (1024 * 1024 / 60_064), "the oldest made room");
    p.pump();
    let mut delivered = 0;
    while let Some(s) = p.b.accept(Dir::Bidi).unwrap() {
        if p.b.recv_stream_datagram(s, p.now).unwrap().is_some() {
            delivered += 1;
        }
    }
    assert_eq!(delivered, 40 - dropped);
}

#[test]
fn held_datagrams_for_streams_in_records_too() {
    // A datagram in a record for a peer stream within the limit that is not
    // opened yet (possible in multipath sessions) is held as well.
    let mut p = Pair::new(dgram_config(), dgram_config());
    let k = p.a.open(Dir::Bidi).unwrap();
    p.a.write(k, b"o").unwrap();
    p.a.send_stream_datagram(k, 0, Bytes::from_static(b"d"), true, p.now)
        .unwrap();
    p.pump();
    let s = p.b.accept(Dir::Bidi).unwrap().expect("opened");
    assert_eq!(
        p.b.recv_stream_datagram(s, p.now).unwrap(),
        Some((0, Bytes::from_static(b"d")))
    );
    assert_eq!(p.b.stats().datagrams_dropped_recv, 0);
}

#[test]
fn tiny_held_datagrams_are_bounded_by_their_entry_cost() {
    let mut p = Pair::attached(dgram_config(), dgram_config());
    p.a.set_pipe_channel(P0, Some(ID), MAX, MAX);
    p.b.set_pipe_channel(P0, Some(ID), MAX, MAX);
    p.pump();
    let now = p.now;
    // Empty datagrams for a stream whose opening frame is withheld: each costs its
    // entry, so the 1 MiB holds 16384 of them at most.
    let k = p.a.open(Dir::Bidi).unwrap();
    p.a.write(k, b"o").unwrap();
    for _ in 0..20_000 {
        p.a.send_stream_datagram(k, 0, Bytes::new(), true, p.now)
            .unwrap();
        move_channel(&mut p.a, &mut p.b, now);
    }
    assert_eq!(p.b.stats().datagrams_dropped_recv, 20_000 - 16_384);
}

#[test]
fn held_datagrams_expire_in_arrival_order() {
    let mut p = pair(Some(MAX), Some(MAX));
    let now = p.now;
    for i in 0..3u8 {
        let k = p.a.open(Dir::Bidi).unwrap();
        p.a.write(k, b"o").unwrap();
        p.a.send_stream_datagram(k, 0, Bytes::from(vec![i]), true, p.now)
            .unwrap();
        move_channel(&mut p.a, &mut p.b, now);
    }
    // One deadline, the oldest's; at it every one due expires.
    p.b.handle_timeout(now + Duration::from_millis(333));
    assert_eq!(p.b.stats().datagrams_dropped_recv, 3);
}

/// `path_datagram_size` is what fits one channel datagram: a datagram of
/// it goes on the channel, one byte more in a record; a smaller channel
/// lowers it and `DatagramPathChanged` reports it.
#[test]
fn the_path_datagram_size_fits_one_channel_datagram() {
    use zmux::proto::session::CoreEvent;
    let mut p = pair(Some(MAX), Some(MAX));
    let max = p.a.max_datagram_size().expect("datagrams");
    let path =
        p.a.datagram_path()
            .native_payload
            .expect("native datagrams");
    assert_eq!(p.a.path_datagram_size(), Some(max));
    // One byte each for Pipe Stream ID, type, Sequence and Flow.
    assert_eq!(path, MAX - 4);
    assert!(path < max);
    p.a.send_datagram(Bytes::from(vec![1u8; path]), true, p.now)
        .unwrap();
    let now = p.now;
    assert_eq!(move_channel(&mut p.a, &mut p.b, now), 1, "on the channel");
    p.a.send_datagram(Bytes::from(vec![2u8; path + 1]), true, p.now)
        .unwrap();
    assert_eq!(move_channel(&mut p.a, &mut p.b, now), 0, "in a record");
    p.pump();
    assert_eq!(p.a.stats().datagrams_sent_channel, 1);
    p.a.set_pipe_channel(P0, Some(ID), MAX - 400, MAX - 400);
    let events: Vec<_> = std::iter::from_fn(|| p.a.poll_event()).collect();
    assert!(
        events.contains(&CoreEvent::DatagramPathChanged {
            path: zmux::DatagramPath {
                payload: Some(max),
                native_payload: Some(path - 400),
                native_room: Some(path - 400),
            }
        }),
        "{events:?}"
    );
    assert_eq!(p.a.datagram_path().native_payload, Some(path - 400));
    // A session without a channel: the records' bound.
    let q = pair(None, None);
    assert_eq!(q.a.path_datagram_size(), q.a.max_datagram_size());
}

#[test]
fn carrier_routing_prefix_is_outside_native_shaping_length() {
    let mut p = pair(Some(MAX), Some(MAX));
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    assert!(p.a.set_pipe_shaper(P0, Some(Box::new(NativeShaper(events.clone())))));
    p.a.set_pipe_channel(P0, channel::Prefix::Carrier(64), MAX, MAX);
    p.a.send_datagram(Bytes::from_static(b"a\0"), true, p.now)
        .unwrap();
    let mut out = Vec::new();
    assert!(p.a.poll_channel(P0, &mut out, p.now));
    assert!(out.is_empty());

    let release = p.now + Duration::from_micros(20);
    p.a.handle_timeout(release);
    assert!(p.a.poll_channel(P0, &mut out, release));
    let d = out.pop().unwrap();
    let (quarter_stream, frame) = channel::split(&d.bytes).unwrap();
    assert_eq!(quarter_stream, 64);
    assert_eq!(frame.len(), 10);
    assert_eq!(frame, [0, 0, 0, 0, 0, 0x30, 0, 0, b'a', 0]);
    p.a.channel_done(P0, d.outcome, NativeDatagramResult::Accepted, release);
    let events = events.lock().unwrap();
    let outbound = events
        .iter()
        .find(|e| e.kind == EventKind::Outbound)
        .unwrap();
    assert_eq!(outbound.len, frame.len());
}

#[test]
fn a_native_hold_spends_the_next_units_delay_on_the_same_flow() {
    let mut p = pair(Some(MAX), Some(MAX));
    let delay = Duration::from_micros(20);
    let mut limits = p.a.shaping_limits();
    limits.profile = Some(zmux::shaping::ProfileLimits::new(10, 0, 540, delay));
    p.a.set_shaping_limits(limits).unwrap();
    let events = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    assert!(p.a.set_pipe_shaper(P0, Some(Box::new(NativeShaper(events)))));
    for data in [Bytes::from_static(b"a"), Bytes::from_static(b"b")] {
        p.a.send_datagram(data, true, p.now).unwrap();
    }
    let mut out = Vec::new();
    p.a.poll_channel(P0, &mut out, p.now);
    assert!(out.is_empty());
    let release = p.now + delay;
    p.a.poll_channel(P0, &mut out, release);
    assert_eq!(out.len(), 1);
    p.a.poll_channel(P0, &mut out, release);
    assert_eq!(
        out.len(),
        2,
        "the successor spent its delay on the held head"
    );
    for unit in out {
        p.a.channel_done(P0, unit.outcome, NativeDatagramResult::Accepted, release);
    }
    let stats = p.a.shaping_stats();
    assert_eq!(stats.max_added_delay, delay);
    assert_eq!(stats.stall_spent, 2 * delay);
    assert!(stats.ledger.measured_bytes > 0);
    assert_eq!(stats.wire_spent, 0);
}

struct FlowDelay;

impl Shaper for FlowDelay {
    fn capabilities(&self) -> Caps {
        Caps::PLAN | Caps::DATAGRAM_PLAN
    }

    fn plan(&mut self, _: &zmux::shaping::RecordView, plan: &mut zmux::shaping::RecordPlan) {
        plan.delay = Duration::from_millis(2);
    }

    fn plan_datagram(&mut self, _: &DatagramView, plan: &mut DatagramPlan) {
        plan.unit.delay = Duration::from_millis(2);
    }
}

#[test]
fn g4_reliable_successors_share_the_flow_delay_budget() {
    let mut p = pair(None, None);
    p.a.set_pipe_shaper(P0, Some(Box::new(FlowDelay)));
    // These two frames fit only in separate records.
    let data = Bytes::from(vec![42; 40_000]);
    p.a.send_datagram(data.clone(), true, p.now).unwrap();
    assert_eq!(p.send(true), 0);
    p.now += Duration::from_micros(100);
    p.a.send_datagram(data.clone(), true, p.now).unwrap();
    p.now += Duration::from_micros(100);
    p.a.send_datagram(data, true, p.now).unwrap();
    p.now += Duration::from_micros(1800);
    p.a.handle_timeout(p.now);
    assert!(p.send(true) > 0);
    assert_eq!(p.b.stats().datagrams_received, 1);
    p.now += Duration::from_micros(99);
    p.a.handle_timeout(p.now);
    assert_eq!(p.send(true), 0);
    p.now += Duration::from_micros(1);
    p.a.handle_timeout(p.now);
    assert!(p.send(true) > 0);
    assert_eq!(p.b.stats().datagrams_received, 2);
    p.now += Duration::from_micros(100);
    p.a.handle_timeout(p.now);
    assert!(p.send(true) > 0);
    assert_eq!(p.b.stats().datagrams_received, 3);
    let stats = p.a.shaping_stats();
    assert_eq!(stats.max_added_delay, Duration::from_millis(2));
    assert_eq!(stats.stall_spent, Duration::from_millis(6));
}

#[test]
fn g4_native_fallback_keeps_its_flow_delay_budget() {
    let mut p = pair(Some(MAX), Some(MAX));
    p.a.set_pipe_shaper(P0, Some(Box::new(FlowDelay)));
    p.a.send_datagram(Bytes::from_static(b"fallback"), true, p.now)
        .unwrap();
    let mut native = Vec::new();
    p.a.poll_channel(P0, &mut native, p.now);
    assert!(native.is_empty());
    p.now += Duration::from_micros(1500);
    p.a.handle_timeout(p.now);
    p.a.set_pipe_channel(P0, Some(ID), 0, 0);
    assert_eq!(p.send(true), 0);
    p.now += Duration::from_micros(499);
    p.a.handle_timeout(p.now);
    assert_eq!(p.send(true), 0);
    p.now += Duration::from_micros(1);
    p.a.handle_timeout(p.now);
    assert!(p.send(true) > 0);
    assert_eq!(
        p.b.recv_datagram(p.now).unwrap().as_deref(),
        Some(&b"fallback"[..])
    );
    let stats = p.a.shaping_stats();
    assert_eq!(stats.stall_spent, Duration::from_millis(2));
    assert_eq!(stats.max_added_delay, Duration::from_millis(2));
}

#[test]
fn g4_native_receipts_share_the_queue_limit_across_shaper_replacement() {
    use zmux::proto::session::{DatagramDrop, DatagramError};

    let mut p = pair(Some(MAX), Some(MAX));
    let limit = p.a.config().datagram_send_queue;
    let mut out = Vec::new();
    for _ in 0..limit {
        p.a.send_datagram(Bytes::from_static(b"x"), true, p.now)
            .unwrap();
        p.a.poll_channel(P0, &mut out, p.now);
    }
    assert_eq!(out.len(), limit);
    assert!(p.a.datagram_queue_full());
    p.a.set_pipe_shaper(P0, Some(Box::new(FlowDelay)));
    assert!(matches!(
        p.a.send_datagram(Bytes::from_static(b"extra"), true, p.now),
        Err(DatagramError::Dropped(DatagramDrop::QueueOverflow))
    ));
    p.a.poll_channel(P0, &mut out, p.now);
    assert_eq!(out.len(), limit);
    let completed = out.pop().unwrap();
    p.a.channel_done(P0, completed.outcome, NativeDatagramResult::Accepted, p.now);
    assert!(!p.a.datagram_queue_full());
    p.a.send_datagram(Bytes::from_static(b"new"), true, p.now)
        .unwrap();
    assert!(p.a.datagram_queue_full());
}

#[test]
fn g4_native_batch_stops_after_the_last_valid_sequence() {
    use zmux::proto::frame::{Frame, Gates};
    use zmux::proto::session::DatagramError;
    use zmux::proto::varint;

    let mut p = pair(Some(MAX), Some(MAX));
    p.a.send_datagram(Bytes::from_static(b"last"), true, p.now)
        .unwrap();
    p.a.send_datagram(Bytes::from_static(b"overflow"), true, p.now)
        .unwrap();
    p.a.seed_datagram_sequence(varint::MAX);
    let mut out = Vec::new();
    p.a.poll_channel(P0, &mut out, p.now);
    assert_eq!(out.len(), 1);
    let unit = out.pop().unwrap();
    let (_, body) = channel::split(&unit.bytes).unwrap();
    let (Frame::Datagram(frame), _) = Frame::decode(body, &Gates::ALL).unwrap() else {
        panic!("expected a DATAGRAM");
    };
    assert_eq!(frame.sequenced().unwrap().0, varint::MAX);
    p.a.channel_done(P0, unit.outcome, NativeDatagramResult::Accepted, p.now);
    assert_eq!(p.a.datagram_stats().drops.sequence_exhausted, 1);
    assert!(matches!(
        p.a.send_datagram(Bytes::from_static(b"x"), true, p.now),
        Err(DatagramError::SequenceExhausted)
    ));
}

#[test]
fn g4_native_rekey_expires_the_old_native_loss_source() {
    use zmux::proto::frame::DatagramChannelKind::{Native, Record};
    use zmux::proto::session::{DatagramLossSample, DatagramLossSourceExpired};

    let mut p = pair(Some(MAX), Some(MAX));
    let sample = |now| DatagramLossSample {
        observed_at: now,
        source_generation: 1,
        finalized: 100,
        lost: 5,
    };
    for channel in [Native, Record] {
        assert_eq!(
            p.a.report_datagram_loss(P0, channel, sample(p.now), p.now),
            Ok(true)
        );
    }
    p.a.set_pipe_channel(P0, Some(64), MAX, MAX);
    p.now += Duration::from_micros(100);
    assert_eq!(
        p.a.report_datagram_loss(P0, Native, sample(p.now), p.now),
        Err(DatagramLossSourceExpired {
            source_generation: 1
        })
    );
    assert_eq!(
        p.a.report_datagram_loss(P0, Record, sample(p.now), p.now),
        Ok(true)
    );
}

#[test]
fn g4_native_original_keeps_session_and_flow_queue_charges() {
    use zmux::proto::session::{DatagramDrop, DatagramError};

    for (slots, flow_bytes, session_bytes, other_flow) in
        [(1, 64, 64, false), (64, 4, 64, false), (64, 64, 4, true)]
    {
        let mut config = dgram_config();
        let datagram = config.datagram_config_mut();
        datagram.send_flow_queue = slots;
        datagram.send_flow_bytes = flow_bytes;
        datagram.send_bytes = session_bytes;
        let mut p = Pair::attached(config, dgram_config());
        p.a.set_pipe_channel(P0, Some(ID), MAX, MAX);
        p.b.set_pipe_channel(P0, Some(ID), MAX, MAX);
        p.pump();

        let stream = p.a.open(Dir::Bidi).unwrap();
        p.a.write(stream, b"open").unwrap();
        p.pump();
        p.a.send_stream_datagram(stream, 0, Bytes::from_static(b"four"), true, p.now)
            .unwrap();

        let mut out = Vec::new();
        assert!(p.a.poll_channel(P0, &mut out, p.now));
        assert_eq!(out.len(), 1);
        assert!(
            !p.a.datagram_queue_full(),
            "the global item limit still has room"
        );
        let send = |p: &mut Pair| {
            if other_flow {
                p.a.send_datagram(Bytes::from_static(b"x"), true, p.now)
            } else {
                p.a.send_stream_datagram(stream, 1, Bytes::from_static(b"x"), true, p.now)
            }
        };
        assert!(matches!(
            send(&mut p),
            Err(DatagramError::Dropped(DatagramDrop::QueueOverflow))
        ));
        let receipt = out.pop().unwrap().outcome;
        p.a.channel_done(P0, receipt, NativeDatagramResult::Rejected, p.now);
        send(&mut p).unwrap();
    }
}

#[test]
fn g4_native_delay_suspends_when_the_channel_has_no_room() {
    let mut p = pair(Some(MAX), Some(MAX));
    p.a.set_pipe_shaper(P0, Some(Box::new(FlowDelay)));
    p.a.send_datagram(Bytes::from_static(b"wait for room"), true, p.now)
        .unwrap();
    let mut out = Vec::new();
    p.a.poll_channel(P0, &mut out, p.now);
    assert!(out.is_empty());

    p.now += Duration::from_micros(500);
    p.a.handle_timeout(p.now);
    p.a.set_pipe_channel(P0, Some(ID), MAX, 0);
    p.now += Duration::from_millis(10);
    p.a.handle_timeout(p.now);
    p.a.poll_channel(P0, &mut out, p.now);
    assert!(out.is_empty());
    assert_eq!(p.a.shaping_stats().stall_spent, Duration::from_micros(500));

    p.a.set_pipe_channel(P0, Some(ID), MAX, MAX);
    p.a.poll_channel(P0, &mut out, p.now);
    assert!(out.is_empty());
    p.now += Duration::from_micros(1499);
    p.a.poll_channel(P0, &mut out, p.now);
    assert!(out.is_empty());
    p.now += Duration::from_micros(1);
    p.a.poll_channel(P0, &mut out, p.now);
    assert_eq!(out.len(), 1);
    let unit = out.pop().unwrap();
    p.a.channel_done(P0, unit.outcome, NativeDatagramResult::Accepted, p.now);
    assert_eq!(p.a.shaping_stats().stall_spent, Duration::from_millis(2));
}
