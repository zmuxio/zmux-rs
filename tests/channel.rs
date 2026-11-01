//! Datagrams on a carrier's datagram channel (EXTENSIONS.md Section 6.8),
//! in the sans-IO core: the per-frame choice between the channel and a
//! record, what a receiver does with channel datagrams, and the datagrams
//! held for streams that have not opened yet, in records and on channels.

use std::time::Duration;

use bytes::Bytes;
use zmux::proto::TransportErrorCode;
use zmux::proto::frame::{Dir, channel};
use zmux::proto::session::shaping::{Caps, Shaper};
use zmux::proto::session::{Config, PipeId, SessionCore, State};

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
        p.a.set_pipe_channel(P0, Some(ID), max);
    }
    if let Some(max) = b {
        p.b.set_pipe_channel(P0, Some(ID), max);
    }
    p.pump();
    assert!(p.a.is_established() && p.b.is_established());
    p
}

/// Takes `from`'s channel datagrams and hands each to `to` as its carrier
/// would, the Pipe Stream ID removed; returns how many moved.
fn move_channel(from: &mut SessionCore, to: &mut SessionCore, now: std::time::Instant) -> usize {
    let mut out = Vec::new();
    assert!(from.poll_channel(P0, &mut out), "channel live");
    for d in &out {
        let (id, frame) = channel::split(d).expect("Pipe Stream ID");
        assert_eq!(id, ID);
        to.receive_channel_datagram(P0, frame, now);
    }
    out.len()
}

#[test]
fn negotiated_datagrams_go_on_the_channel() {
    let mut p = pair(Some(MAX), Some(MAX));
    assert!(p.a.features().carrier_datagrams && p.b.features().carrier_datagrams);
    assert!(p.a.local_parameters().zmux_carrier_datagrams);
    let records = p.a.stats().records_sent;
    p.a.send_datagram(Bytes::from_static(b"hello"), true)
        .unwrap();
    // Not in a record: the pipe has nothing to write for it.
    assert!(!p.a.wants_write(P0));
    let now = p.now;
    let before = p.b.stats().records_received;
    assert_eq!(move_channel(&mut p.a, &mut p.b, now), 1);
    assert_eq!(p.b.recv_datagram().unwrap().as_deref(), Some(&b"hello"[..]));
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
    p.a.send_datagram(Bytes::from_static(b"x"), true).unwrap();
    let mut out = Vec::new();
    assert!(!p.a.poll_channel(P0, &mut out), "the channel's task ends");
    assert!(out.is_empty());
    p.pump();
    assert_eq!(p.b.recv_datagram().unwrap().as_deref(), Some(&b"x"[..]));
    assert_eq!(p.a.stats().datagrams_sent_channel, 0);
    // No channel at all on this end.
    let mut p = pair(None, Some(MAX));
    assert!(!p.b.features().carrier_datagrams);
    p.b.send_datagram(Bytes::from_static(b"y"), true).unwrap();
    p.pump();
    assert_eq!(p.a.recv_datagram().unwrap().as_deref(), Some(&b"y"[..]));
    // Without datagrams the parameter is never sent.
    let mut p = Pair::attached(Config::default(), Config::default());
    p.a.set_pipe_channel(P0, Some(ID), MAX);
    assert!(!p.a.local_parameters().zmux_carrier_datagrams);
}

#[test]
fn the_choice_is_per_frame() {
    let mut p = pair(Some(100), Some(100));
    // Pipe Stream ID 4 (1 byte), type (1), Flow 0 (1): 97 payload bytes fit.
    p.a.send_datagram(Bytes::from(vec![1u8; 97]), true).unwrap();
    p.a.send_datagram(Bytes::from(vec![2u8; 98]), true).unwrap();
    let now = p.now;
    assert_eq!(move_channel(&mut p.a, &mut p.b, now), 1);
    assert!(p.a.wants_write(P0), "the larger one goes in a record");
    p.pump();
    let mut got = Vec::new();
    while let Some(d) = p.b.recv_datagram().unwrap() {
        got.push(d.len());
    }
    got.sort_unstable();
    assert_eq!(got, [97, 98]);
    assert_eq!(p.a.stats().datagrams_sent_channel, 1);
    assert_eq!(p.a.stats().datagrams_sent, 2);
    // A channel that takes nothing now (0): records.
    p.a.set_pipe_channel(P0, Some(ID), 0);
    p.a.send_datagram(Bytes::from_static(b"z"), true).unwrap();
    assert!(p.a.wants_write(P0));
    p.pump();
    assert_eq!(p.b.recv_datagram().unwrap().as_deref(), Some(&b"z"[..]));
}

/// A shaper that changes nothing.
struct Plain;

impl Shaper for Plain {
    fn capabilities(&self) -> Caps {
        Caps::NONE
    }
}

#[test]
fn shaped_pipes_keep_datagrams_in_records() {
    let mut p = pair(Some(MAX), Some(MAX));
    assert!(p.a.set_pipe_shaper(P0, Some(Box::new(Plain))));
    p.a.send_datagram(Bytes::from_static(b"shaped"), true)
        .unwrap();
    let mut out = Vec::new();
    assert!(p.a.poll_channel(P0, &mut out));
    assert!(out.is_empty());
    assert!(p.a.wants_write(P0));
    p.pump();
    assert_eq!(
        p.b.recv_datagram().unwrap().as_deref(),
        Some(&b"shaped"[..])
    );
    // Unshaped again: the channel.
    assert!(p.a.set_pipe_shaper(P0, None));
    p.a.send_datagram(Bytes::from_static(b"plain"), true)
        .unwrap();
    let now = p.now;
    assert_eq!(move_channel(&mut p.a, &mut p.b, now), 1);
}

#[test]
fn failed_channel_sends_count_as_dropped() {
    let mut p = pair(Some(MAX), Some(MAX));
    for _ in 0..3 {
        p.a.send_datagram(Bytes::from_static(b"d"), true).unwrap();
    }
    let mut out = Vec::new();
    assert!(p.a.poll_channel(P0, &mut out));
    assert_eq!(out.len(), 3);
    p.a.channel_send_failed(2);
    let s = p.a.stats();
    assert_eq!((s.datagrams_sent, s.datagrams_sent_channel), (1, 1));
    assert_eq!(s.datagrams_dropped_send, 2);
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
    assert_eq!(q.b.recv_datagram().unwrap(), None);
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
    p.a.set_pipe_channel(P0, Some(ID), MAX);
    p.b.set_pipe_channel(P0, Some(ID), MAX);
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
            .send_datagram(Bytes::from_static(b"tick"), true)
            .is_err()
        {
            // The sender timed out first: neither do its own channel
            // datagrams count as activity.
            break;
        }
        move_channel(&mut p.a, &mut p.b, now);
        assert_eq!(p.b.recv_datagram().unwrap().as_deref(), Some(&b"tick"[..]));
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
        p.a.send_stream_datagram(k, 0, Bytes::from(vec![i]), true)
            .unwrap();
        p.a.send_stream_datagram(k, 2, Bytes::from(vec![i, i]), true)
            .unwrap();
        // The channel first: the opening frame is still to be written.
        let now = p.now;
        assert_eq!(move_channel(&mut p.a, &mut p.b, now), 2);
        assert_eq!(p.b.accept(Dir::Bidi).unwrap(), None);
        p.pump();
        let s = p.b.accept(Dir::Bidi).unwrap().expect("opened");
        assert_eq!(
            p.b.recv_stream_datagram(s).unwrap(),
            Some((0, Bytes::from(vec![i])))
        );
        assert_eq!(
            p.b.recv_stream_datagram(s).unwrap(),
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
    p.a.send_stream_datagram(k, 0, Bytes::from_static(b"late"), true)
        .unwrap();
    let now = p.now;
    move_channel(&mut p.a, &mut p.b, now);
    let due = p.b.poll_timeout().expect("a deadline");
    assert!(due <= now + Duration::from_millis(333));
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
    assert_eq!(p.b.recv_stream_datagram(s).unwrap(), None);
}

#[test]
fn held_datagrams_count_in_the_session_bytes_and_go_first() {
    let mut cfg = dgram_config();
    cfg.max_incoming_streams = 1000;
    let mut p = Pair::attached(dgram_config(), cfg);
    p.a.set_pipe_channel(P0, Some(ID), 70_000);
    p.b.set_pipe_channel(P0, Some(ID), 70_000);
    p.pump();
    let now = p.now;
    // 40 streams not opened at B, 60000 bytes each: more than the 1 MiB
    // of the session's datagram bytes.
    let mut keys = Vec::new();
    for _ in 0..40 {
        let k = p.a.open(Dir::Bidi).unwrap();
        p.a.write(k, b"o").unwrap();
        p.a.send_stream_datagram(k, 0, Bytes::from(vec![7u8; 60_000]), true)
            .unwrap();
        move_channel(&mut p.a, &mut p.b, now);
        keys.push(k);
    }
    let dropped = p.b.stats().datagrams_dropped_recv;
    assert_eq!(dropped, 40 - (1024 * 1024 / 60_064), "the oldest made room");
    p.pump();
    let mut delivered = 0;
    while let Some(s) = p.b.accept(Dir::Bidi).unwrap() {
        if p.b.recv_stream_datagram(s).unwrap().is_some() {
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
    p.a.send_stream_datagram(k, 0, Bytes::from_static(b"d"), true)
        .unwrap();
    p.pump();
    let s = p.b.accept(Dir::Bidi).unwrap().expect("opened");
    assert_eq!(
        p.b.recv_stream_datagram(s).unwrap(),
        Some((0, Bytes::from_static(b"d")))
    );
    assert_eq!(p.b.stats().datagrams_dropped_recv, 0);
}

#[test]
fn tiny_held_datagrams_are_bounded_by_their_entry_cost() {
    let mut cfg = dgram_config();
    cfg.max_incoming_streams = 1 << 20;
    let mut p = Pair::attached(dgram_config(), cfg);
    p.a.set_pipe_channel(P0, Some(ID), MAX);
    p.b.set_pipe_channel(P0, Some(ID), MAX);
    p.pump();
    let now = p.now;
    // Empty datagrams for a stream far ahead, never opened: each costs its
    // entry, so the 1 MiB holds 16384 of them at most.
    let k = p.a.open(Dir::Bidi).unwrap();
    p.a.write(k, b"o").unwrap();
    for _ in 0..20_000 {
        p.a.send_stream_datagram(k, 0, Bytes::new(), true).unwrap();
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
        p.a.send_stream_datagram(k, 0, Bytes::from(vec![i]), true)
            .unwrap();
        move_channel(&mut p.a, &mut p.b, now);
    }
    // One deadline, the oldest's; at it every one due expires.
    let due = p.b.poll_timeout().expect("a deadline");
    p.b.handle_timeout(due);
    assert_eq!(p.b.stats().datagrams_dropped_recv, 3);
}
