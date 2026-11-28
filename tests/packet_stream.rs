//! `helpers::PacketStream` and `helpers::splice_packets` (EXTENSIONS.md
//! Section 12): packets as datagrams or DATAGRAM capsules, the send
//! policies, malformed bytes ending the stream with `ZMUX_PACKET_ERROR`, and
//! a relay that turns a datagram too large for the next hop into a capsule.

#![allow(
    clippy::cast_possible_truncation,
    reason = "test and bench values are small and bounded; checked conversions would only add noise"
)]
#![allow(
    clippy::many_single_char_names,
    reason = "short conventional names in scenario code"
)]

mod common;

use std::future::{Future, poll_fn};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use common::{connect, duplex, multi_thread, watchdog};
use zmux::helpers::{
    PacketError, PacketOptions, PacketStream, SendPolicy, Sent, SpliceDirection, SpliceOptions,
    splice, splice_packets,
};
use zmux::proto::ApplicationErrorCode;
use zmux::{Cap, Config, Limiter, RecvStream, SendStream, Session, StreamError, VarInt};

fn packet_error() -> VarInt {
    VarInt::from_u64(ApplicationErrorCode::ZMUX_PACKET_ERROR.0).unwrap()
}

fn config(datagrams: bool) -> Config {
    let mut c = Config::default();
    c.enable_datagrams = datagrams;
    c
}

async fn pair(datagrams: bool) -> (Session, Session) {
    let ((x, _), (y, _)) = duplex(1 << 20);
    connect(x, y, config(datagrams), config(datagrams)).await
}

/// A bidirectional stream from `a` to `b`, both parts on each side.
async fn stream(a: &Session, b: &Session) -> ((SendStream, RecvStream), (SendStream, RecvStream)) {
    let (s, r) = a.open_bi().await.unwrap();
    s.pin_id().unwrap();
    let far = watchdog(10, "accept", b.accept_bi()).await.unwrap();
    ((s, r), far)
}

async fn packets(a: &Session, b: &Session, opts: PacketOptions) -> (PacketStream, PacketStream) {
    let ((s, r), (fs, fr)) = stream(a, b).await;
    (
        PacketStream::with_options(s, r, opts),
        PacketStream::with_options(fs, fr, opts),
    )
}

async fn next(p: &mut PacketStream) -> (u64, Bytes) {
    let got = watchdog(10, "packet", p.recv()).await.unwrap().unwrap();
    (got.context, got.payload)
}

#[tokio::test]
async fn capsule_only_rejects_inherited_require_native() {
    let (client, _server) = pair(true).await;
    let (send, recv) = client.open_bi().await.unwrap();
    send.set_datagram_options(zmux::DatagramSendOptions {
        carrier: Some(zmux::DatagramCarrier::RequireNative),
        ..zmux::DatagramSendOptions::default()
    })
    .unwrap();
    let mut packet = PacketStream::with_options(
        send,
        recv,
        PacketOptions::with_policy(SendPolicy::StreamOnly),
    );
    assert!(matches!(
        packet.send(Bytes::new()).await,
        Err(PacketError::Datagram(zmux::DatagramError::InvalidOptions(error)))
        if error.field() == "packet_policy"
    ));
    assert_eq!(packet.stats().sent_capsules, 0);
}

/// The DATAGRAM capsule of `payload` with Context ID `context`.
fn capsule(context: u64, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0x00];
    let ctx = varint(context);
    v.extend(varint((ctx.len() + payload.len()) as u64));
    v.extend(ctx);
    v.extend_from_slice(payload);
    v
}

fn varint(v: u64) -> Vec<u8> {
    let mut b = [0; 8];
    let n = zmux::proto::varint::encode(v, &mut b).unwrap();
    b[..n].to_vec()
}

#[test]
fn prefer_datagram_sends_what_fits_as_datagrams_and_the_rest_as_capsules() {
    multi_thread(async {
        let (a, b) = pair(true).await;
        let (mut p, mut q) = packets(&a, &b, PacketOptions::default()).await;
        assert_eq!(
            p.send(Bytes::from_static(b"small")).await,
            Ok(Sent::Datagram)
        );
        assert_eq!(next(&mut q).await, (0, Bytes::from_static(b"small")));
        // Context IDs travel with the packet, either way.
        assert_eq!(
            p.send_with_context(77, Bytes::from_static(b"ctx")).await,
            Ok(Sent::Datagram)
        );
        assert_eq!(next(&mut q).await, (77, Bytes::from_static(b"ctx")));
        // The largest packet does not fit a datagram: a capsule.
        let big = Bytes::from(vec![7u8; 65535]);
        assert_eq!(
            p.send_with_context(1 << 40, big.clone()).await,
            Ok(Sent::Capsule)
        );
        assert_eq!(next(&mut q).await, (1 << 40, big));
        assert_eq!(
            p.send(Bytes::from(vec![0; 65536])).await,
            Err(PacketError::TooLarge { max: 65535 })
        );
        assert_eq!(
            p.send_with_context(1 << 62, Bytes::new()).await,
            Err(PacketError::InvalidContext)
        );
        // An empty packet, and the end.
        p.send(Bytes::new()).await.unwrap();
        assert_eq!(next(&mut q).await, (0, Bytes::new()));
        p.close().await.unwrap();
        assert_eq!(watchdog(10, "end", q.recv()).await, Ok(None));
        let (ps, qs) = (p.stats(), q.stats());
        assert_eq!((ps.sent_datagrams, ps.sent_capsules), (3, 1));
        assert_eq!((qs.received_datagrams, qs.received_capsules), (3, 1));
        // The other direction works the same, through split halves.
        let (mut qt, _qr) = q.split();
        let (_pt, mut pr) = p.split();
        qt.send(Bytes::from_static(b"back")).await.unwrap();
        let got = watchdog(10, "back", pr.recv()).await.unwrap().unwrap();
        assert_eq!(&got.payload[..], b"back");
    });
}

#[test]
fn stream_only_keeps_order_and_datagram_only_refuses_what_does_not_fit() {
    multi_thread(async {
        let (a, b) = pair(true).await;
        let (mut p, mut q) =
            packets(&a, &b, PacketOptions::with_policy(SendPolicy::StreamOnly)).await;
        for i in 0..100u8 {
            assert_eq!(
                p.send(Bytes::from(vec![i; 1 + i as usize])).await,
                Ok(Sent::Capsule)
            );
        }
        for i in 0..100u8 {
            assert_eq!(next(&mut q).await.1, Bytes::from(vec![i; 1 + i as usize]));
        }
        assert_eq!(q.stats().received_capsules, 100);

        let (mut p, mut q) =
            packets(&a, &b, PacketOptions::with_policy(SendPolicy::DatagramOnly)).await;
        assert_eq!(p.send(Bytes::from_static(b"d")).await, Ok(Sent::Datagram));
        assert_eq!(next(&mut q).await.1, Bytes::from_static(b"d"));
        let r = p.send(Bytes::from(vec![0; 65535])).await;
        assert!(
            matches!(r, Err(PacketError::TooLarge { max }) if max < 65535),
            "{r:?}"
        );
        assert_eq!(p.stats().dropped_too_large, 1);
    });
}

#[test]
fn without_datagrams_packets_fall_back_to_capsules() {
    multi_thread(async {
        let (a, b) = pair(false).await;
        let (mut p, mut q) = packets(&a, &b, PacketOptions::default()).await;
        assert_eq!(
            p.send_with_context(5, Bytes::from_static(b"x")).await,
            Ok(Sent::Capsule)
        );
        assert_eq!(next(&mut q).await, (5, Bytes::from_static(b"x")));
        let (mut p, _q) =
            packets(&a, &b, PacketOptions::with_policy(SendPolicy::DatagramOnly)).await;
        assert_eq!(
            p.send(Bytes::from_static(b"x")).await,
            Err(PacketError::NotNegotiated)
        );
    });
}

/// Writes `bytes` raw on a stream whose far end is a packet stream with a
/// bound of 100; what the far end's `recv` returns, and how the raw end
/// saw the stream end: the `STOP_SENDING` code and the reset code.
async fn raw_to_packets(
    bytes: Vec<u8>,
    finish: bool,
) -> (
    Vec<Result<Option<(u64, Bytes)>, PacketError>>,
    Option<VarInt>,
    Option<StreamError>,
    u64,
) {
    let (a, b) = pair(true).await;
    let ((mut s, mut r), (fs, fr)) = stream(&a, &b).await;
    let mut opts = PacketOptions::default();
    opts.max_packet = 100;
    let mut q = PacketStream::with_options(fs, fr, opts);
    s.write_all(&bytes).await.unwrap();
    if finish {
        s.finish().unwrap();
    }
    let mut out = Vec::new();
    loop {
        let got = watchdog(10, "recv", q.recv()).await;
        let end = !matches!(got, Ok(Some(_)));
        out.push(got.map(|o| o.map(|p| (p.context, p.payload))));
        if end {
            break;
        }
    }
    let stopped = if matches!(out.last(), Some(Err(_))) {
        watchdog(10, "stopped", s.stopped()).await.unwrap()
    } else {
        None
    };
    let reset = if matches!(out.last(), Some(Err(_))) {
        let mut buf = [0u8; 64];
        watchdog(10, "reset", async {
            loop {
                match r.read(&mut buf).await {
                    Ok(Some(_)) => {}
                    Ok(None) => return None,
                    Err(e) => return Some(e),
                }
            }
        })
        .await
    } else {
        None
    };
    (out, stopped, reset, q.stats().skipped_capsules)
}

#[test]
fn an_oversized_capsule_ends_the_stream_with_zmux_packet_error() {
    multi_thread(async {
        let mut bytes = capsule(0, &[1; 100]);
        bytes.extend(capsule(0, &[2; 101]));
        let (out, stopped, reset, _) = raw_to_packets(bytes, false).await;
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], Ok(Some((0, Bytes::from(vec![1; 100])))));
        assert_eq!(out[1], Err(PacketError::Malformed));
        assert_eq!(stopped, Some(packet_error()));
        assert!(
            matches!(reset, Some(StreamError::Reset { code, .. }) if code == packet_error()),
            "{reset:?}"
        );
    });
}

#[test]
fn a_stream_ending_inside_a_capsule_ends_it_with_zmux_packet_error() {
    multi_thread(async {
        let mut bytes = capsule(3, b"whole");
        bytes.extend(&capsule(3, b"cut")[..4]);
        let (out, _, reset, _) = raw_to_packets(bytes, true).await;
        assert_eq!(out[0], Ok(Some((3, Bytes::from_static(b"whole")))));
        assert_eq!(out[1], Err(PacketError::Malformed));
        assert!(
            matches!(reset, Some(StreamError::Reset { code, .. }) if code == packet_error()),
            "{reset:?}"
        );
    });
}

#[test]
fn unknown_capsule_types_are_skipped() {
    multi_thread(async {
        // Unknown types, one larger than the packet bound of 100 (but not
        // than the bound of a capsule, 108).
        let mut bytes = vec![0x17, 0x03, 1, 2, 3];
        bytes.extend([0x40, 0x99, 0x40, 108]);
        bytes.extend([9; 108]);
        bytes.extend(capsule(1 << 20, b"after"));
        let (out, _, _, skipped) = raw_to_packets(bytes, true).await;
        assert_eq!(
            out,
            [Ok(Some((1 << 20, Bytes::from_static(b"after")))), Ok(None)]
        );
        assert_eq!(skipped, 2);
    });
}

/// A, the relay R and B; R relays the next stream A opens to B with
/// `relay`, after opening `burn` streams on R–B so that the outbound
/// stream's Flow takes more bytes than the inbound one's.
struct Hop {
    a: Session,
    b: Session,
    relay: tokio::task::JoinHandle<(SpliceDirection, SpliceDirection)>,
    /// The relay's inbound session.
    inbound: Session,
}

impl Hop {
    async fn new(next_hop_datagrams: bool, burn: usize, packets: bool) -> Self {
        Self::with(next_hop_datagrams, burn, packets, SpliceOptions::default()).await
    }

    async fn with(
        next_hop_datagrams: bool,
        burn: usize,
        packets: bool,
        opts: SpliceOptions,
    ) -> Self {
        let ((x, _), (y, _)) = duplex(1 << 20);
        let (a, ra) = connect(x, y, config(true), config(true)).await;
        let ((x, _), (y, _)) = duplex(1 << 20);
        let (rb, b) = connect(x, y, config(next_hop_datagrams), config(next_hop_datagrams)).await;
        let mut keep = Vec::new();
        for _ in 0..burn {
            let (s, r) = rb.open_bi().await.unwrap();
            s.pin_id().unwrap();
            keep.push((s, r));
        }
        let mut far = Vec::new();
        for _ in 0..burn {
            far.push(watchdog(10, "burnt", b.accept_bi()).await.unwrap());
        }
        let inbound = ra.clone();
        let relay = tokio::spawn(async move {
            let (s_in, r_in) = ra.accept_bi().await.unwrap();
            let out = rb.open_bi_with(&r_in.preamble()).await.unwrap();
            let r = if packets {
                splice_packets((s_in, r_in), out, opts).await
            } else {
                splice((s_in, r_in), out, opts).await
            }
            .unwrap();
            drop((keep, far));
            (r.a_to_b, r.b_to_a)
        });
        Self {
            a,
            b,
            relay,
            inbound,
        }
    }
}

#[test]
fn a_packet_relay_turns_a_datagram_too_large_for_the_next_hop_into_a_capsule() {
    multi_thread(async {
        let hop = Hop::new(true, 20, true).await;
        let (mut s, r) = hop.a.open_bi().await.unwrap();
        // Capsules pass through as they are, unknown types included.
        let mut raw = vec![0x17, 0x02, 1, 2];
        raw.extend(capsule(9, b"first"));
        s.write_all(&raw).await.unwrap();
        let max = s.max_datagram_size(9).unwrap();
        let mut p = PacketStream::new(s, r);
        let (fs, fr) = watchdog(10, "accept", hop.b.accept_bi()).await.unwrap();
        assert!(
            fs.id().unwrap().into_inner() >= 64,
            "the outbound Flow takes 2 bytes: {:?}",
            fs.id()
        );
        let mut q = PacketStream::new(fs, fr);
        // A datagram that just fits the first hop, and with the other
        // stream ID not the second: a DATAGRAM capsule there.
        let big = Bytes::from(vec![3u8; max]);
        assert_eq!(
            p.send_with_context(9, big.clone()).await,
            Ok(Sent::Datagram)
        );
        let mut got = Vec::new();
        for _ in 0..2 {
            got.push(next(&mut q).await);
        }
        assert!(got.contains(&(9, Bytes::from_static(b"first"))));
        assert!(got.contains(&(9, big)));
        // Small datagrams stay datagrams.
        assert_eq!(p.send(Bytes::from_static(b"s")).await, Ok(Sent::Datagram));
        assert_eq!(next(&mut q).await, (0, Bytes::from_static(b"s")));
        let qs = q.stats();
        assert_eq!(
            (
                qs.received_capsules,
                qs.received_datagrams,
                qs.skipped_capsules
            ),
            (2, 1, 1)
        );
        p.close().await.unwrap();
        q.close().await.unwrap();
        assert_eq!(watchdog(10, "end", q.recv()).await, Ok(None));
        assert_eq!(watchdog(10, "end", p.recv()).await, Ok(None));
        let (ab, _) = watchdog(10, "relay", hop.relay).await.unwrap();
        assert_eq!((ab.datagrams_as_capsules, ab.drops.total()), (1, 0));
    });
}

#[test]
fn a_packet_relay_turns_datagrams_into_capsules_towards_a_hop_without_datagrams() {
    multi_thread(async {
        let hop = Hop::new(false, 0, true).await;
        let (s, r) = hop.a.open_bi().await.unwrap();
        s.pin_id().unwrap();
        let mut p = PacketStream::new(s, r);
        for i in 0..20u64 {
            assert_eq!(
                p.send_with_context(i, Bytes::from(vec![i as u8; 1000]))
                    .await,
                Ok(Sent::Datagram)
            );
        }
        let (fs, fr) = watchdog(10, "accept", hop.b.accept_bi()).await.unwrap();
        let mut q = PacketStream::new(fs, fr);
        let mut seen = 0;
        while seen < 20 {
            let (c, payload) = next(&mut q).await;
            assert_eq!(payload, Bytes::from(vec![c as u8; 1000]));
            seen += 1;
        }
        assert_eq!(q.stats().received_capsules, 20);
        p.close().await.unwrap();
        q.close().await.unwrap();
        assert_eq!(watchdog(10, "end", p.recv()).await, Ok(None));
        let (ab, _) = watchdog(10, "relay", hop.relay).await.unwrap();
        assert_eq!(ab.datagrams_as_capsules, 20);
    });
}

#[test]
fn splice_counts_datagrams_too_large_for_the_next_hop() {
    multi_thread(async {
        let hop = Hop::new(true, 20, false).await;
        let (mut s, mut r) = hop.a.open_bi().await.unwrap();
        s.write_all(b"x").await.unwrap();
        let (mut fs, mut fr) = watchdog(10, "accept", hop.b.accept_bi()).await.unwrap();
        s.send_datagram(0, Bytes::from(vec![1u8; s.max_datagram_size(0).unwrap()]))
            .unwrap();
        s.send_datagram(0, Bytes::from_static(b"fits")).unwrap();
        let d = watchdog(10, "datagram", fr.read_datagram()).await.unwrap();
        assert_eq!(&d.payload[..], b"fits");
        s.finish().unwrap();
        fs.finish().unwrap();
        let mut buf = [0; 16];
        while watchdog(10, "B reads", fr.read(&mut buf))
            .await
            .unwrap()
            .is_some()
        {}
        while watchdog(10, "A reads", r.read(&mut buf))
            .await
            .unwrap()
            .is_some()
        {}
        let (ab, _) = watchdog(10, "relay", hop.relay).await.unwrap();
        assert_eq!(
            (
                ab.drops.total(),
                ab.drops.dropped_too_large,
                ab.drops.dropped_limiter
            ),
            (1, 1, 0)
        );
        assert_eq!(ab.datagrams_as_capsules, 0);
    });
}

#[test]
fn a_packet_relay_inserts_capsules_only_at_capsule_boundaries() {
    multi_thread(async {
        let hop = Hop::new(true, 20, true).await;
        let (mut s, mut r) = hop.a.open_bi().await.unwrap();
        s.pin_id().unwrap();
        let big = s.max_datagram_size(2).unwrap();
        let mut far = None;
        for i in 0..30u8 {
            // Capsules that the relay reads in pieces, with datagrams that
            // must become capsules between them.
            s.write_all(&capsule(1, &vec![i; 3000 + i as usize * 997]))
                .await
                .unwrap();
            s.send_datagram(2, Bytes::from(vec![i; big])).unwrap();
            if far.is_none() {
                let (fs, fr) = watchdog(10, "accept", hop.b.accept_bi()).await.unwrap();
                far = Some(PacketStream::new(fs, fr));
            }
        }
        s.finish().unwrap();
        let mut q = far.unwrap();
        let (mut ones, mut twos) = (0, 0);
        while let Some(p) = watchdog(10, "packet", q.recv()).await.unwrap() {
            let i = p.payload[0];
            assert!(p.payload.iter().all(|&b| b == i));
            match p.context {
                1 => {
                    assert_eq!((i, p.payload.len()), (ones, 3000 + ones as usize * 997));
                    ones += 1;
                }
                2 => {
                    assert_eq!(p.payload.len(), big);
                    twos += 1;
                }
                c => panic!("context {c}"),
            }
        }
        assert_eq!(ones, 30);
        // The datagrams may be dropped on the way, never cut.
        assert!(twos > 0);
        q.close().await.unwrap();
        let mut buf = [0; 8];
        while watchdog(10, "A reads", r.read(&mut buf))
            .await
            .unwrap()
            .is_some()
        {}
        let (ab, _) = watchdog(10, "relay", hop.relay).await.unwrap();
        assert_eq!(ab.datagrams_as_capsules, twos);
    });
}

/// Waits until everything `a` sent so far reached `b`: a stream opened
/// after it carries a byte across the same carrier.
async fn barrier(a: &Session, b: &Session) {
    let (mut s, _r) = a.open_bi().await.unwrap();
    s.write_all(b"!").await.unwrap();
    let (_fs, mut fr) = watchdog(10, "barrier", b.accept_bi()).await.unwrap();
    let mut one = [0];
    watchdog(10, "barrier byte", fr.read_exact(&mut one))
        .await
        .unwrap();
}

#[test]
fn datagrams_queued_before_the_end_are_delivered_before_it() {
    multi_thread(async {
        let (a, b) = pair(true).await;
        // One and two datagrams: the first `recv` looks at the stream
        // first, then at the datagrams.
        for n in 1..=2u8 {
            let (mut p, mut q) = packets(&a, &b, PacketOptions::default()).await;
            for i in 0..n {
                assert_eq!(p.send(Bytes::from(vec![i; 4])).await, Ok(Sent::Datagram));
            }
            p.close().await.unwrap();
            barrier(&a, &b).await;
            let mut got = Vec::new();
            while let Some(p) = watchdog(10, "recv", q.recv()).await.unwrap() {
                got.push(p.payload[0]);
            }
            got.sort_unstable();
            assert_eq!(got, (0..n).collect::<Vec<_>>());
            assert_eq!(watchdog(10, "ended", q.recv()).await, Ok(None));
        }
    });
}

/// Sends capsules of `size` bytes until one stalls and is cancelled; then
/// lets the far end read everything: the capsules it received and the
/// sender's count of those sent, with the sends that returned `Ok`.
async fn cancel_a_stalled_send(size: usize) -> (u64, u64, u64) {
    const SEND_BUFFER: u64 = 64 * 1024;
    let mut c = config(true);
    c.initial_stream_receive_window = SEND_BUFFER;
    c.max_stream_receive_window = Cap::Fixed(SEND_BUFFER);
    let ((x, gate), (y, _)) = duplex(1 << 20);
    let (a, b) = connect(x, y, c.clone(), c).await;
    let ((mut send, recv), (far_send, far_recv)) = stream(&a, &b).await;
    let credit = watchdog(30, "initial credit", send.wait_send_capacity(1))
        .await
        .unwrap();
    // Occupy every byte of peer credit without returning receive credit.
    // A big capsule has a six-byte header including Context ID.
    let fill = capsule(0, &vec![0; usize::try_from(credit).unwrap() - 6]);
    assert_eq!(fill.len() as u64, credit);
    watchdog(30, "fill peer credit", send.write_all(&fill))
        .await
        .unwrap();
    common::eventually(30, "all peer credit occupied", || {
        far_recv.stats().bytes_received == credit
    })
    .await;
    send.set_send_buffer(SEND_BUFFER).unwrap();
    gate.stall(true);
    let options = PacketOptions::with_policy(SendPolicy::StreamOnly);
    let mut p = PacketStream::with_options(send, recv, options);
    let mut q = PacketStream::with_options(far_send, far_recv, options);
    // A one-byte Context ID and a two-byte Length.
    let payload = Bytes::from(vec![7; size - 4]);
    let ok = SEND_BUFFER / size as u64;
    for _ in 0..ok {
        assert_eq!(
            watchdog(30, "send within buffer", p.send(payload.clone())).await,
            Ok(Sent::Capsule)
        );
    }
    {
        let mut pending = std::pin::pin!(p.send(payload.clone()));
        let poll = poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx))).await;
        assert!(poll.is_pending(), "the next capsule fills the buffer");
    }
    gate.stall(false);
    let reader = tokio::spawn(async move {
        assert_eq!(next(&mut q).await.1.len() as u64, credit - 6);
        let mut n = 0u64;
        while let Some(got) = watchdog(10, "recv", q.recv()).await.unwrap() {
            assert_eq!(got.payload.len(), size - 4);
            n += 1;
        }
        n
    });
    p.close().await.unwrap();
    let received = watchdog(10, "reader", reader).await.unwrap();
    (received, p.stats().sent_capsules, ok)
}

#[test]
fn a_send_cancelled_before_writing_anything_is_not_sent() {
    multi_thread(async {
        // Capsules of 4096 bytes fill the stream's buffer and window to
        // their end: the stalled send wrote nothing.
        let (received, sent, ok) = cancel_a_stalled_send(4096).await;
        assert_eq!((received, sent), (ok, ok));
    });
}

#[test]
fn a_send_cancelled_after_writing_part_is_completed_and_counted() {
    multi_thread(async {
        // Capsules of 4097 bytes end the room inside one: the stalled send
        // wrote part of it, and close completes it.
        let (received, sent, ok) = cancel_a_stalled_send(4097).await;
        assert_eq!((received, sent), (ok + 1, ok + 1));
    });
}

/// A packet relay towards a hop without datagrams, with A inside a capsule
/// when 5 datagrams arrive and then ending its direction (a FIN, or a
/// reset): the datagrams queued as capsules are never written, and are
/// counted as dropped, not forwarded, and not as too large.
async fn queued_capsules_dropped_by_the_end(reset: bool) {
    let hop = Hop::new(false, 0, true).await;
    let (mut s, mut r) = hop.a.open_bi().await.unwrap();
    s.pin_id().unwrap();
    let cut = capsule(1, &[5; 100]);
    s.write_all(&cut[..10]).await.unwrap();
    let (mut fs, mut fr) = watchdog(10, "accept", hop.b.accept_bi()).await.unwrap();
    let mut buf = [0; 10];
    watchdog(10, "B reads", fr.read_exact(&mut buf))
        .await
        .unwrap();
    for i in 0..5u8 {
        s.send_datagram(0, Bytes::from(vec![i; 50])).unwrap();
    }
    // Still inside the capsule: the datagrams wait for its end.
    s.write_all(&cut[10..11]).await.unwrap();
    watchdog(10, "B reads", fr.read_exact(&mut buf[..1]))
        .await
        .unwrap();
    if reset {
        s.reset(VarInt::from_u64(3).unwrap()).unwrap();
    } else {
        s.finish().unwrap();
    }
    let mut all = Vec::new();
    while let Ok(Some(n)) = watchdog(10, "B drains", fr.read(&mut buf)).await {
        all.extend_from_slice(&buf[..n]);
    }
    assert!(all.is_empty(), "{all:?}");
    fs.finish().unwrap();
    while let Ok(Some(_)) = watchdog(10, "A reads", r.read(&mut buf)).await {}
    let (ab, _) = watchdog(10, "relay", hop.relay).await.unwrap();
    assert_eq!(
        (
            ab.datagrams_as_capsules,
            ab.datagram_bytes,
            ab.drops.total(),
            ab.drops.dropped_too_large
        ),
        (0, 0, 5, 0),
        "dropped by the end, not for their size"
    );
}

#[test]
fn a_packet_relay_counts_capsules_a_fin_left_unwritten_as_dropped() {
    multi_thread(queued_capsules_dropped_by_the_end(false));
}

#[test]
fn a_packet_relay_counts_capsules_a_reset_left_unwritten_as_dropped() {
    multi_thread(queued_capsules_dropped_by_the_end(true));
}

/// A limiter that records every call. `acquire` grants at most `burst`
/// (all of `max` when 0) and waits while `open` is false; `try_acquire`
/// grants `try_grant`.
#[derive(Default)]
struct Rec {
    acquires: Mutex<Vec<(u64, u64)>>,
    tries: Mutex<Vec<(u64, u64)>>,
    burst: u64,
    try_grant: AtomicU64,
    closed: AtomicBool,
    requested: tokio::sync::Notify,
    tried: tokio::sync::Notify,
    waiter: Mutex<Option<Waker>>,
    out: AtomicU64,
}

impl Rec {
    fn open(&self) {
        self.closed.store(false, Ordering::SeqCst);
        if let Some(w) = self.waiter.lock().unwrap().take() {
            w.wake();
        }
    }

    /// Granted and not refunded.
    fn outstanding(&self) -> u64 {
        self.out.load(Ordering::SeqCst)
    }
}

impl Limiter for Rec {
    fn max_burst_bytes(&self) -> Option<u64> {
        Some(u64::MAX)
    }

    fn poll_acquire(
        &self,
        cx: &mut Context<'_>,
        min: u64,
        max: u64,
    ) -> Poll<Result<u64, zmux::LimitError>> {
        self.requested.notify_one();
        if self.closed.load(Ordering::SeqCst) {
            *self.waiter.lock().unwrap() = Some(cx.waker().clone());
            if self.closed.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        self.acquires.lock().unwrap().push((min, max));
        let n = if self.burst == 0 {
            max
        } else {
            max.min(self.burst)
        };
        self.out.fetch_add(n, Ordering::SeqCst);
        Poll::Ready(Ok(n))
    }
    fn try_acquire(&self, min: u64, max: u64) -> u64 {
        self.tries.lock().unwrap().push((min, max));
        let n = self.try_grant.load(Ordering::SeqCst).min(max);
        self.out.fetch_add(n, Ordering::SeqCst);
        // Wake the test only after this call has decided its grant.
        self.tried.notify_one();
        n
    }
    fn refund(&self, n: u64) {
        self.out.fetch_sub(n, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn packet_capsules_do_not_call_the_datagram_limiter() {
    let limiter = Arc::new(Rec::default());
    let mut client = config(true);
    client.datagram_limiter.send = Some(limiter.clone());
    let ((a, _), (b, _)) = duplex(1 << 20);
    let (a, b) = connect(a, b, client, config(true)).await;
    let (mut sender, mut receiver) = packets(&a, &b, PacketOptions::default()).await;

    assert!(matches!(
        sender.send(Bytes::from_static(b"denied")).await,
        Err(PacketError::Datagram(zmux::DatagramError::Dropped(
            zmux::DatagramDrop::Limiter
        )))
    ));
    let oversized = Bytes::from(vec![0; 65535]);
    assert_eq!(sender.send(oversized.clone()).await, Ok(Sent::Capsule));
    assert_eq!(next(&mut receiver).await, (0, oversized));
    assert_eq!(*limiter.tries.lock().unwrap(), [(6, 6)]);
}

fn limited(rec: &Arc<Rec>) -> SpliceOptions {
    let mut opts = SpliceOptions::default();
    opts.a_to_b = Some(rec.clone());
    opts
}

/// Reads `p` to its end: the packets in order.
async fn drain(p: &mut PacketStream) -> Vec<(u64, Bytes)> {
    let mut got = Vec::new();
    while let Some(x) = watchdog(10, "packet", p.recv()).await.unwrap() {
        got.push((x.context, x.payload));
    }
    got
}

#[test]
fn a_packet_relay_takes_one_whole_grant_per_capsule() {
    multi_thread(async {
        let rec = Arc::new(Rec::default());
        let mut opts = limited(&rec);
        opts.chunk = 4096;
        let hop = Hop::with(true, 0, true, opts).await;
        let (mut s, r) = hop.a.open_bi().await.unwrap();
        // Larger than the chunk, small, empty, and of an unknown type.
        let sizes = [60_000usize, 5, 0];
        let mut raw = Vec::new();
        let mut want = Vec::new();
        for (i, &n) in sizes.iter().enumerate() {
            let c = capsule(i as u64, &vec![i as u8; n]);
            want.push((c.len() as u64, c.len() as u64));
            raw.extend(c);
        }
        raw.extend([0x17, 0x02, 1, 2]);
        want.push((4, 4));
        s.write_all(&raw).await.unwrap();
        s.finish().unwrap();
        let (fs, fr) = watchdog(10, "accept", hop.b.accept_bi()).await.unwrap();
        let mut q = PacketStream::new(fs, fr);
        let got = drain(&mut q).await;
        assert_eq!(got.len(), sizes.len());
        for (i, (c, p)) in got.iter().enumerate() {
            assert_eq!((*c, p.len()), (i as u64, sizes[i]));
        }
        drop(r);
        q.close().await.unwrap();
        let (ab, _) = watchdog(10, "relay", hop.relay).await.unwrap();
        assert_eq!(ab.bytes, raw.len() as u64);
        assert_eq!(
            *rec.acquires.lock().unwrap(),
            want,
            "one acquire(n, n) per capsule"
        );
        assert_eq!(
            rec.outstanding(),
            raw.len() as u64,
            "every capsule went out"
        );
    });
}

#[test]
fn a_short_atomic_grant_refunds_and_ends_the_direction() {
    multi_thread(async {
        let rec = Arc::new(Rec {
            burst: 10,
            ..Rec::default()
        });
        let hop = Hop::with(true, 0, true, limited(&rec)).await;
        let (mut send, recv) = hop.a.open_bi().await.unwrap();
        let unit = capsule(4, &[9; 1000]);
        send.write_all(&unit).await.unwrap();
        let stopped = watchdog(30, "limiter STOP", send.stopped()).await.unwrap();
        assert_eq!(stopped, Some(VarInt::from_u32(0x5a4d_0001)));
        drop(recv);
        let (result, _) = watchdog(30, "relay", hop.relay).await.unwrap();
        assert_eq!(result.end, zmux::helpers::SpliceEnd::LimiterFailed);
        assert_eq!(result.bytes, 0);
        assert_eq!(rec.outstanding(), 0);
        let n = unit.len() as u64;
        assert_eq!(*rec.acquires.lock().unwrap(), [(n, n)]);
    });
}

#[test]
fn a_packet_relay_holds_only_the_header_while_the_limiter_waits() {
    multi_thread(async {
        let rec = Arc::new(Rec::default());
        rec.closed.store(true, Ordering::SeqCst);
        let hop = Hop::with(true, 0, true, limited(&rec)).await;
        let (mut s, r) = hop.a.open_bi().await.unwrap();
        // Type 0x00, a two-byte Length (1 + 1000), Context ID 4.
        let c = capsule(4, &[9; 1000]);
        s.write_all(&c).await.unwrap();
        // The relay read the header and waits: nothing more is read,
        // nothing granted, nothing forwarded.
        let read = || hop.inbound.stats().bytes_read;
        watchdog(30, "exact reservation requested", rec.requested.notified()).await;
        assert_eq!(read(), 4, "only the complete capsule header is held");
        assert_eq!(rec.outstanding(), 0);
        assert!(rec.acquires.lock().unwrap().is_empty());
        rec.open();
        s.finish().unwrap();
        let (fs, fr) = watchdog(10, "accept", hop.b.accept_bi()).await.unwrap();
        let mut q = PacketStream::new(fs, fr);
        assert_eq!(drain(&mut q).await, [(4, Bytes::from(vec![9; 1000]))]);
        q.close().await.unwrap();
        drop(r);
        watchdog(10, "relay", hop.relay).await.unwrap();
        let n = c.len() as u64;
        assert_eq!(*rec.acquires.lock().unwrap(), [(n, n)]);
    });
}

/// While the grant of a capsule whose header was read is awaited, the
/// upstream reset still ends the direction: a limiter that never grants
/// does not hold it.
#[test]
fn a_reset_ends_a_packet_relay_waiting_for_a_capsule_grant() {
    multi_thread(async {
        let rec = Arc::new(Rec::default());
        rec.closed.store(true, Ordering::SeqCst);
        let hop = Hop::with(true, 0, true, limited(&rec)).await;
        let (mut s, r) = hop.a.open_bi().await.unwrap();
        s.write_all(&capsule(4, &[9; 1000])).await.unwrap();
        watchdog(30, "exact reservation requested", rec.requested.notified()).await;
        s.reset(VarInt::from_u32(9)).unwrap();
        drop(r);
        let (ab, _) = watchdog(10, "relay", hop.relay).await.unwrap();
        assert_eq!(ab.end, zmux::helpers::SpliceEnd::Reset(VarInt::from_u32(9)));
        assert_eq!(rec.outstanding(), 0, "nothing granted");
    });
}

/// A packet relay dropped inside a capsule refunds the part of its grant
/// that was not forwarded.
#[test]
fn a_packet_relay_dropped_inside_a_capsule_refunds_the_rest_of_its_grant() {
    multi_thread(async {
        let rec = Arc::new(Rec::default());
        let hop = Hop::with(true, 0, true, limited(&rec)).await;
        let (mut s, _r) = hop.a.open_bi().await.unwrap();
        let c = capsule(4, &[9; 1000]);
        s.write_all(&c[..13]).await.unwrap();
        let (_fs, mut fr) = watchdog(10, "accept", hop.b.accept_bi()).await.unwrap();
        let mut got = [0; 13];
        watchdog(10, "B reads", fr.read_exact(&mut got))
            .await
            .unwrap();
        assert_eq!(got[..], c[..13]);
        assert_eq!(
            rec.outstanding(),
            c.len() as u64,
            "the whole capsule granted"
        );
        hop.relay.abort();
        let _ = hop.relay.await;
        assert_eq!(rec.outstanding(), 13, "only what was forwarded stays taken");
    });
}

#[test]
fn a_packet_relay_polices_datagrams_and_drops_them_without_a_grant() {
    multi_thread(async {
        for capsules in [false, true] {
            let rec = Arc::new(Rec::default());
            let hop = Hop::with(!capsules, 0, true, limited(&rec)).await;
            let (mut s, mut r) = hop.a.open_bi().await.unwrap();
            s.write_all(&capsule(1, b"x")).await.unwrap();
            let (fs, fr) = watchdog(10, "accept", hop.b.accept_bi()).await.unwrap();
            let mut q = PacketStream::new(fs, fr);
            assert_eq!(next(&mut q).await, (1, Bytes::from_static(b"x")));
            // Refused: dropped and counted. Then granted, and an empty
            // one that passes without a call.
            s.send_datagram(2, Bytes::from(vec![5; 100])).unwrap();
            watchdog(30, "datagram policed", rec.tried.notified()).await;
            rec.try_grant.store(u64::MAX, Ordering::SeqCst);
            s.send_datagram(3, Bytes::from(vec![6; 50])).unwrap();
            s.send_datagram(4, Bytes::new()).unwrap();
            let mut got = vec![next(&mut q).await, next(&mut q).await];
            got.sort();
            assert_eq!(
                got,
                [(3, Bytes::from(vec![6; 50])), (4, Bytes::new())],
                "capsules: {capsules}"
            );
            s.finish().unwrap();
            assert_eq!(drain(&mut q).await.len(), 0, "nothing more");
            q.close().await.unwrap();
            let mut buf = [0; 8];
            while watchdog(10, "A reads", r.read(&mut buf))
                .await
                .unwrap()
                .is_some()
            {}
            let (ab, _) = watchdog(10, "relay", hop.relay).await.unwrap();
            assert_eq!((ab.drops.total(), ab.drops.dropped_limiter), (1, 1));
            let tries = rec.tries.lock().unwrap();
            if capsules {
                assert_eq!(*tries, [(104, 104), (53, 53), (3, 3)]);
            } else {
                assert_eq!(*tries, [(100, 100), (50, 50)]);
            }
            // Only the capsule written by the sender was acquired.
            assert_eq!(*rec.acquires.lock().unwrap(), [(4, 4)]);
            assert_eq!(ab.datagrams_as_capsules, u64::from(capsules) * 2);
        }
    });
}
