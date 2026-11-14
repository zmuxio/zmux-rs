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

use bytes::Bytes;
use common::{connect, duplex, multi_thread, watchdog};
use zmux::helpers::{
    Forwarded, PacketError, PacketOptions, PacketStream, SendPolicy, Sent, SpliceOptions, splice,
    splice_packets,
};
use zmux::proto::ApplicationErrorCode;
use zmux::{Config, RecvStream, SendStream, Session, StreamError, VarInt};

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
    relay: tokio::task::JoinHandle<(Forwarded, Forwarded)>,
}

impl Hop {
    async fn new(next_hop_datagrams: bool, burn: usize, packets: bool) -> Self {
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
        let relay = tokio::spawn(async move {
            let (s_in, r_in) = ra.accept_bi().await.unwrap();
            let out = rb.open_bi_with(&r_in.preamble()).await.unwrap();
            let r = if packets {
                splice_packets((s_in, r_in), out, SpliceOptions::default()).await
            } else {
                splice((s_in, r_in), out, SpliceOptions::default()).await
            }
            .unwrap();
            drop((keep, far));
            (r.a_to_b, r.b_to_a)
        });
        Self { a, b, relay }
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
        let mut p = PacketStream::new(s, r);
        let (fs, fr) = watchdog(10, "accept", hop.b.accept_bi()).await.unwrap();
        assert!(
            fs.id().unwrap().into_inner() >= 64,
            "the outbound Flow takes 2 bytes: {:?}",
            fs.id()
        );
        // The DATAGRAM frame of 65535 bytes less its type, a one-byte Flow
        // and a one-byte Context ID.
        let max = 65535 - 3;
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
        assert_eq!((ab.datagrams_as_capsules, ab.datagrams_dropped), (1, 0));
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
        s.send_datagram(0, Bytes::from(vec![1u8; 65535 - 3]))
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
                ab.datagrams_dropped,
                ab.datagrams_too_large,
                ab.datagrams_limited
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
        let big = 65535 - 3;
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
    let (a, b) = pair(true).await;
    let (mut p, mut q) = packets(&a, &b, PacketOptions::with_policy(SendPolicy::StreamOnly)).await;
    // A one-byte Context ID and a two-byte Length.
    let payload = Bytes::from(vec![7u8; size - 4]);
    let mut ok = 0u64;
    while let Ok(r) = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        p.send(payload.clone()),
    )
    .await
    {
        assert_eq!(r, Ok(Sent::Capsule));
        ok += 1;
    }
    let reader = tokio::spawn(async move {
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
/// counted as dropped, not forwarded.
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
            ab.datagrams_dropped,
            ab.datagrams_too_large
        ),
        (0, 0, 5, 5)
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
