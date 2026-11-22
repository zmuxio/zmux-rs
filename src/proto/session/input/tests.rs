//! Receive-path regressions that need frames no compliant sender writes in
//! that order: they call the frame handlers of a multipath session
//! directly.

use std::time::{Duration, Instant};

use super::super::stream::{RECV_KEEP, RecvPart, make_id};
use bytes::Bytes;

use super::super::{Backing, Config, PipeAuth, PipeId, Role, SessionCore, StreamKey, TransmitBuf};
use crate::proto::frame::{Dir, Stream};
use crate::proto::payload::WirePreamble;
use crate::proto::record::Framing;

/// The frame type handed to the handlers (only error details use it).
const TY: u64 = 0x08;

fn config() -> Config {
    Config {
        max_pipes: 4,
        pipe_auth: PipeAuth::psk(*b"0123456789abcdef0123456789abcdef"),
        max_idle_timeout: Some(Duration::from_secs(600)),
        max_incoming_uni_streams: crate::proto::session::UniCredit::Limit(4),
        ..Config::default()
    }
}

/// A multipath pair on pipe 0, established.
fn pair() -> (SessionCore, SessionCore, Instant) {
    let now = Instant::now();
    let mut a = SessionCore::new(config(), Role::Client, None, now).unwrap();
    let mut b = SessionCore::new(config(), Role::Server, None, now).unwrap();
    a.attach_pipe(PipeId(0), Framing::ByteStream, now);
    b.attach_pipe(PipeId(0), Framing::ByteStream, now);
    pump(&mut a, &mut b, now);
    assert!(a.is_multipath() && b.is_multipath());
    assert!(b.features.preamble);
    (a, b, now)
}

fn pump(a: &mut SessionCore, b: &mut SessionCore, now: Instant) {
    let mut out = TransmitBuf::default();
    let mut wire = Vec::new();
    loop {
        let mut progress = false;
        for dir in [true, false] {
            let (from, to) = if dir {
                (&mut *a, &mut *b)
            } else {
                (&mut *b, &mut *a)
            };
            while from.wants_write(PipeId(0)) {
                from.poll_transmit(PipeId(0), now, &mut out);
                if out.is_empty() {
                    break;
                }
                wire.clear();
                out.copy_to_vec(&mut wire);
                to.receive(PipeId(0), &wire, now);
                progress = true;
            }
        }
        while a.poll_event().is_some() {}
        while b.poll_event().is_some() {}
        if !progress {
            return;
        }
    }
}

/// A's first unidirectional stream, as B sees it.
const UNI: u64 = make_id(0, Dir::Uni, true);

fn stream(offset: u64, data: &[u8]) -> Stream<'_> {
    Stream {
        stream_id: UNI,
        offset,
        data,
        fin: false,
        explicit_offset: true,
        explicit_len: true,
    }
}

fn preamble() -> Vec<u8> {
    let p = WirePreamble {
        open_info: Some(b"open information"),
        ..WirePreamble::default()
    };
    let mut buf = vec![0; p.encoded_len(None)];
    let n = p.encode(None, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn key(s: &SessionCore, id: u64) -> StreamKey {
    s.streams.key_of(id).expect("stream known")
}

/// Bytes of a frame that arrived before the preamble and overlap it leave
/// the buffers when the preamble is parsed:
/// the session's and the stream's buffered counts both drop to 0, and the
/// session credit released covers every byte consumed, the overlap
/// included.
#[test]
fn preamble_overlap_leaves_the_buffers() {
    let (_a, mut b, now) = pair();
    let released = b.streams.recv_flow().released;
    let pre = preamble();
    let p = pre.len();
    let mut data = pre[3..].to_vec();
    data.extend_from_slice(&[7; 100]);
    b.on_stream(stream(3, &data), TY, now).unwrap();
    assert_eq!(b.streams.recv_flow().buffered, (p - 3 + 100) as u64);
    b.on_stream(stream(0, &pre), TY, now).unwrap();
    let k = key(&b, UNI);
    let mut sink = [0u8; 256];
    let (n, _) = b.read(k, &mut sink).unwrap().expect("data");
    assert_eq!(n, 100);
    assert_eq!(&sink[..n], &[7; 100]);
    assert_eq!(
        b.streams.recv_flow().buffered,
        0,
        "preamble bytes still counted"
    );
    assert_eq!(b.stream_stats(k).unwrap().recv_buffered, 0);
    assert_eq!(
        b.streams.recv_flow().released - released,
        (p + 100) as u64,
        "credit of consumed bytes not released"
    );
}

/// Ranges beyond a gap merge as data arrives: a
/// frame adjacent to a range extends it and one that fills a gap joins two,
/// so the bookkeeping follows the gaps, not the frames, and inserts cost
/// O(log n). Nothing is charged: the list of chargeable frames is closed, and a sender spreading
/// small frames over pipes of different delays legitimately leaves many small gaps.
#[test]
fn ranges_beyond_a_gap_merge() {
    let (_a, mut b, now) = pair();
    // Adjacent frames extend one range.
    for off in 2000..2200 {
        b.on_stream(stream(off, &[1]), TY, now).unwrap();
    }
    // A frame that fills the gap between two ranges joins them.
    b.on_stream(stream(1000, &[1; 500]), TY, now).unwrap();
    b.on_stream(stream(1500, &[1; 500]), TY, now).unwrap();
    let r = b.streams.get(key(&b, UNI)).unwrap().recv.as_ref().unwrap();
    assert_eq!(r.fragments(), 1);
    assert_eq!(r.held() - r.buf.len() as u64, 1200);
    let tokens = b.budget.tokens();
    // Small ranges at alternating offsets: held, never charged.
    for i in 0..10_000u64 {
        b.on_stream(stream(150_000 + 2 * i, &[3]), TY, now).unwrap();
    }
    assert_eq!(b.budget.tokens(), tokens);
    // Filling the gaps joins them all.
    for i in 0..10_000u64 {
        b.on_stream(stream(150_001 + 2 * i, &[3]), TY, now).unwrap();
    }
    let r = b.streams.get(key(&b, UNI)).unwrap().recv.as_ref().unwrap();
    assert_eq!(r.fragments(), 2);
}

/// Bytes beyond a gap release session credit when they arrive; the gap
/// releases nothing before its own bytes arrive.
#[test]
fn gap_bytes_release_no_credit_before_they_arrive() {
    let (_a, mut b, now) = pair();
    let released = b.streams.recv_flow().released;
    b.on_stream(stream(100_000, &[5; 1000]), TY, now).unwrap();
    assert_eq!(b.streams.recv_flow().released - released, 1000);
    b.on_stream(stream(50_000, &[5; 1000]), TY, now).unwrap();
    assert_eq!(b.streams.recv_flow().released - released, 2000);
}

/// `bytes_received` counts distinct application bytes and never
/// decreases, also when a reset drops held data.
#[test]
fn bytes_received_is_distinct_and_monotonic() {
    let (_a, mut b, now) = pair();
    let pre = preamble();
    let p = pre.len() as u64;
    b.on_stream(stream(p + 100, &[1; 100]), TY, now).unwrap();
    let k = key(&b, UNI);
    let got = |b: &SessionCore| b.stream_stats(k).unwrap().bytes_received;
    assert_eq!(got(&b), 0, "no application bytes before the preamble");
    b.on_stream(stream(0, &pre), TY, now).unwrap();
    assert_eq!(got(&b), 100);
    b.on_stream(stream(p + 150, &[1; 100]), TY, now).unwrap();
    assert_eq!(got(&b), 150, "duplicates count once");
    // RESET_STREAM_AT below the held data drops it unread.
    b.on_reset(UNI, 9, p + 400, Some(p + 50), TY, now).unwrap();
    assert_eq!(got(&b), 150);
}

/// A receiving buffer that empties gives up a large capacity.
#[test]
fn drained_receive_buffers_release_their_capacity() {
    let (_a, mut b, now) = pair();
    let pre = preamble();
    let mut data = pre.clone();
    data.extend_from_slice(&vec![4; 2 * RECV_KEEP]);
    b.on_stream(stream(0, &data), TY, now).unwrap();
    let k = key(&b, UNI);
    let mut sink = vec![0u8; 4 * RECV_KEEP];
    let (n, _) = b.read(k, &mut sink).unwrap().expect("data");
    assert_eq!(n, 2 * RECV_KEEP);
    let r = b.streams.get(k).unwrap().recv.as_ref().unwrap();
    assert!(
        r.buf.memory() <= RECV_KEEP,
        "an idle stream keeps {} bytes",
        r.buf.memory()
    );
}

/// A local stream's receiving part leaves the buffer cap's `n_local`
/// when it is terminal, before the stream is discarded.
#[allow(
    clippy::many_single_char_names,
    reason = "a and b the two sessions, s and k a stream"
)]
#[test]
fn local_receiving_parts_leave_the_cap_when_terminal() {
    let (mut a, mut b, now) = pair();
    let s = a.open(Dir::Bidi).unwrap();
    assert_eq!(a.streams.local_recv_open(), 1);
    a.write(s, b"request").unwrap();
    pump(&mut a, &mut b, now);
    let r = b.accept(Dir::Bidi).unwrap().expect("stream");
    b.write(r, b"response").unwrap();
    b.finish(r).unwrap();
    pump(&mut a, &mut b, now);
    let mut sink = [0u8; 64];
    let mut fin = false;
    while !fin {
        let (_, f) = a.read(s, &mut sink).unwrap().expect("data");
        fin = f;
    }
    // The sending part is still open: the stream is not discarded.
    assert!(a.streams.get(s).is_some());
    assert_eq!(a.streams.local_recv_open(), 0);
}

/// Received data references the read buffers it arrived in within the
/// session's bound: pieces that are the only
/// data of buffers the reads moved on from are copied out, so that the
/// retired buffers kept alive stay within twice the bytes referenced; a
/// reader that leaves a rest of each buffer of a bulk transfer keeps every
/// piece referenced.
#[allow(
    clippy::many_single_char_names,
    reason = "a and b the two sessions, s and k a stream"
)]
#[test]
fn retired_read_buffers_stay_within_twice_the_referenced_bytes() {
    let (mut a, mut b, now) = pair();
    let s = a.open(Dir::Uni).unwrap();
    let mut out = TransmitBuf::default();
    let mut next = 1000;
    let mut now = now;
    // What A writes arrives in one fresh read buffer of 128 KiB.
    let mut deliver = |a: &mut SessionCore, b: &mut SessionCore, data: &[u8]| {
        now += Duration::from_millis(10);
        a.handle_timeout(now);
        a.write(s, data).unwrap();
        let mut wire = Vec::new();
        while a.wants_write(PipeId(0)) {
            a.poll_transmit(PipeId(0), now, &mut out);
            if out.is_empty() {
                break;
            }
            out.copy_to_vec(&mut wire);
        }
        next += 1;
        let backing = Backing {
            id: next,
            size: 128 * 1024,
        };
        let used = b.receive_shared(PipeId(0), &Bytes::from(wire), backing, now);
        assert!(used > 0);
        while b.poll_event().is_some() {}
        // B's acknowledgements and credit.
        let mut back = Vec::new();
        while b.wants_write(PipeId(0)) {
            b.poll_transmit(PipeId(0), now, &mut out);
            if out.is_empty() {
                break;
            }
            out.copy_to_vec(&mut back);
        }
        a.receive(PipeId(0), &back, now);
    };
    // Small pieces, one per buffer, unread.
    for _ in 0..20 {
        deliver(&mut a, &mut b, &[1; 5000]);
        let (retired, referenced) = b.recv_bound();
        assert!(
            retired <= 2 * referenced,
            "{retired} bytes of retired buffers for {referenced} referenced"
        );
    }
    let k = key(&b, UNI);
    let mut sink = vec![0u8; 1 << 20];
    while b.read(k, &mut sink).unwrap().is_some_and(|(n, _)| n > 0) {}
    // Bulk: 100 KiB per buffer, the reader leaves 10 KiB each time.
    let held =
        |b: &SessionCore| usize::try_from(b.streams.recv(k).map_or(0, RecvPart::held)).unwrap();
    let bulk = vec![2; 100 * 1024];
    for _ in 0..20 {
        deliver(&mut a, &mut b, &bulk);
        let n = held(&b).saturating_sub(10 * 1024);
        if n > 0 {
            b.read(k, &mut sink[..n]).unwrap().expect("data");
        }
        let unread = held(&b);
        assert_eq!(b.recv_bound().1, unread, "every unread byte referenced");
    }
}

/// A FIN-only frame needs no credit: in a
/// multipath session, a stream whose data used up its stream credit sends
/// its FIN at once when it is finished.
#[test]
fn fin_only_frames_go_without_credit() {
    let now = Instant::now();
    let mut small = config();
    small.initial_stream_receive_window = 4096;
    small.max_stream_receive_window = super::super::Cap::Fixed(4096);
    let mut a = SessionCore::new(config(), Role::Client, None, now).unwrap();
    let mut b = SessionCore::new(small, Role::Server, None, now).unwrap();
    a.attach_pipe(PipeId(0), Framing::ByteStream, now);
    b.attach_pipe(PipeId(0), Framing::ByteStream, now);
    pump(&mut a, &mut b, now);
    assert!(a.is_multipath());
    let s = a.open(Dir::Uni).unwrap();
    let mut now = now;
    // Exactly the stream's credit, in small writes.
    for _ in 0..1000 {
        let send = a.streams.send(s).unwrap();
        let left = send.max_data - send.offset - send.buf.len();
        if left == 0 && send.buf.is_empty() {
            break;
        }
        a.write(s, &vec![6; left.min(100) as usize]).unwrap();
        now += Duration::from_millis(5);
        a.handle_timeout(now);
        pump(&mut a, &mut b, now);
    }
    let send = a.streams.send(s).unwrap();
    assert!(
        send.offset == send.max_data && send.buf.is_empty(),
        "credit used up"
    );
    a.finish(s).unwrap();
    pump(&mut a, &mut b, now);
    let r = b.streams.recv(key(&b, UNI)).unwrap();
    assert_eq!(r.final_size, Some(r.received), "the FIN arrived");
}

/// A FIN-only frame needs no session credit: in a
/// multipath session whose credit is used up while another stream waits
/// for more, a finished stream's FIN still goes.
#[test]
fn fin_only_frames_go_without_session_credit() {
    let now = Instant::now();
    let mut small = config();
    small.initial_connection_receive_window = 16 * 1024;
    small.max_connection_receive_window = super::super::Cap::Fixed(16 * 1024);
    let mut a = SessionCore::new(config(), Role::Client, None, now).unwrap();
    let mut b = SessionCore::new(small, Role::Server, None, now).unwrap();
    a.attach_pipe(PipeId(0), Framing::ByteStream, now);
    b.attach_pipe(PipeId(0), Framing::ByteStream, now);
    pump(&mut a, &mut b, now);
    assert!(a.is_multipath());
    let mut out = TransmitBuf::default();
    let mut wire = Vec::new();
    // A's output reaches B; B's (its MAX_DATA) never reaches A.
    let mut deliver = |a: &mut SessionCore, b: &mut SessionCore| {
        while a.wants_write(PipeId(0)) {
            a.poll_transmit(PipeId(0), now, &mut out);
            if out.is_empty() {
                break;
            }
            wire.clear();
            out.copy_to_vec(&mut wire);
            b.receive(PipeId(0), &wire, now);
        }
        while b.poll_event().is_some() {}
    };
    let s1 = a.open(Dir::Uni).unwrap();
    let s2 = a.open(Dir::Uni).unwrap();
    // Both open (their preambles sent).
    a.write(s1, &[1; 10]).unwrap();
    a.write(s2, &[2; 10]).unwrap();
    deliver(&mut a, &mut b);
    // s1 takes exactly the rest of the session credit.
    for _ in 0..1000 {
        let f = a.streams.send_flow();
        let left = f.max.saturating_sub(f.used + f.buffered);
        if left == 0 {
            break;
        }
        a.write(s1, &vec![1; left.min(16 * 1024) as usize]).unwrap();
        deliver(&mut a, &mut b);
    }
    let f = a.streams.send_flow();
    assert_eq!((f.used, f.buffered), (f.max, 0), "credit used up");
    // s2 waits for credit; s1 ends.
    a.write(s2, &[2; 1000]).unwrap();
    a.finish(s1).unwrap();
    deliver(&mut a, &mut b);
    assert!(a.streams.session_stalled());
    let r = b.streams.recv(key(&b, UNI)).unwrap();
    assert_eq!(r.final_size, Some(r.received), "s1's FIN arrived");
}

/// The bound on retired read buffers is checked again when data is
/// consumed, not only when the reads move on: buffers shared by two streams,
/// one of which is read to its end
/// while nothing more arrives, are not kept alive by the other's halves
/// beyond twice the bytes still referenced.
#[test]
fn consumption_rechecks_the_read_buffer_bound() {
    let (mut a, mut b, now) = pair();
    let s1 = a.open(Dir::Uni).unwrap();
    let s2 = a.open(Dir::Uni).unwrap();
    let mut out = TransmitBuf::default();
    let (ones, twos) = (vec![1; 50 * 1024], vec![2; 50 * 1024]);
    let mut now = now;
    // 50 KiB of each stream arrive in one fresh read buffer of 128 KiB.
    for next in 0..8 {
        now += Duration::from_millis(10);
        a.handle_timeout(now);
        a.write(s1, &ones).unwrap();
        a.write(s2, &twos).unwrap();
        let mut wire = Vec::new();
        while a.wants_write(PipeId(0)) {
            a.poll_transmit(PipeId(0), now, &mut out);
            if out.is_empty() {
                break;
            }
            out.copy_to_vec(&mut wire);
        }
        let backing = Backing {
            id: 2000 + next,
            size: 128 * 1024,
        };
        b.receive_shared(PipeId(0), &Bytes::from(wire), backing, now);
        while b.poll_event().is_some() {}
        let mut back = Vec::new();
        while b.wants_write(PipeId(0)) {
            b.poll_transmit(PipeId(0), now, &mut out);
            if out.is_empty() {
                break;
            }
            out.copy_to_vec(&mut back);
        }
        a.receive(PipeId(0), &back, now);
    }
    // The first stream is read to its end; nothing more arrives.
    let k1 = key(&b, UNI);
    let mut sink = vec![0u8; 1 << 20];
    while b.read(k1, &mut sink).unwrap().is_some_and(|(n, _)| n > 0) {}
    let (retired, referenced) = b.recv_bound();
    assert!(
        retired <= 2 * referenced,
        "{retired} bytes of retired buffers for {referenced} referenced"
    );
}

/// A granted datagram the session queue refuses (the session's datagram
/// bytes are held by datagrams waiting for their streams) is dropped,
/// counted, and its grant handed back for a refund.
#[test]
fn a_granted_datagram_the_queue_refuses_is_refunded() {
    let now = Instant::now();
    let mut c = SessionCore::new(config(), Role::Server, None, now).unwrap();
    let cap = c.config.datagram_receive_bytes;
    // The bytes of datagrams held for streams not opened yet.
    c.dgram_mut().recv_bytes = cap;
    c.dgram_mut().held_bytes += 10;
    let mut staged = vec![super::super::ReceivedDatagram {
        stream: None,
        data: Bytes::from_static(&[1; 10]),
        granted: Some(10),
    }];
    assert_eq!(c.admit_datagrams(&mut staged), 10, "the grant is refunded");
    assert_eq!(c.stats.datagrams_dropped_recv, 1);
    assert_eq!(c.recv_datagram(c.now).unwrap(), None);
}

#[test]
fn pipe_snapshot_keeps_epoch_and_distinguishes_missing_lane_positions() {
    let (mut a, _, now) = pair();
    let period = a.config.epoch_policy.period.unwrap();
    let initial = a.pipe_info(PipeId(0)).unwrap();
    assert_eq!(initial.epoch, Some(0));
    assert_eq!(initial.replace_by, now.checked_add(period * 2));
    assert_eq!(initial.lanes, []);
    assert!(a.pipe_info(PipeId(99)).is_none());

    let outbound = a.out_mut(0).unwrap();
    let sent_lane = outbound.request_lane();
    assert!(outbound.lane_attached(sent_lane, Framing::ByteStream, now));
    let inbound_lane = (1 << 40) + 7;
    a.inp_mut(0)
        .unwrap()
        .add_lane(inbound_lane, Framing::ByteStream, 65535, now)
        .unwrap();
    let snapshot = a.pipe_info(PipeId(0)).unwrap();
    let sent = &snapshot.lanes[1];
    assert_eq!(sent.lane.0, sent_lane);
    assert_eq!(
        (
            sent.position_sent,
            sent.position_acked,
            sent.position_received
        ),
        (Some(0), Some(0), None)
    );
    let received = &snapshot.lanes[2];
    assert_eq!(received.lane.0, inbound_lane);
    assert_eq!(
        (
            received.position_sent,
            received.position_acked,
            received.position_received
        ),
        (None, None, Some(0))
    );

    let outbound = a.out_mut(0).unwrap();
    let amount = 1 << 40;
    outbound.batch_sent(sent_lane, amount, amount, None);
    let no_ack = super::super::lanes::lane_infos(Some(outbound), None, false);
    assert_eq!(no_ack[1].position_acked, None);
    let later = a.pipe_info(PipeId(0)).unwrap();
    assert_eq!(later.lanes[1].position_sent, Some(amount));
    assert_eq!(later.bytes_sent - snapshot.bytes_sent, amount);
    assert_eq!(later.records_sent - snapshot.records_sent, amount);
}

#[test]
fn idle_timer_uses_the_configured_duration_and_never_fires_on_clock_overflow() {
    let now = Instant::now();
    let mut peer = config();
    peer.max_idle_timeout = None;
    for idle in [Duration::from_micros(1001), Duration::MAX] {
        let mut local = config();
        local.max_idle_timeout = Some(idle);
        let mut a = SessionCore::new(local, Role::Client, None, now).unwrap();
        let mut b = SessionCore::new(peer.clone(), Role::Server, None, now).unwrap();
        a.attach_pipe(PipeId(0), Framing::ByteStream, now);
        b.attach_pipe(PipeId(0), Framing::ByteStream, now);
        pump(&mut a, &mut b, now);
        assert_eq!(a.idle_timeout(), Some(idle));
        assert_eq!(a.idle_deadline, now.checked_add(idle));
        a.tick(now + Duration::from_secs(1));
        if now.checked_add(idle).is_none() {
            assert!(a.error().is_none());
        }
    }
}

#[test]
fn session_errors_keep_close_data_and_concrete_pipe_sources() {
    use crate::{DetailKey, PipeFailure, SessionError, proto::TransportErrorCode as Code};
    use std::error::Error as _;

    let (_, mut b, now) = pair();
    b.on_connection_close(
        crate::proto::frame::ConnectionClose {
            application: false,
            error_code: Code::PROTOCOL_VIOLATION.0,
            frame_type: 1 << 40,
            reason: b"broken\nlimit=1099511627776 offset=1",
        },
        now,
    );
    assert_eq!(
        b.error(),
        Some(&SessionError::TransportClosed {
            code: Code::PROTOCOL_VIOLATION,
            frame_type: 1 << 40,
            reason: Bytes::from_static(b"broken"),
            details: vec![(DetailKey::Limit, 1 << 40), (DetailKey::Offset, 1)],
            remote: true,
        })
    );

    let (_, mut b, now) = pair();
    b.on_connection_close(
        crate::proto::frame::ConnectionClose {
            application: false,
            error_code: Code::ZMUX_RESUME_FAILED.0,
            frame_type: 0,
            reason: b"resume mismatch",
        },
        now,
    );
    assert_eq!(
        b.error(),
        Some(&SessionError::ResumeFailed {
            reason: Bytes::from_static(b"resume mismatch"),
            remote: true,
        })
    );
    let last = PipeFailure::JoinRefused;
    for end in [
        SessionError::ResumeTimeout { last: Some(last) },
        SessionError::PipesLost { last: Some(last) },
    ] {
        assert_eq!(
            end.source()
                .and_then(|source| source.downcast_ref::<PipeFailure>()),
            Some(&last)
        );
    }
    assert!(SessionError::PipesLost { last: None }.source().is_none());
}

#[test]
fn stream_reset_and_stop_preserve_their_codes_and_reliable_size() {
    use crate::{StreamError, VarInt};
    let (mut a, mut b, now) = pair();
    let mut data = preamble();
    let base = data.len() as u64;
    data.extend_from_slice(b"abc");
    b.on_stream(stream(0, &data), TY, now).unwrap();
    b.on_reset(UNI, 42, base + 3, Some(base + 2), TY, now)
        .unwrap();
    let recv = key(&b, UNI);
    let mut buf = [0; 3];
    assert_eq!(b.read(recv, &mut buf).unwrap().unwrap().0, 2);
    assert_eq!(
        b.read(recv, &mut buf),
        Err(StreamError::Reset {
            code: VarInt::from_u32(42),
            reliable_size: 2
        })
    );

    let send = a.open(Dir::Uni).unwrap();
    a.write(send, b"open").unwrap();
    pump(&mut a, &mut b, now);
    let id = a.stream_id(send).unwrap();
    a.on_stop_sending(
        crate::proto::frame::StopSending {
            stream_id: id,
            error_code: 43,
        },
        TY,
        now,
    )
    .unwrap();
    assert_eq!(
        a.write(send, b"x"),
        Err(StreamError::Stopped(VarInt::from_u32(43)))
    );
}

#[test]
fn resume_grace_uses_the_configured_duration_before_the_peer_cap() {
    let now = Instant::now();
    let mut local = config();
    local.resume_timeout = Some(Duration::from_micros(1001));
    let mut peer = config();
    peer.locator = b"server".to_vec();
    peer.resume_timeout = Some(Duration::MAX);
    let mut a = SessionCore::new(local, Role::Client, None, now).unwrap();
    let mut b = SessionCore::new(peer, Role::Server, None, now).unwrap();
    a.attach_pipe(PipeId(0), Framing::ByteStream, now);
    b.attach_pipe(PipeId(0), Framing::ByteStream, now);
    pump(&mut a, &mut b, now);
    assert!(a.features.resume && b.features.resume);
    a.suspend(now);
    b.suspend(now);
    assert_eq!(
        a.mp.as_ref().unwrap().suspension().deadline(),
        now.checked_add(Duration::from_micros(1001))
    );
    assert_eq!(
        b.mp.as_ref().unwrap().suspension().deadline(),
        now.checked_add(Duration::from_millis(2))
    );
}
