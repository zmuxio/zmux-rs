//! Receive-path regressions that need frames no compliant sender writes in
//! that order: they call the frame handlers of a multipath session
//! directly.

use std::time::{Duration, Instant};

use super::super::stream::{RecvPart, make_id};
use bytes::Bytes;

use super::super::{Backing, Config, PipeAuth, PipeId, Role, SessionCore, StreamKey, TransmitBuf};
use crate::proto::frame::{Dir, Stream};
use crate::proto::payload::WirePreamble;
use crate::proto::record::Framing;

/// The frame type handed to the handlers (only error details use it).
const TY: u64 = 0x08;

fn config() -> Config {
    Config {
        session_policy: crate::SessionPolicy::with_steady_attachments(4),
        pipe_auth: PipeAuth::psk(*b"0123456789abcdef0123456789abcdef"),
        max_idle_timeout: Some(Duration::from_secs(600)),
        max_incoming_uni_streams: crate::proto::session::UniCredit::Limit(4),
        ..Config::default()
    }
}

/// A multipath pair on pipe 0, established.
fn pair() -> (SessionCore, SessionCore, Instant) {
    pair_framed(Framing::ByteStream)
}

fn pair_framed(framing: Framing) -> (SessionCore, SessionCore, Instant) {
    pair_with_config(config(), framing, Instant::now())
}

fn pair_with_config(
    config: Config,
    framing: Framing,
    now: Instant,
) -> (SessionCore, SessionCore, Instant) {
    let mut a = SessionCore::new(config.clone(), Role::Client, None, now).unwrap();
    let mut b = SessionCore::new(config, Role::Server, None, now).unwrap();
    a.attach_pipe(PipeId(0), framing, now);
    b.attach_pipe(PipeId(0), framing, now);
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
                if out.is_records() {
                    let mut offset = 0;
                    for &len in out.message_lens() {
                        let message = crate::proto::ReceivedRecord::copy_from_slice(
                            &wire[offset..offset + len],
                        );
                        to.receive_message(PipeId(0), message, now);
                        offset += len;
                    }
                } else {
                    to.receive(PipeId(0), &wire, now);
                }
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

#[test]
fn owned_message_keeps_the_carrier_allocation_until_the_last_view() {
    let (_, mut recv, now) = pair_framed(Framing::Records);
    let mut payload = preamble();
    let expected = [42; 5000];
    payload.extend_from_slice(&expected);
    let frame = crate::proto::frame::Frame::Stream(stream(0, &payload));
    let mut record = vec![0; frame.encoded_len()];
    frame.encode(&mut record).unwrap();
    let allocation = record[record.len() - expected.len()..].as_ptr();
    recv.receive_message(
        PipeId(0),
        crate::proto::ReceivedRecord::from_vec(record),
        now,
    );
    let (chunk, _) = recv
        .read_chunk(key(&recv, UNI), expected.len())
        .unwrap()
        .unwrap();
    assert_eq!(chunk.as_ptr(), allocation);
    drop(recv);
    assert_eq!(chunk.as_ref(), expected);
}

#[test]
fn nested_record_keeps_the_outer_receive_backing() {
    let (_, mut outer, now) = pair();
    let (_, mut inner, _) = pair();
    let expected = [42; 5000];
    let mut inner_payload = preamble();
    inner_payload.extend_from_slice(&expected);
    let mut outer_payload = preamble();
    append_stream_record(&mut outer_payload, &inner_payload);
    let mut wire = Vec::new();
    append_stream_record(&mut wire, &outer_payload);
    let mut buffer = crate::ChunkBuffer::with_capacity(wire.capacity() * 2);
    buffer.extend_from_slice(&wire);
    let wire = buffer.publish();
    let backing = wire.backing;
    let original = wire.slice(wire.len() - expected.len()..);

    assert!(backing.size > wire.len());
    assert_eq!(outer.receive_shared(PipeId(0), &wire, now), wire.len());
    let (record, _) = outer
        .read_segment(key(&outer, UNI), usize::MAX)
        .unwrap()
        .unwrap();
    inner.receive_segment(PipeId(0).into(), &record, now);
    let (data, _) = inner
        .read_segment(key(&inner, UNI), usize::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(data.backing, backing);
    assert_eq!(data.bytes.as_ptr(), original.as_ptr());
    drop((wire, record, outer, inner));
    assert_eq!(data.bytes.as_ref(), expected);
}

fn append_stream_record(wire: &mut Vec<u8>, data: &[u8]) {
    let frame = crate::proto::frame::Frame::Stream(stream(0, data));
    let len = frame.encoded_len();
    let at = wire.len();
    let size = crate::proto::record::size_len(len as u64);
    wire.resize(at + size + len, 0);
    crate::proto::record::encode_size(len as u64, &mut wire[at..]).unwrap();
    frame.encode(&mut wire[at + size..]).unwrap();
}

#[test]
fn a_shared_receive_root_is_charged_once_and_released_when_sparse() {
    const LEN: usize = 5000;
    let (_, mut recv, now) = pair_framed(Framing::Records);
    let mut payload = preamble();
    payload.resize(payload.len() + LEN, 42);
    let frame = |stream_id| {
        crate::proto::frame::Frame::Stream(Stream {
            stream_id,
            ..stream(0, &payload)
        })
    };
    let next = make_id(1, Dir::Uni, true);
    let first_len = frame(UNI).encoded_len();
    let mut record = vec![0; first_len + frame(next).encoded_len()];
    frame(UNI).encode(&mut record[..first_len]).unwrap();
    frame(next).encode(&mut record[first_len..]).unwrap();
    let capacity = record.capacity();
    recv.receive_message(
        PipeId(0),
        crate::proto::ReceivedRecord::from_vec(record),
        now,
    );
    assert_eq!(recv.receive_root_capacity(), capacity);

    let mut sink = [0; LEN];
    assert_eq!(
        recv.read(key(&recv, UNI), &mut sink).unwrap().unwrap().0,
        LEN
    );
    assert_eq!(recv.receive_root_capacity(), 5000);
    assert_eq!(
        recv.read(key(&recv, next), &mut sink).unwrap().unwrap().0,
        LEN
    );
    assert_eq!(sink, [42; LEN]);
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
    b.on_stream(stream(3, &data), TY, now, None).unwrap();
    assert_eq!(b.streams.recv_flow().buffered, (p - 3 + 100) as u64);
    b.on_stream(stream(0, &pre), TY, now, None).unwrap();
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
        b.on_stream(stream(off, &[1]), TY, now, None).unwrap();
    }
    // A frame that fills the gap between two ranges joins them.
    b.on_stream(stream(1000, &[1; 500]), TY, now, None).unwrap();
    b.on_stream(stream(1500, &[1; 500]), TY, now, None).unwrap();
    let r = b.streams.get(key(&b, UNI)).unwrap().recv.as_ref().unwrap();
    assert_eq!(r.buf.gaps(&b.receive), 1);
    assert_eq!(r.held() - r.buf.len() as u64, 1200);
    let tokens = b.budget.tokens();
    // Small ranges at alternating offsets: held, never charged.
    for i in 0..10_000u64 {
        b.on_stream(stream(150_000 + 2 * i, &[3]), TY, now, None)
            .unwrap();
    }
    assert_eq!(b.budget.tokens(), tokens);
    // Filling the gaps joins them all.
    for i in 0..10_000u64 {
        b.on_stream(stream(150_001 + 2 * i, &[3]), TY, now, None)
            .unwrap();
    }
    let r = b.streams.get(key(&b, UNI)).unwrap().recv.as_ref().unwrap();
    assert_eq!(r.buf.gaps(&b.receive), 2);
}

/// Bytes beyond a gap release session credit when they arrive; the gap
/// releases nothing before its own bytes arrive.
#[test]
fn gap_bytes_release_no_credit_before_they_arrive() {
    let (_a, mut b, now) = pair();
    let released = b.streams.recv_flow().released;
    b.on_stream(stream(100_000, &[5; 1000]), TY, now, None)
        .unwrap();
    assert_eq!(b.streams.recv_flow().released - released, 1000);
    b.on_stream(stream(50_000, &[5; 1000]), TY, now, None)
        .unwrap();
    assert_eq!(b.streams.recv_flow().released - released, 2000);
}

/// `bytes_received` counts distinct application bytes and never
/// decreases, also when a reset drops held data.
#[test]
fn bytes_received_is_distinct_and_monotonic() {
    let (_a, mut b, now) = pair();
    let pre = preamble();
    let p = pre.len() as u64;
    b.on_stream(stream(p + 100, &[1; 100]), TY, now, None)
        .unwrap();
    let k = key(&b, UNI);
    let got = |b: &SessionCore| b.stream_stats(k).unwrap().bytes_received;
    assert_eq!(got(&b), 0, "no application bytes before the preamble");
    b.on_stream(stream(0, &pre), TY, now, None).unwrap();
    assert_eq!(got(&b), 100);
    b.on_stream(stream(p + 150, &[1; 100]), TY, now, None)
        .unwrap();
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
    let size = 128 * 1024;
    data.extend_from_slice(&vec![4; size]);
    b.on_stream(stream(0, &data), TY, now, None).unwrap();
    let k = key(&b, UNI);
    let mut sink = vec![0u8; size];
    let (n, _) = b.read(k, &mut sink).unwrap().expect("data");
    assert_eq!(n, size);
    assert_eq!(b.receive_root_capacity(), 0);
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
        let used = b.receive_buffer(PipeId(0), &Bytes::from(wire), backing, now);
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
        b.receive_buffer(PipeId(0), &Bytes::from(wire), backing, now);
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
        sequence: None,
        stream: None,
        data: crate::Chunk::from_static(&[1; 10]),
        granted: Some(10),
    }];
    assert_eq!(c.admit_datagrams(&mut staged), 10, "the grant is refunded");
    assert_eq!(c.stats().datagrams_dropped_recv, 1);
    assert_eq!(c.recv_datagram(c.now).unwrap(), None);
}

#[test]
fn pipe_snapshot_keeps_epoch_and_distinguishes_missing_lane_positions() {
    let (mut a, _, now) = pair();
    let period = a.config.epoch_policy.period.unwrap();
    let initial = a.pipe_info(PipeId(0)).unwrap();
    assert_eq!(initial.epoch, Some(0));
    assert_eq!(initial.replace_by, now.checked_add(period * 2));
    assert_eq!(initial.lanes, [] as [crate::LaneStats; 0]);
    assert!(a.pipe_info(PipeId(99)).is_none());

    let outbound = a.out_mut(0).unwrap();
    let sent_lane = outbound.request_lane();
    assert!(outbound.lane_attached(sent_lane, Framing::ByteStream));
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
    b.on_stream(stream(0, &data), TY, now, None).unwrap();
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
fn a_shared_listener_advertises_more_streams_before_the_peer_blocks() {
    use super::super::{BIDI, UNI, config::STAGED_UNI_STREAMS};
    use crate::proto::memory::Ledger;

    let now = Instant::now();
    let ledger = Ledger::new(Some(crate::DEFAULT_MEMORY_BUDGET), None);
    let config = Config::default();
    let mut sender = SessionCore::new(config.clone(), Role::Client, None, now).unwrap();
    let mut receiver =
        SessionCore::new_in(config.into(), Role::Server, None, now, Some(ledger), 0).unwrap();
    sender.attach_pipe(PipeId(0), Framing::ByteStream, now);
    receiver.attach_pipe(PipeId(0), Framing::ByteStream, now);
    pump(&mut sender, &mut receiver, now);
    let initial = sender.streams.local_dir(BIDI).peer_max;
    let (staged, target) = STAGED_UNI_STREAMS;
    assert!(initial > 4);
    assert_eq!(sender.streams.local_dir(UNI).peer_max, staged);

    for i in 1..=initial.div_ceil(2) {
        let key = sender.open(Dir::Bidi).unwrap();
        assert_eq!(sender.write(key, b"x").unwrap(), 1);
        pump(&mut sender, &mut receiver, now);
        if i < initial.div_ceil(2) {
            assert_eq!(sender.streams.local_dir(BIDI).peer_max, initial);
        }
    }
    assert!(sender.streams.local_dir(BIDI).peer_max > initial);
    assert_eq!(receiver.streams.remote_dir(BIDI).blocked_seen, None);
    assert_eq!(receiver.accept(Dir::Uni).unwrap(), None);
    pump(&mut sender, &mut receiver, now);
    assert_eq!(sender.streams.local_dir(UNI).peer_max, target);
}

#[test]
fn stop_and_reset_keep_advertised_max_data_backed() {
    use crate::VarInt;

    for stop_first in [false, true] {
        let (_sender, mut recv, now) = pair();
        let pre = preamble();
        let start = pre.len() as u64;
        recv.on_stream(stream(0, &pre), TY, now, None).unwrap();
        let key = key(&recv, UNI);
        recv.on_stream(stream(start + 32, &[1; 8]), TY, now, None)
            .unwrap();
        if stop_first {
            recv.stop(key, VarInt::from_u32(43)).unwrap();
        }
        recv.on_reset(UNI, 42, start + 64, Some(start + 36), TY, now)
            .unwrap();
        if !stop_first {
            recv.stop(key, VarInt::from_u32(43)).unwrap();
        }
        assert!(recv.streams.recv_flow().has_protected_history());

        let limit = recv.streams.recv_flow().limit_sent;
        assert_eq!(recv.reserve_receive_credit(0), limit);
        let wanted = limit + 128;
        let granted = recv.reserve_receive_credit(wanted);
        assert_eq!(granted, wanted);
        recv.streams.max_data_written(granted, now);

        recv.on_reset(UNI, 42, start + 64, Some(start + 16), TY, now)
            .unwrap();
        assert!(!recv.streams.recv_flow().has_protected_history());
        assert_eq!(recv.reserve_receive_credit(0), granted);
        recv.on_stream(stream(start, &[2; 40]), TY, now, None)
            .unwrap();
        assert_eq!(
            recv.streams.recv_flow().unsettled(granted),
            granted - start - 64
        );
    }
}

#[test]
fn fragmented_receive_heap_stays_within_promised_positions() {
    use super::super::{memory::MIN_INITIAL, recv_store::ReceiveStore};
    use proptest::{
        collection::vec,
        prelude::*,
        test_runner::{Config as PropConfig, RngSeed, TestRunner},
    };

    let mut runner = TestRunner::new(PropConfig {
        cases: 96,
        rng_seed: RngSeed::Fixed(0x7A22_C190),
        failure_persistence: None,
        ..PropConfig::default()
    });
    // Every case fixes the connection's receive promise P. The two
    // fragment phases straddle a STOP and a reliable RESET in either order.
    let fragment = (0..MIN_INITIAL, 1usize..128, any::<u8>());
    let fragments = vec(fragment, 64..192);
    let now = Instant::now();
    runner
        .run(
            &(fragments.clone(), fragments, 0..MIN_INITIAL, any::<bool>()),
            |(before, after, cut, stop_first)| {
                let config = Config {
                    initial_connection_receive_window: MIN_INITIAL,
                    ..config()
                };
                let (_sender, mut recv, _) = pair_with_config(config, Framing::ByteStream, now);
                let pre = preamble();
                let base = pre.len() as u64;
                let reliable = base + cut % (MIN_INITIAL - base);
                recv.on_stream(stream(0, &pre), TY, now, None).unwrap();
                let key = key(&recv, UNI);
                let limit = recv.streams.recv_flow().limit_sent;
                prop_assert_eq!(limit, MIN_INITIAL);
                let check = |recv: &SessionCore| {
                    let queue = recv.streams.recv(key).map_or(0, RecvPart::memory);
                    let heap_bytes = recv.receive.heap_bytes() + queue;
                    prop_assert!(
                        heap_bytes as u64 <= limit * ReceiveStore::POSITION_COST,
                        "receive heap {heap_bytes} bytes exceeds the {limit}-position promise"
                    );
                    Ok(())
                };
                let deliver = |recv: &mut SessionCore, (offset, len, byte): (u64, usize, u8)| {
                    let offset = base + offset % (limit - base);
                    let len = len.min(usize::try_from(limit - offset).unwrap());
                    recv.on_stream(stream(offset, &[byte; 128][..len]), TY, now, None)
                        .unwrap();
                    check(recv)
                };
                // Force holes and overlap, so even a shrunk counterexample
                // exercises arrivals before and beyond the contiguous prefix.
                for offset in (1..64).step_by(2) {
                    deliver(&mut recv, (offset, 1, 0x71))?;
                }
                deliver(&mut recv, (8, 24, 0x25))?;
                for fragment in before {
                    deliver(&mut recv, fragment)?;
                }
                if stop_first {
                    recv.stop(key, crate::VarInt::from_u32(43)).unwrap();
                } else {
                    recv.on_reset(UNI, 42, limit, Some(reliable), TY, now)
                        .unwrap();
                }
                check(&recv)?;
                for fragment in after {
                    deliver(&mut recv, fragment)?;
                }
                if stop_first {
                    recv.on_reset(UNI, 42, limit, Some(reliable), TY, now)
                        .unwrap();
                } else {
                    recv.stop(key, crate::VarInt::from_u32(43)).unwrap();
                }
                check(&recv)?;
                recv.on_reset(UNI, 42, limit, Some(base), TY, now).unwrap();
                check(&recv)
            },
        )
        .unwrap();
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

#[cfg(all(feature = "test-hooks", feature = "tokio", not(loom)))]
#[test]
fn refused_splice_read_preserves_reliable_offset_and_credit() {
    let (mut sender, mut receiver, now) = pair();
    let open = sender.open(Dir::Bidi).unwrap();
    sender.write(open, b"unread").unwrap();
    pump(&mut sender, &mut receiver, now);
    let key = receiver.accept(Dir::Bidi).unwrap().unwrap();
    assert!(receiver.test_read_loan_slots(0));
    let before = receiver.stream_stats(key).unwrap();
    let held = receiver.receive_root_capacity();
    let refused = receiver.read_splice_chunk(
        key,
        6,
        |_| panic!("destination root check ran with no receive loan"),
        |_| false,
    );
    assert!(matches!(refused, Err(crate::StreamError::BorrowLimit)));
    let after = receiver.stream_stats(key).unwrap();
    assert_eq!(after.bytes_read, before.bytes_read);
    assert_eq!(after.recv_buffered, before.recv_buffered);
    assert_eq!(receiver.receive_root_capacity(), held);
    let (_, _, chunk) = receiver
        .read_splice_chunk(key, 6, |_| unreachable!(), |size| size == 6)
        .unwrap()
        .unwrap();
    assert!(chunk.copied);
    assert_eq!(&*chunk.data, b"unread");
    assert_eq!(receiver.stream_stats(key).unwrap().bytes_read, 6);
}
