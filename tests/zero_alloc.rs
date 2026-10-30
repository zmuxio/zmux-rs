//! The wire layer allocates nothing per frame: encoding into caller buffers,
//! zero-copy decoding, and record parsing with a warmed-up reader are
//! measured with a counting global allocator. The same allocator tracks the
//! live heap bytes of each thread: a whole session lifecycle (core pair, and
//! the tokio driver over in-memory carriers) gives back every byte it took.

// A global allocator can only be implemented with unsafe code: the trait and
// the System calls it forwards to are unsafe. Nothing else here uses it.
#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use zmux::proto::frame::{
    Frame, MaxStreamData, PipeAck, PipeAckEntry, PipeLane, Priority, PriorityUpdate, Stream,
    StreamHeader,
};
use zmux::proto::record::{Event, RecordBuilder, RecordReader};
use zmux::proto::{Frames, Gates, keys};

struct Counting;

thread_local! {
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
    /// Bytes allocated minus bytes freed on this thread.
    static LIVE: Cell<i64> = const { Cell::new(0) };
}

fn count() {
    // `try_with` because the allocator also runs while threads shut down.
    let _ = ALLOCATIONS.try_with(|c| c.set(c.get() + 1));
}

fn live(delta: i64) {
    let _ = LIVE.try_with(|c| c.set(c.get() + delta));
}

// SAFETY: every method forwards to the system allocator with the caller's
// arguments unchanged, so the GlobalAlloc contract is the System's.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count();
        live(layout.size() as i64);
        // SAFETY: forwarded unchanged (see the impl).
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count();
        live(layout.size() as i64);
        // SAFETY: forwarded unchanged (see the impl).
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        count();
        live(new_size as i64 - layout.size() as i64);
        // SAFETY: forwarded unchanged (see the impl).
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        live(-(layout.size() as i64));
        // SAFETY: forwarded unchanged (see the impl).
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Counting = Counting;

/// Runs `f` and returns its result with the change of this thread's live
/// heap bytes: what it allocated and did not free.
fn live_bytes<R>(f: impl FnOnce() -> R) -> (R, i64) {
    let before = LIVE.with(Cell::get);
    let r = std::hint::black_box(f());
    (r, LIVE.with(Cell::get) - before)
}

/// Runs `f` and returns its result with the number of allocations it made
/// on this thread.
fn allocations<R>(f: impl FnOnce() -> R) -> (R, u64) {
    let before = ALLOCATIONS.with(Cell::get);
    let r = std::hint::black_box(f());
    (r, ALLOCATIONS.with(Cell::get) - before)
}

const ACK_ENTRIES: [PipeAckEntry; 3] = [
    PipeAckEntry {
        pipe_id: 0,
        lane: 0,
        position: 1_048_576,
        ack_delay: 1500,
    },
    PipeAckEntry {
        pipe_id: 2,
        lane: 1,
        position: 65_600,
        ack_delay: 250,
    },
    PipeAckEntry {
        pipe_id: 5,
        lane: 0,
        position: 7,
        ack_delay: 1,
    },
];

fn sample_frames(payload: &[u8]) -> Vec<Frame<'_>> {
    vec![
        Frame::Stream(Stream::new(4, 1 << 20, payload, false)),
        Frame::Stream(Stream::new(8, 0, &payload[..1024], true)),
        Frame::MaxStreamData(MaxStreamData {
            stream_id: 4,
            maximum: 4 << 20,
        }),
        Frame::PipeAck(PipeAck::new(&ACK_ENTRIES)),
        Frame::PipeLane(PipeLane {
            lane_key: [0x7a; 16],
            pipe_id: 2,
            lane: 1,
        }),
        Frame::PriorityUpdate(PriorityUpdate {
            stream_id: 4,
            sequence: 2,
            priority: Priority::new(0, true).unwrap(),
        }),
    ]
}

#[test]
fn encoding_does_not_allocate() {
    let payload = vec![0x5a; 16 * 1024];
    let frames = sample_frames(&payload);
    let mut buf = vec![0u8; 64 * 1024];
    let (written, n) = allocations(|| {
        let mut total = 0;
        for _ in 0..100 {
            for f in &frames {
                total += f.encode(&mut buf).unwrap();
            }
            let header = StreamHeader {
                stream_id: 4,
                offset: 1 << 30,
                len: 16_384,
                fin: false,
                explicit_offset: true,
                explicit_len: true,
            };
            total += header.encode(&mut buf).unwrap();
        }
        total
    });
    assert!(written > 0);
    assert_eq!(n, 0, "encoding allocated {n} times");
}

#[test]
fn decoding_does_not_allocate() {
    let payload = vec![0x5a; 16 * 1024];
    let mut encoded = Vec::new();
    for f in sample_frames(&payload) {
        let mut buf = vec![0u8; f.encoded_len()];
        f.encode(&mut buf).unwrap();
        encoded.push(buf);
    }
    let (frames, n) = allocations(|| {
        let mut count = 0;
        for _ in 0..100 {
            for bytes in &encoded {
                let (frame, len) = Frame::decode(bytes, &Gates::ALL).unwrap();
                assert_eq!(len, bytes.len());
                if let Frame::PipeAck(ack) = frame {
                    count += ack.entries().count();
                }
                count += 1;
            }
        }
        count
    });
    assert!(frames > 0);
    assert_eq!(n, 0, "decoding allocated {n} times");
}

/// A 256 KiB batch of records: 16 KiB STREAM frames and control frames.
fn batch() -> Vec<u8> {
    let payload = vec![0x42u8; 16 * 1024];
    let mut out = vec![0u8; 300 * 1024];
    let mut at = 0;
    let mut offset = 0;
    while at < 256 * 1024 {
        let mut record = RecordBuilder::new(&mut out[at..], 65_535).unwrap();
        record
            .push(&Frame::MaxStreamData(MaxStreamData {
                stream_id: 0,
                maximum: offset + (1 << 22),
            }))
            .unwrap();
        record
            .push(&Frame::Stream(Stream::new(0, offset, &payload, false)))
            .unwrap();
        at += record.finish().unwrap();
        offset += payload.len() as u64;
    }
    out.truncate(at);
    out
}

fn tally(event: Event<'_>, data: &mut u64, records: &mut u64) {
    match event {
        Event::Frame(Frame::Stream(s)) => *data += s.data.len() as u64,
        Event::RecordEnd { .. } => *records += 1,
        Event::Frame(_) => {}
    }
}

/// Feeds the batch in reads of `read_size` bytes with `read`, which copies
/// records that span reads into the reader's buffer.
fn parse(reader: &mut RecordReader, bytes: &[u8], read_size: usize) -> (u64, u64) {
    let (mut data, mut records) = (0u64, 0u64);
    for chunk in bytes.chunks(read_size) {
        let mut input = chunk;
        while let Some(event) = reader.read(&mut input, &Gates::ALL).unwrap() {
            tally(event, &mut data, &mut records);
        }
    }
    (data, records)
}

/// Feeds the batch like a driver with a 128 KiB read buffer: complete
/// records are decoded in place and the incomplete tail is moved to the
/// front before the next read.
fn parse_in_place(
    reader: &mut RecordReader,
    bytes: &[u8],
    read_size: usize,
    buf: &mut [u8],
) -> (u64, u64) {
    let (mut data, mut records) = (0u64, 0u64);
    let (mut filled, mut src) = (0, bytes);
    loop {
        let n = read_size.min(src.len()).min(buf.len() - filled);
        buf[filled..filled + n].copy_from_slice(&src[..n]);
        src = &src[n..];
        filled += n;
        let mut input = &buf[..filled];
        while let Some(event) = reader.read_complete(&mut input, &Gates::ALL).unwrap() {
            tally(event, &mut data, &mut records);
        }
        let left = input.len();
        buf.copy_within(filled - left..filled, 0);
        filled = left;
        if n == 0 {
            return (data, records);
        }
    }
}

#[test]
fn record_parsing_does_not_allocate() {
    let bytes = batch();
    // Reads of 1000 bytes split frames and headers everywhere; 64 KiB
    // reads are what a driver's read buffer delivers.
    for read_size in [1000, 7, 64 * 1024, bytes.len()] {
        let mut reader = RecordReader::new(65_535);
        // Warm up: the reader's buffer for split control frames reaches its
        // steady-state capacity.
        parse(&mut reader, &bytes, read_size);
        let ((data, records), n) = allocations(|| parse(&mut reader, &bytes, read_size));
        assert!(records > 10 && data > 200 * 1024);
        assert_eq!(
            n, 0,
            "record parsing in reads of {read_size} allocated {n} times"
        );
        let mut buf = vec![0u8; 128 * 1024];
        let mut reader = RecordReader::new(65_535);
        let ((data, records), n) =
            allocations(|| parse_in_place(&mut reader, &bytes, read_size, &mut buf));
        assert!(records > 10 && data > 200 * 1024);
        assert_eq!(
            n, 0,
            "in-place parsing in reads of {read_size} allocated {n} times"
        );
    }
    // Iterating over a complete record body.
    let (size, width) = zmux::proto::varint::decode(&bytes).unwrap();
    let body = &bytes[width..width + size as usize];
    let (frames, n) = allocations(|| Frames::new(body, Gates::ALL).map(Result::unwrap).count());
    assert_eq!(frames, 2);
    assert_eq!(n, 0);
}

#[test]
fn the_counter_sees_allocations() {
    let (v, n) = allocations(|| vec![1u8; 100]);
    assert_eq!(v.len(), 100);
    assert!(n >= 1);
}

#[test]
fn key_schedule_does_not_allocate() {
    let (ok, n) = allocations(|| {
        let secret = keys::session_secret(&[1; 16], &[2; 16], &[3; 32], &[]);
        let k = keys::SessionKeys::derive(&secret);
        let mut frame = [
            0x9a, 0x24, 0xde, 0x36, 1, 0x4c, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        keys::sign_join(&k.join_initiator, &mut frame, &[]);
        keys::verify_join(&k.join_initiator, &frame, &[])
    });
    assert!(ok);
    assert_eq!(n, 0);
}

#[path = "common/core_pair.rs"]
mod core_pair;
#[path = "common/join.rs"]
mod join;

// ---- the session core ---------------------------------------------------------

mod core_bulk {
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use zmux::proto::frame::Dir;
    use zmux::proto::record::Framing;
    use zmux::proto::session::{Config, PipeId, RoleConfig, SessionCore, StreamKey};

    const P0: PipeId = PipeId(0);

    /// `memory_usage` feeds the memory budgets: it counts what an idle
    /// session really holds (its inline state and heap), not more.
    #[test]
    fn memory_usage_matches_the_heap_of_an_idle_session() {
        let now = Instant::now();
        let (s, held) = crate::live_bytes(|| {
            let mut s = Box::new(
                SessionCore::new(Config::default(), RoleConfig::Initiator, None, now).unwrap(),
            );
            s.attach_pipe(P0, Framing::ByteStream, now);
            s
        });
        let counted = s.memory_usage() as i64;
        assert!(
            (counted - held).abs() <= held / 20,
            "memory_usage {counted} B, heap {held} B"
        );
    }

    type Pair = crate::core_pair::CorePair;

    /// A pair whose B takes four unidirectional streams at once.
    fn pair() -> Pair {
        let mut b = Config::default();
        b.max_incoming_uni_streams = Some(4);
        Pair::new(Config::default(), b)
    }

    /// Moves `total` bytes on one stream; `chunk` writes either copy
    /// slices or reference a shared buffer.
    fn transfer(
        p: &mut Pair,
        send: StreamKey,
        recv: &mut Option<StreamKey>,
        total: usize,
        shared: Option<&Bytes>,
    ) -> (usize, u64) {
        let data = [7u8; 16 * 1024];
        let mut sink = [0u8; 16 * 1024];
        let mut written = 0;
        let mut read = 0;
        let records_before = p.a.stats().records_sent;
        while read < total {
            while written < total {
                let n = match shared {
                    Some(b) => {
                        p.a.write_chunk(send, b.slice(..(total - written).min(b.len())))
                            .unwrap()
                    }
                    None => {
                        p.a.write(send, &data[..(total - written).min(data.len())])
                            .unwrap()
                    }
                };
                if n == 0 {
                    break;
                }
                written += n;
            }
            p.pump();
            let key = *recv.get_or_insert_with(|| p.b.accept(Dir::Uni).unwrap().expect("stream"));
            while let Some((n, _)) = p.b.read(key, &mut sink).unwrap() {
                if n == 0 {
                    break;
                }
                read += n;
            }
            p.pump();
        }
        (read, p.a.stats().records_sent - records_before)
    }

    /// Requests and responses on new bidirectional streams, both ends;
    /// returns the allocations of the `rounds` requests.
    fn request_on_new_stream(p: &mut Pair, rounds: usize) -> u64 {
        let msg = [3u8; 64];
        let mut buf = [0u8; 256];
        let mut total = 0;
        for _ in 0..rounds {
            let (_, n) = super::allocations(|| {
                let s = p.a.open(Dir::Bidi).unwrap();
                assert_eq!(p.a.write(s, &msg).unwrap(), 64);
                p.a.finish(s).unwrap();
                p.pump();
                let r = p.b.accept(Dir::Bidi).unwrap().expect("stream");
                let (n, _) = p.b.read(r, &mut buf).unwrap().expect("data");
                assert_eq!(n, 64);
                assert_eq!(p.b.write(r, &buf[..n]).unwrap(), 64);
                p.b.finish(r).unwrap();
                while p
                    .b
                    .read(r, &mut buf)
                    .unwrap()
                    .is_some_and(|(n, fin)| n > 0 && !fin)
                {}
                p.b.release(r);
                p.pump();
                let (n, _) = p.a.read(s, &mut buf).unwrap().expect("data");
                assert_eq!(n, 64);
                while p
                    .a
                    .read(s, &mut buf)
                    .unwrap()
                    .is_some_and(|(n, fin)| n > 0 && !fin)
                {}
                p.a.release(s);
                p.pump();
            });
            total += n;
        }
        total
    }

    #[test]
    fn a_request_on_a_new_stream_does_not_allocate() {
        let mut p = pair();
        // Warm up: the stream table and the spare buffers reach their size.
        request_on_new_stream(&mut p, 1000);
        let (n, grew) = super::live_bytes(|| request_on_new_stream(&mut p, 1000));
        assert!(n <= 10, "{n} allocations for 1000 requests on new streams");
        // Nothing accumulates: 1000 streams later the heap is where it was.
        assert!(grew <= 0, "{grew} live bytes more after 1000 requests");
    }

    #[test]
    fn bulk_transfer_does_not_allocate_per_frame() {
        let mut p = pair();
        let send = p.a.open(Dir::Uni).unwrap();
        let mut recv = None;
        // Warm up: windows and buffers reach their steady size.
        transfer(&mut p, send, &mut recv, 64 << 20, None);
        let ((read, records), n) =
            super::allocations(|| transfer(&mut p, send, &mut recv, 256 << 20, None));
        assert_eq!(read, 256 << 20);
        assert!(records > 10_000, "{records} records");
        // Copied writes go into recycled chunks: at most a chunk (and its
        // shared header) when the transfer starts or ends at a new
        // high-water mark, never per frame.
        assert!(n <= 4, "{n} allocations for {records} records");
    }

    #[test]
    fn zero_copy_transfer_does_not_allocate_per_frame() {
        let mut p = pair();
        let send = p.a.open(Dir::Uni).unwrap();
        let chunk = Bytes::from(vec![9u8; 256 * 1024]);
        // A clone makes the buffer shared, so slicing it allocates nothing.
        let shared = chunk.clone();
        let mut recv = None;
        transfer(&mut p, send, &mut recv, 64 << 20, Some(&shared));
        let ((read, records), n) =
            super::allocations(|| transfer(&mut p, send, &mut recv, 256 << 20, Some(&shared)));
        assert_eq!(read, 256 << 20);
        assert!(records > 10_000, "{records} records");
        assert_eq!(n, 0, "{n} allocations for {records} records");
        // Every reference the stream took is gone once the data is
        // delivered: the application's buffer is never kept for reuse.
        drop(shared);
        assert!(chunk.is_unique(), "the stream still references the buffer");
    }

    /// Moves `total` bytes in 1 MiB steps with the clock running, so that
    /// pipe acknowledgement (MULTIPATH.md Section 3.5) takes RTT and
    /// delivery-rate samples on both sides.
    fn ticking_transfer(
        p: &mut Pair,
        send: StreamKey,
        recv: &mut Option<StreamKey>,
        total: usize,
        shared: &Bytes,
    ) {
        let mut read = 0;
        while read < total {
            read += transfer(p, send, recv, 1 << 20, Some(shared)).0;
            p.now += Duration::from_micros(250);
            p.a.handle_timeout(p.now);
            p.b.handle_timeout(p.now);
            p.pump();
        }
    }

    #[test]
    fn acknowledged_transfer_does_not_allocate_per_acknowledgement() {
        let mut p = pair();
        assert!(p.a.features().pipe_ack && p.b.features().pipe_ack);
        let send = p.a.open(Dir::Uni).unwrap();
        let shared = Bytes::from(vec![9u8; 256 * 1024]);
        let mut recv = None;
        ticking_transfer(&mut p, send, &mut recv, 64 << 20, &shared);
        let (_, n) =
            super::allocations(|| ticking_transfer(&mut p, send, &mut recv, 256 << 20, &shared));
        let stats = p.a.stats();
        assert!(stats.min_rtt.is_some(), "no RTT sample from PIPE_ACK");
        assert_eq!(n, 0, "{n} allocations with acknowledgements flowing");
    }
}

// ---- the multipath core ----------------------------------------------------------

/// The per-chunk and per-acknowledgement paths of a multipath session: bulk
/// data spread over two pipes, with PIPE_ACKs, credit and timers running,
/// allocates nothing once warmed up (at 10 Gbit/s and 16 KiB chunks these
/// run about 76 000 times a second).
mod core_multipath {
    use std::time::{Duration, Instant};

    use super::join::{Joined, feed_join};
    use zmux::proto::frame::Dir;
    use zmux::proto::listener::{ListenerConfig, ListenerCore};
    use zmux::proto::record::Framing;
    use zmux::proto::session::{
        Config, PipeAuth, PipeId, PipeOptions, Policy, RoleConfig, SessionCore, StreamKey,
        TransmitBuf,
    };

    const BS: Framing = Framing::ByteStream;

    struct Pair {
        a: SessionCore,
        b: SessionCore,
        pipes: Vec<PipeId>,
        out: TransmitBuf,
        wire: Vec<u8>,
        now: Instant,
    }

    fn config(policy: &Policy) -> Config {
        let mut c = Config::default();
        c.max_pipes = 4;
        c.pipe_auth = PipeAuth::psk(*b"0123456789abcdef0123456789abcdef");
        c.scheduler = policy.clone();
        c.max_idle_timeout = Duration::from_secs(600);
        c.max_incoming_uni_streams = Some(4);
        c
    }

    impl Pair {
        /// A multipath pair on pipe 0, then pipe 1 joined in band through
        /// B's listener.
        fn new(policy: Policy) -> Self {
            let now = Instant::now();
            let mut b_cfg = config(&policy);
            b_cfg.test_hooks().locator = b"server".to_vec();
            let mut a =
                SessionCore::new(config(&policy), RoleConfig::Initiator, None, now).unwrap();
            let mut b = SessionCore::new(b_cfg, RoleConfig::Responder, None, now).unwrap();
            a.attach_pipe(PipeId(0), BS, now);
            b.attach_pipe(PipeId(0), BS, now);
            let mut p = Self {
                a,
                b,
                pipes: vec![PipeId(0)],
                out: TransmitBuf::default(),
                wire: Vec::with_capacity(512 * 1024),
                now,
            };
            p.pump();
            assert!(p.a.is_multipath() && p.b.is_multipath());
            let id =
                p.a.add_pipe(
                    Some(BS),
                    Some(BS),
                    &PipeOptions::default(),
                    false,
                    None,
                    now,
                )
                .unwrap();
            // A's first bytes on the new pipe go through B's listener.
            let mut listener = ListenerCore::new(ListenerConfig::default());
            let mut first = Vec::new();
            while p.a.wants_write(id) {
                p.a.poll_transmit(id, now, &mut p.out);
                if p.out.is_empty() {
                    break;
                }
                p.out.copy_to_vec(&mut first);
            }
            let fed = feed_join(&mut listener, &mut p.b, &mut None, id.0, &first, now);
            assert_eq!(fed.joined, Joined::Attached(id));
            p.pipes.push(id);
            // The pump hands everything over at once, as a carrier with a
            // low-water mark does, which the carrier queue limiter does
            // not pace: the scheduler's own work
            // per chunk and acknowledgement is measured.
            for &q in &p.pipes {
                p.a.set_pipe_low_water(q, true);
                p.b.set_pipe_low_water(q, true);
            }
            for _ in 0..50 {
                p.pump();
                p.tick(Duration::from_millis(2));
            }
            p
        }

        /// Moves everything both sides have to send on every pipe.
        fn pump(&mut self) {
            loop {
                let mut progress = false;
                for i in 0..self.pipes.len() {
                    let pipe = self.pipes[i];
                    for dir in [true, false] {
                        let (from, to) = if dir {
                            (&mut self.a, &mut self.b)
                        } else {
                            (&mut self.b, &mut self.a)
                        };
                        while from.wants_write(pipe) {
                            from.poll_transmit(pipe, self.now, &mut self.out);
                            if self.out.is_empty() {
                                break;
                            }
                            self.wire.clear();
                            self.out.copy_to_vec(&mut self.wire);
                            let used = to.receive_in_place(pipe, &self.wire, self.now);
                            assert_eq!(used, self.wire.len());
                            progress = true;
                        }
                    }
                }
                while self.a.poll_event().is_some() {}
                while self.b.poll_event().is_some() {}
                if !progress {
                    return;
                }
            }
        }

        /// Time passes: acknowledgement delays, pings and probation run.
        fn tick(&mut self, by: Duration) {
            self.now += by;
            self.a.handle_timeout(self.now);
            self.b.handle_timeout(self.now);
        }
    }

    /// Moves `total` bytes on one stream, with a millisecond between rounds.
    fn transfer(
        p: &mut Pair,
        send: StreamKey,
        recv: &mut Option<StreamKey>,
        total: usize,
    ) -> usize {
        let data = [7u8; 16 * 1024];
        let mut sink = [0u8; 64 * 1024];
        let (mut written, mut read) = (0, 0);
        while read < total {
            while written < total {
                let n =
                    p.a.write(send, &data[..(total - written).min(data.len())])
                        .unwrap();
                if n == 0 {
                    break;
                }
                written += n;
            }
            p.pump();
            let key = *recv.get_or_insert_with(|| p.b.accept(Dir::Uni).unwrap().expect("stream"));
            while let Some((n, _)) = p.b.read(key, &mut sink).unwrap() {
                if n == 0 {
                    break;
                }
                read += n;
            }
            p.pump();
            p.tick(Duration::from_millis(1));
        }
        read
    }

    fn bulk_over_two_pipes(policy: Policy) {
        let mut p = Pair::new(policy.clone());
        let send = p.a.open(Dir::Uni).unwrap();
        let mut recv = None;
        // Warm up: windows, buffers and per-pipe state reach their size.
        transfer(&mut p, send, &mut recv, 64 << 20);
        let before: Vec<u64> = p
            .pipes
            .iter()
            .map(|&q| p.a.pipe_info(q).unwrap().bytes_sent)
            .collect();
        let (read, n) = super::allocations(|| transfer(&mut p, send, &mut recv, 128 << 20));
        assert_eq!(read, 128 << 20);
        let sent: Vec<u64> = p
            .pipes
            .iter()
            .zip(&before)
            .map(|(&q, b)| p.a.pipe_info(q).unwrap().bytes_sent - b)
            .collect();
        // The round robin alternates; `spread-eta` picks the pipe with the
        // earliest arrival, which here (no delay) may stay one.
        if !matches!(policy, Policy::SpreadEta) {
            assert!(
                sent.iter().all(|&s| s > 1 << 20),
                "{policy:?}: not spread: {sent:?}"
            );
        }
        assert!(
            n <= 4,
            "{policy:?}: {n} allocations for 128 MiB over two pipes"
        );
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "debug builds recount the multipath ledger, which allocates: run with --release"
    )]
    fn spread_eta_does_not_allocate_per_chunk_or_ack() {
        bulk_over_two_pipes(Policy::SpreadEta);
    }

    #[test]
    #[cfg_attr(
        debug_assertions,
        ignore = "debug builds recount the multipath ledger, which allocates: run with --release"
    )]
    fn round_robin_does_not_allocate_per_chunk_or_ack() {
        bulk_over_two_pipes(Policy::SpreadRoundRobin);
        bulk_over_two_pipes(Policy::SpreadRateWeighted);
    }
}

// ---- the tokio driver ------------------------------------------------------------

mod driver {
    use std::sync::{Mutex, PoisonError};
    use std::time::Duration;

    /// The driver's read buffers come from a pool of the process: one test
    /// at a time uses it, so that a buffer another test takes from the pool
    /// or gives back is not counted in this thread's live bytes.
    static POOL: Mutex<()> = Mutex::new(());

    use zmux::{Config, PipeIo, Session, VarInt};

    /// A runtime, two sessions over an in-memory carrier, streams ended
    /// every way, close: everything dropped at the end, the runtime too.
    fn lifecycle() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(async {
            let (a, b) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(Session::accept(PipeIo::new(b), Config::default()));
            let client = Session::connect(PipeIo::new(a), Config::default())
                .await
                .unwrap();
            let server = server.await.unwrap().unwrap();
            let s = server.clone();
            let echo = tokio::spawn(async move {
                while let Ok((mut send, mut recv)) = s.accept_bi().await {
                    let data = recv.read_to_end(1 << 20).await.unwrap_or_default();
                    let _ = send.write_all(&data).await;
                    let _ = send.finish();
                }
            });
            for i in 0..20u8 {
                let (mut send, mut recv) = client.open_bi().await.unwrap();
                send.write_all(&vec![i; 10_000]).await.unwrap();
                match i % 3 {
                    0 => {
                        send.finish().unwrap();
                        assert_eq!(recv.read_to_end(1 << 20).await.unwrap().len(), 10_000);
                    }
                    1 => {
                        send.reset(VarInt::from_u32(1)).unwrap();
                    }
                    _ => {
                        // Dropped without finish, a read cancelled.
                        let mut b = [0u8; 4];
                        let _ = tokio::time::timeout(Duration::ZERO, recv.read(&mut b)).await;
                    }
                }
            }
            client.close(VarInt::from_u32(0), b"");
            client.closed().await;
            server.closed().await;
            echo.await.unwrap();
        });
        drop(rt);
    }

    /// Moves `mib` MiB from A to B through a splicing relay (A–R and R–B
    /// outer sessions) or directly, over a nested session whose pipe is the
    /// stream or on the stream itself; returns the allocations of the
    /// transfer on this thread (the whole runtime).
    ///
    /// The clock is paused (it moves only when every task waits): a pipe
    /// whose reads paused for a burst's gap gives its read buffers back,
    /// and the next read takes fresh ones, an allocation per pause, not per
    /// frame. On a loaded host the thread stalls past that gap at random;
    /// on the paused clock the count does not depend on the host.
    fn relayed(mib: usize, relay: bool, nested: bool) -> u64 {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .start_paused(true)
            .build()
            .unwrap();
        rt.block_on(async {
            async fn pair() -> (Session, Session) {
                let (a, b) = tokio::io::duplex(256 * 1024);
                let server = tokio::spawn(Session::accept(PipeIo::new(b), Config::default()));
                let client = Session::connect(PipeIo::new(a), Config::default())
                    .await
                    .unwrap();
                (client, server.await.unwrap().unwrap())
            }
            let (a, ra) = pair().await;
            let (rb, b) = if relay {
                pair().await
            } else {
                (a.clone(), ra.clone())
            };
            let splice = relay.then(|| {
                tokio::spawn(async move {
                    let (s_in, r_in) = ra.accept_bi().await.unwrap();
                    let (s_out, r_out) = rb.open_bi_with(&r_in.preamble()).await.unwrap();
                    zmux::helpers::splice(
                        (s_in, r_in),
                        (s_out, r_out),
                        zmux::helpers::SpliceOptions::default(),
                    )
                    .await
                    .unwrap()
                })
            });
            let (src, dst) = if nested {
                let accept = tokio::spawn(async move {
                    let (s, r) = b.accept_bi().await.unwrap();
                    Session::accept(PipeIo::from_stream(s, r), Config::default())
                        .await
                        .unwrap()
                });
                let pipe = a.open_pipe_stream(&zmux::Preamble::new()).await.unwrap();
                let x = Session::connect(pipe, Config::default()).await.unwrap();
                (x, accept.await.unwrap())
            } else {
                (a, b)
            };
            let (mut send, _r) = src.open_bi().await.unwrap();
            let chunk = vec![5u8; 64 * 1024];
            send.write_all(&chunk).await.unwrap();
            let (_s, mut recv) = dst.accept_bi().await.unwrap();
            let mut got = 0;
            let mut buf = vec![0u8; 64 * 1024];
            let before = super::ALLOCATIONS.with(std::cell::Cell::get);
            let writer = tokio::spawn(async move {
                for _ in 0..mib * 16 {
                    send.write_all(&chunk).await.unwrap();
                }
                send
            });
            while got < mib * 1024 * 1024 {
                got += recv.read(&mut buf).await.unwrap().unwrap();
            }
            let after = super::ALLOCATIONS.with(std::cell::Cell::get);
            drop(writer.await.unwrap());
            if let Some(s) = splice {
                s.abort();
                let _ = s.await;
            }
            after - before
        })
    }

    /// The relay helper and the stream carriers hand data over as shared
    /// chunks without allocating per frame (Section
    /// 4.6). 32 MiB more are 2048 more records of 16 KiB and 512 more
    /// chunks of 64 KiB: they may cost at most one allocation per chunk,
    /// the receive buffer's new storage while the chunks it lent are still
    /// queued downstream (zero copy: the bytes are never copied instead).
    #[test]
    fn relaying_and_nesting_allocate_nothing_per_frame() {
        let _pool = POOL.lock().unwrap_or_else(PoisonError::into_inner);
        for (relay, nested) in [(false, false), (true, false), (false, true), (true, true)] {
            let small = relayed(8, relay, nested);
            let large = relayed(40, relay, nested);
            assert!(
                large <= small + 512,
                "relay {relay}, nested {nested}: {small} allocations for 8 MiB, {large} for 40 MiB"
            );
        }
    }

    #[test]
    fn a_driver_lifecycle_gives_back_every_byte() {
        let _pool = POOL.lock().unwrap_or_else(PoisonError::into_inner);
        // Warm up: the runtime's and the process's lazily created state.
        lifecycle();
        lifecycle();
        let ((), grew) = super::live_bytes(lifecycle);
        assert_eq!(grew, 0, "{grew} live bytes left after a driver lifecycle");
    }
}
