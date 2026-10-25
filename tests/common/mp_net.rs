//! Two multipath session cores joined by modelled TCP carriers, sans IO:
//! the shared harness of the multipath core tests.
//!
//! Each direction of a carrier (a [`Flow`]) delays, stalls, swallows, ends
//! or resets what its writer sends, and holds the writer back past the
//! link's capacity; carrier halves an end closes reach the other end in
//! order (an end of stream after the bytes in flight, a reset at once). B
//! joins new pipes through its listener, which may refuse, evict or time
//! out a carrier. Custom scheduling decisions are made before each write.
//! `X` observes each link's batches, `S` is the test's own state.

#![allow(dead_code)]

use std::collections::{BTreeMap, VecDeque};
use std::ops::{Deref, DerefMut};
use std::time::{Duration, Instant};

use zmux::proto::listener::{CarrierId, ListenerConfig, ListenerCore};
use zmux::proto::record::Framing;
use zmux::proto::session::{
    Config, CoreEvent, PickRequest, PipeEnd, PipeHalf, PipeId, PipeOptions, PipeWrite, RoleConfig,
    SessionCore, State, Transmit, TransmitBuf,
};

#[path = "join.rs"]
mod join;

pub(crate) use join::Joined;
use join::feed_join;

/// The dialing end, and the accepting one (indexes of [`MpNet::ends`] and
/// [`Link::flows`]).
pub(crate) const A: usize = 0;
pub(crate) const B: usize = 1;
pub(crate) const BS: Framing = Framing::ByteStream;

/// What a test looks at in a link's batches.
pub(crate) trait Observe: Default {
    /// A batch A wrote on the link.
    fn a_batch(&mut self, _bytes: &[u8]) {}
    /// A batch B wrote on the link.
    fn b_batch(&mut self, _bytes: &[u8]) {}
}

impl Observe for () {}

/// One direction of a carrier (a TCP connection's byte stream).
#[derive(Debug)]
pub(crate) struct Flow {
    /// Bytes in flight, each with the time it may arrive (in order).
    pub(crate) chunks: VecDeque<(Instant, Vec<u8>)>,
    pub(crate) queued: usize,
    pub(crate) delay: Duration,
    /// The carrier takes the writer's bytes (else the writer is not asked
    /// to write, and is not told why).
    pub(crate) takes: bool,
    /// Silently stalled: bytes are taken, nothing arrives.
    pub(crate) stalled: bool,
    /// A middlebox swallows everything written from now on.
    pub(crate) blackhole: bool,
    /// The reader sees the end of stream after the queued bytes.
    pub(crate) fin: bool,
    /// The reader sees a carrier error at once (queued bytes are lost).
    pub(crate) reset: bool,
    /// The reader was told about the end.
    pub(crate) end_reported: bool,
    /// Writes fail; the writer is told once.
    pub(crate) write_err: bool,
    pub(crate) write_err_reported: bool,
    /// The writer shut its half down or closed it.
    pub(crate) writer_closed: bool,
    /// The reader closed its half; bytes pile up unread.
    pub(crate) reader_closed: bool,
    /// Writable, as the writer's core was last told.
    pub(crate) writable: bool,
}

impl Flow {
    fn new() -> Self {
        Self {
            chunks: VecDeque::new(),
            queued: 0,
            delay: Duration::ZERO,
            takes: true,
            stalled: false,
            blackhole: false,
            fin: false,
            reset: false,
            end_reported: false,
            write_err: false,
            write_err_reported: false,
            writer_closed: false,
            reader_closed: false,
            writable: true,
        }
    }

    fn push(&mut self, now: Instant, bytes: &[u8]) {
        if self.blackhole || bytes.is_empty() {
            return;
        }
        self.queued += bytes.len();
        self.chunks.push_back((now + self.delay, bytes.to_vec()));
    }

    /// Up to `limit` bytes that have arrived by `now`, in order.
    fn take(&mut self, now: Instant, limit: usize) -> Vec<u8> {
        let mut out = Vec::new();
        while out.len() < limit {
            let Some((at, chunk)) = self.chunks.front_mut() else {
                break;
            };
            if *at > now {
                break;
            }
            let n = (limit - out.len()).min(chunk.len());
            out.extend_from_slice(&chunk[..n]);
            if n == chunk.len() {
                self.chunks.pop_front();
            } else {
                chunk.drain(..n);
            }
        }
        self.queued -= out.len();
        out
    }

    pub(crate) fn clear(&mut self) {
        self.chunks.clear();
        self.queued = 0;
    }

    /// Nothing was injected and neither end closed it.
    pub(crate) fn healthy(&self) -> bool {
        self.takes
            && !(self.stalled
                || self.blackhole
                || self.fin
                || self.reset
                || self.write_err
                || self.writer_closed
                || self.reader_closed)
    }
}

/// A bidirectional carrier between the endpoints, joined by A.
pub(crate) struct Link<X> {
    /// `[A to B, B to A]`, indexed by the writer.
    pub(crate) flows: [Flow; 2],
    /// What became of the join at B's listener (pipe 0 is attached from
    /// the start); before it is attached A's bytes go to the listener.
    pub(crate) joined: Joined,
    carrier: Option<CarrierId>,
    /// Bytes a flow takes before its writer sees it unwritable.
    pub(crate) cap: usize,
    /// An abortive close resets the carrier (RST) rather than ending it.
    pub(crate) rst: bool,
    /// The carrier died ([`MpNet::fail`]): nothing moves any more.
    pub(crate) failed: bool,
    pub(crate) x: X,
}

impl<X: Observe> Link<X> {
    fn new(joined: Joined) -> Self {
        Self {
            flows: [Flow::new(), Flow::new()],
            joined,
            carrier: None,
            cap: usize::MAX,
            rst: false,
            failed: false,
            x: X::default(),
        }
    }
}

impl<X> Link<X> {
    /// B attached the pipe.
    pub(crate) fn attached(&self) -> bool {
        matches!(self.joined, Joined::Attached(_))
    }

    /// Neither failed nor closed by B's listener.
    pub(crate) fn alive(&self) -> bool {
        !self.failed && !matches!(self.joined, Joined::Refused | Joined::Dropped)
    }

    /// Attached, and nothing injected or closed in either direction.
    pub(crate) fn healthy(&self) -> bool {
        self.attached() && !self.failed && self.flows.iter().all(Flow::healthy)
    }

    /// Both directions stall (`on`) or deliver again.
    pub(crate) fn stall(&mut self, on: bool) {
        for f in &mut self.flows {
            f.stalled = on;
        }
    }

    /// `side` closed both halves of its socket: the peer's writes fail.
    fn socket_closed(&mut self, side: usize) {
        if self.flows[side].writer_closed && self.flows[1 - side].reader_closed {
            self.flows[1 - side].write_err = true;
        }
    }
}

impl<X> Deref for Link<X> {
    type Target = X;

    fn deref(&self) -> &X {
        &self.x
    }
}

impl<X> DerefMut for Link<X> {
    fn deref_mut(&mut self) -> &mut X {
        &mut self.x
    }
}

pub(crate) struct MpNet<X, S> {
    /// A (the initiator) and B.
    pub(crate) ends: [SessionCore; 2],
    pub(crate) now: Instant,
    pub(crate) links: BTreeMap<u64, Link<X>>,
    pub(crate) out: TransmitBuf,
    wire: Vec<u8>,
    listener: ListenerCore,
    /// Every event each end emitted, until the test takes them.
    pub(crate) events: [Vec<CoreEvent>; 2],
    /// Every join must be accepted (a carrier B's listener closes fails
    /// the test).
    pub(crate) strict_joins: bool,
    pub(crate) s: S,
}

impl<X: Observe, S> MpNet<X, S> {
    /// A dials B on pipe 0 (nothing moved yet).
    pub(crate) fn new(a: Config, b: Config, s: S) -> Self {
        let now = Instant::now();
        let mut a = SessionCore::new(a, RoleConfig::Initiator, None, now).unwrap();
        let mut b = SessionCore::new(b, RoleConfig::Responder, None, now).unwrap();
        a.attach_pipe(PipeId(0), BS, now);
        b.attach_pipe(PipeId(0), BS, now);
        let mut links = BTreeMap::new();
        links.insert(0, Link::new(Joined::Attached(PipeId(0))));
        Self {
            ends: [a, b],
            now,
            links,
            out: TransmitBuf::default(),
            wire: Vec::new(),
            listener: ListenerCore::new(ListenerConfig::default()),
            events: [Vec::new(), Vec::new()],
            strict_joins: false,
            s,
        }
    }

    /// Neither session is closing.
    pub(crate) fn alive(&self) -> bool {
        self.ends.iter().all(|s| s.state() < State::Closing)
    }

    /// One round: every end writes what it wants, then each flow delivers
    /// at most `limit` bytes that have arrived.
    pub(crate) fn step(&mut self, limit: usize) {
        let ids: Vec<u64> = self.links.keys().copied().collect();
        for &id in &ids {
            self.transmit(id, A);
            self.transmit(id, B);
        }
        for &id in &ids {
            self.deliver(id, A, limit);
            self.deliver(id, B, limit);
        }
        self.update_writable();
        self.handle_events();
    }

    /// End `w` writes what it wants on link `id`.
    fn transmit(&mut self, id: u64, w: usize) {
        let pipe = PipeId(id);
        let now = self.now;
        let Some(l) = self.links.get_mut(&id) else {
            return;
        };
        if l.failed || (w == B && !l.attached()) {
            return;
        }
        let cap = l.cap;
        let core = &mut self.ends[w];
        // Custom decisions are made outside the core: answer them, then send what they place.
        let mut req = PickRequest::default();
        for round in 0..64 {
            if round > 0 && !core.wants_pick() {
                break;
            }
            while core.take_pick(&mut req) {
                req.run();
                core.answer_pick(&req);
            }
            if l.flows[w].writer_closed {
                break;
            }
            for _ in 0..64 {
                let f = &mut l.flows[w];
                if f.writer_closed || !f.takes || !core.wants_write(pipe) {
                    break;
                }
                if f.write_err {
                    if !std::mem::replace(&mut f.write_err_reported, true) {
                        core.write_failed(pipe, std::io::ErrorKind::BrokenPipe, now);
                    }
                    break;
                }
                if f.queued >= cap {
                    if f.writable {
                        f.writable = false;
                        core.pipe_write(pipe, PipeWrite::returned(now, now, 0, 0, true), now);
                    }
                    break;
                }
                let t = core.poll_transmit(pipe, now, &mut self.out);
                self.wire.clear();
                self.out.copy_to_vec(&mut self.wire);
                if !self.wire.is_empty() {
                    if w == A {
                        l.x.a_batch(&self.wire);
                    } else {
                        l.x.b_batch(&self.wire);
                    }
                }
                let f = &mut l.flows[w];
                f.push(now, &self.wire);
                if t == Transmit::Shutdown {
                    f.writer_closed = true;
                    f.fin = true;
                    l.socket_closed(w);
                    break;
                }
                if self.wire.is_empty() {
                    // A batch that
                    // writes nothing leaves no write interest behind, or a
                    // driver would ask again at once, and again.
                    assert!(
                        !core.wants_write(pipe),
                        "pipe {id} of end {w} keeps asking for a write it does not make"
                    );
                    break;
                }
            }
        }
    }

    /// Link `id` delivers at most `limit` bytes end `w` wrote that have
    /// arrived, then the end of stream that follows them.
    fn deliver(&mut self, id: u64, w: usize, limit: usize) {
        let r = 1 - w;
        let now = self.now;
        let Some(l) = self.links.get_mut(&id) else {
            return;
        };
        if l.failed {
            return;
        }
        let f = &mut l.flows[w];
        if f.end_reported || f.reader_closed {
            return;
        }
        if f.reset {
            f.clear();
            f.end_reported = true;
            self.end_of(id, r, PipeEnd::Error(std::io::ErrorKind::ConnectionReset));
            return;
        }
        if f.stalled {
            return;
        }
        let bytes = f.take(now, limit);
        let eof = f.fin && f.chunks.is_empty();
        if eof {
            f.end_reported = true;
        }
        if !bytes.is_empty() {
            self.feed(id, r, &bytes);
        }
        if eof {
            self.end_of(id, r, PipeEnd::Eof);
        }
    }

    /// Bytes for end `r` on pipe `id`: B's go through its listener until
    /// the join is accepted.
    pub(crate) fn feed(&mut self, id: u64, r: usize, bytes: &[u8]) {
        let now = self.now;
        let pipe = PipeId(id);
        let l = self.links.get_mut(&id).expect("link");
        if r == A || l.attached() {
            self.ends[r].receive(pipe, bytes, now);
            return;
        }
        if !l.alive() {
            return;
        }
        // Every carrier comes from A's one address.
        let fed = feed_join(
            &mut self.listener,
            &mut self.ends[B],
            &mut l.carrier,
            0,
            bytes,
            now,
        );
        match fed.joined {
            Joined::Attached(p) => {
                assert_eq!(p, pipe, "join accepted under another pipe ID");
                l.joined = fed.joined;
            }
            Joined::Pending => {}
            Joined::Refused | Joined::Dropped => self.listener_close(id, fed.joined),
        }
        if let Some(e) = fed.evicted {
            let victim = self
                .links
                .iter()
                .find(|(_, l)| l.carrier == Some(e))
                .map(|(k, _)| *k);
            if let Some(v) = victim {
                self.listener_close(v, Joined::Dropped);
            }
        }
    }

    /// The end of a flow reached end `r`.
    fn end_of(&mut self, id: u64, r: usize, end: PipeEnd) {
        if r == B && !self.links[&id].attached() {
            self.listener_close(id, Joined::Dropped);
            return;
        }
        self.ends[r].pipe_ended(PipeId(id), end, self.now);
    }

    /// B's listener closes a carrier it has not handed to the session
    /// (`why`: the session refused the join, or the listener dropped the
    /// carrier): A's writes fail and A reads the end of stream.
    fn listener_close(&mut self, id: u64, why: Joined) {
        let Some(l) = self.links.get_mut(&id) else {
            return;
        };
        if !l.alive() || l.attached() {
            return;
        }
        assert!(!self.strict_joins, "the join of pipe {id} failed: {why:?}");
        l.joined = why;
        if let Some(c) = l.carrier.take() {
            self.listener.done(c);
        }
        let [ab, ba] = &mut l.flows;
        ab.reader_closed = true;
        ab.clear();
        ab.write_err = true;
        ba.writer_closed = true;
        ba.fin = true;
    }

    /// Each writer learns when its flow can take bytes again, or no more.
    fn update_writable(&mut self) {
        let now = self.now;
        for (&id, l) in &mut self.links {
            if l.failed {
                continue;
            }
            for w in [A, B] {
                if w == B && !l.attached() {
                    continue;
                }
                let f = &mut l.flows[w];
                let writable = f.queued < l.cap;
                if f.writer_closed || f.writable == writable {
                    continue;
                }
                f.writable = writable;
                self.ends[w].pipe_write(
                    PipeId(id),
                    PipeWrite::returned(now, now, 0, 0, !writable),
                    now,
                );
            }
        }
    }

    /// Takes both ends' events into [`MpNet::events`]; the carrier halves
    /// they close are closed.
    pub(crate) fn handle_events(&mut self) {
        for side in [A, B] {
            while let Some(e) = self.ends[side].poll_event() {
                if let CoreEvent::ClosePipe { pipe, half, abort } = e {
                    self.close_half(side, pipe.0, half, abort);
                }
                self.events[side].push(e);
            }
        }
    }

    /// End `side` closes a half of its carrier of pipe `id`.
    fn close_half(&mut self, side: usize, id: u64, half: PipeHalf, abort: bool) {
        let Some(l) = self.links.get_mut(&id) else {
            return;
        };
        match half {
            PipeHalf::Outbound => {
                let rst = abort && l.rst;
                let f = &mut l.flows[side];
                if !f.writer_closed {
                    f.writer_closed = true;
                    if rst {
                        f.reset = true;
                    } else {
                        f.fin = true;
                    }
                }
                if rst {
                    let back = &mut l.flows[1 - side];
                    back.reader_closed = true;
                    back.clear();
                    back.write_err = true;
                }
            }
            PipeHalf::Inbound => l.flows[1 - side].reader_closed = true,
        }
        l.socket_closed(side);
    }

    /// Time passes: both ends' and the listener's timers run.
    pub(crate) fn advance(&mut self, ms: u64) {
        self.now += Duration::from_millis(ms);
        for s in &mut self.ends {
            s.handle_timeout(self.now);
        }
        for c in self.listener.expired(self.now) {
            let link = self
                .links
                .iter()
                .find(|(_, l)| l.carrier == Some(c))
                .map(|(k, _)| *k);
            if let Some(id) = link {
                self.listener_close(id, Joined::Dropped);
            }
        }
        self.handle_events();
    }

    /// The carrier dies at once: bytes in flight are lost, and each end
    /// that holds it reads an error and sees its writes fail (unless it
    /// closed that half already).
    pub(crate) fn fail(&mut self, id: u64) {
        let Some(l) = self.links.get_mut(&id) else {
            return;
        };
        if l.failed {
            return;
        }
        l.failed = true;
        if let Some(c) = l.carrier.take() {
            self.listener.done(c);
        }
        for f in &mut l.flows {
            f.clear();
        }
        let now = self.now;
        for side in [A, B] {
            if side == B && !l.attached() {
                continue;
            }
            let inbound = &mut l.flows[1 - side];
            if !std::mem::replace(&mut inbound.end_reported, true) {
                self.ends[side].pipe_ended(
                    PipeId(id),
                    PipeEnd::Error(std::io::ErrorKind::ConnectionReset),
                    now,
                );
            }
            let outbound = &mut l.flows[side];
            if !outbound.writer_closed && !std::mem::replace(&mut outbound.write_err_reported, true)
            {
                outbound.write_err = true;
                self.ends[side].write_failed(PipeId(id), std::io::ErrorKind::BrokenPipe, now);
            }
        }
        self.handle_events();
    }

    /// A adds a pipe (B joins it through its listener); `None` when A
    /// refuses.
    pub(crate) fn add_pipe(&mut self, opts: &PipeOptions) -> Option<u64> {
        let id = self.ends[A]
            .add_pipe(Some(BS), Some(BS), opts, false, None, self.now)
            .ok()?
            .0;
        assert!(!self.links.contains_key(&id), "pipe ID {id} reused");
        self.links.insert(id, Link::new(Joined::Pending));
        Some(id)
    }
}
