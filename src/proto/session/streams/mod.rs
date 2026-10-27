//! The stream layer: the streams of a session with their identifiers,
//! the per-direction stream credit, session flow control, the fair share of
//! the send buffers, the scheduling queues and the control-frame queue.
//!
//! Its state is private: the session looks streams up and reads the credit
//! state through [`Streams`], and changes it only through the operations
//! here, which keep the layer's running counts (the owed stream updates,
//! the open local receiving parts, the fair share, the queues) with the
//! streams they count.

mod flow;
mod share;
mod spare;

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};

use super::CoreEvent;
use super::stream::{self, ChunkPool, Offer, RecvPart, SendPart, Slab, Stream, StreamKey};
use super::{config, di};

pub(super) use flow::{LocalDir, RecvFlow, RemoteDir, SendFlow, Stopped};
pub(super) use share::{SHARE_FLOOR, SendBuffer};
use spare::Spare;

/// A multiplicative hasher for stream identifiers.
#[derive(Default, Clone, Copy)]
struct IdHasher(u64);

impl Hasher for IdHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0.rotate_left(8) ^ u64::from(b)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }

    fn write_u64(&mut self, n: u64) {
        self.0 = (n ^ (n >> 29)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

type IdMap = HashMap<u64, StreamKey, BuildHasherDefault<IdHasher>>;

/// The stream layer's state.
#[derive(Debug)]
pub(crate) struct Streams {
    /// Released chunks of the send buffers, shared by the streams.
    chunks: ChunkPool,
    /// Streams that owe a MAX_STREAM_DATA update.
    stream_updates: usize,
    slab: Slab,
    ids: IdMap,
    local_dirs: [LocalDir; 2],
    remote_dirs: [RemoteDir; 2],
    recv_flow: RecvFlow,
    send_flow: SendFlow,
    /// Streams with control frames to send, each once (its `ctrl_queued`
    /// tells): changed only through [`Streams::queue_ctrl`] and
    /// [`Streams::pop_ctrl`].
    ctrl: VecDeque<StreamKey>,
    /// Streams with data to send, per urgency: their membership changes
    /// only through [`Streams::enqueue`] and the `dequeue` methods, which
    /// keep each stream's `queued` level with it.
    sched: SendQueue,
    /// Peer streams opened above a GOAWAY watermark, to reject once the
    /// frame that opened them is processed.
    pending_rejects: Vec<StreamKey>,
    /// Buffers of discarded streams for the next ones.
    spare: Spare,
    /// Pinned local streams whose opening frame is not written yet, per type
    /// in identifier order; later streams of the type wait for them
    /// (SPEC.md Section 7.2).
    pinned: [VecDeque<StreamKey>; 2],
    /// Every queued stream waits for session credit: nothing to send until
    /// MAX_DATA or a new stream.
    session_stalled: bool,
    /// Local bidirectional streams whose receiving part is open (the
    /// n_local term of the buffer cap, SPEC.md Section 8.3 rule 4): those
    /// whose part `counts_open`.
    local_recv_open: u64,
    /// Streams waiting for send-buffer room, in the order they began to
    /// wait. An entry is current while its stream's `waiter` names it;
    /// `waiters_gone` counts the others, dropped when they are many, and
    /// `waking` is set while writers are woken.
    send_waiters: Vec<StreamKey>,
    waiters_gone: usize,
    waking: bool,
    wake_scratch: Vec<u32>,
    /// Stream directions that hold written-but-unreleased bytes or have a
    /// write waiting (the n of the fair share).
    send_holders: u64,
    /// Bytes held by the directions within their floor (the water-filling
    /// of the fair share).
    small_held: u64,
    /// Memory pressure: new peer streams are rejected and session credit is
    /// released only on consumption.
    memory_pressure: bool,
    /// Sending parts waiting for send capacity
    /// ([`super::SessionCore::wait_send_capacity`]), looked at when session
    /// credit arrives; a part's own credit and its sending look at it
    /// directly. Keys of discarded streams stay until the next look or
    /// compaction.
    capacity_waiters: Vec<StreamKey>,
    /// Discarded streams whose keys may still be in `capacity_waiters`.
    capacity_gone: usize,
}

impl Streams {
    /// No streams yet: `send_buffer` bounds the chunk pool, `stream_limits`
    /// are the initial stream counts granted to the peer per type (more
    /// unidirectional ones on the first accept when `staged_uni`), and
    /// `window` is the session receive window.
    pub(super) fn new(
        send_buffer: u64,
        stream_limits: [u64; 2],
        staged_uni: bool,
        window: u64,
    ) -> Self {
        let mut chunks = ChunkPool::default();
        chunks.set_limit(send_buffer);
        let mut remote_dirs = stream_limits.map(RemoteDir::new);
        remote_dirs[super::UNI].staged = staged_uni;
        Self {
            chunks,
            stream_updates: 0,
            slab: Slab::default(),
            ids: IdMap::default(),
            local_dirs: Default::default(),
            remote_dirs,
            recv_flow: RecvFlow::new(window),
            send_flow: SendFlow::default(),
            ctrl: VecDeque::new(),
            sched: SendQueue::default(),
            pending_rejects: Vec::new(),
            spare: Spare::default(),
            pinned: Default::default(),
            session_stalled: false,
            local_recv_open: 0,
            send_waiters: Vec::new(),
            waiters_gone: 0,
            waking: false,
            wake_scratch: Vec::new(),
            send_holders: 0,
            small_held: 0,
            memory_pressure: false,
            capacity_waiters: Vec::new(),
            capacity_gone: 0,
        }
    }

    // ---- lookup --------------------------------------------------------------

    #[inline]
    pub(super) fn get(&self, key: StreamKey) -> Option<&Stream> {
        self.slab.get(key)
    }

    /// The stream for change (noted for the multipath ledger).
    #[inline]
    pub(super) fn get_mut(&mut self, key: StreamKey) -> Option<&mut Stream> {
        self.slab.get_mut(key)
    }

    /// The stream's sending part.
    #[inline]
    pub(super) fn send(&self, key: StreamKey) -> Option<&SendPart> {
        self.slab.get(key)?.send.as_ref()
    }

    /// The stream's sending part, for change.
    #[inline]
    pub(super) fn send_mut(&mut self, key: StreamKey) -> Option<&mut SendPart> {
        self.slab.get_mut(key)?.send.as_mut()
    }

    /// The stream's receiving part.
    #[inline]
    pub(super) fn recv(&self, key: StreamKey) -> Option<&RecvPart> {
        self.slab.get(key)?.recv.as_ref()
    }

    /// The stream's receiving part, for change.
    #[inline]
    pub(super) fn recv_mut(&mut self, key: StreamKey) -> Option<&mut RecvPart> {
        self.slab.get_mut(key)?.recv.as_mut()
    }

    /// The stream for change, with the chunk pool its send buffer takes
    /// chunks from and releases them to.
    #[inline]
    pub(super) fn stream_and_chunks(
        &mut self,
        key: StreamKey,
    ) -> Option<(&mut Stream, &mut ChunkPool)> {
        Some((self.slab.get_mut(key)?, &mut self.chunks))
    }

    /// The stream for change, with the spare buffers its receive buffer
    /// takes an emptied buffer from or gives one up to.
    #[inline]
    pub(super) fn stream_and_spare(&mut self, key: StreamKey) -> Option<(&mut Stream, &mut Spare)> {
        Some((self.slab.get_mut(key)?, &mut self.spare))
    }

    /// Notes the stream as changed for the multipath ledger.
    pub(super) fn touch(&mut self, key: StreamKey) {
        self.slab.get_mut(key);
    }

    /// The stream with this identifier.
    #[inline]
    pub(super) fn key_of(&self, id: u64) -> Option<StreamKey> {
        self.ids.get(&id).copied()
    }

    /// Streams held.
    #[inline]
    pub(super) fn len(&self) -> usize {
        self.slab.len()
    }

    /// The keys of the streams held, in slot order.
    pub(super) fn keys(&self) -> impl Iterator<Item = StreamKey> + '_ {
        self.slab.keys()
    }

    /// Starts noting changed streams for the multipath ledger, every
    /// present one first.
    pub(super) fn track(&mut self) {
        self.slab.track();
    }

    /// Whether streams changed since the last [`Self::take_touched`].
    pub(super) fn has_touched(&self) -> bool {
        self.slab.has_touched()
    }

    /// Calls `f` with every stream changed or removed since the last call
    /// (`None` for a removed one), and forgets them.
    pub(super) fn take_touched(&self, f: impl FnMut(StreamKey, Option<&Stream>)) {
        self.slab.take_touched(f);
    }

    // ---- reading the credit state --------------------------------------------

    /// Stream credit of the local streams of type `d`.
    #[inline]
    pub(super) fn local_dir(&self, d: usize) -> &LocalDir {
        &self.local_dirs[d]
    }

    /// Stream credit of the peer's streams of type `d`.
    #[inline]
    pub(super) fn remote_dir(&self, d: usize) -> &RemoteDir {
        &self.remote_dirs[d]
    }

    /// Session receive flow control.
    #[inline]
    pub(super) fn recv_flow(&self) -> &RecvFlow {
        &self.recv_flow
    }

    /// Session send flow control.
    #[inline]
    pub(super) fn send_flow_mut(&mut self) -> &mut SendFlow {
        &mut self.send_flow
    }

    pub(super) fn send_flow(&self) -> &SendFlow {
        &self.send_flow
    }

    /// Local bidirectional streams whose receiving part is open.
    pub(super) fn local_recv_open(&self) -> u64 {
        self.local_recv_open
    }

    /// Whether memory pressure is set.
    pub(super) fn memory_pressure(&self) -> bool {
        self.memory_pressure
    }

    /// Sets memory pressure; `false` when it was so already.
    pub(super) fn set_memory_pressure(&mut self, on: bool) -> bool {
        std::mem::replace(&mut self.memory_pressure, on) != on
    }

    /// Whether some local stream of a type failed after the peer's GOAWAY
    /// watermark arrived.
    pub(super) fn goaway_received(&self) -> bool {
        self.local_dirs.iter().any(|d| d.goaway.is_some())
    }

    /// Control frames of the stream layer are pending: credit updates,
    /// BLOCKED reports, or frames of streams.
    pub(super) fn control_pending(&self) -> bool {
        self.recv_flow.update_pending
            || self.recv_flow.resend
            || self.send_flow.blocked_pending
            || self.send_flow.blocked_resend
            || self
                .remote_dirs
                .iter()
                .any(|d| d.update_pending || d.resend)
            || self
                .local_dirs
                .iter()
                .any(|d| d.blocked_pending || d.blocked_resend)
            || self.ctrl_pending()
    }

    /// A credit update (MAX_DATA, MAX_STREAMS, MAX_STREAM_DATA) waits.
    pub(super) fn credit_update_pending(&self) -> bool {
        #[cfg(debug_assertions)]
        if self.slab.len() <= 64 {
            let owed = self
                .slab
                .keys()
                .filter_map(|k| self.recv(k))
                .filter(|r| r.update_pending)
                .count();
            debug_assert_eq!(owed, self.stream_updates, "owed stream updates");
        }
        self.recv_flow.update_pending
            || self.remote_dirs.iter().any(|d| d.update_pending)
            || self.stream_updates > 0
    }

    // ---- creating and discarding streams -------------------------------------

    /// A sending part with stream credit `max_data`, on a spare buffer.
    pub(super) fn new_send_part(&mut self, max_data: u64) -> SendPart {
        SendPart::with_buf(max_data, self.spare.send())
    }

    /// A receiving part with window `window` (growing up to `max_window`),
    /// on a spare buffer.
    pub(super) fn new_recv_part(&mut self, window: u64, max_window: u64) -> RecvPart {
        RecvPart::with_buf(window, max_window, self.spare.recv())
    }

    /// Takes stream credit for a new local stream of type `d`: `false`
    /// when an established session has none left (the opener waits).
    pub(super) fn reserve_local(&mut self, d: usize, established: bool) -> bool {
        self.local_dirs[d].reserve(established)
    }

    /// Gives back the stream credit of a local stream of type `d` that
    /// never got an identifier; `true` when an opener waited for it.
    pub(super) fn unreserve_local(&mut self, d: usize) -> bool {
        self.local_dirs[d].reserved -= 1;
        self.take_waiting(d)
    }

    /// Holds a new local stream.
    pub(super) fn insert(&mut self, s: Stream) -> StreamKey {
        if s.recv.as_ref().is_some_and(|r| r.counts_open) {
            self.local_recv_open += 1;
        }
        self.slab.insert(s)
    }

    /// Holds a new peer stream `s` with identifier `id`. Streams at or
    /// above a GOAWAY watermark already sent are rejected, and so is every
    /// new stream under memory pressure (SPEC.md 8.5): never offered,
    /// whatever frame opened them; [`Self::take_reject`] hands them out.
    pub(super) fn insert_peer(&mut self, id: u64, d: usize, mut s: Stream) -> StreamKey {
        let reject = self.memory_pressure || self.remote_dirs[d].above_goaway(stream::index(id));
        if reject {
            s.offer = Offer::Rejected;
        }
        let key = self.slab.insert(s);
        self.ids.insert(id, key);
        if reject {
            self.pending_rejects.push(key);
        }
        key
    }

    /// The next peer stream opened above a GOAWAY watermark, to reject.
    pub(super) fn take_reject(&mut self) -> Option<StreamKey> {
        self.pending_rejects.pop()
    }

    /// The index of the next peer stream of type `d` to open implicitly
    /// up to `index` (SPEC.md Section 7.2 rule 4), counted as opened.
    pub(super) fn open_peer_index(&mut self, d: usize, index: u64) -> Option<u64> {
        let r = &mut self.remote_dirs[d];
        if r.opened > index {
            return None;
        }
        r.opened += 1;
        Some(r.opened - 1)
    }

    /// Allocates the next identifier of a local stream's type
    /// (`client`: this endpoint is the initiator) and returns the stream
    /// with it.
    pub(super) fn assign_id(&mut self, key: StreamKey, client: bool) -> Option<&mut Stream> {
        let s = self.slab.get_mut(key)?;
        let ld = &mut self.local_dirs[di(s.dir)];
        let id = stream::make_id(ld.next_index, s.dir, client);
        ld.next_index += 1;
        s.id = Some(id);
        self.ids.insert(id, key);
        Some(s)
    }

    /// A local bidirectional stream's receiving part leaves `n_local` of
    /// the buffer cap once it is terminal (SPEC.md Section 8.3 rule 4), not
    /// when the stream is discarded.
    pub(super) fn settle_local_recv(&mut self, key: StreamKey) {
        if let Some(r) = self.recv_mut(key)
            && r.counts_open
            && r.state.is_terminal()
        {
            r.counts_open = false;
            self.local_recv_open -= 1;
        }
    }

    /// Takes a stream out of the layer: out of the identifiers, the owed
    /// updates, the fair share and (eventually) the capacity waiters. The
    /// caller settles its credit and gives it to [`Self::recycle`].
    pub(super) fn remove(&mut self, key: StreamKey) -> Option<Stream> {
        let s = self.slab.remove(key)?;
        if s.recv.as_ref().is_some_and(|r| r.update_pending) {
            self.stream_updates -= 1;
        }
        if let Some(send) = &s.send {
            self.drop_holder(send);
            if send.cold().capacity_wait.is_some() {
                // The stale key stays (a wake skips it); the list is
                // compacted once at least half of it may be stale:
                // amortized constant work per discarded stream.
                self.capacity_gone += 1;
                if self.capacity_gone * 2 >= self.capacity_waiters.len() {
                    let slab = &self.slab;
                    self.capacity_waiters.retain(|&k| {
                        slab.get(k)
                            .and_then(|s| s.send.as_ref())
                            .is_some_and(|s| s.cold().capacity_wait.is_some())
                    });
                    self.capacity_gone = 0;
                }
            }
        }
        if let Some(id) = s.id {
            self.ids.remove(&id);
        }
        Some(s)
    }

    /// Keeps the buffers of a removed stream for the next ones; a local
    /// receiving part still open leaves `n_local`.
    pub(super) fn recycle(&mut self, s: Stream) {
        if s.local && s.recv.as_ref().is_some_and(|r| r.counts_open) {
            self.local_recv_open -= 1;
        }
        if let Some(send) = s.send {
            self.spare.put_send(send.buf);
        }
        if let Some(mut recv) = s.recv {
            self.spare.put_tuner(recv.tuner.take());
            self.spare.put_recv(recv.buf.into_storage());
        }
    }

    // ---- local streams -------------------------------------------------------

    /// Whether an opener of type `d` waited for credit; it waits no more.
    pub(super) fn take_waiting(&mut self, d: usize) -> bool {
        std::mem::replace(&mut self.local_dirs[d].waiting, false)
    }

    /// The peer's initial limits: MAX_DATA and MAX_STREAMS per type.
    pub(super) fn peer_limits(&mut self, max_data: u64, max_streams: [u64; 2]) {
        self.send_flow.max = max_data;
        for (d, max) in self.local_dirs.iter_mut().zip(max_streams) {
            d.peer_max = max;
        }
    }

    /// MAX_STREAMS raised the limit of type `d` to `max`; `false` when it
    /// did not.
    pub(super) fn raise_local(&mut self, d: usize, max: u64) -> bool {
        self.local_dirs[d].raise(max)
    }

    /// A local stream of type `d` waits for stream credit: STREAMS_BLOCKED
    /// is owed unless reported.
    pub(super) fn report_streams_blocked(&mut self, d: usize) {
        self.local_dirs[d].report_blocked();
    }

    /// The peer's GOAWAY watermark for type `d`: `true` when it lowered the
    /// minimum.
    pub(super) fn lower_goaway(&mut self, d: usize, watermark: u64) -> bool {
        self.local_dirs[d].goaway(watermark)
    }

    /// Pins a local stream's identifier: its opening frame goes out in
    /// identifier order (`write_openings`).
    pub(super) fn pin(&mut self, key: StreamKey) -> Option<()> {
        let s = self.slab.get_mut(key)?;
        s.pinned = true;
        s.open_pending = true;
        self.pinned[di(s.dir)].push_back(key);
        Some(())
    }

    /// The pinned streams of type `d` whose opening frame is owed, in
    /// identifier order.
    pub(super) fn pinned(&self, d: usize) -> &VecDeque<StreamKey> {
        &self.pinned[d]
    }

    /// Whether any type has a pinned stream whose opening frame is owed.
    pub(super) fn pinned_fronts(&self) -> impl Iterator<Item = StreamKey> + '_ {
        self.pinned.iter().filter_map(|q| q.front().copied())
    }

    /// The first pinned stream of type `d` opened (or left): its control
    /// state set before the opening goes out now. `false` when the stream
    /// is gone.
    pub(super) fn unpin_first(&mut self, d: usize) -> bool {
        let Some(key) = self.pinned[d].pop_front() else {
            return false;
        };
        let Some(s) = self.slab.get_mut(key) else {
            return false;
        };
        s.open_pending = false;
        self.queue_ctrl(key);
        true
    }

    /// A pinned stream of type `d` never opens.
    pub(super) fn unpin(&mut self, d: usize, key: StreamKey) {
        self.pinned[d].retain(|&p| p != key);
    }

    // ---- peer streams --------------------------------------------------------

    /// The application asks for a peer stream of type `d` for the first
    /// time: staged credit is granted (when `grant`) and no longer staged.
    pub(super) fn unstage(&mut self, d: usize, grant: bool) {
        let r = &mut self.remote_dirs[d];
        if r.staged {
            r.staged = false;
            if grant {
                r.initial = config::STAGED_UNI_STREAMS.1;
                r.update_pending = true;
            }
        }
    }

    /// The next queued peer stream of type `d`, accepted.
    pub(super) fn accept(&mut self, d: usize) -> Option<StreamKey> {
        while let Some(key) = self.remote_dirs[d].accept.pop_front() {
            if let Some(s) = self.slab.get_mut(key)
                && s.offer == Offer::Queued
            {
                s.offer = Offer::Accepted;
                return Some(key);
            }
        }
        None
    }

    /// Offers peer stream `key` once it is ready: at once without
    /// preambles (`preamble` false), else when its own preamble arrived,
    /// regardless of lower-numbered streams (SPEC.md Section 7.2 rule 5).
    /// A stream stopped before its preamble arrived is never offered
    /// (EXTENSIONS.md Section 4.4 rule 5).
    pub(super) fn offer(
        &mut self,
        key: StreamKey,
        preamble: bool,
        events: &mut VecDeque<CoreEvent>,
    ) {
        let Some(s) = self.slab.get_mut(key) else {
            return;
        };
        let Some(id) = s.id.filter(|_| s.offer == Offer::Pending) else {
            return;
        };
        let recv = s.recv.as_ref();
        if preamble && !recv.is_some_and(|r| r.preamble_size.is_some()) {
            if recv.is_some_and(|r| r.cold().stopped.is_some()) {
                s.offer = Offer::Rejected;
            }
            return;
        }
        s.offer = Offer::Queued;
        let dir = s.dir;
        let r = &mut self.remote_dirs[di(dir)];
        r.offered = r.offered.max((id >> 2) + 1);
        let was_empty = r.accept.is_empty();
        r.accept.push_back(key);
        if was_empty {
            events.push_back(CoreEvent::StreamOpened(dir));
        }
    }

    /// A peer stream of type `d` was discarded: its count returns to the
    /// peer with MAX_STREAMS (SPEC.md Section 8.5), owed when `raise` (an
    /// endpoint that sent GOAWAY raises MAX_STREAMS no more, EXTENSIONS.md
    /// Section 3.3).
    pub(super) fn count_discarded(&mut self, d: usize, raise: bool) {
        let r = &mut self.remote_dirs[d];
        r.discarded += 1;
        if raise {
            r.update_pending = true;
        }
    }

    /// STREAMS_BLOCKED from the peer at `limit` for type `d`, new.
    pub(super) fn remote_blocked(&mut self, d: usize, limit: u64) {
        self.remote_dirs[d].blocked_seen = Some(limit);
    }

    /// GOAWAY with watermark `watermark` for type `d` was written: the
    /// lowest one sent, and MAX_STREAMS is owed no more.
    pub(super) fn goaway_written(&mut self, d: usize, watermark: u64) {
        let r = &mut self.remote_dirs[d];
        r.goaway_sent = Some(r.goaway_sent.map_or(watermark, |c| c.min(watermark)));
        r.update_pending = false;
    }

    /// The watermark of the final GOAWAY for type `d`.
    pub(super) fn set_goaway_watermark(&mut self, d: usize, watermark: u64) {
        self.remote_dirs[d].goaway_sent = Some(watermark);
    }

    // ---- notifications -------------------------------------------------------

    /// Notes the writable event of a stream, once until it is polled.
    pub(super) fn notify_writable(&mut self, key: StreamKey, events: &mut VecDeque<CoreEvent>) {
        if let Some(s) = self.slab.get_mut(key)
            && !s.notified_writable
        {
            s.notified_writable = true;
            events.push_back(CoreEvent::StreamWritable(key));
        }
    }

    // ---- memory --------------------------------------------------------------

    /// Heap bytes held by the layer: the stream table and the streams'
    /// slots, the pools, the identifiers and the lists.
    pub(super) fn heap_bytes(&self) -> usize {
        let keys = self.pending_rejects.capacity()
            + self.send_waiters.capacity()
            + self.capacity_waiters.capacity()
            + self.pinned.iter().map(VecDeque::capacity).sum::<usize>()
            + self
                .remote_dirs
                .iter()
                .map(|d| d.accept.capacity())
                .sum::<usize>();
        self.slab.memory()
            + self.spare.heap_bytes()
            + self.chunks.memory()
            + self.ids.capacity() * (size_of::<(u64, StreamKey)>() + 1)
            + self.queues_heap_bytes()
            + self.wake_scratch.capacity() * size_of::<u32>()
            + keys * size_of::<StreamKey>()
    }
}

/// The sending parts with data to send, by urgency (8 levels), in round
/// robin within a level.
#[derive(Debug, Default)]
pub(crate) struct SendQueue {
    /// Allocated with the first part queued: a session that never sends
    /// holds none.
    levels: Option<Box<[VecDeque<StreamKey>; 8]>>,
    len: usize,
    /// Turns served at strict priority since a lower level was last
    /// served (anti-starvation).
    turns: u32,
}

/// The levels of a queue that never held a part.
static NO_LEVELS: [VecDeque<StreamKey>; 8] = [const { VecDeque::new() }; 8];

impl SendQueue {
    /// Queued parts, all levels.
    pub(super) fn len(&self) -> usize {
        self.len
    }

    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The queue of urgency `u`.
    pub(super) fn level(&self, u: usize) -> &VecDeque<StreamKey> {
        &self.levels()[u]
    }

    /// The queues, by urgency.
    pub(super) fn levels(&self) -> &[VecDeque<StreamKey>; 8] {
        self.levels.as_deref().unwrap_or(&NO_LEVELS)
    }

    /// Every queued part, by urgency and queue order.
    pub(super) fn keys(&self) -> impl Iterator<Item = StreamKey> + '_ {
        self.levels().iter().flatten().copied()
    }

    /// Moves the part at index `i` of level `u` to the back of its level.
    fn move_back(&mut self, u: usize, i: usize) {
        if let Some(q) = self.levels.as_deref_mut().map(|l| &mut l[u])
            && let Some(k) = q.remove(i)
        {
            q.push_back(k);
        }
    }

    /// The next part: strict priority by urgency, except that every 16th
    /// turn goes to the next non-empty lower level so that no level
    /// starves.
    fn pick(&mut self) -> Option<(usize, StreamKey)> {
        let all = self.levels.as_deref()?;
        let mut levels = (0..8).filter(|&u| !all[u].is_empty());
        let first = levels.next()?;
        self.turns += 1;
        let u = if self.turns >= 16 {
            self.turns = 0;
            levels.next().unwrap_or(first)
        } else {
            first
        };
        all[u].front().map(|&k| (u, k))
    }

    /// Heap bytes held.
    fn heap_bytes(&self) -> usize {
        self.levels.as_ref().map_or(0, |l| {
            size_of::<[VecDeque<StreamKey>; 8]>()
                + l.iter()
                    .map(|q| q.capacity() * size_of::<StreamKey>())
                    .sum::<usize>()
        })
    }

    fn push(&mut self, u: usize, key: StreamKey) {
        self.levels.get_or_insert_with(Box::default)[u].push_back(key);
        self.len += 1;
    }

    fn remove_at(&mut self, u: usize, i: usize) -> Option<StreamKey> {
        let k = self.levels.as_deref_mut()?[u].remove(i)?;
        self.len -= 1;
        Some(k)
    }
}

impl Streams {
    /// The scheduling queues.
    #[inline]
    pub(super) fn queue(&self) -> &SendQueue {
        &self.sched
    }

    /// Every queued part waits for session credit.
    #[inline]
    pub(super) fn session_stalled(&self) -> bool {
        self.session_stalled
    }

    /// Stream data is queued, and not all of it waits for session credit.
    #[inline]
    pub(super) fn data_waiting(&self) -> bool {
        !self.sched.is_empty() && !self.session_stalled
    }

    /// The next part to serve (see [`SendQueue::pick`]), left queued.
    #[inline]
    pub(super) fn pick(&mut self) -> Option<(usize, StreamKey)> {
        self.sched.pick()
    }

    /// Moves the part at index `i` of level `u` to the back of its level.
    #[inline]
    pub(super) fn move_back(&mut self, u: usize, i: usize) {
        self.sched.move_back(u, i);
    }

    /// Queues the sending part of `key` at urgency `u` (it has something
    /// to send and is not queued).
    pub(super) fn enqueue(&mut self, key: StreamKey, u: u8) {
        let Some(send) = self.slab.get_mut(key).and_then(|s| s.send.as_mut()) else {
            debug_assert!(false, "only a sending part is queued");
            return;
        };
        debug_assert!(send.queued.is_none());
        send.queued = Some(u);
        self.sched.push(usize::from(u), key);
        self.session_stalled = false;
    }

    /// Takes the part at index `i` of level `u` out of the queue.
    pub(super) fn dequeue_at(&mut self, u: usize, i: usize) -> Option<StreamKey> {
        let key = self.sched.remove_at(u, i)?;
        self.clear_queued(key);
        Some(key)
    }

    /// Takes `key` out of level `u`, wherever it is in it.
    pub(super) fn dequeue(&mut self, u: usize, key: StreamKey) {
        let at = self.sched.level(u).iter().position(|&k| k == key);
        debug_assert!(at.is_some(), "a queued part is in the level it names");
        if let Some(i) = at {
            self.sched.remove_at(u, i);
        }
        self.clear_queued(key);
    }

    /// Takes `key`, the first part of level `u` (just picked), out of the
    /// queue.
    pub(super) fn dequeue_first(&mut self, u: usize, key: StreamKey) {
        debug_assert_eq!(self.sched.level(u).front(), Some(&key));
        self.dequeue_at(u, 0);
    }

    /// Queues a stream for its control frames.
    pub(super) fn queue_ctrl(&mut self, key: StreamKey) {
        if let Some(s) = self.slab.get_mut(key)
            && !s.ctrl_queued
        {
            s.ctrl_queued = true;
            self.ctrl.push_back(key);
        }
    }

    /// Takes the next stream with control frames to send.
    pub(super) fn pop_ctrl(&mut self) -> Option<StreamKey> {
        let key = self.ctrl.pop_front()?;
        if let Some(s) = self.slab.get_mut(key) {
            s.ctrl_queued = false;
        }
        Some(key)
    }

    /// Puts a stream whose control frames did not fit back first.
    pub(super) fn requeue_ctrl(&mut self, key: StreamKey) {
        if let Some(s) = self.slab.get_mut(key)
            && !s.ctrl_queued
        {
            s.ctrl_queued = true;
            self.ctrl.push_front(key);
        }
    }

    /// Some stream has control frames to send.
    pub(super) fn ctrl_pending(&self) -> bool {
        !self.ctrl.is_empty()
    }

    /// Heap bytes of the queues.
    fn queues_heap_bytes(&self) -> usize {
        self.ctrl.capacity() * size_of::<StreamKey>() + self.sched.heap_bytes()
    }

    /// Every queued part waits for session credit, when any is queued.
    pub(super) fn stall_if_queued(&mut self) {
        self.session_stalled = !self.sched.is_empty();
    }

    fn clear_queued(&mut self, key: StreamKey) {
        if let Some(send) = self.slab.get_mut(key).and_then(|s| s.send.as_mut()) {
            send.queued = None;
        }
    }
}
