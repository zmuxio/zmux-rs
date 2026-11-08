//! The server of the exchange carrier: a table of carriers, each with one
//! state that the requests of the carrier and the two halves zmux holds
//! share under one lock.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use http::{Request, Response, header};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::time::Instant;
use zmux::carrier::MemoryCharge;
use zmux::{Listener, PipeHint, PipeIo};

use super::ExchangeOptions;
use super::record::Record;
use super::wire::{
    self, BUSY, CarrierId, FIN, GONE, Key, Kind, MAX_PREFIX, MAX_REASON, REQ_FIN, unix_seconds,
};
use crate::body::{PipeBody, ReplayBody, read_len};

/// The granularity of the memory charged to the listener, so that small
/// changes do not touch its account.
const CHARGE_UNIT: u64 = 64 << 10;

/// The server of the exchange carrier: it turns the requests of each
/// carrier into one pipe handed to its [`Listener`]. Cheap to clone; all
/// clones share the carriers.
///
/// Serve it with [`crate::serve`] and the other serve functions
/// ([`Options::with_exchange`](crate::Options::with_exchange)), which
/// route requests whose path starts with the fixed part of
/// [`ExchangeOptions::path`] or [`ExchangeOptions::down_path`] here, or call
/// [`ExchangeServer::handle`] from an HTTP server of the application's own. A carrier's requests may
/// arrive on any connection.
///
/// The bytes a carrier holds (uplink pieces for zmux, downlink bytes not
/// yet acknowledged) are charged to the listener's memory budget
/// ([`Listener::charge_memory`]).
#[derive(Clone)]
pub struct ExchangeServer {
    inner: Arc<Shared>,
}

impl std::fmt::Debug for ExchangeServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExchangeServer")
            .field("path", &self.inner.options.path)
            .field("carriers", &self.carriers())
            .finish_non_exhaustive()
    }
}

struct Shared {
    listener: Listener,
    options: ExchangeOptions,
    /// The time window in seconds.
    window: i64,
    record: Record,
    table: Mutex<Table>,
}

#[derive(Default)]
struct Table {
    live: HashMap<CarrierId, Arc<Carrier>>,
    /// Carriers that ended, until their expiry, oldest first in `order`.
    gone: HashMap<CarrierId, Instant>,
    order: VecDeque<(CarrierId, Instant)>,
}

impl Table {
    /// Forgets ended carriers past their expiry, and the oldest beyond
    /// `most`.
    fn prune(&mut self, now: Instant, most: Option<usize>) {
        while let Some(&(id, at)) = self.order.front() {
            if at > now && most.is_none_or(|m| self.order.len() <= m) {
                break;
            }
            self.order.pop_front();
            if self.gone.get(&id) == Some(&at) {
                self.gone.remove(&id);
            }
        }
    }

    fn remember(&mut self, id: CarrierId, until: Instant, most: Option<usize>) {
        self.gone.insert(id, until);
        self.order.push_back((id, until));
        self.prune(Instant::now(), most);
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a request gets: flags and data, MAC'd for the request.
struct Answer {
    flags: u8,
    data: Bytes,
}

impl Answer {
    fn flags(flags: u8) -> Self {
        Self {
            flags,
            data: Bytes::new(),
        }
    }
}

impl ExchangeServer {
    /// A server whose carriers are handed to `listener`. Fails
    /// ([`io::ErrorKind::InvalidInput`]) on options without a PSK
    /// that do not choose to run unauthenticated
    /// ([`ExchangeOptions::unauthenticated`]), or that set both.
    pub fn new(listener: &Listener, options: ExchangeOptions) -> io::Result<Self> {
        options.mac_psk()?;
        // A difference of Times is a signed 32-bit value: a wider window
        // takes every Time.
        let window = i64::try_from(options.time_window.as_secs())
            .unwrap_or(i64::MAX)
            .min(i64::from(i32::MAX) + 1);
        Ok(Self {
            inner: Arc::new(Shared {
                listener: listener.clone(),
                window,
                record: Record::new(window, options.max_recorded),
                options,
                table: Mutex::default(),
            }),
        })
    }

    /// The options.
    pub fn options(&self) -> &ExchangeOptions {
        &self.inner.options
    }

    /// Carriers with state now (not those only remembered as ended).
    pub fn carriers(&self) -> usize {
        lock(&self.inner.table).live.len()
    }

    /// Whether `path` is that of an exchange request.
    pub(crate) fn matches(&self, path: &str) -> bool {
        self.inner
            .options
            .path_prefixes()
            .iter()
            .any(|p| path.starts_with(p))
    }

    /// Serves one request routed here by an HTTP server of the
    /// application's own. A request that is not an exchange request as
    /// [`crate::classify`] tells is given back at once. One that the
    /// server authenticates (a `Content-Length` within the body limit, a
    /// body that is a
    /// request, whose MAC verifies, whose Time is within
    /// [`ExchangeOptions::time_window`] of the clock and whose (Carrier ID,
    /// Nonce) pair was not recorded before) is answered; the response has
    /// a fixed length, and a held DOWN request resolves within
    /// [`ExchangeOptions::hold`]. Every other request changes nothing and
    /// is given back as `Err`, the body bytes read replayed in front of the
    /// rest, for the host server's fallback. An exchange request that an intermediary
    /// forwarded from TLS early data is answered `425 (Too Early)`
    /// ([`crate::too_early`]). `peer` is the connection's remote address;
    /// the carrier's source is the client a trusted intermediary reports in
    /// a forwarding header field on top ([`crate::request_source`]), which
    /// the listener's per-source limits use. A new carrier goes through the
    /// listener's admission like any ([`Listener::handle_pipe`]). Must be
    /// called inside a tokio runtime.
    #[allow(
        clippy::result_large_err,
        reason = "the request is handed back by value, as a host server routes it"
    )]
    pub async fn handle<B>(
        &self,
        req: Request<B>,
        peer: Option<SocketAddr>,
    ) -> Result<Response<PipeBody>, Request<ReplayBody<B>>>
    where
        B: http_body::Body + Unpin,
        B::Data: Buf,
    {
        let (parts, mut body) = req.into_parts();
        // The one classification: any other
        // request is the host's, before anything else.
        if crate::classify(&parts) != Some(crate::RequestClass::Exchange) {
            return Err(Request::from_parts(
                parts,
                ReplayBody::new([Bytes::new(), Bytes::new()], Some(body)),
            ));
        }
        if crate::forwarded_early_data(&parts.headers) {
            // Forwarded from TLS early data: no carrier is taken from it.
            self.inner.listener.count_setup_failure();
            return Ok(crate::too_early());
        }
        let o = &self.inner.options;
        let limit = wire::encoded_len(
            o.encoding,
            MAX_PREFIX + o.max_up_piece_size().max(MAX_REASON),
        );
        let len = content_length(&parts.headers).filter(|&n| n <= limit);
        let Some(len) = len else {
            return Err(Request::from_parts(
                parts,
                ReplayBody::new([Bytes::new(), Bytes::new()], Some(body)),
            ));
        };
        let deadline = Instant::now() + o.idle_timeout;
        let (raw, complete) = read_len(&mut body, len, deadline).await;
        let request = complete
            .then(|| wire::decode_body(o.encoding, raw.clone()))
            .flatten()
            .and_then(wire::Request::parse);
        let authenticated = request.and_then(|r| {
            let (lookup, key) = self.inner.authenticate(&r)?;
            Some((r, lookup, key))
        });
        let Some((request, lookup, key)) = authenticated else {
            return Err(Request::from_parts(
                parts,
                ReplayBody::new([raw, Bytes::new()], Some(body)),
            ));
        };
        let peer = peer.map(|p| {
            let fields = parts
                .headers
                .iter()
                .map(|(n, v)| (n.as_str(), v.as_bytes()));
            (p, self.inner.listener.trusted_proxies().source(p, fields))
        });
        let answer = self.inner.process(&request, lookup, &key, peer).await;
        Ok(self.respond(&key, &request.answering(), answer))
    }

    fn respond(&self, key: &Key, to: &wire::Answering<'_>, answer: Answer) -> Response<PipeBody> {
        let o = &self.inner.options;
        let head = wire::response_head(key, to, answer.flags, &answer.data);
        let (head, tail) = wire::encode_body(o.encoding, head, answer.data);
        let mut r = Response::new(PipeBody::fixed(head, tail));
        let h = r.headers_mut();
        h.insert(
            header::CACHE_CONTROL,
            http::HeaderValue::from_static("no-store"),
        );
        h.insert(
            header::CONTENT_TYPE,
            http::HeaderValue::from_static(match o.encoding {
                super::BodyEncoding::Base64 => "text/plain",
                _ => "application/octet-stream",
            }),
        );
        r
    }
}

/// The value of a request's `Content-Length`, when it has exactly one that
/// is a number.
fn content_length(h: &http::HeaderMap) -> Option<usize> {
    let mut values = h.get_all(header::CONTENT_LENGTH).iter();
    let v = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let v = v.as_bytes();
    if v.is_empty() || !v.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(v).ok()?.parse().ok()
}

/// The time in seconds that the Time `time` stands for when the clock is
/// `now`, or `None` when the two differ by more than `window`: the
/// difference is taken modulo 2^32 as a signed 32-bit value.
fn within_window(time: u32, now: i64, window: i64) -> Option<i64> {
    let d = i64::from(time.wrapping_sub(now as u32) as i32);
    (d.abs() <= window).then_some(now + d)
}

/// What the server holds for a request's Carrier ID.
enum Lookup {
    Live(Arc<Carrier>),
    Gone,
    New,
}

impl Shared {
    /// Authenticates a parsed request: its MAC, its Time
    /// within the window, and its (Carrier ID, Nonce) pair, which it
    /// records. `None` when it is not authenticated.
    fn authenticate(&self, req: &wire::Request) -> Option<(Lookup, Key)> {
        let o = &self.options;
        let lookup = {
            let mut t = lock(&self.table);
            t.prune(Instant::now(), o.max_carriers);
            match t.live.get(&req.cid) {
                Some(c) => Lookup::Live(c.clone()),
                None if t.gone.contains_key(&req.cid) => Lookup::Gone,
                None => Lookup::New,
            }
        };
        let key = match &lookup {
            Lookup::Live(c) => c.key.clone(),
            _ => Key::new(&o.psk, &req.cid),
        };
        if !req.authentic(&key) {
            return None;
        }
        let now = i64::try_from(unix_seconds()).ok()?;
        let time = within_window(req.time, now, self.window)?;
        let mut pair = [0; 24];
        pair[..16].copy_from_slice(&req.cid);
        pair[16..].copy_from_slice(&req.nonce);
        self.record
            .insert(pair, time, now - self.window)
            .then_some((lookup, key))
    }

    /// Processes an authenticated request; returns its answer.
    async fn process(
        self: &Arc<Self>,
        req: &wire::Request,
        lookup: Lookup,
        key: &Key,
        peer: Option<(SocketAddr, SocketAddr)>,
    ) -> Answer {
        let o = &self.options;
        let Some(kind) = req.valid_kind() else {
            // Authenticated, but its fields break the request rules.
            if let Lookup::Live(c) = lookup {
                c.fail();
            }
            return Answer::flags(GONE);
        };
        let carrier = match lookup {
            Lookup::Live(c) => c,
            Lookup::Gone => return Answer::flags(GONE),
            Lookup::New if kind == Kind::Close => {
                // Created and closed at once.
                let until = Instant::now() + o.gone_memory;
                lock(&self.table).remember(req.cid, until, o.max_carriers);
                return Answer::flags(0);
            }
            Lookup::New => match self.create(req.cid, key.clone(), peer) {
                Some(c) => c,
                None => return Answer::flags(BUSY),
            },
        };
        carrier.request(kind, req).await
    }

    /// The carrier `cid`: a new one handed to the listener, or the one
    /// another request just made; `None` beyond the limit, or when the
    /// listener refuses it (its source has its share of pending carriers,
    /// [`zmux::ListenerConfig::max_pending_per_source`]).
    fn create(
        self: &Arc<Self>,
        cid: CarrierId,
        key: Key,
        peer: Option<(SocketAddr, SocketAddr)>,
    ) -> Option<Arc<Carrier>> {
        let o = &self.options;
        let carrier = {
            let mut t = lock(&self.table);
            if let Some(c) = t.live.get(&cid) {
                return Some(c.clone());
            }
            if t.gone.contains_key(&cid) || o.max_carriers.is_some_and(|m| t.live.len() >= m) {
                return None;
            }
            let c = Arc::new(Carrier::new(
                cid,
                key,
                Arc::downgrade(self),
                o,
                &self.listener,
            ));
            t.live.insert(cid, c.clone());
            c
        };
        let io = PipeIo::from_halves(UpReader(carrier.clone()), DownWriter(carrier.clone()))
            .with_abort({
                let c = carrier.clone();
                move || c.fail()
            })
            .with_carrier(zmux::CarrierKind::Exchange);
        let hint = match peer {
            Some((peer, source)) => PipeHint::from_peer(peer).with_source(source),
            None => PipeHint::default(),
        };
        let l = self.listener.clone();
        let mut handle = Box::pin(async move { l.handle_pipe(io, hint).await });
        // The listener takes or refuses the carrier on the first poll,
        // before it waits for anything: a carrier beyond the source's share
        // of pending carriers (or of a closed listener) is refused now, so
        // that it holds no state and the request is answered BUSY.
        let refused = matches!(
            handle
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(zmux::HandleError::Refused))
        );
        if refused {
            // Not remembered as ended either (the dropped pipe may have
            // retired it): a refused request consumed nothing.
            let mut t = lock(&self.table);
            if t.live.get(&cid).is_some_and(|c| Arc::ptr_eq(c, &carrier)) {
                t.live.remove(&cid);
            }
            if t.gone.remove(&cid).is_some() && t.order.back().is_some_and(|e| e.0 == cid) {
                t.order.pop_back();
            }
            return None;
        }
        tokio::spawn(handle);
        tokio::spawn(carrier.clone().watch_idle());
        Some(carrier)
    }
}

/// What an out-of-order UP piece counts against the uplink store limit
/// besides its bytes; it bounds how many pieces are held, empty ones too.
pub(crate) const PIECE_COST: usize = 64;

/// The local parameters a carrier uses.
#[derive(Clone, Copy)]
struct Limits {
    hold: Duration,
    coalesce: Duration,
    down_piece: usize,
    down_window: u64,
    up_store: usize,
    idle: Duration,
    gone_memory: Duration,
    max_carriers: Option<usize>,
}

/// One carrier of the server.
struct Carrier {
    cid: CarrierId,
    key: Key,
    server: Weak<Shared>,
    limits: Limits,
    listener: Listener,
    state: Mutex<State>,
    /// Held DOWN requests wait on it: an assignment, new bytes, the end.
    changed: Notify,
    /// The idle watch waits on it: the carrier left the table.
    ended: Notify,
}

#[derive(Clone)]
struct Piece {
    data: Bytes,
    fin: bool,
}

#[derive(Default)]
struct State {
    /// Failed or closed: every request is answered GONE.
    failed: bool,
    /// Left the table (complete or failed).
    retired: bool,
    last_request: Option<Instant>,

    // ---- uplink ----
    /// The lowest uplink number not received.
    up_next: u64,
    /// Pieces received above `up_next`.
    up_ooo: BTreeMap<u64, Bytes>,
    /// Their bytes, and PIECE_COST for each.
    up_ooo_bytes: usize,
    up_fin: Option<u64>,
    /// The highest uplink number received.
    up_top: Option<u64>,
    /// Contiguous uplink bytes for zmux.
    queue: VecDeque<Bytes>,
    queue_bytes: usize,
    reader: Option<Waker>,
    reader_gone: bool,

    // ---- downlink ----
    /// Bytes zmux wrote that no piece holds yet.
    pending: BytesMut,
    /// When the bytes of `pending` started to wait for a piece.
    pending_since: Option<Instant>,
    write_closed: bool,
    writer: Option<Waker>,
    /// Assigned pieces from `ack` on.
    pieces: BTreeMap<u64, Piece>,
    pieces_bytes: usize,
    /// The lowest unassigned number.
    contig: u64,
    /// The highest assigned number plus one.
    assigned_end: u64,
    down_fin: Option<u64>,
    /// The highest Down Ack received.
    ack: u64,
    /// The DOWN requests held, by number: the ticket of the latest.
    held: HashMap<u64, u64>,
    tickets: u64,

    charge: Option<MemoryCharge>,
    charged: u64,
}

/// What to do after the state's lock is released.
#[derive(Default)]
#[must_use]
struct Effects {
    reader: Option<Waker>,
    writer: Option<Waker>,
    changed: bool,
    retire: bool,
}

/// The next step of a held DOWN request.
enum Step {
    Answer(Answer),
    Wait(Instant),
}

impl State {
    fn fail(&mut self) -> Effects {
        if self.failed {
            return Effects::default();
        }
        self.failed = true;
        self.up_ooo.clear();
        self.queue.clear();
        self.pending = BytesMut::new();
        self.pieces.clear();
        self.up_ooo_bytes = 0;
        self.queue_bytes = 0;
        self.pieces_bytes = 0;
        self.charge = None;
        self.charged = 0;
        Effects {
            reader: self.reader.take(),
            writer: self.writer.take(),
            changed: true,
            retire: true,
        }
    }

    fn up_eof(&self) -> bool {
        self.up_fin.is_some_and(|f| self.up_next > f)
    }

    /// Complete: the uplink FIN passed to zmux, and the client past the
    /// downlink FIN.
    fn complete(&self) -> bool {
        self.up_eof() && self.down_fin.is_some_and(|f| self.ack > f)
    }

    /// Takes a Down Ack; an impossible one fails the carrier.
    fn take_ack(&mut self, ack: u64) -> Result<(), ()> {
        if ack <= self.ack {
            return Ok(());
        }
        if ack > self.assigned_end {
            return Err(());
        }
        self.ack = ack;
        let kept = self.pieces.split_off(&ack);
        for p in std::mem::replace(&mut self.pieces, kept).into_values() {
            self.pieces_bytes -= p.data.len();
        }
        Ok(())
    }

    /// An uplink piece.
    fn up(&mut self, n: u64, fin: bool, data: &Bytes, l: &Limits) -> Result<(Answer, Effects), ()> {
        if let Some(f) = self.up_fin
            && (n > f || (fin && n != f))
        {
            return Err(());
        }
        if fin && self.up_top.is_some_and(|t| t > n) {
            return Err(());
        }
        if n < self.up_next || self.up_ooo.contains_key(&n) {
            return Ok((Answer::flags(0), Effects::default()));
        }
        let room = if n == self.up_next {
            self.reader_gone || self.queue_bytes < l.up_store
        } else {
            self.up_ooo_bytes + data.len() + PIECE_COST <= l.up_store
        };
        if !room {
            return Ok((Answer::flags(BUSY), Effects::default()));
        }
        if fin {
            self.up_fin = Some(n);
        }
        self.up_top = Some(self.up_top.map_or(n, |t| t.max(n)));
        let mut fx = Effects::default();
        if n == self.up_next {
            self.deliver(data.clone());
            self.up_next += 1;
            while let Some(d) = self.up_ooo.remove(&self.up_next) {
                self.up_ooo_bytes -= d.len() + PIECE_COST;
                self.deliver(d);
                self.up_next += 1;
            }
            fx.reader = self.reader.take();
        } else {
            self.up_ooo_bytes += data.len() + PIECE_COST;
            self.up_ooo.insert(n, data.clone());
        }
        Ok((Answer::flags(0), fx))
    }

    fn deliver(&mut self, d: Bytes) {
        if !self.reader_gone && !d.is_empty() {
            self.queue_bytes += d.len();
            self.queue.push_back(d);
        }
    }

    /// Whether held DOWN request `n` can be answered now.
    fn ready(&self, n: u64, now: Instant, held_at: Instant, l: &Limits) -> bool {
        if self.down_fin.is_some() || (self.write_closed && self.pending.is_empty()) {
            return true;
        }
        n == self.contig
            && self.pending_since.is_some_and(|t| {
                self.pending.len() >= l.down_piece || now >= t.max(held_at) + l.coalesce
            })
    }

    /// The next step of held DOWN request `n` with `ticket`, held until
    /// `deadline`.
    fn down_step(
        &mut self,
        n: u64,
        ticket: u64,
        now: Instant,
        deadline: Instant,
        l: &Limits,
    ) -> (Step, Effects) {
        let none = Effects::default;
        if self.failed {
            return (Step::Answer(Answer::flags(GONE)), none());
        }
        if self.held.get(&n) != Some(&ticket) || n < self.ack {
            // A newer repetition holds it, or the client has it.
            return (Step::Answer(Answer::flags(BUSY)), none());
        }
        if let Some(p) = self.pieces.get(&n) {
            return (Step::Answer(piece_answer(p)), none());
        }
        // The coalescing delay runs only while a request is held.
        let held_at = deadline - l.hold;
        if self.ready(n, now, held_at, l) || now >= deadline {
            let (p, fx) = self.assign(n, now, l);
            return (Step::Answer(piece_answer(&p)), fx);
        }
        let mut at = deadline;
        if n == self.contig
            && let Some(t) = self.pending_since
        {
            at = at.min(t.max(held_at) + l.coalesce);
        }
        (Step::Wait(at), none())
    }

    /// Assigns downlink piece `n`.
    fn assign(&mut self, n: u64, now: Instant, l: &Limits) -> (Piece, Effects) {
        let mut fx = Effects {
            changed: true,
            ..Effects::default()
        };
        let piece = if let Some(f) = self.down_fin {
            Piece {
                data: Bytes::new(),
                fin: n > f,
            }
        } else if n == self.contig && !self.pending.is_empty() {
            let take = self.pending.len().min(l.down_piece.max(1));
            let data = self.pending.split_to(take).freeze();
            // The rest goes to the next piece, which may take bytes from now.
            self.pending_since = (!self.pending.is_empty()).then_some(now);
            fx.writer = self.writer.take();
            let fin = self.write_closed && self.pending.is_empty();
            Piece { data, fin }
        } else {
            Piece {
                data: Bytes::new(),
                fin: self.write_closed && self.pending.is_empty(),
            }
        };
        if piece.fin && self.down_fin.is_none() {
            self.down_fin = Some(n);
        }
        self.pieces_bytes += piece.data.len();
        self.pieces.insert(n, piece.clone());
        self.assigned_end = self.assigned_end.max(n + 1);
        while self.pieces.contains_key(&self.contig) {
            self.contig += 1;
        }
        (piece, fx)
    }

    /// The bytes held for the carrier.
    fn held_bytes(&self) -> u64 {
        (self.queue_bytes + self.up_ooo_bytes + self.pending.len() + self.pieces_bytes) as u64
    }
}

fn piece_answer(p: &Piece) -> Answer {
    Answer {
        flags: if p.fin { FIN } else { 0 },
        data: p.data.clone(),
    }
}

/// Removes a held DOWN request when its handler ends, however it ends.
struct Held<'a> {
    carrier: &'a Carrier,
    n: u64,
    ticket: u64,
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        let mut st = self.carrier.lock();
        if st.held.get(&self.n) == Some(&self.ticket) {
            st.held.remove(&self.n);
        }
    }
}

impl Carrier {
    fn new(
        cid: CarrierId,
        key: Key,
        server: Weak<Shared>,
        o: &ExchangeOptions,
        listener: &Listener,
    ) -> Self {
        Self {
            cid,
            key,
            server,
            limits: Limits {
                hold: o.hold,
                coalesce: o.coalesce,
                down_piece: o.down_piece_size(),
                down_window: o.down_window.max(1),
                up_store: o.up_store,
                idle: o.idle_timeout,
                gone_memory: o.gone_memory,
                max_carriers: o.max_carriers,
            },
            listener: listener.clone(),
            state: Mutex::new(State {
                last_request: Some(Instant::now()),
                ..State::default()
            }),
            changed: Notify::new(),
            ended: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    /// Releases the lock, then wakes, recharges and retires as `fx` says.
    fn apply(&self, mut st: MutexGuard<'_, State>, mut fx: Effects) {
        if !st.retired && !st.failed && st.complete() {
            fx.retire = true;
        }
        if fx.retire {
            if st.retired {
                fx.retire = false;
            }
            st.retired = true;
        }
        if !st.failed {
            let want = st.held_bytes().div_ceil(CHARGE_UNIT) * CHARGE_UNIT;
            if want != st.charged {
                st.charged = want;
                st.charge = (want > 0).then(|| self.listener.charge_memory(want));
            }
        }
        drop(st);
        for w in [fx.reader, fx.writer].into_iter().flatten() {
            w.wake();
        }
        if fx.changed {
            self.changed.notify_waiters();
        }
        if fx.retire {
            self.ended.notify_one();
            if let Some(server) = self.server.upgrade() {
                let mut t = lock(&server.table);
                if t.live
                    .get(&self.cid)
                    .is_some_and(|c| std::ptr::eq(&**c, self))
                {
                    t.live.remove(&self.cid);
                }
                let until = Instant::now() + self.limits.gone_memory;
                t.remember(self.cid, until, self.limits.max_carriers);
            }
        }
    }

    fn fail(&self) {
        let mut st = self.lock();
        let fx = st.fail();
        self.apply(st, fx);
    }

    /// Processes an authentic request of `kind`.
    async fn request(&self, kind: Kind, req: &wire::Request) -> Answer {
        let now = Instant::now();
        match self.request_now(kind, req, now) {
            Ok(a) => a,
            Err((n, ticket)) => self.hold(n, ticket, now + self.limits.hold).await,
        }
    }

    /// Processes a request as far as it can be at once; a DOWN request to
    /// hold is returned as its number and ticket.
    fn request_now(
        &self,
        kind: Kind,
        req: &wire::Request,
        now: Instant,
    ) -> Result<Answer, (u64, u64)> {
        let mut st = self.lock();
        if st.failed {
            return Ok(Answer::flags(GONE));
        }
        st.last_request = Some(now);
        if st.take_ack(req.ack).is_err() {
            let fx = st.fail();
            self.apply(st, fx);
            return Ok(Answer::flags(GONE));
        }
        match kind {
            Kind::Close => {
                // Complete when its Down Ack passed the downlink FIN and
                // the uplink FIN reached zmux; otherwise an abort.
                let fx = if st.complete() {
                    Effects::default()
                } else {
                    st.fail()
                };
                self.apply(st, fx);
                Ok(Answer::flags(0))
            }
            Kind::Up => match st.up(req.seq, req.flags & REQ_FIN != 0, &req.data, &self.limits) {
                Ok((a, fx)) => {
                    self.apply(st, fx);
                    Ok(a)
                }
                Err(()) => {
                    let fx = st.fail();
                    self.apply(st, fx);
                    Ok(Answer::flags(GONE))
                }
            },
            Kind::Down => {
                let n = req.seq;
                if n < st.ack {
                    self.apply(st, Effects::default());
                    return Ok(Answer::flags(BUSY));
                }
                if let Some(p) = st.pieces.get(&n) {
                    let a = piece_answer(p);
                    self.apply(st, Effects::default());
                    return Ok(a);
                }
                if n - st.ack >= self.limits.down_window {
                    self.apply(st, Effects::default());
                    return Ok(Answer::flags(BUSY));
                }
                st.tickets += 1;
                let ticket = st.tickets;
                // A newer repetition displaces the older one, which is
                // answered BUSY.
                let displaced = st.held.insert(n, ticket).is_some();
                self.apply(
                    st,
                    Effects {
                        changed: displaced,
                        ..Effects::default()
                    },
                );
                Err((n, ticket))
            }
        }
    }

    /// Holds DOWN request `n` until it can be answered, at most until
    /// `deadline`.
    async fn hold(&self, n: u64, ticket: u64, deadline: Instant) -> Answer {
        let _held = Held {
            carrier: self,
            n,
            ticket,
        };
        loop {
            let notified = self.changed.notified();
            let mut notified = std::pin::pin!(notified);
            notified.as_mut().enable();
            let step = {
                let mut st = self.lock();
                let (step, fx) = st.down_step(n, ticket, Instant::now(), deadline, &self.limits);
                self.apply(st, fx);
                step
            };
            match step {
                Step::Answer(a) => return a,
                Step::Wait(at) => {
                    tokio::select! {
                        () = notified => {}
                        () = tokio::time::sleep_until(at) => {}
                    }
                }
            }
        }
    }

    /// Fails the carrier after the idle timeout without a request; one that
    /// zmux finished in both directions ends without a failure.
    async fn watch_idle(self: Arc<Self>) {
        loop {
            let at = {
                let st = self.lock();
                if st.retired {
                    return;
                }
                st.last_request.unwrap_or_else(Instant::now) + self.limits.idle
            };
            tokio::select! {
                () = self.ended.notified() => {}
                () = tokio::time::sleep_until(at) => {}
            }
            let mut st = self.lock();
            if st.retired {
                return;
            }
            if st
                .last_request
                .is_some_and(|t| t + self.limits.idle <= Instant::now())
            {
                let fx = if st.up_eof() && st.down_fin.is_some() {
                    Effects {
                        retire: true,
                        ..Effects::default()
                    }
                } else {
                    st.fail()
                };
                self.apply(st, fx);
                return;
            }
        }
    }
}

/// The uplink as zmux reads it.
struct UpReader(Arc<Carrier>);

impl AsyncRead for UpReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let c = &self.0;
        let mut st = c.lock();
        if st.queue.is_empty() {
            if st.failed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "exchange carrier failed",
                )));
            }
            if st.up_eof() {
                return Poll::Ready(Ok(()));
            }
            st.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        while buf.remaining() > 0 {
            let Some(front) = st.queue.front_mut() else {
                break;
            };
            let n = front.len().min(buf.remaining());
            buf.put_slice(&front[..n]);
            front.advance(n);
            if front.is_empty() {
                st.queue.pop_front();
            }
            st.queue_bytes -= n;
        }
        c.apply(st, Effects::default());
        Poll::Ready(Ok(()))
    }
}

impl Drop for UpReader {
    fn drop(&mut self) {
        let mut st = self.0.lock();
        st.reader_gone = true;
        st.queue.clear();
        st.queue_bytes = 0;
        self.0.apply(st, Effects::default());
    }
}

/// The downlink as zmux writes it.
struct DownWriter(Arc<Carrier>);

impl AsyncWrite for DownWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let c = &self.0;
        let mut st = c.lock();
        if st.failed || st.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let room = c.limits.down_piece.saturating_sub(st.pending.len());
        if room == 0 {
            st.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(buf.len());
        if st.pending.is_empty() {
            st.pending_since = Some(Instant::now());
        }
        st.pending.extend_from_slice(&buf[..n]);
        let fx = Effects {
            changed: !st.held.is_empty(),
            ..Effects::default()
        };
        c.apply(st, fx);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let c = &self.0;
        let mut st = c.lock();
        if st.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        st.write_closed = true;
        c.apply(
            st,
            Effects {
                changed: true,
                ..Effects::default()
            },
        );
        Poll::Ready(Ok(()))
    }
}

impl Drop for DownWriter {
    fn drop(&mut self) {
        // zmux shuts a sending half down before it drops it gracefully.
        let mut st = self.0.lock();
        let fx = if st.write_closed {
            Effects::default()
        } else {
            st.fail()
        };
        self.0.apply(st, fx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::collect;
    use http::StatusCode;
    use std::sync::atomic::{AtomicU64, Ordering};
    use wire::{Outgoing, Response};

    static NONCES: AtomicU64 = AtomicU64::new(1);

    fn server(o: ExchangeOptions) -> (Listener, ExchangeServer) {
        let listener = Listener::new(zmux::Config::default(), zmux::ListenerConfig::default())
            .expect("valid listener configuration");
        let server = ExchangeServer::new(&listener, o.with_unauthenticated()).unwrap();
        (listener, server)
    }

    /// A request of carrier `cid` with this Time and Nonce, and its body.
    fn request(
        cid: &CarrierId,
        kind: Kind,
        flags: u8,
        seq: u64,
        time: u32,
        nonce: [u8; 8],
        data: &[u8],
    ) -> (Outgoing, Request<PipeBody>) {
        let key = Key::new(b"", cid);
        let out = Outgoing::new(&key, cid, kind, flags, seq, 0, time, nonce, data);
        let mut body = BytesMut::from(&out.prefix[..]);
        body.extend_from_slice(data);
        let req = Request::post("/zmux/exchange")
            .header(header::CONTENT_LENGTH, body.len())
            .body(PipeBody::full(body.freeze()))
            .unwrap();
        (out, req)
    }

    /// Sends one request of carrier `cid` and returns its verified
    /// response.
    async fn send(
        server: &ExchangeServer,
        cid: &CarrierId,
        kind: Kind,
        flags: u8,
        seq: u64,
        data: &'static [u8],
    ) -> Response {
        let nonce = NONCES.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        let (out, req) = request(cid, kind, flags, seq, wire::unix_time(), nonce, data);
        let resp = server.handle(req, None).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = collect(resp.into_body(), 1 << 20).await.unwrap().unwrap();
        let r = Response::parse(body).unwrap();
        assert!(out.verifies(&Key::new(b"", cid), cid, kind, &r));
        r
    }

    /// The bytes of a body handed back.
    async fn replayed(req: Request<ReplayBody<PipeBody>>) -> Bytes {
        collect(req.into_body(), 4 << 20).await.unwrap().unwrap()
    }

    /// Only an exchange request as the endpoint classifies it is served: a
    /// POST with a pairing token is an uplink, not an exchange request,
    /// and goes back to the host with its body untouched.
    #[tokio::test]
    async fn requests_of_another_class_go_back_to_the_host() {
        let (listener, server) = server(ExchangeOptions::default());
        let nonce = NONCES.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        let (_, req) = request(&[9; 16], Kind::Up, 0, 0, wire::unix_time(), nonce, b"x");
        let (mut parts, body) = req.into_parts();
        parts
            .headers
            .insert(zmux::PAIR_HEADER, http::HeaderValue::from_static("x"));
        let back = server
            .handle(Request::from_parts(parts, body), None)
            .await
            .expect_err("not an exchange request");
        assert!(!replayed(back).await.is_empty());
        assert_eq!(server.carriers(), 0);
        listener.close();
    }

    /// An authentic request that breaks the request rules fails its
    /// carrier and is answered GONE, as is every later request of that
    /// carrier; one of an unknown carrier creates nothing.
    #[tokio::test]
    async fn invalid_authentic_requests_fail_the_carrier() {
        let (listener, server) = server(ExchangeOptions::default());
        let cid = [7; 16];
        assert_eq!(send(&server, &cid, Kind::Up, 0, 0, b"x").await.flags, 0);
        assert_eq!(server.carriers(), 1);
        // A DOWN request with data.
        assert_eq!(
            send(&server, &cid, Kind::Down, 0, 0, b"x").await.flags,
            GONE
        );
        assert_eq!(server.carriers(), 0);
        assert_eq!(send(&server, &cid, Kind::Up, 0, 1, b"y").await.flags, GONE);
        // A reserved UP flag, for a carrier the server does not know.
        let other = [8; 16];
        assert_eq!(
            send(&server, &other, Kind::Up, 0x02, 0, b"x").await.flags,
            GONE
        );
        assert_eq!(server.carriers(), 0);
        listener.close();
    }

    /// Out-of-order UP pieces count PIECE_COST each against the uplink
    /// store, so empty ones are bounded too; the piece the carrier waits for
    /// is still taken.
    #[tokio::test]
    async fn empty_out_of_order_pieces_are_bounded() {
        let (listener, server) = server(ExchangeOptions {
            up_store: 3 * PIECE_COST + 1,
            ..ExchangeOptions::default()
        });
        let cid = [5; 16];
        for n in 1..=3 {
            assert_eq!(send(&server, &cid, Kind::Up, 0, n, b"").await.flags, 0);
        }
        assert_eq!(send(&server, &cid, Kind::Up, 0, 4, b"").await.flags, BUSY);
        assert_eq!(send(&server, &cid, Kind::Up, 0, 0, b"").await.flags, 0);
        assert_eq!(send(&server, &cid, Kind::Up, 0, 4, b"").await.flags, 0);
        listener.close();
    }

    /// A new carrier goes through the listener's per-source limit of
    /// pending carriers: one beyond it is answered BUSY and holds nothing.
    #[tokio::test]
    async fn new_carriers_take_the_sources_pending_share() {
        let mut limits = zmux::ListenerConfig::default();
        limits.max_pending_per_source = 1;
        let listener =
            Listener::new(zmux::Config::default(), limits).expect("valid listener configuration");
        let server =
            ExchangeServer::new(&listener, ExchangeOptions::default().with_unauthenticated())
                .unwrap();
        assert_eq!(send(&server, &[1; 16], Kind::Up, 0, 1, b"").await.flags, 0);
        assert_eq!(server.carriers(), 1);
        assert_eq!(
            send(&server, &[2; 16], Kind::Up, 0, 1, b"").await.flags,
            BUSY
        );
        assert_eq!(server.carriers(), 1);
        // Not remembered as ended: once the share is free it is served.
        assert_eq!(
            send(&server, &[1; 16], Kind::Close, 0, 0, b"").await.flags,
            0
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while send(&server, &[2; 16], Kind::Up, 0, 1, b"").await.flags != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        listener.close();
    }

    #[test]
    fn time_window_arithmetic() {
        let now = 1_000_000;
        assert_eq!(within_window(now as u32, now, 60), Some(now));
        assert_eq!(within_window(now as u32 + 60, now, 60), Some(now + 60));
        assert_eq!(within_window(now as u32 - 60, now, 60), Some(now - 60));
        assert_eq!(within_window(now as u32 + 61, now, 60), None);
        assert_eq!(within_window(now as u32 - 61, now, 60), None);
        // Across 2^32: the clock just past it, the Time just before, and
        // the reverse.
        let now = 1 << 32;
        assert_eq!(within_window(u32::MAX - 9, now, 60), Some(now - 10));
        assert_eq!(within_window(u32::MAX - 60, now, 60), None);
        let now = (1 << 32) - 5;
        assert_eq!(within_window(20, now, 60), Some(now + 25));
        assert_eq!(within_window(56, now, 60), None);
        // A Time 2^31 away in either direction.
        assert_eq!(within_window(0x8000_0000, 0, 0x7fff_ffff), None);
        assert_eq!(
            within_window(0x8000_0000, 0, 0x8000_0000),
            Some(-0x8000_0000)
        );
    }

    /// A request whose Time is outside the window, ahead or behind, is
    /// handed back with its body and creates nothing.
    #[tokio::test]
    async fn requests_outside_the_window_are_handed_back() {
        let (listener, server) =
            server(ExchangeOptions::default().with_time_window(Duration::from_secs(30)));
        let now = wire::unix_time();
        for time in [now.wrapping_add(40), now.wrapping_sub(40)] {
            let (_, req) = request(&[1; 16], Kind::Up, 0, 0, time, [time as u8; 8], b"hi");
            let body = http_body::Body::size_hint(req.body()).exact().unwrap();
            let back = server.handle(req, None).await.unwrap_err();
            assert_eq!(replayed(back).await.len() as u64, body);
        }
        assert_eq!(server.carriers(), 0);
        let (_, req) = request(&[1; 16], Kind::Up, 0, 0, now.wrapping_add(5), [1; 8], b"hi");
        assert!(server.handle(req, None).await.is_ok());
        listener.close();
    }

    /// A request repeated with the same (Carrier ID, Nonce) is handed back.
    #[tokio::test]
    async fn a_repeated_nonce_is_handed_back() {
        let (listener, server) = server(ExchangeOptions::default());
        let now = wire::unix_time();
        let (_, req) = request(&[2; 16], Kind::Up, 0, 0, now, [9; 8], b"a");
        assert!(server.handle(req, None).await.is_ok());
        let (_, req) = request(&[2; 16], Kind::Up, 0, 0, now, [9; 8], b"a");
        let back = server.handle(req, None).await.unwrap_err();
        assert!(replayed(back).await.ends_with(b"a"));
        // The same Nonce with another carrier is another pair.
        let (_, req) = request(&[3; 16], Kind::Up, 0, 0, now, [9; 8], b"a");
        assert!(server.handle(req, None).await.is_ok());
        listener.close();
    }

    /// A request that finds the record full is handed back.
    #[tokio::test]
    async fn a_full_record_hands_requests_back() {
        let (listener, server) = server(ExchangeOptions::default().with_max_recorded(2));
        let now = wire::unix_time();
        for n in 0..3u8 {
            let (_, req) = request(&[4; 16], Kind::Up, 0, n.into(), now, [n; 8], b"a");
            assert_eq!(server.handle(req, None).await.is_ok(), n < 2, "{n}");
        }
        listener.close();
    }

    /// Requests that are not authenticated are all handed back the same
    /// way, with what was read of their bodies.
    #[tokio::test]
    async fn requests_not_authenticated_are_handed_back() {
        let (listener, server) = server(ExchangeOptions::default());
        // Not POST.
        let req = Request::get("/zmux/exchange")
            .body(PipeBody::empty())
            .unwrap();
        let back = server.handle(req, None).await.unwrap_err();
        assert_eq!(back.method(), http::Method::GET);
        assert!(replayed(back).await.is_empty());
        // Without a Content-Length: nothing read.
        let req = Request::post("/zmux/exchange")
            .body(PipeBody::full(Bytes::from_static(b"body")))
            .unwrap();
        assert_eq!(
            &replayed(server.handle(req, None).await.unwrap_err()).await[..],
            b"body"
        );
        // Not a request, read whole.
        let req = Request::post("/zmux/exchange")
            .header(header::CONTENT_LENGTH, 4)
            .body(PipeBody::full(Bytes::from_static(b"body")))
            .unwrap();
        assert_eq!(
            &replayed(server.handle(req, None).await.unwrap_err()).await[..],
            b"body"
        );
        // A MAC that does not verify.
        let (_, req) = request(&[5; 16], Kind::Up, 0, 0, wire::unix_time(), [1; 8], b"a");
        let (parts, body) = req.into_parts();
        let mut bytes = BytesMut::from(&collect(body, 1 << 10).await.unwrap().unwrap()[..]);
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let sent = bytes.freeze();
        let req = Request::from_parts(parts, PipeBody::full(sent.clone()));
        assert_eq!(
            replayed(server.handle(req, None).await.unwrap_err()).await,
            sent
        );
        // Over the body limit: nothing read.
        let big = Bytes::from(vec![0; MAX_PREFIX + (1 << 20) + 1]);
        let req = Request::post("/zmux/exchange")
            .header(header::CONTENT_LENGTH, big.len())
            .body(PipeBody::full(big.clone()))
            .unwrap();
        assert_eq!(
            replayed(server.handle(req, None).await.unwrap_err()).await,
            big
        );
        assert_eq!(server.carriers(), 0);
        listener.close();
    }
}
