//! The server of the exchange carrier: a table of carriers, each with one
//! state that the requests of the carrier and the two halves zmux holds
//! share under one lock.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::error::Error as StdError;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Request, Response, StatusCode, header};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use tokio::time::Instant;
use zmux::carrier::MemoryCharge;
use zmux::{Listener, PipeHint, PipeIo};

use super::ExchangeOptions;
use super::wire::{
    self, BUSY, CarrierId, FIN, GONE, Key, Kind, MAX_PREFIX, MAX_REASON, Malformed, REQ_FIN,
};
use crate::body::{PipeBody, collect};

/// The granularity of the memory charged to the listener, so that small
/// changes do not touch its account.
const CHARGE_UNIT: u64 = 64 << 10;

/// The server of the exchange carrier: it turns the requests of each
/// carrier into one pipe handed to its [`Listener`]. Cheap to clone; all
/// clones share the carriers.
///
/// Serve it with [`crate::serve`] and the other serve functions
/// ([`Options::with_exchange`](crate::Options::with_exchange)), which
/// route POST requests whose path starts with the fixed part of
/// [`ExchangeOptions::path`] or [`ExchangeOptions::down_path`] here, or call [`ExchangeServer::handle`] from
/// an HTTP server of the application's own. A carrier's requests may
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

/// A response without a result.
fn status(code: StatusCode) -> Response<PipeBody> {
    let mut r = Response::new(PipeBody::empty());
    *r.status_mut() = code;
    r
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
    /// A server whose carriers are handed to `listener`.
    pub fn new(listener: &Listener, options: ExchangeOptions) -> Self {
        Self {
            inner: Arc::new(Shared {
                listener: listener.clone(),
                options,
                table: Mutex::default(),
            }),
        }
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

    /// Answers one exchange request: a request of the application's own
    /// HTTP server routed here (any method but POST is answered with 405).
    /// `peer` is the client's address, which the listener's per-source
    /// limits use. The response has a fixed length; a held DOWN request
    /// resolves within [`ExchangeOptions::hold`]. Must be called inside a
    /// tokio runtime.
    pub async fn handle<B>(&self, req: Request<B>, peer: Option<IpAddr>) -> Response<PipeBody>
    where
        B: http_body::Body<Data = Bytes> + Unpin,
        B::Error: Into<Box<dyn StdError + Send + Sync>>,
    {
        if req.method() != Method::POST {
            return status(StatusCode::METHOD_NOT_ALLOWED);
        }
        let o = &self.inner.options;
        let limit = wire::encoded_len(o.encoding, MAX_PREFIX + o.max_up_piece.max(MAX_REASON));
        let body = match tokio::time::timeout(o.idle_timeout, collect(req.into_body(), limit)).await
        {
            Ok(Ok(Ok(b))) => b,
            Ok(Ok(Err(start))) => return self.over_limit(start),
            _ => return status(StatusCode::BAD_REQUEST),
        };
        let Some(request) =
            wire::decode_body(o.encoding, body).and_then(|b| wire::Request::parse(b).ok())
        else {
            return status(StatusCode::BAD_REQUEST);
        };
        let (key, answer) = match self.inner.process(&request, peer).await {
            Ok(r) => r,
            // Unauthenticated requests look like any unknown target.
            Err(Malformed::Mac) => return status(StatusCode::NOT_FOUND),
            Err(_) => return status(StatusCode::BAD_REQUEST),
        };
        self.respond(&key, &request.answering(), answer)
    }

    /// The answer to an UP request over the local limit: GONE, never
    /// retried. Its data is not read, so its MAC is not checked; the
    /// carrier's state does not change.
    fn over_limit(&self, start: Bytes) -> Response<PipeBody> {
        let o = &self.inner.options;
        let start = match o.encoding {
            super::BodyEncoding::Base64 => start.slice(..start.len() / 4 * 4),
            _ => start,
        };
        let parsed =
            wire::decode_body(o.encoding, start).and_then(|b| wire::Request::parse(b).ok());
        match parsed {
            Some(r) if r.kind_byte() == Kind::Up as u8 => {
                let key = Key::new(&o.psk, &r.cid);
                self.respond(&key, &r.answering(), Answer::flags(GONE))
            }
            _ => status(StatusCode::PAYLOAD_TOO_LARGE),
        }
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

/// The answer to an authentic request that breaks Section 3: GONE, bound
/// like every response to the Kind byte as sent.
fn invalid(key: Key) -> (Key, Answer) {
    (key, Answer::flags(GONE))
}

enum Lookup {
    Live(Arc<Carrier>),
    Gone,
    New,
}

impl Shared {
    /// Processes an authentic request; returns the key and kind it is
    /// answered with, and the answer.
    async fn process(
        self: &Arc<Self>,
        req: &wire::Request,
        peer: Option<IpAddr>,
    ) -> Result<(Key, Answer), Malformed> {
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
        let carrier = match lookup {
            Lookup::Live(c) => c,
            Lookup::Gone => {
                let key = Key::new(&o.psk, &req.cid);
                match req.verify(&key) {
                    Ok(_) | Err(Malformed::Invalid) => return Ok((key, Answer::flags(GONE))),
                    Err(e) => return Err(e),
                }
            }
            Lookup::New => {
                let key = Key::new(&o.psk, &req.cid);
                let kind = match req.verify(&key) {
                    Ok(k) => k,
                    Err(Malformed::Invalid) => return Ok(invalid(key)),
                    Err(e) => return Err(e),
                };
                if kind == Kind::Close {
                    // Created and closed at once.
                    let until = Instant::now() + o.gone_memory;
                    lock(&self.table).remember(req.cid, until, o.max_carriers);
                    return Ok((key, Answer::flags(0)));
                }
                match self.create(req.cid, key.clone(), peer) {
                    Some(c) => c,
                    None => return Ok((key, Answer::flags(BUSY))),
                }
            }
        };
        let kind = match req.verify(&carrier.key) {
            Ok(k) => k,
            Err(Malformed::Invalid) => {
                carrier.fail();
                return Ok(invalid(carrier.key.clone()));
            }
            Err(e) => return Err(e),
        };
        let answer = carrier.request(kind, req).await;
        Ok((carrier.key.clone(), answer))
    }

    /// The carrier `cid`: a new one handed to the listener, or the one
    /// another request just made; `None` beyond the limit.
    fn create(
        self: &Arc<Self>,
        cid: CarrierId,
        key: Key,
        peer: Option<IpAddr>,
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
            });
        let hint = peer.map(PipeHint::from_addr).unwrap_or_default();
        let l = self.listener.clone();
        tokio::spawn(async move {
            let _ = l.handle_pipe(io, hint).await;
        });
        tokio::spawn(carrier.clone().watch_idle());
        Some(carrier)
    }
}

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
            self.up_ooo_bytes + data.len() <= l.up_store
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
                self.up_ooo_bytes -= d.len();
                self.deliver(d);
                self.up_next += 1;
            }
            fx.reader = self.reader.take();
        } else {
            self.up_ooo_bytes += data.len();
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

    /// Assigns piece `n` (Section 7.3).
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
                down_piece: o.down_piece.max(1),
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
    use wire::{Outgoing, Response};

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
        let key = Key::new(b"", cid);
        let out = Outgoing::new(&key, cid, kind, flags, seq, 0, [seq as u8; 8], data);
        let mut body = BytesMut::from(&out.prefix[..]);
        body.extend_from_slice(data);
        let req = Request::post("/zmux/exchange")
            .body(PipeBody::fixed(body.freeze(), Bytes::new()))
            .unwrap();
        let resp = server.handle(req, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = collect(resp.into_body(), 1 << 20).await.unwrap().unwrap();
        let r = Response::parse(body).unwrap();
        assert!(out.verifies(&key, cid, kind, &r));
        r
    }

    /// An authentic request that breaks Section 3 fails its carrier and is
    /// answered GONE, as is every later request of that carrier; one of an
    /// unknown carrier creates nothing.
    #[tokio::test]
    async fn invalid_authentic_requests_fail_the_carrier() {
        let listener = Listener::new(zmux::Config::default(), zmux::ListenerConfig::default());
        let server = ExchangeServer::new(&listener, ExchangeOptions::default());
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
}
