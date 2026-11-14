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
use zmux::adapter::Entry;
use zmux::adapter::MemoryCharge;
use zmux::{Listener, PipeHint, PipeIo};

use super::ExchangeOptions;
use super::record::Record;
use super::wire::{
    self, BUSY, CarrierId, FIN, GONE, HEADER_LEN, Header, Key, Kind, MAC_LEN, MAX_REASON, REQ_FIN,
    REQUEST_OVERHEAD, unix_seconds,
};
use crate::body::{Gathered, PipeBody, ReplayBody, read_to};

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
/// [`ExchangeOptions::path`] or `ExchangeOptions::down_path` here, or call
/// [`ExchangeServer::handle`] from an HTTP server of the application's own. A carrier's requests may
/// arrive on any connection.
///
/// The bytes a carrier holds (uplink pieces for zmux, downlink bytes not
/// yet acknowledged) are charged to the listener's memory budget
/// ([`ListenerAdapter::charge_memory`](zmux::adapter::ListenerAdapter::charge_memory)).
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
    /// The listener's first-record timeout: the authentication header
    /// arrives within it.
    first_record: Duration,
    /// The listener's handshake timeout: the rest of an authenticated body
    /// arrives within it.
    handshake: Duration,
    /// The `Content-Length` of a request, in the body encoding.
    bodies: std::ops::RangeInclusive<usize>,
    /// The length of the authentication header in the body encoding.
    header_len: usize,
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
        let limits = listener.limits();
        let enc = options.encoding;
        Ok(Self {
            inner: Arc::new(Shared {
                listener: listener.clone(),
                window,
                record: Record::new(window, options.max_recorded),
                first_record: limits.first_record_timeout,
                handshake: limits.handshake_timeout,
                bodies: wire::encoded_len(enc, REQUEST_OVERHEAD)
                    ..=wire::encoded_len(
                        enc,
                        REQUEST_OVERHEAD + options.max_up_piece_size().max(MAX_REASON),
                    ),
                header_len: wire::encoded_len(enc, HEADER_LEN),
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
    /// [`crate::classify`] tells with `pair`, the pairing field the host
    /// serves split halves by ([`crate::Options::pair_field`]), is given
    /// back at once.
    ///
    /// Every other request takes a place under the listener's limits of
    /// pending carriers, its source's and the global one
    /// ([`ListenerAdapter::enter`](zmux::adapter::ListenerAdapter::enter)); one that finds none is answered `503` without
    /// a body, its body unread, and is not given back. A closed listener
    /// holds no place for a request but still authenticates it, to answer
    /// GONE for a carrier it does not know. The server then reads the
    /// request's authentication header alone, within the listener's
    /// first-record timeout from the request's arrival, and authenticates
    /// it: a `Content-Length` within the body limit that agrees with the
    /// header's Data Length, a Header MAC that verifies, a Time within
    /// [`ExchangeOptions::time_window`] of the clock, and a (Carrier ID,
    /// Nonce) pair not recorded before. A request that is not
    /// authenticated changes nothing and is given back as `Err`, the body
    /// bytes read replayed in front of the rest, for the host server's
    /// fallback. A request of a known carrier gives its place back once
    /// authenticated; one that creates a carrier keeps it until the
    /// carrier enters a session, and the listener's admission decides on
    /// the new carrier ([`Listener::handle_pipe`]). A carrier that the
    /// listener refuses because it closed after the request arrived is
    /// answered BUSY.
    ///
    /// The rest of an authenticated body is read within the listener's
    /// handshake timeout, and its Data MAC verified before anything is
    /// done: one that ends early, arrives late or does not verify changes
    /// nothing and is answered `400` without a body. The body is buffered
    /// as it arrives, never by its declared length. The response has a
    /// fixed length, and a held DOWN request resolves within
    /// [`ExchangeOptions::hold`].
    ///
    /// An exchange request that an intermediary forwarded from TLS early
    /// data is answered `425 (Too Early)` ([`crate::too_early`]). `peer` is
    /// the connection's remote address; the request's source is the client
    /// a trusted intermediary reports in a forwarding header field on top
    /// ([`crate::request_source`]). Must be called inside a tokio runtime.
    #[allow(
        clippy::result_large_err,
        reason = "the request is handed back by value, as a host server routes it"
    )]
    pub async fn handle<B>(
        &self,
        req: Request<B>,
        peer: Option<SocketAddr>,
        pair: &crate::PairField,
    ) -> Result<Response<PipeBody>, Request<ReplayBody<B>>>
    where
        B: http_body::Body + Unpin,
        B::Data: Buf,
    {
        let arrival = Instant::now();
        let (parts, mut body) = req.into_parts();
        let back = |parts, read: Bytes, body| {
            Err(Request::from_parts(
                parts,
                ReplayBody::new([read, Bytes::new()], Some(body)),
            ))
        };
        // The one classification: any other request is the host's, before
        // anything else.
        if crate::classify(&parts, pair) != Some(crate::RequestClass::Exchange) {
            return back(parts, Bytes::new(), body);
        }
        let s = &self.inner;
        if crate::forwarded_early_data(&parts.headers) {
            // Forwarded from TLS early data: no carrier is taken from it.
            s.listener.adapter().count_setup_failure();
            return Ok(crate::too_early());
        }
        let peer = peer.unwrap_or(NO_ADDR);
        let source = crate::request_source(&s.listener, &parts.headers, Some(peer)).unwrap_or(peer);
        // The request's slots from its arrival; none for a closed listener,
        // which still authenticates the request to answer GONE.
        let entry = match s.listener.adapter().enter(peer, Some(source)) {
            Some(e) => Some(e),
            None if s.listener.adapter().is_closed() => None,
            None => {
                return Ok(crate::server::status(http::StatusCode::SERVICE_UNAVAILABLE));
            }
        };
        let Some(len) = content_length(&parts.headers).filter(|n| s.bodies.contains(n)) else {
            if let Some(e) = entry {
                e.release();
            }
            return back(parts, Bytes::new(), body);
        };

        // The authentication header, and nothing more, within the
        // first-record timeout.
        let mut read = Gathered::default();
        let arrived = read_to(&mut body, &mut read, s.header_len, arrival + s.first_record).await;
        let authenticated = arrived
            .then(|| s.header(&read.as_slice()[..s.header_len]))
            .flatten()
            .and_then(|h| {
                let (lookup, key) = s.authenticate(&h, len)?;
                Some((h, lookup, key))
            });
        let Some((header, lookup, key)) = authenticated else {
            if let Some(e) = entry {
                e.release();
            }
            return back(parts, read.freeze(), body);
        };
        // A request of a known carrier gives its place back now; one that
        // may create a carrier keeps it.
        let entry = match lookup {
            Lookup::New => entry,
            _ => {
                if let Some(e) = entry {
                    e.release();
                }
                None
            }
        };

        // Data and the Data MAC, within the handshake timeout.
        let complete = read_to(&mut body, &mut read, len, Instant::now() + s.handshake).await
            && read.len() == len;
        let data_len = header.data_len as usize;
        let rest = read.freeze().slice(s.header_len..);
        let bin = complete
            .then(|| wire::decode_body(s.options.encoding, rest))
            .flatten()
            .filter(|b| b.len() == data_len + MAC_LEN);
        let Some(bin) = bin.filter(|b| header.data_authentic(&key, &b[..data_len], &b[data_len..]))
        else {
            // Changes nothing; the client sees no result.
            if let Some(e) = entry {
                e.release();
            }
            return Ok(crate::server::status(http::StatusCode::BAD_REQUEST));
        };
        let data = bin.slice(..data_len);
        let answer = s.process(&header, &data, lookup, &key, entry).await;
        Ok(self.respond(&key, &header.answering(), answer))
    }

    fn respond(&self, key: &Key, to: &wire::Answering<'_>, answer: Answer) -> Response<PipeBody> {
        let o = &self.inner.options;
        let head = wire::response_head(key, to, answer.flags, &answer.data);
        let mut r = Response::new(PipeBody::fixed(wire::encode_body(
            o.encoding,
            [head, answer.data],
        )));
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

/// The address of a request whose server gave none.
const NO_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

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
    /// The authentication header in its body encoding, decoded.
    fn header(&self, encoded: &[u8]) -> Option<Header> {
        let mut raw = [0; HEADER_LEN];
        match self.options.encoding {
            super::BodyEncoding::Binary => raw.copy_from_slice(encoded),
            super::BodyEncoding::Base64 => {
                // Decoded on the stack; a decoding of another length fails.
                if wire::decode_base64_into(encoded, &mut raw)? != HEADER_LEN {
                    return None;
                }
            }
        }
        Some(Header::parse(raw))
    }

    /// Authenticates a request's header, the body's `len` included: its
    /// MAC, its Time within the window, its Data Length, and its (Carrier
    /// ID, Nonce) pair, which it records. `None` when it is not
    /// authenticated.
    fn authenticate(&self, h: &Header, len: usize) -> Option<(Lookup, Key)> {
        let o = &self.options;
        let lookup = {
            let mut t = lock(&self.table);
            t.prune(Instant::now(), o.max_carriers);
            match t.live.get(&h.cid) {
                Some(c) => Lookup::Live(c.clone()),
                None if t.gone.contains_key(&h.cid) => Lookup::Gone,
                None => Lookup::New,
            }
        };
        let key = match &lookup {
            Lookup::Live(c) => c.key.clone(),
            _ => Key::new(&o.psk, &h.cid),
        };
        if !h.authentic(&key) {
            return None;
        }
        let now = i64::try_from(unix_seconds()).ok()?;
        let time = within_window(h.time, now, self.window)?;
        // The Data Length against the body and the limit of the Kind,
        // before the pair is recorded: a request refused here is refused
        // again however often it is repeated.
        let data_len = h.data_len as usize;
        if data_len > h.data_limit(o.max_up_piece_size())
            || wire::encoded_len(o.encoding, REQUEST_OVERHEAD + data_len) != len
        {
            return None;
        }
        let mut pair = [0; 24];
        pair[..16].copy_from_slice(&h.cid);
        pair[16..].copy_from_slice(&h.nonce);
        self.record
            .insert(pair, time, now - self.window)
            .then_some((lookup, key))
    }

    /// Processes an authenticated request whose Data MAC verified; returns
    /// its answer. `entry` is the place of a request that may create a
    /// carrier.
    async fn process(
        self: &Arc<Self>,
        h: &Header,
        data: &Bytes,
        lookup: Lookup,
        key: &Key,
        entry: Option<Entry>,
    ) -> Answer {
        let o = &self.options;
        let Some(kind) = h.valid_kind(data) else {
            // Authenticated, but its fields break the request rules.
            if let Lookup::Live(c) = lookup {
                c.fail();
            }
            if let Some(e) = entry {
                e.release();
            }
            return Answer::flags(GONE);
        };
        let carrier = match lookup {
            Lookup::Live(c) => c,
            Lookup::Gone => return Answer::flags(GONE),
            Lookup::New if kind == Kind::Close => {
                // Created and closed at once.
                if let Some(e) = entry {
                    e.release();
                }
                let until = Instant::now() + o.gone_memory;
                lock(&self.table).remember(h.cid, until, o.max_carriers);
                return Answer::flags(0);
            }
            // Arrived at a closed listener, which takes no new carrier.
            Lookup::New => match entry {
                None => return Answer::flags(GONE),
                Some(e) => match self.create(h.cid, key.clone(), e) {
                    Ok(c) => c,
                    Err(flags) => return Answer::flags(flags),
                },
            },
        };
        carrier.request(kind, h, data).await
    }

    /// The carrier `cid`: a new one handed to the listener with the
    /// request's `entry`, or the one another request just made. Otherwise
    /// the answer's flags: GONE for a carrier that ended meanwhile, BUSY
    /// beyond the limit or when the listener refuses it (it closed after
    /// the request arrived).
    fn create(
        self: &Arc<Self>,
        cid: CarrierId,
        key: Key,
        entry: Entry,
    ) -> Result<Arc<Carrier>, u8> {
        let o = &self.options;
        let carrier = {
            let mut t = lock(&self.table);
            if let Some(c) = t.live.get(&cid) {
                entry.release();
                return Ok(c.clone());
            }
            if t.gone.contains_key(&cid) {
                entry.release();
                return Err(GONE);
            }
            if o.max_carriers.is_some_and(|m| t.live.len() >= m) {
                entry.release();
                return Err(BUSY);
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
        let hint = PipeHint::from_entry(entry);
        let l = self.listener.clone();
        let mut handle = Box::pin(async move { l.handle_pipe(io, hint).await });
        // The listener takes or refuses the carrier on the first poll,
        // before it waits for anything: a carrier of a closed listener is
        // refused now, so that it holds no state and the request is
        // answered BUSY.
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
            return Err(BUSY);
        }
        tokio::spawn(handle);
        tokio::spawn(carrier.clone().watch_idle());
        Ok(carrier)
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
                st.charge = (want > 0).then(|| self.listener.adapter().charge_memory(want));
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
    async fn request(&self, kind: Kind, req: &Header, data: &Bytes) -> Answer {
        let now = Instant::now();
        match self.request_now(kind, req, data, now) {
            Ok(a) => a,
            Err((n, ticket)) => self.hold(n, ticket, now + self.limits.hold).await,
        }
    }

    /// Processes a request as far as it can be at once; a DOWN request to
    /// hold is returned as its number and ticket.
    fn request_now(
        &self,
        kind: Kind,
        req: &Header,
        data: &Bytes,
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
            Kind::Up => match st.up(req.seq, req.flags & REQ_FIN != 0, data, &self.limits) {
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
    use crate::PairField;
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
        kind: impl Into<u8>,
        flags: u8,
        seq: u64,
        time: u32,
        nonce: [u8; 8],
        data: &[u8],
    ) -> (Outgoing, Request<PipeBody>) {
        let key = Key::new(b"", cid);
        let out = Outgoing::new(&key, cid, kind, flags, seq, 0, time, nonce, data);
        let mut body = BytesMut::from(&out.header[..]);
        body.extend_from_slice(data);
        body.extend_from_slice(&out.data_mac);
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
        kind: impl Into<u8> + Copy,
        flags: u8,
        seq: u64,
        data: &'static [u8],
    ) -> Response {
        let nonce = NONCES.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        let (out, req) = request(cid, kind, flags, seq, wire::unix_time(), nonce, data);
        let resp = server
            .handle(req, None, &PairField::default())
            .await
            .unwrap();
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
        parts.headers.insert(
            zmux::adapter::PAIR_HEADER,
            http::HeaderValue::from_static("x"),
        );
        let back = server
            .handle(
                Request::from_parts(parts, body),
                None,
                &PairField::default(),
            )
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
        // A DOWN request with data is over the limit of its kind: not
        // authenticated, handed back, and the carrier goes on.
        let nonce = NONCES.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        let (_, req) = request(&cid, Kind::Down, 0, 0, wire::unix_time(), nonce, b"x");
        assert!(
            server
                .handle(req, None, &PairField::default())
                .await
                .is_err()
        );
        assert_eq!(server.carriers(), 1);
        // A DOWN request with a reserved flag.
        assert_eq!(
            send(&server, &cid, Kind::Down, 0x01, 0, b"").await.flags,
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

    /// Every request takes a place under its source's limit of pending
    /// carriers when it arrives: a new carrier keeps its place until it
    /// enters a session, a request of a known carrier gives it back once
    /// authenticated, and a request that finds none is handed back with
    /// nothing read.
    #[tokio::test]
    async fn requests_take_the_sources_pending_share() {
        let mut limits = zmux::ListenerConfig::default();
        limits.max_pending_per_source = 2;
        let listener =
            Listener::new(zmux::Config::default(), limits).expect("valid listener configuration");
        let server =
            ExchangeServer::new(&listener, ExchangeOptions::default().with_unauthenticated())
                .unwrap();
        // A carrier holds one place; its own requests pass through the
        // other, again and again.
        assert_eq!(send(&server, &[1; 16], Kind::Up, 0, 1, b"").await.flags, 0);
        for n in 2..5 {
            assert_eq!(send(&server, &[1; 16], Kind::Up, 0, n, b"").await.flags, 0);
        }
        assert_eq!(server.carriers(), 1);
        // A second carrier takes the other place.
        assert_eq!(send(&server, &[2; 16], Kind::Up, 0, 1, b"").await.flags, 0);
        assert_eq!(server.carriers(), 2);
        // No place left: 503 without a body, the body unread, not handed
        // back.
        let nonce = NONCES.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        let (_, req) = request(&[3; 16], Kind::Up, 0, 0, wire::unix_time(), nonce, b"x");
        assert_unread_503(&server, req, None).await;
        assert_eq!(server.carriers(), 2);
        listener.close();
    }

    /// A body that records whether it was read.
    struct Watched(PipeBody, Arc<std::sync::atomic::AtomicBool>);

    impl http_body::Body for Watched {
        type Data = <PipeBody as http_body::Body>::Data;
        type Error = <PipeBody as http_body::Body>::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
            self.1.store(true, Ordering::Relaxed);
            Pin::new(&mut self.0).poll_frame(cx)
        }
    }

    /// `req` is answered 503 with an empty body, without a byte of its
    /// body read and without being handed back.
    async fn assert_unread_503(
        server: &ExchangeServer,
        req: Request<PipeBody>,
        peer: Option<SocketAddr>,
    ) {
        let read = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let req = req.map(|b| Watched(b, read.clone()));
        let resp = server
            .handle(req, peer, &PairField::default())
            .await
            .unwrap_or_else(|_| panic!("handed back"));
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(
            collect(resp.into_body(), 1 << 10)
                .await
                .unwrap()
                .unwrap()
                .is_empty()
        );
        assert!(!read.load(Ordering::Relaxed), "the body was read");
    }

    /// A request that finds no free slot of the listener (the global
    /// bound) is answered 503 as one without a slot of its source.
    #[tokio::test]
    async fn no_global_slot_is_503() {
        let mut limits = zmux::ListenerConfig::default();
        limits.max_pending = Some(1);
        let listener =
            Listener::new(zmux::Config::default(), limits).expect("valid listener configuration");
        let server =
            ExchangeServer::new(&listener, ExchangeOptions::default().with_unauthenticated())
                .unwrap();
        // A new carrier keeps the one slot.
        assert_eq!(send(&server, &[1; 16], Kind::Up, 0, 0, b"").await.flags, 0);
        let nonce = NONCES.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        let (_, req) = request(&[2; 16], Kind::Up, 0, 0, wire::unix_time(), nonce, b"x");
        let other: SocketAddr = "192.0.2.7:1000".parse().unwrap();
        assert_unread_503(&server, req, Some(other)).await;
        assert_eq!(server.carriers(), 1);
        listener.close();
    }

    /// The defaults let an exchange carrier make progress: the request
    /// that creates it holds a slot of its source until it enters a
    /// session, and its next requests need another one.
    #[tokio::test]
    async fn the_default_source_bound_admits_a_carriers_next_requests() {
        assert!(zmux::ListenerConfig::default().max_pending_per_source >= 2);
        let (listener, server) = server(ExchangeOptions::default());
        let cid = [4; 16];
        assert_eq!(send(&server, &cid, Kind::Up, 0, 0, b"a").await.flags, 0);
        assert_eq!(send(&server, &cid, Kind::Up, 0, 1, b"b").await.flags, 0);
        assert_eq!(server.carriers(), 1);
        listener.close();
    }

    /// A closed listener holds no slot but authenticates: an
    /// authenticated request of an unknown carrier is answered GONE and
    /// creates nothing; one that is not authenticated is handed back.
    #[tokio::test]
    async fn a_closed_listener_answers_gone() {
        let (listener, server) = server(ExchangeOptions::default());
        listener.close();
        assert!(listener.adapter().is_closed());
        for kind in [Kind::Up, Kind::Down] {
            assert_eq!(send(&server, &[1; 16], kind, 0, 0, b"").await.flags, GONE);
        }
        assert_eq!(server.carriers(), 0);
        let (_, req) = request(&[1; 16], Kind::Up, 0, 0, 0, [1; 8], b"a");
        assert!(
            server
                .handle(req, None, &PairField::default())
                .await
                .is_err()
        );
    }

    /// A request that arrived while the listener was open, whose carrier
    /// the listener refuses because it closed before the carrier was
    /// created, is answered BUSY and leaves no state.
    #[tokio::test]
    async fn closed_after_arrival_is_busy() {
        let (listener, server) = server(ExchangeOptions::default());
        let cid = [2; 16];
        let nonce = NONCES.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        let (out, req) = request(&cid, Kind::Up, 0, 0, wire::unix_time(), nonce, b"x");
        let full = collect(req.into_body(), 1 << 10).await.unwrap().unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(2);
        let req = Request::post("/zmux/exchange")
            .header(header::CONTENT_LENGTH, full.len())
            .body(Chan(rx))
            .unwrap();
        tx.send(full.slice(..HEADER_LEN)).await.unwrap();
        let task = tokio::spawn({
            let server = server.clone();
            async move { server.handle(req, None, &PairField::default()).await }
        });
        // Authenticated with its slot; the listener closes before the rest.
        while tx.capacity() < 2 {
            tokio::task::yield_now().await;
        }
        listener.close();
        tx.send(full.slice(HEADER_LEN..)).await.unwrap();
        let resp = task
            .await
            .unwrap()
            .unwrap_or_else(|_| panic!("handed back"));
        assert_eq!(resp.status(), StatusCode::OK);
        let body = collect(resp.into_body(), 1 << 10).await.unwrap().unwrap();
        let r = Response::parse(body).unwrap();
        assert!(out.verifies(&Key::new(b"", &cid), &cid, Kind::Up, &r));
        assert_eq!(r.flags, BUSY);
        assert_eq!(server.carriers(), 0);
    }

    /// A request body in pieces sent through a channel.
    struct Chan(tokio::sync::mpsc::Receiver<Bytes>);

    impl http_body::Body for Chan {
        type Data = Bytes;
        type Error = std::convert::Infallible;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<http_body::Frame<Bytes>, Self::Error>>> {
            self.0
                .poll_recv(cx)
                .map(|d| d.map(|d| Ok(http_body::Frame::data(d))))
        }
    }

    /// After authentication, a body that ends early or arrives late, as
    /// one whose Data MAC fails, is answered 400 with an empty body and
    /// changes nothing: the carrier still waits for that piece.
    #[tokio::test]
    async fn failures_after_authentication_are_400() {
        let mut limits = zmux::ListenerConfig::default();
        limits.handshake_timeout = Duration::from_millis(50);
        let listener =
            Listener::new(zmux::Config::default(), limits).expect("valid listener configuration");
        let server =
            ExchangeServer::new(&listener, ExchangeOptions::default().with_unauthenticated())
                .unwrap();
        let cid = [3; 16];
        assert_eq!(send(&server, &cid, Kind::Up, 0, 0, b"a").await.flags, 0);
        for late in [false, true] {
            let nonce = NONCES.fetch_add(1, Ordering::Relaxed).to_be_bytes();
            let (_, req) = request(&cid, Kind::Up, REQ_FIN, 1, wire::unix_time(), nonce, b"b");
            let full = collect(req.into_body(), 1 << 10).await.unwrap().unwrap();
            let (tx, rx) = tokio::sync::mpsc::channel::<Bytes>(1);
            tx.send(full.slice(..full.len() - 1)).await.unwrap();
            // Ends early: the sender is gone. Late: it stays.
            let keep = late.then_some(tx);
            let req = Request::post("/zmux/exchange")
                .header(header::CONTENT_LENGTH, full.len())
                .body(Chan(rx))
                .unwrap();
            let resp = server
                .handle(req, None, &PairField::default())
                .await
                .unwrap_or_else(|_| panic!("handed back"));
            drop(keep);
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "late {late}");
            assert!(
                collect(resp.into_body(), 1 << 10)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_empty()
            );
        }
        // Nothing changed: piece 1 is taken now, with its FIN, and a piece
        // above it still fails the carrier.
        assert_eq!(
            send(&server, &cid, Kind::Up, REQ_FIN, 1, b"b").await.flags,
            0
        );
        assert_eq!(server.carriers(), 1);
        assert_eq!(send(&server, &cid, Kind::Up, 0, 2, b"").await.flags, GONE);
        listener.close();
    }

    /// A Kind the binding does not define has a Data limit of 0: with Data
    /// it is not authenticated and is handed back; without, it is
    /// authenticated, malformed, fails its carrier and is answered GONE.
    #[tokio::test]
    async fn an_undefined_kind_is_malformed() {
        let (listener, server) = server(ExchangeOptions::default());
        let cid = [6; 16];
        assert_eq!(send(&server, &cid, Kind::Up, 0, 0, b"a").await.flags, 0);
        let nonce = NONCES.fetch_add(1, Ordering::Relaxed).to_be_bytes();
        let (_, req) = request(&cid, 9u8, 0, 0, wire::unix_time(), nonce, b"x");
        assert!(
            server
                .handle(req, None, &PairField::default())
                .await
                .is_err()
        );
        assert_eq!(server.carriers(), 1);
        assert_eq!(send(&server, &cid, 9u8, 0, 0, b"").await.flags, GONE);
        assert_eq!(server.carriers(), 0);
        // A carrier the server does not know: nothing is created.
        assert_eq!(send(&server, &[7; 16], 0u8, 0, 0, b"").await.flags, GONE);
        assert_eq!(server.carriers(), 0);
        listener.close();
    }

    /// An authenticated request whose body does not complete, or whose
    /// Data MAC does not verify, is answered with no result and creates
    /// nothing; its place is given back.
    #[tokio::test]
    async fn a_failed_data_mac_creates_nothing() {
        let mut limits = zmux::ListenerConfig::default();
        limits.max_pending_per_source = 2;
        let listener =
            Listener::new(zmux::Config::default(), limits).expect("valid listener configuration");
        let server =
            ExchangeServer::new(&listener, ExchangeOptions::default().with_unauthenticated())
                .unwrap();
        for _ in 0..3 {
            let nonce = NONCES.fetch_add(1, Ordering::Relaxed).to_be_bytes();
            let (_, req) = request(&[6; 16], Kind::Up, 0, 0, wire::unix_time(), nonce, b"abc");
            let (parts, body) = req.into_parts();
            let mut bytes = BytesMut::from(&collect(body, 1 << 10).await.unwrap().unwrap()[..]);
            bytes[HEADER_LEN] ^= 1;
            let req = Request::from_parts(parts, PipeBody::full(bytes.freeze()));
            let resp = server
                .handle(req, None, &PairField::default())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
            assert_eq!(server.carriers(), 0);
        }
        // The places were given back, not counted as failed setups.
        assert_eq!(listener.stats().setup_failures, 0);
        listener.close();
    }

    /// A new carrier beyond `max_carriers` is answered BUSY and gives its
    /// place back: no failed setup is counted.
    #[tokio::test]
    async fn busy_beyond_max_carriers_counts_no_failure() {
        let (listener, server) = server(ExchangeOptions {
            max_carriers: Some(1),
            ..ExchangeOptions::default()
        });
        assert_eq!(
            send(&server, &[10; 16], Kind::Up, 0, 0, b"a").await.flags,
            0
        );
        assert_eq!(
            send(&server, &[11; 16], Kind::Up, 0, 0, b"a").await.flags,
            BUSY
        );
        assert_eq!(server.carriers(), 1);
        assert_eq!(listener.stats().setup_failures, 0);
        listener.close();
    }

    /// The server reads the authentication header and nothing more before
    /// it authenticates: a request whose header does not arrive within the
    /// first-record timeout is handed back with what arrived.
    #[tokio::test]
    async fn a_late_header_is_handed_back() {
        let mut limits = zmux::ListenerConfig::default();
        limits.first_record_timeout = Duration::from_millis(50);
        let listener =
            Listener::new(zmux::Config::default(), limits).expect("valid listener configuration");
        let server =
            ExchangeServer::new(&listener, ExchangeOptions::default().with_unauthenticated())
                .unwrap();
        let (tx, body) = tokio::sync::mpsc::channel::<Bytes>(1);
        let req = Request::post("/zmux/exchange")
            .header(header::CONTENT_LENGTH, REQUEST_OVERHEAD)
            .body(Chan(body))
            .unwrap();
        tx.send(Bytes::from_static(&[0; 10])).await.unwrap();
        let back = server
            .handle(req, None, &PairField::default())
            .await
            .unwrap_err();
        let (front, rest) = back.into_body().into_parts();
        assert_eq!(front.len(), 10);
        assert!(rest.is_some());
        drop(tx);
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
            let back = server
                .handle(req, None, &PairField::default())
                .await
                .unwrap_err();
            assert_eq!(replayed(back).await.len() as u64, body);
        }
        assert_eq!(server.carriers(), 0);
        let (_, req) = request(&[1; 16], Kind::Up, 0, 0, now.wrapping_add(5), [1; 8], b"hi");
        assert!(
            server
                .handle(req, None, &PairField::default())
                .await
                .is_ok()
        );
        listener.close();
    }

    /// A request repeated with the same (Carrier ID, Nonce) is handed back.
    #[tokio::test]
    async fn a_repeated_nonce_is_handed_back() {
        let (listener, server) = server(ExchangeOptions::default());
        let now = wire::unix_time();
        let (_, req) = request(&[2; 16], Kind::Up, 0, 0, now, [9; 8], b"a");
        assert!(
            server
                .handle(req, None, &PairField::default())
                .await
                .is_ok()
        );
        let (_, req) = request(&[2; 16], Kind::Up, 0, 0, now, [9; 8], b"a");
        let back = server
            .handle(req, None, &PairField::default())
            .await
            .unwrap_err();
        assert_eq!(replayed(back).await.len(), REQUEST_OVERHEAD + 1);
        // The same Nonce with another carrier is another pair.
        let (_, req) = request(&[3; 16], Kind::Up, 0, 0, now, [9; 8], b"a");
        assert!(
            server
                .handle(req, None, &PairField::default())
                .await
                .is_ok()
        );
        listener.close();
    }

    /// A request that finds the record full is handed back.
    #[tokio::test]
    async fn a_full_record_hands_requests_back() {
        let (listener, server) = server(ExchangeOptions::default().with_max_recorded(2));
        let now = wire::unix_time();
        for n in 0..3u8 {
            let (_, req) = request(&[4; 16], Kind::Up, 0, n.into(), now, [n; 8], b"a");
            assert_eq!(
                server
                    .handle(req, None, &PairField::default())
                    .await
                    .is_ok(),
                n < 2,
                "{n}"
            );
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
        let back = server
            .handle(req, None, &PairField::default())
            .await
            .unwrap_err();
        assert_eq!(back.method(), http::Method::GET);
        assert!(replayed(back).await.is_empty());
        // Without a Content-Length: nothing read.
        let req = Request::post("/zmux/exchange")
            .body(PipeBody::full(Bytes::from_static(b"body")))
            .unwrap();
        assert_eq!(
            &replayed(
                server
                    .handle(req, None, &PairField::default())
                    .await
                    .unwrap_err()
            )
            .await[..],
            b"body"
        );
        // Not a request, read whole.
        let req = Request::post("/zmux/exchange")
            .header(header::CONTENT_LENGTH, 4)
            .body(PipeBody::full(Bytes::from_static(b"body")))
            .unwrap();
        assert_eq!(
            &replayed(
                server
                    .handle(req, None, &PairField::default())
                    .await
                    .unwrap_err()
            )
            .await[..],
            b"body"
        );
        // A Header MAC that does not verify.
        let (_, req) = request(&[5; 16], Kind::Up, 0, 0, wire::unix_time(), [1; 8], b"a");
        let (parts, body) = req.into_parts();
        let mut bytes = BytesMut::from(&collect(body, 1 << 10).await.unwrap().unwrap()[..]);
        bytes[HEADER_LEN - 1] ^= 1;
        let sent = bytes.freeze();
        let req = Request::from_parts(parts, PipeBody::full(sent.clone()));
        assert_eq!(
            replayed(
                server
                    .handle(req, None, &PairField::default())
                    .await
                    .unwrap_err()
            )
            .await,
            sent
        );
        // Over the body limit: nothing read.
        let big = Bytes::from(vec![0; REQUEST_OVERHEAD + (1 << 20) + 1]);
        let req = Request::post("/zmux/exchange")
            .header(header::CONTENT_LENGTH, big.len())
            .body(PipeBody::full(big.clone()))
            .unwrap();
        assert_eq!(
            replayed(
                server
                    .handle(req, None, &PairField::default())
                    .await
                    .unwrap_err()
            )
            .await,
            big
        );
        assert_eq!(server.carriers(), 0);
        listener.close();
    }
}
