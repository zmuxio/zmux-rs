//! The client of the exchange carrier: one driver task per carrier owns its
//! state and its requests; the two halves zmux holds share only their
//! buffers with it.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Request, StatusCode, header};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{Notify, watch};
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::Instant;
use zmux::{ConnectError, PipeIo, Session};

use super::ExchangeOptions;
use super::wire::{self, BUSY, CarrierId, FIN, GONE, Key, Kind, Outgoing, REQ_FIN, RESPONSE_HEAD};
use crate::body::{PipeBody, collect};

/// An exchange carrier to `addr` (`host:port`, also the `Host` header)
/// over plain TCP connections ([`dial_exchange_split`] with one endpoint
/// for both directions).
///
/// Returns at once, without a round trip; must be called inside a tokio
/// runtime.
pub fn dial_exchange(addr: &str, options: &ExchangeOptions) -> PipeIo {
    let e = ExchangeEndpoint::tcp(addr);
    dial_exchange_split(e.clone(), e, options)
}

/// An exchange carrier whose requests go over HTTP/1.1 connections that
/// `connect` makes (TCP, TLS whose ALPN chose `http/1.1`, ...), with
/// `authority` as their `Host` header ([`dial_exchange_split`] with one
/// endpoint for both directions).
///
/// ```no_run
/// # async fn example(tls: tokio_rustls::TlsConnector,
/// #     name: tokio_rustls::rustls::pki_types::ServerName<'static>) -> Result<(), Box<dyn std::error::Error>> {
/// let options = zmux_http::ExchangeOptions::default().with_psk(*b"a shared secret");
/// let pipe = zmux_http::dial_exchange_with(
///     move || {
///         let (tls, name) = (tls.clone(), name.clone());
///         async move {
///             let tcp = tokio::net::TcpStream::connect("example.com:443").await?;
///             tls.connect(name, tcp).await
///         }
///     },
///     "example.com",
///     &options,
/// );
/// let session = zmux::Session::connect(pipe, zmux::Config::default()).await?;
/// # drop(session);
/// # Ok(())
/// # }
/// ```
pub fn dial_exchange_with<C, F, IO>(
    connect: C,
    authority: &str,
    options: &ExchangeOptions,
) -> PipeIo
where
    C: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let e = ExchangeEndpoint::new(connect, authority);
    dial_exchange_split(e.clone(), e, options)
}

/// Where the requests of one direction go: how to connect and the `Host`
/// header. Cheap to clone.
#[derive(Clone)]
pub struct ExchangeEndpoint {
    connect: Arc<Connect>,
    authority: String,
}

impl std::fmt::Debug for ExchangeEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExchangeEndpoint")
            .field("authority", &self.authority)
            .finish_non_exhaustive()
    }
}

impl ExchangeEndpoint {
    /// Connections that `connect` makes (TCP, TLS whose ALPN chose
    /// `http/1.1`, ...), with `authority` as their `Host` header.
    pub fn new<C, F, IO>(connect: C, authority: &str) -> Self
    where
        C: Fn() -> F + Send + Sync + 'static,
        F: Future<Output = io::Result<IO>> + Send + 'static,
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self {
            connect: Arc::new(Box::new(move || {
                let f = connect();
                Box::pin(async move { f.await.map(|io| Box::new(io) as BoxIo) })
            })),
            authority: authority.to_owned(),
        }
    }

    /// Plain TCP connections to `addr` (`host:port`, also the `Host`
    /// header).
    pub fn tcp(addr: &str) -> Self {
        let target = addr.to_owned();
        Self::new(
            move || {
                let target = target.clone();
                async move {
                    let tcp = TcpStream::connect(target).await?;
                    let _ = tcp.set_nodelay(true);
                    Ok(tcp)
                }
            },
            addr,
        )
    }
}

/// An exchange carrier whose UP and CLOSE requests go to `up` and whose
/// DOWN requests go to `down`, which may differ in host, port, scheme and
/// path ([`ExchangeOptions::down_path`]) as long as all requests of the
/// carrier reach the same server. A few connections of each are kept open
/// for the next requests; a request whose connection fails is repeated on
/// another.
///
/// The carrier is returned at once, without a round trip, so that zmux
/// writes its first record into the first UP request. It fails when a
/// request has had no result for [`ExchangeOptions::deadline`], or the
/// server answers GONE; zmux then sees a carrier failure. Must be called
/// inside a tokio runtime.
pub fn dial_exchange_split(
    up: ExchangeEndpoint,
    down: ExchangeEndpoint,
    options: &ExchangeOptions,
) -> PipeIo {
    let mut cid: CarrierId = [0; 16];
    getrandom::fill(&mut cid).expect("the system's random source");
    let o = options;
    let (alive, _) = watch::channel(());
    let alive = Arc::new(alive);
    let http = |e: ExchangeEndpoint, most: usize| {
        Arc::new(Http {
            connect: e.connect,
            authority: e.authority,
            idle: Mutex::new(Vec::new()),
            most_idle: most.max(1),
            alive: alive.clone(),
        })
    };
    let up_http = http(up, o.up_requests + 1);
    let down_http = http(down, o.down_requests);
    let mut token = [0u8; 8];
    getrandom::fill(&mut token).expect("the system's random source");
    let ctx = Arc::new(Ctx {
        key: Key::new(&o.psk, &cid),
        cid,
        instance: hex(&token),
        options: o.clone(),
    });
    let shared = Arc::new(Halves::default());
    let driver = Driver {
        halves: shared.clone(),
        ctx,
        up_http,
        down_http,
        tasks: JoinSet::new(),
        up_next: 0,
        up: BTreeMap::new(),
        up_fin_sent: false,
        up_limit: o.up_requests.max(1),
        ack: 0,
        got: BTreeMap::new(),
        down_fin: None,
        down: HashMap::new(),
        down_limit: o.down_requests.max(1),
    };
    tokio::spawn(driver.run());
    let abort = shared.clone();
    PipeIo::from_halves(Reader(shared.clone()), Writer(shared, o.up_piece.max(1))).with_abort(
        move || {
            abort.lock().aborted = true;
            abort.driver.notify_one();
        },
    )
}

/// Establishes a session over an exchange carrier to `addr`
/// ([`dial_exchange`]).
pub async fn connect_exchange(
    addr: &str,
    options: &ExchangeOptions,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<Session, ConnectError> {
    Session::connect(dial_exchange(addr, options), config).await
}

// ---- the halves ------------------------------------------------------------------------

/// What the driver and the two halves share.
#[derive(Default)]
struct Halves {
    state: Mutex<HalfState>,
    /// Wakes the driver.
    driver: Notify,
}

#[derive(Default)]
struct HalfState {
    /// Uplink bytes zmux wrote that no piece holds yet.
    up: BytesMut,
    /// zmux shut the uplink down.
    up_closed: bool,
    writer: Option<Waker>,
    writer_gone: bool,
    /// Downlink pieces in order, for zmux.
    down: VecDeque<Bytes>,
    down_eof: bool,
    reader: Option<Waker>,
    reader_gone: bool,
    /// zmux failed the carrier.
    aborted: bool,
    /// The carrier failed.
    failed: bool,
}

impl Halves {
    fn lock(&self) -> MutexGuard<'_, HalfState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The downlink as zmux reads it.
struct Reader(Arc<Halves>);

impl AsyncRead for Reader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut st = self.0.lock();
        if st.down.is_empty() {
            if st.failed {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "exchange carrier failed",
                )));
            }
            if st.down_eof {
                return Poll::Ready(Ok(()));
            }
            st.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let mut freed = false;
        while buf.remaining() > 0 {
            let Some(front) = st.down.front_mut() else {
                break;
            };
            let n = front.len().min(buf.remaining());
            buf.put_slice(&front[..n]);
            front.advance(n);
            if front.is_empty() {
                st.down.pop_front();
                freed = true;
            }
        }
        drop(st);
        if freed {
            // Room for another DOWN request.
            self.0.driver.notify_one();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        let mut st = self.0.lock();
        st.reader_gone = true;
        st.down.clear();
        drop(st);
        self.0.driver.notify_one();
    }
}

/// The uplink as zmux writes it: bytes wait for a piece, at most one piece
/// size of them.
struct Writer(Arc<Halves>, usize);

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut st = self.0.lock();
        if st.failed || st.up_closed || st.aborted {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let room = self.1.saturating_sub(st.up.len());
        if room == 0 {
            st.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = room.min(buf.len());
        st.up.extend_from_slice(&buf[..n]);
        drop(st);
        self.0.driver.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut st = self.0.lock();
        if st.failed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        st.up_closed = true;
        drop(st);
        self.0.driver.notify_one();
        Poll::Ready(Ok(()))
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let mut st = self.0.lock();
        st.writer_gone = true;
        drop(st);
        self.0.driver.notify_one();
    }
}

// ---- HTTP ------------------------------------------------------------------------------

type BoxIo = Box<dyn IoStream>;
trait IoStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> IoStream for T {}

type Connect =
    Box<dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<BoxIo>> + Send>> + Send + Sync>;

/// The carrier's HTTP/1.1 connections: made on demand, kept open while
/// idle for the next requests.
struct Http {
    connect: Arc<Connect>,
    authority: String,
    idle: Mutex<Vec<http1::SendRequest<PipeBody>>>,
    most_idle: usize,
    /// Dropped with the carrier: its connections close.
    alive: Arc<watch::Sender<()>>,
}

impl Http {
    /// Sends one request and returns its whole response body (status 200
    /// only), at most `limit` bytes.
    async fn send(
        &self,
        target: &str,
        head: Bytes,
        tail: Bytes,
        limit: usize,
    ) -> io::Result<Bytes> {
        let mut sender = self.sender().await?;
        let req = Request::builder()
            .method(Method::POST)
            .uri(target)
            .header(header::HOST, self.authority.as_str())
            .header(header::CACHE_CONTROL, "no-store")
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(PipeBody::fixed(head, tail))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let resp = sender.send_request(req).await.map_err(io::Error::other)?;
        if resp.status() != StatusCode::OK {
            return Err(io::Error::other(format!(
                "the server answered {}",
                resp.status()
            )));
        }
        let body = collect(resp.into_body(), limit)
            .await?
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response over the limit"))?;
        if !sender.is_closed() {
            let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
            if idle.len() < self.most_idle {
                idle.push(sender);
            }
        }
        Ok(body)
    }

    /// An idle connection that is ready, or a new one.
    async fn sender(&self) -> io::Result<http1::SendRequest<PipeBody>> {
        loop {
            let s = self
                .idle
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop();
            let Some(mut s) = s else {
                break;
            };
            if !s.is_closed() && s.ready().await.is_ok() {
                return Ok(s);
            }
        }
        let io = (self.connect)().await?;
        let (sender, conn) = http1::handshake::<_, PipeBody>(TokioIo::new(io))
            .await
            .map_err(io::Error::other)?;
        let mut alive = self.alive.subscribe();
        tokio::spawn(async move {
            tokio::select! {
                _ = conn => {}
                _ = alive.changed() => {}
            }
        });
        Ok(sender)
    }
}

// ---- the driver ------------------------------------------------------------------------

/// What every request of the carrier uses.
struct Ctx {
    cid: CarrierId,
    /// The carrier's `{instance}` token.
    instance: String,
    key: Key,
    options: ExchangeOptions,
}

/// The result of one attempt of a request.
enum Outcome {
    /// A verified response: its flags and data.
    Answer(u8, Bytes),
    /// No result (Section 6.2).
    NoResult,
    /// A verified response that fails the carrier.
    Invalid,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn random_u64() -> u64 {
    getrandom::u64().expect("the system's random source")
}

/// One attempt of a request, after `delay`.
#[allow(clippy::too_many_arguments)]
async fn attempt(
    http: Arc<Http>,
    ctx: Arc<Ctx>,
    kind: Kind,
    flags: u8,
    seq: u64,
    ack: u64,
    data: Bytes,
    delay: Duration,
) -> Outcome {
    if !delay.is_zero() {
        tokio::time::sleep(delay).await;
    }
    let o = &ctx.options;
    let nonce = random_u64().to_be_bytes();
    let out = Outgoing::new(&ctx.key, &ctx.cid, kind, flags, seq, ack, nonce, &data);
    let (head, tail) = wire::encode_body(o.encoding, out.prefix.clone(), data);
    let target = o.target(kind == Kind::Down, &ctx.instance, &hex(&nonce));
    let limit = wire::encoded_len(o.encoding, RESPONSE_HEAD + o.max_down_piece);
    let sent = tokio::time::timeout(o.request_timeout, http.send(&target, head, tail, limit)).await;
    let body = match sent {
        Ok(Ok(body)) => body,
        // Over the local limit: a configuration error, never retried.
        Ok(Err(e)) if e.kind() == io::ErrorKind::InvalidData => return Outcome::Invalid,
        _ => return Outcome::NoResult,
    };
    let Some(resp) = wire::decode_body(o.encoding, body).and_then(wire::Response::parse) else {
        return Outcome::NoResult;
    };
    if !out.verifies(&ctx.key, &ctx.cid, kind, &resp) {
        return Outcome::NoResult;
    }
    if !resp.valid_for(kind) {
        return Outcome::Invalid;
    }
    Outcome::Answer(resp.flags, resp.data)
}

/// A request until it has its result.
struct Pending {
    /// When it was first sent, or last had a result (BUSY).
    since: Instant,
    attempts: u32,
    task: AbortHandle,
}

/// An UP request until it is processed.
struct UpPiece {
    data: Bytes,
    fin: bool,
    req: Pending,
}

/// How the carrier ended.
enum End {
    Complete,
    /// Failed; send CLOSE when the server may still hold state.
    Failed {
        close: bool,
    },
}

struct Driver {
    halves: Arc<Halves>,
    ctx: Arc<Ctx>,
    up_http: Arc<Http>,
    down_http: Arc<Http>,
    tasks: JoinSet<(Kind, u64, Outcome)>,
    /// The next uplink number.
    up_next: u64,
    /// UP requests not yet processed.
    up: BTreeMap<u64, UpPiece>,
    up_fin_sent: bool,
    up_limit: usize,
    /// Down Ack: the lowest downlink number not received.
    ack: u64,
    /// Pieces received above `ack`.
    got: BTreeMap<u64, Bytes>,
    /// The lowest number of a piece with FIN.
    down_fin: Option<u64>,
    /// DOWN requests outstanding.
    down: HashMap<u64, Pending>,
    down_limit: usize,
}

impl Driver {
    async fn run(mut self) {
        let end = loop {
            if let Some(end) = self.pump() {
                break end;
            }
            tokio::select! {
                () = self.halves.driver.notified() => {}
                Some(done) = self.tasks.join_next() => {
                    let end = match done {
                        Ok((kind, seq, outcome)) => self.result(kind, seq, outcome),
                        Err(e) if e.is_cancelled() => None,
                        Err(_) => Some(End::Failed { close: true }),
                    };
                    if let Some(end) = end {
                        break end;
                    }
                }
            }
        };
        self.tasks.abort_all();
        if let End::Complete = end {
            // Tells the server that the Down Ack passed the downlink FIN.
            self.send_close();
        }
        if let End::Failed { close } = end {
            let wakers = {
                let mut st = self.halves.lock();
                st.failed = true;
                st.up = BytesMut::new();
                (st.reader.take(), st.writer.take())
            };
            for w in [wakers.0, wakers.1].into_iter().flatten() {
                w.wake();
            }
            if close {
                // The server may still hold state: abort it there.
                self.send_close();
            }
        }
    }

    /// Sends one CLOSE with the current Down Ack; nothing waits for its
    /// result.
    fn send_close(&self) {
        let (http, ctx, ack) = (self.up_http.clone(), self.ctx.clone(), self.ack);
        tokio::spawn(async move {
            attempt(
                http,
                ctx,
                Kind::Close,
                0,
                0,
                ack,
                Bytes::new(),
                Duration::ZERO,
            )
            .await;
        });
    }

    fn spawn(
        &mut self,
        kind: Kind,
        seq: u64,
        flags: u8,
        data: Bytes,
        delay: Duration,
    ) -> AbortHandle {
        let http = if kind == Kind::Down {
            &self.down_http
        } else {
            &self.up_http
        }
        .clone();
        let (ctx, ack) = (self.ctx.clone(), self.ack);
        self.tasks.spawn(async move {
            let outcome = attempt(http, ctx, kind, flags, seq, ack, data, delay).await;
            (kind, seq, outcome)
        })
    }

    fn backoff(&self, attempts: u32) -> Duration {
        self.ctx.options.backoff.delay(attempts, random_u64())
    }

    /// Starts the requests the state calls for; the end of the carrier
    /// when it has ended.
    fn pump(&mut self) -> Option<End> {
        let o = &self.ctx.options;
        let (piece, fin, reader_gone, room) = {
            let mut st = self.halves.lock();
            if st.aborted || (st.writer_gone && !st.up_closed) {
                return Some(End::Failed { close: true });
            }
            let mut piece = None;
            let mut fin = false;
            if !self.up_fin_sent && self.up.len() < self.up_limit {
                if !st.up.is_empty() {
                    let n = st.up.len().min(o.up_piece.max(1));
                    piece = Some(st.up.split_to(n).freeze());
                    fin = st.up_closed && st.up.is_empty();
                } else if st.up_closed {
                    piece = Some(Bytes::new());
                    fin = true;
                }
            }
            let writer = piece.as_ref().and_then(|_| st.writer.take());
            let room = st.reader_gone || st.down.len() < o.down_requests.max(1);
            let r = (piece, fin, st.reader_gone, room);
            drop(st);
            if let Some(w) = writer {
                w.wake();
            }
            r
        };
        if let Some(data) = piece {
            let n = self.up_next;
            self.up_next += 1;
            self.up_fin_sent = fin;
            let flags = if fin { REQ_FIN } else { 0 };
            let task = self.spawn(Kind::Up, n, flags, data.clone(), Duration::ZERO);
            self.up.insert(
                n,
                UpPiece {
                    data,
                    fin,
                    req: Pending {
                        since: Instant::now(),
                        attempts: 0,
                        task,
                    },
                },
            );
            // More may be waiting.
            self.halves.driver.notify_one();
        }
        let up_done = self.up_fin_sent && self.up.is_empty();
        let down_done = self.down_fin.is_some_and(|f| self.ack > f);
        if up_done && (down_done || reader_gone) {
            return Some(End::Complete);
        }
        // DOWN requests for consecutive numbers from the Down Ack on.
        if room && !down_done {
            let end = self.ack + self.down_limit as u64;
            for n in self.ack..end {
                if self.down_fin.is_some_and(|f| n > f) {
                    break;
                }
                if self.got.contains_key(&n) || self.down.contains_key(&n) {
                    continue;
                }
                let task = self.spawn(Kind::Down, n, 0, Bytes::new(), Duration::ZERO);
                self.down.insert(
                    n,
                    Pending {
                        since: Instant::now(),
                        attempts: 0,
                        task,
                    },
                );
            }
        }
        None
    }

    /// Takes the outcome of an attempt of request `seq` of `kind`.
    fn result(&mut self, kind: Kind, seq: u64, outcome: Outcome) -> Option<End> {
        let (flags, data) = match outcome {
            Outcome::Invalid => return Some(End::Failed { close: true }),
            Outcome::NoResult => return self.repeat(kind, seq, false),
            Outcome::Answer(flags, data) => (flags, data),
        };
        match flags {
            GONE => return Some(End::Failed { close: false }),
            BUSY => return self.repeat(kind, seq, true),
            _ => {}
        }
        match kind {
            Kind::Close => {}
            Kind::Up => {
                if self.up.remove(&seq).is_some() {
                    self.up_limit = (self.up_limit + 1).min(self.ctx.options.up_requests.max(1));
                    self.halves.driver.notify_one();
                }
            }
            Kind::Down => {
                self.down.remove(&seq);
                self.down_limit = (self.down_limit + 1).min(self.ctx.options.down_requests.max(1));
                return self.piece(seq, flags == FIN, data);
            }
        }
        None
    }

    /// Repeats request `seq` of `kind` after a backoff, or fails the
    /// carrier when it has had no result for the deadline.
    fn repeat(&mut self, kind: Kind, seq: u64, busy: bool) -> Option<End> {
        let now = Instant::now();
        let deadline = self.ctx.options.deadline;
        let (flags, data, attempts) = match kind {
            Kind::Close => return None,
            Kind::Up => {
                let p = self.up.get_mut(&seq)?;
                if busy {
                    p.req.since = now;
                } else if now - p.req.since >= deadline {
                    return Some(End::Failed { close: true });
                }
                p.req.attempts += 1;
                (
                    if p.fin { REQ_FIN } else { 0 },
                    p.data.clone(),
                    p.req.attempts,
                )
            }
            Kind::Down => {
                if seq < self.ack || self.down_fin.is_some_and(|f| seq > f) {
                    // Not needed any more.
                    self.down.remove(&seq);
                    self.halves.driver.notify_one();
                    return None;
                }
                let p = self.down.get_mut(&seq)?;
                if busy {
                    p.since = now;
                } else if now - p.since >= deadline {
                    return Some(End::Failed { close: true });
                }
                p.attempts += 1;
                (0, Bytes::new(), p.attempts)
            }
        };
        if busy {
            // Fewer requests outstanding while the server is busy.
            match kind {
                Kind::Up => self.up_limit = self.up_limit.saturating_sub(1).max(1),
                _ => self.down_limit = self.down_limit.saturating_sub(1).max(1),
            }
        }
        let delay = self.backoff(attempts);
        let task = self.spawn(kind, seq, flags, data, delay);
        match kind {
            Kind::Up => {
                if let Some(p) = self.up.get_mut(&seq) {
                    p.req.task = task;
                }
            }
            _ => {
                if let Some(p) = self.down.get_mut(&seq) {
                    p.task = task;
                }
            }
        }
        None
    }

    /// Downlink piece `n`.
    fn piece(&mut self, n: u64, fin: bool, data: Bytes) -> Option<End> {
        if n < self.ack || self.got.contains_key(&n) {
            // A piece it holds: ignored.
            return None;
        }
        if fin && self.down_fin.is_none_or(|f| n < f) {
            // Pieces above the end carry nothing.
            if self.got.range(n + 1..).any(|(_, d)| !d.is_empty()) {
                return Some(End::Failed { close: true });
            }
            self.down_fin = Some(n);
            let stale: Vec<u64> = self.down.keys().copied().filter(|&k| k > n).collect();
            for k in stale {
                if let Some(p) = self.down.remove(&k) {
                    p.task.abort();
                }
            }
            self.got.split_off(&(n + 1));
        }
        if let Some(f) = self.down_fin
            && n > f
        {
            return if data.is_empty() {
                None
            } else {
                Some(End::Failed { close: true })
            };
        }
        self.got.insert(n, data);
        let mut ready = Vec::new();
        while let Some(d) = self.got.remove(&self.ack) {
            if !d.is_empty() {
                ready.push(d);
            }
            self.ack += 1;
        }
        let eof = self.down_fin.is_some_and(|f| self.ack > f);
        if ready.is_empty() && !eof {
            return None;
        }
        let reader = {
            let mut st = self.halves.lock();
            if !st.reader_gone {
                st.down.extend(ready);
            }
            st.down_eof |= eof;
            st.reader.take()
        };
        if let Some(w) = reader {
            w.wake();
        }
        None
    }
}
