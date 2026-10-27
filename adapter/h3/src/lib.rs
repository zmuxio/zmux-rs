//! HTTP/3 request streams as zmux carriers over h3 and quinn: a pipe is one
//! HTTP/3 request, its request body the
//! client's outbound direction and its response body the client's inbound
//! direction (the server's the other way round). HTTP/3 reaches servers
//! through front ends, proxies and load balancers that forward HTTP/3
//! requests, where a plain QUIC carrier may not.
//!
//! The client ([`H3Client`]) reports the QUIC connection as the carrier
//! connection of its pipes and opens their lanes as further requests on it
//! (MULTIPATH.md Sections 2.5 and 5.8): the request streams of one
//! connection are delivered independently, so a loss on one lane does not
//! hold back the others. Lanes are opened by the client only: an HTTP/3
//! server cannot open request streams, so the server's outbound directions
//! stay on their pipes' own streams (lanes in both directions need
//! WebTransport). On the server ([`serve`], [`serve_connection`]) every
//! request of a connection is a carrier handed to a [`Listener`]
//! with the connection's identity, which tells a new session, a join and a
//! client lane apart by its first record.
//!
//! What the carriers have:
//!
//! - the TLS 1.3 exporter of the QUIC connection (RFC 9001 Section 4), for
//!   [`zmux::PipeAuth::tls`] and carrier-bound joins (MULTIPATH.md Section
//!   10.5); behind a front end that terminates TLS the two ends export
//!   different values, so such deployments use a PSK (MULTIPATH.md);
//! - a connection receive window sized for the lanes ([`Options`]),
//!   charged to the memory budget: the client's to the zmux session its
//!   pipes carry, the server's to the listener's while the connection is
//!   served;
//! - failure signalling: a body that zmux drops without ending it is reset
//!   (or its reading stopped) with `ZMUX_CARRIER_FAILED`; a request, its
//!   response or the connection that fails under a pipe is a failure of
//!   the pipe, and only the end of a body is its graceful end.
//!
//! The QUIC endpoints carry the HTTP/3 ALPN identifier `h3` ([`ALPN`]),
//! which names the HTTP layer; zmux's own identifiers do not apply.
//! [`client_config`] and [`server_config`] set it and the transport
//! configuration ([`Options::transport_config`]).
//!
//! Each body write is handed to the HTTP/3 stream as one DATA frame, and at
//! most one such write is in flight per body: a write returns once the
//! previous one was taken by the stream, which bounds what the carrier
//! holds to one write call.
//!
//! ```no_run
//! # async fn example(endpoint: quinn::Endpoint) -> Result<(), Box<dyn std::error::Error>> {
//! use zmux::{Config, PipeAuth};
//! use zmux_h3::Options;
//!
//! let uri: http::Uri = "https://example.com/zmux".parse()?;
//! let addr = "192.0.2.1:443".parse()?;
//! let mut config = Config::default();
//! config.pipe_auth = PipeAuth::tls();
//! let session = zmux_h3::connect(&endpoint, addr, uri, &Options::default(), config).await?;
//! # drop(session);
//! # Ok(())
//! # }
//! ```

use std::future::{Future, poll_fn};
use std::io::{self, IoSlice};
use std::pin::{Pin, pin};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use quinn::rustls;
use quinn::{Connection, Endpoint, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use zmux::carrier::CarrierConnId;
use zmux::proto::ApplicationErrorCode;
use zmux::proto::keys::{EXPORTER_PIPE_LABEL, EXPORTER_SESSION_LABEL};
use zmux::{ConnectError, Listener, PipeHint, PipeIo, Session};

/// The HTTP/3 ALPN identifier, which the QUIC endpoints must carry.
pub const ALPN: &[u8] = b"h3";

type ClientSend = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ClientRecv = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;
type ServerSend = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ServerRecv = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;

/// How the carriers size the connection's flow control for lanes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// The stream receive window (1 250 000 bytes by default, quinn's
    /// default): the endpoint's transport configuration takes it from
    /// [`Options::transport_config`], its one source.
    pub stream_window: u64,
    /// Lanes that may be blocked at once (default 4): the connection's
    /// receive window is set to `lanes + 1` stream windows. Lanes are
    /// requests, so the requests the peer may open at once (quinn's
    /// `max_concurrent_bidi_streams`) bound them too.
    pub lanes: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            stream_window: 1_250_000,
            lanes: 4,
        }
    }
}

impl Options {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// With this stream receive window.
    #[must_use]
    pub fn with_stream_window(mut self, bytes: u64) -> Self {
        self.stream_window = bytes;
        self
    }

    /// With this many lanes that may be blocked at once.
    #[must_use]
    pub fn with_lanes(mut self, lanes: u32) -> Self {
        self.lanes = lanes;
        self
    }

    /// The connection receive window these options ask for: a stream
    /// window for each lane and one for a pipe.
    pub fn receive_window(&self) -> u64 {
        self.stream_window
            .saturating_mul(u64::from(self.lanes) + 1)
            .min(VarInt::MAX.into_inner())
    }

    /// quinn's transport configuration for these options: the stream
    /// receive window and the connection window for the lanes; the rest
    /// quinn's defaults. Build the endpoints' client and server
    /// configurations with it.
    pub fn transport_config(&self) -> quinn::TransportConfig {
        let mut t = quinn::TransportConfig::default();
        t.stream_receive_window(VarInt::from_u64(self.stream_window).unwrap_or(VarInt::MAX))
            .receive_window(VarInt::from_u64(self.receive_window()).unwrap_or(VarInt::MAX));
        t
    }
}

/// A quinn client configuration from a rustls one: the ALPN identifier
/// `h3` added when missing, and the transport configuration of `options`
/// ([`Options::transport_config`]).
#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
pub fn client_config(
    mut tls: rustls::ClientConfig,
    options: &Options,
) -> Result<quinn::ClientConfig, quinn::crypto::rustls::NoInitialCipherSuite> {
    if !tls.alpn_protocols.iter().any(|a| a == ALPN) {
        tls.alpn_protocols.push(ALPN.to_vec());
    }
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut c = quinn::ClientConfig::new(Arc::new(crypto));
    c.transport_config(Arc::new(options.transport_config()));
    Ok(c)
}

/// A quinn server configuration from a rustls one: the ALPN identifier
/// `h3` added when missing, and the transport configuration of `options`
/// ([`Options::transport_config`]).
#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
pub fn server_config(
    mut tls: rustls::ServerConfig,
    options: &Options,
) -> Result<quinn::ServerConfig, quinn::crypto::rustls::NoInitialCipherSuite> {
    if !tls.alpn_protocols.iter().any(|a| a == ALPN) {
        tls.alpn_protocols.push(ALPN.to_vec());
    }
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut c = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    c.transport_config(Arc::new(options.transport_config()));
    Ok(c)
}

/// `ZMUX_CARRIER_FAILED` as an HTTP/3 stream error code.
fn carrier_failed() -> h3::error::Code {
    h3::error::Code::from(ApplicationErrorCode::ZMUX_CARRIER_FAILED.0)
}

/// The exporter values of a connection for both labels zmux uses.
fn exported(conn: &Connection) -> [Option<Vec<u8>>; 2] {
    let export = |label: &str| {
        let mut out = vec![0u8; 32];
        conn.export_keying_material(&mut out, label.as_bytes(), b"")
            .ok()
            .map(|()| out)
    };
    [export(EXPORTER_SESSION_LABEL), export(EXPORTER_PIPE_LABEL)]
}

/// A carrier with the connection's identity and exporter.
fn with_connection(io: PipeIo, id: CarrierConnId, exported: &[Option<Vec<u8>>; 2]) -> PipeIo {
    let exported = exported.clone();
    io.with_carrier_conn(id)
        .with_tls_exporter(|label| match label {
            EXPORTER_SESSION_LABEL => exported[0].clone(),
            EXPORTER_PIPE_LABEL => exported[1].clone(),
            _ => None,
        })
}

fn h3_error(e: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, e)
}

// ---- client --------------------------------------------------------------

/// The client side of an HTTP/3 connection whose requests carry zmux pipes
/// and lanes (see the crate documentation). Cheap to clone. The HTTP/3
/// connection is driven while any clone, or any pipe or lane made from it,
/// is alive; once none is, its driver stops.
#[derive(Clone)]
#[must_use = "the connection is driven while the client and its pipes are alive"]
pub struct H3Client {
    inner: Arc<ClientInner>,
}

impl std::fmt::Debug for H3Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Client")
            .field("connection", &self.inner.conn.stable_id())
            .finish()
    }
}

struct ClientInner {
    conn: Connection,
    send: SendRequest<h3_quinn::OpenStreams, Bytes>,
    uri: http::Uri,
    /// The connection's identity for zmux: this state's allocation.
    id: OnceLock<CarrierConnId>,
    exported: [Option<Vec<u8>>; 2],
    window: u64,
    driver: tokio::task::AbortHandle,
}

impl Drop for ClientInner {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl H3Client {
    /// The HTTP/3 client of `conn`, an established QUIC connection with
    /// the ALPN identifier `h3`, whose pipes and lanes are requests to
    /// `uri` (inside a tokio runtime): it exchanges the HTTP/3 settings and
    /// starts driving the connection. The connection's receive window is
    /// set for the lanes and charged to the zmux session the pipes carry.
    pub async fn new(conn: Connection, uri: http::Uri, options: &Options) -> io::Result<Self> {
        let window = options.receive_window();
        conn.set_receive_window(VarInt::from_u64(window).unwrap_or(VarInt::MAX));
        let (mut driver, send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(h3_error)?;
        let driver = tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        })
        .abort_handle();
        let inner = Arc::new(ClientInner {
            exported: exported(&conn),
            conn,
            send,
            uri,
            id: OnceLock::new(),
            window,
            driver,
        });
        let _ = inner.id.set(CarrierConnId::new(&inner));
        Ok(Self { inner })
    }

    /// The QUIC connection, for its own features (datagrams, statistics,
    /// path, close).
    pub fn connection(&self) -> &Connection {
        &self.inner.conn
    }

    /// A new pipe on a request of the connection: the bootstrap carrier of
    /// a session this endpoint starts, or a pipe it joins. Returns once the
    /// request was sent (its response is awaited by the pipe's reads).
    pub async fn open_pipe(&self) -> io::Result<PipeIo> {
        let inner = &self.inner;
        let (send, recv) = inner.request().await?;
        let opener = inner.clone();
        let (r, w) = paired(
            BodyReader::client(recv, inner.clone()),
            BodyWriter::new(SendHalf::Client(send), Some(inner.clone())),
        );
        let io = PipeIo::from_halves(r, w)
            .with_connection_memory(inner.window)
            .with_lane_opener(move || {
                let inner = opener.clone();
                async move {
                    let (send, recv) = inner.request().await?;
                    // The response stays open, unread: stopping it would make
                    // the server drop the request before the lane is routed.
                    let mut lane = BodyWriter::new(SendHalf::Client(send), Some(inner));
                    lane.response = Some(recv);
                    Ok(lane)
                }
            });
        Ok(with_connection(io, inner.id(), &inner.exported))
    }
}

impl ClientInner {
    fn id(&self) -> CarrierConnId {
        self.id.get().expect("set at creation").clone()
    }

    /// A new request: its body and its response's.
    async fn request(&self) -> io::Result<(ClientSend, ClientRecv)> {
        let request = http::Request::post(self.uri.clone())
            .body(())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let stream = self
            .send
            .clone()
            .send_request(request)
            .await
            .map_err(h3_error)?;
        Ok(stream.split())
    }
}

/// A carrier over a new HTTP/3 connection of `endpoint` (its default
/// client configuration, with the ALPN identifier `h3`: [`client_config`])
/// to `addr`, verified for the host of `uri`: a request to `uri`. For
/// [`zmux::helpers::PipePool`] and [`Session::add_pipe`]; to open more pipes
/// on one connection, make an [`H3Client`] instead.
pub async fn dial(
    endpoint: &Endpoint,
    addr: std::net::SocketAddr,
    uri: http::Uri,
    options: &Options,
) -> io::Result<PipeIo> {
    let host = uri.host().unwrap_or("localhost").to_owned();
    let conn = endpoint
        .connect(addr, &host)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        .await
        .map_err(io::Error::other)?;
    H3Client::new(conn, uri, options).await?.open_pipe().await
}

/// Establishes a session over a new HTTP/3 connection ([`dial`], then
/// [`Session::connect`]).
pub async fn connect(
    endpoint: &Endpoint,
    addr: std::net::SocketAddr,
    uri: http::Uri,
    options: &Options,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<Session, ConnectError> {
    let pipe = dial(endpoint, addr, uri, options)
        .await
        .map_err(|e| ConnectError::Io(Arc::new(e)))?;
    Session::connect(pipe, config).await
}

// ---- server --------------------------------------------------------------

/// Serves the HTTP/3 connections `endpoint` accepts until `listener` is
/// closed or the endpoint is ([`serve_connection`] for each, in a task of
/// its own).
pub async fn serve(listener: Listener, endpoint: Endpoint, options: Options) {
    loop {
        let next = {
            let mut accept = pin!(endpoint.accept());
            let mut closed = pin!(listener.closed());
            poll_fn(|cx| {
                if closed.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
                accept.as_mut().poll(cx)
            })
            .await
        };
        let Some(incoming) = next else {
            return;
        };
        let (listener, options) = (listener.clone(), options.clone());
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let _ = serve_connection(&listener, conn, &options).await;
                }
                Err(_) => listener.count_setup_failure(),
            }
        });
    }
}

/// Serves one HTTP/3 connection (the ALPN identifier `h3`) until it ends:
/// every request is answered with 200 and handed, with its body and its
/// response's, to [`Listener::handle_pipe`] as a carrier of the
/// connection. The connection's receive window is set for the lanes and
/// charged to the listener's budget meanwhile.
pub async fn serve_connection(
    listener: &Listener,
    conn: Connection,
    options: &Options,
) -> io::Result<()> {
    let window = options.receive_window();
    conn.set_receive_window(VarInt::from_u64(window).unwrap_or(VarInt::MAX));
    let _charge = listener.charge_memory(window);
    let identity = Arc::new(conn.stable_id());
    let id = CarrierConnId::new(&identity);
    let exported = exported(&conn);
    let mut h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .map_err(h3_error)?;
    let hint = || PipeHint::from_addr(conn.remote_address().ip());
    while let Some(resolver) = h3.accept().await.map_err(h3_error)? {
        let (listener, id, exported, hint) =
            (listener.clone(), id.clone(), exported.clone(), hint());
        tokio::spawn(async move {
            let Ok((_request, mut stream)) = resolver.resolve_request().await else {
                return;
            };
            if stream.send_response(http::Response::new(())).await.is_err() {
                return;
            }
            let (send, recv) = stream.split();
            let (r, w) = paired(
                BodyReader::server(recv),
                BodyWriter::new(SendHalf::Server(send), None),
            );
            let io = PipeIo::from_halves(r, w);
            let _ = listener
                .handle_pipe(with_connection(io, id, &exported), hint)
                .await;
        });
    }
    Ok(())
}

// ---- bodies -----------------------------------------------------------------

/// A request or response body being sent.
enum SendHalf {
    Client(ClientSend),
    Server(ServerSend),
}

impl SendHalf {
    async fn send(&mut self, data: Bytes) -> Result<(), h3::error::StreamError> {
        match self {
            Self::Client(s) => s.send_data(data).await,
            Self::Server(s) => s.send_data(data).await,
        }
    }

    async fn finish(&mut self) -> Result<(), h3::error::StreamError> {
        match self {
            Self::Client(s) => s.finish().await,
            Self::Server(s) => s.finish().await,
        }
    }

    fn reset(&mut self) {
        match self {
            Self::Client(s) => s.stop_stream(carrier_failed()),
            Self::Server(s) => s.stop_stream(carrier_failed()),
        }
    }
}

/// A write or the end of a body, in progress on a task of its own, so that
/// it completes whether or not the carrier is polled again.
type Op = tokio::task::JoinHandle<Result<(), h3::error::StreamError>>;

/// A body as the sending half of a carrier: each write is one DATA frame,
/// at most one in flight; `poll_shutdown` ends the body (FIN), and a body
/// dropped otherwise is reset with `ZMUX_CARRIER_FAILED`.
struct BodyWriter {
    half: Arc<Mutex<SendHalf>>,
    op: Option<Op>,
    finished: bool,
    /// Set once the body ended gracefully, for the reader of the same
    /// pipe (see `paired`).
    ended_gracefully: Arc<AtomicBool>,
    /// The client a pipe's body keeps alive.
    _keep: Option<Arc<ClientInner>>,
    /// A lane's response, held unread while the lane lives.
    response: Option<ClientRecv>,
}

impl BodyWriter {
    fn new(half: SendHalf, keep: Option<Arc<ClientInner>>) -> Self {
        Self {
            half: Arc::new(Mutex::new(half)),
            op: None,
            finished: false,
            ended_gracefully: Arc::default(),
            _keep: keep,
            response: None,
        }
    }

    /// Drives the write in flight to its end.
    fn poll_op(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(op) = self.op.as_mut() {
            let r = ready!(Pin::new(op).poll(cx));
            self.op = None;
            r.map_err(io::Error::other)?.map_err(h3_error)?;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for BodyWriter {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // A write in flight ends here; the half is reset once it is free.
        if let Some(op) = self.op.take() {
            op.abort();
        }
        if let Ok(mut h) = self.half.try_lock() {
            h.reset();
            return;
        }
        if let Ok(rt) = tokio::runtime::Handle::try_current() {
            let half = self.half.clone();
            rt.spawn(async move { half.lock().await.reset() });
        }
    }
}

impl AsyncWrite for BodyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_op(cx))?;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let (half, data) = (self.half.clone(), Bytes::copy_from_slice(buf));
        // Taken now; the next call waits for it, and reports its error.
        self.op = Some(tokio::spawn(
            async move { half.lock().await.send(data).await },
        ));
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_op(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        ready!(self.poll_op(cx))?;
        if self.op.is_none() {
            let half = self.half.clone();
            self.op = Some(tokio::spawn(
                async move { half.lock().await.finish().await },
            ));
        }
        ready!(self.poll_op(cx))?;
        self.finished = true;
        self.ended_gracefully.store(true, Ordering::Release);
        Poll::Ready(Ok(()))
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        // One frame for all of them: a copy is made anyway.
        let total: usize = bufs.iter().map(|b| b.len()).sum();
        let mut data = Vec::with_capacity(total);
        for b in bufs {
            data.extend_from_slice(b);
        }
        self.poll_write(cx, &data)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

/// The two bodies of one pipe: a graceful end of the sent body keeps the
/// reader from stopping the received one when it is dropped.
fn paired(mut r: BodyReader, w: BodyWriter) -> (BodyReader, BodyWriter) {
    r.peer_may_finish = w.ended_gracefully.clone();
    (r, w)
}

/// A body being received.
enum RecvHalf {
    Client(ClientRecv),
    Server(ServerRecv),
}

type Response = Pin<Box<dyn Future<Output = (ClientRecv, io::Result<()>)> + Send>>;

/// A body as the receiving half of a carrier; dropped before its end, its
/// reading is stopped with `ZMUX_CARRIER_FAILED`.
struct BodyReader {
    half: Option<RecvHalf>,
    /// The client's wait for the response head.
    response: Option<Response>,
    held: Bytes,
    ended: bool,
    /// A read of the body is in progress: the stack holds the stream, and
    /// stopping it now would panic in h3-quinn (dropping it stops it).
    reading: bool,
    /// The pipe's request or response body this endpoint sends ended
    /// gracefully: the carrier closes cleanly, and the peer's body is not
    /// stopped, or its sender could fail before it reads what was sent.
    peer_may_finish: Arc<AtomicBool>,
    _keep: Option<Arc<ClientInner>>,
}

impl BodyReader {
    fn client(mut recv: ClientRecv, keep: Arc<ClientInner>) -> Self {
        let response: Response = Box::pin(async move {
            let r = match recv.recv_response().await {
                Ok(resp) if resp.status().is_success() => Ok(()),
                Ok(resp) => Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("HTTP/3 status {}", resp.status()),
                )),
                Err(e) => Err(h3_error(e)),
            };
            (recv, r)
        });
        Self {
            half: None,
            response: Some(response),
            held: Bytes::new(),
            ended: false,
            reading: false,
            peer_may_finish: Arc::default(),
            _keep: Some(keep),
        }
    }

    fn server(recv: ServerRecv) -> Self {
        Self {
            half: Some(RecvHalf::Server(recv)),
            response: None,
            held: Bytes::new(),
            ended: false,
            reading: false,
            peer_may_finish: Arc::default(),
            _keep: None,
        }
    }
}

impl Drop for BodyReader {
    fn drop(&mut self) {
        if self.ended || self.reading || self.peer_may_finish.load(Ordering::Acquire) {
            return;
        }
        match self.half.as_mut() {
            Some(RecvHalf::Client(r)) => r.stop_sending(carrier_failed()),
            Some(RecvHalf::Server(r)) => r.stop_sending(carrier_failed()),
            None => {}
        }
    }
}

impl AsyncRead for BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(response) = this.response.as_mut() {
            let (recv, r) = ready!(response.as_mut().poll(cx));
            this.response = None;
            this.half = Some(RecvHalf::Client(recv));
            r?;
        }
        while this.held.is_empty() {
            if this.ended {
                return Poll::Ready(Ok(()));
            }
            let polled = match this.half.as_mut() {
                Some(RecvHalf::Client(r)) => r
                    .poll_recv_data(cx)
                    .map(|p| p.map(|d| d.map(|mut d| d.copy_to_bytes(d.remaining())))),
                Some(RecvHalf::Server(r)) => r
                    .poll_recv_data(cx)
                    .map(|p| p.map(|d| d.map(|mut d| d.copy_to_bytes(d.remaining())))),
                None => return Poll::Ready(Ok(())),
            };
            this.reading = polled.is_pending();
            let polled = ready!(polled);
            match polled.map_err(h3_error)? {
                Some(data) => this.held = data,
                None => this.ended = true,
            }
        }
        let n = this.held.len().min(buf.remaining());
        buf.put_slice(&this.held.split_to(n));
        Poll::Ready(Ok(()))
    }
}
