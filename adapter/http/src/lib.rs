//! HTTP/1.1 and HTTP/2 exchanges as zmux pipes over hyper.
//!
//! A pipe is one HTTP exchange, its two bodies paired: the request body
//! carries the client's outbound direction and the response body its
//! inbound one; the server sees the mirror. The server answers at once
//! with a streaming response, so both bodies flow at the same time. A body
//! that ends cleanly is the graceful end of its direction; a failed pipe
//! ends its body with an error (an HTTP/2 stream reset, an HTTP/1.1
//! connection closed mid-body), and an exchange that is cut is a read
//! error at the other end, never a clean end.
//!
//! - HTTP/1.1: one pipe per connection ([`dial_http1`], [`connect_http1`]).
//! - HTTP/2: one connection carries many pipes ([`Http2Connection`]),
//!   which report the connection as their carrier connection, so that the
//!   listener knows they share it. Lanes (further requests of the same
//!   connection carrying a pipe's records) are off by default: the streams
//!   of an HTTP/2 connection share one ordered TCP byte stream, so lanes
//!   recover nothing from a loss (MULTIPATH.md Section 2.5);
//!   [`Options::lanes`] turns them on. Only the client opens lanes (a
//!   server cannot open requests).
//! - The server: [`serve`] accepts TCP connections and serves both
//!   protocols (HTTP/2 with prior knowledge), handing every exchange on
//!   [`Options::path`] to a [`Listener`]; [`serve_with`] sets each
//!   connection up first (TLS), [`serve_connection`] serves one
//!   established connection, and [`handle_request`] hands over one request
//!   inside an existing HTTP server.
//!
//! An out-of-band join travels in the `Zmux-Pipe-Join` request header
//! ([`Options::join_header`], [`zmux::PipeReservation::header`]). TLS is
//! the caller's: the `*_over`/[`Http2Connection::handshake`] entry points
//! and [`serve_with`] speak HTTP over any established connection.
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use zmux::{Config, Listener, ListenerConfig};
//! use zmux_http::Options;
//!
//! // Server.
//! let listener = Listener::new(Config::default(), ListenerConfig::default());
//! let tcp = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
//! tokio::spawn(zmux_http::serve(listener.clone(), tcp, Options::default()));
//!
//! // Client: one session over an HTTP/2 connection.
//! let session = zmux_http::connect_http2("127.0.0.1:8080", &Options::default(), Config::default()).await?;
//! let server_side = listener.accept().await;
//! # drop((session, server_side));
//! # Ok(())
//! # }
//! ```

mod body;

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use http::{Method, Request, Response, StatusCode, Version};
use hyper::body::Incoming;
use hyper::client::conn::{http1, http2};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use zmux::carrier::CarrierConnId;
use zmux::{ConnectError, Listener, PipeHint, PipeIo, Session};

pub use body::PipeBody;
use body::{BodyReader, body};

/// The adapter's options.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// The request path of the exchanges that carry pipes (default
    /// `/zmux`); a server answers others with 404.
    pub path: String,
    /// HTTP/2 client: open lanes on further requests of the connection
    /// (default off; see the crate documentation).
    pub lanes: bool,
    /// The `Zmux-Pipe-Join` header value the client sends with its
    /// request (an out-of-band join).
    pub join_header: Option<String>,
    /// Client: the limit on establishing an exchange, from the connection's
    /// HTTP handshake (HTTP/1.1) to the response head (default 10 s); an
    /// exchange not answered within it fails with `TimedOut`.
    pub timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            path: "/zmux".into(),
            lanes: false,
            join_header: None,
            timeout: Duration::from_secs(10),
        }
    }
}

impl Options {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// With this request path.
    #[must_use]
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    /// With HTTP/2 lanes on or off.
    #[must_use]
    pub fn with_lanes(mut self, on: bool) -> Self {
        self.lanes = on;
        self
    }

    /// With this `Zmux-Pipe-Join` header value.
    #[must_use]
    pub fn with_join_header(mut self, value: impl Into<String>) -> Self {
        self.join_header = Some(value.into());
        self
    }

    /// With this limit on establishing an exchange.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The request of an exchange: POST to the path, `body` as its body.
    fn request(
        &self,
        authority: &str,
        version: Version,
        body: PipeBody,
    ) -> io::Result<Request<PipeBody>> {
        let mut req = Request::builder().method(Method::POST).version(version);
        req = if version == Version::HTTP_2 {
            req.uri(format!("http://{authority}{}", self.path))
        } else {
            req.uri(self.path.as_str())
                .header(http::header::HOST, authority)
        };
        if let Some(j) = &self.join_header {
            req = req.header(zmux::JOIN_HEADER, j.as_str());
        }
        req.body(body)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }
}

fn hyper_err(e: hyper::Error) -> io::Error {
    io::Error::other(e)
}

/// `f` within `limit`, or a `TimedOut` error.
async fn within<T>(limit: Duration, f: impl Future<Output = io::Result<T>>) -> io::Result<T> {
    tokio::time::timeout(limit, f).await.unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the exchange was not established in time",
        ))
    })
}

/// A pipe on an exchange whose response arrived: its body is the inbound
/// half, `writer` the request body (the outbound half).
fn exchange_pipe(
    resp: Response<Incoming>,
    writer: body::BodyWriter,
    abort: body::Abort,
) -> io::Result<PipeIo> {
    if resp.status() != StatusCode::OK {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("the server answered {}", resp.status()),
        ));
    }
    Ok(
        PipeIo::from_halves(BodyReader::new(resp.into_body()), writer)
            .with_abort(move || abort.run()),
    )
}

// ---- HTTP/1.1 client -----------------------------------------------------------------

/// A pipe over a new HTTP/1.1 connection to `addr` (`host:port`, also the
/// `Host` header): one exchange, its request and response bodies streamed
/// at the same time ([`dial_http1_over`] on a TCP connection).
pub async fn dial_http1(addr: &str, options: &Options) -> io::Result<PipeIo> {
    let tcp = TcpStream::connect(addr).await?;
    let _ = tcp.set_nodelay(true);
    dial_http1_over(tcp, addr, options).await
}

/// A pipe over an established connection, any byte stream such as a TLS
/// stream whose ALPN chose `http/1.1`: one HTTP/1.1 exchange with
/// `authority` as its `Host` header, established within
/// [`Options::timeout`].
///
/// ```no_run
/// # async fn example(tls: tokio_rustls::TlsConnector,
/// #     name: tokio_rustls::rustls::pki_types::ServerName<'static>) -> std::io::Result<()> {
/// let tcp = tokio::net::TcpStream::connect("example.com:443").await?;
/// let conn = tls.connect(name, tcp).await?;
/// let pipe = zmux_http::dial_http1_over(conn, "example.com", &zmux_http::Options::default()).await?;
/// # drop(pipe);
/// # Ok(())
/// # }
/// ```
pub async fn dial_http1_over<IO>(io: IO, authority: &str, options: &Options) -> io::Result<PipeIo>
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    within(options.timeout, async {
        let (mut sender, conn) = http1::handshake::<_, PipeBody>(TokioIo::new(io))
            .await
            .map_err(hyper_err)?;
        tokio::spawn(conn);
        let (writer, req_body, abort) = body();
        let resp = sender
            .send_request(options.request(authority, Version::HTTP_11, req_body)?)
            .await
            .map_err(hyper_err)?;
        // One exchange per connection: it closes once this one is done.
        drop(sender);
        exchange_pipe(resp, writer, abort)
    })
    .await
}

/// Establishes a session over a new HTTP/1.1 connection ([`dial_http1`]).
pub async fn connect_http1(
    addr: &str,
    options: &Options,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<Session, ConnectError> {
    let io = dial_http1(addr, options)
        .await
        .map_err(|e| ConnectError::Io(Arc::new(e)))?;
    Session::connect(io, config).await
}

// ---- HTTP/2 client -------------------------------------------------------------------

/// An HTTP/2 client connection whose exchanges carry pipes: every pipe it
/// opens reports the connection as its carrier connection, and opens
/// lanes as further requests when [`Options::lanes`] is on. Cheap to
/// clone; the connection stays open while a clone or one of its exchanges
/// is alive.
#[derive(Clone)]
pub struct Http2Connection {
    inner: Arc<H2Inner>,
}

struct H2Inner {
    sender: http2::SendRequest<PipeBody>,
    authority: String,
    options: Options,
}

impl std::fmt::Debug for Http2Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http2Connection")
            .field("authority", &self.inner.authority)
            .finish_non_exhaustive()
    }
}

impl Http2Connection {
    /// An HTTP/2 connection (prior knowledge, no TLS) to `addr`
    /// (`host:port`, also the `:authority`).
    pub async fn connect(addr: &str, options: Options) -> io::Result<Self> {
        let tcp = TcpStream::connect(addr).await?;
        let _ = tcp.set_nodelay(true);
        Self::handshake(tcp, addr, options).await
    }

    /// HTTP/2 on an established connection, any byte stream such as a TLS
    /// stream whose ALPN chose `h2`, with `authority` as the
    /// `:authority` of its requests.
    ///
    /// ```no_run
    /// # async fn example(tls: tokio_rustls::TlsConnector,
    /// #     name: tokio_rustls::rustls::pki_types::ServerName<'static>) -> Result<(), Box<dyn std::error::Error>> {
    /// let tcp = tokio::net::TcpStream::connect("example.com:443").await?;
    /// let conn = tls.connect(name, tcp).await?;
    /// let h2 = zmux_http::Http2Connection::handshake(conn, "example.com", Default::default()).await?;
    /// let session = h2.connect_session(zmux::Config::default()).await?;
    /// # drop(session);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn handshake<IO>(io: IO, authority: &str, options: Options) -> io::Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (sender, conn) =
            http2::handshake::<_, _, PipeBody>(TokioExecutor::new(), TokioIo::new(io))
                .await
                .map_err(hyper_err)?;
        tokio::spawn(conn);
        Ok(Self {
            inner: Arc::new(H2Inner {
                sender,
                authority: authority.to_owned(),
                options,
            }),
        })
    }

    /// The connection's identity, as its pipes report it.
    pub fn conn_id(&self) -> CarrierConnId {
        CarrierConnId::new(&self.inner)
    }

    /// A pipe on a new exchange of the connection, answered within
    /// [`Options::timeout`].
    pub async fn open_pipe(&self) -> io::Result<PipeIo> {
        let (writer, req_body, abort) = body();
        let resp = within(self.inner.options.timeout, self.inner.send(req_body)).await?;
        let mut io = exchange_pipe(resp, writer, abort)?.with_carrier_conn(self.conn_id());
        if self.inner.options.lanes {
            let inner = self.inner.clone();
            io = io.with_lane_opener(move || {
                let inner = inner.clone();
                async move { inner.open_lane().await }
            });
        }
        Ok(io)
    }

    /// Establishes a session on a new exchange of the connection.
    pub async fn connect_session(
        &self,
        config: impl Into<Arc<zmux::Config>>,
    ) -> Result<Session, ConnectError> {
        let io = self
            .open_pipe()
            .await
            .map_err(|e| ConnectError::Io(Arc::new(e)))?;
        Session::connect(io, config).await
    }
}

impl H2Inner {
    /// Sends a request with `body` and waits for its response head.
    async fn send(&self, body: PipeBody) -> io::Result<Response<Incoming>> {
        let mut sender = self.sender.clone();
        sender.ready().await.map_err(hyper_err)?;
        let req = self
            .options
            .request(&self.authority, Version::HTTP_2, body)?;
        sender.send_request(req).await.map_err(hyper_err)
    }

    /// A lane: a further request whose body is the lane. Its response, the
    /// unused reverse half, is read to its end meanwhile.
    async fn open_lane(self: Arc<Self>) -> io::Result<body::BodyWriter> {
        let (writer, req_body, _abort) = body();
        let resp = within(self.options.timeout, self.send(req_body)).await?;
        if resp.status() != StatusCode::OK {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        tokio::spawn(async move {
            let mut reader = BodyReader::new(resp.into_body());
            let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
        });
        Ok(writer)
    }
}

/// Establishes a session over a new HTTP/2 connection
/// ([`Http2Connection::connect`], then
/// [`Http2Connection::connect_session`]); further pipes of the session
/// need the connection handle.
pub async fn connect_http2(
    addr: &str,
    options: &Options,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<Session, ConnectError> {
    let conn = Http2Connection::connect(addr, options.clone())
        .await
        .map_err(|e| ConnectError::Io(Arc::new(e)))?;
    conn.connect_session(config).await
}

// ---- server --------------------------------------------------------------------------

/// Hands the exchange of `req` to `listener` as a carrier and returns the
/// response that carries its other direction (status 200, the body fed by
/// zmux): for an HTTP server of the application's own, which routes the
/// request here. `peer` is the client's address, `conn` the identity of an
/// HTTP/2 connection whose exchanges are pipes (one value per
/// connection), `None` for HTTP/1.1. The `Zmux-Pipe-Join` header is
/// passed on. Must be called inside a tokio runtime.
pub fn handle_request<B>(
    listener: &Listener,
    req: Request<B>,
    peer: Option<IpAddr>,
    conn: Option<CarrierConnId>,
) -> Response<PipeBody>
where
    B: http_body::Body<Data = bytes::Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let mut hint = peer.map(PipeHint::from_addr).unwrap_or_default();
    if let Some(j) = req
        .headers()
        .get(zmux::JOIN_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        hint = hint.with_join_header(j);
    }
    let (writer, resp_body, abort) = body();
    let mut io = PipeIo::from_halves(BodyReader::new(req.into_body()), writer)
        .with_abort(move || abort.run());
    if let Some(c) = conn {
        io = io.with_carrier_conn(c);
    }
    let l = listener.clone();
    tokio::spawn(async move { l.handle_pipe(io, hint).await });
    Response::new(resp_body)
}

/// Serves HTTP/1.1 and HTTP/2 (prior knowledge) on a TCP listener until
/// `listener` is closed ([`serve_with`] without a setup step).
pub async fn serve(listener: Listener, tcp: TcpListener, options: Options) {
    serve_with(
        listener,
        || tcp.accept(),
        |stream: TcpStream, _| {
            let _ = stream.set_nodelay(true);
            std::future::ready(Ok(stream))
        },
        options,
    )
    .await;
}

/// Serves the connections `accept` yields until `listener` is closed: each
/// is set up by `setup` (for example a TLS handshake, whose ALPN may offer
/// `h2` and `http/1.1`) within the listener's `handshake_timeout`, then
/// served in a task of its own ([`serve_connection`]). At most the
/// listener's `max_pending` connections are in setup at once (as with
/// [`Listener::serve_with`]): one beyond them is dropped at once. A
/// connection whose setup fails, is dropped or carries no pipe counts in
/// [`Listener::stats`]. Run it in
/// a task of its own; it ends with [`Listener::close`].
///
/// ```no_run
/// # async fn example(listener: zmux::Listener, tcp: tokio::net::TcpListener,
/// #     tls: tokio_rustls::TlsAcceptor) {
/// // https://: TLS, then HTTP/1.1 or HTTP/2.
/// zmux_http::serve_with(
///     listener,
///     || tcp.accept(),
///     move |conn, _| tls.accept(conn),
///     zmux_http::Options::default(),
/// )
/// .await;
/// # }
/// ```
pub async fn serve_with<T, IO, A, AF, F, SF>(
    listener: Listener,
    mut accept: A,
    setup: F,
    options: Options,
) where
    A: FnMut() -> AF,
    AF: Future<Output = io::Result<(T, SocketAddr)>>,
    F: Fn(T, SocketAddr) -> SF,
    SF: Future<Output = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let options = Arc::new(options);
    let limits = listener.limits();
    let (limit, most) = (limits.handshake_timeout, limits.max_pending.max(1));
    // Each setup task holds a clone while it runs.
    let pending = Arc::new(());
    loop {
        let accepted = {
            let mut accept = std::pin::pin!(accept());
            let mut closed = std::pin::pin!(listener.closed());
            std::future::poll_fn(|cx| {
                if closed.as_mut().poll(cx).is_ready() {
                    return std::task::Poll::Ready(None);
                }
                accept.as_mut().poll(cx).map(Some)
            })
            .await
        };
        let (conn, peer) = match accepted {
            None => return,
            Some(Ok(a)) => a,
            Some(Err(e)) => {
                accept_failed(&e).await;
                continue;
            }
        };
        if Arc::strong_count(&pending) > most {
            drop(conn);
            listener.count_setup_failure();
            continue;
        }
        let (listener, options, made) = (listener.clone(), options.clone(), setup(conn, peer));
        let token = pending.clone();
        tokio::spawn(async move {
            let made = tokio::time::timeout(limit, made).await;
            drop(token);
            match made {
                Ok(Ok(io)) => serve_connection(&listener, io, Some(peer.ip()), &options).await,
                _ => listener.count_setup_failure(),
            }
        });
    }
}

/// Serves one established connection, HTTP/1.1 or HTTP/2 (prior
/// knowledge, or as its TLS ALPN chose), until it closes: POST requests to
/// [`Options::path`] are pipes handed to `listener` ([`handle_request`]),
/// the exchanges of one HTTP/2 connection with the same carrier
/// connection; other requests are answered with 404. A connection that
/// sends no request header within the listener's `handshake_timeout`
/// (HTTP/1.1), or no pipe request within it (either version), is closed
/// and counted as a setup failure ([`Listener::stats`]). `peer` is the
/// client's address.
pub async fn serve_connection<IO>(
    listener: &Listener,
    io: IO,
    peer: Option<IpAddr>,
    options: &Options,
) where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let limit = listener.limits().handshake_timeout;
    let path: Arc<str> = options.path.as_str().into();
    // The connection's identity for the exchanges of HTTP/2.
    let tag = Arc::new(ConnTag);
    let conn = CarrierConnId::new(&tag);
    let used = Arc::new(AtomicBool::new(false));
    let (seen, l) = (used.clone(), listener.clone());
    let service = service_fn(move |req: Request<Incoming>| {
        let resp = if req.method() == Method::POST && req.uri().path() == &*path {
            seen.store(true, Ordering::Relaxed);
            let h2 = (req.version() == Version::HTTP_2).then(|| conn.clone());
            handle_request(&l, req, peer, h2)
        } else {
            let mut r = Response::new(PipeBody::empty());
            *r.status_mut() = StatusCode::NOT_FOUND;
            r
        };
        std::future::ready(Ok::<_, Infallible>(resp))
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limit);
    let served = builder.serve_connection(TokioIo::new(io), service);
    let mut served = std::pin::pin!(served);
    // A connection that carries no pipe within the limit is closed.
    if tokio::time::timeout(limit, served.as_mut()).await.is_err() {
        if used.load(Ordering::Relaxed) {
            let _ = served.await;
        } else {
            served.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(limit, served).await;
        }
    }
    if !used.load(Ordering::Relaxed) {
        // Closed without carrying a pipe.
        listener.count_setup_failure();
    }
    drop(tag);
}

/// The identity of a served connection.
struct ConnTag;

/// After a failed accept: a connection gone before it was accepted is no
/// reason to wait; anything else is retried after 100 ms.
async fn accept_failed(e: &io::Error) {
    use io::ErrorKind as K;
    if !matches!(
        e.kind(),
        K::ConnectionAborted | K::ConnectionReset | K::Interrupted | K::WouldBlock
    ) {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
