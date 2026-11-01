//! The server: requests classified by their head and handed to a listener
//! as carriers.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use zmux::carrier::CarrierConnId;
use zmux::{Admit, CarrierInfo, Listener, PipeHint, PipeIo};

use crate::body::{self, BodyReader, PipeBody, ReplayBody};
use crate::classify::{RequestClass, classify, forwarded_early_data};
use crate::{ExchangeServer, Options};

/// A request [`handle_request`] did not hand to the listener.
#[derive(Debug)]
pub enum Unhandled<B> {
    /// For the fallback target: the caller serves it with its HTTP handler
    /// for requests that carry no pipe, or answers 404 without one. Its
    /// body gives back every byte read from the request body in front of
    /// the rest; a request the listener did not take has no body (the
    /// listener read it).
    Fallback(Box<Request<ReplayBody<B>>>),
    /// To be ended without a response, at once: refused at its source's
    /// limit, an admission's `Close`, or its `Stall` once the stall is over
    /// (the request body was read and discarded meanwhile). In hyper, a service error does that: it
    /// closes an HTTP/1.1 connection and resets an HTTP/2 stream.
    Abort,
}

/// The HTTP handler of the requests that carry no pipe
/// ([`Options::fallback`]), given the request, with the body bytes read
/// before given back in front ([`ReplayBody`]), and the client's address.
/// Cheap to clone.
#[derive(Clone)]
pub struct HttpFallback(Arc<FallbackFn>);

/// The request an [`HttpFallback`] serves.
pub type FallbackRequest = Request<ReplayBody<Incoming>>;

type FallbackFn = dyn Fn(
        FallbackRequest,
        Option<SocketAddr>,
    ) -> Pin<Box<dyn Future<Output = Response<PipeBody>> + Send>>
    + Send
    + Sync;

impl std::fmt::Debug for HttpFallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HttpFallback(..)")
    }
}

impl HttpFallback {
    /// The handler `f`.
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(FallbackRequest, Option<SocketAddr>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response<PipeBody>> + Send + 'static,
    {
        Self(Arc::new(move |req, peer| Box::pin(f(req, peer))))
    }

    /// Serves `req` from `peer`.
    pub async fn serve(
        &self,
        req: FallbackRequest,
        peer: Option<SocketAddr>,
    ) -> Response<PipeBody> {
        (self.0)(req, peer).await
    }
}

/// The address of a request whose server gave none.
const NO_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// A response without a body.
fn status(code: StatusCode) -> Response<PipeBody> {
    let mut r = Response::new(PipeBody::empty());
    *r.status_mut() = code;
    r
}

/// The answer to a carrier request that an intermediary forwarded from TLS
/// early data (`Early-Data: 1`): `425 (Too Early)`, so that it repeats the
/// request after its handshake.
pub fn too_early() -> Response<PipeBody> {
    status(StatusCode::TOO_EARLY)
}

/// The source of a request from `peer`: the client a trusted intermediary
/// reports in its forwarding header field
/// ([`zmux::TrustedProxies::source`]), else `peer`.
pub fn request_source(
    listener: &Listener,
    headers: &http::HeaderMap,
    peer: Option<SocketAddr>,
) -> Option<SocketAddr> {
    let peer = peer?;
    Some(listener.trusted_proxies().source(
        peer,
        headers.iter().map(|(n, v)| (n.as_str(), v.as_bytes())),
    ))
}

/// The response of an accepted carrier: status 200 with `body`, sent
/// without a `Content-Length`. One that carries a downlink asks
/// intermediaries neither to cache nor to buffer it.
///
/// On HTTP/1.1 the connection is not reused after the carrier (`Connection:
/// close`): the request body may not have been read to its end, and a
/// client that sent a further request on the connection would wait for
/// it.
fn carrier_response(
    class: RequestClass,
    version: http::Version,
    body: PipeBody,
) -> Response<PipeBody> {
    let mut r = Response::new(body);
    let h = r.headers_mut();
    if version <= http::Version::HTTP_11 {
        h.insert(http::header::CONNECTION, HeaderValue::from_static("close"));
    }
    h.insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    h.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if class != RequestClass::Uplink {
        h.insert("x-accel-buffering", HeaderValue::from_static("no"));
    }
    r
}

/// Hands the carrier of `req`, a request of an HTTP server of the
/// application's own that routes it here, to `listener`, and returns its
/// response: status 200, whose body is the downlink (fed by zmux) or, for
/// an uplink, empty and ended with the carrier. The request is classified
/// by its head ([`classify`]):
///
/// - a bidirectional `POST` (no `Content-Length`): the request body is the
///   uplink, the response body the downlink;
/// - a downlink `GET` (with `Zmux-Pipe-Pair` or `Zmux-Pipe-Join`): the
///   response body is the downlink;
/// - an uplink `POST` (with `Zmux-Pipe-Pair`, or `Zmux-Pipe-Join` and no
///   `Content-Length`): the request body is the uplink.
///
/// A split bootstrap's two halves are paired by the listener; the
/// `Zmux-Pipe-Join` and `Zmux-Pipe-Pair` headers are passed on
/// ([`PipeHint`]). Every other request (an exchange request, an upgrade,
/// one of another method) is [`Unhandled::Fallback`] at once, its body
/// untouched. A carrier request that an intermediary forwarded from early
/// data is answered [`too_early`]. `peer` is the connection's remote
/// address (the client a PROXY protocol header reported, for one from a
/// trusted intermediary), and the carrier's source the client a trusted
/// intermediary reports in a forwarding header field on top
/// ([`request_source`]); `conn` the
/// identity of an HTTP/2 connection whose requests are carriers (one
/// value per connection), `None` for HTTP/1.1. Must be called inside a
/// tokio runtime; the carrier runs in a task of its own.
///
/// The carrier takes its source slot first ([`Listener::enter`]):
/// refused (the source has its share, or the listener is closed), the
/// request, untouched, is [`Unhandled::Fallback`]. Nothing is answered
/// before the carrier is accepted:
///
/// - With the listener's admission ([`zmux::ListenerConfig::admission`]),
///   up to its `peek` bytes of the request
///   body are read first, within its peek timeout, and decided on with the
///   request's head (`&http::request::Parts` as the
///   [`CarrierInfo::with_request`] value) and the source. A request without
///   a body (a downlink `GET`, or a body that ends before its first byte)
///   is decided on its head ([`CarrierInfo::head`]): no prefix, a
///   credential in a header field. `Accept(k)` returns the response at
///   once, the carrier having the prefix after `k` bytes in front, and the
///   request body is read on while the response flows (also on
///   HTTP/1.1); `Fallback` returns [`Unhandled::Fallback`] with every byte
///   read given back in front of the rest of the body; `Stall` reads and
///   discards the body for a stall's duration (or until it ends) and then
///   returns [`Unhandled::Abort`]; `Close` returns that at once.
/// - Without, the response is returned when the listener first writes on
///   the carrier or has taken it ([`PipeIo::with_taken`]: a lane, an
///   uplink, a paired split bootstrap); a carrier the listener does not
///   take, with nothing written, is [`Unhandled::Fallback`] without a body.
pub async fn handle_request<B>(
    listener: &Listener,
    req: Request<B>,
    peer: Option<SocketAddr>,
    conn: Option<CarrierConnId>,
) -> Result<Response<PipeBody>, Unhandled<B>>
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let (parts, body) = req.into_parts();
    let version = parts.version;
    let class = match classify(&parts) {
        Some(c @ (RequestClass::Bidirectional | RequestClass::Uplink | RequestClass::Downlink)) => {
            c
        }
        _ => {
            return Err(Unhandled::Fallback(Box::new(Request::from_parts(
                parts,
                ReplayBody::new([Bytes::new(), Bytes::new()], Some(body)),
            ))));
        }
    };
    if forwarded_early_data(&parts.headers) {
        listener.count_setup_failure();
        return Ok(too_early());
    }
    let peer = peer.unwrap_or(NO_ADDR);
    let source = request_source(listener, &parts.headers, Some(peer)).unwrap_or(peer);
    let Some(mut entry) = listener.enter(peer, Some(source)) else {
        // Not taken, nothing written: the host's fallback serves it.
        return Err(Unhandled::Fallback(Box::new(Request::from_parts(
            parts,
            ReplayBody::new([Bytes::new(), Bytes::new()], Some(body)),
        ))));
    };
    let join = |name| {
        parts
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    let (join, pair) = (join(zmux::JOIN_HEADER), join(zmux::PAIR_HEADER));
    let hint_of = move |entry| {
        let mut hint = PipeHint::from_entry(entry);
        if let Some(j) = &join {
            hint = hint.with_join_header(j);
        }
        if let Some(p) = &pair {
            hint = hint.with_pair_header(p);
        }
        hint
    };
    let bodiless = class == RequestClass::Downlink || body.is_end_stream();
    let mut reader = BodyReader::new(body);
    let (writer, resp_body, abort) = body::body();
    // The carrier of the class: its halves, the abort of the response
    // body, the connection of HTTP/2.
    // The carrier of the class, with the abort of the response body and
    // the connection of HTTP/2; an uplink's response body, which carries
    // nothing, is held until the carrier ends, and ends with it.
    let carrier = {
        let abort = abort.clone();
        move |reader: BodyReader<B>, writer: StartWriter| {
            let (io, held) = match class {
                RequestClass::Uplink => (
                    PipeIo::reader(reader).with_carrier(zmux::CarrierKind::Split),
                    Some(writer),
                ),
                RequestClass::Downlink => (
                    PipeIo::chunk_writer(writer).with_carrier(zmux::CarrierKind::Split),
                    None,
                ),
                _ => (
                    PipeIo::from_chunk_halves(reader, writer)
                        .with_carrier(zmux::CarrierKind::Streaming),
                    None,
                ),
            };
            let io = io.with_abort(move || abort.run());
            let io = match conn {
                Some(c) => io.with_carrier_conn(c),
                None => io,
            };
            (io, held)
        }
    };
    let ending = abort.clone();
    let handled = move |l: Listener, (io, held): (PipeIo, Option<StartWriter>), hint: PipeHint| async move {
        let r = l.handle_pipe(io, hint).await;
        if held.is_some() {
            match r {
                Ok(()) => ending.finish(),
                Err(_) => ending.run(),
            }
        }
        r
    };
    if listener.admission().is_some() {
        let prefix = if bodiless {
            Vec::new()
        } else {
            entry.read_prefix(&mut reader).await
        };
        let head = bodiless || (prefix.is_empty() && reader.ended());
        let admit = {
            let mut info = CarrierInfo::new().with_request(&parts).with_headers(|| {
                parts
                    .headers
                    .iter()
                    .map(|(n, v)| (n.as_str(), v.as_bytes()))
            });
            if head {
                info = info.with_head();
            }
            entry.decide(info, prefix).await
        };
        return match admit {
            Admit::Accept(rest) => {
                let writer = StartWriter {
                    inner: writer,
                    started: None,
                };
                let (io, held) = carrier(reader, writer);
                tokio::spawn(handled(
                    listener.clone(),
                    (io.with_prefix(rest), held),
                    hint_of(entry),
                ));
                Ok(carrier_response(class, version, resp_body))
            }
            Admit::Fallback(prefix) => {
                let (rest, pending) = reader.into_parts();
                let body = ReplayBody::new([prefix.into(), pending], Some(rest));
                Err(Unhandled::Fallback(Box::new(Request::from_parts(
                    parts, body,
                ))))
            }
            Admit::Stall => {
                entry.stall(Some(&mut reader)).await;
                Err(Unhandled::Abort)
            }
            _ => Err(Unhandled::Abort),
        };
    }
    // Without an admission, accepted at once.
    let _ = entry.decide(CarrierInfo::new(), Vec::new()).await;
    let hint = hint_of(entry);
    let (started, mut start) = tokio::sync::watch::channel(false);
    let started = Arc::new(started);
    let on_taken = started.clone();
    let (io, held) = carrier(
        reader,
        StartWriter {
            inner: writer,
            started: Some(started),
        },
    );
    let io = io.with_taken(move || {
        on_taken.send_replace(true);
    });
    let mut done = tokio::spawn(handled(listener.clone(), (io, held), hint));
    tokio::select! {
        biased;
        Ok(_) = start.wait_for(|s| *s) => return Ok(carrier_response(class, version, resp_body)),
        _ = &mut done => {}
    }
    if *start.borrow() {
        return Ok(carrier_response(class, version, resp_body));
    }
    Err(Unhandled::Fallback(Box::new(Request::from_parts(
        parts,
        ReplayBody::new([Bytes::new(), Bytes::new()], None),
    ))))
}

/// The sending half of a carrier: one whose response is returned at its
/// first write marks `started` before the write.
struct StartWriter {
    inner: body::BodyWriter,
    started: Option<Arc<tokio::sync::watch::Sender<bool>>>,
}

impl zmux::carrier::ChunkWrite for StartWriter {
    fn poll_write_chunks(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<io::Result<usize>> {
        if let Some(s) = self.started.take() {
            s.send_replace(true);
        }
        Pin::new(&mut self.inner).poll_write_chunks(cx, chunks)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Serves HTTP/1.1 and HTTP/2 (prior knowledge) on a TCP listener until
/// `listener` is closed ([`serve_with`] without a setup step). A
/// connection from an intermediary the listener trusts to send the PROXY
/// protocol ([`zmux::TrustedProxies::proxy_protocol`]) has its header read
/// first, its client the source of its carriers.
pub async fn serve(listener: Listener, tcp: TcpListener, options: Options) {
    let trusted = Arc::new(listener.trusted_proxies().clone());
    serve_proxied(
        listener,
        || tcp.accept(),
        move |stream: TcpStream, peer| {
            let trusted = trusted.clone();
            async move {
                let _ = stream.set_nodelay(true);
                let mut stream = stream;
                let source = zmux::proxied_source(&mut stream, peer, &trusted).await?;
                Ok((stream, source))
            }
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
/// [`Listener::serve_connections`]): one beyond them ends the oldest setup.
/// A connection whose setup fails, is ended or carries no pipe counts in
/// [`Listener::stats`]. Run it in a task of its own; it ends with
/// [`Listener::close`].
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
    accept: A,
    setup: F,
    options: Options,
) where
    A: FnMut() -> AF,
    AF: Future<Output = io::Result<(T, SocketAddr)>>,
    F: Fn(T, SocketAddr) -> SF,
    SF: Future<Output = io::Result<IO>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    serve_proxied(
        listener,
        accept,
        move |conn, peer| {
            let made = setup(conn, peer);
            async move { Ok((made.await?, peer)) }
        },
        options,
    )
    .await;
}

/// [`serve_with`] whose `setup` also gives the connection's source: the
/// peer, or the client an intermediary reports for it (the PROXY protocol,
/// [`zmux::proxied_source`]).
pub async fn serve_proxied<T, IO, A, AF, F, SF>(
    listener: Listener,
    accept: A,
    setup: F,
    options: Options,
) where
    A: FnMut() -> AF,
    AF: Future<Output = io::Result<(T, SocketAddr)>>,
    F: Fn(T, SocketAddr) -> SF,
    SF: Future<Output = io::Result<(IO, SocketAddr)>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let l = listener.clone();
    let o = Arc::new(options.clone());
    serve_proxied_with(listener, accept, setup, options, move |req, peer, conn| {
        let (l, o) = (l.clone(), o.clone());
        async move { route_request(&l, req, peer, Some(conn), &o).await }
    })
    .await;
}

/// [`serve_proxied`] with `route` in place of [`route_request`]
/// ([`serve_connection_with`]).
pub async fn serve_proxied_with<T, IO, A, AF, F, SF, H, HF>(
    listener: Listener,
    mut accept: A,
    setup: F,
    options: Options,
    route: H,
) where
    A: FnMut() -> AF,
    AF: Future<Output = io::Result<(T, SocketAddr)>>,
    F: Fn(T, SocketAddr) -> SF,
    SF: Future<Output = io::Result<(IO, SocketAddr)>> + Send + 'static,
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    H: Fn(Request<Incoming>, Option<SocketAddr>, CarrierConnId) -> HF + Send + Sync + 'static,
    HF: Future<Output = Result<Response<PipeBody>, Unhandled<Incoming>>> + Send + 'static,
{
    let options = Arc::new(options);
    let route = Arc::new(route);
    let l = listener.clone();
    l.serve_connections(
        || {
            let next = accept();
            async move { Some(next.await) }
        },
        |(conn, peer)| {
            let (made, guard) = (setup(conn, peer), listener.setup_guard());
            async move {
                let made = made.await?;
                guard.done();
                Ok::<_, io::Error>(made)
            }
        },
        move |listener, (io, source): (IO, SocketAddr)| {
            let (options, route) = (options.clone(), route.clone());
            async move {
                serve_connection_with(&listener, io, Some(source), &options, move |r, s, c| {
                    route(r, s, c)
                })
                .await;
            }
        },
    )
    .await;
}

/// Serves one established connection, HTTP/1.1 or HTTP/2 (prior
/// knowledge, or as its TLS ALPN chose), until it closes. Requests to
/// [`Options::path`] are classified by their head ([`classify`]): the
/// bidirectional, uplink and downlink carriers go to `listener`
/// ([`handle_request`], which says when they are answered), the requests
/// of one HTTP/2 connection with the same carrier connection; exchange
/// requests on a path of [`Options::exchange`] go to it. A carrier request
/// an intermediary forwarded from early data is answered [`too_early`].
/// Requests that carry no pipe (other requests, and those handed back)
/// go to [`Options::fallback`], and are answered with 404 without it;
/// [`Unhandled::Abort`] ends the request without a response. A connection
/// that sends no request header within the listener's `handshake_timeout`
/// (HTTP/1.1), or neither a pipe request nor one the fallback handler
/// serves within it (either version), is closed and counted as a setup
/// failure ([`Listener::stats`]). `peer` is the client's address (or the
/// client a PROXY protocol header reported); a trusted intermediary's
/// forwarding header field is applied on top ([`request_source`]).
pub async fn serve_connection<IO>(
    listener: &Listener,
    io: IO,
    peer: Option<SocketAddr>,
    options: &Options,
) where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (l, o) = (listener.clone(), Arc::new(options.clone()));
    serve_connection_with(listener, io, peer, options, move |req, peer, conn| {
        let (l, o) = (l.clone(), o.clone());
        async move { route_request(&l, req, peer, Some(conn), &o).await }
    })
    .await;
}

/// [`serve_connection`] with `route` in place of [`route_request`]: it is
/// given each request, the connection's peer and the connection's
/// identity, and answers it, or gives it back for
/// [`Options::fallback`] (only the fallback of `options` is used). HTTP/1.1
/// upgrades and HTTP/2's extended `CONNECT` are allowed, for routes that
/// also serve WebSocket.
pub async fn serve_connection_with<IO, H, HF>(
    listener: &Listener,
    io: IO,
    peer: Option<SocketAddr>,
    options: &Options,
    route: H,
) where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    H: Fn(Request<Incoming>, Option<SocketAddr>, CarrierConnId) -> HF + Send + Sync + 'static,
    HF: Future<Output = Result<Response<PipeBody>, Unhandled<Incoming>>> + Send + 'static,
{
    let limit = listener.limits().handshake_timeout;
    let fallback = options.fallback.clone();
    let route = Arc::new(route);
    // The connection's identity for the requests of HTTP/2.
    let tag = Arc::new(ConnTag);
    let conn = CarrierConnId::new(&tag);
    let used = Arc::new(AtomicBool::new(false));
    let (seen, l) = (used.clone(), listener.clone());
    let service = service_fn(move |req: Request<Incoming>| {
        let (seen, l, fallback, route, conn) = (
            seen.clone(),
            l.clone(),
            fallback.clone(),
            route.clone(),
            conn.clone(),
        );
        async move {
            let source = request_source(&l, req.headers(), peer);
            let req = match route(req, peer, conn).await {
                Ok(resp) => {
                    seen.store(true, Ordering::Relaxed);
                    return Ok(resp);
                }
                Err(Unhandled::Fallback(req)) => *req,
                Err(Unhandled::Abort) => {
                    seen.store(true, Ordering::Relaxed);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "request ended without a response",
                    ));
                }
            };
            Ok(match &fallback {
                Some(f) => {
                    seen.store(true, Ordering::Relaxed);
                    f.serve(req, source).await
                }
                None => status(StatusCode::NOT_FOUND),
            })
        }
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(limit);
    builder.http2().enable_connect_protocol();
    let served = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
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
        // Closed without carrying a pipe or answering a request (a 425
        // answer is counted where it is made).
        listener.count_setup_failure();
    }
    drop(tag);
}

/// The route of [`serve_connection`]: a carrier on [`Options::path`]
/// ([`handle_request`]) or an exchange request on a path of
/// [`Options::exchange`], classified by the request's head ([`classify`]),
/// or the request back for the fallback. `peer` is the connection's
/// remote address ([`handle_request`]); `conn` the connection's identity,
/// which only HTTP/2 requests take as their carrier connection.
pub async fn route_request(
    listener: &Listener,
    req: Request<Incoming>,
    peer: Option<SocketAddr>,
    conn: Option<CarrierConnId>,
    options: &Options,
) -> Result<Response<PipeBody>, Unhandled<Incoming>> {
    let path = req.uri().path().to_owned();
    let (parts, body) = req.into_parts();
    let class = classify(&parts);
    let req = Request::from_parts(parts, body);
    match class {
        Some(RequestClass::Exchange) if exchange_on(options.exchange.as_ref(), &path) => {
            let x = options.exchange.as_ref().expect("matched an exchange path");
            x.handle(req, peer)
                .await
                .map_err(|req| Unhandled::Fallback(Box::new(req)))
        }
        Some(RequestClass::Bidirectional | RequestClass::Uplink | RequestClass::Downlink)
            if path == options.path =>
        {
            let h2 = (req.version() == http::Version::HTTP_2)
                .then_some(conn)
                .flatten();
            handle_request(listener, req, peer, h2).await
        }
        _ => Err(Unhandled::Fallback(Box::new(req.map(|b| {
            ReplayBody::new([Bytes::new(), Bytes::new()], Some(b))
        })))),
    }
}

fn exchange_on(exchange: Option<&ExchangeServer>, path: &str) -> bool {
    exchange.is_some_and(|x| x.matches(path))
}

/// The identity of a served connection.
struct ConnTag;
