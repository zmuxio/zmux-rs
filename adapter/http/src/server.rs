//! The server: requests classified by their head and handed to a listener
//! as carriers.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderValue, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use zmux::adapter::Admit;
use zmux::adapter::CarrierConnId;
use zmux::{CarrierInfo, Listener, PipeHint, PipeIo};

use crate::body::{self, BodyReader, PipeBody, ReplayBody};
use crate::classify::{RequestClass, classify};
use crate::tls::binding_of;
use crate::{Options, PairField};
use zmux_rustls::TlsBinding;

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
pub struct Fallback(Arc<FallbackFn>);

/// The request an [`Fallback`] serves.
pub type FallbackRequest = Request<ReplayBody<Incoming>>;

type FallbackFn = dyn Fn(
        FallbackRequest,
        Option<SocketAddr>,
    ) -> Pin<Box<dyn Future<Output = Response<PipeBody>> + Send>>
    + Send
    + Sync;

impl std::fmt::Debug for Fallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Fallback(..)")
    }
}

impl Fallback {
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
        let handler = &self.0;
        zmux::adapter::host_future(|| handler(req, peer))
            .await
            .unwrap_or_else(|| status(StatusCode::INTERNAL_SERVER_ERROR))
    }
}

/// The address of a request whose server gave none.
const NO_ADDR: SocketAddr =
    SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// A response without a body.
pub(crate) fn status(code: StatusCode) -> Response<PipeBody> {
    let mut r = Response::new(PipeBody::empty());
    *r.status_mut() = code;
    r
}

/// The answer to a carrier request that an intermediary forwarded from TLS
/// early data (`Early-Data: 1`): `425 (Too Early)`, so that it repeats the
/// request after its handshake.
#[must_use]
pub fn too_early() -> Response<PipeBody> {
    status(StatusCode::TOO_EARLY)
}

/// The source of a request from `peer`: the client a trusted intermediary
/// reports in its forwarding header field
/// ([`zmux::TrustedProxies::source`]), else `peer`.
#[must_use]
pub fn request_source(
    listener: &Listener,
    headers: &http::HeaderMap,
    peer: Option<SocketAddr>,
) -> Option<SocketAddr> {
    let peer = peer?;
    Some(listener.adapter().trusted_proxies().source(peer, headers))
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
/// by its head ([`classify`] with `pair`, the pairing field of split
/// halves, [`Options::pair_field`]):
///
/// - a bidirectional `POST` (no `Content-Length`): the request body is the
///   uplink, the response body the downlink;
/// - a downlink `GET` (with the pairing field): the response body is the
///   downlink;
/// - an uplink `POST` (with the pairing field): the request body is the
///   uplink.
///
/// A split bootstrap's two halves are paired by the listener, which is
/// given the pairing field's value ([`PipeHint`]). Every other request (an exchange request, an upgrade,
/// one of another method) is [`Unhandled::Fallback`] at once, its body
/// untouched. A carrier request that an intermediary forwarded from early
/// data is answered [`too_early`]. `peer` is the connection's remote
/// address (the client a PROXY protocol header reported, for one from a
/// trusted intermediary), and the carrier's source the client a trusted
/// intermediary reports in a forwarding header field on top
/// ([`request_source`]); `conn` the
/// identity of an HTTP/2 connection whose requests are carriers (one
/// value per connection), `None` for HTTP/1.1. A bidirectional carrier
/// declares the [`TlsBinding`] in the request's extensions,
/// that of the TLS connection it arrived on. Must be called inside a
/// tokio runtime; the carrier runs in a task of its own. A custom server
/// acknowledges its successful header flush with [`PipeBody::response_head_flushed`].
///
/// The carrier takes its source slot first ([`ListenerAdapter::enter`](zmux::adapter::ListenerAdapter::enter)):
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
///   is decided on its head ([`CarrierInfo::stage`]): no prefix, a
///   credential in a header field. `Accept(k)` returns the response at
///   once, the carrier having the prefix after `k` bytes in front, and the
///   request body is read on while the response flows (also on
///   HTTP/1.1); `Takeover`, with a listener's
///   fallback ([`zmux::ListenerConfig::fallback`]), hands the carrier to
///   it as a [`zmux::Takeover`]: the response is returned at once as for
///   an acceptance, and the takeover's pipe is the request body, every
///   byte read replayed in front, and (but for an uplink, whose empty
///   response ends once the host drops the request body) the response
///   body, full duplex, each half closed on its own; once the fallback's
///   future completed, a response the host did not end is reset, unless
///   it detached the takeover ([`zmux::Takeover::detach`]). Without a byte-stream
///   target, `Takeover` stalls. `Fallback` returns
///   [`Unhandled::Fallback`] with every byte read given back in front of
///   the rest of the body; `Stall` reads and
///   discards the body for a stall's duration (or until it ends) and then
///   returns [`Unhandled::Abort`]; `Close` returns that at once.
/// - Without, the response is returned when the listener first writes on
///   the carrier or has taken it ([`PipeIo::with_taken`]: a lane, an
///   uplink, a paired split bootstrap); a carrier the listener does not
///   take, with nothing written, is [`Unhandled::Fallback`] without a body.
///
/// # Errors
///
/// [`Unhandled`] for a request the listener did not take, as above.
pub async fn handle_request<B>(
    listener: &Listener,
    req: Request<B>,
    peer: Option<SocketAddr>,
    conn: Option<CarrierConnId>,
    pair: &PairField,
) -> Result<Response<PipeBody>, Unhandled<B>>
where
    B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if pair
        .check_ticket_header(
            listener
                .adapter()
                .admission()
                .and_then(zmux::Admission::prefix_ticket_header),
        )
        .is_err()
    {
        return Err(Unhandled::Abort);
    }
    let (mut parts, body) = req.into_parts();
    let version = parts.version;
    let binding = parts.extensions.get::<TlsBinding>().cloned();
    let transport = parts
        .extensions
        .get::<std::sync::Weak<zmux_rustls::TcpReset>>()
        .cloned();
    let Some(class @ (RequestClass::Bidirectional | RequestClass::Uplink | RequestClass::Downlink)) =
        classify(&parts, pair)
    else {
        return Err(Unhandled::Fallback(Box::new(Request::from_parts(
            parts,
            ReplayBody::new([Bytes::new(), Bytes::new()], Some(body)),
        ))));
    };
    let peer = peer.unwrap_or(NO_ADDR);
    let Ok(source) = zmux_http_head::preprocess(listener, &parts.headers, peer) else {
        return Ok(too_early());
    };
    let Some(mut entry) = listener.adapter().enter(peer, Some(source)) else {
        // Not taken, nothing written: the host's fallback serves it.
        return Err(Unhandled::Fallback(Box::new(Request::from_parts(
            parts,
            ReplayBody::new([Bytes::new(), Bytes::new()], Some(body)),
        ))));
    };
    let pair = parts
        .headers
        .get(pair.name())
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let hint_of = move |entry| {
        let mut hint = PipeHint::from_entry(entry);
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
        move |reader: BodyReader<B>, writer: StartWriter, taken_over: bool| {
            let (reader, probe) = zmux::adapter::SetupRead::new(body::SetupBody::new(reader));
            let (io, held) = match class {
                // An uplink taken over: its empty response ends once the
                // host is done with the request body.
                RequestClass::Uplink if taken_over => (
                    PipeIo::reader(UplinkBody {
                        inner: reader,
                        end: Some((abort.clone(), writer)),
                    })
                    .with_carrier(zmux::CarrierKind::Split),
                    None,
                ),
                RequestClass::Uplink => (
                    PipeIo::reader(reader).with_carrier(zmux::CarrierKind::Split),
                    Some(writer),
                ),
                RequestClass::Downlink => (
                    PipeIo::chunk_writer(writer).with_carrier(zmux::CarrierKind::Split),
                    None,
                ),
                _ => {
                    let io = PipeIo::from_chunk_halves(reader, writer)
                        .with_carrier(zmux::CarrierKind::Streaming);
                    let io = match &binding {
                        Some(b) => b.apply(io),
                        None => io,
                    };
                    (io, None)
                }
            };
            let io = io.with_abort(move || abort.run());
            let io = match (conn, io.carrier()) {
                (Some(conn), Some(kind)) => io.with_carrier_transport(kind, conn),
                _ => io,
            };
            (io, held, probe)
        }
    };
    let ending = abort.clone();
    let on_setup = transport.clone();
    let handled = move |l: Listener,
                        (mut io, held, probe): (PipeIo, Option<StartWriter>, _),
                        hint: PipeHint| async move {
        // The uplink's empty response owns its writer until its carrier is released.
        let (io, end) = if let Some(writer) = held {
            let worker = io.worker_guard();
            let (released, end) = tokio::sync::oneshot::channel();
            (
                io.with_close_code(move |_| {
                    let _ = released.send(());
                }),
                Some((end, writer, worker)),
            )
        } else {
            (io, None)
        };
        let absent = body::request_gone(probe, ending.dropped(), on_setup);
        let Some(r) = l.adapter().setup_until(io, hint, absent).await else {
            return Err(zmux::HandleError::Refused);
        };
        if let Some((end, writer, worker)) = end {
            // A refused bootstrap still has a protocol close in flight on
            // the downlink. Only the carrier owner can end this response.
            let _ = end.await;
            ending.finish();
            drop(writer);
            drop(worker);
        }
        r
    };
    if listener.adapter().admission().is_some() {
        let admit = {
            // The TLS connection's metadata, when the request came over one.
            let base = parts
                .extensions
                .get::<TlsBinding>()
                .map_or_else(CarrierInfo::new, TlsBinding::info);
            let info = base.with_request_head(
                Arc::new(parts.clone()),
                |p: &http::request::Parts, each| {
                    zmux::adapter::visit_fields(&p.headers, each);
                },
            );
            // A request without a body is decided on its head.
            let body = (!bodiless).then_some(&mut reader);
            entry.decide_request(info, body).await
        };
        return match admit {
            Admit::Accept(rest) => {
                let writer = StartWriter {
                    inner: writer,
                    started: None,
                };
                let (io, start, probe) = carrier(reader, writer, false);
                tokio::spawn(handled(
                    listener.clone(),
                    (io.with_prefix(rest), start, probe),
                    hint_of(entry),
                ));
                Ok(carrier_response(class, version, resp_body))
            }
            Admit::TakeOver(prefix) => {
                // A carrier decided on its body, to the listener's
                // fallback: answered as an accepted one, its pipe the
                // request body in and the response body out.
                let writer = StartWriter {
                    inner: writer,
                    started: None,
                };
                let (io, _, probe) = carrier(reader, writer, true);
                // The request is closed with the call unless detached: a
                // response the host did not end is reset.
                let gone = body::request_gone(probe, abort.dropped(), transport);
                let io = zmux::adapter::AdmitIo::pipe(io).with_on_return(move || abort.run());
                let (sent, head) = entry.response_head();
                tokio::spawn(async move {
                    let flushed = entry
                        .takeover_head(async {
                            tokio::select! {
                                biased;
                                () = gone => false,
                                result = head => result.is_ok(),
                            }
                        })
                        .await;
                    if flushed {
                        entry.take_over(io, prefix).await;
                    }
                });
                Ok(carrier_response(class, version, resp_body.with_head(sent)))
            }
            Admit::Fallback(prefix) => {
                zmux_http_head::return_fallback(&mut entry, &mut parts.extensions);
                let mut body = reader.replay(prefix.into());
                body.stop_with(listener.clone());
                Err(Unhandled::Fallback(Box::new(Request::from_parts(
                    parts, body,
                ))))
            }
            Admit::Stall => {
                entry
                    .stall_request(Some(reader), move |_| async move {
                        drop((writer, resp_body));
                    })
                    .await;
                Err(Unhandled::Abort)
            }
            _ => Err(Unhandled::Abort),
        };
    }
    // Without an admission, accepted at once.
    let _ = entry
        .decide_request(CarrierInfo::new(), None::<&mut tokio::io::Empty>)
        .await;
    let hint = hint_of(entry);
    let (started, mut start) = tokio::sync::watch::channel(false);
    let started = Arc::new(started);
    let on_taken = started.clone();
    let (io, held, probe) = carrier(
        reader,
        StartWriter {
            inner: writer,
            started: Some(started),
        },
        false,
    );
    let io = io.with_taken(move || {
        on_taken.send_replace(true);
    });
    let mut done = tokio::spawn(handled(listener.clone(), (io, held, probe), hint));
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

/// The request body of an uplink taken over: dropped, it ends the
/// request's empty response cleanly.
struct UplinkBody<R> {
    inner: R,
    end: Option<(body::Abort, StartWriter)>,
}

impl<R: AsyncRead + Unpin> AsyncRead for UplinkBody<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<R> Drop for UplinkBody<R> {
    fn drop(&mut self) {
        if let Some((end, held)) = self.end.take() {
            end.finish();
            drop(held);
        }
    }
}

/// The sending half of a carrier: one whose response is returned at its
/// first write marks `started` before the write.
struct StartWriter {
    inner: body::BodyWriter,
    started: Option<Arc<tokio::sync::watch::Sender<bool>>>,
}

impl zmux::adapter::ChunkWrite for StartWriter {
    fn poll_write_chunks(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        chunks: &mut [zmux::Chunk],
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
    let trusted = Arc::new(listener.adapter().trusted_proxies().clone());
    serve_proxied(
        listener,
        || tcp.accept(),
        move |stream: TcpStream, peer| {
            let trusted = trusted.clone();
            async move {
                let _ = stream.set_nodelay(true);
                let mut stream = stream;
                let source = zmux::adapter::proxied_source(&mut stream, peer, &trusted).await?;
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
/// served in a task of its own ([`serve_connection`]). A connection's
/// setup holds no listener slot (each request that carries a pipe takes
/// its own, [`ListenerAdapter::enter`](zmux::adapter::ListenerAdapter::enter)); it is bounded by the handshake timeout.
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
///     move |conn, _| {
///         let accepted = tls.accept(conn);
///         async move { accepted.await.map(zmux_rustls::TlsConnection::new) }
///     },
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
/// [`zmux::adapter::proxied_source`]).
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
            let (made, guard) = (setup(conn, peer), listener.adapter().setup_guard());
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
/// failure ([`Listener::stats`]). Once it served one, it is closed
/// gracefully after [`Options::idle_timeout`] without a request or a
/// response in progress (a carrier's response lasts as long as the
/// carrier), on both versions. `peer` is the client's address (or the
/// client a PROXY protocol header reported); a trusted intermediary's
/// forwarding header field is applied on top ([`request_source`]). A
/// [`zmux_rustls::TlsConnection`] as `io` adds its binding to the
/// extensions of each request.
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
    let limit = listener.adapter().handshake_timeout();
    let fallback = options.fallback.clone();
    let route = Arc::new(route);
    // The connection's identity for the requests of HTTP/2.
    let tag = Arc::new(ConnTag);
    let conn = CarrierConnId::new(&tag);
    let binding = binding_of(&io);
    let Ok(transport) = zmux_rustls::TcpReset::observe(&io) else {
        return;
    };
    let transport = transport.map(Arc::new);
    let used = Arc::new(AtomicBool::new(false));
    let activity = Arc::new(Activity::new());
    let (seen, l, act) = (used.clone(), listener.clone(), activity.clone());
    let inbox = Arc::new(HeadInbox::default());
    let heads = inbox.clone();
    let service = service_fn(move |mut req: Request<Incoming>| {
        zmux_http_head::track_fallback(req.extensions_mut());
        if let Some(transport) = &transport {
            req.extensions_mut().insert(Arc::downgrade(transport));
        }
        if let Some(b) = &binding {
            req.extensions_mut().insert(b.clone());
        }
        let (seen, l, fallback, route, conn) = (
            seen.clone(),
            l.clone(),
            fallback.clone(),
            route.clone(),
            conn.clone(),
        );
        // Active from now until the response body is dropped.
        let mut active = Active::new(act.clone());
        let heads = heads.clone();
        async move {
            let source = request_source(&l, req.headers(), peer);
            // An HTTP/2 extended CONNECT whose tunnel outlives its response
            // body.
            let tunnel = req.method() == http::Method::CONNECT
                && req.extensions().get::<hyper::ext::Protocol>().is_some();
            // Routed to zmux while `route` has it: only such requests hold
            // a connection that carries no pipe past its setup end.
            active.route(true);
            let routed = zmux::adapter::host_future(|| route(req, peer, conn))
                .await
                .unwrap_or(Err(Unhandled::Abort));
            let mut req = match routed {
                Ok(resp) => {
                    seen.store(true, Ordering::Relaxed);
                    active.tunnel_opened(tunnel && resp.status().is_success());
                    return Ok(resp.map(|mut body| Tracked {
                        upgrade: if tunnel {
                            body.take_response_head()
                        } else {
                            None
                        },
                        heads: Some(heads),
                        body,
                        _active: active,
                    }));
                }
                Err(Unhandled::Fallback(req)) => {
                    active.route(false);
                    *req
                }
                Err(Unhandled::Abort) => {
                    seen.store(true, Ordering::Relaxed);
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "request ended without a response",
                    ));
                }
            };
            zmux_http_head::finish_fallback(req.extensions_mut(), fallback.is_some());
            let resp = match &fallback {
                Some(f) => {
                    seen.store(true, Ordering::Relaxed);
                    let mut req = req;
                    req.body_mut().stop_with(l.clone());
                    f.serve(req, source).await
                }
                None => status(StatusCode::NOT_FOUND),
            };
            active.tunnel_opened(tunnel && resp.status().is_success());
            Ok(resp.map(|body| Tracked {
                upgrade: None,
                heads: None,
                body,
                _active: active,
            }))
        }
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(
            zmux::adapter::handshake_deadline(tokio::time::Instant::now().into_std(), limit)
                .map(|_| limit),
        );
    builder.http2().enable_connect_protocol();
    let flush = Arc::new(AtomicBool::new(false));
    let io = FlushIo {
        io,
        flushed: flush.clone(),
    };
    let served = builder.serve_connection_with_upgrades(TokioIo::new(io), service);
    let mut receipts = Vec::new();
    let mut driver_waker: Option<std::task::Waker> = None;
    let mut served = std::pin::pin!(served);
    // A connection that carries no pipe within the limit is closed; one
    // that did, once it has been idle for the idle timeout. Only a request
    // routed to zmux in progress holds it past the setup end, bounded by its
    // own deadlines (an exchange request's hold may outlast the setup limit
    // on a connection of its own, so no fixed cap applies); other requests
    // (a fallback 404 whose body the peer does not take) never do.
    let deadline = || {
        zmux::adapter::handshake_deadline(tokio::time::Instant::now().into_std(), limit)
            .map(tokio::time::Instant::from_std)
    };
    let setup_end = deadline();
    loop {
        // Before its first request is served, both ends are looked at:
        // the setup's, and the idle timeout's once it served one.
        let idle_end = options
            .idle_timeout
            .map_or_else(far_future, |idle| activity.idle_end(idle));
        // A routed request in progress is bounded by its own deadlines (an
        // exchange's hold among them), not by the setup's: past the setup
        // end the connection is looked at again once the request ended.
        let busy = activity.routed.load(Ordering::Acquire) > 0;
        let wake = if used.load(Ordering::Relaxed) {
            Some(idle_end)
        } else if busy {
            setup_end
                .zip(deadline())
                .map(|(setup, routed)| setup.max(routed))
        } else if idle_end > tokio::time::Instant::now() {
            Some(setup_end.map_or(idle_end, |end| end.min(idle_end)))
        } else {
            setup_end
        };
        tokio::select! {
            _ = std::future::poll_fn(|cx| {
                inbox.receive(cx, &mut driver_waker, &mut receipts);
                if receipts.is_empty() {
                    return served.as_mut().poll(cx);
                }
                // These bodies were already polled, so Hyper has submitted
                // their heads. Drive a fresh connection poll: HTTP/2 drains
                // its pending stream frames, HTTP/1 its buffered response.
                flush.store(false, Ordering::Relaxed);
                let result = served.as_mut().poll(cx);
                if !matches!(result, Poll::Ready(Err(_))) && flush.load(Ordering::Relaxed) {
                    for receipt in receipts.drain(..) {
                        receipt.flushed();
                    }
                }
                result
            }) => break,
            () = zmux::adapter::wait_deadline(wake) => {}
        }
        let now = tokio::time::Instant::now();
        let close = if used.load(Ordering::Relaxed) {
            options
                .idle_timeout
                .is_some_and(|idle| activity.idle_end(idle) <= now)
        } else {
            setup_end.is_some_and(|end| now >= end) && activity.routed.load(Ordering::Acquire) == 0
        };
        if close {
            served.as_mut().graceful_shutdown();
            let _ =
                zmux::adapter::while_open(zmux::adapter::wait_deadline(deadline()), served).await;
            break;
        }
    }
    if !used.load(Ordering::Relaxed) {
        // Closed without carrying a pipe or answering a request (a 425
        // answer is counted where it is made).
        listener.adapter().count_setup_failure();
    }
    drop(tag);
}

/// The route of [`serve_connection`]: a carrier on [`Options::path`]
/// ([`handle_request`]) or an exchange request on a path of
/// [`Options::exchange`], classified by the request's head ([`classify`]),
/// or the request back for the fallback. `peer` is the connection's
/// remote address ([`handle_request`]); `conn` the connection's identity,
/// which only HTTP/2 requests take as their carrier connection.
///
/// # Errors
///
/// [`Unhandled::Fallback`] with the request for a request that carries no
/// pipe here, or that the listener refers to the fallback;
/// [`Unhandled::Abort`] for one to end without a response.
pub async fn route_request(
    listener: &Listener,
    req: Request<Incoming>,
    peer: Option<SocketAddr>,
    conn: Option<CarrierConnId>,
    options: &Options,
) -> Result<Response<PipeBody>, Unhandled<Incoming>> {
    if options.validate_server(listener).is_err() {
        return Err(Unhandled::Abort);
    }
    let path = req.uri().path().to_owned();
    let (parts, body) = req.into_parts();
    let class = classify(&parts, &options.pair_field);
    let req = Request::from_parts(parts, body);
    let exchange = options.exchange.as_ref().filter(|x| x.matches(&path));
    match (class, exchange) {
        (Some(RequestClass::Exchange), Some(x)) => x.handle(req, peer, &options.pair_field).await,
        (Some(RequestClass::Bidirectional | RequestClass::Uplink | RequestClass::Downlink), _)
            if path == options.path =>
        {
            let h2 = (req.version() == http::Version::HTTP_2)
                .then_some(conn)
                .flatten();
            handle_request(listener, req, peer, h2, &options.pair_field).await
        }
        _ => Err(Unhandled::Fallback(Box::new(req.map(|b| {
            ReplayBody::new([Bytes::new(), Bytes::new()], Some(b))
        })))),
    }
}

/// The identity of a served connection.
struct ConnTag;

/// A time beyond every timer of a connection.
fn far_future() -> tokio::time::Instant {
    tokio::time::Instant::now() + Duration::from_hours(8760)
}

/// The requests of a connection in progress, and when the last ended.
struct Activity {
    start: tokio::time::Instant,
    active: AtomicUsize,
    /// The requests in progress routed to zmux (see `Active::route`).
    routed: AtomicUsize,
    /// An extended CONNECT tunnel was opened: the connection is in use
    /// until it ends, as an upgraded HTTP/1.1 connection is, since hyper
    /// does not tell when a tunnel ends.
    tunnel: AtomicBool,
    /// When the last request ended, in milliseconds from `start`.
    last: AtomicU64,
}

impl Activity {
    fn new() -> Self {
        Self {
            start: tokio::time::Instant::now(),
            active: AtomicUsize::new(0),
            routed: AtomicUsize::new(0),
            tunnel: AtomicBool::new(false),
            last: AtomicU64::new(0),
        }
    }

    fn ended(&self) {
        let ms = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last.fetch_max(ms, Ordering::Relaxed);
        self.active.fetch_sub(1, Ordering::AcqRel);
    }

    /// When the connection is idle for `idle`: `idle` after the last
    /// request ended, or `idle` from now while one is in progress, to look
    /// again then.
    fn idle_end(&self, idle: Duration) -> tokio::time::Instant {
        if self.tunnel.load(Ordering::Relaxed) {
            return far_future();
        }
        let since = if self.active.load(Ordering::Acquire) > 0 {
            tokio::time::Instant::now()
        } else {
            self.start + Duration::from_millis(self.last.load(Ordering::Relaxed))
        };
        since.checked_add(idle).unwrap_or_else(far_future)
    }
}

/// A request in progress, from its arrival until its response body is
/// dropped; whether it is routed to zmux.
struct Active(Arc<Activity>, bool);

impl Active {
    fn new(a: Arc<Activity>) -> Self {
        a.active.fetch_add(1, Ordering::AcqRel);
        Self(a, false)
    }

    /// Routed to zmux (`true`) or handed back to the fallback.
    fn route(&mut self, routed: bool) {
        if routed != self.1 {
            self.1 = routed;
            if routed {
                self.0.routed.fetch_add(1, Ordering::AcqRel);
            } else {
                self.0.routed.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }

    /// Marks the connection as carrying a tunnel when `opened`.
    fn tunnel_opened(&self, opened: bool) {
        if opened {
            self.0.tunnel.store(true, Ordering::Relaxed);
        }
    }
}

impl Drop for Active {
    fn drop(&mut self) {
        self.route(false);
        self.0.ended();
    }
}

type Receipt = zmux::adapter::ResponseHead;

/// Only a submitted takeover or a change of driver waker needs the mutex.
#[derive(Default)]
struct HeadInbox {
    queued: AtomicBool,
    pending: std::sync::Mutex<(Vec<Receipt>, Option<std::task::Waker>)>,
}

impl HeadInbox {
    fn submit(&self, receipt: Receipt) {
        let wake = {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            pending.0.push(receipt);
            self.queued.store(true, Ordering::Release);
            pending.1.clone()
        };
        if let Some(wake) = wake {
            wake.wake();
        }
    }

    fn receive(
        &self,
        cx: &Context<'_>,
        last: &mut Option<std::task::Waker>,
        receipts: &mut Vec<Receipt>,
    ) {
        let changed = last.as_ref().is_none_or(|w| !w.will_wake(cx.waker()));
        if changed || self.queued.load(Ordering::Acquire) {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if changed {
                *last = Some(cx.waker().clone());
                pending.1.clone_from(last);
            }
            receipts.append(&mut pending.0);
            self.queued.store(false, Ordering::Release);
        }
    }
}

/// Observes a transport flush performed by the connection task. An incomplete
/// write later in the same poll invalidates an earlier intermediate flush.
struct FlushIo<I> {
    io: I,
    flushed: Arc<AtomicBool>,
}

impl<I: AsyncRead + Unpin> AsyncRead for FlushIo<I> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for FlushIo<I> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.flushed.store(false, Ordering::Relaxed);
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.io).poll_flush(cx);
        self.flushed
            .store(matches!(result, Poll::Ready(Ok(()))), Ordering::Relaxed);
        result
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.flushed.store(false, Ordering::Relaxed);
        Pin::new(&mut self.io).poll_write_vectored(cx, bytes)
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
}

/// A response body that keeps its request in progress while it lives.
struct Tracked {
    // Hyper consumes a successful CONNECT response by giving out its
    // tunnel and dropping the body, without polling that body for DATA.
    upgrade: Option<Receipt>,
    heads: Option<Arc<HeadInbox>>,
    body: PipeBody,
    _active: Active,
}

impl Drop for Tracked {
    fn drop(&mut self) {
        if let (Some(sent), Some(heads)) = (self.upgrade.take(), &self.heads) {
            heads.submit(sent);
        }
    }
}

impl http_body::Body for Tracked {
    type Data = <PipeBody as http_body::Body>::Data;
    type Error = <PipeBody as http_body::Body>::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        if let Some(heads) = self.heads.take()
            && let Some(sent) = self.body.take_response_head()
        {
            heads.submit(sent);
        }
        Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.body.size_hint()
    }
}
