//! WebSocket pipe carriers for zmux over tokio-tungstenite.
//!
//! A WebSocket carries zmux records with message framing
//! ([`PipeIo::records`]): every binary message is one record's
//! Frames field, without the Size, byte-compatible with other QMux
//! implementations over WebSocket. A message never splits a record and a
//! record never spans messages, so intermediaries that re-chunk the byte
//! stream (proxies, CDNs) cannot break the framing.
//!
//! - [`connect`] and [`dial`] open a WebSocket to a URL and make a session
//!   or a carrier of it; [`serve`] accepts WebSocket upgrades on a TCP
//!   listener for a [`Listener`], and [`accept`] upgrades one
//!   connection inside the application's own server ([`Upgrade`]). With
//!   the `hyper` feature, `accept_request` upgrades one request a hyper
//!   server received (the HTTP/1.1 Upgrade, or HTTP/2's extended
//!   `CONNECT`), for endpoints that serve WebSocket next to other
//!   requests.
//! - The subprotocol (`Sec-WebSocket-Protocol`) is the ALPN identifier, as
//!   with TLS ([`Options`]): `qmux-02` or `qmux-02.<application>`, or an
//!   application's own identifier (such as `moq-transport-18`, whose
//!   specification then names the QMux version). A client offers its
//!   identifiers and their draft-01 aliases unless the request names its
//!   own, a server selects the first offered one it accepts, and the
//!   negotiated one is the session's protocol.
//! - An empty message is a record without frames, a no-op that the
//!   session counts in its pipe positions and does not charge; zmux never
//!   sends one.
//! - A server upgrades only a client that offers a subprotocol it
//!   accepts. Any other request, one offering none, one that is not a
//!   valid upgrade, or one the listener's admission does not accept
//!   ([`zmux::ListenerConfig::admission`]), is refused
//!   before anything is written: [`serve`] hands it to the listener's
//!   fallback ([`zmux::ListenerConfig::fallback`]), with the bytes read replayed, or answers
//!   it with `404 Not Found` ([`not_found`]).
//! - An admission decides on the request head, so a client's credential
//!   travels in a request header field ([`Options::with_credential`],
//!   [`Credential::header`]): a prefix authentication token in
//!   `Zmux-Prefix-Auth`, bound to the TLS connection under it where the
//!   adapter holds that ([`dial_tls`], and [`accept`] with the
//!   connection's exporter).
//! - Closing the sending half sends a Close frame, the graceful end; a pipe
//!   that zmux fails over a plain TCP connection is aborted by shutting the
//!   socket down without a Close frame, so that the peer sees a failure. A
//!   connection that ends without a Close frame is a carrier error, never a
//!   clean end. Text messages are a protocol error of the carrier.
//!
//! - `wss://`: [`dial_tls`] and [`connect_tls`] with the application's
//!   `tokio_rustls::TlsConnector`, or [`dial_over`] on a TLS stream the
//!   application established. [`dial`] and [`connect`] take `ws://`, and
//!   with the `wss` feature also `wss://`, through [`dial_tls`] with
//!   [`tls_connector`] of the Mozilla roots (webpki-roots) and the ring
//!   provider; without the feature a `wss://` URL is refused as invalid input.
//!   Over TLS 1.3 a carrier of [`dial_tls`] or [`serve_tls`] has the
//!   connection's exporter and is declared secure, for Bound joins.
//! - A client follows a redirect of the upgrade to the same host only
//!   ([`Options::with_max_redirects`], [`RedirectError`]).
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let session = zmux_websocket::connect("ws://example.com/zmux", &Default::default(), zmux::Config::default()).await?;
//! # drop(session);
//! # Ok(())
//! # }
//! ```
//!
//! A server:
//!
//! ```no_run
//! # async fn example() -> std::io::Result<()> {
//! use zmux::{Config, Listener, ListenerConfig};
//!
//! let listener = Listener::new(Config::default(), ListenerConfig::default()).expect("valid listener configuration");
//! let tcp = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
//! tokio::spawn(zmux_websocket::serve(listener.clone(), tcp, Default::default()));
//! while let Some(session) = listener.accept().await {
//!     // ...
//! #   drop(session);
//! }
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

#[cfg(feature = "hyper")]
mod hyper_upgrade;
#[cfg(feature = "hyper")]
pub use hyper_upgrade::{RequestUpgrade, UpgradedCarrier, accept_request};
pub use zmux::redirect::{DEFAULT_MAX_REDIRECTS, RedirectError};

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, ready};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::ProtocolVersion;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::{
    Request as ClientRequest, Response as ClientResponse,
};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::http::{self, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::tungstenite::{Bytes, Message};
use zmux::carrier::ChunkWrite;
use zmux::{
    Admit, CarrierInfo, ConnectError, Credential, Entry, Listener, PipeHint, PipeIo, Prefixed,
    Session,
};

pub(crate) const PROTOCOL_HEADER: &str = "Sec-WebSocket-Protocol";

/// A pipe carrier from an established WebSocket, client or server:
/// message framing, the subprotocol `protocol` as the session's protocol.
/// Without an abort (see [`dial`] for plain TCP) a failed pipe ends with a
/// Close frame.
pub fn pipe<S>(ws: WebSocketStream<S>, protocol: Option<String>) -> PipeIo
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = ws.split();
    let io = PipeIo::from_chunk_halves(
        Reader { stream },
        Writer {
            sink,
            started: (0, 0),
        },
    )
    .records()
    .with_carrier(zmux::CarrierKind::WebSocket);
    match protocol {
        Some(p) => io.with_protocol(p),
        None => io,
    }
}

/// A carrier over a new WebSocket to `request` (a `ws://` URL, or a request
/// with headers of the host's): the subprotocols default to
/// [`zmux::alpn_protocols`], and the header field of
/// [`Options::with_credential`] is added (given no exporter: there is no TLS).
/// Over plain TCP, a pipe that zmux fails is aborted without a Close
/// frame. A `wss://` request goes over TLS as with [`dial_tls`], with the
/// default [`tls_connector`] (feature `wss`); without the feature it is
/// refused with [`io::ErrorKind::InvalidInput`]. Redirects of the upgrade
/// are followed as [`Options::with_max_redirects`] says.
pub async fn dial(
    request: impl IntoClientRequest + Unpin,
    options: &Options,
) -> io::Result<PipeIo> {
    let request = request.into_client_request().map_err(io::Error::other)?;
    dial_following(request, None, options)
        .await
        .map(|(io, _)| io)
}

/// What became of one upgrade request that did not upgrade.
enum Hop {
    /// A redirect: its status and `Location`.
    Redirect(u16, Option<String>),
    Failed(io::Error),
}

impl From<io::Error> for Hop {
    fn from(e: io::Error) -> Self {
        Hop::Failed(e)
    }
}

impl From<Hop> for io::Error {
    /// A redirect where none is followed: a refusal.
    fn from(h: Hop) -> Self {
        match h {
            Hop::Failed(e) => e,
            Hop::Redirect(status, _) => io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("the server answered {status}"),
            ),
        }
    }
}

/// Dials `request` and follows its redirects, each over a new connection
/// that `hop` makes, with the credential presented anew: the carrier and
/// the URL it was upgraded at.
async fn follow<F, Fut>(
    request: ClientRequest,
    options: &Options,
    hop: F,
) -> io::Result<(PipeIo, http::Uri)>
where
    F: Fn(ClientRequest) -> Fut,
    Fut: Future<Output = Result<PipeIo, Hop>>,
{
    let mut request = request;
    let mut hops = 0;
    loop {
        match hop(copy(&request)).await {
            Ok(io) => return Ok((io, request.uri().clone())),
            Err(Hop::Failed(e)) => return Err(e),
            Err(Hop::Redirect(status, location)) => {
                let next = zmux::redirect::check(
                    &request.uri().to_string(),
                    "GET",
                    status,
                    location.as_deref(),
                )?;
                let next: http::Uri = next
                    .parse()
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                if hops >= options.max_redirects {
                    return Err(RedirectError {
                        status,
                        location: location.unwrap_or_default(),
                        reason: "too many redirects",
                    }
                    .into());
                }
                hops += 1;
                request = retarget(&request, next)?;
            }
        }
    }
}

/// A copy of a request head.
fn copy(r: &ClientRequest) -> ClientRequest {
    let mut c = ClientRequest::new(());
    *c.method_mut() = r.method().clone();
    *c.uri_mut() = r.uri().clone();
    *c.version_mut() = r.version();
    *c.headers_mut() = r.headers().clone();
    c
}

/// `request` at `uri`: a new upgrade request there, with the header fields
/// of `request` that it does not set itself.
fn retarget(request: &ClientRequest, uri: http::Uri) -> io::Result<ClientRequest> {
    let mut next = uri.into_client_request().map_err(io::Error::other)?;
    for name in request.headers().keys() {
        if next.headers().contains_key(name) {
            continue;
        }
        for v in request.headers().get_all(name) {
            next.headers_mut().append(name.clone(), v.clone());
        }
    }
    Ok(next)
}

/// [`dial`] and [`dial_tls`]: a `ws://` URL over TCP, a `wss://` one over
/// TLS with `tls` (the default connector without), redirects followed.
async fn dial_following(
    request: ClientRequest,
    tls: Option<&tokio_rustls::TlsConnector>,
    options: &Options,
) -> io::Result<(PipeIo, http::Uri)> {
    let tls = tls.cloned();
    let shared = Arc::new(options.clone());
    follow(request, options, move |r| {
        let (tls, options) = (tls.clone(), shared.clone());
        async move { dial_once(r, tls.as_ref(), &options).await }
    })
    .await
}

/// One upgrade request to its URL's host and port.
async fn dial_once(
    request: ClientRequest,
    tls: Option<&tokio_rustls::TlsConnector>,
    options: &Options,
) -> Result<PipeIo, Hop> {
    let uri = request.uri();
    let secure = match uri.scheme_str() {
        Some("wss") => true,
        Some("ws") => false,
        _ => {
            return Err(Hop::Failed(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a ws:// or wss:// URL",
            )));
        }
    };
    let host = uri
        .host()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL without a host"))?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
    if !secure {
        let tcp = TcpStream::connect((host.as_str(), port)).await?;
        let _ = tcp.set_nodelay(true);
        let socket = tcp_dup(&tcp);
        let request = offer(request, options, &CarrierInfo::new())?;
        return Ok(with_socket(upgrade_over(tcp, request).await?, socket));
    }
    #[cfg(feature = "wss")]
    let tls = tls.unwrap_or_else(|| default_tls_connector());
    #[cfg(not(feature = "wss"))]
    let Some(tls) = tls else {
        return Err(Hop::Failed(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a wss:// URL needs dial_tls or the wss feature",
        )));
    };
    let name = ServerName::try_from(host.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    let _ = tcp.set_nodelay(true);
    let socket = tcp_dup(&tcp);
    let peer = tcp.peer_addr().ok();
    let conn = SharedTls::new(tls.connect(name, tcp).await?);
    let request = {
        let mut info = conn.info().with_server_name(Some(&host));
        if let Some(p) = peer {
            info = info.with_source(p).with_peer(p);
        }
        offer(request, options, &info)?
    };
    let exporter = conn.exporter();
    let io = with_socket(upgrade_over(conn, request).await?, socket);
    let state = zmux::TlsState::new(None, Some(host));
    Ok(secured(
        io.with_terminated_tls(move || Some(state.clone())),
        exporter,
    ))
}

/// A carrier over a new WebSocket on `io`, an established byte stream such
/// as a TLS stream: the client handshake for `request` (a `ws://` or
/// `wss://` URL, or a request with headers), the subprotocols and the
/// credential's header field as in [`dial`] (the credential is given no
/// exporter: a bound one needs [`dial_tls`]). A redirect is not followed
/// (it is a refusal: the connection is the caller's). The carrier has no
/// exporter and is not declared secure: the adapter does not see the TLS
/// layer of `io`. Give the carrier the TCP socket underneath
/// ([`PipeIo::with_tcp_socket`]) so that a failed pipe is aborted without a
/// Close frame, as [`dial_tls`] does.
///
/// ```no_run
/// # async fn example(tls: tokio_rustls::TlsConnector,
/// #     name: tokio_rustls::rustls::pki_types::ServerName<'static>) -> std::io::Result<()> {
/// let tcp = tokio::net::TcpStream::connect("example.com:443").await?;
/// let conn = tls.connect(name, tcp).await?;
/// let pipe = zmux_websocket::dial_over(conn, "wss://example.com/zmux", &Default::default()).await?;
/// # drop(pipe);
/// # Ok(())
/// # }
/// ```
pub async fn dial_over<S>(
    io: S,
    request: impl IntoClientRequest + Unpin,
    options: &Options,
) -> io::Result<PipeIo>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let request = offer(request, options, &CarrierInfo::new())?;
    Ok(upgrade_over(io, request).await?)
}

/// The client handshake of `request` on `io`.
async fn upgrade_over<S>(io: S, request: ClientRequest) -> Result<PipeIo, Hop>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (ws, response) =
        tokio_tungstenite::client_async_with_config(request, io, Some(ws_config()))
            .await
            .map_err(|e| match e {
                // The server or an intermediary answered without upgrading.
                tokio_tungstenite::tungstenite::Error::Http(r) => {
                    let status = r.status().as_u16();
                    if zmux::redirect::is_redirect(status) {
                        let location = r
                            .headers()
                            .get(http::header::LOCATION)
                            .and_then(|v| v.to_str().ok())
                            .map(str::to_owned);
                        Hop::Redirect(status, location)
                    } else {
                        Hop::Failed(io::Error::new(
                            io::ErrorKind::ConnectionRefused,
                            format!("the server answered {}", r.status()),
                        ))
                    }
                }
                e => Hop::Failed(io::Error::other(e)),
            })?;
    Ok(pipe(ws, negotiated(&response)))
}

/// A carrier over a new WebSocket over TLS to a `wss://` `request`: TCP to
/// the URL's host and port (443 by default), TLS with `tls` for the host's
/// name (the application's client configuration chooses roots, ALPN and
/// early data, as with the other adapters), then the client handshake,
/// with the credential given the server's address, the negotiated ALPN
/// identifier, the host's name and the TLS exporter. Over TLS 1.3 the
/// carrier has the connection's exporter and is declared secure
/// ([`PipeIo::with_carrier_secure`]), for Bound joins and the session's
/// exporter. A pipe that zmux fails is aborted without a Close frame.
/// Redirects of the upgrade are followed as [`Options::with_max_redirects`]
/// says, each over a new connection with the credential presented anew.
pub async fn dial_tls(
    request: impl IntoClientRequest + Unpin,
    tls: &tokio_rustls::TlsConnector,
    options: &Options,
) -> io::Result<PipeIo> {
    let request = request.into_client_request().map_err(io::Error::other)?;
    dial_following(request, Some(tls), options)
        .await
        .map(|(io, _)| io)
}

/// The exporter of a TLS connection, for a carrier.
type Exporter = Arc<dyn Fn(&str, &[u8], &mut [u8]) -> bool + Send + Sync>;

/// `io` with `exporter` and declared secure, when there is one.
fn secured(io: PipeIo, exporter: Option<Exporter>) -> PipeIo {
    match exporter {
        Some(e) => io
            .with_carrier_secure()
            .with_exporter(move |label, context, out| e(label, context, out)),
        None => io,
    }
}

/// A TLS stream of either side, as the carrier needs it.
trait TlsSide {
    fn export(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> bool;
    fn tls13(&self) -> bool;
    fn alpn(&self) -> Option<Vec<u8>>;
    fn server_name(&self) -> Option<String>;
}

impl<IO> TlsSide for tokio_rustls::client::TlsStream<IO> {
    fn export(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> bool {
        let c = self.get_ref().1;
        !c.is_handshaking() && c.export_keying_material(out, label, Some(context)).is_ok()
    }
    fn tls13(&self) -> bool {
        self.get_ref().1.protocol_version() == Some(ProtocolVersion::TLSv1_3)
    }
    fn alpn(&self) -> Option<Vec<u8>> {
        self.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)
    }
    fn server_name(&self) -> Option<String> {
        None
    }
}

impl<IO> TlsSide for tokio_rustls::server::TlsStream<IO> {
    fn export(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> bool {
        let c = self.get_ref().1;
        !c.is_handshaking() && c.export_keying_material(out, label, Some(context)).is_ok()
    }
    fn tls13(&self) -> bool {
        self.get_ref().1.protocol_version() == Some(ProtocolVersion::TLSv1_3)
    }
    fn alpn(&self) -> Option<Vec<u8>> {
        self.get_ref().1.alpn_protocol().map(<[u8]>::to_vec)
    }
    fn server_name(&self) -> Option<String> {
        self.get_ref().1.server_name().map(str::to_owned)
    }
}

/// A TLS stream that the WebSocket takes while the carrier keeps its
/// exporter: both share the stream, which a lock taken per poll guards. The
/// exporter does not keep it: once the WebSocket is gone it gives no value.
struct SharedTls<S> {
    stream: Arc<Mutex<S>>,
    alpn: Option<Vec<u8>>,
    server_name: Option<String>,
}

fn lock<S>(m: &Mutex<S>) -> std::sync::MutexGuard<'_, S> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<S: TlsSide + Send + 'static> SharedTls<S> {
    fn new(stream: S) -> Self {
        Self {
            alpn: stream.alpn(),
            server_name: stream.server_name(),
            stream: Arc::new(Mutex::new(stream)),
        }
    }

    /// The metadata for an admission or a credential: the exporter, the
    /// ALPN identifier and the server name.
    fn info(&self) -> CarrierInfo<'_> {
        let stream = &self.stream;
        CarrierInfo::new()
            .with_alpn(self.alpn.as_deref())
            .with_server_name(self.server_name.as_deref())
            .with_exporter(move |label, context, out| lock(stream).export(label, context, out))
    }

    /// The carrier's exporter, over TLS 1.3 only.
    fn exporter(&self) -> Option<Exporter> {
        if !lock(&self.stream).tls13() {
            return None;
        }
        let weak = Arc::downgrade(&self.stream);
        Some(Arc::new(move |label, context, out| {
            weak.upgrade()
                .is_some_and(|s| lock(&s).export(label.as_bytes(), context, out))
        }))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SharedTls<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut *lock(&self.stream)).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SharedTls<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *lock(&self.stream)).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *lock(&self.stream)).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *lock(&self.stream)).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut *lock(&self.stream)).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        lock(&self.stream).is_write_vectored()
    }
}

/// A TLS connector for `wss://` that trusts `roots`, with rustls's ring provider, its
/// safe default protocol versions and the ALPN identifier `http/1.1`, as [`serve_tls`]
/// expects; [`dial`] uses the one of the Mozilla roots.
#[cfg(feature = "wss")]
pub fn tls_connector(roots: tokio_rustls::rustls::RootCertStore) -> tokio_rustls::TlsConnector {
    use tokio_rustls::rustls;
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("the ring provider supports the default protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

/// The [`tls_connector`] of the Mozilla roots of webpki-roots, made once.
#[cfg(feature = "wss")]
fn default_tls_connector() -> &'static tokio_rustls::TlsConnector {
    static CONNECTOR: std::sync::OnceLock<tokio_rustls::TlsConnector> = std::sync::OnceLock::new();
    CONNECTOR.get_or_init(|| {
        tls_connector(tokio_rustls::rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
    })
}

/// Establishes a session over a new WebSocket over TLS ([`dial_tls`], then
/// [`Session::connect`]).
pub async fn connect_tls(
    request: impl IntoClientRequest + Unpin,
    tls: &tokio_rustls::TlsConnector,
    options: &Options,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<Session, ConnectError> {
    let io = dial_tls(request, tls, options)
        .await
        .map_err(|e| ConnectError::Io(Arc::new(e)))?;
    Session::connect(io, config).await
}

/// The request with the offered subprotocols unless it names its own, and
/// the header field of [`Options::with_credential`] for a carrier with metadata
/// `info`.
fn offer(
    request: impl IntoClientRequest + Unpin,
    options: &Options,
    info: &CarrierInfo<'_>,
) -> io::Result<ClientRequest> {
    let mut request = request.into_client_request().map_err(io::Error::other)?;
    if !request.headers().contains_key(PROTOCOL_HEADER) {
        let offer = options.offer().join(", ");
        let value = HeaderValue::from_str(&offer).map_err(io::Error::other)?;
        request.headers_mut().insert(PROTOCOL_HEADER, value);
    }
    if let Some(c) = &options.credential {
        let (name, value) = c.header(info)?;
        let name = http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let value = HeaderValue::from_str(&value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        request.headers_mut().insert(name, value);
    }
    Ok(request)
}

/// The subprotocol the server selected.
fn negotiated(response: &ClientResponse) -> Option<String> {
    response
        .headers()
        .get(PROTOCOL_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// The carrier with the TCP socket underneath, for aborts.
fn with_socket(io: PipeIo, socket: Option<SocketDup>) -> PipeIo {
    #[cfg(any(unix, windows))]
    if let Some(s) = socket {
        return io.with_tcp_socket(&s);
    }
    #[cfg(not(any(unix, windows)))]
    let _ = socket;
    io
}

/// Establishes a session over a new WebSocket ([`dial`], then
/// [`Session::connect`]).
pub async fn connect(
    request: impl IntoClientRequest + Unpin,
    options: &Options,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<Session, ConnectError> {
    let io = dial(request, options)
        .await
        .map_err(|e| ConnectError::Io(Arc::new(e)))?;
    Session::connect(io, config).await
}

/// What became of an upgrade request ([`accept`]).
#[derive(Debug)]
// Returned once per connection and taken apart at once.
#[allow(clippy::large_enum_variant)]
pub enum Upgrade<S> {
    /// Upgraded: the carrier and its hint, for [`Listener::handle_pipe`].
    Accepted(PipeIo, PipeHint),
    /// Not upgraded: the connection, every byte read from it replayed in
    /// front, for the application's HTTP handler; without one, answer it
    /// with [`not_found`].
    Refused(Prefixed<S>),
    /// Stalled or closed by the admission; nothing more to do.
    Ended,
}

/// Upgrades one accepted connection, any byte stream such as a TLS
/// stream, to a WebSocket carrier (messages of at most one record), or
/// refuses it. `entry` is the connection's entry into the listener
/// ([`Listener::enter`], taken before its TLS handshake). Nothing is
/// written on the connection before the upgrade is decided.
///
/// The request head is read first, up to [`Options::max_request_head`]
/// bytes (bound the call: [`serve`] bounds it with the listener's
/// handshake timeout); with the TLS handshake before, it is the carrier's
/// outer handshake. It is upgraded when it is a WebSocket upgrade request
/// (`GET`, HTTP/1.1, `Connection: upgrade`, `Upgrade: websocket`, version
/// 13 and a key), the client offers a subprotocol that `options` accepts
/// (an identifier of it or its draft-01 alias; the first offered one is
/// selected), and the listener's admission
/// ([`zmux::ListenerConfig::admission`]) accepts it. The admission decides
/// on the request head, which the metadata carries
/// ([`CarrierInfo::request`], an `http::request::Parts`, and its header
/// fields, [`CarrierInfo::for_each_header`]; [`CarrierInfo::head`] is
/// set), without a prefix ([`zmux::Admission::prefix_auth`] takes its
/// token from the request header field), so that nothing is answered or
/// read as a WebSocket before the decision and a refused request is replayed
/// as it came; no message of the carrier is read for it. It also has what
/// `info` gives
/// of the connection (over TLS its exporter, ALPN identifier and server
/// name: `zmux_rustls::carrier_info`). Every other request, a malformed
/// or oversized head included, is [`Upgrade::Refused`], the bytes read
/// replayed, as is one the admission decides on with `Fallback`; `Stall`
/// reads and discards for a stall's duration and then closes, and `Close`
/// closes, without a response ([`Upgrade::Ended`]). When the entry's peer
/// is an intermediary the listener trusts to report its client in a
/// forwarding header field, the client it reports is the carrier's source
/// instead ([`zmux::TrustedProxies::source`], [`Entry::set_source`]). The
/// hint carries the entry,
/// for [`Listener::handle_pipe`]. An upgrade that an intermediary
/// forwarded from TLS early data (`Early-Data: 1`) is answered
/// `425 Too Early` before any admission and is [`Upgrade::Ended`]. A
/// refused or too-early request counts in the listener's statistics as a
/// failed handshake. Over TLS, give the carrier the TCP socket underneath
/// ([`PipeIo::with_tcp_socket`]) so that a failed pipe is aborted without
/// a Close frame. The carrier has no exporter and is not declared
/// secure ([`PipeIo::with_carrier_secure`]): the stream is the caller's,
/// and [`serve_tls`] gives both.
///
/// ```no_run
/// # async fn example(listener: zmux::Listener, tcp: tokio::net::TcpListener,
/// #     tls: tokio_rustls::TlsAcceptor) -> std::io::Result<()> {
/// use zmux_websocket::Upgrade;
///
/// // wss://: the source slot, TLS, then the upgrade.
/// let (conn, peer) = tcp.accept().await?;
/// let Some(entry) = listener.enter(peer, None) else {
///     return Ok(());
/// };
/// let conn = tls.accept(conn).await?;
/// // zmux_rustls::carrier_info(c) also gives the TLS exporter, for bound
/// // tokens.
/// let options = zmux_websocket::Options::default();
/// let upgraded = zmux_websocket::accept(conn, entry, |_| zmux::CarrierInfo::new(), &listener, &options);
/// match upgraded.await? {
///     Upgrade::Accepted(pipe, hint) => {
///         let _ = listener.handle_pipe(pipe, hint).await;
///     }
///     Upgrade::Refused(mut conn) => zmux_websocket::not_found(&mut conn).await?,
///     Upgrade::Ended => {}
/// }
/// # Ok(())
/// # }
/// ```
pub async fn accept<S, I>(
    mut io: S,
    mut entry: Entry,
    info: I,
    listener: &Listener,
    options: &Options,
) -> io::Result<Upgrade<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    I: for<'a> FnOnce(&'a S) -> CarrierInfo<'a>,
{
    let (buf, head_len) = read_head(&mut io, options.max_request_head).await?;
    // Not an upgrade this server takes: a failed upgrade (the entry
    // dropped counts it).
    let Some(head_len) = head_len else {
        return Ok(Upgrade::Refused(Prefixed::new(io, buf)));
    };
    let Some(upgrade) = parse_upgrade(&buf[..head_len], options) else {
        return Ok(Upgrade::Refused(Prefixed::new(io, buf)));
    };
    let fields = || {
        upgrade
            .parts
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_bytes()))
    };
    if zmux::forwarded_early_data(fields()) {
        // Forwarded from TLS early data: no carrier is taken from it, and
        // the intermediary repeats it after its handshake.
        io.write_all(b"HTTP/1.1 425 Too Early\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            .await?;
        let _ = io.shutdown().await;
        return Ok(Upgrade::Ended);
    }
    // Behind a PROXY protocol header, the client it reported is the hop
    // whose forwarding header field counts.
    let source = listener.trusted_proxies().source(entry.source(), fields());
    if !entry.set_source(source) {
        return Ok(Upgrade::Ended);
    }
    let admit = {
        let info = info(&io)
            .with_head()
            .with_request(&upgrade.parts)
            .with_headers(fields);
        entry.decide(info, Vec::new()).await
    };
    match admit {
        Admit::Accept(_) => {}
        Admit::Fallback(_) => return Ok(Upgrade::Refused(Prefixed::new(io, buf))),
        Admit::Stall => {
            entry.stall(Some(&mut io)).await;
            let _ = io.shutdown().await;
            return Ok(Upgrade::Ended);
        }
        _ => return Ok(Upgrade::Ended),
    }
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
         Sec-WebSocket-Accept: {}\r\n{PROTOCOL_HEADER}: {}\r\n\r\n",
        upgrade.accept_key, upgrade.protocol
    );
    io.write_all(response.as_bytes()).await?;
    io.flush().await?;
    let rest = buf[head_len..].to_vec();
    let ws = WebSocketStream::from_partially_read(io, rest, Role::Server, Some(ws_config())).await;
    let hint = PipeHint::from_entry(entry);
    Ok(Upgrade::Accepted(pipe(ws, Some(upgrade.protocol)), hint))
}

/// Answers a refused request with `404 Not Found` and ends the
/// connection's write side: the answer of a server without an HTTP
/// handler for requests it does not upgrade.
pub async fn not_found<S: AsyncWrite + Unpin + ?Sized>(io: &mut S) -> io::Result<()> {
    io.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await?;
    io.shutdown().await
}

/// Reads until the end of the request head: the bytes read, and the
/// head's length once its end is among them within `limit` bytes (`None`
/// when the connection ended, or the limit passed, before it).
async fn read_head<S: AsyncRead + Unpin>(
    io: &mut S,
    limit: usize,
) -> io::Result<(Vec<u8>, Option<usize>)> {
    let mut buf = Vec::with_capacity(limit.min(1024));
    let mut chunk = [0u8; 1024];
    loop {
        let n = io
            .read(&mut chunk[..(limit - buf.len()).clamp(1, 1024)])
            .await?;
        if n == 0 {
            return Ok((buf, None));
        }
        let from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            return Ok((buf, Some(from + i + 4)));
        }
        if buf.len() >= limit {
            return Ok((buf, None));
        }
    }
}

/// A request head that upgrades.
struct UpgradeRequest {
    parts: http::request::Parts,
    protocol: String,
    accept_key: String,
}

/// The upgrade of `head` (a complete request head), when it is a
/// WebSocket upgrade request offering a subprotocol `options` accepts.
fn parse_upgrade(head: &[u8], options: &Options) -> Option<UpgradeRequest> {
    let lines = head.windows(2).filter(|w| w == b"\r\n").count();
    let mut headers = vec![httparse::EMPTY_HEADER; lines];
    let mut req = httparse::Request::new(&mut headers);
    if !matches!(req.parse(head), Ok(httparse::Status::Complete(_))) || req.version != Some(1) {
        return None;
    }
    let mut builder = http::Request::builder()
        .method(req.method?)
        .uri(req.path?)
        .version(http::Version::HTTP_11);
    for h in req.headers.iter() {
        builder = builder.header(h.name, h.value);
    }
    let (parts, ()) = builder.body(()).ok()?.into_parts();
    let headers = &parts.headers;
    let tokens = |name: &str| {
        headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .map(str::trim)
            .map(str::to_owned)
            .collect::<Vec<_>>()
    };
    let upgrade = parts.method == http::Method::GET
        && tokens("Connection")
            .iter()
            .any(|t| t.eq_ignore_ascii_case("upgrade"))
        && tokens("Upgrade")
            .iter()
            .any(|t| t.eq_ignore_ascii_case("websocket"))
        && headers
            .get("Sec-WebSocket-Version")
            .is_some_and(|v| v.as_bytes() == b"13");
    if !upgrade {
        return None;
    }
    let key = headers.get("Sec-WebSocket-Key")?;
    let protocol = options.select(&tokens(PROTOCOL_HEADER))?;
    Some(UpgradeRequest {
        accept_key: derive_accept_key(key.as_bytes()),
        protocol,
        parts,
    })
}

/// Serves WebSocket upgrades on a TCP listener until `listener` is
/// closed: each connection, in a task of its own and as a setup of
/// [`Listener::serve_connections`] (within the listener's
/// `handshake_timeout` and `max_pending`), has the PROXY protocol header
/// of an intermediary the listener trusts to send it read first
/// ([`zmux::proxied_source`]: the client it reports is the source, a
/// forwarding header field then applies on top), takes its source slot
/// ([`Listener::enter`]) and is upgraded by [`accept`], the listener's
/// admission deciding. An upgraded carrier goes to
/// [`Listener::handle_pipe`] (new sessions to [`Listener::accept`]), and
/// a refused request to the listener's byte-stream fallback
/// ([`zmux::ListenerConfig::fallback`]), given the connection with every
/// byte read replayed and the source, or else is answered with
/// [`not_found`]. [`serve_tls`] serves `wss://`.
pub async fn serve(listener: Listener, tcp: TcpListener, options: Options) {
    serve_over(
        listener,
        tcp,
        options,
        |conn| std::future::ready(Ok(conn)),
        |_| CarrierInfo::new(),
        |_| None,
    )
    .await;
}

/// Serves WebSocket upgrades over TLS (`wss://`) on a TCP listener until
/// `listener` is closed, as [`serve`] does: the PROXY protocol header of a
/// trusted intermediary is read and the source slot taken before the
/// handshake, the handshake and the upgrade run within the listener's
/// `handshake_timeout`, and the admission decides with the connection's
/// exporter, ALPN identifier and server name
/// (as `zmux_rustls::carrier_info` gives). Over TLS 1.3 a carrier has the
/// connection's exporter and is declared secure
/// ([`PipeIo::with_carrier_secure`]), for Bound joins and the session's
/// exporter. `tls` should offer the ALPN identifier `http/1.1`.
pub async fn serve_tls(
    listener: Listener,
    tcp: TcpListener,
    tls: tokio_rustls::TlsAcceptor,
    options: Options,
) {
    serve_over(
        listener,
        tcp,
        options,
        move |conn| {
            let accepted = tls.accept(conn);
            async move { accepted.await.map(SharedTls::new) }
        },
        SharedTls::info,
        SharedTls::exporter,
    )
    .await;
}

/// [`serve`] with `setup` (a TLS handshake) between the PROXY protocol
/// header and the upgrade, `info` the metadata of a set-up connection and
/// `exporter` its exporter for the carrier.
async fn serve_over<C, S, SF>(
    listener: Listener,
    tcp: TcpListener,
    options: Options,
    setup: S,
    info: fn(&C) -> CarrierInfo<'_>,
    exporter: fn(&C) -> Option<Exporter>,
) where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    S: Fn(TcpStream) -> SF + Send + Sync + 'static,
    SF: Future<Output = io::Result<C>> + Send,
{
    let trusted = listener.trusted_proxies().clone();
    let shared = Arc::new((options, trusted, setup));
    let upgrade = {
        let listener = listener.clone();
        move |(mut conn, peer): (TcpStream, SocketAddr)| {
            let (shared, listener) = (shared.clone(), listener.clone());
            async move {
                let (options, trusted, setup) = &*shared;
                let _ = conn.set_nodelay(true);
                let socket = tcp_dup(&conn);
                let Ok(source) = zmux::proxied_source(&mut conn, peer, trusted).await else {
                    listener.count_setup_failure();
                    return Err(());
                };
                let entry = listener.enter(peer, Some(source)).ok_or(())?;
                // A failed handshake or upgrade counts with the entry.
                let conn = setup(conn).await.map_err(drop)?;
                let exporter = exporter(&conn);
                let upgraded = accept(conn, entry, info, &listener, options)
                    .await
                    .map_err(drop)?;
                Ok((upgraded, socket, source, exporter))
            }
        }
    };
    let served = move |l: Listener, (upgraded, socket, source, exporter)| async move {
        match upgraded {
            Upgrade::Accepted(io, hint) => {
                let io = secured(with_socket(io, socket), exporter);
                let _ = l.handle_pipe(io, hint).await;
            }
            Upgrade::Refused(conn) => match l.limits().fallback {
                Some(f) => {
                    let (conn, prefix) = conn.into_parts();
                    let conn: Box<dyn zmux::FallbackStream> = Box::new(conn);
                    f.serve(Prefixed::new(conn, prefix), source).await;
                }
                None => {
                    let mut conn = conn;
                    let _ = not_found(&mut conn).await;
                }
            },
            Upgrade::Ended => {}
        }
    };
    listener
        .serve_connections(|| async { Some(tcp.accept().await) }, upgrade, served)
        .await;
}

/// The subprotocols of the carrier: the identifiers a client offers (with
/// their draft-01 aliases after them) and a server accepts.
///
/// ```
/// use zmux_websocket::Options;
///
/// // qmux-02.chat (and its alias qmux-01.chat) ...
/// let chat = Options::for_application("chat");
/// // ... or an application's own identifier, as a QMux-over-WebSocket
/// // application defines it.
/// let moq = Options::for_protocol("moq-transport-18");
/// # drop((chat, moq));
/// ```
#[derive(Debug, Clone)]
pub struct Options {
    protocols: Vec<String>,
    credential: Option<Arc<dyn Credential>>,
    max_request_head: usize,
    max_redirects: usize,
}

/// The default of [`Options::max_request_head`].
pub const DEFAULT_MAX_REQUEST_HEAD: usize = 16 << 10;

impl Default for Options {
    /// `qmux-02`, with its alias `qmux-01`; no admission.
    fn default() -> Self {
        Self::for_protocol(String::from_utf8_lossy(zmux::proto::ident::DEFAULT_ALPN).into_owned())
    }
}

impl Options {
    /// `qmux-02.<application>` (and its alias `qmux-01.<application>`).
    pub fn for_application(application: &str) -> Self {
        Self::for_protocol(format!(
            "{}.{application}",
            String::from_utf8_lossy(zmux::proto::ident::DEFAULT_ALPN)
        ))
    }

    /// An identifier used as it is, such as an application's own ALPN
    /// identifier; one that does not end in `-02` has no alias.
    pub fn for_protocol(id: impl Into<String>) -> Self {
        Self {
            protocols: vec![id.into()],
            credential: None,
            max_request_head: DEFAULT_MAX_REQUEST_HEAD,
            max_redirects: DEFAULT_MAX_REDIRECTS,
        }
    }

    /// With the credential a client presents in a request header field
    /// ([`Credential::header`]), such as a prefix authentication token.
    #[must_use]
    pub fn with_credential(mut self, credential: Arc<dyn Credential>) -> Self {
        self.credential = Some(credential);
        self
    }

    /// With this bound on a request head a server reads (default
    /// [`DEFAULT_MAX_REQUEST_HEAD`], at least 1): a longer one is refused.
    #[must_use]
    pub fn with_max_request_head(mut self, bytes: usize) -> Self {
        self.max_request_head = bytes.max(1);
        self
    }

    /// The bound on a request head a server reads.
    pub fn max_request_head(&self) -> usize {
        self.max_request_head
    }

    /// With this bound on the redirects of the upgrade a client follows
    /// (default [`DEFAULT_MAX_REDIRECTS`]; 0 follows none). A redirect is
    /// followed only to the same host: the same scheme and port, or `ws`
    /// to `wss` on any port; never `wss` to `ws`, another host, or a
    /// location with credentials. Each is a new connection with the
    /// credential presented anew. One not followed fails the dial with a
    /// [`RedirectError`].
    #[must_use]
    pub fn with_max_redirects(mut self, redirects: usize) -> Self {
        self.max_redirects = redirects;
        self
    }

    /// The bound on the redirects of the upgrade a client follows.
    pub fn max_redirects(&self) -> usize {
        self.max_redirects
    }

    /// With one more identifier, after the others in preference.
    #[must_use]
    pub fn with_protocol(mut self, id: impl Into<String>) -> Self {
        self.protocols.push(id.into());
        self
    }

    /// The offer: the identifiers, then their aliases.
    fn offer(&self) -> Vec<String> {
        let aliases = self
            .protocols
            .iter()
            .filter_map(|p| zmux::proto::ident::alpn_alias(p.as_bytes()))
            .map(|a| String::from_utf8_lossy(&a).into_owned());
        self.protocols.iter().cloned().chain(aliases).collect()
    }

    /// The offered identifier selected: the first of
    /// these, in order, that the client offered as it is or as its alias;
    /// the identifier as it is when both were offered.
    pub(crate) fn select(&self, offered: &[String]) -> Option<String> {
        self.protocols.iter().find_map(|p| {
            offered
                .iter()
                .find(|o| o.as_str() == p.as_str())
                .or_else(|| {
                    offered
                        .iter()
                        .find(|o| zmux::proto::ident::alpn_matches(p.as_bytes(), o.as_bytes()))
                })
                .cloned()
        })
    }
}

/// The message limits: one byte more than the largest record's Frames
/// field, so that a peer cannot make the stack buffer much more than a
/// record before the carrier sees it, and a message above the session's
/// `max_record_size` reaches it as the record above the limit that it is
/// (FRAME_ENCODING_ERROR) rather than as a carrier failure. The session's
/// read buffer holds every message this lets through.
pub(crate) fn ws_config() -> WebSocketConfig {
    let max = zmux::proto::params::ZMUX_MAX_RECORD_SIZE as usize + 1;
    WebSocketConfig::default()
        .max_message_size(Some(max))
        .max_frame_size(Some(max))
}

/// A duplicate of the TCP socket, for the carrier's queries and abort.
fn tcp_dup(tcp: &TcpStream) -> Option<SocketDup> {
    #[cfg(unix)]
    return std::os::fd::AsFd::as_fd(tcp).try_clone_to_owned().ok();
    #[cfg(windows)]
    return std::os::windows::io::AsSocket::as_socket(tcp)
        .try_clone_to_owned()
        .ok();
    #[cfg(not(any(unix, windows)))]
    {
        let _ = tcp;
        None
    }
}

#[cfg(unix)]
type SocketDup = std::os::fd::OwnedFd;
#[cfg(windows)]
type SocketDup = std::os::windows::io::OwnedSocket;
#[cfg(not(any(unix, windows)))]
type SocketDup = ();

/// The receiving half: one binary message per read.
struct Reader<S> {
    stream: SplitStream<WebSocketStream<S>>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Reader<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let msg = match ready!(Pin::new(&mut self.stream).poll_next(cx)) {
                // The end of the stream without a Close frame is reported
                // as an error by tungstenite; a Close frame is the end.
                None | Some(Ok(Message::Close(_))) => return Poll::Ready(Ok(())),
                Some(Err(e)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, e)));
                }
                Some(Ok(m)) => m,
            };
            match msg {
                // An empty message is an empty record, a no-op for the
                // session (a read of nothing would be the end).
                Message::Binary(b) if b.is_empty() => {
                    return Poll::Ready(Err(zmux::carrier::empty_message()));
                }
                Message::Binary(b) if b.len() <= buf.remaining() => {
                    buf.put_slice(&b);
                    return Poll::Ready(Ok(()));
                }
                // Cannot happen with zmux's driver, whose buffer holds the
                // largest message `ws_config` lets through; another reader
                // with less room gets an error rather than a split record.
                Message::Binary(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "a message larger than the read buffer",
                    )));
                }
                Message::Text(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "a text message on a zmux carrier",
                    )));
                }
                // Pings are answered by the stack.
                _ => {}
            }
        }
    }
}

/// The sending half: one binary message per write, the session's buffer
/// as it is, flushed before the write returns.
struct Writer<S> {
    sink: SplitSink<WebSocketStream<S>, Message>,
    /// The messages handed to the sink and not yet flushed: their count and
    /// bytes.
    started: (usize, usize),
}

fn ws_error(e: tokio_tungstenite::tungstenite::Error) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, e)
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> ChunkWrite for Writer<S> {
    /// `chunks` is one message.
    fn poll_write_chunks(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_message_batch(cx, chunks)
    }

    fn takes_message_batches(&self) -> bool {
        true
    }

    /// The messages go into the sink's buffer, then one flush.
    fn poll_write_message_batch(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        messages: &mut [Bytes],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        while let Some(msg) = messages.get(this.started.0) {
            ready!(Pin::new(&mut this.sink).poll_ready(cx)).map_err(ws_error)?;
            // Shared with the sink; taken from `messages` once flushed.
            Pin::new(&mut this.sink)
                .start_send(Message::Binary(msg.clone()))
                .map_err(ws_error)?;
            this.started.0 += 1;
            this.started.1 += msg.len();
        }
        ready!(Pin::new(&mut this.sink).poll_flush(cx)).map_err(ws_error)?;
        let (_, bytes) = std::mem::take(&mut this.started);
        messages.fill(Bytes::new());
        Poll::Ready(Ok(bytes))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.sink).poll_flush(cx).map_err(ws_error)
    }

    /// Sends a Close frame: the graceful end.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.sink).poll_close(cx).map_err(ws_error)
    }
}

/// A [`zmux::Candidate`] of [`zmux::CarrierKind::WebSocket`] for carrier
/// modes: a WebSocket to `url` (`ws://` or `wss://`, its target the
/// endpoint's) over a connection that `connect` makes, plain TCP or TLS
/// ([`dial_over`]). A redirect is followed when it keeps the scheme, host
/// and port (the connection is `connect`'s), and later carriers start at
/// the URL it led to; one that fails starts at `url` again.
pub fn candidate<C, F, S>(connect: C, url: &str, options: &Options) -> zmux::Candidate
where
    C: Fn() -> F + Send + Sync + 'static,
    F: Future<Output = io::Result<S>> + Send + 'static,
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let connect = Arc::new(connect);
    let target = Arc::new(zmux::HttpTarget::new(url));
    let options = Arc::new(options.clone());
    let named = target.clone();
    zmux::Candidate::new(zmux::CarrierKind::WebSocket, move || {
        let (connect, target, options) = (connect.clone(), target.clone(), options.clone());
        async move {
            let request = target
                .url()
                .into_client_request()
                .map_err(io::Error::other)?;
            let scheme = request.uri().scheme().cloned();
            let dialed = follow(request, &options, |r| {
                let (connect, options, scheme) = (connect.clone(), options.clone(), scheme.clone());
                async move {
                    if r.uri().scheme() != scheme.as_ref() {
                        return Err(Hop::Failed(
                            RedirectError {
                                status: 0,
                                location: r.uri().to_string(),
                                reason: "another scheme over the same connection",
                            }
                            .into(),
                        ));
                    }
                    let request = offer(r, &options, &CarrierInfo::new())?;
                    upgrade_over(connect().await?, request).await
                }
            })
            .await;
            match &dialed {
                Ok((_, last)) => target.redirected(&last.to_string()),
                Err(_) => target.reset(),
            }
            dialed.map(|(io, _)| io)
        }
    })
    .with_target(named)
}

/// A [`zmux::Candidate`] of [`zmux::CarrierKind::WebSocket`] over TLS to a
/// `wss://` `url` ([`dial_tls`]): later carriers start at the URL
/// redirects led the last one to, and one that fails starts at `url`
/// again.
pub fn candidate_tls(
    url: &str,
    tls: tokio_rustls::TlsConnector,
    options: &Options,
) -> zmux::Candidate {
    let target = Arc::new(zmux::HttpTarget::new(url));
    let options = Arc::new(options.clone());
    let named = target.clone();
    zmux::Candidate::new(zmux::CarrierKind::WebSocket, move || {
        let (target, tls, options) = (target.clone(), tls.clone(), options.clone());
        async move {
            let request = target
                .url()
                .into_client_request()
                .map_err(io::Error::other)?;
            let dialed = dial_following(request, Some(&tls), &options).await;
            match &dialed {
                Ok((_, last)) => target.redirected(&last.to_string()),
                Err(_) => target.reset(),
            }
            dialed.map(|(io, _)| io)
        }
    })
    .with_target(named)
}

#[cfg(test)]
mod tests {
    use super::Options;

    fn offer(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The server's order of preference decides, and the identifier as it
    /// is wins over its alias.
    #[test]
    fn the_server_selects_in_its_own_order() {
        let o = Options::for_protocol("app-02").with_protocol("qmux-02");
        assert_eq!(
            o.select(&offer(&["qmux-02", "app-02"])).as_deref(),
            Some("app-02")
        );
        assert_eq!(
            o.select(&offer(&["qmux-02", "app-01"])).as_deref(),
            Some("app-01")
        );
        assert_eq!(
            o.select(&offer(&["app-01", "app-02"])).as_deref(),
            Some("app-02")
        );
        assert_eq!(o.select(&offer(&["qmux-01"])).as_deref(), Some("qmux-01"));
        assert_eq!(o.select(&offer(&["qmux-00", "other"])), None);
    }
}
