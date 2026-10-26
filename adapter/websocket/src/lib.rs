//! WebSocket pipe carriers for zmux over tokio-tungstenite.
//!
//! A WebSocket carries zmux records with message framing (SPEC.md Section
//! 3.4, [`zmux::PipeIo::records`]): every binary message is one record's
//! Frames field, without the Size, byte-compatible with other QMux
//! implementations over WebSocket. A message never splits a record and a
//! record never spans messages, so intermediaries that re-chunk the byte
//! stream (proxies, CDNs) cannot break the framing.
//!
//! - [`connect`] and [`dial`] open a WebSocket to a URL and make a session
//!   or a carrier of it; [`serve`] accepts WebSocket upgrades on a TCP
//!   listener for a [`zmux::Listener`], and [`accept`] upgrades one
//!   connection inside the application's own server.
//! - The subprotocol (`Sec-WebSocket-Protocol`) is the ALPN identifier, as
//!   with TLS ([`Options`]): `qmux-02` or `qmux-02.<application>`, or an
//!   application's own identifier (such as `moq-transport-18`, whose
//!   specification then names the QMux version). A client offers its
//!   identifiers and their draft-01 aliases unless the request names its
//!   own, a server selects the first offered one it accepts, and the
//!   negotiated one is the session's protocol.
//! - An empty message is a record without frames, a no-op that the
//!   session counts like a record of PADDING only; zmux never sends one.
//! - A server accepts a client whose offered subprotocols include none it
//!   accepts, or that offers none, as other QMux implementations may not
//!   offer one: it answers without a subprotocol and the session has no
//!   negotiated protocol. The handshake that follows still has to succeed,
//!   so this admits nothing a client could not reach by offering the
//!   default identifier.
//! - The `Zmux-Pipe-Join` request header ([`zmux::JOIN_HEADER`]) carries an
//!   out-of-band join (MULTIPATH.md Section 5.3): [`serve`] and [`accept`]
//!   hand it to the listener.
//! - Closing the sending half sends a Close frame, the graceful end; a pipe
//!   that zmux fails over a plain TCP connection is aborted by shutting the
//!   socket down without a Close frame, so that the peer sees a failure. A
//!   connection that ends without a Close frame is a carrier error, never a
//!   clean end. Text messages are a protocol error of the carrier.
//!
//! - `wss://`: [`dial_tls`] and [`connect_tls`] with the application's
//!   `tokio_rustls::TlsConnector`, or [`dial_over`] on a TLS stream the
//!   application established; [`dial`] and [`connect`] are for `ws://`.
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
//! let listener = Listener::new(Config::default(), ListenerConfig::default());
//! let tcp = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
//! tokio::spawn(zmux_websocket::serve(listener.clone(), tcp, Default::default()));
//! while let Some(session) = listener.accept().await {
//!     // ...
//! #   drop(session);
//! }
//! # Ok(())
//! # }
//! ```

use std::io::{self, IoSlice};
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::{
    Request as ClientRequest, Response as ClientResponse,
};
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{Bytes, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use zmux::{ConnectError, Listener, PipeHint, PipeIo, Session};

const PROTOCOL_HEADER: &str = "Sec-WebSocket-Protocol";

/// A pipe carrier from an established WebSocket, client or server:
/// message framing, the subprotocol `protocol` as the session's protocol.
/// Without an abort (see [`dial`] for plain TCP) a failed pipe ends with a
/// Close frame.
pub fn pipe<S>(ws: WebSocketStream<S>, protocol: Option<String>) -> PipeIo
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, stream) = ws.split();
    let io = PipeIo::from_halves(
        Reader { stream },
        Writer {
            sink,
            started: None,
        },
    )
    .records();
    match protocol {
        Some(p) => io.with_protocol(p),
        None => io,
    }
}

/// A carrier over a new WebSocket to `request` (a `ws://` URL, or a request
/// with headers such as [`zmux::JOIN_HEADER`]): the subprotocols default to
/// [`zmux::alpn_protocols`]. Over plain TCP, a pipe that zmux fails is
/// aborted without a Close frame.
pub async fn dial(
    request: impl IntoClientRequest + Unpin,
    options: &Options,
) -> io::Result<PipeIo> {
    let request = offer(request, options)?;
    let (ws, response) =
        tokio_tungstenite::connect_async_with_config(request, Some(ws_config()), true)
            .await
            .map_err(io::Error::other)?;
    let protocol = negotiated(&response);
    let socket = match ws.get_ref() {
        MaybeTlsStream::Plain(tcp) => {
            let _ = tcp.set_nodelay(true);
            tcp_dup(tcp)
        }
        #[allow(unreachable_patterns)]
        _ => None,
    };
    Ok(with_socket(pipe(ws, protocol), socket))
}

/// A carrier over a new WebSocket on `io`, an established byte stream such
/// as a TLS stream: the client handshake for `request` (a `ws://` or
/// `wss://` URL, or a request with headers), the subprotocols as in
/// [`dial`]. Give the carrier the TCP socket underneath
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
    let request = offer(request, options)?;
    let (ws, response) =
        tokio_tungstenite::client_async_with_config(request, io, Some(ws_config()))
            .await
            .map_err(io::Error::other)?;
    Ok(pipe(ws, negotiated(&response)))
}

/// A carrier over a new WebSocket over TLS to a `wss://` `request`: TCP to
/// the URL's host and port (443 by default), TLS with `tls` for the host's
/// name (the application's client configuration chooses roots, ALPN and
/// early data, as with the other adapters), then [`dial_over`]. A pipe
/// that zmux fails is aborted without a Close frame.
pub async fn dial_tls(
    request: impl IntoClientRequest + Unpin,
    tls: &tokio_rustls::TlsConnector,
    options: &Options,
) -> io::Result<PipeIo> {
    let request = request.into_client_request().map_err(io::Error::other)?;
    let uri = request.uri();
    let host = uri
        .host()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL without a host"))?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = uri.port_u16().unwrap_or(443);
    let name = ServerName::try_from(host.clone())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let tcp = TcpStream::connect((host.as_str(), port)).await?;
    let _ = tcp.set_nodelay(true);
    let socket = tcp_dup(&tcp);
    let conn = tls.connect(name, tcp).await?;
    Ok(with_socket(
        dial_over(conn, request, options).await?,
        socket,
    ))
}

/// Establishes a session over a new WebSocket over TLS ([`dial_tls`], then
/// [`zmux::Session::connect`]).
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

/// The request with the offered subprotocols unless it names its own.
fn offer(request: impl IntoClientRequest + Unpin, options: &Options) -> io::Result<ClientRequest> {
    let mut request = request.into_client_request().map_err(io::Error::other)?;
    if !request.headers().contains_key(PROTOCOL_HEADER) {
        let offer = options.offer().join(", ");
        let value = HeaderValue::from_str(&offer).map_err(io::Error::other)?;
        request.headers_mut().insert(PROTOCOL_HEADER, value);
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
/// [`zmux::Session::connect`]).
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

/// Upgrades one accepted connection, any byte stream such as a TLS
/// stream, to a WebSocket carrier (messages of at most one record): the
/// subprotocol is the first the client offers that `options` accepts (an
/// identifier of it or its draft-01 alias; none when the client offers
/// none of them, which is accepted), and the hint carries `peer`
/// (the client's address) and the [`zmux::JOIN_HEADER`] of the request,
/// for [`Listener::handle_pipe`]. Over TLS, give the carrier the TCP
/// socket underneath ([`PipeIo::with_tcp_socket`]) so that a failed pipe is
/// aborted without a Close frame.
///
/// ```no_run
/// # async fn example(listener: zmux::Listener, tcp: tokio::net::TcpListener,
/// #     tls: tokio_rustls::TlsAcceptor) {
/// // wss://: TLS, then the upgrade, within the listener's limits.
/// listener
///     .serve_with(
///         || tcp.accept(),
///         move |conn, peer| {
///             let tls = tls.clone();
///             async move {
///                 let conn = tls.accept(conn).await?;
///                 zmux_websocket::accept(conn, Some(peer.ip()), &Default::default()).await
///             }
///         },
///     )
///     .await;
/// # }
/// ```
// The handshake callback's error type is tungstenite's.
#[allow(clippy::result_large_err)]
pub async fn accept<S>(
    io: S,
    peer: Option<IpAddr>,
    options: &Options,
) -> io::Result<(PipeIo, PipeHint)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut chosen = None;
    let mut join = None;
    let ws = tokio_tungstenite::accept_hdr_async_with_config(
        io,
        |req: &Request, mut resp: Response| {
            handshake(options, req, &mut resp, &mut chosen, &mut join);
            Ok(resp)
        },
        Some(ws_config()),
    )
    .await
    .map_err(io::Error::other)?;
    let mut hint = peer.map(PipeHint::from_addr).unwrap_or_default();
    if let Some(j) = &join {
        hint = hint.with_join_header(j);
    }
    Ok((pipe(ws, chosen), hint))
}

/// [`accept`] on a TCP connection, which also aborts a failed pipe.
async fn accept_tcp(
    tcp: TcpStream,
    peer: SocketAddr,
    options: Arc<Options>,
) -> io::Result<(PipeIo, PipeHint)> {
    let _ = tcp.set_nodelay(true);
    let socket = tcp_dup(&tcp);
    let (io, hint) = accept(tcp, Some(peer.ip()), &options).await?;
    #[cfg(any(unix, windows))]
    if let Some(s) = socket {
        return Ok((io.with_tcp_socket(&s), hint));
    }
    #[cfg(not(any(unix, windows)))]
    let _ = socket;
    Ok((io, hint))
}

/// The server side of the upgrade: the subprotocol and the join header.
fn handshake(
    options: &Options,
    req: &Request,
    resp: &mut Response,
    chosen: &mut Option<String>,
    join: &mut Option<String>,
) {
    let offered = req
        .headers()
        .get_all(PROTOCOL_HEADER)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim);
    for o in offered {
        if options.accepts(o) {
            if let Ok(v) = HeaderValue::from_str(o) {
                resp.headers_mut().insert(PROTOCOL_HEADER, v);
                *chosen = Some(o.to_owned());
            }
            break;
        }
    }
    *join = req
        .headers()
        .get(zmux::JOIN_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
}

/// Serves WebSocket upgrades on a TCP listener until `listener` is
/// closed ([`Listener::serve_with`]): each connection's upgrade runs in a
/// task of its own within the listener's `handshake_timeout`, and its
/// carrier goes to [`Listener::handle_pipe`] (new sessions to
/// [`Listener::accept`]).
pub async fn serve(listener: Listener, tcp: TcpListener, options: Options) {
    let options = Arc::new(options);
    listener
        .serve_with(
            || tcp.accept(),
            |conn, peer| accept_tcp(conn, peer, options.clone()),
        )
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
}

impl Default for Options {
    /// `qmux-02`, with its alias `qmux-01`.
    fn default() -> Self {
        Self {
            protocols: vec![String::from_utf8_lossy(zmux::proto::ident::DEFAULT_ALPN).into_owned()],
        }
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
        }
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

    /// Whether an offered identifier is one of these or an alias of one.
    fn accepts(&self, offered: &str) -> bool {
        self.protocols
            .iter()
            .any(|p| zmux::proto::ident::alpn_matches(p.as_bytes(), offered.as_bytes()))
    }
}

/// The message limits: one byte more than the largest record's Frames
/// field, so that a peer cannot make the stack buffer much more than a
/// record before the carrier sees it, and a message above the session's
/// `max_record_size` reaches it as the record above the limit that it is
/// (FRAME_ENCODING_ERROR) rather than as a carrier failure. The session's
/// read buffer holds every message this lets through.
fn ws_config() -> WebSocketConfig {
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
                // An empty message is an empty record, which the session
                // charges like a record of PADDING only (a read of nothing
                // would be the end).
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

/// The sending half: one binary message per write, flushed before the write
/// returns.
struct Writer<S> {
    sink: SplitSink<WebSocketStream<S>, Message>,
    /// The length of the message handed to the sink and not yet flushed.
    started: Option<usize>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> Writer<S> {
    fn poll_message(
        &mut self,
        cx: &mut Context<'_>,
        make: impl FnOnce() -> Bytes,
    ) -> Poll<io::Result<usize>> {
        let err = |e| io::Error::new(io::ErrorKind::ConnectionReset, e);
        if self.started.is_none() {
            ready!(Pin::new(&mut self.sink).poll_ready(cx)).map_err(err)?;
            let msg = make();
            let n = msg.len();
            Pin::new(&mut self.sink)
                .start_send(Message::Binary(msg))
                .map_err(err)?;
            self.started = Some(n);
        }
        ready!(Pin::new(&mut self.sink).poll_flush(cx)).map_err(err)?;
        Poll::Ready(Ok(self.started.take().unwrap_or(0)))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Writer<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .poll_message(cx, || Bytes::copy_from_slice(buf))
    }

    /// The slices as one message.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_message(cx, || {
            let mut v = Vec::with_capacity(bufs.iter().map(|b| b.len()).sum());
            for b in bufs {
                v.extend_from_slice(b);
            }
            Bytes::from(v)
        })
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.sink)
            .poll_flush(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e))
    }

    /// Sends a Close frame: the graceful end.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.sink)
            .poll_close(cx)
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionReset, e))
    }
}
