//! WebTransport sessions as zmux carriers over web-transport-quinn: zmux
//! sessions whose pipes are bidirectional streams of a
//! WebTransport session and whose lanes are its unidirectional streams, in
//! both directions (MULTIPATH.md Sections 2.5 and 5.8). WebTransport runs
//! over HTTP/3, so a carrier reaches a server through HTTP/3 front ends and
//! load balancers that forward WebTransport, where a plain QUIC carrier may
//! not; the session's own features (datagrams, statistics, close) and the
//! QUIC connection under it stay the application's
//! ([`WebTransportCarrier::session`]).
//!
//! One step from a client to a zmux session, and from a server to the
//! sessions it accepts: [`connect`] and [`serve`]; with
//! [`ListenerConfig::admission`](zmux::ListenerConfig::admission), [`serve`] decides on each session request before
//! it answers it ([`admit`]), on the request head: a client's credential
//! travels in a request header field ([`Options::with_credential`]), such
//! as a prefix authentication token in `Zmux-Prefix-Auth`, bound to the
//! QUIC connection with [`dial_over`]. The QUIC endpoints carry the HTTP/3
//! ALPN identifier `h3` ([`web_transport_quinn::ALPN`]), which names the
//! HTTP layer; zmux's own identifiers do not apply. Build their transport
//! configuration with [`Options::transport_config`], so that the stream
//! window has one source.
//!
//! A [`WebTransportCarrier`] takes a whole established session: a pipe is
//! one bidirectional stream of it ([`WebTransportCarrier::open_pipe`],
//! [`WebTransportCarrier::accept_pipe`]), and the pipe's lanes are further
//! unidirectional streams, which zmux opens itself as it needs them. The
//! carrier runs the session's accept loop: every stream the peer opens is a
//! carrier, handed to the [`Listener`] given, or else a lane to
//! [`zmux::carrier::handle_lane`] and a pipe to [`WebTransportCarrier::accept_pipe`];
//! zmux routes lanes by their Lane Key and checks that they are on the
//! session of their pipe, whose identity is the carrier. One WebTransport
//! session owns its QUIC connection, so the session's streams belong to
//! zmux.
//!
//! What the session gives zmux:
//!
//! - its datagrams, as the datagram channel of its stream pipes
//!   (EXTENSIONS.md Section 6.8): a zmux session with datagrams enabled
//!   sends each datagram that fits one there rather than in a record when
//!   the peer negotiated it. Each WebTransport datagram starts with the
//!   pipe's QUIC stream ID; one receive loop per WebTransport session
//!   routes them to its pipes ([`WebTransportCarrier::channel_dropped`]
//!   counts those that named none), so the session's datagrams belong to
//!   zmux;
//! - the TLS 1.3 exporter of its QUIC connection (RFC 9001 Section 4), for
//!   [`zmux::PipeAuth::tls`] and carrier-bound joins (MULTIPATH.md Section
//!   10.5); behind an HTTP/3 front end that terminates TLS the two ends
//!   export different values, so such deployments use a PSK (MULTIPATH.md);
//! - flow control sized for its lanes: the peer may open [`LaneWindows::lanes`] lanes at once (beside
//!   the HTTP/3 control streams), and the connection's receive window
//!   covers that many stream windows and a pipe's own, charged to the
//!   memory budget for as long as the carrier lives: the listener's
//!   ([`WebTransportCarrier::with_listener`]), or else the zmux session's
//!   own.
//!
//! A stream's sending part that zmux drops without ending it gracefully
//! (a failed pipe or lane) is reset, and a receiving part dropped before
//! its end is stopped, with `ZMUX_CARRIER_FAILED`, so that the peer sees a
//! failure rather than a graceful end; a session or connection that ends
//! under the pipes is a failure of the pipes. Streams report no unsent
//! count to zmux: the carrier queue limiter paces them.
//!
//! ```no_run
//! # async fn example(client: web_transport_quinn::Client) -> Result<(), Box<dyn std::error::Error>> {
//! use zmux::{Config, PipeAuth};
//! use zmux_webtransport::Options;
//!
//! let url: zmux_webtransport::Url = "https://example.com/zmux".parse()?;
//! let mut config = Config::default();
//! config.pipe_auth = PipeAuth::tls();
//! let session = zmux_webtransport::connect(&client, url, &Options::default(), config).await?;
//! # drop(session);
//! # Ok(())
//! # }
//! ```

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io;
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::task::{Context, Poll};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
pub use url::Url;
pub use web_transport_quinn;
use web_transport_quinn::proto::ConnectRequest;
use web_transport_quinn::quinn::{self, VarInt};
use web_transport_quinn::{self as wt, Session};
use zmux::carrier::{
    CarrierConnId, ChannelDemux, ChannelReceiver, ChannelRegistration, ChunkWrite, DatagramChannel,
    MemoryCharge,
};
use zmux::proto::ApplicationErrorCode;
use zmux::proto::keys::{EXPORTER_PIPE_LABEL, EXPORTER_SESSION_LABEL};
use zmux::{
    Admit, Admitted, CarrierInfo, ConnectError, Credential, Entry, Listener, PipeHint, PipeIo,
};
pub use zmux_quinn::LaneWindows;

/// The unidirectional streams an HTTP/3 endpoint keeps open on its own
/// (control, QPACK encoder and decoder).
const H3_UNI_STREAMS: u32 = 3;

/// The adapter's options: how the carrier sizes the connection's flow
/// control for lanes, the fallback of session requests, and a client's
/// credential.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Options {
    /// The windows; [`LaneWindows::lanes`] is the lanes the peer may open
    /// on the session at once.
    pub windows: LaneWindows,
    /// Server: the handler of the session requests the listener's
    /// admission hands to the fallback or that are not upgraded (none by default: such
    /// requests are answered with 404).
    pub fallback: Option<WebTransportFallback>,
    /// Client: the credential whose header field
    /// ([`Credential::header`]) goes on each session request (none by
    /// default).
    pub credential: Option<Arc<dyn Credential>>,
}

impl Options {
    /// The defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// With these windows.
    #[must_use]
    pub fn with_windows(mut self, windows: LaneWindows) -> Self {
        self.windows = windows;
        self
    }

    /// Client: with `credential`, presented in a header field of each
    /// session request.
    #[must_use]
    pub fn with_credential(mut self, credential: Arc<dyn Credential>) -> Self {
        self.credential = Some(credential);
        self
    }

    /// Serves the session requests that are not accepted with `fallback`.
    #[must_use]
    pub fn with_fallback(mut self, fallback: WebTransportFallback) -> Self {
        self.fallback = Some(fallback);
        self
    }

    /// quinn's transport configuration for these options: the stream
    /// receive window, the connection window for the lanes and the
    /// unidirectional streams the peer may open (the lanes and HTTP/3's
    /// own); the rest quinn's defaults. Build the endpoints' client and
    /// server configurations with it.
    pub fn transport_config(&self) -> quinn::TransportConfig {
        let mut t = self.windows.transport_config();
        t.max_concurrent_uni_streams(VarInt::from_u32(
            self.windows.lanes.saturating_add(H3_UNI_STREAMS),
        ));
        t
    }
}

/// A carrier over a new WebTransport session of `client` to `request` (its
/// URL): a stream of the session, which carries the pipe's lanes and stays
/// open while the pipe is used. For [`zmux::helpers::PipePool`] and
/// [`zmux::Session::add_pipe`]; to reach the WebTransport session itself,
/// make it and its carrier ([`WebTransportCarrier::new`]) instead. The
/// header field of [`Options::credential`] goes on the request, the
/// credential given no exporter (the client makes the QUIC connection and
/// sends the request in one step): a bound one needs [`dial_over`].
pub async fn dial(
    client: &wt::Client,
    request: impl Into<ConnectRequest>,
    options: &Options,
) -> io::Result<PipeIo> {
    let request = credential_header(request.into(), options, &CarrierInfo::new())?;
    let session = client.connect(request).await.map_err(io::Error::other)?;
    WebTransportCarrier::new(session, options.clone())
        .open_pipe()
        .await
}

/// [`dial`] on `conn`, an established QUIC connection with the ALPN
/// identifier `h3` and nothing else on it: the credential is given the
/// connection's metadata ([`zmux_quinn::Handshake::carrier_info`]), its
/// exporter for a bound one among them.
pub async fn dial_over(
    conn: quinn::Connection,
    request: impl Into<ConnectRequest>,
    options: &Options,
) -> io::Result<PipeIo> {
    let handshake = zmux_quinn::Handshake::of(&conn);
    let request = credential_header(request.into(), options, &handshake.carrier_info(&conn))?;
    let session = Session::connect(conn, request)
        .await
        .map_err(io::Error::other)?;
    WebTransportCarrier::new(session, options.clone())
        .open_pipe()
        .await
}

/// `request` with the header field of [`Options::credential`] for a
/// carrier with metadata `info`.
fn credential_header(
    mut request: ConnectRequest,
    options: &Options,
    info: &CarrierInfo<'_>,
) -> io::Result<ConnectRequest> {
    if let Some(c) = &options.credential {
        let (name, value) = c.header(info)?;
        let invalid = |e| io::Error::new(io::ErrorKind::InvalidInput, e);
        let name = wt::http::HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| invalid(e.to_string()))?;
        let value = wt::http::HeaderValue::from_str(&value).map_err(|e| invalid(e.to_string()))?;
        request.headers.insert(name, value);
    }
    Ok(request)
}

/// Establishes a zmux session over a new WebTransport session ([`dial`],
/// then [`zmux::Session::connect`]).
pub async fn connect(
    client: &wt::Client,
    request: impl Into<ConnectRequest>,
    options: &Options,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<zmux::Session, ConnectError> {
    let pipe = dial(client, request, options)
        .await
        .map_err(|e| ConnectError::Io(Arc::new(e)))?;
    zmux::Session::connect(pipe, config).await
}

/// Serves the WebTransport sessions of the QUIC connections `endpoint`
/// (with the ALPN `h3`, as a `web_transport_quinn::Server` would have it)
/// accepts until `listener` is closed or the endpoint is: each connection
/// takes its source slot ([`Listener::enter`]) before its QUIC handshake,
/// and the handshake and the arrival of its session request run within
/// the listener's limits ([`Listener::serve_connections`]; one that fails
/// or misses them counts as a failed handshake); the request is then
/// decided by [`admit`]. An application that routes by URL accepts the
/// requests itself and passes them to [`admit`].
///
/// The handshake is awaited in full: no request is taken from early data.
/// With an admission, the endpoint's server configuration should refuse
/// early data (rustls `max_early_data_size` 0).
pub async fn serve(listener: Listener, endpoint: quinn::Endpoint, options: Options) {
    let l = listener.clone();
    let endpoint = &endpoint;
    l.serve_connections(
        move || async move { endpoint.accept().await.map(Ok) },
        move |incoming: quinn::Incoming| {
            let entry = listener.enter(incoming.remote_address(), None);
            async move {
                let entry = entry.ok_or(())?;
                let conn = incoming.await.map_err(drop)?;
                let request = wt::Request::accept(conn).await.map_err(drop)?;
                Ok::<_, ()>((request, entry))
            }
        },
        move |listener, (request, entry): (wt::Request, Entry)| {
            let options = options.clone();
            async move { admit(request, entry, &listener, &options).await }
        },
    )
    .await;
}

/// Decides on a session request by the listener's admission
/// ([`zmux::ListenerConfig::admission`]) and serves it until it ends;
/// `entry` is the connection's entry into the listener
/// ([`Listener::enter`], taken before its QUIC handshake). Nothing is
/// answered before the decision. The decision has no prefix; its metadata
/// is the connection's ([`zmux_quinn::Handshake::carrier_info`]), with the
/// request ([`ConnectRequest`] as the [`CarrierInfo::with_request`]
/// value, its header fields as [`CarrierInfo::for_each_header`] gives
/// them) and [`CarrierInfo::head`] set, so that
/// [`zmux::Admission::prefix_auth`] takes its token from the request
/// header field; behind an intermediary the listener trusts, the source is
/// the client it reports in a forwarding header field
/// ([`Entry::set_source`]). Then:
///
/// - `Accept`: 200 OK, and the session is a [`WebTransportCarrier`] of
///   `listener` for as long as it is open, its streams admitted with it;
/// - `Fallback`:
///   [`Options::fallback`] is given the request, or it is answered with
///   404 without one;
/// - `Stall`: nothing is answered; once a stall's duration has passed, or
///   the connection closed, the request is ended without a response and
///   the connection closed;
/// - `Close`: the connection is closed at once.
///
/// Without an admission, every request is accepted. A request that an
/// intermediary forwarded from TLS early data (`Early-Data: 1`) is
/// answered `425 (Too Early)` before any admission, and no carrier is
/// taken from it.
pub async fn admit(request: wt::Request, mut entry: Entry, listener: &Listener, options: &Options) {
    let connect: &ConnectRequest = &request;
    if zmux::forwarded_early_data(
        connect
            .headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_bytes())),
    ) {
        refuse(request, wt::http::StatusCode::TOO_EARLY, listener).await;
        return;
    }
    let source = source_of(request.conn().remote_address(), Some(connect), listener);
    if !entry.set_source(source) {
        request.conn().close(VarInt::from_u32(0), b"");
        return;
    }
    let decided = {
        let conn = request.conn();
        let handshake = zmux_quinn::Handshake::of(conn);
        let connect: &ConnectRequest = &request;
        let headers = &connect.headers;
        let info = handshake
            .carrier_info(conn)
            .with_head()
            .with_request(connect)
            .with_headers(|| headers.iter().map(|(n, v)| (n.as_str(), v.as_bytes())));
        entry.decide(info, Vec::new()).await
    };
    let conn = request.conn().clone();
    match decided {
        Admit::Accept(_) => {
            let admitted = listener.admission().and(entry.admitted());
            drop(entry);
            let Ok(session) = request.ok().await else {
                return;
            };
            let carrier = WebTransportCarrier::start(
                session.clone(),
                Some(listener.clone()),
                options.clone(),
                admitted,
            );
            // Held while the session is open: its accept loop serves it.
            session.closed().await;
            drop(carrier);
        }
        Admit::Fallback(_) => {
            drop(entry);
            match &options.fallback {
                Some(f) => f.serve(request).await,
                None => refuse(request, wt::http::StatusCode::NOT_FOUND, listener).await,
            }
        }
        Admit::Stall => {
            let mut closed = pin!(conn.closed());
            let mut stall = pin!(entry.stall(None::<&mut tokio::io::Empty>));
            poll_fn(|cx| {
                if closed.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(());
                }
                stall.as_mut().poll(cx)
            })
            .await;
            drop(request);
            conn.close(VarInt::from_u32(0), b"");
        }
        _ => conn.close(VarInt::from_u32(0), b""),
    }
}

/// The source of a WebTransport session a server accepted: the client a
/// trusted intermediary reports in a forwarding header field of its
/// session request ([`zmux::TrustedProxies::source`]), else the
/// connection's peer.
fn session_source(session: &Session, listener: &Listener) -> std::net::SocketAddr {
    source_of(session.remote_address(), session.request(), listener)
}

fn source_of(
    peer: std::net::SocketAddr,
    request: Option<&ConnectRequest>,
    listener: &Listener,
) -> std::net::SocketAddr {
    match request {
        Some(r) => listener.trusted_proxies().source(
            peer,
            r.headers.iter().map(|(n, v)| (n.as_str(), v.as_bytes())),
        ),
        None => peer,
    }
}

/// Answers `request` with `status` and keeps its connection until the
/// client closes it, at most the listener's `handshake_timeout`: QUIC
/// closes a connection whose last handle is dropped and discards the data
/// still in flight, the answer with it.
async fn refuse(request: wt::Request, status: wt::http::StatusCode, listener: &Listener) {
    let conn = request.conn().clone();
    if request.reject(status).await.is_ok() {
        let _ = tokio::time::timeout(listener.limits().handshake_timeout, conn.closed()).await;
    }
}

type FallbackFn = dyn Fn(wt::Request) -> Pin<Box<dyn Future<Output = ()> + std::marker::Send>>
    + std::marker::Send
    + Sync;

/// The handler of the session requests that are not accepted
/// ([`Options::fallback`]), given the request, not answered yet. Cheap to
/// clone.
#[derive(Clone)]
pub struct WebTransportFallback(Arc<FallbackFn>);

impl std::fmt::Debug for WebTransportFallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WebTransportFallback(..)")
    }
}

impl WebTransportFallback {
    /// The handler `f`.
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(wt::Request) -> Fut + std::marker::Send + Sync + 'static,
        Fut: Future<Output = ()> + std::marker::Send + 'static,
    {
        Self(Arc::new(move |r| Box::pin(f(r))))
    }

    /// Serves `request`.
    pub async fn serve(&self, request: wt::Request) {
        let handler = &self.0;
        handler(request).await;
    }
}

/// A WebTransport session whose streams carry zmux pipes and lanes (see
/// the crate documentation). Cheap to clone; the accept loop runs while the
/// session is open and any clone, or any pipe made from it, is alive.
/// Once none is, the loop stops and the carrier's hold on the connection
/// ends: keep a clone while the peer may still open pipes on it.
#[derive(Clone)]
#[must_use = "the accept loop stops once the carrier and its pipes are gone"]
pub struct WebTransportCarrier {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for WebTransportCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebTransportCarrier")
            .field("connection", &self.inner.conn.stable_id())
            .finish()
    }
}

struct Inner {
    conn: Session,
    /// The session's identity for zmux: this state's allocation.
    id: OnceLock<CarrierConnId>,
    /// The receive window charged to the sessions its pipes carry, without
    /// a listener (0 with one, which is charged instead).
    own_charge: u64,
    exported: [Option<Vec<u8>>; 2],
    /// Streams of pipes the peer opened, without a listener (made pipes
    /// when taken, so that the queue holds no reference to this state).
    accepted: Mutex<Accepted>,
    notify: Notify,
    /// Stops the accept loop when the last handle is gone.
    accept_task: OnceLock<tokio::task::AbortHandle>,
    _charge: Option<MemoryCharge>,
    /// The session's datagrams, the channels of its pipes.
    datagrams: Arc<Datagrams>,
}

#[derive(Default)]
struct Accepted {
    pipes: VecDeque<(Send, Recv)>,
    closed: bool,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(t) = self.accept_task.get() {
            t.abort();
        }
    }
}

impl WebTransportCarrier {
    /// The carrier of `session`, an established WebTransport session,
    /// without a listener; its accept loop starts here (inside a tokio
    /// runtime). The peer's pipes go to
    /// [`WebTransportCarrier::accept_pipe`], and the connection's receive
    /// window is charged to the zmux session its pipes carry. Make one
    /// carrier per session: its lanes are recognised by it.
    pub fn new(session: Session, options: Options) -> Self {
        Self::start(session, None, options, None)
    }

    /// The carrier of `session` for `listener`: every stream the peer
    /// opens goes to [`Listener::handle_pipe`], and the connection's
    /// receive window is charged to the listener's budget while the
    /// carrier lives.
    pub fn with_listener(session: Session, listener: &Listener, options: Options) -> Self {
        Self::start(session, Some(listener.clone()), options, None)
    }

    fn start(
        conn: Session,
        listener: Option<Listener>,
        options: Options,
        admitted: Option<Admitted>,
    ) -> Self {
        let window = options.windows.receive_window();
        conn.set_receive_window(VarInt::from_u64(window).unwrap_or(VarInt::MAX));
        // The HTTP/3 control and QPACK streams stay open beside the lanes.
        conn.set_max_concurrent_uni_streams(VarInt::from_u32(
            options.windows.lanes.saturating_add(H3_UNI_STREAMS),
        ));
        let export = |label: &str| {
            let mut out = vec![0u8; 32];
            conn.export_keying_material(&mut out, label.as_bytes(), b"")
                .ok()
                .map(|()| out)
        };
        let exported = [export(EXPORTER_SESSION_LABEL), export(EXPORTER_PIPE_LABEL)];
        let own_charge = if listener.is_some() { 0 } else { window };
        let inner = Arc::new(Inner {
            conn: conn.clone(),
            id: OnceLock::new(),
            own_charge,
            exported,
            accepted: Mutex::default(),
            notify: Notify::new(),
            accept_task: OnceLock::new(),
            _charge: listener.as_ref().map(|l| l.charge_memory(window)),
            datagrams: Arc::new(Datagrams {
                session: conn.clone(),
                demux: ChannelDemux::new(),
                receiving: OnceLock::new(),
            }),
        });
        let _ = inner.id.set(CarrierConnId::new(&inner));
        let source = listener.as_ref().map(|l| session_source(&conn, l));
        let task = tokio::spawn(accept_loop(
            conn,
            Arc::downgrade(&inner),
            listener,
            source,
            admitted,
        ));
        let _ = inner.accept_task.set(task.abort_handle());
        Self { inner }
    }

    /// The WebTransport session, for its own features (statistics,
    /// close) and, through it, the QUIC connection. Its streams and
    /// datagrams belong to zmux.
    pub fn session(&self) -> &Session {
        &self.inner.conn
    }

    /// The session's datagrams received that named no pipe attached to a
    /// zmux session (an unknown, not yet attached or closed one).
    pub fn channel_dropped(&self) -> u64 {
        self.inner.datagrams.demux.dropped()
    }

    /// A new pipe on a bidirectional stream of the session: the
    /// bootstrap carrier of a session this endpoint starts, or a pipe it
    /// joins. Waits for the peer's stream credit.
    pub async fn open_pipe(&self) -> io::Result<PipeIo> {
        let (send, recv) = self.inner.conn.open_bi().await.map_err(io::Error::other)?;
        Ok(self.inner.pipe(Send::new(send), Recv::new(recv)))
    }

    /// The next pipe the peer opened, on a carrier without a listener (for
    /// [`zmux::Session::accept`]); `None` once the connection is closed.
    /// With a listener, the listener takes them. Pipes nobody takes wait,
    /// as many as the connection lets the peer open bidirectional streams
    /// (QUIC MAX_STREAMS).
    pub async fn accept_pipe(&self) -> Option<PipeIo> {
        let inner = &self.inner;
        loop {
            let notified = inner.notify.notified();
            let mut notified = pin!(notified);
            notified.as_mut().enable();
            {
                let mut a = inner.accepted();
                if let Some((send, recv)) = a.pipes.pop_front() {
                    return Some(inner.pipe(send, recv));
                }
                if a.closed {
                    return None;
                }
            }
            notified.await;
        }
    }
}

impl Inner {
    fn accepted(&self) -> std::sync::MutexGuard<'_, Accepted> {
        self.accepted.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn id(&self) -> CarrierConnId {
        self.id.get().expect("set at creation").clone()
    }

    /// A pipe carrier on a bidirectional stream, with the connection's
    /// identity, lane opener and exporter. Its streams and lanes keep this
    /// state (and so the accept loop) alive.
    fn pipe(self: &Arc<Self>, mut send: Send, mut recv: Recv) -> PipeIo {
        send.keep = Some(self.clone());
        recv.keep = Some(self.clone());
        let opener = self.clone();
        let exported = self.exported.clone();
        let channel = Arc::new(WtChannel {
            datagrams: self.datagrams.clone(),
            id: recv.stream.quic_id().into(),
        });
        let io = PipeIo::from_chunk_halves(recv, send)
            .with_carrier(zmux::CarrierKind::WebTransport)
            .with_carrier_conn(self.id())
            .with_connection_memory(self.own_charge)
            .with_datagram_channel(channel);
        io.with_chunk_lane_opener(move || {
            let inner = opener.clone();
            async move {
                let send = inner.conn.open_uni().await.map_err(io::Error::other)?;
                let mut send = Send::new(send);
                send.keep = Some(inner);
                Ok(send)
            }
        })
        .with_tls_exporter(|label| match label {
            EXPORTER_SESSION_LABEL => exported[0].clone(),
            EXPORTER_PIPE_LABEL => exported[1].clone(),
            _ => None,
        })
    }
}

/// The datagrams of a WebTransport session as the datagram channels of its
/// pipes: each starts with the pipe's QUIC stream ID. The receive loop
/// starts with the first pipe that receives, and stops with this state.
struct Datagrams {
    session: Session,
    demux: ChannelDemux,
    receiving: OnceLock<tokio::task::AbortHandle>,
}

impl Drop for Datagrams {
    fn drop(&mut self) {
        if let Some(t) = self.receiving.get() {
            t.abort();
        }
    }
}

/// The datagram channel of one pipe of a WebTransport session.
struct WtChannel {
    datagrams: Arc<Datagrams>,
    id: u64,
}

impl DatagramChannel for WtChannel {
    fn channel_id(&self) -> Option<u64> {
        Some(self.id)
    }

    fn max_datagram_size(&self) -> usize {
        self.datagrams.session.max_datagram_size()
    }

    fn send(
        &self,
        datagram: Bytes,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + std::marker::Send + '_>> {
        Box::pin(async move {
            self.datagrams
                .session
                .send_datagram_wait(datagram)
                .await
                .map_err(io::Error::other)
        })
    }

    fn receive(&self, receiver: ChannelReceiver) -> ChannelRegistration {
        let d = &self.datagrams;
        let r = d.demux.register(self.id, receiver);
        d.receiving.get_or_init(|| {
            let (session, demux) = (d.session.clone(), d.demux.clone());
            tokio::spawn(async move {
                while let Ok(b) = session.read_datagram().await {
                    demux.deliver(b);
                }
            })
            .abort_handle()
        });
        r
    }
}

/// Hands every stream the peer opens to zmux until the session closes or
/// the carrier is gone.
async fn accept_loop(
    conn: Session,
    inner: Weak<Inner>,
    listener: Option<Listener>,
    source: Option<std::net::SocketAddr>,
    admitted: Option<Admitted>,
) {
    let source = source.unwrap_or_else(|| conn.remote_address());
    let peer = conn.remote_address();
    let hint = || match &admitted {
        Some(a) => PipeHint::from_admitted(a.clone()),
        None => PipeHint::from_peer(peer).with_source(source),
    };
    loop {
        let accepted = {
            let mut bi = pin!(conn.accept_bi());
            let mut uni = pin!(conn.accept_uni());
            poll_fn(|cx| {
                if let Poll::Ready(r) = bi.as_mut().poll(cx) {
                    return Poll::Ready(r.map(|(s, r)| Stream::Bi(s, r)));
                }
                uni.as_mut().poll(cx).map(|r| r.map(Stream::Uni))
            })
            .await
        };
        let Ok(stream) = accepted else {
            break;
        };
        // Wrapped at once: a stream dropped from here on is reset or
        // stopped, never ended gracefully.
        let stream = match stream {
            Stream::Bi(send, recv) => Incoming::Bi(Send::new(send), Recv::new(recv)),
            Stream::Uni(recv) => Incoming::Uni(Recv::new(recv)),
        };
        let Some(inner) = inner.upgrade() else {
            break;
        };
        match (stream, &listener) {
            (Incoming::Bi(send, recv), Some(l)) => {
                let (l, io, hint) = (l.clone(), inner.pipe(send, recv), hint());
                tokio::spawn(async move { l.handle_pipe(io, hint).await });
            }
            (Incoming::Bi(send, recv), None) => {
                inner.accepted().pipes.push_back((send, recv));
                inner.notify.notify_waiters();
            }
            (Incoming::Uni(recv), l) => {
                let io = PipeIo::reader(recv)
                    .with_carrier(zmux::CarrierKind::WebTransport)
                    .with_carrier_conn(inner.id());
                match l {
                    Some(l) => {
                        let (l, hint) = (l.clone(), hint());
                        tokio::spawn(async move { l.handle_pipe(io, hint).await });
                    }
                    None => {
                        tokio::spawn(zmux::carrier::handle_lane(io));
                    }
                }
            }
        }
    }
    if let Some(inner) = inner.upgrade() {
        let pipes = {
            let mut a = inner.accepted();
            a.closed = true;
            std::mem::take(&mut a.pipes)
        };
        inner.notify.notify_waiters();
        drop(pipes);
    }
}

enum Stream {
    Bi(wt::SendStream, wt::RecvStream),
    Uni(wt::RecvStream),
}

/// An accepted stream, wrapped.
enum Incoming {
    Bi(Send, Recv),
    Uni(Recv),
}

/// `ZMUX_CARRIER_FAILED` as a WebTransport stream error code (32 bits).
fn carrier_failed() -> u32 {
    u32::try_from(ApplicationErrorCode::ZMUX_CARRIER_FAILED.0).unwrap_or(u32::MAX)
}

/// A stream's sending part: ended gracefully by `poll_shutdown` (FIN),
/// reset with `ZMUX_CARRIER_FAILED` when dropped otherwise; a pipe's keeps
/// its carrier alive. A finished one is held until the peer acknowledged
/// all of it (see [`linger`]).
struct Send {
    /// Taken only when dropped.
    stream: Option<wt::SendStream>,
    finished: bool,
    keep: Option<Arc<Inner>>,
}

impl Send {
    fn new(stream: wt::SendStream) -> Self {
        Self {
            stream: Some(stream),
            finished: false,
            keep: None,
        }
    }

    fn stream(&mut self) -> &mut wt::SendStream {
        self.stream.as_mut().expect("taken only when dropped")
    }
}

impl Drop for Send {
    fn drop(&mut self) {
        let Some(mut stream) = self.stream.take() else {
            return;
        };
        if self.finished {
            linger(stream);
        } else {
            let _ = stream.reset(carrier_failed());
        }
    }
}

/// Keeps a finished stream, and with it the QUIC connection, until the
/// peer acknowledged all of it, stopped it, or the connection ended: QUIC
/// closes a connection whose last handle is dropped, and discards the data
/// still in flight, so a carrier's last records (a CONNECTION_CLOSE) would
/// be lost with it.
fn linger(stream: wt::SendStream) {
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        rt.spawn(async move {
            let _ = stream.stopped().await;
        });
    }
}

/// Owned buffers go to quinn as they are: one lock of the connection per
/// call, and payloads without copying.
impl ChunkWrite for Send {
    fn poll_write_chunks(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<io::Result<usize>> {
        // Cancel safe: a write that is not ready took nothing, and
        // registered the waker.
        let polled = pin!(self.stream().write_chunks(chunks)).poll(cx);
        polled.map(|r| r.map(|w| w.bytes).map_err(write_error))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(self.stream()), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = AsyncWrite::poll_shutdown(Pin::new(self.stream()), cx);
        if r.is_ready() {
            self.finished = true;
        }
        r
    }
}

/// A write error as quinn reports it through `AsyncWrite`.
fn write_error(e: wt::WriteError) -> io::Error {
    let kind = match e {
        wt::WriteError::Stopped(_) | wt::WriteError::InvalidStopped(_) => {
            io::ErrorKind::ConnectionReset
        }
        _ => io::ErrorKind::NotConnected,
    };
    io::Error::new(kind, e)
}

/// A stream's receiving part: stopped with `ZMUX_CARRIER_FAILED` when
/// dropped before its end; a pipe's keeps its carrier alive.
struct Recv {
    stream: wt::RecvStream,
    keep: Option<Arc<Inner>>,
}

impl Recv {
    fn new(stream: wt::RecvStream) -> Self {
        Self { stream, keep: None }
    }
}

impl Drop for Recv {
    fn drop(&mut self) {
        let _ = self.stream.stop(carrier_failed());
    }
}

impl AsyncRead for Recv {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.stream), cx, buf)
    }
}

/// A [`zmux::Candidate`] of [`zmux::CarrierKind::WebTransport`] for carrier
/// modes: a WebTransport session to `url` made by `client` ([`dial`]).
pub fn candidate(client: wt::Client, url: Url, options: &Options) -> zmux::Candidate {
    let options = Arc::new(options.clone());
    zmux::Candidate::new(zmux::CarrierKind::WebTransport, move || {
        let (client, url, options) = (client.clone(), url.clone(), options.clone());
        async move { dial(&client, url, &options).await }
    })
}
