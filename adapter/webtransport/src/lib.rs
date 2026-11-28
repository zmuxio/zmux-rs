//! WebTransport sessions over Quinn as zmux carriers. Pipes use bidirectional
//! WebTransport streams and their lanes use unidirectional streams.
//! WebTransport runs
//! over HTTP/3, so a carrier reaches a server through HTTP/3 front ends and
//! load balancers that forward WebTransport, where a plain QUIC carrier may
//! not; the session's own features (datagrams, statistics, close) and the
//! QUIC connection under it stay the application's
//! ([`Carrier::session`]).
//!
//! One step from a client to a zmux session, and from a server to the
//! sessions it accepts: [`connect`] and [`serve`]; with
//! [`ListenerConfig::admission`](zmux::ListenerConfig::admission), [`serve`] decides on each session request before
//! it answers it ([`admit`]), on the request head: a client's credential
//! travels in a request header field ([`Options::with_carrier_credential`]), such
//! as a prefix authentication token in `Zmux-Prefix-Auth`, bound to the
//! QUIC connection with [`dial_over`]. The head may defer the decision to
//! the session's first bidirectional stream
//! ([`AdmissionVerdict::Defer`](zmux::AdmissionVerdict::Defer)), which the
//! listener's fallback may then take over
//! ([`ListenerConfig::fallback`](zmux::ListenerConfig::fallback),
//! [`takeover_session`]). The QUIC endpoints carry the HTTP/3
//! ALPN identifier `h3` ([`ALPN`]), which names the
//! HTTP layer; zmux's own identifiers do not apply. Build their transport
//! configuration with [`Options::transport_config`], so that the stream
//! window has one source.
//!
//! A [`Carrier`] takes a whole established session: a pipe is
//! one bidirectional stream of it ([`Carrier::open_pipe`],
//! [`Carrier::accept_pipe`]), and the pipe's lanes are further
//! unidirectional streams, which zmux opens itself as it needs them. The
//! carrier runs the session's accept loop: every stream the peer opens is a
//! carrier, handed to the [`Listener`] given, or else a lane to
//! [`zmux::adapter::handle_lane`] and a pipe to [`Carrier::accept_pipe`];
//! zmux routes lanes by their Lane Key and checks that they are on the
//! session of their pipe, whose identity is the carrier. One WebTransport
//! session owns its QUIC connection, so the session's streams belong to
//! zmux.
//!
//! What the session gives zmux:
//!
//! - its datagrams, as the datagram channel of its stream pipes: a zmux
//!   session with datagrams enabled sends each datagram that fits one there rather than in a record when
//!   the peer negotiated it. RFC 9297 supplies the CONNECT Quarter Stream ID.
//!   The WebTransport payload starts with the pipe's QUIC stream ID, which
//!   routes it to the attached zmux session ([`Carrier::channel_dropped`]
//!   counts those that named none), so the session's datagrams belong to
//!   zmux;
//! - the TLS 1.3 exporter of its QUIC connection (RFC 9001 Section 4), for
//!   [`zmux::PipeAuth::exporter`] and Bound joins (the carriers declare the
//!   secure carrier's Bound contract; the Binding names the connection, not
//!   the stream); behind an HTTP/3 front end that terminates TLS the two ends
//!   export different values, so such deployments use a PSK.
//!   The exporter does not keep the connection: once it is gone it gives
//!   no value ([`zmux::ExportError::Unavailable`]);
//! - flow control sized for its lanes: the peer may open [`LaneWindows::lanes`] lanes at once (beside
//!   the HTTP/3 control streams), and the connection's receive window
//!   covers that many stream windows and a pipe's own, charged to the
//!   memory budget for as long as the carrier lives: the listener's
//!   ([`Carrier::with_listener`]), or else the zmux session's
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
//! # async fn example(client: zmux_webtransport::Client) -> Result<(), Box<dyn std::error::Error>> {
//! use zmux::{Config, PipeAuth};
//! use zmux_webtransport::Options;
//!
//! let url: zmux_webtransport::Url = "https://example.com/zmux".parse()?;
//! let mut config = Config::default();
//! config.pipe_auth = PipeAuth::exporter();
//! let session = zmux_webtransport::connect(&client, url, &Options::default(), config).await?;
//! # drop(session);
//! # Ok(())
//! # }
//! ```
#![forbid(unsafe_code)]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use bytes::Bytes;
pub use quinn;
use quinn::VarInt;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
pub use url::Url;

mod h3;
mod protocol;
mod streams;

pub use streams::{RecvStream, SendStream};

pub use protocol::{ALPN, Client, ConnectRejected, ConnectRequest, Request, Session, SessionEnd};
use zmux::adapter::{Admit, Entry};
use zmux::adapter::{CarrierConnId, ChannelDemux, MemoryCharge};
use zmux::proto::ApplicationErrorCode;
use zmux::{CarrierCredential, CarrierInfo, ConnectError, Listener, PipeHint, PipeIo, Takeover};
use zmux_quinn::Handshake;
pub use zmux_quinn::LaneWindows;
use zmux_quinn::parts::{self, AcceptQueue, DatagramConn, Datagrams, RecvPart, SendPart};

/// The unidirectional streams an HTTP/3 endpoint keeps open on its own
/// (control, QPACK encoder and decoder).
const H3_UNI_STREAMS: u32 = 3;

/// The adapter's options: how the carrier sizes the connection's flow
/// control for lanes, and a client's credential.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// The windows; [`LaneWindows::lanes`] is the lanes the peer may open
    /// on the session at once.
    pub windows: LaneWindows,
    /// Client: the credential whose header field
    /// ([`CarrierCredential::header`]) goes on each session request (none by
    /// default).
    pub carrier_credential: Option<Arc<dyn CarrierCredential>>,
    /// Client: the bound on a dial, from the connection to the session's
    /// first stream opened (default [`zmux::adapter::DIAL_TIMEOUT`], 10 s);
    /// one not done within it fails with `TimedOut`.
    pub timeout: std::time::Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            windows: LaneWindows::default(),
            carrier_credential: None,
            timeout: zmux::adapter::DIAL_TIMEOUT,
        }
    }
}

impl Options {
    /// The defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// With this bound on a dial ([`Options::timeout`]).
    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;
        self
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
    pub fn with_carrier_credential(mut self, credential: Arc<dyn CarrierCredential>) -> Self {
        self.carrier_credential = Some(credential);
        self
    }

    /// quinn's transport configuration for these options: the stream
    /// receive window, the connection window for the lanes and the
    /// unidirectional streams the peer may open (the lanes and HTTP/3's
    /// own); the rest quinn's defaults. Build the endpoints' client and
    /// server configurations with it.
    #[must_use]
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
/// open while the pipe is used. For [`zmux::SessionController`] and
/// [`zmux::Session::begin_change`]; to reach the WebTransport session itself,
/// make it and its carrier ([`Carrier::new`]) instead. The
/// header field of [`Options::carrier_credential`] goes on the request, the
/// credential given no exporter (the client makes the QUIC connection and
/// sends the request in one step): a bound one needs [`dial_over`].
///
/// # Errors
///
/// The credential's error, or `InvalidInput`, when its header cannot be
/// made; `Other` when the connection, the WebTransport session or its
/// stream cannot be opened; `TimedOut` past [`Options::timeout`].
pub async fn dial(
    client: &Client,
    request: impl Into<ConnectRequest>,
    options: &Options,
) -> io::Result<PipeIo> {
    let request = credential_header(
        request.into(),
        options,
        &CarrierInfo::new().with_encrypted(),
    )?;
    zmux::adapter::within(options.timeout, async {
        let session = client.connect(request).await?;
        Carrier::start(
            session,
            None,
            options,
            None,
            options.windows.receive_window(),
        )
        .open_pipe()
        .await
    })
    .await
}

/// [`dial`] on `conn`, an established QUIC connection with the ALPN
/// identifier `h3` and nothing else on it: the credential is given the
/// connection's metadata ([`zmux_quinn::Handshake::carrier_info`]), its
/// exporter for a bound one among them.
///
/// # Errors
///
/// The credential's error, or `InvalidInput`, when its header cannot be
/// made or the actual receive window is missing or invalid; `Other` when the WebTransport session or its stream cannot be
/// opened; `TimedOut` past [`Options::timeout`].
pub async fn dial_over(
    conn: quinn::Connection,
    request: impl Into<ConnectRequest>,
    options: &Options,
) -> io::Result<PipeIo> {
    let window = options.windows.established_receive_window()?;
    let handshake = Handshake::of(&conn);
    let request = credential_header(request.into(), options, &handshake.carrier_info(&conn))?;
    zmux::adapter::within(options.timeout, async {
        let session = Session::connect(conn, request).await?;
        Carrier::start(session, None, options, None, window)
            .open_pipe()
            .await
    })
    .await
}

/// `request` with the header field of [`Options::carrier_credential`] for a
/// carrier with metadata `info`.
fn credential_header(
    mut request: ConnectRequest,
    options: &Options,
    info: &CarrierInfo,
) -> io::Result<ConnectRequest> {
    if let Some(c) = &options.carrier_credential {
        let (name, value) = c.header(info)?;
        let invalid = |e| io::Error::new(io::ErrorKind::InvalidInput, e);
        let name =
            http::HeaderName::from_bytes(name.as_bytes()).map_err(|e| invalid(e.to_string()))?;
        let value = http::HeaderValue::from_str(&value).map_err(|e| invalid(e.to_string()))?;
        request.headers.insert(name, value);
    }
    Ok(request)
}

/// Establishes a zmux session over a new WebTransport session ([`dial`],
/// then [`zmux::Session::connect`]).
///
/// # Errors
///
/// [`ConnectError::Io`] with an error of [`dial`], and the errors of
/// [`zmux::Session::connect`].
pub async fn connect(
    client: &Client,
    request: impl Into<ConnectRequest>,
    options: &Options,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<zmux::Session, ConnectError> {
    let pipe = dial(client, request, options)
        .await
        .map_err(|e| ConnectError::Io(Arc::new(e)))?;
    zmux::Session::connect(pipe, config).await
}

/// Serves WebTransport on the QUIC connections accepted by `endpoint`
/// with ALPN `h3`. It runs until the listener or endpoint closes. Each connection
/// takes its source slot ([`ListenerAdapter::enter`](zmux::adapter::ListenerAdapter::enter)) before its QUIC handshake,
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
    let window = options.windows.receive_window();
    l.serve_connections(
        move || async move { endpoint.accept().await.map(Ok) },
        move |incoming: quinn::Incoming| {
            let entry = listener.adapter().enter(incoming.remote_address(), None);
            let charge = entry
                .as_ref()
                .and_then(|_| listener.adapter().reserve_memory(window).ok());
            async move {
                let entry = entry.ok_or(())?;
                let Some(charge) = charge else {
                    entry.release();
                    return Err(());
                };
                let conn = incoming.await.map_err(drop)?;
                let request = Request::accept(conn).await.map_err(drop)?;
                Ok::<_, ()>((request, entry, charge))
            }
        },
        move |listener, (request, entry, charge): (Request, Entry, _)| {
            let options = options.clone();
            async move {
                let _ = admit_reserved(request, entry, &listener, &options, charge).await;
            }
        },
    )
    .await;
}

/// Decides on a session request by the listener's admission
/// ([`zmux::ListenerConfig::admission`]) and serves it until it ends;
/// `entry` is the connection's entry into the listener
/// ([`ListenerAdapter::enter`](zmux::adapter::ListenerAdapter::enter), taken before its QUIC handshake). Nothing is
/// answered before the decision. The decision on the head
/// ([`Entry::decide_upgrade`]) has no prefix; its metadata
/// is the connection's ([`zmux_quinn::Handshake::carrier_info`]), with the
/// request ([`ConnectRequest`] as the [`CarrierInfo::with_request`]
/// value, its header fields as [`CarrierInfo::for_each_header`] gives
/// them), the head stage and [`CarrierInfo::upgrade`], so that
/// [`zmux::Admission::prefix_auth`] takes its token from the request
/// header field; behind an intermediary the listener trusts, the source is
/// the client it reports in a forwarding header field
/// ([`Entry::set_source`]). Then:
///
/// - `Accept`: 200 OK, and the session is a [`Carrier`] of
///   `listener` for as long as it is open, its streams admitted with it;
/// - `Defer`: 200 OK, and the decision is taken again on the session's
///   first bidirectional stream ([`Entry::admit_first`]): its first
///   [`zmux::Admission::peek`] bytes, with the same metadata; the stream
///   arrives and its prefix is read within what remains of the peek
///   timeout. A timeout closes the session. Further streams and lanes
///   reach the listener once it accepts the first stream as a pipe.
///   `Fallback` and `Takeover` give the host the first stream with every
///   byte read replayed ([`Takeover::into_stream`], [`takeover_session`]).
///   Without a host target, either verdict stalls the session. The adapter
///   closes the session when the stall ends or the host returns it;
/// - `Fallback`: the request is answered with 404 (a request, which this
///   adapter has no HTTP handler for: a server that serves other requests
///   routes them before [`admit`]);
/// - `Stall`: nothing is answered; once a stall's duration has passed, or
///   the connection closed, the request is ended without a response and
///   the connection closed;
/// - `Close`: the connection is closed at once.
///
/// Without an admission, every request is accepted. A request that an
/// intermediary forwarded from TLS early data (`Early-Data: 1`) is
/// answered `425 (Too Early)` before any admission, and no carrier is
/// taken from it.
///
/// # Errors
///
/// Returns `InvalidInput` if the actual receive window is missing or invalid,
/// or ticket admission lacks QUIC early-data provenance tracking.
/// Ticket admission checks the bytes of the associated CONNECT stream.
pub async fn admit(
    request: Request,
    entry: Entry,
    listener: &Listener,
    options: &Options,
) -> io::Result<()> {
    let window = options.windows.established_receive_window()?;
    let Ok(charge) = listener.adapter().reserve_memory(window) else {
        entry.release();
        refuse(request, http::StatusCode::SERVICE_UNAVAILABLE, listener).await;
        return Ok(());
    };
    admit_reserved(request, entry, listener, options, charge).await
}

async fn admit_reserved(
    request: Request,
    mut entry: Entry,
    listener: &Listener,
    options: &Options,
    charge: MemoryCharge,
) -> io::Result<()> {
    let connect: &ConnectRequest = &request;
    let handshake = Handshake::of(request.conn());
    let info = handshake.server_carrier_info(request.conn(), Some(request.id()));
    if info.is_early_data() || zmux::adapter::forwarded_early_data(&connect.headers) {
        let _ = entry
            .setup_step(request.reject(http::StatusCode::TOO_EARLY))
            .await;
        return Ok(());
    }
    if let Err(error) = handshake.require_ticket_provenance(listener) {
        request.conn().close(VarInt::from_u32(0), b"");
        return Err(error);
    }
    let source = source_of(request.conn().remote_address(), connect, listener);
    if !entry.set_source(source) {
        request.conn().close(VarInt::from_u32(0), b"");
        return Ok(());
    }
    let decided = {
        let info = info.with_request_head(Arc::new(connect.clone()), |c, each| {
            zmux::adapter::visit_fields(&c.headers, each);
        });
        entry.decide_upgrade(info).await
    };
    let conn = request.conn().clone();
    match decided {
        Admit::Accept(_) => {
            let admitted = listener.adapter().admission().and(entry.admitted());
            let Some(Ok(session)) = entry.setup_step(request.ok()).await else {
                return Ok(());
            };
            if entry.hand_off_connection().is_err() {
                return Ok(());
            }
            let listener = listener.clone();
            let carrier = Carrier::make(session.clone(), Some(charge), options, 0);
            let service = parts::ConnectionService::start(|delivery| {
                delivery.serve(WtStreams(session), carrier.inner, listener, admitted, None)
            });
            service.admission_stopped().await;
        }
        Admit::Defer | Admit::TakeOver(_) => {
            admit_first_stream(request, entry, listener, options, charge).await;
        }
        Admit::Fallback(_) => {
            entry.complete_request_fallback(false);
            drop(entry);
            refuse(request, http::StatusCode::NOT_FOUND, listener).await;
        }
        Admit::Stall => {
            let stall = entry.stall_request(None::<tokio::io::Empty>, move |_| async move {
                request.conn().close(VarInt::from_u32(0), b"");
            });
            zmux::adapter::while_open(conn.closed(), stall).await;
        }
        _ => conn.close(VarInt::from_u32(0), b""),
    }
    Ok(())
}

/// The session of a request whose head deferred the decision ([`admit`]):
/// answered, and admitted on its first bidirectional stream.
async fn admit_first_stream(
    request: Request,
    entry: Entry,
    listener: &Listener,
    options: &Options,
    charge: MemoryCharge,
) {
    let closing = request.conn().clone();
    let returned = closing.clone();
    let listener = listener.clone();
    let options = options.clone();
    let service = parts::ConnectionService::start(|delivery| {
        delivery.admit(
            listener,
            entry,
            move |first| async move {
                let session = request.ok().await.map_err(io::Error::other)?;
                let (send, recv) = session.accept_bi().await.map_err(io::Error::other)?;
                let carrier_session = session.clone();
                let stalled = session.clone();
                let io = first
                    .prepare(WtSend(send), WtRecv(recv), move || {
                        let carrier =
                            Carrier::make(carrier_session.clone(), Some(charge), &options, 0);
                        (WtStreams(carrier_session), carrier.inner)
                    })
                    .with_connection(Arc::new(session))
                    .with_stall_until(async move {
                        let _ = stalled.closed().await;
                    })
                    .with_on_return(move || returned.close(VarInt::from_u32(0), b""));
                Ok((CarrierInfo::new(), io))
            },
            move || closing.close(VarInt::from_u32(0), b""),
        )
    });
    service.admission_stopped().await;
}

/// The WebTransport session of a stream the listener's fallback took over
/// ([`zmux::ListenerConfig::fallback`]) from [`admit`]: the session's first
/// bidirectional stream, as [`Takeover::into_stream`] gives it, after its
/// head deferred the decision. The session is closed once the fallback's
/// future completed, unless the host detached the takeover
/// ([`Takeover::detach`]): it is then the host's to close.
#[must_use]
pub fn takeover_session(takeover: &Takeover) -> Option<Session> {
    takeover.connection()?.downcast_ref::<Session>().cloned()
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
    request: &ConnectRequest,
    listener: &Listener,
) -> std::net::SocketAddr {
    listener
        .adapter()
        .trusted_proxies()
        .source(peer, &request.headers)
}

/// Rejects a request whose setup slot has already been released.
async fn refuse(request: Request, status: http::StatusCode, listener: &Listener) {
    let adapter = listener.adapter();
    let _ = zmux::adapter::while_open(
        adapter.closed(),
        tokio::time::timeout(adapter.handshake_timeout(), request.reject(status)),
    )
    .await;
}

/// A WebTransport session whose streams carry zmux pipes and lanes (see
/// the crate documentation). Cheap to clone; the accept loop runs while the
/// session is open and any clone, or any pipe made from it, is alive.
/// Once none is, the loop stops and the WebTransport session is closed:
/// keep a clone while the peer may still open pipes on it.
///
/// A pipe holds the session until its zmux session is done with it (every
/// pipe's inbound side ended or its linger timeout passed), so that the
/// WebTransport close never cuts off the zmux close before it: after a graceful end it holds it on until the peer
/// acknowledged the pipe's stream, for at most
/// [`DRAIN_LIMIT`](zmux::adapter::DRAIN_LIMIT) (the pipe's drain,
/// [`PipeIo::with_drain`]). The
/// WebTransport session is then closed with the application error code of
/// the `CONNECTION_CLOSE` that ended the last zmux session on it, when it
/// fits the 32-bit WebTransport code, and 0 otherwise, after any other end
/// and for a session that never carried one. On a WebTransport session
/// several zmux sessions share, the pipe zmux is done with last decides the
/// code, 0 for one removed while its zmux session goes on.
#[derive(Clone)]
#[must_use = "the accept loop stops once the carrier and its pipes are gone"]
pub struct Carrier {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for Carrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Carrier")
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
    /// Streams of pipes the peer opened, without a listener (made pipes
    /// when taken, so that the queue holds no reference to this state).
    accepted: AcceptQueue<(Send, Recv)>,
    _charge: Option<MemoryCharge>,
    /// The session's datagrams, the channels of its pipes.
    datagrams: Arc<Datagrams<WtDatagrams>>,
    close: parts::ConnectionClose,
}

impl Drop for Inner {
    /// No carrier and no pipe holds the session any more: it closes with
    /// the last zmux session's code (a no-op on one already closed).
    fn drop(&mut self) {
        self.close.close(|code| {
            // The peer already received zmux's full CONNECTION_CLOSE.
            self.conn.close(u32::try_from(code).unwrap_or(0), b"");
        });
    }
}

impl Carrier {
    /// The carrier of `session`, an established WebTransport session,
    /// without a listener; its accept loop starts here (inside a tokio
    /// runtime). The peer's pipes go to
    /// [`Carrier::accept_pipe`], and the connection's receive
    /// window is charged to the zmux session its pipes carry. Make one
    /// carrier per session: its lanes are recognised by it.
    ///
    /// # Errors
    ///
    /// Returns `InvalidInput` if the actual receive window is missing or invalid.
    pub fn new(session: Session, options: &Options) -> io::Result<Self> {
        let window = options.windows.established_receive_window()?;
        Ok(Self::start(session, None, options, None, window))
    }

    /// The carrier of `session` for `listener`: every stream the peer
    /// opens goes to [`Listener::handle_pipe`], and the connection's
    /// receive window is charged to the listener's budget while the
    /// carrier lives.
    ///
    /// # Errors
    ///
    /// The actual receive window is missing or invalid, or the listener's
    /// budget cannot cover it.
    pub fn with_listener(
        session: Session,
        listener: &Listener,
        options: &Options,
    ) -> io::Result<Self> {
        let window = options.windows.established_receive_window()?;
        let charge = listener.adapter().reserve_memory(window)?;
        Ok(Self::start(
            session,
            Some(listener.clone()),
            options,
            Some(charge),
            0,
        ))
    }

    fn start(
        conn: Session,
        listener: Option<Listener>,
        options: &Options,
        charge: Option<MemoryCharge>,
        own_charge: u64,
    ) -> Self {
        let carrier = Self::make(conn.clone(), charge, options, own_charge);
        parts::start_receivers(WtStreams(conn), &carrier.inner, listener);
        carrier
    }

    /// The carrier with close responsibility and receivers still unassigned.
    fn make(
        conn: Session,
        charge: Option<MemoryCharge>,
        options: &Options,
        own_charge: u64,
    ) -> Self {
        // The HTTP/3 control and QPACK streams stay open beside the lanes.
        conn.set_max_concurrent_uni_streams(VarInt::from_u32(
            options.windows.lanes.saturating_add(H3_UNI_STREAMS),
        ));
        let inner = Arc::new(Inner {
            conn: conn.clone(),
            id: OnceLock::new(),
            own_charge,
            accepted: AcceptQueue::default(),
            _charge: charge,
            datagrams: Datagrams::with(WtDatagrams(conn)),
            close: parts::ConnectionClose::default(),
        });
        let _ = inner.id.set(CarrierConnId::new(&inner));
        Self { inner }
    }

    /// The WebTransport session, for its own features (statistics,
    /// close) and, through it, the QUIC connection. Its streams and
    /// datagrams belong to zmux.
    #[must_use]
    pub fn session(&self) -> &Session {
        &self.inner.conn
    }

    /// The session's datagrams received that named no pipe attached to a
    /// zmux session (an unknown, not yet attached or closed one).
    #[must_use]
    pub fn channel_dropped(&self) -> u64 {
        self.inner.datagrams.dropped()
    }

    /// A new pipe on a bidirectional stream of the session: the
    /// bootstrap carrier of a session this endpoint starts, or a pipe it
    /// joins. Waits for the peer's stream credit.
    ///
    /// # Errors
    ///
    /// `Other` when the stream cannot be opened.
    pub async fn open_pipe(&self) -> io::Result<PipeIo> {
        let (send, recv) = self.inner.conn.open_bi().await?;
        Ok(self
            .inner
            .pipe(Send::new(WtSend(send)), Recv::new(WtRecv(recv))))
    }

    /// The next pipe the peer opened, on a carrier without a listener (for
    /// [`zmux::Session::accept`]); `None` once the connection is closed.
    /// With a listener, the listener takes them. Pipes nobody takes wait,
    /// as many as the connection lets the peer open bidirectional streams
    /// (QUIC `MAX_STREAMS`).
    pub async fn accept_pipe(&self) -> Option<PipeIo> {
        let (send, recv) = self.inner.accepted.pop().await?;
        Some(self.inner.pipe(send, recv))
    }
}

impl Inner {
    fn with_lanes(self: &Arc<Self>, io: PipeIo) -> PipeIo {
        let opener = self.clone();
        io.with_lane_opener(move || {
            let inner = opener.clone();
            async move {
                let send = inner.conn.open_uni().await.map_err(io::Error::other)?;
                Ok(parts::lane(WtSend(send), inner))
            }
        })
    }

    fn id(&self) -> CarrierConnId {
        self.id.get().expect("set at creation").clone()
    }

    /// A pipe carrier on a bidirectional stream, with the connection's
    /// identity, lane opener and exporter. Its streams and lanes keep this
    /// state (and so the accept loop) alive.
    fn pipe(self: &Arc<Self>, send: Send, recv: Recv) -> PipeIo {
        // Holds the session until the zmux session is done with the pipe,
        // and gives the session's close its code.
        let closer = self.clone();
        // Does not keep the connection: gives no value once it is gone.
        let exporter = Arc::downgrade(self);
        let channel = self.datagrams.channel(recv.get_ref().0.id().into());
        let io = zmux_quinn::with_packet_counters(
            parts::pipe(send, recv, self.clone()),
            self,
            |inner| &inner.conn,
        )
        .with_carrier_transport(zmux::CarrierKind::WebTransport, self.id())
        .with_connection_memory(self.own_charge)
        .with_datagram_channel(channel)
        .with_close_code(move |code| {
            closer.close.set_code(code.into_inner());
        });
        self.with_lanes(io)
            // HTTP/3 runs over ALPN `h3`, as the other QUIC carriers report theirs.
            .with_terminated_tls(|| Some(zmux::TlsState::new(Some(b"h3".to_vec()), None)))
            // QUIC protects the records; the Binding is the connection's, not the stream's.
            .with_carrier_secure()
            .with_exporter(move |label, context, out| {
                exporter.upgrade().is_some_and(|inner| {
                    inner
                        .conn
                        .export_keying_material(out, label.as_bytes(), context)
                        .is_ok()
                })
            })
    }
}

/// A WebTransport session's datagrams, which start with the pipe's QUIC
/// stream ID ([`Datagrams`]).
struct WtDatagrams(Session);

impl DatagramConn for WtDatagrams {
    fn max_datagram_size(&self) -> usize {
        self.0.max_datagram_size()
    }

    async fn send_datagram(&self, datagram: Bytes) -> io::Result<()> {
        self.0
            .send_datagram_wait(datagram)
            .await
            .map_err(io::Error::other)
    }

    fn deliver(
        &self,
        demux: ChannelDemux,
    ) -> impl Future<Output = ()> + std::marker::Send + 'static {
        let session = self.0.clone();
        async move {
            while let Ok(b) = session.read_datagram().await {
                demux.deliver(b);
            }
        }
    }
}

/// A WebTransport session's streams the peer opens
/// ([`parts::accept_loop`]).
struct WtStreams(Session);

impl parts::StreamConn for WtStreams {
    type Send = WtSend;
    type Recv = WtRecv;

    fn hints(&self, listener: Option<&Listener>) -> impl Fn() -> PipeHint {
        let peer = self.0.remote_address();
        let source = listener.map_or(peer, |listener| session_source(&self.0, listener));
        move || PipeHint::from_peer(peer).with_source(source)
    }

    async fn accept_bi(&self) -> Option<(WtSend, WtRecv)> {
        let (send, recv) = self.0.accept_bi().await.ok()?;
        Some((WtSend(send), WtRecv(recv)))
    }

    async fn accept_uni(&self) -> Option<WtRecv> {
        self.0.accept_uni().await.ok().map(WtRecv)
    }
}

impl parts::CarrierState<WtSend, WtRecv> for Inner {
    fn pipe(self: &Arc<Self>, send: Send, recv: Recv) -> PipeIo {
        Inner::pipe(self, send, recv)
    }

    fn conn_id(&self) -> CarrierConnId {
        self.id()
    }

    fn close(&self) -> &parts::ConnectionClose {
        &self.close
    }

    fn kind(&self) -> zmux::CarrierKind {
        zmux::CarrierKind::WebTransport
    }

    fn accepted(&self) -> &AcceptQueue<(Send, Recv)> {
        &self.accepted
    }
}

/// `ZMUX_CARRIER_FAILED` as a WebTransport stream error code (32 bits).
fn carrier_failed() -> u32 {
    u32::try_from(ApplicationErrorCode::ZMUX_CARRIER_FAILED.0).unwrap_or(u32::MAX)
}

/// A pipe's or lane's sending part ([`parts::QuicSend`]).
type Send = parts::QuicSend<WtSend>;
/// A pipe's receiving part ([`parts::QuicRecv`]).
type Recv = parts::QuicRecv<WtRecv>;

/// A WebTransport stream's sending part, with its close codes.
struct WtSend(SendStream);

impl SendPart for WtSend {
    fn poll_write(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.0), cx, bytes)
    }

    fn poll_send_bytes(
        &mut self,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<io::Result<usize>> {
        self.0.poll_chunks(cx, chunks)
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.0), cx)
    }

    fn reset(&mut self) {
        let _ = self.0.reset(protocol::application_code(carrier_failed()));
    }

    fn stopped(&self) -> impl Future<Output = ()> + std::marker::Send + 'static {
        let stopped = self.0.stopped();
        async move {
            let _ = stopped.await;
        }
    }
}

/// A write error as quinn reports it through `AsyncWrite`.
fn write_error(e: quinn::WriteError) -> io::Error {
    let kind = match e {
        quinn::WriteError::Stopped(_) => io::ErrorKind::ConnectionReset,
        _ => io::ErrorKind::NotConnected,
    };
    io::Error::new(kind, e)
}

/// A WebTransport stream's receiving part, with its close code.
struct WtRecv(RecvStream);

impl RecvPart for WtRecv {
    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.0), cx, buf)
    }

    fn stop(&mut self) {
        let _ = self.0.stop(protocol::application_code(carrier_failed()));
    }
}

/// A [`zmux::Candidate`] of [`zmux::CarrierKind::WebTransport`] for carrier
/// modes: a WebTransport session to `url` made by `client` ([`dial`]).
#[must_use]
pub fn candidate(client: Client, url: Url, options: &Options) -> zmux::Candidate {
    let options = Arc::new(options.clone());
    zmux::Candidate::new(zmux::CarrierKind::WebTransport, move || {
        let (client, url, options) = (client.clone(), url.clone(), options.clone());
        async move { dial(&client, url, &options).await }
    })
}

#[cfg(test)]
mod tests;
