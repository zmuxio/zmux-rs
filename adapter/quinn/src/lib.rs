//! QUIC connections as zmux carriers over quinn: zmux
//! sessions whose pipes and lanes are streams of QUIC connections. The
//! connection's own features (datagrams, statistics, path, close) stay the
//! application's, through the raw [`Connection`]
//! ([`QuicCarrier::connection`]).
//!
//! One step from an endpoint to a session, and from an endpoint to the
//! sessions it accepts: [`connect`] and [`serve`]. With the `rustls-ring`
//! (default) or `rustls-aws-lc-rs` feature, [`client_config`] and
//! [`server_config`] make quinn configurations from rustls ones with zmux's
//! ALPN identifiers when they have none ([`zmux::alpn_protocols`]) and the
//! transport parameters the carrier needs ([`Options::transport_config`]);
//! without them, configure the endpoint with [`Options::transport_config`]
//! and the ALPN identifiers yourself.
//!
//! A [`QuicCarrier`] takes a whole established connection: a pipe is one
//! bidirectional stream of it ([`QuicCarrier::open_pipe`],
//! [`QuicCarrier::accept_pipe`]), and the pipe's lanes are further
//! unidirectional streams (MULTIPATH.md Sections 2.5 and 5.8), which zmux
//! opens itself as it needs them. The carrier runs the connection's accept
//! loop: every stream the peer opens is a carrier, handed to the
//! [`Listener`] given, or else a lane to [`zmux::carrier::handle_lane`] and a
//! pipe to [`QuicCarrier::accept_pipe`]; zmux routes lanes by their Lane Key
//! and checks that they are on the connection of their pipe, whose identity
//! is the carrier. The connection's streams therefore belong to zmux.
//!
//! What the connection gives zmux:
//!
//! - its TLS 1.3 exporter (RFC 9001 Section 4), shared by its streams: the
//!   session secret of a bootstrap pipe with [`zmux::PipeAuth::tls`], and
//!   the binding of carrier-bound joins (MULTIPATH.md Section 10.5). A
//!   connection whose handshake had not completed when the carrier was made
//!   (0-RTT) has none;
//! - flow control sized for its lanes: the peer may open [`Options::lanes`] lanes at once, and the
//!   connection's receive window covers that many stream windows and a
//!   pipe's own, so that a lane blocked by a loss never holds the others
//!   back at the connection level. The window is charged to the memory
//!   budget for as long as the carrier lives: the listener's
//!   ([`QuicCarrier::with_listener`]), or else the session's own
//!   ([`PipeIo::with_connection_memory`]). The stream window has one
//!   source, [`Options::stream_window`]: build the endpoint's transport
//!   configuration with [`Options::transport_config`]. Opening a lane waits
//!   for the peer's stream credit, which zmux counts as the pipe's one lane
//!   not yet confirmed.
//!
//! A stream's sending part that zmux drops without ending it gracefully
//! (a failed pipe or lane) is reset, and a receiving part dropped before
//! its end is stopped, with `ZMUX_CARRIER_FAILED`, so that the peer sees a
//! failure rather than a graceful end. Streams report no unsent count to
//! zmux (quinn exposes none): the carrier queue limiter paces them.
//!
//! ```no_run
//! # async fn example(tls: rustls::ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
//! use zmux::{Config, PipeAuth};
//! use zmux_quinn::Options;
//!
//! let opts = Options::default();
//! let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;
//! endpoint.set_default_client_config(zmux_quinn::client_config(tls, &opts)?);
//! let mut config = Config::default();
//! config.pipe_auth = PipeAuth::tls();
//! let addr = "192.0.2.1:443".parse()?;
//! let session = zmux_quinn::connect(&endpoint, addr, "example.com", &opts, config).await?;
//! # drop(session);
//! # Ok(())
//! # }
//! ```

use std::collections::VecDeque;
use std::future::{Future, poll_fn};
use std::io::{self, IoSlice};
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::task::{Context, Poll};

#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
use quinn::rustls;
use quinn::{Connection, Endpoint, VarInt};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
use zmux::carrier::{CarrierConnId, MemoryCharge};
use zmux::proto::ApplicationErrorCode;
use zmux::proto::keys::{EXPORTER_PIPE_LABEL, EXPORTER_SESSION_LABEL};
use zmux::{ConnectError, Listener, PipeHint, PipeIo, Session};

/// How the carrier sizes the connection's flow control for lanes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// The stream receive window (1 250 000 bytes by default, quinn's
    /// default): the endpoint's transport configuration takes it from
    /// [`Options::transport_config`], its one source.
    pub stream_window: u64,
    /// Lanes the peer may open on the connection at once (QUIC
    /// MAX_STREAMS for unidirectional streams; default 4): zmux opens more
    /// lanes on a pipe only as the peer's stream credit allows. The
    /// connection's receive window is set to `lanes + 1` stream windows,
    /// which a listener's budget is charged with from the moment the
    /// carrier is made, before any join on it is authenticated.
    pub lanes: u32,
    /// QUIC 0-RTT (off by default; [`Options::with_zero_rtt`]).
    pub zero_rtt: Option<ParameterMemory>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            stream_window: 1_250_000,
            lanes: 4,
            zero_rtt: None,
        }
    }
}

/// The servers' transport parameters a client keeps for QUIC 0-RTT, by
/// server name: each session [`connect`] establishes leaves the server's
/// parameters stored for 0-RTT here, and the next connection to that name
/// that resumes its TLS session sends its first records as 0-RTT data under
/// them. Cheap to clone; share one between the connections to a server.
/// (quinn keeps no data of the application with its tickets: this stands
/// for it, and relies on the server obligation described at
/// [`server_config`].)
///
/// The memory lives in this process only, as long as a clone of it does;
/// nothing expires by time (a server that changed its parameters rejects
/// 0-RTT, which costs one round trip, and the new parameters replace the
/// old ones). [`ParameterMemory::new`] keeps every name;
/// [`ParameterMemory::with_capacity`] bounds the number of names for a
/// client that reaches many servers, forgetting the name set longest ago.
#[derive(Debug, Clone, Default)]
pub struct ParameterMemory {
    inner: Arc<Mutex<Memory>>,
}

#[derive(Debug, Default)]
struct Memory {
    /// The parameters by name, with the sequence number of their setting.
    by_name: std::collections::HashMap<String, (u64, zmux::proto::params::TransportParameters)>,
    next: u64,
    /// The most names kept (`None`: no bound).
    capacity: Option<usize>,
}

impl ParameterMemory {
    /// An empty memory that keeps every name.
    pub fn new() -> Self {
        Self::default()
    }

    /// An empty memory that keeps at most `names` names (at least one),
    /// forgetting the one set longest ago to make room.
    pub fn with_capacity(names: usize) -> Self {
        let m = Self::default();
        m.lock().capacity = Some(names.max(1));
        m
    }

    /// The parameters kept for `server_name`.
    pub fn get(&self, server_name: &str) -> Option<zmux::proto::params::TransportParameters> {
        self.lock()
            .by_name
            .get(server_name)
            .map(|(_, tp)| tp.clone())
    }

    /// Keeps `tp` for `server_name`.
    pub fn set(&self, server_name: &str, tp: zmux::proto::params::TransportParameters) {
        let mut m = self.lock();
        let seq = m.next;
        m.next += 1;
        if m.by_name
            .insert(server_name.to_owned(), (seq, tp))
            .is_none()
            && let Some(cap) = m.capacity
            && m.by_name.len() > cap
            && let Some(oldest) = m
                .by_name
                .iter()
                .min_by_key(|(_, (s, _))| *s)
                .map(|(k, _)| k.clone())
        {
            m.by_name.remove(&oldest);
        }
    }

    /// Forgets what is kept for `server_name`.
    pub fn forget(&self, server_name: &str) {
        self.lock().by_name.remove(server_name);
    }

    /// Forgets every name.
    pub fn clear(&self) {
        self.lock().by_name.clear();
    }

    /// The number of names kept.
    pub fn len(&self) -> usize {
        self.lock().by_name.len()
    }

    /// Whether no name is kept.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Memory> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// What became of the 0-RTT data of a session [`connect_with_report`]
/// established, for diagnostics and metrics. Cheap to clone; read it at any
/// time: the outcome is known once the server answered the handshake.
#[derive(Clone, Default)]
pub struct ZeroRtt {
    retry: Option<Arc<Retry>>,
}

impl ZeroRtt {
    /// Whether the session's first records were sent as 0-RTT data (the
    /// options and configuration allowed it, the memory held the server's
    /// parameters and the TLS session was resumed).
    pub fn sent(&self) -> bool {
        self.retry.is_some()
    }

    /// Whether the server accepted the 0-RTT data: `None` when none was
    /// sent, or while the handshake has not completed.
    pub fn accepted(&self) -> Option<bool> {
        self.retry.as_ref().and_then(|r| r.lock().accepted)
    }

    /// Whether the server rejected the 0-RTT data and the session wrote
    /// everything again on a 1-RTT stream (no stream failed: the round
    /// trip 0-RTT would have saved was spent).
    pub fn rewritten(&self) -> bool {
        self.retry.as_ref().is_some_and(|r| r.lock().switched)
    }
}

impl std::fmt::Debug for ZeroRtt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroRtt")
            .field("sent", &self.sent())
            .field("accepted", &self.accepted())
            .field("rewritten", &self.rewritten())
            .finish()
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

    /// With this many lanes the peer may open at once.
    #[must_use]
    pub fn with_lanes(mut self, lanes: u32) -> Self {
        self.lanes = lanes;
        self
    }

    /// With QUIC 0-RTT, the servers' parameters kept in `memory`. A
    /// client sends its first records as 0-RTT data when the session's
    /// configuration allows carrier early data
    /// ([`zmux::EarlyData::carrier_early_data`]) and it resumes a TLS
    /// session with a server whose parameters `memory` holds: such data may
    /// be replayed by an attacker. A server ([`client_config`],
    /// [`server_config`] and [`serve`] with these options) accepts 0-RTT
    /// data only when its listener's configuration allows carrier early
    /// data, and the streams opened in it are replayable until the
    /// handshake completes ([`zmux::RecvStream::is_replayable`]); without
    /// that, 0-RTT data is processed only once the handshake completed,
    /// when it can no longer be a replay. A bootstrap pipe sent in 0-RTT
    /// has no TLS exporter (it exists only once the handshake completed):
    /// authenticate multipath joins with a pre-shared key there.
    #[must_use]
    pub fn with_zero_rtt(mut self, memory: ParameterMemory) -> Self {
        self.zero_rtt = Some(memory);
        self
    }

    /// The connection receive window these options ask for: a stream
    /// window for each lane the peer may open and one for a pipe.
    pub fn receive_window(&self) -> u64 {
        self.stream_window
            .saturating_mul(u64::from(self.lanes) + 1)
            .min(VarInt::MAX.into_inner())
    }

    /// quinn's transport configuration for these options: the stream
    /// receive window, the connection window for the lanes and the lanes
    /// the peer may open; the rest quinn's defaults. Build the endpoint's
    /// client and server configurations with it, so that the window has
    /// one source. The send window stays quinn's (8 stream windows): quinn
    /// reports no unsent count, so zmux's carrier queue limiter paces the
    /// pipe, and a send window below its in-flight cap would cap the pipe's
    /// rate on paths that change.
    pub fn transport_config(&self) -> quinn::TransportConfig {
        let mut t = quinn::TransportConfig::default();
        t.stream_receive_window(VarInt::from_u64(self.stream_window).unwrap_or(VarInt::MAX))
            .receive_window(VarInt::from_u64(self.receive_window()).unwrap_or(VarInt::MAX))
            .max_concurrent_uni_streams(VarInt::from_u32(self.lanes));
        t
    }
}

/// A quinn client configuration from a rustls one: zmux's ALPN
/// identifiers when it has none, and the transport configuration of
/// `options` ([`Options::transport_config`]).
#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
pub fn client_config(
    mut tls: rustls::ClientConfig,
    options: &Options,
) -> Result<quinn::ClientConfig, quinn::crypto::rustls::NoInitialCipherSuite> {
    if tls.alpn_protocols.is_empty() {
        tls.alpn_protocols = zmux::alpn_protocols(&[]);
    }
    if options.zero_rtt.is_some() {
        tls.enable_early_data = true;
    }
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut c = quinn::ClientConfig::new(Arc::new(crypto));
    c.transport_config(Arc::new(options.transport_config()));
    Ok(c)
}

/// A quinn server configuration from a rustls one: zmux's ALPN
/// identifiers when it has none, and the transport configuration of
/// `options` ([`Options::transport_config`]).
///
/// A server that accepts 0-RTT ([`Options::with_zero_rtt`]) has an
/// obligation: clients remember its parameters by its verified server
/// name ([`ParameterMemory`]), not per ticket, so it must keep the
/// mandatory parameters (flow-control limits, `max_record_size` and the
/// others a client may assume) stable across every ticket it issued under
/// that name, and servers sharing the name must share those values. A
/// server that lowers one of them, or cannot tell whether a ticket
/// predates such a change, must reject 0-RTT for those tickets (for all
/// older tickets when it binds no version to them, for example by
/// rotating its ticket keys); it never accepts early data under limits it
/// no longer honours. Raising a value needs nothing.
#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
pub fn server_config(
    mut tls: rustls::ServerConfig,
    options: &Options,
) -> Result<quinn::ServerConfig, quinn::crypto::rustls::NoInitialCipherSuite> {
    if tls.alpn_protocols.is_empty() {
        tls.alpn_protocols = zmux::alpn_protocols(&[]);
    }
    if options.zero_rtt.is_some() {
        // QUIC requires the maximum (RFC 9001 Section 4.6.1).
        tls.max_early_data_size = u32::MAX;
    }
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut c = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    c.transport_config(Arc::new(options.transport_config()));
    Ok(c)
}

/// A carrier over a new connection of `endpoint` (its default client
/// configuration) to `addr`, verified for `server_name`: a stream of the
/// connection, which carries the pipe's lanes and stays open while the
/// pipe is used. For [`zmux::helpers::PipePool`] and [`Session::add_pipe`];
/// to reach the connection itself, make it and its carrier
/// ([`QuicCarrier::new`]) instead.
pub async fn dial(
    endpoint: &Endpoint,
    addr: std::net::SocketAddr,
    server_name: &str,
    options: &Options,
) -> io::Result<PipeIo> {
    let conn = endpoint
        .connect(addr, server_name)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        .await
        .map_err(io::Error::other)?;
    QuicCarrier::new(conn, options.clone()).open_pipe().await
}

/// Establishes a session over a new connection ([`dial`], then
/// [`Session::connect`]). With [`Options::with_zero_rtt`] and carrier
/// early data allowed in `config`, a connection that resumes a TLS session
/// with a server whose parameters the memory holds sends the session's
/// first records as 0-RTT data and returns at once; if the server rejects
/// 0-RTT, the session writes everything again on a new stream once the
/// handshake completed, and no stream fails. Every session it establishes
/// leaves the server's parameters in the memory. [`connect_with_report`]
/// also tells whether 0-RTT was used.
///
/// The whole 0-RTT flow (a client that both sends and allows replay):
///
/// ```no_run
/// # async fn f(endpoint: quinn::Endpoint, addr: std::net::SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
/// use zmux::{Config, EarlyData};
/// use zmux_quinn::{Options, ParameterMemory};
///
/// // One memory for the process; the endpoint's client configuration
/// // comes from `client_config` with the same options (TLS resumption).
/// let options = Options::new().with_zero_rtt(ParameterMemory::with_capacity(1024));
/// let mut config = Config::default();
/// // Only for requests whose effect may happen twice: 0-RTT can be replayed.
/// config.early_data = EarlyData::for_zmux_peer().with_carrier_early_data(true);
///
/// // The first connection learns the server's parameters (1-RTT); later
/// // ones resume TLS and send their first records in 0-RTT.
/// let (session, zero_rtt) =
///     zmux_quinn::connect_with_report(&endpoint, addr, "example.com", &options, config.clone())
///         .await?;
/// let (send, recv) = session.open_bi().await?;
/// // ... write the request, read the response ...
/// # drop((send, recv));
/// println!("0-RTT sent {}, rewritten {}", zero_rtt.sent(), zero_rtt.rewritten());
///
/// // A peer that is not a zmux endpoint processed none of it: retry
/// // without declaring it one.
/// if session.closed().await.is_early_data_rejected() {
///     config.early_data = EarlyData::default();
///     let _again = zmux_quinn::connect(&endpoint, addr, "example.com", &options, config).await?;
/// }
/// # Ok(()) }
/// ```
pub async fn connect(
    endpoint: &Endpoint,
    addr: std::net::SocketAddr,
    server_name: &str,
    options: &Options,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<Session, ConnectError> {
    connect_with_report(endpoint, addr, server_name, options, config)
        .await
        .map(|(session, _)| session)
}

/// [`connect`], also returning what became of its 0-RTT data.
pub async fn connect_with_report(
    endpoint: &Endpoint,
    addr: std::net::SocketAddr,
    server_name: &str,
    options: &Options,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<(Session, ZeroRtt), ConnectError> {
    let config: Arc<zmux::Config> = config.into();
    let io_err = |e: io::Error| ConnectError::Io(Arc::new(e));
    let memory = options
        .zero_rtt
        .clone()
        .filter(|_| config.early_data.carrier_early_data);
    let mut connecting = endpoint
        .connect(addr, server_name)
        .map_err(|e| io_err(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
    if let Some(remembered) = memory.as_ref().and_then(|m| m.get(server_name)) {
        match connecting.into_0rtt() {
            Ok((conn, accepted)) => {
                let carrier = QuicCarrier::new(conn.clone(), options.clone());
                let (send, recv) = conn
                    .open_bi()
                    .await
                    .map_err(|e| io_err(io::Error::other(e)))?;
                let retry = Arc::new(Retry::default());
                let (mut send, mut recv) = (Send::new(send), Recv::new(recv));
                send.retry = Some(retry.clone());
                recv.retry = Some(retry.clone());
                let report = ZeroRtt {
                    retry: Some(retry.clone()),
                };
                let decided = retry.clone();
                let settled = async move {
                    let ok = accepted.await;
                    // After a rejection the pipe goes on on a 1-RTT stream,
                    // from the session's first record written again.
                    let streams = if ok { None } else { conn.open_bi().await.ok() };
                    decided.decide(ok, streams);
                    ok
                };
                let pipe = carrier
                    .inner
                    .pipe(send, recv)
                    .with_early_data(remembered, settled)
                    .with_early_restart(move || retry.switch());
                let wait = config.handshake_timeout;
                let session = Session::connect(pipe, config).await?;
                remember(&session, memory, server_name, wait);
                return Ok((session, report));
            }
            Err(c) => connecting = c,
        }
    }
    let conn = connecting.await.map_err(|e| io_err(io::Error::other(e)))?;
    let pipe = QuicCarrier::new(conn, options.clone())
        .open_pipe()
        .await
        .map_err(io_err)?;
    let wait = config.handshake_timeout;
    let session = Session::connect(pipe, config).await?;
    remember(&session, memory, server_name, wait);
    Ok((session, ZeroRtt::default()))
}

/// Keeps the server's parameters once the session has them (at once when
/// it is established; after the server's parameters arrived for one that
/// returned with early data).
fn remember(
    session: &Session,
    memory: Option<ParameterMemory>,
    server_name: &str,
    wait: std::time::Duration,
) {
    let Some(memory) = memory else {
        return;
    };
    if let Some(tp) = session.parameters_to_remember() {
        memory.set(server_name, tp);
        return;
    }
    let (session, name) = (session.clone(), server_name.to_owned());
    tokio::spawn(async move {
        // Bounded by the handshake timeout; ends with the session.
        let end = tokio::time::Instant::now() + wait;
        while tokio::time::Instant::now() < end && session.close_reason().is_none() {
            if let Some(tp) = session.parameters_to_remember() {
                memory.set(&name, tp);
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    });
}

/// Serves the connections `endpoint` accepts until `listener` is closed or
/// the endpoint is: each is a [`QuicCarrier`] of `listener`
/// ([`QuicCarrier::with_listener`]) for as long as it is open, so that its
/// streams start sessions ([`Listener::accept`]) and join them.
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
            // 0-RTT data is taken before the handshake completes only when
            // the sessions allow carrier early data; otherwise it is
            // processed once the handshake completed.
            let zero_rtt =
                options.zero_rtt.is_some() && listener.config().early_data.carrier_early_data;
            let (conn, handshake) = match incoming.accept() {
                Ok(connecting) if zero_rtt => match connecting.into_0rtt() {
                    Ok((conn, done)) => {
                        let (tx, rx) = tokio::sync::watch::channel(false);
                        tokio::spawn(async move {
                            let _ = done.await;
                            let _ = tx.send(true);
                        });
                        (conn, Some(rx))
                    }
                    Err(connecting) => match connecting.await {
                        Ok(conn) => (conn, None),
                        Err(_) => return listener.count_setup_failure(),
                    },
                },
                Ok(connecting) => match connecting.await {
                    Ok(conn) => (conn, None),
                    Err(_) => return listener.count_setup_failure(),
                },
                Err(_) => return listener.count_setup_failure(),
            };
            let carrier = QuicCarrier::start(conn.clone(), Some(listener), options, handshake);
            // Held while the connection is open: its accept loop serves it.
            conn.closed().await;
            drop(carrier);
        });
    }
}

/// A QUIC connection whose streams carry zmux pipes and lanes (see the
/// crate documentation). Cheap to clone; the accept loop runs while the
/// connection is open and any clone, or any pipe made from it, is alive.
/// Once none is, the loop stops and the carrier's hold on the connection
/// ends: keep a clone while the peer may still open pipes on it.
#[derive(Clone)]
#[must_use = "the accept loop stops once the carrier and its pipes are gone"]
pub struct QuicCarrier {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for QuicCarrier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicCarrier")
            .field("connection", &self.inner.conn.stable_id())
            .finish()
    }
}

struct Inner {
    conn: Connection,
    /// The connection's identity for zmux: this state's allocation.
    id: OnceLock<CarrierConnId>,
    /// The receive window charged to the sessions its pipes carry, without
    /// a listener (0 with one, which is charged instead).
    own_charge: u64,
    /// The connection's ALPN identifier, where the crypto layer reports it.
    alpn: Option<String>,
    exported: [Option<Vec<u8>>; 2],
    /// Streams of pipes the peer opened, without a listener (made pipes
    /// when taken, so that the queue holds no reference to this state).
    accepted: Mutex<Accepted>,
    notify: Notify,
    /// Stops the accept loop when the last handle is gone.
    accept_task: OnceLock<tokio::task::AbortHandle>,
    _charge: Option<MemoryCharge>,
    /// A server connection taken in 0-RTT: true once its handshake
    /// completed; pipes opened before carry replayable data.
    handshake: Option<tokio::sync::watch::Receiver<bool>>,
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

impl QuicCarrier {
    /// The carrier of `conn`, an established connection, without a
    /// listener; its accept loop starts here (inside a tokio runtime). The
    /// peer's pipes go to [`QuicCarrier::accept_pipe`], and the
    /// connection's receive window is charged to the session its pipes
    /// carry. Make one carrier per connection: its lanes are recognised by
    /// it.
    pub fn new(conn: Connection, options: Options) -> Self {
        Self::start(conn, None, options, None)
    }

    /// The carrier of `conn` for `listener`: every stream the peer opens
    /// goes to [`Listener::handle_pipe`], and the connection's receive
    /// window is charged to the listener's budget while the carrier lives.
    pub fn with_listener(conn: Connection, listener: &Listener, options: Options) -> Self {
        Self::start(conn, Some(listener.clone()), options, None)
    }

    fn start(
        conn: Connection,
        listener: Option<Listener>,
        options: Options,
        handshake: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> Self {
        let window = options.receive_window();
        conn.set_receive_window(VarInt::from_u64(window).unwrap_or(VarInt::MAX));
        conn.set_max_concurrent_uni_streams(VarInt::from_u32(options.lanes));
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
            alpn: alpn(&conn),
            exported,
            accepted: Mutex::default(),
            notify: Notify::new(),
            accept_task: OnceLock::new(),
            _charge: listener.as_ref().map(|l| l.charge_memory(window)),
            handshake,
        });
        let _ = inner.id.set(CarrierConnId::new(&inner));
        let task = tokio::spawn(accept_loop(conn, Arc::downgrade(&inner), listener));
        let _ = inner.accept_task.set(task.abort_handle());
        Self { inner }
    }

    /// The QUIC connection, for its own features (datagrams, statistics,
    /// path, close). Its streams belong to zmux.
    pub fn connection(&self) -> &Connection {
        &self.inner.conn
    }

    /// A new pipe on a bidirectional stream of the connection: the
    /// bootstrap carrier of a session this endpoint starts, or a pipe it
    /// joins. Waits for the peer's stream credit.
    pub async fn open_pipe(&self) -> io::Result<PipeIo> {
        let (send, recv) = self.inner.conn.open_bi().await.map_err(io::Error::other)?;
        Ok(self.inner.pipe(Send::new(send), Recv::new(recv)))
    }

    /// The next pipe the peer opened, on a carrier without a listener (for
    /// [`Session::accept`]); `None` once the connection is closed.
    /// With a listener, the listener takes them. Pipes nobody takes wait,
    /// as many as the connection lets the peer open bidirectional streams
    /// (QUIC MAX_STREAMS): an endpoint that never accepts pipes sets that
    /// to zero in its transport configuration.
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
        let io = PipeIo::from_halves(recv, send)
            .with_carrier_conn(self.id())
            .with_connection_memory(self.own_charge);
        let io = match &self.alpn {
            Some(a) => io.with_protocol(a.clone()),
            None => io,
        };
        let io = match self.handshake.clone().filter(|h| !*h.borrow()) {
            // Opened in 0-RTT: replayable until the handshake completes.
            Some(mut h) => io.with_early_data_in(async move {
                let _ = h.wait_for(|done| *done).await;
            }),
            None => io,
        };
        io.with_lane_opener(move || {
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

/// The ALPN identifier the connection negotiated, with quinn's rustls
/// crypto layer.
fn alpn(conn: &Connection) -> Option<String> {
    #[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
    {
        let data = conn.handshake_data()?;
        let data = data
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .ok()?;
        data.protocol
            .map(|p| String::from_utf8_lossy(&p).into_owned())
    }
    #[cfg(not(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs")))]
    {
        let _ = conn;
        None
    }
}

/// Hands every stream the peer opens to zmux until the connection closes
/// or the carrier is gone.
async fn accept_loop(conn: Connection, inner: Weak<Inner>, listener: Option<Listener>) {
    let hint = || PipeHint::from_addr(conn.remote_address().ip());
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
                let io = PipeIo::reader(recv).with_carrier_conn(inner.id());
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
    Bi(quinn::SendStream, quinn::RecvStream),
    Uni(quinn::RecvStream),
}

/// An accepted stream, wrapped.
enum Incoming {
    Bi(Send, Recv),
    Uni(Recv),
}

/// `ZMUX_CARRIER_FAILED` as a QUIC application error code.
fn carrier_failed() -> VarInt {
    VarInt::from_u64(ApplicationErrorCode::ZMUX_CARRIER_FAILED.0).unwrap_or(VarInt::MAX)
}

/// A stream's sending part: ended gracefully by `poll_shutdown` (FIN),
/// reset with `ZMUX_CARRIER_FAILED` when dropped otherwise; a pipe's keeps
/// its carrier alive.
struct Send {
    stream: quinn::SendStream,
    finished: bool,
    keep: Option<Arc<Inner>>,
    /// The bootstrap stream of a 0-RTT connection: replaced if the server
    /// rejects 0-RTT.
    retry: Option<Arc<Retry>>,
}

impl Send {
    fn new(stream: quinn::SendStream) -> Self {
        Self {
            stream,
            finished: false,
            keep: None,
            retry: None,
        }
    }

    /// One write, moving to the 1-RTT stream after a 0-RTT rejection.
    fn write_one(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        loop {
            if let Some(r) = &self.retry
                && let Some(next) = r.take(|s| s.send.take())
            {
                self.stream = next;
                self.retry = None;
            }
            match AsyncWrite::poll_write(Pin::new(&mut self.stream), cx, buf) {
                Poll::Ready(Err(e)) => match &self.retry {
                    Some(r) => match r.after_error(cx, true) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(After::Again) => continue,
                        Poll::Ready(After::Swallow) => return Poll::Ready(Ok(buf.len())),
                        Poll::Ready(After::Fail) => return Poll::Ready(Err(e)),
                    },
                    None => return Poll::Ready(Err(e)),
                },
                other => return other,
            }
        }
    }
}

/// The streams of a 0-RTT bootstrap pipe: when the server rejects 0-RTT,
/// nothing written reached it, and the pipe goes on on a new 1-RTT stream
/// (zmux writes everything again).
#[derive(Default)]
struct Retry {
    st: Mutex<RetryState>,
}

#[derive(Default)]
struct RetryState {
    /// Whether the server accepted 0-RTT, once known.
    accepted: Option<bool>,
    /// After a rejection: the session started writing again, so the pipe
    /// is on the 1-RTT stream from now on.
    switched: bool,
    send: Option<quinn::SendStream>,
    recv: Option<quinn::RecvStream>,
    wakers: Vec<std::task::Waker>,
}

impl Retry {
    fn lock(&self) -> std::sync::MutexGuard<'_, RetryState> {
        self.st.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The outcome, with the 1-RTT stream after a rejection.
    fn decide(&self, accepted: bool, streams: Option<(quinn::SendStream, quinn::RecvStream)>) {
        let wakers = {
            let mut st = self.lock();
            st.accepted = Some(accepted);
            if let Some((s, r)) = streams {
                st.send = Some(s);
                st.recv = Some(r);
            }
            std::mem::take(&mut st.wakers)
        };
        for w in wakers {
            w.wake();
        }
    }

    /// The session writes again from its first record: from now on the
    /// pipe is the 1-RTT stream, or fails without one.
    fn switch(&self) -> io::Result<()> {
        let wakers = {
            let mut st = self.lock();
            if st.switched {
                return Ok(());
            }
            if st.send.is_none() || st.recv.is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "no 1-RTT stream after the 0-RTT rejection",
                ));
            }
            st.switched = true;
            std::mem::take(&mut st.wakers)
        };
        for w in wakers {
            w.wake();
        }
        Ok(())
    }

    /// The 1-RTT half, once the pipe switched to it.
    fn take<T>(&self, f: impl FnOnce(&mut RetryState) -> Option<T>) -> Option<T> {
        let mut st = self.lock();
        if st.switched { f(&mut st) } else { None }
    }

    /// After an error on the 0-RTT stream (`write`: of a write): what
    /// follows. `Again` once the pipe switched, `Swallow` for a write after
    /// a rejection and before the switch (what the session wrote then is
    /// written again from its start), `Fail` when the error stands;
    /// otherwise wait.
    fn after_error(&self, cx: &mut Context<'_>, write: bool) -> Poll<After> {
        let mut st = self.lock();
        match (st.accepted, st.switched) {
            (Some(true), _) => Poll::Ready(After::Fail),
            (Some(false), true) => Poll::Ready(if st.send.is_some() || st.recv.is_some() {
                After::Again
            } else {
                After::Fail
            }),
            (Some(false), false) if write => Poll::Ready(After::Swallow),
            _ => {
                st.wakers.push(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

/// What follows an error on a 0-RTT stream.
enum After {
    Again,
    Swallow,
    Fail,
}

impl AsyncWrite for Send {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_one(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.stream), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let r = AsyncWrite::poll_shutdown(Pin::new(&mut self.stream), cx);
        if r.is_ready() {
            self.finished = true;
        }
        r
    }

    /// Each slice in turn until the stream takes less (one lock of the
    /// connection per slice; quinn copies them anyway).
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut written = 0;
        for b in bufs.iter().filter(|b| !b.is_empty()) {
            match self.write_one(cx, b) {
                Poll::Ready(Ok(n)) => {
                    written += n;
                    if n < b.len() {
                        break;
                    }
                }
                Poll::Ready(Err(e)) if written == 0 => return Poll::Ready(Err(e)),
                Poll::Pending if written == 0 => return Poll::Pending,
                Poll::Ready(Err(_)) | Poll::Pending => break,
            }
        }
        Poll::Ready(Ok(written))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

/// A stream's receiving part: stopped with `ZMUX_CARRIER_FAILED` when
/// dropped before its end; a pipe's keeps its carrier alive.
struct Recv {
    stream: quinn::RecvStream,
    keep: Option<Arc<Inner>>,
    retry: Option<Arc<Retry>>,
}

impl Recv {
    fn new(stream: quinn::RecvStream) -> Self {
        Self {
            stream,
            keep: None,
            retry: None,
        }
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
        loop {
            if let Some(r) = &self.retry
                && let Some(next) = r.take(|s| s.recv.take())
            {
                self.stream = next;
                self.retry = None;
            }
            match AsyncRead::poll_read(Pin::new(&mut self.stream), cx, buf) {
                Poll::Ready(Err(e)) => match &self.retry {
                    Some(r) => match r.after_error(cx, false) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(After::Again) => continue,
                        Poll::Ready(After::Swallow | After::Fail) => return Poll::Ready(Err(e)),
                    },
                    None => return Poll::Ready(Err(e)),
                },
                other => return other,
            }
        }
    }
}
