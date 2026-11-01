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
//! Nothing is answered on a request before its carrier is accepted
//! ([`serve_connection`]): by an admission ([`ListenerConfig::admission`](zmux::ListenerConfig::admission)) on the
//! first bytes of its body, or else by the listener's first write or its
//! taking the carrier. Requests that carry no pipe go to
//! [`Options::fallback`]. A client writes the prefix of its credential,
//! such as a prefix authentication token, first on each request body
//! ([`Options::credential`]).
//!
//! What the carriers have:
//!
//! - HTTP Datagrams (RFC 9297) of their request streams, as the datagram
//!   channel of the pipe (EXTENSIONS.md Section 6.8): a session with
//!   datagrams enabled sends each datagram that fits one there rather than
//!   in a record when the peer negotiated it. Both ends enable HTTP
//!   Datagrams (`SETTINGS_H3_DATAGRAM`), and a pipe's channel is usable
//!   once the peer's SETTINGS enabled them too; each HTTP Datagram, a QUIC
//!   datagram that starts with the request stream's Quarter Stream ID,
//!   carries the DATAGRAM frame alone. One receive loop per connection
//!   routes them to its pipes ([`ConnectionDatagrams`]), so
//!   the HTTP Datagrams of a connection that carries pipes belong to zmux;
//! - the TLS 1.3 exporter of the QUIC connection (RFC 9001 Section 4), for
//!   [`zmux::PipeAuth::tls`] and carrier-bound joins (MULTIPATH.md Section
//!   10.5); behind a front end that terminates TLS the two ends export
//!   different values, so such deployments use a PSK (MULTIPATH.md);
//! - a connection receive window sized for the lanes ([`Options`]),
//!   charged to the memory budget: the client's to the zmux session its
//!   pipes carry, the server's to the listener's while the connection is
//!   served;
//! - failure signalling: a sent body dropped without ending it is reset
//!   with `ZMUX_CARRIER_FAILED`; a dropped received body is cancelled by
//!   the transport with STOP_SENDING(0). Either signals a failure; a request, its
//!   response or the connection that fails under a pipe is a failure of
//!   the pipe, and only the end of a body is its graceful end.
//!
//! The QUIC endpoints carry the HTTP/3 ALPN identifier `h3` ([`ALPN`]),
//! which names the HTTP layer; zmux's own identifiers do not apply.
//! [`client_config`] and [`server_config`] set it and the transport
//! configuration ([`Options::transport_config`]).
//!
//! Each body write hands the HTTP/3 stream the session's buffers as they
//! are, as one DATA frame (payloads are not copied), and at most one
//! such write is in flight per body: a write returns once the
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
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h3::ConnectionState;
use h3::client::SendRequest;
#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
use quinn::rustls;
use quinn::{Connection, Endpoint, VarInt};
use tokio::io::{AsyncRead, ReadBuf};
use zmux::carrier::{CarrierConnId, ChunkBuf, ChunkWrite};
use zmux::proto::ApplicationErrorCode;
use zmux::proto::keys::{EXPORTER_PIPE_LABEL, EXPORTER_SESSION_LABEL};
use zmux::{Admit, ConnectError, Credential, Entry, Listener, PipeHint, PipeIo, Session};
pub use zmux_quinn::LaneWindows;
use zmux_quinn::{ConnectionDatagrams, QuicChannel};

/// The HTTP/3 ALPN identifier, which the QUIC endpoints must carry.
pub const ALPN: &[u8] = b"h3";

type ClientSend = h3::client::RequestStream<h3_quinn::SendStream<ChunkBuf>, ChunkBuf>;
type ClientRecv = h3::client::RequestStream<h3_quinn::RecvStream, ChunkBuf>;
/// The sending half of a server's request stream: the response.
pub type ServerSend = h3::server::RequestStream<h3_quinn::SendStream<ChunkBuf>, ChunkBuf>;
/// The receiving half of a server's request stream: the request body.
pub type ServerRecv = h3::server::RequestStream<h3_quinn::RecvStream, ChunkBuf>;

/// The adapter's options: how the carriers size the connection's flow
/// control for lanes, and the fallback of requests.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct Options {
    /// The windows; [`LaneWindows::lanes`] is the lanes that may be
    /// blocked at once. Lanes are requests, so the requests the peer may
    /// open at once (quinn's `max_concurrent_bidi_streams`) bound them too.
    pub windows: LaneWindows,
    /// Server: the handler of the requests that carry no pipe: those the
    /// listener's admission hands to the fallback and those the listener does not
    /// take (none by default: such requests are answered with 404).
    pub fallback: Option<H3Fallback>,
    /// Client: the credential whose prefix ([`Credential::prefix`], given
    /// the connection's [`zmux_quinn::Handshake::carrier_info`]) is written
    /// first on each request body that carries a pipe or a lane, for a
    /// server with an admission ([`zmux::ListenerConfig::admission`]; none
    /// by default).
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

    /// Serves the requests that carry no pipe with `fallback`.
    #[must_use]
    pub fn with_fallback(mut self, fallback: H3Fallback) -> Self {
        self.fallback = Some(fallback);
        self
    }

    /// Writes the prefix of `credential` first on each request body.
    #[must_use]
    pub fn with_credential(mut self, credential: Arc<dyn Credential>) -> Self {
        self.credential = Some(credential);
        self
    }

    /// quinn's transport configuration for these options: the windows
    /// ([`LaneWindows::transport_config`]); the rest quinn's defaults.
    /// Build the endpoints' client and server configurations with it.
    pub fn transport_config(&self) -> quinn::TransportConfig {
        self.windows.transport_config()
    }
}

/// A quinn client configuration from a rustls one: the ALPN identifier
/// `h3` when it has none, and the transport configuration of `options`
/// ([`Options::transport_config`]).
#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
pub fn client_config(
    mut tls: rustls::ClientConfig,
    options: &Options,
) -> Result<quinn::ClientConfig, quinn::crypto::rustls::NoInitialCipherSuite> {
    zmux::default_alpn(&mut tls.alpn_protocols, || vec![ALPN.to_vec()]);
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut c = quinn::ClientConfig::new(Arc::new(crypto));
    c.transport_config(Arc::new(options.transport_config()));
    Ok(c)
}

/// A quinn server configuration from a rustls one: the ALPN identifier
/// `h3` when it has none, and the transport configuration of `options`
/// ([`Options::transport_config`]). Early data is refused
/// (`max_early_data_size` 0): no request is taken from it.
#[cfg(any(feature = "rustls-ring", feature = "rustls-aws-lc-rs"))]
pub fn server_config(
    mut tls: rustls::ServerConfig,
    options: &Options,
) -> Result<quinn::ServerConfig, quinn::crypto::rustls::NoInitialCipherSuite> {
    zmux::default_alpn(&mut tls.alpn_protocols, || vec![ALPN.to_vec()]);
    tls.max_early_data_size = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut c = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    c.transport_config(Arc::new(options.transport_config()));
    Ok(c)
}

/// The HTTP Datagrams of the request stream `stream_id` as its pipe's
/// datagram channel: QUIC datagrams of the connection that start with the
/// Quarter Stream ID, usable while `peer_enabled` (the peer's SETTINGS).
fn h3_channel(
    datagrams: &Arc<ConnectionDatagrams>,
    stream_id: u64,
    peer_enabled: Box<dyn Fn() -> bool + Send + Sync>,
) -> Arc<QuicChannel> {
    datagrams.channel_when(stream_id / 4, Some(peer_enabled))
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
    send: SendRequest<h3_quinn::OpenStreams, ChunkBuf>,
    uri: http::Uri,
    /// The connection's identity for zmux: this state's allocation.
    id: OnceLock<CarrierConnId>,
    exported: [Option<Vec<u8>>; 2],
    window: u64,
    /// The credential of each request, and the connection's handshake it
    /// is given.
    credential: Option<(Arc<dyn Credential>, zmux_quinn::Handshake)>,
    driver: tokio::task::AbortHandle,
    /// The connection's HTTP Datagrams, the channels of its pipes.
    datagrams: Arc<ConnectionDatagrams>,
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
    /// With [`Options::credential`], each request body starts with its
    /// prefix.
    pub async fn new(conn: Connection, uri: http::Uri, options: &Options) -> io::Result<Self> {
        let credential = options
            .credential
            .clone()
            .map(|c| (c, zmux_quinn::Handshake::of(&conn)));
        let window = options.windows.receive_window();
        conn.set_receive_window(VarInt::from_u64(window).unwrap_or(VarInt::MAX));
        let (mut driver, send) = h3::client::builder()
            .enable_datagram(true)
            .build::<_, _, ChunkBuf>(h3_quinn::Connection::new(conn.clone()))
            .await
            .map_err(h3_error)?;
        let driver = tokio::spawn(async move {
            let _ = poll_fn(|cx| driver.poll_close(cx)).await;
        })
        .abort_handle();
        let inner = Arc::new(ClientInner {
            datagrams: ConnectionDatagrams::new(conn.clone()),
            exported: exported(&conn),
            conn,
            send,
            uri,
            id: OnceLock::new(),
            window,
            credential,
            driver,
        });
        let _ = inner.id.set(CarrierConnId::new(&inner));
        Ok(Self { inner })
    }

    /// The QUIC connection, for its own features (statistics, path,
    /// close).
    pub fn connection(&self) -> &Connection {
        &self.inner.conn
    }

    /// The connection's HTTP Datagrams as the datagram channels of its
    /// pipes: [`ConnectionDatagrams::dropped`] counts those that named no
    /// pipe.
    pub fn datagrams(&self) -> &Arc<ConnectionDatagrams> {
        &self.inner.datagrams
    }

    /// A new pipe on a request of the connection: the bootstrap carrier of
    /// a session this endpoint starts, or a pipe it joins. Returns once the
    /// request was sent (its response is awaited by the pipe's reads).
    pub async fn open_pipe(&self) -> io::Result<PipeIo> {
        let inner = &self.inner;
        let (send, recv) = inner.request().await?;
        let settings = inner.send.clone();
        let channel = h3_channel(
            &inner.datagrams,
            recv.id().into_inner(),
            Box::new(move || settings.settings().enable_datagram()),
        );
        let opener = inner.clone();
        let (r, w) = paired(
            BodyReader::client(recv, inner.clone()),
            BodyWriter::new(SendHalf::Client(send), Some(inner.clone())),
        );
        let io = PipeIo::from_chunk_halves(r, w)
            .with_carrier(zmux::CarrierKind::Http3)
            .with_connection_memory(inner.window)
            .with_datagram_channel(channel)
            .with_chunk_lane_opener(move || {
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

    /// A new request: its body, the credential's prefix first, and its
    /// response's.
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
        let (mut send, recv) = stream.split();
        if let Some((credential, handshake)) = &self.credential {
            let prefix = credential.prefix(&handshake.carrier_info(&self.conn))?;
            let mut data = ChunkBuf::new();
            data.take_from(&mut [Bytes::from(prefix)]);
            send.send_data(data).await.map_err(h3_error)?;
        }
        Ok((send, recv))
    }
}

/// A carrier over a new HTTP/3 connection of `endpoint` (its default
/// client configuration, with the ALPN identifier `h3`: [`client_config`])
/// to `addr`, verified for the host of `uri`: a request to `uri`. For
/// [`zmux::helpers::PipePool`] and [`Session::add_pipe`]; to open more pipes
/// on one connection, make an [`H3Client`] instead.
pub async fn dial(
    endpoint: &Endpoint,
    addr: SocketAddr,
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
    addr: SocketAddr,
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
/// its own), their QUIC handshakes within the listener's limits
/// ([`Listener::serve_connections`]; a failed one counts as a setup
/// failure, the requests then entering the listener one by one).
pub async fn serve(listener: Listener, endpoint: Endpoint, options: Options) {
    let l = listener.clone();
    let endpoint = &endpoint;
    l.serve_connections(
        move || async move { endpoint.accept().await.map(Ok) },
        |incoming: quinn::Incoming| {
            let guard = listener.setup_guard();
            async move {
                let conn = incoming.await?;
                guard.done();
                Ok::<_, io::Error>(conn)
            }
        },
        move |listener, conn: Connection| {
            let options = options.clone();
            async move {
                let _ = serve_connection(&listener, conn, &options).await;
            }
        },
    )
    .await;
}

/// Serves one HTTP/3 connection (the ALPN identifier `h3`) until it ends:
/// every request is a carrier of the connection for
/// [`Listener::handle_pipe`], its body and its response's the two
/// directions. The connection's receive window is set for the lanes and
/// charged to the listener's budget meanwhile.
///
/// Each request takes its source slot ([`Listener::enter`]; the source is
/// the client a trusted intermediary reports in a forwarding header
/// field, else the connection's peer); refused, it goes to
/// [`Options::fallback`] untouched.
/// Nothing is answered before the carrier is accepted:
///
/// - With the listener's admission ([`zmux::ListenerConfig::admission`]),
///   up to its `peek` bytes of the request
///   body are read first, within its peek timeout, and decided on with the
///   request's head (`&http::request::Parts` as the
///   [`zmux::CarrierInfo::with_request`] value) and the connection's
///   metadata ([`zmux_quinn::Handshake::carrier_info`]). `Accept(k)`
///   answers 200 and hands the carrier to the listener, the prefix after
///   `k` bytes in front; `Fallback` hands the request to
///   [`Options::fallback`] with every byte read ([`FallbackRequest`]), or
///   answers 404 without one; `Stall` reads and discards the body for a
///   stall's duration (or until it ends) and then resets the request
///   without a response; `Close` resets it at once.
/// - Without, 200 is answered when the listener first writes on the
///   carrier or has taken it (a lane, which it never writes on); a
///   carrier the listener does not take, with nothing written, goes to
///   [`Options::fallback`] (the body bytes the listener read are not
///   given back), or is answered with 404.
///
/// The connection's handshake is complete before its requests are read:
/// no request is taken from early data.
pub async fn serve_connection(
    listener: &Listener,
    conn: Connection,
    options: &Options,
) -> io::Result<()> {
    let window = options.windows.receive_window();
    conn.set_receive_window(VarInt::from_u64(window).unwrap_or(VarInt::MAX));
    let _charge = listener.charge_memory(window);
    let identity = Arc::new(conn.stable_id());
    let shared = Arc::new(Served {
        datagrams: ConnectionDatagrams::new(conn.clone()),
        listener: listener.clone(),
        id: CarrierConnId::new(&identity),
        exported: exported(&conn),
        handshake: zmux_quinn::Handshake::of(&conn),
        conn: conn.clone(),
        fallback: options.fallback.clone(),
    });
    let mut h3 = h3::server::builder()
        .enable_datagram(true)
        .build::<_, ChunkBuf>(h3_quinn::Connection::new(conn.clone()))
        .await
        .map_err(h3_error)?;
    while let Some(resolver) = h3.accept().await.map_err(h3_error)? {
        let shared = shared.clone();
        tokio::spawn(async move {
            let Ok((head, stream)) = resolver.resolve_request().await else {
                return;
            };
            let (mut send, recv) = stream.split();
            if zmux::forwarded_early_data(
                head.headers()
                    .iter()
                    .map(|(n, v)| (n.as_str(), v.as_bytes())),
            ) {
                // Forwarded from TLS early data: no carrier is taken from
                // it.
                shared.listener.count_setup_failure();
                let mut resp = http::Response::new(());
                *resp.status_mut() = http::StatusCode::TOO_EARLY;
                if send.send_response(resp).await.is_ok() {
                    let _ = send.finish().await;
                }
                return;
            }
            let peer = shared.conn.remote_address();
            let source = shared.source(head.headers());
            let Some(entry) = shared.listener.enter(peer, Some(source)) else {
                // Not taken, nothing answered: to the fallback.
                shared.fall_back(head, Bytes::new(), send, recv).await;
                return;
            };
            if shared.listener.admission().is_some() {
                shared.admit(entry, head, send, recv).await;
            } else {
                shared.serve_unadmitted(entry, head, send, recv).await;
            }
        });
    }
    Ok(())
}

/// What the requests of one served connection share.
struct Served {
    listener: Listener,
    id: CarrierConnId,
    exported: [Option<Vec<u8>>; 2],
    handshake: zmux_quinn::Handshake,
    conn: Connection,
    fallback: Option<H3Fallback>,
    /// The connection's HTTP Datagrams, the channels of its pipes.
    datagrams: Arc<ConnectionDatagrams>,
}

impl Served {
    /// The datagram channel of the pipe on request `send`: usable when the
    /// client's SETTINGS, which precede its requests, enabled HTTP
    /// Datagrams.
    fn channel(&self, send: &ServerSend) -> Arc<QuicChannel> {
        let enabled = send.settings().enable_datagram();
        h3_channel(
            &self.datagrams,
            send.send_id().into_inner(),
            Box::new(move || enabled),
        )
    }

    /// The source of a request with `headers`: the client a trusted
    /// intermediary reports in its forwarding header field
    /// ([`zmux::TrustedProxies::source`]), else the connection's peer.
    fn source(&self, headers: &http::HeaderMap) -> SocketAddr {
        self.listener.trusted_proxies().source(
            self.conn.remote_address(),
            headers.iter().map(|(n, v)| (n.as_str(), v.as_bytes())),
        )
    }

    async fn handle(&self, io: PipeIo, entry: Entry) {
        let _ = self
            .listener
            .handle_pipe(
                with_connection(io, self.id.clone(), &self.exported),
                PipeHint::from_entry(entry),
            )
            .await;
    }

    /// A request the listener does not get: to the fallback, or 404.
    async fn fall_back(
        &self,
        head: http::Request<()>,
        prefix: Bytes,
        mut send: ServerSend,
        recv: ServerRecv,
    ) {
        match &self.fallback {
            Some(f) => {
                let peer = self.source(head.headers());
                f.serve(FallbackRequest {
                    head,
                    prefix,
                    send,
                    recv,
                    peer,
                })
                .await;
            }
            None => {
                let mut resp = http::Response::new(());
                *resp.status_mut() = http::StatusCode::NOT_FOUND;
                if send.send_response(resp).await.is_ok() {
                    let _ = send.finish().await;
                }
            }
        }
    }

    /// The admission of one request ([`serve_connection`]).
    async fn admit(
        &self,
        mut entry: Entry,
        head: http::Request<()>,
        mut send: ServerSend,
        recv: ServerRecv,
    ) {
        let mut reader = BodyReader::server(recv);
        let prefix = entry.read_prefix(&mut reader).await;
        let (parts, ()) = head.into_parts();
        let admit = {
            let info = self
                .handshake
                .carrier_info(&self.conn)
                .with_request(&parts)
                .with_headers(|| {
                    parts
                        .headers
                        .iter()
                        .map(|(n, v)| (n.as_str(), v.as_bytes()))
                });
            entry.decide(info, prefix).await
        };
        match admit {
            Admit::Accept(rest) => {
                if send.send_response(http::Response::new(())).await.is_err() {
                    return;
                }
                let channel = self.channel(&send);
                let (r, w) = paired(reader, BodyWriter::new(SendHalf::Server(send), None));
                self.handle(
                    PipeIo::from_chunk_halves(r, w)
                        .with_carrier(zmux::CarrierKind::Http3)
                        .with_prefix(rest)
                        .with_datagram_channel(channel),
                    entry,
                )
                .await;
            }
            Admit::Fallback(prefix) => {
                drop(entry);
                let (recv, held) = reader.into_server();
                let mut replay = prefix;
                replay.extend_from_slice(&held);
                self.fall_back(
                    http::Request::from_parts(parts, ()),
                    replay.into(),
                    send,
                    recv,
                )
                .await;
            }
            Admit::Stall => {
                entry.stall(Some(&mut reader)).await;
                send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            }
            _ => send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED),
        }
    }

    /// A request without admission ([`serve_connection`]).
    async fn serve_unadmitted(
        &self,
        mut entry: Entry,
        head: http::Request<()>,
        send: ServerSend,
        recv: ServerRecv,
    ) {
        // Without an admission, accepted at once.
        let _ = entry.decide(zmux::CarrierInfo::new(), Vec::new()).await;
        let channel = self.channel(&send);
        let answer = Arc::new(Answer::new(send));
        let mut reader = BodyReader::server(recv);
        reader.answer = Some(answer.clone());
        let (r, w) = paired(reader, BodyWriter::unanswered(answer.clone()));
        let taken = answer.clone();
        let io = PipeIo::from_chunk_halves(r, w)
            .with_carrier(zmux::CarrierKind::Http3)
            .with_taken(move || Answer::taken(taken))
            .with_datagram_channel(channel);
        self.handle(io, entry).await;
        if let Some((send, recv)) = answer.reclaim() {
            self.fall_back(head, Bytes::new(), send, recv).await;
        }
    }
}

/// A request [`serve_connection`] hands to [`Options::fallback`]: the
/// request head, the bytes of its body read before (`prefix`, to be
/// replayed in front of the rest of `recv`), its two halves, and the
/// client's address. No response was sent on `send`.
#[non_exhaustive]
pub struct FallbackRequest {
    /// The request head.
    pub head: http::Request<()>,
    /// The body bytes read before.
    pub prefix: Bytes,
    /// The response half.
    pub send: ServerSend,
    /// The rest of the request body.
    pub recv: ServerRecv,
    /// The client's address: the one a trusted intermediary reports in its
    /// forwarding header field ([`zmux::ListenerConfig::trusted_proxies`]),
    /// else the connection's peer.
    pub peer: SocketAddr,
}

impl std::fmt::Debug for FallbackRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FallbackRequest")
            .field("head", &self.head)
            .field("prefix", &self.prefix.len())
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

type FallbackFn = dyn Fn(FallbackRequest) -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync;

/// The handler of the requests that carry no pipe ([`Options::fallback`]).
/// Cheap to clone.
#[derive(Clone)]
pub struct H3Fallback(Arc<FallbackFn>);

impl std::fmt::Debug for H3Fallback {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("H3Fallback(..)")
    }
}

impl H3Fallback {
    /// The handler `f`.
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(FallbackRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        Self(Arc::new(move |r| Box::pin(f(r))))
    }

    /// Serves `req`.
    pub async fn serve(&self, req: FallbackRequest) {
        let handler = &self.0;
        handler(req).await;
    }
}

/// The response of a request served without admission, sent at most once:
/// when the carrier's writer first writes, or when the listener has taken
/// the carrier. Until then the sending half waits here, and the receiving
/// half returns here when its reader is dropped, so that a carrier nobody
/// committed to can go to the fallback ([`Answer::reclaim`]).
struct Answer {
    send: tokio::sync::Mutex<Option<Box<SendHalf>>>,
    recv: Mutex<Option<ServerRecv>>,
    /// The writer started, the listener took the carrier, or it was
    /// reclaimed.
    committed: AtomicBool,
    responded: AtomicBool,
}

impl Answer {
    fn new(send: ServerSend) -> Self {
        Self {
            send: tokio::sync::Mutex::new(Some(Box::new(SendHalf::Server(send)))),
            recv: Mutex::new(None),
            committed: AtomicBool::new(false),
            responded: AtomicBool::new(false),
        }
    }

    /// Sends the response on `half`, once per request.
    async fn respond(&self, half: &mut SendHalf) -> io::Result<()> {
        if self.responded.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        half.respond().await.map_err(h3_error)
    }

    /// The listener took the carrier: the response is sent now.
    fn taken(this: Arc<Self>) {
        this.committed.store(true, Ordering::Release);
        tokio::spawn(async move {
            let mut slot = this.send.lock().await;
            if let Some(half) = slot.as_mut() {
                let _ = this.respond(half).await;
            }
        });
    }

    /// The sending half for the writer, the response sent.
    async fn take(this: Arc<Self>) -> io::Result<Box<SendHalf>> {
        let half = this.send.lock().await.take();
        let Some(half) = half else {
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        let mut guard = ResetOnDrop(Some(half));
        this.respond(guard.half()).await?;
        Ok(guard.release())
    }

    /// Both halves, when nothing committed to the carrier.
    fn reclaim(&self) -> Option<(ServerSend, ServerRecv)> {
        if self.committed.swap(true, Ordering::AcqRel) {
            return None;
        }
        let send = self.send.try_lock().ok()?.take()?;
        let recv = self
            .recv
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()?;
        match *send {
            SendHalf::Server(s) => Some((s, recv)),
            SendHalf::Client(_) => None,
        }
    }
}

impl Drop for Answer {
    fn drop(&mut self) {
        // A half nobody took fails, as a dropped body does.
        if let Some(h) = self.send.get_mut().as_mut() {
            h.reset();
        }
    }
}

// ---- bodies -----------------------------------------------------------------

/// A request or response body being sent.
enum SendHalf {
    Client(ClientSend),
    Server(ServerSend),
}

impl SendHalf {
    async fn send(&mut self, data: ChunkBuf) -> Result<(), h3::error::StreamError> {
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

    async fn respond(&mut self) -> Result<(), h3::error::StreamError> {
        match self {
            Self::Client(_) => Ok(()),
            Self::Server(s) => s.send_response(http::Response::new(())).await,
        }
    }

    fn reset(&mut self) {
        match self {
            Self::Client(s) => s.stop_stream(carrier_failed()),
            Self::Server(s) => s.stop_stream(carrier_failed()),
        }
    }
}

/// Resets the half it holds when dropped unreleased: a write or end
/// cancelled with its body (a QUIC stream dropped otherwise would end
/// gracefully).
struct ResetOnDrop(Option<Box<SendHalf>>);

impl ResetOnDrop {
    fn half(&mut self) -> &mut SendHalf {
        self.0.as_mut().expect("held until released")
    }

    fn release(mut self) -> Box<SendHalf> {
        self.0.take().expect("held until released")
    }
}

impl Drop for ResetOnDrop {
    fn drop(&mut self) {
        if let Some(h) = self.0.as_mut() {
            h.reset();
        }
    }
}

/// What a write or the end of a body gives back: the half and the outcome.
type OpDone = (Box<SendHalf>, Result<(), h3::error::StreamError>);

/// A write or the end of a body in progress, owning the half until done.
type Op = Pin<Box<dyn Future<Output = OpDone> + Send>>;

/// The sending half, idle or in a write (boxed: it moves in and out of
/// the write).
enum Sending {
    /// A server's half before its response ([`Answer`]).
    Unanswered(Arc<Answer>),
    /// The response being sent.
    Answering(Pin<Box<dyn Future<Output = io::Result<Box<SendHalf>>> + Send>>),
    Idle(Box<SendHalf>),
    Busy(Op),
    /// Lost to a panicking write.
    Gone,
}

/// A body as the sending half of a carrier: each write takes the buffers
/// it is given as one DATA frame without copying them, at most one
/// write in flight, driven by the next call (the session flushes
/// after writing); `poll_shutdown` ends the body (FIN), and a body dropped
/// otherwise is reset with `ZMUX_CARRIER_FAILED`, also with a write in
/// flight, with or without a runtime.
struct BodyWriter {
    sending: Sending,
    /// The end of the body is in flight.
    finishing: bool,
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
            sending: Sending::Idle(Box::new(half)),
            finishing: false,
            finished: false,
            ended_gracefully: Arc::default(),
            _keep: keep,
            response: None,
        }
    }

    /// A server's half that sends its response before its first write.
    fn unanswered(answer: Arc<Answer>) -> Self {
        Self {
            sending: Sending::Unanswered(answer),
            finishing: false,
            finished: false,
            ended_gracefully: Arc::default(),
            _keep: None,
            response: None,
        }
    }

    /// Sends the response first, when it is still to be sent.
    fn poll_answer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match &mut self.sending {
                Sending::Unanswered(a) => {
                    let a = a.clone();
                    a.committed.store(true, Ordering::Release);
                    self.sending = Sending::Answering(Box::pin(Answer::take(a)));
                }
                Sending::Answering(f) => {
                    let r = ready!(f.as_mut().poll(cx));
                    self.sending = match r {
                        Ok(half) => Sending::Idle(half),
                        Err(e) => {
                            self.sending = Sending::Gone;
                            return Poll::Ready(Err(e));
                        }
                    };
                }
                _ => return Poll::Ready(Ok(())),
            }
        }
    }

    /// Drives the write in flight to its end.
    fn poll_op(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Sending::Busy(op) = &mut self.sending else {
            return Poll::Ready(Ok(()));
        };
        let (half, r) = ready!(op.as_mut().poll(cx));
        self.sending = Sending::Idle(half);
        Poll::Ready(r.map_err(h3_error))
    }

    /// Takes the buffers of `chunks` once the previous write is done, and
    /// sends each as one DATA frame.
    fn poll_send(&mut self, cx: &mut Context<'_>, chunks: &mut [Bytes]) -> Poll<io::Result<usize>> {
        if chunks.iter().all(Bytes::is_empty) {
            return Poll::Ready(Ok(0));
        }
        ready!(self.poll_answer(cx))?;
        ready!(self.poll_op(cx))?;
        let mut data = ChunkBuf::new();
        let n = data.take_from(chunks);
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        // Taken now; the next call drives it, and reports its error.
        self.start(cx, |mut g| async move {
            let r = g.half().send(data).await;
            (g.release(), r)
        })?;
        Poll::Ready(Ok(n))
    }

    /// Starts `op` on the idle half, and polls it once.
    fn start<F, Fut>(&mut self, cx: &mut Context<'_>, op: F) -> io::Result<()>
    where
        F: FnOnce(ResetOnDrop) -> Fut,
        Fut: Future<Output = OpDone> + Send + 'static,
    {
        let Sending::Idle(half) = std::mem::replace(&mut self.sending, Sending::Gone) else {
            return Err(io::Error::other("body writer lost its stream"));
        };
        self.sending = Sending::Busy(Box::pin(op(ResetOnDrop(Some(half)))));
        match self.poll_op(cx) {
            Poll::Ready(r) => r,
            Poll::Pending => Ok(()),
        }
    }
}

impl Drop for BodyWriter {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        // A write in flight resets its half as it is dropped.
        if let Sending::Idle(h) = &mut self.sending {
            h.reset();
        }
    }
}

impl ChunkWrite for BodyWriter {
    fn poll_write_chunks(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        chunks: &mut [Bytes],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().poll_send(cx, chunks)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Sending::Unanswered(_) = self.sending {
            return Poll::Ready(Ok(()));
        }
        ready!(self.poll_answer(cx))?;
        self.poll_op(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.finished {
            return Poll::Ready(Ok(()));
        }
        // The end is taken once: a second one fails on the ended stream,
        // and the body would then be reset, discarding its last records.
        if !self.finishing {
            ready!(self.poll_answer(cx))?;
            ready!(self.poll_op(cx))?;
            self.finishing = true;
            self.start(cx, |mut g| async move {
                let r = g.half().finish().await;
                (g.release(), r)
            })?;
        }
        ready!(self.poll_op(cx))?;
        self.finished = true;
        self.ended_gracefully.store(true, Ordering::Release);
        Poll::Ready(Ok(()))
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

/// A body as the receiving half of a carrier. Dropping it cancels the
/// transport read, including a pending read held inside the HTTP decoder.
struct BodyReader {
    half: Option<RecvHalf>,
    /// The client's wait for the response head.
    response: Option<Response>,
    held: Bytes,
    ended: bool,
    /// The pipe's request or response body this endpoint sends ended
    /// gracefully: the carrier closes cleanly, and the peer's body is not
    /// stopped, or its sender could fail before it reads what was sent.
    peer_may_finish: Arc<AtomicBool>,
    keep: Option<Arc<ClientInner>>,
    /// A server's request served without admission: the half returns to
    /// it on drop while nothing committed to the carrier.
    answer: Option<Arc<Answer>>,
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
            peer_may_finish: Arc::default(),
            keep: Some(keep),
            answer: None,
        }
    }

    fn server(recv: ServerRecv) -> Self {
        Self {
            half: Some(RecvHalf::Server(recv)),
            response: None,
            held: Bytes::new(),
            ended: false,
            peer_may_finish: Arc::default(),
            keep: None,
            answer: None,
        }
    }

    /// A server's receiving half and the bytes read but not returned.
    fn into_server(mut self) -> (ServerRecv, Bytes) {
        self.ended = true;
        let held = std::mem::take(&mut self.held);
        match self.half.take() {
            Some(RecvHalf::Server(r)) => (r, held),
            _ => unreachable!("a server reader holds a server half"),
        }
    }
}

impl Drop for BodyReader {
    fn drop(&mut self) {
        if let Some(a) = self.answer.take()
            && !a.committed.load(Ordering::Acquire)
            && let Some(RecvHalf::Server(r)) = self.half.take()
        {
            *a.recv.lock().unwrap_or_else(PoisonError::into_inner) = Some(r);
            return;
        }
        if self.ended {
            return;
        }
        if self.peer_may_finish.load(Ordering::Acquire)
            && let Some(keep) = self.keep.take()
        {
            linger(self.response.take(), self.half.take(), keep);
        }
        // The HTTP decoder may return buffered data while its transport
        // read is still pending. Its outer Poll cannot tell us whether an
        // explicit stop is safe. Dropping the receive half cancels both
        // the buffered decoder and its pending transport read together.
    }
}

/// Keeps a client's connection after its pipe's request body ended
/// gracefully, until the response body ends (or fails): QUIC closes a
/// connection whose last handle is dropped, and discards the data still in
/// flight, so the request body's last records (a CONNECTION_CLOSE) would be
/// lost with it. The server ends the response once it read the request
/// body to its end, or its session ended on its own; what it still sends
/// is discarded.
fn linger(response: Option<Response>, half: Option<RecvHalf>, keep: Arc<ClientInner>) {
    let Ok(rt) = tokio::runtime::Handle::try_current() else {
        return;
    };
    rt.spawn(async move {
        let mut recv = match (response, half) {
            (Some(response), _) => match response.await {
                (recv, Ok(())) => recv,
                (_, Err(_)) => return,
            },
            (None, Some(RecvHalf::Client(recv))) => recv,
            _ => return,
        };
        while let Ok(Some(_)) = poll_fn(|cx| recv.poll_recv_data(cx)).await {}
        drop(keep);
    });
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

/// A [`zmux::Candidate`] of [`zmux::CarrierKind::Http3`] for carrier
/// modes: a request to `uri` on a new HTTP/3 connection of `endpoint` to
/// `addr` ([`dial`]).
pub fn http3_candidate(
    endpoint: Endpoint,
    addr: SocketAddr,
    uri: http::Uri,
    options: &Options,
) -> zmux::Candidate {
    let options = Arc::new(options.clone());
    zmux::Candidate::new(zmux::CarrierKind::Http3, move || {
        let (endpoint, uri, options) = (endpoint.clone(), uri.clone(), options.clone());
        async move { dial(&endpoint, addr, uri, &options).await }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn drop_reader_after_buffered_data_with_a_pending_transport_read() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let der = cert.cert.der().clone();
            let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let tls = rustls::ServerConfig::builder_with_provider(provider.clone())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![der.clone()], key.into())
                .unwrap();
            let server = Endpoint::server(
                server_config(tls, &Options::default()).unwrap(),
                "127.0.0.1:0".parse().unwrap(),
            )
            .unwrap();
            let mut roots = rustls::RootCertStore::empty();
            roots.add(der).unwrap();
            let tls = rustls::ClientConfig::builder_with_provider(provider)
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client.set_default_client_config(client_config(tls, &Options::default()).unwrap());
            let (c, s) = tokio::join!(
                client
                    .connect(server.local_addr().unwrap(), "localhost")
                    .unwrap(),
                async { server.accept().await.unwrap().await },
            );
            let (c, s) = (c.unwrap(), s.unwrap());
            let client = H3Client::new(
                c.clone(),
                "https://localhost/".parse().unwrap(),
                &Options::default(),
            )
            .await
            .unwrap();
            let mut server =
                h3::server::Connection::<_, ChunkBuf>::new(h3_quinn::Connection::new(s.clone()))
                    .await
                    .unwrap();
            // Put an entire request header and DATA frame in one QUIC write.
            // Resolving the header buffers the DATA before the body's first poll.
            let (mut send, _recv) = c.open_bi().await.unwrap();
            // QPACK prefix, static :method POST, :scheme https, :path /,
            // and a literal :authority using its static name index.
            send.write_all(&[
                1, 16, 0, 0, 0xd4, 0xd7, 0xc1, 0x50, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o',
                b's', b't', 0, 3, b'a', b'b', b'c',
            ])
            .await
            .unwrap();
            let (_, request) = server
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            let (_send, recv) = request.split();
            let mut reader = BodyReader::server(recv);
            let mut byte = [0];
            reader.read_exact(&mut byte).await.unwrap();
            assert_eq!(byte, [b'a']);
            // The HTTP decoder just returned buffered data despite a pending
            // transport read. Dropping used to call stop_sending and panic.
            drop(reader);
            assert_eq!(send.stopped().await.unwrap(), Some(0u32.into()));
            drop(client);
            c.close(0u32.into(), b"");
            s.close(0u32.into(), b"");
        })
        .await
        .unwrap();
    }
}
