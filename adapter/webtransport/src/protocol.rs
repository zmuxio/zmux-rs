//! WebTransport over one dedicated Quinn connection.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;

use bytes::{Buf as _, Bytes, BytesMut};
use futures_util::stream::{FuturesUnordered, StreamExt as _};
use http::{HeaderMap, StatusCode};
use quinn::{Connection, RecvStream, SendStream, VarInt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, watch};
use url::{Host, Url};

use crate::h3;
use crate::streams::{self, Streams};

const H3_NO_ERROR: VarInt = VarInt::from_u32(0x100);
const H3_STREAM_CREATION_ERROR: VarInt = VarInt::from_u32(0x103);
const H3_CLOSED_CRITICAL_STREAM: VarInt = VarInt::from_u32(0x104);
const H3_FRAME_UNEXPECTED: VarInt = VarInt::from_u32(0x105);
const H3_ID_ERROR: VarInt = VarInt::from_u32(0x108);
const H3_REQUEST_REJECTED: VarInt = VarInt::from_u32(0x10b);
const H3_SETTINGS_ERROR: VarInt = VarInt::from_u32(0x109);
const H3_REQUEST_CANCELLED: VarInt = VarInt::from_u32(0x10c);
const H3_MESSAGE_ERROR: VarInt = VarInt::from_u32(0x10e);
const WT_BUFFERED_STREAM_REJECTED: VarInt = VarInt::from_u32(0x3994_bd84);
pub(crate) const WT_SESSION_GONE: VarInt = VarInt::from_u32(0x170d_7b68);
const WT_REQUIREMENTS_NOT_MET: VarInt = VarInt::from_u32(0x212c_0d48);
const WT_CLOSE_SESSION: u64 = 0x2843;
const WT_DRAIN_SESSION: u64 = 0x78ae;
const CLOSE_REASON_LIMIT: usize = 1024;

/// The TLS application protocol for a WebTransport connection.
pub const ALPN: &str = "h3";

/// The URL and header fields for an Extended CONNECT.
#[derive(Clone, Debug)]
pub struct ConnectRequest {
    /// The HTTPS URL to connect to.
    pub url: Url,
    /// Additional request header fields.
    pub headers: HeaderMap,
}

impl ConnectRequest {
    /// Creates a CONNECT request without additional header fields.
    #[must_use]
    pub fn new(url: Url) -> Self {
        Self {
            url,
            headers: HeaderMap::new(),
        }
    }
}

impl From<Url> for ConnectRequest {
    fn from(url: Url) -> Self {
        Self::new(url)
    }
}

/// The final HTTP status of a refused WebTransport CONNECT.
#[derive(Clone, Debug)]
pub struct ConnectRejected {
    /// The final HTTP status.
    pub status: StatusCode,
}

impl std::fmt::Display for ConnectRejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WebTransport CONNECT returned {}", self.status)
    }
}

impl std::error::Error for ConnectRejected {}

/// A WebTransport client using the endpoint and TLS policy provided by the caller.
#[derive(Clone)]
pub struct Client {
    endpoint: quinn::Endpoint,
    config: quinn::ClientConfig,
}

impl Client {
    /// Uses the given endpoint and HTTP/3 QUIC client configuration.
    #[must_use]
    pub fn new(endpoint: quinn::Endpoint, config: quinn::ClientConfig) -> Self {
        Self { endpoint, config }
    }

    /// Dials and establishes an owned WebTransport session.
    ///
    /// # Errors
    ///
    /// Returns an error on address resolution, QUIC or HTTP/3 failure, or a refused CONNECT.
    pub async fn connect(&self, request: impl Into<ConnectRequest>) -> io::Result<Session> {
        let request = request.into();
        let host = request
            .url
            .host()
            .ok_or_else(|| h3::invalid("missing host"))?;
        let port = request
            .url
            .port_or_known_default()
            .ok_or_else(|| h3::invalid("missing port"))?;
        let (addr, name) = match host {
            Host::Domain(name) => {
                let ipv4_only = self.endpoint.local_addr()?.is_ipv4();
                let addr = tokio::net::lookup_host((name, port))
                    .await?
                    .find(|addr| !ipv4_only || addr.is_ipv4())
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::AddrNotAvailable, "no usable address")
                    })?;
                (addr, name.to_owned())
            }
            Host::Ipv4(ip) => (SocketAddr::new(IpAddr::V4(ip), port), ip.to_string()),
            Host::Ipv6(ip) => (SocketAddr::new(IpAddr::V6(ip), port), ip.to_string()),
        };
        let conn = self
            .endpoint
            .connect_with(self.config.clone(), addr, &name)
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)?;
        Session::connect(conn, request).await
    }
}

struct Dedicated(Connection);

impl Drop for Dedicated {
    fn drop(&mut self) {
        if self.0.close_reason().is_none() {
            self.0.close(H3_NO_ERROR, b"");
        }
    }
}

type Bidi = (SendStream, RecvStream);
type Parsed = io::Result<Option<(u64, Option<u64>)>>;
type PrefixFuture<T> = Pin<Box<dyn Future<Output = (T, Parsed)> + Send>>;

struct Incoming<T> {
    pending: FuturesUnordered<PrefixFuture<T>>,
    early: VecDeque<(T, u64)>,
}

impl<T> Default for Incoming<T> {
    fn default() -> Self {
        Self {
            pending: FuturesUnordered::new(),
            early: VecDeque::new(),
        }
    }
}

async fn prefix(conn: &Connection, recv: &mut RecvStream, wt: u64) -> Parsed {
    let Some(ty) = h3::read(recv).await? else {
        return Ok(None);
    };
    let id = if ty == wt {
        let id = h3::required(h3::read(recv).await?)?;
        if id % 4 != 0 {
            conn.close(H3_ID_ERROR, b"invalid WebTransport session ID");
            return Err(h3::invalid("invalid WebTransport session ID"));
        }
        Some(id)
    } else {
        None
    };
    Ok(Some((ty, id)))
}

impl Incoming<Bidi> {
    async fn next(&mut self, conn: &Connection) -> io::Result<(Bidi, u64, Option<u64>)> {
        loop {
            tokio::select! {
                stream = conn.accept_bi() => {
                    let mut stream = stream.map_err(io::Error::other)?;
                    let conn = conn.clone();
                    self.pending.push(Box::pin(async move {
                        let head = prefix(&conn, &mut stream.1, h3::WT_BIDI).await;
                        (stream, head)
                    }));
                }
                Some((mut stream, parsed)) = self.pending.next() => {
                    if let Ok(Some((ty, id))) = parsed {
                        return Ok((stream, ty, id));
                    }
                    reject_bidi(&mut stream, H3_REQUEST_CANCELLED);
                }
            }
        }
    }
}

fn reject_bidi(stream: &mut Bidi, code: VarInt) {
    let _ = stream.0.reset(code);
    let _ = stream.1.stop(code);
}

#[derive(Default)]
struct Uni {
    streams: Incoming<RecvStream>,
    qpack: [Option<RecvStream>; 2],
}

impl Uni {
    async fn next(&mut self, conn: &Connection) -> io::Result<(RecvStream, u64, Option<u64>)> {
        loop {
            tokio::select! {
                stream = conn.accept_uni() => {
                    let mut stream = stream.map_err(io::Error::other)?;
                    let conn = conn.clone();
                    self.streams.pending.push(Box::pin(async move {
                        let head = prefix(&conn, &mut stream, h3::WT_UNI).await;
                        (stream, head)
                    }));
                }
                Some((mut stream, parsed)) = self.streams.pending.next() => {
                    let Ok(Some((ty, id))) = parsed else {
                        let _ = stream.stop(H3_STREAM_CREATION_ERROR);
                        continue;
                    };
                    let index = match ty {
                        h3::QPACK_ENCODER => 0,
                        h3::QPACK_DECODER => 1,
                        h3::CONTROL | h3::WT_UNI => return Ok((stream, ty, id)),
                        _ => {
                            let _ = stream.stop(H3_STREAM_CREATION_ERROR);
                            continue;
                        }
                    };
                    if self.qpack[index].is_some() {
                        conn.close(H3_STREAM_CREATION_ERROR, b"duplicate QPACK stream");
                        return Err(h3::invalid("duplicate HTTP/3 QPACK stream"));
                    }
                    // Both dynamic table settings default to zero. Keep the peer's
                    // critical streams open even though no dynamic table is used.
                    self.qpack[index] = Some(stream);
                }
            }
        }
    }
}

struct H3 {
    // These ends are critical and stay open for the life of the connection.
    send: SendStream,
    recv: RecvStream,
    peer_wt: bool,
}

impl H3 {
    async fn negotiate(conn: &Connection, uni: &mut Uni, peer_server: bool) -> io::Result<Self> {
        if conn.max_datagram_size().is_none() {
            conn.close(WT_REQUIREMENTS_NOT_MET, b"missing QUIC DATAGRAM");
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "peer did not enable QUIC DATAGRAM",
            ));
        }
        let receive = async {
            loop {
                let (mut stream, ty, id) = uni.next(conn).await?;
                if ty == h3::CONTROL {
                    let result = h3::receive_settings(&mut stream, peer_server).await;
                    if let Err(error) = &result {
                        let code = if error.kind() == io::ErrorKind::Unsupported {
                            WT_REQUIREMENTS_NOT_MET
                        } else {
                            H3_SETTINGS_ERROR
                        };
                        conn.close(code, b"WebTransport SETTINGS");
                    }
                    return Ok((stream, result?));
                }
                if let Some(id) = id {
                    uni.streams.early.push_back((stream, id));
                }
            }
        };
        let (send, (recv, peer_wt)) =
            tokio::try_join!(h3::send_settings(conn, !peer_server), receive)?;
        Ok(Self {
            send,
            recv,
            peer_wt,
        })
    }

    async fn drive(&mut self, conn: &Connection, draining: &watch::Sender<bool>) -> io::Result<()> {
        let stopped = self.send.stopped();
        tokio::pin!(stopped);
        loop {
            let frame = tokio::select! {
                frame = h3::frame(&mut self.recv) => frame?,
                _ = &mut stopped => None,
            };
            let Some((ty, len)) = frame else {
                conn.close(H3_CLOSED_CRITICAL_STREAM, b"HTTP/3 control stream closed");
                return Err(h3::invalid("HTTP/3 control stream closed"));
            };
            match ty {
                h3::GOAWAY => {
                    h3::skip(&mut self.recv, len).await?;
                    draining.send_replace(true);
                }
                h3::SETTINGS | h3::DATA | h3::HEADERS | h3::WT_BIDI | 0x02 | 0x06 | 0x08 | 0x09 => {
                    conn.close(H3_FRAME_UNEXPECTED, b"unexpected control frame");
                    return Err(h3::invalid("unexpected HTTP/3 control frame"));
                }
                _ => h3::skip(&mut self.recv, len).await?,
            }
        }
    }
}

struct Setup {
    conn: Dedicated,
    h3: H3,
    bi: Incoming<Bidi>,
    uni: Uni,
}

impl Setup {
    async fn new(conn: Connection, peer_server: bool) -> io::Result<Self> {
        let conn = Dedicated(conn);
        if zmux_quinn::Handshake::of(&conn.0)
            .alpn
            .as_deref()
            .is_some_and(|alpn| alpn != ALPN.as_bytes())
        {
            return Err(h3::invalid("WebTransport requires HTTP/3 ALPN"));
        }
        let mut uni = Uni::default();
        let h3 = H3::negotiate(&conn.0, &mut uni, peer_server).await?;
        Ok(Self {
            conn,
            h3,
            bi: Incoming::default(),
            uni,
        })
    }
}

/// An unanswered WebTransport CONNECT request on a dedicated H3 connection.
pub struct Request {
    setup: Setup,
    connect: Bidi,
    head: ConnectRequest,
}

impl Deref for Request {
    type Target = ConnectRequest;

    fn deref(&self) -> &ConnectRequest {
        &self.head
    }
}

impl Request {
    /// Accepts the first WebTransport request on an established, dedicated H3 connection.
    ///
    /// # Errors
    ///
    /// Returns an error if SETTINGS, the CONNECT head, or the connection fails.
    pub async fn accept(conn: Connection) -> io::Result<Self> {
        let mut setup = Setup::new(conn, false).await?;
        loop {
            let (mut stream, ty, id) = setup.bi.next(&setup.conn.0).await?;
            if let Some(id) = id {
                setup.bi.early.push_back((stream, id));
                continue;
            }
            let (url, headers, legacy) = match h3::read_request(&mut stream.1, ty).await {
                Ok(head) => head,
                Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                    reject_connect(&mut stream.0, StatusCode::NOT_IMPLEMENTED).await?;
                    return Err(error);
                }
                Err(error) => {
                    reject_bidi(&mut stream, H3_MESSAGE_ERROR);
                    return Err(error);
                }
            };
            if !setup.h3.peer_wt && !legacy {
                setup
                    .conn
                    .0
                    .close(WT_REQUIREMENTS_NOT_MET, b"missing WebTransport SETTINGS");
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "peer did not enable WebTransport",
                ));
            }
            if !valid_origin(&url, &headers) {
                reject_connect(&mut stream.0, StatusCode::FORBIDDEN).await?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "invalid WebTransport Origin",
                ));
            }
            return Ok(Self {
                setup,
                connect: stream,
                head: ConnectRequest { url, headers },
            });
        }
    }

    /// The associated QUIC connection.
    #[must_use]
    pub fn conn(&self) -> &Connection {
        &self.setup.conn.0
    }

    /// The full client bidirectional CONNECT stream ID.
    #[must_use]
    pub fn id(&self) -> u64 {
        h3::id(&self.connect.0)
    }

    /// Sends the accepting response and establishes the WT session.
    ///
    /// # Errors
    ///
    /// Returns the error if the response cannot be written.
    pub async fn ok(mut self) -> io::Result<Session> {
        h3::write_response(&mut self.connect.0, StatusCode::OK).await?;
        Ok(Session::start(self.setup, self.connect, self.head))
    }

    /// Sends a final refusal and waits for its delivery or cancellation.
    ///
    /// # Errors
    ///
    /// Returns the error if the response is invalid or the QUIC stream fails.
    pub async fn reject(mut self, status: StatusCode) -> io::Result<()> {
        if status.is_success() || status.is_informational() {
            return Err(h3::invalid("a refusal requires a final non-2xx status"));
        }
        reject_connect(&mut self.connect.0, status).await
    }
}

fn valid_origin(url: &Url, headers: &HeaderMap) -> bool {
    let mut origins = headers.get_all(http::header::ORIGIN).iter();
    let Some(origin) = origins.next() else {
        return true;
    };
    if origins.next().is_some() {
        return false;
    }
    let Ok(value) = origin.to_str() else {
        return false;
    };
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    authority.parse::<http::uri::Authority>().is_ok()
        && !authority.contains(['@', '/', '?', '#', '\\'])
        && Url::parse(value).is_ok_and(|origin| origin.origin() == url.origin())
}

async fn reject_connect(send: &mut SendStream, status: StatusCode) -> io::Result<()> {
    h3::write_response(send, status).await?;
    send.finish().map_err(io::Error::other)?;
    match send.stopped().await {
        Ok(_)
        | Err(quinn::StoppedError::ConnectionLost(
            quinn::ConnectionError::ApplicationClosed(_)
            | quinn::ConnectionError::ConnectionClosed(_),
        )) => Ok(()),
        Err(error) => Err(io::Error::other(error)),
    }
}

/// Why an established WebTransport session ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEnd {
    /// The CONNECT body ended with a close capsule.
    Closed {
        /// The WebTransport application error code.
        code: u32,
        /// The UTF-8 reason phrase sent with the code.
        reason: String,
        /// Whether the close capsule came from the remote endpoint.
        remote: bool,
    },
    /// The peer ended CONNECT with application code zero and an empty reason.
    Finished,
    /// The CONNECT stream or H3 connection failed before a clean close.
    Failed(String),
}

/// One active WebTransport session on an owned Quinn connection.
#[derive(Clone)]
pub struct Session(Arc<State>);

struct State {
    conn: Connection,
    id: u64,
    request: ConnectRequest,
    bi: Mutex<Incoming<Bidi>>,
    uni: Mutex<Uni>,
    close: watch::Sender<Option<(u32, String)>>,
    end: watch::Receiver<Option<SessionEnd>>,
    drained: watch::Receiver<bool>,
    peer_draining: watch::Receiver<bool>,
    streams: Arc<Streams>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("id", &self.0.id)
            .finish_non_exhaustive()
    }
}

impl Deref for Session {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.0.conn
    }
}

impl Session {
    /// Establishes one session on the dedicated H3 connection.
    ///
    /// # Errors
    ///
    /// Returns an error when SETTINGS, the connection, or CONNECT fails.
    /// An HTTP refusal includes a downcastable `ConnectRejected`.
    pub async fn connect(conn: Connection, request: impl Into<ConnectRequest>) -> io::Result<Self> {
        let request = request.into();
        let setup = Setup::new(conn, true).await?;
        let mut stream = setup.conn.0.open_bi().await.map_err(io::Error::other)?;
        h3::write_request(&mut stream.0, &request.url, &request.headers).await?;
        let status = h3::read_response(&mut stream.1).await?;
        if !status.is_success() {
            return Err(io::Error::other(ConnectRejected { status }));
        }
        Ok(Self::start(setup, stream, request))
    }

    fn start(setup: Setup, connect: Bidi, request: ConnectRequest) -> Self {
        let id = h3::id(&connect.0);
        let Setup { conn, h3, bi, uni } = setup;
        let (close, close_rx) = watch::channel(None);
        let (end_tx, end) = watch::channel(None);
        let (drained_tx, drained) = watch::channel(false);
        let (draining_tx, peer_draining) = watch::channel(false);
        let connection = conn.0.clone();
        let streams = Arc::new(Streams::default());
        tokio::spawn(drive_session(
            conn,
            h3,
            connect,
            close_rx,
            Lifecycle {
                end: end_tx,
                drained: drained_tx,
                peer_draining: draining_tx,
                streams: streams.clone(),
            },
        ));
        Self(Arc::new(State {
            conn: connection,
            id,
            request,
            bi: Mutex::new(bi),
            uni: Mutex::new(uni),
            close,
            end,
            drained,
            peer_draining,
            streams,
        }))
    }

    /// The full client bidirectional CONNECT stream ID.
    #[must_use]
    pub fn id(&self) -> u64 {
        self.0.id
    }

    /// The CONNECT request associated with the session.
    #[must_use]
    pub fn request(&self) -> &ConnectRequest {
        &self.0.request
    }

    /// Opens a bidirectional WebTransport stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream or its association header cannot be sent.
    pub async fn open_bi(&self) -> io::Result<(streams::SendStream, streams::RecvStream)> {
        self.while_open(async {
            let (send, recv) = self.0.conn.open_bi().await.map_err(io::Error::other)?;
            let send = associate(send, h3::WT_BIDI, self.id()).await?;
            Ok((self.0.streams.send(send)?, self.0.streams.recv(recv)?))
        })
        .await
    }

    /// Opens a unidirectional WebTransport stream.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream or its association header cannot be sent.
    pub async fn open_uni(&self) -> io::Result<streams::SendStream> {
        self.while_open(async {
            let send = self.0.conn.open_uni().await.map_err(io::Error::other)?;
            self.0
                .streams
                .send(associate(send, h3::WT_UNI, self.id()).await?)
        })
        .await
    }

    /// Accepts the next bidirectional stream associated with this session.
    ///
    /// # Errors
    ///
    /// Returns an error when the session or connection ends.
    pub async fn accept_bi(&self) -> io::Result<(streams::SendStream, streams::RecvStream)> {
        self.while_open(async {
            let mut incoming = self.0.bi.lock().await;
            loop {
                let (mut stream, id) = if let Some((stream, id)) = incoming.early.pop_front() {
                    (stream, Some(id))
                } else {
                    let (stream, _, id) = incoming.next(&self.0.conn).await?;
                    (stream, id)
                };
                if id == Some(self.id()) {
                    return Ok((
                        self.0.streams.send(stream.0)?,
                        self.0.streams.recv(stream.1)?,
                    ));
                }
                reject_bidi(
                    &mut stream,
                    if id.is_some() {
                        WT_BUFFERED_STREAM_REJECTED
                    } else {
                        H3_REQUEST_REJECTED
                    },
                );
            }
        })
        .await
    }

    /// Accepts the next unidirectional stream associated with this session.
    ///
    /// # Errors
    ///
    /// Returns an error when the session or connection ends.
    pub async fn accept_uni(&self) -> io::Result<streams::RecvStream> {
        self.while_open(async {
            let mut incoming = self.0.uni.lock().await;
            loop {
                let (mut stream, id) =
                    if let Some((stream, id)) = incoming.streams.early.pop_front() {
                        (stream, Some(id))
                    } else {
                        let (stream, ty, id) = incoming.next(&self.0.conn).await?;
                        if ty == h3::CONTROL {
                            self.0
                                .conn
                                .close(H3_STREAM_CREATION_ERROR, b"duplicate control stream");
                            return Err(h3::invalid("duplicate HTTP/3 control stream"));
                        }
                        (stream, id)
                    };
                if id == Some(self.id()) {
                    return self.0.streams.recv(stream);
                }
                let _ = stream.stop(WT_BUFFERED_STREAM_REJECTED);
            }
        })
        .await
    }

    /// Maximum current datagram payload size, after the HTTP/3 prefix.
    #[must_use]
    pub fn max_datagram_size(&self) -> usize {
        let mut header = [0; 8];
        let len = zmux::proto::varint::encode(self.id() / 4, &mut header).unwrap_or(0);
        self.0
            .conn
            .max_datagram_size()
            .unwrap_or(0)
            .saturating_sub(len)
    }

    /// Queues one RFC 9297 datagram, waiting for Quinn's send buffer.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload cannot be queued or the session ends.
    pub async fn send_datagram_wait(&self, payload: Bytes) -> io::Result<()> {
        self.while_open(async {
            let mut header = [0; 8];
            let len = zmux::proto::varint::encode(self.id() / 4, &mut header)
                .map_err(io::Error::other)?;
            let mut data = BytesMut::with_capacity(len + payload.len());
            data.extend_from_slice(&header[..len]);
            data.extend_from_slice(&payload);
            self.0
                .conn
                .send_datagram_wait(data.freeze())
                .await
                .map_err(io::Error::other)
        })
        .await
    }

    /// Receives a datagram addressed to this session.
    ///
    /// # Errors
    ///
    /// Returns an error when the session or connection ends.
    pub async fn read_datagram(&self) -> io::Result<Bytes> {
        self.while_open(async {
            loop {
                let mut data = self
                    .0
                    .conn
                    .read_datagram()
                    .await
                    .map_err(io::Error::other)?;
                let Some((quarter, len)) = zmux::proto::varint::decode(&data) else {
                    continue;
                };
                if quarter == self.id() / 4 {
                    data.advance(len);
                    return Ok(data);
                }
            }
        })
        .await
    }

    /// Starts a graceful close. The first call supplies the application code and reason.
    pub fn close(&self, code: u32, reason: &[u8]) {
        let mut reason = String::from_utf8_lossy(reason).into_owned();
        reason.truncate(reason.floor_char_boundary(CLOSE_REASON_LIMIT));
        self.0.close.send_if_modified(|close| {
            if close.is_some() {
                return false;
            }
            *close = Some((code, reason));
            true
        });
    }

    /// Waits for the CLOSE exchange or a terminal connection failure.
    pub async fn closed(&self) -> SessionEnd {
        let _ = self.0.drained.clone().wait_for(|drained| *drained).await;
        self.0
            .end
            .borrow()
            .clone()
            .unwrap_or_else(|| SessionEnd::Failed("session owner stopped".into()))
    }

    /// Waits for the peer to request graceful drain.
    ///
    /// # Errors
    ///
    /// Returns an error if the session ends before the notification arrives.
    pub async fn draining(&self) -> io::Result<()> {
        let mut draining = self.0.peer_draining.clone();
        draining
            .wait_for(|value| *value)
            .await
            .map_err(|_| io::ErrorKind::NotConnected)?;
        Ok(())
    }

    async fn while_open<T>(&self, work: impl Future<Output = io::Result<T>>) -> io::Result<T> {
        let mut ended = self.0.end.clone();
        let mut closing = self.0.close.subscribe();
        tokio::select! {
            biased;
            _ = ended.wait_for(Option::is_some) => Err(io::ErrorKind::NotConnected.into()),
            _ = closing.wait_for(Option::is_some) => Err(io::ErrorKind::NotConnected.into()),
            result = work => result,
        }
    }
}

async fn associate(send: SendStream, ty: u64, id: u64) -> io::Result<SendStream> {
    // A cancelled opener resets its incomplete association header.
    struct Header(Option<SendStream>);
    impl Drop for Header {
        fn drop(&mut self) {
            if let Some(send) = &mut self.0 {
                let _ = send.reset(WT_BUFFERED_STREAM_REJECTED);
            }
        }
    }
    let mut guard = Header(Some(send));
    AsyncWriteExt::write_all(
        guard.0.as_mut().expect("uncommitted stream"),
        &h3::prefix(ty, id),
    )
    .await?;
    Ok(guard.0.take().expect("associated stream"))
}

struct Lifecycle {
    end: watch::Sender<Option<SessionEnd>>,
    drained: watch::Sender<bool>,
    peer_draining: watch::Sender<bool>,
    streams: Arc<Streams>,
}

async fn drive_session(
    conn: Dedicated,
    mut h3: H3,
    (mut send, mut recv): Bidi,
    mut close: watch::Receiver<Option<(u32, String)>>,
    life: Lifecycle,
) {
    let mut capsules = Capsules::default();
    let outcome = tokio::select! {
        biased;
        remote = capsules.receive(&mut recv, &life.peer_draining) => remote,
        requested = close.wait_for(Option::is_some) => {
            let Ok(requested) = requested else {
                life.streams.abort();
                return;
            };
            let (code, reason) = requested.clone().expect("requested close");
            Ok(SessionEnd::Closed { code, reason, remote: false })
        }
        failed = h3.drive(&conn.0, &life.peer_draining) => failed.map(|()| SessionEnd::Finished),
    };
    life.streams.abort();
    let end = outcome.unwrap_or_else(|error| SessionEnd::Failed(error.to_string()));
    life.end.send_replace(Some(end.clone()));

    let code = if let SessionEnd::Closed {
        code,
        reason,
        remote: false,
    } = &end
    {
        let mut body = Vec::new();
        h3::put(&mut body, WT_CLOSE_SESSION);
        h3::put(&mut body, reason.len() as u64 + 4);
        body.extend_from_slice(&code.to_be_bytes());
        body.extend_from_slice(reason.as_bytes());
        let flushed = tokio::time::timeout(zmux::adapter::DRAIN_LIMIT, async {
            h3::write_frame(&mut send, h3::DATA, body).await?;
            send.finish().map_err(io::Error::other)?;
            send.stopped().await.map_err(io::Error::other)?;
            Ok::<(), io::Error>(())
        })
        .await;
        if !matches!(flushed, Ok(Ok(()))) {
            let _ = send.reset(WT_SESSION_GONE);
        }
        H3_NO_ERROR
    } else if matches!(end, SessionEnd::Failed(_)) {
        H3_MESSAGE_ERROR
    } else {
        H3_NO_ERROR
    };
    match end {
        SessionEnd::Finished | SessionEnd::Closed { remote: true, .. } => {
            if send.finish().is_ok() {
                let _ = tokio::time::timeout(zmux::adapter::DRAIN_LIMIT, send.stopped()).await;
            }
        }
        SessionEnd::Failed(_) => {
            let _ = send.reset(H3_MESSAGE_ERROR);
        }
        SessionEnd::Closed { remote: false, .. } => {}
    }
    let _ = recv.stop(if code == H3_MESSAGE_ERROR {
        code
    } else {
        WT_SESSION_GONE
    });
    if conn.0.close_reason().is_none() {
        conn.0.close(code, b"");
    }
    life.drained.send_replace(true);
}

// A capsule is a byte sequence in the CONNECT body. HTTP/3 DATA frames
// can end at any byte of its type, length or payload.
#[derive(Default)]
struct Capsules {
    remaining: u64,
}

impl Capsules {
    async fn read(&mut self, recv: &mut RecvStream, buf: &mut [u8]) -> io::Result<usize> {
        while self.remaining == 0 {
            let Some((ty, len)) = h3::frame(recv).await? else {
                return Ok(0);
            };
            match ty {
                h3::DATA => self.remaining = len,
                h3::HEADERS | h3::SETTINGS | h3::GOAWAY | h3::WT_BIDI | 0x03 | 0x05 | 0x0d => {
                    return Err(h3::invalid(
                        "unexpected HTTP/3 frame on WebTransport CONNECT",
                    ));
                }
                _ => h3::skip(recv, len).await?,
            }
        }
        let count = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let read = AsyncReadExt::read(recv, &mut buf[..count]).await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        self.remaining -= read as u64;
        Ok(read)
    }

    async fn exact(&mut self, recv: &mut RecvStream, mut buf: &mut [u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let read = self.read(recv, buf).await?;
            if read == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            buf = &mut buf[read..];
        }
        Ok(())
    }

    async fn varint(&mut self, recv: &mut RecvStream) -> io::Result<Option<u64>> {
        let mut buf = [0; 8];
        if self.read(recv, &mut buf[..1]).await? == 0 {
            return Ok(None);
        }
        let len = 1 << (buf[0] >> 6);
        self.exact(recv, &mut buf[1..len]).await?;
        Ok(zmux::proto::varint::decode(&buf[..len]).map(|(value, _)| value))
    }

    async fn receive(
        &mut self,
        recv: &mut RecvStream,
        draining: &watch::Sender<bool>,
    ) -> io::Result<SessionEnd> {
        while let Some(ty) = self.varint(recv).await? {
            let len = h3::required(self.varint(recv).await?)?;
            match ty {
                WT_CLOSE_SESSION => {
                    let len = usize::try_from(len)
                        .ok()
                        .filter(|len| (4..=4 + CLOSE_REASON_LIMIT).contains(len))
                        .ok_or_else(|| h3::invalid("invalid WebTransport CLOSE capsule length"))?;
                    let mut code = [0; 4];
                    self.exact(recv, &mut code).await?;
                    let mut reason = vec![0; len - 4];
                    self.exact(recv, &mut reason).await?;
                    // The CLOSE capsule is the last body payload; the peer follows it with FIN.
                    let mut extra = [0];
                    let read = tokio::time::timeout(
                        zmux::adapter::DRAIN_LIMIT,
                        self.read(recv, &mut extra),
                    )
                    .await??;
                    if read != 0 {
                        return Err(h3::invalid("payload after WebTransport CLOSE capsule"));
                    }
                    return Ok(SessionEnd::Closed {
                        code: u32::from_be_bytes(code),
                        reason: String::from_utf8(reason).map_err(h3::invalid)?,
                        remote: true,
                    });
                }
                WT_DRAIN_SESSION if len == 0 => {
                    draining.send_replace(true);
                }
                WT_DRAIN_SESSION => return Err(h3::invalid("invalid WebTransport DRAIN capsule")),
                _ => {
                    let mut buf = [0; 1024];
                    let mut left = len;
                    while left != 0 {
                        let count = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
                        self.exact(recv, &mut buf[..count]).await?;
                        left -= count as u64;
                    }
                }
            }
        }
        Ok(SessionEnd::Finished)
    }
}

// The HTTP/3 grease codepoints are skipped in WebTransport's application range.
pub(super) fn application_code(code: u32) -> VarInt {
    let code = u64::from(code);
    VarInt::try_from(0x52e4_a40f_a8db + code + code / 30).expect("WebTransport application error")
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
