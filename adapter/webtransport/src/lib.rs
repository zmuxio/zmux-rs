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
//! sessions it accepts: [`connect`] and [`serve`]. The QUIC endpoints carry
//! the HTTP/3 ALPN identifier `h3` ([`web_transport_quinn::ALPN`]), which
//! names the HTTP layer; zmux's own identifiers do not apply. Build their
//! transport configuration with [`Options::transport_config`], so that the
//! stream window has one source.
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
//! - the TLS 1.3 exporter of its QUIC connection (RFC 9001 Section 4), for
//!   [`zmux::PipeAuth::tls`] and carrier-bound joins (MULTIPATH.md Section
//!   10.5); behind an HTTP/3 front end that terminates TLS the two ends
//!   export different values, so such deployments use a PSK (MULTIPATH.md);
//! - flow control sized for its lanes: the peer may open [`Options::lanes`] lanes at once (beside
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
use std::io::{self, IoSlice};
use std::pin::{Pin, pin};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;
pub use url::Url;
pub use web_transport_quinn;
use web_transport_quinn::proto::ConnectRequest;
use web_transport_quinn::quinn::{self, VarInt};
use web_transport_quinn::{self as wt, Session};
use zmux::carrier::{CarrierConnId, MemoryCharge};
use zmux::proto::ApplicationErrorCode;
use zmux::proto::keys::{EXPORTER_PIPE_LABEL, EXPORTER_SESSION_LABEL};
use zmux::{ConnectError, Listener, PipeHint, PipeIo};

/// The unidirectional streams an HTTP/3 endpoint keeps open on its own
/// (control, QPACK encoder and decoder).
const H3_UNI_STREAMS: u32 = 3;

/// How the carrier sizes the connection's flow control for lanes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// The stream receive window (1 250 000 bytes by default, quinn's
    /// default): the endpoint's transport configuration takes it from
    /// [`Options::transport_config`], its one source.
    pub stream_window: u64,
    /// Lanes the peer may open on the session at once (default 4): zmux
    /// opens more lanes on a pipe only as the peer's stream credit allows.
    /// The connection's receive window is set to `lanes + 1` stream
    /// windows, which a listener's budget is charged with from the moment
    /// the carrier is made, before any join on it is authenticated.
    pub lanes: u32,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            stream_window: 1_250_000,
            lanes: 4,
        }
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

    /// The connection receive window these options ask for: a stream
    /// window for each lane the peer may open and one for a pipe.
    pub fn receive_window(&self) -> u64 {
        self.stream_window
            .saturating_mul(u64::from(self.lanes) + 1)
            .min(VarInt::MAX.into_inner())
    }

    /// quinn's transport configuration for these options: the stream
    /// receive window, the connection window for the lanes and the
    /// unidirectional streams the peer may open (the lanes and HTTP/3's
    /// own); the rest quinn's defaults. Build the endpoints' client and
    /// server configurations with it.
    pub fn transport_config(&self) -> quinn::TransportConfig {
        let mut t = quinn::TransportConfig::default();
        t.stream_receive_window(VarInt::from_u64(self.stream_window).unwrap_or(VarInt::MAX))
            .receive_window(VarInt::from_u64(self.receive_window()).unwrap_or(VarInt::MAX))
            .max_concurrent_uni_streams(VarInt::from_u32(
                self.lanes.saturating_add(H3_UNI_STREAMS),
            ));
        t
    }
}

/// A carrier over a new WebTransport session of `client` to `request` (its
/// URL): a stream of the session, which carries the pipe's lanes and stays
/// open while the pipe is used. For [`zmux::helpers::PipePool`] and
/// [`zmux::Session::add_pipe`]; to reach the WebTransport session itself,
/// make it and its carrier ([`WebTransportCarrier::new`]) instead.
pub async fn dial(
    client: &wt::Client,
    request: impl Into<ConnectRequest>,
    options: &Options,
) -> io::Result<PipeIo> {
    let session = client.connect(request).await.map_err(io::Error::other)?;
    WebTransportCarrier::new(session, options.clone())
        .open_pipe()
        .await
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

/// Serves the WebTransport sessions `server` accepts until `listener` is
/// closed or the server's endpoint is: each request is accepted (200 OK)
/// and its session is a [`WebTransportCarrier`] of `listener` for as long
/// as it is open, so that its streams start zmux sessions
/// ([`Listener::accept`]) and join them. An application that routes by
/// URL accepts the requests itself and makes the carriers with
/// [`WebTransportCarrier::with_listener`].
pub async fn serve(listener: Listener, mut server: wt::Server, options: Options) {
    loop {
        let next = {
            let mut accept = pin!(server.accept());
            let mut closed = pin!(listener.closed());
            poll_fn(|cx| {
                if closed.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(None);
                }
                accept.as_mut().poll(cx)
            })
            .await
        };
        let Some(request) = next else {
            return;
        };
        let (listener, options) = (listener.clone(), options.clone());
        tokio::spawn(async move {
            let Ok(session) = request.ok().await else {
                listener.count_setup_failure();
                return;
            };
            let carrier = WebTransportCarrier::with_listener(session.clone(), &listener, options);
            // Held while the session is open: its accept loop serves it.
            session.closed().await;
            drop(carrier);
        });
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
        Self::start(session, None, options)
    }

    /// The carrier of `session` for `listener`: every stream the peer
    /// opens goes to [`Listener::handle_pipe`], and the connection's
    /// receive window is charged to the listener's budget while the
    /// carrier lives.
    pub fn with_listener(session: Session, listener: &Listener, options: Options) -> Self {
        Self::start(session, Some(listener.clone()), options)
    }

    fn start(conn: Session, listener: Option<Listener>, options: Options) -> Self {
        let window = options.receive_window();
        conn.set_receive_window(VarInt::from_u64(window).unwrap_or(VarInt::MAX));
        // The HTTP/3 control and QPACK streams stay open beside the lanes.
        conn.set_max_concurrent_uni_streams(VarInt::from_u32(
            options.lanes.saturating_add(H3_UNI_STREAMS),
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
        });
        let _ = inner.id.set(CarrierConnId::new(&inner));
        let task = tokio::spawn(accept_loop(conn, Arc::downgrade(&inner), listener));
        let _ = inner.accept_task.set(task.abort_handle());
        Self { inner }
    }

    /// The WebTransport session, for its own features (datagrams,
    /// statistics, close) and, through it, the QUIC connection. Its streams
    /// belong to zmux.
    pub fn session(&self) -> &Session {
        &self.inner.conn
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
        let io = PipeIo::from_halves(recv, send)
            .with_carrier_conn(self.id())
            .with_connection_memory(self.own_charge);
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

/// Hands every stream the peer opens to zmux until the session closes or
/// the carrier is gone.
async fn accept_loop(conn: Session, inner: Weak<Inner>, listener: Option<Listener>) {
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

impl AsyncWrite for Send {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(self.stream()), cx, buf)
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

    /// Each slice in turn until the stream takes less (one lock of the
    /// connection per slice; quinn copies them anyway).
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let mut written = 0;
        for b in bufs.iter().filter(|b| !b.is_empty()) {
            match AsyncWrite::poll_write(Pin::new(self.stream()), cx, b) {
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
