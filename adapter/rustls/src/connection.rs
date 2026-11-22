//! A TLS connection that another layer (an HTTP server or client, a
//! WebSocket) owns while the carriers on it read its exporter.

use std::any::Any;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsStream;
use tokio_rustls::rustls::{CommonState, ConnectionCommon, ProtocolVersion};
use zmux::{CarrierInfo, PipeIo, TlsState};

/// Whether the carriers on a rustls connection meet the Bound contract
/// ([`PipeIo::with_carrier_secure`]): its handshake is complete and it
/// negotiated TLS 1.3. Every carrier this crate and the HTTP and WebSocket
/// adapters declare secure over TLS passes it.
#[must_use]
pub fn is_bound(conn: &CommonState) -> bool {
    !conn.is_handshaking() && conn.protocol_version() == Some(ProtocolVersion::TLSv1_3)
}

/// A tokio-rustls stream, client or server, as the shared connection holds it.
trait Stream: AsyncRead + AsyncWrite + Send + Unpin {
    fn common(&self) -> &CommonState;
    fn tcp(&self) -> Option<&tokio::net::TcpStream>;
    fn export(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> bool;
}

impl<IO: AsyncRead + AsyncWrite + Send + Unpin + 'static> Stream for TlsStream<IO> {
    fn common(&self) -> &CommonState {
        self.get_ref().1
    }

    fn tcp(&self) -> Option<&tokio::net::TcpStream> {
        (self.get_ref().0 as &dyn Any).downcast_ref()
    }

    fn export(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> bool {
        if self.common().is_handshaking() {
            return false;
        }
        match self {
            TlsStream::Client(s) => s
                .get_ref()
                .1
                .export_keying_material(out, label, Some(context)),
            TlsStream::Server(s) => s
                .get_ref()
                .1
                .export_keying_material(out, label, Some(context)),
        }
        .is_ok()
    }
}

/// Observes failure of a shared TCP connection even while an upper
/// protocol applies read backpressure. A normal peer half-close is valid.
#[derive(Debug)]
pub struct TcpReset(tokio::net::TcpStream);

impl TcpReset {
    /// Observe plain TCP or TCP beneath a terminated TLS connection.
    /// There is one observation descriptor per connection, shared across requests.
    ///
    /// # Errors
    ///
    /// Returns the socket or reactor error if registering the observer fails.
    pub fn observe(io: &dyn Any) -> io::Result<Option<Self>> {
        use tokio::net::TcpStream;
        let tcp = io
            .downcast_ref::<TcpStream>()
            .or_else(|| {
                io.downcast_ref::<TlsStream<TcpStream>>()
                    .map(|s| s.get_ref().0)
            })
            .or_else(|| {
                io.downcast_ref::<tokio_rustls::server::TlsStream<TcpStream>>()
                    .map(|s| s.get_ref().0)
            })
            .or_else(|| {
                io.downcast_ref::<tokio_rustls::client::TlsStream<TcpStream>>()
                    .map(|s| s.get_ref().0)
            });
        if let Some(tcp) = tcp {
            return Self::register(tcp).map(Some);
        }
        if let Some(tls) = io.downcast_ref::<TlsConnection>() {
            return lock(&tls.stream).tcp().map(Self::register).transpose();
        }
        Ok(None)
    }

    fn register(tcp: &tokio::net::TcpStream) -> io::Result<Self> {
        #[cfg(unix)]
        let socket = std::os::fd::AsFd::as_fd(tcp).try_clone_to_owned()?.into();
        #[cfg(windows)]
        let socket = std::os::windows::io::AsSocket::as_socket(tcp)
            .try_clone_to_owned()?
            .into();
        let observer = tokio::net::TcpStream::from_std(socket)?;
        Ok(Self(observer))
    }

    /// Wait for a transport error without consuming DATA or clearing the socket error.
    ///
    /// On Windows, requires a Tokio runtime with the time driver enabled.
    pub async fn failed(&self) {
        self.wait_for_failure().await;
    }

    #[cfg(unix)]
    async fn wait_for_failure(&self) {
        let _ = self.0.ready(tokio::io::Interest::ERROR).await;
    }

    #[cfg(windows)]
    async fn wait_for_failure(&self) {
        use tokio::io::Interest;
        let interest = Interest::ERROR | Interest::WRITABLE;
        loop {
            match self.0.ready(interest).await {
                Ok(ready) if !ready.is_error() && !ready.is_write_closed() => {}
                _ => return,
            }
            // Mio reports an established connection abort as write-closed on
            // Windows. Writable readiness also matches a healthy TCP socket,
            // so sample the cached readiness without spinning or doing I/O.
            // HTTP only waits here before handoff, within the setup deadline.
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
    }
}

type Shared = Mutex<Box<dyn Stream>>;

fn lock(m: &Shared) -> std::sync::MutexGuard<'_, Box<dyn Stream>> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A TLS connection this process terminates, as a byte stream for the layer
/// above it (an HTTP connection, a WebSocket), whose carriers declare
/// themselves through its [`TlsBinding`]. Reads and writes take a lock per
/// poll, shared with the exporter.
///
/// The HTTP adapter recognises it as the connection it serves or sends
/// requests on, and the WebSocket adapter's hyper upgrades find its
/// binding in a request's extensions.
pub struct TlsConnection {
    stream: Arc<Shared>,
    alpn: Option<Vec<u8>>,
    server_name: Option<String>,
}

impl std::fmt::Debug for TlsConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsConnection")
            .field("alpn", &self.alpn)
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl TlsConnection {
    /// The connection of an established tokio-rustls stream, client or
    /// server; a client's [`TlsConnection::client`] also reports the server
    /// name it dialled.
    pub fn new<IO>(stream: impl Into<TlsStream<IO>>) -> Self
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let stream = stream.into();
        let server_name = match &stream {
            TlsStream::Server(s) => s.get_ref().1.server_name().map(str::to_owned),
            TlsStream::Client(_) => None,
        };
        Self::of(stream, server_name)
    }

    /// The connection of an established client stream to `server_name`.
    pub fn client<IO>(stream: tokio_rustls::client::TlsStream<IO>, server_name: &str) -> Self
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::of(stream.into(), Some(server_name.to_owned()))
    }

    fn of<IO>(stream: TlsStream<IO>, server_name: Option<String>) -> Self
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let alpn = stream.get_ref().1.alpn_protocol().map(<[u8]>::to_vec);
        Self {
            stream: Arc::new(Mutex::new(Box::new(stream))),
            alpn,
            server_name,
        }
    }

    /// The metadata for an admission or a credential: its binding's
    /// ([`TlsBinding::info`]).
    #[must_use]
    pub fn info(&self) -> CarrierInfo {
        self.binding().info()
    }

    /// The binding the connection's carriers declare.
    #[must_use]
    pub fn binding(&self) -> TlsBinding {
        TlsBinding {
            stream: Arc::downgrade(&self.stream),
            state: TlsState::new(self.alpn.clone(), self.server_name.clone()),
        }
    }
}

impl AsyncRead for TlsConnection {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut **lock(&self.stream)).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsConnection {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut **lock(&self.stream)).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **lock(&self.stream)).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **lock(&self.stream)).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut **lock(&self.stream)).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        lock(&self.stream).is_write_vectored()
    }
}

/// What the carriers on one [`TlsConnection`] declare: the TLS terminated
/// here and, while [`is_bound`] holds, the Bound contract with the
/// connection's exporter, the same for every carrier on it (the streams of
/// an HTTP/2 connection share it). It does not keep the connection: once
/// that is gone it is neither bound nor gives exporter values.
#[derive(Clone)]
pub struct TlsBinding {
    stream: Weak<Shared>,
    state: TlsState,
}

impl std::fmt::Debug for TlsBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsBinding")
            .field("bound", &self.is_bound())
            .finish_non_exhaustive()
    }
}

impl TlsBinding {
    /// Whether the connection meets the Bound contract now ([`is_bound`]):
    /// false while it is still handshaking (early data) and once it is gone.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.stream
            .upgrade()
            .is_some_and(|s| is_bound(lock(&s).common()))
    }

    /// TLS-Exporter(label, context, L) of the connection while it is bound
    /// ([`TlsBinding::is_bound`]); `false` otherwise.
    pub fn export(&self, label: &str, context: &[u8], out: &mut [u8]) -> bool {
        self.stream.upgrade().is_some_and(|s| {
            let s = lock(&s);
            is_bound(s.common()) && s.export(label.as_bytes(), context, out)
        })
    }

    /// The handshake's results once it is complete; `None` before, and once
    /// the connection is gone.
    #[must_use]
    pub fn terminated_tls(&self) -> Option<TlsState> {
        let s = self.stream.upgrade()?;
        let done = !lock(&s).common().is_handshaking();
        done.then(|| self.state.clone())
    }

    /// The connection's metadata for an admission or a credential, the one
    /// source of it: the negotiated ALPN identifier, the server name, and
    /// the exporter while the connection is bound ([`Self::export`]).
    #[must_use]
    pub fn info(&self) -> CarrierInfo {
        let binding = self.clone();
        tls_info(
            self.state.alpn.as_deref(),
            self.state.server_name.as_deref(),
            zmux::CarrierExporter::new(move |label, context, out| {
                binding.export(label, context, out)
            }),
        )
    }

    /// `io` as a carrier on the connection: with the TLS terminated here
    /// once the handshake is complete, and, when the connection is bound
    /// now, declared secure with its exporter ([`TlsBinding::export`]).
    #[must_use]
    pub fn apply(&self, io: PipeIo) -> PipeIo {
        let Some(state) = self.terminated_tls() else {
            return io;
        };
        let io = io.with_terminated_tls(move || Some(state.clone()));
        if !self.is_bound() {
            return io;
        }
        let binding = self.clone();
        io.with_carrier_secure()
            .with_exporter(move |label, context, out| binding.export(label, context, out))
    }
}

/// A TLS connection's metadata: its ALPN identifier, its server name and
/// `exporter`; what [`TlsBinding::info`] and the metadata of a borrowed
/// stream ([`crate::carrier_info`]) are made of.
pub(crate) fn tls_info(
    alpn: Option<&[u8]>,
    server_name: Option<&str>,
    exporter: zmux::CarrierExporter,
) -> CarrierInfo {
    CarrierInfo::new()
        .with_alpn(alpn)
        .with_server_name(server_name)
        .with_exporter(exporter)
}

/// The exporter values zmux reads from `conn` now
/// ([`zmux::CarrierExporter::snapshot`]), for a stream borrowed only for the
/// call.
pub(crate) fn snapshot_exporter<D>(conn: &ConnectionCommon<D>) -> zmux::CarrierExporter {
    zmux::CarrierExporter::snapshot(|label, context, out| {
        conn.export_keying_material(out, label.as_bytes(), Some(context))
            .is_ok()
    })
}
