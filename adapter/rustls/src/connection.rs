//! A TLS connection that another layer (an HTTP server or client, a
//! WebSocket) owns while the carriers on it read its exporter.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsStream;
use tokio_rustls::rustls::{CommonState, ProtocolVersion};
use zmux::{CarrierInfo, PipeIo, TlsState};

/// Whether the carriers on a rustls connection meet the Bound contract
/// ([`PipeIo::with_carrier_secure`]): its handshake is complete and it
/// negotiated TLS 1.3. Every carrier this crate and the HTTP and WebSocket
/// adapters declare secure over TLS passes it.
pub fn is_bound(conn: &CommonState) -> bool {
    !conn.is_handshaking() && conn.protocol_version() == Some(ProtocolVersion::TLSv1_3)
}

/// A tokio-rustls stream, client or server, as the shared connection holds it.
trait Stream: AsyncRead + AsyncWrite + Send + Unpin {
    fn common(&self) -> &CommonState;
    fn export(&self, label: &[u8], context: &[u8], out: &mut [u8]) -> bool;
}

impl<IO: AsyncRead + AsyncWrite + Send + Unpin> Stream for TlsStream<IO> {
    fn common(&self) -> &CommonState {
        self.get_ref().1
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
    /// The connection of an established tokio-rustls stream, client or server.
    pub fn new<IO>(stream: impl Into<TlsStream<IO>>) -> Self
    where
        IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let stream = stream.into();
        let common = stream.get_ref().1;
        let alpn = common.alpn_protocol().map(<[u8]>::to_vec);
        let server_name = match &stream {
            TlsStream::Server(s) => s.get_ref().1.server_name().map(str::to_owned),
            TlsStream::Client(_) => None,
        };
        Self {
            stream: Arc::new(Mutex::new(Box::new(stream))),
            alpn,
            server_name,
        }
    }

    /// The metadata for an admission or a credential: the exporter, the
    /// negotiated ALPN identifier and a server's client-given name.
    pub fn info(&self) -> CarrierInfo<'_> {
        let stream = &self.stream;
        CarrierInfo::new()
            .with_alpn(self.alpn.as_deref())
            .with_server_name(self.server_name.as_deref())
            .with_exporter(move |label, context, out| lock(stream).export(label, context, out))
    }

    /// The binding the connection's carriers declare.
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
    pub fn terminated_tls(&self) -> Option<TlsState> {
        let s = self.stream.upgrade()?;
        let done = !lock(&s).common().is_handshaking();
        done.then(|| self.state.clone())
    }

    /// `io` as a carrier on the connection: with the TLS terminated here
    /// once the handshake is complete, and, when the connection is bound
    /// now, declared secure with its exporter ([`TlsBinding::export`]).
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
