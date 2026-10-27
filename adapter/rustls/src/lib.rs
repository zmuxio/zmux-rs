//! TLS 1.3 pipe carriers for zmux over tokio-rustls.
//!
//! One step from an address to a session, and from a TCP listener to the
//! sessions it accepts:
//!
//! - [`connect`] dials TCP, runs the TLS handshake and establishes a
//!   session; [`dial`] makes the carrier alone, for further pipes
//!   ([`Session::add_pipe`], `maintain_pipes`);
//! - [`serve`] accepts TCP connections, runs each handshake in a task of
//!   its own within the listener's `handshake_timeout`, and hands the
//!   carriers to a [`Listener`].
//!
//! Both fill in the ALPN identifiers when the rustls configuration has none
//! ([`zmux::alpn_protocols`]: a client offers `qmux-02` then `qmux-01`, a
//! server accepts both); configured identifiers are left as they are.
//!
//! [`pipe`] turns an established tokio-rustls stream, client or server,
//! into a [`PipeIo`] with what the TLS connection can tell zmux:
//!
//! - its TLS 1.3 exporter (RFC 8446 Section 7.5) for both labels zmux uses
//!   (MULTIPATH.md Sections 10.2 and 10.5): the session secret of a
//!   bootstrap carrier with [`zmux::PipeAuth::tls`], and the binding of a
//!   carrier-bound join, made or accepted on this carrier, so that a join
//!   token copied to another connection does not verify. A connection that
//!   negotiated TLS 1.2, or is still handshaking (early data), has none and
//!   its joins are not carrier-bound;
//! - its reads, which return one TLS record's plaintext each: zmux reads
//!   again before it decides that no input is pending
//!   ([`PipeIo::with_partial_reads`]);
//! - the negotiated ALPN identifier, as the session's protocol.
//!
//! [`over_tcp`] does the same for TLS over TCP, and adds the TCP socket
//! below it: its minimum RTT, unsent bytes and low-water mark are used as
//! for a plain TCP carrier, and a pipe that zmux fails is aborted by
//! shutting the socket down without TLS close_notify, so that the peer sees
//! a failure rather than a graceful end ([`PipeIo::with_tcp_socket`];
//! one duplicate of the socket serves both).
//!
//! The adapter takes the configuration as it is otherwise: no crypto
//! provider, protocol version or buffer size is chosen here. Bytes rustls
//! buffers above the socket (up to its buffer limit, 64 KiB by default) are
//! not in the socket's unsent count.
//!
//! ```no_run
//! # async fn example(tls: std::sync::Arc<rustls::ClientConfig>) -> Result<(), Box<dyn std::error::Error>> {
//! use zmux::{Config, PipeAuth};
//!
//! let mut config = Config::default();
//! config.pipe_auth = PipeAuth::tls();
//! let session = zmux_rustls::connect("example.com:443", "example.com", tls, config).await?;
//! # drop(session);
//! # Ok(())
//! # }
//! ```
//!
//! A server:
//!
//! ```no_run
//! # async fn example(tls: std::sync::Arc<rustls::ServerConfig>) -> std::io::Result<()> {
//! use zmux::{Config, Listener, ListenerConfig, PipeAuth};
//!
//! let listener = Listener::new(Config::multipath(PipeAuth::tls()), ListenerConfig::default());
//! let tcp = tokio::net::TcpListener::bind("0.0.0.0:443").await?;
//! tokio::spawn(zmux_rustls::serve(listener.clone(), tcp, tls));
//! while let Some(session) = listener.accept().await {
//!     // ...
//! #   drop(session);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! TLS 1.3 early data is not used as carrier early data: tokio-rustls
//! sends rejected early data again by itself, before zmux could wait for
//! the server's new parameters, so a client never offers it and a server
//! never accepts it. Early data under the zmux floor
//! ([`zmux::EarlyData::zmux_peer`]) goes after the handshake and needs
//! none.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{
    ClientConfig, ClientConnection, ProtocolVersion, ServerConfig, ServerConnection,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, TlsStream};
use zmux::proto::keys::{EXPORTER_PIPE_LABEL, EXPORTER_SESSION_LABEL};
use zmux::{ConnectError, Listener, PipeHint, PipeIo, Session};

/// The length of zmux's exporter values (MULTIPATH.md Section 10).
const EXPORTER_LEN: usize = 32;

/// A pipe carrier from an established TLS stream over any transport: the
/// exporter (TLS 1.3, handshake complete), partial reads and the ALPN
/// identifier wired (see the crate documentation).
pub fn pipe<IO>(stream: impl Into<TlsStream<IO>>) -> PipeIo
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let stream = stream.into();
    // Exported while the stream is whole: the carrier splits it.
    let exporter = Exporter::of(&stream);
    let exported = [EXPORTER_SESSION_LABEL, EXPORTER_PIPE_LABEL].map(|l| exporter.export(l));
    let alpn = stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|p| String::from_utf8_lossy(p).into_owned());
    let mut io = PipeIo::new(stream)
        .with_partial_reads()
        .with_tls_exporter(|label| match label {
            EXPORTER_SESSION_LABEL => exported[0].clone(),
            EXPORTER_PIPE_LABEL => exported[1].clone(),
            _ => None,
        });
    if let Some(alpn) = alpn {
        io = io.with_protocol(alpn);
    }
    io
}

/// A pipe carrier from an established TLS stream over TCP: [`pipe`], plus
/// the TCP socket's capabilities and an abort that shuts the socket down
/// without TLS close_notify.
pub fn over_tcp(stream: impl Into<TlsStream<TcpStream>>) -> PipeIo {
    let stream = stream.into();
    let tcp = stream.get_ref().0;
    let _ = tcp.set_nodelay(true);
    #[cfg(any(unix, windows))]
    let socket = {
        #[cfg(unix)]
        let s = std::os::fd::AsFd::as_fd(tcp).try_clone_to_owned();
        #[cfg(windows)]
        let s = std::os::windows::io::AsSocket::as_socket(tcp).try_clone_to_owned();
        s.ok()
    };
    let io = pipe(stream);
    #[cfg(any(unix, windows))]
    if let Some(s) = socket {
        return io.with_tcp_socket(&s);
    }
    io
}

/// A TLS carrier over a new TCP connection to `addr`, verified for
/// `server_name`: for [`Session::connect`], or as a further pipe of a
/// session. The ALPN identifiers default as the crate documentation says.
pub async fn dial(
    addr: impl ToSocketAddrs,
    server_name: &str,
    tls: Arc<ClientConfig>,
) -> io::Result<PipeIo> {
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let tcp = TcpStream::connect(addr).await?;
    let stream = TlsConnector::from(client_alpn(tls))
        .connect(name, tcp)
        .await?;
    Ok(over_tcp(stream))
}

/// Establishes a session over a new TLS connection to `addr` ([`dial`],
/// then [`Session::connect`]).
pub async fn connect(
    addr: impl ToSocketAddrs,
    server_name: &str,
    tls: Arc<ClientConfig>,
    config: impl Into<Arc<zmux::Config>>,
) -> Result<Session, ConnectError> {
    let io = dial(addr, server_name, tls)
        .await
        .map_err(|e| ConnectError::Io(Arc::new(e)))?;
    Session::connect(io, config).await
}

/// Serves TLS over a TCP listener until `listener` is closed: each
/// connection's handshake runs in a task of its own, within the
/// listener's `handshake_timeout`, and its carrier goes to
/// [`Listener::handle_pipe`] (new sessions to [`Listener::accept`]). The
/// ALPN identifiers default as the crate documentation says.
pub async fn serve(listener: Listener, tcp: TcpListener, tls: Arc<ServerConfig>) {
    let acceptor = TlsAcceptor::from(server_alpn(tls));
    listener
        .serve_with(
            || tcp.accept(),
            move |stream, peer| {
                let accept = acceptor.accept(stream);
                async move { Ok((over_tcp(accept.await?), PipeHint::from_addr(peer.ip()))) }
            },
        )
        .await;
}

/// The client configuration with zmux's ALPN identifiers when it has none.
fn client_alpn(tls: Arc<ClientConfig>) -> Arc<ClientConfig> {
    if !tls.alpn_protocols.is_empty() {
        return tls;
    }
    let mut c = (*tls).clone();
    c.alpn_protocols = zmux::alpn_protocols(&[]);
    Arc::new(c)
}

/// The server configuration with zmux's ALPN identifiers when it has none.
fn server_alpn(tls: Arc<ServerConfig>) -> Arc<ServerConfig> {
    if !tls.alpn_protocols.is_empty() {
        return tls;
    }
    let mut c = (*tls).clone();
    c.alpn_protocols = zmux::alpn_protocols(&[]);
    Arc::new(c)
}

/// The exporter of a TLS 1.3 connection whose handshake completed.
enum Exporter<'a> {
    Client(&'a ClientConnection),
    Server(&'a ServerConnection),
    None,
}

impl<'a> Exporter<'a> {
    fn of<IO>(stream: &'a TlsStream<IO>) -> Self {
        let common = stream.get_ref().1;
        if common.is_handshaking() || common.protocol_version() != Some(ProtocolVersion::TLSv1_3) {
            return Self::None;
        }
        match stream {
            TlsStream::Client(s) => Self::Client(s.get_ref().1),
            TlsStream::Server(s) => Self::Server(s.get_ref().1),
        }
    }

    /// TLS-Exporter(label, "", 32).
    fn export(&self, label: &str) -> Option<Vec<u8>> {
        let out = vec![0u8; EXPORTER_LEN];
        let (label, context) = (label.as_bytes(), Some(&[][..]));
        match self {
            Self::Client(c) => c.export_keying_material(out, label, context).ok(),
            Self::Server(c) => c.export_keying_material(out, label, context).ok(),
            Self::None => None,
        }
    }
}
