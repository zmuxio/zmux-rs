//! zmux: multiplexed streams and datagrams over one or many reliable byte pipes.
//!
//! zmux is a session protocol that is wire-compatible with QMux
//! (draft-ietf-quic-qmux-02): QUIC version 1 frames carried in size-prefixed
//! records over reliable byte pipes such as TCP or TLS connections. With a
//! plain QMux peer a session is a plain single-pipe QMux session. Between two
//! zmux endpoints, transport parameters negotiate multipath (many
//! unidirectional pipes with per-frame spreading, failover and reinjection),
//! resumption after all pipes are lost, and the base extensions (roles,
//! GOAWAY, stream preambles, priorities and datagram flows).
//!
//! The crate is built around a sans-IO core:
//!
//! - [`proto`]: the wire layer and the session state machine
//!   ([`proto::session::SessionCore`]), without I/O or clock;
//! - the crate root (feature `tokio`, on by default): [`Session`],
//!   [`SendStream`] and [`RecvStream`] over a [`PipeIo`], one tokio task per
//!   session;
//! - `blocking` (feature `blocking`): the same API for threads.
//!
//! Every delivery guarantee, exactly-once in-order stream data across pipes
//! and resumptions included, ends at the peer's zmux endpoint (SPEC.md
//! Section 7.4): a completed write, a finished stream or a closed session
//! says nothing about whether the peer's application read, processed or
//! stored the data. Applications that need that acknowledge at their own
//! level, as over TCP.
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let tcp = tokio::net::TcpStream::connect("127.0.0.1:4433").await?;
//! let session = zmux::Session::connect(zmux::PipeIo::tcp(tcp), zmux::Config::default()).await?;
//! let (mut send, mut recv) = session.open_bi().await?;
//! send.write_all(b"hello").await?;
//! send.finish()?;
//! let reply = recv.read_to_end(1 << 20).await?;
//! # let _ = reply;
//! # Ok(())
//! # }
//! ```
//!
//! # Choosing a carrier
//!
//! A session runs over any reliable, ordered byte pipe ([`PipeIo`]). The
//! carrier crates turn common transports into pipes, each with `dial`
//! (a [`PipeIo`]), `connect` (a [`Session`]) and `serve` (into a
//! [`Listener`]):
//!
//! | Carrier | Crate | Passes HTTP proxies and CDNs | Lanes | TLS exporter (`PipeAuth::tls`) |
//! |---|---|---|---|---|
//! | TCP | this crate ([`PipeIo::tcp`], [`Listener::serve`]) | no | no | no |
//! | TLS over TCP | `zmux-rustls` | no | no | yes |
//! | QUIC | `zmux-quinn` | no | yes (QUIC streams) | yes |
//! | WebSocket (`ws`, `wss`) | `zmux-websocket` | yes | no | no |
//! | HTTP/1.1, HTTP/2 | `zmux-http` | yes | HTTP/2 only, off by default | no |
//! | HTTP/3 | `zmux-h3` | yes | yes (further requests) | yes |
//! | WebTransport | `zmux-webtransport` | yes | yes | yes |
//!
//! Lanes are further streams of the same connection that carry a pipe's
//! records, so that a loss on one stalls only its own records: they help
//! over QUIC, where streams are independent, and not over a single TCP
//! byte stream. Where the carrier has no TLS exporter, authenticate
//! multipath joins with a pre-shared key ([`PipeAuth::psk`]). The
//! TLS-based carriers take the application's own rustls configuration;
//! the HTTP and WebSocket crates also run over any connection the
//! application set up itself (for example `zmux_http::serve_with` with a
//! TLS handshake as the setup step).
//!
//! # Multipath and resumption
//!
//! Both ends opt in with [`Config::multipath`] and a [`PipeAuth`]. The
//! server takes every carrier through one [`Listener`], which starts new
//! sessions ([`Listener::accept`]) and routes joins to existing ones; the
//! client adds pipes with [`Session::add_pipe`](Session#method.add_pipe), or keeps a
//! pool of them up with [`helpers::maintain_pipes`] and a
//! [`helpers::PipePool`] whose dial function is a carrier crate's `dial`.
//! The session spreads frames over its pipes and fails over and reinjects
//! when one is lost; with `resume_timeout` set ([`Config`]) it also
//! survives losing all of them, resuming on the next pipe that joins in
//! time. [`SessionEvent`]s
//! ([`Session::next_event`](Session#method.next_event)) report pipes joining, failing
//! ([`PipeFailure`]) and changing quality; [`Session::pipe_stats`](Session#method.pipe_stats) and
//! [`Listener::stats`] give the counters.
//!
//! # Relays and nesting
//!
//! A relay accepts a stream, reads its [`Preamble`] (routing metadata in
//! application TLVs), opens the next hop's stream with it and forwards the
//! two into each other with [`helpers::splice`], which forwards data only
//! as the next hop's flow control allows and forwards resets with their
//! Reliable Size. A session can also run inside another one: a stream
//! opened with [`Session::open_pipe_stream`](Session#method.open_pipe_stream) is a pipe of a
//! nested session (on the accepting side, a stream whose preamble
//! [`is a pipe carrier`](Preamble::is_pipe_carrier) becomes one with
//! [`PipeIo::from_stream`]), for
//! example an end-to-end session through relays that see only its
//! records.

// Unsafe code is denied (Cargo.toml) and forbidden in the sans-IO core
// (`proto`); the one exception is the TCP carriers' socket queries and
// low-water mark (`driver/tcp.rs`).
// Loom builds leave the drivers out (src/driver/loom.rs): their helpers go
// unused there.
#![cfg_attr(loom, allow(dead_code, unused_imports))]

mod driver;
mod error;
#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
pub mod helpers;
pub mod proto;

pub use driver::{DialRequest, PipeDirection, StreamId};
pub use error::{ConnectError, ReadExactError, ReadToEndError};
pub use proto::frame::{Dir, Priority};
pub use proto::ident::alpn_protocols;
pub use proto::limit::{DatagramLimiter, Limiter};
pub use proto::listener::{ListenerConfig, MAX_INSTANCE_ID_LEN, MemoryPressure, OnMemoryPressure};
pub use proto::meter::{AppBytes, Meter};
pub use proto::oob::JOIN_HEADER;
pub use proto::params::Role;
pub use proto::session::{
    Cap, CapacityFloor, Config, DatagramError, EarlyData, EarlyDataState, GoAway, LaneStats,
    Multipath, OpenError, PipeAuth, PipeError, PipeFailure, PipeHalf, PipeId, PipeOptions,
    PipeState, PipeStats, Policy, Preamble, PrioritySource, QualityBand, Redundancy, RttSource,
    SessionError, SessionEvent, SessionStats, State as SessionState, StreamError, StreamStats,
    Tracer,
};
pub use proto::{DetailKey, VarInt};

// The drivers are left out of loom builds, which check their
// synchronization units only (src/driver/loom.rs).
#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
pub use driver::handle::Written;
#[cfg(all(feature = "tokio", not(loom)))]
pub use driver::listen::{HandleError, Listener, ListenerStats, PipeHint};
#[cfg(all(feature = "tokio", not(loom)))]
pub use driver::tokio::{Dial, Pipe, PipeIo, PipeReservation, RecvStream, SendStream, Session};

/// What carrier adapters use beyond [`PipeIo`]'s builder methods: the identity
/// of a multi-stream carrier connection, the
/// router of its incoming lanes, and the memory charge of a connection
/// held for a listener's sessions. Applications that only use carriers
/// need none of it. The [`PipeIo`] methods for carrier authors are
/// `with_carrier_conn`, `with_lane_opener`, `with_lanes`,
/// `with_connection_memory`, `with_tcp_socket`, `with_low_water`,
/// `with_partial_reads`, `with_tls_exporter`, `with_abort` and
/// `with_protocol`.
#[cfg(all(feature = "tokio", not(loom)))]
pub mod carrier {
    pub use crate::driver::empty_message;
    pub use crate::driver::lanes::{CarrierConnId, handle_lane};
    pub use crate::driver::listen::MemoryCharge;
}

/// Resource accounting for leak tests (feature `test-hooks`; never enable
/// it in production builds).
#[cfg(all(
    feature = "test-hooks",
    any(feature = "tokio", feature = "blocking"),
    not(loom)
))]
#[doc(hidden)]
pub mod test_hooks {
    pub use crate::driver::resources::{Resources, Tables, resources, take_write_call_bytes};

    /// Read buffers in the process-wide pool of idle pipes' buffers.
    pub fn read_pool_buffers() -> usize {
        crate::driver::read_pool::len()
    }

    /// The Lane Keys in the process's lane routing table (tokio driver).
    #[cfg(feature = "tokio")]
    pub fn lane_keys() -> Vec<[u8; 16]> {
        crate::driver::lanes::registered()
    }
}

/// The std driver: the API of the crate root without `async`. Streams
/// implement `std::io::Read` and `Write`.
///
/// The handles are the crate root's with the std driver: the same types,
/// errors and non-waiting methods; the calls that wait block the calling
/// thread instead of returning a future. A stream's
/// `set_read_timeout`/`set_write_timeout` bound each call that waits
/// ([`StreamError::TimedOut`]).
///
/// A call that may wait fails at once with the `OnDriverThread` variant of
/// its error ([`WaitError::OnDriverThread`](blocking::WaitError) for the
/// session-wide waits, [`StreamError::OnDriverThread`], ...) when it is
/// made on a thread that
/// drives sessions: inside a tokio runtime (`spawn_blocking` included), or
/// on a session's own threads, for example inside a carrier's `Read` or
/// `Write` or an abort closure. Calls that
/// never wait, and waits with a zero timeout, work on any thread.
///
/// What only the tokio driver has (the same API without
/// `async`, for what both drivers have):
///
/// | | tokio | std |
/// |---|---|---|
/// | sessions, streams, datagrams, pipes, events, tracer | yes | yes |
/// | `resolve_duplicate` | yes | yes |
/// | early data under the zmux floor (`EarlyData::zmux_peer`) | yes | yes |
/// | carrier early data (`PipeIo::with_early_data`, QUIC 0-RTT) | yes | no |
/// | `Listener` (joins, resumption at the accepting side) | yes | no |
/// | streams as pipes (`open_pipe_stream`, `PipeIo::from_stream`) | yes | no |
/// | lanes, `handle_lane` | yes | no |
/// | `helpers::splice`, `helpers::maintain_pipes` | yes | no |
/// | adapter crates (TLS, QUIC, WebSocket, HTTP) | yes | no |
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use zmux::blocking::{PipeIo, Session};
///
/// let tcp = std::net::TcpStream::connect("127.0.0.1:4433")?;
/// let session = Session::connect(PipeIo::tcp(tcp)?, zmux::Config::default())?;
/// let (mut send, mut recv) = session.open_bi()?;
/// send.write_all(b"hello")?;
/// send.finish()?;
/// let reply = recv.read_to_end(1 << 20)?;
/// # let _ = reply;
/// # Ok(())
/// # }
/// ```
#[cfg(all(feature = "blocking", not(loom)))]
pub mod blocking {
    pub use crate::driver::blocking::{
        Dial, DuplicateOptions, Pipe, PipeIo, PipeReservation, RecvStream, Resolved, SendStream,
        Session, WaitError, resolve_duplicate,
    };
    pub use crate::driver::empty_message;
}
