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
//! - the sans-IO core (the hidden `proto` module): the wire layer and the
//!   session state machine, without I/O or clock, which the drivers, the
//!   carrier crates and the bindings build on;
//! - the crate root (feature `tokio`, on by default): [`Session`],
//!   [`SendStream`] and [`RecvStream`] over a [`PipeIo`], one tokio task per
//!   session;
//! - `blocking` (feature `blocking`): the same API for threads.
//!
//! Every delivery guarantee, exactly-once in-order stream data across pipes
//! and resumptions included, ends at the peer's zmux endpoint: a completed
//! write, a finished stream or a closed session says nothing about whether
//! the peer's application read, processed or stored the data. Applications
//! that need that acknowledge at their own level, as over TCP.
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
//! | Carrier | Crate | Passes HTTP proxies and CDNs | Lanes | Exporter (`PipeAuth::exporter`) |
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
#![warn(missing_debug_implementations)]
mod driver;
mod error;
#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
pub mod helpers;
// The sans-IO core and the wire codecs: what the drivers, the carrier
// adapters, the secure carrier crates and the language bindings build on.
// No stable API: applications use the items the crate root re-exports.
#[doc(hidden)]
pub mod proto;
pub mod redirect;
pub mod util;

pub use driver::{DialRequest, PipeDirection, StreamId};
pub use error::{ConnectError, ReadExactError, ReadToEndError};
pub use proto::admission::{
    Admission, AdmissionVerdict, AdmittedValue, CarrierCredential, CarrierInfo, Decide,
    DecideFuture, Decision, PEEK_TIMEOUT_DRAWN, STALL_MAX_DRAWN,
};
pub use proto::exporter::{CarrierExporter, ExportError, RESERVED_EXPORTER_PREFIX, TlsState};
pub use proto::frame::{Dir, Priority};
pub use proto::ident::{FirstBytes, MAX_FIRST_BYTES, classify_first_bytes};
pub use proto::ident::{alpn_protocols, default_alpn};
pub use proto::limit::{DatagramLimiter, Limiter};
pub use proto::listener::{
    ListenerConfig, MAX_INSTANCE_ID_LEN, MemoryPressure, OnMemoryPressure, OnReject, RejectAction,
    RejectError, RejectInfo,
};
pub use proto::listener::{SessionCarrier, SessionConfigFn};
pub use proto::meter::{AppBytes, Meter};
pub use proto::oob::{PAIR_HEADER, PAIRING_TOKEN_LEN};
pub use proto::params::DEFAULT_MAX_RECORD_SIZE;
pub use proto::params::Role;
pub use proto::prefix_auth::{
    InvalidPrefixAuth, PREFIX_AUTH_BINDING_LEN, PREFIX_AUTH_EXPORTER_LABEL, PREFIX_AUTH_HEADER,
    PREFIX_TOKEN_LEN, PrefixAuth, PrefixAuthVerifier,
};
pub use proto::replay::{InvalidReplayConfig, ReplayFilter, ReplayVerdict};
pub use proto::seal::SessionCrypto;
pub use proto::session::InvalidConfig;
pub use proto::session::shaping;
pub use proto::session::{
    AllowRecordMode, AuthorizeJoin, RecordMode, RecordPolicy, RecordPolicyInput,
};
pub use proto::session::{
    CandidateOutcome, CandidateResult, Cap, CapacityFloor, CarrierKind, Change, Config,
    DEFAULT_HANDSHAKE_TIMEOUT, DEFAULT_IDLE_TIMEOUT, DEFAULT_JOIN_TIMEOUT,
    DEFAULT_KEEP_ALIVE_PERIOD, DEFAULT_LATENCY_BUDGET, DEFAULT_MAX_BACKOFF, DEFAULT_MEMORY_BUDGET,
    DEFAULT_MIN_BACKOFF, DEFAULT_OVERFLOW_DELAY, DEFAULT_PROBE_INTERVAL, DEFAULT_PROBE_JITTER,
    DEFAULT_SEND_BUFFER_MAX, DEFAULT_STANDBY_PROBE, DEFAULT_SUSPECT_FLOOR, DatagramError,
    DirectionState, EarlyData, EarlyDataState, EpochPolicy, GoAway, InboundState, Inherit,
    JoinMissing, LaneStats, Liveness, LogLevel, Logger, MAX_STREAM_CREDIT, Multipath, OpenError,
    OutboundState, PipeAuth, PipeError, PipeFailure, PipeHalf, PipeId, PipeLiveness, PipeOptions,
    PipeStats, PipeUpdate, Policy, Preamble, PrioritySource, QualityBand, Redundancy, RttSource,
    SESSION_WINDOW_FLOOR, STREAM_WINDOW_FLOOR, SessionError, SessionEvent, SessionStats,
    State as SessionState, StreamError, StreamStats, Support, Tracer, UniCredit, WindowIncrease,
};

/// The QMux version this crate speaks, the only one: what
/// [`Session::qmux_version`](Session#method.qmux_version) reports.
pub const QMUX_VERSION: &str = proto::draft::CURRENT.name;
pub use proto::trusted::{InvalidNet, IpNet, TrustedProxies, forwarded_early_data};
pub use proto::{DetailKey, VarInt};

// The drivers are left out of loom builds, which check their
// synchronization units only (src/driver/loom.rs).
#[cfg(all(feature = "tokio", not(loom)))]
pub use driver::admission::{Fallback, FallbackStream, Prefixed, proxied_source};
#[cfg(all(feature = "tokio", not(loom)))]
pub use driver::cache::{
    CacheOutcome, CacheSnapshot, CacheSnapshotEntry, CarrierCache, SnapshotError, WallTime,
};
#[cfg(all(feature = "tokio", not(loom)))]
pub use driver::choice::{
    Candidate, CarrierChoice, CarrierChoiceError, CarrierChoicePolicy, HttpTarget, dial_choice,
};
#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
pub use driver::handle::Written;
#[cfg(all(feature = "tokio", not(loom)))]
pub use driver::listen::{
    AdmissionStats, AdmissionVariants, Admit, Admitted, Entry, HandleError, JoinPrefix, Listener,
    ListenerStats, MAX_ADMISSION_VARIANTS, PipeHint, SetupGuard, VariantStats,
};
#[cfg(all(feature = "tokio", not(loom)))]
pub use driver::tokio::{Dial, Pipe, PipeIo, RecvStream, SendStream, Session};
#[cfg(all(feature = "tokio", not(loom)))]
pub use driver::transform::{InboundTransform, PipeStream};

/// What carrier adapters use beyond [`PipeIo`]'s builder methods: the identity
/// of a multi-stream carrier connection, the
/// router of its incoming lanes, and the memory charge of a connection
/// held for a listener's sessions. Applications that only use carriers
/// need none of it. The [`PipeIo`] methods for carrier authors are
/// `from_chunk_halves`, `with_carrier_conn`, `with_lane_opener`, `with_lanes`,
/// `with_connection_memory`, `with_tcp_socket`, `with_unsent`, `with_low_water`,
/// `with_partial_reads`, `with_exporter`, `with_abort`,
/// `with_datagram_channel` and `with_protocol`.
#[cfg(all(feature = "tokio", not(loom)))]
pub mod carrier {
    pub use crate::driver::channel::{
        ChannelDemux, ChannelReceiver, ChannelRegistration, DatagramChannel,
    };
    pub use crate::driver::empty_message;
    pub use crate::driver::lanes::{CarrierConnId, Lane, handle_lane};
    pub use crate::driver::listen::MemoryCharge;
    pub use crate::driver::tokio::{ChunkBuf, ChunkWrite};
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

    /// A byte-stream carrier's halves as Sealed records (tokio driver).
    #[cfg(feature = "tokio")]
    pub use crate::driver::sealed::{
        SealedReadHalf, SealedWriteHalf, sealed_halves as tokio_sealed_halves,
    };

    /// A byte-stream carrier's halves as Sealed records (std driver).
    #[cfg(feature = "blocking")]
    pub use crate::driver::blocking::sealed_halves as blocking_sealed_halves;

    /// Read buffers in the process-wide pool of idle pipes' buffers.
    pub fn read_pool_buffers() -> usize {
        crate::driver::read_pool::len()
    }

    /// How often an outbound pipe of `session` became suspect, a DRAINING
    /// one included, whose public state stays DRAINING and so reports no
    /// `PipeSuspect` (tokio driver).
    #[cfg(feature = "tokio")]
    pub fn suspects(session: &crate::Session) -> u64 {
        session.suspects()
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
/// thread instead of returning a future. Where a tokio future is bounded by
/// its caller (`tokio::time::timeout`, or dropping it), a blocking call is
/// bounded by a timeout: a stream's `set_read_timeout`/`set_write_timeout`
/// bound each of its calls that waits ([`StreamError::TimedOut`]), and a
/// session's [`set_wait_timeout`](blocking::Session#method.set_wait_timeout)
/// bounds every other wait of the session and its pipes (the `TimedOut`
/// variant of the call's error). Since a future of the tokio driver ends
/// only by resolving, its session-wide waits return the [`SessionError`]
/// itself; the blocking ones return a [`blocking::WaitError`], which adds
/// the timeout and the refusal below.
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
/// What only the tokio driver has, and why:
///
/// | | tokio | std | why not in the std driver |
/// |---|---|---|---|
/// | sessions, streams, datagrams, pipes, events, tracer, close and abort | yes | yes | |
/// | `resolve_duplicate` | yes | yes | |
/// | early data under the zmux floor (`EarlyData::zmux_peer`) | yes | yes | |
/// | carrier early data (`PipeIo::with_early_data`, QUIC 0-RTT) | yes | no | only the QUIC and TLS adapters, all async, produce it |
/// | `Listener`: sessions, joins, resumption, `count_setup_failure` | yes | yes | |
/// | `Listener`: split carriers, lanes, admission (`Fallback`, `Prefixed`), memory budget | yes | no | they serve the HTTP and QUIC adapters, all async |
/// | `CarrierChoice`, `dial_choice`, `CarrierCache` | yes | no | its candidates are the async adapters' carriers |
/// | streams as pipes (`open_pipe_stream`, `PipeIo::from_stream`) | yes | no | a nested session's pipe threads would block on the outer stream, which a thread that drives sessions may not do |
/// | lanes, `handle_lane` | yes | no | only multi-stream carriers (QUIC, HTTP/2 and 3) have lanes, all async |
/// | `helpers::splice`, `helpers::maintain_pipes` | yes | no | each runs as a task beside the sessions; a thread per relay or pool would be the application's choice |
/// | adapter crates (TLS, QUIC, WebSocket, HTTP) | yes | no | they build on tokio-based libraries |
///
/// ```no_run
/// # fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use zmux::blocking::{PipeIo, Session};
///
/// let tcp = std::net::TcpStream::connect("127.0.0.1:4433")?;
/// let session = Session::connect(PipeIo::tcp(tcp), zmux::Config::default())?;
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
        Dial, HandshakeWait, Pipe, PipeIo, RecvStream, SendStream, Session, WaitError, Watchdog,
    };
    pub use crate::driver::blocking_listen::{InboundTransform, Listener, PipeHint};
    pub use crate::driver::empty_message;
    pub use crate::proto::listener::{HandleError, ListenerStats};

    /// The helpers of the std driver, as `zmux::helpers` has them for the
    /// tokio one.
    pub mod helpers {
        pub use crate::driver::blocking::{DuplicateOptions, Resolved, resolve_duplicate};
        pub use crate::helpers::{DuplicateError, DuplicateRule};
    }
}

/// The README's examples, compiled as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;
