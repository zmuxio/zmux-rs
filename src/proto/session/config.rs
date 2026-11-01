//! Session configuration and the transport parameters it
//! produces (SPEC.md Section 5.3).

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::Tracer;
use super::policy::Policy;
use crate::proto::keys::secret_flags;
use crate::proto::limit::DatagramLimiter;
use crate::proto::params::floor;
use crate::proto::params::{
    Grease, LanesParameter, Locator, MultipathParameter, RoleParameter, TransportParameters,
    ZMUX_MAX_RECORD_SIZE, grease_id,
};

/// Join credentials: the secret sources this endpoint offers for pipe joins
/// (MULTIPATH.md Section 10.1). There is no default:
/// a configuration that offers multipath without them is refused
/// ([`crate::ConnectError::InvalidConfig`]).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PipeAuth {
    pub(crate) exporter: bool,
    pub(crate) psk: Option<Vec<u8>>,
    pub(crate) insecure: bool,
}

impl PipeAuth {
    /// No credentials (the default): multipath cannot be offered.
    pub fn none() -> Self {
        Self::default()
    }

    /// Derives the join secret from the exporter of the innermost
    /// end-to-end handshake of the bootstrap carriers (E); today its
    /// source is TLS 1.3 that this process terminates (a TLS connection,
    /// or the QUIC connection under the carrier). The driver supplies the
    /// exporter value of the bootstrap carrier; a carrier without one
    /// fails the session.
    pub fn exporter() -> Self {
        Self {
            exporter: true,
            ..Self::default()
        }
    }

    /// A pre-shared key of at least 16 bytes (P): static, or derived per
    /// session by the application from its own authenticated exchange
    /// (MULTIPATH.md Section 10.2).
    pub fn psk(key: impl Into<Vec<u8>>) -> Self {
        Self {
            psk: Some(key.into()),
            ..Self::default()
        }
    }

    /// Allows insecure joins (I): only for deployments protected by other
    /// means. Cannot be combined with a PSK.
    pub fn insecure() -> Self {
        Self {
            insecure: true,
            ..Self::default()
        }
    }

    /// Adds a pre-shared key to these credentials.
    #[must_use]
    pub fn with_psk(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.psk = Some(key.into());
        self
    }

    /// The Secret Flags these credentials select.
    pub fn flags(&self) -> u8 {
        let mut f = 0;
        if self.exporter {
            f |= secret_flags::EXPORTER;
        }
        if self.psk.is_some() {
            f |= secret_flags::PSK;
        }
        if self.insecure {
            f |= secret_flags::INSECURE;
        }
        f
    }
}

impl fmt::Debug for PipeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipeAuth")
            .field("exporter", &self.exporter)
            .field("psk", &self.psk.as_ref().map(|_| ".."))
            .field("insecure", &self.insecure)
            .finish()
    }
}

/// The role argument of session creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoleConfig {
    /// The dialling side; uses the transport role, sends no `zmux_role`.
    Initiator,
    /// The accepting side; uses the transport role, sends no `zmux_role`.
    Responder,
    /// A symmetric carrier: sends `zmux_role` auto with a random nonce
    /// (EXTENSIONS.md Section 2).
    Auto,
}

/// A per-pipe override of the session's probe interval: a period, or off.
///
/// The override fields (`Option<Period>` of
/// [`PipeOptions`](crate::proto::session::PipeOptions) and of the pool
/// decision) keep the session's setting when `None`, which is why off needs
/// a variant of its own here; [`Config`]'s own periods are plain
/// `Option<Duration>`, `None` being off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Period {
    /// Run with this period.
    Every(Duration),
    /// Turned off.
    Off,
}

impl Period {
    /// The period; `None` when off.
    #[must_use]
    pub const fn duration(self) -> Option<Duration> {
        match self {
            Self::Every(d) => Some(d),
            Self::Off => None,
        }
    }

    /// Whether this is off or a period of at least 1 s, the range of the
    /// probe intervals.
    pub(crate) fn off_or_seconds(self) -> bool {
        self.duration().is_none_or(|d| d >= Duration::from_secs(1))
    }
}

impl From<Duration> for Period {
    fn from(d: Duration) -> Self {
        Self::Every(d)
    }
}

/// A memory budget: a number of bytes, or unlimited.
///
/// A budget of `Bytes(0)` is a budget of no byte: nothing grows beyond the
/// floors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Budget {
    /// At most this many bytes.
    Bytes(u64),
    /// No limit.
    Unlimited,
}

impl Budget {
    /// The bytes; `None` when unlimited.
    #[must_use]
    pub const fn bytes(self) -> Option<u64> {
        match self {
            Self::Bytes(b) => Some(b),
            Self::Unlimited => None,
        }
    }
}

impl From<u64> for Budget {
    fn from(b: u64) -> Self {
        Self::Bytes(b)
    }
}

/// The default handshake timeout ([`Config::handshake_timeout`]).
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The default probe interval of idle pipe pairs ([`Config::probe_interval`](Config#structfield.probe_interval)).
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// The default keep-alive period ([`Config::keep_alive_period`]).
pub const DEFAULT_KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(15);

/// The default standby probe interval ([`Config::standby_probe`](Config#structfield.standby_probe)).
pub const DEFAULT_STANDBY_PROBE: Duration = Duration::from_secs(1);

/// The default idle timeout ([`Config::max_idle_timeout`]).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The default probe jitter j ([`Config::probe_jitter`]).
pub const DEFAULT_PROBE_JITTER: f64 = 0.25;

/// The default overflow delay D of tier gating.
pub const DEFAULT_OVERFLOW_DELAY: Duration = Duration::from_secs(1);

/// The default latency budget B of receive-window auto-tuning.
pub const DEFAULT_LATENCY_BUDGET: Duration = Duration::from_micros(100);

/// The floor of the automatic maximum of the session send buffer in
/// multipath sessions, which also caps the retransmit budget: the stream window floor.
pub const DEFAULT_SEND_BUFFER_MAX: u64 = 64 * 1024 * 1024;

/// The floor of the automatic stream window cap: K x the BDP of the
/// 1 Gbit/s x 100 ms design point (4 x 12.5 MB) rounded up to a power of
/// two.
pub const STREAM_WINDOW_FLOOR: u64 = 64 * 1024 * 1024;

/// The floor of the automatic session window cap, 1.5 x the stream floor;
/// also the cap the session receive buffer cap is computed from (SPEC.md
/// Section 8.3 rule 4).
pub const SESSION_WINDOW_FLOOR: u64 = 96 * 1024 * 1024;

/// The default memory budget of a session without a listener, the same as a listener's.
pub const DEFAULT_MEMORY_BUDGET: u64 = 1 << 30;

/// A memory bound of the configuration: the window caps and the send
/// buffer maximum. These are memory
/// bounds, not protocol limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cap {
    /// The default: a floor, and above it as far as the measured rate and
    /// RTT ask and the memory budget allows, the listener's `MemoryBudget`
    /// or the session's own `memory_budget`.
    #[default]
    Auto,
    /// A fixed bound.
    Fixed(u64),
}

/// The `initial_max_streams_uni` of an unset `max_incoming_uni_streams`,
/// and the limit the first accept raises it to (SPEC.md Section 8.5 rule
/// 4).
pub(crate) const STAGED_UNI_STREAMS: (u64, u64) = (16, 256);

/// The predicate of `allow_connection_window_increase`:
/// it is shown the proposed increase of the session receive window and
/// answers whether to allow it. It runs outside every zmux lock on the
/// session's hook context, never on a
/// driver thread; a panic counts as a refusal.
#[derive(Clone)]
pub struct WindowIncrease(pub Arc<dyn Fn(u64) -> bool + Send + Sync>);

impl fmt::Debug for WindowIncrease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WindowIncrease(..)")
    }
}

/// Which stream directions of a multipath session send copies of their
/// chunks on a second pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Redundancy {
    /// Directions of urgency 0 to 2 (the default).
    #[default]
    Urgent,
    /// None, unless a stream turns it on.
    Off,
}

/// Session configuration. The fields map to the configuration knobs.
///
/// # Example
///
/// A multipath session that spreads every stream over its pipes, with
/// resumption after all pipes are lost:
///
/// ```
/// use std::time::Duration;
/// use zmux::{Config, PipeAuth, Policy};
///
/// let mut config = Config::default();
/// config.max_pipes = 8;
/// config.resume_timeout = Some(Duration::from_secs(60));
/// config.pipe_auth = PipeAuth::psk(b"a pre-shared key, 16 bytes or more".to_vec());
/// config.scheduler = Policy::SpreadEta;
/// // Let the preferred tier queue up to 200 ms before a fallback tier
/// // takes the excess.
/// config.overflow_delay = Duration::from_millis(200);
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// Abandon establishment and unconfirmed joins and lanes after this
    /// long (default [`DEFAULT_HANDSHAKE_TIMEOUT`], 10 s; `None` is no
    /// timeout).
    pub handshake_timeout: Option<Duration>,
    /// `max_idle_timeout` (default [`DEFAULT_IDLE_TIMEOUT`], 30 s; `None`
    /// is no local limit and announces none). A set duration is at least
    /// 1 ms, the unit of the transport parameter, whose 0 means none.
    pub max_idle_timeout: Option<Duration>,
    /// Send QX_PING after this much silence (default
    /// [`DEFAULT_KEEP_ALIVE_PERIOD`], 15 s; `None` turns keep-alive off; a
    /// period below 1 s, zero included, is not valid).
    /// The period in effect is capped at half the effective idle timeout, and each wait is drawn from \[k (1 - j), k\]
    /// with j the [`probe_jitter`](Self::probe_jitter) (SPEC.md Section
    /// 6.4). On, an idle session stays open while the peer answers and
    /// closes within the idle timeout once its carrier dies; off, the idle
    /// timeout ends any session without application activity.
    pub keep_alive_period: Option<Duration>,
    /// Initial stream receive window (default 256 KiB; at least 4 KiB,
    /// the early-data floor of [`params::floor`](floor)).
    pub initial_stream_receive_window: u64,
    /// Cap of auto-tuned stream windows (default [`Cap::Auto`]: at least
    /// [`STREAM_WINDOW_FLOOR`], 64 MiB, K x the BDP of the 1 Gbit/s x
    /// 100 ms design point, and beyond it as far as auto-tuning asks and
    /// the memory budget allows).
    pub max_stream_receive_window: Cap,
    /// The latency budget B of auto-tuning, a parameter of
    /// `max_stream_receive_window` (default 100 us): each window is the
    /// arrival rate times max(4 x RTT_min, B).
    pub latency_budget: Duration,
    /// Initial session receive window (default 1 MiB; at least 16 KiB,
    /// the early-data floor of [`params::floor`](floor)).
    pub initial_connection_receive_window: u64,
    /// Cap of the auto-tuned session window (default [`Cap::Auto`]: at
    /// least [`SESSION_WINDOW_FLOOR`], 96 MiB, and beyond it within the
    /// memory budget). The session receive buffer cap is computed from a
    /// fixed cap or from the floor, never from a grown window (SPEC.md
    /// Section 8.3 rule 4).
    pub max_connection_receive_window: Cap,
    /// The `memory_budget` parameter of `max_connection_receive_window`
    /// (`None`, the default, is [`DEFAULT_MEMORY_BUDGET`], 1 GiB;
    /// [`Budget::Unlimited`] lifts it): the memory budget of a session
    /// without a listener, a listener's `MemoryBudget` otherwise. Buffered,
    /// retained and unread bytes and the session
    /// window's growth count against it; window and send-buffer growth
    /// above the floors of [`Cap::Auto`] stops at it.
    pub memory_budget: Option<Budget>,
    /// Concurrent bidirectional streams the peer may open (default 256; 0,
    /// or at least 4, the early-data floor of [`params::floor`](floor)). An
    /// application that never accepts peer streams sets 0; a peer's early
    /// data then fails with `EarlyDataRejected` at the peer.
    pub max_incoming_streams: u64,
    /// Concurrent unidirectional streams the peer may open. `None` (the
    /// default) stages the credit: `initial_max_streams_uni` is 16 and
    /// MAX_STREAMS 256 is sent when the application first accepts a
    /// unidirectional stream (SPEC.md Section 8.5 rule 4). A value
    /// (including 0) is advertised at once.
    pub max_incoming_uni_streams: Option<u64>,
    /// Announce datagram support (default false).
    pub enable_datagrams: bool,
    /// Datagrams waiting for a pipe (default 64, at least 1); when the
    /// queue is full the oldest is dropped (EXTENSIONS.md Section 6.5).
    pub datagram_send_queue: usize,
    /// Received session datagrams (flow 0) waiting for the application
    /// (default 128, at least 1); the oldest make room.
    pub datagram_receive_queue: usize,
    /// Received datagrams waiting per stream (default 32, at least 1); the
    /// stream's oldest make room.
    pub datagram_stream_queue: usize,
    /// Bytes of every received datagram queue together, those held for
    /// streams not opened yet included (default 1 MiB, at least 1).
    pub datagram_receive_bytes: usize,
    /// Written-but-unreleased bytes per session before writes wait
    /// (default 4 MiB): unsent on a single pipe, unacknowledged in a
    /// multipath session. Shared fairly between stream directions, each of
    /// which can always hold 64 KiB.
    pub send_buffer: u64,
    /// The `max` parameter of `send_buffer` (default [`Cap::Auto`]: at
    /// least [`DEFAULT_SEND_BUFFER_MAX`], 64 MiB, and beyond it within the
    /// memory budget, which retained data is charged to): in a multipath
    /// session the send buffer grows to the retransmit budget up to this,
    /// which also caps that budget. A fixed
    /// value below `send_buffer` counts as `send_buffer`.
    pub send_buffer_max: Cap,
    /// The largest Frames field of the records this endpoint sends, before
    /// the peer's `max_record_size` caps it (default 16382, one TLS record).
    pub max_send_record: usize,
    /// The attachments this endpoint aims for with its own joins. 1 (the
    /// default) keeps multipath off; 8 is the recommended value when
    /// multipath is used. The peer may have up to `max_pipes +
    /// pipe_headroom` attachments live at once (MULTIPATH.md Section 5.4
    /// step 9).
    pub max_pipes: u32,
    /// The attachment headroom H, a parameter of `max_pipes` (default 8):
    /// room for failed attachments whose retirement has not completed
    /// (MULTIPATH.md Section 5.4 step 9).
    pub pipe_headroom: u32,
    /// The replay window W, a parameter of `max_pipes`, in pipe IDs of the
    /// peer's parity; `None` (the default) is max(64, 2 x (max_pipes + H)),
    /// and a value must be at least max_pipes + H (MULTIPATH.md Section
    /// 4.3).
    pub replay_window: Option<u64>,
    /// The lanes accepted on each inbound pipe, lane 0 included, a
    /// parameter of `max_pipes` that applies to every session, single-pipe
    /// ones included (default 258; any value, and 1 accepts no lanes): the `zmux_max_lanes` this endpoint sends (MULTIPATH.md
    /// Sections 2.5 and 3.6). Outbound lanes follow the peer's value and
    /// the carrier.
    pub max_lanes: std::num::NonZeroU64,
    /// Resume grace period; `None` (the default) disables resume.
    pub resume_timeout: Option<Duration>,
    /// The session's default scheduling policy (default `affinity`).
    pub scheduler: Policy,
    /// Upper bounds of what the session's shapers add (default: none).
    pub shaping_limits: super::shaping::Limits,
    /// The shaper factory installed when the session is created (default:
    /// none), as if by `set_shaper`: every pipe of the session, the
    /// bootstrap pipe of an accepted session and joined pipes included, is
    /// shaped from its first record. `set_shaper` replaces it.
    pub shaper: Option<Arc<dyn super::shaping::Factory>>,
    /// The `spread-eta` chunk size (default 16 KiB).
    pub spread_chunk: usize,
    /// The floor of T_suspect for every pipe (default 250 ms, at least
    /// 50 ms; MULTIPATH.md Section 7.1).
    pub suspect_floor: Duration,
    /// dead_timeout (at least 1 s): how long the last pipe of a direction
    /// may stall before it fails, effective max(T_suspect, dead_timeout).
    /// `None`: T_fail with resume, max(T_fail, half the idle timeout)
    /// without (MULTIPATH.md Section 7.1).
    pub dead_timeout: Option<Duration>,
    /// The base of the probation of pipes that join or return from
    /// suspicion; `None` (the default) is 4 x smoothed RTT for the first
    /// join of a path without history and max(1 s, 4 x smoothed RTT)
    /// otherwise, zero disables probation.
    pub probation: Option<Duration>,
    /// The overflow delay D of tier gating: a
    /// tier is saturated when the data offered to it and queued on its
    /// pipes would take longer than this to drain at its aggregate rate,
    /// or data has waited for it longer; only the excess goes to the next
    /// tier. Default 1 s.
    pub overflow_delay: Duration,
    /// The `redundancy` parameter of `scheduler` (default
    /// [`Redundancy::Urgent`]): which stream directions have copies of
    /// their chunks sent on a second pipe of the tier; a stream's `set_redundant` overrides it.
    pub redundancy: Redundancy,
    /// The `standby_probe` parameter of `scheduler` (default
    /// [`DEFAULT_STANDBY_PROBE`], 1 s; `None` turns these
    /// faster probes off, leaving such pipes at the probe interval; a
    /// period below 1 s is not valid): how often standby pipes and pipes of a
    /// less-preferred tier get a PIPE_PING while the session is busy, a
    /// traffic frame having been sent or received within the last 15 s
    /// (MULTIPATH.md Section 7.1). A quiet session probes them at the
    /// probe interval, and once more when traffic resumes.
    pub standby_probe: Option<Duration>,
    /// The `probe_interval` parameter of `scheduler` (default
    /// [`DEFAULT_PROBE_INTERVAL`], 15 s; `None` turns these
    /// idle probes off, and a period below 1 s is not valid): how long an outbound pipe
    /// of a pipe pair stays without an ack-eliciting byte handed to its
    /// carrier before it gets a PIPE_PING (MULTIPATH.md Section 7.1). A
    /// longer interval only delays the detection of a pipe pair that dies
    /// while idle. Off turns off only these probes: the PIPE_PING that
    /// goes with the answer to the peer's, the standby probes and the
    /// probes of attachments without an outbound direction at the peer
    /// stay, and a pipe pair with them off at both ends is not judged while the
    /// session is quiet. The deadline is measured to the carrier: records
    /// that shaping may hold for up to `max_delay` are built that much
    /// earlier (but not more often than every second). A pipe's
    /// [`PipeOptions::probe_interval`](crate::PipeOptions::probe_interval)
    /// replaces it. Pipes whose attachment has no outbound direction at the
    /// peer are always probed, at most every 15 s (the protocol constant
    /// on which the peer's inbound silence rule relies).
    pub probe_interval: Option<Duration>,
    /// The `probe_jitter` parameter of `scheduler` (default 0.25, at least
    /// 0 and below 1): each wait for an idle probe is drawn once, when it
    /// starts (the pipe becomes ACTIVE, or a PIPE_PING was sent), uniformly
    /// from \[k (1 - j), k\] for the probe interval k (MULTIPATH.md Section
    /// 7.1), and the first wait of the bootstrap pipe from \[0, k\];
    /// ack-eliciting bytes sent meanwhile move its start without a new
    /// draw. The interval stays the upper bound. Zero gives the fixed
    /// schedule of tests; the standby probes are never jittered. The draws
    /// come from a generator seeded by the operating system's.
    pub probe_jitter: f64,
    /// `allow_connection_window_increase`: when set,
    /// the session receive window grows only by increases the predicate
    /// approves. The core keeps at most one proposal outstanding; the
    /// driver runs the predicate outside every lock.
    pub allow_connection_window_increase: Option<WindowIncrease>,
    /// `datagram_limiter`: limiters that police the
    /// datagrams of each direction; unset (the default) nothing is called.
    /// The core never calls them: the driver asks them outside every lock
    /// and passes the verdicts ([`super::SessionCore::send_datagram`],
    /// [`super::ReceivedDatagram`]).
    pub datagram_limiter: DatagramLimiter,
    /// Join credentials (required for multipath).
    pub pipe_auth: PipeAuth,
    /// `protocols`: application protocols to
    /// offer, in preference order, with the `qmux` crate's
    /// `application_protocols` transport parameter, for carriers without
    /// TLS (SPEC.md Section 13.3). The protocol both offered (the
    /// accepting side's preference first) is the session's `protocol()`.
    /// `None` (the default) sends nothing; interoperability only, not part
    /// of zmux.
    pub protocols: Option<Vec<String>>,
    /// `tracer`: observes the session's events, called
    /// in order outside every lock on the session's hook context. `None` (the default) costs
    /// nothing.
    pub tracer: Option<Arc<dyn Tracer>>,
    /// `early_data` (default off): stream data before the peer's
    /// parameters arrive; see [`EarlyData`].
    pub early_data: EarlyData,
    /// The Session Locator this endpoint announces: set by a listener that
    /// routes joins to the session (and, for the sans-IO core's tests, by
    /// `TestHooks::locator`); empty accepts no joins.
    pub(crate) locator: Vec<u8>,
    pub(crate) hooks: TestHooks,
}

/// Early data: stream data sent before the peer's transport parameters
/// arrive, saving the round trip that would otherwise pass before the
/// first stream byte. Off by default.
///
/// With [`EarlyData::zmux_peer`] the application declares the peer a zmux
/// endpoint. Every zmux endpoint advertises at least the floor of
/// [`params::floor`](floor), so data within it needs no
/// parameters: at most the first 4 bidirectional streams, 4096 bytes of
/// each (preamble included) and 16384 bytes in all. Opening more streams
/// and writing more is allowed; what lies beyond the floor simply waits
/// and goes out once the parameters arrive. If the declaration was wrong
/// (the peer is a plain QMux endpoint, or accepts no bidirectional
/// streams), the peer processed none of the early data and the session
/// ends with [`SessionError::EarlyDataRejected`](super::SessionError):
/// open the streams again on a new session without early data. Early data
/// needs a role that does not depend on the peer: `Session::peer` (role
/// auto) refuses a configuration with it as
/// [`ConnectError::InvalidConfig`](crate::ConnectError::InvalidConfig), and
/// the sans-IO core given role auto sends no early data.
///
/// [`EarlyData::carrier_early_data`] allows TLS 1.3 early data or QUIC
/// 0-RTT on a resumed carrier. Such data can be replayed by an attacker:
/// a client allows it only for streams whose effect may happen twice, and
/// a server that allows it sees the streams opened in it as replayable
/// until the handshake completes
/// (`RecvStream::is_replayable`).
/// The flow: (1) a first session, established in full, yields the
/// server's parameters (`Session::parameters_to_remember`);
/// (2) the client keeps them with the carrier's resumption state; (3) a
/// resumed carrier is given them ([`PipeIo::with_early_data`](crate::PipeIo::with_early_data)),
/// and the session's first records go out as carrier early data; (4) if
/// the carrier rejects that data, the session writes everything again
/// once the handshake completed, and no stream fails. The QUIC adapter
/// (`zmux-quinn`, `connect`) does all four with a parameter memory and
/// documents a complete client.
///
/// A session that ends with `EarlyDataRejected` is the one end that
/// [`SessionError::is_retryable`](super::SessionError::is_retryable) reports:
///
/// ```no_run
/// # async fn f(carrier: zmux::PipeIo, again: zmux::PipeIo) -> Result<(), zmux::ConnectError> {
/// use zmux::{Config, EarlyData, Session};
///
/// let mut config = Config::default();
/// config.early_data = EarlyData::for_zmux_peer();
/// let session = Session::connect(carrier, config.clone()).await?;
/// let (send, recv) = session.open_bi().await.map_err(|e| zmux::ConnectError::Io(std::sync::Arc::new(e.into())))?;
/// // ... the request leaves with the parameters, before the peer's arrive ...
/// # drop((send, recv));
/// if session.closed().await.is_early_data_rejected() {
///     // The peer is not a zmux endpoint and processed nothing.
///     config.early_data = EarlyData::default();
///     let session = Session::connect(again, config).await?;
///     # drop(session);
/// }
/// # Ok(()) }
/// ```
///
/// ```
/// use zmux::{Config, EarlyData};
///
/// // Both ends run zmux: the first request leaves with the parameters.
/// let mut config = Config::default();
/// config.early_data = EarlyData::for_zmux_peer();
/// assert!(config.early_data.zmux_peer && !config.early_data.carrier_early_data);
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct EarlyData {
    /// The peer is declared a zmux endpoint: early data under the floor.
    pub zmux_peer: bool,
    /// Carrier early data (TLS 1.3 early data, QUIC 0-RTT) is allowed, so
    /// early streams may be replayed.
    pub carrier_early_data: bool,
}

impl EarlyData {
    /// Early data toward a peer declared a zmux endpoint, without carrier
    /// early data.
    pub const fn for_zmux_peer() -> Self {
        Self {
            zmux_peer: true,
            carrier_early_data: false,
        }
    }

    /// With the peer declared a zmux endpoint (or not).
    #[must_use]
    pub const fn with_zmux_peer(mut self, on: bool) -> Self {
        self.zmux_peer = on;
        self
    }

    /// With carrier early data allowed (or not); see the type's
    /// documentation for replay.
    #[must_use]
    pub const fn with_carrier_early_data(mut self, on: bool) -> Self {
        self.carrier_early_data = on;
        self
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            handshake_timeout: Some(DEFAULT_HANDSHAKE_TIMEOUT),
            max_idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
            keep_alive_period: Some(DEFAULT_KEEP_ALIVE_PERIOD),
            initial_stream_receive_window: 256 * 1024,
            max_stream_receive_window: Cap::Auto,
            latency_budget: DEFAULT_LATENCY_BUDGET,
            initial_connection_receive_window: 1024 * 1024,
            max_connection_receive_window: Cap::Auto,
            memory_budget: None,
            max_incoming_streams: 256,
            max_incoming_uni_streams: None,
            enable_datagrams: false,
            datagram_send_queue: 64,
            datagram_receive_queue: 128,
            datagram_stream_queue: 32,
            datagram_receive_bytes: 1024 * 1024,
            send_buffer: 4 * 1024 * 1024,
            send_buffer_max: Cap::Auto,
            max_send_record: crate::proto::params::DEFAULT_MAX_RECORD_SIZE as usize,
            max_pipes: 1,
            pipe_headroom: 8,
            replay_window: None,
            max_lanes: crate::proto::params::DEFAULT_MAX_LANES,
            resume_timeout: None,
            scheduler: Policy::Affinity,
            shaping_limits: super::shaping::Limits::default(),
            shaper: None,
            spread_chunk: 16 * 1024,
            suspect_floor: Duration::from_millis(250),
            dead_timeout: None,
            probation: None,
            overflow_delay: DEFAULT_OVERFLOW_DELAY,
            redundancy: Redundancy::Urgent,
            standby_probe: Some(DEFAULT_STANDBY_PROBE),
            probe_interval: Some(DEFAULT_PROBE_INTERVAL),
            probe_jitter: DEFAULT_PROBE_JITTER,
            allow_connection_window_increase: None,
            datagram_limiter: DatagramLimiter::default(),
            pipe_auth: PipeAuth::default(),
            protocols: None,
            tracer: None,
            early_data: EarlyData::default(),
            locator: Vec::new(),
            hooks: TestHooks::default(),
        }
    }
}

/// Deterministic values for the conformance trace runner (TRACES.md Section
/// 3.3). Only reachable with the `test-hooks` feature.
#[doc(hidden)]
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
#[cfg_attr(not(feature = "test-hooks"), allow(unreachable_pub))]
pub struct TestHooks {
    /// Send exactly these transport parameters (plus the GREASE one).
    pub transport_parameters: Option<TransportParameters>,
    /// The GREASE transport parameter.
    pub grease_tp: Option<(u64, Vec<u8>)>,
    /// The GREASE TLV of the first preamble; no other preamble carries one.
    pub grease_tlv: Option<(u64, Vec<u8>)>,
    /// The `zmux_role` nonce.
    pub role_nonce: Option<u64>,
    /// The first QX_PING request sequence number.
    pub ping_seq_start: Option<u64>,
    /// The initial smoothed RTT.
    pub rtt: Option<Duration>,
    /// The `zmux_multipath` Session Nonce.
    pub session_nonce: Option<[u8; 16]>,
    /// The `zmux_max_lanes` Lane Key instead of a random one.
    pub lane_key: Option<[u8; 16]>,
    /// The initial smoothed RTT of particular pipes.
    pub pipe_rtt: Vec<(u64, Duration)>,
    /// The Session Locator a core announces without a listener, so that
    /// joins can be routed to it in tests of the sans-IO core.
    pub locator: Vec<u8>,
    /// The cap of unretired attachments of the peer, instead of max_pipes +
    /// H (MULTIPATH.md Section 5.4 step 9).
    pub pipe_cap: Option<usize>,
    /// No QX_PING request in the first record (the traces predate that
    /// optional sample).
    pub no_first_ping: bool,
    /// The carrier queue limiter paces no carrier: the traces' in-memory
    /// carriers take bytes as the trace says.
    pub unpaced: bool,
    /// The seed of the idle-probe and keep-alive waits' draws instead of
    /// a random one (each pipe's draws follow from it and the pipe ID).
    pub probe_seed: Option<u64>,
    /// Ablations for the scheduler's unit tests, each turning one rule
    /// off. The spreading policies place data at R_p alone, without the
    /// placement rate.
    pub no_placement_rate: bool,
    /// `spread-eta`'s ECF backlog with all ready data of the level for
    /// every direction, not the round robin's share.
    pub no_ecf_share: bool,
    /// `spread-eta`'s BLEST checks all of F against the stream's credit,
    /// not F / n.
    pub no_blest_share: bool,
}

impl Config {
    /// A configuration for multipath: the
    /// recommended `max_pipes` of 8 (MULTIPATH.md Section 15) and the join
    /// credentials, which multipath needs; the rest default.
    ///
    /// ```
    /// use zmux::{Config, PipeAuth};
    ///
    /// let config = Config::multipath(PipeAuth::psk(*b"a pre-shared key of 32 bytes...."));
    /// assert_eq!(config.max_pipes, 8);
    /// ```
    pub fn multipath(pipe_auth: PipeAuth) -> Self {
        Self {
            max_pipes: 8,
            pipe_auth,
            ..Self::default()
        }
    }

    /// The locator this endpoint announces: the listener's, else the test
    /// hook's.
    pub(crate) fn own_locator(&self) -> &[u8] {
        if self.locator.is_empty() {
            &self.hooks.locator
        } else {
            &self.locator
        }
    }

    /// The trace-runner hooks.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn test_hooks(&mut self) -> &mut TestHooks {
        &mut self.hooks
    }

    /// The Maximum Preamble Size this endpoint announces: 4096, or its
    /// smallest initial stream window when that is smaller (EXTENSIONS.md
    /// Section 4.1).
    pub(super) fn preamble_limit(&self) -> u64 {
        self.initial_stream_receive_window.clamp(1, 4096)
    }

    /// A stream's own cap of auto-tuning: a fixed cap, or none (the
    /// automatic cap is the memory allowance, applied as the window grows).
    pub(crate) fn stream_window_cap(&self) -> u64 {
        match self.max_stream_receive_window {
            Cap::Fixed(v) => v,
            Cap::Auto => crate::proto::varint::MAX,
        }
    }

    /// The session window cap a stream's window settings are held to: a
    /// fixed cap, or none.
    pub(crate) fn session_window_cap(&self) -> u64 {
        match self.max_connection_receive_window {
            Cap::Fixed(v) => v,
            Cap::Auto => crate::proto::varint::MAX,
        }
    }

    /// The session window cap the receive buffer cap is computed from: a
    /// fixed cap, or the floor of the automatic one (SPEC.md Section 8.3
    /// rule 4).
    pub(crate) fn session_window_base(&self) -> u64 {
        match self.max_connection_receive_window {
            Cap::Fixed(v) => v,
            Cap::Auto => SESSION_WINDOW_FLOOR,
        }
    }

    /// Whether this endpoint offers multipath.
    pub(crate) fn offers_multipath(&self) -> bool {
        self.max_pipes > 1 || self.resume_timeout.is_some()
    }

    /// The transport parameters this endpoint sends (SPEC.md Section 5.3),
    /// with `zmux_role` auto when `role_nonce` is given.
    pub(crate) fn transport_parameters(
        &self,
        role_nonce: Option<u64>,
        session_nonce: [u8; 16],
        lane_key: [u8; 16],
    ) -> TransportParameters {
        if let Some(tp) = &self.hooks.transport_parameters {
            return tp.clone();
        }
        let idle = self.idle_millis();
        let window = self.initial_stream_receive_window;
        let mp = self.offers_multipath();
        let resume = self
            .resume_timeout
            .map(|t| u64::try_from(t.as_millis()).unwrap_or(u64::MAX).max(1));
        TransportParameters {
            zmux_multipath: mp.then(|| MultipathParameter {
                secret_flags: self.pipe_auth.flags(),
                session_nonce,
                locator: Locator::new(self.own_locator()).unwrap_or_default(),
            }),
            zmux_resume: resume.filter(|_| mp),
            max_idle_timeout: (idle > 0).then_some(idle),
            initial_max_data: Some(self.initial_connection_receive_window),
            initial_max_stream_data_bidi_local: Some(window),
            initial_max_stream_data_bidi_remote: Some(window),
            initial_max_stream_data_uni: Some(window),
            initial_max_streams_bidi: Some(self.max_incoming_streams),
            initial_max_streams_uni: Some(
                self.max_incoming_uni_streams
                    .unwrap_or(STAGED_UNI_STREAMS.0),
            ),
            reset_stream_at: true,
            max_datagram_frame_size: self.enable_datagrams.then_some(ZMUX_MAX_RECORD_SIZE),
            max_record_size: Some(ZMUX_MAX_RECORD_SIZE),
            zmux_role: role_nonce.map(|nonce| RoleParameter::Auto { nonce }),
            zmux_goaway: true,
            zmux_preamble: Some(self.preamble_limit()),
            zmux_priority: true,
            zmux_pipe_ack: true,
            zmux_max_lanes: Some(LanesParameter {
                max_lanes: self.max_lanes,
                lane_key,
            }),
            zmux_datagram_flows: self.enable_datagrams,
            // A pipe that a multipath session joins may have a datagram
            // channel; a single-pipe session announces it only when its
            // bootstrap carrier has one ([`super::SessionCore::set_pipe_channel`]).
            zmux_carrier_datagrams: self.enable_datagrams && mp,
            application_protocols: self
                .protocols
                .as_ref()
                .map(|p| p.iter().map(|n| n.as_bytes().to_vec()).collect()),
            ..TransportParameters::default()
        }
    }

    /// The GREASE parameter: the hook's, or a random one (SPEC.md Section
    /// 5.2 rule 6).
    pub(crate) fn grease_parameter(&self, random: u64) -> (u64, Vec<u8>) {
        if let Some(g) = &self.hooks.grease_tp {
            return g.clone();
        }
        let n = random & 0xffff_ffff;
        let id = grease_id(n).unwrap_or(27);
        let len = ((random >> 32) % 17) as usize;
        let value = (0..len).map(|i| (random >> (i % 8 * 8)) as u8).collect();
        (id, value)
    }

    /// The handshake timeout in effect: [`Config::handshake_timeout`], or
    /// its default; `Duration::MAX`, a deadline that never comes, for no
    /// timeout.
    #[must_use]
    pub fn handshake_wait(&self) -> Duration {
        self.handshake_timeout.unwrap_or(Duration::MAX)
    }

    /// The `max_idle_timeout` this endpoint announces, in milliseconds
    /// (0: none).
    pub(crate) fn idle_millis(&self) -> u64 {
        self.max_idle_timeout
            .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
    }

    /// The keep-alive period in effect; `None` when off.
    pub(crate) fn keep_alive(&self) -> Option<Duration> {
        self.keep_alive_period
    }

    /// The memory budget in effect; `None` when unlimited.
    pub(crate) fn memory_budget(&self) -> Option<u64> {
        self.memory_budget
            .unwrap_or(Budget::Bytes(DEFAULT_MEMORY_BUDGET))
            .bytes()
    }

    /// The standby probe interval in effect; `None` when off.
    pub(crate) fn standby_probe(&self) -> Option<Duration> {
        self.standby_probe
    }

    /// The probe interval of idle pipe pairs in effect.
    pub(crate) fn probe_interval(&self) -> Option<Duration> {
        self.probe_interval
    }

    pub(crate) fn validate(&self) -> Result<(), &'static str> {
        let fixed = |c: Cap| match c {
            Cap::Auto => u64::MAX,
            Cap::Fixed(v) => v,
        };
        if self.initial_stream_receive_window > fixed(self.max_stream_receive_window) {
            return Err("initial_stream_receive_window above max_stream_receive_window");
        }
        if self.initial_connection_receive_window > fixed(self.max_connection_receive_window) {
            return Err("initial_connection_receive_window above max_connection_receive_window");
        }
        // Every zmux endpoint advertises at least the early-data floor
        // (SPEC.md Section 6.1.2).
        if self.initial_stream_receive_window < floor::MAX_STREAM_DATA {
            return Err("initial_stream_receive_window below the 4 KiB early-data floor");
        }
        if self.initial_connection_receive_window < floor::MAX_DATA {
            return Err("initial_connection_receive_window below the 16 KiB early-data floor");
        }
        if self.max_incoming_streams != 0 && self.max_incoming_streams < floor::MAX_STREAMS_BIDI {
            return Err("max_incoming_streams neither 0 nor at least the early-data floor of 4");
        }
        if self.max_incoming_streams > 1 << 60
            || self.max_incoming_uni_streams.unwrap_or(0) > 1 << 60
        {
            return Err("stream limits above 2^60");
        }
        // Values sent as variable-length integers.
        let varint_max = (1u64 << 62) - 1;
        let windows = [
            self.max_stream_receive_window,
            self.max_connection_receive_window,
        ];
        if windows
            .into_iter()
            .any(|c| matches!(c, Cap::Fixed(v) if v > varint_max))
            || self.initial_stream_receive_window > varint_max
            || self.initial_connection_receive_window > varint_max
            || self.idle_millis() > varint_max
        {
            return Err("a window or timeout is too large to encode");
        }
        if !(1024..=65535).contains(&self.max_send_record) {
            return Err("max_send_record outside 1024..=65535");
        }
        if self.send_buffer == 0 {
            return Err("send_buffer is zero");
        }
        if self.datagram_send_queue == 0
            || self.datagram_receive_queue == 0
            || self.datagram_stream_queue == 0
            || self.datagram_receive_bytes == 0
        {
            return Err("a datagram queue or the datagram receive bytes is zero");
        }
        if self.max_pipes == 0 {
            return Err("max_pipes is zero");
        }
        if self.max_lanes.get() > varint_max {
            return Err("max_lanes above 2^62 - 1");
        }
        if self.own_locator().len() > 16 {
            return Err("locator above 16 bytes");
        }
        if self.suspect_floor < Duration::from_millis(50) {
            return Err("suspect_floor below 50 ms");
        }
        if self
            .dead_timeout
            .is_some_and(|d| d < Duration::from_secs(1))
        {
            return Err("dead_timeout below 1 s");
        }
        if !(0.0..1.0).contains(&self.probe_jitter) {
            return Err("probe_jitter outside [0, 1)");
        }
        let below = |d: Option<Duration>, min| d.is_some_and(|d| d < min);
        if below(self.max_idle_timeout, Duration::from_millis(1)) {
            return Err("max_idle_timeout below 1 ms");
        }
        if below(self.keep_alive_period, Duration::from_secs(1)) {
            return Err("keep_alive_period below 1 s");
        }
        if below(self.standby_probe, Duration::from_secs(1)) {
            return Err("standby_probe below 1 s");
        }
        if below(self.probe_interval, Duration::from_secs(1)) {
            return Err("probe_interval below 1 s");
        }
        self.shaping_limits.validate()?;
        if !(1024..=65535).contains(&self.spread_chunk) {
            return Err("spread_chunk outside 1024..=65535");
        }
        let a = &self.pipe_auth;
        if a.psk.as_ref().is_some_and(|k| k.len() < 16) {
            return Err("pipe_auth PSK must hold at least 16 bytes");
        }
        if a.insecure && a.psk.is_some() {
            return Err("insecure joins cannot be combined with a PSK");
        }
        if self
            .replay_window
            .is_some_and(|w| w < u64::from(self.max_pipes) + u64::from(self.pipe_headroom))
        {
            return Err("replay_window below max_pipes + pipe_headroom");
        }
        if self.resume_timeout.is_some_and(|t| t.is_zero()) {
            return Err("resume_timeout is zero");
        }
        if self
            .protocols
            .as_ref()
            .is_some_and(|p| p.is_empty() || p.iter().any(|n| n.is_empty()))
        {
            return Err("protocols must hold at least one non-empty name");
        }
        if self.offers_multipath() && self.pipe_auth.flags() == 0 {
            return Err("multipath (max_pipes above 1 or resume_timeout) needs pipe_auth");
        }
        Ok(())
    }
}

/// Borrowed GREASE parameter for encoding.
pub(crate) fn grease_ref(g: &(u64, Vec<u8>)) -> Grease<'_> {
    Grease {
        id: g.0,
        value: &g.1,
    }
}
