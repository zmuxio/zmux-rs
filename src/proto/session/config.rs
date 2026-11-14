//! Session configuration and the transport parameters it
//! produces.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use super::Tracer;
use super::policy::Scheduler;
use crate::proto::keys::secret_flags;
use crate::proto::limit::DatagramLimiter;
use crate::proto::params::floor;
use crate::proto::params::{
    Grease, LanesParameter, Locator, MultipathParameter, RoleParameter, TransportParameters,
    ZMUX_MAX_RECORD_SIZE, grease_id,
};

/// Join credentials: the secret sources this endpoint offers for pipe joins. There is no default:
/// a configuration that offers multipath without them is refused
/// ([`crate::ConnectError::InvalidConfig`]).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct PipeAuth {
    pub(crate) exporter: bool,
    pub(crate) psk: Option<JoinSecret>,
    pub(crate) deferred_psk: bool,
    pub(crate) end_to_end: bool,
}

/// A pre-shared key: its bytes are overwritten when it is dropped.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct JoinSecret(Vec<u8>);

impl JoinSecret {
    pub(crate) fn new(key: Vec<u8>) -> Self {
        Self(key)
    }
}

impl std::ops::Deref for JoinSecret {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for JoinSecret {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&mut self.0);
    }
}

impl PipeAuth {
    /// No credentials (the default): multipath cannot be offered.
    pub fn none() -> Self {
        Self::default()
    }

    /// Derives the join secret from the exporter of the innermost
    /// end-to-end handshake of the bootstrap carriers (E); today its
    /// source is TLS 1.3 that this process terminates (a TLS connection,
    /// or the QUIC connection under the carrier). The driver reads the
    /// value from the bootstrap carrier's exporter; a carrier without one
    /// is [`crate::ConnectError::InvalidConfig`].
    pub fn exporter() -> Self {
        Self {
            exporter: true,
            ..Self::default()
        }
    }

    /// A pre-shared key of at least 16 bytes (P): static, or derived per
    /// session by the application from its own authenticated exchange.
    pub fn psk(key: impl Into<Vec<u8>>) -> Self {
        Self {
            psk: Some(JoinSecret::new(key.into())),
            ..Self::default()
        }
    }

    /// A pre-shared key given later with
    /// [`SessionCore::set_join_secret`](super::SessionCore::set_join_secret),
    /// for example once the application authenticated the peer. It offers P like a static key.
    /// Until the key is given, local joins fail with
    /// [`PipeError::JoinPending`](super::PipeError::JoinPending)
    /// and the peer's are held for at most the handshake timeout. Excludes
    /// a static key.
    pub fn deferred_psk() -> Self {
        Self {
            deferred_psk: true,
            ..Self::default()
        }
    }

    /// Adds a deferred pre-shared key to these credentials
    /// ([`Self::deferred_psk`]).
    #[must_use]
    pub fn with_deferred_psk(mut self) -> Self {
        self.deferred_psk = true;
        self
    }

    /// Whether these credentials name a secret source: a pre-shared key
    /// (static or deferred) or the exporter. [`Self::with_end_to_end`] is
    /// no source.
    #[cfg(all(not(loom), any(feature = "tokio", feature = "blocking")))]
    pub(crate) fn has_source(&self) -> bool {
        self.exporter || self.psk.is_some() || self.deferred_psk
    }

    /// Declares in advance what
    /// [`SessionCore::declare_end_to_end`](super::SessionCore::declare_end_to_end) declares:
    /// the host proved pipe 0 end to end. Without it, a session whose first pipe is
    /// not on the secure carrier has no join keys. It is no secret source: it only
    /// releases the join keys of one. On a secure first pipe it is accepted and has
    /// no effect, so one configuration serves both kinds of first pipe.
    #[must_use]
    pub fn with_end_to_end(mut self) -> Self {
        self.end_to_end = true;
        self
    }

    /// Adds a pre-shared key to these credentials.
    #[must_use]
    pub fn with_psk(mut self, key: impl Into<Vec<u8>>) -> Self {
        self.psk = Some(JoinSecret::new(key.into()));
        self
    }

    /// The static pre-shared key, for a test's scripted peer.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    pub fn psk_bytes(&self) -> &[u8] {
        self.psk.as_deref().unwrap_or_default()
    }

    /// The Secret Flags these credentials select.
    pub fn flags(&self) -> u8 {
        let mut f = 0;
        if self.exporter {
            f |= secret_flags::EXPORTER;
        }
        if self.psk.is_some() || self.deferred_psk {
            f |= secret_flags::PSK;
        }
        f
    }
}

impl fmt::Debug for PipeAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PipeAuth")
            .field("exporter", &self.exporter)
            .field("psk", &self.psk.as_ref().map(|_| ".."))
            .field("deferred_psk", &self.deferred_psk)
            .field("end_to_end", &self.end_to_end)
            .finish()
    }
}

/// The level of a [`Logger`] message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum LogLevel {
    /// Detail for debugging.
    Debug,
    /// Information.
    Info,
    /// Something the application should look at.
    Warn,
    /// A failure zmux contained.
    Error,
}

/// The logger of a session or listener ([`Config::logger`]): a callback
/// taking a level and a message, so that zmux depends on no logging crate.
#[derive(Clone)]
pub struct Logger(pub Arc<LogFn>);

/// The callable behind a [`Logger`].
pub type LogFn = dyn Fn(LogLevel, &str) + Send + Sync;

impl Logger {
    /// A logger from a closure.
    pub fn new(f: impl Fn(LogLevel, &str) + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// Logs `message` at `level`; a panic of the callback is contained.
    #[cfg(all(not(loom), any(feature = "tokio", feature = "blocking")))]
    pub(crate) fn log(&self, level: LogLevel, message: &str) {
        let f = &self.0;
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(level, message)));
    }
}

impl fmt::Debug for Logger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Logger(..)")
    }
}

/// What a [`RecordPolicy`] and an [`AllowRecordMode`] know of a carrier.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RecordPolicyInput {
    /// It has an exporter.
    pub has_exporter: bool,
    /// It declares the Bound contract.
    pub secure: bool,
    /// The host's name of the path.
    pub label: Option<Arc<str>>,
    /// It is the session's first pipe.
    pub is_first_pipe: bool,
}

/// Chooses each carrier's record mode at the joiner: [`Config::record_policy`].
/// A choice of [`RecordMode::Unmanaged`](crate::RecordMode::Unmanaged), which
/// no pipe is joined in, fails the join with the configuration error.
#[derive(Clone)]
pub struct RecordPolicy(Arc<RecordPolicyFn>);

type RecordPolicyFn = dyn Fn(&RecordPolicyInput) -> crate::proto::seal::RecordMode + Send + Sync;

impl RecordPolicy {
    /// The policy `f`.
    pub fn new(
        f: impl Fn(&RecordPolicyInput) -> crate::proto::seal::RecordMode + Send + Sync + 'static,
    ) -> Self {
        Self(Arc::new(f))
    }

    /// Asks the policy.
    pub fn choose(&self, input: &RecordPolicyInput) -> crate::proto::seal::RecordMode {
        (self.0)(input)
    }
}

/// The acceptor's check of a Hello's mode, with the session's host value:
/// [`Config::allow_record_mode`].
#[derive(Clone)]
pub struct AllowRecordMode(Arc<AllowRecordModeFn>);

type AllowRecordModeFn = dyn Fn(
        &RecordPolicyInput,
        crate::proto::seal::RecordMode,
        Option<&crate::proto::admission::AdmittedValue>,
    ) -> bool
    + Send
    + Sync;

impl AllowRecordMode {
    /// The check `f`: given the carrier, the mode its Hello asks for and
    /// the host value the session's admission attached, if any.
    pub fn new(
        f: impl Fn(
            &RecordPolicyInput,
            crate::proto::seal::RecordMode,
            Option<&crate::proto::admission::AdmittedValue>,
        ) -> bool
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self(Arc::new(f))
    }

    /// Asks the check.
    pub fn allows(
        &self,
        input: &RecordPolicyInput,
        mode: crate::proto::seal::RecordMode,
        admitted: Option<&crate::proto::admission::AdmittedValue>,
    ) -> bool {
        (self.0)(input, mode, admitted)
    }
}

/// An acceptor's further check of a join: [`Config::authorize_join`].
#[derive(Clone)]
pub struct AuthorizeJoin(Arc<dyn Fn(super::PipeId) -> bool + Send + Sync>);

impl AuthorizeJoin {
    /// The check `f`, given the pipe ID of the join.
    pub fn new(f: impl Fn(super::PipeId) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// Asks the check.
    pub fn allows(&self, pipe: super::PipeId) -> bool {
        (self.0)(pipe)
    }
}

impl fmt::Debug for RecordPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecordPolicy(..)")
    }
}

impl fmt::Debug for AllowRecordMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AllowRecordMode(..)")
    }
}

impl fmt::Debug for AuthorizeJoin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthorizeJoin(..)")
    }
}

/// The liveness settings of a session: the one place of the settings that
/// judge whether the session and its pipes are alive ([`Config::liveness`],
/// replaced while the session runs by `Session::set_liveness`). A pipe's
/// own settings are a [`PipeLiveness`](crate::PipeLiveness).
///
/// ```
/// use std::time::Duration;
/// use zmux::{Cap, Config, Liveness};
///
/// let mut config = Config::default();
/// config.liveness = Liveness {
///     keep_alive_period: None,
///     dead_timeout: Cap::Fixed(Duration::from_secs(5)),
///     ..Liveness::default()
/// };
/// assert!(config.liveness.validate().is_ok());
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Liveness {
    /// Send QX_PING after this much silence (default
    /// [`DEFAULT_KEEP_ALIVE_PERIOD`], 15 s; `None` turns keep-alive off;
    /// at least 1 s when on). The period in effect is capped at half the
    /// effective idle timeout, and each wait is drawn from \[k (1 - j), k\]
    /// with j the [`probe_jitter`](Self::probe_jitter). On, an idle session
    /// stays open while the peer answers and closes within the idle timeout
    /// once its carrier dies; off, the idle timeout ends any session without
    /// application activity.
    pub keep_alive_period: Option<Duration>,
    /// The floor of T_suspect for every pipe (default 250 ms, at least
    /// 50 ms).
    pub suspect_floor: Duration,
    /// How long a suspect pipe stays suspect before it fails, effective
    /// max(T_suspect, dead_timeout). [`Cap::Auto`] (the default) is T_fail
    /// with resume and max(T_fail, half the idle timeout) without; a fixed
    /// value is at least 1 s.
    pub dead_timeout: Cap<Duration>,
    /// How often standby pipes and pipes of a less-preferred tier get a
    /// PIPE_PING while the session is busy, a traffic frame having been
    /// sent or received within the last 15 s (default
    /// [`DEFAULT_STANDBY_PROBE`], 1 s; `None` turns these faster probes
    /// off, leaving such pipes at the probe interval; at least 1 s when on).
    /// A quiet session probes them at the probe interval, and once more
    /// when traffic resumes.
    pub standby_probe: Option<Duration>,
    /// How long an outbound pipe of a pipe pair stays without an
    /// ack-eliciting byte handed to its carrier before it gets a PIPE_PING
    /// (default [`DEFAULT_PROBE_INTERVAL`], 15 s; `None` turns these idle
    /// probes off; at least 1 s when on). A longer interval only delays the
    /// detection of a pipe pair that dies while idle. Off turns off only
    /// these probes: the PIPE_PING that goes with the answer to the peer's,
    /// the standby probes and the probes of attachments without an outbound
    /// direction at the peer stay, and a pipe pair with them off at both
    /// ends is not judged while the session is quiet. The deadline is
    /// measured to the carrier: records that shaping may hold for up to
    /// `max_delay` are built that much earlier (but not more often than
    /// every second). Pipes whose attachment has no outbound direction at
    /// the peer are always probed, at most every 15 s.
    pub probe_interval: Option<Duration>,
    /// The probe jitter j (default [`DEFAULT_PROBE_JITTER`], 0.25; at least
    /// 0 and below 1): each wait for an idle probe is drawn once, when it
    /// starts, uniformly from \[k (1 - j), k\] for the probe interval k,
    /// and the first wait of the bootstrap pipe from \[0, k\]; it also
    /// spreads the keep-alive waits. Zero gives the fixed schedule of
    /// tests; the standby probes are never jittered.
    pub probe_jitter: f64,
}

impl Default for Liveness {
    fn default() -> Self {
        Self {
            keep_alive_period: Some(DEFAULT_KEEP_ALIVE_PERIOD),
            suspect_floor: DEFAULT_SUSPECT_FLOOR,
            dead_timeout: Cap::Auto,
            standby_probe: Some(DEFAULT_STANDBY_PROBE),
            probe_interval: Some(DEFAULT_PROBE_INTERVAL),
            probe_jitter: DEFAULT_PROBE_JITTER,
        }
    }
}

impl Liveness {
    /// Whether the settings are valid: each within the range its field
    /// states.
    pub fn validate(&self) -> Result<(), crate::InvalidConfig> {
        let e = crate::InvalidConfig::new;
        let below = |d: Option<Duration>| d.is_some_and(|d| d < Duration::from_secs(1));
        if self.suspect_floor < Duration::from_millis(50) {
            return Err(e("liveness.suspect_floor", "below 50 ms"));
        }
        if matches!(self.dead_timeout, Cap::Fixed(d) if d < Duration::from_secs(1)) {
            return Err(e("liveness.dead_timeout", "below 1 s"));
        }
        if !(0.0..1.0).contains(&self.probe_jitter) {
            return Err(e("liveness.probe_jitter", "outside [0, 1)"));
        }
        if below(self.keep_alive_period) {
            return Err(e("liveness.keep_alive_period", "below 1 s"));
        }
        if below(self.standby_probe) {
            return Err(e("liveness.standby_probe", "below 1 s"));
        }
        if below(self.probe_interval) {
            return Err(e("liveness.probe_interval", "below 1 s"));
        }
        Ok(())
    }

    /// The dead timeout of a fixed setting; `None` for the derived one.
    pub(crate) fn dead_timeout(&self) -> Option<Duration> {
        match self.dead_timeout {
            Cap::Fixed(d) => Some(d),
            Cap::Auto => None,
        }
    }
}

/// A pipe or pool setting that follows the session's
/// ([`Inherit::Session`], the default) or is its own
/// ([`Inherit::Set`]). `T` may itself be an `Option`, `Set(None)` turning
/// the feature off for that pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Inherit<T> {
    /// Follow the session's setting, now and after it changes.
    #[default]
    Session,
    /// This value.
    Set(T),
}

impl<T> Inherit<T> {
    /// The own value; `None` when it follows the session's.
    pub fn own(self) -> Option<T> {
        match self {
            Self::Session => None,
            Self::Set(v) => Some(v),
        }
    }

    /// The value in effect: the own one, else `session`.
    pub fn or(self, session: T) -> T {
        match self {
            Self::Session => session,
            Self::Set(v) => v,
        }
    }
}

/// One field of a [`PipeUpdate`](crate::PipeUpdate): keep the setting
/// ([`Change::Keep`], the default), clear it back to its default
/// ([`Change::Clear`]), or set it ([`Change::Set`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Change<T> {
    /// Leave the setting as it is.
    #[default]
    Keep,
    /// Return the setting to its default, as the field says.
    Clear,
    /// This value.
    Set(T),
}

impl<T> Change<T> {
    /// Whether the field changes anything.
    pub fn is_keep(&self) -> bool {
        matches!(self, Self::Keep)
    }
}

/// A per-pipe probe interval: a period, or off; `None` of an override
/// follows the session's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Period {
    /// Run with this period.
    Every(Duration),
    /// Turned off.
    Off,
}

impl Period {
    /// The period; `None` when off.
    #[must_use]
    pub(crate) const fn duration(self) -> Option<Duration> {
        match self {
            Self::Every(d) => Some(d),
            Self::Off => None,
        }
    }

    /// The period of an own setting, `None` being off.
    pub(crate) fn of(d: Option<Duration>) -> Self {
        d.map_or(Self::Off, Self::Every)
    }
}

/// The largest stream count credit the encoding allows, 2^60 (RFC 9000
/// Section 4.6): the value that grants the peer as many streams as the
/// protocol can count, which is in effect no limit. It is the top of the
/// range of [`Config::max_incoming_streams`] and
/// [`UniCredit::Limit`], and of `Session::raise_incoming_streams`; it is a
/// value of that range, not a setting (those options have no unlimited
/// setting, and 0 keeps meaning none).
pub const MAX_STREAM_CREDIT: u64 = crate::proto::frame::MAX_COUNT;

/// The default payload bytes of a stream's received datagram queue
/// ([`Config::datagram_stream_bytes`]): 512 KiB.
pub(crate) const DEFAULT_DATAGRAM_STREAM_BYTES: usize = 512 * 1024;

/// The default handshake timeout ([`Config::handshake_timeout`]).
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The default join deadline ([`Config::join_timeout`]).
pub const DEFAULT_JOIN_TIMEOUT: Duration = Duration::from_secs(10);

/// The default shortest wait between redials: of the
/// [`redial`](Config#structfield.redial) hook and of a pipe pool.
pub const DEFAULT_MIN_BACKOFF: Duration = Duration::from_secs(1);

/// The default longest wait between redials, which also bounds a policy's
/// dial delay.
pub const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(60);

/// The default probe interval of idle pipe pairs
/// ([`Liveness::probe_interval`]).
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_secs(15);

/// The default keep-alive period ([`Liveness::keep_alive_period`]).
pub const DEFAULT_KEEP_ALIVE_PERIOD: Duration = Duration::from_secs(15);

/// The default standby probe interval
/// ([`Liveness::standby_probe`]).
pub const DEFAULT_STANDBY_PROBE: Duration = Duration::from_secs(1);

/// The default idle timeout ([`Config::max_idle_timeout`]).
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The default probe jitter j ([`Liveness::probe_jitter`]).
pub const DEFAULT_PROBE_JITTER: f64 = 0.25;

/// The default floor of T_suspect ([`Liveness::suspect_floor`]).
pub const DEFAULT_SUSPECT_FLOOR: Duration = Duration::from_millis(250);

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
/// also the cap the session receive buffer cap is computed from.
pub const SESSION_WINDOW_FLOOR: u64 = 96 * 1024 * 1024;

/// The default memory budget of a session without a listener, the same as a listener's.
pub const DEFAULT_MEMORY_BUDGET: u64 = 1 << 30;

/// A bound or setting of the configuration that is computed unless a
/// value is given: the window caps and the send buffer maximum (bytes),
/// the replay window (pipe IDs), the dead timeout and the probation base
/// (durations). [`Cap::Auto`] is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Cap<T = u64> {
    /// The default: the value the field derives (a memory cap: a floor,
    /// and above it as far as the measured rate and RTT ask and the memory
    /// budget allows).
    #[default]
    Auto,
    /// A fixed value.
    Fixed(T),
}

/// The unidirectional streams the peer may open
/// ([`Config::max_incoming_uni_streams`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum UniCredit {
    /// Staged credit (the default): `initial_max_streams_uni` is 16, and
    /// MAX_STREAMS 256 is sent when the application first accepts a
    /// unidirectional stream.
    #[default]
    Staged,
    /// This many at once (0: none; at most [`MAX_STREAM_CREDIT`]).
    Limit(u64),
}

/// The `initial_max_streams_uni` of an unset `max_incoming_uni_streams`,
/// and the limit the first accept raises it to.
pub(crate) const STAGED_UNI_STREAMS: (u64, u64) = (16, 256);

/// The predicate of `allow_connection_window_increase`:
/// it is shown the proposed increase of the session receive window and
/// answers whether to allow it. It runs outside every zmux lock on the
/// session's hook context, never on a
/// driver thread; a panic counts as a refusal.
#[derive(Clone)]
pub struct WindowIncrease(Arc<dyn Fn(u64) -> bool + Send + Sync>);

impl WindowIncrease {
    /// The predicate `f`.
    pub fn new(f: impl Fn(u64) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// Asks the predicate.
    pub fn allows(&self, increase: u64) -> bool {
        (self.0)(increase)
    }
}

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
/// use zmux::{Config, PipeAuth, sched::Scheduler};
///
/// let mut config = Config::default();
/// config.max_pipes = 8;
/// config.resume_timeout = Some(Duration::from_secs(60));
/// config.pipe_auth = PipeAuth::psk(b"a pre-shared key, 16 bytes or more".to_vec());
/// config.scheduler = Scheduler::SpreadEta;
/// // Let the preferred tier queue up to 200 ms before a fallback tier
/// // takes the excess.
/// config.overflow_delay = Duration::from_millis(200);
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
    /// Abandon establishment after this long (default
    /// [`DEFAULT_HANDSHAKE_TIMEOUT`], 10 s; `None` is no timeout). It
    /// bounds establishment only.
    pub handshake_timeout: Option<Duration>,
    /// The join deadline (default [`DEFAULT_JOIN_TIMEOUT`], 10 s; a
    /// positive duration of at most [`MAX_JOIN_DEADLINE`](super::MAX_JOIN_DEADLINE),
    /// 60 s, which session epochs rely on; there is no setting without a timeout): every
    /// join, lane confirmation and held peer join ends by it, and
    /// [`Session`](crate::Session)`::add_pipe` waits at most this
    /// long. It does not depend on `handshake_timeout`.
    pub join_timeout: Duration,
    /// `max_idle_timeout` (default [`DEFAULT_IDLE_TIMEOUT`], 30 s; `None`
    /// is no local limit and announces none). A set duration is at least
    /// 1 ms, the unit of the transport parameter, whose 0 means none.
    pub max_idle_timeout: Option<Duration>,
    /// The liveness settings of the session and the defaults of its pipes
    /// (default [`Liveness::default`]): keep-alive, the suspicion floor, the
    /// dead timeout and the probes.
    pub liveness: Liveness,
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
    /// fixed cap or from the floor, never from a grown window.
    pub max_connection_receive_window: Cap,
    /// The `memory_budget` parameter of `max_connection_receive_window`
    /// (default [`DEFAULT_MEMORY_BUDGET`], 1 GiB; `None` is unlimited): the
    /// memory budget of a session without a listener, a listener's
    /// `memory_budget` otherwise. Buffered, retained and unread bytes and the
    /// session window's growth count against it; window and send-buffer
    /// growth above the floors of [`Cap::Auto`] stops at it.
    pub memory_budget: Option<u64>,
    /// Concurrent bidirectional streams the peer may open (default 256; 0,
    /// or from 4, the early-data floor of [`params::floor`](floor), to
    /// [`MAX_STREAM_CREDIT`], which grants as many as the protocol can
    /// count). An
    /// application that never accepts peer streams sets 0; a peer's early
    /// data then fails with `EarlyDataRejected` at the peer.
    pub max_incoming_streams: u64,
    /// Concurrent unidirectional streams the peer may open (default
    /// [`UniCredit::Staged`]: `initial_max_streams_uni` is 16 and
    /// MAX_STREAMS 256 is sent when the application first accepts a
    /// unidirectional stream). A [`UniCredit::Limit`], 0 included, is
    /// advertised at once.
    pub max_incoming_uni_streams: UniCredit,
    /// Announce datagram support (default false).
    pub enable_datagrams: bool,
    /// Datagrams waiting for a pipe (default 64, at least 1); when the
    /// queue is full the oldest is dropped.
    pub datagram_send_queue: usize,
    /// Received session datagrams (flow 0) waiting for the application
    /// (default 128, at least 1); the oldest make room.
    pub datagram_receive_queue: usize,
    /// Received datagrams waiting per stream (default 32, at least 1); the
    /// stream's oldest make room.
    pub datagram_stream_queue: usize,
    /// Payload bytes of the received session datagrams and of those held
    /// for streams not opened yet, together (default 1 MiB, at least 1);
    /// stream queues are bounded by their own limits and do not count.
    pub datagram_receive_bytes: usize,
    /// Payload bytes of received datagrams waiting per stream (default
    /// `Some(512 KiB)`; `None` leaves
    /// [`Config::datagram_stream_queue`] the only bound; `Some(0)` is a
    /// configuration error). A datagram that would exceed this or the
    /// count drops the stream's oldest datagrams until both hold, each
    /// counted as dropped; a single datagram larger than this is kept
    /// alone. The default holds the default 32 datagrams up to 9000-byte
    /// packets without a drop the count would not make.
    pub datagram_stream_bytes: Option<usize>,
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
    /// value below `send_buffer` is a configuration error.
    pub send_buffer_max: Cap,
    /// The largest Frames field of the records this endpoint sends, before
    /// the peer's `max_record_size` caps it (default 16382, one TLS record).
    pub max_send_record: usize,
    /// The attachments this endpoint aims for with its own joins. 1 (the
    /// default) keeps multipath off; 8 is the recommended value when
    /// multipath is used. The peer may have up to `max_pipes +
    /// pipe_headroom` attachments live at once.
    pub max_pipes: u32,
    /// The attachment headroom H, a parameter of `max_pipes` (default 8):
    /// room for failed attachments whose retirement has not completed.
    pub pipe_headroom: u32,
    /// This endpoint's sets of Join Suites and Groups, as `zmux_session_crypto` declares
    /// them and the join keys and epoch secrets take them: every Suite and Group of this
    /// build by default. Each set is ascending, without duplicates, and holds Suite 1 and
    /// Group 2 respectively and only values of this build. An endpoint that requires
    /// post-quantum joins leaves Group 1 out.
    pub session_crypto: crate::proto::seal::SessionCrypto,
    /// When the session starts an epoch exchange on its own:
    /// every hour, every 2^16 joins, once after the first Sealed or Bound pipe of a session
    /// whose secret is a TLS exporter's or a pre-shared key's, and once after a
    /// suspension, by default.
    pub epoch_policy: crate::proto::session::EpochPolicy,
    /// The first batch of a Hello, in bytes (default 8 KiB; `None` turns it
    /// off; a set value is at least 1): larger ones outgrow the first
    /// congestion window and delay both the Hello and the Reply. A first
    /// batch has no forward secrecy: a host whose data needs it turns it off.
    pub join_early_hello: Option<usize>,
    /// Chooses the record mode of each carrier this endpoint joins; unset is always
    /// Sealed. [`PipeOptions::record_mode`](crate::PipeOptions::record_mode) wins over it.
    pub record_policy: Option<RecordPolicy>,
    /// Plans the messages of a Join; unset: none. The kind in its view is the carrier's.
    pub handshake_shaper: Option<super::shaping::HandshakeShaper>,
    /// The acceptor's check of a Hello's mode; unset passes only Sealed.
    pub allow_record_mode: Option<AllowRecordMode>,
    /// An acceptor's further check of a join; unset passes all.
    pub authorize_join: Option<AuthorizeJoin>,
    /// The replay window W, a parameter of `max_pipes`, in pipe IDs of the
    /// peer's parity; [`Cap::Auto`] (the default) is max(64, 2 x (max_pipes +
    /// H)), and a fixed value is at least max_pipes + H.
    pub replay_window: Cap,
    /// The lanes accepted on each inbound pipe, lane 0 included, a
    /// parameter of `max_pipes` that applies to every session, single-pipe
    /// ones included (default 258; any value, and 1 accepts no lanes): the `zmux_max_lanes` this
    /// endpoint sends. Outbound lanes follow the peer's value and the carrier.
    pub max_lanes: std::num::NonZeroU64,
    /// Resume grace period; `None` (the default) disables resume. A set
    /// period is at least 1 ms: `Some(Duration::ZERO)` is a configuration
    /// error, and a fraction of a millisecond is rounded up to the
    /// millisecond the transport parameter carries. It needs a secret
    /// source, and a session that accepts needs a listener; a dialling
    /// session should have a redial source
    /// ([`redial`](Config#structfield.redial) or a pipe pool).
    pub resume_timeout: Option<Duration>,
    /// The backoff between two dials of the
    /// [`redial`](Config#structfield.redial) hook (default
    /// [`Backoff::default`](crate::Backoff): from [`DEFAULT_MIN_BACKOFF`],
    /// 1 s, doubling after each failure up to [`DEFAULT_MAX_BACKOFF`],
    /// 60 s, with [`DEFAULT_BACKOFF_JITTER`](crate::DEFAULT_BACKOFF_JITTER)),
    /// measured from the start of the previous attempt.
    pub redial_backoff: crate::Backoff,
    /// The redial hook: dials a carrier that replaces the session's pipe
    /// once the session suspends or lacks a direction, for a session that
    /// runs on one pipe at a time. A dialling session runs it
    /// (`Session::connect` and `Session::peer`); a session a listener
    /// accepted never dials, and its peer redials. It runs with
    /// [`redial_backoff`](Config#structfield.redial_backoff); a refused
    /// join adds its own backoff, and a dial waits for the longer of the
    /// two. A multipath session that keeps several pipes uses pipe pools
    /// instead (`helpers::maintain_pipes`). The hook is built for the
    /// driver that runs the session ([`Redial::new`] for the tokio driver,
    /// [`Redial::blocking`] for the std driver); a driver ignores a hook
    /// built for the other one.
    pub redial: Option<Redial>,
    /// The logger: called with a level and a message, outside every lock;
    /// it must not block. Unset (the default), nothing is logged. zmux logs
    /// only what the application would otherwise not see: the removal of
    /// the last pipe of a direction while streams are open,
    /// [`SessionEvent::ResumeUnattended`](crate::SessionEvent::ResumeUnattended),
    /// and failures of host callbacks that zmux contains.
    pub logger: Option<Logger>,
    /// The session's default scheduling policy (default `affinity`).
    pub scheduler: Scheduler,
    /// The application's bounds on shaping (default: no account, one wait up to 1 s).
    pub shaping_limits: super::shaping::Limits,
    /// Gives the shaping configuration's budget, called once when the session is created
    /// (default: none). It cannot widen `shaping_limits`.
    pub shaping_budget: Option<super::shaping::ShapingBudget>,
    /// The shaper factory installed when the session is created (default:
    /// none), as if by `set_shaper`: every pipe of the session, the
    /// bootstrap pipe of an accepted session and joined pipes included, is
    /// shaped from its first record. `set_shaper` replaces it.
    pub shaper: Option<Arc<dyn super::shaping::Factory>>,
    /// The `spread-eta` chunk size (default 16 KiB).
    pub spread_chunk: usize,
    /// The base of the probation of pipes that join or return from
    /// suspicion, a parameter of `scheduler` (default `Some(Cap::Auto)`: 4 x
    /// smoothed RTT for the first join of a path without history and max(1
    /// s, 4 x smoothed RTT) otherwise; `None` turns probation off; a fixed
    /// base is above zero).
    pub probation: Option<Cap<Duration>>,
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
    /// TLS. The protocol both offered (the
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
/// for their whole life (`RecvStream::is_replayable`).
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
/// if session.closing().await.is_early_data_rejected() {
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
    /// The bootstrap pipe's first carrier write waits for
    /// [`Session`](crate::Session)`::release_first_flight`,
    /// or until [`Config::handshake_timeout`] has passed since the session
    /// started
    /// ([`SessionStats::first_flight_timeouts`](super::SessionStats::first_flight_timeouts)); the
    /// handshake timeout runs from the release. Streams written before the release leave in the
    /// same write as the transport parameters, as a carrier whose first message carries the first
    /// flight wants. A client with early data only ([`Self::zmux_peer`] or
    /// [`Self::carrier_early_data`]).
    pub hold_first_flight: bool,
}

impl EarlyData {
    /// Early data toward a peer declared a zmux endpoint, without carrier
    /// early data.
    pub const fn for_zmux_peer() -> Self {
        Self {
            zmux_peer: true,
            carrier_early_data: false,
            hold_first_flight: false,
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

    /// With the first flight held (or not); see
    /// [`Self::hold_first_flight`].
    #[must_use]
    pub const fn with_hold_first_flight(mut self, on: bool) -> Self {
        self.hold_first_flight = on;
        self
    }
}

/// The [`redial`](Config#structfield.redial) hook of a session: a dial
/// function built for the driver that runs the session. Clones share the
/// function.
#[derive(Clone)]
pub struct Redial(RedialFn);

#[derive(Clone)]
enum RedialFn {
    #[cfg(all(feature = "tokio", not(loom)))]
    Tokio(crate::Dial),
    #[cfg(all(feature = "blocking", not(loom)))]
    Blocking(crate::blocking::Dial),
}

impl Redial {
    /// The tokio driver's hook: an async dial function, run on a task of
    /// the session.
    #[cfg(all(feature = "tokio", not(loom)))]
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(crate::DialRequest) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = std::io::Result<crate::PipeIo>> + Send + 'static,
    {
        Self(RedialFn::Tokio(crate::Dial::new(f)))
    }

    /// The std driver's hook: a blocking dial function, run on a thread of
    /// the session.
    #[cfg(all(feature = "blocking", not(loom)))]
    pub fn blocking<F>(f: F) -> Self
    where
        F: Fn(crate::DialRequest) -> std::io::Result<crate::blocking::PipeIo>
            + Send
            + Sync
            + 'static,
    {
        Self(RedialFn::Blocking(crate::blocking::Dial::new(f)))
    }

    /// The tokio driver's dial function, if built for it.
    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn as_tokio(&self) -> Option<&crate::Dial> {
        #[allow(unreachable_patterns)]
        match &self.0 {
            RedialFn::Tokio(d) => Some(d),
            _ => None,
        }
    }

    /// The std driver's dial function, if built for it.
    #[cfg(all(feature = "blocking", not(loom)))]
    pub(crate) fn as_blocking(&self) -> Option<&crate::blocking::Dial> {
        #[allow(unreachable_patterns)]
        match &self.0 {
            RedialFn::Blocking(d) => Some(d),
            _ => None,
        }
    }
}

impl fmt::Debug for Redial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Redial(..)")
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            handshake_timeout: Some(DEFAULT_HANDSHAKE_TIMEOUT),
            join_timeout: DEFAULT_JOIN_TIMEOUT,
            max_idle_timeout: Some(DEFAULT_IDLE_TIMEOUT),
            liveness: Liveness::default(),
            initial_stream_receive_window: 256 * 1024,
            max_stream_receive_window: Cap::Auto,
            latency_budget: DEFAULT_LATENCY_BUDGET,
            initial_connection_receive_window: 1024 * 1024,
            max_connection_receive_window: Cap::Auto,
            memory_budget: Some(DEFAULT_MEMORY_BUDGET),
            max_incoming_streams: 256,
            max_incoming_uni_streams: UniCredit::Staged,
            enable_datagrams: false,
            datagram_send_queue: 64,
            datagram_receive_queue: 128,
            datagram_stream_queue: 32,
            datagram_receive_bytes: 1024 * 1024,
            datagram_stream_bytes: Some(DEFAULT_DATAGRAM_STREAM_BYTES),
            send_buffer: 4 * 1024 * 1024,
            send_buffer_max: Cap::Auto,
            max_send_record: crate::proto::params::DEFAULT_MAX_RECORD_SIZE as usize,
            max_pipes: 1,
            pipe_headroom: 8,
            session_crypto: crate::proto::seal::SessionCrypto::local(),
            epoch_policy: crate::proto::session::EpochPolicy::default(),
            join_early_hello: Some(8 << 10),
            record_policy: None,
            handshake_shaper: None,
            allow_record_mode: None,
            authorize_join: None,
            replay_window: Cap::Auto,
            max_lanes: crate::proto::params::DEFAULT_MAX_LANES,
            resume_timeout: None,
            redial_backoff: crate::Backoff::default(),
            redial: None,
            logger: None,
            scheduler: Scheduler::Affinity,
            shaping_limits: super::shaping::Limits::default(),
            shaping_budget: None,
            shaper: None,
            spread_chunk: 16 * 1024,
            probation: Some(Cap::Auto),
            overflow_delay: DEFAULT_OVERFLOW_DELAY,
            redundancy: Redundancy::Urgent,
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

/// Deterministic values for the conformance trace runner. Only reachable with the `test-hooks`
/// feature.
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
    /// The Locator of epoch e announced as this prefix followed by e in decimal ASCII.
    pub epoch_locator_prefix: Option<Vec<u8>>,
    /// The cap of unretired attachments of the peer, instead of max_pipes +
    /// H.
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
    /// How long an application close waits for the carriers to take
    /// CONNECTION_CLOSE instead of 1 s.
    pub close_handoff_limit: Option<Duration>,
    /// The linger timeout instead of three RTTs within 250 ms to 2 s.
    pub linger_timeout: Option<Duration>,
    /// Set once a shutdown's GOAWAY phase 2 is done (its final GOAWAY
    /// sent, or none needed).
    pub goaway_final: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl Config {
    /// A configuration for multipath: the
    /// recommended `max_pipes` of 8 and the join
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
    /// smallest initial stream window when that is smaller.
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
    /// fixed cap, or the floor of the automatic one.
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

    /// The transport parameters this endpoint sends,
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
            zmux_session_crypto: mp.then(|| self.session_crypto.clone()),
            zmux_resume: resume.filter(|_| mp),
            max_idle_timeout: (idle > 0).then_some(idle),
            initial_max_data: Some(self.initial_connection_receive_window),
            initial_max_stream_data_bidi_local: Some(window),
            initial_max_stream_data_bidi_remote: Some(window),
            initial_max_stream_data_uni: Some(window),
            initial_max_streams_bidi: Some(self.max_incoming_streams),
            initial_max_streams_uni: Some(match self.max_incoming_uni_streams {
                UniCredit::Limit(n) => n,
                UniCredit::Staged => STAGED_UNI_STREAMS.0,
            }),
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

    /// The GREASE parameter: the hook's, or a random one.
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

    /// The join deadline ([`Config::join_timeout`]).
    pub(crate) fn join_wait(&self) -> Duration {
        self.join_timeout
    }

    /// The handshake timeout in effect: [`Config::handshake_timeout`];
    /// `Duration::MAX`, a deadline that never comes, for no timeout.
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
        self.liveness.keep_alive_period
    }

    /// The memory budget in effect; `None` when unlimited.
    pub(crate) fn memory_budget(&self) -> Option<u64> {
        self.memory_budget
    }

    /// The standby probe interval in effect; `None` when off.
    pub(crate) fn standby_probe(&self) -> Option<Duration> {
        self.liveness.standby_probe
    }

    /// The probe interval of idle pipe pairs in effect.
    pub(crate) fn probe_interval(&self) -> Option<Duration> {
        self.liveness.probe_interval
    }
    /// Checks the configuration as creating a session does: the error a
    /// connect, accept or listener with it would fail with, naming the
    /// field ([`InvalidConfig::field`](crate::InvalidConfig::field)).
    /// Checks that need the first pipe (its secret source) are left to
    /// the session.
    pub fn validate(&self) -> Result<(), crate::InvalidConfig> {
        if self.own_locator().len() > Locator::MAX_LEN {
            return Err(crate::InvalidConfig::new("locator", "above 255 bytes"));
        }
        self.epoch_policy.validate()?;
        let fixed = |c: Cap| match c {
            Cap::Auto => u64::MAX,
            Cap::Fixed(v) => v,
        };
        if self.initial_stream_receive_window > fixed(self.max_stream_receive_window) {
            return Err(crate::InvalidConfig::new(
                "initial_stream_receive_window",
                "above max_stream_receive_window",
            ));
        }
        if self.initial_connection_receive_window > fixed(self.max_connection_receive_window) {
            return Err(crate::InvalidConfig::new(
                "initial_connection_receive_window",
                "above max_connection_receive_window",
            ));
        }
        // Every zmux endpoint advertises at least the early-data floor.
        if self.initial_stream_receive_window < floor::MAX_STREAM_DATA {
            return Err(crate::InvalidConfig::new(
                "initial_stream_receive_window",
                "below the 4 KiB early-data floor",
            ));
        }
        if self.initial_connection_receive_window < floor::MAX_DATA {
            return Err(crate::InvalidConfig::new(
                "initial_connection_receive_window",
                "below the 16 KiB early-data floor",
            ));
        }
        if self.max_incoming_streams != 0 && self.max_incoming_streams < floor::MAX_STREAMS_BIDI {
            return Err(crate::InvalidConfig::new(
                "max_incoming_streams",
                "neither 0 nor at least the early-data floor of 4",
            ));
        }
        if self.max_incoming_streams > MAX_STREAM_CREDIT
            || matches!(self.max_incoming_uni_streams, UniCredit::Limit(n) if n > MAX_STREAM_CREDIT)
        {
            return Err(crate::InvalidConfig::new(
                "max_incoming_streams",
                "a stream limit above MAX_STREAM_CREDIT (2^60)",
            ));
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
            return Err(crate::InvalidConfig::new(
                "max_idle_timeout",
                "a window or timeout is too large to encode",
            ));
        }
        if !(1024..=65535).contains(&self.max_send_record) {
            return Err(crate::InvalidConfig::new(
                "max_send_record",
                "outside 1024..=65535",
            ));
        }
        if self.send_buffer == 0 {
            return Err(crate::InvalidConfig::new("send_buffer", "zero"));
        }
        if self.datagram_send_queue == 0
            || self.datagram_receive_queue == 0
            || self.datagram_stream_queue == 0
            || self.datagram_receive_bytes == 0
            || self.datagram_stream_bytes == Some(0)
        {
            return Err(crate::InvalidConfig::new(
                "datagram_send_queue",
                "a datagram queue or the datagram receive bytes is zero",
            ));
        }
        if self.max_pipes == 0 {
            return Err(crate::InvalidConfig::new("max_pipes", "zero"));
        }
        if self.max_lanes.get() > varint_max {
            return Err(crate::InvalidConfig::new("max_lanes", "above 2^62 - 1"));
        }
        if self.own_locator().len() > Locator::MAX_LEN {
            return Err(crate::InvalidConfig::new("locator", "above 255 bytes"));
        }
        if self
            .max_idle_timeout
            .is_some_and(|d| d < Duration::from_millis(1))
        {
            return Err(crate::InvalidConfig::new("max_idle_timeout", "below 1 ms"));
        }
        self.liveness.validate()?;
        if self.join_early_hello == Some(0) {
            return Err(crate::InvalidConfig::new(
                "join_early_hello",
                "zero: turn the first batch off with None",
            ));
        }
        if matches!(self.probation, Some(Cap::Fixed(d)) if d.is_zero()) {
            return Err(crate::InvalidConfig::new(
                "probation",
                "a base of zero: turn probation off with None",
            ));
        }
        self.shaping_limits.validate()?;
        if !(1024..=65535).contains(&self.spread_chunk) {
            return Err(crate::InvalidConfig::new(
                "spread_chunk",
                "outside 1024..=65535",
            ));
        }
        let a = &self.pipe_auth;
        if a.psk.as_ref().is_some_and(|k| k.len() < 16) {
            return Err(crate::InvalidConfig::new(
                "pipe_auth",
                "a pre-shared key must hold at least 16 bytes",
            ));
        }
        if self.session_crypto.check_local().is_err() {
            return Err(crate::InvalidConfig::new(
                "session_crypto",
                "must hold Suite 1 and Group 2 and only values of this build, ascending, once each",
            ));
        }
        if a.deferred_psk && a.psk.is_some() {
            return Err(crate::InvalidConfig::new(
                "pipe_auth",
                "a deferred pre-shared key cannot be combined with a static one",
            ));
        }
        if matches!(self.replay_window,
            Cap::Fixed(w) if w < u64::from(self.max_pipes) + u64::from(self.pipe_headroom))
        {
            return Err(crate::InvalidConfig::new(
                "replay_window",
                "below max_pipes + pipe_headroom",
            ));
        }
        if self.resume_timeout.is_some_and(|t| t.is_zero()) {
            return Err(crate::InvalidConfig::new("resume_timeout", "zero"));
        }
        if self
            .protocols
            .as_ref()
            .is_some_and(|p| p.is_empty() || p.iter().any(|n| n.is_empty()))
        {
            return Err(crate::InvalidConfig::new(
                "protocols",
                "must hold at least one non-empty name",
            ));
        }
        if self.join_timeout.is_zero() {
            return Err(crate::InvalidConfig::new("join_timeout", "zero"));
        }
        if self.join_timeout > super::MAX_JOIN_DEADLINE {
            return Err(crate::InvalidConfig::new(
                "join_timeout",
                "above the maximum join deadline of 60 s",
            ));
        }
        if let (Cap::Fixed(max), b) = (self.send_buffer_max, self.send_buffer)
            && max < b
        {
            return Err(crate::InvalidConfig::new(
                "send_buffer_max",
                "below send_buffer",
            ));
        }
        self.redial_backoff
            .validate()
            .map_err(|e| crate::InvalidConfig::new("redial_backoff", e.reason()))?;
        Ok(())
    }

    /// The secret source check, made once the first pipe is known: with
    /// multipath or resume, a pipe_auth with a source, or a first pipe on
    /// the secure carrier; on a secure first pipe, no other source.
    /// `EndToEnd` is no source.
    #[cfg(all(not(loom), any(feature = "tokio", feature = "blocking")))]
    pub(crate) fn check_source(&self, secure_first_pipe: bool) -> Result<(), crate::InvalidConfig> {
        if secure_first_pipe {
            if self.pipe_auth.has_source() {
                return Err(crate::InvalidConfig::new(
                    "pipe_auth",
                    "a PSK or the exporter on a secure first pipe: the secure carrier is the source, leave pipe_auth unset",
                ));
            }
        } else if self.offers_multipath() && !self.pipe_auth.has_source() {
            return Err(crate::InvalidConfig::new(
                "pipe_auth",
                "multipath (max_pipes above 1 or resume_timeout) needs a secret source: a PSK, a deferred PSK, the exporter, or a secure first pipe",
            ));
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

#[cfg(test)]
mod locator_tests {
    use super::Config;

    /// A Locator its length field cannot hold is an error, not an empty one.
    #[test]
    fn a_locator_above_255_bytes_is_an_error() {
        let mut c = Config {
            locator: vec![1; 255],
            ..Config::default()
        };
        assert_eq!(c.validate(), Ok(()));
        c.locator = vec![1; 256];
        assert_eq!(
            c.validate(),
            Err(crate::InvalidConfig::new("locator", "above 255 bytes"))
        );
    }
}
