//! Shared scoring, retry admission and versioned carrier history.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::util::checked_clock_deadline;
use crate::{Backoff, CarrierKind, InvalidConfig};

use super::capacity_change::{OpenerAdmission, RetryAdmission};
use super::choice::Candidate;
use super::handle::Driver;
use super::retry::{
    CooldownReason, Cooling, DROP_WINDOW, HEALTH_RESET, LocalCooldown, RecoveryCadence, millis,
};

const VERSION: i64 = 2;

pub(super) type Key = (String, CarrierKind, String);

/// How one observation is committed, beyond its outcome and sample.
struct Write<'a> {
    target: Option<&'a crate::HttpTarget>,
    clock: Option<Clock>,
    start_cooling: bool,
    journal: Option<&'a mut OutageJournal>,
}

impl Write<'_> {
    const fn new(start_cooling: bool) -> Self {
        Self {
            target: None,
            clock: None,
            start_cooling,
            journal: None,
        }
    }
}

/// Settings shared by every user of a carrier cache.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CarrierCacheConfig {
    /// Clock domain shared by the owners of these observations.
    pub clock_domain: crate::ClockDomain,
    wall_clock: Option<WallClock>,
    /// Uniform fraction in [0, 1] for each recovery advance.
    pub recovery_sample: fn() -> f64,
    /// Half-life of the scoring history.
    pub half_life: Duration,
    /// A failure before this age counts as an early drop.
    pub drop_window: Duration,
    /// Maximum age of performance evidence.
    pub performance_window: Duration,
    /// Required continuous healthy time to reset backoff.
    pub health_reset: Duration,
    /// Retry settings, shared by all users of the cache.
    pub backoff: Backoff,
    short_drop_resilient: bool,
    /// Optional positive multiplicative priors by carrier kind.
    pub kind_priors: HashMap<CarrierKind, f64>,
    /// Maximum number of rows accepted per imported snapshot.
    pub import_limit: Option<usize>,
    /// Maximum age of history kept without fresh evidence or active cooling.
    pub max_age: Option<Duration>,
    /// Evict history below this effective weight when no other evidence remains.
    pub min_weight: f64,
}

#[derive(Clone)]
struct WallClock(Arc<dyn Fn() -> SystemTime + Send + Sync>);

impl fmt::Debug for WallClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WallClock(..)")
    }
}

impl CarrierCacheConfig {
    /// Selects the deployment profile for repeated short drops.
    ///
    /// Its backoff and ten-minute floor are resolved together.
    #[must_use]
    pub fn with_short_drop_resilience(mut self) -> Self {
        self.backoff = Self::short_drop_backoff();
        self.short_drop_resilient = true;
        self
    }

    fn short_drop_backoff() -> Backoff {
        let mut backoff = Backoff::new(Duration::from_secs(30), Duration::from_mins(30));
        backoff.jitter_up = crate::DEFAULT_BACKOFF_JITTER;
        backoff
    }

    /// Supplies the wall source for cache creation, explicit reports and snapshots.
    /// Internal observations follow the resulting wall anchor using [`Self::clock_domain`].
    #[must_use]
    pub fn with_wall_clock(mut self, now: impl Fn() -> SystemTime + Send + Sync + 'static) -> Self {
        self.wall_clock = Some(WallClock(Arc::new(now)));
        self
    }
}

/// Authority to report observations for one cache key, kind and variant.
///
/// Each registration has its own sequence space. Clones share replay state.
#[derive(Debug, Clone)]
pub struct CarrierReportSource(Arc<ReportSource>);

#[derive(Debug)]
struct ReportSource {
    cache: std::sync::Weak<Inner>,
    key: Key,
    replay: Mutex<ReportWindow>,
}

#[derive(Debug, Default)]
struct ReportWindow {
    high: u64,
    seen: u64,
}

impl ReportWindow {
    fn claim(&mut self, sequence: u64) -> Result<bool, CarrierCacheError> {
        if sequence == 0 {
            return Err(CarrierCacheError::Value);
        }
        if sequence > self.high {
            let shift = sequence - self.high;
            self.seen = if shift < u64::from(u64::BITS) {
                self.seen << shift
            } else {
                0
            };
            self.high = sequence;
        }
        let offset = self.high - sequence;
        if offset >= u64::from(u64::BITS) {
            return Err(CarrierCacheError::StaleReport);
        }
        let mask = 1 << offset;
        let fresh = self.seen & mask == 0;
        self.seen |= mask;
        Ok(fresh)
    }
}

impl Default for CarrierCacheConfig {
    fn default() -> Self {
        Self {
            clock_domain: crate::ClockDomain::default(),
            wall_clock: None,
            recovery_sample: crate::backoff::random_fraction,
            half_life: Duration::from_hours(6),
            drop_window: DROP_WINDOW,
            performance_window: Duration::from_mins(1),
            health_reset: HEALTH_RESET,
            backoff: Backoff::new(Duration::from_mins(1), Duration::from_hours(6)),
            short_drop_resilient: false,
            kind_priors: HashMap::new(),
            import_limit: None,
            max_age: None,
            min_weight: 0.0,
        }
    }
}

/// The carrier score and evidence used by automatic selection.
#[derive(Debug, Clone, Copy)]
pub struct CarrierScore {
    /// The score including the carrier kind prior.
    pub score: f64,
    /// Smoothed handshake success times stability squared, before ranking factors.
    pub reliability: f64,
    /// All settled handshake attempts for this candidate.
    pub attempts: u64,
    /// Effective handshake sample weight.
    pub weight: f64,
    /// Effective weight of successful handshakes.
    pub success_weight: f64,
    /// Effective weight of completed initial survival windows.
    pub window_survived: f64,
    /// Effective weight of faults before the initial window ended.
    pub short_drops: f64,
    /// Effective weight of faults at or after the window boundary.
    pub post_window_faults: f64,
    /// Age of the scoring history, when history exists.
    pub age: Option<Duration>,
    /// Effective observed post-window exposure, in seconds.
    pub post_window_seconds: f64,
    /// Latest protocol RTT measurement, in seconds.
    pub rtt: Option<CarrierMeasurement>,
    /// Latest ACK delivery rate measurement, in bytes per second.
    pub rate: Option<CarrierMeasurement>,
    /// Committed cooldown rounds since the last health reset, including after expiry.
    pub cooldown_level: u64,
    /// Current retry cooldown.
    pub cooldown: Option<Cooldown>,
}

/// The latest measurement for one cache field, including an expired measurement.
#[derive(Debug, Clone, Copy)]
pub struct CarrierMeasurement {
    /// The measured value, in the units of its score field.
    pub value: f64,
    /// Elapsed time since the original sample.
    pub age: Duration,
    /// Effective lifetime including the cache's maximum age.
    pub valid_for: Duration,
    /// How this sample reached the cache, if known.
    pub source: Option<CarrierMeasurementSource>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
/// Where a cache measurement was observed.
pub enum CarrierMeasurementSource {
    /// Observed by the protocol on an attached member.
    #[default]
    Protocol,
    /// Reported through a registered host source.
    HostReport,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct CarrierRank {
    pub(super) score: f64,
    pub(super) reliability: f64,
    pub(super) attempts: u64,
    pub(super) retry_at: Option<Instant>,
}

/// The active cooling decision for one candidate key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cooldown {
    /// Cause of the current decision, if observed locally.
    pub reason: Option<CooldownReason>,
    /// Monotonic local commit of this decision, if observed locally.
    pub started_at: Option<Instant>,
    /// Wait before jitter was applied.
    pub nominal_wait: Duration,
    /// Wait after the original draw, if observed locally.
    pub sampled_wait: Option<Duration>,
    /// Monotonic end of this decision's wait.
    pub retry_at: Instant,
    /// Time remaining to the scheduled retry.
    pub remaining: Duration,
}

/// Candidate identity shared by all users of a carrier cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierCacheKey {
    /// Opaque host key.
    pub key: String,
    /// Carrier transport.
    pub kind: CarrierKind,
    /// Carrier variant.
    pub variant: String,
}

impl From<&Key> for CarrierCacheKey {
    fn from((key, kind, variant): &Key) -> Self {
        Self {
            key: key.clone(),
            kind: *kind,
            variant: variant.clone(),
        }
    }
}

/// A committed change to the candidate's local cooldown.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CooldownEvent {
    /// A new fault episode committed its retry schedule.
    Started {
        /// Shared candidate key.
        key: CarrierCacheKey,
        /// Monotonically increasing local fault episode.
        episode: u64,
        /// Committed cooldown level.
        level: u64,
        /// Cause of the cooldown.
        reason: CooldownReason,
        /// Monotonic fault commit time.
        started_at: Instant,
        /// Wait before applying jitter.
        nominal_wait: Duration,
        /// Wait after the single jitter draw.
        sampled_wait: Duration,
        /// Ordinary local retry deadline.
        retry_at: Instant,
    },
    /// A round committed while its session had no usable pipe was withdrawn
    /// because the session reconnected.
    Retracted {
        /// Shared candidate key.
        key: CarrierCacheKey,
        /// The withdrawn local fault episode.
        episode: u64,
        /// Restored cooldown level.
        level: u64,
        /// Restored ordinary retry deadline, if still in the future.
        retry_at: Option<Instant>,
        /// Monotonic retraction commit time.
        retracted_at: Instant,
    },
    /// Continuous health cleared the cooldown sequence.
    Reset {
        /// Shared candidate key.
        key: CarrierCacheKey,
        /// Most recent local fault episode, if observed on this cache.
        episode: Option<u64>,
        /// Monotonic reset commit time.
        reset_at: Instant,
    },
}

/// Process-local retry counters for a candidate key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RetryMetrics {
    /// Actual opener invocations.
    pub attempted_starts: u64,
    /// Most recent nominal missing-direction retry interval.
    pub recovery_nominal: Duration,
    /// Interval drawn at the last recovery failure.
    pub recovery_sampled: Duration,
    /// Shared opportunity for a live missing direction.
    pub recovery_retry_at: Option<Instant>,
    /// Unique episodes that committed a local cooldown.
    pub faults: u64,
    /// Blocked start opportunities by reason.
    pub suppressions: BTreeMap<RetryAdmission, u64>,
    /// Elapsed time since the current fault, when anchored.
    pub elapsed: Option<Duration>,
    /// Remaining ordinary local cooldown, excluding hard restrictions.
    pub remaining: Duration,
}

impl RetryMetrics {
    fn suppress(&mut self, reason: RetryAdmission) {
        let count = self.suppressions.entry(reason).or_default();
        *count = count.saturating_add(1);
    }
}

/// A completed dial attempt or observation from an attached member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CacheOutcome {
    /// Successful zmux handshake.
    Usable,
    /// Failed carrier opening or handshake.
    Failed,
    /// Definitive path rejection.
    Rejected,
    /// Completed the initial observation window.
    Survived,
    /// First service failure inside the observation window.
    ShortDrop,
    /// First service failure after the observation window.
    LateDrop,
    /// New observed lifetime after the initial window.
    Lifetime,
    /// New protocol RTT or ACK delivery rate.
    Performance,
    /// Continuous healthy interval that may clear cooling.
    Recovered,
}

/// The timestamp and measurements accompanying a cache observation.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct CarrierObservation {
    /// Original sample time, or the current cache clock if absent.
    pub at: Option<Instant>,
    /// Newly observed lifetime or continuous recovery interval.
    pub duration: Duration,
    /// Protocol RTT, zero when absent.
    pub rtt: Duration,
    /// ACK delivery rate in bytes per second, zero when absent.
    pub rate: u64,
    /// Optional stricter expiry from the estimator, zero when absent.
    pub valid_for: Duration,
    pub(crate) physical_failure: Option<Arc<crate::CarrierFailureEvent>>,
    pub(crate) source: CarrierMeasurementSource,
}

impl CarrierObservation {
    /// Creates an observation with the sample time, protocol RTT and delivery rate.
    #[must_use]
    pub fn measured(at: Option<Instant>, rtt: Duration, rate: u64) -> Self {
        Self {
            at,
            rtt,
            rate,
            ..Self::default()
        }
    }
}

/// An unsuccessful cache interchange or report.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum CarrierCacheError {
    /// Unsupported snapshot version.
    Version,
    /// Malformed JSON or a value of the wrong JSON type.
    Format,
    /// Invalid sample or snapshot value.
    Value,
    /// The source belongs to a different carrier cache.
    UnknownSource,
    /// The sequence predates the source's replay window.
    StaleReport,
}

impl fmt::Display for CarrierCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Version => "unsupported carrier cache version",
            Self::Format => "malformed carrier cache",
            Self::Value => "invalid carrier cache value",
            Self::UnknownSource => "unknown carrier report source",
            Self::StaleReport => "carrier report fell outside the replay window",
        })
    }
}

impl std::error::Error for CarrierCacheError {}

#[derive(Debug, Clone, Copy)]
struct Clock {
    mono: Instant,
    wall: OffsetDateTime,
}

impl Clock {
    fn now(config: &CarrierCacheConfig) -> Self {
        Self {
            mono: config.clock_domain.now(),
            wall: config
                .wall_clock
                .as_ref()
                .map_or_else(SystemTime::now, |clock| (clock.0)())
                .into(),
        }
    }

    fn age(self, earlier: OffsetDateTime) -> Duration {
        Duration::try_from(self.wall - earlier).unwrap_or_default()
    }
}

fn zero_time() -> OffsetDateTime {
    time::Date::MIN
        .midnight()
        .assume_utc()
        .replace_year(1)
        .expect("year one")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
struct Point {
    #[serde(with = "time::serde::rfc3339")]
    at: OffsetDateTime,
    age_ns: i64,
    #[serde(skip)]
    observed: Option<(Instant, Duration)>,
}

impl Default for Point {
    fn default() -> Self {
        Self {
            at: zero_time(),
            age_ns: 0,
            observed: None,
        }
    }
}

impl Point {
    fn new(clock: Clock, at: Instant) -> Self {
        let age = clock.mono.saturating_duration_since(at);
        Self {
            at: clock
                .wall
                .saturating_sub(time::Duration::try_from(age).unwrap_or(time::Duration::MAX)),
            age_ns: 0,
            observed: Some((at, Duration::ZERO)),
        }
    }

    fn age(&self, now: Instant) -> Duration {
        self.known_age(now).unwrap_or_default()
    }

    fn known_age(&self, now: Instant) -> Option<Duration> {
        self.observed
            .map(|(at, age)| age.saturating_add(now.saturating_duration_since(at)))
    }

    fn export(&mut self, now: Instant) {
        self.age_ns = i64::try_from(self.age(now).as_nanos()).unwrap_or(i64::MAX);
    }

    fn import(&mut self, now: Instant, elapsed: Duration) {
        if self.at != zero_time() {
            let age = Duration::from_nanos(self.age_ns.unsigned_abs()).saturating_add(elapsed);
            self.observed = Some((now, age.min(Duration::from_nanos(i64::MAX.unsigned_abs()))));
        }
    }

    fn valid(&self) -> bool {
        self.age_ns >= 0 && (self.at != zero_time() || self.age_ns == 0)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct History {
    #[serde(flatten)]
    point: Point,
    attempts: u64,
    success: f64,
    failure: f64,
    survived: f64,
    short_drop: f64,
    late_drop: f64,
    late_seconds: f64,
}

impl History {
    fn decay(&mut self, factor: f64) {
        self.success *= factor;
        self.failure *= factor;
        self.survived *= factor;
        self.short_drop *= factor;
        self.late_drop *= factor;
        self.late_seconds *= factor;
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Performance {
    #[serde(flatten)]
    point: Point,
    value: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    valid_for_ns: Option<i64>,
    #[serde(skip)]
    source: Option<CarrierMeasurementSource>,
}

impl Performance {
    fn valid_for(&self, window: Duration) -> Duration {
        self.valid_for_ns
            .filter(|&v| v > 0)
            .map_or(window, |valid| {
                window.min(Duration::from_nanos(valid.unsigned_abs()))
            })
    }

    fn fresh(&self, now: Instant, window: Duration) -> bool {
        self.value > 0.0 && self.point.age(now) < self.valid_for(window)
    }

    fn measurement(&self, now: Instant, window: Duration) -> Option<CarrierMeasurement> {
        (self.value > 0.0).then_some(())?;
        Some(CarrierMeasurement {
            value: self.value,
            age: self.point.known_age(now)?,
            valid_for: self.valid_for(window),
            source: self.source,
        })
    }

    fn update(
        &mut self,
        point: &Point,
        value: f64,
        valid_for: Duration,
        source: CarrierMeasurementSource,
    ) {
        if value > 0.0 && point.at > self.point.at {
            self.point = point.clone();
            self.value = value;
            self.source = Some(source);
            self.valid_for_ns = (!valid_for.is_zero())
                .then(|| i64::try_from(valid_for.as_nanos()).unwrap_or(i64::MAX));
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Entry {
    history: History,
    cooling: Cooling<Point>,
    #[serde(rename = "rtt_seconds")]
    rtt: Performance,
    #[serde(rename = "rate_bytes_per_second")]
    rate: Performance,
    #[serde(skip)]
    url: Option<String>,
    #[serde(skip)]
    in_flight: Option<Arc<AttemptTicket>>,
    #[serde(skip)]
    demand: usize,
    #[serde(skip)]
    recovery: RecoveryCadence,
    #[serde(skip)]
    physical_failures: HashMap<crate::CarrierConnId, std::num::NonZeroU64>,
    #[serde(skip)]
    hard_retry: Option<Instant>,
    #[serde(skip)]
    metrics: RetryMetrics,
}

impl Entry {
    fn has_snapshot_data(&self) -> bool {
        [
            &self.history.point,
            &self.cooling.point,
            &self.rtt.point,
            &self.rate.point,
        ]
        .iter()
        .any(|point| point.at != zero_time())
    }

    fn export(mut self, now: Instant) -> Self {
        for point in self.points() {
            point.export(now);
        }
        self.cooling.remaining_ms = self.cooling.active(now).map_or(0, |end| millis(end - now));
        self
    }

    fn points(&mut self) -> impl Iterator<Item = &mut Point> {
        [
            &mut self.history.point,
            &mut self.cooling.point,
            &mut self.rtt.point,
            &mut self.rate.point,
        ]
        .into_iter()
        .chain(&mut self.cooling.short)
    }

    fn validate(&mut self, backoff: Backoff) -> bool {
        let h = &self.history;
        [
            h.success,
            h.failure,
            h.survived,
            h.short_drop,
            h.late_drop,
            h.late_seconds,
            self.rtt.value,
            self.rate.value,
        ]
        .into_iter()
        .all(|v| v.is_finite() && v >= 0.0)
            && (0..=millis(backoff.max)).contains(&self.cooling.nominal_ms)
            && (0..=millis(backoff.wait_upper())).contains(&self.cooling.remaining_ms)
            && self.cooling.level >= 0
            && (self.cooling.level == 0 || self.cooling.point.at != zero_time())
            && self.cooling.short.len() <= 3
            && self.rtt.valid_for_ns.is_none_or(|v| v >= 0)
            && self.rate.valid_for_ns.is_none_or(|v| v >= 0)
            && self.points().all(|point| point.valid())
    }

    fn merge(&mut self, mut entry: Self, now: Clock, elapsed: Duration) {
        for point in entry.points() {
            point.import(now.mono, elapsed);
        }
        if entry.history.point.at > self.history.point.at {
            self.history = entry.history;
        }
        if entry.cooling.point.at > self.cooling.point.at {
            let left = Duration::from_millis(entry.cooling.remaining_ms.unsigned_abs());
            entry.cooling.until = now.mono.checked_add(left.saturating_sub(elapsed));
            self.cooling = entry.cooling;
        }
        if entry.rtt.point.at > self.rtt.point.at {
            self.rtt = entry.rtt;
        }
        if entry.rate.point.at > self.rate.point.at {
            self.rate = entry.rate;
        }
    }

    fn scored_history(
        &self,
        config: &CarrierCacheConfig,
        now: Instant,
        prior: f64,
    ) -> (f64, f64, History) {
        let mut h = self.history.clone();
        let age = h.point.age(now);
        h.decay(decay(age, config.half_life));
        let weight = h.success + h.failure;
        let success = (1.0 + h.success) / (2.0 + weight);
        let survival = (1.0 + h.survived) / (2.0 + h.survived + h.short_drop);
        let window = config.drop_window.as_secs_f64();
        let stability = survival / (1.0 + h.late_drop * window / (window + h.late_seconds));
        let rtt = if self.rtt.fresh(now, config.performance_window) {
            (0.1 / self.rtt.value).clamp(0.5, 2.0)
        } else {
            1.0
        };
        let rate = if self.rate.fresh(now, config.performance_window) {
            (self.rate.value / 1_250_000.0).clamp(0.5, 2.0)
        } else {
            1.0
        };
        let reliability = success * stability * stability;
        (reliability * (rate * rtt).sqrt() * prior, reliability, h)
    }

    fn rank(&self, config: &CarrierCacheConfig, now: Instant, prior: f64) -> CarrierRank {
        let (score, reliability, h) = self.scored_history(config, now, prior);
        CarrierRank {
            score,
            reliability,
            attempts: h.attempts,
            retry_at: self.retry_at(now),
        }
    }

    fn score(&self, config: &CarrierCacheConfig, now: Instant, prior: f64) -> CarrierScore {
        let (score, reliability, h) = self.scored_history(config, now, prior);
        let cooldown_level = self.cooling.level.unsigned_abs();
        CarrierScore {
            score,
            reliability,
            attempts: h.attempts,
            weight: h.success + h.failure,
            success_weight: h.success,
            window_survived: h.survived,
            short_drops: h.short_drop,
            post_window_faults: h.late_drop,
            age: h.point.known_age(now),
            post_window_seconds: h.late_seconds,
            rtt: self.rtt.measurement(now, config.performance_window),
            rate: self.rate.measurement(now, config.performance_window),
            cooldown_level,
            cooldown: self.cooling.active(now).map(|retry_at| Cooldown {
                reason: self.cooling.local.map(|local| local.reason),
                started_at: self.cooling.local.map(|local| local.at),
                nominal_wait: self.cooling.nominal(),
                sampled_wait: self.cooling.local.map(|local| local.sampled_wait),
                retry_at,
                remaining: retry_at - now,
            }),
        }
    }

    fn keep(&self, config: &CarrierCacheConfig, now: Instant) -> bool {
        if self.demand != 0 || self.in_flight.is_some() || self.retry_at(now).is_some() {
            return true;
        }
        let age = [
            &self.history.point,
            &self.cooling.point,
            &self.rtt.point,
            &self.rate.point,
        ]
        .into_iter()
        .filter(|point| point.observed.is_some())
        .map(|point| point.age(now))
        .min();
        let history_weight = self.history.success
            + self.history.failure
            + self.history.survived
            + self.history.short_drop
            + self.history.late_drop;
        config
            .max_age
            .is_none_or(|max| age.is_some_and(|age| age < max))
            && (history_weight * decay(self.history.point.age(now), config.half_life)
                >= config.min_weight
                || self.rtt.fresh(now, config.performance_window)
                || self.rate.fresh(now, config.performance_window))
    }

    fn retry_at(&self, now: Instant) -> Option<Instant> {
        self.cooling
            .active(now)
            .max(self.hard_retry.filter(|&retry_at| retry_at > now))
    }

    fn defer_until(&mut self, retry_at: Instant) {
        self.hard_retry = self.hard_retry.max(Some(retry_at));
    }

    fn physical_failure(&mut self, event: &crate::CarrierFailureEvent) -> bool {
        let report = &event.report;
        self.physical_failures
            .retain(|id, _| id == &report.connection || id.is_live());
        if self
            .physical_failures
            .get(&report.connection)
            .is_some_and(|&round| round >= report.round)
        {
            return false;
        }
        self.physical_failures
            .insert(report.connection.clone(), report.round);
        if let Some(retry_at) = event.retry_at {
            self.defer_until(retry_at);
        }
        true
    }
}

fn decay(age: Duration, half_life: Duration) -> f64 {
    (-age.as_secs_f64() / half_life.as_secs_f64()).exp2()
}

#[derive(Debug, Serialize, Deserialize)]
struct Snapshot {
    version: i64,
    #[serde(default = "zero_time", with = "time::serde::rfc3339")]
    exported_at: OffsetDateTime,
    #[serde(default)]
    entries: Vec<Row>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Row {
    key: String,
    kind: String,
    #[serde(default)]
    variant: String,
    #[serde(flatten)]
    entry: Entry,
}

#[derive(Debug)]
struct Inner {
    anchor: Clock,
    config: CarrierCacheConfig,
    entries: Mutex<HashMap<Key, Entry>>,
    episodes: AtomicU64,
    changed: tokio::sync::watch::Sender<u64>,
    cooldown_events: tokio::sync::broadcast::Sender<CooldownEvent>,
}

/// Shared carrier scores, cooldowns and in-process redirect hints.
#[derive(Debug, Clone)]
pub struct CarrierCache(Arc<Inner>);

impl Default for CarrierCache {
    fn default() -> Self {
        Self::from_config(CarrierCacheConfig::default())
    }
}

impl CarrierCache {
    pub(super) fn shares_history(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// Creates an empty cache with shared scoring and backoff settings.
    ///
    /// # Errors
    ///
    /// Returns an invalid configuration error for zero durations, waits that
    /// exceed the configured clock, invalid backoff bounds, or invalid scoring settings.
    pub fn new(config: CarrierCacheConfig) -> Result<Self, InvalidConfig> {
        config.backoff.validate()?;
        if config.short_drop_resilient && config.backoff != CarrierCacheConfig::short_drop_backoff()
        {
            return Err(InvalidConfig::new(
                "CarrierCacheConfig::backoff",
                "cannot override the short-drop-resilient profile",
            ));
        }
        let now = config.clock_domain.now();
        for (field, duration) in [
            ("CarrierCacheConfig::half_life", config.half_life),
            ("CarrierCacheConfig::drop_window", config.drop_window),
            (
                "CarrierCacheConfig::performance_window",
                config.performance_window,
            ),
            ("CarrierCacheConfig::health_reset", config.health_reset),
            ("Backoff::max", config.backoff.wait_upper()),
        ] {
            if duration.is_zero() {
                return Err(InvalidConfig::new(field, "zero duration"));
            }
            checked_clock_deadline(now, duration, field)?;
        }
        if let Some(max_age) = config.max_age {
            checked_clock_deadline(now, max_age, "CarrierCacheConfig::max_age")?;
        }
        if !config.min_weight.is_finite()
            || config.min_weight < 0.0
            || config
                .kind_priors
                .values()
                .any(|&prior| !prior.is_finite() || prior <= 0.0)
        {
            return Err(InvalidConfig::new(
                "CarrierCacheConfig",
                "invalid weight or prior",
            ));
        }
        Ok(Self::from_config(config))
    }

    fn from_config(config: CarrierCacheConfig) -> Self {
        Self(Arc::new(Inner {
            anchor: Clock::now(&config),
            config,
            entries: Mutex::default(),
            episodes: AtomicU64::new(0),
            changed: tokio::sync::watch::Sender::new(0),
            cooldown_events: tokio::sync::broadcast::channel(256).0,
        }))
    }

    fn owner_clock(&self) -> Clock {
        let anchor = self.0.anchor;
        let mono = self.clock_domain().now();
        let elapsed = time::Duration::try_from(mono.saturating_duration_since(anchor.mono))
            .unwrap_or(time::Duration::MAX);
        Clock {
            mono,
            wall: anchor.wall.saturating_add(elapsed),
        }
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<Key, Entry>> {
        self.0
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn health_deadline(
        &self,
        key: &Key,
        since: Instant,
        now: Instant,
    ) -> Option<(Instant, Duration)> {
        let hold = self.0.config.health_reset;
        let entries = self.entries();
        let cooling = &entries.get(key)?.cooling;
        if cooling.level == 0 {
            return None;
        }
        let age = cooling
            .point
            .known_age(now)?
            .min(now.saturating_duration_since(since));
        Some((now.checked_add(hold.saturating_sub(age))?, hold))
    }

    /// Clock domain of observations entering this cache.
    #[must_use]
    pub fn clock_domain(&self) -> &crate::ClockDomain {
        &self.0.config.clock_domain
    }

    pub(super) fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.0.changed.subscribe()
    }

    fn notify(&self) {
        self.0.changed.send_modify(|seq| *seq = seq.wrapping_add(1));
    }

    pub(crate) fn drop_window(&self) -> Duration {
        self.0.config.drop_window
    }

    /// Subscribes to future cooldown commits, in commit order.
    ///
    /// A receiver that falls behind the bounded history receives a lag error.
    #[must_use]
    pub fn subscribe_cooldown(&self) -> tokio::sync::broadcast::Receiver<CooldownEvent> {
        self.0.cooldown_events.subscribe()
    }

    /// Returns a point-in-time view of retry counters and the local wait.
    #[must_use]
    pub fn retry_metrics(&self, key: &str, kind: CarrierKind, variant: &str) -> RetryMetrics {
        self.query_at(
            key,
            kind,
            variant,
            self.clock_domain().now(),
            |entry, _, now, _| {
                let mut metrics = entry.metrics.clone();
                metrics.recovery_nominal = entry.recovery.nominal;
                metrics.recovery_sampled = entry.recovery.sampled;
                metrics.recovery_retry_at = entry.recovery.retry_at;
                if !entry.cooling.nominal().is_zero() || entry.cooling.level > 0 {
                    metrics.elapsed = entry.cooling.point.known_age(now);
                }
                metrics.remaining = entry
                    .cooling
                    .active(now)
                    .map_or(Duration::ZERO, |at| at - now);
                metrics
            },
        )
    }

    pub(super) fn suppress<D: Driver>(
        &self,
        key: &str,
        candidate: &Candidate<D>,
        reason: RetryAdmission,
    ) {
        self.entries()
            .entry(candidate_key(key, candidate))
            .or_default()
            .metrics
            .suppress(reason);
    }

    /// Returns the current score and backing evidence.
    #[must_use]
    pub fn score(&self, key: &str, kind: CarrierKind, variant: &str) -> CarrierScore {
        self.query_at(key, kind, variant, self.clock_domain().now(), Entry::score)
    }

    pub(super) fn rank_at(
        &self,
        key: &str,
        kind: CarrierKind,
        variant: &str,
        now: Instant,
    ) -> CarrierRank {
        self.query_at(key, kind, variant, now, Entry::rank)
    }

    fn query_at<T>(
        &self,
        key: &str,
        kind: CarrierKind,
        variant: &str,
        now: Instant,
        query: impl FnOnce(&Entry, &CarrierCacheConfig, Instant, f64) -> T,
    ) -> T {
        let config = &self.0.config;
        let prior = config.kind_priors.get(&kind).copied().unwrap_or(1.0);
        let entries = self.entries();
        let entry = entries
            .get(&(key.to_owned(), kind, variant.to_owned()))
            .filter(|entry| entry.keep(config, now));
        match entry {
            Some(entry) => query(entry, config, now, prior),
            None => query(&Entry::default(), config, now, prior),
        }
    }

    /// Registers a host source scoped to the given cache key, carrier kind and variant.
    #[must_use]
    pub fn register_report_source(
        &self,
        key: impl Into<String>,
        kind: CarrierKind,
        variant: impl Into<String>,
    ) -> CarrierReportSource {
        CarrierReportSource(Arc::new(ReportSource {
            cache: Arc::downgrade(&self.0),
            key: (key.into(), kind, variant.into()),
            replay: Mutex::default(),
        }))
    }

    /// Applies a typed host observation once in its source's sequence space.
    ///
    /// Returns whether the observation was new.
    ///
    /// # Errors
    ///
    /// Rejects foreign sources, invalid samples and sequences outside the replay window.
    pub fn report_from(
        &self,
        source: &CarrierReportSource,
        sequence: u64,
        outcome: CacheOutcome,
        mut observation: CarrierObservation,
    ) -> Result<bool, CarrierCacheError> {
        let source = &source.0;
        if !std::ptr::eq(source.cache.as_ptr(), Arc::as_ptr(&self.0)) {
            return Err(CarrierCacheError::UnknownSource);
        }
        let now = Clock::now(&self.0.config);
        if observation.at.is_some_and(|at| at > now.mono) {
            return Err(CarrierCacheError::Value);
        }
        let mut replay = source
            .replay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !replay.claim(sequence)? {
            return Ok(false);
        }
        observation.source = CarrierMeasurementSource::HostReport;
        self.update(
            &source.key,
            outcome,
            observation,
            Write {
                clock: Some(now),
                ..Write::new(true)
            },
        )?;
        Ok(true)
    }

    /// Records one completed attempt or later observation.
    ///
    /// # Errors
    ///
    /// Returns [`CarrierCacheError::Value`] when the sample is from the future.
    pub(super) fn report(
        &self,
        key: &str,
        kind: CarrierKind,
        variant: &str,
        outcome: CacheOutcome,
        observation: CarrierObservation,
    ) -> Result<(), CarrierCacheError> {
        self.update(
            &(key.to_owned(), kind, variant.to_owned()),
            outcome,
            observation,
            Write::new(true),
        )
    }

    /// Records a member observation into a session's outage journal.
    pub(super) fn report_journaled(
        &self,
        key: &Key,
        outcome: CacheOutcome,
        observation: CarrierObservation,
        journal: Option<&mut OutageJournal>,
    ) {
        let _ = self.update(
            key,
            outcome,
            observation,
            Write {
                journal,
                ..Write::new(true)
            },
        );
    }

    pub(super) fn record<D: Driver>(
        &self,
        key: &str,
        candidate: &Candidate<D>,
        outcome: CacheOutcome,
        start_cooling: bool,
    ) {
        let _ = self.update(
            &candidate_key(key, candidate),
            outcome,
            CarrierObservation::default(),
            Write {
                target: candidate.target().map(AsRef::as_ref),
                ..Write::new(start_cooling)
            },
        );
    }

    fn cool_journaled(
        &self,
        key: &Key,
        entry: &mut Entry,
        reason: CooldownReason,
        now: Clock,
        at: Instant,
        journal: Option<&mut OutageJournal>,
    ) {
        match journal {
            Some(journal) => {
                if !journal.defers(key, reason) {
                    journal.before_cool(key, entry);
                    self.cool(key, entry, reason, now, at);
                    journal.after_cool(key, entry, reason);
                }
            }
            None => self.cool(key, entry, reason, now, at),
        }
    }

    fn cool(&self, key: &Key, entry: &mut Entry, reason: CooldownReason, now: Clock, at: Instant) {
        let config = &self.0.config;
        let sampled_wait = entry.cooling.escalate(
            config.backoff,
            at,
            Point::new(now, at),
            reason,
            config
                .short_drop_resilient
                .then_some(Duration::from_mins(10)),
            |point| point.age(at),
        );
        // All episode commits hold the entries lock.
        let episode = self
            .0
            .episodes
            .load(Ordering::Relaxed)
            .checked_add(1)
            .expect("carrier cache episode IDs exhausted");
        self.0.episodes.store(episode, Ordering::Relaxed);
        entry.cooling.local = Some(LocalCooldown {
            episode,
            reason,
            at,
            sampled_wait,
        });
        entry.metrics.faults = entry.metrics.faults.saturating_add(1);
        if self.0.cooldown_events.receiver_count() != 0 {
            let _ = self.0.cooldown_events.send(CooldownEvent::Started {
                key: key.into(),
                episode,
                level: entry.cooling.level.unsigned_abs(),
                reason,
                started_at: at,
                nominal_wait: entry.cooling.nominal(),
                sampled_wait,
                retry_at: entry.cooling.until.unwrap_or(at),
            });
        }
    }

    fn update(
        &self,
        key: &Key,
        outcome: CacheOutcome,
        observation: CarrierObservation,
        write: Write<'_>,
    ) -> Result<(), CarrierCacheError> {
        let Write {
            target,
            clock,
            start_cooling,
            mut journal,
        } = write;
        let redirected = target.and_then(|target| match outcome {
            CacheOutcome::Usable => {
                let url = target.url();
                (url != target.base()).then_some(url)
            }
            CacheOutcome::Failed | CacheOutcome::Rejected => {
                target.reset();
                None
            }
            _ => None,
        });
        let config = &self.0.config;
        let now = clock.unwrap_or_else(|| self.owner_clock());
        let mut entries = self.entries();
        let at = observation.at.unwrap_or(now.mono);
        if at > now.mono {
            return Err(CarrierCacheError::Value);
        }
        entries.retain(|_, entry| entry.keep(config, now.mono));
        let entry = entries.entry(key.clone()).or_default();
        let start_cooling = start_cooling
            && observation
                .physical_failure
                .is_none_or(|failure| entry.physical_failure(&failure));
        let age = now.mono - at;
        let weight = decay(age, config.half_life);
        if let Some(journal) = journal.as_deref_mut()
            && matches!(
                outcome,
                CacheOutcome::Failed
                    | CacheOutcome::Rejected
                    | CacheOutcome::ShortDrop
                    | CacheOutcome::LateDrop
            )
        {
            journal.history(key, outcome, weight, now.mono, config.half_life);
        }
        let h = &mut entry.history;
        if !matches!(outcome, CacheOutcome::Performance | CacheOutcome::Recovered) {
            h.decay(decay(h.point.age(now.mono), config.half_life));
            h.point = Point::new(now, now.mono);
        }
        let mut cool = |entry: &mut Entry, reason| {
            if start_cooling {
                self.cool_journaled(key, entry, reason, now, at, journal.as_deref_mut());
            }
        };
        match outcome {
            CacheOutcome::Usable => {
                h.attempts = h.attempts.saturating_add(1);
                h.success += weight;
                if target.is_some() {
                    entry.url = redirected;
                }
            }
            CacheOutcome::Failed | CacheOutcome::Rejected => {
                h.attempts = h.attempts.saturating_add(1);
                h.failure += weight;
                cool(
                    entry,
                    if outcome == CacheOutcome::Rejected {
                        CooldownReason::Rejected
                    } else {
                        CooldownReason::Attempt
                    },
                );
                entry.url = None;
            }
            CacheOutcome::Survived => h.survived += weight,
            CacheOutcome::ShortDrop | CacheOutcome::LateDrop => {
                if outcome == CacheOutcome::ShortDrop {
                    h.short_drop += weight;
                } else {
                    h.late_drop += weight;
                }
                cool(
                    entry,
                    if outcome == CacheOutcome::ShortDrop {
                        CooldownReason::ShortDrop
                    } else {
                        CooldownReason::LateDrop
                    },
                );
            }
            CacheOutcome::Lifetime => {
                let lambda = std::f64::consts::LN_2 / config.half_life.as_secs_f64();
                let seconds = observation.duration.as_secs_f64();
                h.late_seconds += weight * -(-lambda * seconds).exp_m1() / lambda;
            }
            CacheOutcome::Performance => {
                let point = Point::new(now, at);
                entry.rtt.update(
                    &point,
                    observation.rtt.as_secs_f64(),
                    observation.valid_for,
                    observation.source,
                );
                entry.rate.update(
                    &point,
                    crate::util::f64_of(observation.rate),
                    observation.valid_for,
                    observation.source,
                );
            }
            CacheOutcome::Recovered => {
                if observation.duration >= config.health_reset
                    && entry.cooling.point.age(now.mono) >= age.saturating_add(observation.duration)
                {
                    self.reset_cooling(key, entry, now);
                }
            }
        }
        drop(entries);
        self.notify();
        Ok(())
    }

    pub(crate) fn prime<D: Driver>(&self, key: &str, candidate: &Candidate<D>) {
        let Some(target) = candidate.target() else {
            return;
        };
        let url = self
            .entries()
            .get(&candidate_key(key, candidate))
            .and_then(|entry| entry.url.clone());
        if let Some(url) = url {
            target.redirected(&url);
        }
    }

    /// `cutoff` is the session's latest useful recovery start, which caps the
    /// shared cadence wait.
    pub(super) fn candidate_admission<D: Driver>(
        &self,
        key: &str,
        candidate: &Candidate<D>,
        recover_direction: bool,
        cutoff: Option<Instant>,
    ) -> Result<bool, RetryAdmission> {
        let entries = self.entries();
        let now = self.clock_domain().now();
        entries
            .get(&candidate_key(key, candidate))
            .map_or(Ok(false), |entry| {
                Self::admission(entry, now, recover_direction, cutoff)
            })
    }

    pub(super) fn recovery_due<D: Driver>(
        &self,
        key: &str,
        candidate: &Candidate<D>,
        now: Instant,
        cutoff: Option<Instant>,
    ) -> bool {
        self.entries()
            .get(&candidate_key(key, candidate))
            .and_then(|entry| recovery_gate(&entry.recovery, cutoff))
            .is_none_or(|at| now >= at)
    }

    pub(super) fn next_candidate_retry<D: Driver>(
        &self,
        key: &str,
        candidate: &Candidate<D>,
        recovery: bool,
        cutoff: Option<Instant>,
    ) -> Option<Instant> {
        let now = self.clock_domain().now();
        let entries = self.entries();
        let entry = entries.get(&candidate_key(key, candidate))?;
        if recovery {
            recovery_gate(&entry.recovery, cutoff)
                .max(entry.hard_retry)
                .filter(|&due| due > now)
        } else {
            entry.retry_at(now)
        }
    }

    fn reset_cooling(&self, key: &Key, entry: &mut Entry, now: Clock) -> bool {
        let previous = std::mem::take(&mut entry.cooling);
        entry.cooling.point = Point::new(now, now.mono);
        let committed = previous.level != 0 || !previous.nominal().is_zero();
        if committed && self.0.cooldown_events.receiver_count() != 0 {
            let _ = self.0.cooldown_events.send(CooldownEvent::Reset {
                key: key.into(),
                episode: previous.local.map(|local| local.episode),
                reset_at: now.mono,
            });
        }
        committed
    }

    fn clear_cooldown(&self, key: &Key, entry: &mut Entry, now: Clock) -> bool {
        let mut cleared = false;
        if entry.cooling.level != 0 || !entry.cooling.nominal().is_zero() {
            cleared = self.reset_cooling(key, entry, now);
        }
        if entry.recovery != RecoveryCadence::default() {
            entry.recovery = RecoveryCadence::default();
            cleared = true;
        }
        cleared
    }

    /// Clears one key's ordinary cooldown (level, backoff, retry time and
    /// short-drop marks) and recovery cadence at once, as a health reset does.
    /// Scoring history, peer retry deadlines and an in-flight attempt are
    /// kept. Hosts call it when the network changes. Returns whether any state
    /// was cleared.
    #[must_use = "reports whether any state was cleared"]
    pub fn reset_cooldown(&self, key: &str, kind: CarrierKind, variant: &str) -> bool {
        let now = self.owner_clock();
        let mut entries = self.entries();
        let key = (key.to_owned(), kind, variant.to_owned());
        let cleared = entries
            .get_mut(&key)
            .is_some_and(|entry| self.clear_cooldown(&key, entry, now));
        drop(entries);
        if cleared {
            self.notify();
        }
        cleared
    }

    /// Applies [`Self::reset_cooldown`] to every key and returns how many had
    /// state to clear.
    #[must_use = "reports how many keys were cleared"]
    pub fn reset_cooldowns(&self) -> usize {
        let now = self.owner_clock();
        let mut entries = self.entries();
        let mut cleared = 0;
        for (key, entry) in entries.iter_mut() {
            cleared += usize::from(self.clear_cooldown(key, entry, now));
        }
        drop(entries);
        if cleared != 0 {
            self.notify();
        }
        cleared
    }

    /// Reads retry admission for a candidate's cache key.
    ///
    /// Admission is checked again when a dial reserves its token. Session and
    /// host admission constraints are evaluated by the caller of the cache.
    ///
    /// # Errors
    ///
    /// Returns the current cache-level reason if an attempt is suppressed.
    pub fn retry_admission(
        &self,
        key: &str,
        kind: CarrierKind,
        variant: &str,
    ) -> Result<(), RetryAdmission> {
        let now = self.clock_domain().now();
        self.entries()
            .get(&(key.to_owned(), kind, variant.to_owned()))
            .map_or(Ok(()), |entry| {
                Self::admission(entry, now, false, None).map(|_| ())
            })
    }

    fn admission(
        entry: &Entry,
        now: Instant,
        recover_direction: bool,
        cutoff: Option<Instant>,
    ) -> Result<bool, RetryAdmission> {
        if entry.in_flight.is_some() {
            return Err(RetryAdmission::AlreadyInFlight);
        }
        if entry.hard_retry.is_some_and(|retry_at| retry_at > now) {
            return Err(RetryAdmission::RetryAfter);
        }
        Self::time_admission(entry, now, recover_direction, cutoff)
    }

    fn time_admission(
        entry: &Entry,
        now: Instant,
        recovery: bool,
        cutoff: Option<Instant>,
    ) -> Result<bool, RetryAdmission> {
        if recovery && recovery_gate(&entry.recovery, cutoff).is_some_and(|due| now < due) {
            return Err(RetryAdmission::RecoveryWait);
        }
        let cooling = entry.cooling.active(now).is_some();
        if cooling && !recovery {
            return Err(RetryAdmission::Cooling);
        }
        Ok(cooling)
    }

    pub(super) fn recovery_demand(&self, key: &Key, add: bool) {
        let mut entries = self.entries();
        let entry = entries.entry(key.clone()).or_default();
        if add {
            entry.demand += 1;
        } else {
            entry.demand -= 1;
            if entry.demand == 0 {
                entry.recovery = RecoveryCadence::default();
            }
        }
    }

    pub(super) fn begin<D: Driver>(
        &self,
        key: &str,
        candidate: &Candidate<D>,
        recover_direction: bool,
        dial: Option<super::controller::DialGate>,
    ) -> Result<AttemptPermit, RetryAdmission> {
        let key = candidate_key(key, candidate);
        let mut entries = self.entries();
        let now = self.clock_domain().now();
        let entry = entries.entry(key.clone()).or_default();
        let admission = if dial
            .as_ref()
            .is_some_and(|gate| gate.blocked(now).is_some())
        {
            Err(RetryAdmission::DialAfter)
        } else {
            Self::admission(
                entry,
                now,
                recover_direction,
                dial.as_ref()
                    .and_then(super::controller::DialGate::recovery_cutoff),
            )
        };
        admission?;
        let ticket = Arc::new(AttemptTicket {
            key,
            started: AtomicBool::new(false),
            logical_done: AtomicBool::new(false),
            host_returned: AtomicBool::new(false),
            handshake_recorded: AtomicBool::new(false),
            replies: Mutex::new((candidate.layout.len(), None)),
            recovery: recover_direction,
        });
        entry.in_flight = Some(ticket.clone());
        Ok(AttemptPermit(AttemptStart {
            cache: self.clone(),
            ticket,
            target: candidate.target().cloned(),
            dial,
            opportunity: None,
        }))
    }

    /// Exports the Go-compatible version 2 snapshot. Redirect hints are process-local.
    ///
    /// # Errors
    ///
    /// Returns an encoding error if the snapshot cannot be represented in JSON.
    pub fn export(&self) -> Result<Vec<u8>, CarrierCacheError> {
        let now = Clock::now(&self.0.config);
        let mut entries: Vec<_> = self
            .entries()
            .iter()
            .filter(|(_, entry)| entry.has_snapshot_data() && entry.keep(&self.0.config, now.mono))
            .map(|((key, kind, variant), entry)| Row {
                key: key.clone(),
                kind: kind.name().into(),
                variant: variant.clone(),
                entry: entry.clone().export(now.mono),
            })
            .collect();
        entries.sort_unstable_by(|a, b| {
            (&a.key, &a.kind, &a.variant).cmp(&(&b.key, &b.kind, &b.variant))
        });
        serde_json::to_vec(&Snapshot {
            version: VERSION,
            exported_at: now.wall,
            entries,
        })
        .map_err(|_| CarrierCacheError::Format)
    }

    /// Atomically validates and merges a version 2 snapshot. Replay of an equal
    /// timestamp preserves the local observation and cooling deadline.
    ///
    /// # Errors
    ///
    /// Returns a distinct error for an unsupported version, malformed format,
    /// or an invalid value. All entries are validated before any are merged.
    pub fn import(&self, bytes: &[u8]) -> Result<(), CarrierCacheError> {
        let config = &self.0.config;
        let snapshot: Snapshot =
            serde_json::from_slice(bytes).map_err(|_| CarrierCacheError::Format)?;
        if snapshot.version != VERSION {
            return Err(CarrierCacheError::Version);
        }
        if snapshot.exported_at == zero_time()
            || config
                .import_limit
                .is_some_and(|limit| snapshot.entries.len() > limit)
        {
            return Err(CarrierCacheError::Value);
        }
        let mut keys = HashSet::new();
        let mut validated = Vec::with_capacity(snapshot.entries.len());
        for row in snapshot.entries {
            let kind = CarrierKind::from_name(&row.kind).ok_or(CarrierCacheError::Value)?;
            let key = (row.key, kind, row.variant);
            let mut entry = row.entry;
            if !entry.validate(config.backoff) || !keys.insert(key.clone()) {
                return Err(CarrierCacheError::Value);
            }
            validated.push((key, entry));
        }
        let now = Clock::now(config);
        let elapsed = now.age(snapshot.exported_at);
        let mut entries = self.entries();
        for (key, entry) in validated {
            entries.entry(key).or_default().merge(entry, now, elapsed);
        }
        entries.retain(|_, entry| entry.keep(config, now.mono));
        drop(entries);
        self.notify();
        Ok(())
    }
}

/// The recovery time gate capped at the session's cutoff.
/// The cap applies only to a wait drawn before the cutoff, so the session
/// gets one start at the cutoff and later failures keep the cadence.
fn recovery_gate(recovery: &RecoveryCadence, cutoff: Option<Instant>) -> Option<Instant> {
    let retry = recovery.retry_at?;
    let drawn = retry.checked_sub(recovery.sampled);
    Some(match cutoff {
        Some(cutoff) if cutoff < retry && drawn.is_some_and(|at| at < cutoff) => cutoff,
        _ => retry,
    })
}

pub(super) fn candidate_key<D: Driver>(key: &str, candidate: &Candidate<D>) -> Key {
    (
        key.to_owned(),
        candidate.kind(),
        candidate.variant().map_or("", |v| v.as_ref()).to_owned(),
    )
}

/// A carrier opener's authenticated refusal with a retry deadline for its candidate.
/// Convert to `std::io::Error` and return it from the opener.
#[derive(Debug, Clone, Copy)]
pub struct CarrierRetryAfter {
    delay: Duration,
}

impl CarrierRetryAfter {
    /// Creates a refusal with a delay measured from the observed completion.
    #[must_use]
    pub const fn new(delay: Duration) -> Self {
        Self { delay }
    }

    fn find(mut source: &(dyn std::error::Error + 'static)) -> Option<Duration> {
        loop {
            if let Some(retry) = source.downcast_ref::<Self>() {
                return Some(retry.delay);
            }
            source = if let Some(io) = source.downcast_ref::<std::io::Error>()
                && let Some(inner) = io.get_ref()
            {
                inner
            } else {
                source.source()?
            };
        }
    }
}

fn retry_deadline(now: Instant, delay: Duration) -> Instant {
    if let Some(at) = now.checked_add(delay) {
        return at;
    }
    // An unrepresentable peer deadline blocks until the end of the clock.
    let mut lower = Duration::ZERO;
    let mut upper = delay;
    while upper.saturating_sub(lower) > Duration::from_nanos(1) {
        let midpoint = lower + upper.saturating_sub(lower) / 2;
        if now.checked_add(midpoint).is_some() {
            lower = midpoint;
        } else {
            upper = midpoint;
        }
    }
    now + lower
}

impl fmt::Display for CarrierRetryAfter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the carrier requires a later retry")
    }
}

impl std::error::Error for CarrierRetryAfter {}

impl From<CarrierRetryAfter> for std::io::Error {
    fn from(error: CarrierRetryAfter) -> Self {
        Self::new(std::io::ErrorKind::ConnectionRefused, error)
    }
}

#[derive(Debug)]
struct AttemptTicket {
    handshake_recorded: AtomicBool,
    replies: Mutex<(usize, Option<Instant>)>,
    key: Key,
    recovery: bool,
    logical_done: AtomicBool,
    host_returned: AtomicBool,
    started: AtomicBool,
}

#[derive(Clone)]
pub(super) struct AttemptStart {
    target: Option<Arc<crate::HttpTarget>>,
    cache: CarrierCache,
    ticket: Arc<AttemptTicket>,
    dial: Option<super::controller::DialGate>,
    opportunity: Option<super::controller::domain::Suppression>,
}

impl AttemptStart {
    pub(super) fn handshake(&self, outcome: CacheOutcome, at: Option<Instant>) {
        self.handshake_journaled(outcome, at, None);
    }

    fn handshake_journaled(
        &self,
        outcome: CacheOutcome,
        at: Option<Instant>,
        journal: Option<&mut OutageJournal>,
    ) {
        if !self.ticket.handshake_recorded.swap(true, Ordering::Relaxed) {
            let _ = self.cache.update(
                &self.ticket.key,
                outcome,
                CarrierObservation {
                    at,
                    ..CarrierObservation::default()
                },
                Write {
                    target: self.target.as_deref(),
                    journal,
                    ..Write::new(true)
                },
            );
        }
    }

    pub(super) fn start(&self) -> Result<(), RetryAdmission> {
        let mut entries = self.cache.entries();
        let now = self.cache.clock_domain().now();
        let entry = entries.entry(self.ticket.key.clone()).or_default();
        let result = self.check_start(entry, now);
        if let Err(reason) = result {
            if self.count_suppression() {
                entry.metrics.suppress(reason);
            }
            return Err(reason);
        }
        if let Some(opportunity) = &self.opportunity {
            opportunity.started();
        }
        self.ticket.started.store(true, Ordering::Relaxed);
        entry.metrics.attempted_starts = entry.metrics.attempted_starts.saturating_add(1);
        Ok(())
    }

    fn check_start(&self, entry: &mut Entry, now: Instant) -> Result<(), RetryAdmission> {
        if self.ticket.started.load(Ordering::Relaxed)
            || entry
                .in_flight
                .as_ref()
                .is_none_or(|held| !Arc::ptr_eq(held, &self.ticket))
        {
            return Err(RetryAdmission::Stale);
        }
        if self
            .dial
            .as_ref()
            .is_some_and(|gate| gate.blocked(now).is_some())
        {
            return Err(RetryAdmission::DialAfter);
        }
        if entry.hard_retry.is_some_and(|at| at > now) {
            return Err(RetryAdmission::RetryAfter);
        }
        CarrierCache::time_admission(
            entry,
            now,
            self.ticket.recovery,
            self.dial
                .as_ref()
                .and_then(super::controller::DialGate::recovery_cutoff),
        )
        .map(|_| ())
    }

    fn count_suppression(&self) -> bool {
        self.opportunity
            .as_ref()
            .is_none_or(super::controller::domain::Suppression::count)
    }

    pub(super) fn suppress(&self, reason: RetryAdmission) {
        if !self.count_suppression() {
            return;
        }
        self.cache
            .entries()
            .entry(self.ticket.key.clone())
            .or_default()
            .metrics
            .suppress(reason);
    }

    pub(super) fn sample(&self) -> f64 {
        (self.cache.0.config.recovery_sample)()
    }

    pub(super) fn record_refusal(&self, error: &std::io::Error) {
        self.record_refusal_at(error, self.cache.clock_domain().now());
    }

    fn record_refusal_at(&self, error: &std::io::Error, at: Instant) {
        let Some(delay) = CarrierRetryAfter::find(error) else {
            return;
        };
        let mut entries = self.cache.entries();
        if let Some(entry) = entries.get_mut(&self.ticket.key)
            && entry
                .in_flight
                .as_ref()
                .is_some_and(|held| Arc::ptr_eq(held, &self.ticket))
        {
            entry.defer_until(retry_deadline(at, delay));
        }
        drop(entries);
        self.cache.notify();
    }
}

impl OpenerAdmission for AttemptStart {
    fn replied(&self, at: Instant) {
        let mut replies = self
            .ticket
            .replies
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if replies.0 == 0 {
            return;
        }
        replies.0 -= 1;
        replies.1 = Some(replies.1.map_or(at, |prior| prior.max(at)));
        if replies.0 == 0 {
            self.handshake(CacheOutcome::Usable, replies.1);
        }
    }
    fn start(&self) -> Result<(), RetryAdmission> {
        self.start()
    }
    fn suppress(&self, reason: RetryAdmission) {
        self.suppress(reason);
    }
    fn host_returned(&self) {
        self.finish(false);
    }
}

pub(crate) struct AttemptPermit(AttemptStart);

impl AttemptPermit {
    pub(super) fn with_opportunity(
        mut self,
        opportunity: super::controller::domain::Suppression,
    ) -> Self {
        self.0.opportunity = Some(opportunity);
        self
    }

    pub(super) fn start_handle(&self) -> AttemptStart {
        self.0.clone()
    }

    pub(super) fn confirm(&self) {
        let start = &self.0;
        if let Some(entry) = start.cache.entries().get_mut(&start.ticket.key) {
            entry.recovery = RecoveryCadence::default();
        }
    }

    /// Linearizes the demand check with its cadence update while the session
    /// still owns the attempt. Sampling happens only after releasing both owners.
    pub(super) fn commit_cadence(
        &self,
        reason: crate::AttemptReason,
        failed: bool,
        at: Instant,
        sample: Option<f64>,
        outage: Option<&OutageLog>,
    ) -> Result<(), AttemptStart> {
        let start = &self.0;
        if !start.ticket.started.load(Ordering::Relaxed) {
            return Ok(());
        }
        // Lock order: the outage journal before the cache entries.
        let commit = |journal: Option<&mut OutageJournal>| {
            let mut entries = start.cache.entries();
            let Some(entry) = entries.get_mut(&start.ticket.key) else {
                return Ok(());
            };
            if reason == crate::AttemptReason::Confirmed {
                entry.recovery = RecoveryCadence::default();
            } else if failed && start.ticket.recovery && entry.demand != 0 {
                let Some(sample) = sample else {
                    return Err(start.clone());
                };
                let before = entry.recovery;
                entry.recovery.advance(at, sample);
                if let Some(journal) = journal {
                    journal.recovery(&start.ticket.key, before, entry.recovery);
                }
            }
            Ok(())
        };
        match outage {
            Some(outage) => outage.with(false, commit),
            None => commit(None),
        }
    }

    #[cfg(test)]
    pub(super) fn record_refusal(&self, error: &std::io::Error) {
        self.0.record_refusal(error);
    }

    pub(super) fn settle(
        self,
        result: &crate::AttemptResult,
        at: Instant,
        outage: Option<&OutageLog>,
    ) {
        match outage {
            Some(outage) => {
                outage.with(false, |journal| self.settle_journaled(result, at, journal));
            }
            None => self.settle_journaled(result, at, None),
        }
    }

    fn settle_journaled(
        &self,
        result: &crate::AttemptResult,
        at: Instant,
        journal: Option<&mut OutageJournal>,
    ) {
        let start = &self.0;
        if !start.ticket.started.load(Ordering::Relaxed) {
            return;
        }
        if let Some(error) = &result.open_error {
            start.record_refusal_at(error, at);
        }
        if result.candidate_failed() {
            let now = start.cache.owner_clock();
            if start.ticket.handshake_recorded.load(Ordering::Relaxed) {
                let mut entries = start.cache.entries();
                if let Some(entry) = entries.get_mut(&start.ticket.key) {
                    start.cache.cool_journaled(
                        &start.ticket.key,
                        entry,
                        CooldownReason::Attempt,
                        now,
                        at,
                        journal,
                    );
                }
            } else {
                start.handshake_journaled(CacheOutcome::Failed, Some(at), journal);
            }
            start.cache.notify();
        }
    }
}

impl Drop for AttemptPermit {
    fn drop(&mut self) {
        self.0.finish(true);
    }
}

impl AttemptStart {
    fn finish(&self, logical: bool) {
        let mut entries = self.cache.entries();
        let ticket = &self.ticket;
        let Some(entry) = entries.get_mut(&ticket.key) else {
            return;
        };
        if entry
            .in_flight
            .as_ref()
            .is_none_or(|held| !Arc::ptr_eq(held, ticket))
        {
            return;
        }
        if logical {
            ticket.logical_done.store(true, Ordering::Relaxed);
        } else {
            ticket.host_returned.store(true, Ordering::Relaxed);
        }
        if !ticket.logical_done.load(Ordering::Relaxed)
            || ticket.started.load(Ordering::Relaxed)
                && !ticket.host_returned.load(Ordering::Relaxed)
        {
            return;
        }
        entry.in_flight = None;
        if entry.demand == 0
            && !entry.has_snapshot_data()
            && entry.hard_retry.is_none()
            && entry.metrics == RetryMetrics::default()
        {
            entries.remove(&ticket.key);
        }
        drop(entries);
        self.cache.notify();
    }
}

mod outage;
pub(super) use outage::{OutageJournal, OutageLog};

#[cfg(test)]
mod vectors;
