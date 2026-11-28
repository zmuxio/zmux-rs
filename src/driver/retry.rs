//! Retry rounds shared by carrier scoring and the private recovery keys.

use std::time::{Duration, Instant};

use crate::Backoff;

const SHORT_WINDOW: Duration = Duration::from_mins(10);
pub(super) const DROP_WINDOW: Duration = Duration::from_mins(1);
pub(super) const HEALTH_RESET: Duration = Duration::from_mins(10);
/// One sampled recovery opportunity, independent of ordinary scoring history.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct RecoveryCadence {
    pub(super) nominal: Duration,
    pub(super) sampled: Duration,
    pub(super) retry_at: Option<Instant>,
}

impl RecoveryCadence {
    pub(super) fn advance(&mut self, now: Instant, sample: f64) {
        self.nominal = (self.nominal * 2).clamp(Duration::from_secs(1), Duration::from_secs(60));
        self.sampled = crate::backoff::scale_nanos(self.nominal, sample);
        self.retry_at = now.checked_add(self.sampled);
    }
}

/// Why a candidate entered a retry cooldown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CooldownReason {
    /// A carrier open or protocol handshake failed.
    Attempt,
    /// Service failed inside the initial survival window.
    ShortDrop,
    /// Service failed at or after the initial survival window.
    LateDrop,
    /// The carrier path was definitively rejected.
    Rejected,
}

#[cfg(feature = "blocking")]
impl CooldownReason {
    pub(crate) fn from_pipe_error(error: &crate::PipeError) -> Option<Self> {
        use crate::{PipeError, PipeFailure};
        match error {
            PipeError::Io(error) => (!matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::QuotaExceeded
            ))
            .then_some(Self::Attempt),
            PipeError::Failed(PipeFailure::Aborted | PipeFailure::CallerDeadline) => None,
            PipeError::Failed(_) => Some(Self::Attempt),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub(super) struct Cooling<P> {
    #[serde(flatten)]
    pub(super) point: P,
    pub(super) nominal_ms: i64,
    #[serde(skip)]
    pub(super) last_nominal: Option<Duration>,

    pub(super) remaining_ms: i64,

    pub(super) level: i64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) short: Vec<P>,
    #[serde(skip)]
    pub(super) until: Option<Instant>,

    #[serde(skip)]
    pub(super) local: Option<LocalCooldown>,
}

/// Ephemeral exact details that the v2 interchange format omits.

#[derive(Debug, Clone, Copy)]
pub(super) struct LocalCooldown {
    pub(super) episode: u64,
    pub(super) reason: CooldownReason,
    pub(super) at: Instant,
    pub(super) sampled_wait: Duration,
}

impl<P: Clone> Cooling<P> {
    pub(super) fn nominal(&self) -> Duration {
        self.last_nominal
            .unwrap_or_else(|| Duration::from_millis(self.nominal_ms.unsigned_abs()))
    }

    pub(super) fn active(&self, now: Instant) -> Option<Instant> {
        self.until.filter(|&end| end > now)
    }

    pub(super) fn escalate(
        &mut self,
        settings: Backoff,
        now: Instant,
        point: P,
        reason: CooldownReason,
        short_drop_floor: Option<Duration>,
        age: impl Fn(&P) -> Duration,
    ) -> Duration {
        let mut nominal = settings.next_nominal(self.nominal());
        if reason == CooldownReason::ShortDrop
            && let Some(floor) = short_drop_floor
        {
            self.short.retain(|point| age(point) < SHORT_WINDOW);
            if self.short.len() == 3 {
                self.short.remove(0);
            }
            self.short.push(point.clone());
            if self.short.len() == 3 {
                nominal = nominal.max(floor);
            }
        }

        if reason == CooldownReason::Rejected {
            nominal = settings.max;
        }
        let sampled_wait = settings.wait(nominal);

        {
            self.level = self.level.saturating_add(1);
        }
        self.nominal_ms = millis(nominal);
        self.last_nominal = Some(nominal);
        self.point = point;
        self.until = now.checked_add(sampled_wait);
        sampled_wait
    }
}

pub(super) fn millis(duration: Duration) -> i64 {
    i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
}

/// A private key has a single cooling history and a minimum inter-attempt pace.
#[cfg(feature = "blocking")]
pub(crate) struct PrivateRetry {
    settings: Backoff,
    cooling: Cooling<Option<Instant>>,
    pace: Option<Instant>,
    cadence: RecoveryCadence,
    hard_retry: Option<Instant>,
}

#[cfg(feature = "blocking")]
impl PrivateRetry {
    pub(crate) fn new(settings: Backoff) -> Self {
        Self {
            settings,
            cooling: Cooling::default(),
            pace: None,
            cadence: RecoveryCadence::default(),
            hard_retry: None,
        }
    }

    pub(crate) fn deadline(&self, now: Instant, missing: bool) -> Option<Instant> {
        let soft = if missing {
            self.cadence.retry_at
        } else {
            self.pace.max(self.cooling.active(now))
        };
        soft.max(self.hard_retry).filter(|&end| end > now)
    }

    pub(crate) fn attempt_ended(
        &mut self,
        result: &crate::AttemptResult,
        now: Instant,
        missing: bool,
    ) {
        if result.reason == crate::AttemptReason::Confirmed || !missing {
            self.cadence = RecoveryCadence::default();
        } else if result.id.0 != 0 && result.candidate_failed() {
            self.cadence.advance(now, crate::backoff::random_fraction());
        }
    }

    pub(crate) fn success(&mut self, attempt: Instant) {
        self.pace = self
            .pace
            .max(attempt.checked_add(self.settings.wait(self.settings.min)));
    }

    pub(crate) fn failure(&mut self, now: Instant, reason: CooldownReason) {
        self.cooling
            .escalate(self.settings, now, Some(now), reason, None, |point| {
                point.map_or(Duration::MAX, |at| now.saturating_duration_since(at))
            });
    }

    fn recovered(&mut self, since: Instant, now: Instant) -> bool {
        if now.saturating_duration_since(since) >= HEALTH_RESET
            && self.cooling.point.is_none_or(|failure| failure <= since)
        {
            self.cooling = Cooling::default();
            true
        } else {
            false
        }
    }
}

/// Counts one handshake and each subsequent service fault for a member.
#[derive(Default)]
#[cfg(feature = "blocking")]
pub(crate) struct PrivateMember {
    joined: Option<Instant>,
    last_fault: u64,
    active_fault: bool,
    healthy_since: Option<Instant>,
    reset: bool,
}

#[cfg(feature = "blocking")]
pub(crate) struct MemberHealth {
    pub(crate) joined: Option<Instant>,
    pub(crate) fault: Option<crate::PipeHealthChange>,
    pub(crate) settled: bool,
    recovered: bool,
}

#[cfg(feature = "blocking")]
impl MemberHealth {
    pub(crate) fn from_pipes<D: super::handle::Driver>(
        pipes: &[super::handle::Pipe<D>],
        infos: &[Option<crate::PipeStats>],
    ) -> Self {
        let joined = infos
            .iter()
            .try_fold(None, |latest, info| {
                let joined = info.as_ref()?.health.joined_at?;
                Some(latest.max(Some(joined)))
            })
            .flatten();
        let fault = pipes
            .iter()
            .filter_map(super::handle::Pipe::last_health_fault)
            .max_by_key(|change| change.seq);
        let settled = infos
            .iter()
            .all(|info| info.as_ref().is_some_and(|info| info.health.settled()));
        let recovered = infos.iter().all(|info| {
            info.as_ref().is_some_and(|info| {
                let health = info.health;
                health.peer_attached && health.send.recovered() && health.receive.recovered()
            })
        });
        if !settled {
            for (pipe, info) in pipes.iter().zip(infos) {
                if info.as_ref().is_some_and(|info| {
                    info.health.peer_attached && !info.health.ending() && !info.health.settled()
                }) {
                    pipe.request_stability();
                }
            }
        }
        Self {
            joined,
            fault,
            settled,
            recovered,
        }
    }
}

#[cfg(feature = "blocking")]
impl PrivateMember {
    pub(crate) fn established(joined: Instant) -> Self {
        Self {
            joined: Some(joined),
            ..Self::default()
        }
    }

    pub(crate) fn observe(
        &mut self,
        retry: &mut PrivateRetry,
        now: Instant,
        started: Instant,
        health: MemberHealth,
    ) {
        if self.joined.is_none()
            && let Some(joined) = health.joined
        {
            self.joined = Some(joined);
            retry.success(started);
        }
        if let Some(fault) = health.fault.filter(|fault| fault.seq > self.last_fault) {
            self.last_fault = fault.seq;
            if !self.active_fault {
                let reason = if self
                    .joined
                    .is_some_and(|joined| fault.at.saturating_duration_since(joined) < DROP_WINDOW)
                {
                    CooldownReason::ShortDrop
                } else {
                    CooldownReason::LateDrop
                };
                retry.failure(now, reason);
                if let Some(event) = fault.physical_failure {
                    retry.hard_retry = retry.hard_retry.max(event.retry_at);
                }
                self.active_fault = true;
                self.healthy_since = None;
                self.reset = false;
            }
        }
        if health.recovered {
            self.active_fault = false;
        }
        if health.settled {
            let since = *self.healthy_since.get_or_insert(now);
            if !self.reset {
                self.reset = retry.recovered(since, now);
            }
        } else {
            self.healthy_since = None;
            self.reset = false;
        }
    }
}
