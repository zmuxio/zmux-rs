//! Probation of an outbound pipe and the probation history of a path.

use std::time::{Duration, Instant};

/// Probation of an outbound pipe.
#[derive(Debug, Clone, Default)]
pub(super) struct Probation {
    /// When the current probation started (`None` when none runs).
    started: Option<Instant>,
    /// Its backoff exponent k_p.
    k: u32,
    /// The probation history of a pipe of fate group 0 (others keep it
    /// per fate group).
    history: History,
    /// When the last probation probe was sent.
    ping: Option<Instant>,
    /// The start of the current ACTIVE period when it counts for the
    /// uptime cap: it began once the path had history.
    up_since: Option<Instant>,
}

impl Probation {
    /// In probation.
    pub(super) fn active(&self) -> bool {
        self.started.is_some()
    }

    /// When the current probation started, and its exponent.
    pub(super) fn current(&self) -> Option<(Instant, u32)> {
        self.started.map(|s| (s, self.k))
    }

    /// The pipe's own history (fate group 0).
    pub(super) fn history(&self) -> History {
        self.history
    }

    pub(super) fn history_mut(&mut self) -> &mut History {
        &mut self.history
    }

    /// A probation with exponent `k` starts now, when `enabled`; the ACTIVE
    /// period that begins counts for the uptime cap when `counted`.
    pub(super) fn start(&mut self, k: u32, enabled: bool, counted: bool, now: Instant) {
        self.k = k;
        self.started = enabled.then_some(now);
        self.ping = None;
        self.up_since = counted.then_some(now);
    }

    /// The probation was disabled: one in progress ends now; whether one
    /// was.
    pub(super) fn cancel(&mut self) -> bool {
        if self.started.take().is_some() {
            self.ping = None;
            return true;
        }
        false
    }

    /// The probation ended when due.
    pub(super) fn end(&mut self) {
        self.started = None;
    }

    /// The pipe became suspect: a probation in progress ends, and so does
    /// the ACTIVE period. Whether it was in probation, and when the period
    /// began if it counts for the uptime cap.
    pub(super) fn suspected(&mut self) -> (bool, Option<Instant>) {
        (self.started.take().is_some(), self.up_since.take())
    }

    /// The attachment failed: whether it was in probation, and when the
    /// ACTIVE period it ends began if it counts for the uptime cap.
    pub(super) fn failed(&mut self) -> (bool, Option<Instant>) {
        (self.active(), self.up_since.take())
    }

    /// A probation probe is due every `every`: whether one goes now.
    pub(super) fn probe(&mut self, every: Duration, now: Instant) -> bool {
        if self.ping.is_none_or(|t| now >= t + every) {
            self.ping = Some(now);
            return true;
        }
        false
    }

    /// When the next probation probe is due, every `every`.
    pub(super) fn next_probe(&self, every: Duration, now: Instant) -> Instant {
        self.ping.map_or(now, |t| t + every)
    }
}

/// The probation history of a pipe, or of a non-zero fate group and
/// direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct History {
    /// The backoff exponent k of the next probation.
    k: u32,
    /// When the last probation ended, and the 10 x base window after it.
    ended: Option<(Instant, Duration)>,
    /// A suspicion or failure in a probation or within 10 x base after one:
    /// the next probation raises k.
    pending: bool,
    /// The path has history: a pipe of it has been suspect or has failed
    /// (the 1 s floor of the base applies).
    trouble: bool,
    /// U_max: the longest ACTIVE period that began once the path had
    /// history and ended in a suspicion or failure; it caps probation at
    /// max(base, 2 x U_max), and is forgotten with k.
    u_max: Option<Duration>,
}

impl History {
    /// The largest backoff exponent.
    const MAX_K: u32 = 6;
    /// Bases after the end of a probation within which a suspicion still
    /// raises k, and after which k returns to 0.
    const RECENT: u32 = 10;

    /// The path has history: a pipe of it has been suspect or has failed.
    pub(crate) fn trouble(&self) -> bool {
        self.trouble
    }

    /// U_max, while it is remembered.
    pub(crate) fn u_max(&self) -> Option<Duration> {
        self.u_max
    }

    /// When the last probation ended.
    pub(crate) fn ended(&self) -> Option<(Instant, Duration)> {
        self.ended
    }

    /// A probation ended at `end`, with the backoff base `base`.
    pub(crate) fn probation_ended(&mut self, end: Instant, base: Duration) {
        self.ended = Some((end, base));
    }

    /// Whether `at` falls within 10 bases after the last probation ended.
    pub(crate) fn recent(&self, at: Instant) -> bool {
        // A base too large to add is recent for ever.
        self.ended.is_some_and(|(end, base)| {
            base.checked_mul(Self::RECENT)
                .and_then(|d| end.checked_add(d))
                .is_none_or(|until| at <= until)
        })
    }

    /// A suspicion or failure at `at`, `in_probation` or not, which ends
    /// an ACTIVE period that counts for the uptime cap when it began at
    /// `up_since`.
    pub(crate) fn trouble_at(
        &mut self,
        in_probation: bool,
        up_since: Option<Instant>,
        at: Instant,
    ) {
        if let Some(from) = up_since {
            let up = at.saturating_duration_since(from);
            self.u_max = Some(self.u_max.map_or(up, |u| u.max(up)));
        }
        self.trouble = true;
        if in_probation || self.recent(at) {
            self.pending = true;
        }
    }

    /// The exponent of a probation that starts now: k, raised when a
    /// suspicion or failure is pending.
    pub(crate) fn next_k(&mut self) -> u32 {
        if std::mem::take(&mut self.pending) {
            self.k = (self.k + 1).min(Self::MAX_K);
        }
        self.k
    }

    /// k returns to 0, and U_max is forgotten, once 10 bases passed since
    /// the last probation ended without a new suspicion (`quiet`: none
    /// pending, none running).
    pub(crate) fn decay(&mut self, quiet: bool, now: Instant) {
        if quiet
            && !self.pending
            && (self.k > 0 || self.u_max.is_some())
            && self.ended.is_some()
            && !self.recent(now)
        {
            self.k = 0;
            self.u_max = None;
        }
    }

    /// Whether the history no longer matters at `now`: k is 0, nothing is
    /// pending, no probation ended within 10 bases, and the path never had
    /// trouble.
    pub(crate) fn quiet(&self, now: Instant) -> bool {
        self.k == 0 && !self.pending && !self.trouble && !self.recent(now)
    }
}
