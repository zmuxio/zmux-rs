//! Connectivity-first attribution: failures committed while a session has no
//! usable pipe, and the member drops that led into that state, stay
//! provisional until the session reconnects. History and the recovery cadence
//! take them at once; ordinary cooldown never rises during the outage. Rounds
//! of the onset drops are withdrawn when it begins and later rounds deferred.
//! A success retracts everything; an end without one commits the deferred
//! rounds.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use super::{CacheOutcome, CarrierCache, Clock, CooldownEvent, Entry, Key, Point, decay};
use crate::driver::retry::{CooldownReason, Cooling, RecoveryCadence};

/// One session's provisional contributions, coalesced per key.
#[derive(Debug, Default)]
pub(in crate::driver) struct OutageJournal {
    keys: Vec<(Key, Undo)>,
    active: bool,
}

/// History weights are kept decayed to `anchor`. Cooling and recovery are
/// restored only while the key still holds the state this journal produced,
/// so a later fault committed by another session stays in force.
#[derive(Debug, Default)]
struct Undo {
    anchor: Option<Instant>,
    failure: f64,
    short: f64,
    late: f64,
    attempts: u64,
    cooling: Option<(Cooling<Point>, Option<u64>)>,
    recovery: Option<(RecoveryCadence, RecoveryCadence)>,
    rounds: Vec<CooldownReason>,
    /// At most one round per key: an outage stands for one failure.
    deferred: Option<CooldownReason>,
}

impl OutageJournal {
    fn undo(&mut self, key: &Key) -> &mut Undo {
        let index = self
            .keys
            .iter()
            .position(|(k, _)| k == key)
            .unwrap_or_else(|| {
                self.keys.push((key.clone(), Undo::default()));
                self.keys.len() - 1
            });
        &mut self.keys[index].1
    }

    pub(super) fn history(
        &mut self,
        key: &Key,
        outcome: CacheOutcome,
        weight: f64,
        now: Instant,
        half_life: std::time::Duration,
    ) {
        let undo = self.undo(key);
        if let Some(anchor) = undo.anchor {
            let factor = decay(now.saturating_duration_since(anchor), half_life);
            undo.failure *= factor;
            undo.short *= factor;
            undo.late *= factor;
        }
        undo.anchor = Some(now);
        match outcome {
            CacheOutcome::ShortDrop => undo.short += weight,
            CacheOutcome::LateDrop => undo.late += weight,
            _ => {
                undo.failure += weight;
                undo.attempts = undo.attempts.saturating_add(1);
            }
        }
    }

    /// During an outage a round is deferred instead of committed.
    pub(super) fn defers(&mut self, key: &Key, reason: CooldownReason) -> bool {
        if self.active {
            defer(&mut self.undo(key).deferred, reason);
        }
        self.active
    }

    /// Captures the cooling state before the first provisional round.
    pub(super) fn before_cool(&mut self, key: &Key, entry: &Entry) {
        let undo = self.undo(key);
        if undo.cooling.is_none() {
            undo.cooling = Some((entry.cooling.clone(), None));
        }
    }

    pub(super) fn after_cool(&mut self, key: &Key, entry: &Entry, reason: CooldownReason) {
        let undo = self.undo(key);
        undo.rounds.push(reason);
        if let Some((_, episode)) = &mut undo.cooling {
            *episode = entry.cooling.local.map(|local| local.episode);
        }
    }

    /// The outage began: withdraw the rounds of the onset drops.
    fn suspend(&mut self, cache: &CarrierCache) {
        self.active = true;
        let now = cache.owner_clock();
        let mut entries = cache.entries();
        for (key, undo) in &mut self.keys {
            let Some((prior, Some(episode))) = undo.cooling.take() else {
                continue;
            };
            let rounds = std::mem::take(&mut undo.rounds);
            if let Some(entry) = entries.get_mut(key)
                && entry.cooling.local.map(|local| local.episode) == Some(episode)
            {
                restore(cache, key, entry, prior, episode, now);
                for reason in rounds {
                    defer(&mut undo.deferred, reason);
                }
            }
        }
        drop(entries);
        cache.notify();
    }

    /// The outage ended without a success: commit the deferred rounds.
    fn commit(self, cache: &CarrierCache) {
        let now = cache.owner_clock();
        let mut entries = cache.entries();
        for (key, undo) in self.keys {
            if let Some(entry) = entries.get_mut(&key)
                && let Some(reason) = undo.deferred
            {
                cache.cool(&key, entry, reason, now, now.mono);
            }
        }
        drop(entries);
        cache.notify();
    }

    pub(super) fn recovery(&mut self, key: &Key, before: RecoveryCadence, after: RecoveryCadence) {
        let undo = self.undo(key);
        let prior = undo.recovery.map_or(before, |(prior, _)| prior);
        undo.recovery = Some((prior, after));
    }

    fn retract(self, cache: &CarrierCache) {
        if self.keys.is_empty() {
            return;
        }
        let now: Clock = cache.owner_clock();
        let half_life = cache.0.config.half_life;
        let mut entries = cache.entries();
        for (key, undo) in self.keys {
            let Some(entry) = entries.get_mut(&key) else {
                continue;
            };
            if let Some(anchor) = undo.anchor {
                let factor = decay(now.mono.saturating_duration_since(anchor), half_life);
                let h = &mut entry.history;
                h.decay(decay(h.point.age(now.mono), half_life));
                h.point = Point::new(now, now.mono);
                h.failure = (h.failure - undo.failure * factor).max(0.0);
                h.short_drop = (h.short_drop - undo.short * factor).max(0.0);
                h.late_drop = (h.late_drop - undo.late * factor).max(0.0);
                h.attempts = h.attempts.saturating_sub(undo.attempts);
            }
            if let Some((prior, Some(episode))) = undo.cooling
                && entry.cooling.local.map(|local| local.episode) == Some(episode)
            {
                restore(cache, &key, entry, prior, episode, now);
            }
            if let Some((prior, after)) = undo.recovery
                && entry.recovery == after
            {
                entry.recovery = prior;
            }
        }
        drop(entries);
        cache.notify();
    }
}

/// Keeps one deferred round per key, the most severe: a rejection jumps to
/// the maximum backoff and wins over other faults.
fn defer(slot: &mut Option<CooldownReason>, reason: CooldownReason) {
    if slot.is_none() || reason == CooldownReason::Rejected {
        *slot = Some(reason);
    }
}

fn restore(
    cache: &CarrierCache,
    key: &Key,
    entry: &mut Entry,
    prior: Cooling<Point>,
    episode: u64,
    now: Clock,
) {
    entry.cooling = prior;
    if cache.0.cooldown_events.receiver_count() != 0 {
        let _ = cache.0.cooldown_events.send(CooldownEvent::Retracted {
            key: key.into(),
            episode,
            level: entry.cooling.level.unsigned_abs(),
            retry_at: entry.cooling.active(now.mono),
            retracted_at: now.mono,
        });
    }
}

#[derive(Debug)]
struct OutageState {
    cache: CarrierCache,
    journal: OutageJournal,
}

impl Drop for OutageState {
    fn drop(&mut self) {
        let journal = std::mem::take(&mut self.journal);
        if journal.active {
            journal.commit(&self.cache);
        }
    }
}

/// The outage journal of one session binding, shared with its member
/// observers. Dropping the last handle makes the provisional failures final.
#[derive(Debug, Clone)]
pub(in crate::driver) struct OutageLog {
    cache: CarrierCache,
    state: Arc<Mutex<OutageState>>,
}

impl OutageLog {
    pub(in crate::driver) fn new(cache: CarrierCache) -> Self {
        Self {
            state: Arc::new(Mutex::new(OutageState {
                cache: cache.clone(),
                journal: OutageJournal::default(),
            })),
            cache,
        }
    }

    pub(in crate::driver) const fn cache(&self) -> &CarrierCache {
        &self.cache
    }

    /// Runs `f` with the journal that a failure committed now belongs to:
    /// drops always join it, attempt failures only during an outage.
    pub(in crate::driver) fn with<R>(
        &self,
        drop: bool,
        f: impl FnOnce(Option<&mut OutageJournal>) -> R,
    ) -> R {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if drop || state.journal.active {
            f(Some(&mut state.journal))
        } else {
            f(None)
        }
    }

    /// Records whether any attached pipe carries a direction. Regaining a
    /// pipe ends an outage as a success and also settles earlier drops.
    pub(in crate::driver) fn observe(&self, connected: bool) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if !connected {
            if !state.journal.active {
                state.journal.suspend(&self.cache);
            }
        } else if state.journal.active {
            std::mem::take(&mut state.journal).retract(&self.cache);
        }
    }

    /// A confirmed attempt or a pipe gain: retract during an outage,
    /// otherwise the drops before it become final.
    pub(in crate::driver) fn connected(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let journal = std::mem::take(&mut state.journal);
        if journal.active {
            journal.retract(&self.cache);
        }
    }

    /// Carries the journal to a successor binding on the same cache.
    pub(in crate::driver) fn adopt(&self, previous: &Self) {
        if !self.cache.shares_history(&previous.cache) {
            return;
        }
        let old = std::mem::take(
            &mut previous
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .journal,
        );
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .journal = old;
    }
}
