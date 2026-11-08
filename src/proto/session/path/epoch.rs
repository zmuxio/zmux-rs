//! Session epochs: the two-message exchange of SESSION_EPOCH,
//! the epoch a local join uses, the epochs and Locators the acceptor takes, and when a
//! carrier joined in an older epoch is to be replaced.
//!
//! `d` is the epoch this end last completed. The exchange targets d+1; O is the end that
//! offered and A the other. Both accept {d, d+1} once they committed d+1:
//!
//! ```text
//! O: Stable(d) -offer-> Offering -answer-> Switched (new joins use d+1)
//! A: Stable(d) -offer/answer-> Answered -answer acknowledged, or a join of phase d+1->
//!    Switched
//! Switched -R after the switch-> Stable(d+1): d, its join keys and Locators are deleted
//! ```
//!
//! A repeats its answer until a record that carried it is acknowledged, also after a join
//! switched it.
//!
//! An end offers only in Stable, so after it deleted d itself; the other end may keep d a
//! little longer, and an offer of d+2 ends its exchange first.

use std::time::{Duration, Instant};

use crate::proto::Error;
use crate::proto::frame::{EpochPhase, Frame, SessionEpoch};
use crate::proto::params::{Locator, Role};
use crate::proto::seal::{Group, GroupInitiator, Mode, Secret, derive_epoch_secret};
#[cfg(feature = "test-hooks")]
use crate::proto::session::PipeId;
use crate::proto::session::join::EpochKeys;
use crate::proto::session::output::Records;
use crate::proto::session::pipes::SentFrame;
use crate::proto::session::rtt::PROBE_INTERVAL;
use crate::proto::session::{CoreEvent, SessionCore, State};

const TYPE: u64 = 0x024e_93eb;

/// The default epoch period: an exchange starts after this long in Stable.
pub const DEFAULT_EPOCH_PERIOD: Duration = Duration::from_secs(3600);
/// The default number of joins after which an exchange starts.
pub const DEFAULT_EPOCH_JOINS: u64 = 1 << 16;
/// The upper bound of a join deadline.
pub const MAX_JOIN_DEADLINE: Duration = Duration::from_secs(60);
/// R: how long an end keeps the old epoch after it switched to the new one.
pub const EPOCH_RETENTION: Duration = MAX_JOIN_DEADLINE.saturating_mul(3);

/// When an endpoint starts an exchange on its own, and when it replaces carriers
/// (local policy). Every value is local: the peer neither sees
/// nor relies on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochPolicy {
    /// After this long in Stable; zero is the default of one hour, `None` never by time. A
    /// carrier lives at most twice as long before it is to be replaced by a new join.
    pub period: Option<Duration>,
    /// After this many joins of the session in the epoch; zero is the default of 2^16,
    /// `None` never by count.
    pub joins: Option<u64>,
    /// Once as soon as the first Sealed or Bound pipe exists, in a session whose secret
    /// comes from a TLS exporter or a pre-shared key.
    pub after_first_pipe: bool,
    /// Once after leaving a suspension, when Stable.
    pub after_resume: bool,
}

impl Default for EpochPolicy {
    fn default() -> Self {
        Self {
            period: Some(DEFAULT_EPOCH_PERIOD),
            joins: Some(DEFAULT_EPOCH_JOINS),
            after_first_pipe: true,
            after_resume: true,
        }
    }
}

impl EpochPolicy {
    /// The period in effect: zero is the default.
    fn period_in_effect(&self) -> Option<Duration> {
        self.period
            .map(|p| if p.is_zero() { DEFAULT_EPOCH_PERIOD } else { p })
    }

    /// The join count in effect: zero is the default.
    fn joins_in_effect(&self) -> Option<u64> {
        self.joins
            .map(|n| if n == 0 { DEFAULT_EPOCH_JOINS } else { n })
    }

    /// No exchange starts on its own; only `advance_epoch` and a forced advance do.
    pub const MANUAL: Self = Self {
        period: None,
        joins: None,
        after_first_pipe: false,
        after_resume: false,
    };
}

/// A frame this end owns and repeats: the bytes stay the same.
#[derive(Clone, Debug)]
struct Own {
    phase: EpochPhase,
    epoch: u64,
    share: Vec<u8>,
    locator: Vec<u8>,
}

impl Own {
    fn frame(&self) -> SessionEpoch<'_> {
        SessionEpoch {
            phase: self.phase,
            epoch: self.epoch,
            share: &self.share,
            locator: &self.locator,
            raw: &[],
        }
    }

    fn body(&self) -> Vec<u8> {
        self.frame().body()
    }
}

/// A forced advance (`force_epoch_advance`).
#[derive(Clone, Copy, Debug)]
struct Forced {
    /// The first epoch of new keys: carriers joined with an older one are replaced.
    target: u64,
    /// When this end started using `target`; replacements are due from then.
    ready: Option<Instant>,
    /// When the advance was asked for.
    at: Instant,
    /// The latest time of a replacement: until `ready`, a carrier that joined after `at`
    /// used the old epoch too, and replacing it again would not help.
    by: Instant,
}

enum St {
    Stable,
    /// O sent its offer and holds the private values.
    Offering {
        kex: GroupInitiator,
    },
    /// A committed d+1 and answered; new joins still use d.
    Answered,
    /// This end uses d+1 since `since`; d goes after R.
    Switched {
        since: Instant,
    },
}

impl St {
    fn name(&self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Offering { .. } => "offering",
            Self::Answered => "answered",
            Self::Switched { .. } => "switched",
        }
    }
}

/// The epoch state of a multipath session.
pub(in crate::proto::session) struct Epochs {
    d: u64,
    st: St,
    /// The frame being repeated, and when it last went on each pipe.
    own: Option<Own>,
    sent: Vec<(u64, Instant)>,
    /// This end's Locators by the epoch from which each is accepted, ascending.
    local: Vec<(u64, Vec<u8>)>,
    /// The peer's Locators by epoch, ascending.
    peer: Vec<(u64, Locator)>,
    /// The length of the instance identifier that opens every local Locator.
    instance: usize,
    /// An exchange is wanted as soon as this end may offer.
    wanted: bool,
    /// A forced advance: carriers of an epoch before its target are to be replaced.
    forced: Option<Forced>,
    stable_at: Instant,
    joins: u64,
    first_pipe_done: bool,
    /// Each attachment's epoch and the time it joined.
    joined: Vec<(u64, u64, Instant)>,
}

impl std::fmt::Debug for Epochs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Epochs")
            .field("d", &self.d)
            .field("state", &self.st.name())
            .finish_non_exhaustive()
    }
}

impl Epochs {
    pub(in crate::proto::session) fn new(
        local: &[u8],
        peer: Locator,
        instance: usize,
        now: Instant,
    ) -> Self {
        Self {
            d: 0,
            st: St::Stable,
            own: None,
            sent: Vec::new(),
            local: vec![(0, local.to_vec())],
            peer: vec![(0, peer)],
            instance: instance.min(local.len()),
            wanted: false,
            forced: None,
            stable_at: now,
            joins: 0,
            first_pipe_done: false,
            joined: vec![(0, 0, now)],
        }
    }

    /// The epoch new local joins use.
    fn use_epoch(&self) -> u64 {
        match self.st {
            St::Switched { .. } => self.d + 1,
            _ => self.d,
        }
    }

    /// The epochs accepted as acceptor, ascending.
    fn accepted(&self) -> Vec<u64> {
        match self.st {
            St::Stable | St::Offering { .. } => vec![self.d],
            St::Answered | St::Switched { .. } => vec![self.d, self.d + 1],
        }
    }

    fn set_own(&mut self, own: Option<Own>) {
        self.own = own;
        self.sent.clear();
    }
}

impl SessionCore {
    fn epochs(&self) -> Option<&Epochs> {
        self.mp.as_deref().map(|m| &m.epochs)
    }

    fn epochs_mut(&mut self) -> &mut Epochs {
        &mut self.mp_mut().epochs
    }

    /// The epoch new local joins use, and the peer's Locator for it.
    pub(in crate::proto::session) fn join_epoch(&self) -> (u64, Locator) {
        let ep = &self.mp().epochs;
        let e = ep.use_epoch();
        let locator = ep
            .peer
            .iter()
            .rev()
            .find(|(from, _)| *from <= e)
            .map_or_else(|| self.mp().peer_locator.clone(), |(_, l)| l.clone());
        (e, locator)
    }

    /// The epochs this end accepts as acceptor, ascending.
    pub(in crate::proto::session) fn accepted_epochs(&self) -> Vec<u64> {
        self.epochs().map_or_else(|| vec![0], Epochs::accepted)
    }

    /// The epoch new local joins use; `None` outside a multipath session.
    pub fn epoch(&self) -> Option<u64> {
        self.mp.as_ref().map(|_| self.join_epoch().0)
    }

    /// The epoch this end last completed: its older epochs are deleted.
    pub fn completed_epoch(&self) -> u64 {
        self.epochs().map_or(0, |e| e.d)
    }

    /// The Session Locators this end accepts now: the current one, and during an exchange
    /// also the next. A listener finds the session by any of them.
    pub fn accepted_locators(&self) -> Vec<Vec<u8>> {
        match self.epochs() {
            Some(e) => e.local.iter().map(|(_, l)| l.clone()).collect(),
            None => {
                let l = self.local_locator();
                if l.is_empty() {
                    Vec::new()
                } else {
                    vec![l.to_vec()]
                }
            }
        }
    }

    /// Whether a Hello's Locator names this session.
    pub fn accepts_locator(&self, locator: &[u8]) -> bool {
        match self.epochs() {
            Some(e) => e.local.iter().any(|(_, l)| l == locator),
            None => !locator.is_empty() && self.local_locator() == locator,
        }
    }

    /// The length of the instance identifier at the start of this session's Locators, which
    /// every new Locator keeps; the rest is random. A listener sets it with the Locator.
    pub fn set_locator_instance(&mut self, len: usize) {
        self.locator_instance = len;
        if let Some(mp) = self.mp.as_deref_mut() {
            mp.epochs.instance = len.min(self.locator_instance);
        }
    }

    /// Starts an epoch exchange as soon as this end may offer.
    /// `Err` outside a multipath session.
    pub fn advance_epoch(&mut self, now: Instant) -> Result<(), crate::proto::session::PipeError> {
        self.tick(now);
        if self.mp.is_none() {
            return Err(crate::proto::session::PipeError::NotNegotiated);
        }
        self.epochs_mut().wanted = true;
        self.epoch_progress(now);
        Ok(())
    }

    /// For a suspected leak of a session-level secret: advances as soon as this end may
    /// offer, and every carrier joined with an older epoch is to be replaced by a new join
    /// once the new epoch is in use, within `deadline`
    /// ([`PipeStats::replace_by`](crate::proto::session::PipeStats::replace_by); a
    /// `PipePool` or a redial hook replaces it, else the host).
    /// A revoked peer identity closes the session instead.
    pub fn force_epoch_advance(
        &mut self,
        deadline: Duration,
        now: Instant,
    ) -> Result<(), crate::proto::session::PipeError> {
        self.tick(now);
        if self.mp.is_none() {
            return Err(crate::proto::session::PipeError::NotNegotiated);
        }
        let ep = self.epochs_mut();
        ep.wanted = true;
        // An exchange already committed counts as begun before the advance: the target is
        // the one after it.
        let target = match ep.st {
            St::Stable | St::Offering { .. } => ep.d + 1,
            St::Answered | St::Switched { .. } => ep.d + 2,
        };
        ep.forced = Some(Forced {
            target,
            ready: None,
            at: now,
            by: now.checked_add(deadline).unwrap_or(now),
        });
        self.epoch_progress(now);
        Ok(())
    }

    /// Counts a join of the session in the current epoch, for the policy.
    pub(in crate::proto::session) fn epoch_note_join(&mut self) {
        if let Some(mp) = self.mp.as_deref_mut() {
            mp.epochs.joins += 1;
        }
    }

    /// Notes the epoch and time of a new attachment.
    pub(in crate::proto::session) fn epoch_attached(&mut self, id: u64, epoch: u64, now: Instant) {
        let live: Vec<u64> = self.atts.iter().map(|a| a.id()).collect();
        if let Some(mp) = self.mp.as_deref_mut() {
            // Retired attachments leave the list.
            mp.epochs
                .joined
                .retain(|(p, _, _)| *p != id && live.contains(p));
            mp.epochs.joined.push((id, epoch, now));
        }
    }

    /// When the carrier of attachment `id` is to be replaced by a new join: twice the
    /// epoch period after it joined, and, when it joined with an epoch older than a forced
    /// advance's, as soon as this end uses the new epoch and at the latest by the
    /// deadline. `None`: not by the epoch policy.
    pub(in crate::proto::session) fn pipe_replace_by(&self, id: u64) -> Option<Instant> {
        let ep = self.epochs()?;
        let &(_, epoch, at) = ep.joined.iter().find(|(p, _, _)| *p == id)?;
        let age = self
            .config
            .epoch_policy
            .period_in_effect()
            .and_then(|p| at.checked_add(p.saturating_mul(2)));
        let forced = ep
            .forced
            .filter(|f| epoch < f.target)
            .and_then(|f| match f.ready {
                Some(r) => Some(r.min(f.by)),
                None => (at <= f.at).then_some(f.by),
            });
        match (age, forced) {
            (Some(a), Some(f)) => Some(a.min(f)),
            (a, f) => a.or(f),
        }
    }

    /// The epoch attachment `id` joined with.
    pub(in crate::proto::session) fn pipe_epoch(&self, id: u64) -> Option<u64> {
        let ep = self.epochs()?;
        ep.joined
            .iter()
            .find(|(p, _, _)| *p == id)
            .map(|(_, e, _)| *e)
    }

    /// A Sealed or Bound pipe exists now; with a secret from a TLS exporter or a pre-shared
    /// key, that starts the first exchange.
    pub(in crate::proto::session) fn epoch_first_pipe(&mut self) {
        let policy = self.config.epoch_policy;
        let from_establish = self.first_pipe_mode.is_some();
        let Some(mp) = self.mp.as_deref_mut() else {
            return;
        };
        if mp.epochs.first_pipe_done {
            return;
        }
        mp.epochs.first_pipe_done = true;
        if policy.after_first_pipe && !from_establish {
            mp.epochs.wanted = true;
        }
    }

    /// Leaving a suspension: once, when Stable.
    pub(in crate::proto::session) fn epoch_after_resume(&mut self, now: Instant) {
        if self.config.epoch_policy.after_resume
            && let Some(mp) = self.mp.as_deref_mut()
            && matches!(mp.epochs.st, St::Stable)
        {
            mp.epochs.wanted = true;
            self.epoch_progress(now);
        }
    }

    /// The record mode of pipe `id`, `None` for an Unmanaged first pipe.
    fn pipe_mode(&self, id: u64) -> Option<Mode> {
        if id == 0 {
            return self.first_pipe_mode;
        }
        self.att(id).and_then(|a| a.mode())
    }

    /// Whether SESSION_EPOCH may go on, or come from, pipe `id`.
    fn epoch_pipe(&self, id: u64) -> bool {
        matches!(self.pipe_mode(id), Some(Mode::Sealed | Mode::Bound))
    }

    /// Moves the exchange on by time: the old epoch's deletion, a wanted offer, the
    /// policy's own advances.
    pub(in crate::proto::session) fn epoch_progress(&mut self, now: Instant) {
        if self.state >= State::Closing || self.state == State::Establishing {
            return;
        }
        let Some(mp) = self.mp.as_deref() else {
            return;
        };
        if mp.keys.ready().is_none() {
            return;
        }
        match mp.epochs.st {
            St::Switched { since } if now.saturating_duration_since(since) >= EPOCH_RETENTION => {
                self.enter_stable(now);
            }
            St::Stable => {
                let policy = self.config.epoch_policy;
                let ep = &self.mp().epochs;
                let due = ep.wanted
                    || policy
                        .period_in_effect()
                        .is_some_and(|p| now.saturating_duration_since(ep.stable_at) >= p)
                    || policy.joins_in_effect().is_some_and(|n| ep.joins >= n);
                if due && self.atts.iter().any(|a| self.epoch_pipe(a.id())) {
                    self.send_offer();
                }
            }
            _ => {}
        }
    }

    fn send_offer(&mut self) {
        let Some(group) = self.epoch_group() else {
            return;
        };
        let Ok((share, kex)) = group.initiate() else {
            return;
        };
        let d = self.mp().epochs.d;
        let locator = self.new_locator(d + 1);
        let offer = Own {
            phase: EpochPhase::Offer,
            epoch: d + 1,
            share,
            locator,
        };
        let ep = self.epochs_mut();
        ep.wanted = false;
        ep.set_own(Some(offer));
        ep.st = St::Offering { kex };
    }

    /// The usable Group of highest priority.
    fn epoch_group(&self) -> Option<&'static Group> {
        let keys = self.mp().keys.ready()?;
        Group::highest(&keys.group_values())
    }

    /// A new local Locator for epoch `e`: the test hook's `prefix ‖ e`, else the instance
    /// identifier followed by random bytes, at least 8 of them.
    fn new_locator(&self, e: u64) -> Vec<u8> {
        if let Some(prefix) = &self.config.hooks.epoch_locator_prefix {
            let mut l = prefix.clone();
            l.extend_from_slice(e.to_string().as_bytes());
            return l;
        }
        let ep = &self.mp().epochs;
        let current = &ep.local.last().map(|(_, l)| l.clone()).unwrap_or_default();
        if current.is_empty() {
            // A session that accepts no joins keeps accepting none.
            return Vec::new();
        }
        let head = &current[..ep.instance.min(current.len())];
        let len = current.len().max(head.len() + 8).max(16);
        let mut l = head.to_vec();
        let mut rest = vec![0; len - head.len()];
        if crate::proto::seal::fill_random(&mut rest).is_err() {
            return Vec::new();
        }
        l.extend_from_slice(&rest);
        l
    }

    fn session_probe_interval(&self) -> Duration {
        self.config.probe_interval().unwrap_or(PROBE_INTERVAL)
    }

    /// The probe interval of pipe `id`, by which a frame repeats.
    fn pipe_probe_interval(&self, id: u64) -> Duration {
        let own = self
            .out_ref(id)
            .and_then(|o| o.probe_settings().0)
            .map(|p| p.duration());
        match own {
            Some(d) => d.unwrap_or(PROBE_INTERVAL),
            None => self.session_probe_interval(),
        }
    }

    /// Commits epoch `d + 1` from the two bodies and the shared secrets: both epochs are
    /// accepted from here on.
    fn commit(
        &mut self,
        offer_body: &[u8],
        answer_body: &[u8],
        secrets: &[Secret],
        local_locator: &[u8],
        peer_locator: &[u8],
    ) -> Result<(), Error> {
        let d = self.mp().epochs.d;
        let keys =
            self.mp().keys.ready().ok_or_else(|| {
                Error::protocol_violation(TYPE, "SESSION_EPOCH without join keys")
            })?;
        let old = keys
            .epoch(d)
            .ok_or_else(|| Error::protocol_violation(TYPE, "epoch secret missing"))?;
        let (_, secret) = derive_epoch_secret(
            &old.secret,
            d + 1,
            &keys.session_crypto,
            offer_body,
            answer_body,
            secrets,
        )
        .map_err(|_| Error::protocol_violation(TYPE, "epoch derivation"))?;
        let next = EpochKeys::derive(d + 1, secret, &keys.suites, &keys.session_crypto);
        let mp = self.mp_mut();
        if let Some(keys) = mp.keys.ready_mut() {
            keys.epochs.retain(|k| k.epoch <= d);
            keys.epochs.push(next);
        }
        let locators = !local_locator.is_empty();
        if locators {
            mp.epochs.local.push((d + 1, local_locator.to_vec()));
        }
        self.push_event(CoreEvent::EpochCommitted(d + 1));
        if locators {
            self.push_event(CoreEvent::LocatorsChanged);
        }
        if let Some(l) = Locator::new(peer_locator).filter(|_| !peer_locator.is_empty()) {
            self.mp_mut().epochs.peer.push((d + 1, l));
        }
        Ok(())
    }

    /// New joins use d+1 from now; d goes after R.
    /// An answer not acknowledged yet keeps repeating: only `epoch_answer_acked` ends it.
    fn switch(&mut self, now: Instant) {
        let ep = self.epochs_mut();
        ep.st = St::Switched { since: now };
        let e = ep.d + 1;
        if let Some(f) = ep
            .forced
            .as_mut()
            .filter(|f| f.ready.is_none() && e >= f.target)
        {
            f.ready = Some(now);
        }
    }

    /// R passed: deletes epoch d, then moves on to an offer the policy wants.
    fn enter_stable(&mut self, now: Instant) {
        self.delete_previous(now);
        self.epoch_progress(now);
    }

    /// Deletes epoch d: its secret, its join keys and its Locators; this end completed
    /// d+1 and is Stable.
    fn delete_previous(&mut self, now: Instant) {
        let mp = self.mp_mut();
        let d = mp.epochs.d + 1;
        if let Some(keys) = mp.keys.ready_mut() {
            keys.epochs.retain(|k| k.epoch >= d);
        }
        let ep = &mut mp.epochs;
        ep.d = d;
        ep.st = St::Stable;
        ep.set_own(None);
        ep.stable_at = now;
        ep.joins = 0;
        let before = ep.local.len();
        if let Some(i) = ep.local.iter().rposition(|(from, _)| *from <= d) {
            ep.local.drain(..i);
        }
        if let Some(i) = ep.peer.iter().rposition(|(from, _)| *from <= d) {
            ep.peer.drain(..i);
        }
        if ep.local.len() != before {
            self.push_event(CoreEvent::LocatorsChanged);
        }
        self.push_event(CoreEvent::EpochDeleted(d - 1));
    }

    /// A received SESSION_EPOCH on the pipe being read.
    pub(in crate::proto::session) fn on_session_epoch(
        &mut self,
        f: SessionEpoch<'_>,
        now: Instant,
    ) -> Result<(), Error> {
        let pipe = self.rx;
        if !self.epoch_pipe(pipe) {
            return Err(Error::protocol_violation(
                TYPE,
                "SESSION_EPOCH on a pipe that is neither Sealed nor Bound",
            ));
        }
        // Without the session secret yet (join pending), ignored.
        if self.mp().keys.ready().is_none() {
            return Ok(());
        }
        let d = self.mp().epochs.d;
        let keeps_previous = matches!(self.mp().epochs.st, St::Answered | St::Switched { .. });
        match f.epoch.checked_sub(d) {
            // An offer is at most d.
            None | Some(0) => return Ok(()),
            Some(1) => {}
            Some(2) if f.phase == EpochPhase::Offer && keeps_previous => {
                self.end_exchange_for_next(now);
                return self.on_offer(f);
            }
            Some(_) => {
                return Err(Error::protocol_violation(
                    TYPE,
                    "SESSION_EPOCH beyond the next epoch",
                ));
            }
        }
        let initiator = self.role == Role::Initiator;
        match (&self.mp().epochs.st, f.phase) {
            (St::Stable, EpochPhase::Offer) => self.on_offer(f),
            (St::Stable, EpochPhase::Answer) => Err(Error::protocol_violation(
                TYPE,
                "SESSION_EPOCH answer without an offer",
            )),
            (St::Offering { .. }, EpochPhase::Offer) => {
                if initiator {
                    return Ok(());
                }
                // Crossed offers: the session's responder yields, its own offer is dropped.
                let ep = self.epochs_mut();
                ep.st = St::Stable;
                ep.set_own(None);
                self.on_offer(f)
            }
            (St::Offering { .. }, EpochPhase::Answer) => self.on_answer(f, now),
            // d+1 is committed, so every frame of it is a copy.
            (St::Answered | St::Switched { .. }, _) => Ok(()),
        }
    }

    /// The peer offers d+2 only after it deleted d, so this end, which still keeps
    /// d, ends its exchange first: it uses d+1 and deletes d, and is Stable(d+1).
    fn end_exchange_for_next(&mut self, now: Instant) {
        if matches!(self.mp().epochs.st, St::Answered) {
            self.switch(now);
        }
        self.delete_previous(now);
    }

    fn check_share(&self, group: &Group, share: &[u8], initiator: bool) -> Result<(), Error> {
        if share.len() != group.share_len(initiator) {
            return Err(Error::protocol_violation(
                TYPE,
                "SESSION_EPOCH share of the wrong length",
            ));
        }
        Ok(())
    }

    /// Stable(d) answers offer(d+1): it commits d+1 and keeps using d until the answer is
    /// acknowledged or a join of the new phase arrives.
    fn on_offer(&mut self, f: SessionEpoch<'_>) -> Result<(), Error> {
        let group = self
            .epoch_group()
            .ok_or_else(|| Error::protocol_violation(TYPE, "no Group"))?;
        self.check_share(group, f.share, true)?;
        let (share, secrets) = group
            .respond(f.share)
            .map_err(|_| Error::protocol_violation(TYPE, "SESSION_EPOCH share refused"))?;
        let d = self.mp().epochs.d;
        let locator = self.new_locator(d + 1);
        let answer = Own {
            phase: EpochPhase::Answer,
            epoch: d + 1,
            share,
            locator: locator.clone(),
        };
        self.commit(
            &f.body(),
            &answer.body(),
            secrets.as_slice(),
            &locator,
            f.locator,
        )?;
        let ep = self.epochs_mut();
        ep.st = St::Answered;
        ep.set_own(Some(answer));
        Ok(())
    }

    /// Offering receives answer(d+1): commits d+1 and switches at once.
    fn on_answer(&mut self, f: SessionEpoch<'_>, now: Instant) -> Result<(), Error> {
        let St::Offering { kex } = std::mem::replace(&mut self.epochs_mut().st, St::Stable) else {
            return Ok(());
        };
        let Some(offer) = self.mp().epochs.own.clone() else {
            return Ok(());
        };
        self.check_share(kex.group(), f.share, false)?;
        let secrets = kex
            .finish(f.share)
            .map_err(|_| Error::protocol_violation(TYPE, "SESSION_EPOCH share refused"))?;
        self.commit(
            &offer.body(),
            &f.body(),
            secrets.as_slice(),
            &offer.locator,
            f.locator,
        )?;
        self.switch(now);
        self.epochs_mut().set_own(None);
        Ok(())
    }

    /// The record that carried this end's answer of `epoch` was acknowledged.
    /// It switches an answering end, and ends the repeats of the answer also when a join
    /// switched it first.
    pub(in crate::proto::session) fn epoch_answer_acked(&mut self, epoch: u64, now: Instant) {
        let Some(mp) = self.mp.as_deref() else {
            return;
        };
        let ep = &mp.epochs;
        if ep.d + 1 != epoch {
            return;
        }
        let answering = matches!(ep.st, St::Answered);
        let repeating = ep
            .own
            .as_ref()
            .is_some_and(|o| o.phase == EpochPhase::Answer && o.epoch == epoch);
        if answering {
            self.switch(now);
        }
        if repeating {
            self.epochs_mut().set_own(None);
        }
    }

    /// A Hello of epoch `epoch` verified: the peer uses it, so an answering end switches;
    /// its answer repeats until a record that carried it is acknowledged.
    pub(in crate::proto::session) fn epoch_peer_joined(&mut self, epoch: u64, now: Instant) {
        if let Some(mp) = self.mp.as_deref()
            && matches!(mp.epochs.st, St::Answered)
            && mp.epochs.d + 1 == epoch
        {
            self.switch(now);
        }
    }

    /// Whether pipe `id` owes an epoch frame now.
    pub(in crate::proto::session) fn epoch_owed(&self, id: u64, now: Instant) -> bool {
        let Some(ep) = self.epochs() else {
            return false;
        };
        if ep.own.is_none() || !self.epoch_pipe(id) {
            return false;
        }
        match ep.sent.iter().find(|(p, _)| *p == id) {
            None => true,
            Some((_, at)) => now.saturating_duration_since(*at) >= self.pipe_probe_interval(id),
        }
    }

    /// The next time the exchange moves on by itself: a repeat, the deletion of the old
    /// epoch, an offer the policy holds back.
    pub(in crate::proto::session) fn epoch_deadline(&self) -> Option<Instant> {
        let ep = self.epochs()?;
        let mut next: Option<Instant> = None;
        let mut at = |t: Option<Instant>| {
            if let Some(t) = t {
                next = Some(next.map_or(t, |n| n.min(t)));
            }
        };
        if ep.own.is_some() {
            for &(p, sent) in &ep.sent {
                at(sent.checked_add(self.pipe_probe_interval(p)));
            }
        }
        match ep.st {
            St::Switched { since } => at(since.checked_add(EPOCH_RETENTION)),
            St::Stable => {
                if let Some(p) = self.config.epoch_policy.period_in_effect() {
                    at(ep.stable_at.checked_add(p));
                }
            }
            _ => {}
        }
        next
    }

    /// Writes the epoch frame pipe `id` owes; `false` when the record is full.
    pub(in crate::proto::session) fn write_epoch(
        &mut self,
        id: u64,
        w: &mut Records<'_>,
        now: Instant,
    ) -> bool {
        if !self.epoch_owed(id, now) {
            return true;
        }
        let Some(own) = self.mp().epochs.own.clone() else {
            return true;
        };
        if !w.try_frame(&Frame::SessionEpoch(own.frame())) {
            return false;
        }
        self.note_activity(w);
        if own.phase == EpochPhase::Answer {
            self.log(w, SentFrame::EpochAnswer { epoch: own.epoch });
        }
        let ep = self.epochs_mut();
        ep.sent.retain(|(p, _)| *p != id);
        ep.sent.push((id, now));
        true
    }

    /// The state of the exchange, for tests.
    #[cfg(feature = "test-hooks")]
    pub fn epoch_state(&self) -> Option<(u64, &'static str)> {
        self.epochs().map(|e| (e.d, e.st.name()))
    }

    /// The pipe IDs whose carriers joined in epoch `e`, for tests.
    #[cfg(feature = "test-hooks")]
    pub fn pipes_of_epoch(&self, e: u64) -> Vec<PipeId> {
        self.epochs().map_or_else(Vec::new, |ep| {
            ep.joined
                .iter()
                .filter(|(_, x, _)| *x == e)
                .map(|(p, _, _)| PipeId(*p))
                .collect()
        })
    }
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    /// Zero is the default, `None` never, any other value itself.
    #[test]
    fn zero_period_and_joins_are_the_defaults() {
        let zero = EpochPolicy {
            period: Some(Duration::ZERO),
            joins: Some(0),
            ..EpochPolicy::default()
        };
        assert_eq!(zero.period_in_effect(), Some(DEFAULT_EPOCH_PERIOD));
        assert_eq!(zero.joins_in_effect(), Some(DEFAULT_EPOCH_JOINS));
        assert_eq!(EpochPolicy::MANUAL.period_in_effect(), None);
        assert_eq!(EpochPolicy::MANUAL.joins_in_effect(), None);
        let set = EpochPolicy {
            period: Some(Duration::from_secs(5)),
            joins: Some(3),
            ..EpochPolicy::MANUAL
        };
        assert_eq!(set.period_in_effect(), Some(Duration::from_secs(5)));
        assert_eq!(set.joins_in_effect(), Some(3));
    }
}
