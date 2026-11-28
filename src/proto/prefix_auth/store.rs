use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::future::Future;
use std::io;
use std::num::NonZeroU64;
use std::ops::RangeInclusive;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use super::InvalidPrefixAuth;
use crate::ClockDomain;

/// Immutable slot parameters for an admission domain. Widen a live window only
/// with complete replay history for the new window or after retiring its tickets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixWindow {
    pub(super) seconds: NonZeroU64,
    pub(super) skew: u32,
}

impl PrefixWindow {
    /// Configures whole seconds per slot, tolerance and a local upper bound.
    ///
    /// # Errors
    ///
    /// The slot duration must be positive and the tolerance at most the limit.
    pub fn new(seconds: u64, skew: u32, limit: u32) -> Result<Self, InvalidPrefixAuth> {
        let seconds = NonZeroU64::new(seconds).ok_or(InvalidPrefixAuth("zero slot length"))?;
        if skew > limit {
            return Err(InvalidPrefixAuth("skew exceeds local limit"));
        }
        Ok(Self { seconds, skew })
    }

    /// Seconds in a slot.
    #[must_use]
    pub const fn slot_seconds(self) -> u64 {
        self.seconds.get()
    }

    /// Number of slots on either side of the verifier's current slot.
    #[must_use]
    pub const fn skew(self) -> u32 {
        self.skew
    }

    pub(super) fn slots(self, current: u64) -> RangeInclusive<u64> {
        let skew = u64::from(self.skew);
        current.saturating_sub(skew)..=current.saturating_add(skew)
    }
}

/// An outer key with its inclusive issue-slot interval.
#[derive(Clone, Debug)]
pub struct PrefixGeneration {
    pub(super) key: Arc<super::Key>,
    slots: RangeInclusive<u64>,
}

impl PrefixGeneration {
    /// Takes a dedicated random outer key. At cutover U the old interval ends
    /// at U-1 and the new interval starts at U.
    #[must_use]
    pub fn new(key: [u8; 32], slots: RangeInclusive<u64>) -> Self {
        Self {
            key: super::Key::shared(key),
            slots,
        }
    }

    pub(super) fn first(&self) -> u64 {
        *self.slots.start()
    }

    pub(super) fn contains(&self, slot: u64) -> bool {
        self.slots.contains(&slot)
    }
}

/// The versioned snapshot cached locally by verifiers.
#[derive(Clone, Debug)]
pub struct PrefixSchedule {
    version: u64,
    generations: Vec<PrefixGeneration>,
}

impl PrefixSchedule {
    /// Builds a schedule. Change the version on every update to the authority.
    ///
    /// # Errors
    ///
    /// Issue intervals must be nonempty and disjoint.
    pub fn new(
        version: u64,
        mut generations: Vec<PrefixGeneration>,
    ) -> Result<Self, InvalidPrefixAuth> {
        generations.sort_unstable_by_key(PrefixGeneration::first);
        if generations.iter().any(|g| g.slots.is_empty())
            || generations
                .windows(2)
                .any(|pair| pair[0].slots.end() >= pair[1].slots.start())
        {
            return Err(InvalidPrefixAuth(
                "invalid or overlapping generation intervals",
            ));
        }
        Ok(Self {
            version,
            generations,
        })
    }

    /// The authority's revision of this schedule.
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }

    pub(super) fn eligible(&self, slots: &RangeInclusive<u64>) -> &[PrefixGeneration] {
        let start = self
            .generations
            .partition_point(|g| g.slots.end() < slots.start());
        let end = self
            .generations
            .partition_point(|g| g.slots.start() <= slots.end());
        &self.generations[start..end]
    }
}

/// A ticket record at the authority. Its version identifies immutable
/// credentials, lifetime and usage policy for this ID.
#[derive(Clone, Debug)]
pub struct PrefixTicket {
    pub(super) id: [u8; 16],
    pub(super) key: Arc<super::Key>,
    pub(super) version: u64,
    pub(super) slots: RangeInclusive<u64>,
    single_use: bool,
}

impl PrefixTicket {
    /// Takes a dedicated random key for a new, independently random ID.
    /// The lifetime is an inclusive interval of verifier UTC slots.
    #[must_use]
    pub fn new(
        id: [u8; 16],
        key: [u8; 32],
        version: u64,
        slots: RangeInclusive<u64>,
        single_use: bool,
    ) -> Self {
        Self {
            id,
            key: super::Key::shared(key),
            version,
            slots,
            single_use,
        }
    }
}

/// A conditional redemption. All fields apply to one atomic commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefixClaim {
    /// Ticket ID.
    pub id: [u8; 16],
    /// Presentation nonce, shared across generation and carrier types.
    pub nonce: [u8; 16],
    /// Stable identifier of this operation, including when its receipt is lost.
    pub commit_id: [u8; 16],
    /// Immutable ticket version read at lookup.
    pub version: u64,
    /// Schedule revision read from the local cache.
    pub schedule: u64,
    /// First issue slot of the matching generation.
    pub generation: u64,
    /// Slot matching the ticket MAC.
    pub issue_slot: u64,
    /// Effective slot used for outer authentication and slot trials.
    pub checked_slot: u64,
    /// Verifier UTC slot sampled immediately before submitting the claim.
    pub local_slot: u64,
}

/// A monotonic deadline and cancellation for a storage operation.
#[derive(Clone, Debug)]
pub struct PrefixDeadline {
    pub(super) clock: ClockDomain,
    pub(super) at: Option<Instant>,
    cancelled: Arc<AtomicBool>,
}

impl PrefixDeadline {
    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn new(clock: ClockDomain, at: Option<Instant>) -> Self {
        Self {
            clock,
            at,
            cancelled: Arc::default(),
        }
    }

    /// Absolute deadline in the verifier's clock domain.
    #[must_use]
    pub const fn deadline(&self) -> Option<Instant> {
        self.at
    }

    /// True once the deadline passes or the attempt is dropped.
    #[must_use]
    pub fn ended(&self) -> bool {
        self.cancelled.load(Ordering::Acquire) || self.at.is_some_and(|at| self.clock.now() >= at)
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }
}

/// An asynchronously computed result from the admission authority.
pub type PrefixStoreFuture<'a, T> = Pin<Box<dyn Future<Output = io::Result<T>> + Send + 'a>>;

/// Linearizable storage for a single admission domain. Share it across every
/// verifier of the domain. A durable implementation restores its schedule,
/// tickets, rollback floor and all live claims together. Refuse whenever
/// freshness cannot be established.
pub trait PrefixStore: Send + Sync + 'static {
    /// Immutable parameters for this domain.
    fn window(&self) -> PrefixWindow;

    /// A locally cached schedule and floor lower bound. Publish updates
    /// independently of presentations. This call must perform no remote I/O.
    fn local_schedule(&self) -> (Arc<PrefixSchedule>, u64);

    /// Reads the authoritative rollback floor after a unique outer MAC match.
    fn floor(&self, attempt: PrefixDeadline) -> PrefixStoreFuture<'_, u64>;

    /// Looks up an immutable version without mutating the authority.
    fn lookup(
        &self,
        attempt: PrefixDeadline,
        id: [u8; 16],
    ) -> PrefixStoreFuture<'_, Option<PrefixTicket>>;

    /// Atomically checks the deadline, effective slot, schedule revision,
    /// generation, ticket version and both claims. If the effective slot
    /// changed from the checked slot, refuse or prove the eligible generation
    /// set is identical before accepting. Acceptance records the nonce and
    /// consumes a single-use ticket in the same transaction that advances the
    /// floor to the effective slot. Expiry also advances that floor atomically.
    /// Keep nonce claims through issue slot plus skew and consumption through
    /// ticket expiry.
    fn claim(&self, attempt: PrefixDeadline, claim: PrefixClaim) -> PrefixStoreFuture<'_, bool>;

    /// Looks up the outcome of the exact original operation. This uses an
    /// independent short deadline and never redeems or reverses a claim.
    /// A single-use ticket may have been consumed without admitting the
    /// carrier if the receipt was lost or the original attempt ended. Return
    /// an error if the authority cannot establish the original outcome.
    fn resolve(&self, attempt: PrefixDeadline, claim: PrefixClaim) -> PrefixStoreFuture<'_, bool>;
}

type Nonce = ([u8; 16], [u8; 16]);

struct Authority {
    floor: u64,
    tickets: HashMap<[u8; 16], TicketState>,
    claims: HashMap<Nonce, [u8; 16]>,
    expiry: BinaryHeap<Reverse<(u64, Nonce)>>,
    ticket_expiry: BinaryHeap<Reverse<(u64, [u8; 16])>>,
}

enum TicketState {
    Live(PrefixTicket),
    Retired(Option<([u8; 16], [u8; 16])>),
}

/// In-memory authority for a single process. After state loss, retire the old
/// credentials or restore a durable authority before taking presentations.
pub struct MemoryPrefixStore {
    window: PrefixWindow,
    capacity: usize,
    authority: Mutex<Authority>,
    cache: RwLock<Arc<PrefixSchedule>>,
    floor_hint: AtomicU64,
}

impl std::fmt::Debug for MemoryPrefixStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryPrefixStore")
            .field("window", &self.window)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

impl MemoryPrefixStore {
    /// Creates an authority. Capacity separately bounds live nonce claims and
    /// all issued or revoked IDs, including tombstones. Zero selects 65536.
    /// The ID capacity is a lifetime quota for this in-process authority:
    /// expiration, redemption and revocation never free an ID for reuse.
    ///
    /// # Errors
    ///
    /// Generation issue intervals must be nonempty and disjoint.
    pub fn new(
        window: PrefixWindow,
        generations: Vec<PrefixGeneration>,
        capacity: usize,
    ) -> Result<Self, InvalidPrefixAuth> {
        Ok(Self {
            window,
            capacity: if capacity == 0 { 1 << 16 } else { capacity },
            authority: Mutex::new(Authority {
                floor: 0,
                tickets: HashMap::new(),
                claims: HashMap::new(),
                expiry: BinaryHeap::new(),
                ticket_expiry: BinaryHeap::new(),
            }),
            cache: RwLock::new(Arc::new(PrefixSchedule::new(1, generations)?)),
            floor_hint: AtomicU64::new(0),
        })
    }

    /// Publishes a replacement schedule, invalidating outstanding claims
    /// checked with the previous version. Remove a generation to revoke it.
    ///
    /// # Errors
    ///
    /// The intervals must be valid and a new schedule revision representable.
    pub fn set_generations(
        &self,
        generations: Vec<PrefixGeneration>,
    ) -> Result<(), InvalidPrefixAuth> {
        let mut schedule = PrefixSchedule::new(0, generations)?;
        let _authority = lock(&self.authority);
        let mut cache = self
            .cache
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        schedule.version = cache
            .version
            .checked_add(1)
            .ok_or(InvalidPrefixAuth("schedule version exhausted"))?;
        *cache = Arc::new(schedule);
        Ok(())
    }

    /// Installs a fresh ID. A previously revoked ID stays reserved.
    ///
    /// # Errors
    ///
    /// The lifetime must be valid, the ID unused, and the authority have room.
    pub fn add_ticket(&self, ticket: PrefixTicket) -> Result<(), InvalidPrefixAuth> {
        let mut state = lock(&self.authority);
        if state.tickets.len() >= self.capacity
            || state.tickets.contains_key(&ticket.id)
            || ticket.slots.is_empty()
            || *ticket.slots.end() < state.floor
        {
            return Err(InvalidPrefixAuth(
                "invalid ticket, duplicate ID or exhausted ID capacity",
            ));
        }
        state
            .ticket_expiry
            .push(Reverse((*ticket.slots.end(), ticket.id)));
        state.tickets.insert(ticket.id, TicketState::Live(ticket));
        Ok(())
    }

    /// Revokes an ID even when it has never been installed. At capacity all
    /// previously unseen IDs are already barred from installation.
    pub fn revoke_ticket(&self, id: [u8; 16]) {
        let mut state = lock(&self.authority);
        if let Some(ticket) = state.tickets.get_mut(&id) {
            if matches!(ticket, TicketState::Live(_)) {
                *ticket = TicketState::Retired(None);
            }
        } else if state.tickets.len() < self.capacity {
            state.tickets.insert(id, TicketState::Retired(None));
        }
    }

    /// Retires expired replay records and tickets while persisting the
    /// effective cleanup slot if any state was removed.
    pub fn expire(&self, unix_seconds: u64) {
        let mut state = lock(&self.authority);
        let current = (unix_seconds / self.window.slot_seconds()).max(state.floor);
        Self::expire_at(&mut state, current);
        self.floor_hint.store(state.floor, Ordering::Release);
    }

    fn expire_at(state: &mut Authority, current: u64) {
        while state
            .expiry
            .peek()
            .is_some_and(|Reverse((last, _))| *last < current)
        {
            let Reverse((_, key)) = state.expiry.pop().expect("checked expiry");
            state.claims.remove(&key);
            state.floor = current;
        }
        while state
            .ticket_expiry
            .peek()
            .is_some_and(|Reverse((last, _))| *last < current)
        {
            let Reverse((_, id)) = state.ticket_expiry.pop().expect("checked ticket expiry");
            if let Some(ticket @ TicketState::Live(_)) = state.tickets.get_mut(&id) {
                *ticket = TicketState::Retired(None);
            }
        }
    }

    fn redeem(&self, attempt: &PrefixDeadline, claim: PrefixClaim) -> io::Result<bool> {
        let mut state = lock(&self.authority);
        let current = claim.local_slot.max(state.floor);
        let slots = self.window.slots(current);
        let (schedule, _) = self.local_schedule();
        let Some(TicketState::Live(ticket)) = state.tickets.get(&claim.id) else {
            return Ok(false);
        };
        if !ticket.slots.contains(&current)
            || ticket.version != claim.version
            || schedule.version != claim.schedule
            || !slots.contains(&claim.issue_slot)
            || !std::ptr::eq(
                schedule.eligible(&slots),
                schedule.eligible(&self.window.slots(claim.checked_slot)),
            )
            || !schedule
                .eligible(&slots)
                .iter()
                .any(|g| g.first() == claim.generation && g.contains(claim.issue_slot))
        {
            return Ok(false);
        }
        let single_use = ticket.single_use;
        check_deadline(attempt)?;
        Self::expire_at(&mut state, current);
        self.floor_hint.store(state.floor, Ordering::Release);
        let key = (claim.id, claim.nonce);
        if state.claims.contains_key(&key) || state.claims.len() >= self.capacity {
            return Ok(false);
        }
        check_deadline(attempt)?;
        state.claims.insert(key, claim.commit_id);
        state.expiry.push(Reverse((
            claim.issue_slot.saturating_add(u64::from(self.window.skew)),
            key,
        )));
        if single_use {
            state.tickets.insert(
                claim.id,
                TicketState::Retired(Some((claim.nonce, claim.commit_id))),
            );
        }
        state.floor = current;
        self.floor_hint.store(current, Ordering::Release);
        Ok(true)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn check_deadline(attempt: &PrefixDeadline) -> io::Result<()> {
    if attempt.ended() {
        Err(io::ErrorKind::TimedOut.into())
    } else {
        Ok(())
    }
}

impl PrefixStore for MemoryPrefixStore {
    fn window(&self) -> PrefixWindow {
        self.window
    }

    fn local_schedule(&self) -> (Arc<PrefixSchedule>, u64) {
        let schedule = self
            .cache
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        (schedule, self.floor_hint.load(Ordering::Acquire))
    }

    fn floor(&self, attempt: PrefixDeadline) -> PrefixStoreFuture<'_, u64> {
        Box::pin(async move {
            let state = lock(&self.authority);
            check_deadline(&attempt)?;
            Ok(state.floor)
        })
    }

    fn lookup(
        &self,
        attempt: PrefixDeadline,
        id: [u8; 16],
    ) -> PrefixStoreFuture<'_, Option<PrefixTicket>> {
        Box::pin(async move {
            let state = lock(&self.authority);
            check_deadline(&attempt)?;
            Ok(match state.tickets.get(&id) {
                Some(TicketState::Live(ticket)) => Some(ticket.clone()),
                _ => None,
            })
        })
    }

    fn claim(&self, attempt: PrefixDeadline, claim: PrefixClaim) -> PrefixStoreFuture<'_, bool> {
        Box::pin(async move { self.redeem(&attempt, claim) })
    }

    fn resolve(&self, attempt: PrefixDeadline, claim: PrefixClaim) -> PrefixStoreFuture<'_, bool> {
        Box::pin(async move {
            let state = lock(&self.authority);
            check_deadline(&attempt)?;
            if let Some(TicketState::Retired(Some((nonce, commit)))) = state.tickets.get(&claim.id)
                && *nonce == claim.nonce
                && *commit == claim.commit_id
            {
                return Ok(true);
            }
            match state.claims.get(&(claim.id, claim.nonce)) {
                Some(commit) => Ok(*commit == claim.commit_id),
                None => Err(io::ErrorKind::NotFound.into()),
            }
        })
    }
}
