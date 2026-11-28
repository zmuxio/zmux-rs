//! A memory domain's reservation ledger. Carriers and sessions can share
//! the ledger without taking each other's owner locks.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::BuildHasherDefault;

use crate::util::{CapacityPool, IdHasher};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) used: u64,
    pub(crate) limit: Option<u64>,
    pub(crate) pressure: bool,
    pub(crate) generation: u64,
}

impl Snapshot {
    pub(crate) fn available(self) -> Option<u64> {
        self.limit.map(|limit| limit.saturating_sub(self.used))
    }
}

#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
#[derive(Default)]
pub(crate) struct BudgetWait {
    waker: Mutex<Option<std::task::Waker>>,
    rechecked: AtomicU64,
}

type Notify = Box<dyn Fn(Snapshot) + Send + Sync>;

#[derive(Default)]
struct ReceiveGrowth {
    limit: i64,
    /// Counts of live session window grants by their physical byte charge.
    holders: BTreeMap<u64, usize>,
}

impl ReceiveGrowth {
    fn replace(&mut self, old: Option<u64>, new: Option<u64>) {
        if let Some(old) = old {
            let count = self.holders.get_mut(&old).expect("live receive window");
            *count -= 1;
            if *count == 0 {
                self.holders.remove(&old);
            }
        }
        if let Some(new) = new {
            *self.holders.entry(new).or_default() += 1;
        }
    }

    fn room(&self, state: Snapshot, initial: u64, current: u64) -> u64 {
        let growth_limit = match self.limit {
            ..0 => u64::MAX,
            0 => state.limit.map_or(u64::MAX, |limit| limit / 4),
            limit => limit.unsigned_abs(),
        };
        let mut room = initial.saturating_add(growth_limit).saturating_sub(current);
        if state.pressure
            && let Some((&least, _)) = self.holders.first_key_value()
            && let Some((&most, _)) = self.holders.last_key_value()
            && least < most
        {
            // While pressure persists, let smaller windows catch up first.
            room = room.min(most.saturating_sub(current));
        }
        room
    }
}

pub(crate) struct Ledger {
    state: Mutex<LedgerState>,
    pressure: AtomicBool,
    notify: Option<Notify>,
    ingress: u64,
    /// Release epoch in the upper bits, with a registered wait in bit zero.
    released: AtomicU64,
    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    waits: Mutex<Vec<std::sync::Weak<BudgetWait>>>,
}

struct LedgerState {
    snapshot: Snapshot,
    write_roots: Option<Box<WriteRegistry>>,
    receive_growth: Option<Box<ReceiveGrowth>>,
}

impl fmt::Debug for Ledger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Ledger").field(&self.snapshot()).finish()
    }
}

impl Ledger {
    pub(crate) fn new(limit: Option<u64>, notify: Option<Notify>) -> Arc<Self> {
        Self::create(limit, notify, 0, None)
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn for_listener(
        limit: Option<u64>,
        notify: Option<Notify>,
        ingress: u64,
        session_growth_limit: i64,
    ) -> Arc<Self> {
        Self::create(limit, notify, ingress, Some(session_growth_limit))
    }

    #[cfg(test)]
    pub(crate) fn with_ingress(
        limit: Option<u64>,
        notify: Option<Notify>,
        ingress: u64,
    ) -> Arc<Self> {
        Self::create(limit, notify, ingress, Some(0))
    }

    fn create(
        limit: Option<u64>,
        notify: Option<Notify>,
        ingress: u64,
        session_growth_limit: Option<i64>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(LedgerState {
                snapshot: Snapshot {
                    used: 0,
                    limit,
                    pressure: false,
                    generation: 0,
                },
                write_roots: None,
                receive_growth: session_growth_limit.map(|limit| {
                    Box::new(ReceiveGrowth {
                        limit,
                        ..ReceiveGrowth::default()
                    })
                }),
            }),
            pressure: AtomicBool::new(false),
            notify,
            ingress,
            released: AtomicU64::new(0),
            #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
            waits: Mutex::new(Vec::new()),
        })
    }

    fn lock(&self) -> MutexGuard<'_, LedgerState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn write_root_fits(&self, backing: crate::proto::session::Backing) -> bool {
        self.snapshot()
            .limit
            .is_none_or(|limit| (backing.size as u64).saturating_add(WriteSlot::OVERHEAD) <= limit)
    }

    pub(crate) fn reserve_write_root(
        self: &Arc<Self>,
        backing: crate::proto::session::Backing,
    ) -> Option<WriteRoot> {
        let mut state = self.lock();
        if let Some(slot) = state
            .write_roots
            .as_deref()
            .and_then(|roots| roots.get(backing.id))
        {
            return Some(slot.share());
        }
        let overhead = if state
            .write_roots
            .as_deref()
            .is_none_or(|roots| roots.reusable_count == 0)
        {
            WriteSlot::OVERHEAD
        } else {
            0
        };
        let bytes = (backing.size as u64).checked_add(overhead)?;
        if !self.growth_fits(state.snapshot, bytes) {
            return None;
        }
        state.snapshot.used += bytes;
        let roots = state.write_roots.get_or_insert_with(Box::default);
        let slot = roots.pop().unwrap_or_else(WriteSlot::take);
        slot.start(
            self,
            backing.id,
            WriteGrant::Ledger(Reservation {
                ledger: self.clone(),
                bytes: (backing.size as u64) + WriteSlot::OVERHEAD,
            }),
        );
        roots.insert(backing.id, slot.clone());
        self.publish(state);
        Some(WriteRoot(slot))
    }

    pub(crate) fn state_heap_bytes(&self) -> usize {
        let state = self.lock();
        size_of::<Self>()
            + 2 * size_of::<usize>()
            + state.write_roots.as_deref().map_or(0, size_of_val)
            + state.receive_growth.as_deref().map_or(0, size_of_val)
    }

    pub(crate) fn snapshot(&self) -> Snapshot {
        self.lock().snapshot
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn pressure(&self) -> bool {
        self.pressure.load(Ordering::Acquire)
    }

    #[cfg(any(test, all(any(feature = "tokio", feature = "blocking"), not(loom))))]
    fn prune_write_cache(&self) {
        let mut state = self.lock();
        let Some(roots) = state.write_roots.as_deref_mut() else {
            return;
        };
        let unused = roots.reusable_count as u64 * WriteSlot::OVERHEAD;
        roots.empty_cache();
        let needed = roots.active.len();
        roots.resize_index(needed);
        if unused != 0 {
            state.snapshot.used -= unused;
            self.publish(state);
            self.release_event();
        }
    }

    #[cfg(test)]
    pub(crate) fn set_limit(&self, limit: Option<u64>) -> bool {
        self.set_limits(limit, None)
    }

    /// Changes limits atomically when the new budget covers every live grant.
    #[cfg(any(test, all(any(feature = "tokio", feature = "blocking"), not(loom))))]
    pub(crate) fn set_limits(&self, limit: Option<u64>, session_growth_limit: Option<i64>) -> bool {
        let budget = self.snapshot().limit.unwrap_or(u64::MAX);
        if limit.is_some_and(|limit| limit < budget) {
            self.prune_write_cache();
        }
        let mut state = self.lock();
        let old = state.snapshot;
        if limit != old.limit && limit.is_some_and(|limit| limit < old.used) {
            return false;
        }
        state.snapshot.limit = limit;
        let mut policy_changed = false;
        if let (Some(growth), Some(limit)) = (&mut state.receive_growth, session_growth_limit) {
            policy_changed = growth.limit != limit;
            growth.limit = limit;
        }
        let updated = self.publish(state);
        if policy_changed
            || updated.available().unwrap_or(u64::MAX) > old.available().unwrap_or(u64::MAX)
        {
            self.release_event();
        }
        true
    }

    pub(crate) fn reserve(self: &Arc<Self>, bytes: u64) -> Option<Reservation> {
        if bytes != 0 {
            self.resize(0, bytes)?;
        }
        Some(Reservation {
            ledger: self.clone(),
            bytes,
        })
    }

    fn growth_fits(&self, state: Snapshot, bytes: u64) -> bool {
        bytes <= self.growth_room(state)
    }

    pub(crate) fn reserve_growth(self: &Arc<Self>, bytes: u64) -> Option<Reservation> {
        let mut state = self.lock();
        if !self.growth_fits(state.snapshot, bytes) {
            return None;
        }
        state.snapshot.used += bytes;
        self.publish(state);
        Some(Reservation {
            ledger: self.clone(),
            bytes,
        })
    }

    /// The fixed workspace and minimum window may use ingress. Any
    /// additional positions must leave the next minimum admission funded.
    pub(crate) fn reserve_receive(
        self: &Arc<Self>,
        fixed: u64,
        cost: u64,
        minimum: u64,
        wanted: u64,
    ) -> Option<(Reservation, ReceiveWindow)> {
        let mut state = self.lock();
        let remaining = state.snapshot.limit.unwrap_or(u64::MAX) - state.snapshot.used;
        let room = remaining.checked_sub(fixed);
        let Some(room) = room.filter(|room| room / cost >= minimum) else {
            self.publish(state);
            return None;
        };
        let ingress = if state.snapshot.limit.is_some() {
            self.ingress
        } else {
            0
        };
        let units = wanted.min((room.saturating_sub(ingress) / cost).max(minimum));
        let bytes = units * cost;
        state.snapshot.used += fixed + bytes;
        if let Some(growth) = &mut state.receive_growth {
            growth.replace(None, Some(bytes));
        }
        self.publish(state);
        Some((
            Reservation {
                ledger: self.clone(),
                bytes: fixed,
            },
            ReceiveWindow {
                ledger: self.clone(),
                initial: bytes,
                bytes,
            },
        ))
    }

    fn growth_room(&self, state: Snapshot) -> u64 {
        state
            .available()
            .unwrap_or(u64::MAX - state.used)
            .saturating_sub(self.ingress)
    }

    fn resize(&self, old: u64, new: u64) -> Option<Snapshot> {
        let mut state = self.lock();
        let unchanged = state.snapshot.used - old;
        let used = unchanged.checked_add(new)?;
        if new > old && state.snapshot.limit.is_some_and(|limit| used > limit) {
            self.publish(state);
            return None;
        }
        state.snapshot.used = used;
        let snapshot = self.publish(state);
        if new < old {
            self.release_event();
        }
        Some(snapshot)
    }

    #[cfg(all(feature = "tokio", not(loom)))]
    pub(crate) fn release_epoch(&self) -> u64 {
        self.released.load(Ordering::Acquire) >> 1
    }

    fn release_event(&self) {
        let previous = self.released.fetch_add(2, Ordering::Release);
        #[cfg(not(all(any(feature = "tokio", feature = "blocking"), not(loom))))]
        let _ = previous;
        #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
        if previous & 1 != 0 {
            let waiting = {
                let mut waits = self.waits.lock().unwrap_or_else(PoisonError::into_inner);
                self.released.fetch_and(!1, Ordering::AcqRel);
                std::mem::take(&mut *waits)
            };
            for waiter in waiting.into_iter().filter_map(|waiter| waiter.upgrade()) {
                let waker = waiter
                    .waker
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some(waker) = waker {
                    waker.wake();
                }
            }
        }
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn watch(
        &self,
        expected: u64,
        slot: &mut Option<Arc<BudgetWait>>,
        waker: &std::task::Waker,
    ) -> bool {
        let mut waits = self.waits.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.released.fetch_or(1, Ordering::AcqRel) >> 1;
        let slot = slot.get_or_insert_with(Arc::default);
        // One immediate recheck covers a release before subscription. If
        // the carrier still cannot take a batch, its own writable event
        // must drive it, without repeatedly polling this old mismatch.
        if current != expected && slot.rechecked.swap(current, Ordering::Relaxed) != current {
            if waits.is_empty() {
                self.released.fetch_and(!1, Ordering::AcqRel);
            }
            return true;
        }
        let weak = Arc::downgrade(slot);
        waits.retain(|wait| wait.strong_count() > 0);
        if !waits.iter().any(|wait| wait.ptr_eq(&weak)) {
            waits.push(weak);
        }
        let mut pending = slot.waker.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(pending) = &mut *pending {
            pending.clone_from(waker);
        } else {
            *pending = Some(waker.clone());
        }
        false
    }

    fn publish(&self, mut state: MutexGuard<'_, LedgerState>) -> Snapshot {
        let pressure = state.snapshot.limit.is_some_and(|limit| {
            let remaining = limit.saturating_sub(state.snapshot.used);
            remaining < self.ingress
                || remaining == 0
                || state.snapshot.pressure && state.snapshot.used >= limit - limit / 4
        });
        if pressure == state.snapshot.pressure {
            return state.snapshot;
        }
        state.snapshot.pressure = pressure;
        self.pressure.store(pressure, Ordering::Release);
        state.snapshot.generation += 1;
        let event = state.snapshot;
        drop(state);
        if let Some(notify) = &self.notify {
            notify(event);
        }
        event
    }
}

/// Physical send backing held by one or more views in an ownership domain.
#[derive(Debug)]
pub(crate) struct WriteRoot(Arc<WriteSlot>);

impl WriteRoot {
    pub(crate) fn domain_id(&self) -> usize {
        self.0.domain.load(Ordering::Relaxed)
    }

    pub(crate) fn belongs_to(&self, ledger: &Arc<Ledger>) -> bool {
        self.domain_id() == Arc::as_ptr(ledger).addr()
    }
}

impl Clone for WriteRoot {
    #[inline]
    fn clone(&self) -> Self {
        self.0.share()
    }
}

impl Drop for WriteRoot {
    #[inline]
    fn drop(&mut self) {
        // No lock in the common case. The last *potential* ledger owner
        // takes the registry lock before decrementing to zero, which
        // serializes the release against accepting another view of this root.
        if self
            .0
            .refs
            .try_update(Ordering::AcqRel, Ordering::Acquire, |refs| {
                (refs > 1).then(|| refs - 1)
            })
            .is_ok()
        {
            return;
        }
        self.release_last();
    }
}

impl WriteRoot {
    #[cold]
    fn release_last(&self) {
        let ledger = {
            let state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
            let (_, grant) = state.as_ref().expect("a live token holds a grant");
            match grant {
                WriteGrant::Ledger(grant) => grant.domain().clone(),
                #[cfg(all(feature = "tokio", not(loom)))]
                WriteGrant::Workspace(_charge) => {
                    // Workspace roots are never looked up in the registry.
                    let mut state = state;
                    let retired = state.take();
                    drop(state);
                    drop(retired);
                    WriteSlot::recycle(self.0.clone());
                    return;
                }
            }
        };
        let mut state = ledger.lock();
        let roots = state
            .write_roots
            .as_deref_mut()
            .expect("live backing registry");
        if self.0.refs.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let (id, grant) = self
            .0
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .expect("the last view returns the grant");
        #[cfg(all(feature = "tokio", not(loom)))]
        let WriteGrant::Ledger(mut grant) = grant else {
            unreachable!("workspace roots are private");
        };
        #[cfg(not(all(feature = "tokio", not(loom))))]
        let WriteGrant::Ledger(mut grant) = grant;
        let slot = roots.remove(id).expect("live backing");
        // A tiny charged cache of the metadata alone makes repeated buf
        // writes allocate nothing after their first use.
        if roots.cache(slot) {
            grant.bytes -= WriteSlot::OVERHEAD;
        }
        if roots.active.capacity() > 32 && roots.active.len() < roots.active.capacity() / 4 {
            let retain = roots.active.len().saturating_mul(2).max(16);
            roots.resize_index(retain);
        }
        let bytes = std::mem::take(&mut grant.bytes);
        state.snapshot.used -= bytes;
        ledger.publish(state);
        if bytes != 0 {
            ledger.release_event();
        }
    }
}

type WriteIndex = HashMap<u64, Arc<WriteSlot>, BuildHasherDefault<IdHasher>>;

#[derive(Default)]
struct WriteRegistry {
    /// The common case when a forwarding stream has one backing in flight.
    first: Option<(u64, Arc<WriteSlot>)>,
    active: WriteIndex,
    reusable: [Option<Arc<WriteSlot>>; 8],
    reusable_count: usize,
}

impl WriteRegistry {
    #[inline]
    fn get(&self, id: u64) -> Option<&Arc<WriteSlot>> {
        if let Some((_, first)) = self.first.as_ref().filter(|(known, _)| *known == id) {
            return Some(first);
        }
        self.active.get(&id)
    }

    fn insert(&mut self, id: u64, slot: Arc<WriteSlot>) {
        if self.first.is_none() {
            self.first = Some((id, slot));
            return;
        }
        if self.active.len() == self.active.capacity() {
            self.resize_index(self.active.len() + 1);
        }
        self.active.insert(id, slot);
    }

    fn remove(&mut self, id: u64) -> Option<Arc<WriteSlot>> {
        if self.first.as_ref().is_some_and(|(known, _)| *known == id) {
            return self.first.take().map(|(_, slot)| slot);
        }
        self.active.remove(&id)
    }

    #[cold]
    fn resize_index(&mut self, wanted: usize) {
        let mut next = take_index_storage(wanted);
        let mut previous = std::mem::take(&mut self.active);
        next.extend(previous.drain());
        self.active = next;
        give_index_storage(previous);
    }

    fn pop(&mut self) -> Option<Arc<WriteSlot>> {
        self.reusable_count = self.reusable_count.checked_sub(1)?;
        self.reusable[self.reusable_count].take()
    }

    /// Returns whether the slot stays charged to this ledger.
    fn cache(&mut self, slot: Arc<WriteSlot>) -> bool {
        let Some(entry) = self.reusable.get_mut(self.reusable_count) else {
            WriteSlot::recycle(slot);
            return false;
        };
        *entry = Some(slot);
        self.reusable_count += 1;
        true
    }

    fn empty_cache(&mut self) {
        while let Some(slot) = self.pop() {
            WriteSlot::recycle(slot);
        }
    }
}

impl Drop for WriteRegistry {
    fn drop(&mut self) {
        self.empty_cache();
        debug_assert!(self.first.is_none() && self.active.is_empty());
        give_index_storage(std::mem::take(&mut self.active));
    }
}

/// Idle index buffers, bounded by actual capacity.
static WRITE_INDICES: Mutex<CapacityPool<WriteIndex>> = Mutex::new(CapacityPool::new(2048));

fn take_index_storage(wanted: usize) -> WriteIndex {
    let range = wanted..=wanted.saturating_mul(2).saturating_add(1);
    let cached = WRITE_INDICES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .take(range);
    cached.unwrap_or_else(|| {
        WriteIndex::with_capacity_and_hasher(wanted, BuildHasherDefault::default())
    })
}

fn give_index_storage(mut index: WriteIndex) {
    debug_assert!(index.is_empty());
    index.clear();
    WRITE_INDICES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .give(index.capacity(), index);
}

// A small process cache of empty ownership slots. A cached slot holds
// neither the backing nor a reference to its former ledger. Only the
// hot per-domain cache counts against that domain.
static WRITE_SLOTS: Mutex<CapacityPool<Arc<WriteSlot>>> = Mutex::new(CapacityPool::new(256));

#[derive(Debug, Default)]
struct WriteSlot {
    domain: AtomicUsize,
    refs: AtomicUsize,
    state: Mutex<Option<(u64, WriteGrant)>>,
}

impl WriteSlot {
    const OVERHEAD: u64 = (size_of::<Self>() + 12 * size_of::<usize>()) as u64;

    fn take() -> Arc<Self> {
        let saved = WRITE_SLOTS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take(1..=1);
        saved.unwrap_or_default()
    }

    fn recycle(slot: Arc<Self>) {
        WRITE_SLOTS
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .give(1, slot);
    }

    fn start(&self, ledger: &Arc<Ledger>, id: u64, grant: WriteGrant) {
        self.domain
            .store(Arc::as_ptr(ledger).addr(), Ordering::Relaxed);
        *self.state.lock().unwrap_or_else(PoisonError::into_inner) = Some((id, grant));
        self.refs.store(1, Ordering::Release);
    }

    #[inline]
    fn share(self: &Arc<Self>) -> WriteRoot {
        self.refs.fetch_add(1, Ordering::Relaxed);
        WriteRoot(self.clone())
    }
}

#[derive(Debug)]
enum WriteGrant {
    Ledger(Reservation),
    #[cfg(all(feature = "tokio", not(loom)))]
    Workspace(WorkspaceCharge),
}

#[cfg(all(feature = "tokio", not(loom)))]
#[derive(Debug)]
struct WorkspaceCharge {
    space: Arc<WriteWorkspace>,
    bytes: u64,
}

#[cfg(all(feature = "tokio", not(loom)))]
impl Drop for WorkspaceCharge {
    fn drop(&mut self) {
        self.space.used.fetch_sub(self.bytes, Ordering::AcqRel);
        self.space.grant.ledger.release_event();
    }
}

/// Committed writer space for the current batch and a replacement. Each
/// root which uses it keeps the space alive through carrier retention.
#[cfg(all(feature = "tokio", not(loom)))]
#[derive(Debug)]
pub(crate) struct WriteWorkspace {
    grant: Reservation,
    used: AtomicU64,
}

#[cfg(all(feature = "tokio", not(loom)))]
impl WriteWorkspace {
    pub(crate) const MAX_ROOT: usize = crate::proto::receive::MAX_CLASS;
    pub(crate) const COST: u64 = 2 * (Self::MAX_ROOT as u64 + WriteSlot::OVERHEAD);

    pub(crate) fn new(grant: Reservation) -> Arc<Self> {
        assert_eq!(grant.bytes(), Self::COST);
        Arc::new(Self {
            grant,
            used: AtomicU64::new(0),
        })
    }

    pub(crate) fn domain(&self) -> &Arc<Ledger> {
        self.grant.domain()
    }

    pub(crate) fn take(
        self: &Arc<Self>,
        backing: crate::proto::session::Backing,
    ) -> Option<WriteRoot> {
        let bytes = (backing.size as u64).checked_add(WriteSlot::OVERHEAD)?;
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|&next| next <= Self::COST)
            })
            .ok()?;
        let slot = WriteSlot::take();
        slot.start(
            self.domain(),
            backing.id,
            WriteGrant::Workspace(WorkspaceCharge {
                space: self.clone(),
                bytes,
            }),
        );
        Some(WriteRoot(slot))
    }
}

/// An exclusive grant. Moving the token keeps the charge in the same
/// ledger, and dropping it returns what the owner still holds.
#[derive(Debug)]
pub(crate) struct Reservation {
    ledger: Arc<Ledger>,
    bytes: u64,
}

impl Reservation {
    pub(crate) fn domain(&self) -> &Arc<Ledger> {
        &self.ledger
    }

    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Grows an existing grant by as many complete units as fit. It uses
    /// the same admission transaction as a new carrier reservation.
    pub(crate) fn grow_units(&mut self, cost: u64, wanted: u64) -> u64 {
        if wanted == 0 {
            return 0;
        }
        let mut state = self.ledger.lock();
        let room = self.ledger.growth_room(state.snapshot);
        let units = (room / cost).min(wanted);
        let bytes = units * cost;
        self.bytes += bytes;
        state.snapshot.used += bytes;
        self.ledger.publish(state);
        units
    }

    pub(crate) fn resize_growth(&mut self, bytes: u64) -> bool {
        if bytes <= self.bytes {
            return self.resize(bytes);
        }
        let mut state = self.ledger.lock();
        let added = bytes - self.bytes;
        if !self.ledger.growth_fits(state.snapshot, added) {
            return false;
        }
        state.snapshot.used += added;
        self.bytes = bytes;
        self.ledger.publish(state);
        true
    }

    pub(crate) fn release_epoch(&self) -> u64 {
        self.ledger.released.load(Ordering::Acquire) >> 1
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn watch(
        &self,
        expected: u64,
        slot: &mut Option<Arc<BudgetWait>>,
        waker: &std::task::Waker,
    ) -> bool {
        self.ledger.watch(expected, slot, waker)
    }

    pub(crate) fn reserve(&self, bytes: u64) -> Option<Self> {
        self.ledger.reserve(bytes)
    }

    /// Assigns part of an admitted grant to a different owner.
    pub(crate) fn split_off(&mut self, bytes: u64) -> Self {
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .expect("split within reservation");
        Self {
            ledger: self.ledger.clone(),
            bytes,
        }
    }

    /// Grows or shrinks this grant atomically. Refusal preserves its bytes.
    pub(crate) fn resize(&mut self, bytes: u64) -> bool {
        if bytes == self.bytes {
            return true;
        }
        if self.ledger.resize(self.bytes, bytes).is_none() {
            return false;
        }
        self.bytes = bytes;
        true
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.bytes != 0 {
            let released = self.ledger.resize(self.bytes, 0);
            debug_assert!(released.is_some());
        }
    }
}

/// The receive-position grant participates in listener fairness independently
/// of transport, direction and other work reservations.
#[derive(Debug)]
pub(crate) struct ReceiveWindow {
    ledger: Arc<Ledger>,
    initial: u64,
    bytes: u64,
}

impl ReceiveWindow {
    pub(crate) fn bytes(&self) -> u64 {
        self.bytes
    }

    fn room(&self, state: &LedgerState) -> u64 {
        let room = self.ledger.growth_room(state.snapshot);
        state.receive_growth.as_ref().map_or(room, |growth| {
            room.min(growth.room(state.snapshot, self.initial, self.bytes))
        })
    }

    pub(crate) fn growth_room(&self) -> u64 {
        self.room(&self.ledger.lock())
    }

    pub(crate) fn grow_units(&mut self, cost: u64, wanted: u64) {
        if wanted == 0 {
            return;
        }
        let mut state = self.ledger.lock();
        let extra = (self.room(&state) / cost).min(wanted) * cost;
        if extra == 0 {
            return;
        }
        let new = self.bytes + extra;
        Self::replace(&mut state, self.bytes, Some(new));
        self.bytes = new;
        self.ledger.publish(state);
    }

    pub(crate) fn shrink(&mut self, bytes: u64) {
        if bytes < self.bytes {
            self.release(Some(bytes));
        }
    }

    fn replace(state: &mut LedgerState, old: u64, new: Option<u64>) {
        state.snapshot.used = state.snapshot.used - old + new.unwrap_or(0);
        if let Some(growth) = &mut state.receive_growth {
            growth.replace(Some(old), new);
        }
    }

    fn release(&mut self, new: Option<u64>) {
        let mut state = self.ledger.lock();
        Self::replace(&mut state, self.bytes, new);
        self.bytes = new.unwrap_or(0);
        self.ledger.publish(state);
        self.ledger.release_event();
    }
}

impl Drop for ReceiveWindow {
    fn drop(&mut self) {
        self.release(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn growth_preserves_ingress_and_reports_pressure_below_one_admission() {
        let ledger = Ledger::with_ingress(Some(100), None, 20);
        let mut first = ledger.reserve(17).unwrap();
        assert_eq!(first.grow_units(8, 100), 7);
        assert_eq!(ledger.snapshot().used, 73);
        assert_eq!(ledger.growth_room(ledger.snapshot()), 7);
        assert!(!ledger.snapshot().pressure);

        let second = ledger.reserve(20).unwrap();
        assert_eq!(ledger.snapshot().used, 93);
        assert!(ledger.snapshot().pressure);
        drop(second);
        assert!(!ledger.snapshot().pressure);
        assert!(ledger.set_limit(Some(85)));
        assert!(ledger.snapshot().pressure);
    }

    #[test]
    fn bootstrap_extra_positions_leave_room_for_the_next_admission() {
        let ledger = Ledger::with_ingress(Some(100), None, 30);
        let (first, window) = ledger.reserve_receive(10, 4, 5, 25).unwrap();
        assert_eq!(window.bytes(), 60);
        assert!(first.domain().reserve_growth(1).is_none());
        let (_second, second_window) = ledger.reserve_receive(10, 4, 5, 25).unwrap();
        assert_eq!(second_window.bytes(), 20);
        assert!(ledger.snapshot().pressure);
    }

    #[test]
    fn under_pressure_smaller_receive_windows_have_priority() {
        let ledger = Ledger::with_ingress(Some(1000), None, 100);
        let (_first, mut first) = ledger.reserve_receive(0, 1, 400, 400).unwrap();
        let (_second, mut second) = ledger.reserve_receive(0, 1, 250, 250).unwrap();
        let steady = ledger.reserve(150).unwrap();
        let transient = ledger.reserve(105).unwrap();
        drop(transient);
        assert!(ledger.snapshot().pressure);
        assert_eq!(ledger.growth_room(ledger.snapshot()), 100);

        first.grow_units(1, 100);
        assert_eq!(first.bytes(), 400);
        second.grow_units(1, 100);
        assert_eq!(second.bytes(), 350);
        drop(steady);
        second.shrink(349);
        assert!(!ledger.snapshot().pressure);
        first.grow_units(1, 150);
        assert_eq!(first.bytes(), 550);
    }

    #[test]
    fn receive_growth_limit_changes_leave_existing_grants_live() {
        let ledger = Ledger::with_ingress(Some(1000), None, 100);
        let (_fixed, mut window) = ledger.reserve_receive(0, 1, 100, 100).unwrap();
        window.grow_units(1, 1000);
        assert_eq!(window.bytes(), 350, "zero means a quarter of the budget");

        assert!(ledger.set_limits(Some(1000), Some(100)));
        assert_eq!(window.bytes(), 350);
        window.grow_units(1, 1000);
        assert_eq!(window.bytes(), 350);
        window.shrink(150);
        window.grow_units(1, 1000);
        assert_eq!(window.bytes(), 200);

        assert!(ledger.set_limits(Some(1000), Some(-1)));
        window.grow_units(1, 1000);
        assert_eq!(window.bytes(), 900, "negative still preserves ingress");
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    #[test]
    fn release_wakes_an_installed_waiter_and_a_racing_registration_rechecks_once() {
        use std::task::{Wake, Waker};
        #[derive(Default)]
        struct Count(AtomicU64);
        impl Wake for Count {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let ledger = Ledger::new(Some(100), None);
        let watched = ledger.reserve(80).unwrap();
        let excess = ledger.reserve(20).unwrap();
        let count = Arc::new(Count::default());
        let waker = Waker::from(count.clone());
        let mut waiter = None;
        let epoch = watched.release_epoch();
        assert!(!watched.watch(epoch, &mut waiter, &waker));
        drop(excess);
        assert_eq!(count.0.load(Ordering::Relaxed), 1);
        assert!(watched.watch(epoch, &mut waiter, &waker));
        assert!(!watched.watch(epoch, &mut waiter, &waker));
    }

    #[test]
    fn refusal_preserves_live_grants_and_limit() {
        let ledger = Ledger::new(Some(900), None);
        let mut carrier = ledger.reserve(200).unwrap();
        let (receive, window) = ledger.reserve_receive(100, 4, 100, 250).unwrap();
        assert_eq!(window.bytes(), 600);
        assert_eq!(receive.bytes(), 100);
        assert!(Arc::ptr_eq(&receive.ledger, &ledger));
        assert_eq!(ledger.snapshot().available(), Some(0));
        assert!(!carrier.resize(201));
        assert!(ledger.reserve_receive(0, 4, 1, 10).is_none());
        assert!(!ledger.set_limit(Some(899)));
        assert_eq!(ledger.snapshot().used, 900);
        assert_eq!(ledger.snapshot().limit, Some(900));
        assert!(carrier.resize(100));
        assert_eq!(ledger.snapshot().available(), Some(100));
        drop((receive, window, carrier));
        assert_eq!(ledger.snapshot().used, 0);
    }

    #[test]
    fn pressure_uses_the_live_sum_and_three_quarter_hysteresis() {
        let ledger = Ledger::new(Some(100), None);
        let mut grant = ledger.reserve(100).unwrap();
        assert!(ledger.snapshot().pressure);
        assert!(grant.resize(75));
        assert!(ledger.snapshot().pressure);
        assert!(grant.resize(74));
        assert!(!ledger.snapshot().pressure);
        assert!(grant.resize(100));
        assert!(ledger.snapshot().pressure);
        assert!(ledger.set_limit(None));
        assert!(!ledger.snapshot().pressure);
    }

    #[test]
    fn competing_reservations_cannot_overcommit_a_domain() {
        let ledger = Ledger::new(Some(100), None);
        let entered = std::sync::Barrier::new(3);
        let attempted = std::sync::Barrier::new(3);
        std::thread::scope(|scope| {
            let reserve = || {
                entered.wait();
                let held = ledger.reserve(60);
                attempted.wait();
                held.is_some()
            };
            let left = scope.spawn(reserve);
            let right = scope.spawn(reserve);
            entered.wait();
            attempted.wait();
            assert_ne!(left.join().unwrap(), right.join().unwrap());
        });
        assert_eq!(ledger.snapshot().used, 0);
    }
}
