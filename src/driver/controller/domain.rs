use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::watch;

use crate::driver::cache::Key;

use super::{ControllerBlock, ControllerError, ControllerLimits, lock};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(in crate::driver) struct Demand {
    pub(in crate::driver) opener: bool,
    pub(in crate::driver) cleanup: usize,
}

struct State {
    pending: VecDeque<(u64, Option<Demand>)>,
    openers: usize,
    cleanup: usize,
    closed: bool,
}

pub(in crate::driver) struct Domain {
    limits: ControllerLimits,
    next: AtomicU64,
    state: Mutex<State>,
    changed: watch::Sender<()>,
}

impl Domain {
    pub(in crate::driver) fn new(limits: ControllerLimits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            next: AtomicU64::new(0),
            state: Mutex::new(State {
                pending: VecDeque::new(),
                openers: 0,
                cleanup: 0,
                closed: false,
            }),
            changed: watch::Sender::new(()),
        })
    }

    pub(in crate::driver) fn owner(self: &Arc<Self>) -> Owner {
        Owner {
            domain: self.clone(),
            id: self.next.fetch_add(1, Ordering::Relaxed),
            starts: StartOpportunities::default(),
            usage: Arc::default(),
        }
    }

    pub(in crate::driver) fn subscribe(&self) -> watch::Receiver<()> {
        self.changed.subscribe()
    }

    pub(in crate::driver) fn usage(&self) -> (usize, usize) {
        let state = lock(&self.state);
        (state.openers, state.cleanup)
    }

    pub(in crate::driver) fn idle(&self) -> bool {
        let state = lock(&self.state);
        state.openers == 0 && state.cleanup == 0 && state.pending.is_empty()
    }

    pub(in crate::driver) fn released(&self) -> bool {
        let state = lock(&self.state);
        state.closed && state.openers == 0 && state.cleanup == 0
    }

    pub(in crate::driver) fn close(&self) {
        let mut state = lock(&self.state);
        state.closed = true;
        state.pending.clear();
        self.changed.send_replace(());
    }

    fn release(&self, bill: &Usage, opener: bool, cleanup: usize) {
        let mut state = lock(&self.state);
        state.openers -= usize::from(opener);
        state.cleanup -= cleanup;
        bill.openers
            .fetch_sub(usize::from(opener), Ordering::Relaxed);
        bill.cleanup.fetch_sub(cleanup, Ordering::Relaxed);
        self.changed.send_replace(());
    }
}

#[derive(Clone, Default)]
pub(in crate::driver) struct StartOpportunities(Arc<Mutex<BTreeMap<(Key, bool), Suppression>>>);

impl StartOpportunities {
    pub(in crate::driver) fn opportunity(&self, key: Key, recovery: bool) -> Suppression {
        lock(&self.0).entry((key, recovery)).or_default().clone()
    }

    pub(in crate::driver) fn retain_recovery(&self, wanted: &BTreeSet<Key>) {
        lock(&self.0).retain(|(key, recovery), _| !recovery || wanted.contains(key));
    }

    pub(in crate::driver) fn finish_ordinary(&self) {
        lock(&self.0).retain(|(_, recovery), _| *recovery);
    }

    pub(in crate::driver) fn transfer(
        &self,
        next: &Self,
        recovery_keys: &BTreeSet<Key>,
        same_target: bool,
    ) {
        let old = lock(&self.0);
        lock(&next.0).extend(
            old.iter()
                .filter(|((key, recovery), _)| {
                    if *recovery {
                        recovery_keys.contains(key)
                    } else {
                        same_target
                    }
                })
                .map(|(key, value)| (key.clone(), value.clone())),
        );
    }
}

#[derive(Clone, Default)]
pub(in crate::driver) struct Suppression(Arc<AtomicBool>);

impl Suppression {
    pub(in crate::driver) fn count(&self) -> bool {
        !self.0.swap(true, Ordering::Relaxed)
    }

    pub(in crate::driver) fn started(&self) {
        self.0.store(false, Ordering::Relaxed);
    }
}

#[derive(Default)]
struct Usage {
    openers: AtomicUsize,
    cleanup: AtomicUsize,
}

pub(in crate::driver) struct Owner {
    domain: Arc<Domain>,
    id: u64,
    pub(in crate::driver) starts: StartOpportunities,
    usage: Arc<Usage>,
}

impl Owner {
    pub(in crate::driver) fn usage(&self) -> (usize, usize) {
        let _state = lock(&self.domain.state);
        (
            self.usage.openers.load(Ordering::Relaxed),
            self.usage.cleanup.load(Ordering::Relaxed),
        )
    }

    pub(in crate::driver) fn subscribe(&self) -> watch::Receiver<()> {
        self.domain.subscribe()
    }

    pub(in crate::driver) fn enqueue(&self) -> Result<(), ControllerError> {
        self.ensure_pending(&mut lock(&self.domain.state))
            .map(|_| ())
    }

    fn ensure_pending(&self, state: &mut State) -> Result<usize, ControllerError> {
        if state.closed {
            return Err(ControllerError::Closed);
        }
        if let Some(index) = state.pending.iter().position(|(id, _)| *id == self.id) {
            return Ok(index);
        }
        let index = state.pending.len();
        if index == self.domain.limits.pending_owners.get() {
            return Err(ControllerError::QueueFull);
        }
        state.pending.push_back((self.id, None));
        Ok(index)
    }

    pub(in crate::driver) fn blocked(&self) {
        let mut state = lock(&self.domain.state);
        if let Some(index) = state.pending.iter().position(|(id, _)| *id == self.id)
            && state.pending[index].1.is_some()
        {
            state.pending.remove(index);
            state.pending.push_back((self.id, None));
            self.domain.changed.send_replace(());
        }
    }

    pub(in crate::driver) fn withdraw(&self) {
        let mut state = lock(&self.domain.state);
        if let Some(index) = state.pending.iter().position(|(id, _)| *id == self.id) {
            state.pending.remove(index);
            self.domain.changed.send_replace(());
        }
    }

    pub(in crate::driver) fn grant(
        &self,
        demand: Demand,
        keep_pending: bool,
    ) -> Result<Grant, ControllerBlock> {
        self.grant_with(demand, keep_pending, || Ok(()))
            .map(|(grant, ())| grant)
    }

    pub(in crate::driver) fn grant_with<T>(
        &self,
        demand: Demand,
        keep_pending: bool,
        admit: impl FnOnce() -> Result<T, ControllerBlock>,
    ) -> Result<(Grant, T), ControllerBlock> {
        let mut state = lock(&self.domain.state);
        if state.closed {
            return Err(ControllerBlock::OwnerClosed);
        }
        if demand.cleanup > self.domain.limits.cleanup_attachments.get() {
            return Err(ControllerBlock::Cleanup);
        }
        let index = self
            .ensure_pending(&mut state)
            .map_err(|error| ControllerBlock::from_owner(&error))?;
        let openers = self.domain.limits.concurrent_openers.get() - state.openers;
        let cleanup = self.domain.limits.cleanup_attachments.get() - state.cleanup;
        if state.pending[index].1.replace(demand) != Some(demand) {
            self.domain.changed.send_replace(());
        }
        if demand.opener && openers == 0 {
            return Err(ControllerBlock::Execution);
        }
        if demand.cleanup > cleanup {
            return Err(ControllerBlock::Cleanup);
        }
        let (mut opener_priority, mut cleanup_priority) = (false, false);
        for (_, earlier) in state.pending.iter().take(index) {
            if let Some(earlier) = earlier
                && !(earlier.opener && opener_priority || earlier.cleanup != 0 && cleanup_priority)
            {
                opener_priority |= earlier.opener;
                cleanup_priority |= earlier.cleanup != 0;
            }
        }
        if demand.cleanup != 0 && cleanup_priority {
            return Err(ControllerBlock::Cleanup);
        }
        if demand.opener && opener_priority {
            return Err(ControllerBlock::Execution);
        }
        let admitted = admit()?;
        state.pending.remove(index);
        if keep_pending {
            state.pending.push_back((self.id, None));
        }
        state.openers += usize::from(demand.opener);
        state.cleanup += demand.cleanup;
        self.usage
            .openers
            .fetch_add(usize::from(demand.opener), Ordering::Relaxed);
        self.usage
            .cleanup
            .fetch_add(demand.cleanup, Ordering::Relaxed);
        self.domain.changed.send_replace(());
        Ok((
            Grant {
                opener: demand
                    .opener
                    .then(|| Permit::new(&self.domain, &self.usage, true, 0)),
                cleanup: Permit::new(&self.domain, &self.usage, false, demand.cleanup),
            },
            admitted,
        ))
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        self.withdraw();
    }
}

pub(in crate::driver) struct Grant {
    pub(in crate::driver) opener: Option<Permit>,
    pub(in crate::driver) cleanup: Permit,
}

impl Grant {
    pub(in crate::driver) fn reserve_opener<D: crate::driver::handle::Driver>(
        self,
        opener: crate::driver::capacity_change::CarrierOpenerFor<D::Carrier>,
    ) -> (
        crate::driver::capacity_change::CarrierOpenerFor<D::Carrier>,
        Vec<CleanupObserver>,
    ) {
        let Grant {
            opener: execution,
            mut cleanup,
        } = self;
        let slots: Vec<CleanupSlot> = std::iter::from_fn(|| cleanup.split())
            .map(|permit| Arc::new(Mutex::new(Some(permit))))
            .collect();
        let observed = slots.iter().map(Arc::downgrade).collect();
        let reserved = Mutex::new(Some((execution, slots)));
        let wrapped = crate::driver::capacity_change::CarrierOpenerFor::new(move |request| {
            let reserved = lock(&reserved).take().expect("one controller attempt");
            let opener = opener.clone();
            async move {
                let (execution, slots) = reserved;
                let mut result = opener.open(request).await;
                drop(execution);
                for (io, slot) in result.carriers.iter_mut().zip(slots) {
                    D::hold_cleanup(io, slot);
                }
                result
            }
        });
        (wrapped, observed)
    }
}

pub(in crate::driver) struct Permit {
    domain: Arc<Domain>,
    bill: Arc<Usage>,
    opener: bool,
    cleanup: usize,
}

impl Permit {
    fn new(domain: &Arc<Domain>, bill: &Arc<Usage>, opener: bool, cleanup: usize) -> Self {
        Self {
            domain: domain.clone(),
            bill: bill.clone(),
            opener,
            cleanup,
        }
    }

    pub(in crate::driver) fn split(&mut self) -> Option<Self> {
        if self.cleanup == 0 {
            return None;
        }
        self.cleanup -= 1;
        Some(Self::new(&self.domain, &self.bill, false, 1))
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if self.opener || self.cleanup != 0 {
            self.domain.release(&self.bill, self.opener, self.cleanup);
        }
    }
}

type CleanupSlot = Arc<Mutex<Option<Permit>>>;
pub(in crate::driver) type CleanupObserver = Weak<Mutex<Option<Permit>>>;

pub(in crate::driver) fn confirm(slot: &CleanupObserver) {
    if let Some(slot) = slot.upgrade() {
        lock(&slot).take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SINGLE: Demand = Demand {
        opener: true,
        cleanup: 1,
    };
    const SPLIT: Demand = Demand {
        opener: true,
        cleanup: 2,
    };

    #[tokio::test]
    async fn controller_queue_is_bounded_and_coalesces() {
        let options = crate::ControllerOptions::new("controller-test-queue", Vec::new());
        let controller = crate::SessionController::new(options).unwrap();
        let domain = &controller.0.domain;
        let owners = (0..64).map(|_| domain.owner()).collect::<Vec<_>>();
        for owner in &owners {
            owner.enqueue().unwrap();
        }
        owners[0].enqueue().unwrap();
        assert!(matches!(
            controller
                .open(
                    crate::Config::default(),
                    super::super::SessionTarget::default()
                )
                .await,
            Err(ControllerError::QueueFull)
        ));
        owners[0].withdraw();
        let extra = domain.owner();
        extra.enqueue().unwrap();
        assert!(matches!(
            owners[0].enqueue(),
            Err(ControllerError::QueueFull)
        ));
    }

    #[test]
    fn controller_execution_and_cleanup_have_independent_limits() {
        let domain = Domain::new(ControllerLimits::default());
        let owners = (0..6).map(|_| domain.owner()).collect::<Vec<_>>();
        let mut running = owners
            .iter()
            .take(4)
            .map(|owner| owner.grant(SPLIT, false).unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            owners[4].grant(SINGLE, false),
            Err(ControllerBlock::Execution)
        ));
        drop(running[0].opener.take());
        assert!(matches!(
            owners[4].grant(SINGLE, false),
            Err(ControllerBlock::Cleanup)
        ));
        drop(running[0].cleanup.split());
        let _next = owners[4].grant(SINGLE, false).unwrap();
        assert!(matches!(
            owners[5].grant(SINGLE, false),
            Err(ControllerBlock::Execution)
        ));
    }

    #[test]
    fn controller_accumulates_contested_cleanup_for_split() {
        let domain = Domain::new(ControllerLimits::default());
        let retiring = domain.owner();
        let mut cleanup = retiring
            .grant(
                Demand {
                    opener: false,
                    cleanup: 8,
                },
                false,
            )
            .unwrap()
            .cleanup;
        let split = domain.owner();
        let single = domain.owner();
        split.enqueue().unwrap();
        single.enqueue().unwrap();
        assert!(matches!(
            split.grant(SPLIT, false),
            Err(ControllerBlock::Cleanup)
        ));
        drop(cleanup.split());
        assert!(matches!(
            single.grant(SINGLE, false),
            Err(ControllerBlock::Cleanup)
        ));
        drop(cleanup.split());
        let _split = split.grant(SPLIT, false).unwrap();
        assert!(matches!(
            single.grant(SINGLE, false),
            Err(ControllerBlock::Cleanup)
        ));
    }

    #[test]
    fn a_waiting_opener_keeps_its_cleanup_class() {
        let domain = Domain::new(ControllerLimits::default());
        let opener_only = Demand {
            opener: true,
            cleanup: 0,
        };
        let cleanup_only = Demand {
            opener: false,
            cleanup: 1,
        };
        let mut occupied = (0..4)
            .map(|_| domain.owner().grant(opener_only, false).unwrap())
            .collect::<Vec<_>>();
        let first = domain.owner();
        let later = domain.owner();
        assert!(matches!(
            first.grant(SINGLE, false),
            Err(ControllerBlock::Execution)
        ));
        assert!(matches!(
            later.grant(cleanup_only, false),
            Err(ControllerBlock::Cleanup)
        ));
        drop(occupied[0].opener.take());
        let _grant = first.grant(SINGLE, false).unwrap();
        assert!(later.grant(cleanup_only, false).is_ok());
        domain.close();
        assert!(matches!(
            later.grant(cleanup_only, false),
            Err(ControllerBlock::OwnerClosed)
        ));
    }
}

#[cfg(test)]
#[test]
fn a_suppressed_recovery_opportunity_survives_grant_and_handoff() {
    let domain = Domain::new(ControllerLimits::default());
    let next_domain = Domain::new(ControllerLimits::default());
    let first = domain.owner();
    let next = next_domain.owner();
    let key = (
        "shared".into(),
        crate::CarrierKind::Streaming,
        String::new(),
    );
    let opportunity = first.starts.opportunity(key.clone(), true);
    assert!(opportunity.count());
    let grant = first
        .grant(
            Demand {
                opener: true,
                cleanup: 1,
            },
            false,
        )
        .unwrap();
    assert_eq!(first.usage(), (1, 1));
    assert_eq!(domain.usage(), (1, 1));
    assert_eq!(next.usage(), (0, 0));
    assert!(!opportunity.count());
    first
        .starts
        .transfer(&next.starts, &BTreeSet::from([key.clone()]), false);
    assert!(!next.starts.opportunity(key.clone(), true).count());
    drop(grant);
    assert_eq!(first.usage(), (0, 0));
    next.starts.retain_recovery(&BTreeSet::new());
    assert!(next.starts.opportunity(key, true).count());
}
