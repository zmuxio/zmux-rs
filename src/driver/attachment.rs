//! One completion group for a carrier and all its teardown obligations.
use super::wake::WakeList;
use crate::proto::session::PipeError;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// Join resources whose I/O or callback may outlive protocol state.
#[derive(Default)]
pub(super) struct JoinResources {
    pub(super) authorizing: super::sync::Slots,
    pub(super) carriers: super::sync::Slots,
    releases: AtomicU64,
    wait: OnceLock<tokio::sync::watch::Sender<()>>,
}

impl JoinResources {
    pub(super) fn subscribe(&self) -> tokio::sync::watch::Receiver<()> {
        self.wait
            .get_or_init(|| tokio::sync::watch::Sender::new(()))
            .subscribe()
    }

    pub(super) fn released(&self) -> u64 {
        self.releases.load(Ordering::Acquire)
    }

    fn release_carrier(&self) {
        self.release_carriers(1);
    }

    fn release_carriers(&self, count: usize) {
        self.carriers.release_count(count);
        self.releases.fetch_add(1, Ordering::Release);
        if let Some(wait) = self.wait.get() {
            wait.send_replace(());
        }
    }
}

/// Actual opener work holds these slots through handoff or eventual exit.
pub(super) struct CarrierReservation {
    resources: Arc<JoinResources>,
    remaining: usize,
}

impl CarrierReservation {
    pub(super) fn new(resources: &Arc<JoinResources>, count: usize, limit: usize) -> Option<Self> {
        resources
            .carriers
            .try_acquire_count(count, limit)
            .then(|| Self {
                resources: resources.clone(),
                remaining: count,
            })
    }

    pub(super) fn transfer(&mut self, carrier: &Attachment) -> bool {
        let mut members = carrier
            .members
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if self.remaining == 0 || members.as_ref().is_some_and(|m| m.lifetime.is_some()) {
            return false;
        }
        members.get_or_insert_default().lifetime = Some(self.resources.clone());
        self.remaining -= 1;
        true
    }
}

impl Drop for CarrierReservation {
    fn drop(&mut self) {
        if self.remaining != 0 {
            self.resources.release_carriers(self.remaining);
        }
    }
}

/// The protocol outcome survives retirement while a handle or carrier still uses it.
#[derive(Default)]
pub(crate) struct PipeOutcome {
    reply: Mutex<Reply>,

    /// Assigned under the same session lock as cancellation, before installation.
    pub(super) id: OnceLock<crate::PipeId>,
    pub(super) join: OnceLock<Result<(), PipeError>>,
    #[cfg(feature = "blocking")]
    pub(super) successor: std::sync::atomic::AtomicU64,
    pub(super) released: super::wait::PipeDone,
    pub(super) sample: OnceLock<Arc<super::carrier_stats::Cache>>,
    pub(super) accounting: OnceLock<Arc<crate::proto::session::accounting::Ledger>>,
    pub(super) fault: Mutex<Option<Box<FaultJournal>>>,
}

#[derive(Default)]
pub(super) struct FaultJournal {
    pub(super) latest: Option<Box<crate::PipeHealthChange>>,
    pub(super) observer: Option<std::sync::Weak<super::choice::MemberFaults>>,
}

#[derive(Default)]
struct Reply {
    at: Option<std::time::Instant>,
    observer: Option<Arc<dyn super::capacity_change::OpenerAdmission>>,
}

impl PipeOutcome {
    pub(super) fn watch_reply(&self, observer: Arc<dyn super::capacity_change::OpenerAdmission>) {
        let mut reply = self.reply.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(at) = reply.at {
            observer.replied(at);
        } else {
            reply.observer = Some(observer);
        }
    }

    pub(super) fn verified_reply(&self, at: std::time::Instant) {
        let mut reply = self.reply.lock().unwrap_or_else(PoisonError::into_inner);
        if reply.at.is_some() {
            return;
        }
        reply.at = Some(at);
        if let Some(observer) = reply.observer.take() {
            observer.replied(at);
        }
    }

    pub(super) fn watch_faults(&self, observer: &Arc<super::choice::MemberFaults>) {
        let mut journal = self.fault.lock().unwrap_or_else(PoisonError::into_inner);
        let journal = journal.get_or_insert_default();
        journal.observer = Some(Arc::downgrade(observer));
        if let Some(fault) = journal.latest.as_deref() {
            observer.observe(fault);
        }
    }

    pub(super) fn report_health(&self, change: &crate::PipeHealthChange) {
        let mut journal = self.fault.lock().unwrap_or_else(PoisonError::into_inner);
        if change.reason.is_fault() && !change.before.reason.is_fault() {
            journal.get_or_insert_default().latest = Some(Box::new(change.clone()));
        }
        if let Some(observer) = journal
            .as_ref()
            .and_then(|j| j.observer.as_ref())
            .and_then(std::sync::Weak::upgrade)
        {
            observer.observe(change);
        }
    }
}

/// Held by the carrier and each worker that can outlive its protocol state.
#[derive(Default)]
pub(crate) struct Attachment {
    outcome: OnceLock<Arc<PipeOutcome>>,
    sample: OnceLock<super::carrier_stats::Registration>,
    reader_memory: OnceLock<crate::proto::memory::Reservation>,
    #[cfg(feature = "tokio")]
    writer_memory: OnceLock<Arc<crate::proto::memory::WriteWorkspace>>,
    #[cfg(feature = "tokio")]
    retiring: OnceLock<Arc<super::wait::PipeDone>>,
    members: Mutex<Option<Box<Members>>>,
}

#[derive(Default)]
struct Members {
    work: Option<Box<MemberWork>>,
    /// Carrier budget lease, released after teardown resources.
    lifetime: Option<Arc<JoinResources>>,
}

#[derive(Default)]
struct MemberWork {
    resources: Vec<Box<dyn Send>>,
    #[cfg(feature = "tokio")]
    workers: Vec<std::sync::Weak<Worker>>,
}

#[cfg(feature = "tokio")]
type Worker = Mutex<Vec<Arc<Attachment>>>;

impl Attachment {
    pub(super) fn hold_reader_memory(&self, grant: crate::proto::memory::Reservation) {
        self.reader_memory
            .set(grant)
            .expect("one receive reservation per carrier");
    }

    #[cfg(feature = "tokio")]
    pub(super) fn reader_memory(&self) -> Option<&crate::proto::memory::Reservation> {
        self.reader_memory.get()
    }

    pub(super) fn take_carrier(&self, resources: &Arc<JoinResources>, limit: usize) -> bool {
        let mut members = self.members.lock().unwrap_or_else(PoisonError::into_inner);
        let members = members.get_or_insert_default();
        if members.lifetime.is_some() || !resources.carriers.try_acquire(limit) {
            return false;
        }
        members.lifetime = Some(resources.clone());
        true
    }

    /// Registers cleanup that may start before setup knows its final session.
    #[cfg(feature = "tokio")]
    pub(super) fn worker(self: &Arc<Self>) -> impl Send + Sync + 'static + use<> {
        let worker = Arc::new(Mutex::new(vec![self.clone()]));
        self.register(Arc::downgrade(&worker));
        worker
    }

    #[cfg(feature = "tokio")]
    fn register(&self, worker: std::sync::Weak<Worker>) {
        let mut members = self.members.lock().unwrap_or_else(PoisonError::into_inner);
        let work = members.get_or_insert_default().work.get_or_insert_default();
        if work.workers.len() == work.workers.capacity() {
            work.workers.retain(|w| w.strong_count() != 0);
        }
        work.workers.push(worker);
    }

    /// Bring a newly classified carrier's existing workers into this group.
    /// Only workers hold strong references to groups. Merging groups can
    /// therefore never introduce an ownership cycle.
    #[cfg(feature = "tokio")]
    pub(super) fn adopt(self: &Arc<Self>, original: Option<&Arc<Self>>) {
        let Some(original) = original.filter(|g| !Arc::ptr_eq(g, self)) else {
            return;
        };
        let workers = {
            let members = original
                .members
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let Some(work) = members.as_ref().and_then(|members| members.work.as_ref()) else {
                return;
            };
            work.workers.clone()
        };
        for weak in workers {
            if let Some(worker) = weak.upgrade() {
                let mut leases = worker.lock().unwrap_or_else(PoisonError::into_inner);
                if !leases.iter().any(|g| Arc::ptr_eq(g, self)) {
                    leases.push(self.clone());
                    self.register(weak);
                }
            }
        }
    }

    pub(super) fn enable_accounting(
        &self,
        core: &mut crate::proto::session::SessionCore,
        session: crate::SessionId,
        id: crate::PipeId,
        mut sources: crate::CarrierHalfSources,
    ) -> Result<(), crate::InvalidConfig> {
        use crate::PipeHalf;
        let adapter_connection = [
            sources.send.connection.as_ref(),
            sources.receive.connection.as_ref(),
        ]
        .into_iter()
        .flatten()
        .find(|connection| connection.is_verified())
        .cloned();
        if let Some(identity) = self.sample_cache().and_then(|sample| sample.identity()) {
            if sources
                .send
                .connection
                .as_ref()
                .is_some_and(|send| sources.receive.connection.as_ref() == Some(send))
            {
                sources.receive.connection = Some(identity.clone());
            }
            sources.send.connection = Some(identity);
        }
        if let Some(identity) = adapter_connection.or_else(|| sources.send.connection.clone()) {
            core.set_pipe_connection(id, identity);
        }
        let policy = core.config().accounting;
        if !policy.enabled {
            return Ok(());
        }
        let send = core.pipe_state(id, PipeHalf::Outbound).is_some();
        let receive = core.pipe_state(id, PipeHalf::Inbound).is_some();
        if policy.strict && sources.over_budget(send, receive, policy) {
            return Err(crate::InvalidConfig::new(
                "accounting",
                "carrier source limit",
            ));
        }
        let end = self.outcome();
        let first = end.accounting.get().is_none();
        let ledger = end.accounting.get_or_init(|| {
            Arc::new(crate::proto::session::accounting::Ledger::new(
                id, sources, send, receive, policy,
            ))
        });
        core.set_pipe_ledger(id, ledger.clone());
        if first && let Some(tickets) = &core.config().accounting_tickets {
            tickets.publish(session, id, end);
        }
        Ok(())
    }

    pub(crate) fn outcome(&self) -> &Arc<PipeOutcome> {
        let end = self.outcome.get_or_init(Arc::default);
        if let Some(cache) = self.sample_cache() {
            end.sample.get_or_init(|| cache.clone());
        }
        end
    }

    pub(super) fn register_sample(
        &self,
        source: super::carrier_stats::Source,
        now: fn() -> std::time::Instant,
    ) {
        if self.sample.get().is_none()
            && let Some(registration) = source.attach(now)
        {
            let _ = self.sample.set(registration);
        }
        if let Some(cache) = self.sample_cache()
            && let Some(end) = self.outcome.get()
        {
            end.sample.get_or_init(|| cache.clone());
        }
    }

    pub(super) fn sample_cache(&self) -> Option<&Arc<super::carrier_stats::Cache>> {
        self.sample.get().map(|registration| &registration.cache)
    }

    pub(super) fn detach_sample(&self) {
        if let Some(sample) = self.sample.get() {
            sample.detach();
        }
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn retirement(&self) -> &Arc<super::wait::PipeDone> {
        self.retiring.get_or_init(Arc::default)
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn retire(&self, wakes: &mut WakeList) {
        self.detach_sample();
        if let Some(signal) = self.retiring.get() {
            signal.finish_into(wakes);
        }
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn writer_memory(&self) -> Option<&Arc<crate::proto::memory::WriteWorkspace>> {
        self.writer_memory.get()
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn hold_writer_memory(&self, grant: crate::proto::memory::Reservation) {
        let _ = self
            .writer_memory
            .set(crate::proto::memory::WriteWorkspace::new(grant));
    }

    /// Releases an owned resource before notifying external waiters. No host
    /// code runs while registering the obligation.
    pub(crate) fn hold(&self, resource: impl Send + 'static) {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert_default()
            .work
            .get_or_insert_default()
            .resources
            .push(Box::new(resource));
    }

    #[cfg(feature = "tokio")]
    pub(crate) async fn during<T>(lease: Option<Arc<Self>>, work: impl Future<Output = T>) -> T {
        let _lease = lease;
        work.await
    }
}

impl Drop for Attachment {
    fn drop(&mut self) {
        self.detach_sample();
        let mut members = self
            .members
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let lifetime = members.as_mut().and_then(|members| members.lifetime.take());
        drop(members);
        drop(self.reader_memory.take());
        if let Some(resources) = lifetime {
            resources.release_carrier();
        }
        if let Some(outcome) = self.outcome.get() {
            outcome.released.finish_into(&mut WakeList::default());
        }
    }
}

#[cfg(all(feature = "test-hooks", feature = "tokio"))]
pub(crate) fn attachment_footprint(sample: impl Fn() -> i64) -> [i64; 3] {
    let before = sample();
    let first = Arc::<Attachment>::default();
    let idle = sample();
    let worker = first.worker();
    let registered = sample();
    let pair = Arc::<Attachment>::default();
    let before_adopt = sample();
    pair.adopt(Some(&first));
    let adopted = sample();
    drop((first, pair, worker));
    [idle - before, registered - idle, adopted - before_adopt]
}

#[cfg(all(test, feature = "tokio"))]
mod tests {
    use super::*;
    use std::task::{Context, Waker};

    #[test]
    // HS-06
    fn released_attachment_cannot_register_another_worker() {
        let group = Arc::<Attachment>::default();
        let weak = Arc::downgrade(&group);
        let outcome = group.outcome().clone();
        let worker = group.worker();
        drop(group);
        let mut ticket = None;
        let cx = Context::from_waker(Waker::noop());
        assert!(outcome.released.poll_done(&mut ticket, &cx).is_pending());
        drop(worker);
        assert!(outcome.released.poll_done(&mut ticket, &cx).is_ready());
        assert!(weak.upgrade().is_none());
        assert!(outcome.released.poll_done(&mut ticket, &cx).is_ready());
    }
}
