//! One completion group for a carrier and all its teardown obligations.
use super::wake::WakeList;
use crate::proto::session::PipeError;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// The protocol outcome survives retirement while a handle or carrier still uses it.
#[derive(Default)]
pub(crate) struct PipeOutcome {
    /// Assigned under the same session lock as cancellation, before installation.
    pub(super) id: OnceLock<crate::PipeId>,
    pub(super) join: OnceLock<Result<(), PipeError>>,
    pub(super) released: super::wait::PipeDone,
    pub(super) sample: OnceLock<Arc<super::carrier_stats::Cache>>,
}

/// Held by the carrier and each worker that can outlive its protocol state.
#[derive(Default)]
pub(crate) struct Attachment {
    outcome: OnceLock<Arc<PipeOutcome>>,
    sample: OnceLock<super::carrier_stats::Registration>,
    #[cfg(feature = "tokio")]
    retiring: OnceLock<Arc<super::wait::PipeDone>>,
    members: Mutex<Option<Box<Members>>>,
}

#[derive(Default)]
struct Members {
    resources: Vec<Box<dyn Send>>,
    #[cfg(feature = "tokio")]
    workers: Vec<std::sync::Weak<Worker>>,
}

#[cfg(feature = "tokio")]
type Worker = Mutex<Vec<Arc<Attachment>>>;

impl Attachment {
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
        let members = members.get_or_insert_default();
        if members.workers.len() == members.workers.capacity() {
            members.workers.retain(|w| w.strong_count() != 0);
        }
        members.workers.push(worker);
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
            let Some(members) = members.as_ref() else {
                return;
            };
            members.workers.clone()
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

    /// Releases an owned resource before notifying external waiters. No host
    /// code runs while registering the obligation.
    pub(crate) fn hold(&self, resource: impl Send + 'static) {
        self.members
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
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
        self.members
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
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
