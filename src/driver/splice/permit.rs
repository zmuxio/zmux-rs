//! Ownership of an external limiter request before target admission.

use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::task::{Context, Poll};

use tokio::sync::{OwnedSemaphorePermit, Semaphore, oneshot};

use crate::proto::limit::{Limiter, Permit, refund};

pub(super) struct Grant {
    limiter: Arc<dyn Limiter>,
    refunded: Arc<AtomicU64>,
    left: u64,
}

impl Grant {
    fn new(limiter: Arc<dyn Limiter>, refunded: Arc<AtomicU64>, left: u64) -> Self {
        Self {
            limiter,
            refunded,
            left,
        }
    }

    pub(super) fn len(&self) -> u64 {
        self.left
    }

    pub(super) fn prepaid(&mut self) -> (&Arc<dyn Limiter>, &mut u64) {
        (&self.limiter, &mut self.left)
    }
}

impl Drop for Grant {
    fn drop(&mut self) {
        self.refunded.fetch_add(self.left, Ordering::Relaxed);
        refund(Some(&*self.limiter), self.left);
    }
}

pub(super) struct Requests {
    limiter: Arc<dyn Limiter>,
    refunded: Arc<AtomicU64>,
    reliable: Arc<Semaphore>,
    datagram: Arc<Semaphore>,
}

impl Requests {
    pub(super) fn new(
        limiter: Arc<dyn Limiter>,
        refunded: Arc<AtomicU64>,
        reliable: usize,
        datagram: usize,
    ) -> Self {
        Self {
            limiter,
            refunded,
            reliable: Arc::new(Semaphore::new(reliable)),
            datagram: Arc::new(Semaphore::new(datagram)),
        }
    }

    pub(super) fn refunded(&self) -> u64 {
        self.refunded.load(Ordering::Relaxed)
    }

    pub(super) fn try_exact(&self, bytes: u64) -> Option<Request> {
        let slot = self.datagram.clone().try_acquire_owned().ok()?;
        let limiter = self.limiter.clone();
        let refunded = self.refunded.clone();
        let (tx, rx) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            if tx.is_closed() {
                return;
            }
            let got =
                catch_unwind(AssertUnwindSafe(|| limiter.try_acquire(bytes, bytes))).unwrap_or(0);
            let grant = Grant::new(limiter, refunded, got);
            let grant = (got == bytes).then_some(grant);
            let _ = tx.send((grant, slot));
        });
        Some(Request(rx))
    }

    pub(super) fn acquire(&self, min: u64, max: u64) -> ReliableRequest {
        let slots = self.reliable.clone();
        let limiter = self.limiter.clone();
        let refunded = self.refunded.clone();
        Box::pin(async move {
            let slot = slots
                .acquire_owned()
                .await
                .expect("the limiter slots stay open");
            let (mut tx, rx) = oneshot::channel();
            tokio::spawn(async move {
                let limiter = MeasuredLimiter { limiter, refunded };
                let acquired = tokio::select! {
                    biased;
                    () = tx.closed() => return,
                    result = Permit::acquire(&limiter, min, max) => {
                        result.ok().map(Permit::take_all)
                    }
                };
                let grant = acquired.map(|n| Grant::new(limiter.limiter, limiter.refunded, n));
                let _ = tx.send((grant, slot));
            });
            rx.await.ok().and_then(|(grant, _slot)| grant)
        })
    }
}

/// A pending request owns its slot through callback completion and adoption or refund.
/// Dropping the receiver revokes publication. Any later grant stays with the worker.
pub(super) struct Request(oneshot::Receiver<(Option<Grant>, OwnedSemaphorePermit)>);

impl Request {
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Option<Grant>> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|result| result.ok().and_then(|(grant, _slot)| grant))
    }
}

pub(super) type ReliableRequest = Pin<Box<dyn Future<Output = Option<Grant>> + Send>>;

struct MeasuredLimiter {
    limiter: Arc<dyn Limiter>,
    refunded: Arc<AtomicU64>,
}

impl Limiter for MeasuredLimiter {
    fn poll_acquire(
        &self,
        cx: &mut Context<'_>,
        min: u64,
        max: u64,
    ) -> Poll<Result<u64, crate::LimitError>> {
        self.limiter.poll_acquire(cx, min, max)
    }

    fn try_acquire(&self, min: u64, max: u64) -> u64 {
        self.limiter.try_acquire(min, max)
    }

    fn refund(&self, n: u64) {
        self.refunded.fetch_add(n, Ordering::Relaxed);
        self.limiter.refund(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::sync::Notify;

    struct HeldLimiter {
        started: Notify,
        release: Mutex<Option<oneshot::Receiver<()>>>,
        calls: Mutex<Vec<u64>>,
        refunds: Mutex<Vec<u64>>,
    }

    impl Limiter for HeldLimiter {
        fn poll_acquire(
            &self,
            _: &mut Context<'_>,
            _: u64,
            _: u64,
        ) -> Poll<Result<u64, crate::LimitError>> {
            panic!("datagram requests are nonblocking")
        }

        fn try_acquire(&self, min: u64, max: u64) -> u64 {
            assert_eq!(min, max);
            self.calls.lock().unwrap().push(max);
            self.started.notify_one();
            if let Some(release) = self.release.lock().unwrap().take() {
                let _ = release.blocking_recv();
                max
            } else {
                1
            }
        }

        fn refund(&self, n: u64) {
            self.refunds.lock().unwrap().push(n);
        }
    }

    #[tokio::test]
    async fn revocation_retains_cleanup_slot_and_returns_short_grants_once() {
        let (resume, release) = oneshot::channel();
        let limiter = Arc::new(HeldLimiter {
            started: Notify::new(),
            release: Mutex::new(Some(release)),
            calls: Mutex::default(),
            refunds: Mutex::default(),
        });
        let requests = Requests::new(limiter.clone(), Arc::default(), 1, 1);
        let request = requests.try_exact(3).unwrap();
        limiter.started.notified().await;
        drop(request);
        assert!(requests.try_exact(5).is_none());
        assert_eq!(requests.refunded(), 0);
        resume.send(()).unwrap();

        let slot = requests.datagram.acquire().await.unwrap();
        assert_eq!(requests.refunded(), 3);
        drop(slot);
        let mut request = requests.try_exact(5).unwrap();
        assert!(std::future::poll_fn(|cx| request.poll(cx)).await.is_none());
        assert_eq!(requests.refunded(), 4);
        assert_eq!(*limiter.calls.lock().unwrap(), [3, 5]);
        assert_eq!(*limiter.refunds.lock().unwrap(), [3, 1]);
    }
}
