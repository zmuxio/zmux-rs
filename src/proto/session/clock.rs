//! Identity and monotonic time shared by controller and session.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

/// Supplies monotonic time and deadline wakeups for a clock domain.
pub trait MonotonicClock: Send + Sync + 'static {
    /// Reads this clock. Values must never decrease. Implementations must be fast
    /// and must not call into a session.
    fn now(&self) -> Instant;

    /// Completes when this clock reaches the deadline. A pending poll must
    /// arrange for the task to be woken when the deadline is reached.
    fn sleep_until(&self, deadline: Instant) -> Pin<Box<dyn Future<Output = ()> + Send + '_>>;

    /// Called once per timer, just after its first pending poll registered
    /// its wakeup. A test clock can use this signal to let its caller advance
    /// time. A timer that completes on its first poll needs no registration.
    /// This runs on the timer's polling thread and must return promptly.
    fn timer_registered(&self, _deadline: Instant) {}
}

#[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
pub(crate) type ClockWait = Pin<Box<dyn Future<Output = ()> + Send>>;

struct Domain {
    source: Option<Arc<dyn MonotonicClock>>,
}

/// Identifies a shared monotonic clock domain. Clones share the source and identity.
#[derive(Clone, Default)]
pub struct ClockDomain(Option<Arc<Domain>>);

impl std::fmt::Debug for ClockDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClockDomain").finish_non_exhaustive()
    }
}

impl PartialEq for ClockDomain {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Eq for ClockDomain {}

impl ClockDomain {
    /// Creates a distinct domain using the driver's monotonic clock.
    #[must_use]
    pub fn new() -> Self {
        Self(Some(Arc::new(Domain { source: None })))
    }

    /// Creates a distinct domain with its own monotonic time and deadline wakeups.
    #[must_use]
    pub fn with_source(source: impl MonotonicClock) -> Self {
        Self(Some(Arc::new(Domain {
            source: Some(Arc::new(source)),
        })))
    }

    /// Reads the monotonic clock for this domain.
    #[must_use]
    pub fn now(&self) -> Instant {
        self.now_with(|| {
            #[cfg(feature = "tokio")]
            {
                ::tokio::time::Instant::now().into_std()
            }
            #[cfg(not(feature = "tokio"))]
            Instant::now()
        })
    }

    fn source(&self) -> Option<&dyn MonotonicClock> {
        self.0.as_ref()?.source.as_deref()
    }

    #[cfg(all(any(feature = "tokio", feature = "blocking"), not(loom)))]
    pub(crate) fn wait_until(&self, deadline: Instant) -> Option<ClockWait> {
        let source = self.0.as_ref()?.source.as_ref()?.clone();
        Some(Box::pin(async move {
            let mut wait = source.sleep_until(deadline);
            let mut registered = false;
            std::future::poll_fn(|cx| {
                let poll = wait.as_mut().poll(cx);
                if poll.is_pending() && !registered {
                    registered = true;
                    source.timer_registered(deadline);
                }
                poll
            })
            .await;
        }))
    }

    pub(crate) fn now_with(&self, fallback: impl FnOnce() -> Instant) -> Instant {
        self.source().map_or_else(fallback, MonotonicClock::now)
    }
}
