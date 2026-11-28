//! An injected clock with a registration signal for synchronization.

use std::time::{Duration, Instant};

use super::{ClockDomain, MonotonicClock};
use tokio::sync::{broadcast, watch};

#[derive(Clone)]
pub(super) struct ManualClock {
    time: watch::Sender<Instant>,
    timers: broadcast::Sender<Instant>,
}

impl ManualClock {
    pub(super) fn domain(offset: Duration) -> (Self, ClockDomain) {
        let now = Instant::now();
        let clock = Self {
            time: watch::Sender::new(now.checked_sub(offset).unwrap_or(now)),
            timers: broadcast::Sender::new(32),
        };
        let domain = ClockDomain::with_source(clock.clone());
        (clock, domain)
    }

    #[allow(
        dead_code,
        reason = "some test binaries synchronize their clock to carrier events"
    )]
    pub(super) fn registrations(&self) -> broadcast::Receiver<Instant> {
        self.timers.subscribe()
    }

    pub(super) fn advance(&self, elapsed: Duration) {
        self.time.send_modify(|now| *now += elapsed);
    }
}

impl MonotonicClock for ManualClock {
    fn now(&self) -> Instant {
        *self.time.borrow()
    }

    fn sleep_until(
        &self,
        deadline: Instant,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        let mut clock = self.time.subscribe();
        Box::pin(async move {
            let _ = clock.wait_for(|&now| now >= deadline).await;
        })
    }

    fn timer_registered(&self, deadline: Instant) {
        let _ = self.timers.send(deadline);
    }
}
