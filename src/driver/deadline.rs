//! Driver waits on the same clock as the state that computes the deadline.

use std::future::Future;
use std::future::{pending, poll_fn};
use std::pin::pin;
use std::task::Poll;
use std::time::Instant;

use super::handle::Driver;
use crate::ClockDomain;

pub(super) async fn sleep<D: Driver>(clock: &ClockDomain, deadline: Option<Instant>) {
    match deadline {
        Some(at) => match clock.wait_until(at) {
            Some(wait) => wait.await,
            None => D::sleep_until(at).await,
        },
        None => pending().await,
    }
}

#[cfg(feature = "tokio")]
impl ClockDomain {
    /// Waits on this domain in the Tokio driver. An unrepresentable deadline
    /// (`None`) is unbounded.
    pub async fn sleep_until(&self, deadline: Option<Instant>) {
        sleep::<super::tokio::Tokio>(self, deadline).await;
    }
}

pub(super) fn earlier(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    a.into_iter().chain(b).min()
}

/// Lets an already-ready operation complete without registering a timer.
pub(super) async fn race<F: Future>(
    deadline: impl Future<Output = ()>,
    work: F,
) -> Option<F::Output> {
    let mut deadline = pin!(deadline);
    let mut work = pin!(work);
    poll_fn(|cx| {
        if let Poll::Ready(result) = work.as_mut().poll(cx) {
            Poll::Ready(Some(result))
        } else {
            deadline.as_mut().poll(cx).map(|()| None)
        }
    })
    .await
}

#[cfg(feature = "tokio")]
pub(super) fn timeout<F: Future>(
    clock: &ClockDomain,
    deadline: Option<Instant>,
    work: F,
) -> impl Future<Output = Option<F::Output>> {
    race(sleep::<super::tokio::Tokio>(clock, deadline), work)
}
