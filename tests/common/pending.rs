//! One-poll readiness checks for tests that control when a wait resolves.

use std::future::{Future, poll_fn};
use std::pin::Pin;
use std::task::Poll;

pub(super) async fn is_pending<F: Future>(operation: Pin<&mut F>) -> bool {
    poll_once(operation).await.is_pending()
}

pub(super) async fn poll_once<F: Future>(mut operation: Pin<&mut F>) -> Poll<F::Output> {
    poll_fn(|cx| Poll::Ready(operation.as_mut().poll(cx))).await
}
