//! Buffers of discarded streams, reused by the next ones.

use super::super::stream::SendBuf;
use super::super::tuner::Tuner;

/// Buffers of discarded streams, kept for the next streams so that a
/// stream per request does not allocate them each time.
#[derive(Debug, Default)]
pub(in super::super) struct Spare {
    send: Vec<SendBuf>,
    /// Auto-tuning state of discarded streams, cleared: the boxes
    /// themselves are what the streams take, without allocating.
    #[allow(clippy::vec_box)]
    tuners: Vec<Box<Tuner>>,
}

impl Spare {
    /// Buffers kept, at most.
    const COUNT: usize = 8;
    /// The largest buffer kept, in bytes.
    const CAPACITY: usize = 4096;

    pub(super) fn put_send(&mut self, mut buf: SendBuf) {
        let cap = buf.capacity();
        if cap > 0 && cap <= Self::CAPACITY && self.send.len() < Self::COUNT {
            buf.clear();
            self.send.push(buf);
        }
    }

    #[cfg(feature = "tokio")]
    pub(super) fn release_send(&mut self) {
        self.send = Vec::new();
    }

    /// Keeps a discarded stream's auto-tuning state, cleared.
    pub(super) fn put_tuner(&mut self, t: Option<Box<Tuner>>) {
        if let Some(t) = t
            && self.tuners.len() < Self::COUNT
        {
            self.tuners.push(t);
        }
    }

    /// Auto-tuning state for a stream, cleared.
    #[allow(
        clippy::unnecessary_box_returns,
        reason = "the spare pool recycles boxed tuners; the box is what streams hold"
    )]
    pub(super) fn tuner(&mut self) -> Box<Tuner> {
        self.tuners.pop().unwrap_or_default()
    }

    pub(super) fn send(&mut self) -> SendBuf {
        self.send.pop().unwrap_or_default()
    }

    /// Heap bytes held.
    pub(super) fn heap_bytes(&self) -> usize {
        self.send.iter().map(SendBuf::capacity).sum::<usize>()
            + self.tuners.len() * size_of::<Tuner>()
    }
}
