//! Buffers of discarded streams, reused by the next ones.

use bytes::BytesMut;

use super::super::stream::SendBuf;
use super::super::tuner::Tuner;

/// Buffers of discarded streams, kept for the next streams so that a
/// stream per request does not allocate them each time.
#[derive(Debug, Default)]
pub(in super::super) struct Spare {
    send: Vec<SendBuf>,
    recv: Vec<BytesMut>,
    /// Auto-tuning state of discarded streams, cleared: the boxes
    /// themselves are what the streams take, without allocating.
    #[allow(clippy::vec_box)]
    tuners: Vec<Box<Tuner>>,
    /// A large receive buffer a stream gave up when it emptied, for the
    /// next stream data: a transfer keeps reusing it, and streams that
    /// went idle keep nothing.
    drained: Option<BytesMut>,
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

    pub(super) fn put_recv(&mut self, mut buf: BytesMut) {
        let cap = buf.capacity();
        if cap > 0 && cap <= Self::CAPACITY && self.recv.len() < Self::COUNT {
            buf.clear();
            self.recv.push(buf);
        }
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
    pub(super) fn tuner(&mut self) -> Box<Tuner> {
        self.tuners.pop().unwrap_or_default()
    }

    pub(super) fn send(&mut self) -> SendBuf {
        self.send.pop().unwrap_or_default()
    }

    pub(super) fn recv(&mut self) -> BytesMut {
        self.recv.pop().unwrap_or_default()
    }

    /// Keeps an emptied receive buffer (the last one given up).
    pub(in super::super) fn put_drained(&mut self, mut buf: BytesMut) {
        buf.clear();
        self.drained = Some(buf);
    }

    /// The emptied receive buffer kept, if any.
    pub(in super::super) fn take_drained(&mut self) -> Option<BytesMut> {
        self.drained.take()
    }

    /// Heap bytes held.
    pub(super) fn heap_bytes(&self) -> usize {
        self.send.iter().map(SendBuf::capacity).sum::<usize>()
            + self.recv.iter().map(BytesMut::capacity).sum::<usize>()
            + self.drained.as_ref().map_or(0, BytesMut::capacity)
            + self.tuners.len() * std::mem::size_of::<Tuner>()
    }
}
