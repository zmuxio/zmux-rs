//! Independently owned, bounded best-effort splice samples.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use bytes::Bytes;
use tokio::sync::Notify;

use crate::{Chunk, proto::session::Backing};

use super::{
    SpliceBudget, SpliceKind, SpliceMeta,
    hooks::{Payload, Roots},
};

/// A sampled input offered to a diagnostic consumer.
#[derive(Debug)]
pub struct SpliceSample {
    /// Unit shape.
    pub kind: SpliceKind,
    /// Local sequence.
    pub sequence: u64,
    /// Admission generation.
    pub generation: u64,
    /// At most the configured number of payload bytes.
    pub prefix: Bytes,
}

/// Storage used for an independent mirror sample.
#[derive(Clone, Copy, Debug, Default)]
pub enum SpliceMirrorMode {
    /// Copy the selected prefix into independent storage.
    #[default]
    Copy,
    /// Share a contiguous prefix when doing so cannot prolong a receive loan.
    Lease,
}

/// Configuration and publisher endpoint of a bounded diagnostic mirror.
#[derive(Clone, Debug)]
pub struct SpliceMirror(Arc<Mirror>);

/// The receiving endpoint of a bounded splice mirror.
#[derive(Debug)]
pub struct SpliceMirrorReceiver(Arc<Mirror>);

#[derive(Debug)]
struct Mirror {
    items: usize,
    bytes: usize,
    prefix: usize,
    mode: SpliceMirrorMode,
    ready: Notify,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    queue: VecDeque<(SpliceSample, Backing)>,
    publishers: usize,
    closed: bool,
}

impl Mirror {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn close(&self, state: &mut State) {
        state.closed = true;
        state.queue.clear();
        self.ready.notify_waiters();
    }
}

impl SpliceMirror {
    /// Creates a diagnostic mirror that copies up to `prefix` bytes per sample.
    ///
    /// # Errors
    ///
    /// The item capacity is zero or the total backing bound overflows.
    pub fn channel(
        items: usize,
        prefix: usize,
    ) -> Result<(Self, SpliceMirrorReceiver), SpliceBudget> {
        let bytes = items.checked_mul(prefix).ok_or(SpliceBudget)?;
        Self::bounded(items, bytes, prefix, SpliceMirrorMode::Copy)
    }

    /// Creates a mirror with independent item and distinct-root bounds.
    ///
    /// # Errors
    ///
    /// The item capacity is zero.
    pub fn bounded(
        items: usize,
        bytes: usize,
        prefix: usize,
        mode: SpliceMirrorMode,
    ) -> Result<(Self, SpliceMirrorReceiver), SpliceBudget> {
        if items == 0 {
            return Err(SpliceBudget);
        }
        let mirror = Arc::new(Mirror {
            items,
            bytes,
            prefix,
            mode,
            ready: Notify::new(),
            state: Mutex::default(),
        });
        Ok((Self(mirror.clone()), SpliceMirrorReceiver(mirror)))
    }

    pub(super) fn attach(&self) -> MirrorPublisher {
        self.0.lock().publishers += 1;
        MirrorPublisher(self.0.clone())
    }
}

impl SpliceMirrorReceiver {
    /// Takes the next available sample, releasing its mirror capacity.
    ///
    /// Returns `None` after the mirror shuts down.
    pub async fn recv(&mut self) -> Option<SpliceSample> {
        loop {
            let next = self.0.ready.notified();
            {
                let mut state = self.0.lock();
                if let Some((sample, _)) = state.queue.pop_front() {
                    return Some(sample);
                }
                if state.closed {
                    return None;
                }
            }
            next.await;
        }
    }
}

impl Drop for SpliceMirrorReceiver {
    fn drop(&mut self) {
        self.0.close(&mut self.0.lock());
    }
}

pub(super) struct MirrorPublisher(Arc<Mirror>);

impl Drop for MirrorPublisher {
    fn drop(&mut self) {
        let mut state = self.0.lock();
        state.publishers -= 1;
        if state.publishers == 0 {
            self.0.close(&mut state);
        }
    }
}

impl MirrorPublisher {
    pub(super) fn publish(&self, meta: &SpliceMeta<'_>, payload: &Payload) -> Option<usize> {
        let mut state = self.0.lock();
        if state.closed || state.queue.len() == self.0.items {
            return None;
        }
        let mut roots = Roots::default();
        for &(_, root) in &state.queue {
            roots.add_backing(root, self.0.bytes).ok()?;
        }
        let len = payload.len.min(self.0.prefix);
        let (chunk, copied) = match self.0.mode {
            SpliceMirrorMode::Copy => {
                roots.reserve(len, self.0.bytes).ok()?;
                let mut copy = vec![0; len].into_boxed_slice();
                let mut offset = 0;
                for segment in &payload.pieces {
                    let n = segment.len().min(len - offset);
                    copy[offset..offset + n].copy_from_slice(&segment[..n]);
                    offset += n;
                }
                (Chunk::from(copy.into_vec()), len)
            }
            SpliceMirrorMode::Lease if len != 0 => {
                if payload.receive_view {
                    return None;
                }
                let first = payload.pieces.first()?;
                roots.add(first, self.0.bytes).ok()?;
                (first.slice(..first.len().min(len)), 0)
            }
            SpliceMirrorMode::Lease => (Chunk::new(), 0),
        };
        let root = chunk.backing;
        let sample = SpliceSample {
            kind: meta.kind,
            sequence: meta.sequence,
            generation: meta.generation,
            prefix: chunk.into_bytes(),
        };
        state.queue.push_back((sample, root));
        drop(state);
        self.0.ready.notify_one();
        Some(copied)
    }
}
