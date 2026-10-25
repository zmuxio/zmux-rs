//! The pipe I/O both drivers share, without I/O of its own: a pipe's
//! outbound batch with its write calls, and the session timer's handling.
//! The tokio driver and the std driver decide only when to call it, and do
//! the reads and writes with their carriers.

use std::io::IoSlice;
use std::time::{Duration, Instant};

use super::CallLimit;
use crate::proto::record::Framing;
use crate::proto::session::{
    DEFAULT_BATCH, LaneId, PipeWrite, SessionCore as Core, Transmit, TransmitBuf, WRITE_CALL_MIN,
};

/// How long the last batches of a closed session may take to be written
/// before the carriers are ended.
pub(crate) const FINAL_WRITE: Duration = Duration::from_secs(1);

/// A deadline as a timer is armed for it: never in the past, which would
/// fire at once forever.
pub(crate) fn timer_deadline(deadline: Option<Instant>, now: Instant) -> Option<Instant> {
    deadline.map(|d| d.max(now + Duration::from_millis(1)))
}

/// Fires the core's timers when due; returns whether that changed the next
/// deadline (a deadline that stays due changed nothing).
pub(crate) fn fire_timers(core: &mut Core, now: Instant) -> bool {
    let due = core.poll_timeout();
    if !due.is_some_and(|t| t <= now) {
        return false;
    }
    core.handle_timeout(now);
    core.poll_timeout() != due
}

/// How a driver's write calls behave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) enum Calls {
    /// Non-blocking calls that may take part of a batch.
    NonBlocking,
    /// Blocking calls on a writer thread: a call's bytes are handed on
    /// when it returns.
    Blocking,
}

/// A pipe's write calls that the core has not heard of, as the one
/// write-progress report both drivers send:
/// the std driver as its blocking calls start and return, the tokio driver
/// for the calls of a round, in the next critical section. Calls in between
/// merge (the first start, the last end, the bytes of all, the last
/// outcome), and a report that changes nothing the core holds (a call
/// that returned while the carrier took everything, a refusal again) is
/// not sent: the core's write-progress state is a call in progress, a
/// refusing carrier, or neither.
#[derive(Debug, Default)]
pub(crate) struct Progress {
    pending: Option<Pending>,
    /// What the reports sent left the core with.
    told: Told,
    /// The bytes of the last call that took any, across reports: what a
    /// carrier with a low-water mark may hold beyond the mark when a later
    /// call finds it full.
    last_added: u64,
}

#[derive(Debug, Clone, Copy)]
struct Pending {
    start: Instant,
    end: Option<Instant>,
    bytes: u64,
    refused: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Told {
    #[default]
    Open,
    Call,
    Refused,
}

impl Progress {
    /// A blocking call handed `bytes` to the carrier at `start`.
    #[cfg_attr(not(feature = "blocking"), allow(dead_code))]
    pub(crate) fn started(&mut self, start: Instant, bytes: usize) {
        self.pending = Some(Pending {
            start,
            end: None,
            bytes: bytes as u64,
            refused: false,
        });
    }

    /// A call that started at `start` returned at `end`: the carrier took
    /// `bytes`, and `refused` the rest.
    pub(crate) fn returned(&mut self, start: Instant, end: Instant, bytes: usize, refused: bool) {
        let bytes = bytes as u64;
        if bytes > 0 {
            self.last_added = bytes;
        }
        let p = match &mut self.pending {
            // A later call of the same round.
            Some(p) if p.end.is_some() => {
                p.bytes += bytes;
                p
            }
            pending => pending.insert(Pending {
                start,
                end: None,
                bytes,
                refused,
            }),
        };
        p.end = Some(end);
        p.refused = refused;
    }

    /// Hands the report to the core, under its lock, when it changes what
    /// the core holds; returns whether it did. U is 0 unless the carrier
    /// refused bytes; then, with a low-water mark (`low_water`), up to the
    /// mark the core gives it plus what the last call added (MULTIPATH.md
    /// Section 7.1).
    pub(crate) fn report(
        &mut self,
        core: &mut Core,
        id: impl Into<LaneId>,
        low_water: bool,
        now: Instant,
    ) -> bool {
        let id = id.into();
        let Some(p) = self.pending.take() else {
            return false;
        };
        let told = match p.end {
            None => Told::Call,
            Some(_) if p.refused => Told::Refused,
            Some(_) => Told::Open,
        };
        if told == self.told && told != Told::Call {
            return false;
        }
        self.told = told;
        let write = match p.end {
            None => PipeWrite::started(p.start, p.bytes),
            Some(end) => {
                let unsent = self.unsent(p.refused, low_water.then(|| core.notsent_lowat(id.pipe)));
                PipeWrite::returned(p.start, end, p.bytes, unsent, p.refused)
            }
        };
        core.pipe_write(id, write, now);
        true
    }

    /// U of a call that ended: 0 unless the carrier refused bytes; then,
    /// with a low-water mark `mark`, the mark plus what the last call that
    /// took bytes added, however many reports ago it was.
    fn unsent(&self, refused: bool, mark: Option<u64>) -> u64 {
        match mark {
            Some(m) if refused => m + self.last_added,
            _ => 0,
        }
    }
}

/// A pipe's outbound batch: taken from the core under its lock, written in
/// bounded calls without it.
pub(crate) struct Outbound {
    framing: Framing,
    calls: Calls,
    out: TransmitBuf,
    /// Bytes of the batch already written.
    pos: usize,
    /// The batch ends with a shutdown of the write side.
    shutdown: bool,
    /// The most bytes one write call hands the carrier.
    call_limit: usize,
    /// `call_limit` as computed under the core lock, reused within the
    /// latency budget.
    cached: CallLimit,
    /// One message of a message-framed carrier, reused.
    msg: Vec<u8>,
}

impl Outbound {
    pub(crate) fn new(framing: Framing, calls: Calls) -> Self {
        Self {
            framing,
            calls,
            out: TransmitBuf::default(),
            pos: 0,
            shutdown: false,
            call_limit: WRITE_CALL_MIN,
            cached: CallLimit::default(),
            msg: Vec::new(),
        }
    }

    pub(crate) fn framing(&self) -> Framing {
        self.framing
    }

    /// The batch, whole (written or not).
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn batch(&self) -> &TransmitBuf {
        &self.out
    }

    /// Where the unwritten rest of the batch starts.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn pos(&self) -> usize {
        self.pos
    }

    /// Bytes of the batch left to write.
    pub(crate) fn left(&self) -> usize {
        self.out.len() - self.pos
    }

    /// Nothing left to write.
    pub(crate) fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// The batch ends with a shutdown of the write side, still to do.
    pub(crate) fn shutdown_pending(&self) -> bool {
        self.shutdown
    }

    /// The shutdown was done (or the side closed).
    pub(crate) fn shutdown_done(&mut self) {
        self.shutdown = false;
    }

    /// Drops the batch: the write side is closed.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn clear(&mut self) {
        self.out.clear();
        self.pos = 0;
        self.shutdown = false;
    }

    /// The batch's buffers go while the pipe is idle.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn release(&mut self) {
        self.out.shrink();
        self.msg = Vec::new();
    }

    /// The batch's storage is that of a small batch.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn is_small(&self) -> bool {
        self.out.is_small()
    }

    /// Heap bytes held.
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn capacity(&self) -> usize {
        self.out.capacity() + self.msg.capacity()
    }

    /// Takes the next batch of pipe `id` from the core, under its lock,
    /// when the last one is done; `input`: reads deliver data, so batches
    /// are smaller and do not hold the reads back. Returns whether there is
    /// something to write or a shutdown to do.
    pub(crate) fn take_batch(
        &mut self,
        core: &mut Core,
        id: impl Into<LaneId>,
        now: Instant,
        input: bool,
    ) -> bool {
        let id = id.into();
        if !self.out.is_empty() || self.shutdown || !core.wants_write(id) {
            return false;
        }
        let blocking = self.calls == Calls::Blocking;
        // A smaller batch while reads deliver data, and write calls bounded
        // while latency-sensitive work waits (whatever the carrier is: these
        // use zmux's own state and rate estimate).
        let batch = match self.calls {
            Calls::NonBlocking => core.batch_limit(id.pipe, DEFAULT_BATCH, input),
            Calls::Blocking => DEFAULT_BATCH,
        };
        self.out.set_max_len(batch);
        if self.framing == Framing::Records {
            // One message per call, built within the bound.
            let limit = core.write_call_limit(id.pipe, batch, blocking, input, now);
            self.out.set_max_message(limit);
        }
        let t = core.poll_transmit(id, now, &mut self.out);
        self.pos = 0;
        self.shutdown = t == Transmit::Shutdown;
        let left = self.out.len();
        let limit = core.write_call_limit(id.pipe, left, blocking, input, now);
        self.call_limit = self
            .cached
            .set(left, limit, input, now, core.latency_budget());
        !self.out.is_empty() || self.shutdown
    }

    /// The limit of the next write call: the cached one while it holds,
    /// else `compute` (under the core lock) gives the core's limit and the
    /// session's latency budget for the bytes left.
    pub(crate) fn call_limit(
        &mut self,
        input: bool,
        now: Instant,
        compute: impl FnOnce(usize) -> (usize, Duration),
    ) -> usize {
        let left = self.left();
        if self.framing == Framing::Records || left <= WRITE_CALL_MIN {
            // Whole messages, or a call within the floor anyway.
            return self.call_limit;
        }
        // The first call of a batch keeps the decision made when it was
        // taken, which saw this round's input, while that decision holds
        // (within the latency budget).
        let input = input && self.pos > 0;
        self.call_limit = match self.cached.get(left, input, now) {
            Some(limit) => limit,
            None => {
                let (limit, budget) = compute(left);
                self.cached.set(left, limit, input, now, budget)
            }
        };
        self.call_limit
    }

    /// The cached call limit (for writes with a budget of their own).
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) fn current_call_limit(&self) -> usize {
        self.call_limit
    }

    /// The next call's bytes of a byte stream: at most `limit` of the rest
    /// of the batch, as slices.
    pub(crate) fn slices<'a>(&'a self, limit: usize, slices: &mut [IoSlice<'a>]) -> usize {
        self.out.io_slices_from(self.pos, limit, slices)
    }

    /// The next message of a message-framed carrier, whole.
    pub(crate) fn message(&mut self) -> &[u8] {
        let mut at = 0;
        let mut len = self.out.len() - self.pos;
        for &l in self.out.message_lens() {
            if at == self.pos {
                len = l;
                break;
            }
            at += l;
        }
        self.msg.clear();
        let mut skip = self.pos;
        for c in self.out.chunks() {
            if skip >= c.len() {
                skip -= c.len();
                continue;
            }
            let take = (c.len() - skip).min(len - self.msg.len());
            self.msg.extend_from_slice(&c[skip..skip + take]);
            skip = 0;
            if self.msg.len() == len {
                break;
            }
        }
        &self.msg
    }

    /// A write call took `n` bytes; returns whether the batch is done.
    pub(crate) fn written(&mut self, n: usize) -> bool {
        self.pos += n;
        if self.pos >= self.out.len() {
            self.out.clear();
            self.pos = 0;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::session::{Config, PipeId, RoleConfig};

    #[test]
    fn progress_reports_what_changes_the_cores_write_state() {
        let now = Instant::now();
        let mut core = Core::new(Config::default(), RoleConfig::Initiator, None, now).unwrap();
        let id = PipeId(0);
        core.attach_pipe(id, Framing::ByteStream, now);
        let writable = |c: &Core| c.pipe_info(id).is_some_and(|p| p.writable);
        let mut p = Progress::default();
        // Non-blocking calls that took everything: nothing to tell.
        p.returned(now, now, 100, false);
        assert!(!p.report(&mut core, id, false, now));
        // A refusal, merged with the call of the round before it.
        p.returned(now, now, 100, false);
        p.returned(now, now, 0, true);
        assert!(p.report(&mut core, id, true, now));
        assert!(!writable(&core));
        // Refused again: nothing new.
        p.returned(now, now, 0, true);
        assert!(!p.report(&mut core, id, true, now));
        p.returned(now, now, 10, false);
        assert!(p.report(&mut core, id, true, now));
        assert!(writable(&core));
        // A blocking call: reported as it starts and as it returns.
        p.started(now, 1000);
        assert!(p.report(&mut core, id, false, now));
        p.returned(now, now, 1000, false);
        assert!(p.report(&mut core, id, false, now));
        assert!(writable(&core));
    }

    /// A carrier with a low-water mark that refuses bytes holds the mark
    /// plus what the last call that took bytes added, also when that call
    /// was in an earlier round whose report changed nothing.
    #[test]
    fn the_unsent_bytes_count_the_last_call_of_an_earlier_round() {
        let now = Instant::now();
        let mut core = Core::new(Config::default(), RoleConfig::Initiator, None, now).unwrap();
        let id = PipeId(0);
        core.attach_pipe(id, Framing::ByteStream, now);
        let mut p = Progress::default();
        p.returned(now, now, 16_384, false);
        assert!(!p.report(&mut core, id, true, now));
        p.returned(now, now, 0, true);
        assert_eq!(p.unsent(true, Some(4096)), 4096 + 16_384);
        assert_eq!(p.unsent(true, None), 0);
        assert!(p.report(&mut core, id, true, now));
    }
}
