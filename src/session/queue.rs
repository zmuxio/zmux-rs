use super::liveness::note_blocked_write_locked;
use super::state::{ensure_projected_session_memory_cap, fail_session_with_close};
use super::types::WriterQueueStats;
use super::types::{Inner, WriteJob};
use crate::error::{Error, ErrorCode, Result};
use crate::frame::{Frame, FrameType, FRAME_FLAG_OPEN_METADATA};
use crate::payload::{
    build_code_payload, parse_data_payload_metadata_offset, parse_priority_update_metadata,
};
use crate::protocol::{EXT_PRIORITY_UPDATE, METADATA_STREAM_GROUP, METADATA_STREAM_PRIORITY};
use crate::varint::{append_varint_reserved, parse_varint, varint_len};
use std::collections::{hash_map::Entry, HashMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const MAX_CONDVAR_TIMED_WAIT: Duration = Duration::from_secs(3600);
const MAX_WRITE_BATCH_FRAMES: usize = crate::config::DEFAULT_WRITE_BATCH_MAX_FRAMES;
const MAX_INITIAL_QUEUE_SCRATCH_RESERVE: usize = 64;
const FRAME_QUEUE_OVERHEAD_BYTES: usize = 1;
const RETAINED_DATA_STREAM_COST_CAP: usize = 64;
const SHRINK_DATA_STREAM_COST_CAP: usize = 4096;
const DATA_STREAM_COST_SHRINK_FACTOR: usize = 8;
const LANE_SPARSE_SHRINK_FACTOR: usize = 4;

#[derive(Debug)]
pub(super) struct WriteQueue {
    state: Mutex<WriteQueueState>,
    not_empty: Condvar,
    not_full: Condvar,
    max_bytes: usize,
    urgent_max_bytes: usize,
    session_data_max_bytes: usize,
    per_stream_data_max_bytes: usize,
    pending_control_max_bytes: usize,
    pending_priority_max_bytes: usize,
    max_batch_bytes: usize,
    max_batch_frames: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WriteQueueLimits {
    pub(super) max_bytes: usize,
    pub(super) urgent_max_bytes: usize,
    pub(super) session_data_max_bytes: usize,
    pub(super) per_stream_data_max_bytes: usize,
    pub(super) pending_control_max_bytes: usize,
    pub(super) pending_priority_max_bytes: usize,
    pub(super) max_batch_bytes: usize,
    pub(super) max_batch_frames: usize,
}

#[derive(Debug, Default)]
struct WriteQueueState {
    urgent_jobs: VecDeque<WriteJob>,
    ordinary_jobs: VecDeque<WriteJob>,
    queued_bytes: usize,
    urgent_queued_bytes: usize,
    data_queued_bytes: usize,
    data_queued_by_stream: HashMap<u64, usize>,
    pending_control_bytes: usize,
    pending_priority_bytes: usize,
    closed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueLane {
    Urgent,
    Ordinary,
}

#[cfg(test)]
pub(super) enum WriteQueuePop {
    Batch(Vec<WriteJob>),
    TimedOut,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteQueuePopStatus {
    Batch,
    TimedOut,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoalesceKey {
    PriorityUpdate { stream_id: u64 },
    MaxData { stream_id: u64 },
    Blocked { stream_id: u64 },
    GoAway,
}

#[derive(Debug, Clone)]
struct QueueCost {
    queued: usize,
    urgent: usize,
    data: DataCosts,
    pending_control: usize,
    pending_priority: usize,
}

#[derive(Debug, Clone, Default)]
struct DataCosts {
    total: usize,
    first: Option<(u64, usize)>,
    rest: Vec<(u64, usize)>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(super) struct StreamDiscardStats {
    pub(super) removed_frames: usize,
    pub(super) data_frames: usize,
    pub(super) data_bytes: usize,
    pub(super) terminal_frames: usize,
}

impl StreamDiscardStats {
    #[inline]
    fn add_frame(&mut self, frame: &Frame) {
        self.removed_frames = self.removed_frames.saturating_add(1);
        if frame.frame_type == FrameType::Data {
            self.data_frames = self.data_frames.saturating_add(1);
            self.data_bytes = self.data_bytes.saturating_add(frame_data_app_bytes(frame));
        }
        if matches!(
            frame.frame_type,
            FrameType::Abort | FrameType::Reset | FrameType::StopSending
        ) {
            self.terminal_frames = self.terminal_frames.saturating_add(1);
        }
    }

    #[inline]
    fn add(&mut self, other: Self) {
        self.removed_frames = self.removed_frames.saturating_add(other.removed_frames);
        self.data_frames = self.data_frames.saturating_add(other.data_frames);
        self.data_bytes = self.data_bytes.saturating_add(other.data_bytes);
        self.terminal_frames = self.terminal_frames.saturating_add(other.terminal_frames);
    }

    #[inline]
    pub(super) fn removed_any(self) -> bool {
        self.removed_frames != 0
    }
}

#[inline]
fn frame_data_app_bytes(frame: &Frame) -> usize {
    if frame.frame_type != FrameType::Data {
        return 0;
    }
    let payload_len = frame.payload.len();
    if frame.flags & FRAME_FLAG_OPEN_METADATA == 0 {
        return payload_len;
    }
    let offset = match parse_data_payload_metadata_offset(&frame.payload, frame.flags) {
        Ok((_, _, offset)) => offset,
        Err(_) => 0,
    };
    payload_len - offset
}

impl DataCosts {
    #[inline]
    fn is_empty(&self) -> bool {
        self.total == 0
    }

    #[inline]
    fn total(&self) -> usize {
        self.total
    }

    #[inline]
    fn add(&mut self, stream_id: u64, bytes: usize) {
        self.total = self.total.saturating_add(bytes);
        if let Some((id, existing)) = self.first.as_mut() {
            if *id == stream_id {
                *existing = existing.saturating_add(bytes);
                return;
            }
        } else {
            self.first = Some((stream_id, bytes));
            return;
        }
        for (id, existing) in &mut self.rest {
            if *id == stream_id {
                *existing = existing.saturating_add(bytes);
                return;
            }
        }
        self.rest.push((stream_id, bytes));
    }

    #[inline]
    fn get(&self, stream_id: u64) -> usize {
        if let Some((existing_stream_id, bytes)) = self.first {
            if existing_stream_id == stream_id {
                return bytes;
            }
        }
        for &(id, bytes) in &self.rest {
            if id == stream_id {
                return bytes;
            }
        }
        0
    }

    #[inline]
    fn iter(&self) -> impl Iterator<Item = (u64, usize)> + '_ {
        self.first.iter().copied().chain(self.rest.iter().copied())
    }
}

impl WriteQueue {
    pub(super) fn new(limits: WriteQueueLimits) -> Self {
        Self {
            state: Mutex::new(WriteQueueState::default()),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
            max_bytes: limits.max_bytes.max(1),
            urgent_max_bytes: limits.urgent_max_bytes.max(1),
            session_data_max_bytes: limits.session_data_max_bytes.max(1),
            per_stream_data_max_bytes: limits.per_stream_data_max_bytes.max(1),
            pending_control_max_bytes: limits.pending_control_max_bytes.max(1),
            pending_priority_max_bytes: limits.pending_priority_max_bytes.max(1),
            max_batch_bytes: limits.max_batch_bytes.max(1),
            max_batch_frames: limits.max_batch_frames.clamp(1, MAX_WRITE_BATCH_FRAMES),
        }
    }

    pub(super) fn data_burst_max_bytes(&self) -> usize {
        self.max_bytes
            .min(self.session_data_max_bytes)
            .min(self.per_stream_data_max_bytes)
            .max(1)
    }

    pub(super) fn max_batch_frames(&self) -> usize {
        self.max_batch_frames
    }

    pub(super) fn push(&self, mut job: WriteJob) -> Result<()> {
        let mut cost = job.cost_bytes();
        let coalesce_key = job.coalesce_key();
        let bypass_capacity = job.bypasses_capacity()
            || matches!(coalesce_key, Some(CoalesceKey::PriorityUpdate { .. }));
        let bypass_urgent_capacity = job.bypasses_urgent_capacity();
        let mut state = self.state.lock().unwrap();
        loop {
            if state.closed {
                return Err(Error::session_closed());
            }
            if let Some((lane, index)) = find_coalesced_key(&state, coalesce_key) {
                merge_coalesced_priority_update(state.job(lane, index), &mut job)?;
                cost = job.cost_bytes();
                let old_cost = state.job(lane, index).cost_bytes();
                let old_accounting = queue_cost_for(lane, state.job(lane, index), old_cost);
                let new_accounting = queue_cost_for(lane, &job, cost);
                if let Some(message) = self.intrinsic_pending_capacity_error(&new_accounting) {
                    return Err(Error::new(ErrorCode::Internal, message));
                }
                if self.intrinsic_data_capacity_error(&new_accounting) {
                    return Err(Error::new(
                        ErrorCode::Internal,
                        "zmux: queued data high watermark exceeded",
                    ));
                }
                if !bypass_capacity
                    && self.replacement_would_exceed_capacity(&state, old_cost, cost)
                {
                    state = self.not_full.wait(state).unwrap();
                    continue;
                }
                if !bypass_urgent_capacity
                    && self.replacement_would_exceed_urgent_capacity(
                        &state,
                        old_accounting.urgent,
                        new_accounting.urgent,
                    )
                {
                    state = self.not_full.wait(state).unwrap();
                    continue;
                }
                if self.replacement_would_exceed_pending_capacity(
                    &state,
                    &old_accounting,
                    &new_accounting,
                ) || self.replacement_would_exceed_data_capacity(
                    &state,
                    &old_accounting,
                    &new_accounting,
                ) {
                    state = self.not_full.wait(state).unwrap();
                    continue;
                }
                self.replace_locked(&mut state, lane, index, job, old_accounting, new_accounting);
                return Ok(());
            }
            let lane = state.lane_for(&job);
            let accounting = queue_cost_for(lane, &job, cost);
            if let Some(message) = self.intrinsic_pending_capacity_error(&accounting) {
                return Err(Error::new(ErrorCode::Internal, message));
            }
            if self.intrinsic_data_capacity_error(&accounting) {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "zmux: queued data high watermark exceeded",
                ));
            }
            if (!bypass_capacity && self.would_exceed_capacity(&state, cost))
                || (!bypass_urgent_capacity
                    && self.would_exceed_urgent_capacity(&state, accounting.urgent))
                || self.would_exceed_pending_capacity(&state, &accounting)
                || self.would_exceed_data_capacity(&state, &accounting)
            {
                state = self.not_full.wait(state).unwrap();
                continue;
            }
            return self.push_locked(&mut state, job, lane, accounting);
        }
    }

    pub(super) fn push_until<D, C>(
        &self,
        job: WriteJob,
        mut deadline: D,
        mut check: C,
        operation: &str,
        blocked_write_total: &mut Duration,
    ) -> Result<()>
    where
        D: FnMut() -> Option<Instant>,
        C: FnMut() -> Result<()>,
    {
        let coalesce_key = job.coalesce_key();
        let bypass_capacity = job.bypasses_capacity()
            || matches!(coalesce_key, Some(CoalesceKey::PriorityUpdate { .. }));
        let bypass_urgent_capacity = job.bypasses_urgent_capacity();
        let mut pending = Some(job);
        loop {
            check()?;
            let current_deadline = deadline();
            if current_deadline.is_some_and(|deadline| deadline <= Instant::now()) {
                return Err(Error::timeout(operation));
            }
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(Error::session_closed());
            }
            if let Some((lane, index)) = find_coalesced_key(&state, coalesce_key) {
                let mut job = pending.take().expect("queued job already consumed");
                merge_coalesced_priority_update(state.job(lane, index), &mut job)?;
                let cost = job.cost_bytes();
                let old_cost = state.job(lane, index).cost_bytes();
                let old_accounting = queue_cost_for(lane, state.job(lane, index), old_cost);
                let new_accounting = queue_cost_for(lane, &job, cost);
                if let Some(message) = self.intrinsic_pending_capacity_error(&new_accounting) {
                    return Err(Error::new(ErrorCode::Internal, message));
                }
                if self.intrinsic_data_capacity_error(&new_accounting) {
                    return Err(Error::new(
                        ErrorCode::Internal,
                        "zmux: queued data high watermark exceeded",
                    ));
                }
                if !bypass_capacity
                    && self.replacement_would_exceed_capacity(&state, old_cost, cost)
                {
                    pending = Some(job);
                    drop(self.wait_not_full_until_tracked(
                        state,
                        current_deadline,
                        operation,
                        blocked_write_total,
                    )?);
                    continue;
                }
                if !bypass_urgent_capacity
                    && self.replacement_would_exceed_urgent_capacity(
                        &state,
                        old_accounting.urgent,
                        new_accounting.urgent,
                    )
                {
                    pending = Some(job);
                    drop(self.wait_not_full_until_tracked(
                        state,
                        current_deadline,
                        operation,
                        blocked_write_total,
                    )?);
                    continue;
                }
                if self.replacement_would_exceed_pending_capacity(
                    &state,
                    &old_accounting,
                    &new_accounting,
                ) || self.replacement_would_exceed_data_capacity(
                    &state,
                    &old_accounting,
                    &new_accounting,
                ) {
                    pending = Some(job);
                    drop(self.wait_not_full_until_tracked(
                        state,
                        current_deadline,
                        operation,
                        blocked_write_total,
                    )?);
                    continue;
                }
                self.replace_locked(&mut state, lane, index, job, old_accounting, new_accounting);
                return Ok(());
            }
            let job = pending.as_ref().unwrap();
            let cost = job.cost_bytes();
            let lane = state.lane_for(job);
            let accounting = queue_cost_for(lane, job, cost);
            if let Some(message) = self.intrinsic_pending_capacity_error(&accounting) {
                return Err(Error::new(ErrorCode::Internal, message));
            }
            if self.intrinsic_data_capacity_error(&accounting) {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "zmux: queued data high watermark exceeded",
                ));
            }
            if (!bypass_capacity && self.would_exceed_capacity(&state, cost))
                || (!bypass_urgent_capacity
                    && self.would_exceed_urgent_capacity(&state, accounting.urgent))
                || self.would_exceed_pending_capacity(&state, &accounting)
                || self.would_exceed_data_capacity(&state, &accounting)
            {
                drop(self.wait_not_full_until_tracked(
                    state,
                    current_deadline,
                    operation,
                    blocked_write_total,
                )?);
                continue;
            }
            let job = pending.take().expect("queued job already consumed");
            return self.push_locked(&mut state, job, lane, accounting);
        }
    }

    pub(super) fn try_push(&self, mut job: WriteJob) -> Result<()> {
        let mut cost = job.cost_bytes();
        let coalesce_key = job.coalesce_key();
        let bypass_capacity = job.bypasses_capacity()
            || matches!(coalesce_key, Some(CoalesceKey::PriorityUpdate { .. }));
        let bypass_urgent_capacity = job.bypasses_urgent_capacity();
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(Error::session_closed());
        }
        if let Some((lane, index)) = find_coalesced_key(&state, coalesce_key) {
            merge_coalesced_priority_update(state.job(lane, index), &mut job)?;
            cost = job.cost_bytes();
            let old_cost = state.job(lane, index).cost_bytes();
            let old_accounting = queue_cost_for(lane, state.job(lane, index), old_cost);
            let new_accounting = queue_cost_for(lane, &job, cost);
            if !bypass_capacity && self.replacement_would_exceed_capacity(&state, old_cost, cost) {
                return Err(Error::new(ErrorCode::Internal, "zmux: writer queue full"));
            }
            if !bypass_urgent_capacity
                && self.replacement_would_exceed_urgent_capacity(
                    &state,
                    old_accounting.urgent,
                    new_accounting.urgent,
                )
            {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "zmux: urgent writer queue full",
                ));
            }
            if let Some(message) =
                self.replacement_pending_capacity_error(&state, &old_accounting, &new_accounting)
            {
                return Err(Error::new(ErrorCode::Internal, message));
            }
            if self.replacement_would_exceed_data_capacity(&state, &old_accounting, &new_accounting)
            {
                return Err(Error::new(
                    ErrorCode::Internal,
                    "zmux: queued data high watermark exceeded",
                ));
            }
            self.replace_locked(&mut state, lane, index, job, old_accounting, new_accounting);
            return Ok(());
        }
        let lane = state.lane_for(&job);
        let accounting = queue_cost_for(lane, &job, cost);
        if !bypass_capacity && self.would_exceed_capacity(&state, cost) {
            return Err(Error::new(ErrorCode::Internal, "zmux: writer queue full"));
        }
        if !bypass_urgent_capacity && self.would_exceed_urgent_capacity(&state, accounting.urgent) {
            return Err(Error::new(
                ErrorCode::Internal,
                "zmux: urgent writer queue full",
            ));
        }
        if let Some(message) = self.pending_capacity_error(&state, &accounting) {
            return Err(Error::new(ErrorCode::Internal, message));
        }
        if self.would_exceed_data_capacity(&state, &accounting) {
            return Err(Error::new(
                ErrorCode::Internal,
                "zmux: queued data high watermark exceeded",
            ));
        }
        self.push_locked(&mut state, job, lane, accounting)
    }

    pub(super) fn force_push(&self, mut job: WriteJob) -> Result<()> {
        let mut cost = job.cost_bytes();
        let coalesce_key = job.coalesce_key();
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return Err(Error::session_closed());
        }
        if let Some((lane, index)) = find_coalesced_key(&state, coalesce_key) {
            merge_coalesced_priority_update(state.job(lane, index), &mut job)?;
            cost = job.cost_bytes();
            let old_cost = state.job(lane, index).cost_bytes();
            let old_accounting = queue_cost_for(lane, state.job(lane, index), old_cost);
            let new_accounting = queue_cost_for(lane, &job, cost);
            self.replace_locked(&mut state, lane, index, job, old_accounting, new_accounting);
            return Ok(());
        }
        let lane = state.lane_for(&job);
        let accounting = queue_cost_for(lane, &job, cost);
        self.push_locked(&mut state, job, lane, accounting)
    }

    pub(super) fn wake_push_waiters(&self) {
        self.not_full.notify_all();
    }

    pub(super) fn shutdown(&self) {
        let mut state = self.state.lock().unwrap();
        clear_queue_locked(&mut state);
        state.closed = true;
        self.not_empty.notify_all();
        self.not_full.notify_all();
    }

    pub(super) fn shutdown_after_close(&self, frame: Frame) {
        let mut state = self.state.lock().unwrap();
        clear_queue_locked(&mut state);
        let job = WriteJob::Frame(frame);
        let cost = job.cost_bytes();
        let accounting = queue_cost_for(QueueLane::Urgent, &job, cost);
        apply_queue_cost_add(&mut state, &accounting);
        state.urgent_jobs.push_back(job);
        state.urgent_jobs.push_back(WriteJob::Shutdown);
        state.closed = true;
        self.not_empty.notify_all();
        self.not_full.notify_all();
    }

    pub(super) fn close_after_draining(&self) {
        let mut state = self.state.lock().unwrap();
        state.closed = true;
        self.not_empty.notify_all();
        self.not_full.notify_all();
    }

    pub(super) fn stats(&self) -> WriterQueueStats {
        let state = self.state.lock().unwrap();
        WriterQueueStats {
            urgent_jobs: state.urgent_jobs.len(),
            ordinary_jobs: state.ordinary_jobs.len(),
            queued_bytes: state.queued_bytes,
            max_bytes: self.max_bytes,
            urgent_queued_bytes: state.urgent_queued_bytes,
            urgent_max_bytes: self.urgent_max_bytes,
            data_queued_bytes: state.data_queued_bytes,
            session_data_high_watermark: self.session_data_max_bytes,
            per_stream_data_high_watermark: self.per_stream_data_max_bytes,
            pending_control_bytes: state.pending_control_bytes,
            pending_control_bytes_budget: self.pending_control_max_bytes,
            pending_priority_bytes: state.pending_priority_bytes,
            pending_priority_bytes_budget: self.pending_priority_max_bytes,
            max_batch_frames: self.max_batch_frames,
        }
    }

    pub(super) fn data_queued_bytes_for_stream(&self, stream_id: u64) -> usize {
        let state = self.state.lock().unwrap();
        state
            .data_queued_by_stream
            .get(&stream_id)
            .copied()
            .unwrap_or(0)
    }

    pub(super) fn terminal_control_queued_for_stream(&self, stream_id: u64) -> bool {
        let state = self.state.lock().unwrap();
        jobs_have_terminal_control_for_stream(&state.urgent_jobs, stream_id)
            || jobs_have_terminal_control_for_stream(&state.ordinary_jobs, stream_id)
    }

    pub(super) fn discard_stream(&self, stream_id: u64) -> StreamDiscardStats {
        if stream_id == 0 {
            return StreamDiscardStats::default();
        }
        let mut state = self.state.lock().unwrap();
        let mut stats = discard_stream_from_lane(
            &mut state,
            QueueLane::Urgent,
            stream_id,
            frame_belongs_to_stream,
        );
        stats.add(discard_stream_from_lane(
            &mut state,
            QueueLane::Ordinary,
            stream_id,
            frame_belongs_to_stream,
        ));
        if stats.removed_any() {
            drop(state);
            self.not_full.notify_all();
        }
        stats
    }

    pub(super) fn discard_stream_send_tail(&self, stream_id: u64) -> StreamDiscardStats {
        if stream_id == 0 {
            return StreamDiscardStats::default();
        }
        let mut state = self.state.lock().unwrap();
        let mut stats = discard_stream_from_lane(
            &mut state,
            QueueLane::Urgent,
            stream_id,
            frame_is_send_tail_for_stream,
        );
        stats.add(discard_stream_from_lane(
            &mut state,
            QueueLane::Ordinary,
            stream_id,
            frame_is_send_tail_for_stream,
        ));
        if stats.removed_any() {
            drop(state);
            self.not_full.notify_all();
        }
        stats
    }

    pub(super) fn discard_priority_update(&self, stream_id: u64) -> bool {
        if stream_id == 0 {
            return false;
        }
        self.discard_coalesced(CoalesceKey::PriorityUpdate { stream_id })
    }

    pub(super) fn discard_stream_max_data(&self, stream_id: u64) -> bool {
        if stream_id == 0 {
            return false;
        }
        self.discard_coalesced(CoalesceKey::MaxData { stream_id })
    }

    pub(super) fn cancel_tracked_write(
        &self,
        completion: &super::types::WriteCompletion,
    ) -> Option<super::types::TrackedWriteJob> {
        let mut state = self.state.lock().unwrap();
        let removed = if let Some((lane, index)) = find_tracked_completion(&state, completion) {
            remove_lane_job(&mut state, lane, index).map(|job| (lane, job))
        } else {
            None
        };
        let (lane, job) = removed?;
        let queued = job.cost_bytes();
        let cost = queue_cost_for(lane, &job, queued);
        apply_queue_cost_remove(&mut state, &cost);
        drop(state);
        self.not_full.notify_all();
        match job {
            WriteJob::TrackedFrames(tracked) => Some(tracked),
            _ => None,
        }
    }

    fn discard_coalesced(&self, key: CoalesceKey) -> bool {
        let mut state = self.state.lock().unwrap();
        let mut removed = false;
        while let Some((lane, index)) = state.find_coalesced(key) {
            let Some(job) = remove_lane_job(&mut state, lane, index) else {
                break;
            };
            let queued = job.cost_bytes();
            let cost = queue_cost_for(lane, &job, queued);
            apply_queue_cost_remove(&mut state, &cost);
            removed = true;
        }
        if removed {
            drop(state);
            self.not_full.notify_all();
        }
        removed
    }

    #[cfg(test)]
    pub(super) fn pop_batch(&self) -> Option<Vec<WriteJob>> {
        match self.pop_batch_wait(None) {
            WriteQueuePop::Batch(batch) => Some(batch),
            WriteQueuePop::TimedOut | WriteQueuePop::Closed => None,
        }
    }

    #[cfg(test)]
    pub(super) fn pop_batch_wait(&self, timeout: Option<Duration>) -> WriteQueuePop {
        let mut batch =
            Vec::with_capacity(self.max_batch_frames.min(MAX_INITIAL_QUEUE_SCRATCH_RESERVE));
        match self.pop_batch_wait_into(&mut batch, timeout) {
            WriteQueuePopStatus::Batch => WriteQueuePop::Batch(batch),
            WriteQueuePopStatus::TimedOut => WriteQueuePop::TimedOut,
            WriteQueuePopStatus::Closed => WriteQueuePop::Closed,
        }
    }

    pub(super) fn pop_batch_wait_into(
        &self,
        batch: &mut Vec<WriteJob>,
        timeout: Option<Duration>,
    ) -> WriteQueuePopStatus {
        batch.clear();
        let batch_frame_limit = self.max_batch_frames.max(1);
        let min_capacity = batch_frame_limit.min(MAX_INITIAL_QUEUE_SCRATCH_RESERVE);
        if batch.capacity() < min_capacity {
            let _ = batch.try_reserve(min_capacity - batch.len());
        }
        let mut state = self.state.lock().unwrap();
        let started = if timeout.is_some() {
            Some(Instant::now())
        } else {
            None
        };
        while state.is_empty() && !state.closed {
            let Some(timeout) = timeout else {
                state = self.not_empty.wait(state).unwrap();
                continue;
            };
            let elapsed = if let Some(started) = started {
                started.elapsed()
            } else {
                Duration::default()
            };
            if elapsed >= timeout {
                return WriteQueuePopStatus::TimedOut;
            }
            let wait = timeout.saturating_sub(elapsed).min(MAX_CONDVAR_TIMED_WAIT);
            let (next, timed_out) = self.not_empty.wait_timeout(state, wait).unwrap();
            state = next;
            if timed_out.timed_out()
                && wait != MAX_CONDVAR_TIMED_WAIT
                && state.is_empty()
                && !state.closed
            {
                return WriteQueuePopStatus::TimedOut;
            }
        }
        if state.is_empty() {
            return WriteQueuePopStatus::Closed;
        }

        let mut saw_nonurgent = false;
        let mut nonurgent_batch_bytes = 0usize;
        for _ in 0..batch_frame_limit {
            let Some((lane, job)) = pop_next_batch_job(&mut state) else {
                break;
            };
            let cost = job.cost_bytes();
            if lane != QueueLane::Urgent {
                let would_exceed =
                    nonurgent_batch_bytes.saturating_add(cost) > self.max_batch_bytes;
                if saw_nonurgent && would_exceed {
                    push_front_batch_job(&mut state, lane, job);
                    break;
                }
                saw_nonurgent = true;
                nonurgent_batch_bytes = nonurgent_batch_bytes.saturating_add(cost);
            }
            let accounting = queue_cost_for(lane, &job, cost);
            apply_queue_cost_remove(&mut state, &accounting);
            batch.push(job);
            if matches!(
                batch.last(),
                Some(WriteJob::Shutdown | WriteJob::DrainShutdown)
            ) {
                break;
            }
        }
        maybe_shrink_empty_lanes(&mut state);
        drop(state);
        self.not_full.notify_all();
        WriteQueuePopStatus::Batch
    }

    fn would_exceed_capacity(&self, state: &WriteQueueState, cost: usize) -> bool {
        cost > self.max_bytes.saturating_sub(state.queued_bytes)
    }

    fn replacement_would_exceed_capacity(
        &self,
        state: &WriteQueueState,
        old_cost: usize,
        new_cost: usize,
    ) -> bool {
        replacement_would_exceed_limit(state.queued_bytes, old_cost, new_cost, self.max_bytes)
    }

    fn would_exceed_urgent_capacity(&self, state: &WriteQueueState, cost: usize) -> bool {
        cost > self
            .urgent_max_bytes
            .saturating_sub(state.urgent_queued_bytes)
    }

    fn replacement_would_exceed_urgent_capacity(
        &self,
        state: &WriteQueueState,
        old_cost: usize,
        new_cost: usize,
    ) -> bool {
        replacement_would_exceed_limit(
            state.urgent_queued_bytes,
            old_cost,
            new_cost,
            self.urgent_max_bytes,
        )
    }

    fn would_exceed_pending_capacity(&self, state: &WriteQueueState, cost: &QueueCost) -> bool {
        self.pending_capacity_error(state, cost).is_some()
    }

    fn intrinsic_pending_capacity_error(&self, cost: &QueueCost) -> Option<&'static str> {
        if cost.pending_control > self.pending_control_max_bytes {
            Some("zmux: pending control budget exceeded")
        } else if cost.pending_priority > self.pending_priority_max_bytes {
            Some("zmux: pending priority budget exceeded")
        } else {
            None
        }
    }

    fn pending_capacity_error(
        &self,
        state: &WriteQueueState,
        cost: &QueueCost,
    ) -> Option<&'static str> {
        if cost.pending_control
            > self
                .pending_control_max_bytes
                .saturating_sub(state.pending_control_bytes)
        {
            Some("zmux: pending control budget exceeded")
        } else if cost.pending_priority
            > self
                .pending_priority_max_bytes
                .saturating_sub(state.pending_priority_bytes)
        {
            Some("zmux: pending priority budget exceeded")
        } else {
            None
        }
    }

    fn replacement_would_exceed_pending_capacity(
        &self,
        state: &WriteQueueState,
        old: &QueueCost,
        new: &QueueCost,
    ) -> bool {
        self.replacement_pending_capacity_error(state, old, new)
            .is_some()
    }

    fn replacement_pending_capacity_error(
        &self,
        state: &WriteQueueState,
        old: &QueueCost,
        new: &QueueCost,
    ) -> Option<&'static str> {
        if replacement_would_exceed_limit(
            state.pending_control_bytes,
            old.pending_control,
            new.pending_control,
            self.pending_control_max_bytes,
        ) {
            Some("zmux: pending control budget exceeded")
        } else if replacement_would_exceed_limit(
            state.pending_priority_bytes,
            old.pending_priority,
            new.pending_priority,
            self.pending_priority_max_bytes,
        ) {
            Some("zmux: pending priority budget exceeded")
        } else {
            None
        }
    }

    fn would_exceed_data_capacity(&self, state: &WriteQueueState, cost: &QueueCost) -> bool {
        if cost.data.is_empty() {
            return false;
        }
        if self.intrinsic_data_capacity_error(cost) {
            return true;
        }
        let data_total = cost.data.total();
        if data_total
            > self
                .session_data_max_bytes
                .saturating_sub(state.data_queued_bytes)
        {
            return true;
        }
        for (stream_id, bytes) in cost.data.iter() {
            let queued = state
                .data_queued_by_stream
                .get(&stream_id)
                .copied()
                .unwrap_or(0);
            if bytes > self.per_stream_data_max_bytes.saturating_sub(queued) {
                return true;
            }
        }
        false
    }

    fn intrinsic_data_capacity_error(&self, cost: &QueueCost) -> bool {
        if cost.data.is_empty() {
            return false;
        }
        if cost.data.total() > self.session_data_max_bytes {
            return true;
        }
        for (_, bytes) in cost.data.iter() {
            if bytes > self.per_stream_data_max_bytes {
                return true;
            }
        }
        false
    }

    fn replacement_would_exceed_data_capacity(
        &self,
        state: &WriteQueueState,
        old: &QueueCost,
        new: &QueueCost,
    ) -> bool {
        if new.data.is_empty() {
            return false;
        }
        let old_total = old.data.total();
        let new_total = new.data.total();
        if replacement_would_exceed_limit(
            state.data_queued_bytes,
            old_total,
            new_total,
            self.session_data_max_bytes,
        ) {
            return true;
        }
        for (stream_id, new_bytes) in new.data.iter() {
            let old_bytes = old.data.get(stream_id);
            if replacement_would_exceed_limit(
                state
                    .data_queued_by_stream
                    .get(&stream_id)
                    .copied()
                    .unwrap_or(0),
                old_bytes,
                new_bytes,
                self.per_stream_data_max_bytes,
            ) {
                return true;
            }
        }
        false
    }

    fn replace_locked(
        &self,
        state: &mut WriteQueueState,
        lane: QueueLane,
        index: usize,
        job: WriteJob,
        old_cost: QueueCost,
        new_cost: QueueCost,
    ) {
        *state.job_mut(lane, index) = job;
        apply_queue_cost_remove(state, &old_cost);
        apply_queue_cost_add(state, &new_cost);
        self.not_empty.notify_one();
        self.not_full.notify_all();
    }

    fn push_locked(
        &self,
        state: &mut WriteQueueState,
        job: WriteJob,
        lane: QueueLane,
        cost: QueueCost,
    ) -> Result<()> {
        if state.closed {
            return Err(Error::session_closed());
        }
        apply_queue_cost_add(state, &cost);
        match lane {
            QueueLane::Urgent => state.urgent_jobs.push_back(job),
            QueueLane::Ordinary => state.ordinary_jobs.push_back(job),
        }
        self.not_empty.notify_one();
        Ok(())
    }

    fn wait_not_full_until<'a>(
        &self,
        state: std::sync::MutexGuard<'a, WriteQueueState>,
        deadline: Option<Instant>,
        operation: &str,
    ) -> Result<std::sync::MutexGuard<'a, WriteQueueState>> {
        let Some(deadline) = deadline else {
            return Ok(self.not_full.wait(state).unwrap());
        };
        let Some(wait) = deadline.checked_duration_since(Instant::now()) else {
            return Err(Error::timeout(operation));
        };
        let wait = wait.min(MAX_CONDVAR_TIMED_WAIT);
        let (state, timed_out) = self.not_full.wait_timeout(state, wait).unwrap();
        if timed_out.timed_out() && wait != MAX_CONDVAR_TIMED_WAIT {
            return Err(Error::timeout(operation));
        }
        Ok(state)
    }

    fn wait_not_full_until_tracked<'a>(
        &self,
        state: std::sync::MutexGuard<'a, WriteQueueState>,
        deadline: Option<Instant>,
        operation: &str,
        blocked_write_total: &mut Duration,
    ) -> Result<std::sync::MutexGuard<'a, WriteQueueState>> {
        let started = Instant::now();
        let result = self.wait_not_full_until(state, deadline, operation);
        *blocked_write_total = blocked_write_total.saturating_add(started.elapsed());
        result
    }
}

#[inline]
fn replacement_would_exceed_limit(
    current: usize,
    old_cost: usize,
    new_cost: usize,
    limit: usize,
) -> bool {
    new_cost > old_cost && new_cost > limit.saturating_sub(current.saturating_sub(old_cost))
}

fn push_front_batch_job(state: &mut WriteQueueState, lane: QueueLane, job: WriteJob) {
    match lane {
        QueueLane::Urgent => state.urgent_jobs.push_front(job),
        QueueLane::Ordinary => state.ordinary_jobs.push_front(job),
    }
}

fn find_tracked_completion(
    state: &WriteQueueState,
    completion: &super::types::WriteCompletion,
) -> Option<(QueueLane, usize)> {
    if let Some(found) =
        find_tracked_completion_in_lane(&state.urgent_jobs, QueueLane::Urgent, completion)
    {
        return Some(found);
    }
    find_tracked_completion_in_lane(&state.ordinary_jobs, QueueLane::Ordinary, completion)
}

fn find_tracked_completion_in_lane(
    jobs: &VecDeque<WriteJob>,
    lane: QueueLane,
    completion: &super::types::WriteCompletion,
) -> Option<(QueueLane, usize)> {
    for (index, job) in jobs.iter().enumerate() {
        if job.tracks_completion(completion) {
            return Some((lane, index));
        }
    }
    None
}

fn pop_next_batch_job(state: &mut WriteQueueState) -> Option<(QueueLane, WriteJob)> {
    if let Some(job) = state.urgent_jobs.pop_front() {
        return Some((QueueLane::Urgent, job));
    }
    state
        .ordinary_jobs
        .pop_front()
        .map(|job| (QueueLane::Ordinary, job))
}

fn discard_stream_from_lane(
    state: &mut WriteQueueState,
    lane: QueueLane,
    stream_id: u64,
    remove: fn(&Frame, u64) -> bool,
) -> StreamDiscardStats {
    if !jobs_have_removable_stream_frame(state.lane(lane), stream_id, remove) {
        return StreamDiscardStats::default();
    }

    let mut jobs = match lane {
        QueueLane::Urgent => std::mem::take(&mut state.urgent_jobs),
        QueueLane::Ordinary => std::mem::take(&mut state.ordinary_jobs),
    };
    let original_len = jobs.len();
    let mut kept = VecDeque::new();
    let _ = kept.try_reserve(original_len.min(MAX_INITIAL_QUEUE_SCRATCH_RESERVE));
    let mut stats = StreamDiscardStats::default();
    while let Some(job) = jobs.pop_front() {
        let queued = job.cost_bytes();
        let old_cost = queue_cost_for(lane, &job, queued);
        let (next, removed) = remove_stream_frames(job, stream_id, remove);
        if removed.removed_any() {
            stats.add(removed);
            apply_queue_cost_remove(state, &old_cost);
            if let Some(next) = next {
                let new_queued = next.cost_bytes();
                let new_cost = queue_cost_for(lane, &next, new_queued);
                apply_queue_cost_add(state, &new_cost);
                kept.push_back(next);
            }
        } else if let Some(next) = next {
            kept.push_back(next);
        }
    }
    shrink_sparse_lane(&mut kept);

    match lane {
        QueueLane::Urgent => state.urgent_jobs = kept,
        QueueLane::Ordinary => state.ordinary_jobs = kept,
    }
    stats
}

fn job_has_removable_stream_frame(
    job: &WriteJob,
    stream_id: u64,
    remove: fn(&Frame, u64) -> bool,
) -> bool {
    match job {
        WriteJob::Frame(frame) | WriteJob::GracefulClose(frame) => remove(frame, stream_id),
        WriteJob::Frames(frames) => frames_have_removable_stream_frame(frames, stream_id, remove),
        WriteJob::TrackedFrames(tracked) => {
            frames_have_removable_stream_frame(&tracked.frames, stream_id, remove)
        }
        WriteJob::Shutdown | WriteJob::DrainShutdown => false,
    }
}

fn frames_have_removable_stream_frame(
    frames: &[Frame],
    stream_id: u64,
    remove: fn(&Frame, u64) -> bool,
) -> bool {
    for frame in frames {
        if remove(frame, stream_id) {
            return true;
        }
    }
    false
}

fn jobs_have_removable_stream_frame(
    jobs: &VecDeque<WriteJob>,
    stream_id: u64,
    remove: fn(&Frame, u64) -> bool,
) -> bool {
    for job in jobs {
        if job_has_removable_stream_frame(job, stream_id, remove) {
            return true;
        }
    }
    false
}

fn remove_lane_job(state: &mut WriteQueueState, lane: QueueLane, index: usize) -> Option<WriteJob> {
    match lane {
        QueueLane::Urgent => state.urgent_jobs.remove(index),
        QueueLane::Ordinary => state.ordinary_jobs.remove(index),
    }
}

fn remove_stream_frames(
    job: WriteJob,
    stream_id: u64,
    remove: fn(&Frame, u64) -> bool,
) -> (Option<WriteJob>, StreamDiscardStats) {
    match job {
        WriteJob::Frame(frame) => {
            if remove(&frame, stream_id) {
                let mut stats = StreamDiscardStats::default();
                stats.add_frame(&frame);
                (None, stats)
            } else {
                (Some(WriteJob::Frame(frame)), StreamDiscardStats::default())
            }
        }
        WriteJob::GracefulClose(frame) => {
            if remove(&frame, stream_id) {
                let mut stats = StreamDiscardStats::default();
                stats.add_frame(&frame);
                (None, stats)
            } else {
                (
                    Some(WriteJob::GracefulClose(frame)),
                    StreamDiscardStats::default(),
                )
            }
        }
        WriteJob::Frames(mut frames) => {
            let mut stats = StreamDiscardStats::default();
            frames.retain(|frame| {
                if remove(frame, stream_id) {
                    stats.add_frame(frame);
                    false
                } else {
                    true
                }
            });
            if !stats.removed_any() {
                (Some(WriteJob::Frames(frames)), stats)
            } else if frames.is_empty() {
                (None, stats)
            } else {
                (Some(WriteJob::Frames(frames)), stats)
            }
        }
        WriteJob::TrackedFrames(mut tracked) => {
            let mut stats = StreamDiscardStats::default();
            tracked.frames.retain(|frame| {
                if remove(frame, stream_id) {
                    stats.add_frame(frame);
                    false
                } else {
                    true
                }
            });
            if !stats.removed_any() {
                return (Some(WriteJob::TrackedFrames(tracked)), stats);
            }
            tracked
                .completion
                .complete_err(Error::local("zmux: queued write was discarded"));
            if tracked.frames.is_empty() {
                (None, stats)
            } else {
                (Some(WriteJob::TrackedFrames(tracked)), stats)
            }
        }
        WriteJob::Shutdown => (Some(WriteJob::Shutdown), StreamDiscardStats::default()),
        WriteJob::DrainShutdown => (Some(WriteJob::DrainShutdown), StreamDiscardStats::default()),
    }
}

#[inline]
fn frame_belongs_to_stream(frame: &Frame, stream_id: u64) -> bool {
    stream_id != 0 && frame.stream_id == stream_id
}

#[inline]
fn frame_is_send_tail_for_stream(frame: &Frame, stream_id: u64) -> bool {
    frame_belongs_to_stream(frame, stream_id)
        && matches!(
            frame.frame_type,
            FrameType::Data | FrameType::Blocked | FrameType::Ext
        )
}

impl WriteQueueState {
    #[inline]
    fn is_empty(&self) -> bool {
        self.urgent_jobs.is_empty() && self.ordinary_jobs.is_empty()
    }

    fn lane_for(&self, job: &WriteJob) -> QueueLane {
        if matches!(job.coalesce_key(), Some(CoalesceKey::PriorityUpdate { .. })) {
            return QueueLane::Ordinary;
        }
        let Some(stream_id) = job.urgent_stream_id() else {
            return if job.is_urgent() {
                QueueLane::Urgent
            } else {
                QueueLane::Ordinary
            };
        };
        if self.has_queued_data_for_stream(stream_id) {
            QueueLane::Ordinary
        } else {
            QueueLane::Urgent
        }
    }

    #[inline]
    fn has_queued_data_for_stream(&self, stream_id: u64) -> bool {
        self.data_queued_by_stream
            .get(&stream_id)
            .is_some_and(|bytes| *bytes != 0)
    }

    fn find_coalesced(&self, key: CoalesceKey) -> Option<(QueueLane, usize)> {
        if let Some(found) = find_coalesced_in_lane(&self.urgent_jobs, QueueLane::Urgent, key) {
            return Some(found);
        }
        find_coalesced_in_lane(&self.ordinary_jobs, QueueLane::Ordinary, key)
    }

    #[inline]
    fn lane(&self, lane: QueueLane) -> &VecDeque<WriteJob> {
        match lane {
            QueueLane::Urgent => &self.urgent_jobs,
            QueueLane::Ordinary => &self.ordinary_jobs,
        }
    }

    #[inline]
    fn job(&self, lane: QueueLane, index: usize) -> &WriteJob {
        match lane {
            QueueLane::Urgent => &self.urgent_jobs[index],
            QueueLane::Ordinary => &self.ordinary_jobs[index],
        }
    }

    #[inline]
    fn job_mut(&mut self, lane: QueueLane, index: usize) -> &mut WriteJob {
        match lane {
            QueueLane::Urgent => &mut self.urgent_jobs[index],
            QueueLane::Ordinary => &mut self.ordinary_jobs[index],
        }
    }
}

fn find_coalesced_in_lane(
    jobs: &VecDeque<WriteJob>,
    lane: QueueLane,
    key: CoalesceKey,
) -> Option<(QueueLane, usize)> {
    for (index, job) in jobs.iter().enumerate().rev() {
        if job.coalesce_key() == Some(key) {
            return Some((lane, index));
        }
    }
    None
}

#[inline]
fn find_coalesced_key(
    state: &WriteQueueState,
    key: Option<CoalesceKey>,
) -> Option<(QueueLane, usize)> {
    let key = key?;
    state.find_coalesced(key)
}

#[inline]
fn queue_cost_for(lane: QueueLane, job: &WriteJob, queued: usize) -> QueueCost {
    let urgent = if lane == QueueLane::Urgent && job.is_urgent() && !job.bypasses_urgent_capacity()
    {
        queued
    } else {
        0
    };
    let (pending_control, pending_priority) = match job.coalesce_key() {
        Some(CoalesceKey::PriorityUpdate { .. }) => (0, queued),
        Some(CoalesceKey::MaxData { .. } | CoalesceKey::Blocked { .. }) => (queued, 0),
        Some(CoalesceKey::GoAway) => (0, 0),
        None => (terminal_control_bytes(job), 0),
    };
    QueueCost {
        queued,
        urgent,
        data: data_costs(job),
        pending_control,
        pending_priority,
    }
}

fn data_costs(job: &WriteJob) -> DataCosts {
    let mut costs = DataCosts::default();
    match job {
        WriteJob::Frame(frame) | WriteJob::GracefulClose(frame) => {
            add_frame_data_cost(&mut costs, frame);
        }
        WriteJob::Frames(frames) => {
            for frame in frames {
                add_frame_data_cost(&mut costs, frame);
            }
        }
        WriteJob::TrackedFrames(tracked) => {
            for frame in &tracked.frames {
                add_frame_data_cost(&mut costs, frame);
            }
        }
        WriteJob::Shutdown | WriteJob::DrainShutdown => {}
    }
    costs
}

fn terminal_control_bytes(job: &WriteJob) -> usize {
    match job {
        WriteJob::Frame(frame) | WriteJob::GracefulClose(frame) => {
            frame_terminal_control_bytes(frame)
        }
        WriteJob::Frames(frames) => frames_terminal_control_bytes(frames),
        WriteJob::TrackedFrames(tracked) => frames_terminal_control_bytes(&tracked.frames),
        WriteJob::Shutdown | WriteJob::DrainShutdown => 0,
    }
}

#[inline]
fn frames_terminal_control_bytes(frames: &[Frame]) -> usize {
    let mut bytes = 0usize;
    for frame in frames {
        bytes = bytes.saturating_add(frame_terminal_control_bytes(frame));
    }
    bytes
}

fn frame_terminal_control_bytes(frame: &Frame) -> usize {
    if matches!(
        frame.frame_type,
        FrameType::Abort | FrameType::Reset | FrameType::StopSending
    ) {
        frame
            .payload
            .len()
            .saturating_add(FRAME_QUEUE_OVERHEAD_BYTES)
    } else {
        0
    }
}

fn job_has_terminal_control_for_stream(job: &WriteJob, stream_id: u64) -> bool {
    match job {
        WriteJob::Frame(frame) | WriteJob::GracefulClose(frame) => {
            frame_has_terminal_control_for_stream(frame, stream_id)
        }
        WriteJob::Frames(frames) => frames_have_terminal_control_for_stream(frames, stream_id),
        WriteJob::TrackedFrames(tracked) => {
            frames_have_terminal_control_for_stream(&tracked.frames, stream_id)
        }
        WriteJob::Shutdown | WriteJob::DrainShutdown => false,
    }
}

fn frames_have_terminal_control_for_stream(frames: &[Frame], stream_id: u64) -> bool {
    for frame in frames {
        if frame_has_terminal_control_for_stream(frame, stream_id) {
            return true;
        }
    }
    false
}

fn jobs_have_terminal_control_for_stream(jobs: &VecDeque<WriteJob>, stream_id: u64) -> bool {
    for job in jobs {
        if job_has_terminal_control_for_stream(job, stream_id) {
            return true;
        }
    }
    false
}

fn frame_has_terminal_control_for_stream(frame: &Frame, stream_id: u64) -> bool {
    frame.stream_id == stream_id
        && matches!(
            frame.frame_type,
            FrameType::Abort | FrameType::Reset | FrameType::StopSending
        )
}

fn add_frame_data_cost(costs: &mut DataCosts, frame: &Frame) {
    if frame.frame_type != FrameType::Data {
        return;
    }
    add_data_cost(costs, frame.stream_id, retained_frame_queue_cost(frame));
}

fn add_data_cost(costs: &mut DataCosts, stream_id: u64, bytes: usize) {
    costs.add(stream_id, bytes);
}

fn clear_queue_locked(state: &mut WriteQueueState) {
    let err = Error::session_closed();
    complete_drained_jobs(state.urgent_jobs.drain(..), &err);
    complete_drained_jobs(state.ordinary_jobs.drain(..), &err);
    state.queued_bytes = 0;
    state.urgent_queued_bytes = 0;
    state.data_queued_bytes = 0;
    state.data_queued_by_stream.clear();
    state.pending_control_bytes = 0;
    state.pending_priority_bytes = 0;
    maybe_shrink_empty_lanes(state);
    maybe_shrink_data_queued_by_stream(state);
}

fn complete_drained_jobs<I>(jobs: I, err: &Error)
where
    I: IntoIterator<Item = WriteJob>,
{
    for job in jobs {
        complete_job_error(job, err);
    }
}

fn complete_job_error(job: WriteJob, err: &Error) {
    if let WriteJob::TrackedFrames(tracked) = job {
        tracked.completion.complete_err(err.clone());
    }
}

fn maybe_shrink_empty_lanes(state: &mut WriteQueueState) {
    shrink_empty_lane(&mut state.urgent_jobs);
    shrink_empty_lane(&mut state.ordinary_jobs);
}

fn shrink_empty_lane(lane: &mut VecDeque<WriteJob>) {
    if lane.is_empty() && lane.capacity() > MAX_INITIAL_QUEUE_SCRATCH_RESERVE {
        lane.shrink_to(0);
    }
}

fn shrink_sparse_lane<T>(lane: &mut VecDeque<T>) {
    if lane.is_empty() {
        if lane.capacity() > MAX_INITIAL_QUEUE_SCRATCH_RESERVE {
            lane.shrink_to(0);
        }
        return;
    }
    if lane.capacity() > MAX_INITIAL_QUEUE_SCRATCH_RESERVE
        && lane.len().saturating_mul(LANE_SPARSE_SHRINK_FACTOR) < lane.capacity()
    {
        lane.shrink_to(lane.len().max(MAX_INITIAL_QUEUE_SCRATCH_RESERVE));
    }
}

fn append_metadata_varint(dst: &mut Vec<u8>, typ: u64, value: u64) -> Result<()> {
    append_varint_reserved(dst, typ)?;
    append_varint_reserved(dst, varint_len(value)? as u64)?;
    append_varint_reserved(dst, value)
}

fn priority_update_fields(payload: &[u8]) -> Option<(Option<u64>, Option<u64>)> {
    let (extension_id, n) = parse_varint(payload).ok()?;
    if extension_id != EXT_PRIORITY_UPDATE {
        return None;
    }
    let (metadata, valid) = parse_priority_update_metadata(&payload[n..]).ok()?;
    if valid {
        Some((metadata.priority, metadata.group))
    } else {
        None
    }
}

fn merged_priority_update_payload(
    old_payload: &[u8],
    new_payload: &[u8],
) -> Result<Option<Vec<u8>>> {
    let Some((old_priority, old_group)) = priority_update_fields(old_payload) else {
        return Ok(None);
    };
    let Some((new_priority, new_group)) = priority_update_fields(new_payload) else {
        return Ok(None);
    };
    let priority = new_priority.or(old_priority);
    let group = new_group.or(old_group);
    if priority.is_none() && group.is_none() {
        return Ok(None);
    }

    let len = merged_priority_update_payload_len(priority, group)?;
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| Error::local("zmux: priority update merge allocation failed"))?;
    append_varint_reserved(&mut out, EXT_PRIORITY_UPDATE)?;
    if let Some(priority) = priority {
        append_metadata_varint(&mut out, METADATA_STREAM_PRIORITY, priority)?;
    }
    if let Some(group) = group {
        append_metadata_varint(&mut out, METADATA_STREAM_GROUP, group)?;
    }
    Ok(Some(out))
}

fn merged_priority_update_payload_len(priority: Option<u64>, group: Option<u64>) -> Result<usize> {
    let mut len = varint_len(EXT_PRIORITY_UPDATE)?;
    if let Some(priority) = priority {
        len = len.saturating_add(metadata_varint_tlv_len(METADATA_STREAM_PRIORITY, priority)?);
    }
    if let Some(group) = group {
        len = len.saturating_add(metadata_varint_tlv_len(METADATA_STREAM_GROUP, group)?);
    }
    Ok(len)
}

fn metadata_varint_tlv_len(typ: u64, value: u64) -> Result<usize> {
    let value_len = varint_len(value)?;
    Ok(varint_len(typ)? + varint_len(value_len as u64)? + value_len)
}

fn merge_coalesced_priority_update(old: &WriteJob, new: &mut WriteJob) -> Result<()> {
    let (
        WriteJob::Frame(Frame {
            frame_type: FrameType::Ext,
            stream_id: old_stream_id,
            payload: old_payload,
            ..
        }),
        WriteJob::Frame(Frame {
            frame_type: FrameType::Ext,
            stream_id: new_stream_id,
            payload: new_payload,
            ..
        }),
    ) = (old, new)
    else {
        return Ok(());
    };
    if old_stream_id != new_stream_id {
        return Ok(());
    }
    if let Some(merged) = merged_priority_update_payload(old_payload, new_payload)? {
        *new_payload = merged;
    }
    Ok(())
}

fn apply_queue_cost_add(state: &mut WriteQueueState, cost: &QueueCost) {
    state.queued_bytes = state.queued_bytes.saturating_add(cost.queued);
    state.urgent_queued_bytes = state.urgent_queued_bytes.saturating_add(cost.urgent);
    state.pending_control_bytes = state
        .pending_control_bytes
        .saturating_add(cost.pending_control);
    state.pending_priority_bytes = state
        .pending_priority_bytes
        .saturating_add(cost.pending_priority);
    let data_total = cost.data.total();
    state.data_queued_bytes = state.data_queued_bytes.saturating_add(data_total);
    for (stream_id, bytes) in cost.data.iter() {
        let entry = state.data_queued_by_stream.entry(stream_id).or_default();
        *entry = entry.saturating_add(bytes);
    }
}

fn apply_queue_cost_remove(state: &mut WriteQueueState, cost: &QueueCost) {
    state.queued_bytes = state.queued_bytes.saturating_sub(cost.queued);
    state.urgent_queued_bytes = state.urgent_queued_bytes.saturating_sub(cost.urgent);
    state.pending_control_bytes = state
        .pending_control_bytes
        .saturating_sub(cost.pending_control);
    state.pending_priority_bytes = state
        .pending_priority_bytes
        .saturating_sub(cost.pending_priority);
    let data_total = cost.data.total();
    state.data_queued_bytes = state.data_queued_bytes.saturating_sub(data_total);
    for (stream_id, bytes) in cost.data.iter() {
        match state.data_queued_by_stream.entry(stream_id) {
            Entry::Occupied(mut entry) => {
                let remaining = entry.get().saturating_sub(bytes);
                if remaining == 0 {
                    entry.remove();
                } else {
                    *entry.get_mut() = remaining;
                }
            }
            Entry::Vacant(_) => {}
        }
    }
    maybe_shrink_data_queued_by_stream(state);
}

impl WriteJob {
    fn cost_bytes(&self) -> usize {
        match self {
            Self::Frame(frame) | Self::GracefulClose(frame) => retained_frame_queue_cost(frame),
            Self::Frames(frames) => retained_frames_queue_cost(frames),
            Self::TrackedFrames(tracked) => retained_frames_queue_cost(&tracked.frames),
            Self::Shutdown | Self::DrainShutdown => 0,
        }
    }

    fn is_urgent(&self) -> bool {
        match self {
            Self::Shutdown => true,
            Self::DrainShutdown | Self::GracefulClose(_) => false,
            Self::Frame(frame) => frame_is_urgent(frame),
            Self::Frames(frames) => frames_are_all_urgent(frames),
            Self::TrackedFrames(tracked) => frames_are_all_urgent(&tracked.frames),
        }
    }

    fn bypasses_capacity(&self) -> bool {
        match self {
            Self::Frame(frame) => frame_bypasses_capacity(frame),
            Self::Frames(frames) => frames_bypass_capacity(frames),
            Self::TrackedFrames(tracked) => frames_bypass_capacity(&tracked.frames),
            Self::Shutdown | Self::DrainShutdown => true,
            Self::GracefulClose(_) => false,
        }
    }

    fn bypasses_urgent_capacity(&self) -> bool {
        match self {
            Self::Frame(frame) | Self::GracefulClose(frame) => {
                frame_bypasses_urgent_capacity(frame)
            }
            Self::Frames(frames) => frames_bypass_urgent_capacity(frames),
            Self::TrackedFrames(tracked) => frames_bypass_urgent_capacity(&tracked.frames),
            Self::Shutdown | Self::DrainShutdown => true,
        }
    }

    fn projected_data_queue_cost_bytes(&self) -> usize {
        if self.contains_data_frame() {
            self.cost_bytes()
        } else {
            0
        }
    }

    fn contains_data_frame(&self) -> bool {
        match self {
            Self::Frame(frame) | Self::GracefulClose(frame) => frame.frame_type == FrameType::Data,
            Self::Frames(frames) => frames_contain_data_frame(frames),
            Self::TrackedFrames(tracked) => frames_contain_data_frame(&tracked.frames),
            Self::Shutdown | Self::DrainShutdown => false,
        }
    }

    fn urgent_stream_id(&self) -> Option<u64> {
        match self {
            Self::Frame(frame) if frame_is_urgent(frame) && frame.stream_id != 0 => {
                Some(frame.stream_id)
            }
            Self::Frames(frames) => urgent_frames_stream_id(frames),
            Self::TrackedFrames(tracked) => urgent_frames_stream_id(&tracked.frames),
            _ => None,
        }
    }

    fn coalesce_key(&self) -> Option<CoalesceKey> {
        let frame = match self {
            Self::Frame(frame) => frame,
            Self::Frames(_)
            | Self::TrackedFrames(_)
            | Self::GracefulClose(_)
            | Self::Shutdown
            | Self::DrainShutdown => return None,
        };
        match frame.frame_type {
            FrameType::Ext => {
                let Ok((extension_id, _)) = parse_varint(&frame.payload) else {
                    return None;
                };
                if extension_id == EXT_PRIORITY_UPDATE {
                    Some(CoalesceKey::PriorityUpdate {
                        stream_id: frame.stream_id,
                    })
                } else {
                    None
                }
            }
            FrameType::MaxData => Some(CoalesceKey::MaxData {
                stream_id: frame.stream_id,
            }),
            FrameType::Blocked => {
                let Ok((_, n)) = parse_varint(&frame.payload) else {
                    return None;
                };
                if n == frame.payload.len() {
                    Some(CoalesceKey::Blocked {
                        stream_id: frame.stream_id,
                    })
                } else {
                    None
                }
            }
            FrameType::GoAway => Some(CoalesceKey::GoAway),
            _ => None,
        }
    }

    fn tracks_completion(&self, completion: &super::types::WriteCompletion) -> bool {
        match self {
            Self::TrackedFrames(tracked) => tracked.completion.same(completion),
            Self::Frame(_)
            | Self::Frames(_)
            | Self::GracefulClose(_)
            | Self::Shutdown
            | Self::DrainShutdown => false,
        }
    }
}

fn urgent_frames_stream_id(frames: &[Frame]) -> Option<u64> {
    let mut stream_id = None;
    for frame in frames {
        if !frame_is_urgent(frame) || frame.stream_id == 0 {
            return None;
        }
        match stream_id {
            Some(existing) if existing != frame.stream_id => return None,
            Some(_) => {}
            None => stream_id = Some(frame.stream_id),
        }
    }
    stream_id
}

fn frames_are_all_urgent(frames: &[Frame]) -> bool {
    for frame in frames {
        if !frame_is_urgent(frame) {
            return false;
        }
    }
    true
}

fn frames_bypass_capacity(frames: &[Frame]) -> bool {
    for frame in frames {
        if !frame_bypasses_capacity(frame) {
            return false;
        }
    }
    true
}

fn frames_bypass_urgent_capacity(frames: &[Frame]) -> bool {
    for frame in frames {
        if !frame_bypasses_urgent_capacity(frame) {
            return false;
        }
    }
    true
}

fn frames_contain_data_frame(frames: &[Frame]) -> bool {
    for frame in frames {
        if frame.frame_type == FrameType::Data {
            return true;
        }
    }
    false
}

#[inline]
fn retained_frame_queue_cost(frame: &Frame) -> usize {
    frame
        .payload
        .len()
        .saturating_add(FRAME_QUEUE_OVERHEAD_BYTES)
}

fn maybe_shrink_data_queued_by_stream(state: &mut WriteQueueState) {
    let len = state.data_queued_by_stream.len();
    let cap = state.data_queued_by_stream.capacity();
    if len == 0 {
        if cap > SHRINK_DATA_STREAM_COST_CAP {
            state
                .data_queued_by_stream
                .shrink_to(RETAINED_DATA_STREAM_COST_CAP);
        }
    } else if cap > SHRINK_DATA_STREAM_COST_CAP
        && cap > len.saturating_mul(DATA_STREAM_COST_SHRINK_FACTOR)
    {
        state
            .data_queued_by_stream
            .shrink_to(len.max(RETAINED_DATA_STREAM_COST_CAP));
    }
}

#[inline]
fn retained_frames_queue_cost(frames: &[Frame]) -> usize {
    let mut cost = 0usize;
    for frame in frames {
        cost = cost.saturating_add(retained_frame_queue_cost(frame));
    }
    cost
}

#[inline]
fn frame_is_urgent(frame: &Frame) -> bool {
    matches!(
        frame.frame_type,
        FrameType::Abort
            | FrameType::Reset
            | FrameType::StopSending
            | FrameType::MaxData
            | FrameType::Blocked
            | FrameType::Ping
            | FrameType::Pong
            | FrameType::GoAway
            | FrameType::Close
    )
}

#[inline]
fn frame_bypasses_capacity(frame: &Frame) -> bool {
    frame_is_urgent(frame)
}

#[inline]
fn frame_bypasses_urgent_capacity(frame: &Frame) -> bool {
    matches!(
        frame.frame_type,
        FrameType::Abort
            | FrameType::Reset
            | FrameType::StopSending
            | FrameType::GoAway
            | FrameType::Close
    )
}

impl Inner {
    pub(super) fn queue_frame(&self, frame: Frame) -> Result<()> {
        self.write_queue.push(WriteJob::Frame(frame))
    }

    pub(super) fn queue_frame_until<D, C>(
        self: &Arc<Self>,
        frame: Frame,
        deadline: D,
        check: C,
        operation: &str,
    ) -> Result<()>
    where
        D: FnMut() -> Option<Instant>,
        C: FnMut() -> Result<()>,
    {
        let job = WriteJob::Frame(frame);
        self.ensure_data_job_fits_session_memory(&job, operation)?;
        let mut blocked = Duration::ZERO;
        let result = self
            .write_queue
            .push_until(job, deadline, check, operation, &mut blocked);
        self.note_writer_queue_blocked(blocked);
        result
    }

    pub(super) fn queue_frames_until<D, C>(
        self: &Arc<Self>,
        frames: Vec<Frame>,
        deadline: D,
        check: C,
        operation: &str,
    ) -> Result<()>
    where
        D: FnMut() -> Option<Instant>,
        C: FnMut() -> Result<()>,
    {
        if frames.is_empty() {
            return Ok(());
        }
        let job = WriteJob::Frames(frames);
        self.ensure_data_job_fits_session_memory(&job, operation)?;
        let mut blocked = Duration::ZERO;
        let result = self
            .write_queue
            .push_until(job, deadline, check, operation, &mut blocked);
        self.note_writer_queue_blocked(blocked);
        result
    }

    pub(super) fn queue_tracked_frames_until<D, C>(
        self: &Arc<Self>,
        frames: Vec<Frame>,
        completion: super::types::WriteCompletion,
        deadline: D,
        check: C,
        operation: &str,
    ) -> Result<()>
    where
        D: FnMut() -> Option<Instant>,
        C: FnMut() -> Result<()>,
    {
        if frames.is_empty() {
            completion.complete_ok();
            return Ok(());
        }
        let job = WriteJob::TrackedFrames(super::types::TrackedWriteJob { frames, completion });
        self.ensure_data_job_fits_session_memory(&job, operation)?;
        let mut blocked = Duration::ZERO;
        let result = self
            .write_queue
            .push_until(job, deadline, check, operation, &mut blocked);
        self.note_writer_queue_blocked(blocked);
        result
    }

    pub(super) fn try_queue_frame(&self, frame: Frame) -> Result<()> {
        self.write_queue.try_push(WriteJob::Frame(frame))
    }

    pub(super) fn force_queue_frame(&self, frame: Frame) -> Result<()> {
        self.write_queue.force_push(WriteJob::Frame(frame))
    }

    pub(super) fn queue_graceful_close_frame(&self, frame: Frame) -> Result<()> {
        self.write_queue.push(WriteJob::GracefulClose(frame))
    }

    pub(super) fn wake_writer_queue_waiters(&self) {
        self.write_queue.wake_push_waiters();
    }

    fn note_writer_queue_blocked(&self, blocked: Duration) {
        if blocked.is_zero() {
            return;
        }
        let mut state = self.state.lock().unwrap();
        note_blocked_write_locked(&mut state, blocked);
    }

    fn ensure_data_job_fits_session_memory(
        self: &Arc<Self>,
        job: &WriteJob,
        operation: &str,
    ) -> Result<()> {
        let projected_writer_bytes = job.projected_data_queue_cost_bytes();
        if projected_writer_bytes == 0 {
            return Ok(());
        }
        if let Err(err) =
            ensure_projected_session_memory_cap(self, projected_writer_bytes, operation)
        {
            let close_frame = Frame {
                frame_type: FrameType::Close,
                flags: 0,
                stream_id: 0,
                payload: build_code_payload(
                    err.numeric_code().unwrap_or(ErrorCode::Internal.as_u64()),
                    &err.to_string(),
                    self.peer_preface.settings.max_control_payload_bytes,
                )
                .unwrap_or_default(),
            };
            fail_session_with_close(self, err.clone(), close_frame);
            return Err(err);
        }
        Ok(())
    }

    pub(super) fn shutdown_writer(&self) {
        self.write_queue.shutdown();
    }

    pub(super) fn shutdown_writer_with_close(&self, frame: Frame) {
        self.write_queue.shutdown_after_close(frame);
    }

    pub(super) fn drain_shutdown_writer(&self) {
        let _ = self.write_queue.force_push(WriteJob::DrainShutdown);
        self.write_queue.close_after_draining();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{Frame, FrameType};
    use crate::payload::{
        build_go_away_payload, build_priority_update_payload, parse_go_away_payload,
    };
    use crate::MetadataUpdate;
    use crate::{CAPABILITY_PRIORITY_HINTS, CAPABILITY_PRIORITY_UPDATE, CAPABILITY_STREAM_GROUPS};
    use std::sync::{mpsc, Arc};
    use std::thread;

    fn frame(frame_type: FrameType, stream_id: u64) -> WriteJob {
        WriteJob::Frame(Frame {
            frame_type,
            flags: 0,
            stream_id,
            payload: Vec::new(),
        })
    }

    fn frame_with_payload(frame_type: FrameType, stream_id: u64, payload: Vec<u8>) -> WriteJob {
        WriteJob::Frame(Frame {
            frame_type,
            flags: 0,
            stream_id,
            payload,
        })
    }

    fn priority_update_frame(stream_id: u64, value: u8) -> WriteJob {
        WriteJob::Frame(Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id,
            payload: vec![EXT_PRIORITY_UPDATE as u8, value],
        })
    }

    fn queue(max_bytes: usize, urgent_max_bytes: usize, max_batch_frames: usize) -> WriteQueue {
        queue_with_limits(
            max_bytes,
            urgent_max_bytes,
            1024,
            1024,
            1024,
            1024,
            max_batch_frames,
        )
    }

    fn queue_with_limits(
        max_bytes: usize,
        urgent_max_bytes: usize,
        session_data_max_bytes: usize,
        per_stream_data_max_bytes: usize,
        pending_control_max_bytes: usize,
        pending_priority_max_bytes: usize,
        max_batch_frames: usize,
    ) -> WriteQueue {
        WriteQueue::new(WriteQueueLimits {
            max_bytes,
            urgent_max_bytes,
            session_data_max_bytes,
            per_stream_data_max_bytes,
            pending_control_max_bytes,
            pending_priority_max_bytes,
            max_batch_bytes: usize::MAX,
            max_batch_frames,
        })
    }

    fn queue_with_batch_cost_limit(max_batch_bytes: usize, max_batch_frames: usize) -> WriteQueue {
        WriteQueue::new(WriteQueueLimits {
            max_bytes: usize::MAX,
            urgent_max_bytes: usize::MAX,
            session_data_max_bytes: usize::MAX,
            per_stream_data_max_bytes: usize::MAX,
            pending_control_max_bytes: usize::MAX,
            pending_priority_max_bytes: usize::MAX,
            max_batch_bytes,
            max_batch_frames,
        })
    }

    #[test]
    fn timed_pop_zero_wait_returns_timeout_without_closing_queue() {
        let queue = queue(1024, 1024, 8);

        assert!(matches!(
            queue.pop_batch_wait(Some(Duration::ZERO)),
            WriteQueuePop::TimedOut
        ));

        queue.push(frame(FrameType::Ping, 0)).unwrap();
        let batch = queue.pop_batch().unwrap();
        assert_eq!(job_frame_types(batch), vec![FrameType::Ping]);
    }

    #[test]
    fn pop_batch_wait_into_reuses_caller_batch_storage() {
        let queue = queue(1024, 1024, 8);
        let mut batch = Vec::with_capacity(8);
        batch.push(frame(FrameType::Ping, 0));

        assert_eq!(
            queue.pop_batch_wait_into(&mut batch, Some(Duration::ZERO)),
            WriteQueuePopStatus::TimedOut
        );
        assert!(batch.is_empty());
        assert!(batch.capacity() >= 8);

        queue.push(frame(FrameType::Ping, 0)).unwrap();
        assert_eq!(
            queue.pop_batch_wait_into(&mut batch, Some(Duration::ZERO)),
            WriteQueuePopStatus::Batch
        );
        assert_eq!(batch.len(), 1);
        assert!(batch.capacity() >= 8);
    }

    #[test]
    fn configured_batch_frame_limit_is_capped() {
        let queue = queue(1024, 1024, usize::MAX);

        assert_eq!(queue.stats().max_batch_frames, MAX_WRITE_BATCH_FRAMES);
    }

    #[test]
    fn frame_and_frames_queue_cost_include_frame_overhead() {
        let frame = Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: 1,
            payload: b"abc".to_vec(),
        };

        assert_eq!(retained_frame_queue_cost(&frame), 4);
        assert_eq!(WriteJob::Frame(frame.clone()).cost_bytes(), 4);
        assert_eq!(WriteJob::Frames(vec![frame.clone(), frame]).cost_bytes(), 8);
    }

    #[test]
    fn urgent_batch_frame_limit_leaves_tail_queued() {
        let queue = queue(1024, 1024, 32);
        for _ in 0..40 {
            queue.push(frame(FrameType::Ping, 0)).unwrap();
        }

        let batch = queue.pop_batch().unwrap();

        assert_eq!(batch.len(), 32);
        assert_eq!(job_frame_types(batch), vec![FrameType::Ping; 32]);
        assert_eq!(queue.stats().urgent_jobs, 8);
    }

    #[test]
    fn empty_urgent_control_retains_queue_cost_until_dequeued() {
        let queue = queue(1024, 1024, 8);

        queue.push(frame(FrameType::Ping, 0)).unwrap();

        assert_eq!(
            queue.stats().urgent_queued_bytes,
            FRAME_QUEUE_OVERHEAD_BYTES
        );
        assert_eq!(queue.stats().queued_bytes, FRAME_QUEUE_OVERHEAD_BYTES);
        let batch = queue.pop_batch().unwrap();
        assert_eq!(job_frame_types(batch), vec![FrameType::Ping]);
        assert_eq!(queue.stats().urgent_queued_bytes, 0);
        assert_eq!(queue.stats().queued_bytes, 0);
    }

    #[test]
    fn ordinary_batch_cost_limit_leaves_large_data_tail_queued() {
        let frame_payload = 16usize;
        let frame_cost = frame_payload + FRAME_QUEUE_OVERHEAD_BYTES;
        let queue = queue_with_batch_cost_limit(frame_cost * 4, 32);
        for stream_id in [1, 5, 9, 13, 17] {
            queue
                .push(frame_with_payload(
                    FrameType::Data,
                    stream_id,
                    vec![b'x'; frame_payload],
                ))
                .unwrap();
        }

        let batch = queue.pop_batch().unwrap();

        assert_eq!(batch.len(), 4);
        assert_eq!(job_frame_types(batch), vec![FrameType::Data; 4]);
        assert_eq!(queue.stats().ordinary_jobs, 1);
        assert_eq!(queue.stats().data_queued_bytes, frame_cost);
        assert_eq!(queue.data_queued_bytes_for_stream(17), frame_cost);
    }

    fn job_frame_types(batch: Vec<WriteJob>) -> Vec<FrameType> {
        let mut types = Vec::new();
        for job in batch {
            match job {
                WriteJob::Frame(frame) | WriteJob::GracefulClose(frame) => {
                    types.push(frame.frame_type);
                }
                WriteJob::Frames(frames) => {
                    types.extend(frames.into_iter().map(|frame| frame.frame_type));
                }
                WriteJob::TrackedFrames(tracked) => {
                    types.extend(tracked.frames.into_iter().map(|frame| frame.frame_type));
                }
                WriteJob::DrainShutdown => types.push(FrameType::Close),
                WriteJob::Shutdown => panic!("unexpected urgent shutdown"),
            }
        }
        types
    }

    #[test]
    fn abortive_shutdown_clears_all_lanes_and_accounting_before_close() {
        let queue = queue_with_limits(1 << 20, 1 << 20, 1 << 20, 1 << 20, 1 << 20, 1 << 20, 8);
        queue
            .push(frame_with_payload(FrameType::Data, 1, b"ordinary".to_vec()))
            .unwrap();
        queue.push(priority_update_frame(5, 7)).unwrap();
        queue
            .push(frame_with_payload(FrameType::Reset, 9, vec![1]))
            .unwrap();

        let before = queue.stats();
        assert_ne!(before.ordinary_jobs, 0);
        assert_ne!(before.urgent_jobs, 0);
        assert_ne!(before.data_queued_bytes, 0);
        assert_ne!(before.pending_control_bytes, 0);
        assert_ne!(before.pending_priority_bytes, 0);

        queue.shutdown_after_close(Frame {
            frame_type: FrameType::Close,
            flags: 0,
            stream_id: 0,
            payload: Vec::new(),
        });

        let after = queue.stats();
        assert_eq!(after.ordinary_jobs, 0);
        assert_eq!(after.urgent_jobs, 2);
        assert_eq!(after.data_queued_bytes, 0);
        assert_eq!(after.pending_control_bytes, 0);
        assert_eq!(after.pending_priority_bytes, 0);
        assert_eq!(after.queued_bytes, FRAME_QUEUE_OVERHEAD_BYTES);

        let batch = queue.pop_batch().expect("close shutdown batch");
        assert!(matches!(
            batch.first(),
            Some(WriteJob::Frame(frame)) if frame.frame_type == FrameType::Close
        ));
        assert!(matches!(batch.get(1), Some(WriteJob::Shutdown)));
        assert!(queue.pop_batch().is_none());
    }

    #[test]
    fn fully_drained_lanes_release_oversized_backings() {
        let queue = queue(1 << 20, 1 << 20, MAX_WRITE_BATCH_FRAMES);
        for i in 0..96u64 {
            queue
                .push(frame_with_payload(FrameType::Ping, 0, vec![i as u8]))
                .unwrap();
            queue
                .push(priority_update_frame(1 + i * 4, i as u8))
                .unwrap();
            queue
                .push(frame_with_payload(
                    FrameType::Data,
                    4097 + i * 4,
                    vec![b'x'],
                ))
                .unwrap();
        }
        let initial = {
            let state = queue.state.lock().unwrap();
            (state.urgent_jobs.capacity(), state.ordinary_jobs.capacity())
        };
        assert!(initial.0 > MAX_INITIAL_QUEUE_SCRATCH_RESERVE);
        assert!(initial.1 > MAX_INITIAL_QUEUE_SCRATCH_RESERVE);

        while queue.stats().queued_bytes != 0 {
            let batch = queue.pop_batch().expect("queued batch");
            assert!(!batch.is_empty());
        }

        let drained = queue.state.lock().unwrap();
        assert!(drained.urgent_jobs.capacity() <= MAX_INITIAL_QUEUE_SCRATCH_RESERVE);
        assert!(drained.ordinary_jobs.capacity() <= MAX_INITIAL_QUEUE_SCRATCH_RESERVE);
        assert_eq!(drained.data_queued_by_stream.len(), 0);
    }

    #[test]
    fn discard_absent_stream_does_not_rebuild_lane_backing() {
        let queue = queue(1 << 20, 1 << 20, MAX_WRITE_BATCH_FRAMES);
        for i in 0..96u64 {
            queue
                .push(frame_with_payload(FrameType::Data, 1 + i * 4, vec![b'x']))
                .unwrap();
        }
        let before = queue.state.lock().unwrap().ordinary_jobs.capacity();
        assert!(before > MAX_INITIAL_QUEUE_SCRATCH_RESERVE);

        let discarded = queue.discard_stream(999_999);

        assert!(!discarded.removed_any());
        let after = queue.state.lock().unwrap().ordinary_jobs.capacity();
        assert_eq!(after, before);
        assert_eq!(queue.stats().ordinary_jobs, 96);
    }

    #[test]
    fn urgent_session_control_is_dequeued_before_ordinary_data() {
        let queue = queue(1024, 1024, 4);
        queue.push(frame(FrameType::Data, 1)).unwrap();
        queue.push(frame(FrameType::Close, 0)).unwrap();

        let batch = queue.pop_batch().unwrap();
        let types = job_frame_types(batch);
        assert_eq!(types, vec![FrameType::Close, FrameType::Data]);
    }

    #[test]
    fn abortive_shutdown_discards_ordinary_data_before_close() {
        let queue = queue(1024, 1024, 8);
        queue
            .push(frame_with_payload(FrameType::Data, 1, vec![1; 32]))
            .unwrap();
        queue
            .push(frame_with_payload(FrameType::Data, 5, vec![2; 16]))
            .unwrap();

        queue.shutdown_after_close(Frame {
            frame_type: FrameType::Close,
            flags: 0,
            stream_id: 0,
            payload: Vec::new(),
        });

        let stats = queue.stats();
        assert_eq!(stats.ordinary_jobs, 0);
        assert_eq!(stats.data_queued_bytes, 0);
        let batch = queue.pop_batch().expect("close batch");
        assert_eq!(batch.len(), 2);
        assert!(matches!(
            batch.first(),
            Some(WriteJob::Frame(frame)) if frame.frame_type == FrameType::Close
        ));
        assert!(matches!(batch.get(1), Some(WriteJob::Shutdown)));
        assert!(queue.pop_batch().is_none());
    }

    #[test]
    fn shutdown_discards_pending_jobs_without_close_frame() {
        let queue = queue(1024, 1024, 8);
        queue
            .push(frame_with_payload(FrameType::Data, 1, vec![1; 32]))
            .unwrap();
        queue.push(frame(FrameType::Ping, 0)).unwrap();

        queue.shutdown();

        let stats = queue.stats();
        assert_eq!(stats.queued_bytes, 0);
        assert_eq!(stats.urgent_jobs, 0);
        assert_eq!(stats.ordinary_jobs, 0);
        assert!(queue.pop_batch().is_none());
    }

    #[test]
    fn force_push_rejects_after_shutdown() {
        let queue = queue(1024, 1024, 8);
        queue.shutdown();

        let err = queue.force_push(frame(FrameType::Ping, 0)).unwrap_err();

        assert!(err.is_session_closed());
        assert!(queue.pop_batch().is_none());
    }

    #[test]
    fn stream_control_remains_in_ordinary_order_with_data() {
        let queue = queue(1024, 1024, 4);
        queue.push(frame(FrameType::Data, 1)).unwrap();
        queue.push(frame(FrameType::Reset, 1)).unwrap();

        let batch = queue.pop_batch().unwrap();
        let types = job_frame_types(batch);
        assert_eq!(types, vec![FrameType::Data, FrameType::Reset]);
    }

    #[test]
    fn stream_control_bypasses_capacity_behind_same_stream_data() {
        let queue = queue(17, 1024, 4);
        queue
            .push(frame_with_payload(FrameType::Data, 1, vec![b'x']))
            .unwrap();
        queue.push(frame(FrameType::Reset, 1)).unwrap();

        let batch = queue.pop_batch().unwrap();
        let types = job_frame_types(batch);
        assert_eq!(types, vec![FrameType::Data, FrameType::Reset]);
    }

    #[test]
    fn stream_control_bypasses_other_stream_data() {
        let queue = queue(17, 1024, 4);
        queue
            .push(frame_with_payload(FrameType::Data, 1, vec![b'x']))
            .unwrap();
        queue.push(frame(FrameType::Reset, 5)).unwrap();

        let batch = queue.pop_batch().unwrap();
        let types = job_frame_types(batch);
        assert_eq!(types, vec![FrameType::Reset, FrameType::Data]);
    }

    #[test]
    fn priority_update_is_latest_only_per_stream() {
        let queue = queue(1024, 1024, 4);
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id: 1,
                payload: vec![EXT_PRIORITY_UPDATE as u8, 10],
            }))
            .unwrap();
        queue.push(frame(FrameType::Data, 1)).unwrap();
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id: 1,
                payload: vec![EXT_PRIORITY_UPDATE as u8, 20],
            }))
            .unwrap();

        let batch = queue.pop_batch().unwrap();
        let ext_frames: Vec<_> = batch
            .iter()
            .filter_map(|job| match job {
                WriteJob::Frame(frame) | WriteJob::GracefulClose(frame)
                    if frame.frame_type == FrameType::Ext =>
                {
                    Some(frame)
                }
                _ => None,
            })
            .collect();
        assert_eq!(ext_frames.len(), 1);
        assert_eq!(ext_frames[0].payload, vec![EXT_PRIORITY_UPDATE as u8, 20]);
    }

    #[test]
    fn priority_update_replacement_merges_partial_fields() {
        let caps =
            CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS | CAPABILITY_STREAM_GROUPS;
        let queue = queue(1024, 1024, 4);
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id: 1,
                payload: build_priority_update_payload(
                    caps,
                    MetadataUpdate {
                        priority: Some(7),
                        group: None,
                    },
                    1024,
                )
                .unwrap(),
            }))
            .unwrap();
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id: 1,
                payload: build_priority_update_payload(
                    caps,
                    MetadataUpdate {
                        priority: None,
                        group: Some(9),
                    },
                    1024,
                )
                .unwrap(),
            }))
            .unwrap();

        let batch = queue.pop_batch().unwrap();
        let ext = batch
            .iter()
            .find_map(|job| match job {
                WriteJob::Frame(frame) if frame.frame_type == FrameType::Ext => Some(frame),
                _ => None,
            })
            .expect("missing priority update");
        assert_eq!(
            ext.payload,
            build_priority_update_payload(
                caps,
                MetadataUpdate {
                    priority: Some(7),
                    group: Some(9),
                },
                1024,
            )
            .unwrap()
        );
    }

    #[test]
    fn priority_update_bypasses_ordinary_byte_limit() {
        let queue = queue_with_limits(17, 1024, 1024, 1024, 1024, 1024, 4);
        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id: 1,
                payload: vec![EXT_PRIORITY_UPDATE as u8; 32],
            }))
            .unwrap();

        let stats = queue.stats();
        assert_eq!(stats.ordinary_jobs, 1);
        assert_eq!(stats.pending_priority_bytes, 33);
    }

    #[test]
    fn discard_priority_update_removes_shared_lane_updates() {
        let before_data = queue(1024, 1024, 8);
        before_data.push(priority_update_frame(1, 10)).unwrap();
        before_data.push(frame(FrameType::Data, 1)).unwrap();

        assert!(before_data.discard_priority_update(1));
        let batch = before_data.pop_batch().unwrap();
        assert_eq!(job_frame_types(batch), vec![FrameType::Data]);
        assert_eq!(before_data.stats().pending_priority_bytes, 0);

        let ordinary = queue(1024, 1024, 8);
        ordinary.push(frame(FrameType::Data, 1)).unwrap();
        ordinary.push(priority_update_frame(1, 20)).unwrap();

        assert!(ordinary.discard_priority_update(1));
        let batch = ordinary.pop_batch().unwrap();
        assert_eq!(job_frame_types(batch), vec![FrameType::Data]);
        assert_eq!(ordinary.stats().pending_priority_bytes, 0);
    }

    #[test]
    fn discard_stream_max_data_removes_only_stream_credit() {
        let queue = queue(1024, 1024, 8);
        queue
            .push(frame_with_payload(FrameType::MaxData, 1, vec![4]))
            .unwrap();
        queue.push(frame(FrameType::Data, 1)).unwrap();
        queue
            .push(frame_with_payload(FrameType::MaxData, 0, vec![8]))
            .unwrap();

        assert!(queue.discard_stream_max_data(1));
        assert!(!queue.discard_stream_max_data(1));
        assert_eq!(queue.stats().pending_control_bytes, 2);

        let batch = queue.pop_batch().unwrap();
        assert_eq!(
            job_frame_types(batch),
            vec![FrameType::MaxData, FrameType::Data]
        );
    }

    #[test]
    fn drained_priority_updates_release_ordinary_backing() {
        let queue = queue(8192, 8192, 8);
        for stream_id in 1..=96 {
            queue.push(priority_update_frame(stream_id, 1)).unwrap();
        }
        let initial_capacity = queue.state.lock().unwrap().ordinary_jobs.capacity();
        assert!(initial_capacity > MAX_INITIAL_QUEUE_SCRATCH_RESERVE);

        while queue.stats().ordinary_jobs != 0 {
            let batch = queue.pop_batch().unwrap();
            assert!(!batch.is_empty());
        }

        let retained_capacity = queue.state.lock().unwrap().ordinary_jobs.capacity();
        assert!(retained_capacity <= MAX_INITIAL_QUEUE_SCRATCH_RESERVE);
    }

    #[test]
    fn priority_update_shares_ordinary_lane_after_urgent() {
        let queue = queue(1024, 1024, 4);
        queue.push(frame(FrameType::Data, 1)).unwrap();
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id: 5,
                payload: vec![EXT_PRIORITY_UPDATE as u8, 10],
            }))
            .unwrap();
        queue.push(frame(FrameType::Ping, 0)).unwrap();

        let batch = queue.pop_batch().unwrap();
        assert_eq!(
            job_frame_types(batch),
            vec![FrameType::Ping, FrameType::Data, FrameType::Ext]
        );
    }

    #[test]
    fn priority_updates_keep_shared_ordinary_lane_order() {
        let queue = queue(1024, 1024, 8);
        for stream_id in [1, 5] {
            queue
                .push(WriteJob::Frame(Frame {
                    frame_type: FrameType::Ext,
                    flags: 0,
                    stream_id,
                    payload: vec![EXT_PRIORITY_UPDATE as u8, stream_id as u8],
                }))
                .unwrap();
        }
        queue.push(frame(FrameType::Data, 9)).unwrap();
        queue.push(frame(FrameType::Data, 13)).unwrap();

        let batch = queue.pop_batch().unwrap();
        let stream_ids: Vec<_> = batch
            .into_iter()
            .filter_map(|job| match job {
                WriteJob::Frame(frame) => Some(frame.stream_id),
                _ => None,
            })
            .collect();
        assert_eq!(stream_ids, vec![1, 5, 9, 13]);
    }

    #[test]
    fn same_stream_priority_update_stays_behind_queued_data() {
        let queue = queue(1024, 1024, 4);
        queue.push(frame(FrameType::Data, 1)).unwrap();
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id: 1,
                payload: vec![EXT_PRIORITY_UPDATE as u8, 10],
            }))
            .unwrap();

        let batch = queue.pop_batch().unwrap();
        assert_eq!(
            job_frame_types(batch),
            vec![FrameType::Data, FrameType::Ext]
        );
    }

    #[test]
    fn max_data_is_latest_only_per_scope() {
        let queue = queue(1024, 1024, 4);
        queue.push(frame(FrameType::Data, 1)).unwrap();
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 0,
                payload: vec![4],
            }))
            .unwrap();
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 0,
                payload: vec![8],
            }))
            .unwrap();

        let batch = queue.pop_batch().unwrap();
        let max_data: Vec<_> = batch
            .iter()
            .filter_map(|job| match job {
                WriteJob::Frame(frame) if frame.frame_type == FrameType::MaxData => Some(frame),
                _ => None,
            })
            .collect();
        assert_eq!(max_data.len(), 1);
        assert_eq!(max_data[0].payload, vec![8]);
    }

    #[test]
    fn blocked_keeps_latest_offset_per_scope() {
        let queue = queue(1024, 1024, 4);
        for payload in [vec![5], vec![5], vec![6]] {
            queue
                .push(WriteJob::Frame(Frame {
                    frame_type: FrameType::Blocked,
                    flags: 0,
                    stream_id: 1,
                    payload,
                }))
                .unwrap();
        }

        let batch = queue.pop_batch().unwrap();
        let blocked: Vec<_> = batch
            .iter()
            .filter_map(|job| match job {
                WriteJob::Frame(frame) if frame.frame_type == FrameType::Blocked => Some(frame),
                _ => None,
            })
            .collect();
        assert_eq!(blocked.len(), 1);
        assert_eq!(blocked[0].payload, vec![6]);
    }

    #[test]
    fn goaway_keeps_latest_pending_replacement() {
        let queue = queue(1024, 1024, 4);
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::GoAway,
                flags: 0,
                stream_id: 0,
                payload: build_go_away_payload(100, 100, 0, "initial").unwrap(),
            }))
            .unwrap();
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::GoAway,
                flags: 0,
                stream_id: 0,
                payload: build_go_away_payload(40, 80, 0, "final").unwrap(),
            }))
            .unwrap();

        let batch = queue.pop_batch().unwrap();
        let goaways: Vec<_> = batch
            .iter()
            .filter_map(|job| match job {
                WriteJob::Frame(frame) if frame.frame_type == FrameType::GoAway => Some(frame),
                _ => None,
            })
            .collect();
        assert_eq!(goaways.len(), 1);
        let payload = parse_go_away_payload(&goaways[0].payload).unwrap();
        assert_eq!(payload.last_accepted_bidi, 40);
        assert_eq!(payload.last_accepted_uni, 80);
        assert_eq!(payload.reason, "final");
    }

    #[test]
    fn urgent_lane_cap_limits_non_terminal_control() {
        let queue = queue(1024, 33, 8);
        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 0,
                payload: vec![0; 16],
            }))
            .unwrap();

        let err = queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ping,
                flags: 0,
                stream_id: 0,
                payload: vec![0; 16],
            }))
            .unwrap_err();
        assert!(err.to_string().contains("urgent writer queue full"));

        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::Close,
                flags: 0,
                stream_id: 0,
                payload: vec![0; 128],
            }))
            .unwrap();
        let stats = queue.stats();
        assert_eq!(stats.urgent_queued_bytes, 17);
        assert_eq!(stats.urgent_max_bytes, 33);

        let batch = queue.pop_batch().unwrap();
        let types = job_frame_types(batch);
        assert_eq!(types, vec![FrameType::MaxData, FrameType::Close]);
        assert_eq!(queue.stats().urgent_queued_bytes, 0);
    }

    #[test]
    fn urgent_lane_cap_applies_to_coalesced_replacements() {
        let queue = queue(1024, 24, 8);
        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 0,
                payload: vec![1; 8],
            }))
            .unwrap();
        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 0,
                payload: vec![2; 16],
            }))
            .unwrap();

        let err = queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 0,
                payload: vec![3; 32],
            }))
            .unwrap_err();
        assert!(err.to_string().contains("urgent writer queue full"));
        assert_eq!(queue.stats().urgent_queued_bytes, 17);

        let batch = queue.pop_batch().unwrap();
        let max_data: Vec<_> = batch
            .iter()
            .filter_map(|job| match job {
                WriteJob::Frame(frame) if frame.frame_type == FrameType::MaxData => Some(frame),
                _ => None,
            })
            .collect();
        assert_eq!(max_data.len(), 1);
        assert_eq!(max_data[0].payload, vec![2; 16]);
    }

    #[test]
    fn pending_control_budget_limits_coalesced_flow_control() {
        let queue = queue_with_limits(1024, 1024, 1024, 1024, 33, 1024, 8);
        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 0,
                payload: vec![1; 16],
            }))
            .unwrap();

        let err = queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 4,
                payload: vec![2; 16],
            }))
            .unwrap_err();
        assert!(err.to_string().contains("pending control budget"));
        assert_eq!(queue.stats().pending_control_bytes, 17);

        let batch = queue.pop_batch().unwrap();
        assert_eq!(job_frame_types(batch), vec![FrameType::MaxData]);
        assert_eq!(queue.stats().pending_control_bytes, 0);
    }

    #[test]
    fn smaller_pending_control_replacement_wakes_blocked_push() {
        let queue = Arc::new(queue_with_limits(1024, 1024, 1024, 1024, 33, 1024, 8));
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 0,
                payload: vec![1; 16],
            }))
            .unwrap();

        let worker_queue = queue.clone();
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = worker_queue.push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 4,
                payload: vec![2; 16],
            }));
            tx.send(result).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());

        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 0,
                payload: Vec::new(),
            }))
            .unwrap();

        rx.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
        worker.join().unwrap();
        assert_eq!(queue.stats().pending_control_bytes, 18);
    }

    #[test]
    fn discard_stream_removes_pending_flow_control_and_releases_budget() {
        let queue = queue_with_limits(1024, 1024, 1024, 1024, 1024, 1024, 8);
        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 64,
                payload: vec![1; 16],
            }))
            .unwrap();
        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::Blocked,
                flags: 0,
                stream_id: 64,
                payload: vec![2; 16],
            }))
            .unwrap();
        assert!(queue.stats().pending_control_bytes > 0);

        let discarded = queue.discard_stream(64);

        assert!(discarded.removed_any());
        assert_eq!(queue.stats().pending_control_bytes, 0);
        assert!(matches!(
            queue.pop_batch_wait(Some(Duration::ZERO)),
            WriteQueuePop::TimedOut
        ));
    }

    #[test]
    fn discard_stream_send_tail_preserves_receive_side_terminal_control() {
        let queue = queue_with_limits(4096, 4096, 4096, 4096, 4096, 4096, 8);
        queue
            .try_push(WriteJob::Frames(vec![
                Frame {
                    frame_type: FrameType::Data,
                    flags: 0,
                    stream_id: 64,
                    payload: b"hello".to_vec(),
                },
                Frame {
                    frame_type: FrameType::Ext,
                    flags: 0,
                    stream_id: 64,
                    payload: vec![EXT_PRIORITY_UPDATE as u8, 7],
                },
                Frame {
                    frame_type: FrameType::StopSending,
                    flags: 0,
                    stream_id: 64,
                    payload: vec![1],
                },
            ]))
            .unwrap();
        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::Blocked,
                flags: 0,
                stream_id: 64,
                payload: vec![2],
            }))
            .unwrap();
        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 64,
                payload: vec![3],
            }))
            .unwrap();

        let discarded = queue.discard_stream_send_tail(64);

        assert_eq!(discarded.data_frames, 1);
        assert_eq!(discarded.data_bytes, 5);
        assert_eq!(discarded.terminal_frames, 0);
        assert_eq!(queue.data_queued_bytes_for_stream(64), 0);
        let types = job_frame_types(queue.pop_batch().unwrap());
        assert!(types.contains(&FrameType::StopSending));
        assert!(types.contains(&FrameType::MaxData));
        assert!(!types.contains(&FrameType::Data));
        assert!(!types.contains(&FrameType::Blocked));
        assert!(!types.contains(&FrameType::Ext));
    }

    #[test]
    fn abortive_shutdown_discards_pending_flow_control_before_close() {
        let queue = queue_with_limits(1024, 1024, 1024, 1024, 1024, 1024, 8);
        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                flags: 0,
                stream_id: 0,
                payload: vec![1; 16],
            }))
            .unwrap();
        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::Blocked,
                flags: 0,
                stream_id: 64,
                payload: vec![2; 16],
            }))
            .unwrap();
        assert!(queue.stats().pending_control_bytes > 0);

        queue.shutdown_after_close(Frame {
            frame_type: FrameType::Close,
            flags: 0,
            stream_id: 0,
            payload: Vec::new(),
        });

        assert_eq!(queue.stats().pending_control_bytes, 0);
        let batch = queue.pop_batch().expect("close batch");
        assert_eq!(batch.len(), 2);
        assert!(matches!(
            batch.first(),
            Some(WriteJob::Frame(frame)) if frame.frame_type == FrameType::Close
        ));
        assert!(matches!(batch.get(1), Some(WriteJob::Shutdown)));
        assert!(queue.pop_batch().is_none());
    }

    #[test]
    fn pending_control_budget_limits_terminal_control_pressure() {
        let queue = queue_with_limits(1024, 1024, 1024, 1024, 33, 1024, 8);
        queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::Reset,
                flags: 0,
                stream_id: 1,
                payload: vec![1; 16],
            }))
            .unwrap();

        let err = queue
            .try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::StopSending,
                flags: 0,
                stream_id: 5,
                payload: vec![2; 16],
            }))
            .unwrap_err();
        assert!(err.to_string().contains("pending control budget"));
        assert_eq!(queue.stats().pending_control_bytes, 17);

        let batch = queue.pop_batch().unwrap();
        assert_eq!(job_frame_types(batch), vec![FrameType::Reset]);
        assert_eq!(queue.stats().pending_control_bytes, 0);
    }

    #[test]
    fn pending_priority_budget_limits_priority_updates() {
        let queue = queue_with_limits(1024, 1024, 1024, 1024, 1024, 33, 8);
        for stream_id in [1, 5] {
            let mut payload = vec![EXT_PRIORITY_UPDATE as u8, stream_id as u8];
            payload.extend_from_slice(&[0; 14]);
            let result = queue.try_push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id,
                payload,
            }));
            if stream_id == 1 {
                result.unwrap();
            } else {
                let err = result.unwrap_err();
                assert!(err.to_string().contains("pending priority budget"));
            }
        }
        assert_eq!(queue.stats().pending_priority_bytes, 17);
    }

    #[test]
    fn pending_priority_replacement_uses_delta_against_budget() {
        let queue = queue_with_limits(1024, 1024, 1024, 1024, 1024, 6, 8);
        queue.push(priority_update_frame(1, 1)).unwrap();
        queue.push(priority_update_frame(5, 5)).unwrap();

        queue.push(priority_update_frame(1, 9)).unwrap();

        assert_eq!(queue.stats().pending_priority_bytes, 6);
        let batch = queue.pop_batch().unwrap();
        assert_eq!(batch.len(), 2);
        assert_eq!(queue.stats().pending_priority_bytes, 0);
    }

    #[test]
    fn smaller_pending_priority_replacement_wakes_blocked_push() {
        let queue = Arc::new(queue_with_limits(1024, 1024, 1024, 1024, 1024, 33, 8));
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id: 1,
                payload: vec![EXT_PRIORITY_UPDATE as u8; 32],
            }))
            .unwrap();

        let worker_queue = queue.clone();
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = worker_queue.push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id: 5,
                payload: vec![EXT_PRIORITY_UPDATE as u8; 16],
            }));
            tx.send(result).unwrap();
        });
        assert!(rx.recv_timeout(Duration::from_millis(50)).is_err());

        queue.push(priority_update_frame(1, 1)).unwrap();

        rx.recv_timeout(Duration::from_secs(1)).unwrap().unwrap();
        worker.join().unwrap();
        assert_eq!(queue.stats().pending_priority_bytes, 20);
    }

    #[test]
    fn timed_priority_replacement_keeps_merged_cost_after_wait() {
        let caps =
            CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS | CAPABILITY_STREAM_GROUPS;
        let queue = Arc::new(queue_with_limits(1024, 1024, 1024, 1024, 1024, 10, 1));
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id: 1,
                payload: build_priority_update_payload(
                    caps,
                    MetadataUpdate {
                        priority: Some(7),
                        group: None,
                    },
                    1024,
                )
                .unwrap(),
            }))
            .unwrap();
        queue
            .push(WriteJob::Frame(Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id: 5,
                payload: build_priority_update_payload(
                    caps,
                    MetadataUpdate {
                        priority: Some(3),
                        group: None,
                    },
                    1024,
                )
                .unwrap(),
            }))
            .unwrap();

        let worker_queue = queue.clone();
        let (done_tx, done_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(200);
            let mut blocked = Duration::ZERO;
            let result = worker_queue.push_until(
                WriteJob::Frame(Frame {
                    frame_type: FrameType::Ext,
                    flags: 0,
                    stream_id: 1,
                    payload: build_priority_update_payload(
                        caps,
                        MetadataUpdate {
                            priority: None,
                            group: Some(9),
                        },
                        1024,
                    )
                    .unwrap(),
                }),
                || Some(deadline),
                || Ok(()),
                "priority update",
                &mut blocked,
            );
            let _ = done_tx.send(result);
        });

        assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
        let old = queue.pop_batch().expect("old priority update");
        assert_eq!(old.len(), 1);

        let err = done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("timed replacement should finish")
            .unwrap_err();
        assert!(err.is_timeout());
        worker.join().unwrap();
        assert_eq!(queue.stats().pending_priority_bytes, 5);
    }

    #[test]
    fn queued_data_high_watermarks_limit_session_and_stream_pressure() {
        let session_queue = queue_with_limits(1024, 1024, 33, 1024, 1024, 1024, 8);
        session_queue
            .try_push(frame_with_payload(FrameType::Data, 1, vec![b'x'; 16]))
            .unwrap();
        let err = session_queue
            .try_push(frame_with_payload(FrameType::Data, 5, vec![b'y'; 16]))
            .unwrap_err();
        assert!(err.to_string().contains("queued data high watermark"));
        assert_eq!(session_queue.stats().data_queued_bytes, 17);
        let _ = session_queue.pop_batch().unwrap();
        assert_eq!(session_queue.stats().data_queued_bytes, 0);

        let stream_queue = queue_with_limits(1024, 1024, 1024, 33, 1024, 1024, 8);
        stream_queue
            .try_push(frame_with_payload(FrameType::Data, 1, vec![b'x'; 16]))
            .unwrap();
        let err = stream_queue
            .try_push(frame_with_payload(FrameType::Data, 1, vec![b'y'; 16]))
            .unwrap_err();
        assert!(err.to_string().contains("queued data high watermark"));
    }

    #[test]
    fn per_stream_data_high_watermark_does_not_block_other_streams() {
        let queue = queue_with_limits(1024, 1024, 1024, 17, 1024, 1024, 8);
        queue
            .try_push(frame_with_payload(FrameType::Data, 1, vec![b'x'; 16]))
            .unwrap();

        queue
            .try_push(frame_with_payload(FrameType::Data, 5, vec![b'y'; 16]))
            .unwrap();

        let err = queue
            .try_push(frame_with_payload(FrameType::Data, 1, vec![b'z'; 1]))
            .unwrap_err();
        assert!(err.to_string().contains("queued data high watermark"));
        assert_eq!(queue.data_queued_bytes_for_stream(1), 17);
        assert_eq!(queue.data_queued_bytes_for_stream(5), 17);
    }

    #[test]
    fn queued_data_high_watermark_checks_use_saturating_addition() {
        let session_queue = queue_with_limits(
            usize::MAX,
            usize::MAX,
            usize::MAX - 1,
            usize::MAX,
            1024,
            1024,
            8,
        );
        session_queue.state.lock().unwrap().data_queued_bytes = usize::MAX - 1;
        let err = session_queue
            .try_push(frame_with_payload(FrameType::Data, 1, b"x".to_vec()))
            .unwrap_err();
        assert!(err.to_string().contains("queued data high watermark"));

        let stream_queue = queue_with_limits(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX - 1,
            1024,
            1024,
            8,
        );
        stream_queue
            .state
            .lock()
            .unwrap()
            .data_queued_by_stream
            .insert(1, usize::MAX - 1);
        let err = stream_queue
            .try_push(frame_with_payload(FrameType::Data, 1, b"x".to_vec()))
            .unwrap_err();
        assert!(err.to_string().contains("queued data high watermark"));
    }

    #[test]
    fn data_high_watermark_predicate_handles_backpressure_edges() {
        fn would_block(
            session_queued: usize,
            stream_queued: usize,
            requested: usize,
            session_high_watermark: usize,
            stream_high_watermark: usize,
        ) -> bool {
            let queue = queue_with_limits(
                usize::MAX,
                usize::MAX,
                session_high_watermark,
                stream_high_watermark,
                usize::MAX,
                usize::MAX,
                8,
            );
            let mut state = WriteQueueState {
                data_queued_bytes: session_queued,
                ..WriteQueueState::default()
            };
            if stream_queued != 0 {
                state.data_queued_by_stream.insert(1, stream_queued);
            }
            let mut data = DataCosts::default();
            if requested != 0 {
                data.add(1, requested);
            }
            let cost = QueueCost {
                queued: requested,
                urgent: 0,
                data,
                pending_control: 0,
                pending_priority: 0,
            };

            queue.would_exceed_data_capacity(&state, &cost)
        }

        let cases = [
            ("zero_request", 0, 0, 0, 8, 4, false),
            ("session_crosses_hwm", 4, 0, 5, 8, 8, true),
            ("stream_crosses_hwm", 0, 2, 3, 8, 4, true),
            ("session_at_zero_still_respects_limit", 0, 0, 9, 8, 8, true),
            ("below_limits", 3, 1, 2, 8, 4, false),
        ];

        for (
            name,
            session_queued,
            stream_queued,
            requested,
            session_high_watermark,
            stream_high_watermark,
            expected,
        ) in cases
        {
            assert_eq!(
                would_block(
                    session_queued,
                    stream_queued,
                    requested,
                    session_high_watermark,
                    stream_high_watermark,
                ),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn popping_one_data_frame_leaves_tail_data_accounting() {
        let queue = queue_with_limits(1024, 1024, 1024, 1024, 1024, 1024, 1);
        let first = frame_with_payload(FrameType::Data, 1, b"body".to_vec());
        let second = frame_with_payload(FrameType::Data, 1, b"tail".to_vec());
        let first_cost = first.cost_bytes();
        let second_cost = second.cost_bytes();

        queue.push(first).unwrap();
        queue.push(second).unwrap();
        assert_eq!(queue.stats().data_queued_bytes, first_cost + second_cost);

        let batch = queue.pop_batch().unwrap();

        assert_eq!(batch.len(), 1);
        assert_eq!(queue.stats().data_queued_bytes, second_cost);
        assert_eq!(queue.data_queued_bytes_for_stream(1), second_cost);
    }

    #[test]
    fn popping_queued_data_wakes_push_blocked_by_data_high_watermark() {
        fn assert_pop_wakes_blocked_push(
            session_data_max_bytes: usize,
            per_stream_data_max_bytes: usize,
            second_stream_id: u64,
        ) {
            let queue = Arc::new(queue_with_limits(
                1024,
                1024,
                session_data_max_bytes,
                per_stream_data_max_bytes,
                1024,
                1024,
                8,
            ));
            queue
                .try_push(frame_with_payload(FrameType::Data, 1, vec![b'x'; 16]))
                .unwrap();

            let writer_queue = queue.clone();
            let (done_tx, done_rx) = mpsc::channel();
            let writer = thread::spawn(move || {
                let result = writer_queue.push(frame_with_payload(
                    FrameType::Data,
                    second_stream_id,
                    vec![b'y'; 16],
                ));
                let _ = done_tx.send(result);
            });

            assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
            let _ = queue.pop_batch().unwrap();
            match done_rx.recv_timeout(Duration::from_secs(1)) {
                Ok(result) => result.unwrap(),
                Err(err) => {
                    queue.shutdown();
                    panic!("blocked data push did not wake after pop: {err}");
                }
            }
            writer.join().unwrap();
            assert_eq!(queue.stats().data_queued_bytes, 17);
        }

        assert_pop_wakes_blocked_push(17, 1024, 5);
        assert_pop_wakes_blocked_push(1024, 17, 1);
    }

    #[test]
    fn graceful_close_drains_after_ordinary_data_before_shutdown() {
        let queue = queue(1024, 1024, 8);
        queue.push(frame(FrameType::Data, 1)).unwrap();
        queue
            .push(WriteJob::GracefulClose(Frame {
                frame_type: FrameType::Close,
                flags: 0,
                stream_id: 0,
                payload: Vec::new(),
            }))
            .unwrap();
        queue.force_push(WriteJob::DrainShutdown).unwrap();

        let batch = queue.pop_batch().unwrap();
        let types = job_frame_types(batch);
        assert_eq!(
            types,
            vec![FrameType::Data, FrameType::Close, FrameType::Close]
        );
    }
}
