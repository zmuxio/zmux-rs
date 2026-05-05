use super::ingress::retry_pending_receive_credit;
use super::liveness::{
    clear_unsent_keepalive_ping, close_for_idle_timeout, poll_keepalive, record_outbound_activity,
    KeepaliveAction,
};
use super::queue::WriteQueuePopStatus;
use super::scheduler::{BatchConfig, BatchItem, GroupKey, RequestMeta, StreamMeta};
use super::state::{
    emit_event, fail_session, mark_stream_peer_visible_by_id, maybe_release_active_count,
    note_written_stream_frames_locked, queue_peer_visible_pending_priority,
};
use super::types::{Inner, SessionState, WriteCompletion, WriteJob};
use crate::error::{Error, Result};
use crate::frame::{
    Frame, FrameType, Limits, FRAME_FLAG_FIN, FRAME_FLAG_OPEN_METADATA, MAX_FRAME_HEADER_LEN,
};
use crate::payload::parse_data_payload_metadata_offset;
use crate::protocol::EXT_PRIORITY_UPDATE;
use crate::settings::SchedulerHint;
use crate::varint::parse_varint;
use std::collections::HashSet;
use std::io::{ErrorKind, IoSlice, Write};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

pub(super) fn spawn_writer<W>(inner: Arc<Inner>, mut writer: W)
where
    W: Write + Send + 'static,
{
    thread::spawn(move || {
        let _close_on_exit = TransportCloseOnExit {
            inner: inner.clone(),
        };
        let mut encoded = Vec::new();
        let mut encoded_frames = Vec::new();
        let mut opened_streams = Vec::new();
        let mut opened_stream_seen = HashSet::new();
        let mut opened_events = Vec::new();
        let mut pending_priorities = Vec::new();
        let mut queue_batch = Vec::new();
        let mut write_completions = Vec::new();
        let mut dropped_data = Vec::new();
        let mut writable_cache = Vec::new();
        let mut scheduler_items = Vec::new();
        let mut order = Vec::new();
        let mut scheduler_order = Vec::new();
        let mut inverse_order = Vec::new();
        let mut stats = EncodedBatchStats::default();
        while next_writer_batch(&inner, &mut queue_batch) {
            let mut shutdown = false;
            stats.clear();
            write_completions.clear();
            encoded.clear();
            encoded_frames.clear();
            opened_streams.clear();
            opened_stream_seen.clear();
            opened_events.clear();
            pending_priorities.clear();
            order_batch(
                &inner,
                &mut queue_batch,
                &mut scheduler_items,
                &mut order,
                &mut scheduler_order,
                &mut inverse_order,
            );
            scheduler_items.clear();
            order.clear();
            scheduler_order.clear();
            trim_vec_capacity(
                &mut scheduler_items,
                queue_batch.len(),
                MIN_RETAINED_BATCH_FRAMES,
                MAX_RETAINED_ACCOUNTING_ENTRIES,
            );
            trim_vec_capacity(
                &mut order,
                queue_batch.len(),
                MIN_RETAINED_BATCH_FRAMES,
                MAX_RETAINED_ACCOUNTING_ENTRIES,
            );
            trim_vec_capacity(
                &mut scheduler_order,
                queue_batch.len(),
                MIN_RETAINED_BATCH_FRAMES,
                MAX_RETAINED_ACCOUNTING_ENTRIES,
            );
            filter_writable_batch_cached(
                &inner,
                &mut queue_batch,
                &mut dropped_data,
                &mut writable_cache,
            );
            let retained_batch_len = queue_batch.len();
            if queue_batch.is_empty() {
                trim_vec_capacity(
                    &mut queue_batch,
                    retained_batch_len,
                    MIN_RETAINED_BATCH_FRAMES,
                    MAX_RETAINED_ACCOUNTING_ENTRIES,
                );
                continue;
            }
            if let Err(err) = encode_batch(
                &mut queue_batch,
                inner.peer_preface.settings.limits(),
                EncodeBatchScratch {
                    encoded: &mut encoded_frames,
                    shutdown: &mut shutdown,
                    opened_streams: &mut opened_streams,
                    opened_stream_seen: &mut opened_stream_seen,
                    stats: &mut stats,
                    completions: &mut write_completions,
                },
            ) {
                complete_write_completions(&mut write_completions, Err(err.clone()));
                fail_session(&inner, err);
                return;
            }
            if encoded_frames.is_empty() {
                complete_write_completions(&mut write_completions, Ok(()));
                if shutdown {
                    break;
                }
                continue;
            }
            add_inflight_data(&inner, &stats.data_cost_by_stream);
            let write_started = Instant::now();
            let write_result = if should_use_vectored_batch(&stats) {
                write_encoded_frames_vectored(&mut writer, &encoded_frames).map_err(Error::from)
            } else {
                append_encoded_frames(&encoded_frames, stats.encoded_bytes, &mut encoded)
                    .and_then(|()| writer.write_all(&encoded).map_err(Error::from))
            };
            if let Err(err) = write_result {
                remove_inflight_data(&inner, &stats.data_cost_by_stream);
                record_writer_failure_diagnostic(&inner, stats.close_frames != 0);
                complete_write_completions(&mut write_completions, Err(err.clone()));
                fail_session(&inner, err);
                return;
            }
            if let Err(err) = writer.flush() {
                let err = Error::from(err);
                remove_inflight_data(&inner, &stats.data_cost_by_stream);
                record_writer_failure_diagnostic(&inner, stats.close_frames != 0);
                complete_write_completions(&mut write_completions, Err(err.clone()));
                fail_session(&inner, err);
                break;
            }
            clear_written_batch_scratch(&mut encoded, &mut encoded_frames, &stats);
            remove_inflight_data(&inner, &stats.data_cost_by_stream);
            let opened_count = opened_streams.len();
            if opened_events.try_reserve(opened_count).is_err()
                || pending_priorities.try_reserve(opened_count).is_err()
            {
                let err = Error::local("zmux: stream-open event allocation failed");
                complete_write_completions(&mut write_completions, Err(err.clone()));
                fail_session(&inner, err);
                return;
            }
            for stream_id in opened_streams.drain(..) {
                if let Some(update) = mark_stream_peer_visible_by_id(&inner, stream_id) {
                    opened_events.push(update.event);
                    if let Some(payload) = update.pending_priority {
                        pending_priorities.push((stream_id, payload));
                    }
                }
            }
            complete_written_stream_frames(
                &inner,
                &stats.data_frame_count_by_stream,
                &stats.terminal_frame_count_by_stream,
            );
            complete_write_completions(&mut write_completions, Ok(()));
            if let Err(err) = retry_pending_receive_credit(&inner) {
                fail_session(&inner, err);
                return;
            }
            if stats.encoded_bytes > 0 {
                record_outbound_activity(
                    &inner,
                    stats.encoded_bytes,
                    write_started.elapsed(),
                    stats.frames,
                    stats.data_bytes,
                );
            }
            for (stream_id, payload) in pending_priorities.drain(..) {
                queue_peer_visible_pending_priority(&inner, stream_id, payload);
            }
            for event in opened_events.drain(..) {
                emit_event(&inner, event);
            }
            trim_vec_capacity(
                &mut opened_streams,
                opened_count,
                MIN_RETAINED_BATCH_FRAMES,
                MAX_RETAINED_ACCOUNTING_ENTRIES,
            );
            trim_vec_capacity(
                &mut opened_events,
                opened_count,
                MIN_RETAINED_BATCH_FRAMES,
                MAX_RETAINED_ACCOUNTING_ENTRIES,
            );
            trim_vec_capacity(
                &mut pending_priorities,
                opened_count,
                MIN_RETAINED_BATCH_FRAMES,
                MAX_RETAINED_ACCOUNTING_ENTRIES,
            );
            trim_vec_capacity(
                &mut queue_batch,
                retained_batch_len,
                MIN_RETAINED_BATCH_FRAMES,
                MAX_RETAINED_ACCOUNTING_ENTRIES,
            );
            opened_stream_seen.clear();
            trim_hashset_capacity(
                &mut opened_stream_seen,
                opened_count,
                MIN_RETAINED_BATCH_FRAMES,
                MAX_RETAINED_ACCOUNTING_ENTRIES,
            );
            if shutdown {
                break;
            }
        }
    });
}

struct TransportCloseOnExit {
    inner: Arc<Inner>,
}

impl Drop for TransportCloseOnExit {
    fn drop(&mut self) {
        if let Some(control) = &self.inner.transport_control {
            control.close();
        }
    }
}

fn next_writer_batch(inner: &Arc<Inner>, batch: &mut Vec<WriteJob>) -> bool {
    loop {
        match poll_keepalive(inner, Instant::now()) {
            Err(err) => {
                fail_session(inner, err);
                continue;
            }
            Ok(action) => match action {
                KeepaliveAction::SendPing(payload) => {
                    if let Err(err) = inner.force_queue_frame(Frame {
                        frame_type: FrameType::Ping,
                        flags: 0,
                        stream_id: 0,
                        payload,
                    }) {
                        clear_unsent_keepalive_ping(inner);
                        if err.is_session_closed() {
                            return false;
                        }
                        fail_session(inner, err);
                    }
                    continue;
                }
                KeepaliveAction::Timeout => {
                    close_for_idle_timeout(inner);
                    continue;
                }
                KeepaliveAction::Wait(wait) => {
                    match inner.write_queue.pop_batch_wait_into(batch, wait) {
                        WriteQueuePopStatus::Batch => return true,
                        WriteQueuePopStatus::TimedOut => continue,
                        WriteQueuePopStatus::Closed => return false,
                    }
                }
            },
        }
    }
}

fn record_writer_failure_diagnostic(inner: &Arc<Inner>, close_frame_attempted: bool) {
    let mut state = inner.state.lock().unwrap();
    if close_frame_attempted {
        state.close_frame_flush_error_count = state.close_frame_flush_error_count.saturating_add(1);
    } else {
        state.skipped_close_on_dead_io_count =
            state.skipped_close_on_dead_io_count.saturating_add(1);
    }
}

fn encode_batch(
    batch: &mut Vec<WriteJob>,
    limits: Limits,
    scratch: EncodeBatchScratch<'_>,
) -> Result<()> {
    let EncodeBatchScratch {
        encoded,
        shutdown,
        opened_streams,
        opened_stream_seen,
        stats,
        completions,
    } = scratch;
    let frame_count = batch.iter().try_fold(0usize, |sum, job| {
        sum.checked_add(job_frame_count(job))
            .ok_or_else(|| Error::frame_size("write batch frame count overflow"))
    })?;
    encoded
        .try_reserve(frame_count)
        .map_err(|_| Error::local("zmux: encoded frame batch allocation failed"))?;
    opened_streams
        .try_reserve(frame_count)
        .map_err(|_| Error::local("zmux: opened stream batch allocation failed"))?;
    stats
        .data_cost_by_stream
        .try_reserve(frame_count)
        .map_err(|_| Error::local("zmux: write accounting allocation failed"))?;
    stats
        .data_frame_count_by_stream
        .try_reserve(frame_count)
        .map_err(|_| Error::local("zmux: write accounting allocation failed"))?;
    stats
        .terminal_frame_count_by_stream
        .try_reserve(frame_count)
        .map_err(|_| Error::local("zmux: write accounting allocation failed"))?;
    for job in batch.drain(..) {
        match job {
            WriteJob::Frame(frame) | WriteJob::GracefulClose(frame) => {
                encode_frame(
                    frame,
                    limits,
                    encoded,
                    opened_streams,
                    opened_stream_seen,
                    stats,
                )?;
            }
            WriteJob::Frames(frames) => {
                for frame in frames {
                    encode_frame(
                        frame,
                        limits,
                        encoded,
                        opened_streams,
                        opened_stream_seen,
                        stats,
                    )?;
                }
            }
            WriteJob::TrackedFrames(tracked) => {
                completions.push(tracked.completion);
                for frame in tracked.frames {
                    encode_frame(
                        frame,
                        limits,
                        encoded,
                        opened_streams,
                        opened_stream_seen,
                        stats,
                    )?;
                }
            }
            WriteJob::Shutdown | WriteJob::DrainShutdown => {
                *shutdown = true;
                break;
            }
        }
    }
    stats.coalesce_stream_accounting();
    Ok(())
}

struct EncodeBatchScratch<'a> {
    encoded: &'a mut Vec<EncodedFrame>,
    shutdown: &'a mut bool,
    opened_streams: &'a mut Vec<u64>,
    opened_stream_seen: &'a mut HashSet<u64>,
    stats: &'a mut EncodedBatchStats,
    completions: &'a mut Vec<WriteCompletion>,
}

fn complete_write_completions(completions: &mut Vec<WriteCompletion>, result: Result<()>) {
    for completion in completions.drain(..) {
        match &result {
            Ok(()) => completion.complete_ok(),
            Err(err) => completion.complete_err(err.clone()),
        }
    }
}

#[cfg(test)]
pub(super) fn filter_writable_batch(
    inner: &Arc<Inner>,
    batch: &mut Vec<WriteJob>,
    dropped: &mut Vec<(u64, usize, u64)>,
) {
    let mut writable_cache = Vec::new();
    filter_writable_batch_cached(inner, batch, dropped, &mut writable_cache);
}

fn filter_writable_batch_cached(
    inner: &Arc<Inner>,
    batch: &mut Vec<WriteJob>,
    dropped: &mut Vec<(u64, usize, u64)>,
    writable_cache: &mut Vec<WritableFrameDecision>,
) {
    dropped.clear();
    writable_cache.clear();
    batch.retain_mut(|job| retain_writable_job(inner, job, dropped, writable_cache));
    release_dropped_data(inner, dropped);
    let dropped_count = dropped.len();
    dropped.clear();
    trim_vec_capacity(
        dropped,
        dropped_count,
        MIN_RETAINED_BATCH_FRAMES,
        MAX_RETAINED_ACCOUNTING_ENTRIES,
    );
    let cached_count = writable_cache.len();
    writable_cache.clear();
    trim_vec_capacity(
        writable_cache,
        cached_count,
        MIN_RETAINED_BATCH_FRAMES,
        MAX_RETAINED_ACCOUNTING_ENTRIES,
    );
}

#[derive(Clone, Copy)]
struct WritableFrameDecision {
    stream_id: u64,
    data: bool,
    priority_update: bool,
    priority_update_before_data: bool,
    priority_update_before_fin: bool,
}

impl WritableFrameDecision {
    fn blocked(stream_id: u64) -> Self {
        Self {
            stream_id,
            data: false,
            priority_update: false,
            priority_update_before_data: false,
            priority_update_before_fin: false,
        }
    }
}

fn retain_writable_job(
    inner: &Arc<Inner>,
    job: &mut WriteJob,
    dropped: &mut Vec<(u64, usize, u64)>,
    writable_cache: &mut Vec<WritableFrameDecision>,
) -> bool {
    match job {
        WriteJob::Frame(frame) => {
            retain_writable_frame(inner, frame, dropped, writable_cache, false)
        }
        WriteJob::Frames(frames) => {
            retain_writable_frames(inner, frames, dropped, writable_cache);
            !frames.is_empty()
        }
        WriteJob::TrackedFrames(tracked) => {
            let dropped_data_frame =
                retain_writable_frames(inner, &mut tracked.frames, dropped, writable_cache);
            if tracked.frames.is_empty() || dropped_data_frame {
                tracked
                    .completion
                    .complete_err(Error::local("zmux: queued write is no longer writable"));
                return false;
            }
            true
        }
        WriteJob::GracefulClose(_) | WriteJob::Shutdown | WriteJob::DrainShutdown => true,
    }
}

fn retain_writable_frames(
    inner: &Arc<Inner>,
    frames: &mut Vec<Frame>,
    dropped: &mut Vec<(u64, usize, u64)>,
    writable_cache: &mut Vec<WritableFrameDecision>,
) -> bool {
    let mut dropped_data_frame = false;
    let mut opening_priority_stream = None;
    let has_priority_before_data_candidate = frames.windows(2).any(|pair| {
        frame_is_priority_update(&pair[0])
            && pair[1].frame_type == FrameType::Data
            && pair[1].stream_id == pair[0].stream_id
    });
    let mut priority_before_data = Vec::new();
    if has_priority_before_data_candidate {
        priority_before_data.reserve_exact(frames.len());
        for index in 0..frames.len() {
            priority_before_data.push(priority_update_allowed_before_following_data(
                inner,
                frames,
                index,
                writable_cache,
            ));
        }
    }
    let mut index = 0usize;
    frames.retain(|frame| {
        let allow_opening_priority_update =
            frame_is_priority_update(frame) && opening_priority_stream == Some(frame.stream_id);
        let allow_priority_before_data = has_priority_before_data_candidate
            && priority_before_data.get(index).copied().unwrap_or(false);
        index = index.saturating_add(1);
        let keep = retain_writable_frame(
            inner,
            frame,
            dropped,
            writable_cache,
            allow_opening_priority_update || allow_priority_before_data,
        );
        dropped_data_frame |= !keep && frame.frame_type == FrameType::Data;
        opening_priority_stream = next_opening_priority_stream(inner, frame, keep, writable_cache);
        keep
    });
    dropped_data_frame
}

fn priority_update_allowed_before_following_data(
    inner: &Arc<Inner>,
    frames: &[Frame],
    index: usize,
    writable_cache: &mut Vec<WritableFrameDecision>,
) -> bool {
    let Some(frame) = frames.get(index) else {
        return false;
    };
    if !frame_is_priority_update(frame) {
        return false;
    }
    let Some(next) = frames.get(index.saturating_add(1)) else {
        return false;
    };
    if next.frame_type != FrameType::Data || next.stream_id != frame.stream_id {
        return false;
    }
    let decision = writable_frame_decision(inner, frame.stream_id, writable_cache);
    decision.data
        && (decision.priority_update_before_data
            || (next.flags & FRAME_FLAG_FIN != 0 && decision.priority_update_before_fin))
}

fn next_opening_priority_stream(
    inner: &Arc<Inner>,
    frame: &Frame,
    keep: bool,
    writable_cache: &mut Vec<WritableFrameDecision>,
) -> Option<u64> {
    if keep && frame.frame_type == FrameType::Data && frame.stream_id != 0 {
        let decision = writable_frame_decision(inner, frame.stream_id, writable_cache);
        if !decision.priority_update {
            return Some(frame.stream_id);
        }
    }
    None
}

fn retain_writable_frame(
    inner: &Arc<Inner>,
    frame: &Frame,
    dropped: &mut Vec<(u64, usize, u64)>,
    writable_cache: &mut Vec<WritableFrameDecision>,
    allow_opening_priority_update: bool,
) -> bool {
    if frame.frame_type == FrameType::Data {
        if writable_frame_decision(inner, frame.stream_id, writable_cache).data {
            return true;
        }
        note_dropped_data(dropped, frame.stream_id, frame_data_bytes(frame));
        return false;
    }
    !frame_is_priority_update(frame)
        || allow_opening_priority_update
        || writable_frame_decision(inner, frame.stream_id, writable_cache).priority_update
}

fn writable_frame_decision(
    inner: &Arc<Inner>,
    stream_id: u64,
    writable_cache: &mut Vec<WritableFrameDecision>,
) -> WritableFrameDecision {
    if let Some(decision) = writable_cache
        .iter()
        .find(|decision| decision.stream_id == stream_id)
        .copied()
    {
        return decision;
    }
    let decision = stream_writable_decision(inner, stream_id);
    writable_cache.push(decision);
    decision
}

fn stream_writable_decision(inner: &Arc<Inner>, stream_id: u64) -> WritableFrameDecision {
    let stream = {
        let state = inner.state.lock().unwrap();
        if matches!(state.state, SessionState::Closed | SessionState::Failed) {
            return WritableFrameDecision::blocked(stream_id);
        }
        state.streams.get(&stream_id).cloned()
    };
    let Some(stream) = stream else {
        return WritableFrameDecision::blocked(stream_id);
    };
    let state = stream.state.lock().unwrap();
    let data = state.aborted.is_none() && state.send_reset.is_none();
    let priority_update_non_terminal =
        stream.local_send && state.aborted.is_none() && state.stopped_by_peer.is_none();
    let priority_update = priority_update_send_state_allows(
        stream.local_send,
        stream.opened_locally,
        state.peer_visible,
        state.aborted.is_some(),
        state.stopped_by_peer.is_some(),
        state.send_fin,
        state.send_reset.is_some(),
    );
    let priority_update_before_data = priority_update_non_terminal
        && state.send_reset.is_none()
        && stream.opened_locally
        && state.opened_on_wire
        && !state.peer_visible;
    let priority_update_before_fin = priority_update_non_terminal
        && state.send_reset.is_none()
        && (!stream.opened_locally || state.opened_on_wire);
    WritableFrameDecision {
        stream_id,
        data,
        priority_update,
        priority_update_before_data,
        priority_update_before_fin,
    }
}

fn priority_update_send_state_allows(
    local_send: bool,
    opened_locally: bool,
    peer_visible: bool,
    aborted: bool,
    stopped_by_peer: bool,
    send_fin: bool,
    send_reset: bool,
) -> bool {
    local_send
        && !aborted
        && !stopped_by_peer
        && !send_fin
        && !send_reset
        && (!opened_locally || peer_visible)
}

fn note_dropped_data(dropped: &mut Vec<(u64, usize, u64)>, stream_id: u64, bytes: u64) {
    if let Some((_, frames, total)) = dropped.iter_mut().find(|(id, _, _)| *id == stream_id) {
        *frames = frames.saturating_add(1);
        *total = total.saturating_add(bytes);
    } else {
        dropped.push((stream_id, 1, bytes));
    }
}

fn release_dropped_data(inner: &Arc<Inner>, dropped: &[(u64, usize, u64)]) {
    if dropped.is_empty() {
        return;
    }
    let mut conn_state = inner.state.lock().unwrap();
    for (stream_id, frames, bytes) in dropped {
        let Some(stream) = conn_state.streams.get(stream_id).cloned() else {
            continue;
        };
        let mut stream_state = stream.state.lock().unwrap();
        stream_state.pending_data_frames = stream_state.pending_data_frames.saturating_sub(*frames);
        let released = (*bytes).min(stream_state.send_used);
        stream_state.send_used = stream_state.send_used.saturating_sub(released);
        conn_state.send_session_used = conn_state.send_session_used.saturating_sub(released);
        maybe_release_active_count(&mut conn_state, &stream, &mut stream_state);
        drop(stream_state);
        stream.cond.notify_all();
    }
    drop(conn_state);
    inner.cond.notify_all();
}

fn job_frame_count(job: &WriteJob) -> usize {
    match job {
        WriteJob::Frame(_) | WriteJob::GracefulClose(_) => 1,
        WriteJob::Frames(frames) => frames.len(),
        WriteJob::TrackedFrames(tracked) => tracked.frames.len(),
        WriteJob::Shutdown | WriteJob::DrainShutdown => 0,
    }
}

#[derive(Default)]
struct EncodedBatchStats {
    frames: u64,
    close_frames: u64,
    encoded_bytes: usize,
    data_bytes: u64,
    payload_bytes: usize,
    segments: usize,
    data_cost_by_stream: Vec<(u64, usize)>,
    data_frame_count_by_stream: Vec<(u64, usize)>,
    terminal_frame_count_by_stream: Vec<(u64, usize)>,
}

impl EncodedBatchStats {
    fn clear(&mut self) {
        let recent_frames = usize::try_from(self.frames).unwrap_or(usize::MAX);
        self.frames = 0;
        self.close_frames = 0;
        self.encoded_bytes = 0;
        self.data_bytes = 0;
        self.payload_bytes = 0;
        self.segments = 0;
        self.data_cost_by_stream.clear();
        self.data_frame_count_by_stream.clear();
        self.terminal_frame_count_by_stream.clear();
        trim_vec_capacity(
            &mut self.data_cost_by_stream,
            recent_frames,
            MIN_RETAINED_BATCH_FRAMES,
            MAX_RETAINED_ACCOUNTING_ENTRIES,
        );
        trim_vec_capacity(
            &mut self.data_frame_count_by_stream,
            recent_frames,
            MIN_RETAINED_BATCH_FRAMES,
            MAX_RETAINED_ACCOUNTING_ENTRIES,
        );
        trim_vec_capacity(
            &mut self.terminal_frame_count_by_stream,
            recent_frames,
            MIN_RETAINED_BATCH_FRAMES,
            MAX_RETAINED_ACCOUNTING_ENTRIES,
        );
    }

    fn coalesce_stream_accounting(&mut self) {
        coalesce_stream_values(&mut self.data_cost_by_stream);
        coalesce_stream_values(&mut self.data_frame_count_by_stream);
        coalesce_stream_values(&mut self.terminal_frame_count_by_stream);
    }
}

struct EncodedFrame {
    header: [u8; MAX_FRAME_HEADER_LEN],
    header_len: u8,
    payload: Vec<u8>,
}

fn order_batch(
    inner: &Arc<Inner>,
    batch: &mut [WriteJob],
    scheduler_items: &mut Vec<BatchItem>,
    order: &mut Vec<usize>,
    scheduler_order: &mut Vec<usize>,
    inverse_order: &mut Vec<usize>,
) {
    let ordered_len = batch
        .iter()
        .position(job_is_ordered_tail)
        .unwrap_or(batch.len());
    order_batch_frames(
        inner,
        &mut batch[..ordered_len],
        scheduler_items,
        order,
        scheduler_order,
        inverse_order,
    );
}

fn order_batch_frames(
    inner: &Arc<Inner>,
    batch: &mut [WriteJob],
    scheduler_items: &mut Vec<BatchItem>,
    order: &mut Vec<usize>,
    scheduler_order: &mut Vec<usize>,
    inverse_order: &mut Vec<usize>,
) {
    if batch.len() < 2 {
        return;
    }

    let urgent_len = batch.iter().take_while(|job| job_is_urgent(job)).count();
    let needs_urgent_order = urgent_len > 1;
    let needs_nonurgent_order =
        urgent_len < batch.len() && !same_stream_burst_keeps_order(&batch[urgent_len..]);
    if !needs_urgent_order && !needs_nonurgent_order {
        return;
    }

    if urgent_len == batch.len() {
        order_with_scheduler(inner, batch, true, scheduler_items, order);
        apply_order_if_needed(batch, order, inverse_order);
        return;
    }
    if urgent_len == 0 {
        order_with_scheduler(inner, batch, false, scheduler_items, order);
        apply_order_if_needed(batch, order, inverse_order);
        return;
    }

    order.clear();
    if order.capacity() < batch.len() && order.try_reserve(batch.len()).is_err() {
        return;
    }
    order.extend(0..batch.len());
    if needs_urgent_order {
        order_with_scheduler(
            inner,
            &batch[..urgent_len],
            true,
            scheduler_items,
            scheduler_order,
        );
        if scheduler_order.len() == urgent_len {
            for (dst, idx) in scheduler_order.iter().copied().enumerate() {
                order[dst] = idx;
            }
        }
    }

    if needs_nonurgent_order {
        let nonurgent = &batch[urgent_len..];
        order_with_scheduler(inner, nonurgent, false, scheduler_items, scheduler_order);
        if scheduler_order.len() == nonurgent.len() {
            for (dst, idx) in scheduler_order.iter().copied().enumerate() {
                order[urgent_len + dst] = urgent_len + idx;
            }
        }
    }

    apply_order_if_needed(batch, order, inverse_order);
}

fn apply_order_if_needed(batch: &mut [WriteJob], order: &[usize], inverse_order: &mut Vec<usize>) {
    if order.len() != batch.len() || order_is_identity(order) {
        return;
    }
    let _ = apply_order_in_place(batch, order, inverse_order);
}

fn job_is_ordered_tail(job: &WriteJob) -> bool {
    matches!(
        job,
        WriteJob::GracefulClose(_) | WriteJob::Shutdown | WriteJob::DrainShutdown
    )
}

fn order_is_identity(order: &[usize]) -> bool {
    order
        .iter()
        .enumerate()
        .all(|(idx, ordered)| idx == *ordered)
}

fn order_with_scheduler(
    inner: &Arc<Inner>,
    jobs: &[WriteJob],
    urgent: bool,
    items: &mut Vec<BatchItem>,
    order: &mut Vec<usize>,
) {
    order.clear();
    let group_fair = inner.peer_preface.settings.scheduler_hints == SchedulerHint::GroupFair;
    items.clear();
    if items.try_reserve(jobs.len()).is_err() {
        return;
    }
    let mut state = inner.state.lock().unwrap();
    for (idx, job) in jobs.iter().enumerate() {
        let mut request = classify_job_for_scheduler(job);
        request.group_key = GroupKey::transient(idx);
        let mut stream = StreamMeta::default();
        if request.stream_scoped {
            request.group_key = GroupKey::stream(request.stream_id);
            if let Some((priority, group)) =
                state.streams.get(&request.stream_id).map(|stream_inner| {
                    let stream_state = stream_inner.state.lock().unwrap();
                    (
                        stream_state.metadata.priority.unwrap_or(0),
                        stream_state.metadata.group,
                    )
                })
            {
                stream.priority = priority;
                if !urgent {
                    request.group_key =
                        state
                            .scheduler
                            .group_key_for_stream(request.stream_id, group, group_fair);
                }
            } else if !urgent {
                state.scheduler.drop_stream(request.stream_id);
            }
        }
        items.push(BatchItem { request, stream });
    }

    state.scheduler.order_into(
        BatchConfig {
            urgent,
            scheduler_hint: inner.peer_preface.settings.scheduler_hints,
            max_frame_payload: inner.peer_preface.settings.max_frame_payload,
        },
        items,
        order,
    );
    drop(state);
    items.clear();
}

fn apply_order_in_place(
    batch: &mut [WriteJob],
    order: &[usize],
    inverse_order: &mut Vec<usize>,
) -> bool {
    if batch.len() != order.len() {
        return false;
    }
    inverse_order.clear();
    if inverse_order.try_reserve(order.len()).is_err() {
        return false;
    }
    inverse_order.resize(order.len(), usize::MAX);
    for (new_idx, old_idx) in order.iter().copied().enumerate() {
        if old_idx >= order.len() || inverse_order[old_idx] != usize::MAX {
            inverse_order.clear();
            return false;
        }
        inverse_order[old_idx] = new_idx;
    }

    for idx in 0..batch.len() {
        while inverse_order[idx] != idx {
            let target = inverse_order[idx];
            batch.swap(idx, target);
            inverse_order.swap(idx, target);
        }
    }
    inverse_order.clear();
    true
}

fn same_stream_burst_keeps_order(jobs: &[WriteJob]) -> bool {
    let Some(first) = jobs.first() else {
        return false;
    };
    let first = classify_job_for_scheduler(first);
    if !first.stream_scoped || first.is_priority_update {
        return false;
    }
    jobs.iter().skip(1).all(|job| {
        let request = classify_job_for_scheduler(job);
        request.stream_scoped && !request.is_priority_update && request.stream_id == first.stream_id
    })
}

fn classify_job_for_scheduler(job: &WriteJob) -> RequestMeta {
    let mut request = RequestMeta {
        cost: job_cost(job),
        urgency_rank: job_urgency_rank(job),
        ..RequestMeta::default()
    };
    if let Some(stream_id) = job_stream_scope(job) {
        request.stream_id = stream_id;
        request.stream_scoped = true;
        request.group_key = GroupKey::stream(stream_id);
    }
    request.is_priority_update = job_is_priority_update(job) && request.stream_scoped;
    request
}

fn job_cost(job: &WriteJob) -> i64 {
    let cost = match job {
        WriteJob::Frame(frame) | WriteJob::GracefulClose(frame) => frame_cost(frame),
        WriteJob::Frames(frames) => frames
            .iter()
            .fold(0usize, |sum, frame| sum.saturating_add(frame_cost(frame))),
        WriteJob::TrackedFrames(tracked) => tracked
            .frames
            .iter()
            .fold(0usize, |sum, frame| sum.saturating_add(frame_cost(frame))),
        WriteJob::Shutdown | WriteJob::DrainShutdown => 1,
    };
    i64::try_from(cost.max(1)).unwrap_or(i64::MAX)
}

fn frame_cost(frame: &Frame) -> usize {
    frame
        .payload
        .len()
        .saturating_add(FRAME_BATCH_COST_OVERHEAD_BYTES)
}

fn job_urgency_rank(job: &WriteJob) -> i32 {
    match job {
        WriteJob::Frame(frame) | WriteJob::GracefulClose(frame) => frame_urgency_rank(frame),
        WriteJob::Frames(frames) => frames
            .iter()
            .map(frame_urgency_rank)
            .min()
            .unwrap_or(DEFAULT_URGENCY_RANK),
        WriteJob::TrackedFrames(tracked) => tracked
            .frames
            .iter()
            .map(frame_urgency_rank)
            .min()
            .unwrap_or(DEFAULT_URGENCY_RANK),
        WriteJob::Shutdown | WriteJob::DrainShutdown => 0,
    }
}

const DEFAULT_URGENCY_RANK: i32 = 100;
const FRAME_BATCH_COST_OVERHEAD_BYTES: usize = 1;

fn frame_urgency_rank(frame: &Frame) -> i32 {
    match frame.frame_type {
        FrameType::Close => 0,
        FrameType::GoAway => 1,
        FrameType::Abort => 2,
        FrameType::Reset => 3,
        FrameType::StopSending => 4,
        FrameType::MaxData => 5,
        FrameType::Blocked => 6,
        FrameType::Pong => 7,
        FrameType::Ping => 8,
        _ => DEFAULT_URGENCY_RANK,
    }
}

fn job_is_urgent(job: &WriteJob) -> bool {
    match job {
        WriteJob::Shutdown => true,
        WriteJob::DrainShutdown | WriteJob::GracefulClose(_) => false,
        WriteJob::Frame(frame) => frame_is_urgent(frame),
        WriteJob::Frames(frames) => !frames.is_empty() && frames.iter().all(frame_is_urgent),
        WriteJob::TrackedFrames(tracked) => {
            !tracked.frames.is_empty() && tracked.frames.iter().all(frame_is_urgent)
        }
    }
}

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

fn job_stream_scope(job: &WriteJob) -> Option<u64> {
    match job {
        WriteJob::Frame(frame) | WriteJob::GracefulClose(frame) => frame_stream_scope(frame),
        WriteJob::Frames(frames) => {
            let mut stream_id = None;
            for frame in frames {
                let id = frame_stream_scope(frame)?;
                match stream_id {
                    Some(existing) if existing != id => return None,
                    Some(_) => {}
                    None => stream_id = Some(id),
                }
            }
            stream_id
        }
        WriteJob::TrackedFrames(tracked) => {
            let mut stream_id = None;
            for frame in &tracked.frames {
                let id = frame_stream_scope(frame)?;
                match stream_id {
                    Some(existing) if existing != id => return None,
                    Some(_) => {}
                    None => stream_id = Some(id),
                }
            }
            stream_id
        }
        WriteJob::Shutdown | WriteJob::DrainShutdown => None,
    }
}

fn frame_stream_scope(frame: &Frame) -> Option<u64> {
    if frame.stream_id == 0 {
        return None;
    }
    matches!(
        frame.frame_type,
        FrameType::Data
            | FrameType::MaxData
            | FrameType::StopSending
            | FrameType::Blocked
            | FrameType::Reset
            | FrameType::Abort
            | FrameType::Ext
    )
    .then_some(frame.stream_id)
}

fn job_is_priority_update(job: &WriteJob) -> bool {
    match job {
        WriteJob::Frame(frame) => frame_is_priority_update(frame),
        WriteJob::Frames(_)
        | WriteJob::TrackedFrames(_)
        | WriteJob::GracefulClose(_)
        | WriteJob::Shutdown
        | WriteJob::DrainShutdown => false,
    }
}

fn frame_is_priority_update(frame: &Frame) -> bool {
    if frame.frame_type != FrameType::Ext || frame.stream_id == 0 {
        return false;
    }
    parse_varint(&frame.payload).is_ok_and(|(extension_id, _)| extension_id == EXT_PRIORITY_UPDATE)
}

fn encode_frame(
    frame: Frame,
    limits: Limits,
    encoded: &mut Vec<EncodedFrame>,
    opened_streams: &mut Vec<u64>,
    opened_stream_seen: &mut HashSet<u64>,
    stats: &mut EncodedBatchStats,
) -> Result<()> {
    let stream_id = frame.stream_id;
    let opens_local_stream = frame_opens_local_stream(&frame);
    let data_bytes = frame_data_bytes(&frame);
    let payload_len = frame.payload.len();
    let mut header = [0u8; MAX_FRAME_HEADER_LEN];
    let header_len = frame.encode_header_with_limits(limits, &mut header)?;
    let encoded_len = header_len
        .checked_add(payload_len)
        .ok_or_else(|| Error::frame_size("write batch too large"))?;
    stats.frames = stats.frames.saturating_add(1);
    if frame.frame_type == FrameType::Close {
        stats.close_frames = stats.close_frames.saturating_add(1);
    }
    stats.encoded_bytes = stats
        .encoded_bytes
        .checked_add(encoded_len)
        .ok_or_else(|| Error::frame_size("encoded write batch too large"))?;
    stats.data_bytes = stats.data_bytes.saturating_add(data_bytes);
    stats.payload_bytes = stats.payload_bytes.saturating_add(payload_len);
    stats.segments = stats
        .segments
        .saturating_add(1 + usize::from(payload_len > 0));
    if frame.frame_type == FrameType::Data {
        push_stream_value(
            &mut stats.data_cost_by_stream,
            stream_id,
            frame_cost(&frame),
        );
        push_stream_value(&mut stats.data_frame_count_by_stream, stream_id, 1);
    }
    if frame.stream_id != 0
        && matches!(
            frame.frame_type,
            FrameType::Abort | FrameType::Reset | FrameType::StopSending
        )
    {
        push_stream_value(&mut stats.terminal_frame_count_by_stream, stream_id, 1);
    }
    if opens_local_stream {
        add_stream_id_once(opened_streams, opened_stream_seen, stream_id);
    }
    encoded.push(EncodedFrame {
        header,
        header_len: header_len as u8,
        payload: frame.payload,
    });
    Ok(())
}

const MIN_VECTORED_PAYLOAD_BYTES: usize = 16 << 10;
const MAX_VECTORED_SEGMENTS: usize = 64;
const MIN_VECTORED_PAYLOAD_BYTES_PER_SEGMENT: usize = 1024;
const MIN_RETAINED_ENCODED_BUFFER_BYTES: usize = 64 << 10;
const MAX_RETAINED_ENCODED_BUFFER_BYTES: usize = 512 << 10;
const MIN_RETAINED_BATCH_FRAMES: usize = 64;
const MAX_RETAINED_ACCOUNTING_ENTRIES: usize = 4096;
const SCRATCH_RETAIN_FACTOR: usize = 4;
const OPENED_STREAM_LINEAR_DEDUP_LIMIT: usize = 64;

fn should_use_vectored_batch(stats: &EncodedBatchStats) -> bool {
    stats.payload_bytes >= MIN_VECTORED_PAYLOAD_BYTES
        && stats.segments > 0
        && stats.segments <= MAX_VECTORED_SEGMENTS
        && stats.payload_bytes / stats.segments >= MIN_VECTORED_PAYLOAD_BYTES_PER_SEGMENT
}

fn append_encoded_frames(
    frames: &[EncodedFrame],
    encoded_bytes: usize,
    encoded: &mut Vec<u8>,
) -> Result<()> {
    encoded.clear();
    encoded
        .try_reserve(encoded_bytes)
        .map_err(|_| Error::local("zmux: encoded write batch allocation failed"))?;
    for frame in frames {
        encoded.extend_from_slice(&frame.header[..frame.header_len as usize]);
        encoded.extend_from_slice(&frame.payload);
    }
    if encoded.len() != encoded_bytes {
        return Err(Error::local("zmux: encoded write batch length mismatch"));
    }
    Ok(())
}

fn clear_written_batch_scratch(
    encoded: &mut Vec<u8>,
    encoded_frames: &mut Vec<EncodedFrame>,
    stats: &EncodedBatchStats,
) {
    encoded.clear();
    encoded_frames.clear();
    trim_vec_capacity(
        encoded,
        stats.encoded_bytes,
        MIN_RETAINED_ENCODED_BUFFER_BYTES,
        MAX_RETAINED_ENCODED_BUFFER_BYTES,
    );
    trim_vec_capacity(
        encoded_frames,
        usize::try_from(stats.frames).unwrap_or(usize::MAX),
        MIN_RETAINED_BATCH_FRAMES,
        usize::MAX,
    );
}

fn trim_vec_capacity<T>(
    values: &mut Vec<T>,
    recent_len: usize,
    min_retain: usize,
    max_retain: usize,
) {
    let retain_limit = recent_len
        .saturating_mul(SCRATCH_RETAIN_FACTOR)
        .max(min_retain)
        .min(max_retain);
    if values.capacity() > retain_limit {
        if values.is_empty() {
            if recent_len > max_retain {
                *values = Vec::new();
                return;
            }
            let retain = recent_len.min(retain_limit);
            let mut replacement = Vec::new();
            if replacement.try_reserve_exact(retain).is_ok() {
                *values = replacement;
            } else {
                *values = Vec::new();
            }
        } else {
            values.shrink_to(retain_limit);
        }
    }
}

fn trim_hashset_capacity<T: Eq + std::hash::Hash>(
    values: &mut HashSet<T>,
    recent_len: usize,
    min_retain: usize,
    max_retain: usize,
) {
    let retain_limit = recent_len
        .saturating_mul(SCRATCH_RETAIN_FACTOR)
        .max(min_retain)
        .min(max_retain);
    if values.capacity() > retain_limit {
        values.shrink_to(retain_limit);
    }
}

fn write_encoded_frames_vectored<W: Write>(
    writer: &mut W,
    frames: &[EncodedFrame],
) -> std::io::Result<()> {
    let mut frame_idx = 0usize;
    let mut part_idx = 0usize;
    let mut offset = 0usize;
    let mut slices: [IoSlice<'_>; MAX_VECTORED_SEGMENTS] =
        std::array::from_fn(|_| IoSlice::new(&[]));
    skip_empty_parts(frames, &mut frame_idx, &mut part_idx, &mut offset);
    while frame_idx < frames.len() {
        let (slice_count, offered) =
            encoded_io_slices(frames, frame_idx, part_idx, offset, &mut slices);
        if slice_count == 0 {
            break;
        }
        let written = writer.write_vectored(&slices[..slice_count])?;
        if written == 0 {
            return Err(std::io::Error::from(ErrorKind::WriteZero));
        }
        if written > offered {
            return Err(std::io::Error::other(
                "vectored write reported invalid progress",
            ));
        }
        advance_encoded_position(frames, &mut frame_idx, &mut part_idx, &mut offset, written);
    }
    Ok(())
}

fn encoded_io_slices<'a>(
    frames: &'a [EncodedFrame],
    mut frame_idx: usize,
    mut part_idx: usize,
    mut offset: usize,
    slices: &mut [IoSlice<'a>; MAX_VECTORED_SEGMENTS],
) -> (usize, usize) {
    let mut slice_count = 0usize;
    let mut offered = 0usize;
    while frame_idx < frames.len() && slice_count < slices.len() {
        let part = encoded_part(&frames[frame_idx], part_idx);
        if offset < part.len() {
            slices[slice_count] = IoSlice::new(&part[offset..]);
            offered = offered.saturating_add(part.len() - offset);
            slice_count += 1;
            offset = 0;
        }
        part_idx += 1;
        if part_idx == 2 {
            part_idx = 0;
            frame_idx += 1;
        }
    }
    (slice_count, offered)
}

fn advance_encoded_position(
    frames: &[EncodedFrame],
    frame_idx: &mut usize,
    part_idx: &mut usize,
    offset: &mut usize,
    mut written: usize,
) {
    while *frame_idx < frames.len() && written > 0 {
        let part = encoded_part(&frames[*frame_idx], *part_idx);
        let remaining = part.len().saturating_sub(*offset);
        if written < remaining {
            *offset += written;
            return;
        }
        written -= remaining;
        *offset = 0;
        *part_idx += 1;
        if *part_idx == 2 {
            *part_idx = 0;
            *frame_idx += 1;
        }
        skip_empty_parts(frames, frame_idx, part_idx, offset);
    }
}

fn skip_empty_parts(
    frames: &[EncodedFrame],
    frame_idx: &mut usize,
    part_idx: &mut usize,
    offset: &mut usize,
) {
    *offset = 0;
    while *frame_idx < frames.len() && encoded_part(&frames[*frame_idx], *part_idx).is_empty() {
        *part_idx += 1;
        if *part_idx == 2 {
            *part_idx = 0;
            *frame_idx += 1;
        }
    }
}

fn encoded_part(frame: &EncodedFrame, part_idx: usize) -> &[u8] {
    if part_idx == 0 {
        &frame.header[..frame.header_len as usize]
    } else {
        &frame.payload
    }
}

fn add_inflight_data(inner: &Arc<Inner>, data: &[(u64, usize)]) {
    if data.is_empty() {
        return;
    }
    let mut state = inner.state.lock().unwrap();
    for (stream_id, bytes) in data {
        let entry = state.inflight_data_by_stream.entry(*stream_id).or_default();
        *entry = entry.saturating_add(*bytes);
    }
}

fn remove_inflight_data(inner: &Arc<Inner>, data: &[(u64, usize)]) {
    if data.is_empty() {
        return;
    }
    let mut state = inner.state.lock().unwrap();
    for (stream_id, bytes) in data {
        let mut remove = false;
        if let Some(entry) = state.inflight_data_by_stream.get_mut(stream_id) {
            *entry = entry.saturating_sub(*bytes);
            remove = *entry == 0;
        }
        if remove {
            state.inflight_data_by_stream.remove(stream_id);
        }
    }
}

fn complete_written_stream_frames(
    inner: &Arc<Inner>,
    data_frames: &[(u64, usize)],
    terminal_frames: &[(u64, usize)],
) {
    if data_frames.is_empty() && terminal_frames.is_empty() {
        return;
    }
    let mut state = inner.state.lock().unwrap();
    for (stream_id, count) in data_frames {
        note_written_stream_frames_locked(&mut state, *stream_id, *count, 0);
    }
    for (stream_id, count) in terminal_frames {
        note_written_stream_frames_locked(&mut state, *stream_id, 0, *count);
    }
}

fn push_stream_value(values: &mut Vec<(u64, usize)>, stream_id: u64, value: usize) {
    if value == 0 {
        return;
    }
    values.push((stream_id, value));
}

fn coalesce_stream_values(values: &mut Vec<(u64, usize)>) {
    if values.len() < 2 {
        return;
    }
    values.sort_unstable_by_key(|(stream_id, _)| *stream_id);
    let mut write = 0usize;
    for read in 0..values.len() {
        let (stream_id, value) = values[read];
        if write > 0 && values[write - 1].0 == stream_id {
            values[write - 1].1 = values[write - 1].1.saturating_add(value);
        } else {
            values[write] = (stream_id, value);
            write += 1;
        }
    }
    values.truncate(write);
}

fn add_stream_id_once(stream_ids: &mut Vec<u64>, seen: &mut HashSet<u64>, stream_id: u64) {
    if stream_id == 0 {
        return;
    }
    if !seen.is_empty() {
        if seen.insert(stream_id) {
            stream_ids.push(stream_id);
        }
        return;
    }
    if stream_ids.len() < OPENED_STREAM_LINEAR_DEDUP_LIMIT {
        if !stream_ids.contains(&stream_id) {
            stream_ids.push(stream_id);
        }
        return;
    }
    if seen
        .try_reserve(stream_ids.len().saturating_add(1))
        .is_err()
    {
        if !stream_ids.contains(&stream_id) {
            stream_ids.push(stream_id);
        }
        return;
    }
    seen.extend(stream_ids.iter().copied());
    if !seen.insert(stream_id) {
        return;
    }
    stream_ids.push(stream_id);
}

fn frame_data_bytes(frame: &Frame) -> u64 {
    if frame.frame_type != FrameType::Data {
        return 0;
    }
    let offset = if frame.flags & FRAME_FLAG_OPEN_METADATA != 0 {
        parse_data_payload_metadata_offset(&frame.payload, frame.flags)
            .map(|(_, _, offset)| offset)
            .unwrap_or(frame.payload.len())
    } else {
        0
    };
    usize_to_u64_saturating(frame.payload.len().saturating_sub(offset))
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn frame_opens_local_stream(frame: &Frame) -> bool {
    frame.stream_id != 0 && matches!(frame.frame_type, FrameType::Data | FrameType::Abort)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FRAME_FLAG_FIN;

    struct PartialVectoredWriter {
        bytes: Vec<u8>,
        max_chunk: usize,
        vectored_calls: usize,
    }

    struct ZeroProgressVectoredWriter;

    struct InvalidProgressVectoredWriter;

    fn encoded_frame(header: &[u8], payload: &[u8]) -> EncodedFrame {
        assert!(header.len() <= MAX_FRAME_HEADER_LEN);
        let mut fixed = [0u8; MAX_FRAME_HEADER_LEN];
        fixed[..header.len()].copy_from_slice(header);
        EncodedFrame {
            header: fixed,
            header_len: header.len() as u8,
            payload: payload.to_vec(),
        }
    }

    impl Write for PartialVectoredWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = self.max_chunk.min(buf.len());
            self.bytes.extend_from_slice(&buf[..n]);
            Ok(n)
        }

        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
            self.vectored_calls += 1;
            let mut remaining = self.max_chunk;
            let mut written = 0usize;
            for buf in bufs {
                if remaining == 0 {
                    break;
                }
                let n = remaining.min(buf.len());
                self.bytes.extend_from_slice(&buf[..n]);
                written += n;
                remaining -= n;
            }
            Ok(written)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Write for InvalidProgressVectoredWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            Ok(buf.len().saturating_add(1))
        }

        fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
            let offered = bufs
                .iter()
                .fold(0usize, |sum, buf| sum.saturating_add(buf.len()));
            Ok(offered.saturating_add(1))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Write for ZeroProgressVectoredWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Ok(0)
        }

        fn write_vectored(&mut self, _bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn graceful_close_and_shutdown_are_split_into_fixed_tail() {
        let jobs = [
            WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id: 1,
                payload: Vec::new(),
            }),
            WriteJob::GracefulClose(Frame {
                frame_type: FrameType::Close,
                flags: 0,
                stream_id: 0,
                payload: Vec::new(),
            }),
            WriteJob::DrainShutdown,
        ];

        let tail_start = jobs.iter().position(job_is_ordered_tail).unwrap();
        let (prefix, tail) = jobs.split_at(tail_start);

        assert_eq!(tail_start, 1);
        assert_eq!(prefix.len(), 1);
        assert!(matches!(
            prefix.first(),
            Some(WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                ..
            }))
        ));
        assert!(matches!(
            tail.first(),
            Some(WriteJob::GracefulClose(Frame {
                frame_type: FrameType::Close,
                ..
            }))
        ));
        assert!(matches!(tail.get(1), Some(WriteJob::DrainShutdown)));
    }

    #[test]
    fn vectored_batch_write_handles_partial_progress_and_empty_payloads() {
        let frames = vec![
            encoded_frame(b"h1", b"payload"),
            encoded_frame(b"h2", b""),
            encoded_frame(b"h3", b"tail"),
        ];
        let expected_len = frames
            .iter()
            .map(|frame| frame.header_len as usize + frame.payload.len())
            .sum();
        let mut expected = Vec::new();
        append_encoded_frames(&frames, expected_len, &mut expected).unwrap();

        let mut writer = PartialVectoredWriter {
            bytes: Vec::new(),
            max_chunk: 3,
            vectored_calls: 0,
        };
        write_encoded_frames_vectored(&mut writer, &frames).unwrap();

        assert_eq!(writer.bytes, expected);
        assert!(writer.vectored_calls > 1);
    }

    #[test]
    fn vectored_batch_write_rejects_invalid_progress() {
        let frames = vec![encoded_frame(b"h", b"payload")];
        let mut writer = InvalidProgressVectoredWriter;

        let err = write_encoded_frames_vectored(&mut writer, &frames).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::Other);
    }

    #[test]
    fn vectored_batch_write_rejects_zero_progress() {
        let frames = vec![encoded_frame(b"h", b"payload")];
        let mut writer = ZeroProgressVectoredWriter;

        let err = write_encoded_frames_vectored(&mut writer, &frames).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::WriteZero);
    }

    #[test]
    fn vectored_batch_threshold_requires_large_dense_payloads() {
        let small = EncodedBatchStats {
            payload_bytes: MIN_VECTORED_PAYLOAD_BYTES - 1,
            segments: 1,
            ..EncodedBatchStats::default()
        };
        assert!(!should_use_vectored_batch(&small));

        let sparse = EncodedBatchStats {
            payload_bytes: MIN_VECTORED_PAYLOAD_BYTES,
            segments: MAX_VECTORED_SEGMENTS,
            ..EncodedBatchStats::default()
        };
        assert!(!should_use_vectored_batch(&sparse));

        let dense = EncodedBatchStats {
            payload_bytes: MIN_VECTORED_PAYLOAD_BYTES,
            segments: MIN_VECTORED_PAYLOAD_BYTES / MIN_VECTORED_PAYLOAD_BYTES_PER_SEGMENT,
            ..EncodedBatchStats::default()
        };
        assert!(should_use_vectored_batch(&dense));
    }

    #[test]
    fn encode_batch_uses_peer_frame_limit_for_large_data_payloads() {
        let limits = Limits {
            max_frame_payload: 32 * 1024,
            ..Limits::default()
        };
        let payload = vec![b'g'; 24 * 1024];
        let mut batch = vec![WriteJob::Frame(Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: 1,
            payload: payload.clone(),
        })];
        let mut encoded = Vec::new();
        let mut shutdown = false;
        let mut opened_streams = Vec::new();
        let mut opened_stream_seen = HashSet::new();
        let mut stats = EncodedBatchStats::default();
        let mut completions = Vec::new();

        encode_batch(
            &mut batch,
            limits,
            EncodeBatchScratch {
                encoded: &mut encoded,
                shutdown: &mut shutdown,
                opened_streams: &mut opened_streams,
                opened_stream_seen: &mut opened_stream_seen,
                stats: &mut stats,
                completions: &mut completions,
            },
        )
        .unwrap();

        assert!(should_use_vectored_batch(&stats));
        let mut writer = PartialVectoredWriter {
            bytes: Vec::new(),
            max_chunk: usize::MAX,
            vectored_calls: 0,
        };
        write_encoded_frames_vectored(&mut writer, &encoded).unwrap();

        assert_eq!(writer.vectored_calls, 1);
        let (decoded, used) = Frame::parse(&writer.bytes, limits).unwrap();
        assert_eq!(used, writer.bytes.len());
        assert_eq!(decoded.frame_type, FrameType::Data);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn merged_encoding_preserves_open_metadata_and_large_application_payload() {
        let limits = Limits {
            max_frame_payload: 32 * 1024,
            ..Limits::default()
        };
        let mut payload = crate::payload::build_open_metadata_prefix(
            crate::protocol::CAPABILITY_OPEN_METADATA,
            None,
            None,
            b"meta",
            limits.max_frame_payload,
        )
        .unwrap();
        payload.extend_from_slice(&vec![b'a'; 8 * 1024]);
        payload.extend_from_slice(&vec![b'b'; 8 * 1024]);
        let mut batch = vec![WriteJob::Frame(Frame {
            frame_type: FrameType::Data,
            flags: FRAME_FLAG_OPEN_METADATA | FRAME_FLAG_FIN,
            stream_id: 1,
            payload,
        })];
        let mut encoded = Vec::new();
        let mut shutdown = false;
        let mut opened_streams = Vec::new();
        let mut opened_stream_seen = HashSet::new();
        let mut stats = EncodedBatchStats::default();
        let mut completions = Vec::new();

        encode_batch(
            &mut batch,
            limits,
            EncodeBatchScratch {
                encoded: &mut encoded,
                shutdown: &mut shutdown,
                opened_streams: &mut opened_streams,
                opened_stream_seen: &mut opened_stream_seen,
                stats: &mut stats,
                completions: &mut completions,
            },
        )
        .unwrap();

        let mut merged = Vec::new();
        append_encoded_frames(&encoded, stats.encoded_bytes, &mut merged).unwrap();
        let (decoded, used) = Frame::parse(&merged, limits).unwrap();
        let data = crate::payload::parse_data_payload(&decoded.payload, decoded.flags).unwrap();

        assert_eq!(used, merged.len());
        assert_eq!(decoded.frame_type, FrameType::Data);
        assert_eq!(decoded.flags, FRAME_FLAG_OPEN_METADATA | FRAME_FLAG_FIN);
        assert_eq!(data.metadata.open_info, b"meta");
        assert_eq!(data.app_data.len(), 16 * 1024);
        assert_eq!(data.app_data.first().copied(), Some(b'a'));
        assert_eq!(data.app_data.last().copied(), Some(b'b'));
    }

    #[test]
    fn tiny_payload_uses_merged_encoding_without_vectored_threshold() {
        let mut batch = vec![WriteJob::Frame(Frame {
            frame_type: FrameType::Data,
            flags: FRAME_FLAG_FIN,
            stream_id: 1,
            payload: b"hello".to_vec(),
        })];
        let mut encoded = Vec::new();
        let mut shutdown = false;
        let mut opened_streams = Vec::new();
        let mut opened_stream_seen = HashSet::new();
        let mut stats = EncodedBatchStats::default();
        let mut completions = Vec::new();

        encode_batch(
            &mut batch,
            Limits::default(),
            EncodeBatchScratch {
                encoded: &mut encoded,
                shutdown: &mut shutdown,
                opened_streams: &mut opened_streams,
                opened_stream_seen: &mut opened_stream_seen,
                stats: &mut stats,
                completions: &mut completions,
            },
        )
        .unwrap();

        assert!(!should_use_vectored_batch(&stats));
        let mut merged = Vec::new();
        append_encoded_frames(&encoded, stats.encoded_bytes, &mut merged).unwrap();
        let (decoded, used) = Frame::parse(&merged, Limits::default()).unwrap();

        assert_eq!(used, merged.len());
        assert_eq!(decoded.frame_type, FrameType::Data);
        assert_eq!(decoded.flags, FRAME_FLAG_FIN);
        assert_eq!(decoded.payload, b"hello");
    }

    #[test]
    fn encode_batch_drains_jobs_while_retaining_batch_storage() {
        let mut batch = Vec::with_capacity(8);
        batch.push(WriteJob::Frame(Frame {
            frame_type: FrameType::Ping,
            flags: 0,
            stream_id: 0,
            payload: vec![1; 8],
        }));
        let mut encoded = Vec::new();
        let mut shutdown = false;
        let mut opened_streams = Vec::new();
        let mut opened_stream_seen = HashSet::new();
        let mut stats = EncodedBatchStats::default();
        let mut completions = Vec::new();

        encode_batch(
            &mut batch,
            Limits::default(),
            EncodeBatchScratch {
                encoded: &mut encoded,
                shutdown: &mut shutdown,
                opened_streams: &mut opened_streams,
                opened_stream_seen: &mut opened_stream_seen,
                stats: &mut stats,
                completions: &mut completions,
            },
        )
        .unwrap();

        assert!(batch.is_empty());
        assert!(batch.capacity() >= 8);
        assert_eq!(encoded.len(), 1);
        assert!(!shutdown);
    }

    #[test]
    fn stream_scoped_ext_priority_classification_uses_subtype() {
        assert!(frame_is_priority_update(&Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id: 4,
            payload: vec![EXT_PRIORITY_UPDATE as u8],
        }));
        assert!(!frame_is_priority_update(&Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id: 4,
            payload: crate::varint::encode_varint(99).unwrap(),
        }));
        assert!(!frame_is_priority_update(&Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id: 0,
            payload: vec![EXT_PRIORITY_UPDATE as u8],
        }));
        assert!(!frame_is_priority_update(&Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id: 4,
            payload: vec![0x40],
        }));
    }

    #[test]
    fn priority_updates_only_flush_for_peer_visible_open_send_halves() {
        assert!(priority_update_send_state_allows(
            true, false, false, false, false, false, false
        ));
        assert!(priority_update_send_state_allows(
            true, true, true, false, false, false, false
        ));

        assert!(!priority_update_send_state_allows(
            false, false, false, false, false, false, false
        ));
        assert!(!priority_update_send_state_allows(
            true, true, false, false, false, false, false
        ));
        assert!(!priority_update_send_state_allows(
            true, true, true, true, false, false, false
        ));
        assert!(!priority_update_send_state_allows(
            true, true, true, false, true, false, false
        ));
        assert!(!priority_update_send_state_allows(
            true, true, true, false, false, true, false
        ));
        assert!(!priority_update_send_state_allows(
            true, true, true, false, false, false, true
        ));
    }

    #[test]
    fn encode_batch_aggregates_data_accounting_by_stream() {
        let mut batch = vec![
            WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id: 1,
                payload: vec![1; 4],
            }),
            WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id: 2,
                payload: vec![3; 8],
            }),
            WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id: 1,
                payload: vec![2; 6],
            }),
        ];
        let mut encoded = Vec::new();
        let mut shutdown = false;
        let mut opened_streams = Vec::new();
        let mut opened_stream_seen = HashSet::new();
        let mut stats = EncodedBatchStats::default();
        let mut completions = Vec::new();

        encode_batch(
            &mut batch,
            Limits::default(),
            EncodeBatchScratch {
                encoded: &mut encoded,
                shutdown: &mut shutdown,
                opened_streams: &mut opened_streams,
                opened_stream_seen: &mut opened_stream_seen,
                stats: &mut stats,
                completions: &mut completions,
            },
        )
        .unwrap();

        assert_eq!(stats.data_cost_by_stream, vec![(1, 12), (2, 9)]);
        assert_eq!(stats.data_frame_count_by_stream, vec![(1, 2), (2, 1)]);
        assert_eq!(opened_streams, vec![1, 2]);
    }

    #[test]
    fn opened_stream_dedup_promotes_for_large_batches_without_reordering() {
        let unique_streams = OPENED_STREAM_LINEAR_DEDUP_LIMIT + 4;
        let mut batch = Vec::new();
        for stream_id in 1..=unique_streams as u64 {
            batch.push(WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id,
                payload: Vec::new(),
            }));
        }
        for stream_id in [2, 4, unique_streams as u64, 1] {
            batch.push(WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id,
                payload: Vec::new(),
            }));
        }
        let mut encoded = Vec::new();
        let mut shutdown = false;
        let mut opened_streams = Vec::new();
        let mut opened_stream_seen = HashSet::new();
        let mut stats = EncodedBatchStats::default();
        let mut completions = Vec::new();

        encode_batch(
            &mut batch,
            Limits::default(),
            EncodeBatchScratch {
                encoded: &mut encoded,
                shutdown: &mut shutdown,
                opened_streams: &mut opened_streams,
                opened_stream_seen: &mut opened_stream_seen,
                stats: &mut stats,
                completions: &mut completions,
            },
        )
        .unwrap();

        assert_eq!(
            opened_streams,
            (1..=unique_streams as u64).collect::<Vec<_>>()
        );
        assert!(!opened_stream_seen.is_empty());
    }

    #[test]
    fn stream_value_accounting_orders_removes_and_clears_entries() {
        let mut values = Vec::new();
        push_stream_value(&mut values, 9, 90);
        push_stream_value(&mut values, 1, 10);
        push_stream_value(&mut values, 5, 50);
        push_stream_value(&mut values, 5, 5);

        coalesce_stream_values(&mut values);

        assert_eq!(values, vec![(1, 10), (5, 55), (9, 90)]);
        assert_eq!(
            values.iter().position(|(stream_id, _)| *stream_id == 5),
            Some(1)
        );

        values.remove(1);

        assert_eq!(values, vec![(1, 10), (9, 90)]);
        assert_eq!(
            values.iter().position(|(stream_id, _)| *stream_id == 5),
            None
        );

        values.clear();

        assert!(values.is_empty());
    }

    #[test]
    fn apply_order_in_place_reorders_without_losing_jobs() {
        let mut batch = vec![
            WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id: 1,
                payload: Vec::new(),
            }),
            WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id: 2,
                payload: Vec::new(),
            }),
            WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id: 3,
                payload: Vec::new(),
            }),
        ];
        let mut inverse = Vec::new();

        assert!(apply_order_in_place(&mut batch, &[2, 0, 1], &mut inverse));

        let stream_ids: Vec<_> = batch
            .iter()
            .map(|job| match job {
                WriteJob::Frame(frame) => frame.stream_id,
                _ => 0,
            })
            .collect();
        assert_eq!(stream_ids, vec![3, 1, 2]);
        assert!(inverse.is_empty());
    }

    #[test]
    fn written_batch_scratch_is_released_before_next_pop() {
        let mut encoded = Vec::with_capacity(MAX_RETAINED_ENCODED_BUFFER_BYTES * 2);
        encoded.resize(MAX_RETAINED_ENCODED_BUFFER_BYTES + 1, 0);
        let mut encoded_frames = Vec::with_capacity(MIN_RETAINED_BATCH_FRAMES * 4);
        encoded_frames.push(encoded_frame(
            b"h",
            &vec![1; MIN_RETAINED_ENCODED_BUFFER_BYTES],
        ));
        let stats = EncodedBatchStats {
            frames: 1,
            encoded_bytes: encoded.len(),
            ..EncodedBatchStats::default()
        };

        clear_written_batch_scratch(&mut encoded, &mut encoded_frames, &stats);

        assert!(encoded.is_empty());
        assert_eq!(encoded.capacity(), 0);
        assert!(encoded_frames.is_empty());
        assert!(encoded_frames.capacity() <= MIN_RETAINED_BATCH_FRAMES);
    }

    #[test]
    fn empty_written_batch_scratch_drops_oversized_retained_vectors() {
        let mut encoded = Vec::with_capacity(MIN_RETAINED_ENCODED_BUFFER_BYTES * 2);
        let mut encoded_frames = Vec::with_capacity(MIN_RETAINED_BATCH_FRAMES * 4);
        let stats = EncodedBatchStats::default();

        clear_written_batch_scratch(&mut encoded, &mut encoded_frames, &stats);

        assert_eq!(encoded.capacity(), 0);
        assert_eq!(encoded_frames.capacity(), 0);
    }

    #[test]
    fn trim_vec_capacity_preserves_non_empty_values() {
        let mut values = Vec::with_capacity(MAX_RETAINED_ACCOUNTING_ENTRIES * 4);
        values.extend([1, 2, 3]);

        trim_vec_capacity(
            &mut values,
            MAX_RETAINED_ACCOUNTING_ENTRIES * 2,
            MIN_RETAINED_BATCH_FRAMES,
            MAX_RETAINED_ACCOUNTING_ENTRIES,
        );

        assert_eq!(values, vec![1, 2, 3]);
        assert!(values.capacity() >= values.len());
    }
}
