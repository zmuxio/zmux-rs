use super::queue::StreamDiscardStats;
use super::types::{
    ActiveStreamStats, ConnState, Inner, MemoryStats, PeerGoAwayError, SessionState, StreamInner,
    StreamState, WriterQueueStats,
};
use crate::config::{
    DEFAULT_LATE_DATA_PER_STREAM_CAP_FLOOR, DEFAULT_SESSION_MEMORY_HARD_CAP_FLOOR,
};
use crate::error::{
    Error, ErrorCode, ErrorDirection, ErrorOperation, ErrorScope, ErrorSource, Result,
    TerminationKind,
};
use crate::event::{dispatch_event, Event, EventType, StreamEventInfo};
use crate::frame::{Frame, FrameType};
use crate::payload::StreamMetadata;
use std::collections::hash_map::Entry;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

const MIN_RETAINED_STATE_UNIT: usize = 4 * 1024;
const COMPACT_TERMINAL_STATE_UNIT: usize = 64;
const HIDDEN_CONTROL_RETAINED_MAX_AGE: Duration = Duration::from_secs(1);
const MARKER_ONLY_RANGE_COMPACT_THRESHOLD: usize = 64;
const PROVISIONAL_OPEN_EXPIRED_REASON: &str =
    "zmux: provisional local open expired before first-frame commit";
const PROVISIONAL_OPEN_BASE_MAX_AGE: Duration = Duration::from_secs(5);
const PROVISIONAL_OPEN_MAX_AGE_ADAPTIVE_CAP: Duration = Duration::from_secs(20);
const PROVISIONAL_OPEN_RTT_ADAPTIVE_SLACK: Duration = Duration::from_millis(250);
const PROVISIONAL_OPEN_RTT_MULTIPLIER: u32 = 6;
const MAX_REASON_STATS_CODES: usize = 1024;
const ACCEPT_QUEUE_RETAIN_MIN_CAP: usize = 1024;
const PROVISIONAL_QUEUE_RETAIN_MIN_CAP: usize = 1024;
const RETENTION_QUEUE_RETAIN_MIN_CAP: usize = 1024;

#[inline]
fn usize_to_u64_saturating(value: usize) -> u64 {
    value.min(u64::MAX as usize) as u64
}

#[inline]
fn u64_to_usize_saturating(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

#[inline]
fn effective_session_memory_cap(inner: &Inner) -> Option<usize> {
    match inner.session_memory_cap {
        Some(cap) if cap > 0 => Some(cap),
        _ => None,
    }
}

#[inline]
fn nonzero_duration(value: Option<Duration>) -> Option<Duration> {
    match value {
        Some(value) if !value.is_zero() => Some(value),
        _ => None,
    }
}

#[inline]
pub(super) fn compact_retained_bytes(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() {
        Vec::new()
    } else if bytes.len() == bytes.capacity() {
        bytes
    } else {
        bytes.shrink_to_fit();
        bytes
    }
}

#[inline]
pub(super) fn clear_stream_open_prefix_locked(stream_state: &mut StreamState) {
    stream_state.open_prefix = Vec::new();
}

pub(super) fn fail_session(inner: &Arc<Inner>, err: Error) {
    fail_session_inner(inner, err, None);
}

pub(super) fn fail_session_with_close(inner: &Arc<Inner>, err: Error, close_frame: Frame) {
    fail_session_inner(inner, err, Some(close_frame));
}

fn fail_session_inner(inner: &Arc<Inner>, err: Error, close_frame: Option<Frame>) {
    let err = if err.termination_kind() == TerminationKind::Unknown {
        err.with_termination_kind(TerminationKind::SessionTermination)
    } else {
        err
    }
    .with_session_context(ErrorOperation::Unknown);
    let event = {
        let mut state = inner.state.lock().unwrap();
        if matches!(state.state, SessionState::Closed | SessionState::Failed) {
            return;
        }
        state.state = SessionState::Failed;
        state.graceful_close_active = false;
        let ping_err = err.clone();
        state.close_error = Some(err);
        state.scheduler.clear();
        fail_pending_pings_locked(&mut state, ping_err);
        release_session_runtime_state_locked(&mut state);
        let event = take_session_closed_event_locked(inner, &mut state);
        drop(state);
        inner.cond.notify_all();
        event
    };
    if let Some(frame) = close_frame {
        inner.shutdown_writer_with_close(frame);
    } else {
        inner.shutdown_writer();
    }
    emit_event(inner, event);
}

pub(super) fn emit_event(inner: &Arc<Inner>, event: Option<Event>) {
    let Some(mut event) = event else {
        return;
    };
    let Some(handler) = inner.event_handler.as_ref() else {
        return;
    };
    {
        let mut dispatch = inner.event_dispatch.lock().unwrap();
        if dispatch.emitting {
            dispatch.queue.push_back(event);
            return;
        }
        dispatch.emitting = true;
    }

    loop {
        dispatch_event(handler, event);
        let mut dispatch = inner.event_dispatch.lock().unwrap();
        let Some(next_event) = dispatch.queue.pop_front() else {
            dispatch.emitting = false;
            drop(dispatch);
            return;
        };
        event = next_event;
    }
}

pub(super) fn memory_stats_locked(
    inner: &Inner,
    state: &ConnState,
    writer: &WriterQueueStats,
) -> MemoryStats {
    let tracked = tracked_session_memory_locked(inner, state, writer);
    let hard_cap = session_memory_hard_cap_locked(inner, state, writer);
    MemoryStats {
        tracked_bytes: tracked,
        hard_cap,
        over_cap: tracked > hard_cap,
    }
}

pub(super) fn ensure_session_memory_cap(inner: &Arc<Inner>, operation: &str) -> Result<()> {
    let memory = {
        let mut state = inner.state.lock().unwrap();
        let writer = inner.write_queue.stats();
        reap_tombstones_for_memory_pressure_locked(inner, &mut state, &writer);
        compact_marker_only_ranges_locked(&mut state);
        let marker_count = marker_only_retained_count_locked(&state);
        if marker_count > state.used_marker_limit {
            return Err(Error::new(
                ErrorCode::Internal,
                format!(
                    "{operation}: marker-only used-stream cap exceeded: count={} cap={}",
                    marker_count, state.used_marker_limit
                ),
            ));
        }
        memory_stats_locked(inner, &state, &writer)
    };
    if memory.over_cap {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "{operation}: session memory cap exceeded: tracked={} cap={}",
                memory.tracked_bytes, memory.hard_cap
            ),
        ));
    }
    Ok(())
}

pub(super) fn ensure_projected_session_memory_cap(
    inner: &Arc<Inner>,
    additional_writer_bytes: usize,
    operation: &str,
) -> Result<()> {
    let mut state = inner.state.lock().unwrap();
    ensure_projected_session_memory_cap_locked(
        inner,
        &mut state,
        additional_writer_bytes,
        operation,
    )
}

pub(super) fn ensure_projected_session_memory_cap_locked(
    inner: &Inner,
    state: &mut ConnState,
    additional_writer_bytes: usize,
    operation: &str,
) -> Result<()> {
    let writer = inner.write_queue.stats();
    reap_tombstones_for_memory_pressure_locked(inner, state, &writer);
    compact_marker_only_ranges_locked(state);
    let marker_count = marker_only_retained_count_locked(state);
    if marker_count > state.used_marker_limit {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "{operation}: marker-only used-stream cap exceeded: count={} cap={}",
                marker_count, state.used_marker_limit
            ),
        ));
    }
    let tracked = projected_live_stream_memory_locked(inner, state, &writer, 0);
    let hard_cap = session_memory_hard_cap_locked(inner, state, &writer);
    let projected = tracked.saturating_add(additional_writer_bytes);
    if projected > hard_cap {
        return Err(Error::new(
            ErrorCode::Internal,
            format!(
                "{operation}: session memory cap exceeded: tracked={} projected={} cap={}",
                tracked, projected, hard_cap
            ),
        ));
    }
    Ok(())
}

pub(super) fn ensure_pending_priority_update_limits_locked(
    inner: &Inner,
    state: &ConnState,
    current_stream_id: u64,
    current_stream: &StreamState,
    replacement_len: usize,
    operation: &str,
) -> Result<()> {
    let writer = inner.write_queue.stats();
    let (pending, stream_metadata) = stream_metadata_pending_priority_replacement_totals_locked(
        state,
        current_stream_id,
        current_stream,
        replacement_len,
    );
    if pending > writer.pending_priority_bytes_budget {
        return Err(Error::new(
            ErrorCode::Internal,
            "zmux: pending priority budget exceeded",
        ));
    }

    let tracked =
        tracked_session_memory_base_locked(inner, state, &writer).saturating_add(stream_metadata);
    let hard_cap = session_memory_hard_cap_locked(inner, state, &writer);
    if tracked > hard_cap {
        return Err(Error::new(
            ErrorCode::Internal,
            format!("{operation}: session memory cap exceeded: tracked={tracked} cap={hard_cap}"),
        ));
    }
    Ok(())
}

pub(super) fn session_memory_pressure_high_fast_locked(inner: &Inner, state: &ConnState) -> bool {
    let writer = inner.write_queue.stats();
    let tracked = tracked_session_memory_fast_locked(inner, state, &writer);
    let hard_cap = session_memory_hard_cap_locked(inner, state, &writer);
    tracked >= memory_high_threshold(hard_cap)
}

#[inline]
pub(super) fn memory_high_threshold(hard_cap: usize) -> usize {
    if hard_cap <= 4 {
        hard_cap
    } else {
        hard_cap - hard_cap / 4
    }
}

fn tracked_session_memory_locked(
    inner: &Inner,
    state: &ConnState,
    writer: &WriterQueueStats,
) -> usize {
    let mut total = tracked_session_memory_base_locked(inner, state, writer);
    for stream in state.streams.values() {
        let stream_state = stream.state.lock().unwrap();
        total = total.saturating_add(stream_retained_metadata_bytes(
            &stream_state,
            pending_priority_update_len(&stream_state),
        ));
    }
    total
}

#[inline]
fn tracked_session_memory_base_locked(
    inner: &Inner,
    state: &ConnState,
    writer: &WriterQueueStats,
) -> usize {
    let mut total = writer.queued_bytes;
    total = total.saturating_add(state.retained_open_info_bytes);
    total = total.saturating_add(state.retained_peer_reason_bytes);
    total = total.saturating_add(tracked_retained_state_memory_locked(inner, state));
    total.saturating_add(state.recv_session_retained)
}

fn stream_metadata_pending_priority_replacement_totals_locked(
    state: &ConnState,
    current_stream_id: u64,
    current_stream: &StreamState,
    replacement_len: usize,
) -> (usize, usize) {
    let mut pending_total = 0usize;
    let mut metadata_total = 0usize;
    let mut current_counted = false;
    for (stream_id, stream) in &state.streams {
        let (stream_state, pending_len) = if *stream_id == current_stream_id {
            current_counted = true;
            (current_stream, replacement_len)
        } else {
            let stream_state = stream.state.lock().unwrap();
            let pending_len = pending_priority_update_len(&stream_state);
            pending_total = pending_total.saturating_add(pending_len);
            metadata_total = metadata_total
                .saturating_add(stream_retained_metadata_bytes(&stream_state, pending_len));
            continue;
        };
        pending_total = pending_total.saturating_add(pending_len);
        metadata_total = metadata_total
            .saturating_add(stream_retained_metadata_bytes(stream_state, pending_len));
    }
    if !current_counted {
        pending_total = pending_total.saturating_add(replacement_len);
        metadata_total = metadata_total.saturating_add(stream_retained_metadata_bytes(
            current_stream,
            replacement_len,
        ));
    }
    (pending_total, metadata_total)
}

#[inline]
fn stream_retained_metadata_bytes(
    stream_state: &StreamState,
    pending_priority_len: usize,
) -> usize {
    stream_state
        .open_prefix
        .len()
        .saturating_add(
            stream_state
                .open_info
                .len()
                .saturating_sub(stream_state.retained_open_info_bytes),
        )
        .saturating_add(pending_priority_len)
}

#[inline]
fn pending_priority_update_len(stream_state: &StreamState) -> usize {
    if let Some(payload) = stream_state.pending_priority_update.as_ref() {
        payload.len()
    } else {
        0
    }
}

#[inline]
fn tracked_session_memory_fast_locked(
    inner: &Inner,
    state: &ConnState,
    writer: &WriterQueueStats,
) -> usize {
    tracked_session_memory_base_locked(inner, state, writer)
}

fn live_stream_pressure_units_locked(state: &ConnState) -> usize {
    let live_streams = state
        .active
        .local_bidi
        .saturating_add(state.active.local_uni)
        .saturating_add(state.active.peer_bidi)
        .saturating_add(state.active.peer_uni);
    let live_streams = u64_to_usize_saturating(live_streams);
    state
        .provisional_bidi
        .len()
        .saturating_add(state.provisional_uni.len())
        .saturating_add(live_streams)
}

fn projected_live_stream_memory_locked(
    inner: &Inner,
    state: &ConnState,
    writer: &WriterQueueStats,
    extra_units: usize,
) -> usize {
    let units = live_stream_pressure_units_locked(state).saturating_add(extra_units);
    tracked_session_memory_fast_locked(inner, state, writer)
        .saturating_add(units.saturating_mul(retained_state_unit_locked(inner)))
}

pub(super) fn ensure_local_open_memory_cap_locked(
    inner: &Inner,
    state: &ConnState,
    additional_retained_bytes: usize,
) -> Result<()> {
    let Some(cap) = effective_session_memory_cap(inner) else {
        return Ok(());
    };
    let writer = inner.write_queue.stats();
    let projected = projected_live_stream_memory_locked(inner, state, &writer, 1)
        .saturating_add(additional_retained_bytes);
    if projected > cap {
        return Err(Error::new(
            ErrorCode::StreamLimit,
            "zmux: local open limited by session memory cap",
        )
        .with_scope(ErrorScope::Session)
        .with_operation(ErrorOperation::Open)
        .with_source(ErrorSource::Local)
        .with_direction(ErrorDirection::Both));
    }
    Ok(())
}

pub(super) fn tracked_retained_state_memory_locked(inner: &Inner, state: &ConnState) -> usize {
    let hidden = state
        .hidden_tombstones
        .saturating_mul(retained_state_unit_locked(inner));
    let visible_tombstones = state
        .tombstones
        .len()
        .saturating_sub(state.hidden_tombstones);
    let visible = visible_tombstones.saturating_mul(COMPACT_TERMINAL_STATE_UNIT);
    let markers =
        marker_only_retained_count_locked(state).saturating_mul(COMPACT_TERMINAL_STATE_UNIT);
    hidden.saturating_add(visible).saturating_add(markers)
}

#[inline]
fn retained_state_unit_locked(inner: &Inner) -> usize {
    let settings = inner.local_preface.settings;
    u64_to_usize_saturating(settings.max_frame_payload)
        .max(u64_to_usize_saturating(settings.max_control_payload_bytes))
        .max(u64_to_usize_saturating(
            settings.max_extension_payload_bytes,
        ))
        .max(MIN_RETAINED_STATE_UNIT)
}

#[inline]
fn session_memory_hard_cap_locked(
    inner: &Inner,
    state: &ConnState,
    writer: &WriterQueueStats,
) -> usize {
    if let Some(cap) = effective_session_memory_cap(inner) {
        return cap;
    }
    let recv_window = u64_to_usize_saturating(inner.local_preface.settings.initial_max_data);
    recv_window
        .saturating_add(state.accept_backlog_bytes_limit)
        .saturating_add(writer.session_data_high_watermark)
        .saturating_add(writer.urgent_max_bytes)
        .saturating_add(writer.pending_control_bytes_budget)
        .saturating_add(writer.pending_priority_bytes_budget)
        .saturating_add(state.retained_open_info_bytes_budget)
        .saturating_add(state.retained_peer_reason_bytes_budget)
        .max(DEFAULT_SESSION_MEMORY_HARD_CAP_FLOOR)
}

pub(super) fn take_session_closed_event_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
) -> Option<Event> {
    inner.event_handler.as_ref()?;
    if state.session_closed_event_sent {
        return None;
    }
    state.session_closed_event_sent = true;
    Some(Event {
        event_type: EventType::SessionClosed,
        session_state: state.state,
        stream_id: 0,
        stream: None,
        local: false,
        bidirectional: false,
        time: SystemTime::now(),
        error: state.close_error.clone(),
        application_visible: false,
    })
}

pub(super) fn take_stream_event_locked(
    inner: &Arc<Inner>,
    stream: &Arc<StreamInner>,
    stream_state: &mut StreamState,
    session_state: SessionState,
    event_type: EventType,
    error: Option<Error>,
) -> Option<Event> {
    inner.event_handler.as_ref()?;
    match event_type {
        EventType::StreamOpened => {
            if !stream.opened_locally
                || !stream_state.peer_visible
                || stream_state.opened_event_sent
            {
                return None;
            }
            stream_state.opened_event_sent = true;
        }
        EventType::StreamAccepted => {
            if stream.opened_locally
                || !stream.application_visible
                || stream_state.accept_pending
                || stream_state.accepted_event_sent
            {
                return None;
            }
            stream_state.accepted_event_sent = true;
        }
        EventType::SessionClosed => return None,
    }
    let stream_id = stream.id.load(Ordering::Acquire);
    let application_visible = match event_type {
        EventType::StreamOpened => false,
        EventType::StreamAccepted => stream.application_visible,
        EventType::SessionClosed => false,
    };
    let stream_info = StreamEventInfo {
        stream_id,
        metadata: StreamMetadata {
            priority: stream_state.metadata.priority,
            group: stream_state.metadata.group,
            open_info: stream_state.open_info.clone(),
        },
        local: stream.opened_locally,
        bidirectional: stream.bidi,
        application_visible,
    };
    Some(Event {
        event_type,
        session_state,
        stream_id,
        stream: Some(stream_info),
        local: stream.opened_locally,
        bidirectional: stream.bidi,
        time: SystemTime::now(),
        error,
        application_visible,
    })
}

pub(super) struct PeerVisibleUpdate {
    pub(super) event: Option<Event>,
    pub(super) pending_priority: Option<Vec<u8>>,
}

pub(super) fn mark_stream_peer_visible_locked(
    inner: &Arc<Inner>,
    stream: &Arc<StreamInner>,
    stream_state: &mut StreamState,
    session_state: SessionState,
) -> Option<PeerVisibleUpdate> {
    if !stream.opened_locally || stream_state.peer_visible {
        return None;
    }
    let stream_id = stream.id.load(Ordering::Acquire);
    if stream_id == 0 {
        return None;
    }
    stream_state.peer_visible = true;
    clear_stream_open_prefix_locked(stream_state);
    let pending_priority = stream_state.pending_priority_update.take();
    let event = take_stream_event_locked(
        inner,
        stream,
        stream_state,
        session_state,
        EventType::StreamOpened,
        None,
    );
    Some(PeerVisibleUpdate {
        event,
        pending_priority,
    })
}

pub(super) fn mark_stream_peer_visible_by_id(
    inner: &Arc<Inner>,
    stream_id: u64,
) -> Option<PeerVisibleUpdate> {
    let (stream, session_state) = {
        let state = inner.state.lock().unwrap();
        (state.streams.get(&stream_id).cloned()?, state.state)
    };
    let mut stream_state = stream.state.lock().unwrap();
    if stream_state.aborted.is_some() && stream_state.abort_source == ErrorSource::Remote {
        return None;
    }
    mark_stream_peer_visible_locked(inner, &stream, &mut stream_state, session_state)
}

pub(super) fn queue_peer_visible_pending_priority(
    inner: &Arc<Inner>,
    stream_id: u64,
    payload: Vec<u8>,
) {
    let queued_cost = payload.len().saturating_add(1);
    let queued = match ensure_projected_session_memory_cap(inner, queued_cost, "priority update") {
        Ok(()) => inner.try_queue_frame(Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id,
            payload,
        }),
        Err(err) => Err(err),
    };
    if queued.is_err() {
        let mut state = inner.state.lock().unwrap();
        state.dropped_local_priority_update_count =
            state.dropped_local_priority_update_count.saturating_add(1);
    }
}

pub(super) fn fail_pending_pings_locked(state: &mut ConnState, err: Error) {
    state.keepalive_ping = None;
    state.canceled_ping_payload = None;
    if let Some(ping) = state.ping_waiter.take() {
        let slot = ping.slot;
        {
            let mut result = slot.result.lock().unwrap();
            *result = Some(Err(err));
        }
        slot.cond.notify_all();
    }
}

pub(super) fn notify_all_streams(state: &ConnState) {
    for stream in state.streams.values() {
        stream.cond.notify_all();
    }
    for stream in state
        .provisional_bidi
        .iter()
        .chain(state.provisional_uni.iter())
    {
        stream.cond.notify_all();
    }
}

pub(super) fn release_session_runtime_state_locked(state: &mut ConnState) {
    let live_streams = std::mem::take(&mut state.streams);
    let provisional_bidi = std::mem::take(&mut state.provisional_bidi);
    let provisional_uni = std::mem::take(&mut state.provisional_uni);

    for stream in live_streams
        .into_values()
        .chain(provisional_bidi)
        .chain(provisional_uni)
    {
        let mut stream_state = stream.state.lock().unwrap();
        stream_state.recv_buf.clear_detailed();
        stream_state.recv_pending = 0;
        clear_stream_open_prefix_locked(&mut stream_state);
        stream_state.pending_priority_update = None;
        stream_state.pending_data_frames = 0;
        stream_state.pending_terminal_frames = 0;
        stream_state.provisional_created_at = None;
        stream_state.active_counted = false;
        clear_accept_backlog_entry_locked(state, &mut stream_state);
        clear_stream_open_info_locked(state, &mut stream_state);
        clear_stream_peer_reasons_locked(state, &mut stream_state);
        drop(stream_state);
        stream.cond.notify_all();
    }

    state.scheduler.clear();
    state.inflight_data_by_stream = Default::default();
    state.tombstones = Default::default();
    state.tombstone_order = Default::default();
    state.hidden_tombstone_order = Default::default();
    state.hidden_tombstones = 0;
    state.used_markers = Default::default();
    state.used_marker_order = Default::default();
    state.used_marker_ranges = Default::default();
    state.used_marker_range_mode = false;
    state.accept_bidi = Default::default();
    state.accept_uni = Default::default();
    state.accept_backlog_bytes = 0;
    state.retained_open_info_bytes = 0;
    state.active = ActiveStreamStats::default();
    state.send_session_used = 0;
    state.send_session_blocked_at = None;
    state.recv_session_used = 0;
    state.recv_session_buffered = 0;
    state.recv_session_retained = 0;
    state.recv_session_pending = 0;
    state.recv_replenish_retry = false;
    state.read_idle_ping_due_at = None;
    state.write_idle_ping_due_at = None;
    state.max_ping_due_at = None;
    state.keepalive_ping = None;
    state.canceled_ping_payload = None;
    if let Some(ping) = state.ping_waiter.take() {
        {
            let mut result = ping.slot.result.lock().unwrap();
            *result = Some(Err(Error::session_closed()));
        }
        ping.slot.cond.notify_all();
    }
    state.last_ping_sent_at = None;
    state.last_pong_at = None;
    state.last_ping_rtt = None;
}

pub(super) fn account_session_receive_buffered_locked(
    state: &mut ConnState,
    bytes: u64,
    retained_bytes: usize,
) {
    state.recv_session_buffered = state.recv_session_buffered.saturating_add(bytes);
    state.recv_session_retained = state.recv_session_retained.saturating_add(retained_bytes);
}

pub(super) fn release_session_receive_buffered_locked(
    state: &mut ConnState,
    bytes: u64,
    retained_bytes: usize,
) {
    state.recv_session_buffered = state.recv_session_buffered.saturating_sub(bytes);
    if state.recv_session_buffered == 0 {
        state.recv_session_retained = 0;
    } else {
        state.recv_session_retained = state.recv_session_retained.saturating_sub(retained_bytes);
    }
}

pub(super) fn clear_stream_receive_credit_locked(
    inner: &Arc<Inner>,
    stream: &StreamInner,
    stream_state: &mut StreamState,
) {
    stream_state.recv_pending = 0;
    inner
        .write_queue
        .discard_stream_max_data(stream.id.load(Ordering::Acquire));
}

pub(super) fn ensure_session_open(state: &ConnState) -> Result<()> {
    match state.state {
        SessionState::Ready | SessionState::Draining => Ok(()),
        SessionState::Closing | SessionState::Closed | SessionState::Failed => Err(state
            .close_error
            .clone()
            .unwrap_or_else(Error::session_closed)),
    }
}

pub(super) fn ensure_session_not_closed(state: &ConnState) -> Result<()> {
    match state.state {
        SessionState::Ready | SessionState::Draining | SessionState::Closing => Ok(()),
        SessionState::Closed | SessionState::Failed => Err(state
            .close_error
            .clone()
            .unwrap_or_else(Error::session_closed)),
    }
}

#[inline]
pub(super) fn provisional_available_count(next_id: u64, goaway: u64) -> usize {
    if next_id > goaway {
        return 0;
    }
    let slots = (goaway - next_id) / 4 + 1;
    u64_to_usize_saturating(slots)
}

pub(super) fn reap_expired_provisionals_locked(
    state: &mut ConnState,
    bidi: bool,
    skip_locked_stream: Option<&StreamInner>,
) {
    let max_age = provisional_open_max_age(state.last_ping_rtt);
    if max_age.is_zero() {
        return;
    }
    let now = Instant::now();
    loop {
        let stream = {
            let queue = if bidi {
                &mut state.provisional_bidi
            } else {
                &mut state.provisional_uni
            };
            let Some(front) = queue.front() else {
                return;
            };
            if skip_locked_stream.is_some_and(|skip| std::ptr::eq(Arc::as_ptr(front), skip)) {
                return;
            }
            let expired = {
                let stream_state = front.state.lock().unwrap();
                provisional_expired_locked(&stream_state, now, max_age)
            };
            if expired {
                queue.pop_front()
            } else {
                None
            }
        };
        let Some(stream) = stream else {
            return;
        };
        shrink_provisional_queue_locked(state, bidi);
        let mut stream_state = stream.state.lock().unwrap();
        fail_expired_provisional_locked(state, &mut stream_state);
        stream.cond.notify_all();
    }
}

#[inline]
pub(super) fn provisional_open_expired_reason() -> &'static str {
    PROVISIONAL_OPEN_EXPIRED_REASON
}

#[inline]
pub(super) fn provisional_expired_locked(
    stream_state: &StreamState,
    now: Instant,
    max_age: Duration,
) -> bool {
    stream_state
        .provisional_created_at
        .is_some_and(|created| now.saturating_duration_since(created) > max_age)
}

pub(super) fn provisional_open_max_age(last_ping_rtt: Option<Duration>) -> Duration {
    let mut timeout = PROVISIONAL_OPEN_BASE_MAX_AGE;
    if let Some(rtt) = nonzero_duration(last_ping_rtt) {
        let candidate = rtt
            .saturating_mul(PROVISIONAL_OPEN_RTT_MULTIPLIER)
            .saturating_add(PROVISIONAL_OPEN_RTT_ADAPTIVE_SLACK);
        timeout = timeout.max(candidate);
    }
    timeout.min(PROVISIONAL_OPEN_MAX_AGE_ADAPTIVE_CAP)
}

pub(super) fn fail_expired_provisional_locked(
    state: &mut ConnState,
    stream_state: &mut StreamState,
) {
    stream_state.provisional_created_at = None;
    stream_state.aborted = Some((
        ErrorCode::Cancelled.as_u64(),
        PROVISIONAL_OPEN_EXPIRED_REASON.to_owned(),
    ));
    stream_state.abort_source = ErrorSource::Local;
    let released = stream_state.recv_buf.clear_detailed();
    stream_state.recv_pending = 0;
    release_session_receive_buffered_locked(
        state,
        usize_to_u64_saturating(released.bytes),
        released.released_retained_bytes,
    );
    clear_stream_open_info_locked(state, stream_state);
    clear_stream_open_prefix_locked(stream_state);
    state.provisional_open_expired_count = state.provisional_open_expired_count.saturating_add(1);
}

#[inline]
pub(super) fn late_data_per_stream_cap(
    configured: Option<u64>,
    initial_stream_window: u64,
    max_frame_payload: u64,
) -> u64 {
    match configured {
        Some(cap) => cap,
        None => DEFAULT_LATE_DATA_PER_STREAM_CAP_FLOOR.max(
            max_frame_payload
                .saturating_mul(2)
                .min(initial_stream_window / 8),
        ),
    }
}

pub(super) fn reclaim_provisionals_after_go_away(state: &mut ConnState, bidi: bool) {
    let (next_id, goaway) = if bidi {
        (state.next_local_bidi, state.peer_go_away_bidi)
    } else {
        (state.next_local_uni, state.peer_go_away_uni)
    };
    let available = provisional_available_count(next_id, goaway);
    loop {
        let stream = {
            let queue = if bidi {
                &mut state.provisional_bidi
            } else {
                &mut state.provisional_uni
            };
            if queue.len() <= available {
                None
            } else {
                queue.pop_back()
            }
        };
        let Some(stream) = stream else {
            break;
        };
        let mut stream_state = stream.state.lock().unwrap();
        stream_state.aborted = Some((
            ErrorCode::RefusedStream.as_u64(),
            "peer GOAWAY refuses provisional open".to_owned(),
        ));
        stream_state.abort_source = ErrorSource::Remote;
        stream_state.provisional_created_at = None;
        let released = stream_state.recv_buf.clear_detailed();
        stream_state.recv_pending = 0;
        release_session_receive_buffered_locked(
            state,
            usize_to_u64_saturating(released.bytes),
            released.released_retained_bytes,
        );
        clear_stream_open_info_locked(state, &mut stream_state);
        clear_stream_open_prefix_locked(&mut stream_state);
        drop(stream_state);
        stream.cond.notify_all();
    }
    shrink_provisional_queue_locked(state, bidi);
}

pub(super) fn reclaim_unseen_local_streams_after_go_away(
    state: &mut ConnState,
    bidi: bool,
) -> Vec<Arc<StreamInner>> {
    let goaway = if bidi {
        state.peer_go_away_bidi
    } else {
        state.peer_go_away_uni
    };
    let mut streams = Vec::new();
    for stream in state.streams.values() {
        if !stream.opened_locally || stream.bidi != bidi {
            continue;
        }
        let stream_id = stream.id.load(Ordering::Acquire);
        if stream_id != 0 && stream_id > goaway {
            streams.push(Arc::clone(stream));
        }
    }
    let mut reclaimed = Vec::new();
    for stream in streams {
        let stream_id = stream.id.load(Ordering::Acquire);
        debug_assert!(stream_id != 0 && stream_id > goaway);
        let mut stream_state = stream.state.lock().unwrap();
        if stream_state.peer_visible
            || stream_state.aborted.is_some()
            || stream_fully_terminal(&stream, &stream_state)
        {
            continue;
        }

        stream_state.aborted = Some((ErrorCode::RefusedStream.as_u64(), String::new()));
        stream_state.abort_source = ErrorSource::Remote;
        let released_recv = stream_state.recv_buf.clear_detailed();
        stream_state.recv_pending = 0;
        release_session_receive_buffered_locked(
            state,
            usize_to_u64_saturating(released_recv.bytes),
            released_recv.released_retained_bytes,
        );
        if stream_state.send_used != 0 {
            state.send_session_used = state
                .send_session_used
                .saturating_sub(stream_state.send_used);
            stream_state.send_used = 0;
            stream_state.send_blocked_at = None;
            state.send_session_blocked_at = None;
        }
        stream_state.pending_priority_update = None;
        clear_stream_open_prefix_locked(&mut stream_state);
        clear_stream_open_info_locked(state, &mut stream_state);
        maybe_release_active_count(state, &stream, &mut stream_state);
        drop(stream_state);
        stream.cond.notify_all();
        reclaimed.push(stream);
    }
    reclaimed
}

pub(super) fn clear_accepted_backlog_accounting(state: &mut ConnState, stream: &Arc<StreamInner>) {
    let mut stream_state = stream.state.lock().unwrap();
    clear_accept_backlog_entry_locked(state, &mut stream_state);
    release_stream_open_info_budget_locked(state, &mut stream_state);
}

pub(super) fn shrink_accept_queue_locked(state: &mut ConnState, bidi: bool) {
    let queue = if bidi {
        &mut state.accept_bidi
    } else {
        &mut state.accept_uni
    };
    shrink_queue_if_sparse(queue, ACCEPT_QUEUE_RETAIN_MIN_CAP, false);
}

pub(super) fn shrink_provisional_queue_locked(state: &mut ConnState, bidi: bool) {
    let queue = if bidi {
        &mut state.provisional_bidi
    } else {
        &mut state.provisional_uni
    };
    shrink_queue_if_sparse(queue, PROVISIONAL_QUEUE_RETAIN_MIN_CAP, false);
}

pub(super) fn refresh_accept_backlog_bytes_locked(
    state: &mut ConnState,
    stream_state: &mut StreamState,
) {
    if !stream_state.accept_pending {
        return;
    }
    let next_bytes = stream_state
        .recv_buf
        .len()
        .saturating_add(stream_state.open_info.len());
    state.accept_backlog_bytes = state
        .accept_backlog_bytes
        .saturating_sub(stream_state.accept_backlog_bytes)
        .saturating_add(next_bytes);
    stream_state.accept_backlog_bytes = next_bytes;
}

pub(super) fn retain_stream_open_info_locked(
    state: &mut ConnState,
    stream_state: &mut StreamState,
    open_info: Vec<u8>,
) {
    clear_stream_open_info_locked(state, stream_state);
    let open_info = compact_retained_bytes(open_info);
    stream_state.retained_open_info_bytes = open_info.len();
    state.retained_open_info_bytes = state
        .retained_open_info_bytes
        .saturating_add(stream_state.retained_open_info_bytes);
    stream_state.open_info = open_info;
}

pub(super) fn clear_stream_open_info_locked(state: &mut ConnState, stream_state: &mut StreamState) {
    release_stream_open_info_budget_locked(state, stream_state);
    stream_state.open_info = Vec::new();
}

fn release_stream_open_info_budget_locked(state: &mut ConnState, stream_state: &mut StreamState) {
    state.retained_open_info_bytes = state
        .retained_open_info_bytes
        .saturating_sub(stream_state.retained_open_info_bytes);
    stream_state.retained_open_info_bytes = 0;
}

pub(super) fn clear_accept_backlog_entry_locked(
    state: &mut ConnState,
    stream_state: &mut StreamState,
) {
    if !stream_state.accept_pending {
        return;
    }
    state.accept_backlog_bytes = state
        .accept_backlog_bytes
        .saturating_sub(stream_state.accept_backlog_bytes);
    stream_state.accept_pending = false;
    stream_state.accept_backlog_bytes = 0;
}

pub(super) fn remove_accept_queue_entry_locked(state: &mut ConnState, stream: &Arc<StreamInner>) {
    let stream_id = stream.id.load(Ordering::Acquire);
    let queue = if stream.bidi {
        &mut state.accept_bidi
    } else {
        &mut state.accept_uni
    };
    queue.retain(|candidate| candidate.id.load(Ordering::Acquire) != stream_id);
    shrink_accept_queue_locked(state, stream.bidi);
}

pub(super) fn enforce_accept_backlog_bytes_locked(state: &mut ConnState) -> Vec<(u64, u64, usize)> {
    let mut refused = Vec::new();
    while state.accept_backlog_bytes_limit > 0
        && state.accept_backlog_bytes > state.accept_backlog_bytes_limit
    {
        let Some(stream) = pop_newest_accept_pending_locked(state) else {
            break;
        };
        let stream_id = stream.id.load(Ordering::Acquire);
        {
            let mut stream_state = stream.state.lock().unwrap();
            clear_accept_backlog_entry_locked(state, &mut stream_state);
            state.accept_backlog_refused = state.accept_backlog_refused.saturating_add(1);
            note_abort_reason_locked(state, ErrorCode::RefusedStream.as_u64());
            stream_state.aborted = Some((
                ErrorCode::RefusedStream.as_u64(),
                "accept backlog byte limit exceeded".to_owned(),
            ));
            stream_state.abort_source = ErrorSource::Local;
            let released = stream_state.recv_buf.clear_detailed();
            stream_state.recv_pending = 0;
            clear_stream_open_info_locked(state, &mut stream_state);
            maybe_release_active_count(state, &stream, &mut stream_state);
            refused.push((
                stream_id,
                usize_to_u64_saturating(released.bytes),
                released.released_retained_bytes,
            ));
        }
        stream.cond.notify_all();
    }
    refused
}

pub(super) fn enforce_retained_open_info_budget_locked(
    state: &mut ConnState,
) -> Vec<(u64, u64, usize)> {
    let mut refused = Vec::new();
    while state.retained_open_info_bytes > state.retained_open_info_bytes_budget {
        let Some(stream) = pop_newest_accept_pending_locked(state) else {
            break;
        };
        let stream_id = stream.id.load(Ordering::Acquire);
        {
            let mut stream_state = stream.state.lock().unwrap();
            clear_accept_backlog_entry_locked(state, &mut stream_state);
            state.accept_backlog_refused = state.accept_backlog_refused.saturating_add(1);
            note_abort_reason_locked(state, ErrorCode::RefusedStream.as_u64());
            stream_state.aborted = Some((
                ErrorCode::RefusedStream.as_u64(),
                "open_info budget exceeded".to_owned(),
            ));
            stream_state.abort_source = ErrorSource::Local;
            let released = stream_state.recv_buf.clear_detailed();
            stream_state.recv_pending = 0;
            clear_stream_open_info_locked(state, &mut stream_state);
            maybe_release_active_count(state, &stream, &mut stream_state);
            refused.push((
                stream_id,
                usize_to_u64_saturating(released.bytes),
                released.released_retained_bytes,
            ));
        }
        stream.cond.notify_all();
    }
    refused
}

pub(super) fn enforce_session_memory_accept_backlog_locked(
    inner: &Inner,
    state: &mut ConnState,
) -> Vec<(u64, u64, usize)> {
    let Some(cap) = effective_session_memory_cap(inner) else {
        return Vec::new();
    };
    let mut refused = Vec::new();
    loop {
        let writer = inner.write_queue.stats();
        if projected_live_stream_memory_locked(inner, state, &writer, 0) <= cap {
            break;
        }
        let Some(stream) = pop_newest_accept_pending_locked(state) else {
            break;
        };
        let stream_id = stream.id.load(Ordering::Acquire);
        {
            let mut stream_state = stream.state.lock().unwrap();
            clear_accept_backlog_entry_locked(state, &mut stream_state);
            state.accept_backlog_refused = state.accept_backlog_refused.saturating_add(1);
            note_abort_reason_locked(state, ErrorCode::RefusedStream.as_u64());
            stream_state.aborted = Some((
                ErrorCode::RefusedStream.as_u64(),
                "session memory cap exceeded".to_owned(),
            ));
            stream_state.abort_source = ErrorSource::Local;
            let released = stream_state.recv_buf.clear_detailed();
            stream_state.recv_pending = 0;
            clear_stream_open_info_locked(state, &mut stream_state);
            maybe_release_active_count(state, &stream, &mut stream_state);
            refused.push((
                stream_id,
                usize_to_u64_saturating(released.bytes),
                released.released_retained_bytes,
            ));
        }
        stream.cond.notify_all();
    }
    refused
}

#[inline]
pub(super) fn retained_open_info_available(state: &ConnState) -> usize {
    state
        .retained_open_info_bytes_budget
        .saturating_sub(state.retained_open_info_bytes)
}

pub(super) fn retain_peer_reason_locked(
    inner: &Inner,
    state: &mut ConnState,
    reason: String,
) -> (String, usize) {
    let budget_available = state
        .retained_peer_reason_bytes_budget
        .saturating_sub(state.retained_peer_reason_bytes);
    if reason.is_empty() || budget_available == 0 {
        return (String::new(), 0);
    }
    let writer = inner.write_queue.stats();
    let hard_cap = session_memory_hard_cap_locked(inner, state, &writer);
    let tracked = projected_live_stream_memory_locked(inner, state, &writer, 0);
    let available = budget_available.min(hard_cap.saturating_sub(tracked));
    let retained = truncate_utf8(reason, available);
    let retained_len = retained.len();
    state.retained_peer_reason_bytes = state
        .retained_peer_reason_bytes
        .saturating_add(retained_len);
    (retained, retained_len)
}

#[inline]
pub(super) fn release_peer_reason_locked(state: &mut ConnState, bytes: usize) {
    state.retained_peer_reason_bytes = state.retained_peer_reason_bytes.saturating_sub(bytes);
}

pub(super) fn retain_peer_go_away_error_locked(
    inner: &Inner,
    state: &mut ConnState,
    code: u64,
    reason: String,
) {
    if let Some(old) = state.peer_go_away_error.take() {
        release_peer_reason_locked(state, old.reason.len());
    }
    let (reason, _) = retain_peer_reason_locked(inner, state, reason);
    state.peer_go_away_error = Some(PeerGoAwayError { code, reason });
}

pub(super) fn retain_stream_recv_reset_reason_locked(
    inner: &Inner,
    state: &mut ConnState,
    stream_state: &mut StreamState,
    code: u64,
    reason: String,
) {
    note_reset_reason_locked(state, code);
    release_peer_reason_locked(state, stream_state.retained_recv_reset_reason_bytes);
    let (reason, bytes) = retain_peer_reason_locked(inner, state, reason);
    stream_state.recv_reset = Some((code, reason));
    stream_state.retained_recv_reset_reason_bytes = bytes;
}

pub(super) fn retain_stream_abort_reason_locked(
    inner: &Inner,
    state: &mut ConnState,
    stream_state: &mut StreamState,
    code: u64,
    reason: String,
) {
    note_abort_reason_locked(state, code);
    release_peer_reason_locked(state, stream_state.retained_abort_reason_bytes);
    let (reason, bytes) = retain_peer_reason_locked(inner, state, reason);
    stream_state.aborted = Some((code, reason));
    stream_state.abort_source = ErrorSource::Remote;
    stream_state.retained_abort_reason_bytes = bytes;
}

pub(super) fn retain_stream_stopped_reason_locked(
    inner: &Inner,
    state: &mut ConnState,
    stream_state: &mut StreamState,
    code: u64,
    reason: String,
) {
    release_peer_reason_locked(state, stream_state.retained_stopped_reason_bytes);
    let (reason, bytes) = retain_peer_reason_locked(inner, state, reason);
    stream_state.stopped_by_peer = Some((code, reason));
    stream_state.retained_stopped_reason_bytes = bytes;
}

pub(super) fn note_reset_reason_locked(state: &mut ConnState, code: u64) {
    note_reason_locked(
        &mut state.reset_reason_counts,
        &mut state.reset_reason_overflow,
        code,
    );
}

pub(super) fn note_abort_reason_locked(state: &mut ConnState, code: u64) {
    note_reason_locked(
        &mut state.abort_reason_counts,
        &mut state.abort_reason_overflow,
        code,
    );
}

fn note_reason_locked(
    counts: &mut std::collections::HashMap<u64, u64>,
    overflow: &mut u64,
    code: u64,
) {
    let can_insert = counts.len() < MAX_REASON_STATS_CODES;
    match counts.entry(code) {
        Entry::Occupied(mut entry) => {
            let count = entry.get_mut();
            *count = (*count).saturating_add(1);
        }
        Entry::Vacant(entry) if can_insert => {
            entry.insert(1);
        }
        Entry::Vacant(_) => {
            *overflow = overflow.saturating_add(1);
        }
    }
}

pub(super) fn clear_stream_peer_reasons_locked(
    state: &mut ConnState,
    stream_state: &mut StreamState,
) {
    release_peer_reason_field_locked(state, &mut stream_state.retained_recv_reset_reason_bytes);
    release_peer_reason_field_locked(state, &mut stream_state.retained_abort_reason_bytes);
    release_peer_reason_field_locked(state, &mut stream_state.retained_stopped_reason_bytes);
}

#[inline]
fn release_peer_reason_field_locked(state: &mut ConnState, bytes: &mut usize) {
    release_peer_reason_locked(state, *bytes);
    *bytes = 0;
}

#[inline]
fn compact_retained_string(value: String) -> String {
    if value.is_empty() {
        String::new()
    } else if value.len() == value.capacity() {
        value
    } else {
        value.into_boxed_str().into_string()
    }
}

fn truncate_utf8(mut value: String, max_len: usize) -> String {
    if value.len() <= max_len {
        return compact_retained_string(value);
    }
    let mut keep = max_len;
    while !value.is_char_boundary(keep) {
        keep -= 1;
    }
    if keep == 0 {
        return String::new();
    }
    value.truncate(keep);
    compact_retained_string(value)
}

#[inline]
fn accept_seq_is_newer_or_equal(lhs: u64, rhs: u64) -> bool {
    lhs.wrapping_sub(rhs) < (1u64 << 63)
}

pub(super) fn pop_newest_accept_pending_locked(state: &mut ConnState) -> Option<Arc<StreamInner>> {
    let bidi_seq = state
        .accept_bidi
        .back()
        .map(|stream| stream.state.lock().unwrap().accept_seq);
    let uni_seq = state
        .accept_uni
        .back()
        .map(|stream| stream.state.lock().unwrap().accept_seq);
    match (bidi_seq, uni_seq) {
        (None, None) => None,
        (Some(_), None) => {
            let stream = state.accept_bidi.pop_back();
            shrink_accept_queue_locked(state, true);
            stream
        }
        (None, Some(_)) => {
            let stream = state.accept_uni.pop_back();
            shrink_accept_queue_locked(state, false);
            stream
        }
        (Some(bidi), Some(uni)) if accept_seq_is_newer_or_equal(bidi, uni) => {
            let stream = state.accept_bidi.pop_back();
            shrink_accept_queue_locked(state, true);
            stream
        }
        (Some(_), Some(_)) => {
            let stream = state.accept_uni.pop_back();
            shrink_accept_queue_locked(state, false);
            stream
        }
    }
}

#[inline]
pub(super) fn check_write_open(state: &StreamState) -> Result<()> {
    if state.send_fin {
        return Err(Error::write_closed().with_termination_kind(TerminationKind::Graceful));
    }
    if let Some((code, reason)) = &state.stopped_by_peer {
        return Err(Error::application(*code, reason.clone())
            .with_source(ErrorSource::Remote)
            .with_termination_kind(TerminationKind::Stopped));
    }
    if let Some((code, reason)) = &state.aborted {
        return Err(stream_abort_error(state, *code, reason.clone()));
    }
    if let Some((code, reason)) = &state.send_reset {
        return Err(local_reset_error(*code, reason.clone()));
    }
    Ok(())
}

pub(super) fn stream_abort_error(state: &StreamState, code: u64, reason: String) -> Error {
    Error::application(code, reason)
        .with_source(state.abort_source)
        .with_termination_kind(TerminationKind::Abort)
}

pub(super) fn peer_reset_error(code: u64, reason: String) -> Error {
    Error::application(code, reason)
        .with_source(ErrorSource::Remote)
        .with_termination_kind(TerminationKind::Reset)
}

pub(super) fn local_reset_error(code: u64, reason: String) -> Error {
    Error::application(code, reason)
        .with_source(ErrorSource::Local)
        .with_termination_kind(TerminationKind::Reset)
}

pub(super) fn maybe_release_active_count(
    state: &mut ConnState,
    stream: &StreamInner,
    stream_state: &mut StreamState,
) {
    if !stream_fully_terminal(stream, stream_state) {
        return;
    }

    if stream_state.active_counted {
        stream_state.active_counted = false;
        if stream.opened_locally {
            if stream.bidi {
                state.active.local_bidi = state.active.local_bidi.saturating_sub(1);
            } else {
                state.active.local_uni = state.active.local_uni.saturating_sub(1);
            }
        } else if stream.bidi {
            state.active.peer_bidi = state.active.peer_bidi.saturating_sub(1);
        } else {
            state.active.peer_uni = state.active.peer_uni.saturating_sub(1);
        }
    }

    maybe_compact_stream_locked(state, stream, stream_state);
}

pub(super) fn maybe_compact_stream_locked(
    state: &mut ConnState,
    stream: &StreamInner,
    stream_state: &mut StreamState,
) {
    if !stream_fully_terminal(stream, stream_state)
        || !stream_state.recv_buf.is_empty()
        || stream_state.read_stop_pending_code.is_some()
        || stream_state.pending_data_frames != 0
        || stream_state.pending_terminal_frames != 0
        || (stream_state.accept_pending && !stream_state.open_info.is_empty())
    {
        return;
    }
    let stream_id = stream.id.load(Ordering::Acquire);
    if state
        .inflight_data_by_stream
        .get(&stream_id)
        .is_some_and(|bytes| *bytes != 0)
    {
        return;
    }
    if stream_id == 0
        || !state
            .streams
            .get(&stream_id)
            .is_some_and(|stored| std::ptr::eq(Arc::as_ptr(stored), stream))
    {
        return;
    }
    state.scheduler.drop_stream(stream_id);

    let tombstone = super::types::StreamTombstone {
        data_disposition: terminal_data_disposition(stream, stream_state),
        late_data_received: stream_state.late_data_received,
        late_data_cap: stream_state.late_data_cap,
        hidden: !stream.application_visible,
        created_at: Instant::now(),
    };
    state.streams.remove(&stream_id);
    clear_stream_open_prefix_locked(stream_state);
    clear_stream_open_info_locked(state, stream_state);
    clear_stream_peer_reasons_locked(state, stream_state);
    stream_state.pending_priority_update = None;
    record_tombstone_locked(state, stream_id, tombstone);
}

pub(super) fn note_written_stream_frames_locked(
    state: &mut ConnState,
    stream_id: u64,
    data_frames: usize,
    terminal_frames: usize,
) {
    if data_frames == 0 && terminal_frames == 0 {
        return;
    }
    let Some(stream) = state.streams.get(&stream_id).cloned() else {
        return;
    };
    let mut stream_state = stream.state.lock().unwrap();
    stream_state.pending_data_frames = stream_state.pending_data_frames.saturating_sub(data_frames);
    stream_state.pending_terminal_frames = stream_state
        .pending_terminal_frames
        .saturating_sub(terminal_frames);
    maybe_compact_stream_locked(state, &stream, &mut stream_state);
    drop(stream_state);
    stream.cond.notify_all();
}

pub(super) fn release_discarded_queued_stream_frames_locked(
    state: &mut ConnState,
    stream: &Arc<StreamInner>,
    stats: StreamDiscardStats,
) {
    if stats.removed_frames == 0 {
        return;
    }
    let mut stream_state = stream.state.lock().unwrap();
    stream_state.pending_data_frames = stream_state
        .pending_data_frames
        .saturating_sub(stats.data_frames);
    stream_state.pending_terminal_frames = stream_state
        .pending_terminal_frames
        .saturating_sub(stats.terminal_frames);
    let released_send = usize_to_u64_saturating(stats.data_bytes).min(stream_state.send_used);
    stream_state.send_used = stream_state.send_used.saturating_sub(released_send);
    state.send_session_used = state.send_session_used.saturating_sub(released_send);
    stream_state.send_blocked_at = None;
    if released_send != 0 {
        state.send_session_blocked_at = None;
    }
    maybe_release_active_count(state, stream, &mut stream_state);
    drop(stream_state);
    stream.cond.notify_all();
}

#[inline]
pub(super) fn stream_fully_terminal(stream: &StreamInner, state: &StreamState) -> bool {
    if state.aborted.is_some() {
        return true;
    }
    let send_terminal = !stream.local_send || state.send_fin || state.send_reset.is_some();
    let recv_terminal = !stream.local_recv || state.recv_fin || state.recv_reset.is_some();
    send_terminal && recv_terminal
}

fn terminal_data_disposition(
    stream: &StreamInner,
    state: &StreamState,
) -> super::types::TerminalDataDisposition {
    super::types::TerminalDataDisposition {
        action: terminal_data_action_for(
            stream.local_recv,
            state.aborted.is_some(),
            state.recv_reset.is_some(),
            state.read_stopped,
            state.recv_fin,
        ),
        cause: late_data_cause_for(state),
    }
}

#[inline]
pub(super) fn late_data_cause_for(state: &StreamState) -> super::types::LateDataCause {
    if state.read_stopped {
        return super::types::LateDataCause::CloseRead;
    }
    if state.recv_reset.is_some() {
        return super::types::LateDataCause::Reset;
    }
    if state.aborted.is_some() {
        return super::types::LateDataCause::Abort;
    }
    super::types::LateDataCause::None
}

#[inline]
fn terminal_data_action_for(
    local_recv: bool,
    aborted: bool,
    recv_reset: bool,
    read_stopped: bool,
    recv_fin: bool,
) -> super::types::TerminalDataAction {
    if !local_recv || aborted || recv_reset || read_stopped {
        return super::types::TerminalDataAction::Ignore;
    }
    if recv_fin {
        return super::types::TerminalDataAction::Abort(ErrorCode::StreamClosed.as_u64());
    }
    super::types::TerminalDataAction::Ignore
}

pub(super) fn record_tombstone_locked(
    state: &mut ConnState,
    stream_id: u64,
    tombstone: super::types::StreamTombstone,
) {
    if state.tombstone_limit == 0 {
        let old = state.tombstones.remove(&stream_id);
        if tombstone.hidden && !old.as_ref().is_some_and(|old| old.hidden) {
            state.hidden_streams_reaped = state.hidden_streams_reaped.saturating_add(1);
        }
        if let Some(old) = old {
            if old.hidden {
                state.hidden_tombstones = state.hidden_tombstones.saturating_sub(1);
            }
            record_used_marker_locked(state, stream_id, old.data_disposition);
        } else {
            record_used_marker_locked(state, stream_id, tombstone.data_disposition);
        }
        return;
    }
    let old = state.tombstones.insert(stream_id, tombstone);
    if tombstone.hidden && !old.as_ref().is_some_and(|old| old.hidden) {
        state.hidden_streams_reaped = state.hidden_streams_reaped.saturating_add(1);
    }
    match old {
        Some(old) => {
            if old.hidden && !tombstone.hidden {
                state.hidden_tombstones = state.hidden_tombstones.saturating_sub(1);
            } else if !old.hidden && tombstone.hidden {
                state.hidden_tombstones = state.hidden_tombstones.saturating_add(1);
                state.hidden_tombstone_order.push_back(stream_id);
            }
        }
        None => {
            state.tombstone_order.push_back(stream_id);
            if tombstone.hidden {
                state.hidden_tombstones = state.hidden_tombstones.saturating_add(1);
                state.hidden_tombstone_order.push_back(stream_id);
            }
        }
    }
    enforce_hidden_tombstones_locked(state, Instant::now());
    while state.tombstones.len() > state.tombstone_limit {
        let Some(oldest) = pop_oldest_tombstone_id_locked(state) else {
            break;
        };
        remove_tombstone_locked(state, oldest);
    }
    shrink_retention_queues_locked(state);
}

pub(super) fn reap_expired_hidden_tombstones_locked(state: &mut ConnState, now: Instant) {
    let mut removed = false;
    while let Some(stream_id) = oldest_hidden_tombstone_id_locked(state) {
        let Some(tombstone) = state.tombstones.get(&stream_id) else {
            continue;
        };
        if now.saturating_duration_since(tombstone.created_at) <= HIDDEN_CONTROL_RETAINED_MAX_AGE {
            break;
        }
        remove_tombstone_locked(state, stream_id);
        removed = true;
    }
    if removed {
        shrink_retention_queues_locked(state);
    }
}

fn enforce_hidden_tombstones_locked(state: &mut ConnState, now: Instant) {
    reap_expired_hidden_tombstones_locked(state, now);
    while state.hidden_tombstones > state.hidden_tombstone_limit {
        let Some(newest) = newest_hidden_tombstone_id_locked(state) else {
            break;
        };
        remove_tombstone_locked(state, newest);
    }
    shrink_retention_queues_locked(state);
}

pub(super) fn reap_tombstones_for_memory_pressure_locked(
    inner: &Inner,
    state: &mut ConnState,
    writer: &WriterQueueStats,
) {
    let hard_cap = session_memory_hard_cap_locked(inner, state, writer);
    loop {
        let tracked = tracked_session_memory_locked(inner, state, writer);
        if tracked <= hard_cap {
            break;
        }
        let Some(stream_id) = pop_oldest_tombstone_id_locked(state) else {
            break;
        };
        let Some(tombstone) = state.tombstones.get(&stream_id) else {
            continue;
        };
        if !tombstone.hidden && visible_tombstone_count_locked(state) <= 1 {
            state.tombstone_order.push_front(stream_id);
            break;
        }
        remove_tombstone_locked(state, stream_id);
    }
    shrink_retention_queues_locked(state);
}

#[inline]
fn visible_tombstone_count_locked(state: &ConnState) -> usize {
    state
        .tombstones
        .len()
        .saturating_sub(state.hidden_tombstones)
}

fn pop_oldest_tombstone_id_locked(state: &mut ConnState) -> Option<u64> {
    while let Some(stream_id) = state.tombstone_order.pop_front() {
        if state.tombstones.contains_key(&stream_id) {
            return Some(stream_id);
        }
    }
    None
}

fn oldest_hidden_tombstone_id_locked(state: &mut ConnState) -> Option<u64> {
    while let Some(&stream_id) = state.hidden_tombstone_order.front() {
        if state
            .tombstones
            .get(&stream_id)
            .is_some_and(|tombstone| tombstone.hidden)
        {
            return Some(stream_id);
        }
        state.hidden_tombstone_order.pop_front();
    }
    None
}

fn newest_hidden_tombstone_id_locked(state: &mut ConnState) -> Option<u64> {
    while let Some(stream_id) = state.hidden_tombstone_order.pop_back() {
        if state
            .tombstones
            .get(&stream_id)
            .is_some_and(|tombstone| tombstone.hidden)
        {
            return Some(stream_id);
        }
    }
    None
}

fn remove_tombstone_locked(state: &mut ConnState, stream_id: u64) {
    let Some(tombstone) = state.tombstones.remove(&stream_id) else {
        return;
    };
    if tombstone.hidden {
        state.hidden_tombstones = state.hidden_tombstones.saturating_sub(1);
    }
    record_used_marker_locked(state, stream_id, tombstone.data_disposition);
}

pub(super) fn terminal_marker_disposition_locked(
    state: &ConnState,
    stream_id: u64,
) -> Option<super::types::TerminalDataDisposition> {
    if let Some(tombstone) = state.tombstones.get(&stream_id) {
        return Some(tombstone.data_disposition);
    }
    if let Some(disposition) = state.used_markers.get(&stream_id).copied() {
        return Some(disposition);
    }
    marker_range_disposition_locked(state, stream_id)
}

#[inline]
pub(super) fn has_terminal_marker_locked(state: &ConnState, stream_id: u64) -> bool {
    terminal_marker_disposition_locked(state, stream_id).is_some()
}

pub(super) fn record_used_marker_locked(
    state: &mut ConnState,
    stream_id: u64,
    disposition: super::types::TerminalDataDisposition,
) {
    if state.used_marker_range_mode {
        upsert_marker_range_locked(state, stream_id, disposition);
        state.used_markers.remove(&stream_id);
        if state.used_markers.is_empty() {
            state.used_markers.shrink_to_fit();
        }
        enforce_used_marker_limit_locked(state);
        return;
    }
    if state.used_markers.insert(stream_id, disposition).is_none() {
        state.used_marker_order.push_back(stream_id);
    }
    enforce_used_marker_limit_locked(state);
}

#[inline]
pub(super) fn marker_only_retained_count_locked(state: &ConnState) -> usize {
    marker_only_map_count_locked(state).saturating_add(state.used_marker_ranges.len())
}

fn marker_only_map_count_locked(state: &ConnState) -> usize {
    if state.used_markers.is_empty() || state.tombstones.is_empty() {
        return state.used_markers.len();
    }
    let mut count = 0usize;
    for stream_id in state.used_markers.keys() {
        if !state.tombstones.contains_key(stream_id) {
            count += 1;
        }
    }
    count
}

fn enforce_used_marker_limit_locked(state: &mut ConnState) {
    compact_marker_only_ranges_locked(state);
    compact_used_marker_order_locked(state);
}

fn compact_marker_only_ranges_locked(state: &mut ConnState) {
    let marker_count = marker_only_map_count_locked(state);
    if marker_count == 0
        || (marker_count <= state.used_marker_limit
            && marker_count < MARKER_ONLY_RANGE_COMPACT_THRESHOLD)
    {
        return;
    }
    let mut stream_ids = Vec::new();
    if stream_ids.try_reserve(marker_count).is_err() {
        return;
    }
    for stream_id in state.used_markers.keys() {
        if !state.tombstones.contains_key(stream_id) {
            stream_ids.push(*stream_id);
        }
    }
    if stream_ids.is_empty() {
        return;
    }
    stream_ids.sort_unstable();
    for stream_id in stream_ids {
        if let Some(disposition) = state.used_markers.remove(&stream_id) {
            upsert_marker_range_locked(state, stream_id, disposition);
        }
    }
    state.used_marker_range_mode = true;
    compact_used_marker_order_locked(state);
    if state.used_markers.is_empty() {
        state.used_markers.shrink_to_fit();
    }
}

fn compact_used_marker_order_locked(state: &mut ConnState) {
    if state.used_marker_order.is_empty() {
        return;
    }
    state
        .used_marker_order
        .retain(|stream_id| state.used_markers.contains_key(stream_id));
    shrink_retention_queues_locked(state);
}

fn shrink_retention_queues_locked(state: &mut ConnState) {
    if state.tombstone_order.len() > state.tombstones.len() {
        state
            .tombstone_order
            .retain(|stream_id| state.tombstones.contains_key(stream_id));
    }
    if state.hidden_tombstone_order.len() > state.hidden_tombstones {
        state.hidden_tombstone_order.retain(|stream_id| {
            state
                .tombstones
                .get(stream_id)
                .is_some_and(|tombstone| tombstone.hidden)
        });
    }
    if state.used_marker_order.len() > state.used_markers.len() {
        state
            .used_marker_order
            .retain(|stream_id| state.used_markers.contains_key(stream_id));
    }
    shrink_sparse_queue(&mut state.tombstone_order);
    shrink_sparse_queue(&mut state.hidden_tombstone_order);
    shrink_sparse_queue(&mut state.used_marker_order);
    let ranges_sparse = state.used_marker_ranges.capacity() > RETENTION_QUEUE_RETAIN_MIN_CAP
        && state.used_marker_ranges.len().saturating_mul(4) < state.used_marker_ranges.capacity();
    if state.used_marker_ranges.is_empty() || ranges_sparse {
        state.used_marker_ranges.shrink_to_fit();
    }
}

fn shrink_sparse_queue<T>(queue: &mut std::collections::VecDeque<T>) {
    shrink_queue_if_sparse(queue, RETENTION_QUEUE_RETAIN_MIN_CAP, true);
}

#[inline]
fn shrink_queue_if_sparse<T>(
    queue: &mut std::collections::VecDeque<T>,
    retain_min_cap: usize,
    shrink_empty: bool,
) {
    let sparse =
        queue.capacity() > retain_min_cap && queue.len().saturating_mul(4) < queue.capacity();
    if (shrink_empty && queue.is_empty()) || sparse {
        queue.shrink_to_fit();
    }
}

fn marker_range_disposition_locked(
    state: &ConnState,
    stream_id: u64,
) -> Option<super::types::TerminalDataDisposition> {
    let index = first_marker_range_starting_after(&state.used_marker_ranges, stream_id);
    if index == 0 {
        return None;
    }
    let range = state.used_marker_ranges[index - 1];
    if marker_range_contains(range, stream_id) {
        Some(range.disposition)
    } else {
        None
    }
}

fn upsert_marker_range_locked(
    state: &mut ConnState,
    stream_id: u64,
    disposition: super::types::TerminalDataDisposition,
) {
    let index = first_marker_range_starting_after(&state.used_marker_ranges, stream_id);
    if index > 0 && marker_range_contains(state.used_marker_ranges[index - 1], stream_id) {
        set_contained_marker_range_locked(state, index - 1, stream_id, disposition);
        return;
    }
    state.used_marker_ranges.insert(
        index,
        super::types::UsedMarkerRange {
            start: stream_id,
            end: stream_id,
            disposition,
        },
    );
    merge_marker_ranges_around_locked(state, index);
}

fn set_contained_marker_range_locked(
    state: &mut ConnState,
    index: usize,
    stream_id: u64,
    disposition: super::types::TerminalDataDisposition,
) {
    let current = state.used_marker_ranges[index];
    if current.disposition == disposition {
        return;
    }
    state.used_marker_ranges.remove(index);
    let mut insert = index;
    if current.start < stream_id {
        if let Some(end) = stream_id.checked_sub(4) {
            state.used_marker_ranges.insert(
                insert,
                super::types::UsedMarkerRange {
                    start: current.start,
                    end,
                    disposition: current.disposition,
                },
            );
            insert += 1;
        }
    }
    let inserted = insert;
    state.used_marker_ranges.insert(
        insert,
        super::types::UsedMarkerRange {
            start: stream_id,
            end: stream_id,
            disposition,
        },
    );
    insert += 1;
    if stream_id < current.end {
        if let Some(start) = stream_id.checked_add(4) {
            state.used_marker_ranges.insert(
                insert,
                super::types::UsedMarkerRange {
                    start,
                    end: current.end,
                    disposition: current.disposition,
                },
            );
        }
    }
    merge_marker_ranges_around_locked(state, inserted);
}

fn merge_marker_ranges_around_locked(state: &mut ConnState, mut index: usize) {
    while index > 0
        && marker_ranges_mergeable(
            state.used_marker_ranges[index - 1],
            state.used_marker_ranges[index],
        )
    {
        let current = state.used_marker_ranges.remove(index);
        let previous = &mut state.used_marker_ranges[index - 1];
        previous.end = previous.end.max(current.end);
        index -= 1;
    }
    while index + 1 < state.used_marker_ranges.len()
        && marker_ranges_mergeable(
            state.used_marker_ranges[index],
            state.used_marker_ranges[index + 1],
        )
    {
        let next = state.used_marker_ranges.remove(index + 1);
        state.used_marker_ranges[index].end = state.used_marker_ranges[index].end.max(next.end);
    }
}

#[inline]
fn marker_ranges_mergeable(
    left: super::types::UsedMarkerRange,
    right: super::types::UsedMarkerRange,
) -> bool {
    left.disposition == right.disposition
        && left.start % 4 == right.start % 4
        && marker_range_end_reaches(left.end, right.start)
        && marker_range_end_reaches(right.end, left.start)
}

#[inline]
fn marker_range_end_reaches(end: u64, start: u64) -> bool {
    end >= start || end.checked_add(4).is_some_and(|next| next >= start)
}

#[inline]
fn marker_range_contains(range: super::types::UsedMarkerRange, stream_id: u64) -> bool {
    stream_id >= range.start
        && stream_id <= range.end
        && (stream_id - range.start).is_multiple_of(4)
}

#[inline]
fn first_marker_range_starting_after(
    ranges: &[super::types::UsedMarkerRange],
    stream_id: u64,
) -> usize {
    ranges.partition_point(|range| range.start <= stream_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::buffer::RecvBuffer;

    fn stream_state_for_write_check() -> StreamState {
        StreamState {
            recv_buf: RecvBuffer::default(),
            recv_fin: false,
            recv_reset: None,
            aborted: None,
            abort_source: ErrorSource::Unknown,
            read_stopped: false,
            read_stop_pending_code: None,
            read_deadline: None,
            write_deadline: None,
            write_completion: None,
            write_in_progress: false,
            pending_data_frames: 0,
            pending_terminal_frames: 0,
            send_fin: false,
            send_reset: None,
            send_reset_from_stop: false,
            stopped_by_peer: None,
            provisional_created_at: None,
            opened_on_wire: true,
            peer_visible: true,
            received_open: true,
            send_used: 0,
            send_max: 0,
            send_blocked_at: None,
            recv_used: 0,
            recv_advertised: 0,
            recv_pending: 0,
            late_data_received: 0,
            late_data_cap: 0,
            open_prefix: Vec::new(),
            open_info: Vec::new(),
            retained_open_info_bytes: 0,
            metadata: StreamMetadata::default(),
            metadata_revision: 0,
            pending_priority_update: None,
            open_initial_group: None,
            opened_event_sent: false,
            accepted_event_sent: false,
            accept_pending: false,
            accept_seq: 0,
            accept_backlog_bytes: 0,
            active_counted: false,
            visible_churn_counted: false,
            retained_recv_reset_reason_bytes: 0,
            retained_abort_reason_bytes: 0,
            retained_stopped_reason_bytes: 0,
        }
    }

    #[test]
    fn tombstone_late_data_action_ignores_absent_receive_half() {
        assert_eq!(
            terminal_data_action_for(false, false, false, false, false),
            super::super::types::TerminalDataAction::Ignore
        );
    }

    #[test]
    fn tombstone_late_data_action_aborts_after_recv_fin() {
        assert_eq!(
            terminal_data_action_for(true, false, false, false, true),
            super::super::types::TerminalDataAction::Abort(ErrorCode::StreamClosed.as_u64())
        );
    }

    #[test]
    fn tombstone_late_data_action_keeps_local_read_stop_dominant_after_recv_fin() {
        assert_eq!(
            terminal_data_action_for(true, false, false, true, true),
            super::super::types::TerminalDataAction::Ignore
        );
    }

    #[test]
    fn check_write_open_surfaces_peer_stop_before_stop_driven_reset() {
        let mut state = stream_state_for_write_check();
        state.stopped_by_peer = Some((77, "peer stop".to_owned()));
        state.send_reset = Some((ErrorCode::Cancelled.as_u64(), String::new()));
        state.send_reset_from_stop = true;

        let err = check_write_open(&state).unwrap_err();

        assert_eq!(err.numeric_code(), Some(77));
        assert_eq!(err.reason(), Some("peer stop"));
        assert_eq!(err.source(), ErrorSource::Remote);
        assert_eq!(err.termination_kind(), TerminationKind::Stopped);
    }

    #[test]
    fn check_write_open_prefers_queued_graceful_fin_over_peer_stop() {
        let mut state = stream_state_for_write_check();
        state.stopped_by_peer = Some((ErrorCode::Cancelled.as_u64(), "peer stop".to_owned()));
        state.send_fin = true;

        let err = check_write_open(&state).unwrap_err();

        assert_eq!(err.source(), ErrorSource::Local);
        assert_eq!(err.termination_kind(), TerminationKind::Graceful);
    }

    #[test]
    fn provisional_open_max_age_uses_rtt_floor_and_cap() {
        assert_eq!(provisional_open_max_age(None), Duration::from_secs(5));
        assert_eq!(
            provisional_open_max_age(Some(Duration::from_secs(1))),
            Duration::from_secs(6) + Duration::from_millis(250)
        );
        assert_eq!(
            provisional_open_max_age(Some(Duration::from_secs(100))),
            Duration::from_secs(20)
        );
    }

    #[test]
    fn provisional_available_count_matches_open_helper_boundaries() {
        assert_eq!(provisional_available_count(9, 21), 4);
        assert_eq!(provisional_available_count(25, 21), 0);

        let huge_count = (u64::MAX / 4).saturating_add(1);
        let expected = usize::try_from(huge_count).unwrap_or(usize::MAX);
        assert_eq!(provisional_available_count(0, u64::MAX), expected);
    }

    #[test]
    fn provisional_expiration_requires_pending_open_and_old_creation_time() {
        let now = Instant::now();
        let max_age = Duration::from_secs(5);
        let mut state = stream_state_for_write_check();

        state.provisional_created_at = None;
        assert!(!provisional_expired_locked(&state, now, max_age));

        state.provisional_created_at = Some(now - max_age);
        assert!(!provisional_expired_locked(&state, now, max_age));

        state.provisional_created_at = Some(now - max_age - Duration::from_millis(1));
        assert!(provisional_expired_locked(&state, now, max_age));
    }

    #[test]
    fn memory_high_threshold_uses_small_caps_and_three_quarter_boundary() {
        assert_eq!(memory_high_threshold(0), 0);
        assert_eq!(memory_high_threshold(4), 4);
        assert_eq!(memory_high_threshold(8), 6);
        assert_eq!(memory_high_threshold(9), 7);
    }

    #[test]
    fn default_late_data_per_stream_cap_matches_receive_runtime_policy() {
        assert_eq!(
            late_data_per_stream_cap(None, 64 * 1024, 16 * 1024),
            8 * 1024
        );
        assert_eq!(
            late_data_per_stream_cap(None, 1024 * 1024, 16 * 1024),
            32 * 1024
        );
        assert_eq!(late_data_per_stream_cap(None, 0, 16 * 1024), 1024);
    }

    #[test]
    fn compact_retained_bytes_drops_excess_capacity() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(b"ssh");

        let compact = compact_retained_bytes(bytes);

        assert_eq!(compact, b"ssh");
        assert_eq!(compact.capacity(), compact.len());
        assert_eq!(compact_retained_bytes(Vec::with_capacity(64)).capacity(), 0);
    }

    #[test]
    fn truncate_utf8_drops_excess_capacity() {
        let mut reason = String::with_capacity(64);
        reason.push_str("éx");

        let compact = truncate_utf8(reason, 2);

        assert_eq!(compact, "é");
        assert_eq!(compact.capacity(), compact.len());

        let mut untrimmed = String::with_capacity(64);
        untrimmed.push_str("ok");
        let compact = truncate_utf8(untrimmed, 8);
        assert_eq!(compact, "ok");
        assert_eq!(compact.capacity(), compact.len());
        assert_eq!(truncate_utf8(String::from("€x"), 3), "€");
        assert_eq!(truncate_utf8(String::from("€x"), 2), "");
        assert_eq!(truncate_utf8(String::from("abc"), 0).capacity(), 0);
    }

    #[test]
    fn reason_stats_bound_distinct_codes_and_count_overflow() {
        let mut reset = std::collections::HashMap::new();
        let mut reset_overflow = 0;
        let mut abort = std::collections::HashMap::new();
        let mut abort_overflow = 0;
        let overflow = 5;

        for i in 0..MAX_REASON_STATS_CODES + overflow {
            note_reason_locked(
                &mut reset,
                &mut reset_overflow,
                10_000 + u64::try_from(i).unwrap(),
            );
            note_reason_locked(
                &mut abort,
                &mut abort_overflow,
                20_000 + u64::try_from(i).unwrap(),
            );
        }
        note_reason_locked(&mut reset, &mut reset_overflow, 10_000);
        note_reason_locked(&mut abort, &mut abort_overflow, 20_000);

        assert_eq!(reset.len(), MAX_REASON_STATS_CODES);
        assert_eq!(abort.len(), MAX_REASON_STATS_CODES);
        assert_eq!(reset_overflow, u64::try_from(overflow).unwrap());
        assert_eq!(abort_overflow, u64::try_from(overflow).unwrap());
        assert_eq!(reset.get(&10_000), Some(&2));
        assert_eq!(abort.get(&20_000), Some(&2));
    }

    #[test]
    fn reason_stats_snapshots_are_detached_owned_values() {
        let mut reset = std::collections::HashMap::new();
        let mut reset_overflow = 0;
        let mut abort = std::collections::HashMap::new();
        let mut abort_overflow = 0;

        note_reason_locked(&mut reset, &mut reset_overflow, 7);
        note_reason_locked(&mut abort, &mut abort_overflow, 9);

        let first = super::super::types::ReasonStats {
            reset: reset.clone(),
            reset_overflow,
            abort: abort.clone(),
            abort_overflow,
        };
        assert_eq!(first.reset.get(&7), Some(&1));
        assert_eq!(first.abort.get(&9), Some(&1));

        let mut caller_owned = first.clone();
        caller_owned.reset.insert(8, 1);
        caller_owned.abort.insert(10, 1);
        assert_eq!(caller_owned.reset.get(&8), Some(&1));
        assert_eq!(caller_owned.abort.get(&10), Some(&1));

        note_reason_locked(&mut reset, &mut reset_overflow, 7);
        note_reason_locked(&mut abort, &mut abort_overflow, 9);

        assert_eq!(first.reset.get(&7), Some(&1));
        assert_eq!(first.abort.get(&9), Some(&1));
        let second = super::super::types::ReasonStats {
            reset,
            reset_overflow,
            abort,
            abort_overflow,
        };
        assert_eq!(second.reset.get(&7), Some(&2));
        assert_eq!(second.abort.get(&9), Some(&2));
        assert!(!second.reset.contains_key(&8));
        assert!(!second.abort.contains_key(&10));
    }
}
