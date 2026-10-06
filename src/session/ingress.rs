use super::flow::{
    negotiated_frame_payload, next_credit_limit, receive_window_exceeded, receive_window_exhausted,
    replenish_min_pending, session_emergency_threshold, session_standing_growth_allowed,
    session_window_target, should_flush_receive_credit, stream_emergency_threshold,
    stream_standing_growth_allowed, stream_window_target,
};
use super::liveness::{
    canceled_ping_payload_matches, note_matching_pong_locked, pong_payload_for_ping_locked,
    pong_payload_matches_ping, record_inbound_activity_locked,
};
use super::state::{
    account_session_receive_buffered_locked, clear_accept_backlog_entry_locked,
    clear_stream_receive_credit_locked, emit_event, enforce_accept_backlog_bytes_locked,
    enforce_retained_open_info_budget_locked, enforce_session_memory_accept_backlog_locked,
    ensure_session_memory_cap, fail_pending_pings_locked, fail_session, fail_session_with_close,
    has_terminal_marker_locked, late_data_allowance, late_data_cause_for, late_data_per_stream_cap,
    mark_stream_peer_visible_locked, maybe_release_active_count, note_abort_reason_locked,
    note_written_stream_frames_locked, queue_peer_visible_pending_priority,
    reap_expired_hidden_tombstones_locked, reclaim_provisionals_after_go_away,
    reclaim_unseen_local_streams_after_go_away, record_tombstone_locked,
    refresh_accept_backlog_bytes_locked, release_discarded_queued_stream_frames_locked,
    release_local_opener_turn, release_peer_reason_locked, release_session_receive_buffered_locked,
    release_session_runtime_state_locked, remove_accept_queue_entry_locked,
    retain_peer_go_away_error_locked, retain_peer_reason_locked, retain_stream_abort_reason_locked,
    retain_stream_open_info_locked, retain_stream_recv_reset_reason_locked,
    retain_stream_stopped_reason_locked, session_memory_pressure_high_fast_locked,
    stream_fully_terminal, take_session_closed_event_locked, terminal_marker_disposition_locked,
    PeerVisibleUpdate,
};
use super::types::*;
use crate::error::{Error, ErrorCode, ErrorOperation, ErrorSource, Result};
use crate::frame::{
    read_session_frame, Frame, FrameType, Limits, FRAME_FLAG_FIN, FRAME_FLAG_OPEN_METADATA,
};
use crate::payload::{
    build_code_payload, malformed_payload_error, normalize_stream_group,
    parse_data_payload_app_offset, parse_data_payload_metadata_offset, parse_inbound_error_payload,
    parse_inbound_go_away_payload, parse_priority_update_metadata, StreamMetadata,
};
use crate::protocol::{
    capabilities_can_carry_group_in_update, capabilities_can_carry_group_on_open,
    capabilities_can_carry_priority_in_update, capabilities_can_carry_priority_on_open,
    CAPABILITY_OPEN_METADATA, CAPABILITY_PRIORITY_UPDATE, CAPABILITY_STREAM_GROUPS,
    EXT_PRIORITY_UPDATE,
};
use crate::settings::SchedulerHint;
use crate::stream_id::{
    initial_receive_window, initial_send_window, stream_is_bidi, stream_is_local,
    validate_go_away_watermark_creator, validate_go_away_watermark_for_direction,
};
use crate::varint::{append_varint_reserved, parse_varint, MAX_VARINT62};
use std::io::Read;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const PING_TOKEN_BYTES: usize = 8;

pub(super) fn spawn_reader<R>(inner: Arc<Inner>, mut reader: R)
where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let limits = Limits {
            max_frame_payload: inner.local_preface.settings.max_frame_payload,
            max_control_payload_bytes: inner.local_preface.settings.max_control_payload_bytes,
            max_extension_payload_bytes: inner.local_preface.settings.max_extension_payload_bytes,
        };
        loop {
            match read_session_frame(&mut reader, limits) {
                Ok(frame) => {
                    if let Err(err) = handle_frame(&inner, frame) {
                        let err = mark_inbound_error_source(err);
                        let close_frame = session_close_frame_for(&inner, &err);
                        fail_session_with_close(&inner, err, close_frame);
                        break;
                    }
                }
                Err(err) => {
                    if complete_local_close_after_peer_read_error(&inner, &err) {
                        break;
                    }
                    if should_ignore_peer_non_close_read_error(&inner) {
                        break;
                    }
                    let err = mark_inbound_error_source(err);
                    if err.source_io_error_kind().is_some() {
                        // The transport itself failed; there is nothing to
                        // signal the peer through.
                        fail_session(&inner, err);
                    } else {
                        // Envelope violations found while reading the frame
                        // (size limits, flags, scope, unknown type, header
                        // varints) are session errors that SPEC §4.3/§10.2
                        // signal with CLOSE before the transport is closed,
                        // exactly like errors found by the frame handlers.
                        let close_frame = session_close_frame_for(&inner, &err);
                        fail_session_with_close(&inner, err, close_frame);
                    }
                    break;
                }
            }
        }
    });
}

fn session_close_frame_for(inner: &Inner, err: &Error) -> Frame {
    let code = match err.code() {
        Some(code) => code,
        // Local failures without a wire code (for example allocation
        // failures) are internal errors, not peer protocol violations.
        None if err.source() == ErrorSource::Local => ErrorCode::Internal,
        None => ErrorCode::Protocol,
    };
    Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: build_code_payload(
            code.as_u64(),
            &err.to_string(),
            inner.peer_preface.settings.max_control_payload_bytes,
        )
        .unwrap_or_default(),
    }
}

fn complete_local_close_after_peer_read_error(inner: &Arc<Inner>, err: &Error) -> bool {
    if !is_transport_close_error(err) {
        return false;
    }
    let close_event = {
        let mut state = inner.state.lock().unwrap();
        if state.state != SessionState::Closing && !state.graceful_close_active {
            return false;
        }
        state.state = SessionState::Closed;
        state.graceful_close_active = false;
        state.close_error = None;
        state.peer_close_error = None;
        state.scheduler.clear();
        fail_pending_pings_locked(&mut state, Error::session_closed());
        release_session_runtime_state_locked(&mut state);
        let event = take_session_closed_event_locked(inner, &mut state);
        drop(state);
        inner.cond.notify_all();
        event
    };
    inner.shutdown_writer();
    emit_event(inner, close_event);
    true
}

#[inline]
fn is_transport_close_error(err: &Error) -> bool {
    matches!(
        err.source_io_error_kind(),
        Some(
            std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
        )
    )
}

#[inline]
fn mark_inbound_error_source(err: Error) -> Error {
    if err.source() != ErrorSource::Unknown || err.source_io_error_kind().is_some() {
        return err;
    }
    match err.code() {
        Some(ErrorCode::Internal) => err,
        _ => err.with_source(ErrorSource::Remote),
    }
}

fn handle_frame(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let received_at = Instant::now();
    let frame_type = frame.frame_type;
    if frame.frame_type != FrameType::Close {
        let mut state = inner.state.lock().unwrap();
        state.received_frames = state.received_frames.saturating_add(1);
        record_inbound_activity_locked(inner, &mut state, received_at);
        inner.cond.notify_all();
        if ignore_peer_non_close_locked(&state) {
            return Ok(());
        }
        reap_expired_hidden_tombstones_locked(&mut state, received_at);
        record_inbound_rate_budget_locked(
            &mut state,
            frame.frame_type,
            frame.payload.len(),
            received_at,
        )?;
    }
    match frame.frame_type {
        FrameType::Data => handle_data(inner, frame),
        FrameType::MaxData => handle_max_data(inner, frame),
        FrameType::Blocked => handle_blocked(inner, frame),
        FrameType::StopSending => handle_stop_sending(inner, frame),
        FrameType::Reset => handle_reset(inner, frame),
        FrameType::Abort => handle_abort(inner, frame),
        FrameType::Ping => handle_ping(inner, frame),
        FrameType::Pong => handle_pong(inner, frame),
        FrameType::GoAway => handle_go_away(inner, frame),
        FrameType::Close => {
            {
                let mut state = inner.state.lock().unwrap();
                state.received_frames = state.received_frames.saturating_add(1);
                record_inbound_activity_locked(inner, &mut state, received_at);
                if matches!(state.state, SessionState::Closed | SessionState::Failed) {
                    return Ok(());
                }
                reap_expired_hidden_tombstones_locked(&mut state, received_at);
                record_inbound_rate_budget_locked(
                    &mut state,
                    frame.frame_type,
                    frame.payload.len(),
                    received_at,
                )?;
            }
            let (code, reason) = match parse_inbound_error_payload(&frame.payload) {
                Ok(parsed) => parsed,
                Err(err) => {
                    let state = inner.state.lock().unwrap();
                    if matches!(state.state, SessionState::Closed | SessionState::Failed) {
                        return Ok(());
                    }
                    return Err(err);
                }
            };
            let close_event = {
                let mut state = inner.state.lock().unwrap();
                if matches!(state.state, SessionState::Closed | SessionState::Failed) {
                    return Ok(());
                }
                let no_error = code == 0;
                state.state = if no_error {
                    SessionState::Closed
                } else {
                    SessionState::Failed
                };
                state.graceful_close_active = false;
                if let Some(old) = state.peer_close_error.take() {
                    release_peer_reason_locked(&mut state, old.reason.len());
                }
                let retained_reason = if no_error {
                    String::new()
                } else {
                    let (retained, _) = retain_peer_reason_locked(inner, &mut state, reason);
                    retained
                };
                state.peer_close_error = if no_error {
                    None
                } else {
                    Some(PeerCloseError {
                        code,
                        reason: retained_reason.clone(),
                    })
                };
                state.close_error = if no_error {
                    None
                } else {
                    Some(
                        Error::application(code, retained_reason)
                            .with_source(ErrorSource::Remote)
                            .with_session_context(ErrorOperation::Close),
                    )
                };
                state.scheduler.clear();
                let ping_err = state
                    .close_error
                    .clone()
                    .unwrap_or_else(Error::session_closed);
                fail_pending_pings_locked(&mut state, ping_err);
                release_session_runtime_state_locked(&mut state);
                inner.cond.notify_all();
                take_session_closed_event_locked(inner, &mut state)
            };
            inner.shutdown_writer();
            emit_event(inner, close_event);
            Ok(())
        }
        FrameType::Ext => handle_ext(inner, frame),
    }?;
    if frame_type != FrameType::Close {
        ensure_session_memory_cap(inner, "handle frame")?;
    }
    Ok(())
}

#[inline]
fn ignore_peer_non_close_locked(state: &ConnState) -> bool {
    state.ignore_peer_non_close
        || matches!(state.state, SessionState::Closed | SessionState::Failed)
}

#[inline]
fn ignore_session_control_while_closing_locked(state: &ConnState) -> bool {
    ignore_peer_non_close_locked(state) || state.state == SessionState::Closing
}

fn should_ignore_peer_non_close_read_error(inner: &Arc<Inner>) -> bool {
    let state = inner.state.lock().unwrap();
    matches!(state.state, SessionState::Closed | SessionState::Failed)
}

fn maybe_ignore_peer_non_close_error(inner: &Arc<Inner>, err: Error) -> Result<()> {
    let state = inner.state.lock().unwrap();
    if ignore_peer_non_close_locked(&state) {
        Ok(())
    } else {
        Err(err)
    }
}

fn record_inbound_rate_budget_locked(
    state: &mut ConnState,
    frame_type: FrameType,
    payload_len: usize,
    now: Instant,
) -> Result<()> {
    match frame_type {
        FrameType::Data => Ok(()),
        // Flow-control frames that advance state (a MAX_DATA raising a limit, a
        // BLOCKED answered with credit) are mandatory progress, not abuse; their
        // handlers charge the control budgets only when they turn out to be no-ops.
        FrameType::MaxData | FrameType::Blocked => Ok(()),
        FrameType::Ext => {
            record_traffic_budget_locked(
                TrafficBudgetCounters {
                    window_start: &mut state.inbound_ext_window_start,
                    frames: &mut state.inbound_ext_frames,
                    bytes: &mut state.inbound_ext_bytes,
                },
                TrafficBudgetPolicy {
                    abuse_window: state.abuse_window,
                    frame_budget: state.inbound_ext_frame_budget,
                    byte_budget: state.inbound_ext_bytes_budget,
                    message: "high-rate inbound EXT flood exceeded local threshold",
                },
                payload_len,
                now,
            )?;
            record_traffic_budget_locked(
                TrafficBudgetCounters {
                    window_start: &mut state.inbound_mixed_window_start,
                    frames: &mut state.inbound_mixed_frames,
                    bytes: &mut state.inbound_mixed_bytes,
                },
                TrafficBudgetPolicy {
                    abuse_window: state.abuse_window,
                    frame_budget: state.inbound_mixed_frame_budget,
                    byte_budget: state.inbound_mixed_bytes_budget,
                    message: "high-rate inbound mixed control/EXT flood exceeded local threshold",
                },
                payload_len,
                now,
            )
        }
        _ => record_inbound_control_rate_locked(state, payload_len, now),
    }
}

fn record_inbound_control_rate_locked(
    state: &mut ConnState,
    payload_len: usize,
    now: Instant,
) -> Result<()> {
    record_traffic_budget_locked(
        TrafficBudgetCounters {
            window_start: &mut state.inbound_control_window_start,
            frames: &mut state.inbound_control_frames,
            bytes: &mut state.inbound_control_bytes,
        },
        TrafficBudgetPolicy {
            abuse_window: state.abuse_window,
            frame_budget: state.inbound_control_frame_budget,
            byte_budget: state.inbound_control_bytes_budget,
            message: "high-rate inbound control flood exceeded local threshold",
        },
        payload_len,
        now,
    )?;
    record_traffic_budget_locked(
        TrafficBudgetCounters {
            window_start: &mut state.inbound_mixed_window_start,
            frames: &mut state.inbound_mixed_frames,
            bytes: &mut state.inbound_mixed_bytes,
        },
        TrafficBudgetPolicy {
            abuse_window: state.abuse_window,
            frame_budget: state.inbound_mixed_frame_budget,
            byte_budget: state.inbound_mixed_bytes_budget,
            message: "high-rate inbound mixed control/EXT flood exceeded local threshold",
        },
        payload_len,
        now,
    )
}

/// Charges a MAX_DATA or BLOCKED that did not advance flow-control state to the
/// inbound control/mixed rate budgets (state-advancing ones are exempt).
#[inline]
fn record_inert_flow_control_frame_locked(state: &mut ConnState, payload_len: usize) -> Result<()> {
    record_inbound_control_rate_locked(state, payload_len, Instant::now())
}

struct TrafficBudgetCounters<'a> {
    window_start: &'a mut Option<Instant>,
    frames: &'a mut u64,
    bytes: &'a mut usize,
}

struct TrafficBudgetPolicy {
    abuse_window: Duration,
    frame_budget: u64,
    byte_budget: usize,
    message: &'static str,
}

fn record_traffic_budget_locked(
    counters: TrafficBudgetCounters<'_>,
    policy: TrafficBudgetPolicy,
    payload_len: usize,
    now: Instant,
) -> Result<()> {
    if counters
        .window_start
        .is_none_or(|start| now.saturating_duration_since(start) > policy.abuse_window)
    {
        *counters.window_start = Some(now);
        *counters.frames = 0;
        *counters.bytes = 0;
    }
    *counters.frames = (*counters.frames).saturating_add(1);
    *counters.bytes = (*counters.bytes).saturating_add(payload_len);
    if *counters.frames <= policy.frame_budget && *counters.bytes <= policy.byte_budget {
        Ok(())
    } else {
        Err(Error::protocol(policy.message))
    }
}

fn record_group_rebucket_churn_locked(state: &mut ConnState) -> Result<()> {
    let (start, count, result) = advance_windowed_count(
        state.abuse_window,
        state.group_rebucket_churn_window_start,
        state.group_rebucket_churn_count,
        state.group_rebucket_churn_budget,
        "high-rate effective stream_group rebucketing churn exceeded local threshold",
    );
    state.group_rebucket_churn_window_start = start;
    state.group_rebucket_churn_count = count;
    result
}

fn record_hidden_abort_churn_locked(state: &mut ConnState) -> Result<()> {
    let (start, count, result) = advance_windowed_count(
        state.hidden_abort_churn_window,
        state.hidden_abort_churn_window_start,
        state.hidden_abort_churn_count,
        state.hidden_abort_churn_budget,
        "rapid hidden open-then-abort churn exceeded local threshold",
    );
    state.hidden_abort_churn_window_start = start;
    state.hidden_abort_churn_count = count;
    result
}

fn record_visible_terminal_churn_locked(
    state: &mut ConnState,
    stream: &StreamInner,
    stream_state: &mut StreamState,
) -> Result<()> {
    if stream.opened_locally
        || !stream.application_visible
        || !stream_state.accept_pending
        || stream_state.visible_churn_counted
        || !stream_fully_terminal(stream, stream_state)
    {
        return Ok(());
    }
    stream_state.visible_churn_counted = true;
    let (start, count, result) = advance_windowed_count(
        state.visible_terminal_churn_window,
        state.visible_terminal_churn_window_start,
        state.visible_terminal_churn_count,
        state.visible_terminal_churn_budget,
        "rapid open-then-reset/abort churn exceeded local threshold",
    );
    state.visible_terminal_churn_window_start = start;
    state.visible_terminal_churn_count = count;
    result
}

fn finish_peer_visible_update(
    inner: &Arc<Inner>,
    stream_id: u64,
    update: Option<PeerVisibleUpdate>,
) {
    let Some(update) = update else {
        return;
    };
    release_local_opener_turn(inner, stream_id);
    if let Some(payload) = update.pending_priority {
        queue_peer_visible_pending_priority(inner, stream_id, payload);
    }
    emit_event(inner, update.event);
}

fn handle_data(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let stream_id = frame.stream_id;
    let flags = frame.flags;
    let payload = frame.payload;
    let has_open_metadata = flags & FRAME_FLAG_OPEN_METADATA != 0;
    if has_open_metadata
        && refuse_opening_data_past_go_away_before_metadata_parse(inner, stream_id, &payload)?
    {
        return Ok(());
    }
    if has_open_metadata && inner.negotiated.capabilities & CAPABILITY_OPEN_METADATA == 0 {
        return maybe_ignore_peer_non_close_error(
            inner,
            Error::protocol("DATA|OPEN_METADATA is not negotiated"),
        );
    }
    if has_open_metadata && ignore_or_reject_misplaced_open_metadata_before_parse(inner, stream_id)?
    {
        return Ok(());
    }
    let (metadata, app_offset) = if has_open_metadata {
        match parse_data_payload_metadata_offset(&payload, flags) {
            Ok((metadata, true, app_offset)) => (Some(metadata), app_offset),
            Ok((_, false, app_offset)) => (None, app_offset),
            Err(err) => return maybe_ignore_peer_non_close_error(inner, err),
        }
    } else {
        (None, 0)
    };
    let app_len = usize_to_u64_saturating(payload.len() - app_offset);
    let (stream, refused_accept_ids, peer_visible_update) = {
        let mut state = inner.state.lock().unwrap();
        if ignore_peer_non_close_locked(&state) {
            return Ok(());
        }
        let mut refused_accepts = Vec::new();
        let (stream, stream_existed) = if let Some(stream) = state.streams.get(&stream_id) {
            (Arc::clone(stream), true)
        } else if known_absent_stream_locked(&state, inner, stream_id) {
            if has_open_metadata {
                return Err(Error::protocol(
                    "OPEN_METADATA is valid only on the first DATA",
                ));
            }
            handle_absent_terminal_data_locked(
                inner,
                &mut state,
                stream_id,
                usize_to_u64_saturating(payload.len()),
            )?;
            return Ok(());
        } else {
            let Some(stream) = create_peer_stream(inner, &mut state, stream_id, true, app_len)?
            else {
                // A refused opener's application bytes were charged by the
                // sender, so they are checked, counted and released at the
                // session level (SPEC §8); they are not late data.
                discard_rejected_stream_data_locked(inner, &mut state, app_len)?;
                return Ok(());
            };
            (stream, false)
        };
        if has_open_metadata && stream_existed {
            return Err(Error::protocol(
                "OPEN_METADATA is valid only on the first DATA",
            ));
        }
        let app_chunk = if app_len == 0 {
            None
        } else {
            Some((payload, app_offset))
        };
        let peer_visible_update;
        let mut retained_bytes = 0usize;
        {
            let mut ss = stream.state.lock().unwrap();
            if !stream.local_recv && ss.aborted.is_none() {
                discard_rejected_stream_data_locked(inner, &mut state, app_len)?;
                abort_stream_for_peer_violation_locked(
                    inner,
                    &mut state,
                    &stream,
                    &mut ss,
                    ErrorCode::StreamState.as_u64(),
                    "",
                )?;
                return Ok(());
            }
            if ss.recv_fin && ss.recv_reset.is_none() && ss.aborted.is_none() {
                // DATA after an observed peer FIN is a stream-state violation
                // (SPEC §9.2/§9.6) even after a local read-stop and even when the
                // stream is already fully terminal but not yet compacted.
                peer_visible_update =
                    mark_stream_peer_visible_locked(inner, &stream, &mut ss, state.state);
                discard_rejected_stream_data_locked(inner, &mut state, app_len)?;
                abort_stream_for_peer_violation_locked(
                    inner,
                    &mut state,
                    &stream,
                    &mut ss,
                    ErrorCode::StreamClosed.as_u64(),
                    "",
                )?;
                drop(ss);
                drop(state);
                finish_peer_visible_update(inner, stream_id, peer_visible_update);
                return Ok(());
            }
            if !stream.local_recv
                || ss.recv_reset.is_some()
                || ss.aborted.is_some()
                || ss.read_stopped
            {
                if has_open_metadata {
                    return Err(Error::protocol(
                        "OPEN_METADATA is valid only on the first DATA",
                    ));
                }
                if ss.read_stopped
                    && ss.recv_reset.is_none()
                    && ss.aborted.is_none()
                    && receive_window_exceeded(ss.recv_used, ss.recv_advertised, app_len)
                {
                    // A read-stopped direction still enforces stream credit
                    // (SPEC §8): a compliant peer's in-flight tail never exceeds
                    // the credit it was granted before STOP_SENDING.
                    discard_rejected_stream_data_locked(inner, &mut state, app_len)?;
                    abort_stream_for_peer_violation_locked(
                        inner,
                        &mut state,
                        &stream,
                        &mut ss,
                        ErrorCode::FlowControl.as_u64(),
                        "",
                    )?;
                    return Ok(());
                }
                let stopped_fin = ss.read_stopped && flags & FRAME_FLAG_FIN != 0;
                let cause = late_data_cause_for(&ss);
                peer_visible_update =
                    mark_stream_peer_visible_locked(inner, &stream, &mut ss, state.state);
                discard_peer_data_locked(
                    inner,
                    &mut state,
                    &mut ss,
                    app_len,
                    cause,
                    !stream.application_visible,
                )?;
                clear_stream_receive_credit_locked(inner, &stream, &mut ss);
                if stopped_fin {
                    ss.recv_fin = true;
                    maybe_release_active_count(&mut state, &stream, &mut ss);
                }
                drop(ss);
                drop(state);
                finish_peer_visible_update(inner, stream_id, peer_visible_update);
                return Ok(());
            }
            if receive_window_exceeded(
                state.recv_session_used,
                state.recv_session_advertised,
                app_len,
            ) {
                return Err(Error::flow_control("session MAX_DATA exceeded"));
            }
            if ss.recv_used.saturating_add(app_len) > ss.recv_advertised {
                discard_rejected_stream_data_locked(inner, &mut state, app_len)?;
                abort_stream_for_peer_violation_locked(
                    inner,
                    &mut state,
                    &stream,
                    &mut ss,
                    ErrorCode::FlowControl.as_u64(),
                    "",
                )?;
                return Ok(());
            }
            update_no_op_zero_data_locked(&mut state, stream_existed, app_len, flags)?;
            peer_visible_update =
                mark_stream_peer_visible_locked(inner, &stream, &mut ss, state.state);
            ss.received_open = true;
            if let Some(metadata) = metadata {
                let before = ss.metadata.clone();
                let caps = inner.negotiated.capabilities;
                let StreamMetadata {
                    priority,
                    group,
                    open_info,
                } = metadata;
                if !open_info.is_empty() {
                    retain_stream_open_info_locked(&mut state, &mut ss, open_info);
                }
                if priority.is_some() && capabilities_can_carry_priority_on_open(caps) {
                    ss.metadata.priority = priority;
                }
                if group.is_some() && capabilities_can_carry_group_on_open(caps) {
                    ss.metadata.group = normalize_stream_group(group);
                }
                if ss.metadata != before {
                    ss.metadata_revision = ss.metadata_revision.wrapping_add(1);
                }
            }
            ss.recv_used = ss.recv_used.saturating_add(app_len);
            if let Some((app_chunk, offset)) = app_chunk {
                retained_bytes = ss.recv_buf.push_chunk_with_offset(app_chunk, offset);
            }
            if flags & FRAME_FLAG_FIN != 0 {
                ss.recv_fin = true;
                clear_stream_receive_credit_locked(inner, &stream, &mut ss);
                maybe_release_active_count(&mut state, &stream, &mut ss);
            }
            refresh_accept_backlog_bytes_locked(&mut state, &mut ss);
        }
        state.recv_session_used = state.recv_session_used.saturating_add(app_len);
        state.received_data_bytes = state.received_data_bytes.saturating_add(app_len);
        account_session_receive_buffered_locked(&mut state, app_len, retained_bytes);
        refused_accepts.extend(enforce_accept_backlog_bytes_locked(&mut state));
        refused_accepts.extend(enforce_retained_open_info_budget_locked(&mut state));
        refused_accepts.extend(enforce_session_memory_accept_backlog_locked(
            inner, &mut state,
        ));
        let mut released_refused = 0u64;
        let mut released_refused_retained = 0usize;
        for (_, released, retained) in &refused_accepts {
            released_refused = released_refused.saturating_add(*released);
            released_refused_retained = released_refused_retained.saturating_add(*retained);
        }
        replenish_buffered_session_credit_locked(
            inner,
            &mut state,
            released_refused,
            released_refused_retained,
        )?;
        (stream, refused_accepts, peer_visible_update)
    };
    finish_peer_visible_update(inner, stream_id, peer_visible_update);
    for (stream_id, _, _) in refused_accept_ids {
        queue_abort(inner, stream_id, ErrorCode::RefusedStream.as_u64(), "")?;
    }
    stream.cond.notify_all();
    inner.cond.notify_all();
    Ok(())
}

fn ignore_or_reject_misplaced_open_metadata_before_parse(
    inner: &Arc<Inner>,
    stream_id: u64,
) -> Result<bool> {
    let state = inner.state.lock().unwrap();
    if ignore_peer_non_close_locked(&state) {
        return Ok(true);
    }
    if stream_is_local(inner.negotiated.local_role, stream_id)
        || state.streams.contains_key(&stream_id)
        || known_absent_stream_locked(&state, inner, stream_id)
    {
        return Err(Error::protocol(
            "OPEN_METADATA is valid only on the first DATA",
        ));
    }
    Ok(false)
}

fn refuse_opening_data_past_go_away_before_metadata_parse(
    inner: &Arc<Inner>,
    stream_id: u64,
    payload: &[u8],
) -> Result<bool> {
    let mut state = inner.state.lock().unwrap();
    if ignore_peer_non_close_locked(&state) {
        return Ok(true);
    }
    if state.streams.contains_key(&stream_id)
        || known_absent_stream_locked(&state, inner, stream_id)
        || !refused_by_local_go_away_locked(&state, inner, stream_id)
    {
        return Ok(false);
    }
    // Only the trailing application bytes count against the session window, so
    // decode just the metadata_len prefix; the refused opener's metadata TLVs
    // are never interpreted (SPEC §3.1, §8).
    let app_offset = match parse_data_payload_app_offset(payload, FRAME_FLAG_OPEN_METADATA) {
        Ok(app_offset) => app_offset,
        Err(err) => {
            drop(state);
            return maybe_ignore_peer_non_close_error(inner, err).map(|()| true);
        }
    };
    discard_rejected_stream_data_locked(
        inner,
        &mut state,
        usize_to_u64_saturating(payload.len() - app_offset),
    )?;
    refuse_peer_open_past_local_go_away_locked(inner, &mut state, stream_id)?;
    Ok(true)
}

/// A peer-owned ID above the current local GOAWAY watermark of its class, with
/// no stream state or terminal bookkeeping, can never be opened again in this
/// session because watermarks are non-increasing. It is not consumed, but it is
/// known-absent and refused rather than previously unseen (SPEC §3.1). Callers
/// check live streams and `known_absent_stream_locked` first.
#[inline]
fn refused_by_local_go_away_locked(state: &ConnState, inner: &Arc<Inner>, stream_id: u64) -> bool {
    let goaway = if stream_is_bidi(stream_id) {
        state.local_go_away_bidi
    } else {
        state.local_go_away_uni
    };
    !stream_is_local(inner.negotiated.local_role, stream_id) && stream_id > goaway
}

/// Whether `stream_id` was already answered with ABORT(REFUSED_STREAM) under the
/// local GOAWAY watermark. Peers open the IDs of one class in increasing order,
/// so the highest refused ID per class is enough to answer each ID once.
#[inline]
fn peer_open_already_refused_locked(state: &ConnState, inner: &Arc<Inner>, stream_id: u64) -> bool {
    let highest = if stream_is_bidi(stream_id) {
        state.highest_refused_peer_bidi
    } else {
        state.highest_refused_peer_uni
    };
    stream_id <= highest && refused_by_local_go_away_locked(state, inner, stream_id)
}

/// Non-opening frames on a known-absent ID, including one refused under the
/// local GOAWAY watermark, are ignored rather than treated as frames on a
/// previously unseen stream.
#[inline]
fn known_absent_or_refused_stream_locked(
    state: &ConnState,
    inner: &Arc<Inner>,
    stream_id: u64,
) -> bool {
    known_absent_stream_locked(state, inner, stream_id)
        || refused_by_local_go_away_locked(state, inner, stream_id)
}

/// Refuses a peer open above the local GOAWAY watermark without consuming the
/// ID. Only the first refusal of an ID queues ABORT(REFUSED_STREAM); later frames
/// on it are discarded or ignored by the caller. Returns whether this was the
/// first refusal.
fn refuse_peer_open_past_local_go_away_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    stream_id: u64,
) -> Result<bool> {
    let highest = if stream_is_bidi(stream_id) {
        &mut state.highest_refused_peer_bidi
    } else {
        &mut state.highest_refused_peer_uni
    };
    if stream_id <= *highest {
        return Ok(false);
    }
    *highest = stream_id;
    note_abort_reason_locked(state, ErrorCode::RefusedStream.as_u64());
    queue_abort(inner, stream_id, ErrorCode::RefusedStream.as_u64(), "")?;
    Ok(true)
}

fn handle_absent_terminal_data_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    stream_id: u64,
    app_len: u64,
) -> Result<bool> {
    let disposition =
        if let Some(disposition) = terminal_marker_disposition_locked(state, stream_id) {
            disposition
        } else if stream_id_previously_used(state, inner, stream_id) {
            marker_data_disposition(inner, stream_id)
        } else {
            return Ok(false);
        };
    discard_absent_peer_data_locked(inner, state, stream_id, app_len, disposition.cause)?;
    if let TerminalDataAction::Abort(code) = disposition.action {
        queue_abort(inner, stream_id, code, "")?;
    }
    Ok(true)
}

fn record_ignored_control_locked(state: &mut ConnState) -> Result<()> {
    let (start, count, result) = advance_windowed_count(
        state.abuse_window,
        state.ignored_control_window_start,
        state.ignored_control_count,
        state.ignored_control_budget,
        "ignored control budget exceeded",
    );
    state.ignored_control_window_start = start;
    state.ignored_control_count = count;
    result
}

fn clear_ignored_control_budget_locked(state: &mut ConnState) {
    state.ignored_control_window_start = None;
    state.ignored_control_count = 0;
}

fn record_no_op_max_data_locked(state: &mut ConnState, payload_len: usize) -> Result<()> {
    record_inert_flow_control_frame_locked(state, payload_len)?;
    record_ignored_control_locked(state)?;
    let (start, count, result) = advance_windowed_count(
        state.abuse_window,
        state.no_op_max_data_window_start,
        state.no_op_max_data_count,
        state.no_op_max_data_budget,
        "no-op MAX_DATA budget exceeded",
    );
    state.no_op_max_data_window_start = start;
    state.no_op_max_data_count = count;
    result
}

fn clear_no_op_max_data_budget_locked(state: &mut ConnState) {
    clear_no_op_control_budgets_locked(state);
}

fn record_no_op_blocked_locked(state: &mut ConnState, payload_len: usize) -> Result<()> {
    record_inert_flow_control_frame_locked(state, payload_len)?;
    record_ignored_control_locked(state)?;
    let (start, count, result) = advance_windowed_count(
        state.abuse_window,
        state.no_op_blocked_window_start,
        state.no_op_blocked_count,
        state.no_op_blocked_budget,
        "no-op BLOCKED budget exceeded",
    );
    state.no_op_blocked_window_start = start;
    state.no_op_blocked_count = count;
    result
}

fn clear_no_op_blocked_budget_locked(state: &mut ConnState) {
    clear_no_op_control_budgets_locked(state);
}

fn record_no_op_priority_update_locked(state: &mut ConnState) -> Result<()> {
    record_ignored_control_locked(state)?;
    let (start, count, result) = advance_windowed_count(
        state.abuse_window,
        state.no_op_priority_update_window_start,
        state.no_op_priority_update_count,
        state.no_op_priority_update_budget,
        "no-op PRIORITY_UPDATE budget exceeded",
    );
    state.no_op_priority_update_window_start = start;
    state.no_op_priority_update_count = count;
    result
}

#[inline]
fn record_dropped_priority_update_locked(state: &mut ConnState) {
    state.dropped_priority_update_count = state.dropped_priority_update_count.saturating_add(1);
}

#[inline]
fn clear_no_op_priority_update_budget_locked(state: &mut ConnState) {
    clear_no_op_control_budgets_locked(state);
}

#[inline]
fn clear_no_op_control_budgets_locked(state: &mut ConnState) {
    clear_ignored_control_budget_locked(state);
    state.no_op_max_data_window_start = None;
    state.no_op_max_data_count = 0;
    state.no_op_blocked_window_start = None;
    state.no_op_blocked_count = 0;
    state.no_op_priority_update_window_start = None;
    state.no_op_priority_update_count = 0;
}

fn record_inbound_ping_locked(state: &mut ConnState) -> Result<()> {
    let (start, count, result) = advance_windowed_count(
        state.abuse_window,
        state.inbound_ping_window_start,
        state.inbound_ping_count,
        state.inbound_ping_budget,
        "inbound PING budget exceeded",
    );
    state.inbound_ping_window_start = start;
    state.inbound_ping_count = count;
    result
}

fn update_no_op_zero_data_locked(
    state: &mut ConnState,
    stream_existed: bool,
    app_len: u64,
    flags: u8,
) -> Result<()> {
    let data_control_flags = flags & (FRAME_FLAG_FIN | FRAME_FLAG_OPEN_METADATA);
    let no_op = stream_existed && app_len == 0 && data_control_flags == 0;
    if no_op {
        let (start, count, result) = advance_windowed_count(
            state.abuse_window,
            state.no_op_zero_data_window_start,
            state.no_op_zero_data_count,
            state.no_op_zero_data_budget,
            "zero-length DATA budget exceeded",
        );
        state.no_op_zero_data_window_start = start;
        state.no_op_zero_data_count = count;
        result?;
    } else if app_len > 0 || data_control_flags != 0 {
        // Progress clears only the zero-length DATA budget; the inbound PING
        // budget is a rate limit that expires with its window, not on DATA.
        state.no_op_zero_data_window_start = None;
        state.no_op_zero_data_count = 0;
    }
    Ok(())
}

fn advance_windowed_count(
    abuse_window: Duration,
    window_start: Option<Instant>,
    count: u64,
    budget: u64,
    message: &'static str,
) -> (Option<Instant>, u64, Result<()>) {
    let now = Instant::now();
    let mut start = window_start;
    let mut next_count = count;
    if start.is_none_or(|start| now.saturating_duration_since(start) > abuse_window) {
        start = Some(now);
        next_count = 0;
    }
    next_count = next_count.saturating_add(1);
    let result = if next_count <= budget {
        Ok(())
    } else {
        Err(Error::protocol(message))
    };
    (start, next_count, result)
}

/// Discards late DATA on a live stream whose receive direction no longer
/// accepts data (local read-stop, local or peer ABORT, peer RESET).
fn discard_peer_data_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    stream_state: &mut StreamState,
    app_len: u64,
    cause: LateDataCause,
    hidden: bool,
) -> Result<()> {
    if app_len == 0 {
        return Ok(());
    }
    advance_discarded_session_credit_locked(inner, state, app_len)?;
    // The bytes still count against the stream window the peer sent them under.
    stream_state.recv_used = stream_state.recv_used.saturating_add(app_len);
    stream_state.late_data_received = stream_state.late_data_received.saturating_add(app_len);
    state.late_data_aggregate_received = state.late_data_aggregate_received.saturating_add(app_len);
    record_late_data_discard_locked(state, cause, app_len);
    if hidden {
        state.hidden_unread_bytes_discarded =
            state.hidden_unread_bytes_discarded.saturating_add(app_len);
    }
    check_late_data_allowance(
        stream_state.late_data_received,
        late_data_allowance(stream_state),
    )
}

fn discard_absent_peer_data_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    stream_id: u64,
    app_len: u64,
    cause: LateDataCause,
) -> Result<()> {
    if app_len == 0 {
        return Ok(());
    }
    advance_discarded_session_credit_locked(inner, state, app_len)?;
    record_late_data_discard_locked(state, cause, app_len);
    // Marker-only IDs retain no per-stream accounting: their bytes are discarded
    // and released without counting toward the retained late-data aggregate.
    let Some(tombstone) = state.tombstones.get_mut(&stream_id) else {
        return Ok(());
    };
    tombstone.late_data_received = tombstone.late_data_received.saturating_add(app_len);
    let (late_data_received, late_data_allowance, hidden) = (
        tombstone.late_data_received,
        tombstone.late_data_cap,
        tombstone.hidden,
    );
    state.late_data_aggregate_received = state.late_data_aggregate_received.saturating_add(app_len);
    if hidden {
        state.hidden_unread_bytes_discarded =
            state.hidden_unread_bytes_discarded.saturating_add(app_len);
    }
    check_late_data_allowance(late_data_received, late_data_allowance)
}

/// Session-level handling of DATA that a live stream rejects with a
/// stream-local ABORT (DATA after FIN, wrong direction, stream window overrun).
/// The sender counted the bytes against the session window, so they are checked
/// against it and released back to it (SPEC §8), but they are not late data.
fn discard_rejected_stream_data_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    app_len: u64,
) -> Result<()> {
    if app_len == 0 {
        return Ok(());
    }
    advance_discarded_session_credit_locked(inner, state, app_len)
}

fn record_late_data_discard_locked(state: &mut ConnState, cause: LateDataCause, bytes: u64) {
    match cause {
        LateDataCause::None => {}
        LateDataCause::CloseRead => {
            state.late_data_after_close_read_bytes =
                state.late_data_after_close_read_bytes.saturating_add(bytes);
        }
        LateDataCause::Reset => {
            state.late_data_after_reset_bytes =
                state.late_data_after_reset_bytes.saturating_add(bytes);
        }
        LateDataCause::Abort => {
            state.late_data_after_abort_bytes =
                state.late_data_after_abort_bytes.saturating_add(bytes);
        }
    }
}

/// Only the per-direction allowance escalates: it already covers every byte a
/// compliant peer can have in flight. Exceeding the aggregate allowance keeps
/// discarding (API_SEMANTICS §3), since discarded bytes are not retained.
#[inline]
fn check_late_data_allowance(late_data_received: u64, late_data_allowance: u64) -> Result<()> {
    if late_data_received > late_data_allowance {
        return Err(Error::protocol("late-data cap exceeded"));
    }
    Ok(())
}

fn advance_discarded_session_credit_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    app_len: u64,
) -> Result<()> {
    if receive_window_exceeded(
        state.recv_session_used,
        state.recv_session_advertised,
        app_len,
    ) {
        return Err(Error::flow_control("session MAX_DATA exceeded"));
    }
    state.recv_session_used = state.recv_session_used.saturating_add(app_len);
    state.received_data_bytes = state.received_data_bytes.saturating_add(app_len);
    state.recv_session_advertised = next_credit_limit(
        state.recv_session_advertised,
        app_len,
        state.recv_session_used,
        0,
        false,
    );

    inner.force_queue_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id: 0,
        payload: max_data_payload(state.recv_session_advertised)?,
    })?;
    Ok(())
}

fn replenish_buffered_session_credit_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    released: u64,
    released_retained_bytes: usize,
) -> Result<()> {
    if released == 0 && released_retained_bytes == 0 {
        return Ok(());
    }
    release_session_receive_buffered_locked(state, released, released_retained_bytes);
    state.recv_session_pending = state.recv_session_pending.saturating_add(released);
    flush_pending_session_credit_locked(inner, state, false)?;
    Ok(())
}

fn flush_pending_session_credit_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    force: bool,
) -> Result<bool> {
    let payload =
        negotiated_frame_payload(&inner.local_preface.settings, &inner.peer_preface.settings);
    let target = session_window_target(
        &inner.local_preface.settings,
        inner.session_data_high_watermark,
    );
    // A forced flush (peer BLOCKED, a waiting reader or accept, a retry) also
    // grants standing credit to an exhausted window with nothing to release.
    let grant_exhausted = force
        && receive_window_exhausted(
            state.recv_session_advertised,
            state.recv_session_used,
            state.recv_session_pending,
            state.recv_session_buffered,
        );
    if !grant_exhausted
        && !should_flush_receive_credit(
            state.recv_session_advertised,
            state.recv_session_used,
            state.recv_session_pending,
            target,
            session_emergency_threshold(payload),
            replenish_min_pending(target, payload),
            force,
        )
    {
        return Ok(false);
    }
    let desired = next_credit_limit(
        state.recv_session_advertised,
        state.recv_session_pending,
        state.recv_session_used,
        target,
        session_standing_growth_allowed(
            session_memory_pressure_high_fast_locked(inner, state),
            state.recv_session_buffered,
            state.recv_session_pending,
            inner.session_data_high_watermark,
        ),
    );
    if desired <= state.recv_session_advertised {
        // Standing growth is not allowed (memory pressure): nothing to grant.
        return Ok(false);
    }
    if !try_queue_max_data(inner, 0, desired)? {
        state.recv_replenish_retry = true;
        return Ok(false);
    }
    state.recv_session_advertised = desired;
    state.recv_session_pending = 0;
    Ok(true)
}

fn flush_pending_stream_credit_locked(
    inner: &Arc<Inner>,
    stream: &StreamInner,
    stream_state: &mut StreamState,
    session_memory_pressure_high: bool,
    force: bool,
    retry_needed: &mut bool,
) -> Result<bool> {
    if !stream.local_recv
        || stream_state.read_stopped
        || stream_state.recv_reset.is_some()
        || stream_state.aborted.is_some()
        || stream_state.recv_fin
    {
        stream_state.recv_pending = 0;
        return Ok(false);
    }
    let payload =
        negotiated_frame_payload(&inner.local_preface.settings, &inner.peer_preface.settings);
    let stream_id = stream.id.load(std::sync::atomic::Ordering::Acquire);
    if stream_id == 0 {
        stream_state.recv_pending = 0;
        return Ok(false);
    }
    let initial = initial_receive_window(
        inner.negotiated.local_role,
        &inner.local_preface.settings,
        stream_id,
    );
    let target = stream_window_target(initial, inner.per_stream_data_high_watermark);
    let grant_exhausted = force
        && receive_window_exhausted(
            stream_state.recv_advertised,
            stream_state.recv_used,
            stream_state.recv_pending,
            usize_to_u64_saturating(stream_state.recv_buf.len()),
        );
    if !grant_exhausted
        && !should_flush_receive_credit(
            stream_state.recv_advertised,
            stream_state.recv_used,
            stream_state.recv_pending,
            target,
            stream_emergency_threshold(target, payload),
            replenish_min_pending(target, payload),
            force,
        )
    {
        return Ok(false);
    }
    let desired = next_credit_limit(
        stream_state.recv_advertised,
        stream_state.recv_pending,
        stream_state.recv_used,
        target,
        stream_standing_growth_allowed(
            session_memory_pressure_high,
            usize_to_u64_saturating(stream_state.recv_buf.len()),
            stream_state.recv_pending,
            inner.per_stream_data_high_watermark,
        ),
    );
    if desired <= stream_state.recv_advertised {
        return Ok(false);
    }
    if !try_queue_max_data(inner, stream_id, desired)? {
        *retry_needed = true;
        return Ok(false);
    }
    stream_state.recv_advertised = desired;
    stream_state.recv_pending = 0;
    Ok(true)
}

/// Grants standing session credit to an application about to wait in accept or
/// read while the session receive window is used up with nothing pending. Peers
/// need not send BLOCKED, so a zero initial window would otherwise never grow
/// (SPEC §8).
pub(super) fn grant_exhausted_session_credit_locked(inner: &Arc<Inner>, state: &mut ConnState) {
    if ignore_peer_non_close_locked(state)
        || !receive_window_exhausted(
            state.recv_session_advertised,
            state.recv_session_used,
            state.recv_session_pending,
            state.recv_session_buffered,
        )
    {
        return;
    }
    let _ = flush_pending_session_credit_locked(inner, state, true);
}

/// Like [`grant_exhausted_session_credit_locked`], for a reader about to wait on
/// a stream (and its session) whose receive credit is used up.
pub(super) fn grant_exhausted_receive_credit(inner: &Arc<Inner>, stream: &StreamInner) {
    let mut state = inner.state.lock().unwrap();
    grant_exhausted_session_credit_locked(inner, &mut state);
    if ignore_peer_non_close_locked(&state) {
        return;
    }
    let session_memory_pressure_high = session_memory_pressure_high_fast_locked(inner, &state);
    let mut stream_state = stream.state.lock().unwrap();
    if !receive_window_exhausted(
        stream_state.recv_advertised,
        stream_state.recv_used,
        stream_state.recv_pending,
        usize_to_u64_saturating(stream_state.recv_buf.len()),
    ) {
        return;
    }
    let mut retry_needed = false;
    let _ = flush_pending_stream_credit_locked(
        inner,
        stream,
        &mut stream_state,
        session_memory_pressure_high,
        true,
        &mut retry_needed,
    );
    if retry_needed {
        state.recv_replenish_retry = true;
    }
}

fn try_queue_max_data(inner: &Arc<Inner>, stream_id: u64, limit: u64) -> Result<bool> {
    match inner.try_queue_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id,
        payload: max_data_payload(limit)?,
    }) {
        Ok(()) => Ok(true),
        Err(err) if err.is_urgent_writer_queue_full() || err.is_session_closed() => Ok(false),
        Err(err) => Err(err),
    }
}

#[inline]
fn max_data_payload(limit: u64) -> Result<Vec<u8>> {
    let mut payload = Vec::with_capacity(crate::varint::varint_len(limit)?);
    append_varint_reserved(&mut payload, limit)?;
    Ok(payload)
}

#[cfg(test)]
pub(super) fn flush_pending_receive_credit(inner: &Arc<Inner>) -> Result<()> {
    let mut state = inner.state.lock().unwrap();
    let _ = flush_pending_session_credit_locked(inner, &mut state, false)?;
    let session_memory_pressure_high = session_memory_pressure_high_fast_locked(inner, &state);
    let mut retry_needed = false;
    for stream in state.streams.values() {
        let mut stream_state = stream.state.lock().unwrap();
        let _ = flush_pending_stream_credit_locked(
            inner,
            stream,
            &mut stream_state,
            session_memory_pressure_high,
            false,
            &mut retry_needed,
        )?;
    }
    if retry_needed {
        state.recv_replenish_retry = true;
    }
    Ok(())
}

pub(super) fn retry_pending_receive_credit(inner: &Arc<Inner>) -> Result<()> {
    let mut state = inner.state.lock().unwrap();
    if !state.recv_replenish_retry {
        return Ok(());
    }
    state.recv_replenish_retry = false;
    let _ = flush_pending_session_credit_locked(inner, &mut state, true)?;
    let session_memory_pressure_high = session_memory_pressure_high_fast_locked(inner, &state);
    let mut retry_needed = false;
    for stream in state.streams.values() {
        let mut stream_state = stream.state.lock().unwrap();
        let _ = flush_pending_stream_credit_locked(
            inner,
            stream,
            &mut stream_state,
            session_memory_pressure_high,
            true,
            &mut retry_needed,
        )?;
    }
    if retry_needed {
        state.recv_replenish_retry = true;
    }
    Ok(())
}

#[inline]
fn stream_id_previously_used(state: &ConnState, inner: &Arc<Inner>, stream_id: u64) -> bool {
    if stream_is_local(inner.negotiated.local_role, stream_id) {
        if stream_is_bidi(stream_id) {
            stream_id < state.next_local_bidi
        } else {
            stream_id < state.next_local_uni
        }
    } else if stream_is_bidi(stream_id) {
        stream_id < state.next_peer_bidi
    } else {
        stream_id < state.next_peer_uni
    }
}

fn marker_data_disposition(inner: &Arc<Inner>, stream_id: u64) -> TerminalDataDisposition {
    let action =
        if stream_is_local(inner.negotiated.local_role, stream_id) && !stream_is_bidi(stream_id) {
            TerminalDataAction::Abort(ErrorCode::StreamState.as_u64())
        } else {
            TerminalDataAction::Abort(ErrorCode::StreamClosed.as_u64())
        };
    TerminalDataDisposition {
        action,
        cause: LateDataCause::None,
    }
}

#[inline]
fn known_absent_stream_locked(state: &ConnState, inner: &Arc<Inner>, stream_id: u64) -> bool {
    has_terminal_marker_locked(state, stream_id)
        || stream_id_previously_used(state, inner, stream_id)
}

#[inline]
fn has_marker_only_terminal_marker_locked(state: &ConnState, stream_id: u64) -> bool {
    terminal_marker_disposition_locked(state, stream_id).is_some()
        && !state.tombstones.contains_key(&stream_id)
}

/// Creates the stream a peer opening frame refers to, or refuses it (`None`).
/// `opening_app_len` is the application payload of an opening DATA frame (0 for
/// an opening ABORT).
fn create_peer_stream(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    stream_id: u64,
    application_visible: bool,
    opening_app_len: u64,
) -> Result<Option<Arc<StreamInner>>> {
    if stream_is_local(inner.negotiated.local_role, stream_id) {
        return Err(Error::protocol("peer referenced unopened local stream"));
    }
    let bidi = stream_is_bidi(stream_id);
    if refused_by_local_go_away_locked(state, inner, stream_id) {
        if refuse_peer_open_past_local_go_away_locked(inner, state, stream_id)?
            && !application_visible
        {
            state.hidden_streams_refused = state.hidden_streams_refused.saturating_add(1);
        }
        return Ok(None);
    }
    let expected = if bidi {
        state.next_peer_bidi
    } else {
        state.next_peer_uni
    };
    if expected > MAX_VARINT62 {
        return Err(Error::protocol("peer stream id overflow"));
    }
    if stream_id != expected {
        return Err(Error::protocol("peer stream id skipped expected id"));
    }
    let local_settings = &inner.local_preface.settings;
    let peer_settings = &inner.peer_preface.settings;
    let visible_backlog_len = state
        .accept_bidi
        .len()
        .saturating_add(state.accept_uni.len());
    let over_stream_limit = if bidi {
        state.active.peer_bidi >= local_settings.max_incoming_streams_bidi
    } else {
        state.active.peer_uni >= local_settings.max_incoming_streams_uni
    };
    let over_visible_limit = visible_backlog_len >= state.accept_backlog_limit;
    let refused = over_stream_limit || (application_visible && over_visible_limit);
    let next_peer_id = stream_id + 4;
    if bidi {
        state.next_peer_bidi = next_peer_id;
    } else {
        state.next_peer_uni = next_peer_id;
    }
    if refused {
        if application_visible {
            state.accept_backlog_refused = state.accept_backlog_refused.saturating_add(1);
        } else {
            state.hidden_streams_refused = state.hidden_streams_refused.saturating_add(1);
        }
        note_abort_reason_locked(state, ErrorCode::RefusedStream.as_u64());
        queue_abort(inner, stream_id, ErrorCode::RefusedStream.as_u64(), "")?;
        // The refused ID is consumed and locally aborted, so in-flight DATA on
        // it is late data after ABORT: ignored with session credit release, not
        // treated as DATA after FIN (SPEC §9.5, STATE_MACHINE §8). The peer may
        // still send its whole initial stream window.
        let recv_window =
            initial_receive_window(inner.negotiated.local_role, local_settings, stream_id);
        record_tombstone_locked(
            state,
            stream_id,
            StreamTombstone {
                data_disposition: TerminalDataDisposition {
                    action: TerminalDataAction::Ignore,
                    cause: LateDataCause::Abort,
                },
                late_data_received: 0,
                late_data_cap: late_data_per_stream_cap(
                    state.late_data_per_stream_cap,
                    recv_window,
                    local_settings.max_frame_payload,
                )
                .max(recv_window.saturating_sub(opening_app_len)),
                hidden: !application_visible,
                created_at: Instant::now(),
            },
        );
        clear_ignored_control_budget_locked(state);
        return Ok(None);
    }
    if application_visible {
        if bidi {
            state.active.peer_bidi = state.active.peer_bidi.saturating_add(1);
        } else {
            state.active.peer_uni = state.active.peer_uni.saturating_add(1);
        }
    }
    let accept_seq = if application_visible {
        let seq = state.next_accept_seq;
        state.next_accept_seq = state.next_accept_seq.wrapping_add(1);
        seq
    } else {
        0
    };
    let recv_advertised =
        initial_receive_window(inner.negotiated.local_role, local_settings, stream_id);
    let send_max = initial_send_window(inner.negotiated.local_role, peer_settings, stream_id);
    let stream = Arc::new(StreamInner {
        conn: Arc::clone(inner),
        id: AtomicU64::new(stream_id),
        bidi,
        opened_locally: false,
        application_visible,
        local_send: bidi,
        local_recv: true,
        state: Mutex::new(StreamState {
            recv_buf: Default::default(),
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
            provisional_wait: ProvisionalWait::default(),
            opened_on_wire: false,
            peer_visible: true,
            received_open: false,
            send_used: 0,
            send_max,
            send_blocked_at: None,
            recv_used: 0,
            recv_advertised,
            recv_pending: 0,
            recv_blocked_at: None,
            late_data_received: 0,
            late_data_cap: late_data_per_stream_cap(
                state.late_data_per_stream_cap,
                recv_advertised,
                local_settings.max_frame_payload,
            ),
            open_prefix: Vec::new(),
            open_info: Vec::new(),
            retained_open_info_bytes: 0,
            metadata: StreamMetadata::default(),
            metadata_revision: 0,
            pending_priority_update: None,
            open_initial_group: None,
            opened_event_sent: false,
            accepted_event_sent: false,
            accept_pending: application_visible,
            accept_seq,
            accept_backlog_bytes: 0,
            active_counted: application_visible,
            visible_churn_counted: false,
            retained_recv_reset_reason_bytes: 0,
            retained_abort_reason_bytes: 0,
            retained_stopped_reason_bytes: 0,
        }),
        cond: Condvar::new(),
    });
    state.streams.insert(stream_id, Arc::clone(&stream));
    clear_ignored_control_budget_locked(state);
    if application_visible {
        if bidi {
            state.accept_bidi.push_back(Arc::clone(&stream));
        } else {
            state.accept_uni.push_back(Arc::clone(&stream));
        }
        inner.cond.notify_all();
    }
    Ok(Some(stream))
}

fn handle_max_data(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let (max, n) = match parse_varint(&frame.payload) {
        Ok(parsed) => parsed,
        Err(err) => {
            return maybe_ignore_peer_non_close_error(
                inner,
                malformed_payload_error("invalid MAX_DATA payload", err),
            )
        }
    };
    if n != frame.payload.len() {
        return maybe_ignore_peer_non_close_error(
            inner,
            Error::protocol("MAX_DATA payload has trailing bytes"),
        );
    }
    let payload_len = frame.payload.len();
    let mut state = inner.state.lock().unwrap();
    if ignore_peer_non_close_locked(&state) {
        return Ok(());
    }
    if frame.stream_id == 0 {
        if max > state.send_session_max {
            state.send_session_max = max;
            state.send_session_blocked_at = None;
            clear_no_op_max_data_budget_locked(&mut state);
        } else {
            record_no_op_max_data_locked(&mut state, payload_len)?;
        }
        inner.cond.notify_all();
        return Ok(());
    }
    if let Some(stream) = state.streams.get(&frame.stream_id).cloned() {
        let peer_visible_update = {
            let mut ss = stream.state.lock().unwrap();
            if stream_fully_terminal(&stream, &ss) {
                record_no_op_max_data_locked(&mut state, payload_len)?;
                return Ok(());
            }
            if !stream.local_send {
                record_inert_flow_control_frame_locked(&mut state, payload_len)?;
                abort_stream_for_peer_violation_locked(
                    inner,
                    &mut state,
                    &stream,
                    &mut ss,
                    ErrorCode::StreamState.as_u64(),
                    "",
                )?;
                return Ok(());
            }
            let peer_visible_update =
                mark_stream_peer_visible_locked(inner, &stream, &mut ss, state.state);
            if max > ss.send_max {
                ss.send_max = max;
                ss.send_blocked_at = None;
                clear_no_op_max_data_budget_locked(&mut state);
            } else {
                record_no_op_max_data_locked(&mut state, payload_len)?;
            }
            stream.cond.notify_all();
            inner.cond.notify_all();
            peer_visible_update
        };
        drop(state);
        finish_peer_visible_update(inner, frame.stream_id, peer_visible_update);
        Ok(())
    } else if has_marker_only_terminal_marker_locked(&state, frame.stream_id) {
        record_inert_flow_control_frame_locked(&mut state, payload_len)
    } else if known_absent_or_refused_stream_locked(&state, inner, frame.stream_id) {
        record_no_op_max_data_locked(&mut state, payload_len)?;
        Ok(())
    } else {
        Err(Error::protocol("MAX_DATA on previously unseen stream"))
    }
}

fn handle_blocked(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let (blocked_at, n) = match parse_varint(&frame.payload) {
        Ok(parsed) => parsed,
        Err(err) => {
            return maybe_ignore_peer_non_close_error(
                inner,
                malformed_payload_error("invalid BLOCKED payload", err),
            )
        }
    };
    if n != frame.payload.len() {
        return maybe_ignore_peer_non_close_error(
            inner,
            Error::protocol("BLOCKED payload has trailing bytes"),
        );
    }
    let payload_len = frame.payload.len();
    if frame.stream_id == 0 {
        let mut state = inner.state.lock().unwrap();
        if ignore_peer_non_close_locked(&state) {
            return Ok(());
        }
        let has_pending_credit = state.recv_session_pending != 0;
        let advertised = state.recv_session_advertised;
        let newly_blocked = note_peer_blocked_at(
            &mut state.recv_session_blocked_at,
            blocked_at,
            inner.local_preface.settings.initial_max_data,
            advertised,
        );
        let queued = flush_pending_session_credit_locked(inner, &mut state, true)?;
        if has_pending_credit || queued || newly_blocked {
            clear_no_op_blocked_budget_locked(&mut state);
        } else {
            record_no_op_blocked_locked(&mut state, payload_len)?;
        }
        return Ok(());
    }
    let mut state = inner.state.lock().unwrap();
    if ignore_peer_non_close_locked(&state) {
        return Ok(());
    }
    if let Some(stream) = state.streams.get(&frame.stream_id).cloned() {
        let peer_visible_update = {
            let session_memory_pressure_high =
                session_memory_pressure_high_fast_locked(inner, &state);
            let mut ss = stream.state.lock().unwrap();
            if stream_fully_terminal(&stream, &ss) {
                record_no_op_blocked_locked(&mut state, payload_len)?;
                return Ok(());
            }
            if !stream.local_recv {
                record_inert_flow_control_frame_locked(&mut state, payload_len)?;
                abort_stream_for_peer_violation_locked(
                    inner,
                    &mut state,
                    &stream,
                    &mut ss,
                    ErrorCode::StreamState.as_u64(),
                    "",
                )?;
                return Ok(());
            }
            let peer_visible_update =
                mark_stream_peer_visible_locked(inner, &stream, &mut ss, state.state);
            let has_pending_credit = state.recv_session_pending != 0 || ss.recv_pending != 0;
            let initial = initial_receive_window(
                inner.negotiated.local_role,
                &inner.local_preface.settings,
                frame.stream_id,
            );
            let advertised = ss.recv_advertised;
            let newly_blocked =
                note_peer_blocked_at(&mut ss.recv_blocked_at, blocked_at, initial, advertised);
            let session_queued = flush_pending_session_credit_locked(inner, &mut state, true)?;
            let mut retry_needed = false;
            let stream_queued = flush_pending_stream_credit_locked(
                inner,
                &stream,
                &mut ss,
                session_memory_pressure_high,
                true,
                &mut retry_needed,
            )?;
            if retry_needed {
                state.recv_replenish_retry = true;
            }
            if has_pending_credit || session_queued || stream_queued || newly_blocked {
                clear_no_op_blocked_budget_locked(&mut state);
            } else {
                record_no_op_blocked_locked(&mut state, payload_len)?;
            }
            peer_visible_update
        };
        drop(state);
        finish_peer_visible_update(inner, frame.stream_id, peer_visible_update);
        Ok(())
    } else {
        if has_marker_only_terminal_marker_locked(&state, frame.stream_id) {
            record_inert_flow_control_frame_locked(&mut state, payload_len)
        } else if known_absent_or_refused_stream_locked(&state, inner, frame.stream_id) {
            record_no_op_blocked_locked(&mut state, payload_len)?;
            Ok(())
        } else {
            Err(Error::protocol("BLOCKED on previously unseen stream"))
        }
    }
}

/// Records the limit a peer BLOCKED reports. A compliant sender reports each
/// limit it was granted at most once and in increasing order, so a BLOCKED for a
/// new limit within the granted range is not a repeated no-op, even when a later
/// grant crossed it on the wire.
#[inline]
fn note_peer_blocked_at(
    last_blocked_at: &mut Option<u64>,
    blocked_at: u64,
    initial: u64,
    advertised: u64,
) -> bool {
    if blocked_at < initial
        || blocked_at > advertised
        || last_blocked_at.is_some_and(|last| blocked_at <= last)
    {
        return false;
    }
    *last_blocked_at = Some(blocked_at);
    true
}

fn handle_stop_sending(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let (code, reason) = match parse_inbound_error_payload(&frame.payload) {
        Ok(parsed) => parsed,
        Err(err) => return maybe_ignore_peer_non_close_error(inner, err),
    };
    let mut abort_unopened = false;
    let mut try_graceful_finish = false;
    let (stream, peer_visible_update) = {
        let mut conn_state = inner.state.lock().unwrap();
        if ignore_peer_non_close_locked(&conn_state) {
            return Ok(());
        }
        let Some(stream) = conn_state.streams.get(&frame.stream_id).cloned() else {
            if has_marker_only_terminal_marker_locked(&conn_state, frame.stream_id) {
                return Ok(());
            }
            if known_absent_or_refused_stream_locked(&conn_state, inner, frame.stream_id) {
                record_ignored_control_locked(&mut conn_state)?;
                return Ok(());
            }
            return Err(Error::protocol("STOP_SENDING on previously unseen stream"));
        };
        if !stream.local_send {
            let mut ss = stream.state.lock().unwrap();
            abort_stream_for_peer_violation_locked(
                inner,
                &mut conn_state,
                &stream,
                &mut ss,
                ErrorCode::StreamState.as_u64(),
                "",
            )?;
            return Ok(());
        }
        {
            let mut ss = stream.state.lock().unwrap();
            let peer_visible_update =
                mark_stream_peer_visible_locked(inner, &stream, &mut ss, conn_state.state);
            if ss.stopped_by_peer.is_some()
                || ss.send_fin
                || ss.send_reset.is_some()
                || ss.aborted.is_some()
            {
                record_ignored_control_locked(&mut conn_state)?;
                drop(ss);
                drop(conn_state);
                finish_peer_visible_update(inner, frame.stream_id, peer_visible_update);
                return Ok(());
            }
            retain_stream_stopped_reason_locked(inner, &mut conn_state, &mut ss, code, reason);
            record_visible_terminal_churn_locked(&mut conn_state, &stream, &mut ss)?;
            if !ss.send_fin && ss.send_reset.is_none() && ss.aborted.is_none() {
                if stream.opened_locally && !ss.opened_on_wire {
                    ss.aborted = Some((ErrorCode::Cancelled.as_u64(), String::new()));
                    ss.abort_source = ErrorSource::Local;
                    ss.opened_on_wire = true;
                    ss.pending_terminal_frames = ss.pending_terminal_frames.saturating_add(1);
                    abort_unopened = true;
                } else {
                    try_graceful_finish = ss.recv_reset.is_none();
                }
            }
            maybe_release_active_count(&mut conn_state, &stream, &mut ss);
            drop(ss);
            clear_ignored_control_budget_locked(&mut conn_state);
            (stream, peer_visible_update)
        }
    };
    finish_peer_visible_update(inner, frame.stream_id, peer_visible_update);
    {
        // Writers parked on stream/session credit wait on the session condvar;
        // wake them too so they observe the stop and release the write path.
        stream.cond.notify_all();
        inner.cond.notify_all();
        inner.wake_writer_queue_waiters();
        if try_graceful_finish && stream.try_graceful_finish_after_stop_sending() {
            stream.cond.notify_all();
            return Ok(());
        }

        let mut reply = if abort_unopened {
            Some(FrameType::Abort)
        } else {
            None
        };
        if !abort_unopened {
            let mut conn_state = inner.state.lock().unwrap();
            if ignore_peer_non_close_locked(&conn_state) {
                return Ok(());
            }
            let mut ss = stream.state.lock().unwrap();
            if ss.send_fin || ss.send_reset.is_some() || ss.aborted.is_some() {
                stream.cond.notify_all();
                return Ok(());
            }
            ss.send_reset = Some((ErrorCode::Cancelled.as_u64(), String::new()));
            ss.send_reset_from_stop = true;
            ss.pending_terminal_frames = ss.pending_terminal_frames.saturating_add(1);
            maybe_release_active_count(&mut conn_state, &stream, &mut ss);
            reply = Some(FrameType::Reset);
        }
        if matches!(reply, Some(FrameType::Reset)) {
            discard_stop_sending_reset_tail(inner, frame.stream_id);
        }
        if let Some(frame_type) = reply {
            if let Err(err) = inner.try_queue_frame(Frame {
                frame_type,
                flags: 0,
                stream_id: frame.stream_id,
                payload: build_code_payload(
                    ErrorCode::Cancelled.as_u64(),
                    "",
                    inner.peer_preface.settings.max_control_payload_bytes,
                )?,
            }) {
                let mut state = inner.state.lock().unwrap();
                note_written_stream_frames_locked(&mut state, frame.stream_id, 0, 1);
                return Err(err);
            }
        }
        stream.cond.notify_all();
        Ok(())
    }
}

pub(super) fn discard_stop_sending_reset_tail(inner: &Arc<Inner>, stream_id: u64) {
    let stats = inner.write_queue.discard_stream_send_tail(stream_id);
    if !stats.removed_any() {
        return;
    }
    let mut state = inner.state.lock().unwrap();
    let Some(stream) = state.streams.get(&stream_id).cloned() else {
        return;
    };
    release_discarded_queued_stream_frames_locked(&mut state, &stream, stats);
    inner.cond.notify_all();
}

fn handle_reset(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let (code, reason) = match parse_inbound_error_payload(&frame.payload) {
        Ok(parsed) => parsed,
        Err(err) => return maybe_ignore_peer_non_close_error(inner, err),
    };
    let mut conn_state = inner.state.lock().unwrap();
    if ignore_peer_non_close_locked(&conn_state) {
        return Ok(());
    }
    if let Some(stream) = conn_state.streams.get(&frame.stream_id).cloned() {
        let peer_visible_update = {
            if !stream.local_recv {
                let mut ss = stream.state.lock().unwrap();
                abort_stream_for_peer_violation_locked(
                    inner,
                    &mut conn_state,
                    &stream,
                    &mut ss,
                    ErrorCode::StreamState.as_u64(),
                    "",
                )?;
                return Ok(());
            }
            let mut ss = stream.state.lock().unwrap();
            let peer_visible_update =
                mark_stream_peer_visible_locked(inner, &stream, &mut ss, conn_state.state);
            if ss.recv_fin || ss.recv_reset.is_some() || ss.aborted.is_some() {
                record_ignored_control_locked(&mut conn_state)?;
                drop(ss);
                drop(conn_state);
                finish_peer_visible_update(inner, frame.stream_id, peer_visible_update);
                return Ok(());
            }
            retain_stream_recv_reset_reason_locked(inner, &mut conn_state, &mut ss, code, reason);
            record_visible_terminal_churn_locked(&mut conn_state, &stream, &mut ss)?;
            clear_accept_backlog_entry_locked(&mut conn_state, &mut ss);
            let released = ss.recv_buf.clear_detailed();
            clear_stream_receive_credit_locked(inner, &stream, &mut ss);
            if !stream.application_visible {
                conn_state.hidden_unread_bytes_discarded = conn_state
                    .hidden_unread_bytes_discarded
                    .saturating_add(usize_to_u64_saturating(released.bytes));
            }
            replenish_buffered_session_credit_locked(
                inner,
                &mut conn_state,
                usize_to_u64_saturating(released.bytes),
                released.released_retained_bytes,
            )?;
            maybe_release_active_count(&mut conn_state, &stream, &mut ss);
            clear_ignored_control_budget_locked(&mut conn_state);
            stream.cond.notify_all();
            peer_visible_update
        };
        drop(conn_state);
        finish_peer_visible_update(inner, frame.stream_id, peer_visible_update);
        Ok(())
    } else {
        if has_marker_only_terminal_marker_locked(&conn_state, frame.stream_id) {
            Ok(())
        } else if known_absent_or_refused_stream_locked(&conn_state, inner, frame.stream_id) {
            record_ignored_control_locked(&mut conn_state)?;
            Ok(())
        } else {
            Err(Error::protocol("RESET on previously unseen stream"))
        }
    }
}

fn handle_abort(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let (code, reason) = match parse_inbound_error_payload(&frame.payload) {
        Ok(parsed) => parsed,
        Err(err) => return maybe_ignore_peer_non_close_error(inner, err),
    };
    let mut conn_state = inner.state.lock().unwrap();
    if ignore_peer_non_close_locked(&conn_state) {
        return Ok(());
    }
    let stream = if let Some(stream) = conn_state.streams.get(&frame.stream_id).cloned() {
        Some(stream)
    } else if has_marker_only_terminal_marker_locked(&conn_state, frame.stream_id) {
        None
    } else if known_absent_stream_locked(&conn_state, inner, frame.stream_id)
        || peer_open_already_refused_locked(&conn_state, inner, frame.stream_id)
    {
        record_ignored_control_locked(&mut conn_state)?;
        None
    } else if !stream_is_local(inner.negotiated.local_role, frame.stream_id) {
        let stream = create_peer_stream(inner, &mut conn_state, frame.stream_id, false, 0)?;
        if stream.is_some() {
            record_hidden_abort_churn_locked(&mut conn_state)?;
        }
        stream
    } else {
        return Err(Error::protocol("ABORT on previously unseen local stream"));
    };
    if let Some(stream) = stream {
        let peer_visible_update = {
            let mut ss = stream.state.lock().unwrap();
            if ss.aborted.is_some() {
                record_ignored_control_locked(&mut conn_state)?;
                return Ok(());
            }
            let peer_visible_update =
                mark_stream_peer_visible_locked(inner, &stream, &mut ss, conn_state.state);
            if stream_fully_terminal(&stream, &ss) {
                // A late ABORT for a stream that already finished both halves is
                // ignored (SPEC §6.8/§9.5): unread data stays readable and the
                // terminal outcomes already reached are kept.
                record_ignored_control_locked(&mut conn_state)?;
                drop(ss);
                drop(conn_state);
                finish_peer_visible_update(inner, frame.stream_id, peer_visible_update);
                return Ok(());
            }
            retain_stream_abort_reason_locked(inner, &mut conn_state, &mut ss, code, reason);
            record_visible_terminal_churn_locked(&mut conn_state, &stream, &mut ss)?;
            clear_accept_backlog_entry_locked(&mut conn_state, &mut ss);
            let released = ss.recv_buf.clear_detailed();
            clear_stream_receive_credit_locked(inner, &stream, &mut ss);
            if !stream.application_visible {
                conn_state.hidden_unread_bytes_discarded = conn_state
                    .hidden_unread_bytes_discarded
                    .saturating_add(usize_to_u64_saturating(released.bytes));
            }
            replenish_buffered_session_credit_locked(
                inner,
                &mut conn_state,
                usize_to_u64_saturating(released.bytes),
                released.released_retained_bytes,
            )?;
            maybe_release_active_count(&mut conn_state, &stream, &mut ss);
            clear_ignored_control_budget_locked(&mut conn_state);
            stream.cond.notify_all();
            peer_visible_update
        };
        drop(conn_state);
        finish_peer_visible_update(inner, frame.stream_id, peer_visible_update);
    }
    Ok(())
}

fn handle_ping(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let request_payload = frame.payload;
    let payload = {
        let mut state = inner.state.lock().unwrap();
        if ignore_session_control_while_closing_locked(&state) {
            return Ok(());
        }
        if request_payload.len() < PING_TOKEN_BYTES {
            return Err(Error::frame_size("PING payload too short"));
        }
        record_inbound_ping_locked(&mut state)?;
        pong_payload_for_ping_locked(inner, &mut state, request_payload)?
    };
    let pong = Frame {
        frame_type: FrameType::Pong,
        flags: 0,
        stream_id: 0,
        payload,
    };
    if let Err(err) = inner.try_queue_frame(pong) {
        if err.is_urgent_writer_queue_full() {
            return Ok(());
        }
        return Err(err);
    }
    Ok(())
}

fn handle_pong(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let waiter = {
        let mut state = inner.state.lock().unwrap();
        if ignore_session_control_while_closing_locked(&state) {
            return Ok(());
        }
        if frame.payload.len() < PING_TOKEN_BYTES {
            return Err(Error::frame_size("PONG payload too short"));
        }
        let now = Instant::now();
        let keepalive_sent_at = if let Some(ping) = state.keepalive_ping.as_ref() {
            if pong_payload_matches_ping(&frame.payload, &ping.payload, ping.accepts_padded_pong) {
                Some(ping.sent_at)
            } else {
                None
            }
        } else {
            None
        };
        if let Some(sent_at) = keepalive_sent_at {
            state.keepalive_ping = None;
            note_matching_pong_locked(inner, &mut state, now, sent_at);
            clear_ignored_control_budget_locked(&mut state);
            inner.cond.notify_all();
            return Ok(());
        }
        state.last_pong_at = Some(now);
        let waiter = if let Some(ping) = state.ping_waiter.as_ref() {
            if pong_payload_matches_ping(
                &frame.payload,
                &ping.payload,
                ping.slot.accepts_padded_pong,
            ) {
                let sent_at = ping.slot.sent_at;
                let ping = state.ping_waiter.take().unwrap();
                Some((ping.slot, now.saturating_duration_since(sent_at)))
            } else {
                None
            }
        } else {
            None
        };
        if let Some((slot, _)) = waiter.as_ref() {
            note_matching_pong_locked(inner, &mut state, now, slot.sent_at);
            clear_ignored_control_budget_locked(&mut state);
            inner.cond.notify_all();
        } else if state
            .canceled_ping_payload
            .as_ref()
            .is_some_and(|payload| canceled_ping_payload_matches(&frame.payload, payload))
        {
            state.canceled_ping_payload = None;
            clear_ignored_control_budget_locked(&mut state);
            inner.cond.notify_all();
            return Ok(());
        } else {
            record_ignored_control_locked(&mut state)?;
        }
        waiter
    };
    if let Some((slot, rtt)) = waiter {
        let mut result = slot.result.lock().unwrap();
        *result = Some(Ok(rtt));
        slot.cond.notify_all();
    }
    Ok(())
}

fn handle_go_away(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    {
        let state = inner.state.lock().unwrap();
        if ignore_session_control_while_closing_locked(&state) {
            return Ok(());
        }
    }
    let payload = match parse_inbound_go_away_payload(&frame.payload) {
        Ok(payload) => payload,
        Err(err) => return maybe_ignore_peer_non_close_error(inner, err),
    };
    let reclaimed = {
        let mut state = inner.state.lock().unwrap();
        if ignore_session_control_while_closing_locked(&state) {
            return Ok(());
        }
        validate_go_away_watermark_for_direction(payload.last_accepted_bidi, true)?;
        validate_go_away_watermark_creator(
            inner.negotiated.local_role,
            payload.last_accepted_bidi,
        )?;
        validate_go_away_watermark_for_direction(payload.last_accepted_uni, false)?;
        validate_go_away_watermark_creator(inner.negotiated.local_role, payload.last_accepted_uni)?;
        if payload.last_accepted_bidi > state.peer_go_away_bidi
            || payload.last_accepted_uni > state.peer_go_away_uni
        {
            return Err(Error::protocol("GOAWAY watermarks must be non-increasing"));
        }
        retain_peer_go_away_error_locked(inner, &mut state, payload.code, payload.reason);
        let changed = payload.last_accepted_bidi < state.peer_go_away_bidi
            || payload.last_accepted_uni < state.peer_go_away_uni;
        if !changed {
            record_ignored_control_locked(&mut state)?;
            return Ok(());
        }
        state.peer_go_away_bidi = payload.last_accepted_bidi;
        state.peer_go_away_uni = payload.last_accepted_uni;
        let mut reclaimed = reclaim_unseen_local_streams_after_go_away(&mut state, true);
        reclaimed.extend(reclaim_unseen_local_streams_after_go_away(
            &mut state, false,
        ));
        reclaim_provisionals_after_go_away(&mut state, true);
        reclaim_provisionals_after_go_away(&mut state, false);
        if state.state == SessionState::Ready {
            state.state = SessionState::Draining;
        }
        clear_ignored_control_budget_locked(&mut state);
        inner.cond.notify_all();
        reclaimed
    };
    discard_reclaimed_stream_frames(inner, reclaimed);
    Ok(())
}

fn discard_reclaimed_stream_frames(inner: &Arc<Inner>, streams: Vec<Arc<StreamInner>>) {
    for stream in streams {
        let stream_id = stream.id.load(std::sync::atomic::Ordering::Acquire);
        let stats = inner.write_queue.discard_stream(stream_id);
        if !stats.removed_any() {
            continue;
        }
        let mut state = inner.state.lock().unwrap();
        release_discarded_queued_stream_frames_locked(&mut state, &stream, stats);
        inner.cond.notify_all();
    }
}

fn handle_ext(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    {
        let state = inner.state.lock().unwrap();
        if ignore_session_control_while_closing_locked(&state) {
            return Ok(());
        }
    }
    let (ext_type, n) = match parse_varint(&frame.payload) {
        Ok(parsed) => parsed,
        Err(err) => return maybe_ignore_peer_non_close_error(inner, err),
    };
    if ext_type != EXT_PRIORITY_UPDATE {
        return Ok(());
    }
    if inner.negotiated.capabilities & CAPABILITY_PRIORITY_UPDATE == 0 {
        return Ok(());
    }
    if frame.stream_id == 0 {
        // SPEC §7.6 requires stream_id != 0; stream 0 is not a stream, so
        // this is an invalid frame scope rather than an unseen target.
        return maybe_ignore_peer_non_close_error(
            inner,
            Error::protocol("PRIORITY_UPDATE requires non-zero stream_id"),
        );
    }
    let (metadata, valid) = match parse_priority_update_metadata(&frame.payload[n..]) {
        Ok(parsed) => parsed,
        Err(err) => {
            return maybe_ignore_peer_non_close_error(
                inner,
                malformed_payload_error("malformed PRIORITY_UPDATE payload", err),
            )
        }
    };
    if !valid {
        let mut state = inner.state.lock().unwrap();
        if !ignore_session_control_while_closing_locked(&state) {
            record_dropped_priority_update_locked(&mut state);
        }
        return Ok(());
    }
    let mut state = inner.state.lock().unwrap();
    if ignore_session_control_while_closing_locked(&state) {
        return Ok(());
    }
    if let Some(stream) = state.streams.get(&frame.stream_id).cloned() {
        let mut ss = stream.state.lock().unwrap();
        if stream_fully_terminal(&stream, &ss) {
            record_no_op_priority_update_locked(&mut state)?;
            return Ok(());
        }
        if stream.opened_locally && !ss.peer_visible {
            return Ok(());
        }
        let before_priority = ss.metadata.priority;
        let before_group = ss.metadata.group;
        let caps = inner.negotiated.capabilities;
        if metadata.priority.is_some() && capabilities_can_carry_priority_in_update(caps) {
            ss.metadata.priority = metadata.priority;
        }
        if metadata.group.is_some() && capabilities_can_carry_group_in_update(caps) {
            ss.metadata.group = normalize_stream_group(metadata.group);
        }
        if ss.metadata.priority == before_priority && ss.metadata.group == before_group {
            record_no_op_priority_update_locked(&mut state)?;
        } else {
            ss.metadata_revision = ss.metadata_revision.wrapping_add(1);
            if should_record_group_rebucket_churn_locked(inner, &stream, &ss, before_group) {
                record_group_rebucket_churn_locked(&mut state)?;
            }
            clear_no_op_priority_update_budget_locked(&mut state);
        }
    } else if has_marker_only_terminal_marker_locked(&state, frame.stream_id)
        || known_absent_or_refused_stream_locked(&state, inner, frame.stream_id)
    {
        return Ok(());
    }
    Ok(())
}

fn should_record_group_rebucket_churn_locked(
    inner: &Inner,
    stream: &StreamInner,
    stream_state: &StreamState,
    previous_group: Option<u64>,
) -> bool {
    inner.peer_preface.settings.scheduler_hints == SchedulerHint::GroupFair
        && inner.negotiated.capabilities & CAPABILITY_STREAM_GROUPS != 0
        && stream.local_send
        && !stream_state.send_fin
        && stream_state.send_reset.is_none()
        && stream_state.aborted.is_none()
        && stream_state.metadata.group != previous_group
}

fn abort_stream_for_peer_violation_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    stream: &Arc<StreamInner>,
    stream_state: &mut StreamState,
    code: u64,
    reason: &str,
) -> Result<()> {
    if stream_state.aborted.is_some() {
        return Ok(());
    }
    let payload = build_code_payload(
        code,
        reason,
        inner.peer_preface.settings.max_control_payload_bytes,
    )?;
    retain_stream_abort_reason_locked(inner, state, stream_state, code, reason.to_owned());
    record_visible_terminal_churn_locked(state, stream, stream_state)?;
    if stream_state.accept_pending && !stream_state.received_open {
        remove_accept_queue_entry_locked(state, stream);
    }
    clear_accept_backlog_entry_locked(state, stream_state);
    let released = stream_state.recv_buf.clear_detailed();
    clear_stream_receive_credit_locked(inner, stream, stream_state);
    if !stream.application_visible {
        state.hidden_unread_bytes_discarded = state
            .hidden_unread_bytes_discarded
            .saturating_add(usize_to_u64_saturating(released.bytes));
    }
    replenish_buffered_session_credit_locked(
        inner,
        state,
        usize_to_u64_saturating(released.bytes),
        released.released_retained_bytes,
    )?;
    stream_state.opened_on_wire = true;
    stream_state.pending_terminal_frames = stream_state.pending_terminal_frames.saturating_add(1);
    maybe_release_active_count(state, stream, stream_state);
    if let Err(err) = inner.try_queue_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id: stream.id.load(std::sync::atomic::Ordering::Acquire),
        payload,
    }) {
        stream_state.pending_terminal_frames =
            stream_state.pending_terminal_frames.saturating_sub(1);
        maybe_release_active_count(state, stream, stream_state);
        stream.cond.notify_all();
        inner.cond.notify_all();
        return Err(err);
    }
    stream.cond.notify_all();
    inner.cond.notify_all();
    Ok(())
}

#[inline]
fn usize_to_u64_saturating(value: usize) -> u64 {
    value.min(u64::MAX as usize) as u64
}

fn queue_abort(inner: &Arc<Inner>, stream_id: u64, code: u64, reason: &str) -> Result<()> {
    inner.write_queue.discard_stream_max_data(stream_id);
    inner.try_queue_frame(Frame {
        frame_type: FrameType::Abort,
        flags: 0,
        stream_id,
        payload: build_code_payload(
            code,
            reason,
            inner.peer_preface.settings.max_control_payload_bytes,
        )?,
    })
}
