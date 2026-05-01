use super::flow::{
    negotiated_frame_payload, next_credit_limit, receive_window_exceeded, replenish_min_pending,
    session_emergency_threshold, session_standing_growth_allowed, session_window_target,
    should_flush_receive_credit, stream_emergency_threshold, stream_standing_growth_allowed,
    stream_window_target,
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
    has_terminal_marker_locked, late_data_cause_for, late_data_per_stream_cap,
    mark_stream_peer_visible_locked, maybe_release_active_count, note_abort_reason_locked,
    note_written_stream_frames_locked, queue_peer_visible_pending_priority,
    reap_expired_hidden_tombstones_locked, reclaim_provisionals_after_goaway,
    reclaim_unseen_local_streams_after_goaway, refresh_accept_backlog_bytes_locked,
    release_discarded_queued_stream_frames_locked, release_peer_reason_locked,
    release_session_receive_buffered_locked, release_session_runtime_state_locked,
    remove_accept_queue_entry_locked, retain_peer_goaway_error_locked, retain_peer_reason_locked,
    retain_stream_abort_reason_locked, retain_stream_open_info_locked,
    retain_stream_recv_reset_reason_locked, retain_stream_stopped_reason_locked,
    session_memory_pressure_high_fast_locked, stream_fully_terminal,
    take_session_closed_event_locked, terminal_marker_disposition_locked, PeerVisibleUpdate,
};
use super::types::*;
use crate::error::{Error, ErrorCode, ErrorOperation, ErrorSource, Result};
use crate::frame::{
    read_session_frame, Frame, FrameType, Limits, FRAME_FLAG_FIN, FRAME_FLAG_OPEN_METADATA,
};
use crate::payload::{
    build_code_payload, normalize_stream_group, parse_data_payload_metadata_offset,
    parse_error_payload, parse_goaway_payload, parse_priority_update_metadata, StreamMetadata,
};
use crate::protocol::{
    capabilities_can_carry_group_on_open, capabilities_can_carry_group_update,
    capabilities_can_carry_priority_on_open, capabilities_can_carry_priority_update,
    CAPABILITY_OPEN_METADATA, CAPABILITY_PRIORITY_UPDATE, CAPABILITY_STREAM_GROUPS,
    EXT_PRIORITY_UPDATE,
};
use crate::settings::SchedulerHint;
use crate::stream_id::{
    initial_receive_window, initial_send_window, stream_is_bidi, stream_is_local,
    validate_goaway_watermark_creator, validate_goaway_watermark_for_direction,
};
use crate::varint::{append_varint, parse_varint};
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
                        let code = err.code().unwrap_or(ErrorCode::Protocol).as_u64();
                        let close_frame = Frame {
                            frame_type: FrameType::Close,
                            flags: 0,
                            stream_id: 0,
                            payload: build_code_payload(
                                code,
                                &err.to_string(),
                                inner.peer_preface.settings.max_control_payload_bytes,
                            )
                                .unwrap_or_default(),
                        };
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
                    fail_session(&inner, err);
                    break;
                }
            }
        }
    });
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
        inner.cond.notify_all();
        take_session_closed_event_locked(inner, &mut state)
    };
    inner.shutdown_writer();
    emit_event(inner, close_event);
    true
}

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
        FrameType::GoAway => handle_goaway(inner, frame),
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
            let (code, reason) = match parse_error_payload(&frame.payload) {
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
                state.state = if code == 0 {
                    SessionState::Closed
                } else {
                    SessionState::Failed
                };
                state.graceful_close_active = false;
                if let Some(old) = state.peer_close_error.take() {
                    release_peer_reason_locked(&mut state, old.reason.len());
                }
                let retained_reason = if code == 0 {
                    String::new()
                } else {
                    let (retained, _) = retain_peer_reason_locked(inner, &mut state, reason);
                    retained
                };
                state.peer_close_error = (code != 0).then(|| PeerCloseError {
                    code,
                    reason: retained_reason.clone(),
                });
                state.close_error = if code == 0 {
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

fn ignore_peer_non_close_locked(state: &ConnState) -> bool {
    state.ignore_peer_non_close
        || matches!(state.state, SessionState::Closed | SessionState::Failed)
}

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
        _ => {
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
    }
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
        .is_none_or(|start| now.duration_since(start) > policy.abuse_window)
    {
        *counters.window_start = Some(now);
        *counters.frames = 0;
        *counters.bytes = 0;
    }
    *counters.frames = counters.frames.saturating_add(1);
    *counters.bytes = counters.bytes.saturating_add(payload_len);
    if *counters.frames <= policy.frame_budget && *counters.bytes <= policy.byte_budget {
        Ok(())
    } else {
        Err(Error::protocol(policy.message))
    }
}

fn record_group_rebucket_churn_locked(state: &mut ConnState) -> Result<()> {
    let now = Instant::now();
    if state
        .group_rebucket_churn_window_start
        .is_none_or(|start| now.duration_since(start) > state.abuse_window)
    {
        state.group_rebucket_churn_window_start = Some(now);
        state.group_rebucket_churn_count = 0;
    }
    state.group_rebucket_churn_count = state.group_rebucket_churn_count.saturating_add(1);
    if state.group_rebucket_churn_count <= state.group_rebucket_churn_budget {
        Ok(())
    } else {
        Err(Error::protocol(
            "high-rate effective stream_group rebucketing churn exceeded local threshold",
        ))
    }
}

fn record_hidden_abort_churn_locked(state: &mut ConnState) -> Result<()> {
    let now = Instant::now();
    if state
        .hidden_abort_churn_window_start
        .is_none_or(|start| now.duration_since(start) > state.hidden_abort_churn_window)
    {
        state.hidden_abort_churn_window_start = Some(now);
        state.hidden_abort_churn_count = 0;
    }
    state.hidden_abort_churn_count = state.hidden_abort_churn_count.saturating_add(1);
    if state.hidden_abort_churn_count <= state.hidden_abort_churn_budget {
        Ok(())
    } else {
        Err(Error::protocol(
            "rapid hidden open-then-abort churn exceeded local threshold",
        ))
    }
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
    let now = Instant::now();
    if state
        .visible_terminal_churn_window_start
        .is_none_or(|start| now.duration_since(start) > state.visible_terminal_churn_window)
    {
        state.visible_terminal_churn_window_start = Some(now);
        state.visible_terminal_churn_count = 0;
    }
    state.visible_terminal_churn_count = state.visible_terminal_churn_count.saturating_add(1);
    if state.visible_terminal_churn_count <= state.visible_terminal_churn_budget {
        Ok(())
    } else {
        Err(Error::protocol(
            "rapid open-then-reset/abort churn exceeded local threshold",
        ))
    }
}

fn finish_peer_visible_update(
    inner: &Arc<Inner>,
    stream_id: u64,
    update: Option<PeerVisibleUpdate>,
) {
    let Some(update) = update else {
        return;
    };
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
    if has_open_metadata && refuse_opening_data_past_goaway_before_metadata_parse(inner, stream_id)?
    {
        return Ok(());
    }
    if has_open_metadata && inner.negotiated.capabilities & CAPABILITY_OPEN_METADATA == 0 {
        return maybe_ignore_peer_non_close_error(
            inner,
            Error::protocol("DATA|OPEN_METADATA is not negotiated"),
        );
    }
    let (stream, refused_accept_ids, peer_visible_update) = {
        let mut state = inner.state.lock().unwrap();
        if ignore_peer_non_close_locked(&state) {
            return Ok(());
        }
        let mut refused_accepts = Vec::new();
        let (stream, stream_existed) = if let Some(stream) = state.streams.get(&stream_id) {
            (stream.clone(), true)
        } else if known_absent_stream_locked(&state, inner, stream_id) {
            if flags & FRAME_FLAG_OPEN_METADATA != 0 {
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
            let Some(stream) = create_peer_stream(inner, &mut state, stream_id, true)? else {
                return Ok(());
            };
            (stream, false)
        };
        if has_open_metadata && stream_existed {
            return Err(Error::protocol(
                "OPEN_METADATA is valid only on the first DATA",
            ));
        }
        let (metadata, app_offset) = if has_open_metadata {
            match parse_data_payload_metadata_offset(&payload, flags) {
                Ok((metadata, true, app_offset)) => (Some(metadata), app_offset),
                Ok((_, false, app_offset)) => (None, app_offset),
                Err(err) => return Err(err),
            }
        } else {
            (None, 0)
        };
        let app_len = usize_to_u64_saturating(payload.len() - app_offset);
        let app_chunk = if app_len == 0 {
            None
        } else {
            Some((payload, app_offset))
        };
        let peer_visible_update;
        let mut retained_bytes = 0usize;
        {
            let mut ss = stream.state.lock().unwrap();
            if !stream.local_recv {
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
            if ss.recv_fin {
                peer_visible_update =
                    mark_stream_peer_visible_locked(inner, &stream, &mut ss, state.state);
                discard_peer_data_locked(
                    inner,
                    &mut state,
                    Some(&mut ss),
                    app_len,
                    LateDataCause::None,
                    !stream.application_visible,
                )?;
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
            if ss.recv_reset.is_some() || ss.aborted.is_some() || ss.read_stopped {
                if flags & FRAME_FLAG_OPEN_METADATA != 0 {
                    return Err(Error::protocol(
                        "OPEN_METADATA is valid only on the first DATA",
                    ));
                }
                let stopped_fin = ss.read_stopped && flags & FRAME_FLAG_FIN != 0;
                let cause = late_data_cause_for(&ss);
                peer_visible_update =
                    mark_stream_peer_visible_locked(inner, &stream, &mut ss, state.state);
                discard_peer_data_locked(
                    inner,
                    &mut state,
                    Some(&mut ss),
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
                    ss.metadata_revision = ss.metadata_revision.saturating_add(1);
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
        let released_refused: u64 = refused_accepts
            .iter()
            .fold(0u64, |sum, (_, released, _)| sum.saturating_add(*released));
        let released_refused_retained: usize = refused_accepts
            .iter()
            .fold(0usize, |sum, (_, _, retained)| {
                sum.saturating_add(*retained)
            });
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

fn refuse_opening_data_past_goaway_before_metadata_parse(
    inner: &Arc<Inner>,
    stream_id: u64,
) -> Result<bool> {
    let mut state = inner.state.lock().unwrap();
    if ignore_peer_non_close_locked(&state) {
        return Ok(true);
    }
    if stream_is_local(inner.negotiated.local_role, stream_id)
        || state.streams.contains_key(&stream_id)
        || known_absent_stream_locked(&state, inner, stream_id)
    {
        return Ok(false);
    }
    let goaway = if stream_is_bidi(stream_id) {
        state.local_goaway_bidi
    } else {
        state.local_goaway_uni
    };
    if stream_id <= goaway {
        return Ok(false);
    }
    note_abort_reason_locked(&mut state, ErrorCode::RefusedStream.as_u64());
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
    let (start, count) = advance_windowed_count(
        state.abuse_window,
        state.ignored_control_window_start,
        state.ignored_control_count,
        state.ignored_control_budget,
        "ignored control budget exceeded",
    )?;
    state.ignored_control_window_start = start;
    state.ignored_control_count = count;
    Ok(())
}

fn clear_ignored_control_budget_locked(state: &mut ConnState) {
    state.ignored_control_window_start = None;
    state.ignored_control_count = 0;
}

fn record_no_op_max_data_locked(state: &mut ConnState) -> Result<()> {
    record_ignored_control_locked(state)?;
    let (start, count) = advance_windowed_count(
        state.abuse_window,
        state.no_op_max_data_window_start,
        state.no_op_max_data_count,
        state.no_op_max_data_budget,
        "no-op MAX_DATA budget exceeded",
    )?;
    state.no_op_max_data_window_start = start;
    state.no_op_max_data_count = count;
    Ok(())
}

fn clear_no_op_max_data_budget_locked(state: &mut ConnState) {
    clear_no_op_control_budgets_locked(state);
}

fn record_no_op_blocked_locked(state: &mut ConnState) -> Result<()> {
    record_ignored_control_locked(state)?;
    let (start, count) = advance_windowed_count(
        state.abuse_window,
        state.no_op_blocked_window_start,
        state.no_op_blocked_count,
        state.no_op_blocked_budget,
        "no-op BLOCKED budget exceeded",
    )?;
    state.no_op_blocked_window_start = start;
    state.no_op_blocked_count = count;
    Ok(())
}

fn clear_no_op_blocked_budget_locked(state: &mut ConnState) {
    clear_no_op_control_budgets_locked(state);
}

fn record_no_op_priority_update_locked(state: &mut ConnState) -> Result<()> {
    record_ignored_control_locked(state)?;
    let (start, count) = advance_windowed_count(
        state.abuse_window,
        state.no_op_priority_update_window_start,
        state.no_op_priority_update_count,
        state.no_op_priority_update_budget,
        "no-op PRIORITY_UPDATE budget exceeded",
    )?;
    state.no_op_priority_update_window_start = start;
    state.no_op_priority_update_count = count;
    Ok(())
}

fn record_dropped_priority_update_locked(state: &mut ConnState) {
    state.dropped_priority_update_count = state.dropped_priority_update_count.saturating_add(1);
}

fn clear_no_op_priority_update_budget_locked(state: &mut ConnState) {
    clear_no_op_control_budgets_locked(state);
}

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
    let (start, count) = advance_windowed_count(
        state.abuse_window,
        state.inbound_ping_window_start,
        state.inbound_ping_count,
        state.inbound_ping_budget,
        "inbound PING budget exceeded",
    )?;
    state.inbound_ping_window_start = start;
    state.inbound_ping_count = count;
    Ok(())
}

fn clear_inbound_ping_budget_locked(state: &mut ConnState) {
    state.inbound_ping_window_start = None;
    state.inbound_ping_count = 0;
}

fn update_no_op_zero_data_locked(
    state: &mut ConnState,
    stream_existed: bool,
    app_len: u64,
    flags: u8,
) -> Result<()> {
    let no_op =
        stream_existed && app_len == 0 && flags & (FRAME_FLAG_FIN | FRAME_FLAG_OPEN_METADATA) == 0;
    if no_op {
        let (start, count) = advance_windowed_count(
            state.abuse_window,
            state.no_op_zero_data_window_start,
            state.no_op_zero_data_count,
            state.no_op_zero_data_budget,
            "zero-length DATA budget exceeded",
        )?;
        state.no_op_zero_data_window_start = start;
        state.no_op_zero_data_count = count;
    } else if app_len > 0 || flags & (FRAME_FLAG_FIN | FRAME_FLAG_OPEN_METADATA) != 0 {
        state.no_op_zero_data_window_start = None;
        state.no_op_zero_data_count = 0;
        clear_inbound_ping_budget_locked(state);
    }
    Ok(())
}

fn advance_windowed_count(
    abuse_window: Duration,
    window_start: Option<Instant>,
    count: u64,
    budget: u64,
    message: &'static str,
) -> Result<(Option<Instant>, u64)> {
    let now = Instant::now();
    let mut start = window_start;
    let mut next_count = count;
    if start.is_none_or(|start| now.duration_since(start) > abuse_window) {
        start = Some(now);
        next_count = 0;
    }
    next_count = next_count.saturating_add(1);
    if next_count <= budget {
        Ok((start, next_count))
    } else {
        Err(Error::protocol(message))
    }
}

fn discard_peer_data_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    stream_state: Option<&mut StreamState>,
    app_len: u64,
    cause: LateDataCause,
    hidden: bool,
) -> Result<()> {
    if app_len == 0 {
        return Ok(());
    }
    advance_discarded_session_credit_locked(inner, state, app_len)?;
    let (late_data_received, late_data_cap) = if let Some(stream_state) = stream_state {
        stream_state.late_data_received = stream_state.late_data_received.saturating_add(app_len);
        (stream_state.late_data_received, stream_state.late_data_cap)
    } else {
        (0, u64::MAX)
    };
    record_late_data_discard_locked(state, cause, app_len);
    if hidden {
        state.hidden_unread_bytes_discarded =
            state.hidden_unread_bytes_discarded.saturating_add(app_len);
    }
    check_late_data_caps_locked(state, late_data_received, late_data_cap)
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
    let (late_data_received, late_data_cap, hidden) =
        if let Some(tombstone) = state.tombstones.get_mut(&stream_id) {
            tombstone.late_data_received = tombstone.late_data_received.saturating_add(app_len);
            (
                tombstone.late_data_received,
                tombstone.late_data_cap,
                tombstone.hidden,
            )
        } else {
            (0, u64::MAX, false)
        };
    record_late_data_discard_locked(state, cause, app_len);
    if hidden {
        state.hidden_unread_bytes_discarded =
            state.hidden_unread_bytes_discarded.saturating_add(app_len);
    }
    check_late_data_caps_locked(state, late_data_received, late_data_cap)
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

fn check_late_data_caps_locked(
    state: &ConnState,
    late_data_received: u64,
    late_data_cap: u64,
) -> Result<()> {
    if state.late_data_aggregate_received > state.late_data_aggregate_cap
        || late_data_received > late_data_cap
    {
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
    state.late_data_aggregate_received = state.late_data_aggregate_received.saturating_add(app_len);
    state.recv_session_used = state.recv_session_used.saturating_add(app_len);
    state.received_data_bytes = state.received_data_bytes.saturating_add(app_len);
    state.recv_session_advertised = next_credit_limit(
        state.recv_session_advertised,
        app_len,
        state.recv_session_used,
        0,
        false,
    );

    let mut session_payload = Vec::new();
    append_varint(&mut session_payload, state.recv_session_advertised)?;
    inner.force_queue_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id: 0,
        payload: session_payload,
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
    if !should_flush_receive_credit(
        state.recv_session_advertised,
        state.recv_session_used,
        state.recv_session_pending,
        target,
        session_emergency_threshold(payload),
        replenish_min_pending(target, payload),
        force,
    ) {
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
    stream: &Arc<StreamInner>,
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
    if !should_flush_receive_credit(
        stream_state.recv_advertised,
        stream_state.recv_used,
        stream_state.recv_pending,
        target,
        stream_emergency_threshold(target, payload),
        replenish_min_pending(target, payload),
        force,
    ) {
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
    if !try_queue_max_data(inner, stream_id, desired)? {
        *retry_needed = true;
        return Ok(false);
    }
    stream_state.recv_advertised = desired;
    stream_state.recv_pending = 0;
    Ok(true)
}

fn try_queue_max_data(inner: &Arc<Inner>, stream_id: u64, limit: u64) -> Result<bool> {
    let mut payload = Vec::with_capacity(crate::varint::varint_len(limit)?);
    append_varint(&mut payload, limit)?;
    match inner.try_queue_frame(Frame {
        frame_type: FrameType::MaxData,
        flags: 0,
        stream_id,
        payload,
    }) {
        Ok(()) => Ok(true),
        Err(err) if err.is_urgent_writer_queue_full() || err.is_session_closed() => Ok(false),
        Err(err) => Err(err),
    }
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

fn known_absent_stream_locked(state: &ConnState, inner: &Arc<Inner>, stream_id: u64) -> bool {
    has_terminal_marker_locked(state, stream_id)
        || stream_id_previously_used(state, inner, stream_id)
}

fn has_marker_only_terminal_marker_locked(state: &ConnState, stream_id: u64) -> bool {
    terminal_marker_disposition_locked(state, stream_id).is_some()
        && !state.tombstones.contains_key(&stream_id)
}

fn create_peer_stream(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    stream_id: u64,
    application_visible: bool,
) -> Result<Option<Arc<StreamInner>>> {
    if stream_is_local(inner.negotiated.local_role, stream_id) {
        return Err(Error::protocol("peer referenced unopened local stream"));
    }
    let bidi = stream_is_bidi(stream_id);
    let goaway = if bidi {
        state.local_goaway_bidi
    } else {
        state.local_goaway_uni
    };
    if stream_id > goaway {
        if !application_visible {
            state.hidden_streams_refused = state.hidden_streams_refused.saturating_add(1);
        }
        note_abort_reason_locked(state, ErrorCode::RefusedStream.as_u64());
        queue_abort(inner, stream_id, ErrorCode::RefusedStream.as_u64(), "")?;
        return Ok(None);
    }
    let expected = if bidi {
        state.next_peer_bidi
    } else {
        state.next_peer_uni
    };
    if stream_id != expected {
        return Err(Error::protocol("peer stream id skipped expected id"));
    }
    let visible_backlog_len = state
        .accept_bidi
        .len()
        .saturating_add(state.accept_uni.len());
    let over_stream_limit = if bidi {
        state.active.peer_bidi >= inner.local_preface.settings.max_incoming_streams_bidi
    } else {
        state.active.peer_uni >= inner.local_preface.settings.max_incoming_streams_uni
    };
    let over_visible_limit = visible_backlog_len >= state.accept_backlog_limit;
    let refused = over_stream_limit || (application_visible && over_visible_limit);
    if bidi {
        state.next_peer_bidi = state.next_peer_bidi.saturating_add(4);
    } else {
        state.next_peer_uni = state.next_peer_uni.saturating_add(4);
    }
    if refused {
        if application_visible {
            state.accept_backlog_refused = state.accept_backlog_refused.saturating_add(1);
        } else {
            state.hidden_streams_refused = state.hidden_streams_refused.saturating_add(1);
        }
        note_abort_reason_locked(state, ErrorCode::RefusedStream.as_u64());
        queue_abort(inner, stream_id, ErrorCode::RefusedStream.as_u64(), "")?;
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
        state.next_accept_seq = state.next_accept_seq.saturating_add(1);
        seq
    } else {
        0
    };
    let recv_advertised = initial_receive_window(
        inner.negotiated.local_role,
        &inner.local_preface.settings,
        stream_id,
    );
    let send_max = initial_send_window(
        inner.negotiated.local_role,
        &inner.peer_preface.settings,
        stream_id,
    );
    let stream = Arc::new(StreamInner {
        conn: inner.clone(),
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
            opened_on_wire: false,
            peer_visible: true,
            received_open: false,
            send_used: 0,
            send_max,
            send_blocked_at: None,
            recv_used: 0,
            recv_advertised,
            recv_pending: 0,
            late_data_received: 0,
            late_data_cap: late_data_per_stream_cap(
                state.late_data_per_stream_cap,
                recv_advertised,
                inner.local_preface.settings.max_frame_payload,
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
    state.streams.insert(stream_id, stream.clone());
    clear_ignored_control_budget_locked(state);
    if application_visible {
        if bidi {
            state.accept_bidi.push_back(stream.clone());
        } else {
            state.accept_uni.push_back(stream.clone());
        }
        inner.cond.notify_all();
    }
    Ok(Some(stream))
}

fn handle_max_data(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let (max, n) = match parse_varint(&frame.payload) {
        Ok(parsed) => parsed,
        Err(err) => return maybe_ignore_peer_non_close_error(inner, err),
    };
    if n != frame.payload.len() {
        return maybe_ignore_peer_non_close_error(
            inner,
            Error::protocol("MAX_DATA payload has trailing bytes"),
        );
    }
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
            record_no_op_max_data_locked(&mut state)?;
        }
        inner.cond.notify_all();
        return Ok(());
    }
    if let Some(stream) = state.streams.get(&frame.stream_id).cloned() {
        let peer_visible_update = {
            let mut ss = stream.state.lock().unwrap();
            if stream_fully_terminal(&stream, &ss) {
                record_no_op_max_data_locked(&mut state)?;
                return Ok(());
            }
            if !stream.local_send {
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
                record_no_op_max_data_locked(&mut state)?;
            }
            stream.cond.notify_all();
            inner.cond.notify_all();
            peer_visible_update
        };
        drop(state);
        finish_peer_visible_update(inner, frame.stream_id, peer_visible_update);
        Ok(())
    } else if has_marker_only_terminal_marker_locked(&state, frame.stream_id) {
        Ok(())
    } else if known_absent_stream_locked(&state, inner, frame.stream_id) {
        record_no_op_max_data_locked(&mut state)?;
        Ok(())
    } else {
        Err(Error::protocol("MAX_DATA on previously unseen stream"))
    }
}

fn handle_blocked(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let (_, n) = match parse_varint(&frame.payload) {
        Ok(parsed) => parsed,
        Err(err) => return maybe_ignore_peer_non_close_error(inner, err),
    };
    if n != frame.payload.len() {
        return maybe_ignore_peer_non_close_error(
            inner,
            Error::protocol("BLOCKED payload has trailing bytes"),
        );
    }
    if frame.stream_id == 0 {
        let mut state = inner.state.lock().unwrap();
        if ignore_peer_non_close_locked(&state) {
            return Ok(());
        }
        let has_pending_credit = state.recv_session_pending != 0;
        let queued = flush_pending_session_credit_locked(inner, &mut state, true)?;
        if has_pending_credit || queued {
            clear_no_op_blocked_budget_locked(&mut state);
        } else {
            record_no_op_blocked_locked(&mut state)?;
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
                record_no_op_blocked_locked(&mut state)?;
                return Ok(());
            }
            if !stream.local_recv {
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
            let _ = flush_pending_session_credit_locked(inner, &mut state, true)?;
            let mut retry_needed = false;
            let _ = flush_pending_stream_credit_locked(
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
            if has_pending_credit {
                clear_no_op_blocked_budget_locked(&mut state);
            } else {
                record_no_op_blocked_locked(&mut state)?;
            }
            peer_visible_update
        };
        drop(state);
        finish_peer_visible_update(inner, frame.stream_id, peer_visible_update);
        Ok(())
    } else {
        if has_marker_only_terminal_marker_locked(&state, frame.stream_id) {
            Ok(())
        } else if known_absent_stream_locked(&state, inner, frame.stream_id) {
            record_no_op_blocked_locked(&mut state)?;
            Ok(())
        } else {
            Err(Error::protocol("BLOCKED on previously unseen stream"))
        }
    }
}

fn handle_stop_sending(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let (code, reason) = match parse_error_payload(&frame.payload) {
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
            if known_absent_stream_locked(&conn_state, inner, frame.stream_id) {
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
        stream.cond.notify_all();
        inner.wake_writer_queue_waiters();
        if try_graceful_finish && stream.try_graceful_finish_after_stop_sending()? {
            stream.cond.notify_all();
            return Ok(());
        }

        let mut reply = abort_unopened.then_some(FrameType::Abort);
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
    let (code, reason) = match parse_error_payload(&frame.payload) {
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
        } else if known_absent_stream_locked(&conn_state, inner, frame.stream_id) {
            record_ignored_control_locked(&mut conn_state)?;
            Ok(())
        } else {
            Err(Error::protocol("RESET on previously unseen stream"))
        }
    }
}

fn handle_abort(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    let (code, reason) = match parse_error_payload(&frame.payload) {
        Ok(parsed) => parsed,
        Err(err) => return maybe_ignore_peer_non_close_error(inner, err),
    };
    let mut conn_state = inner.state.lock().unwrap();
    if ignore_peer_non_close_locked(&conn_state) {
        return Ok(());
    }
    let stream = if let Some(stream) = conn_state.streams.get(&frame.stream_id) {
        Some(stream.clone())
    } else if has_marker_only_terminal_marker_locked(&conn_state, frame.stream_id) {
        None
    } else if known_absent_stream_locked(&conn_state, inner, frame.stream_id) {
        record_ignored_control_locked(&mut conn_state)?;
        None
    } else if !stream_is_local(inner.negotiated.local_role, frame.stream_id) {
        let stream = create_peer_stream(inner, &mut conn_state, frame.stream_id, false)?;
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
        let keepalive_sent_at = state
            .keepalive_ping
            .as_ref()
            .filter(|ping| {
                pong_payload_matches_ping(&frame.payload, &ping.payload, ping.accepts_padded_pong)
            })
            .map(|ping| ping.sent_at);
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

fn handle_goaway(inner: &Arc<Inner>, frame: Frame) -> Result<()> {
    {
        let state = inner.state.lock().unwrap();
        if ignore_session_control_while_closing_locked(&state) {
            return Ok(());
        }
    }
    let payload = match parse_goaway_payload(&frame.payload) {
        Ok(payload) => payload,
        Err(err) => return maybe_ignore_peer_non_close_error(inner, err),
    };
    let reclaimed = {
        let mut state = inner.state.lock().unwrap();
        if ignore_session_control_while_closing_locked(&state) {
            return Ok(());
        }
        validate_goaway_watermark_for_direction(payload.last_accepted_bidi, true)?;
        validate_goaway_watermark_creator(inner.negotiated.local_role, payload.last_accepted_bidi)?;
        validate_goaway_watermark_for_direction(payload.last_accepted_uni, false)?;
        validate_goaway_watermark_creator(inner.negotiated.local_role, payload.last_accepted_uni)?;
        if payload.last_accepted_bidi > state.peer_goaway_bidi
            || payload.last_accepted_uni > state.peer_goaway_uni
        {
            return Err(Error::protocol("GOAWAY watermarks must be non-increasing"));
        }
        retain_peer_goaway_error_locked(inner, &mut state, payload.code, payload.reason);
        let changed = payload.last_accepted_bidi < state.peer_goaway_bidi
            || payload.last_accepted_uni < state.peer_goaway_uni;
        if !changed {
            record_ignored_control_locked(&mut state)?;
            return Ok(());
        }
        state.peer_goaway_bidi = payload.last_accepted_bidi;
        state.peer_goaway_uni = payload.last_accepted_uni;
        let mut reclaimed = reclaim_unseen_local_streams_after_goaway(&mut state, true);
        reclaimed.extend(reclaim_unseen_local_streams_after_goaway(&mut state, false));
        reclaim_provisionals_after_goaway(&mut state, true);
        reclaim_provisionals_after_goaway(&mut state, false);
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
    let (metadata, valid) = match parse_priority_update_metadata(&frame.payload[n..]) {
        Ok(parsed) => parsed,
        Err(err) => return maybe_ignore_peer_non_close_error(inner, err),
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
        let before = ss.metadata.clone();
        let caps = inner.negotiated.capabilities;
        if metadata.priority.is_some() && capabilities_can_carry_priority_update(caps) {
            ss.metadata.priority = metadata.priority;
        }
        if metadata.group.is_some() && capabilities_can_carry_group_update(caps) {
            ss.metadata.group = normalize_stream_group(metadata.group);
        }
        if ss.metadata == before {
            record_no_op_priority_update_locked(&mut state)?;
        } else {
            ss.metadata_revision = ss.metadata_revision.saturating_add(1);
            if should_record_group_rebucket_churn_locked(inner, &stream, &ss, before.group) {
                record_group_rebucket_churn_locked(&mut state)?;
            }
            clear_no_op_priority_update_budget_locked(&mut state);
        }
    } else if has_marker_only_terminal_marker_locked(&state, frame.stream_id) {
        return Ok(());
    } else if known_absent_stream_locked(&state, inner, frame.stream_id) {
        record_no_op_priority_update_locked(&mut state)?;
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

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
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
