use super::egress::spawn_writer;
use super::ingress::spawn_reader;
use super::liveness::{
    build_ping_payload_locked, canceled_ping_payload, configured_keepalive_timeout,
    effective_keepalive_timeout_locked, init_keepalive_jitter_state,
    initialize_keepalive_schedules, next_session_ping_token_locked, note_local_ping_sent_locked,
    ping_payload_len, ping_payload_limit, reset_keepalive_idle_schedules_locked,
};
use super::queue::{StreamDiscardStats, WriteQueue, WriteQueueLimits};
use super::state::{
    clear_accepted_backlog_accounting, clear_stream_open_info_locked,
    clear_stream_open_prefix_locked, clear_stream_receive_credit_locked, compact_retained_bytes,
    emit_event, ensure_local_open_memory_cap_locked, ensure_session_open,
    fail_pending_pings_locked, marker_only_retained_count_locked, maybe_release_active_count,
    memory_stats_locked, notify_all_streams, provisional_available_count,
    reap_expired_provisionals_locked, release_discarded_queued_stream_frames_locked,
    release_session_receive_buffered_locked, release_session_runtime_state_locked,
    retained_open_info_available, shrink_accept_queue_locked, shrink_provisional_queue_locked,
    stream_fully_terminal, take_session_closed_event_locked, take_stream_event_locked,
    tracked_retained_state_memory_locked,
};
use super::types::*;
use crate::config::{
    default_accept_backlog_bytes_limit, default_late_data_aggregate_cap, Config, OpenOptions,
    DEFAULT_ACCEPT_BACKLOG_LIMIT, DEFAULT_CLOSE_DRAIN_TIMEOUT,
    DEFAULT_INBOUND_CONTROL_BYTES_BUDGET_FLOOR, DEFAULT_INBOUND_EXT_BYTES_BUDGET_FLOOR,
    DEFAULT_PENDING_CONTROL_BYTES_BUDGET_FLOOR, DEFAULT_PENDING_PRIORITY_BYTES_BUDGET_FLOOR,
    DEFAULT_PER_STREAM_QUEUED_DATA_HIGH_WATERMARK_FLOOR, DEFAULT_RETAINED_OPEN_INFO_BYTES_BUDGET,
    DEFAULT_RETAINED_PEER_REASON_BYTES_BUDGET, DEFAULT_SESSION_QUEUED_DATA_HIGH_WATERMARK_FLOOR,
    DEFAULT_URGENT_QUEUE_MAX_BYTES_FLOOR,
};
use crate::error::{
    Error, ErrorCode, ErrorDirection, ErrorOperation, ErrorScope, ErrorSource, Result,
    TerminationKind,
};
use crate::event::EventType;
#[cfg(test)]
use crate::frame::FRAME_FLAG_FIN;
use crate::frame::{Frame, FrameType};
use crate::open_send::{OpenRequest, OpenSend, WritePayload};
use crate::payload::{
    build_code_payload, build_go_away_payload, build_go_away_payload_capped,
    build_open_metadata_prefix, normalize_stream_group, StreamMetadata,
};
use crate::preface::{negotiate_prefaces, read_preface, Negotiated, Preface};
use crate::protocol::Role;
use crate::stream_id::{
    first_local_stream_id, first_peer_stream_id, projected_local_open_id,
    validate_go_away_watermark_creator, validate_go_away_watermark_for_direction,
};
use crate::varint::MAX_VARINT62;
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

const ESTABLISHMENT_FAILURE_WRITE_WAIT: Duration = Duration::from_millis(250);
const ESTABLISHMENT_SUCCESS_WRITE_WAIT: Duration = Duration::from_secs(1);
const ESTABLISHMENT_CLOSE_DRAIN_DELAY: Duration = Duration::from_millis(10);
const ESTABLISHMENT_EXPEDITE_TIMEOUT: Duration = Duration::from_millis(1);
const CONN_READ_BUFFER_SIZE: usize = 512;
const CLOSE_DRAIN_TIMEOUT_MAX: Duration = Duration::from_secs(5);
const CLOSE_DRAIN_RTT_SLACK: Duration = Duration::from_millis(100);
const MAX_CONDVAR_TIMED_WAIT: Duration = Duration::from_secs(3600);

fn session_result<T>(result: Result<T>, operation: ErrorOperation) -> Result<T> {
    result.map_err(|mut err| {
        if err.scope() == ErrorScope::Stream {
            if err.operation() == ErrorOperation::Unknown {
                err = err.with_operation(operation);
            }
            if err.direction() == ErrorDirection::Unknown {
                err.with_direction(ErrorDirection::Both)
            } else {
                err
            }
        } else {
            err.with_session_context(operation)
        }
    })
}

fn establishment_error(mut err: Error) -> Error {
    if err.source() == ErrorSource::Unknown {
        err = err.with_source(ErrorSource::Local);
    }
    if err.termination_kind() == TerminationKind::Unknown {
        err.with_termination_kind(TerminationKind::SessionTermination)
    } else {
        err
    }
}

trait EstablishmentControl {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn close(&self) -> io::Result<()>;
}

struct DuplexTransportControlAdapter {
    control: Arc<dyn DuplexTransportControl>,
}

impl EstablishmentControl for DuplexTransportControlAdapter {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.control.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.control.set_write_timeout(timeout)
    }

    fn close(&self) -> io::Result<()> {
        self.control.close()
    }
}

impl RuntimeTransportControl for DuplexTransportControlAdapter {
    fn close(&self) {
        let _ = self.control.close();
    }
}

struct PrefaceWriter<W> {
    result: Receiver<(W, Result<()>)>,
}

fn spawn_preface_writer<W>(mut writer: W, payload: Vec<u8>) -> PrefaceWriter<W>
where
    W: Write + Send + 'static,
{
    let (tx, rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = match writer.write_all(&payload) {
            Ok(()) => writer.flush().map_err(Error::from),
            Err(err) => Err(Error::from(err)),
        };
        let _ = tx.send((writer, result));
    });
    PrefaceWriter { result: rx }
}

fn wait_preface_writer<W>(
    writer: PrefaceWriter<W>,
    timeout: Option<Duration>,
) -> Result<(W, Result<()>)> {
    if let Some(timeout) = timeout {
        match writer.result.recv_timeout(timeout) {
            Ok(result) => Ok(result),
            Err(RecvTimeoutError::Timeout) => Err(establishment_write_timeout_error()),
            Err(RecvTimeoutError::Disconnected) => Err(Error::new(
                ErrorCode::Internal,
                "local preface writer panicked",
            )),
        }
    } else {
        writer
            .result
            .recv()
            .map_err(|_| Error::new(ErrorCode::Internal, "local preface writer panicked"))
    }
}

fn establishment_timeout_error(message: &'static str) -> Error {
    Error::new(ErrorCode::Internal, message)
        .with_source(ErrorSource::Local)
        .with_termination_kind(TerminationKind::Timeout)
}

fn establishment_write_timeout_error() -> Error {
    establishment_timeout_error("local preface write stalled during establishment")
}

fn establishment_read_timeout_error() -> Error {
    establishment_timeout_error("peer preface read stalled during establishment")
}

fn normalize_establishment_read_error(err: Error, read_deadline_armed: bool) -> Error {
    if read_deadline_armed && err.is_timeout() {
        establishment_read_timeout_error()
            .with_scope(err.scope())
            .with_operation(err.operation())
            .with_direction(err.direction())
    } else {
        err
    }
}

fn normalize_establishment_write_error(err: Error, write_deadline_armed: bool) -> Error {
    if write_deadline_armed && err.is_timeout() {
        establishment_write_timeout_error()
    } else {
        err
    }
}

fn arm_establishment_read_timeout(
    control: Option<&dyn EstablishmentControl>,
    timeout: Duration,
) -> bool {
    control.is_some_and(|control| control.set_read_timeout(Some(timeout)).is_ok())
}

fn arm_establishment_write_timeout(
    control: Option<&dyn EstablishmentControl>,
    timeout: Duration,
) -> bool {
    control.is_some_and(|control| control.set_write_timeout(Some(timeout)).is_ok())
}

fn clear_establishment_read_timeout(
    control: Option<&dyn EstablishmentControl>,
    armed: bool,
) -> Result<()> {
    if !armed {
        return Ok(());
    }
    if let Some(control) = control {
        control.set_read_timeout(None).map_err(Error::from)?;
    }
    Ok(())
}

fn clear_establishment_write_timeout(
    control: Option<&dyn EstablishmentControl>,
    armed: bool,
) -> Result<()> {
    if !armed {
        return Ok(());
    }
    if let Some(control) = control {
        control.set_write_timeout(None).map_err(Error::from)?;
    }
    Ok(())
}

fn expedite_establishment_write_timeout(control: Option<&dyn EstablishmentControl>, armed: bool) {
    if !armed {
        return;
    }
    if let Some(control) = control {
        let _ = control.set_write_timeout(Some(ESTABLISHMENT_EXPEDITE_TIMEOUT));
    }
}

fn close_establishment_transport(control: Option<&dyn EstablishmentControl>) {
    if let Some(control) = control {
        let _ = control.close();
    }
}

fn wait_timeout_for_control(
    control: Option<&dyn EstablishmentControl>,
    timeout: Duration,
) -> Option<Duration> {
    if control.is_some() {
        Some(timeout)
    } else {
        None
    }
}

fn finish_establishment_failure<W>(
    control: Option<&dyn EstablishmentControl>,
    writer: PrefaceWriter<W>,
    write_deadline_armed: bool,
    local_preface: &Preface,
    peer_preface: Option<&Preface>,
    err: &Error,
) where
    W: Write + Send + 'static,
{
    expedite_establishment_write_timeout(control, write_deadline_armed);
    match wait_preface_writer(
        writer,
        wait_timeout_for_control(control, ESTABLISHMENT_FAILURE_WRITE_WAIT),
    ) {
        Ok((mut writer, Ok(()))) => {
            let close_deadline_armed =
                arm_establishment_write_timeout(control, ESTABLISHMENT_FAILURE_WRITE_WAIT);
            if control.is_none() || close_deadline_armed {
                if emit_establishment_close(&mut writer, local_preface, peer_preface, err).is_ok() {
                    thread::sleep(ESTABLISHMENT_CLOSE_DRAIN_DELAY);
                }
                let _ = clear_establishment_write_timeout(control, close_deadline_armed);
            }
            close_establishment_transport(control);
        }
        Ok((_, Err(_))) | Err(_) => {
            close_establishment_transport(control);
        }
    }
}

impl Conn {
    pub fn new<T>(transport: T) -> Result<Self>
    where
        T: DuplexConnection,
    {
        Self::with_config(transport, Config::default())
    }

    pub fn with_config<T>(transport: T, config: Config) -> Result<Self>
    where
        T: DuplexConnection,
    {
        let result = transport
            .into_transport()
            .and_then(|transport| Self::with_transport_config(transport, config));
        session_result(result, ErrorOperation::Open)
    }

    pub fn client<T>(transport: T) -> Result<Self>
    where
        T: DuplexConnection,
    {
        Self::client_with_config(transport, Config::default())
    }

    pub fn client_with_config<T>(transport: T, mut config: Config) -> Result<Self>
    where
        T: DuplexConnection,
    {
        config.role = Role::Initiator;
        let result = transport
            .into_transport()
            .and_then(|transport| Self::with_transport_config(transport, config));
        session_result(result, ErrorOperation::Open)
    }

    pub fn server<T>(transport: T) -> Result<Self>
    where
        T: DuplexConnection,
    {
        Self::server_with_config(transport, Config::default())
    }

    pub fn server_with_config<T>(transport: T, mut config: Config) -> Result<Self>
    where
        T: DuplexConnection,
    {
        config.role = Role::Responder;
        let result = transport
            .into_transport()
            .and_then(|transport| Self::with_transport_config(transport, config));
        session_result(result, ErrorOperation::Open)
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.local_addr
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.peer_addr
    }

    fn with_transport_config<R, W>(transport: DuplexTransport<R, W>, config: Config) -> Result<Self>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let DuplexTransport {
            reader,
            writer,
            control,
            local_addr,
            peer_addr,
        } = transport;
        let control = control.map(|control| Arc::new(DuplexTransportControlAdapter { control }));
        let establishment_control = control
            .as_deref()
            .map(|control| control as &dyn EstablishmentControl);
        let runtime_control = control
            .as_ref()
            .map(|control| Arc::clone(control) as Arc<dyn RuntimeTransportControl>);
        Self::with_config_control(
            reader,
            writer,
            config,
            establishment_control,
            runtime_control,
            local_addr,
            peer_addr,
        )
    }

    fn with_config_control<R, W>(
        mut reader: R,
        writer: W,
        config: Config,
        control: Option<&dyn EstablishmentControl>,
        runtime_control: Option<Arc<dyn RuntimeTransportControl>>,
        local_addr: Option<SocketAddr>,
        peer_addr: Option<SocketAddr>,
    ) -> Result<Self>
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let config = config.normalized()?;
        let local_preface = config.local_preface()?;
        let local_preface_payload = config.local_preface_payload(&local_preface)?;
        let write_deadline_armed =
            arm_establishment_write_timeout(control, ESTABLISHMENT_SUCCESS_WRITE_WAIT);
        let read_deadline_armed =
            arm_establishment_read_timeout(control, ESTABLISHMENT_SUCCESS_WRITE_WAIT);
        let write_preface = spawn_preface_writer(writer, local_preface_payload);

        let peer_preface = match read_preface(&mut reader) {
            Ok(preface) => preface,
            Err(err) => {
                let err = normalize_establishment_read_error(err, read_deadline_armed);
                let _ = clear_establishment_read_timeout(control, read_deadline_armed);
                finish_establishment_failure(
                    control,
                    write_preface,
                    write_deadline_armed,
                    &local_preface,
                    None,
                    &err,
                );
                return Err(establishment_error(err));
            }
        };
        if let Err(err) = clear_establishment_read_timeout(control, read_deadline_armed) {
            let err = establishment_error(err);
            finish_establishment_failure(
                control,
                write_preface,
                write_deadline_armed,
                &local_preface,
                Some(&peer_preface),
                &err,
            );
            return Err(err);
        }
        let negotiated = match negotiate_prefaces(&local_preface, &peer_preface) {
            Ok(negotiated) => negotiated,
            Err(err) => {
                finish_establishment_failure(
                    control,
                    write_preface,
                    write_deadline_armed,
                    &local_preface,
                    Some(&peer_preface),
                    &err,
                );
                return Err(establishment_error(err));
            }
        };
        let (writer, write_result) = match wait_preface_writer(
            write_preface,
            wait_timeout_for_control(control, ESTABLISHMENT_SUCCESS_WRITE_WAIT),
        ) {
            Ok(result) => result,
            Err(err) => {
                close_establishment_transport(control);
                return Err(establishment_error(normalize_establishment_write_error(
                    err,
                    write_deadline_armed,
                )));
            }
        };
        if let Err(err) = write_result.map_err(|err| {
            establishment_error(normalize_establishment_write_error(
                err,
                write_deadline_armed,
            ))
        }) {
            close_establishment_transport(control);
            return Err(err);
        }
        if let Err(err) = clear_establishment_write_timeout(control, write_deadline_armed) {
            close_establishment_transport(control);
            return Err(establishment_error(err));
        }
        let local_role = negotiated.local_role;
        let local_settings = local_preface.settings;
        let peer_settings = peer_preface.settings;

        let urgent_queue_max_bytes = match config.urgent_queue_max_bytes {
            Some(bytes) => bytes,
            None => default_urgent_queue_max_bytes(local_settings, peer_settings),
        };
        let per_stream_data_hwm = match config.per_stream_queued_data_high_watermark {
            Some(bytes) => bytes,
            None => default_per_stream_queued_data_high_watermark(local_settings, peer_settings),
        }
        .max(1);
        let session_data_hwm = match config.session_queued_data_high_watermark {
            Some(bytes) => bytes,
            None => default_session_queued_data_high_watermark(per_stream_data_hwm),
        }
        .max(1);
        let pending_control_budget = match config.pending_control_bytes_budget {
            Some(bytes) => bytes,
            None => default_pending_control_bytes_budget(peer_settings, local_settings),
        };
        let pending_priority_budget = match config.pending_priority_bytes_budget {
            Some(bytes) => bytes,
            None => default_pending_priority_bytes_budget(peer_settings, local_settings),
        };
        let inbound_control_bytes_budget = match config.inbound_control_bytes_budget {
            Some(bytes) => bytes,
            None => default_inbound_control_bytes_budget(local_settings),
        };
        let inbound_ext_bytes_budget = match config.inbound_ext_bytes_budget {
            Some(bytes) => bytes,
            None => default_inbound_ext_bytes_budget(local_settings),
        };
        let inbound_mixed_frame_budget = match config.inbound_mixed_frame_budget {
            Some(frames) => frames,
            None => config
                .inbound_control_frame_budget
                .max(config.inbound_ext_frame_budget),
        };
        let inbound_mixed_bytes_budget = match config.inbound_mixed_bytes_budget {
            Some(bytes) => bytes,
            None => inbound_control_bytes_budget.max(inbound_ext_bytes_budget),
        };
        let accept_backlog_limit = config
            .accept_backlog_limit
            .unwrap_or(DEFAULT_ACCEPT_BACKLOG_LIMIT);
        let hidden_tombstone_limit = match config.hidden_control_opened_limit {
            Some(limit) => limit,
            None => hidden_control_opened_limit(accept_backlog_limit),
        };
        let write_queue = Arc::new(WriteQueue::new(WriteQueueLimits {
            max_bytes: config.write_queue_max_bytes,
            urgent_max_bytes: urgent_queue_max_bytes,
            session_data_max_bytes: session_data_hwm,
            per_stream_data_max_bytes: per_stream_data_hwm,
            pending_control_max_bytes: pending_control_budget,
            pending_priority_max_bytes: pending_priority_budget,
            max_batch_bytes: default_write_batch_cost_limit(peer_settings.max_frame_payload),
            max_batch_frames: config.write_batch_max_frames,
        }));
        let now = Instant::now();
        let inner = Arc::new(Inner {
            write_queue,
            transport_control: runtime_control,
            local_addr,
            peer_addr,
            state: Mutex::new(ConnState {
                state: SessionState::Ready,
                close_error: None,
                peer_close_error: None,
                peer_go_away_error: None,
                session_closed_event_sent: false,
                graceful_close_active: false,
                ignore_peer_non_close: false,
                streams: HashMap::new(),
                scheduler: Default::default(),
                inflight_data_by_stream: HashMap::new(),
                tombstones: HashMap::new(),
                tombstone_order: VecDeque::new(),
                hidden_tombstone_order: VecDeque::new(),
                tombstone_limit: config.tombstone_limit,
                hidden_tombstone_limit,
                hidden_tombstones: 0,
                used_markers: HashMap::new(),
                used_marker_order: VecDeque::new(),
                used_marker_ranges: Vec::new(),
                used_marker_range_mode: false,
                used_marker_limit: config
                    .marker_only_used_stream_limit
                    .unwrap_or(config.used_marker_limit),
                provisional_bidi: VecDeque::new(),
                provisional_uni: VecDeque::new(),
                accept_bidi: VecDeque::new(),
                accept_uni: VecDeque::new(),
                accept_backlog_limit,
                accept_limit_bidi: u64_to_usize_saturating(
                    local_settings.max_incoming_streams_bidi,
                ),
                accept_limit_uni: u64_to_usize_saturating(local_settings.max_incoming_streams_uni),
                accept_backlog_bytes: 0,
                accept_backlog_bytes_limit: config.accept_backlog_bytes_limit.unwrap_or_else(
                    || default_accept_backlog_bytes_limit(local_settings.max_frame_payload),
                ),
                accept_backlog_refused: 0,
                retained_open_info_bytes: 0,
                retained_open_info_bytes_budget: config
                    .retained_open_info_bytes_budget
                    .unwrap_or(DEFAULT_RETAINED_OPEN_INFO_BYTES_BUDGET),
                retained_peer_reason_bytes: 0,
                retained_peer_reason_bytes_budget: config
                    .retained_peer_reason_bytes_budget
                    .unwrap_or(DEFAULT_RETAINED_PEER_REASON_BYTES_BUDGET),
                reset_reason_counts: HashMap::new(),
                reset_reason_overflow: 0,
                abort_reason_counts: HashMap::new(),
                abort_reason_overflow: 0,
                next_accept_seq: 1,
                next_local_bidi: first_local_stream_id(local_role, true),
                next_local_uni: first_local_stream_id(local_role, false),
                max_provisional_bidi: config.max_provisional_streams_bidi,
                max_provisional_uni: config.max_provisional_streams_uni,
                provisional_open_limited_count: 0,
                provisional_open_expired_count: 0,
                next_peer_bidi: first_peer_stream_id(local_role, true),
                next_peer_uni: first_peer_stream_id(local_role, false),
                active: ActiveStreamStats::default(),
                send_session_used: 0,
                send_session_max: peer_settings.initial_max_data,
                send_session_blocked_at: None,
                recv_session_used: 0,
                recv_session_buffered: 0,
                recv_session_retained: 0,
                recv_session_advertised: local_settings.initial_max_data,
                recv_session_pending: 0,
                recv_replenish_retry: false,
                late_data_per_stream_cap: config.late_data_per_stream_cap,
                late_data_aggregate_received: 0,
                late_data_aggregate_cap: match config.late_data_aggregate_cap {
                    Some(cap) => cap,
                    None => default_late_data_aggregate_cap(local_settings.max_frame_payload),
                },
                ignored_control_window_start: None,
                ignored_control_count: 0,
                ignored_control_budget: config.ignored_control_budget,
                no_op_zero_data_window_start: None,
                no_op_zero_data_count: 0,
                no_op_zero_data_budget: config.no_op_zero_data_budget,
                inbound_ping_window_start: None,
                inbound_ping_count: 0,
                inbound_ping_budget: config.inbound_ping_budget,
                no_op_max_data_window_start: None,
                no_op_max_data_count: 0,
                no_op_max_data_budget: config.no_op_max_data_budget,
                no_op_blocked_window_start: None,
                no_op_blocked_count: 0,
                no_op_blocked_budget: config.no_op_blocked_budget,
                no_op_priority_update_window_start: None,
                no_op_priority_update_count: 0,
                no_op_priority_update_budget: config.no_op_priority_update_budget,
                dropped_priority_update_count: 0,
                dropped_local_priority_update_count: 0,
                late_data_after_close_read_bytes: 0,
                late_data_after_reset_bytes: 0,
                late_data_after_abort_bytes: 0,
                superseded_terminal_signal_count: 0,
                hidden_streams_refused: 0,
                hidden_streams_reaped: 0,
                hidden_unread_bytes_discarded: 0,
                skipped_close_on_dead_io_count: 0,
                close_frame_flush_error_count: 0,
                close_completion_timeout_count: 0,
                graceful_close_timeout_count: 0,
                keepalive_timeout_count: 0,
                abuse_window: config.abuse_window,
                inbound_control_window_start: None,
                inbound_control_frames: 0,
                inbound_control_bytes: 0,
                inbound_control_frame_budget: config.inbound_control_frame_budget,
                inbound_control_bytes_budget,
                inbound_ext_window_start: None,
                inbound_ext_frames: 0,
                inbound_ext_bytes: 0,
                inbound_ext_frame_budget: config.inbound_ext_frame_budget,
                inbound_ext_bytes_budget,
                inbound_mixed_window_start: None,
                inbound_mixed_frames: 0,
                inbound_mixed_bytes: 0,
                inbound_mixed_frame_budget,
                inbound_mixed_bytes_budget,
                group_rebucket_churn_window_start: None,
                group_rebucket_churn_count: 0,
                group_rebucket_churn_budget: config.group_rebucket_churn_budget,
                hidden_abort_churn_window: config.hidden_abort_churn_window,
                hidden_abort_churn_window_start: None,
                hidden_abort_churn_count: 0,
                hidden_abort_churn_budget: config.hidden_abort_churn_budget,
                visible_terminal_churn_window: config.visible_terminal_churn_window,
                visible_terminal_churn_window_start: None,
                visible_terminal_churn_count: 0,
                visible_terminal_churn_budget: config.visible_terminal_churn_budget,
                local_go_away_bidi: MAX_VARINT62,
                local_go_away_uni: MAX_VARINT62,
                local_go_away_issued: false,
                peer_go_away_bidi: MAX_VARINT62,
                peer_go_away_uni: MAX_VARINT62,
                ping_waiter: None,
                canceled_ping_payload: None,
                keepalive_ping: None,
                last_inbound_at: now,
                last_outbound_at: now,
                send_rate_estimate: 0,
                flush_count: 0,
                last_flush_at: None,
                last_flush_frames: 0,
                last_flush_bytes: 0,
                last_open_latency: None,
                last_ping_rtt: None,
                last_control_progress_at: now,
                last_stream_progress_at: None,
                last_application_progress_at: None,
                last_ping_sent_at: None,
                last_pong_at: None,
                blocked_write_total: Duration::ZERO,
                read_idle_ping_due_at: None,
                write_idle_ping_due_at: None,
                max_ping_due_at: None,
                keepalive_jitter_state: init_keepalive_jitter_state(
                    local_preface.tie_breaker_nonce ^ peer_preface.tie_breaker_nonce,
                ),
                ping_nonce_state: init_keepalive_jitter_state(
                    (local_preface.tie_breaker_nonce << 1) ^ peer_preface.tie_breaker_nonce,
                ),
                last_ping_padding_len: 0,
                sent_frames: 0,
                received_frames: 0,
                sent_data_bytes: 0,
                received_data_bytes: 0,
                accepted_streams: 0,
            }),
            cond: Condvar::new(),
            local_preface,
            peer_preface,
            negotiated,
            close_drain_timeout: config.close_drain_timeout,
            go_away_drain_interval: config.go_away_drain_interval,
            session_memory_cap: config.session_memory_cap,
            session_data_high_watermark: session_data_hwm,
            per_stream_data_high_watermark: per_stream_data_hwm,
            stop_sending_graceful_drain_window: config.stop_sending_graceful_drain_window,
            stop_sending_graceful_tail_cap: config.stop_sending_graceful_tail_cap,
            keepalive_interval: config.keepalive_interval,
            keepalive_max_ping_interval: config.keepalive_max_ping_interval,
            keepalive_timeout: configured_keepalive_timeout(
                config.keepalive_interval,
                config.keepalive_timeout,
            ),
            ping_padding: config.ping_padding,
            ping_padding_min_bytes: config.ping_padding_min_bytes,
            ping_padding_max_bytes: config.ping_padding_max_bytes,
            event_handler: config.event_handler.clone(),
            event_dispatch: Mutex::new(EventDispatchState {
                emitting: false,
                queue: VecDeque::new(),
            }),
        });

        initialize_keepalive_schedules(&inner, now);
        spawn_writer(Arc::clone(&inner), writer);
        spawn_reader(
            Arc::clone(&inner),
            io::BufReader::with_capacity(CONN_READ_BUFFER_SIZE, reader),
        );
        Ok(Self { inner })
    }

    pub fn open_stream(&self) -> Result<Stream> {
        self.open_stream_with(OpenRequest::new())
    }

    pub fn open_uni_stream(&self) -> Result<SendStream> {
        self.open_uni_stream_with(OpenRequest::new())
    }

    pub fn open_stream_with(&self, request: impl Into<OpenRequest>) -> Result<Stream> {
        let (opts, timeout) = request.into().into_parts();
        if let Some(timeout) = timeout {
            session_result(
                ensure_positive_timeout("open", timeout),
                ErrorOperation::Open,
            )?;
        }
        let stream = session_result(self.open_stream_inner(true, opts), ErrorOperation::Open)?;
        Ok(Stream { inner: stream })
    }

    pub fn open_uni_stream_with(&self, request: impl Into<OpenRequest>) -> Result<SendStream> {
        let (opts, timeout) = request.into().into_parts();
        if let Some(timeout) = timeout {
            session_result(
                ensure_positive_timeout("open", timeout),
                ErrorOperation::Open,
            )?;
        }
        let stream = session_result(self.open_stream_inner(false, opts), ErrorOperation::Open)?;
        Ok(SendStream { inner: stream })
    }

    pub fn open_and_send<'a>(&self, request: impl Into<OpenSend<'a>>) -> Result<Stream> {
        let (opts, payload, timeout) = request.into().into_parts();
        let requested = payload.checked_len()?;
        let start = Instant::now();
        let mut open = OpenRequest::new().options(opts);
        if let Some(timeout) = timeout {
            open = open.timeout(timeout);
        }
        let stream = self.open_stream_with(open)?;
        if requested == 0 {
            return Ok(stream);
        }
        let write_result: Result<()> = (|| {
            let timeout = timeout
                .map(|timeout| remaining_open_send_write_timeout(start, timeout))
                .transpose()?;
            match (payload, timeout) {
                (WritePayload::Bytes(data), Some(timeout)) => {
                    stream.write_all_timeout(WritePayload::Bytes(data), timeout)?;
                }
                (WritePayload::Bytes(data), None) => {
                    stream.write_all(WritePayload::Bytes(data))?;
                }
                (WritePayload::Vectored(parts), Some(timeout)) => {
                    stream.write_all_timeout(WritePayload::Vectored(parts), timeout)?;
                }
                (WritePayload::Vectored(parts), None) => {
                    stream.write_all(WritePayload::Vectored(parts))?;
                }
            }
            Ok(())
        })();
        if let Err(err) = write_result {
            let code = err.numeric_code().unwrap_or(ErrorCode::Cancelled.as_u64());
            let _ = stream.close_with_error(code, "open_and_send failed");
            return Err(err);
        }
        Ok(stream)
    }

    pub fn open_uni_and_send<'a>(&self, request: impl Into<OpenSend<'a>>) -> Result<SendStream> {
        let (opts, payload, timeout) = request.into().into_parts();
        let requested = payload.checked_len()?;
        let start = Instant::now();
        let mut open = OpenRequest::new().options(opts);
        if let Some(timeout) = timeout {
            open = open.timeout(timeout);
        }
        let stream = self.open_uni_stream_with(open)?;
        let write_result: Result<()> = (|| {
            let timeout = timeout
                .map(|timeout| remaining_open_send_write_timeout(start, timeout))
                .transpose()?;
            let n = match (payload, timeout) {
                (WritePayload::Bytes(data), Some(timeout)) => {
                    stream.write_final_timeout(WritePayload::Bytes(data), timeout)?
                }
                (WritePayload::Bytes(data), None) => {
                    stream.write_final(WritePayload::Bytes(data))?
                }
                (WritePayload::Vectored(parts), Some(timeout)) => {
                    stream.write_vectored_final_timeout(parts, timeout)?
                }
                (WritePayload::Vectored(parts), None) => stream.write_vectored_final(parts)?,
            };
            validate_open_send_progress(n, requested)?;
            Ok(())
        })();
        if let Err(err) = write_result {
            let code = err.numeric_code().unwrap_or(ErrorCode::Cancelled.as_u64());
            let _ = stream.close_with_error(code, "open_uni_and_send failed");
            return Err(err);
        }
        Ok(stream)
    }

    fn open_stream_inner(&self, bidi: bool, opts: OpenOptions) -> Result<Arc<StreamInner>> {
        opts.validate()?;
        let peer_settings = self.inner.peer_preface.settings;
        let caps = self.inner.negotiated.capabilities;
        let open_prefix = compact_retained_bytes(build_open_metadata_prefix(
            caps,
            opts.initial_priority(),
            opts.initial_group(),
            opts.open_info_bytes(),
            peer_settings.max_frame_payload,
        )?);

        let mut state = self.inner.state.lock().unwrap();
        ensure_session_open(&state)?;
        if state.graceful_close_active {
            return Err(Error::session_closed());
        }
        reap_expired_provisionals_locked(&mut state, bidi, None);
        let (next_id, goaway, queued, configured_cap, active_local, peer_stream_limit) = if bidi {
            (
                state.next_local_bidi,
                state.peer_go_away_bidi,
                state.provisional_bidi.len(),
                state.max_provisional_bidi,
                state.active.local_bidi,
                self.inner.peer_preface.settings.max_incoming_streams_bidi,
            )
        } else {
            (
                state.next_local_uni,
                state.peer_go_away_uni,
                state.provisional_uni.len(),
                state.max_provisional_uni,
                state.active.local_uni,
                self.inner.peer_preface.settings.max_incoming_streams_uni,
            )
        };
        let projected_id = projected_local_open_id(next_id, queued);
        if projected_id > MAX_VARINT62 {
            return Err(Error::new(ErrorCode::Protocol, "stream id overflow"));
        }
        if projected_id > goaway {
            return Err(
                Error::new(ErrorCode::RefusedStream, "peer GOAWAY refuses local open")
                    .with_source(ErrorSource::Remote),
            );
        }
        let available_by_goaway = provisional_available_count(next_id, goaway);
        if available_by_goaway == 0 {
            return Err(
                Error::new(ErrorCode::RefusedStream, "peer GOAWAY refuses local open")
                    .with_source(ErrorSource::Remote),
            );
        }
        if active_local >= peer_stream_limit
            || active_local.saturating_add(usize_to_u64_saturating(queued)) >= peer_stream_limit
        {
            return Err(Error::new(
                ErrorCode::RefusedStream,
                "peer incoming stream limit reached",
            )
            .with_source(ErrorSource::Remote));
        }
        let open_info_len = opts.open_info_bytes().len();
        if open_info_len > retained_open_info_available(&state) {
            return Err(
                Error::new(ErrorCode::StreamLimit, "zmux: open_info budget exceeded")
                    .with_source(ErrorSource::Local),
            );
        }
        let additional_retained_bytes = open_info_len.saturating_add(open_prefix.len());
        ensure_local_open_memory_cap_locked(&self.inner, &state, additional_retained_bytes)?;
        let cap = configured_cap.min(available_by_goaway);
        if queued >= cap {
            state.provisional_open_limited_count =
                state.provisional_open_limited_count.saturating_add(1);
            return Err(Error::local("zmux: provisional open limit reached"));
        }
        let (initial_priority, initial_group, open_info) = opts.into_parts();
        let open_info = compact_retained_bytes(open_info);
        let retained_open_info_bytes = open_info.len();
        let stream = Arc::new(StreamInner {
            conn: Arc::clone(&self.inner),
            id: Default::default(),
            bidi,
            opened_locally: true,
            application_visible: true,
            local_send: true,
            local_recv: bidi,
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
                provisional_created_at: Some(Instant::now()),
                opened_on_wire: false,
                peer_visible: false,
                received_open: false,
                send_used: 0,
                send_max: 0,
                send_blocked_at: None,
                recv_used: 0,
                recv_advertised: 0,
                recv_pending: 0,
                late_data_received: 0,
                late_data_cap: 0,
                open_prefix,
                open_info,
                retained_open_info_bytes,
                metadata: StreamMetadata {
                    priority: initial_priority,
                    group: normalize_stream_group(initial_group),
                    open_info: Vec::new(),
                },
                metadata_revision: 0,
                pending_priority_update: None,
                open_initial_group: initial_group,
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
            }),
            cond: Condvar::new(),
        });
        if bidi {
            state.provisional_bidi.push_back(Arc::clone(&stream));
        } else {
            state.provisional_uni.push_back(Arc::clone(&stream));
        }
        if retained_open_info_bytes != 0 {
            state.retained_open_info_bytes = state
                .retained_open_info_bytes
                .saturating_add(retained_open_info_bytes);
        }
        drop(state);
        self.inner.cond.notify_all();
        Ok(stream)
    }

    pub fn accept_stream(&self) -> Result<Stream> {
        let stream = session_result(self.accept_inner(true, None), ErrorOperation::Accept)?;
        Ok(Stream { inner: stream })
    }

    pub fn accept_stream_timeout(&self, timeout: Duration) -> Result<Stream> {
        let deadline = session_result(timeout_deadline("accept", timeout), ErrorOperation::Accept)?;
        let stream = session_result(self.accept_inner(true, deadline), ErrorOperation::Accept)?;
        Ok(Stream { inner: stream })
    }

    pub fn accept_uni_stream(&self) -> Result<RecvStream> {
        let stream = session_result(self.accept_inner(false, None), ErrorOperation::Accept)?;
        Ok(RecvStream { inner: stream })
    }

    pub fn accept_uni_stream_timeout(&self, timeout: Duration) -> Result<RecvStream> {
        let deadline = session_result(timeout_deadline("accept", timeout), ErrorOperation::Accept)?;
        let stream = session_result(self.accept_inner(false, deadline), ErrorOperation::Accept)?;
        Ok(RecvStream { inner: stream })
    }

    fn accept_inner(&self, bidi: bool, deadline: Option<Instant>) -> Result<Arc<StreamInner>> {
        let mut state = self.inner.state.lock().unwrap();
        loop {
            let next = if bidi {
                state.accept_bidi.pop_front()
            } else {
                state.accept_uni.pop_front()
            };
            if let Some(stream) = next {
                shrink_accept_queue_locked(&mut state, bidi);
                state.accepted_streams = state.accepted_streams.saturating_add(1);
                clear_accepted_backlog_accounting(&mut state, &stream);
                let event = {
                    let mut stream_state = stream.state.lock().unwrap();
                    take_stream_event_locked(
                        &self.inner,
                        &stream,
                        &mut stream_state,
                        state.state,
                        EventType::StreamAccepted,
                        None,
                    )
                };
                drop(state);
                emit_event(&self.inner, event);
                return Ok(stream);
            }
            ensure_session_open(&state)?;
            state = wait_conn_until(&self.inner, state, deadline, "accept")?;
        }
    }

    pub fn ping(&self, echo: &[u8]) -> Result<Duration> {
        session_result(self.ping_inner(echo, None), ErrorOperation::Ping)
    }

    pub fn ping_timeout(&self, echo: &[u8], timeout: Duration) -> Result<Duration> {
        let deadline = session_result(timeout_deadline("ping", timeout), ErrorOperation::Ping)?;
        session_result(self.ping_inner(echo, deadline), ErrorOperation::Ping)
    }

    fn ping_inner(&self, echo: &[u8], deadline: Option<Instant>) -> Result<Duration> {
        let max = ping_payload_limit(&self.inner);
        let payload_len = ping_payload_len(echo.len())
            .ok_or_else(|| Error::frame_size("PING payload length overflows u64"))?;
        if payload_len > max {
            return Err(Error::frame_size("PING payload exceeds negotiated limit"));
        }
        check_deadline(deadline, "ping")?;
        let (slot, payload) = {
            let mut state = self.inner.state.lock().unwrap();
            loop {
                ensure_session_open(&state)?;
                check_deadline(deadline, "ping")?;
                if state.ping_waiter.is_none() && state.keepalive_ping.is_none() {
                    let sent_at = Instant::now();
                    let token = next_session_ping_token_locked(&mut state);
                    let (payload, accepts_padded_pong) =
                        build_ping_payload_locked(&self.inner, &mut state, echo, token)?;
                    let new_slot = Arc::new(PingSlot {
                        result: Mutex::new(None),
                        cond: Condvar::new(),
                        sent_at,
                        accepts_padded_pong,
                    });
                    state.ping_waiter = Some(UserPing {
                        payload: payload.clone(),
                        slot: new_slot.clone(),
                    });
                    note_local_ping_sent_locked(&self.inner, &mut state, new_slot.sent_at);
                    self.inner.cond.notify_all();
                    break (new_slot, payload);
                }
                state = wait_conn_until(&self.inner, state, deadline, "ping")?;
            }
        };
        let ping_frame = Frame {
            frame_type: FrameType::Ping,
            flags: 0,
            stream_id: 0,
            payload,
        };
        let queued = if deadline.is_some() {
            self.inner
                .queue_frame_until(ping_frame, || deadline, || Ok(()), "ping")
        } else {
            self.queue_frame(ping_frame)
        };
        if let Err(err) = queued {
            self.remove_ping_waiter(&slot, false);
            return Err(err);
        }
        let mut result = slot.result.lock().unwrap();
        while result.is_none() {
            if let Some(deadline) = deadline {
                let now = Instant::now();
                if now >= deadline {
                    drop(result);
                    if self.remove_ping_waiter(&slot, true) {
                        return Err(Error::timeout("ping"));
                    }
                    result = slot.result.lock().unwrap();
                    continue;
                }
                let remaining = deadline.saturating_duration_since(now);
                let wait = remaining.min(MAX_CONDVAR_TIMED_WAIT);
                let reaches_deadline = wait == remaining;
                let (next, timeout) = slot.cond.wait_timeout(result, wait).unwrap();
                result = next;
                if timeout.timed_out() && reaches_deadline && result.is_none() {
                    drop(result);
                    if self.remove_ping_waiter(&slot, true) {
                        return Err(Error::timeout("ping"));
                    }
                    result = slot.result.lock().unwrap();
                }
            } else {
                result = slot.cond.wait(result).unwrap();
            }
        }
        result.take().unwrap()
    }

    fn remove_ping_waiter(&self, slot: &Arc<PingSlot>, preserve_canceled_payload: bool) -> bool {
        let mut state = self.inner.state.lock().unwrap();
        let Some(active) = state.ping_waiter.as_ref() else {
            return false;
        };
        if !Arc::ptr_eq(&active.slot, slot) {
            return false;
        }
        let active = state.ping_waiter.take().unwrap();
        if preserve_canceled_payload {
            state.canceled_ping_payload =
                canceled_ping_payload(&active.payload, active.slot.accepts_padded_pong);
        }
        reset_keepalive_idle_schedules_locked(&self.inner, &mut state, Instant::now());
        drop(state);
        self.inner.cond.notify_all();
        true
    }

    pub fn go_away(&self, last_accepted_bidi: u64, last_accepted_uni: u64) -> Result<()> {
        session_result(
            self.go_away_with_error(
                last_accepted_bidi,
                last_accepted_uni,
                ErrorCode::NoError.as_u64(),
                "",
            ),
            ErrorOperation::Close,
        )
    }

    pub fn go_away_with_error(
        &self,
        last_accepted_bidi: u64,
        last_accepted_uni: u64,
        code: u64,
        reason: &str,
    ) -> Result<()> {
        session_result(
            validate_go_away_watermark_for_direction(last_accepted_bidi, true),
            ErrorOperation::Close,
        )?;
        session_result(
            validate_go_away_watermark_creator(self.inner.negotiated.peer_role, last_accepted_bidi),
            ErrorOperation::Close,
        )?;
        session_result(
            validate_go_away_watermark_for_direction(last_accepted_uni, false),
            ErrorOperation::Close,
        )?;
        session_result(
            validate_go_away_watermark_creator(self.inner.negotiated.peer_role, last_accepted_uni),
            ErrorOperation::Close,
        )?;
        let payload = session_result(
            build_go_away_payload_capped(
                last_accepted_bidi,
                last_accepted_uni,
                code,
                reason,
                self.inner.peer_preface.settings.max_control_payload_bytes,
            ),
            ErrorOperation::Close,
        )?;
        {
            let mut state = self.inner.state.lock().unwrap();
            ensure_session_open(&state)?;
            if last_accepted_bidi > state.local_go_away_bidi
                || last_accepted_uni > state.local_go_away_uni
            {
                if state.local_go_away_issued
                    && state.local_go_away_bidi <= last_accepted_bidi
                    && state.local_go_away_uni <= last_accepted_uni
                {
                    return Ok(());
                }
                return Err(
                    Error::local("zmux: GOAWAY watermarks must be non-increasing")
                        .with_session_context(ErrorOperation::Close),
                );
            }
            if state.local_go_away_issued
                && last_accepted_bidi == state.local_go_away_bidi
                && last_accepted_uni == state.local_go_away_uni
            {
                return Ok(());
            }
            state.local_go_away_bidi = last_accepted_bidi;
            state.local_go_away_uni = last_accepted_uni;
            state.local_go_away_issued = true;
            state.state = SessionState::Draining;
        }
        self.inner.cond.notify_all();
        session_result(
            self.queue_frame(Frame {
                frame_type: FrameType::GoAway,
                flags: 0,
                stream_id: 0,
                payload,
            }),
            ErrorOperation::Close,
        )
    }

    pub fn close(&self) -> Result<()> {
        session_result(self.close_gracefully(), ErrorOperation::Close)
    }

    pub fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        let result = (|| {
            let (close_event, close_payload) = {
                let mut state = self.inner.state.lock().unwrap();
                if matches!(state.state, SessionState::Closed | SessionState::Failed) {
                    return Ok(());
                }
                let no_error = code == 0;
                let close_payload = build_code_payload(
                    code,
                    reason,
                    self.inner.peer_preface.settings.max_control_payload_bytes,
                )?;
                state.state = if no_error {
                    SessionState::Closed
                } else {
                    SessionState::Failed
                };
                state.graceful_close_active = false;
                state.peer_close_error = None;
                state.close_error = if no_error {
                    None
                } else {
                    Some(
                        Error::application(code, reason)
                            .with_source(ErrorSource::Local)
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
                (
                    take_session_closed_event_locked(&self.inner, &mut state),
                    close_payload,
                )
            };
            emit_event(&self.inner, close_event);
            self.inner.shutdown_writer_with_close(Frame {
                frame_type: FrameType::Close,
                flags: 0,
                stream_id: 0,
                payload: close_payload,
            });
            self.inner.cond.notify_all();
            Ok(())
        })();
        session_result(result, ErrorOperation::Close)
    }

    fn close_gracefully(&self) -> Result<()> {
        let close_payload = build_code_payload(
            ErrorCode::NoError.as_u64(),
            "",
            self.inner.peer_preface.settings.max_control_payload_bytes,
        )?;
        let mut direct_close = false;
        let mut direct_close_event = None;
        let mut initial_go_away_payload = None;
        {
            let mut state = self.inner.state.lock().unwrap();
            if matches!(state.state, SessionState::Closed | SessionState::Failed) {
                return Ok(());
            }
            if state.graceful_close_active {
                drop(state);
                return self.wait();
            }
            if state.state == SessionState::Closing {
                drop(state);
                return self.wait();
            }
            if !close_has_blocking_streams(&self.inner, &state) {
                direct_close = true;
                state.state = SessionState::Closed;
                state.graceful_close_active = false;
                state.close_error = None;
                state.peer_close_error = None;
                state.scheduler.clear();
                fail_pending_pings_locked(&mut state, Error::session_closed());
                release_session_runtime_state_locked(&mut state);
                direct_close_event = take_session_closed_event_locked(&self.inner, &mut state);
            } else {
                if state.local_go_away_bidi == MAX_VARINT62
                    && state.local_go_away_uni == MAX_VARINT62
                {
                    let initial_bidi = effective_go_away_send_watermark(
                        self.inner.negotiated.local_role,
                        true,
                        MAX_VARINT62,
                    );
                    let initial_uni = effective_go_away_send_watermark(
                        self.inner.negotiated.local_role,
                        false,
                        MAX_VARINT62,
                    );
                    state.local_go_away_bidi = initial_bidi;
                    state.local_go_away_uni = initial_uni;
                    state.local_go_away_issued = true;
                    initial_go_away_payload = Some(build_go_away_payload(
                        initial_bidi,
                        initial_uni,
                        ErrorCode::NoError.as_u64(),
                        "",
                    )?);
                }
                state.state = SessionState::Draining;
                state.graceful_close_active = true;
                state.close_error = None;
                state.peer_close_error = None;
                notify_all_streams(&state);
            }
        }
        if direct_close {
            emit_event(&self.inner, direct_close_event);
            self.inner.shutdown_writer_with_close(Frame {
                frame_type: FrameType::Close,
                flags: 0,
                stream_id: 0,
                payload: close_payload,
            });
            self.inner.cond.notify_all();
            return Ok(());
        }
        if let Some(payload) = initial_go_away_payload {
            self.queue_graceful_control_frame(Frame {
                frame_type: FrameType::GoAway,
                flags: 0,
                stream_id: 0,
                payload,
            })?;
            self.wait_for_go_away_drain();
        }
        let mut final_go_away_payload = None;
        let reclaim_streams;
        {
            let mut state = self.inner.state.lock().unwrap();
            if matches!(state.state, SessionState::Failed) {
                return Err(state
                    .close_error
                    .clone()
                    .unwrap_or_else(Error::session_closed));
            }
            if state.state == SessionState::Closed {
                return Ok(());
            }
            state.state = SessionState::Closing;
            state.graceful_close_active = false;
            let final_bidi = state
                .local_go_away_bidi
                .min(accepted_peer_go_away_watermark(
                    self.inner.negotiated.local_role,
                    true,
                    state.next_peer_bidi,
                ));
            let final_uni = state.local_go_away_uni.min(accepted_peer_go_away_watermark(
                self.inner.negotiated.local_role,
                false,
                state.next_peer_uni,
            ));
            if final_bidi < state.local_go_away_bidi || final_uni < state.local_go_away_uni {
                state.local_go_away_bidi = final_bidi;
                state.local_go_away_uni = final_uni;
                state.local_go_away_issued = true;
                final_go_away_payload = Some(build_go_away_payload(
                    final_bidi,
                    final_uni,
                    ErrorCode::NoError.as_u64(),
                    "",
                )?);
            }
            reclaim_streams = reclaim_graceful_close_local_streams_locked(&self.inner, &mut state);
            state.ignore_peer_non_close = true;
        }
        if let Some(payload) = final_go_away_payload {
            self.queue_graceful_control_frame(Frame {
                frame_type: FrameType::GoAway,
                flags: 0,
                stream_id: 0,
                payload,
            })?;
        }
        for stream in reclaim_streams {
            let stream_id = stream.id.load(Ordering::Acquire);
            let stats = self.inner.write_queue.discard_stream(stream_id);
            if stats.removed_any() {
                apply_discarded_stream_frames_locked(&self.inner, &stream, stats);
            }
        }
        self.inner.cond.notify_all();
        let drain_result = self.wait_for_close_drain();
        let close_event = {
            let mut state = self.inner.state.lock().unwrap();
            if matches!(state.state, SessionState::Failed) {
                return Err(state
                    .close_error
                    .clone()
                    .unwrap_or_else(Error::session_closed));
            }
            if state.state == SessionState::Closed {
                return Ok(());
            }
            state.state = SessionState::Closed;
            state.graceful_close_active = false;
            state.close_error = None;
            state.peer_close_error = None;
            state.scheduler.clear();
            fail_pending_pings_locked(&mut state, Error::session_closed());
            release_session_runtime_state_locked(&mut state);
            take_session_closed_event_locked(&self.inner, &mut state)
        };
        emit_event(&self.inner, close_event);
        self.queue_graceful_close_frame(Frame {
            frame_type: FrameType::Close,
            flags: 0,
            stream_id: 0,
            payload: close_payload,
        })?;
        self.inner.drain_shutdown_writer();
        self.inner.cond.notify_all();
        drain_result
    }

    fn wait_for_go_away_drain(&self) {
        let mut state = self.inner.state.lock().unwrap();
        let interval = effective_go_away_drain_interval(
            self.inner.go_away_drain_interval,
            state.last_ping_rtt,
        );
        if interval.is_zero() {
            return;
        }
        let deadline = deadline_after(interval);
        while state.state == SessionState::Draining && state.graceful_close_active {
            let Some(poll) = poll_until_deadline(deadline, DRAIN_WAIT_POLL) else {
                break;
            };
            let (next, _) = self.inner.cond.wait_timeout(state, poll).unwrap();
            state = next;
        }
    }

    fn wait_for_close_drain(&self) -> Result<()> {
        let mut state = self.inner.state.lock().unwrap();
        let timeout =
            effective_close_drain_timeout(self.inner.close_drain_timeout, state.last_ping_rtt);
        if timeout.is_zero() {
            return Ok(());
        }
        let deadline = deadline_after(timeout);
        while state.state == SessionState::Closing
            && close_has_blocking_streams(&self.inner, &state)
        {
            let Some(poll) = poll_until_deadline(deadline, DRAIN_WAIT_POLL) else {
                state.graceful_close_timeout_count =
                    state.graceful_close_timeout_count.saturating_add(1);
                return Err(Error::graceful_close_timeout());
            };
            let (next, _) = self.inner.cond.wait_timeout(state, poll).unwrap();
            state = next;
        }
        Ok(())
    }

    pub fn wait(&self) -> Result<()> {
        let result = (|| {
            let mut state = self.inner.state.lock().unwrap();
            loop {
                match state.state {
                    SessionState::Closed => return Ok(()),
                    SessionState::Failed => {
                        return Err(state
                            .close_error
                            .clone()
                            .unwrap_or_else(Error::session_closed));
                    }
                    _ => state = self.inner.cond.wait(state).unwrap(),
                }
            }
        })();
        session_result(result, ErrorOperation::Close)
    }

    pub fn wait_timeout(&self, timeout: Duration) -> Result<bool> {
        let result = (|| {
            let deadline = if timeout.is_zero() {
                None
            } else {
                Instant::now().checked_add(timeout)
            };
            let mut state = self.inner.state.lock().unwrap();
            loop {
                match state.state {
                    SessionState::Closed => return Ok(true),
                    SessionState::Failed => {
                        return Err(state
                            .close_error
                            .clone()
                            .unwrap_or_else(Error::session_closed));
                    }
                    _ if timeout.is_zero() => return Ok(false),
                    _ => {
                        let Some(deadline) = deadline else {
                            state = self.inner.cond.wait(state).unwrap();
                            continue;
                        };
                        let now = Instant::now();
                        if now >= deadline {
                            return Ok(false);
                        }
                        let remaining = deadline.saturating_duration_since(now);
                        let wait = remaining.min(MAX_CONDVAR_TIMED_WAIT);
                        let reaches_deadline = wait == remaining;
                        let (next, timed_out) = self.inner.cond.wait_timeout(state, wait).unwrap();
                        state = next;
                        if timed_out.timed_out() && reaches_deadline {
                            return match state.state {
                                SessionState::Closed => Ok(true),
                                SessionState::Failed => Err(state
                                    .close_error
                                    .clone()
                                    .unwrap_or_else(Error::session_closed)),
                                _ => Ok(false),
                            };
                        }
                    }
                }
            }
        })();
        session_result(result, ErrorOperation::Close)
    }

    pub fn is_closed(&self) -> bool {
        let state = self.inner.state.lock().unwrap();
        matches!(state.state, SessionState::Closed | SessionState::Failed)
    }

    pub fn close_error(&self) -> Option<Error> {
        self.inner.state.lock().unwrap().close_error.clone()
    }

    pub fn state(&self) -> SessionState {
        self.inner.state.lock().unwrap().state
    }

    pub fn stats(&self) -> SessionStats {
        let state = self.inner.state.lock().unwrap();
        let writer_queue = self.inner.write_queue.stats();
        let now = Instant::now();
        let memory = memory_stats_locked(&self.inner, &state, &writer_queue);
        let buffered_receive_bytes = buffered_receive_bytes_locked(&state);
        let retained_state_bytes = tracked_retained_state_memory_locked(&self.inner, &state);
        let hidden_soft_limit = hidden_soft_limit(state.hidden_tombstone_limit);
        let terminal = matches!(state.state, SessionState::Closed | SessionState::Failed);
        let outstanding_ping_bytes = if terminal {
            0
        } else {
            outstanding_ping_bytes_locked(&state)
        };
        let keepalive_interval = if terminal {
            Duration::ZERO
        } else {
            self.inner.keepalive_interval
        };
        let keepalive_max_ping_interval = if terminal {
            Duration::ZERO
        } else {
            self.inner.keepalive_max_ping_interval
        };
        let ping_outstanding =
            !terminal && (state.keepalive_ping.is_some() || state.ping_waiter.is_some());
        let keepalive_timeout = effective_keepalive_timeout_locked(&self.inner, &state);
        let ping_stalled = !terminal
            && outstanding_ping_sent_at(&state).is_some_and(|sent_at| {
                !keepalive_timeout.is_zero()
                    && now.saturating_duration_since(sent_at) > keepalive_timeout / 2
            });
        SessionStats {
            state: state.state,
            sent_frames: state.sent_frames,
            received_frames: state.received_frames,
            sent_data_bytes: state.sent_data_bytes,
            received_data_bytes: state.received_data_bytes,
            open_streams: state.streams.len(),
            accepted_streams: state.accepted_streams,
            active_streams: active_stream_stats(state.active),
            provisional: ProvisionalStats {
                bidi: state.provisional_bidi.len(),
                uni: state.provisional_uni.len(),
                bidi_limit: state.max_provisional_bidi,
                uni_limit: state.max_provisional_uni,
                limited: state.provisional_open_limited_count,
                expired: state.provisional_open_expired_count,
            },
            accept_backlog: AcceptBacklogStats {
                bidi: state.accept_bidi.len(),
                uni: state.accept_uni.len(),
                limit: state.accept_backlog_limit,
                bidi_limit: state.accept_limit_bidi,
                uni_limit: state.accept_limit_uni,
                bytes: state.accept_backlog_bytes,
                bytes_limit: state.accept_backlog_bytes_limit,
                refused: state.accept_backlog_refused,
            },
            retention: RetentionStats {
                tombstones: state.tombstones.len(),
                tombstone_limit: state.tombstone_limit,
                marker_only_used_streams: marker_only_retained_count_locked(&state),
                marker_only_used_stream_ranges: state.used_marker_ranges.len(),
                marker_only_used_stream_limit: state.used_marker_limit,
                retained_open_info_bytes: state.retained_open_info_bytes,
                retained_open_info_bytes_budget: state.retained_open_info_bytes_budget,
                retained_peer_reason_bytes: state.retained_peer_reason_bytes,
                retained_peer_reason_bytes_budget: state.retained_peer_reason_bytes_budget,
            },
            memory,
            abuse: AbuseStats {
                ignored_control: state.ignored_control_count,
                ignored_control_budget: state.ignored_control_budget,
                no_op_zero_data: state.no_op_zero_data_count,
                no_op_zero_data_budget: state.no_op_zero_data_budget,
                inbound_ping: state.inbound_ping_count,
                inbound_ping_budget: state.inbound_ping_budget,
                no_op_max_data: state.no_op_max_data_count,
                no_op_max_data_budget: state.no_op_max_data_budget,
                no_op_blocked: state.no_op_blocked_count,
                no_op_blocked_budget: state.no_op_blocked_budget,
                no_op_priority_update: state.no_op_priority_update_count,
                no_op_priority_update_budget: state.no_op_priority_update_budget,
                dropped_priority_update: state.dropped_priority_update_count,
                inbound_control_frames: state.inbound_control_frames,
                inbound_control_frame_budget: state.inbound_control_frame_budget,
                inbound_control_bytes: state.inbound_control_bytes,
                inbound_control_bytes_budget: state.inbound_control_bytes_budget,
                inbound_ext_frames: state.inbound_ext_frames,
                inbound_ext_frame_budget: state.inbound_ext_frame_budget,
                inbound_ext_bytes: state.inbound_ext_bytes,
                inbound_ext_bytes_budget: state.inbound_ext_bytes_budget,
                inbound_mixed_frames: state.inbound_mixed_frames,
                inbound_mixed_frame_budget: state.inbound_mixed_frame_budget,
                inbound_mixed_bytes: state.inbound_mixed_bytes,
                inbound_mixed_bytes_budget: state.inbound_mixed_bytes_budget,
                group_rebucket_churn: state.group_rebucket_churn_count,
                group_rebucket_churn_budget: state.group_rebucket_churn_budget,
                hidden_abort_churn: state.hidden_abort_churn_count,
                hidden_abort_churn_budget: state.hidden_abort_churn_budget,
                visible_terminal_churn: state.visible_terminal_churn_count,
                visible_terminal_churn_budget: state.visible_terminal_churn_budget,
            },
            hidden: HiddenStateStats {
                retained: state.hidden_tombstones,
                soft_limit: hidden_soft_limit,
                hard_limit: state.hidden_tombstone_limit,
                at_soft_limit: hidden_soft_limit > 0
                    && state.hidden_tombstones >= hidden_soft_limit,
                at_hard_limit: state.hidden_tombstone_limit > 0
                    && state.hidden_tombstones >= state.hidden_tombstone_limit,
                refused: state.hidden_streams_refused,
                reaped: state.hidden_streams_reaped,
                unread_bytes_discarded: state.hidden_unread_bytes_discarded,
            },
            reasons: ReasonStats {
                reset: state.reset_reason_counts.clone(),
                reset_overflow: state.reset_reason_overflow,
                abort: state.abort_reason_counts.clone(),
                abort_overflow: state.abort_reason_overflow,
            },
            diagnostics: DiagnosticStats {
                dropped_priority_updates: state.dropped_priority_update_count,
                dropped_local_priority_updates: state.dropped_local_priority_update_count,
                late_data_after_close_read: state.late_data_after_close_read_bytes,
                late_data_after_reset: state.late_data_after_reset_bytes,
                late_data_after_abort: state.late_data_after_abort_bytes,
                coalesced_terminal_signals: 0,
                superseded_terminal_signals: state.superseded_terminal_signal_count,
                visible_terminal_churn_events: state.visible_terminal_churn_count,
                group_rebucket_events: state.group_rebucket_churn_count,
                hidden_abort_churn_events: state.hidden_abort_churn_count,
                skipped_close_on_dead_io: state.skipped_close_on_dead_io_count,
                close_frame_flush_errors: state.close_frame_flush_error_count,
                close_completion_timeouts: state.close_completion_timeout_count,
                graceful_close_timeouts: state.graceful_close_timeout_count,
                keepalive_timeouts: state.keepalive_timeout_count,
            },
            pressure: PressureStats {
                receive_backlog_bytes: state.recv_session_buffered,
                receive_backlog_high: state.recv_session_advertised > 0
                    && state.recv_session_buffered >= state.recv_session_advertised / 2,
                aggregate_late_data_bytes: state.late_data_aggregate_received,
                aggregate_late_data_at_cap: state.late_data_aggregate_cap > 0
                    && state.late_data_aggregate_received >= state.late_data_aggregate_cap,
                retained_state_bytes,
                tracked_buffered_bytes: memory.tracked_bytes,
                tracked_buffered_limit: memory.hard_cap,
                tracked_buffered_high: memory.tracked_bytes
                    >= memory_high_threshold(memory.hard_cap),
                tracked_buffered_at_cap: memory.tracked_bytes >= memory.hard_cap,
                buffered_receive_bytes,
                recv_session_advertised_bytes: state.recv_session_advertised,
                recv_session_received_bytes: state.recv_session_used,
                recv_session_pending_bytes: state.recv_session_pending,
                outstanding_ping_bytes,
            },
            flush: FlushStats {
                count: state.flush_count,
                last_at: state.last_flush_at,
                last_frames: state.last_flush_frames,
                last_bytes: state.last_flush_bytes,
            },
            telemetry: TelemetryStats {
                last_open_latency: state.last_open_latency,
                send_rate_estimate_bytes_per_second: state.send_rate_estimate,
            },
            progress: ProgressStats {
                inbound_frame_at: Some(state.last_inbound_at),
                control_progress_at: Some(state.last_control_progress_at),
                transport_write_at: Some(state.last_outbound_at),
                stream_progress_at: state.last_stream_progress_at,
                application_progress_at: state.last_application_progress_at,
                ping_sent_at: if terminal {
                    None
                } else {
                    state.last_ping_sent_at
                },
                pong_at: if terminal { None } else { state.last_pong_at },
            },
            blocked_write_total: state.blocked_write_total,
            writer_queue,
            liveness: LivenessStats {
                keepalive_interval,
                keepalive_max_ping_interval,
                keepalive_timeout,
                ping_outstanding,
                ping_stalled,
                last_ping_rtt: if terminal { None } else { state.last_ping_rtt },
                inbound_idle_for: now.saturating_duration_since(state.last_inbound_at),
                outbound_idle_for: now.saturating_duration_since(state.last_outbound_at),
            },
        }
    }

    pub fn peer_close_error(&self) -> Option<PeerCloseError> {
        self.inner.state.lock().unwrap().peer_close_error.clone()
    }

    pub fn peer_go_away_error(&self) -> Option<PeerGoAwayError> {
        self.inner.state.lock().unwrap().peer_go_away_error.clone()
    }

    pub fn local_preface(&self) -> Preface {
        self.inner.local_preface.clone()
    }

    pub fn peer_preface(&self) -> Preface {
        self.inner.peer_preface.clone()
    }

    pub fn negotiated(&self) -> Negotiated {
        self.inner.negotiated.clone()
    }

    fn queue_frame(&self, frame: Frame) -> Result<()> {
        self.inner.queue_frame(frame)
    }

    fn queue_graceful_control_frame(&self, frame: Frame) -> Result<()> {
        match self.queue_frame(frame) {
            Ok(()) => Ok(()),
            Err(err) if self.local_close_completed_after_writer_shutdown(&err) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn queue_graceful_close_frame(&self, frame: Frame) -> Result<()> {
        match self.inner.queue_graceful_close_frame(frame) {
            Ok(()) => Ok(()),
            Err(err) if self.local_close_completed_after_writer_shutdown(&err) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn local_close_completed_after_writer_shutdown(&self, err: &Error) -> bool {
        err.is_session_closed() && self.inner.state.lock().unwrap().state == SessionState::Closed
    }
}

fn effective_go_away_drain_interval(
    configured: Duration,
    last_ping_rtt: Option<Duration>,
) -> Duration {
    if configured.is_zero() {
        return Duration::ZERO;
    }
    nonzero_duration(last_ping_rtt)
        .map(|rtt| configured.max(rtt / 4))
        .unwrap_or(configured)
}

fn effective_close_drain_timeout(
    configured: Duration,
    last_ping_rtt: Option<Duration>,
) -> Duration {
    if configured.is_zero() || configured != DEFAULT_CLOSE_DRAIN_TIMEOUT {
        return configured;
    }
    let Some(rtt) = nonzero_duration(last_ping_rtt) else {
        return configured;
    };
    let adaptive = match rtt.checked_mul(4) {
        Some(timeout) => timeout
            .checked_add(CLOSE_DRAIN_RTT_SLACK)
            .unwrap_or(Duration::MAX),
        None => Duration::MAX,
    };
    configured.max(adaptive).min(CLOSE_DRAIN_TIMEOUT_MAX)
}

fn hidden_control_opened_limit(pending_limit: usize) -> usize {
    if pending_limit == 0 {
        return 64;
    }
    (pending_limit / 2).max(32)
}

fn active_stream_stats(active: ActiveStreamStats) -> ActiveStreamStats {
    ActiveStreamStats {
        total: active
            .local_bidi
            .saturating_add(active.local_uni)
            .saturating_add(active.peer_bidi)
            .saturating_add(active.peer_uni),
        ..active
    }
}

fn hidden_soft_limit(hard_limit: usize) -> usize {
    if hard_limit <= 1 {
        hard_limit
    } else {
        (hard_limit / 2).max(1)
    }
}

fn memory_high_threshold(hard_cap: usize) -> usize {
    if hard_cap <= 4 {
        hard_cap
    } else {
        hard_cap.saturating_sub(hard_cap / 4)
    }
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    value.min(u64::MAX as usize) as u64
}

#[inline]
fn u64_to_usize_saturating(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

#[inline]
fn u64_to_usize_or(value: u64, fallback: usize) -> usize {
    if value > usize::MAX as u64 {
        fallback
    } else {
        value as usize
    }
}

fn buffered_receive_bytes_locked(state: &ConnState) -> usize {
    u64_to_usize_saturating(state.recv_session_buffered)
}

fn outstanding_ping_bytes_locked(state: &ConnState) -> usize {
    let keepalive = if let Some(ping) = state.keepalive_ping.as_ref() {
        ping.payload.len()
    } else {
        0
    };
    if let Some(ping) = state.ping_waiter.as_ref() {
        keepalive.saturating_add(ping.payload.len())
    } else {
        keepalive
    }
}

fn outstanding_ping_sent_at(state: &ConnState) -> Option<Instant> {
    state
        .keepalive_ping
        .as_ref()
        .map(|ping| ping.sent_at)
        .or_else(|| state.ping_waiter.as_ref().map(|ping| ping.slot.sent_at))
}

fn default_urgent_queue_max_bytes(
    local: crate::settings::Settings,
    peer: crate::settings::Settings,
) -> usize {
    let payload = min_nonzero_or_default(
        local.max_control_payload_bytes,
        peer.max_control_payload_bytes,
        crate::settings::Settings::DEFAULT.max_control_payload_bytes,
    );
    u64_to_usize_or(payload, usize::MAX / 8)
        .saturating_mul(8)
        .max(DEFAULT_URGENT_QUEUE_MAX_BYTES_FLOOR)
}

fn emit_establishment_close<W: Write>(
    writer: &mut W,
    local: &Preface,
    peer: Option<&Preface>,
    err: &Error,
) -> Result<()> {
    let max_payload = match peer {
        Some(preface) if preface.settings.max_control_payload_bytes != 0 => {
            preface.settings.max_control_payload_bytes
        }
        _ => nonzero_or_default(
            local.settings.max_control_payload_bytes,
            crate::settings::Settings::DEFAULT.max_control_payload_bytes,
        ),
    };
    let reason = match err.reason() {
        Some(reason) if !reason.is_empty() => std::borrow::Cow::Borrowed(reason),
        _ => std::borrow::Cow::Owned(err.to_string()),
    };
    let frame = Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: build_code_payload(
            err.numeric_code().unwrap_or(ErrorCode::Internal.as_u64()),
            reason.as_ref(),
            max_payload,
        )?,
    };
    let encoded_len = frame.encoded_len()?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| Error::local("zmux: close frame allocation failed"))?;
    frame.append_to(&mut encoded)?;
    writer.write_all(&encoded)?;
    writer.flush()?;
    Ok(())
}

fn negotiated_nonzero_payload(
    local: crate::settings::Settings,
    peer: crate::settings::Settings,
) -> u64 {
    min_nonzero_or_default(
        local.max_frame_payload,
        peer.max_frame_payload,
        crate::settings::Settings::DEFAULT.max_frame_payload,
    )
}

#[inline]
fn min_nonzero_or_default(lhs: u64, rhs: u64, default: u64) -> u64 {
    match (lhs, rhs) {
        (0, 0) => default,
        (0, rhs) => rhs,
        (lhs, 0) => lhs,
        (lhs, rhs) => lhs.min(rhs),
    }
}

#[inline]
fn nonzero_or_default(value: u64, default: u64) -> u64 {
    if value == 0 {
        default
    } else {
        value
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
fn nonzero_duration_value(value: Duration) -> Option<Duration> {
    if value.is_zero() {
        None
    } else {
        Some(value)
    }
}

fn default_per_stream_queued_data_high_watermark(
    local: crate::settings::Settings,
    peer: crate::settings::Settings,
) -> usize {
    u64_to_usize_or(negotiated_nonzero_payload(local, peer), usize::MAX / 16)
        .saturating_mul(16)
        .max(DEFAULT_PER_STREAM_QUEUED_DATA_HIGH_WATERMARK_FLOOR)
}

fn default_session_queued_data_high_watermark(per_stream_hwm: usize) -> usize {
    per_stream_hwm
        .saturating_mul(4)
        .max(DEFAULT_SESSION_QUEUED_DATA_HIGH_WATERMARK_FLOOR)
}

fn default_write_batch_cost_limit(max_frame_payload: u64) -> usize {
    let max_frame_payload = nonzero_or_default(
        max_frame_payload,
        crate::settings::Settings::DEFAULT.max_frame_payload,
    );
    u64_to_usize_or(max_frame_payload, usize::MAX / 4)
        .saturating_add(1)
        .saturating_mul(4)
        .max(1)
}

fn default_pending_control_bytes_budget(
    peer: crate::settings::Settings,
    local: crate::settings::Settings,
) -> usize {
    u64_to_usize_or(
        nonzero_or_default(
            peer.max_control_payload_bytes,
            local.max_control_payload_bytes,
        ),
        usize::MAX / 8,
    )
    .saturating_mul(8)
    .max(DEFAULT_PENDING_CONTROL_BYTES_BUDGET_FLOOR)
}

fn default_pending_priority_bytes_budget(
    peer: crate::settings::Settings,
    local: crate::settings::Settings,
) -> usize {
    u64_to_usize_or(
        nonzero_or_default(
            peer.max_extension_payload_bytes,
            local.max_extension_payload_bytes,
        ),
        usize::MAX / 8,
    )
    .saturating_mul(8)
    .max(DEFAULT_PENDING_PRIORITY_BYTES_BUDGET_FLOOR)
}

fn default_inbound_control_bytes_budget(settings: crate::settings::Settings) -> usize {
    u64_to_usize_or(settings.max_control_payload_bytes, usize::MAX / 64)
        .saturating_mul(64)
        .max(DEFAULT_INBOUND_CONTROL_BYTES_BUDGET_FLOOR)
}

fn default_inbound_ext_bytes_budget(settings: crate::settings::Settings) -> usize {
    u64_to_usize_or(settings.max_extension_payload_bytes, usize::MAX / 64)
        .saturating_mul(64)
        .max(DEFAULT_INBOUND_EXT_BYTES_BUDGET_FLOOR)
}

fn accepted_peer_go_away_watermark(local_role: Role, bidi: bool, next_peer_id: u64) -> u64 {
    let first_peer_id = first_peer_stream_id(local_role, bidi);
    if next_peer_id <= first_peer_id {
        0
    } else {
        next_peer_id.saturating_sub(4)
    }
}

fn effective_go_away_send_watermark(local_role: Role, bidi: bool, watermark: u64) -> u64 {
    if watermark == MAX_VARINT62 {
        max_peer_go_away_watermark(local_role, bidi)
    } else {
        watermark
    }
}

fn max_peer_go_away_watermark(local_role: Role, bidi: bool) -> u64 {
    let first_peer_id = first_peer_stream_id(local_role, bidi);
    if first_peer_id > MAX_VARINT62 {
        return 0;
    }
    first_peer_id + ((MAX_VARINT62 - first_peer_id) / 4) * 4
}

fn reclaim_graceful_close_local_streams_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
) -> Vec<Arc<StreamInner>> {
    reject_graceful_close_provisionals_locked(state, true);
    reject_graceful_close_provisionals_locked(state, false);

    let mut streams = Vec::new();
    for stream in state.streams.values() {
        if !stream.opened_locally || stream.id.load(Ordering::Acquire) == 0 {
            continue;
        }
        let stream_state = stream.state.lock().unwrap();
        if !stream_state.peer_visible && stream_state.aborted.is_none() {
            streams.push(Arc::clone(stream));
        }
    }
    let mut reclaimed = Vec::new();
    for stream in streams {
        let mut stream_state = stream.state.lock().unwrap();
        if stream_state.peer_visible || stream_state.aborted.is_some() {
            continue;
        }
        stream_state.aborted = Some((ErrorCode::RefusedStream.as_u64(), String::new()));
        stream_state.abort_source = ErrorSource::Local;
        let released = stream_state.recv_buf.clear_detailed();
        clear_stream_receive_credit_locked(inner, &stream, &mut stream_state);
        release_session_receive_buffered_locked(
            state,
            usize_to_u64_saturating(released.bytes),
            released.released_retained_bytes,
        );
        stream_state.pending_priority_update = None;
        clear_stream_open_prefix_locked(&mut stream_state);
        clear_stream_open_info_locked(state, &mut stream_state);
        maybe_release_active_count(state, &stream, &mut stream_state);
        drop(stream_state);
        stream.cond.notify_all();
        reclaimed.push(stream);
    }
    inner.cond.notify_all();
    reclaimed
}

fn reject_graceful_close_provisionals_locked(state: &mut ConnState, bidi: bool) {
    loop {
        let stream = if bidi {
            state.provisional_bidi.pop_back()
        } else {
            state.provisional_uni.pop_back()
        };
        let Some(stream) = stream else {
            break;
        };
        let mut stream_state = stream.state.lock().unwrap();
        stream_state.aborted = Some((ErrorCode::RefusedStream.as_u64(), String::new()));
        stream_state.abort_source = ErrorSource::Local;
        stream_state.provisional_created_at = None;
        let released = stream_state.recv_buf.clear_detailed();
        stream_state.recv_pending = 0;
        release_session_receive_buffered_locked(
            state,
            usize_to_u64_saturating(released.bytes),
            released.released_retained_bytes,
        );
        stream_state.pending_priority_update = None;
        clear_stream_open_prefix_locked(&mut stream_state);
        clear_stream_open_info_locked(state, &mut stream_state);
        maybe_release_active_count(state, &stream, &mut stream_state);
        drop(stream_state);
        stream.cond.notify_all();
    }
    shrink_provisional_queue_locked(state, bidi);
}

fn apply_discarded_stream_frames_locked(
    inner: &Arc<Inner>,
    stream: &Arc<StreamInner>,
    stats: StreamDiscardStats,
) {
    let mut state = inner.state.lock().unwrap();
    release_discarded_queued_stream_frames_locked(&mut state, stream, stats);
    drop(state);
    inner.cond.notify_all();
}

fn close_has_blocking_streams(inner: &Arc<Inner>, state: &ConnState) -> bool {
    if !state.provisional_bidi.is_empty() || !state.provisional_uni.is_empty() {
        return true;
    }
    state.streams.values().any(|stream| {
        if !stream.application_visible {
            return false;
        }
        stream_blocks_graceful_close(inner, state, stream)
    })
}

fn stream_blocks_graceful_close(
    inner: &Arc<Inner>,
    conn_state: &ConnState,
    stream: &Arc<StreamInner>,
) -> bool {
    let stream_id = stream.id.load(Ordering::Acquire);
    let queued_data = inner.write_queue.data_queued_bytes_for_stream(stream_id);
    let inflight_data = conn_state
        .inflight_data_by_stream
        .get(&stream_id)
        .copied()
        .unwrap_or(0);
    let queued_terminal = inner
        .write_queue
        .terminal_control_queued_for_stream(stream_id);
    {
        let stream_state = stream.state.lock().unwrap();
        if stream_fully_terminal(stream, &stream_state)
            && queued_data == 0
            && inflight_data == 0
            && stream_state.pending_data_frames == 0
            && stream_state.pending_terminal_frames == 0
            && !queued_terminal
        {
            return false;
        }
        if stream.opened_locally {
            return true;
        }
        if !stream.local_send {
            return false;
        }
        if stream_state.send_fin
            && (queued_data > 0 || inflight_data > 0 || stream_state.pending_data_frames > 0)
        {
            return true;
        }
        if !stream_state.opened_on_wire
            && queued_data == 0
            && inflight_data == 0
            && !queued_terminal
        {
            return false;
        }
        stream_state.aborted.is_none()
            && stream_state.stopped_by_peer.is_none()
            && !stream_state.send_fin
            && stream_state.send_reset.is_none()
    }
}

fn ensure_positive_timeout(operation: &str, timeout: Duration) -> Result<()> {
    if timeout.is_zero() {
        Err(Error::timeout(operation))
    } else {
        Ok(())
    }
}

fn timeout_deadline(operation: &str, timeout: Duration) -> Result<Option<Instant>> {
    ensure_positive_timeout(operation, timeout)?;
    Ok(deadline_after(timeout))
}

#[cfg(test)]
fn remaining_timeout(deadline: Option<Instant>) -> Option<Duration> {
    deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()))
}

fn remaining_open_send_write_timeout(start: Instant, timeout: Duration) -> Result<Duration> {
    timeout
        .checked_sub(start.elapsed())
        .and_then(nonzero_duration_value)
        .ok_or_else(|| {
            Error::timeout("write")
                .with_stream_context(ErrorOperation::Write, ErrorDirection::Write)
        })
}

fn validate_open_send_progress(n: usize, requested: usize) -> Result<()> {
    if n > requested {
        Err(Error::local("zmux: write reported invalid progress")
            .with_stream_context(ErrorOperation::Write, ErrorDirection::Write))
    } else {
        Ok(())
    }
}

const DRAIN_WAIT_POLL: Duration = Duration::from_millis(10);

fn deadline_after(timeout: Duration) -> Option<Instant> {
    Instant::now().checked_add(timeout)
}

fn poll_until_deadline(deadline: Option<Instant>, poll_cap: Duration) -> Option<Duration> {
    let Some(deadline) = deadline else {
        return Some(poll_cap);
    };
    deadline
        .checked_duration_since(Instant::now())
        .map(|remaining| remaining.min(poll_cap))
}

fn check_deadline(deadline: Option<Instant>, operation: &str) -> Result<()> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        Err(Error::timeout(operation))
    } else {
        Ok(())
    }
}

fn wait_conn_until<'a>(
    inner: &Arc<Inner>,
    state: MutexGuard<'a, ConnState>,
    deadline: Option<Instant>,
    operation: &str,
) -> Result<MutexGuard<'a, ConnState>> {
    let Some(deadline) = deadline else {
        return Ok(inner.cond.wait(state).unwrap());
    };
    let now = Instant::now();
    if now >= deadline {
        return Err(Error::timeout(operation));
    }
    let remaining = deadline.saturating_duration_since(now);
    let wait = remaining.min(MAX_CONDVAR_TIMED_WAIT);
    let (state, timed_out) = inner.cond.wait_timeout(state, wait).unwrap();
    if timed_out.timed_out() {
        check_deadline(Some(deadline), operation)?;
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::super::state::{
        late_data_per_stream_cap, marker_only_retained_count_locked,
        note_written_stream_frames_locked, pop_newest_accept_pending_locked,
        queue_peer_visible_pending_priority, reap_expired_hidden_tombstones_locked,
        reap_tombstones_for_memory_pressure_locked, reclaim_unseen_local_streams_after_go_away,
        record_tombstone_locked, record_used_marker_locked, retain_stream_open_info_locked,
        retain_stream_recv_reset_reason_locked, shrink_accept_queue_locked,
    };
    use super::*;
    use crate::config::{
        DEFAULT_ACCEPT_BACKLOG_BYTES_FLOOR, DEFAULT_LATE_DATA_PER_STREAM_CAP_FLOOR,
        DEFAULT_PER_STREAM_QUEUED_DATA_HIGH_WATERMARK_FLOOR,
        DEFAULT_SESSION_QUEUED_DATA_HIGH_WATERMARK_FLOOR, DEFAULT_URGENT_QUEUE_MAX_BYTES_FLOOR,
    };
    use crate::settings::Settings;
    use std::io::Cursor;

    #[derive(Default)]
    struct RecordingEstablishmentControl {
        read_timeouts: Mutex<Vec<Option<Duration>>>,
        write_timeouts: Mutex<Vec<Option<Duration>>>,
        closed: Mutex<bool>,
    }

    impl RecordingEstablishmentControl {
        fn write_timeouts(&self) -> Vec<Option<Duration>> {
            self.write_timeouts.lock().unwrap().clone()
        }

        fn is_closed(&self) -> bool {
            *self.closed.lock().unwrap()
        }
    }

    impl EstablishmentControl for RecordingEstablishmentControl {
        fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.read_timeouts.lock().unwrap().push(timeout);
            Ok(())
        }

        fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.write_timeouts.lock().unwrap().push(timeout);
            Ok(())
        }

        fn close(&self) -> io::Result<()> {
            *self.closed.lock().unwrap() = true;
            Ok(())
        }
    }

    #[derive(Default)]
    struct TimeoutReader;

    impl Read for TimeoutReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::TimedOut.into())
        }
    }

    #[derive(Default)]
    struct TimeoutWriter;

    impl Write for TimeoutWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::TimedOut.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn sample_session_stats(now: Instant) -> SessionStats {
        SessionStats {
            state: SessionState::Ready,
            sent_frames: 1,
            received_frames: 2,
            sent_data_bytes: 3,
            received_data_bytes: 4,
            open_streams: 5,
            accepted_streams: 6,
            active_streams: ActiveStreamStats {
                local_bidi: 1,
                local_uni: 2,
                peer_bidi: 3,
                peer_uni: 4,
                total: 10,
            },
            provisional: ProvisionalStats {
                bidi: 1,
                uni: 2,
                bidi_limit: 3,
                uni_limit: 4,
                limited: 5,
                expired: 6,
            },
            accept_backlog: AcceptBacklogStats {
                bidi: 1,
                uni: 2,
                limit: 3,
                bidi_limit: 4,
                uni_limit: 5,
                bytes: 6,
                bytes_limit: 7,
                refused: 8,
            },
            retention: RetentionStats {
                tombstones: 1,
                tombstone_limit: 2,
                marker_only_used_streams: 3,
                marker_only_used_stream_ranges: 4,
                marker_only_used_stream_limit: 5,
                retained_open_info_bytes: 6,
                retained_open_info_bytes_budget: 7,
                retained_peer_reason_bytes: 8,
                retained_peer_reason_bytes_budget: 9,
            },
            memory: MemoryStats {
                tracked_bytes: 1,
                hard_cap: 2,
                over_cap: true,
            },
            abuse: AbuseStats {
                ignored_control: 1,
                ignored_control_budget: 2,
                no_op_zero_data: 3,
                no_op_zero_data_budget: 4,
                inbound_ping: 5,
                inbound_ping_budget: 6,
                no_op_max_data: 7,
                no_op_max_data_budget: 8,
                no_op_blocked: 9,
                no_op_blocked_budget: 10,
                no_op_priority_update: 11,
                no_op_priority_update_budget: 12,
                dropped_priority_update: 13,
                inbound_control_frames: 14,
                inbound_control_frame_budget: 15,
                inbound_control_bytes: 16,
                inbound_control_bytes_budget: 17,
                inbound_ext_frames: 18,
                inbound_ext_frame_budget: 19,
                inbound_ext_bytes: 20,
                inbound_ext_bytes_budget: 21,
                inbound_mixed_frames: 22,
                inbound_mixed_frame_budget: 23,
                inbound_mixed_bytes: 24,
                inbound_mixed_bytes_budget: 25,
                group_rebucket_churn: 26,
                group_rebucket_churn_budget: 27,
                hidden_abort_churn: 28,
                hidden_abort_churn_budget: 29,
                visible_terminal_churn: 30,
                visible_terminal_churn_budget: 31,
            },
            hidden: HiddenStateStats {
                retained: 1,
                soft_limit: 2,
                hard_limit: 3,
                at_soft_limit: true,
                at_hard_limit: false,
                refused: 4,
                reaped: 5,
                unread_bytes_discarded: 6,
            },
            reasons: ReasonStats {
                reset: HashMap::from([(7, 8)]),
                reset_overflow: 9,
                abort: HashMap::from([(10, 11)]),
                abort_overflow: 12,
            },
            diagnostics: DiagnosticStats {
                dropped_priority_updates: 1,
                dropped_local_priority_updates: 2,
                late_data_after_close_read: 3,
                late_data_after_reset: 4,
                late_data_after_abort: 5,
                coalesced_terminal_signals: 6,
                superseded_terminal_signals: 7,
                visible_terminal_churn_events: 8,
                group_rebucket_events: 9,
                hidden_abort_churn_events: 10,
                skipped_close_on_dead_io: 11,
                close_frame_flush_errors: 12,
                close_completion_timeouts: 13,
                graceful_close_timeouts: 14,
                keepalive_timeouts: 15,
            },
            pressure: PressureStats {
                receive_backlog_bytes: 1,
                receive_backlog_high: true,
                aggregate_late_data_bytes: 2,
                aggregate_late_data_at_cap: false,
                retained_state_bytes: 3,
                tracked_buffered_bytes: 4,
                tracked_buffered_limit: 5,
                tracked_buffered_high: true,
                tracked_buffered_at_cap: false,
                buffered_receive_bytes: 6,
                recv_session_advertised_bytes: 7,
                recv_session_received_bytes: 8,
                recv_session_pending_bytes: 9,
                outstanding_ping_bytes: 10,
            },
            flush: FlushStats {
                count: 1,
                last_at: Some(now),
                last_frames: 2,
                last_bytes: 3,
            },
            telemetry: TelemetryStats {
                last_open_latency: Some(Duration::from_millis(4)),
                send_rate_estimate_bytes_per_second: 5,
            },
            progress: ProgressStats {
                inbound_frame_at: Some(now),
                control_progress_at: Some(now),
                transport_write_at: Some(now),
                stream_progress_at: Some(now),
                application_progress_at: Some(now),
                ping_sent_at: Some(now),
                pong_at: Some(now),
            },
            blocked_write_total: Duration::from_millis(6),
            writer_queue: WriterQueueStats {
                urgent_jobs: 1,
                advisory_jobs: 2,
                ordinary_jobs: 3,
                queued_bytes: 4,
                max_bytes: 5,
                urgent_queued_bytes: 6,
                urgent_max_bytes: 7,
                advisory_queued_bytes: 8,
                data_queued_bytes: 9,
                session_data_high_watermark: 10,
                per_stream_data_high_watermark: 11,
                pending_control_bytes: 12,
                pending_control_bytes_budget: 13,
                pending_priority_bytes: 14,
                pending_priority_bytes_budget: 15,
                max_batch_frames: 16,
            },
            liveness: LivenessStats {
                keepalive_interval: Duration::from_millis(1),
                keepalive_max_ping_interval: Duration::from_millis(2),
                keepalive_timeout: Duration::from_millis(3),
                ping_outstanding: true,
                ping_stalled: false,
                last_ping_rtt: Some(Duration::from_millis(4)),
                inbound_idle_for: Duration::from_millis(5),
                outbound_idle_for: Duration::from_millis(6),
            },
        }
    }

    #[test]
    fn session_stats_and_nested_stats_compare_by_value() {
        let now = Instant::now();
        let left = sample_session_stats(now);
        let right = sample_session_stats(now);
        assert_eq!(left, right);
        assert_eq!(left.active_streams, right.active_streams);
        assert_eq!(left.provisional, right.provisional);
        assert_eq!(left.accept_backlog, right.accept_backlog);
        assert_eq!(left.retention, right.retention);
        assert_eq!(left.memory, right.memory);
        assert_eq!(left.abuse, right.abuse);
        assert_eq!(left.hidden, right.hidden);
        assert_eq!(left.reasons, right.reasons);
        assert_eq!(left.diagnostics, right.diagnostics);
        assert_eq!(left.pressure, right.pressure);
        assert_eq!(left.flush, right.flush);
        assert_eq!(left.telemetry, right.telemetry);
        assert_eq!(left.progress, right.progress);
        assert_eq!(left.writer_queue, right.writer_queue);
        assert_eq!(left.liveness, right.liveness);
    }

    #[test]
    fn terminal_stats_hide_live_ping_and_keepalive_schedule_surface() {
        let inner = test_inner();
        let now = Instant::now();
        let slot = Arc::new(PingSlot {
            result: Mutex::new(None),
            cond: Condvar::new(),
            sent_at: now - Duration::from_secs(4),
            accepts_padded_pong: false,
        });
        {
            let mut state = inner.state.lock().unwrap();
            state.state = SessionState::Closed;
            state.keepalive_ping = Some(KeepalivePing {
                payload: vec![1, 2, 3],
                sent_at: now - Duration::from_secs(4),
                accepts_padded_pong: false,
            });
            state.ping_waiter = Some(UserPing {
                payload: vec![4, 5, 6, 7],
                slot,
            });
            state.last_ping_sent_at = Some(now - Duration::from_secs(4));
            state.last_pong_at = Some(now - Duration::from_secs(1));
            state.last_ping_rtt = Some(Duration::from_secs(2));
            state.read_idle_ping_due_at = Some(now + Duration::from_secs(1));
            state.write_idle_ping_due_at = Some(now + Duration::from_secs(1));
            state.max_ping_due_at = Some(now + Duration::from_secs(1));
        }

        let stats = Conn { inner }.stats();

        assert_eq!(stats.liveness.keepalive_interval, Duration::ZERO);
        assert_eq!(stats.liveness.keepalive_max_ping_interval, Duration::ZERO);
        assert!(!stats.liveness.keepalive_timeout.is_zero());
        assert!(!stats.liveness.ping_outstanding);
        assert!(!stats.liveness.ping_stalled);
        assert_eq!(stats.liveness.last_ping_rtt, None);
        assert_eq!(stats.progress.ping_sent_at, None);
        assert_eq!(stats.progress.pong_at, None);
        assert_eq!(stats.pressure.outstanding_ping_bytes, 0);
    }

    #[test]
    fn active_stream_stats_total_saturates() {
        let stats = active_stream_stats(ActiveStreamStats {
            local_bidi: u64::MAX,
            local_uni: 1,
            peer_bidi: 0,
            peer_uni: 0,
            total: 0,
        });

        assert_eq!(stats.total, u64::MAX);
    }

    #[derive(Clone)]
    struct FatalCloseTimeoutWriter {
        calls: Arc<Mutex<usize>>,
    }

    impl Write for FatalCloseTimeoutWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let mut calls = self.calls.lock().unwrap();
            *calls += 1;
            if *calls == 1 {
                return Ok(buf.len());
            }
            Err(io::ErrorKind::TimedOut.into())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn controlled_establishment_read_timeout_is_bounded_and_closes_transport() {
        let control = RecordingEstablishmentControl::default();
        let err = match Conn::with_config_control(
            TimeoutReader,
            TimeoutWriter,
            Config::default(),
            Some(&control),
            None,
            None,
            None,
        ) {
            Ok(_) => panic!("controlled establishment unexpectedly succeeded"),
            Err(err) => err,
        };

        assert_eq!(err.code(), Some(ErrorCode::Internal));
        assert!(err.is_timeout());
        assert!(control.is_closed());
        assert!(control
            .write_timeouts()
            .contains(&Some(ESTABLISHMENT_SUCCESS_WRITE_WAIT)));
    }

    #[test]
    fn controlled_establishment_failure_bounds_fatal_close_write() {
        let control = RecordingEstablishmentControl::default();
        let mut invalid_peer = Config::responder()
            .local_preface()
            .unwrap()
            .marshal()
            .unwrap();
        invalid_peer[5] = 0xff;
        let writer_calls = Arc::new(Mutex::new(0));
        let err = match Conn::with_config_control(
            Cursor::new(invalid_peer),
            FatalCloseTimeoutWriter {
                calls: writer_calls.clone(),
            },
            Config::default(),
            Some(&control),
            None,
            None,
            None,
        ) {
            Ok(_) => panic!("controlled establishment unexpectedly succeeded"),
            Err(err) => err,
        };

        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert!(control.is_closed());
        assert_eq!(*writer_calls.lock().unwrap(), 2);
        let write_timeouts = control.write_timeouts();
        assert!(write_timeouts.contains(&Some(ESTABLISHMENT_SUCCESS_WRITE_WAIT)));
        assert!(write_timeouts.contains(&Some(ESTABLISHMENT_EXPEDITE_TIMEOUT)));
        assert!(write_timeouts.contains(&Some(ESTABLISHMENT_FAILURE_WRITE_WAIT)));
    }

    fn test_inner() -> Arc<Inner> {
        let config = Config::default();
        let local_preface = config.local_preface().unwrap();
        let peer_preface = Config::responder().local_preface().unwrap();
        let negotiated = negotiate_prefaces(&local_preface, &peer_preface).unwrap();
        let now = Instant::now();

        Arc::new(Inner {
            write_queue: Arc::new(WriteQueue::new(WriteQueueLimits {
                max_bytes: 1 << 20,
                urgent_max_bytes: 1 << 20,
                session_data_max_bytes: 1 << 20,
                per_stream_data_max_bytes: 1 << 20,
                pending_control_max_bytes: 1 << 20,
                pending_priority_max_bytes: 1 << 20,
                max_batch_bytes: default_write_batch_cost_limit(
                    peer_preface.settings.max_frame_payload,
                ),
                max_batch_frames: config.write_batch_max_frames,
            })),
            transport_control: None,
            local_addr: None,
            peer_addr: None,
            state: Mutex::new(ConnState {
                state: SessionState::Ready,
                close_error: None,
                peer_close_error: None,
                peer_go_away_error: None,
                session_closed_event_sent: false,
                graceful_close_active: false,
                ignore_peer_non_close: false,
                streams: HashMap::new(),
                scheduler: Default::default(),
                inflight_data_by_stream: HashMap::new(),
                tombstones: HashMap::new(),
                tombstone_order: VecDeque::new(),
                hidden_tombstone_order: VecDeque::new(),
                tombstone_limit: config.tombstone_limit,
                hidden_tombstone_limit: 0,
                hidden_tombstones: 0,
                used_markers: HashMap::new(),
                used_marker_order: VecDeque::new(),
                used_marker_ranges: Vec::new(),
                used_marker_range_mode: false,
                used_marker_limit: config.used_marker_limit,
                provisional_bidi: VecDeque::new(),
                provisional_uni: VecDeque::new(),
                accept_bidi: VecDeque::new(),
                accept_uni: VecDeque::new(),
                accept_backlog_limit: DEFAULT_ACCEPT_BACKLOG_LIMIT,
                accept_limit_bidi: usize::MAX,
                accept_limit_uni: usize::MAX,
                accept_backlog_bytes: 0,
                accept_backlog_bytes_limit: usize::MAX,
                accept_backlog_refused: 0,
                retained_open_info_bytes: 0,
                retained_open_info_bytes_budget: usize::MAX,
                retained_peer_reason_bytes: 0,
                retained_peer_reason_bytes_budget: usize::MAX,
                reset_reason_counts: HashMap::new(),
                reset_reason_overflow: 0,
                abort_reason_counts: HashMap::new(),
                abort_reason_overflow: 0,
                next_accept_seq: 1,
                next_local_bidi: 4,
                next_local_uni: 2,
                max_provisional_bidi: config.max_provisional_streams_bidi,
                max_provisional_uni: config.max_provisional_streams_uni,
                provisional_open_limited_count: 0,
                provisional_open_expired_count: 0,
                next_peer_bidi: 1,
                next_peer_uni: 3,
                active: ActiveStreamStats::default(),
                send_session_used: 0,
                send_session_max: u64::MAX,
                send_session_blocked_at: None,
                recv_session_used: 0,
                recv_session_buffered: 0,
                recv_session_retained: 0,
                recv_session_advertised: u64::MAX,
                recv_session_pending: 0,
                recv_replenish_retry: false,
                late_data_per_stream_cap: None,
                late_data_aggregate_received: 0,
                late_data_aggregate_cap: u64::MAX,
                ignored_control_window_start: None,
                ignored_control_count: 0,
                ignored_control_budget: config.ignored_control_budget,
                no_op_zero_data_window_start: None,
                no_op_zero_data_count: 0,
                no_op_zero_data_budget: config.no_op_zero_data_budget,
                inbound_ping_window_start: None,
                inbound_ping_count: 0,
                inbound_ping_budget: config.inbound_ping_budget,
                no_op_max_data_window_start: None,
                no_op_max_data_count: 0,
                no_op_max_data_budget: config.no_op_max_data_budget,
                no_op_blocked_window_start: None,
                no_op_blocked_count: 0,
                no_op_blocked_budget: config.no_op_blocked_budget,
                no_op_priority_update_window_start: None,
                no_op_priority_update_count: 0,
                no_op_priority_update_budget: config.no_op_priority_update_budget,
                dropped_priority_update_count: 0,
                dropped_local_priority_update_count: 0,
                late_data_after_close_read_bytes: 0,
                late_data_after_reset_bytes: 0,
                late_data_after_abort_bytes: 0,
                superseded_terminal_signal_count: 0,
                hidden_streams_refused: 0,
                hidden_streams_reaped: 0,
                hidden_unread_bytes_discarded: 0,
                skipped_close_on_dead_io_count: 0,
                close_frame_flush_error_count: 0,
                close_completion_timeout_count: 0,
                graceful_close_timeout_count: 0,
                keepalive_timeout_count: 0,
                abuse_window: config.abuse_window,
                inbound_control_window_start: None,
                inbound_control_frames: 0,
                inbound_control_bytes: 0,
                inbound_control_frame_budget: config.inbound_control_frame_budget,
                inbound_control_bytes_budget: DEFAULT_INBOUND_CONTROL_BYTES_BUDGET_FLOOR,
                inbound_ext_window_start: None,
                inbound_ext_frames: 0,
                inbound_ext_bytes: 0,
                inbound_ext_frame_budget: config.inbound_ext_frame_budget,
                inbound_ext_bytes_budget: DEFAULT_INBOUND_EXT_BYTES_BUDGET_FLOOR,
                inbound_mixed_window_start: None,
                inbound_mixed_frames: 0,
                inbound_mixed_bytes: 0,
                inbound_mixed_frame_budget: config.inbound_mixed_frame_budget.unwrap_or(
                    config
                        .inbound_control_frame_budget
                        .max(config.inbound_ext_frame_budget),
                ),
                inbound_mixed_bytes_budget: DEFAULT_INBOUND_CONTROL_BYTES_BUDGET_FLOOR,
                group_rebucket_churn_window_start: None,
                group_rebucket_churn_count: 0,
                group_rebucket_churn_budget: config.group_rebucket_churn_budget,
                hidden_abort_churn_window: config.hidden_abort_churn_window,
                hidden_abort_churn_window_start: None,
                hidden_abort_churn_count: 0,
                hidden_abort_churn_budget: config.hidden_abort_churn_budget,
                visible_terminal_churn_window: config.visible_terminal_churn_window,
                visible_terminal_churn_window_start: None,
                visible_terminal_churn_count: 0,
                visible_terminal_churn_budget: config.visible_terminal_churn_budget,
                local_go_away_bidi: MAX_VARINT62,
                local_go_away_uni: MAX_VARINT62,
                local_go_away_issued: false,
                peer_go_away_bidi: MAX_VARINT62,
                peer_go_away_uni: MAX_VARINT62,
                ping_waiter: None,
                canceled_ping_payload: None,
                keepalive_ping: None,
                last_inbound_at: now,
                last_outbound_at: now,
                send_rate_estimate: 0,
                flush_count: 0,
                last_flush_at: None,
                last_flush_frames: 0,
                last_flush_bytes: 0,
                last_open_latency: None,
                last_ping_rtt: None,
                last_control_progress_at: now,
                last_stream_progress_at: None,
                last_application_progress_at: None,
                last_ping_sent_at: None,
                last_pong_at: None,
                blocked_write_total: Duration::ZERO,
                read_idle_ping_due_at: None,
                write_idle_ping_due_at: None,
                max_ping_due_at: None,
                keepalive_jitter_state: 0,
                ping_nonce_state: 0,
                last_ping_padding_len: 0,
                sent_frames: 0,
                received_frames: 0,
                sent_data_bytes: 0,
                received_data_bytes: 0,
                accepted_streams: 0,
            }),
            cond: Condvar::new(),
            local_preface,
            peer_preface,
            negotiated,
            close_drain_timeout: config.close_drain_timeout,
            go_away_drain_interval: config.go_away_drain_interval,
            session_memory_cap: None,
            session_data_high_watermark: 1 << 20,
            per_stream_data_high_watermark: 1 << 20,
            stop_sending_graceful_drain_window: None,
            stop_sending_graceful_tail_cap: None,
            keepalive_interval: config.keepalive_interval,
            keepalive_max_ping_interval: config.keepalive_max_ping_interval,
            keepalive_timeout: config.keepalive_timeout,
            ping_padding: false,
            ping_padding_min_bytes: 0,
            ping_padding_max_bytes: 0,
            event_handler: None,
            event_dispatch: Mutex::new(EventDispatchState {
                emitting: false,
                queue: VecDeque::new(),
            }),
        })
    }

    fn test_disposition(
        action: TerminalDataAction,
        cause: LateDataCause,
    ) -> TerminalDataDisposition {
        TerminalDataDisposition { action, cause }
    }

    fn test_tombstone(hidden: bool, disposition: TerminalDataDisposition) -> StreamTombstone {
        StreamTombstone {
            data_disposition: disposition,
            late_data_received: 0,
            late_data_cap: 1,
            hidden,
            created_at: Instant::now(),
        }
    }

    #[test]
    fn tombstone_replacement_cleans_hidden_order() {
        let inner = test_inner();
        let disposition = test_disposition(TerminalDataAction::Ignore, LateDataCause::None);
        let mut state = inner.state.lock().unwrap();
        state.hidden_tombstone_limit = 16;

        record_tombstone_locked(&mut state, 4, test_tombstone(true, disposition));
        assert_eq!(state.hidden_tombstones, 1);
        assert_eq!(
            state
                .hidden_tombstone_order
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![4]
        );

        record_tombstone_locked(&mut state, 4, test_tombstone(false, disposition));

        assert_eq!(state.hidden_tombstones, 0);
        assert!(state.hidden_tombstone_order.is_empty());
        assert_eq!(state.hidden_tombstone_order.capacity(), 0);
        assert!(state
            .tombstones
            .get(&4)
            .is_some_and(|tombstone| !tombstone.hidden));
    }

    #[test]
    fn expired_hidden_tombstone_releases_orders_and_preserves_marker() {
        let inner = test_inner();
        let disposition = test_disposition(TerminalDataAction::Ignore, LateDataCause::Abort);
        let mut tombstone = test_tombstone(true, disposition);
        tombstone.created_at = Instant::now() - Duration::from_secs(2);
        let mut state = inner.state.lock().unwrap();
        state.hidden_tombstone_limit = 16;
        state.tombstones = HashMap::with_capacity(2048);
        state.tombstones.insert(4, tombstone);
        state.tombstone_order = VecDeque::with_capacity(2048);
        state.tombstone_order.push_back(4);
        state.hidden_tombstone_order = VecDeque::with_capacity(2048);
        state.hidden_tombstone_order.push_back(4);
        state.hidden_tombstones = 1;

        reap_expired_hidden_tombstones_locked(&mut state, Instant::now());

        assert!(state.tombstones.is_empty());
        assert!(state.tombstone_order.is_empty());
        assert_eq!(state.tombstone_order.capacity(), 0);
        assert!(state.hidden_tombstone_order.is_empty());
        assert_eq!(state.hidden_tombstone_order.capacity(), 0);
        assert_eq!(state.hidden_tombstones, 0);
        assert_eq!(state.used_markers.get(&4), Some(&disposition));
    }

    #[test]
    fn tracked_memory_pressure_reaps_oldest_visible_tombstone_to_marker() {
        let mut inner = test_inner();
        Arc::get_mut(&mut inner).unwrap().session_memory_cap = Some(64);
        let disposition = test_disposition(TerminalDataAction::Ignore, LateDataCause::None);
        let mut state = inner.state.lock().unwrap();
        state.tombstone_limit = 16;
        state
            .tombstones
            .insert(4, test_tombstone(false, disposition));
        state
            .tombstones
            .insert(8, test_tombstone(false, disposition));
        state.tombstone_order.push_back(999);
        state.tombstone_order.push_back(4);
        state.tombstone_order.push_back(8);

        let writer = inner.write_queue.stats();
        reap_tombstones_for_memory_pressure_locked(&inner, &mut state, &writer);

        assert!(!state.tombstones.contains_key(&4));
        assert!(state.tombstones.contains_key(&8));
        assert_eq!(
            state.tombstone_order.iter().copied().collect::<Vec<_>>(),
            vec![8]
        );
        assert_eq!(state.used_markers.get(&4), Some(&disposition));
        assert_eq!(marker_only_retained_count_locked(&state), 1);
    }

    #[test]
    fn hidden_tombstone_hard_cap_sheds_newest_and_cleans_order() {
        let inner = test_inner();
        let disposition = test_disposition(TerminalDataAction::Ignore, LateDataCause::Abort);
        let mut state = inner.state.lock().unwrap();
        state.tombstone_limit = 16;
        state.hidden_tombstone_limit = 2;

        for stream_id in [4, 8, 12] {
            record_tombstone_locked(&mut state, stream_id, test_tombstone(true, disposition));
        }

        assert_eq!(state.hidden_tombstones, 2);
        assert!(state.tombstones.contains_key(&4));
        assert!(state.tombstones.contains_key(&8));
        assert!(!state.tombstones.contains_key(&12));
        assert_eq!(
            state
                .hidden_tombstone_order
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![4, 8]
        );
        assert_eq!(state.used_markers.get(&12), Some(&disposition));
    }

    #[test]
    fn visible_tombstone_insert_drops_stale_hidden_tail_without_shedding_live_hidden() {
        let inner = test_inner();
        let hidden = test_disposition(TerminalDataAction::Ignore, LateDataCause::Abort);
        let visible = test_disposition(TerminalDataAction::Ignore, LateDataCause::None);
        let mut state = inner.state.lock().unwrap();
        state.tombstone_limit = 16;
        state.hidden_tombstone_limit = 2;

        for stream_id in [4, 8] {
            record_tombstone_locked(&mut state, stream_id, test_tombstone(true, hidden));
        }
        state.hidden_tombstone_order.push_back(10_000);

        record_tombstone_locked(&mut state, 12, test_tombstone(false, visible));

        assert_eq!(state.hidden_tombstones, 2);
        assert!(state
            .tombstones
            .get(&4)
            .is_some_and(|tombstone| tombstone.hidden));
        assert!(state
            .tombstones
            .get(&8)
            .is_some_and(|tombstone| tombstone.hidden));
        assert!(state
            .tombstones
            .get(&12)
            .is_some_and(|tombstone| !tombstone.hidden));
        assert_eq!(
            state
                .hidden_tombstone_order
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            vec![4, 8]
        );
    }

    #[test]
    fn marker_only_range_compaction_releases_empty_map_backing() {
        let inner = test_inner();
        let disposition = test_disposition(TerminalDataAction::Ignore, LateDataCause::None);
        let mut state = inner.state.lock().unwrap();
        state.used_marker_limit = 4;
        state.used_markers = HashMap::with_capacity(128);

        for i in 0..64u64 {
            record_used_marker_locked(&mut state, 4 + i * 4, disposition);
        }

        assert!(state.used_markers.is_empty());
        assert_eq!(state.used_markers.capacity(), 0);
        assert!(state.used_marker_order.is_empty());
        assert_eq!(state.used_marker_order.capacity(), 0);
        assert_eq!(state.used_marker_ranges.len(), 1);
        assert_eq!(marker_only_retained_count_locked(&state), 1);
        assert_eq!(tracked_retained_state_memory_locked(&inner, &state), 64);
    }

    #[test]
    fn range_mode_marker_update_drops_stale_map_entry() {
        let inner = test_inner();
        let graceful = test_disposition(TerminalDataAction::Ignore, LateDataCause::None);
        let abortive = test_disposition(
            TerminalDataAction::Abort(ErrorCode::StreamClosed.as_u64()),
            LateDataCause::Abort,
        );
        let mut state = inner.state.lock().unwrap();
        state.used_marker_range_mode = true;
        state.used_marker_ranges.push(UsedMarkerRange {
            start: 4,
            end: 4 + 63 * 4,
            disposition: graceful,
        });
        state.used_markers = HashMap::with_capacity(64);
        state.used_markers.insert(4, graceful);

        record_used_marker_locked(&mut state, 4, abortive);

        assert!(state.used_markers.is_empty());
        assert_eq!(state.used_markers.capacity(), 0);
        assert_eq!(state.used_marker_ranges.len(), 2);
        assert_eq!(marker_only_retained_count_locked(&state), 2);
    }

    fn test_local_opened_bidi(inner: &Arc<Inner>, stream_id: u64) -> Arc<StreamInner> {
        Arc::new(StreamInner {
            conn: inner.clone(),
            id: std::sync::atomic::AtomicU64::new(stream_id),
            bidi: true,
            opened_locally: true,
            application_visible: true,
            local_send: true,
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
                pending_data_frames: 1,
                pending_terminal_frames: 0,
                send_fin: false,
                send_reset: None,
                send_reset_from_stop: false,
                stopped_by_peer: None,
                provisional_created_at: None,
                opened_on_wire: true,
                peer_visible: false,
                received_open: false,
                send_used: 6,
                send_max: u64::MAX,
                send_blocked_at: None,
                recv_used: 0,
                recv_advertised: u64::MAX,
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
                active_counted: true,
                visible_churn_counted: false,
                retained_recv_reset_reason_bytes: 0,
                retained_abort_reason_bytes: 0,
                retained_stopped_reason_bytes: 0,
            }),
            cond: Condvar::new(),
        })
    }

    fn test_peer_opened_stream(inner: &Arc<Inner>, stream_id: u64, bidi: bool) -> Arc<StreamInner> {
        Arc::new(StreamInner {
            conn: inner.clone(),
            id: std::sync::atomic::AtomicU64::new(stream_id),
            bidi,
            opened_locally: false,
            application_visible: true,
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
                received_open: true,
                send_used: 0,
                send_max: u64::MAX,
                send_blocked_at: None,
                recv_used: 0,
                recv_advertised: u64::MAX,
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
                accept_pending: true,
                accept_seq: 0,
                accept_backlog_bytes: 0,
                active_counted: true,
                visible_churn_counted: false,
                retained_recv_reset_reason_bytes: 0,
                retained_abort_reason_bytes: 0,
                retained_stopped_reason_bytes: 0,
            }),
            cond: Condvar::new(),
        })
    }

    #[test]
    fn oversized_deadline_is_treated_as_unbounded() {
        assert!(deadline_after(Duration::MAX).is_none());
        assert!(timeout_deadline("open", Duration::MAX).unwrap().is_none());
        assert_eq!(remaining_timeout(None), None);
        assert_eq!(
            poll_until_deadline(None, Duration::from_millis(7)),
            Some(Duration::from_millis(7))
        );
    }

    #[test]
    fn go_away_drain_interval_uses_recent_rtt_floor_unless_disabled() {
        assert_eq!(
            effective_go_away_drain_interval(Duration::from_millis(10), None),
            Duration::from_millis(10)
        );
        assert_eq!(
            effective_go_away_drain_interval(
                Duration::from_millis(10),
                Some(Duration::from_millis(800)),
            ),
            Duration::from_millis(200)
        );
        assert_eq!(
            effective_go_away_drain_interval(Duration::ZERO, Some(Duration::from_millis(800)),),
            Duration::ZERO
        );
    }

    #[test]
    fn close_drain_timeout_uses_observed_rtt_floor_when_default() {
        assert_eq!(
            effective_close_drain_timeout(DEFAULT_CLOSE_DRAIN_TIMEOUT, None),
            DEFAULT_CLOSE_DRAIN_TIMEOUT
        );
        assert_eq!(
            effective_close_drain_timeout(
                DEFAULT_CLOSE_DRAIN_TIMEOUT,
                Some(Duration::from_millis(600)),
            ),
            Duration::from_millis(2_500)
        );
        assert_eq!(
            effective_close_drain_timeout(
                DEFAULT_CLOSE_DRAIN_TIMEOUT,
                Some(Duration::from_secs(2)),
            ),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn explicit_close_drain_timeout_override_wins_over_observed_rtt() {
        assert_eq!(
            effective_close_drain_timeout(Duration::from_millis(200), Some(Duration::from_secs(2)),),
            Duration::from_millis(200)
        );
        assert_eq!(
            effective_close_drain_timeout(Duration::ZERO, Some(Duration::from_secs(2))),
            Duration::ZERO
        );
    }

    #[test]
    fn keepalive_poll_waits_for_earliest_idle_or_max_ping_deadline() {
        let inner = test_inner();
        let now = Instant::now();
        {
            let mut state = inner.state.lock().unwrap();
            state.read_idle_ping_due_at = Some(now + Duration::from_millis(10));
            state.write_idle_ping_due_at = Some(now + Duration::from_millis(1_000));
            state.max_ping_due_at = Some(now + Duration::from_millis(10_000));
        }

        match super::super::liveness::poll_keepalive(&inner, now).unwrap() {
            super::super::liveness::KeepaliveAction::Wait(Some(wait)) => {
                assert_eq!(wait, Duration::from_millis(10));
            }
            _ => panic!("keepalive poll should wait for earliest deadline"),
        }
    }

    #[test]
    fn missing_idle_schedules_are_recovered_from_last_activity_times() {
        let inner = test_inner();
        let now = Instant::now();
        {
            let mut state = inner.state.lock().unwrap();
            state.keepalive_jitter_state = 1;
            state.last_inbound_at = now - Duration::from_secs(120);
            state.last_outbound_at = now - Duration::from_secs(90);
            state.read_idle_ping_due_at = None;
            state.write_idle_ping_due_at = None;
            state.max_ping_due_at = None;
        }

        match super::super::liveness::poll_keepalive(&inner, now).unwrap() {
            super::super::liveness::KeepaliveAction::SendPing(payload) => {
                assert_eq!(payload.len(), 8);
            }
            _ => panic!("stale recovered idle schedules should trigger a keepalive ping"),
        }

        let state = inner.state.lock().unwrap();
        assert!(state.read_idle_ping_due_at.unwrap() < now);
        assert!(state.write_idle_ping_due_at.unwrap() < now);
        assert!(state.max_ping_due_at.unwrap() > now);
    }

    #[test]
    fn matching_pong_refreshes_idle_schedules_and_records_rtt() {
        let inner = test_inner();
        let now = Instant::now();
        let old_due = now - Duration::from_millis(1);
        let sent_at = now - Duration::from_millis(20);
        let mut state = inner.state.lock().unwrap();
        state.keepalive_jitter_state = 1;
        state.read_idle_ping_due_at = Some(old_due);
        state.write_idle_ping_due_at = Some(old_due);

        super::super::liveness::note_matching_pong_locked(&inner, &mut state, now, sent_at);

        assert_eq!(state.last_pong_at, Some(now));
        assert_eq!(state.last_ping_rtt, Some(Duration::from_millis(20)));
        assert!(state.read_idle_ping_due_at.unwrap() > now);
        assert!(state.write_idle_ping_due_at.unwrap() > now);
    }

    #[test]
    fn removed_ping_waiter_refreshes_idle_schedules_and_releases_bytes() {
        let inner = test_inner();
        let conn = Conn {
            inner: inner.clone(),
        };
        let now = Instant::now();
        let slot = Arc::new(PingSlot {
            result: Mutex::new(None),
            cond: Condvar::new(),
            sent_at: now,
            accepts_padded_pong: false,
        });
        let mut payload = 7u64.to_be_bytes().to_vec();
        payload.extend_from_slice(b"timeout");
        {
            let mut state = inner.state.lock().unwrap();
            state.keepalive_jitter_state = 1;
            state.read_idle_ping_due_at = Some(now);
            state.write_idle_ping_due_at = Some(now);
            state.ping_waiter = Some(UserPing {
                payload,
                slot: slot.clone(),
            });
        }

        assert!(conn.remove_ping_waiter(&slot, true));

        let state = inner.state.lock().unwrap();
        assert!(state.ping_waiter.is_none());
        assert!(state.canceled_ping_payload.is_some());
        assert_eq!(outstanding_ping_bytes_locked(&state), 0);
        assert!(state.read_idle_ping_due_at.unwrap() > now);
        assert!(state.write_idle_ping_due_at.unwrap() > now);
    }

    #[test]
    fn completed_outbound_write_records_flush_stats_and_refreshes_write_idle() {
        let inner = test_inner();
        let before = Instant::now();
        {
            let mut state = inner.state.lock().unwrap();
            state.keepalive_jitter_state = 1;
            state.write_idle_ping_due_at = Some(before);
        }

        super::super::liveness::record_outbound_activity(
            &inner,
            4096,
            Duration::from_secs(1),
            2,
            3,
        );

        let state = inner.state.lock().unwrap();
        assert_eq!(state.sent_frames, 2);
        assert_eq!(state.sent_data_bytes, 3);
        assert_eq!(state.flush_count, 1);
        assert_eq!(state.last_flush_frames, 2);
        assert_eq!(state.last_flush_bytes, 4096);
        assert_eq!(state.send_rate_estimate, 4096);
        assert!(state.last_flush_at.unwrap() >= before);
        assert!(state.last_outbound_at >= before);
        assert!(state.write_idle_ping_due_at.unwrap() > state.last_outbound_at);
    }

    #[test]
    fn queued_control_frame_does_not_refresh_write_idle_deadline() {
        let inner = test_inner();
        let due = Instant::now() + Duration::from_secs(10);
        {
            let mut state = inner.state.lock().unwrap();
            state.write_idle_ping_due_at = Some(due);
            state.flush_count = 0;
        }

        inner
            .queue_frame(Frame {
                frame_type: FrameType::Ping,
                flags: 0,
                stream_id: 0,
                payload: vec![0; 8],
            })
            .unwrap();

        let state = inner.state.lock().unwrap();
        assert_eq!(state.write_idle_ping_due_at, Some(due));
        assert_eq!(state.flush_count, 0);
        assert!(state.last_flush_at.is_none());
    }

    #[test]
    fn runtime_default_caps_match_policy_floors() {
        let settings = Settings {
            max_frame_payload: 1,
            max_control_payload_bytes: 1,
            ..Settings::default()
        };

        assert_eq!(
            default_per_stream_queued_data_high_watermark(settings, settings),
            DEFAULT_PER_STREAM_QUEUED_DATA_HIGH_WATERMARK_FLOOR
        );
        assert_eq!(
            default_session_queued_data_high_watermark(1),
            DEFAULT_SESSION_QUEUED_DATA_HIGH_WATERMARK_FLOOR
        );
        assert_eq!(
            default_urgent_queue_max_bytes(settings, settings),
            DEFAULT_URGENT_QUEUE_MAX_BYTES_FLOOR
        );
        assert_eq!(
            default_accept_backlog_bytes_limit(1),
            DEFAULT_ACCEPT_BACKLOG_BYTES_FLOOR
        );
        assert_eq!(
            late_data_per_stream_cap(None, 0, 1),
            DEFAULT_LATE_DATA_PER_STREAM_CAP_FLOOR
        );
    }

    #[test]
    fn newest_accept_pending_uses_unsigned_sequence_order_near_signed_boundary() {
        let inner = test_inner();
        let old_uni = test_peer_opened_stream(&inner, 3, false);
        let new_bidi = test_peer_opened_stream(&inner, 1, true);
        old_uni.state.lock().unwrap().accept_seq = i64::MAX as u64;
        new_bidi.state.lock().unwrap().accept_seq = (i64::MAX as u64) + 1;

        let newest = {
            let mut state = inner.state.lock().unwrap();
            state.accept_uni.push_back(old_uni.clone());
            state.accept_bidi.push_back(new_bidi.clone());
            pop_newest_accept_pending_locked(&mut state).expect("newest accepted stream")
        };

        assert!(Arc::ptr_eq(&newest, &new_bidi));
    }

    #[test]
    fn drained_large_accept_queue_releases_deque_storage() {
        let inner = test_inner();
        let retained_capacity = {
            let mut state = inner.state.lock().unwrap();
            for i in 0..1100 {
                state
                    .accept_bidi
                    .push_back(test_peer_opened_stream(&inner, 1 + i * 4, true));
            }
            let retained_capacity = state.accept_bidi.capacity();
            assert!(retained_capacity >= 1100);

            while state.accept_bidi.pop_front().is_some() {
                shrink_accept_queue_locked(&mut state, true);
            }
            retained_capacity
        };

        let state = inner.state.lock().unwrap();
        assert_eq!(state.accept_bidi.len(), 0);
        assert!(state.accept_bidi.capacity() < retained_capacity);
    }

    #[test]
    fn drained_large_provisional_queue_releases_deque_storage() {
        let inner = test_inner();
        let mut streams = Vec::new();
        let retained_capacity = {
            let mut state = inner.state.lock().unwrap();
            state.provisional_bidi = VecDeque::with_capacity(2048);
            for _ in 0..1100 {
                let stream = test_local_opened_bidi(&inner, 0);
                {
                    let mut stream_state = stream.state.lock().unwrap();
                    stream_state.opened_on_wire = false;
                    stream_state.pending_data_frames = 0;
                    stream_state.provisional_created_at = Some(Instant::now());
                    stream_state.active_counted = false;
                    stream_state.send_used = 0;
                }
                state.provisional_bidi.push_back(stream.clone());
                streams.push(stream);
            }
            state.provisional_bidi.capacity()
        };
        assert!(retained_capacity >= 1100);

        for stream in streams {
            Stream { inner: stream }
                .close_with_error(ErrorCode::Cancelled.as_u64(), "cancel")
                .unwrap();
        }

        let state = inner.state.lock().unwrap();
        assert_eq!(state.provisional_bidi.len(), 0);
        assert!(state.provisional_bidi.capacity() < retained_capacity);
    }

    #[test]
    fn release_session_runtime_state_drops_retained_backings_and_accounting() {
        let inner = test_inner();
        let live = test_peer_opened_stream(&inner, 1, true);
        let provisional = test_local_opened_bidi(&inner, 4);
        let disposition = TerminalDataDisposition {
            action: TerminalDataAction::Ignore,
            cause: LateDataCause::None,
        };
        let slot = Arc::new(PingSlot {
            result: Mutex::new(None),
            cond: Condvar::new(),
            sent_at: Instant::now(),
            accepts_padded_pong: false,
        });

        {
            let mut state = inner.state.lock().unwrap();
            state.streams = HashMap::with_capacity(2048);
            state.streams.insert(1, live.clone());
            state.provisional_bidi = VecDeque::with_capacity(2048);
            state.provisional_bidi.push_back(provisional.clone());
            state.accept_bidi = VecDeque::with_capacity(2048);
            state.accept_bidi.push_back(live.clone());
            state.inflight_data_by_stream = HashMap::with_capacity(2048);
            state.inflight_data_by_stream.insert(1, 3);
            state.tombstones = HashMap::with_capacity(2048);
            state.tombstones.insert(
                9,
                StreamTombstone {
                    data_disposition: disposition,
                    late_data_received: 0,
                    late_data_cap: 1,
                    hidden: true,
                    created_at: Instant::now(),
                },
            );
            state.tombstone_order = VecDeque::with_capacity(2048);
            state.tombstone_order.push_back(9);
            state.hidden_tombstone_order = VecDeque::with_capacity(2048);
            state.hidden_tombstone_order.push_back(9);
            state.hidden_tombstones = 1;
            state.used_markers = HashMap::with_capacity(2048);
            state.used_markers.insert(13, disposition);
            state.used_marker_order = VecDeque::with_capacity(2048);
            state.used_marker_order.push_back(13);
            state.used_marker_ranges = Vec::with_capacity(2048);
            state.used_marker_ranges.push(UsedMarkerRange {
                start: 17,
                end: 17,
                disposition,
            });
            state.used_marker_range_mode = true;
            state.accept_backlog_bytes = 3;
            state.active.peer_bidi = 1;
            state.active.local_bidi = 1;
            state.send_session_used = 7;
            state.send_session_blocked_at = Some(7);
            state.recv_session_used = 11;
            state.recv_session_buffered = 3;
            state.recv_session_retained = 3;
            state.recv_session_pending = 5;
            state.keepalive_ping = Some(KeepalivePing {
                payload: vec![1],
                sent_at: Instant::now(),
                accepts_padded_pong: false,
            });
            state.canceled_ping_payload = Some(CanceledPingPayload {
                nonce: 1,
                hash: 2,
                len: 3,
                accepts_padded_pong: false,
            });
            state.ping_waiter = Some(UserPing {
                payload: vec![9; 16],
                slot: slot.clone(),
            });

            {
                let mut stream_state = live.state.lock().unwrap();
                stream_state
                    .recv_buf
                    .push_chunk_with_offset(vec![1, 2, 3], 0);
                stream_state.accept_pending = true;
                stream_state.accept_backlog_bytes = 3;
                stream_state.pending_priority_update = Some(vec![1, 2]);
                stream_state.pending_data_frames = 1;
                stream_state.pending_terminal_frames = 1;
                stream_state.provisional_created_at = Some(Instant::now());
                stream_state.active_counted = true;
                retain_stream_open_info_locked(&mut state, &mut stream_state, b"info".to_vec());
                retain_stream_recv_reset_reason_locked(
                    &inner,
                    &mut state,
                    &mut stream_state,
                    77,
                    "reason".to_owned(),
                );
            }

            assert!(state.streams.capacity() >= 2048);
            assert!(state.accept_bidi.capacity() >= 2048);
            assert!(state.tombstones.capacity() >= 2048);
            assert!(state.retained_open_info_bytes > 0);
            assert!(state.retained_peer_reason_bytes > 0);

            release_session_runtime_state_locked(&mut state);

            assert_eq!(state.streams.capacity(), 0);
            assert_eq!(state.provisional_bidi.capacity(), 0);
            assert_eq!(state.provisional_uni.capacity(), 0);
            assert_eq!(state.accept_bidi.capacity(), 0);
            assert_eq!(state.accept_uni.capacity(), 0);
            assert_eq!(state.inflight_data_by_stream.capacity(), 0);
            assert_eq!(state.tombstones.capacity(), 0);
            assert_eq!(state.tombstone_order.capacity(), 0);
            assert_eq!(state.hidden_tombstone_order.capacity(), 0);
            assert_eq!(state.used_markers.capacity(), 0);
            assert_eq!(state.used_marker_order.capacity(), 0);
            assert_eq!(state.used_marker_ranges.capacity(), 0);
            assert!(!state.used_marker_range_mode);
            assert_eq!(state.hidden_tombstones, 0);
            assert_eq!(state.accept_backlog_bytes, 0);
            assert_eq!(state.retained_open_info_bytes, 0);
            assert_eq!(state.retained_peer_reason_bytes, 0);
            assert_eq!(state.active.local_bidi, 0);
            assert_eq!(state.active.local_uni, 0);
            assert_eq!(state.active.peer_bidi, 0);
            assert_eq!(state.active.peer_uni, 0);
            assert_eq!(state.send_session_used, 0);
            assert_eq!(state.send_session_blocked_at, None);
            assert_eq!(state.recv_session_used, 0);
            assert_eq!(state.recv_session_buffered, 0);
            assert_eq!(state.recv_session_retained, 0);
            assert_eq!(state.recv_session_pending, 0);
            assert!(state.keepalive_ping.is_none());
            assert!(state.canceled_ping_payload.is_none());
            assert!(state.ping_waiter.is_none());
        }

        assert!(slot.result.lock().unwrap().is_some());
        let stream_state = live.state.lock().unwrap();
        assert!(stream_state.recv_buf.is_empty());
        assert!(stream_state.open_info.is_empty());
        assert_eq!(stream_state.retained_open_info_bytes, 0);
        assert_eq!(stream_state.retained_recv_reset_reason_bytes, 0);
        assert!(stream_state.pending_priority_update.is_none());
        assert_eq!(stream_state.pending_data_frames, 0);
        assert_eq!(stream_state.pending_terminal_frames, 0);
        assert!(stream_state.provisional_created_at.is_none());
        assert!(!stream_state.active_counted);
        assert!(!stream_state.accept_pending);
    }

    #[test]
    fn local_abort_supersedes_pending_reset_and_stop_sending_for_same_stream() {
        fn assert_superseded_terminal_signal(frame_type: FrameType, code: u64) {
            let inner = test_inner();
            let stream = test_peer_opened_stream(&inner, 1, true);
            {
                let mut state = inner.state.lock().unwrap();
                state.streams.insert(1, stream.clone());
                state.active.peer_bidi = 1;
                let mut stream_state = stream.state.lock().unwrap();
                stream_state.pending_terminal_frames = 1;
                match frame_type {
                    FrameType::Reset => stream_state.send_reset = Some((code, String::new())),
                    FrameType::StopSending => {
                        stream_state.read_stopped = true;
                        stream_state.read_stop_pending_code = Some(code);
                    }
                    _ => unreachable!("test only covers terminal stream controls"),
                }
            }
            inner
                .write_queue
                .force_push(WriteJob::Frame(Frame {
                    frame_type,
                    flags: 0,
                    stream_id: 1,
                    payload: build_code_payload(code, "", u64::MAX).unwrap(),
                }))
                .unwrap();

            Stream {
                inner: stream.clone(),
            }
            .close_with_error(12, "abort")
            .unwrap();

            let batch = inner.write_queue.pop_batch().expect("queued abort");
            assert_eq!(batch.len(), 1);
            let WriteJob::Frame(frame) = &batch[0] else {
                panic!("expected queued frame");
            };
            assert_eq!(frame.frame_type, FrameType::Abort);
            assert_eq!(
                crate::payload::parse_error_payload(&frame.payload)
                    .unwrap()
                    .0,
                12
            );
            let stats = Conn {
                inner: inner.clone(),
            }
            .stats();
            assert_eq!(stats.diagnostics.coalesced_terminal_signals, 0);
            assert_eq!(stats.diagnostics.superseded_terminal_signals, 1);
            assert_eq!(stream.state.lock().unwrap().pending_terminal_frames, 1);
        }

        assert_superseded_terminal_signal(FrameType::Reset, 11);
        assert_superseded_terminal_signal(FrameType::StopSending, 21);
    }

    #[test]
    fn graceful_reclaim_discards_queued_not_peer_visible_local_opener() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.streams.insert(4, stream.clone());
        }
        inner
            .write_queue
            .force_push(WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id: 4,
                payload: b"queued".to_vec(),
            }))
            .unwrap();

        let reclaimed = {
            let mut state = inner.state.lock().unwrap();
            assert!(close_has_blocking_streams(&inner, &state));
            reclaim_graceful_close_local_streams_locked(&inner, &mut state)
        };
        assert_eq!(reclaimed.len(), 1);
        assert!(Arc::ptr_eq(&reclaimed[0], &stream));

        let stats = inner.write_queue.discard_stream(4);
        assert_eq!(stats.data_frames, 1);
        assert_eq!(stats.terminal_frames, 0);
        apply_discarded_stream_frames_locked(&inner, &stream, stats);

        let state = inner.state.lock().unwrap();
        let stream_state = stream.state.lock().unwrap();
        assert_eq!(
            stream_state.aborted.as_ref().map(|(code, _)| *code),
            Some(ErrorCode::RefusedStream.as_u64())
        );
        assert_eq!(stream_state.pending_data_frames, 0);
        assert_eq!(state.active.local_bidi, 0);
        assert_eq!(inner.write_queue.data_queued_bytes_for_stream(4), 0);
        assert!(!close_has_blocking_streams(&inner, &state));
    }

    #[test]
    fn graceful_close_waits_for_staged_terminal_stream_data() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.streams.insert(4, stream.clone());
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.send_fin = true;
            stream_state.recv_fin = true;
            stream_state.pending_data_frames = 1;
        }
        {
            let state = inner.state.lock().unwrap();
            assert!(close_has_blocking_streams(&inner, &state));
        }
        {
            let mut state = inner.state.lock().unwrap();
            note_written_stream_frames_locked(&mut state, 4, 1, 0);
            assert!(!close_has_blocking_streams(&inner, &state));
        }
    }

    #[test]
    fn graceful_close_waits_for_peer_opened_bidi_after_local_send_commit() {
        let inner = test_inner();
        let stream = test_peer_opened_stream(&inner, 1, true);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.peer_bidi = 1;
            state.streams.insert(1, stream.clone());
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.recv_fin = true;
            stream_state.opened_on_wire = true;
        }
        {
            let state = inner.state.lock().unwrap();
            assert!(close_has_blocking_streams(&inner, &state));
        }
        {
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.send_fin = true;
            stream_state.pending_data_frames = 1;
        }
        {
            let state = inner.state.lock().unwrap();
            assert!(close_has_blocking_streams(&inner, &state));
        }
        {
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.pending_data_frames = 0;
        }
        {
            let state = inner.state.lock().unwrap();
            assert!(!close_has_blocking_streams(&inner, &state));
        }
    }

    #[test]
    fn peer_go_away_reclaim_discards_committed_not_peer_visible_local_opener() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.send_session_used = 6;
            state.peer_go_away_bidi = 0;
            state.streams.insert(4, stream.clone());
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.pending_priority_update = Some(vec![1]);
        }
        inner
            .write_queue
            .force_push(WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id: 4,
                payload: b"queued".to_vec(),
            }))
            .unwrap();

        let reclaimed = {
            let mut state = inner.state.lock().unwrap();
            reclaim_unseen_local_streams_after_go_away(&mut state, true)
        };
        assert_eq!(reclaimed.len(), 1);
        assert!(Arc::ptr_eq(&reclaimed[0], &stream));

        let stats = inner.write_queue.discard_stream(4);
        assert_eq!(stats.data_frames, 1);
        assert_eq!(stats.terminal_frames, 0);
        apply_discarded_stream_frames_locked(&inner, &stream, stats);

        let state = inner.state.lock().unwrap();
        let stream_state = stream.state.lock().unwrap();
        assert_eq!(
            stream_state.aborted.as_ref().map(|(code, _)| *code),
            Some(ErrorCode::RefusedStream.as_u64())
        );
        assert!(!stream_state.peer_visible);
        assert_eq!(stream_state.pending_data_frames, 0);
        assert_eq!(stream_state.pending_priority_update, None);
        assert_eq!(stream_state.send_used, 0);
        assert_eq!(state.send_session_used, 0);
        assert_eq!(state.active.local_bidi, 0);
        assert_eq!(inner.write_queue.data_queued_bytes_for_stream(4), 0);
    }

    #[test]
    fn stop_sending_reset_discards_queued_tail_and_releases_send_credit() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.send_session_used = 6;
            state.streams.insert(4, stream.clone());
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.pending_data_frames = 1;
            stream_state.pending_terminal_frames = 1;
            stream_state.send_used = 6;
            stream_state.stopped_by_peer = Some((77, "peer stop".to_owned()));
            stream_state.send_reset = Some((ErrorCode::Cancelled.as_u64(), String::new()));
            stream_state.send_reset_from_stop = true;
            stream_state.read_stopped = true;
            stream_state.read_stop_pending_code = Some(ErrorCode::Cancelled.as_u64());
        }
        inner
            .write_queue
            .force_push(WriteJob::Frames(vec![
                Frame {
                    frame_type: FrameType::Data,
                    flags: 0,
                    stream_id: 4,
                    payload: b"queued".to_vec(),
                },
                Frame {
                    frame_type: FrameType::StopSending,
                    flags: 0,
                    stream_id: 4,
                    payload: build_code_payload(ErrorCode::Cancelled.as_u64(), "", u64::MAX)
                        .unwrap(),
                },
                Frame {
                    frame_type: FrameType::MaxData,
                    flags: 0,
                    stream_id: 4,
                    payload: vec![1],
                },
            ]))
            .unwrap();

        super::super::ingress::discard_stop_sending_reset_tail(&inner, 4);

        let state = inner.state.lock().unwrap();
        let stream_state = stream.state.lock().unwrap();
        assert_eq!(stream_state.pending_data_frames, 0);
        assert_eq!(stream_state.pending_terminal_frames, 1);
        assert_eq!(stream_state.send_used, 0);
        assert_eq!(state.send_session_used, 0);
        assert_eq!(inner.write_queue.data_queued_bytes_for_stream(4), 0);
        assert!(inner.write_queue.terminal_control_queued_for_stream(4));
        drop(stream_state);
        drop(state);

        let batch = inner
            .write_queue
            .pop_batch()
            .expect("preserved control frames");
        let frame_types: Vec<_> = batch
            .iter()
            .flat_map(|job| match job {
                WriteJob::Frame(frame) | WriteJob::GracefulClose(frame) => {
                    vec![frame.frame_type].into_iter()
                }
                WriteJob::Frames(frames) => frames
                    .iter()
                    .map(|frame| frame.frame_type)
                    .collect::<Vec<_>>()
                    .into_iter(),
                WriteJob::TrackedFrames(tracked) => tracked
                    .frames
                    .iter()
                    .map(|frame| frame.frame_type)
                    .collect::<Vec<_>>()
                    .into_iter(),
                WriteJob::Shutdown | WriteJob::DrainShutdown => Vec::new().into_iter(),
            })
            .collect();
        assert!(!frame_types.contains(&FrameType::Data));
        assert!(frame_types.contains(&FrameType::StopSending));
        assert!(frame_types.contains(&FrameType::MaxData));
    }

    #[test]
    fn local_open_memory_cap_projection_counts_open_info_at_boundary() {
        fn retained_unit(inner: &Inner) -> usize {
            let settings = inner.local_preface.settings;
            [
                settings.max_frame_payload,
                settings.max_control_payload_bytes,
                settings.max_extension_payload_bytes,
            ]
            .into_iter()
            .map(|value| usize::try_from(value).unwrap_or(usize::MAX))
            .max()
            .unwrap_or(0)
            .max(4096)
        }

        let mut exact = test_inner();
        let cap = retained_unit(&exact).saturating_add(3);
        Arc::get_mut(&mut exact).unwrap().session_memory_cap = Some(cap);
        {
            let state = exact.state.lock().unwrap();
            ensure_local_open_memory_cap_locked(&exact, &state, 3).unwrap();
        }

        let mut over = test_inner();
        Arc::get_mut(&mut over).unwrap().session_memory_cap = Some(cap.saturating_sub(1));
        let state = over.state.lock().unwrap();
        let err = ensure_local_open_memory_cap_locked(&over, &state, 3).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::StreamLimit));
        assert!(err
            .to_string()
            .contains("local open limited by session memory cap"));
    }

    #[test]
    fn local_cancel_write_discards_queued_tail_and_releases_send_credit() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.send_session_used = 6;
            state.streams.insert(4, stream.clone());
        }
        inner
            .write_queue
            .force_push(WriteJob::Frame(Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id: 4,
                payload: b"queued".to_vec(),
            }))
            .unwrap();

        Stream {
            inner: stream.clone(),
        }
        .cancel_write(ErrorCode::Cancelled.as_u64())
        .unwrap();

        let state = inner.state.lock().unwrap();
        let stream_state = stream.state.lock().unwrap();
        assert_eq!(stream_state.pending_data_frames, 0);
        assert_eq!(stream_state.send_used, 0);
        assert_eq!(state.send_session_used, 0);
        assert_eq!(inner.write_queue.data_queued_bytes_for_stream(4), 0);
        assert_eq!(
            stream_state.send_reset.as_ref().map(|(code, _)| *code),
            Some(ErrorCode::Cancelled.as_u64())
        );
    }

    #[test]
    fn pending_receive_credit_flush_respects_urgent_cap_and_retries_tail() {
        let mut inner = test_inner();
        {
            let inner_mut = Arc::get_mut(&mut inner).unwrap();
            inner_mut.write_queue = Arc::new(WriteQueue::new(WriteQueueLimits {
                max_bytes: 1 << 20,
                urgent_max_bytes: 3,
                session_data_max_bytes: 1 << 20,
                per_stream_data_max_bytes: 1 << 20,
                pending_control_max_bytes: 1 << 20,
                pending_priority_max_bytes: 1 << 20,
                max_batch_bytes: 1 << 20,
                max_batch_frames: 8,
            }));
            inner_mut.session_data_high_watermark = 4;
            inner_mut.per_stream_data_high_watermark = 4;
        }
        let stream = test_peer_opened_stream(&inner, 1, true);
        {
            let mut state = inner.state.lock().unwrap();
            state.streams.insert(1, stream.clone());
            state.recv_session_advertised = 4;
            state.recv_session_used = 4;
            state.recv_session_pending = 4;
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.recv_advertised = 4;
            stream_state.recv_used = 4;
            stream_state.recv_pending = 4;
        }

        super::super::ingress::flush_pending_receive_credit(&inner).unwrap();

        let stats = inner.write_queue.stats();
        assert_eq!(stats.urgent_jobs, 1);
        assert_eq!(stats.urgent_queued_bytes, 2);
        {
            let state = inner.state.lock().unwrap();
            assert_eq!(state.recv_session_pending, 0);
            assert!(state.recv_replenish_retry);
            let stream_state = stream.state.lock().unwrap();
            assert_eq!(stream_state.recv_pending, 4);
        }
        let first = inner.write_queue.pop_batch().expect("session credit batch");
        assert!(matches!(
            first.first(),
            Some(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                stream_id: 0,
                ..
            }))
        ));

        super::super::ingress::retry_pending_receive_credit(&inner).unwrap();

        let second = inner.write_queue.pop_batch().expect("stream credit batch");
        assert!(matches!(
            second.first(),
            Some(WriteJob::Frame(Frame {
                frame_type: FrameType::MaxData,
                stream_id: 1,
                ..
            }))
        ));
        let state = inner.state.lock().unwrap();
        assert!(!state.recv_replenish_retry);
        let stream_state = stream.state.lock().unwrap();
        assert_eq!(stream_state.recv_pending, 0);
    }

    #[test]
    fn writer_filter_drops_aborted_staged_data_and_releases_send_credit() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.send_session_used = 4;
            state.streams.insert(4, stream.clone());
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.pending_data_frames = 1;
            stream_state.send_used = 4;
            stream_state.aborted = Some((ErrorCode::Cancelled.as_u64(), String::new()));
            stream_state.abort_source = ErrorSource::Local;
        }
        let mut batch = vec![WriteJob::Frame(Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id: 4,
            payload: b"body".to_vec(),
        })];
        let mut dropped = Vec::new();

        super::super::egress::filter_writable_batch(&inner, &mut batch, &mut dropped);

        assert!(batch.is_empty());
        let state = inner.state.lock().unwrap();
        let stream_state = stream.state.lock().unwrap();
        assert_eq!(stream_state.pending_data_frames, 0);
        assert_eq!(stream_state.send_used, 0);
        assert_eq!(state.send_session_used, 0);
    }

    #[test]
    fn writer_filter_fails_tracked_write_when_data_frame_is_dropped() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.send_session_used = 4;
            state.streams.insert(4, stream.clone());
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.pending_data_frames = 1;
            stream_state.send_used = 4;
            stream_state.aborted = Some((ErrorCode::Cancelled.as_u64(), String::new()));
            stream_state.abort_source = ErrorSource::Local;
        }
        let completion = WriteCompletion::new();
        let mut batch = vec![WriteJob::TrackedFrames(TrackedWriteJob {
            frames: vec![Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id: 4,
                payload: b"body".to_vec(),
            }],
            completion: completion.clone(),
        })];
        let mut dropped = Vec::new();

        super::super::egress::filter_writable_batch(&inner, &mut batch, &mut dropped);

        assert!(batch.is_empty());
        let err = completion.try_result().unwrap().unwrap_err();
        assert!(err
            .to_string()
            .contains("queued write is no longer writable"));
        let state = inner.state.lock().unwrap();
        let stream_state = stream.state.lock().unwrap();
        assert_eq!(stream_state.pending_data_frames, 0);
        assert_eq!(stream_state.send_used, 0);
        assert_eq!(state.send_session_used, 0);
    }

    #[test]
    fn writer_filter_keeps_opening_priority_update_after_same_job_data() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.send_session_used = 4;
            state.streams.insert(4, stream);
        }
        let priority_update_payload = vec![crate::protocol::EXT_PRIORITY_UPDATE as u8];
        let mut dropped = Vec::new();
        let mut standalone_update = vec![WriteJob::Frame(Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id: 4,
            payload: priority_update_payload.clone(),
        })];

        super::super::egress::filter_writable_batch(&inner, &mut standalone_update, &mut dropped);

        assert!(standalone_update.is_empty());

        let mut opening_with_update = vec![WriteJob::Frames(vec![
            Frame {
                frame_type: FrameType::Data,
                flags: 0,
                stream_id: 4,
                payload: b"body".to_vec(),
            },
            Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id: 4,
                payload: priority_update_payload,
            },
        ])];

        super::super::egress::filter_writable_batch(&inner, &mut opening_with_update, &mut dropped);

        let WriteJob::Frames(frames) = &opening_with_update[0] else {
            panic!("opening data and priority update should stay in a frame batch");
        };
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].frame_type, FrameType::Data);
        assert_eq!(frames[1].frame_type, FrameType::Ext);
    }

    #[test]
    fn writer_filter_keeps_priority_update_before_same_job_fin() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.streams.insert(4, stream.clone());
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.peer_visible = true;
            stream_state.send_fin = true;
        }
        let priority_update_payload = vec![crate::protocol::EXT_PRIORITY_UPDATE as u8];
        let mut dropped = Vec::new();
        let mut standalone_update = vec![WriteJob::Frame(Frame {
            frame_type: FrameType::Ext,
            flags: 0,
            stream_id: 4,
            payload: priority_update_payload.clone(),
        })];

        super::super::egress::filter_writable_batch(&inner, &mut standalone_update, &mut dropped);

        assert!(standalone_update.is_empty());

        let mut close_write_with_update = vec![WriteJob::TrackedFrames(TrackedWriteJob {
            frames: vec![
                Frame {
                    frame_type: FrameType::Ext,
                    flags: 0,
                    stream_id: 4,
                    payload: priority_update_payload,
                },
                Frame {
                    frame_type: FrameType::Data,
                    flags: FRAME_FLAG_FIN,
                    stream_id: 4,
                    payload: Vec::new(),
                },
            ],
            completion: WriteCompletion::new(),
        })];

        super::super::egress::filter_writable_batch(
            &inner,
            &mut close_write_with_update,
            &mut dropped,
        );

        let WriteJob::TrackedFrames(tracked) = &close_write_with_update[0] else {
            panic!("priority update and FIN should stay tracked together");
        };
        assert_eq!(tracked.frames.len(), 2);
        assert_eq!(tracked.frames[0].frame_type, FrameType::Ext);
        assert_eq!(tracked.frames[1].frame_type, FrameType::Data);
    }

    #[test]
    fn writer_filter_keeps_priority_update_between_queued_opener_and_fin() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.streams.insert(4, stream.clone());
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.peer_visible = false;
            stream_state.opened_on_wire = true;
            stream_state.send_fin = true;
        }
        let mut dropped = Vec::new();
        let mut close_write_with_update = vec![WriteJob::TrackedFrames(TrackedWriteJob {
            frames: vec![
                Frame {
                    frame_type: FrameType::Ext,
                    flags: 0,
                    stream_id: 4,
                    payload: vec![crate::protocol::EXT_PRIORITY_UPDATE as u8],
                },
                Frame {
                    frame_type: FrameType::Data,
                    flags: FRAME_FLAG_FIN,
                    stream_id: 4,
                    payload: Vec::new(),
                },
            ],
            completion: WriteCompletion::new(),
        })];

        super::super::egress::filter_writable_batch(
            &inner,
            &mut close_write_with_update,
            &mut dropped,
        );

        let WriteJob::TrackedFrames(tracked) = &close_write_with_update[0] else {
            panic!("priority update between queued opener and FIN should stay tracked");
        };
        assert_eq!(tracked.frames.len(), 2);
        assert_eq!(tracked.frames[0].frame_type, FrameType::Ext);
        assert_eq!(tracked.frames[1].frame_type, FrameType::Data);
    }

    #[test]
    fn peer_visible_pending_priority_queue_respects_session_memory_cap() {
        let mut inner = test_inner();
        Arc::get_mut(&mut inner).unwrap().session_memory_cap = Some(1);

        queue_peer_visible_pending_priority(
            &inner,
            4,
            vec![crate::protocol::EXT_PRIORITY_UPDATE as u8, 9],
        );

        assert_eq!(inner.write_queue.stats().pending_priority_bytes, 0);
        let state = inner.state.lock().unwrap();
        assert_eq!(state.dropped_local_priority_update_count, 1);
    }

    #[test]
    fn peer_visible_pending_priority_queue_accounts_success() {
        let inner = test_inner();
        queue_peer_visible_pending_priority(
            &inner,
            4,
            vec![crate::protocol::EXT_PRIORITY_UPDATE as u8, 9],
        );

        assert_ne!(inner.write_queue.stats().pending_priority_bytes, 0);
        let state = inner.state.lock().unwrap();
        assert_eq!(state.dropped_local_priority_update_count, 0);
    }

    #[test]
    fn close_write_carries_visible_pending_priority_before_fin() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.streams.insert(4, stream.clone());
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.pending_data_frames = 0;
            stream_state.send_used = 0;
            stream_state.peer_visible = true;
            stream_state.pending_priority_update =
                Some(vec![crate::protocol::EXT_PRIORITY_UPDATE as u8, 5]);
        }

        let writer = Stream {
            inner: stream.clone(),
        };
        let write_thread = thread::spawn(move || writer.close_write());
        let mut batch = inner.write_queue.pop_batch().expect("queued close write");
        assert_eq!(batch.len(), 1);
        let WriteJob::TrackedFrames(tracked) = batch.pop().unwrap() else {
            panic!("closeWrite should queue a tracked write");
        };
        assert_eq!(tracked.frames.len(), 2);
        assert_eq!(tracked.frames[0].frame_type, FrameType::Ext);
        assert_eq!(tracked.frames[0].stream_id, 4);
        assert_eq!(tracked.frames[1].frame_type, FrameType::Data);
        assert_ne!(tracked.frames[1].flags & FRAME_FLAG_FIN, 0);

        {
            let mut state = inner.state.lock().unwrap();
            note_written_stream_frames_locked(&mut state, 4, 1, 1);
        }
        tracked.completion.complete_ok();
        write_thread.join().unwrap().unwrap();

        let state = inner.state.lock().unwrap();
        let stream_state = stream.state.lock().unwrap();
        assert!(stream_state.pending_priority_update.is_none());
        assert!(stream_state.send_fin);
        assert_eq!(state.dropped_local_priority_update_count, 0);
    }

    #[test]
    fn close_write_carries_queued_opener_pending_priority_before_fin() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.streams.insert(4, stream.clone());
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.pending_data_frames = 1;
            stream_state.send_used = 0;
            stream_state.opened_on_wire = true;
            stream_state.peer_visible = false;
            stream_state.pending_priority_update =
                Some(vec![crate::protocol::EXT_PRIORITY_UPDATE as u8, 7]);
        }

        let writer = Stream {
            inner: stream.clone(),
        };
        let write_thread = thread::spawn(move || writer.close_write());
        let mut batch = inner
            .write_queue
            .pop_batch()
            .expect("queued close after opener");
        assert_eq!(batch.len(), 1);
        let WriteJob::TrackedFrames(tracked) = batch.pop().unwrap() else {
            panic!("closeWrite should queue a tracked write");
        };
        assert_eq!(tracked.frames.len(), 2);
        assert_eq!(tracked.frames[0].frame_type, FrameType::Ext);
        assert_eq!(tracked.frames[0].stream_id, 4);
        assert_eq!(tracked.frames[1].frame_type, FrameType::Data);
        assert_ne!(tracked.frames[1].flags & FRAME_FLAG_FIN, 0);

        {
            let mut state = inner.state.lock().unwrap();
            note_written_stream_frames_locked(&mut state, 4, 1, 1);
        }
        tracked.completion.complete_ok();
        write_thread.join().unwrap().unwrap();

        let state = inner.state.lock().unwrap();
        let stream_state = stream.state.lock().unwrap();
        assert!(stream_state.pending_priority_update.is_none());
        assert!(stream_state.send_fin);
        assert_eq!(state.dropped_local_priority_update_count, 0);
    }

    #[test]
    fn close_write_drops_pending_priority_when_fin_is_opening_frame() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.streams.insert(4, stream.clone());
            let mut stream_state = stream.state.lock().unwrap();
            stream_state.opened_on_wire = false;
            stream_state.peer_visible = false;
            stream_state.pending_data_frames = 0;
            stream_state.send_used = 0;
            stream_state.pending_priority_update =
                Some(vec![crate::protocol::EXT_PRIORITY_UPDATE as u8, 5]);
        }

        let writer = Stream {
            inner: stream.clone(),
        };
        let write_thread = thread::spawn(move || writer.close_write());
        let mut batch = inner.write_queue.pop_batch().expect("queued opening close");
        assert_eq!(batch.len(), 1);
        let WriteJob::TrackedFrames(tracked) = batch.pop().unwrap() else {
            panic!("closeWrite should queue a tracked write");
        };
        assert_eq!(tracked.frames.len(), 1);
        assert_eq!(tracked.frames[0].frame_type, FrameType::Data);
        assert_ne!(tracked.frames[0].flags & FRAME_FLAG_FIN, 0);

        {
            let mut state = inner.state.lock().unwrap();
            note_written_stream_frames_locked(&mut state, 4, 1, 1);
        }
        tracked.completion.complete_ok();
        write_thread.join().unwrap().unwrap();

        let state = inner.state.lock().unwrap();
        let stream_state = stream.state.lock().unwrap();
        assert!(stream_state.pending_priority_update.is_none());
        assert!(stream_state.send_fin);
        assert_eq!(state.dropped_local_priority_update_count, 1);
    }

    #[test]
    fn peer_go_away_reclaim_keeps_peer_visible_local_stream() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        {
            let mut state = inner.state.lock().unwrap();
            state.active.local_bidi = 1;
            state.peer_go_away_bidi = 0;
            state.streams.insert(4, stream.clone());
            stream.state.lock().unwrap().peer_visible = true;
        }

        let reclaimed = {
            let mut state = inner.state.lock().unwrap();
            reclaim_unseen_local_streams_after_go_away(&mut state, true)
        };
        assert!(reclaimed.is_empty());

        let state = inner.state.lock().unwrap();
        let stream_state = stream.state.lock().unwrap();
        assert!(stream_state.aborted.is_none());
        assert!(stream_state.peer_visible);
        assert_eq!(stream_state.send_used, 6);
        assert_eq!(state.active.local_bidi, 1);
    }

    #[test]
    fn written_data_frame_completion_decrements_only_completed_frame() {
        let inner = test_inner();
        let stream = test_local_opened_bidi(&inner, 4);
        stream.state.lock().unwrap().pending_data_frames = 2;
        {
            let mut state = inner.state.lock().unwrap();
            state.streams.insert(4, stream.clone());
            note_written_stream_frames_locked(&mut state, 4, 1, 0);
        }

        assert_eq!(stream.state.lock().unwrap().pending_data_frames, 1);
    }
}
