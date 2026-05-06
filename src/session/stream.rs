use super::buffer::{RecvBuffer, RecvBufferRead};
use super::flow::{
    negotiated_frame_payload, next_credit_limit, replenish_min_pending,
    session_emergency_threshold, session_standing_growth_allowed, session_window_target,
    should_flush_receive_credit, stream_emergency_threshold, stream_standing_growth_allowed,
    stream_window_target,
};
use super::liveness::{note_blocked_write_locked, record_stream_application_progress};
use super::queue::StreamDiscardStats;
use super::scheduler::write_burst_limit;
use super::state::{
    check_write_open, clear_accept_backlog_entry_locked, clear_stream_open_info_locked,
    clear_stream_open_prefix_locked, clear_stream_receive_credit_locked,
    ensure_pending_priority_update_limits_locked, ensure_projected_session_memory_cap_locked,
    ensure_session_not_closed, ensure_session_open, fail_expired_provisional_locked,
    fail_session_with_close, late_data_per_stream_cap, local_reset_error,
    maybe_compact_stream_locked, maybe_release_active_count, note_abort_reason_locked,
    note_reset_reason_locked, note_written_stream_frames_locked, peer_reset_error,
    provisional_expired_locked, provisional_open_expired_reason, provisional_open_max_age,
    reap_expired_provisionals_locked, release_discarded_queued_stream_frames_locked,
    release_session_receive_buffered_locked, session_memory_pressure_high_fast_locked,
    shrink_provisional_queue_locked, stream_abort_error,
};
use super::stop_sending::{evaluate_graceful, GracefulInput};
use super::types::*;
use crate::config::{
    DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW, DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW_MAX,
};
use crate::error::{
    Error, ErrorCode, ErrorDirection, ErrorOperation, ErrorSource, Result, TerminationKind,
};
use crate::frame::{Frame, FrameType, FRAME_FLAG_FIN, FRAME_FLAG_OPEN_METADATA};
use crate::open_send::WritePayload;
use crate::payload::{
    build_code_payload, build_open_metadata_prefix_into, build_priority_update_payload,
    build_priority_update_payload_into, normalize_stream_group, parse_priority_update_metadata,
    priority_update_payload_len, MetadataUpdate, StreamMetadata,
};
use crate::protocol::{
    capabilities_can_carry_group_on_open, capabilities_can_carry_priority_on_open,
    EXT_PRIORITY_UPDATE,
};
use crate::settings::SchedulerHint;
use crate::stream_id::{initial_receive_window, initial_send_window};
use crate::varint::{append_varint_reserved, parse_varint, varint_len, MAX_VARINT62};
use std::borrow::Cow;
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::net::SocketAddr;
use std::ptr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, MutexGuard};
use std::time::{Duration, Instant};

const MAX_CONDVAR_TIMED_WAIT: Duration = Duration::from_secs(3600);

#[inline]
fn stream_result<T>(
    result: Result<T>,
    operation: ErrorOperation,
    direction: ErrorDirection,
) -> Result<T> {
    result.map_err(|err| err.with_stream_context(operation, direction))
}

#[inline]
fn unexpected_eof_error() -> Error {
    Error::io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "failed to fill whole buffer",
    ))
}

#[inline]
fn usize_to_u64_saturating(value: usize) -> u64 {
    value.min(u64::MAX as usize) as u64
}

#[inline]
fn u64_to_usize_saturating(value: u64) -> usize {
    value.min(usize::MAX as u64) as usize
}

#[inline]
fn u128_to_u64_saturating(value: u128) -> u64 {
    value.min(u128::from(u64::MAX)) as u64
}

impl Stream {
    pub fn stream_id(&self) -> u64 {
        self.inner.id()
    }

    pub fn close_identity(&self) -> *const () {
        Arc::as_ptr(&self.inner).cast::<()>()
    }

    pub fn is_opened_locally(&self) -> bool {
        self.inner.opened_locally
    }

    pub fn is_bidirectional(&self) -> bool {
        self.inner.bidi
    }

    pub fn is_read_closed(&self) -> bool {
        self.inner.is_read_closed()
    }

    pub fn is_write_closed(&self) -> bool {
        self.inner.is_write_closed()
    }

    pub fn open_info(&self) -> Vec<u8> {
        self.inner.open_info()
    }

    pub fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        self.inner.append_open_info_to(dst)
    }

    pub fn open_info_len(&self) -> usize {
        self.inner.open_info_len()
    }

    pub fn has_open_info(&self) -> bool {
        self.inner.has_open_info()
    }

    pub fn metadata(&self) -> StreamMetadata {
        self.inner.metadata()
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.conn.local_addr
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.conn.peer_addr
    }

    pub fn update_metadata(&self, update: MetadataUpdate) -> Result<()> {
        stream_result(
            StreamInner::update_metadata(self.inner.as_ref(), update),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn read(&self, dst: &mut [u8]) -> Result<usize> {
        stream_result(
            StreamInner::read(self.inner.as_ref(), dst),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn read_vectored(&self, dsts: &mut [IoSliceMut<'_>]) -> Result<usize> {
        stream_result(
            StreamInner::read_vectored(self.inner.as_ref(), dsts),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn read_vectored_timeout(
        &self,
        dsts: &mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        stream_result(
            StreamInner::read_vectored_timeout(self.inner.as_ref(), dsts, timeout),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn read_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<usize> {
        stream_result(
            StreamInner::read_timeout(self.inner.as_ref(), dst, timeout),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn read_exact_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<()> {
        stream_result(
            StreamInner::read_exact_timeout(self.inner.as_ref(), dst, timeout),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        stream_result(
            StreamInner::set_read_deadline(self.inner.as_ref(), deadline),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        stream_result(
            StreamInner::set_write_deadline(self.inner.as_ref(), deadline),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        stream_result(
            StreamInner::set_deadline(self.inner.as_ref(), deadline),
            ErrorOperation::Unknown,
            ErrorDirection::Both,
        )
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_read_deadline(timeout_to_deadline(timeout))
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_write_deadline(timeout_to_deadline(timeout))
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_deadline(timeout_to_deadline(timeout))
    }

    pub fn write(&self, src: &[u8]) -> Result<usize> {
        stream_result(
            StreamInner::write(self.inner.as_ref(), src, false),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        stream_result(
            StreamInner::write_timeout(self.inner.as_ref(), src, timeout),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_all<'a>(&self, src: impl Into<WritePayload<'a>>) -> Result<()> {
        stream_result(
            StreamInner::write_payload_until(self.inner.as_ref(), src.into(), false, None)
                .map(|_| ()),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_all_timeout<'a>(
        &self,
        src: impl Into<WritePayload<'a>>,
        timeout: Duration,
    ) -> Result<()> {
        stream_result(
            StreamInner::write_payload_until(
                self.inner.as_ref(),
                src.into(),
                false,
                deadline_after(timeout),
            )
            .map(|_| ()),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_vectored(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        stream_result(
            StreamInner::write_vectored(self.inner.as_ref(), parts, false),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        stream_result(
            StreamInner::write_vectored_timeout(self.inner.as_ref(), parts, timeout),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_final<'a>(&self, src: impl Into<WritePayload<'a>>) -> Result<usize> {
        stream_result(
            StreamInner::write_payload_until(self.inner.as_ref(), src.into(), true, None),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        stream_result(
            StreamInner::write_vectored_final(self.inner.as_ref(), parts),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_final_timeout<'a>(
        &self,
        src: impl Into<WritePayload<'a>>,
        timeout: Duration,
    ) -> Result<usize> {
        stream_result(
            StreamInner::write_payload_until(
                self.inner.as_ref(),
                src.into(),
                true,
                deadline_after(timeout),
            ),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        stream_result(
            StreamInner::write_vectored_final_timeout(self.inner.as_ref(), parts, timeout),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn close_read(&self) -> Result<()> {
        stream_result(
            StreamInner::close_read(self.inner.as_ref(), ErrorCode::Cancelled.as_u64()),
            ErrorOperation::Close,
            ErrorDirection::Read,
        )
    }

    pub fn cancel_read(&self, code: u64) -> Result<()> {
        stream_result(
            StreamInner::close_read(self.inner.as_ref(), code),
            ErrorOperation::Close,
            ErrorDirection::Read,
        )
    }

    pub fn close_write(&self) -> Result<()> {
        stream_result(
            StreamInner::close_write(self.inner.as_ref()),
            ErrorOperation::Close,
            ErrorDirection::Write,
        )
    }

    pub fn cancel_write(&self, code: u64) -> Result<()> {
        stream_result(
            StreamInner::cancel_write(self.inner.as_ref(), code, ""),
            ErrorOperation::Close,
            ErrorDirection::Write,
        )
    }

    pub fn close(&self) -> Result<()> {
        stream_result(
            StreamInner::close(self.inner.as_ref()),
            ErrorOperation::Close,
            ErrorDirection::Both,
        )
    }

    pub fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        stream_result(
            StreamInner::abort(self.inner.as_ref(), code, reason),
            ErrorOperation::Close,
            ErrorDirection::Both,
        )
    }
}

#[inline]
fn blocked_frame(stream_id: u64, offset: u64) -> Option<Frame> {
    varint_control_frame(FrameType::Blocked, stream_id, offset)
}

#[inline]
fn max_data_frame(stream_id: u64, limit: u64) -> Option<Frame> {
    varint_control_frame(FrameType::MaxData, stream_id, limit)
}

#[inline]
fn varint_control_frame(frame_type: FrameType, stream_id: u64, value: u64) -> Option<Frame> {
    let value = value.min(MAX_VARINT62);
    let mut payload = Vec::with_capacity(varint_len(value).ok()?);
    append_varint_reserved(&mut payload, value).ok()?;
    Some(Frame {
        frame_type,
        flags: 0,
        stream_id,
        payload,
    })
}

#[inline]
fn try_queue_bounded_control(conn: &Arc<Inner>, frame: Frame) -> bool {
    conn.try_queue_frame(frame).is_ok()
}

impl SendStream {
    pub fn stream_id(&self) -> u64 {
        self.inner.id()
    }

    pub fn close_identity(&self) -> *const () {
        Arc::as_ptr(&self.inner).cast::<()>()
    }

    pub fn is_opened_locally(&self) -> bool {
        self.inner.opened_locally
    }

    pub fn is_bidirectional(&self) -> bool {
        self.inner.bidi
    }

    pub fn is_write_closed(&self) -> bool {
        self.inner.is_write_closed()
    }

    pub fn open_info(&self) -> Vec<u8> {
        self.inner.open_info()
    }

    pub fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        self.inner.append_open_info_to(dst)
    }

    pub fn open_info_len(&self) -> usize {
        self.inner.open_info_len()
    }

    pub fn has_open_info(&self) -> bool {
        self.inner.has_open_info()
    }

    pub fn metadata(&self) -> StreamMetadata {
        self.inner.metadata()
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.conn.local_addr
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.conn.peer_addr
    }

    pub fn update_metadata(&self, update: MetadataUpdate) -> Result<()> {
        stream_result(
            StreamInner::update_metadata(self.inner.as_ref(), update),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        stream_result(
            StreamInner::set_write_deadline(self.inner.as_ref(), deadline),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        stream_result(
            StreamInner::set_write_deadline(self.inner.as_ref(), deadline),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_write_deadline(timeout_to_deadline(timeout))
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_deadline(timeout_to_deadline(timeout))
    }

    pub fn write(&self, src: &[u8]) -> Result<usize> {
        stream_result(
            StreamInner::write(self.inner.as_ref(), src, false),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        stream_result(
            StreamInner::write_timeout(self.inner.as_ref(), src, timeout),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_all<'a>(&self, src: impl Into<WritePayload<'a>>) -> Result<()> {
        stream_result(
            StreamInner::write_payload_until(self.inner.as_ref(), src.into(), false, None)
                .map(|_| ()),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_all_timeout<'a>(
        &self,
        src: impl Into<WritePayload<'a>>,
        timeout: Duration,
    ) -> Result<()> {
        stream_result(
            StreamInner::write_payload_until(
                self.inner.as_ref(),
                src.into(),
                false,
                deadline_after(timeout),
            )
            .map(|_| ()),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_vectored(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        stream_result(
            StreamInner::write_vectored(self.inner.as_ref(), parts, false),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_vectored_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        stream_result(
            StreamInner::write_vectored_timeout(self.inner.as_ref(), parts, timeout),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_final<'a>(&self, src: impl Into<WritePayload<'a>>) -> Result<usize> {
        stream_result(
            StreamInner::write_payload_until(self.inner.as_ref(), src.into(), true, None),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        stream_result(
            StreamInner::write_vectored_final(self.inner.as_ref(), parts),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_final_timeout<'a>(
        &self,
        src: impl Into<WritePayload<'a>>,
        timeout: Duration,
    ) -> Result<usize> {
        stream_result(
            StreamInner::write_payload_until(
                self.inner.as_ref(),
                src.into(),
                true,
                deadline_after(timeout),
            ),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        stream_result(
            StreamInner::write_vectored_final_timeout(self.inner.as_ref(), parts, timeout),
            ErrorOperation::Write,
            ErrorDirection::Write,
        )
    }

    pub fn close_write(&self) -> Result<()> {
        stream_result(
            StreamInner::close_write(self.inner.as_ref()),
            ErrorOperation::Close,
            ErrorDirection::Write,
        )
    }

    pub fn cancel_write(&self, code: u64) -> Result<()> {
        stream_result(
            StreamInner::cancel_write(self.inner.as_ref(), code, ""),
            ErrorOperation::Close,
            ErrorDirection::Write,
        )
    }

    pub fn close(&self) -> Result<()> {
        stream_result(
            StreamInner::close(self.inner.as_ref()),
            ErrorOperation::Close,
            ErrorDirection::Write,
        )
    }

    pub fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        stream_result(
            StreamInner::abort(self.inner.as_ref(), code, reason),
            ErrorOperation::Close,
            ErrorDirection::Write,
        )
    }
}

impl RecvStream {
    pub fn stream_id(&self) -> u64 {
        self.inner.id()
    }

    pub fn close_identity(&self) -> *const () {
        Arc::as_ptr(&self.inner).cast::<()>()
    }

    pub fn is_opened_locally(&self) -> bool {
        self.inner.opened_locally
    }

    pub fn is_bidirectional(&self) -> bool {
        self.inner.bidi
    }

    pub fn is_read_closed(&self) -> bool {
        self.inner.is_read_closed()
    }

    pub fn open_info(&self) -> Vec<u8> {
        self.inner.open_info()
    }

    pub fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        self.inner.append_open_info_to(dst)
    }

    pub fn open_info_len(&self) -> usize {
        self.inner.open_info_len()
    }

    pub fn has_open_info(&self) -> bool {
        self.inner.has_open_info()
    }

    pub fn metadata(&self) -> StreamMetadata {
        self.inner.metadata()
    }

    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.inner.conn.local_addr
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        self.inner.conn.peer_addr
    }

    pub fn read(&self, dst: &mut [u8]) -> Result<usize> {
        stream_result(
            StreamInner::read(self.inner.as_ref(), dst),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn read_vectored(&self, dsts: &mut [IoSliceMut<'_>]) -> Result<usize> {
        stream_result(
            StreamInner::read_vectored(self.inner.as_ref(), dsts),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn read_vectored_timeout(
        &self,
        dsts: &mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        stream_result(
            StreamInner::read_vectored_timeout(self.inner.as_ref(), dsts, timeout),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn read_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<usize> {
        stream_result(
            StreamInner::read_timeout(self.inner.as_ref(), dst, timeout),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn read_exact_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<()> {
        stream_result(
            StreamInner::read_exact_timeout(self.inner.as_ref(), dst, timeout),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        stream_result(
            StreamInner::set_read_deadline(self.inner.as_ref(), deadline),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        stream_result(
            StreamInner::set_read_deadline(self.inner.as_ref(), deadline),
            ErrorOperation::Read,
            ErrorDirection::Read,
        )
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_read_deadline(timeout_to_deadline(timeout))
    }

    pub fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_deadline(timeout_to_deadline(timeout))
    }

    pub fn close_read(&self) -> Result<()> {
        stream_result(
            StreamInner::close_read(self.inner.as_ref(), ErrorCode::Cancelled.as_u64()),
            ErrorOperation::Close,
            ErrorDirection::Read,
        )
    }

    pub fn cancel_read(&self, code: u64) -> Result<()> {
        stream_result(
            StreamInner::close_read(self.inner.as_ref(), code),
            ErrorOperation::Close,
            ErrorDirection::Read,
        )
    }

    pub fn close(&self) -> Result<()> {
        stream_result(
            StreamInner::close(self.inner.as_ref()),
            ErrorOperation::Close,
            ErrorDirection::Read,
        )
    }

    pub fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        stream_result(
            StreamInner::abort(self.inner.as_ref(), code, reason),
            ErrorOperation::Close,
            ErrorDirection::Read,
        )
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Stream::read(self, buf).map_err(Into::into)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        Stream::read_vectored(self, bufs).map_err(Into::into)
    }
}

impl Read for &Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        Stream::read(self, buf).map_err(Into::into)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        Stream::read_vectored(self, bufs).map_err(Into::into)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Stream::write(self, buf).map_err(Into::into)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        Stream::write_vectored(self, bufs).map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for &Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Stream::write(self, buf).map_err(Into::into)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        Stream::write_vectored(self, bufs).map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for RecvStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        RecvStream::read(self, buf).map_err(Into::into)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        RecvStream::read_vectored(self, bufs).map_err(Into::into)
    }
}

impl Read for &RecvStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        RecvStream::read(self, buf).map_err(Into::into)
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        RecvStream::read_vectored(self, bufs).map_err(Into::into)
    }
}

impl Write for SendStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        SendStream::write(self, buf).map_err(Into::into)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        SendStream::write_vectored(self, bufs).map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Write for &SendStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        SendStream::write(self, buf).map_err(Into::into)
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        SendStream::write_vectored(self, bufs).map_err(Into::into)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalCommitStatus {
    Committed,
    AwaitingTurn,
}

struct WritePermit<'a> {
    stream: &'a StreamInner,
}

impl Drop for WritePermit<'_> {
    fn drop(&mut self) {
        {
            let mut state = self.stream.state.lock().unwrap();
            state.write_in_progress = false;
        }
        self.stream.cond.notify_all();
    }
}

struct WriteCompletionRegistration<'a> {
    stream: &'a StreamInner,
    completion: WriteCompletion,
}

impl Drop for WriteCompletionRegistration<'_> {
    fn drop(&mut self) {
        let mut state = self.stream.state.lock().unwrap();
        if state
            .write_completion
            .as_ref()
            .is_some_and(|completion| completion.same(&self.completion))
        {
            state.write_completion = None;
        }
    }
}

struct PreparedDataFrame {
    frame: Frame,
    state: PreparedDataState,
}

struct PreparedDataState {
    opened_on_wire_before: bool,
    send_fin_before: bool,
    send_used_before: u64,
    send_session_used_delta: u64,
    releases_active_on_commit: bool,
    priority_update: PreparedPriorityUpdate,
}

enum PreparedPriorityUpdate {
    None,
    BeforeData(Vec<u8>),
    AfterData(Vec<u8>),
    Dropped(Vec<u8>),
}

impl PreparedPriorityUpdate {
    #[inline]
    fn queued_cost(&self) -> usize {
        match self {
            Self::BeforeData(payload) | Self::AfterData(payload) => payload.len().saturating_add(1),
            Self::None | Self::Dropped(_) => 0,
        }
    }

    #[inline]
    fn dropped(&self) -> bool {
        matches!(self, Self::Dropped(_))
    }

    #[inline]
    fn into_restore_payload(self) -> Option<Vec<u8>> {
        match self {
            Self::BeforeData(payload) | Self::AfterData(payload) | Self::Dropped(payload) => {
                Some(payload)
            }
            Self::None => None,
        }
    }
}

enum WriteBytes<'a> {
    Borrowed(&'a [u8]),
    Owned { bytes: Option<Vec<u8>>, len: usize },
}

impl<'a> WriteBytes<'a> {
    #[inline]
    fn borrowed(bytes: &'a [u8]) -> Self {
        Self::Borrowed(bytes)
    }

    #[inline]
    fn owned(bytes: Vec<u8>) -> Self {
        let len = bytes.len();
        Self::Owned {
            bytes: Some(bytes),
            len,
        }
    }

    #[inline]
    fn len(&self) -> usize {
        match self {
            Self::Borrowed(bytes) => bytes.len(),
            Self::Owned { len, .. } => *len,
        }
    }

    #[inline]
    fn can_move_range_into_empty_payload(&self, start: usize, end: usize) -> bool {
        match self {
            Self::Owned { bytes, len } => bytes.is_some() && start == 0 && end == *len,
            Self::Borrowed(_) => false,
        }
    }

    fn append_range_to(&mut self, dst: &mut Vec<u8>, start: usize, end: usize) -> Result<()> {
        let len = end
            .checked_sub(start)
            .ok_or_else(|| Error::local("zmux: invalid write payload range"))?;
        match self {
            Self::Borrowed(bytes) => append_payload_range(dst, &bytes[start..end], len),
            Self::Owned { bytes, len: total } => {
                if start == 0 && end == *total && dst.is_empty() {
                    *dst = bytes.take().ok_or_else(|| {
                        Error::local("zmux: owned write payload already consumed")
                    })?;
                    Ok(())
                } else {
                    let src = bytes.as_ref().ok_or_else(|| {
                        Error::local("zmux: owned write payload already consumed")
                    })?;
                    append_payload_range(dst, &src[start..end], len)
                }
            }
        }
    }
}

fn append_payload_range(dst: &mut Vec<u8>, src: &[u8], len: usize) -> Result<()> {
    if dst.try_reserve_exact(len).is_err() {
        return Err(Error::local("zmux: DATA payload allocation failed"));
    }
    dst.extend_from_slice(src);
    Ok(())
}

#[inline]
fn prepared_data_queue_cost(prepared: &PreparedDataFrame) -> usize {
    prepared
        .frame
        .payload
        .len()
        .saturating_add(1)
        .saturating_add(prepared.state.priority_update.queued_cost())
}

#[inline]
fn prepared_priority_frame(stream_id: u64, payload: &[u8]) -> Frame {
    Frame {
        frame_type: FrameType::Ext,
        flags: 0,
        stream_id,
        payload: payload.to_vec(),
    }
}

fn push_prepared_data_frame(
    frames: &mut Vec<Frame>,
    states: &mut Vec<PreparedDataState>,
    prepared: PreparedDataFrame,
) {
    let PreparedDataFrame { frame, state } = prepared;
    let stream_id = frame.stream_id;
    match &state.priority_update {
        PreparedPriorityUpdate::BeforeData(payload) => {
            frames.push(prepared_priority_frame(stream_id, payload));
            frames.push(frame);
        }
        PreparedPriorityUpdate::AfterData(payload) => {
            frames.push(frame);
            frames.push(prepared_priority_frame(stream_id, payload));
        }
        PreparedPriorityUpdate::None | PreparedPriorityUpdate::Dropped(_) => {
            frames.push(frame);
        }
    }
    states.push(state);
}

fn prepared_data_frames(
    stream_id: u64,
    frame: Frame,
    priority_update: &PreparedPriorityUpdate,
) -> Vec<Frame> {
    let mut frames = Vec::with_capacity(match priority_update {
        PreparedPriorityUpdate::BeforeData(_) | PreparedPriorityUpdate::AfterData(_) => 2,
        PreparedPriorityUpdate::None | PreparedPriorityUpdate::Dropped(_) => 1,
    });
    match priority_update {
        PreparedPriorityUpdate::BeforeData(payload) => {
            frames.push(prepared_priority_frame(stream_id, payload));
            frames.push(frame);
        }
        PreparedPriorityUpdate::AfterData(payload) => {
            frames.push(frame);
            frames.push(prepared_priority_frame(stream_id, payload));
        }
        PreparedPriorityUpdate::None | PreparedPriorityUpdate::Dropped(_) => frames.push(frame),
    }
    frames
}

const WRITE_COMPLETION_DEADLINE_POLL: Duration = Duration::from_millis(10);
const WRITE_COMPLETION_IDLE_POLL: Duration = Duration::from_secs(1);

#[inline]
fn deadline_after(timeout: Duration) -> Option<Instant> {
    Instant::now().checked_add(timeout)
}

#[inline]
fn timeout_to_deadline(timeout: Option<Duration>) -> Option<Instant> {
    match timeout {
        Some(timeout) => deadline_after(timeout),
        None => None,
    }
}

#[inline]
fn effective_deadline(
    stream_deadline: Option<Instant>,
    operation_deadline: Option<Instant>,
) -> Option<Instant> {
    match (stream_deadline, operation_deadline) {
        (Some(stream), Some(operation)) => Some(stream.min(operation)),
        (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
        (None, None) => None,
    }
}

#[inline]
fn write_deadline_expired(state: &StreamState, operation_deadline: Option<Instant>) -> bool {
    effective_deadline(state.write_deadline, operation_deadline)
        .is_some_and(|deadline| deadline <= Instant::now())
}

#[inline]
fn stop_sending_drain_window_locked(inner: &Inner, state: &ConnState) -> Duration {
    stop_sending_drain_window(
        inner.stop_sending_graceful_drain_window,
        state.last_ping_rtt,
    )
}

fn stop_sending_drain_window(
    configured: Option<Duration>,
    last_ping_rtt: Option<Duration>,
) -> Duration {
    if let Some(window) = nonzero_duration(configured) {
        return window;
    }
    if let Some(rtt) = last_ping_rtt {
        rtt.saturating_mul(2)
            .max(DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW)
            .min(DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW_MAX)
    } else {
        DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW
    }
}

#[inline]
fn nonzero_duration(value: Option<Duration>) -> Option<Duration> {
    match value {
        Some(value) if !value.is_zero() => Some(value),
        _ => None,
    }
}

fn priority_update_unavailable() -> Error {
    Error::local(
        "zmux: metadata update requires negotiated priority_update and matching semantic capability",
    )
}

#[inline]
fn metadata_update_can_carry_on_open(caps: u64, update: &MetadataUpdate) -> bool {
    update
        .priority
        .is_none_or(|_| capabilities_can_carry_priority_on_open(caps))
        && update
            .group
            .is_none_or(|_| capabilities_can_carry_group_on_open(caps))
}

fn validate_open_metadata_update_capability(caps: u64, update: &MetadataUpdate) -> Result<()> {
    if metadata_update_can_carry_on_open(caps, update) {
        Ok(())
    } else {
        Err(priority_update_unavailable())
    }
}

fn rebuild_open_metadata_prefix_locked(
    state: &mut StreamState,
    caps: u64,
    priority: Option<u64>,
    group: Option<u64>,
    max_frame_payload: u64,
) -> Result<()> {
    build_open_metadata_prefix_into(
        &mut state.open_prefix,
        caps,
        priority,
        group,
        &state.open_info,
        max_frame_payload,
    )
}

fn parse_pending_priority_update(payload: &[u8]) -> Result<StreamMetadata> {
    let (ext_type, n) = parse_varint(payload)?;
    if ext_type != EXT_PRIORITY_UPDATE {
        return Err(Error::new(
            ErrorCode::Internal,
            "invalid pending priority update subtype",
        ));
    }
    let (metadata, valid) = parse_priority_update_metadata(&payload[n..])?;
    if !valid {
        return Err(Error::new(
            ErrorCode::Internal,
            "invalid pending priority update payload",
        ));
    }
    Ok(metadata)
}

fn merged_priority_update_payload_len(
    caps: u64,
    update: MetadataUpdate,
    pending_payload: Option<&[u8]>,
    max_payload: u64,
) -> Result<(MetadataUpdate, usize)> {
    let update = merge_pending_priority_update(update, pending_payload)?;
    let len = priority_update_payload_len(caps, update, max_payload)?;
    Ok((update, len))
}

fn merge_pending_priority_update(
    mut update: MetadataUpdate,
    pending_payload: Option<&[u8]>,
) -> Result<MetadataUpdate> {
    if let Some(pending_payload) = pending_payload {
        let pending = parse_pending_priority_update(pending_payload)?;
        if update.priority.is_none() {
            update.priority = pending.priority;
        }
        if update.group.is_none() {
            update.group = pending.group;
        }
    }
    Ok(update)
}

fn build_priority_update_payload_reusing_pending(
    caps: u64,
    update: MetadataUpdate,
    pending_payload: &mut Option<Vec<u8>>,
    max_payload: u64,
) -> Result<Vec<u8>> {
    let mut payload = pending_payload.take().unwrap_or_default();
    match build_priority_update_payload_into(&mut payload, caps, update, max_payload) {
        Ok(()) => Ok(payload),
        Err(err) => {
            if !payload.is_empty() {
                *pending_payload = Some(payload);
            }
            Err(err)
        }
    }
}

#[inline]
fn close_write_noop_after_stop_reset(state: &StreamState) -> bool {
    state.stopped_by_peer.is_some()
        && (state.send_fin || (state.send_reset.is_some() && state.send_reset_from_stop))
}

#[inline]
fn close_write_error_ignored(err: &Error) -> bool {
    err.is_stream_not_writable() || err.is_write_closed() || err.is_read_closed()
}

#[inline]
fn close_read_error_ignored(err: &Error) -> bool {
    err.is_stream_not_readable() || err.is_read_closed() || err.is_write_closed()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalOpenPhase {
    None,
    NeedsCommit,
    NeedsEmit,
    Queued,
    PeerVisible,
}

impl LocalOpenPhase {
    #[inline]
    fn from_flags(
        opened_locally: bool,
        send_committed: bool,
        peer_visible: bool,
        opener_queued: bool,
    ) -> Self {
        if !opened_locally {
            return Self::None;
        }
        if peer_visible {
            return Self::PeerVisible;
        }
        if !send_committed {
            return Self::NeedsCommit;
        }
        if opener_queued {
            return Self::Queued;
        }
        Self::NeedsEmit
    }

    #[inline]
    fn needs_local_opener(self) -> bool {
        self == Self::NeedsCommit
    }

    #[cfg(test)]
    fn awaiting_peer_visibility(self) -> bool {
        matches!(self, Self::NeedsCommit | Self::NeedsEmit | Self::Queued)
    }

    #[inline]
    fn should_emit_opener_frame(self) -> bool {
        matches!(self, Self::NeedsCommit | Self::NeedsEmit)
    }

    #[cfg(test)]
    fn should_mark_peer_visible(self) -> bool {
        self != Self::None && self != Self::PeerVisible
    }

    #[inline]
    fn can_take_pending_priority_update(self) -> bool {
        !matches!(self, Self::NeedsCommit | Self::NeedsEmit | Self::Queued)
    }

    #[inline]
    fn pending_priority_can_precede_data(self) -> bool {
        matches!(self, Self::None | Self::Queued | Self::PeerVisible)
    }

    #[cfg(test)]
    fn should_queue_stream_blocked(self, available_stream: u64) -> bool {
        available_stream == 0 && self == Self::PeerVisible
    }
}

#[inline]
fn local_open_phase(opened_locally: bool, state: &StreamState) -> LocalOpenPhase {
    LocalOpenPhase::from_flags(
        opened_locally,
        state.opened_on_wire,
        state.peer_visible,
        state.opened_on_wire && !state.peer_visible,
    )
}

const DEFAULT_FRAGMENT_TIME_BUDGET: Duration = Duration::from_millis(200);
const MILD_FRAGMENT_TIME_BUDGET: Duration = Duration::from_millis(150);
const STRONG_FRAGMENT_TIME_BUDGET: Duration = Duration::from_millis(100);
const SATURATED_FRAGMENT_TIME_BUDGET: Duration = Duration::from_millis(50);

#[inline]
fn scaled_fragment_cap(max: u64, numerator: u64, denominator: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    if denominator == 0 {
        return max;
    }
    let value = u128_to_u64_saturating(
        u128::from(max).saturating_mul(u128::from(numerator)) / u128::from(denominator),
    );
    value.clamp(1, max)
}

#[inline]
fn fragment_cap(max_payload: u64, prefix_len: u64, priority: u64, hint: SchedulerHint) -> u64 {
    let max_payload = if max_payload == 0 {
        crate::settings::Settings::DEFAULT.max_frame_payload
    } else {
        max_payload
    };
    if prefix_len >= max_payload {
        return 0;
    }
    let available = max_payload - prefix_len;
    match priority {
        16..=u64::MAX => scaled_fragment_cap(available, 1, 4),
        4..=15 => scaled_fragment_cap(available, 1, 2),
        1..=3 => scaled_fragment_cap(available, 3, 4),
        0 if hint == SchedulerHint::Latency => scaled_fragment_cap(available, 1, 2),
        _ => available,
    }
}

#[inline]
fn fragment_time_budget(priority: u64, hint: SchedulerHint) -> Duration {
    match priority {
        16..=u64::MAX => SATURATED_FRAGMENT_TIME_BUDGET,
        4..=15 => STRONG_FRAGMENT_TIME_BUDGET,
        1..=3 => MILD_FRAGMENT_TIME_BUDGET,
        0 if hint == SchedulerHint::Latency => STRONG_FRAGMENT_TIME_BUDGET,
        _ => DEFAULT_FRAGMENT_TIME_BUDGET,
    }
}

#[inline]
fn rate_limited_fragment_cap(
    base_cap: u64,
    estimated_send_rate_bps: u64,
    priority: u64,
    hint: SchedulerHint,
) -> u64 {
    if base_cap == 0 || estimated_send_rate_bps == 0 {
        return base_cap;
    }
    let budget = fragment_time_budget(priority, hint);
    if budget.is_zero() {
        return base_cap;
    }
    const NANOS_PER_SECOND: u128 = 1_000_000_000;

    let raw_cap =
        u128::from(estimated_send_rate_bps).saturating_mul(budget.as_nanos()) / NANOS_PER_SECOND;
    let rate_cap = u128_to_u64_saturating(raw_cap);
    base_cap.min(rate_cap.max(1))
}

fn tx_fragment_cap_locked(
    inner: &Inner,
    conn_state: &ConnState,
    stream_state: &StreamState,
    prefix_len: usize,
) -> usize {
    let priority = stream_state.metadata.priority.unwrap_or(0);
    let peer = inner.peer_preface.settings;
    let base = fragment_cap(
        peer.max_frame_payload,
        usize_to_u64_saturating(prefix_len),
        priority,
        peer.scheduler_hints,
    );
    u64_to_usize_saturating(rate_limited_fragment_cap(
        base,
        conn_state.send_rate_estimate,
        priority,
        peer.scheduler_hints,
    ))
}

#[inline]
fn writable_data_bytes(
    frame_payload_room: usize,
    session_avail: u64,
    stream_avail: u64,
    remaining: usize,
) -> usize {
    frame_payload_room
        .min(u64_to_usize_saturating(session_avail))
        .min(u64_to_usize_saturating(stream_avail))
        .min(remaining)
}

#[inline]
fn checked_io_slice_total_len(lengths: impl IntoIterator<Item = usize>) -> Result<usize> {
    lengths.into_iter().try_fold(0usize, |total, len| {
        total
            .checked_add(len)
            .ok_or_else(|| Error::frame_size("DATA payload too large"))
    })
}

#[inline]
fn total_io_slice_len(parts: &[IoSlice<'_>]) -> Result<usize> {
    checked_io_slice_total_len(parts.iter().map(|part| part.len()))
}

fn append_io_slices(
    dst: &mut Vec<u8>,
    parts: &[IoSlice<'_>],
    mut part_idx: usize,
    mut part_off: usize,
    mut len: usize,
) -> (usize, usize) {
    while len > 0 && part_idx < parts.len() {
        let part = parts[part_idx].as_ref();
        if part_off >= part.len() {
            part_idx += 1;
            part_off = 0;
            continue;
        }
        let take = len.min(part.len() - part_off);
        dst.extend_from_slice(&part[part_off..part_off + take]);
        len -= take;
        part_off += take;
        if part_off == part.len() {
            part_idx += 1;
            part_off = 0;
        }
    }
    debug_assert_eq!(len, 0);
    (part_idx, part_off)
}

impl StreamInner {
    pub(super) fn id(&self) -> u64 {
        self.id.load(Ordering::Acquire)
    }

    fn is_local_uncommitted(&self) -> bool {
        self.opened_locally && self.id() == 0
    }

    fn is_read_closed(&self) -> bool {
        if !self.local_recv {
            return true;
        }
        let state = self.state.lock().unwrap();
        state.aborted.is_some()
            || state.read_stopped
            || state.recv_fin
            || state.recv_reset.is_some()
    }

    fn is_write_closed(&self) -> bool {
        if !self.local_send {
            return true;
        }
        let state = self.state.lock().unwrap();
        state.aborted.is_some()
            || state.stopped_by_peer.is_some()
            || state.send_fin
            || state.send_reset.is_some()
    }

    fn open_info_len(&self) -> usize {
        self.state.lock().unwrap().open_info.len()
    }

    fn has_open_info(&self) -> bool {
        !self.state.lock().unwrap().open_info.is_empty()
    }

    fn open_info(&self) -> Vec<u8> {
        self.state.lock().unwrap().open_info.clone()
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        let state = self.state.lock().unwrap();
        dst.extend_from_slice(&state.open_info);
    }

    fn metadata(&self) -> StreamMetadata {
        self.state.lock().unwrap().metadata.clone()
    }

    pub(super) fn try_graceful_finish_after_stop_sending(&self) -> Result<bool> {
        if !self.local_send {
            return Ok(false);
        }
        let drain_window = {
            let state = self.conn.state.lock().unwrap();
            stop_sending_drain_window_locked(&self.conn, &state)
        };
        let operation_deadline = Instant::now().checked_add(drain_window);
        let _permit = match self.acquire_writer_path_permit(operation_deadline, false) {
            Ok(permit) => permit,
            Err(err) if err.is_timeout() => return Ok(false),
            Err(err) => return Err(err),
        };

        let prepared = {
            let mut conn_state = self.conn.state.lock().unwrap();
            ensure_session_not_closed(&conn_state)?;
            let stream_id = self.id();
            let queued_data_bytes = self
                .conn
                .write_queue
                .data_queued_bytes_for_stream(stream_id);
            let mut stream_state = self.state.lock().unwrap();
            if stream_state.stopped_by_peer.is_none()
                || stream_state.send_fin
                || stream_state.send_reset.is_some()
                || stream_state.aborted.is_some()
                || stream_state.recv_reset.is_some()
            {
                return Ok(false);
            }
            let inflight_queued = conn_state
                .inflight_data_by_stream
                .get(&stream_id)
                .copied()
                .unwrap_or(0);
            let fragment_cap = tx_fragment_cap_locked(&self.conn, &conn_state, &stream_state, 0);
            let local_phase = local_open_phase(self.opened_locally, &stream_state);
            let decision = evaluate_graceful(GracefulInput {
                recv_abortive: stream_state.recv_reset.is_some() || stream_state.aborted.is_some(),
                needs_local_opener: local_phase.needs_local_opener(),
                local_opened: self.opened_locally,
                send_committed: stream_state.opened_on_wire,
                queued_data_bytes: usize_to_u64_saturating(queued_data_bytes),
                inflight_queued: usize_to_u64_saturating(inflight_queued),
                fragment_cap: usize_to_u64_saturating(fragment_cap),
                send_rate_estimate: conn_state.send_rate_estimate,
                explicit_tail_cap: self.conn.stop_sending_graceful_tail_cap,
                drain_window,
            });
            if !decision.attempt {
                return Ok(false);
            }
            self.prepare_data_frame_locked(&mut conn_state, &mut stream_state, &[], true)?
        };

        let queued = self.queue_prepared_data_until(
            prepared,
            || operation_deadline,
            || self.ensure_graceful_stop_sending_still_pending(),
            "write",
            None,
        );
        match queued {
            Ok(prepared_state) => {
                self.commit_prepared_data(prepared_state);
                Ok(true)
            }
            Err(err) if err.is_timeout() => Ok(false),
            Err(err) => Err(err),
        }
    }

    fn ensure_local_open_committed_locked(
        &self,
        conn_state: &mut ConnState,
        stream_state: &mut StreamState,
    ) -> Result<LocalCommitStatus> {
        if !self.is_local_uncommitted() {
            return Ok(LocalCommitStatus::Committed);
        }

        reap_expired_provisionals_locked(conn_state, self.bidi, Some(self));
        let queue = if self.bidi {
            &mut conn_state.provisional_bidi
        } else {
            &mut conn_state.provisional_uni
        };
        let is_head = queue
            .front()
            .is_some_and(|stream| ptr::eq(Arc::as_ptr(stream), self));
        if !is_head {
            return Ok(LocalCommitStatus::AwaitingTurn);
        }

        let now = Instant::now();
        let max_age = provisional_open_max_age(conn_state.last_ping_rtt);
        if provisional_expired_locked(stream_state, now, max_age) {
            queue.pop_front();
            fail_expired_provisional_locked(conn_state, stream_state);
            self.conn.cond.notify_all();
            self.cond.notify_all();
            return Err(Error::application(
                ErrorCode::Cancelled.as_u64(),
                provisional_open_expired_reason(),
            )
            .with_source(ErrorSource::Local)
            .with_termination_kind(TerminationKind::Abort));
        }

        let id = if self.bidi {
            conn_state.next_local_bidi
        } else {
            conn_state.next_local_uni
        };
        let goaway = if self.bidi {
            conn_state.peer_go_away_bidi
        } else {
            conn_state.peer_go_away_uni
        };
        if id > MAX_VARINT62 {
            stream_state.aborted = Some((
                ErrorCode::Protocol.as_u64(),
                "stream id overflow".to_owned(),
            ));
            stream_state.abort_source = ErrorSource::Local;
            stream_state.provisional_created_at = None;
            queue.pop_front();
            clear_stream_open_info_locked(conn_state, stream_state);
            clear_stream_open_prefix_locked(stream_state);
            self.conn.cond.notify_all();
            self.cond.notify_all();
            return Err(Error::new(ErrorCode::Protocol, "stream id overflow")
                .with_source(ErrorSource::Local));
        }
        if id > goaway {
            stream_state.aborted = Some((
                ErrorCode::RefusedStream.as_u64(),
                "peer GOAWAY refuses local open".to_owned(),
            ));
            stream_state.abort_source = ErrorSource::Remote;
            stream_state.provisional_created_at = None;
            queue.pop_front();
            clear_stream_open_info_locked(conn_state, stream_state);
            clear_stream_open_prefix_locked(stream_state);
            self.conn.cond.notify_all();
            self.cond.notify_all();
            return Err(
                Error::new(ErrorCode::RefusedStream, "peer GOAWAY refuses local open")
                    .with_source(ErrorSource::Remote),
            );
        }
        let (active_local, peer_stream_limit) = if self.bidi {
            (
                conn_state.active.local_bidi,
                self.conn.peer_preface.settings.max_incoming_streams_bidi,
            )
        } else {
            (
                conn_state.active.local_uni,
                self.conn.peer_preface.settings.max_incoming_streams_uni,
            )
        };
        if active_local >= peer_stream_limit {
            stream_state.aborted = Some((
                ErrorCode::RefusedStream.as_u64(),
                "peer incoming stream limit reached".to_owned(),
            ));
            stream_state.abort_source = ErrorSource::Remote;
            stream_state.provisional_created_at = None;
            queue.pop_front();
            clear_stream_open_info_locked(conn_state, stream_state);
            clear_stream_open_prefix_locked(stream_state);
            self.conn.cond.notify_all();
            self.cond.notify_all();
            return Err(Error::new(
                ErrorCode::RefusedStream,
                "peer incoming stream limit reached",
            )
            .with_source(ErrorSource::Remote));
        }

        let stream = queue.pop_front().expect("head checked above");
        self.id.store(id, Ordering::Release);
        let next_id = id + 4;
        if self.bidi {
            conn_state.next_local_bidi = next_id;
            conn_state.active.local_bidi = conn_state.active.local_bidi.saturating_add(1);
        } else {
            conn_state.next_local_uni = next_id;
            conn_state.active.local_uni = conn_state.active.local_uni.saturating_add(1);
        }
        stream_state.send_max = initial_send_window(
            self.conn.negotiated.local_role,
            &self.conn.peer_preface.settings,
            id,
        );
        stream_state.recv_advertised = initial_receive_window(
            self.conn.negotiated.local_role,
            &self.conn.local_preface.settings,
            id,
        );
        stream_state.late_data_cap = late_data_per_stream_cap(
            conn_state.late_data_per_stream_cap,
            stream_state.recv_advertised,
            self.conn.local_preface.settings.max_frame_payload,
        );
        if let Some(created_at) = stream_state.provisional_created_at.take() {
            conn_state.last_open_latency =
                Some(Instant::now().saturating_duration_since(created_at));
        }
        stream_state.active_counted = true;
        conn_state.streams.insert(id, Arc::clone(&stream));
        self.conn.cond.notify_all();
        self.cond.notify_all();
        Ok(LocalCommitStatus::Committed)
    }

    fn remove_uncommitted_local_locked(
        &self,
        conn_state: &mut ConnState,
        stream_state: &mut StreamState,
    ) -> bool {
        if !self.is_local_uncommitted() {
            return false;
        }
        let queue = if self.bidi {
            &mut conn_state.provisional_bidi
        } else {
            &mut conn_state.provisional_uni
        };
        if let Some(pos) = queue
            .iter()
            .position(|stream| ptr::eq(Arc::as_ptr(stream), self))
        {
            let _ = queue.remove(pos);
            shrink_provisional_queue_locked(conn_state, self.bidi);
            stream_state.provisional_created_at = None;
            clear_stream_open_info_locked(conn_state, stream_state);
            clear_stream_open_prefix_locked(stream_state);
            self.conn.cond.notify_all();
            return true;
        }
        false
    }

    fn fail_uncommitted_local_abort_locked(
        &self,
        conn_state: &mut ConnState,
        stream_state: &mut StreamState,
        code: u64,
        reason: &str,
    ) -> (u64, usize) {
        self.remove_uncommitted_local_locked(conn_state, stream_state);
        stream_state.aborted = Some((code, reason.to_owned()));
        stream_state.abort_source = ErrorSource::Local;
        let released = stream_state.recv_buf.clear_detailed();
        clear_stream_receive_credit_locked(&self.conn, self, stream_state);
        (
            usize_to_u64_saturating(released.bytes),
            released.released_retained_bytes,
        )
    }

    fn read(&self, dst: &mut [u8]) -> Result<usize> {
        self.read_until(dst, None)
    }

    fn read_vectored(&self, dsts: &mut [IoSliceMut<'_>]) -> Result<usize> {
        self.read_vectored_until(dsts, None)
    }

    fn read_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<usize> {
        self.read_until(dst, deadline_after(timeout))
    }

    fn read_vectored_timeout(
        &self,
        dsts: &mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        self.read_vectored_until(dsts, deadline_after(timeout))
    }

    fn read_exact_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<()> {
        self.read_exact_until(dst, deadline_after(timeout))
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        if !self.local_recv {
            return Err(Error::local("zmux: stream is not readable"));
        }
        {
            let conn_state = self.conn.state.lock().unwrap();
            ensure_session_open(&conn_state)?;
            let mut state = self.state.lock().unwrap();
            state.read_deadline = deadline;
        }
        self.cond.notify_all();
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        if !self.local_send {
            return Err(Error::local("zmux: stream is not writable"));
        }
        let completion = {
            let conn_state = self.conn.state.lock().unwrap();
            ensure_session_open(&conn_state)?;
            let mut state = self.state.lock().unwrap();
            state.write_deadline = deadline;
            state.write_completion.clone()
        };
        self.cond.notify_all();
        self.conn.cond.notify_all();
        self.conn.wake_writer_queue_waiters();
        if let Some(completion) = completion {
            completion.notify_waiters();
        }
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        let completion = {
            let conn_state = self.conn.state.lock().unwrap();
            ensure_session_open(&conn_state)?;
            let mut state = self.state.lock().unwrap();
            if self.local_recv {
                state.read_deadline = deadline;
            }
            if self.local_send {
                state.write_deadline = deadline;
            }
            if self.local_send {
                state.write_completion.clone()
            } else {
                None
            }
        };
        self.cond.notify_all();
        if self.local_send {
            self.conn.cond.notify_all();
            self.conn.wake_writer_queue_waiters();
            if let Some(completion) = completion {
                completion.notify_waiters();
            }
        }
        Ok(())
    }

    fn read_until(&self, dst: &mut [u8], operation_deadline: Option<Instant>) -> Result<usize> {
        if !self.local_recv {
            return Err(Error::local("zmux: stream is not readable"));
        }
        if dst.is_empty() {
            return Ok(0);
        }
        self.read_buffered_until(operation_deadline, |recv_buf| recv_buf.read_detailed(dst))
    }

    fn read_exact_until(
        &self,
        mut dst: &mut [u8],
        operation_deadline: Option<Instant>,
    ) -> Result<()> {
        while !dst.is_empty() {
            let n = self.read_until(dst, operation_deadline)?;
            if n == 0 {
                return Err(unexpected_eof_error());
            }
            let (_, rest) = dst.split_at_mut(n);
            dst = rest;
        }
        Ok(())
    }

    fn read_vectored_until(
        &self,
        dsts: &mut [IoSliceMut<'_>],
        operation_deadline: Option<Instant>,
    ) -> Result<usize> {
        if let [single] = dsts {
            return self.read_until(single.as_mut(), operation_deadline);
        }
        if !self.local_recv {
            return Err(Error::local("zmux: stream is not readable"));
        }
        if dsts.iter().all(|dst| dst.is_empty()) {
            return Ok(0);
        }
        self.read_buffered_until(operation_deadline, |recv_buf| {
            recv_buf.read_vectored_detailed(dsts)
        })
    }

    fn read_buffered_until(
        &self,
        operation_deadline: Option<Instant>,
        mut read_from_buffer: impl FnMut(&mut RecvBuffer) -> RecvBufferRead,
    ) -> Result<usize> {
        let mut state = self.state.lock().unwrap();
        loop {
            if state.read_stopped {
                return Err(Error::read_closed());
            }
            if let Some((code, reason)) = &state.aborted {
                return Err(stream_abort_error(&state, *code, reason.clone()));
            }
            if let Some((code, reason)) = &state.recv_reset {
                return Err(peer_reset_error(*code, reason.clone()));
            }
            if !state.recv_buf.is_empty() {
                let read_result = read_from_buffer(&mut state.recv_buf);
                let should_compact = state.recv_buf.is_empty();
                drop(state);
                self.replenish_released_receive(
                    usize_to_u64_saturating(read_result.bytes),
                    read_result.released_retained_bytes,
                    true,
                );
                record_stream_application_progress(&self.conn, Instant::now());
                if should_compact {
                    self.compact_if_possible();
                }
                return Ok(read_result.bytes);
            }
            if state.recv_fin {
                return Ok(0);
            }
            drop(state);
            let session_err = {
                let conn_state = self.conn.state.lock().unwrap();
                if matches!(
                    conn_state.state,
                    SessionState::Closed | SessionState::Failed
                ) {
                    Some(
                        conn_state
                            .close_error
                            .clone()
                            .unwrap_or_else(Error::session_closed),
                    )
                } else {
                    None
                }
            };
            if let Some(err) = session_err {
                return Err(err);
            }
            state = self.state.lock().unwrap();
            if state.aborted.is_some()
                || state.read_stopped
                || state.recv_reset.is_some()
                || !state.recv_buf.is_empty()
                || state.recv_fin
            {
                continue;
            }
            let deadline = effective_deadline(state.read_deadline, operation_deadline);
            if let Some(deadline) = deadline {
                let Some(wait) = deadline.checked_duration_since(Instant::now()) else {
                    return Err(Error::timeout("read"));
                };
                let wait = wait.min(MAX_CONDVAR_TIMED_WAIT);
                let (next, _) = self.cond.wait_timeout(state, wait).unwrap();
                state = next;
            } else {
                state = self.cond.wait(state).unwrap();
            }
        }
    }

    fn write(&self, src: &[u8], fin: bool) -> Result<usize> {
        self.write_until(src, fin, None)
    }

    fn write_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        self.write_until(src, false, deadline_after(timeout))
    }

    fn write_vectored(&self, parts: &[IoSlice<'_>], fin: bool) -> Result<usize> {
        self.write_vectored_until(parts, fin, None)
    }

    fn write_vectored_timeout(&self, parts: &[IoSlice<'_>], timeout: Duration) -> Result<usize> {
        self.write_vectored_until(parts, false, deadline_after(timeout))
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        self.write_vectored_until(parts, true, None)
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        self.write_vectored_until(parts, true, deadline_after(timeout))
    }

    fn projected_next_data_queue_cost_locked(
        &self,
        conn_state: &ConnState,
        stream_state: &StreamState,
        data_remaining: usize,
        fin: bool,
    ) -> usize {
        if data_remaining == 0 && !fin {
            return 0;
        }
        let prefix_len = if stream_state.opened_on_wire {
            0
        } else {
            stream_state.open_prefix.len()
        };
        if data_remaining == 0 {
            return prefix_len.saturating_add(1);
        }
        let frame_payload_room =
            tx_fragment_cap_locked(&self.conn, conn_state, stream_state, prefix_len);
        let session_avail = conn_state
            .send_session_max
            .saturating_sub(conn_state.send_session_used);
        let stream_avail = stream_state.send_max.saturating_sub(stream_state.send_used);
        let available = writable_data_bytes(
            frame_payload_room,
            session_avail,
            stream_avail,
            data_remaining,
        );
        if available == 0 && stream_state.opened_on_wire {
            return 0;
        }
        let projected_data = if available == 0 {
            data_remaining.min(frame_payload_room).max(1)
        } else {
            available
        };
        prefix_len.saturating_add(projected_data).saturating_add(1)
    }

    fn fail_session_with_close_error(&self, err: Error) {
        let close_frame = Frame {
            frame_type: FrameType::Close,
            flags: 0,
            stream_id: 0,
            payload: build_code_payload(
                err.numeric_code().unwrap_or(ErrorCode::Internal.as_u64()),
                &err.to_string(),
                self.conn.peer_preface.settings.max_control_payload_bytes,
            )
            .unwrap_or_default(),
        };
        fail_session_with_close(&self.conn, err, close_frame);
    }

    fn write_until(
        &self,
        src: &[u8],
        fin: bool,
        operation_deadline: Option<Instant>,
    ) -> Result<usize> {
        self.write_bytes_until(WriteBytes::borrowed(src), fin, operation_deadline)
    }

    fn write_payload_until(
        &self,
        payload: WritePayload<'_>,
        fin: bool,
        operation_deadline: Option<Instant>,
    ) -> Result<usize> {
        match payload {
            WritePayload::Bytes(Cow::Borrowed(src)) => {
                self.write_bytes_until(WriteBytes::borrowed(src), fin, operation_deadline)
            }
            WritePayload::Bytes(Cow::Owned(src)) => {
                self.write_bytes_until(WriteBytes::owned(src), fin, operation_deadline)
            }
            WritePayload::Vectored(parts) => {
                self.write_vectored_until(parts, fin, operation_deadline)
            }
        }
    }

    fn write_bytes_until(
        &self,
        mut src: WriteBytes<'_>,
        fin: bool,
        operation_deadline: Option<Instant>,
    ) -> Result<usize> {
        if !self.local_send {
            return Err(Error::local("zmux: stream is not writable"));
        }
        let src_len = src.len();
        if src_len == 0 && !fin {
            return Ok(0);
        }

        let _permit = self.acquire_write_permit(operation_deadline)?;
        let mut written = 0usize;
        'write_loop: loop {
            let burst_limit = self.conn.write_queue.max_batch_frames().max(1);
            let burst_byte_cap = self.conn.write_queue.data_burst_max_bytes();
            let mut prepared_frames = Vec::with_capacity(burst_limit.min(16));
            let mut prepared_states = Vec::with_capacity(burst_limit.min(16));
            let mut batch_progress = 0usize;
            let mut batch_cost = 0usize;
            let mut burst_frame_limit = burst_limit;
            let mut burst_frame_limit_ready = false;
            let mut done = false;

            for _ in 0..burst_limit {
                let current_written = written.saturating_add(batch_progress);
                let mut prepared;
                let byte_progress;
                let mut app_copy = None;
                let frame_done;
                {
                    let mut conn_state = self.conn.state.lock().unwrap();
                    if let Err(err) = ensure_session_not_closed(&conn_state) {
                        drop(conn_state);
                        self.rollback_prepared_states_batch(prepared_states);
                        return Err(err);
                    }
                    let mut stream_state = self.state.lock().unwrap();
                    if let Err(err) = check_write_open(&stream_state) {
                        drop(stream_state);
                        drop(conn_state);
                        self.rollback_prepared_states_batch(prepared_states);
                        return Err(err);
                    }
                    if write_deadline_expired(&stream_state, operation_deadline) {
                        let projected_cost = self.projected_next_data_queue_cost_locked(
                            &conn_state,
                            &stream_state,
                            src_len.saturating_sub(current_written),
                            fin && current_written == src_len,
                        );
                        if projected_cost > 0 {
                            drop(stream_state);
                            if let Err(err) = ensure_projected_session_memory_cap_locked(
                                &self.conn,
                                &mut conn_state,
                                projected_cost,
                                "write",
                            ) {
                                drop(conn_state);
                                self.fail_session_with_close_error(err.clone());
                                self.rollback_prepared_states_batch(prepared_states);
                                return Err(err);
                            }
                        } else {
                            drop(stream_state);
                        }
                        self.rollback_prepared_states_batch(prepared_states);
                        return Err(Error::timeout("write"));
                    }
                    if !burst_frame_limit_ready {
                        burst_frame_limit = self.write_burst_frame_limit_for_priority(
                            stream_state.metadata.priority.unwrap_or(0),
                        );
                        burst_frame_limit_ready = true;
                    }
                    if !prepared_states.is_empty() && prepared_states.len() >= burst_frame_limit {
                        drop(stream_state);
                        drop(conn_state);
                        break;
                    }
                    let local_commit = if !stream_state.opened_on_wire {
                        match self
                            .ensure_local_open_committed_locked(&mut conn_state, &mut stream_state)
                        {
                            Ok(status) => status,
                            Err(err) => {
                                drop(stream_state);
                                drop(conn_state);
                                self.rollback_prepared_states_batch(prepared_states);
                                return Err(err);
                            }
                        }
                    } else {
                        LocalCommitStatus::Committed
                    };
                    if local_commit == LocalCommitStatus::AwaitingTurn {
                        drop(stream_state);
                        if prepared_states.is_empty() {
                            conn_state = self.wait_conn_write(conn_state, operation_deadline)?;
                            drop(conn_state);
                            continue 'write_loop;
                        }
                        drop(conn_state);
                        break;
                    }

                    if fin && current_written == src_len {
                        if stream_state.send_fin {
                            self.rollback_prepared_states_batch(prepared_states);
                            return Ok(written.saturating_add(batch_progress));
                        }
                        prepared = match self.prepare_data_frame_locked(
                            &mut conn_state,
                            &mut stream_state,
                            &[],
                            true,
                        ) {
                            Ok(prepared) => prepared,
                            Err(err) => {
                                drop(stream_state);
                                drop(conn_state);
                                self.rollback_prepared_states_batch(prepared_states);
                                return Err(err);
                            }
                        };
                        byte_progress = 0;
                        frame_done = true;
                    } else {
                        let prefix_len = if stream_state.opened_on_wire {
                            0
                        } else {
                            stream_state.open_prefix.len()
                        };
                        let frame_payload_room = tx_fragment_cap_locked(
                            &self.conn,
                            &conn_state,
                            &stream_state,
                            prefix_len,
                        );
                        let session_avail = conn_state
                            .send_session_max
                            .saturating_sub(conn_state.send_session_used);
                        let stream_avail =
                            stream_state.send_max.saturating_sub(stream_state.send_used);
                        let available = writable_data_bytes(
                            frame_payload_room,
                            session_avail,
                            stream_avail,
                            src_len - current_written,
                        );

                        if available == 0 {
                            if !stream_state.opened_on_wire {
                                prepared = match self.prepare_data_frame_locked(
                                    &mut conn_state,
                                    &mut stream_state,
                                    &[],
                                    false,
                                ) {
                                    Ok(prepared) => prepared,
                                    Err(err) => {
                                        drop(stream_state);
                                        drop(conn_state);
                                        self.rollback_prepared_states_batch(prepared_states);
                                        return Err(err);
                                    }
                                };
                                byte_progress = 0;
                                frame_done = false;
                            } else if prepared_states.is_empty() {
                                let session_blocked = if session_avail == 0 {
                                    Some(conn_state.send_session_max)
                                } else {
                                    None
                                };
                                let stream_blocked = if stream_avail == 0 {
                                    Some(stream_state.send_max)
                                } else {
                                    None
                                };
                                drop(stream_state);
                                drop(conn_state);
                                self.queue_blocked_signals(session_blocked, stream_blocked);
                                conn_state = self.conn.state.lock().unwrap();
                                ensure_session_not_closed(&conn_state)?;
                                conn_state =
                                    self.wait_conn_write(conn_state, operation_deadline)?;
                                drop(conn_state);
                                continue 'write_loop;
                            } else {
                                drop(stream_state);
                                drop(conn_state);
                                break;
                            }
                        } else {
                            let end = current_written + available;
                            let is_final = fin && end == src_len;
                            prepared = match self.prepare_data_frame_header_locked(
                                &mut conn_state,
                                &mut stream_state,
                                available,
                                is_final,
                                !src.can_move_range_into_empty_payload(current_written, end),
                            ) {
                                Ok(prepared) => prepared,
                                Err(err) => {
                                    drop(stream_state);
                                    drop(conn_state);
                                    self.rollback_prepared_states_batch(prepared_states);
                                    return Err(err);
                                }
                            };
                            byte_progress = available;
                            app_copy = Some((current_written, end));
                            frame_done = end == src_len;
                        }
                    }
                }

                if let Some((start, end)) = app_copy {
                    if let Err(err) = src.append_range_to(&mut prepared.frame.payload, start, end) {
                        self.rollback_prepared_data(prepared.state);
                        self.rollback_prepared_states_batch(prepared_states);
                        return Err(err);
                    }
                }

                let prepared_cost = prepared_data_queue_cost(&prepared);
                if !prepared_states.is_empty()
                    && batch_cost.saturating_add(prepared_cost) > burst_byte_cap
                {
                    self.rollback_prepared_data(prepared.state);
                    break;
                }

                batch_cost = batch_cost.saturating_add(prepared_cost);
                push_prepared_data_frame(&mut prepared_frames, &mut prepared_states, prepared);
                batch_progress = batch_progress.saturating_add(byte_progress);
                done = frame_done;

                if byte_progress == 0 || done {
                    break;
                }
            }

            if prepared_states.is_empty() {
                continue;
            }

            let completion = WriteCompletion::new();
            let prepared_states = self.queue_prepared_data_batch_until(
                prepared_frames,
                prepared_states,
                || self.current_write_deadline(operation_deadline),
                || self.ensure_prepared_write_not_aborted(),
                "write",
                completion.clone(),
            )?;
            let prepared_states = self.wait_prepared_write_batch_completion(
                &completion,
                prepared_states,
                operation_deadline,
            )?;
            self.commit_prepared_data_batch(prepared_states);
            written = written.saturating_add(batch_progress);
            if batch_progress > 0 {
                record_stream_application_progress(&self.conn, Instant::now());
            }
            if done {
                return Ok(written);
            }
        }
    }

    fn write_vectored_until(
        &self,
        parts: &[IoSlice<'_>],
        fin: bool,
        operation_deadline: Option<Instant>,
    ) -> Result<usize> {
        if !self.local_send {
            return Err(Error::local("zmux: stream is not writable"));
        }
        if let [single] = parts {
            return self.write_until(single.as_ref(), fin, operation_deadline);
        }
        let total = total_io_slice_len(parts)?;
        if total == 0 {
            return if fin {
                self.write_until(&[], true, operation_deadline)
            } else {
                Ok(0)
            };
        }

        let _permit = self.acquire_write_permit(operation_deadline)?;
        let mut written = 0usize;
        let mut part_idx = 0usize;
        let mut part_off = 0usize;
        'write_loop: loop {
            let burst_limit = self.conn.write_queue.max_batch_frames().max(1);
            let burst_byte_cap = self.conn.write_queue.data_burst_max_bytes();
            let mut prepared_frames = Vec::with_capacity(burst_limit.min(16));
            let mut prepared_states = Vec::with_capacity(burst_limit.min(16));
            let mut batch_progress = 0usize;
            let mut batch_cost = 0usize;
            let mut batch_part_idx = part_idx;
            let mut batch_part_off = part_off;
            let mut burst_frame_limit = burst_limit;
            let mut burst_frame_limit_ready = false;
            let mut done = false;

            for _ in 0..burst_limit {
                let current_written = written.saturating_add(batch_progress);
                let mut prepared;
                let byte_progress;
                let mut app_copy = None;
                let frame_done;
                {
                    let mut conn_state = self.conn.state.lock().unwrap();
                    if let Err(err) = ensure_session_not_closed(&conn_state) {
                        drop(conn_state);
                        self.rollback_prepared_states_batch(prepared_states);
                        return Err(err);
                    }
                    let mut stream_state = self.state.lock().unwrap();
                    if let Err(err) = check_write_open(&stream_state) {
                        drop(stream_state);
                        drop(conn_state);
                        self.rollback_prepared_states_batch(prepared_states);
                        return Err(err);
                    }
                    if write_deadline_expired(&stream_state, operation_deadline) {
                        let projected_cost = self.projected_next_data_queue_cost_locked(
                            &conn_state,
                            &stream_state,
                            total.saturating_sub(current_written),
                            fin && current_written == total,
                        );
                        if projected_cost > 0 {
                            drop(stream_state);
                            if let Err(err) = ensure_projected_session_memory_cap_locked(
                                &self.conn,
                                &mut conn_state,
                                projected_cost,
                                "write",
                            ) {
                                drop(conn_state);
                                self.fail_session_with_close_error(err.clone());
                                self.rollback_prepared_states_batch(prepared_states);
                                return Err(err);
                            }
                        } else {
                            drop(stream_state);
                        }
                        self.rollback_prepared_states_batch(prepared_states);
                        return Err(Error::timeout("write"));
                    }
                    if !burst_frame_limit_ready {
                        burst_frame_limit = self.write_burst_frame_limit_for_priority(
                            stream_state.metadata.priority.unwrap_or(0),
                        );
                        burst_frame_limit_ready = true;
                    }
                    if !prepared_states.is_empty() && prepared_states.len() >= burst_frame_limit {
                        drop(stream_state);
                        drop(conn_state);
                        break;
                    }
                    let local_commit = if !stream_state.opened_on_wire {
                        match self
                            .ensure_local_open_committed_locked(&mut conn_state, &mut stream_state)
                        {
                            Ok(status) => status,
                            Err(err) => {
                                drop(stream_state);
                                drop(conn_state);
                                self.rollback_prepared_states_batch(prepared_states);
                                return Err(err);
                            }
                        }
                    } else {
                        LocalCommitStatus::Committed
                    };
                    if local_commit == LocalCommitStatus::AwaitingTurn {
                        drop(stream_state);
                        if prepared_states.is_empty() {
                            conn_state = self.wait_conn_write(conn_state, operation_deadline)?;
                            drop(conn_state);
                            continue 'write_loop;
                        }
                        drop(conn_state);
                        break;
                    }

                    let prefix_len = if stream_state.opened_on_wire {
                        0
                    } else {
                        stream_state.open_prefix.len()
                    };
                    let frame_payload_room =
                        tx_fragment_cap_locked(&self.conn, &conn_state, &stream_state, prefix_len);
                    let session_avail = conn_state
                        .send_session_max
                        .saturating_sub(conn_state.send_session_used);
                    let stream_avail = stream_state.send_max.saturating_sub(stream_state.send_used);
                    let available = writable_data_bytes(
                        frame_payload_room,
                        session_avail,
                        stream_avail,
                        total - current_written,
                    );

                    if available == 0 {
                        if !stream_state.opened_on_wire {
                            prepared = match self.prepare_data_frame_locked(
                                &mut conn_state,
                                &mut stream_state,
                                &[],
                                false,
                            ) {
                                Ok(prepared) => prepared,
                                Err(err) => {
                                    drop(stream_state);
                                    drop(conn_state);
                                    self.rollback_prepared_states_batch(prepared_states);
                                    return Err(err);
                                }
                            };
                            byte_progress = 0;
                            frame_done = false;
                        } else if prepared_states.is_empty() {
                            let session_blocked = if session_avail == 0 {
                                Some(conn_state.send_session_max)
                            } else {
                                None
                            };
                            let stream_blocked = if stream_avail == 0 {
                                Some(stream_state.send_max)
                            } else {
                                None
                            };
                            drop(stream_state);
                            drop(conn_state);
                            self.queue_blocked_signals(session_blocked, stream_blocked);
                            conn_state = self.conn.state.lock().unwrap();
                            ensure_session_not_closed(&conn_state)?;
                            conn_state = self.wait_conn_write(conn_state, operation_deadline)?;
                            drop(conn_state);
                            continue 'write_loop;
                        } else {
                            drop(stream_state);
                            drop(conn_state);
                            break;
                        }
                    } else {
                        let end = current_written + available;
                        let is_final = fin && end == total;
                        prepared = match self.prepare_data_frame_header_locked(
                            &mut conn_state,
                            &mut stream_state,
                            available,
                            is_final,
                            true,
                        ) {
                            Ok(prepared) => prepared,
                            Err(err) => {
                                drop(stream_state);
                                drop(conn_state);
                                self.rollback_prepared_states_batch(prepared_states);
                                return Err(err);
                            }
                        };
                        byte_progress = available;
                        app_copy = Some((batch_part_idx, batch_part_off, available));
                        frame_done = end == total;
                    }
                }

                let advanced_cursor =
                    if let Some((copy_part_idx, copy_part_off, copy_len)) = app_copy {
                        if prepared.frame.payload.try_reserve_exact(copy_len).is_err() {
                            self.rollback_prepared_data(prepared.state);
                            self.rollback_prepared_states_batch(prepared_states);
                            return Err(Error::local("zmux: DATA payload allocation failed"));
                        }
                        Some(append_io_slices(
                            &mut prepared.frame.payload,
                            parts,
                            copy_part_idx,
                            copy_part_off,
                            copy_len,
                        ))
                    } else {
                        None
                    };

                let prepared_cost = prepared_data_queue_cost(&prepared);
                if !prepared_states.is_empty()
                    && batch_cost.saturating_add(prepared_cost) > burst_byte_cap
                {
                    self.rollback_prepared_data(prepared.state);
                    break;
                }

                batch_cost = batch_cost.saturating_add(prepared_cost);
                push_prepared_data_frame(&mut prepared_frames, &mut prepared_states, prepared);
                batch_progress = batch_progress.saturating_add(byte_progress);
                if let Some((next_part_idx, next_part_off)) = advanced_cursor {
                    batch_part_idx = next_part_idx;
                    batch_part_off = next_part_off;
                }
                done = frame_done;

                if byte_progress == 0 || done {
                    break;
                }
            }

            if prepared_states.is_empty() {
                continue;
            }

            let completion = WriteCompletion::new();
            let prepared_states = self.queue_prepared_data_batch_until(
                prepared_frames,
                prepared_states,
                || self.current_write_deadline(operation_deadline),
                || self.ensure_prepared_write_not_aborted(),
                "write",
                completion.clone(),
            )?;
            let prepared_states = self.wait_prepared_write_batch_completion(
                &completion,
                prepared_states,
                operation_deadline,
            )?;
            self.commit_prepared_data_batch(prepared_states);
            written = written.saturating_add(batch_progress);
            part_idx = batch_part_idx;
            part_off = batch_part_off;
            if batch_progress > 0 {
                record_stream_application_progress(&self.conn, Instant::now());
            }
            if done {
                return Ok(written);
            }
        }
    }

    fn acquire_write_permit(&self, operation_deadline: Option<Instant>) -> Result<WritePermit<'_>> {
        self.acquire_writer_path_permit(operation_deadline, true)
    }

    fn acquire_writer_path_permit(
        &self,
        operation_deadline: Option<Instant>,
        require_write_open: bool,
    ) -> Result<WritePermit<'_>> {
        let mut state = self.state.lock().unwrap();
        loop {
            if require_write_open {
                check_write_open(&state)?;
            } else if let Some((code, reason)) = &state.aborted {
                return Err(stream_abort_error(&state, *code, reason.clone()));
            }
            if !state.write_in_progress {
                state.write_in_progress = true;
                return Ok(WritePermit { stream: self });
            }
            let deadline = effective_deadline(state.write_deadline, operation_deadline);
            if let Some(deadline) = deadline {
                let Some(wait) = deadline.checked_duration_since(Instant::now()) else {
                    return Err(Error::timeout("write"));
                };
                let wait = wait.min(MAX_CONDVAR_TIMED_WAIT);
                let (next, _) = self.cond.wait_timeout(state, wait).unwrap();
                state = next;
            } else {
                state = self.cond.wait(state).unwrap();
            }
        }
    }

    fn current_write_deadline(&self, operation_deadline: Option<Instant>) -> Option<Instant> {
        let state = self.state.lock().unwrap();
        effective_deadline(state.write_deadline, operation_deadline)
    }

    fn register_write_completion(
        &self,
        completion: &WriteCompletion,
    ) -> WriteCompletionRegistration<'_> {
        let mut state = self.state.lock().unwrap();
        state.write_completion = Some(completion.clone());
        WriteCompletionRegistration {
            stream: self,
            completion: completion.clone(),
        }
    }

    fn wait_prepared_write_batch_completion(
        &self,
        completion: &WriteCompletion,
        prepared: Vec<PreparedDataState>,
        operation_deadline: Option<Instant>,
    ) -> Result<Vec<PreparedDataState>> {
        let _registration = self.register_write_completion(completion);
        let mut prepared = Some(prepared);
        let mut deadline_canceled = false;
        loop {
            if let Some(result) = completion.try_result() {
                return match result {
                    Ok(()) => Ok(prepared.take().expect("prepared write state already used")),
                    Err(err) => Err(err),
                };
            }

            let observed_generation = completion.generation();
            let wait = if deadline_canceled {
                WRITE_COMPLETION_IDLE_POLL
            } else {
                match self.current_write_deadline(operation_deadline) {
                    Some(deadline) => {
                        let now = Instant::now();
                        if now >= deadline {
                            if self
                                .conn
                                .write_queue
                                .cancel_tracked_write(completion)
                                .is_some()
                            {
                                let err = Error::timeout("write");
                                completion.complete_err(err.clone());
                                self.rollback_prepared_states_batch(
                                    prepared.take().expect("prepared write state already used"),
                                );
                                return Err(err);
                            }
                            deadline_canceled = true;
                            continue;
                        }
                        deadline
                            .saturating_duration_since(now)
                            .min(WRITE_COMPLETION_DEADLINE_POLL)
                    }
                    None => WRITE_COMPLETION_IDLE_POLL,
                }
            };
            completion.wait_for_change_since(observed_generation, wait);
        }
    }

    fn ensure_prepared_write_not_aborted(&self) -> Result<()> {
        {
            let conn_state = self.conn.state.lock().unwrap();
            ensure_session_not_closed(&conn_state)?;
        }
        let state = self.state.lock().unwrap();
        if let Some((code, reason)) = &state.aborted {
            return Err(stream_abort_error(&state, *code, reason.clone()));
        }
        if let Some((code, reason)) = &state.stopped_by_peer {
            return Err(Error::application(*code, reason.clone())
                .with_source(ErrorSource::Remote)
                .with_termination_kind(TerminationKind::Stopped));
        }
        if let Some((code, reason)) = &state.send_reset {
            return Err(local_reset_error(*code, reason.clone()));
        }
        Ok(())
    }

    fn ensure_graceful_stop_sending_still_pending(&self) -> Result<()> {
        {
            let conn_state = self.conn.state.lock().unwrap();
            ensure_session_not_closed(&conn_state)?;
        }
        let state = self.state.lock().unwrap();
        if let Some((code, reason)) = &state.aborted {
            return Err(stream_abort_error(&state, *code, reason.clone()));
        }
        if state.stopped_by_peer.is_none() || state.send_reset.is_some() {
            return Err(Error::write_closed());
        }
        Ok(())
    }

    fn wait_conn_write<'a>(
        &self,
        conn_state: MutexGuard<'a, ConnState>,
        operation_deadline: Option<Instant>,
    ) -> Result<MutexGuard<'a, ConnState>> {
        let deadline = self.current_write_deadline(operation_deadline);
        let Some(deadline) = deadline else {
            let blocked_started = Instant::now();
            let mut conn_state = self.conn.cond.wait(conn_state).unwrap();
            note_blocked_write_locked(&mut conn_state, blocked_started.elapsed());
            return Ok(conn_state);
        };
        let Some(wait) = deadline.checked_duration_since(Instant::now()) else {
            return Err(Error::timeout("write"));
        };
        let wait_for = wait.min(MAX_CONDVAR_TIMED_WAIT);
        let reaches_deadline = wait_for == wait;
        let blocked_started = Instant::now();
        let (mut conn_state, timed_out) =
            self.conn.cond.wait_timeout(conn_state, wait_for).unwrap();
        note_blocked_write_locked(&mut conn_state, blocked_started.elapsed());
        if timed_out.timed_out() && reaches_deadline {
            return Err(Error::timeout("write"));
        }
        Ok(conn_state)
    }

    fn replenish_released_receive(
        &self,
        released: u64,
        released_retained_bytes: usize,
        replenish_stream: bool,
    ) {
        if released == 0 && released_retained_bytes == 0 {
            return;
        }
        {
            let mut conn_state = self.conn.state.lock().unwrap();
            release_session_receive_buffered_locked(
                &mut conn_state,
                released,
                released_retained_bytes,
            );
            conn_state.recv_session_pending =
                conn_state.recv_session_pending.saturating_add(released);
            let payload = negotiated_frame_payload(
                &self.conn.local_preface.settings,
                &self.conn.peer_preface.settings,
            );
            let session_target = session_window_target(
                &self.conn.local_preface.settings,
                self.conn.session_data_high_watermark,
            );
            let session_memory_pressure_high =
                session_memory_pressure_high_fast_locked(&self.conn, &conn_state);
            if should_flush_receive_credit(
                conn_state.recv_session_advertised,
                conn_state.recv_session_used,
                conn_state.recv_session_pending,
                session_target,
                session_emergency_threshold(payload),
                replenish_min_pending(session_target, payload),
                false,
            ) {
                let session_limit = next_credit_limit(
                    conn_state.recv_session_advertised,
                    conn_state.recv_session_pending,
                    conn_state.recv_session_used,
                    session_target,
                    session_standing_growth_allowed(
                        session_memory_pressure_high,
                        conn_state.recv_session_buffered,
                        conn_state.recv_session_pending,
                        self.conn.session_data_high_watermark,
                    ),
                );
                if let Some(frame) = max_data_frame(0, session_limit) {
                    if try_queue_bounded_control(&self.conn, frame) {
                        conn_state.recv_session_advertised = session_limit;
                        conn_state.recv_session_pending = 0;
                    } else {
                        conn_state.recv_replenish_retry = true;
                    }
                }
            }

            if replenish_stream {
                let stream_id = self.id();
                let mut stream_state = self.state.lock().unwrap();
                if self.local_recv
                    && !stream_state.read_stopped
                    && stream_state.recv_reset.is_none()
                    && stream_state.aborted.is_none()
                    && !stream_state.recv_fin
                {
                    stream_state.recv_pending = stream_state.recv_pending.saturating_add(released);
                    let initial = initial_receive_window(
                        self.conn.negotiated.local_role,
                        &self.conn.local_preface.settings,
                        stream_id,
                    );
                    let target =
                        stream_window_target(initial, self.conn.per_stream_data_high_watermark);
                    if should_flush_receive_credit(
                        stream_state.recv_advertised,
                        stream_state.recv_used,
                        stream_state.recv_pending,
                        target,
                        stream_emergency_threshold(target, payload),
                        replenish_min_pending(target, payload),
                        false,
                    ) {
                        let stream_limit = next_credit_limit(
                            stream_state.recv_advertised,
                            stream_state.recv_pending,
                            stream_state.recv_used,
                            target,
                            stream_standing_growth_allowed(
                                session_memory_pressure_high,
                                usize_to_u64_saturating(stream_state.recv_buf.len()),
                                stream_state.recv_pending,
                                self.conn.per_stream_data_high_watermark,
                            ),
                        );
                        if let Some(frame) = max_data_frame(stream_id, stream_limit) {
                            if try_queue_bounded_control(&self.conn, frame) {
                                stream_state.recv_advertised = stream_limit;
                                stream_state.recv_pending = 0;
                            } else {
                                conn_state.recv_replenish_retry = true;
                            }
                        }
                    }
                }
            }
        }
        self.conn.wake_writer_queue_waiters();
    }

    fn queue_blocked_signals(&self, session_blocked: Option<u64>, stream_blocked: Option<u64>) {
        if let Some(offset) = session_blocked {
            let should_queue = {
                let conn_state = self.conn.state.lock().unwrap();
                conn_state.send_session_blocked_at != Some(offset)
            };
            if should_queue
                && blocked_frame(0, offset)
                    .is_some_and(|frame| try_queue_bounded_control(&self.conn, frame))
            {
                let mut conn_state = self.conn.state.lock().unwrap();
                conn_state.send_session_blocked_at = Some(offset);
            }
        }
        if let Some(offset) = stream_blocked {
            let should_queue = {
                let stream_state = self.state.lock().unwrap();
                stream_state.send_blocked_at != Some(offset)
            };
            if should_queue
                && blocked_frame(self.id(), offset)
                    .is_some_and(|frame| try_queue_bounded_control(&self.conn, frame))
            {
                let mut stream_state = self.state.lock().unwrap();
                stream_state.send_blocked_at = Some(offset);
            }
        }
    }

    fn compact_if_possible(&self) {
        let mut conn_state = self.conn.state.lock().unwrap();
        let mut stream_state = self.state.lock().unwrap();
        maybe_compact_stream_locked(&mut conn_state, self, &mut stream_state);
    }

    fn prepare_data_frame_locked(
        &self,
        conn_state: &mut ConnState,
        stream_state: &mut StreamState,
        app_data: &[u8],
        fin: bool,
    ) -> Result<PreparedDataFrame> {
        let mut prepared = self.prepare_data_frame_header_locked(
            conn_state,
            stream_state,
            app_data.len(),
            fin,
            true,
        )?;
        prepared.frame.payload.extend_from_slice(app_data);
        Ok(prepared)
    }

    fn prepare_data_frame_header_locked(
        &self,
        conn_state: &mut ConnState,
        stream_state: &mut StreamState,
        app_len: usize,
        fin: bool,
        reserve_app_payload: bool,
    ) -> Result<PreparedDataFrame> {
        let stream_id = self.id();
        if stream_id == 0 {
            return Err(Error::local("zmux: local stream is not committed"));
        }
        let opened_on_wire_before = stream_state.opened_on_wire;
        let send_fin_before = stream_state.send_fin;
        let send_used_before = stream_state.send_used;
        let send_session_used_delta = usize_to_u64_saturating(app_len);
        let mut priority_update = PreparedPriorityUpdate::None;
        let mut flags = 0;
        let local_phase = local_open_phase(self.opened_locally, stream_state);
        let prefix_len = if stream_state.opened_on_wire {
            0
        } else {
            stream_state.open_prefix.len()
        };
        let payload_len = prefix_len
            .checked_add(app_len)
            .ok_or_else(|| Error::frame_size("DATA payload too large"))?;
        let payload_capacity = if reserve_app_payload || prefix_len != 0 {
            payload_len
        } else {
            prefix_len
        };
        let mut payload = Vec::new();
        if payload_capacity != 0 {
            payload
                .try_reserve_exact(payload_capacity)
                .map_err(|_| Error::local("zmux: DATA payload allocation failed"))?;
        }
        if !stream_state.opened_on_wire {
            if !stream_state.open_prefix.is_empty() {
                flags |= FRAME_FLAG_OPEN_METADATA;
                payload.extend_from_slice(&stream_state.open_prefix);
            }
            stream_state.opened_on_wire = true;
            if let Some(priority) = stream_state.pending_priority_update.take() {
                if local_phase.pending_priority_can_precede_data() {
                    priority_update = PreparedPriorityUpdate::BeforeData(priority);
                } else if fin {
                    priority_update = PreparedPriorityUpdate::Dropped(priority);
                } else {
                    priority_update = PreparedPriorityUpdate::AfterData(priority);
                }
            }
        } else if fin && local_phase.pending_priority_can_precede_data() {
            if let Some(priority) = stream_state.pending_priority_update.take() {
                priority_update = PreparedPriorityUpdate::BeforeData(priority);
            }
        } else if fin {
            if let Some(priority) = stream_state.pending_priority_update.take() {
                priority_update = PreparedPriorityUpdate::Dropped(priority);
            }
        }
        if fin {
            flags |= FRAME_FLAG_FIN;
            stream_state.send_fin = true;
        }
        stream_state.send_used = stream_state
            .send_used
            .saturating_add(send_session_used_delta);
        conn_state.send_session_used = conn_state
            .send_session_used
            .saturating_add(send_session_used_delta);
        if app_len > 0 {
            stream_state.send_blocked_at = None;
            conn_state.send_session_blocked_at = None;
        }
        stream_state.pending_data_frames = stream_state.pending_data_frames.saturating_add(1);
        Ok(PreparedDataFrame {
            frame: Frame {
                frame_type: FrameType::Data,
                flags,
                stream_id,
                payload,
            },
            state: PreparedDataState {
                opened_on_wire_before,
                send_fin_before,
                send_used_before,
                send_session_used_delta,
                releases_active_on_commit: fin,
                priority_update,
            },
        })
    }

    fn rollback_prepared_data(&self, prepared: PreparedDataState) {
        let mut conn_state = self.conn.state.lock().unwrap();
        let mut stream_state = self.state.lock().unwrap();
        stream_state.opened_on_wire = prepared.opened_on_wire_before;
        stream_state.send_fin = prepared.send_fin_before;
        stream_state.send_used = prepared.send_used_before;
        stream_state.pending_data_frames = stream_state.pending_data_frames.saturating_sub(1);
        if let Some(priority) = prepared.priority_update.into_restore_payload() {
            stream_state.pending_priority_update.get_or_insert(priority);
        }
        conn_state.send_session_used = conn_state
            .send_session_used
            .saturating_sub(prepared.send_session_used_delta);
        drop(stream_state);
        drop(conn_state);
        self.conn.cond.notify_all();
        self.cond.notify_all();
    }

    fn rollback_prepared_states_batch(&self, states: Vec<PreparedDataState>) {
        for state in states.into_iter().rev() {
            self.rollback_prepared_data(state);
        }
    }

    fn commit_prepared_data(&self, prepared: PreparedDataState) {
        let mut conn_state = self.conn.state.lock().unwrap();
        let mut stream_state = self.state.lock().unwrap();
        if prepared.priority_update.dropped() {
            conn_state.dropped_local_priority_update_count = conn_state
                .dropped_local_priority_update_count
                .saturating_add(1);
        }
        if prepared.releases_active_on_commit {
            maybe_release_active_count(&mut conn_state, self, &mut stream_state);
        }
        drop(stream_state);
        drop(conn_state);
        self.conn.cond.notify_all();
        self.cond.notify_all();
    }

    fn commit_prepared_data_batch(&self, states: Vec<PreparedDataState>) {
        if states.is_empty() {
            return;
        }
        let mut releases_active = false;
        let mut dropped_priority_updates = 0usize;
        for prepared in &states {
            releases_active |= prepared.releases_active_on_commit;
            if prepared.priority_update.dropped() {
                dropped_priority_updates = dropped_priority_updates.saturating_add(1);
            }
        }
        let mut conn_state = self.conn.state.lock().unwrap();
        let mut stream_state = self.state.lock().unwrap();
        if dropped_priority_updates != 0 {
            conn_state.dropped_local_priority_update_count = conn_state
                .dropped_local_priority_update_count
                .saturating_add(usize_to_u64_saturating(dropped_priority_updates));
        }
        if releases_active {
            maybe_release_active_count(&mut conn_state, self, &mut stream_state);
        }
        drop(stream_state);
        drop(conn_state);
        self.conn.cond.notify_all();
        self.cond.notify_all();
    }

    fn write_burst_frame_limit_for_priority(&self, priority: u64) -> usize {
        u64_to_usize_saturating(u64::from(write_burst_limit(
            priority,
            self.conn.peer_preface.settings.scheduler_hints,
        )))
        .max(1)
        .min(self.conn.write_queue.max_batch_frames().max(1))
    }

    fn queue_prepared_data_until<D, C>(
        &self,
        prepared: PreparedDataFrame,
        deadline: D,
        check: C,
        operation: &str,
        completion: Option<WriteCompletion>,
    ) -> Result<PreparedDataState>
    where
        D: FnMut() -> Option<Instant>,
        C: FnMut() -> Result<()>,
    {
        let PreparedDataFrame { frame, state } = prepared;
        let stream_id = frame.stream_id;
        let queued = match completion {
            Some(completion) => self.conn.queue_tracked_frames_until(
                prepared_data_frames(stream_id, frame, &state.priority_update),
                completion,
                deadline,
                check,
                operation,
            ),
            None => match &state.priority_update {
                PreparedPriorityUpdate::BeforeData(payload) => self.conn.queue_frames_until(
                    vec![prepared_priority_frame(stream_id, payload), frame],
                    deadline,
                    check,
                    operation,
                ),
                PreparedPriorityUpdate::AfterData(payload) => self.conn.queue_frames_until(
                    vec![frame, prepared_priority_frame(stream_id, payload)],
                    deadline,
                    check,
                    operation,
                ),
                PreparedPriorityUpdate::None | PreparedPriorityUpdate::Dropped(_) => self
                    .conn
                    .queue_frame_until(frame, deadline, check, operation),
            },
        };
        match queued {
            Ok(()) => Ok(state),
            Err(err) => {
                self.rollback_prepared_data(state);
                Err(err)
            }
        }
    }

    fn queue_prepared_data_batch_until<D, C>(
        &self,
        frames: Vec<Frame>,
        states: Vec<PreparedDataState>,
        deadline: D,
        check: C,
        operation: &str,
        completion: WriteCompletion,
    ) -> Result<Vec<PreparedDataState>>
    where
        D: FnMut() -> Option<Instant>,
        C: FnMut() -> Result<()>,
    {
        if frames.is_empty() {
            completion.complete_ok();
            return Ok(Vec::new());
        }
        match self
            .conn
            .queue_tracked_frames_until(frames, completion, deadline, check, operation)
        {
            Ok(()) => Ok(states),
            Err(err) => {
                self.rollback_prepared_states_batch(states);
                Err(err)
            }
        }
    }

    fn close_write(&self) -> Result<()> {
        {
            let conn_state = self.conn.state.lock().unwrap();
            ensure_session_not_closed(&conn_state)?;
            let stream_state = self.state.lock().unwrap();
            if close_write_noop_after_stop_reset(&stream_state) {
                return Ok(());
            }
            if stream_state.send_fin {
                return Err(Error::write_closed().with_termination_kind(TerminationKind::Graceful));
            }
        }
        match self.write(&[], true) {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn close(&self) -> Result<()> {
        let (needs_close_write, needs_close_read) = {
            let conn_state = self.conn.state.lock().unwrap();
            ensure_session_not_closed(&conn_state)?;
            let stream_state = self.state.lock().unwrap();
            let send_terminal = stream_state.aborted.is_some()
                || stream_state.send_fin
                || stream_state.send_reset.is_some();
            let recv_terminal = stream_state.aborted.is_some()
                || stream_state.recv_fin
                || stream_state.recv_reset.is_some();
            (
                self.local_send && !send_terminal,
                self.local_recv && !recv_terminal && !stream_state.read_stopped,
            )
        };

        let mut first_err = None;
        if needs_close_write {
            if let Err(err) = self.close_write() {
                let write_timed_out = err.is_timeout();
                if !close_write_error_ignored(&err) {
                    first_err = Some(err);
                }
                if write_timed_out {
                    if let Err(cancel_err) =
                        StreamInner::cancel_write(self, ErrorCode::Cancelled.as_u64(), "")
                    {
                        if !close_write_error_ignored(&cancel_err)
                            && !cancel_err.is_session_closed()
                            && first_err.is_none()
                        {
                            first_err = Some(cancel_err);
                        }
                    }
                }
            }
        }
        if needs_close_read {
            if let Err(err) = StreamInner::close_read(self, ErrorCode::Cancelled.as_u64()) {
                if !close_read_error_ignored(&err) && first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
        match first_err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn close_read(&self, code: u64) -> Result<()> {
        if !self.local_recv {
            return Ok(());
        }
        let stop_payload = build_code_payload(
            code,
            "",
            self.conn.peer_preface.settings.max_control_payload_bytes,
        )?;
        let mut opener_permit = None;
        loop {
            let prepared_opener;
            let released_recv_bytes;
            let released_recv_retained_bytes;
            let mut conn_state = self.conn.state.lock().unwrap();
            ensure_session_not_closed(&conn_state)?;
            let mut stream_state = self.state.lock().unwrap();
            if stream_state.read_stopped && stream_state.read_stop_pending_code.is_none() {
                return Err(Error::read_closed());
            }
            if !stream_state.read_stopped && stream_state.recv_fin {
                return Err(Error::read_closed()
                    .with_source(ErrorSource::Remote)
                    .with_termination_kind(TerminationKind::Graceful));
            }
            if !stream_state.read_stopped {
                if let Some((code, reason)) = &stream_state.recv_reset {
                    return Err(peer_reset_error(*code, reason.clone()));
                }
                if let Some((code, reason)) = &stream_state.aborted {
                    return Err(stream_abort_error(&stream_state, *code, reason.clone()));
                }
            }
            if self.opened_locally && !stream_state.opened_on_wire {
                if opener_permit.is_none() {
                    if stream_state.write_in_progress {
                        drop(conn_state);
                        let state = self.cond.wait(stream_state).unwrap();
                        drop(state);
                        continue;
                    }
                    stream_state.write_in_progress = true;
                    opener_permit = Some(WritePermit { stream: self });
                }
                if self.ensure_local_open_committed_locked(&mut conn_state, &mut stream_state)?
                    == LocalCommitStatus::AwaitingTurn
                {
                    drop(stream_state);
                    conn_state = self.wait_conn_write(conn_state, None)?;
                    drop(conn_state);
                    continue;
                }
                prepared_opener = Some(self.prepare_data_frame_locked(
                    &mut conn_state,
                    &mut stream_state,
                    &[],
                    false,
                )?);
            } else {
                prepared_opener = None;
            }
            if !stream_state.read_stopped {
                stream_state.read_stopped = true;
                stream_state.read_stop_pending_code = Some(code);
                clear_accept_backlog_entry_locked(&mut conn_state, &mut stream_state);
                let released = stream_state.recv_buf.clear_detailed();
                clear_stream_receive_credit_locked(&self.conn, self, &mut stream_state);
                released_recv_bytes = released.bytes;
                released_recv_retained_bytes = released.released_retained_bytes;
                maybe_release_active_count(&mut conn_state, self, &mut stream_state);
            } else {
                released_recv_bytes = 0;
                released_recv_retained_bytes = 0;
            }
            let pending_code = stream_state.read_stop_pending_code.unwrap_or(code);
            let stream_id = self.id();
            let stop_frame = Frame {
                frame_type: FrameType::StopSending,
                flags: 0,
                stream_id,
                payload: if pending_code == code {
                    stop_payload.clone()
                } else {
                    build_code_payload(
                        pending_code,
                        "",
                        self.conn.peer_preface.settings.max_control_payload_bytes,
                    )?
                },
            };
            drop(stream_state);
            drop(conn_state);

            self.replenish_released_receive(
                usize_to_u64_saturating(released_recv_bytes),
                released_recv_retained_bytes,
                false,
            );

            if let Some(prepared) = prepared_opener {
                let prepared_state = self.queue_prepared_data_until(
                    prepared,
                    || self.current_write_deadline(None),
                    || self.ensure_close_read_signal_pending(),
                    "write",
                    None,
                );
                let prepared_state = match prepared_state {
                    Ok(prepared_state) => prepared_state,
                    Err(err) => {
                        self.cond.notify_all();
                        return Err(err);
                    }
                };
                self.commit_prepared_data(prepared_state);
            }

            self.note_pending_terminal_frame();
            let queued = self.conn.queue_frame_until(
                stop_frame,
                || self.current_write_deadline(None),
                || self.ensure_close_read_signal_pending(),
                "write",
            );
            if let Err(err) = queued {
                self.rollback_pending_terminal_frame();
                self.cond.notify_all();
                return Err(err);
            }
            self.clear_close_read_signal_pending();
            self.cond.notify_all();
            return Ok(());
        }
    }

    fn ensure_close_read_signal_pending(&self) -> Result<()> {
        let conn_state = self.conn.state.lock().unwrap();
        ensure_session_not_closed(&conn_state)?;
        let state = self.state.lock().unwrap();
        if let Some((code, reason)) = &state.aborted {
            return Err(stream_abort_error(&state, *code, reason.clone()));
        }
        if state.read_stop_pending_code.is_some() {
            Ok(())
        } else {
            Err(Error::read_closed())
        }
    }

    fn clear_close_read_signal_pending(&self) {
        let mut conn_state = self.conn.state.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        state.read_stop_pending_code = None;
        maybe_compact_stream_locked(&mut conn_state, self, &mut state);
    }

    fn note_pending_terminal_frame(&self) {
        let mut state = self.state.lock().unwrap();
        state.pending_terminal_frames = state.pending_terminal_frames.saturating_add(1);
    }

    fn rollback_pending_terminal_frame(&self) {
        let mut conn_state = self.conn.state.lock().unwrap();
        note_written_stream_frames_locked(&mut conn_state, self.id(), 0, 1);
    }

    fn apply_discarded_queued_frames(&self, stats: StreamDiscardStats, count_superseded: bool) {
        if stats.removed_frames == 0 {
            return;
        }
        let stream_id = self.id();
        let mut conn_state = self.conn.state.lock().unwrap();
        if count_superseded && stats.terminal_frames != 0 {
            conn_state.superseded_terminal_signal_count = conn_state
                .superseded_terminal_signal_count
                .saturating_add(usize_to_u64_saturating(stats.terminal_frames));
        }
        if let Some(stream) = conn_state.streams.get(&stream_id).cloned() {
            release_discarded_queued_stream_frames_locked(&mut conn_state, &stream, stats);
        }
        self.conn.cond.notify_all();
    }

    fn cancel_write(&self, code: u64, reason: &str) -> Result<()> {
        if !self.local_send {
            return Err(Error::local("zmux: stream is not writable"));
        }
        let payload = build_code_payload(
            code,
            reason,
            self.conn.peer_preface.settings.max_control_payload_bytes,
        )?;
        let frame_type;
        let stream_id;
        {
            let mut conn_state = self.conn.state.lock().unwrap();
            ensure_session_not_closed(&conn_state)?;
            let mut stream_state = self.state.lock().unwrap();
            check_write_open(&stream_state)?;
            if self.is_local_uncommitted() {
                let (released, released_retained_bytes) = self.fail_uncommitted_local_abort_locked(
                    &mut conn_state,
                    &mut stream_state,
                    code,
                    reason,
                );
                drop(stream_state);
                drop(conn_state);
                self.replenish_released_receive(released, released_retained_bytes, false);
                self.cond.notify_all();
                return Ok(());
            }
            stream_id = self.id();
            frame_type = if self.opened_locally && !stream_state.opened_on_wire {
                note_abort_reason_locked(&mut conn_state, code);
                stream_state.aborted = Some((code, reason.to_owned()));
                stream_state.abort_source = ErrorSource::Local;
                stream_state.opened_on_wire = true;
                FrameType::Abort
            } else {
                note_reset_reason_locked(&mut conn_state, code);
                stream_state.send_reset = Some((code, reason.to_owned()));
                stream_state.send_reset_from_stop = false;
                FrameType::Reset
            };
            stream_state.pending_priority_update = None;
            stream_state.pending_terminal_frames =
                stream_state.pending_terminal_frames.saturating_add(1);
            maybe_release_active_count(&mut conn_state, self, &mut stream_state);
        }
        let discarded = self.conn.write_queue.discard_stream_send_tail(stream_id);
        self.apply_discarded_queued_frames(discarded, false);
        self.conn.write_queue.discard_priority_update(stream_id);
        if let Err(err) = self.conn.queue_frame(Frame {
            frame_type,
            flags: 0,
            stream_id,
            payload,
        }) {
            self.rollback_pending_terminal_frame();
            return Err(err);
        }
        self.cond.notify_all();
        Ok(())
    }

    fn abort(&self, code: u64, reason: &str) -> Result<()> {
        let payload = build_code_payload(
            code,
            reason,
            self.conn.peer_preface.settings.max_control_payload_bytes,
        )?;
        let stream_id;
        {
            let mut conn_state = self.conn.state.lock().unwrap();
            ensure_session_not_closed(&conn_state)?;
            let mut stream_state = self.state.lock().unwrap();
            if stream_state.aborted.is_some() {
                return Ok(());
            }
            if self.is_local_uncommitted() {
                let (released, released_retained_bytes) = self.fail_uncommitted_local_abort_locked(
                    &mut conn_state,
                    &mut stream_state,
                    code,
                    reason,
                );
                drop(stream_state);
                drop(conn_state);
                self.replenish_released_receive(released, released_retained_bytes, false);
                self.cond.notify_all();
                return Ok(());
            }
            stream_id = self.id();
            note_abort_reason_locked(&mut conn_state, code);
            stream_state.aborted = Some((code, reason.to_owned()));
            stream_state.abort_source = ErrorSource::Local;
            let released = stream_state.recv_buf.clear_detailed();
            clear_stream_receive_credit_locked(&self.conn, self, &mut stream_state);
            stream_state.opened_on_wire = true;
            stream_state.pending_terminal_frames =
                stream_state.pending_terminal_frames.saturating_add(1);
            maybe_release_active_count(&mut conn_state, self, &mut stream_state);
            drop(stream_state);
            drop(conn_state);
            self.replenish_released_receive(
                usize_to_u64_saturating(released.bytes),
                released.released_retained_bytes,
                false,
            );
        }
        let discarded = self.conn.write_queue.discard_stream(stream_id);
        self.apply_discarded_queued_frames(discarded, true);
        if let Err(err) = self.conn.queue_frame(Frame {
            frame_type: FrameType::Abort,
            flags: 0,
            stream_id,
            payload,
        }) {
            self.rollback_pending_terminal_frame();
            return Err(err);
        }
        self.cond.notify_all();
        Ok(())
    }

    fn ensure_metadata_update_still_allowed(&self) -> Result<()> {
        let conn_state = self.conn.state.lock().unwrap();
        ensure_session_not_closed(&conn_state)?;
        let state = self.state.lock().unwrap();
        check_write_open(&state)
    }

    fn update_metadata(&self, update: MetadataUpdate) -> Result<()> {
        if !self.local_send {
            return Err(Error::local("zmux: stream is not writable"));
        }
        if update.priority.is_none() && update.group.is_none() {
            return Err(Error::local("zmux: metadata update has no fields"));
        }
        let _permit = self.acquire_writer_path_permit(None, true)?;
        let caps = self.conn.negotiated.capabilities;
        let peer_settings = self.conn.peer_preface.settings;
        let (stream_id, queued_payload, queued_revision, next_metadata, metadata_changed) = {
            let conn_state = self.conn.state.lock().unwrap();
            ensure_session_not_closed(&conn_state)?;
            let mut state = self.state.lock().unwrap();
            check_write_open(&state)?;
            if write_deadline_expired(&state, None) {
                return Err(Error::timeout("write"));
            }

            let mut next = state.metadata.clone();
            let mut wire_update = MetadataUpdate::default();
            if let Some(priority) = update.priority {
                next.priority = Some(priority);
                wire_update.priority = Some(priority);
            }
            if let Some(group) = update.group {
                next.group = normalize_stream_group(Some(group));
                wire_update.group = Some(group);
            }
            let metadata_changed = next != state.metadata;
            let next_open_initial_group = if update.group.is_some() {
                update.group
            } else {
                state.open_initial_group
            };
            let local_phase = local_open_phase(self.opened_locally, &state);
            let stream_id = self.id();
            let needs_local_opener = self.opened_locally && stream_id == 0;
            let can_carry_on_open = metadata_update_can_carry_on_open(caps, &wire_update);
            if needs_local_opener {
                validate_open_metadata_update_capability(caps, &wire_update)?;
                rebuild_open_metadata_prefix_locked(
                    &mut state,
                    caps,
                    next.priority,
                    next_open_initial_group,
                    peer_settings.max_frame_payload,
                )?;
                if metadata_changed {
                    state.metadata = next;
                    state.metadata_revision = state.metadata_revision.wrapping_add(1);
                }
                state.open_initial_group = next_open_initial_group;
                return Ok(());
            }

            let should_emit_opener = local_phase.should_emit_opener_frame();
            if should_emit_opener && can_carry_on_open {
                validate_open_metadata_update_capability(caps, &wire_update)?;
                rebuild_open_metadata_prefix_locked(
                    &mut state,
                    caps,
                    next.priority,
                    next_open_initial_group,
                    peer_settings.max_frame_payload,
                )?;
                if metadata_changed {
                    state.metadata = next;
                    state.metadata_revision = state.metadata_revision.wrapping_add(1);
                }
                state.open_initial_group = next_open_initial_group;
                return Ok(());
            }

            let (merged_update, payload_len) = merged_priority_update_payload_len(
                caps,
                wire_update,
                state.pending_priority_update.as_deref(),
                peer_settings.max_extension_payload_bytes,
            )?;
            if should_emit_opener {
                ensure_pending_priority_update_limits_locked(
                    &self.conn,
                    &conn_state,
                    stream_id,
                    &state,
                    payload_len,
                    "write",
                )?;
                let payload = build_priority_update_payload_reusing_pending(
                    caps,
                    merged_update,
                    &mut state.pending_priority_update,
                    peer_settings.max_extension_payload_bytes,
                )?;
                state.pending_priority_update = Some(payload);
                if metadata_changed {
                    state.metadata = next;
                    state.metadata_revision = state.metadata_revision.wrapping_add(1);
                }
                return Ok(());
            }
            if !local_phase.can_take_pending_priority_update() {
                ensure_pending_priority_update_limits_locked(
                    &self.conn,
                    &conn_state,
                    stream_id,
                    &state,
                    payload_len,
                    "write",
                )?;
                let payload = build_priority_update_payload_reusing_pending(
                    caps,
                    merged_update,
                    &mut state.pending_priority_update,
                    peer_settings.max_extension_payload_bytes,
                )?;
                state.pending_priority_update = Some(payload);
                if metadata_changed {
                    state.metadata = next;
                    state.metadata_revision = state.metadata_revision.wrapping_add(1);
                }
                return Ok(());
            }
            let payload = build_priority_update_payload(
                caps,
                merged_update,
                peer_settings.max_extension_payload_bytes,
            )?;
            if metadata_changed {
                state.metadata_revision = state.metadata_revision.wrapping_add(1);
            }
            (
                stream_id,
                payload,
                state.metadata_revision,
                next,
                metadata_changed,
            )
        };
        let queued = self.conn.queue_frame_until(
            Frame {
                frame_type: FrameType::Ext,
                flags: 0,
                stream_id,
                payload: queued_payload,
            },
            || self.current_write_deadline(None),
            || self.ensure_metadata_update_still_allowed(),
            "write",
        );
        let mut state = self.state.lock().unwrap();
        match queued {
            Ok(()) => {
                if metadata_changed && state.metadata_revision == queued_revision {
                    state.metadata = next_metadata;
                }
                Ok(())
            }
            Err(err) => {
                if metadata_changed && state.metadata_revision == queued_revision {
                    state.metadata_revision = state.metadata_revision.wrapping_sub(1);
                }
                drop(state);
                let mut conn_state = self.conn.state.lock().unwrap();
                conn_state.dropped_local_priority_update_count = conn_state
                    .dropped_local_priority_update_count
                    .saturating_add(1);
                Err(err)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_stream_deadline_is_treated_as_unbounded() {
        assert!(deadline_after(Duration::MAX).is_none());
    }

    #[test]
    fn effective_deadline_uses_earliest_bounded_deadline() {
        let base = Instant::now();
        let soon = base.checked_add(Duration::from_millis(1)).unwrap();
        let later = base.checked_add(Duration::from_secs(1)).unwrap();

        assert_eq!(effective_deadline(None, None), None);
        assert_eq!(effective_deadline(Some(later), None), Some(later));
        assert_eq!(effective_deadline(None, Some(soon)), Some(soon));
        assert_eq!(effective_deadline(Some(later), Some(soon)), Some(soon));
        assert_eq!(effective_deadline(Some(soon), Some(later)), Some(soon));
    }

    #[test]
    fn fragment_policy_matches_priority_latency_and_metadata_prefix_caps() {
        assert_eq!(
            fragment_cap(16_384, 0, 2, SchedulerHint::UnspecifiedOrBalanced),
            12_288
        );
        assert_eq!(
            fragment_cap(16_384, 0, 6, SchedulerHint::UnspecifiedOrBalanced),
            8_192
        );
        assert_eq!(
            fragment_cap(16_384, 0, 20, SchedulerHint::UnspecifiedOrBalanced),
            4_096
        );
        assert_eq!(fragment_cap(16_384, 0, 0, SchedulerHint::Latency), 8_192);

        let prefix_len = 11;
        assert_eq!(
            fragment_cap(16_384, prefix_len, 20, SchedulerHint::UnspecifiedOrBalanced,),
            scaled_fragment_cap(16_384 - prefix_len, 1, 4)
        );
        assert_eq!(
            fragment_cap(16_384, 16_384, 20, SchedulerHint::UnspecifiedOrBalanced),
            0
        );
    }

    #[test]
    fn fragment_rate_limit_and_scaling_use_wide_arithmetic() {
        assert_eq!(
            rate_limited_fragment_cap(16_384, 1_000, 0, SchedulerHint::UnspecifiedOrBalanced),
            200
        );
        assert_eq!(
            rate_limited_fragment_cap(
                1_000_000_000_000,
                50_000_000_000_000,
                0,
                SchedulerHint::UnspecifiedOrBalanced,
            ),
            1_000_000_000_000
        );
        assert_eq!(
            rate_limited_fragment_cap(4_096, 1 << 20, 20, SchedulerHint::UnspecifiedOrBalanced,),
            4_096
        );
        assert_eq!(
            scaled_fragment_cap(MAX_VARINT62, 3, 4),
            3_458_764_513_820_540_927
        );
    }

    #[test]
    fn vectored_write_total_len_rejects_usize_overflow_as_frame_size() {
        let err = checked_io_slice_total_len([usize::MAX, 1]).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::FrameSize));
        assert!(err.to_string().contains("DATA payload too large"));
    }

    #[test]
    fn owned_write_payload_moves_full_frame_without_copy() {
        let payload = b"owned write payload".to_vec();
        let ptr = payload.as_ptr();
        let len = payload.len();
        let mut source = WriteBytes::owned(payload);
        let mut frame_payload = Vec::new();

        source.append_range_to(&mut frame_payload, 0, len).unwrap();

        assert_eq!(frame_payload.as_ptr(), ptr);
        assert_eq!(frame_payload, b"owned write payload");
    }

    #[test]
    fn owned_write_payload_copies_when_frame_has_metadata_prefix() {
        let payload = b"owned write payload".to_vec();
        let ptr = payload.as_ptr();
        let len = payload.len();
        let mut source = WriteBytes::owned(payload);
        let mut frame_payload = b"prefix".to_vec();

        source.append_range_to(&mut frame_payload, 0, len).unwrap();

        assert_ne!(frame_payload.as_ptr(), ptr);
        assert_eq!(frame_payload, b"prefixowned write payload");
    }

    #[test]
    fn stop_sending_drain_window_uses_override_or_adaptive_rtt() {
        assert_eq!(
            stop_sending_drain_window(None, None),
            DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW
        );
        assert_eq!(
            stop_sending_drain_window(Some(Duration::from_millis(250)), None),
            Duration::from_millis(250)
        );
        assert_eq!(
            stop_sending_drain_window(None, Some(Duration::from_millis(800))),
            Duration::from_millis(1600)
        );
        assert_eq!(
            stop_sending_drain_window(None, Some(Duration::from_millis(1))),
            DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW
        );
        assert_eq!(
            stop_sending_drain_window(None, Some(Duration::MAX)),
            DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW_MAX
        );
    }

    #[test]
    fn local_open_phase_predicates_follow_visibility_transitions() {
        let needs_commit = LocalOpenPhase::from_flags(true, false, false, false);
        assert_eq!(needs_commit, LocalOpenPhase::NeedsCommit);
        assert!(needs_commit.needs_local_opener());
        assert!(needs_commit.awaiting_peer_visibility());
        assert!(needs_commit.should_emit_opener_frame());
        assert!(needs_commit.should_mark_peer_visible());
        assert!(!needs_commit.can_take_pending_priority_update());

        let needs_emit = LocalOpenPhase::from_flags(true, true, false, false);
        assert_eq!(needs_emit, LocalOpenPhase::NeedsEmit);
        assert!(!needs_emit.needs_local_opener());
        assert!(needs_emit.awaiting_peer_visibility());
        assert!(needs_emit.should_emit_opener_frame());

        let queued = LocalOpenPhase::from_flags(true, true, false, true);
        assert_eq!(queued, LocalOpenPhase::Queued);
        assert!(queued.awaiting_peer_visibility());
        assert!(!queued.should_emit_opener_frame());
        assert!(!queued.can_take_pending_priority_update());

        let peer_visible = LocalOpenPhase::from_flags(true, true, true, true);
        assert_eq!(peer_visible, LocalOpenPhase::PeerVisible);
        assert!(!peer_visible.awaiting_peer_visibility());
        assert!(!peer_visible.should_mark_peer_visible());
        assert!(peer_visible.can_take_pending_priority_update());
        assert!(peer_visible.should_queue_stream_blocked(0));

        assert_eq!(
            LocalOpenPhase::from_flags(false, false, false, false),
            LocalOpenPhase::None
        );
    }
}
