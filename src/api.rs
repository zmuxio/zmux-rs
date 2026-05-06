use crate::error::{Error, ErrorDirection, ErrorOperation, Result};
use crate::open_send::{OpenRequest, OpenSend, WritePayload};
use crate::payload::{MetadataUpdate, StreamMetadata};
use crate::preface::{Negotiated, Preface};
use crate::protocol::Role;
use crate::session::{
    Conn, PeerCloseError, PeerGoAwayError, RecvStream, SendStream, SessionState, SessionStats,
    Stream,
};
use crate::settings::{SchedulerHint, Settings};
use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem::{self, size_of_val};
use std::net::SocketAddr;
use std::ptr::{from_ref, null};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

const MAX_CONDVAR_TIMED_WAIT: Duration = Duration::from_secs(3600);
const MAX_OPEN_INFO_PREALLOC: usize = 64 * 1024;

#[inline]
fn nonzero_duration_value(value: Duration) -> Option<Duration> {
    (!value.is_zero()).then_some(value)
}

#[inline]
fn condvar_timed_wait_step(remaining: Duration) -> (Duration, bool) {
    let wait = remaining.min(MAX_CONDVAR_TIMED_WAIT);
    (wait, wait == remaining)
}

#[inline]
fn next_generation(current: u64) -> u64 {
    let next = current.wrapping_add(1);
    if next == 0 {
        1
    } else {
        next
    }
}

/// Boxed bidirectional stream trait object used by the native blocking API.
pub type BoxStream = Box<dyn DuplexStreamHandle>;

/// Boxed send-only stream trait object used by the native blocking API.
pub type BoxSendStream = Box<dyn SendStreamHandle>;

/// Boxed receive-only stream trait object used by the native blocking API.
pub type BoxRecvStream = Box<dyn RecvStreamHandle>;

/// Boxed native blocking session trait object.
pub type BoxSession = Box<dyn Session>;

pub trait StreamHandle: Send + Sync {
    fn stream_id(&self) -> u64;
    fn is_opened_locally(&self) -> bool;
    fn is_bidirectional(&self) -> bool;
    fn open_info_len(&self) -> usize;
    fn has_open_info(&self) -> bool {
        self.open_info_len() != 0
    }
    /// Append opaque binary open metadata to `dst`.
    fn append_open_info_to(&self, dst: &mut Vec<u8>);
    /// Return opaque binary open metadata.
    fn open_info(&self) -> Vec<u8> {
        let mut open_info = Vec::with_capacity(self.open_info_len().min(MAX_OPEN_INFO_PREALLOC));
        self.append_open_info_to(&mut open_info);
        open_info
    }
    fn metadata(&self) -> StreamMetadata;
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn set_deadline(&self, deadline: Option<Instant>) -> Result<()>;
    fn clear_deadline(&self) -> Result<()> {
        self.set_deadline(None)
    }
    fn set_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_deadline(timeout_to_deadline(timeout))
    }
    /// Stable resource identity used to avoid closing the same joined full
    /// stream twice.
    fn close_identity(&self) -> *const () {
        if size_of_val(self) == 0 {
            null()
        } else {
            from_ref(self).cast::<()>()
        }
    }
    fn close(&self) -> Result<()>;
    fn close_with_error(&self, code: u64, reason: &str) -> Result<()>;
}

pub trait RecvStreamHandle: StreamHandle + Read {
    fn is_read_closed(&self) -> bool;
    fn read_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<usize>;
    fn read_vectored_timeout(
        &self,
        dsts: &mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        for dst in dsts {
            if !dst.is_empty() {
                return self.read_timeout(dst, timeout);
            }
        }
        Ok(0)
    }
    fn read_exact_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<()> {
        let start = Instant::now();
        let mut remaining = dst;
        while !remaining.is_empty() {
            let timeout = remaining_read_timeout(start, timeout)?;
            let n =
                validate_read_progress(self.read_timeout(remaining, timeout)?, remaining.len())?;
            if n == 0 {
                return Err(unexpected_eof_error());
            }
            let (_, rest) = remaining.split_at_mut(n);
            remaining = rest;
        }
        Ok(())
    }
    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()>;
    fn clear_read_deadline(&self) -> Result<()> {
        self.set_read_deadline(None)
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_read_deadline(timeout_to_deadline(timeout))
    }
    fn close_read(&self) -> Result<()>;
    fn cancel_read(&self, code: u64) -> Result<()>;
}

pub trait SendStreamHandle: StreamHandle + Write {
    fn is_write_closed(&self) -> bool;
    fn update_metadata(&self, update: MetadataUpdate) -> Result<()>;
    fn write_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize>;
    fn write_all_timeout(&self, src: &[u8], timeout: Duration) -> Result<()> {
        let start = Instant::now();
        let mut remaining = src;
        while !remaining.is_empty() {
            let timeout = remaining_write_timeout(start, timeout)?;
            let n =
                validate_write_progress(self.write_timeout(remaining, timeout)?, remaining.len())?;
            if n == 0 {
                return Err(zero_length_write_error());
            }
            remaining = &remaining[n..];
        }
        Ok(())
    }
    fn write_vectored(&self, parts: &[IoSlice<'_>]) -> Result<usize>;
    fn write_vectored_timeout(&self, parts: &[IoSlice<'_>], timeout: Duration) -> Result<usize>;
    fn write_final(&self, src: &[u8]) -> Result<usize>;
    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> Result<usize>;
    fn write_final_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize>;
    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize>;
    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()>;
    fn clear_write_deadline(&self) -> Result<()> {
        self.set_write_deadline(None)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<()> {
        self.set_write_deadline(timeout_to_deadline(timeout))
    }
    fn close_write(&self) -> Result<()>;
    fn cancel_write(&self, code: u64) -> Result<()>;
}

pub trait DuplexStreamHandle: RecvStreamHandle + SendStreamHandle {}

/// Which half supplies metadata for a joined bidirectional stream view.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DuplexInfoSide {
    /// Use the receive half's stream metadata.
    #[default]
    Read,
    /// Use the send half's stream metadata.
    Write,
}

/// Bidirectional stream view backed by one receive-only half and one send-only half.
pub struct DuplexStream<R, W> {
    recv: Arc<NativeJoinedHalf<R>>,
    send: Arc<NativeJoinedHalf<W>>,
    info_side: DuplexInfoSide,
}

type NativeDeadlineApplier<T> = fn(&T, Option<Instant>) -> Result<()>;

struct NativeJoinedHalf<T> {
    state: Mutex<NativeJoinedHalfState<T>>,
    changed: Condvar,
    deadline_operation: &'static str,
}

struct NativeJoinedHalfState<T> {
    current: Option<T>,
    paused: bool,
    active_ops: usize,
    closed: bool,
    deadline: Option<Instant>,
    deadline_generation: u64,
    deadline_applied_generation: u64,
    deadline_applier: Option<NativeDeadlineApplier<T>>,
}

struct ActiveNativeHalf<T> {
    owner: Arc<NativeJoinedHalf<T>>,
    current: Option<T>,
    deadline_generation: u64,
}

impl<T> ActiveNativeHalf<T> {
    fn current_mut(&mut self) -> &mut T {
        self.current
            .as_mut()
            .expect("active native half owns current until drop")
    }
}

/// Pause handle returned by native joined stream read/write half pauses.
///
/// The handle owns the detached half until `resume` reattaches it. Dropping the
/// handle resumes with the currently staged half on a best-effort basis.
pub struct PausedNativeHalf<T> {
    owner: Arc<NativeJoinedHalf<T>>,
    current: Option<T>,
    resumed: bool,
}

/// Detached receive half handle for `DuplexStream`.
pub type PausedNativeRecvHalf<R> = PausedNativeHalf<R>;

/// Detached send half handle for `DuplexStream`.
pub type PausedNativeSendHalf<W> = PausedNativeHalf<W>;

impl<T> NativeJoinedHalf<T> {
    fn new_optional(current: Option<T>, deadline_operation: &'static str) -> Self {
        Self {
            state: Mutex::new(NativeJoinedHalfState {
                current,
                paused: false,
                active_ops: 0,
                closed: false,
                deadline: None,
                deadline_generation: 0,
                deadline_applied_generation: 0,
                deadline_applier: None,
            }),
            changed: Condvar::new(),
            deadline_operation,
        }
    }

    fn with_current_or<U>(&self, default: U, visit: impl FnOnce(&T) -> U) -> U {
        let state = self.state.lock().unwrap();
        if state.closed || state.paused {
            return default;
        }
        state.current.as_ref().map_or(default, visit)
    }

    fn enter(self: &Arc<Self>, missing: impl FnOnce() -> Error) -> Result<ActiveNativeHalf<T>> {
        let mut state = self.state.lock().unwrap();
        loop {
            if state.closed {
                return Err(Error::session_closed());
            }
            if !state.paused {
                if state.active_ops != 0 {
                    state = self.changed.wait(state).unwrap();
                    continue;
                }
                let current = state.current.take().ok_or_else(missing)?;
                state.active_ops += 1;
                let deadline_generation = state.deadline_generation;
                return Ok(ActiveNativeHalf {
                    owner: Arc::clone(self),
                    current: Some(current),
                    deadline_generation,
                });
            }
            state = self.wait_while_paused(state)?;
        }
    }

    fn enter_optional(self: &Arc<Self>) -> Result<Option<ActiveNativeHalf<T>>> {
        let mut state = self.state.lock().unwrap();
        loop {
            if state.closed {
                return Err(Error::session_closed());
            }
            if !state.paused {
                if state.active_ops != 0 {
                    state = self.changed.wait(state).unwrap();
                    continue;
                }
                let Some(current) = state.current.take() else {
                    return Ok(None);
                };
                state.active_ops += 1;
                let deadline_generation = state.deadline_generation;
                return Ok(Some(ActiveNativeHalf {
                    owner: Arc::clone(self),
                    current: Some(current),
                    deadline_generation,
                }));
            }
            state = self.wait_while_paused(state)?;
        }
    }

    fn with_current_result<U>(
        self: &Arc<Self>,
        missing: impl FnOnce() -> Error,
        visit: impl FnOnce(&mut T) -> Result<U>,
    ) -> Result<U> {
        let mut active = self.enter(missing)?;
        visit(active.current_mut())
    }

    fn with_current_result_or<U>(
        self: &Arc<Self>,
        default: U,
        visit: impl FnOnce(&mut T) -> Result<U>,
    ) -> Result<U> {
        match self.enter_optional()? {
            Some(mut active) => visit(active.current_mut()),
            None => Ok(default),
        }
    }

    fn with_current_io<U>(
        self: &Arc<Self>,
        missing: impl FnOnce() -> Error,
        visit: impl FnOnce(&mut T) -> io::Result<U>,
    ) -> io::Result<U> {
        let mut active = self.enter(missing).map_err(io::Error::from)?;
        visit(active.current_mut())
    }

    fn pause(self: &Arc<Self>, timeout: Option<Duration>) -> Result<Option<T>> {
        let start = Instant::now();
        let mut owns_pause = false;
        let mut state = self.state.lock().unwrap();
        loop {
            if state.closed {
                return Err(Error::session_closed());
            }
            if !owns_pause && state.paused {
                state = wait_native_joined_half_state(&self.changed, state, start, timeout)?;
                continue;
            }
            if !owns_pause {
                state.paused = true;
                owns_pause = true;
                self.changed.notify_all();
                continue;
            }
            if state.active_ops == 0 {
                let current = state.current.take();
                self.changed.notify_all();
                return Ok(current);
            }
            match wait_native_joined_half_state(&self.changed, state, start, timeout) {
                Ok(next) => state = next,
                Err(err) => {
                    let mut state = self.state.lock().unwrap();
                    if state.paused && !state.closed {
                        state.paused = false;
                        self.changed.notify_all();
                    }
                    drop(state);
                    return Err(err);
                }
            }
        }
    }

    fn resume(&self, current: Option<T>) -> Result<()> {
        let mut current = current;
        let mut deadline_result = Ok(());
        loop {
            let applied_generation = match current.as_ref() {
                Some(current) => match self.apply_deadline_to_candidate(current) {
                    Ok(generation) => generation,
                    Err(err) => {
                        deadline_result = Err(err);
                        None
                    }
                },
                None => None,
            };

            let mut state = self.state.lock().unwrap();
            if state.closed {
                state.paused = false;
                drop(state);
                self.changed.notify_all();
                return Err(Error::session_closed());
            }
            if deadline_result.is_ok()
                && current.is_some()
                && state.deadline_applier.is_some()
                && Some(state.deadline_generation) != applied_generation
            {
                drop(state);
                continue;
            }
            state.current = current.take();
            state.paused = false;
            drop(state);
            self.changed.notify_all();
            return deadline_result;
        }
    }

    fn replace(&self, next: Option<T>) -> Result<Option<T>> {
        let mut applied_generation = None;
        let mut state = self.state.lock().unwrap();
        loop {
            if state.closed {
                return Err(Error::session_closed());
            }
            if state.paused {
                return Err(Error::local("zmux: joined stream half is paused"));
            }
            if state.active_ops == 0 {
                if next.is_some()
                    && state.deadline_applier.is_some()
                    && Some(state.deadline_generation) != applied_generation
                {
                    drop(state);
                    applied_generation = match next.as_ref() {
                        Some(next) => self.apply_deadline_to_candidate(next)?,
                        None => None,
                    };
                    state = self.state.lock().unwrap();
                    continue;
                }
                let previous = mem::replace(&mut state.current, next);
                self.changed.notify_all();
                return Ok(previous);
            }
            state = self.changed.wait(state).unwrap();
        }
    }

    fn close_detached(&self) -> Option<T> {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return None;
        }
        state.closed = true;
        state.paused = false;
        self.changed.notify_all();
        while state.active_ops != 0 {
            state = self.changed.wait(state).unwrap();
        }
        let current = state.current.take();
        drop(state);
        self.changed.notify_all();
        current
    }

    fn into_current(self: Arc<Self>) -> Option<T> {
        Arc::try_unwrap(self)
            .ok()
            .and_then(|half| half.state.into_inner().unwrap().current)
    }

    fn set_deadline(
        self: &Arc<Self>,
        deadline: Option<Instant>,
        applier: NativeDeadlineApplier<T>,
    ) -> Result<()> {
        let current = {
            let mut state = self.state.lock().unwrap();
            if state.closed {
                return Err(Error::session_closed());
            }
            state.deadline = deadline;
            state.deadline_generation = next_generation(state.deadline_generation);
            state.deadline_applier = Some(applier);
            self.changed.notify_all();
            let current = if state.paused || state.active_ops != 0 {
                None
            } else {
                match state.current.take() {
                    Some(current) => {
                        state.active_ops += 1;
                        Some(current)
                    }
                    None => None,
                }
            };
            drop(state);
            current
        };

        let Some(current) = current else {
            return Ok(());
        };

        let mut current = Some(current);
        let mut deadline_result = Ok(());
        loop {
            if let Some(current) = current.as_ref() {
                if let Err(err) = self.apply_deadline_to_candidate(current) {
                    deadline_result = Err(err);
                }
            }

            let mut state = self.state.lock().unwrap();
            if deadline_result.is_ok()
                && !state.closed
                && current.is_some()
                && state.deadline_applier.is_some()
                && state.deadline_applied_generation != state.deadline_generation
            {
                drop(state);
                continue;
            }
            if state.current.is_none() {
                state.current = current.take();
            }
            if state.active_ops > 0 {
                state.active_ops -= 1;
            }
            drop(state);
            self.changed.notify_all();
            return deadline_result;
        }
    }

    fn apply_deadline_to_candidate(&self, current: &T) -> Result<Option<u64>> {
        let Some((deadline, generation, applier)) = self.deadline_snapshot() else {
            return Ok(None);
        };
        applier(current, deadline)?;
        {
            let mut state = self.state.lock().unwrap();
            if state.deadline_generation == generation {
                state.deadline_applied_generation = generation;
            }
        }
        Ok(Some(generation))
    }

    fn deadline_snapshot(&self) -> Option<(Option<Instant>, u64, NativeDeadlineApplier<T>)> {
        let state = self.state.lock().unwrap();
        state
            .deadline_applier
            .map(|applier| (state.deadline, state.deadline_generation, applier))
    }

    fn wait_while_paused<'a>(
        &self,
        state: MutexGuard<'a, NativeJoinedHalfState<T>>,
    ) -> Result<MutexGuard<'a, NativeJoinedHalfState<T>>> {
        match state.deadline.and_then(|deadline| {
            deadline
                .checked_duration_since(Instant::now())
                .and_then(nonzero_duration_value)
        }) {
            Some(remaining) => {
                let (wait_for, reaches_deadline) = condvar_timed_wait_step(remaining);
                let (state, wait) = self.changed.wait_timeout(state, wait_for).unwrap();
                if wait.timed_out() && reaches_deadline && state.paused {
                    Err(Error::timeout(self.deadline_operation))
                } else {
                    Ok(state)
                }
            }
            None if state.deadline.is_some() => Err(Error::timeout(self.deadline_operation)),
            None => Ok(self.changed.wait(state).unwrap()),
        }
    }
}

impl<T> Drop for ActiveNativeHalf<T> {
    fn drop(&mut self) {
        let mut current = self.current.take();
        let mut applied_generation = Some(self.deadline_generation);
        let mut replay_failed = false;
        let mut state = self.owner.state.lock().unwrap();
        loop {
            let needs_replay = !replay_failed
                && !state.closed
                && state.current.is_none()
                && current.is_some()
                && state.deadline_applier.is_some()
                && Some(state.deadline_generation) != applied_generation;
            if needs_replay {
                drop(state);
                applied_generation = match current.as_ref() {
                    Some(current) => match self.owner.apply_deadline_to_candidate(current) {
                        Ok(generation) => generation,
                        Err(_) => {
                            replay_failed = true;
                            None
                        }
                    },
                    None => None,
                };
                state = self.owner.state.lock().unwrap();
                continue;
            }
            if state.current.is_none() {
                state.current = current.take();
            }
            if state.active_ops > 0 {
                state.active_ops -= 1;
            }
            drop(state);
            self.owner.changed.notify_all();
            return;
        }
    }
}

impl<T> PausedNativeHalf<T> {
    pub fn current(&self) -> Option<&T> {
        self.current.as_ref()
    }

    pub fn current_mut(&mut self) -> Option<&mut T> {
        self.current.as_mut()
    }

    pub fn take(&mut self) -> Option<T> {
        self.current.take()
    }

    pub fn set(&mut self, next: Option<T>) -> Option<T> {
        mem::replace(&mut self.current, next)
    }

    pub fn replace(&mut self, next: T) -> Option<T> {
        self.current.replace(next)
    }

    pub fn resume(mut self) -> Result<()> {
        self.resumed = true;
        let current = self.current.take();
        self.owner.resume(current)
    }
}

impl<T> Drop for PausedNativeHalf<T> {
    fn drop(&mut self) {
        if !self.resumed {
            let current = self.current.take();
            let _ = self.owner.resume(current);
            self.resumed = true;
        }
    }
}

fn wait_native_joined_half_state<'a, T>(
    changed: &Condvar,
    state: MutexGuard<'a, NativeJoinedHalfState<T>>,
    start: Instant,
    timeout: Option<Duration>,
) -> Result<MutexGuard<'a, NativeJoinedHalfState<T>>> {
    match timeout.and_then(|timeout| remaining_timeout(start, timeout)) {
        Some(remaining) => {
            let (wait_for, reaches_deadline) = condvar_timed_wait_step(remaining);
            let (state, wait) = changed.wait_timeout(state, wait_for).unwrap();
            if wait.timed_out() && reaches_deadline {
                Err(Error::timeout("joined half pause"))
            } else {
                Ok(state)
            }
        }
        None if timeout.is_some() => Err(Error::timeout("joined half pause")),
        None => Ok(changed.wait(state).unwrap()),
    }
}

fn joined_read_half_missing_error() -> Error {
    Error::local("zmux: joined stream has no readable half")
}

fn joined_write_half_missing_error() -> Error {
    Error::local("zmux: joined stream has no writable half")
}

fn same_close_identity(first: *const (), second: *const ()) -> bool {
    !first.is_null() && first == second
}

fn validate_read_progress(n: usize, requested: usize) -> Result<usize> {
    if n > requested {
        Err(invalid_read_progress_error())
    } else {
        Ok(n)
    }
}

fn validate_write_progress(n: usize, requested: usize) -> Result<usize> {
    if n > requested {
        Err(invalid_write_progress_error())
    } else {
        Ok(n)
    }
}

fn remaining_timeout(start: Instant, timeout: Duration) -> Option<Duration> {
    timeout
        .checked_sub(start.elapsed())
        .and_then(nonzero_duration_value)
}

fn timeout_to_deadline(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(|timeout| Instant::now().checked_add(timeout))
}

fn remaining_read_timeout(start: Instant, timeout: Duration) -> Result<Duration> {
    remaining_timeout(start, timeout).ok_or_else(|| {
        Error::timeout("read").with_stream_context(ErrorOperation::Read, ErrorDirection::Read)
    })
}

fn ensure_positive_open_timeout(timeout: Duration) -> Result<()> {
    if timeout.is_zero() {
        Err(Error::timeout("open").with_session_context(ErrorOperation::Open))
    } else {
        Ok(())
    }
}

fn remaining_write_timeout(start: Instant, timeout: Duration) -> Result<Duration> {
    remaining_timeout(start, timeout).ok_or_else(|| {
        Error::timeout("write").with_stream_context(ErrorOperation::Write, ErrorDirection::Write)
    })
}

fn write_open_payload_native<S>(
    stream: &mut S,
    payload: WritePayload<'_>,
    timeout: Option<Duration>,
    fin: bool,
    skip_empty: bool,
) -> Result<usize>
where
    S: SendStreamHandle + ?Sized,
{
    let requested = payload.checked_len()?;
    if skip_empty && requested == 0 {
        return Ok(0);
    }
    let n = match (payload, timeout, fin) {
        (WritePayload::Bytes(data), Some(timeout), false) => {
            stream.write_timeout(data.as_ref(), timeout)?
        }
        (WritePayload::Bytes(data), Some(timeout), true) => {
            stream.write_final_timeout(data.as_ref(), timeout)?
        }
        (WritePayload::Bytes(data), None, false) => Write::write(stream, data.as_ref())?,
        (WritePayload::Bytes(data), None, true) => stream.write_final(data.as_ref())?,
        (WritePayload::Vectored(parts), Some(timeout), false) => {
            stream.write_vectored_timeout(parts, timeout)?
        }
        (WritePayload::Vectored(parts), Some(timeout), true) => {
            stream.write_vectored_final_timeout(parts, timeout)?
        }
        (WritePayload::Vectored(parts), None, false) => stream.write_vectored(parts)?,
        (WritePayload::Vectored(parts), None, true) => stream.write_vectored_final(parts)?,
    };
    validate_write_progress(n, requested)
}

fn validate_io_read_progress(n: usize, requested: usize) -> io::Result<usize> {
    if n > requested {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zmux: read reported invalid progress",
        ))
    } else {
        Ok(n)
    }
}

fn validate_io_write_progress(n: usize, requested: usize) -> io::Result<usize> {
    if n > requested {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zmux: write reported invalid progress",
        ))
    } else {
        Ok(n)
    }
}

fn checked_vectored_len(parts: &[IoSlice<'_>]) -> Result<usize> {
    parts.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or_else(vectored_len_overflow_error)
    })
}

fn checked_vectored_read_len(parts: &[IoSliceMut<'_>]) -> Result<usize> {
    parts.iter().try_fold(0usize, |total, part| {
        total
            .checked_add(part.len())
            .ok_or_else(vectored_read_len_overflow_error)
    })
}

fn checked_io_vectored_len(parts: &[IoSlice<'_>]) -> io::Result<usize> {
    parts.iter().try_fold(0usize, |total, part| {
        total.checked_add(part.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "zmux: vectored write length overflow",
            )
        })
    })
}

fn checked_io_vectored_read_len(parts: &[IoSliceMut<'_>]) -> io::Result<usize> {
    parts.iter().try_fold(0usize, |total, part| {
        total.checked_add(part.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "zmux: vectored read length overflow",
            )
        })
    })
}

fn invalid_read_progress_error() -> Error {
    Error::local("zmux: read reported invalid progress")
        .with_stream_context(ErrorOperation::Read, ErrorDirection::Read)
}

fn unexpected_eof_error() -> Error {
    Error::io(io::Error::new(
        io::ErrorKind::UnexpectedEof,
        "failed to fill whole buffer",
    ))
    .with_stream_context(ErrorOperation::Read, ErrorDirection::Read)
}

fn invalid_write_progress_error() -> Error {
    Error::local("zmux: write reported invalid progress")
        .with_stream_context(ErrorOperation::Write, ErrorDirection::Write)
}

fn zero_length_write_error() -> Error {
    Error::io(io::Error::new(
        io::ErrorKind::WriteZero,
        "failed to write whole buffer",
    ))
    .with_stream_context(ErrorOperation::Write, ErrorDirection::Write)
}

fn vectored_len_overflow_error() -> Error {
    Error::local("zmux: vectored write length overflow")
        .with_stream_context(ErrorOperation::Write, ErrorDirection::Write)
}

fn vectored_read_len_overflow_error() -> Error {
    Error::local("zmux: vectored read length overflow")
        .with_stream_context(ErrorOperation::Read, ErrorDirection::Read)
}

fn apply_native_read_deadline<T: RecvStreamHandle>(
    stream: &T,
    deadline: Option<Instant>,
) -> Result<()> {
    stream.set_read_deadline(deadline)
}

fn apply_native_write_deadline<T: SendStreamHandle>(
    stream: &T,
    deadline: Option<Instant>,
) -> Result<()> {
    stream.set_write_deadline(deadline)
}

impl<R, W> DuplexStream<R, W> {
    #[must_use]
    pub fn new(recv: R, send: W) -> Self {
        Self::from_parts(Some(recv), Some(send))
    }

    #[must_use]
    pub fn from_parts(recv: Option<R>, send: Option<W>) -> Self {
        Self {
            recv: Arc::new(NativeJoinedHalf::new_optional(recv, "read")),
            send: Arc::new(NativeJoinedHalf::new_optional(send, "write")),
            info_side: DuplexInfoSide::Read,
        }
    }

    #[must_use]
    pub fn empty() -> Self {
        Self::from_parts(None, None)
    }

    #[must_use]
    pub fn with_info_side(mut self, info_side: DuplexInfoSide) -> Self {
        self.info_side = info_side;
        self
    }

    pub fn info_side(&self) -> DuplexInfoSide {
        self.info_side
    }

    pub fn recv(&self) -> Option<R>
    where
        R: Clone,
    {
        self.recv.with_current_or(None, |recv| Some(recv.clone()))
    }

    pub fn send(&self) -> Option<W>
    where
        W: Clone,
    {
        self.send.with_current_or(None, |send| Some(send.clone()))
    }

    pub fn into_parts(self) -> (Option<R>, Option<W>) {
        (self.recv.into_current(), self.send.into_current())
    }

    pub fn pause_read(&self) -> Result<PausedNativeRecvHalf<R>> {
        self.pause_read_timeout_option(None)
    }

    pub fn pause_read_timeout(&self, timeout: Duration) -> Result<PausedNativeRecvHalf<R>> {
        self.pause_read_timeout_option(Some(timeout))
    }

    fn pause_read_timeout_option(
        &self,
        timeout: Option<Duration>,
    ) -> Result<PausedNativeRecvHalf<R>> {
        Ok(PausedNativeHalf {
            owner: Arc::clone(&self.recv),
            current: self.recv.pause(timeout)?,
            resumed: false,
        })
    }

    pub fn pause_write(&self) -> Result<PausedNativeSendHalf<W>> {
        self.pause_write_timeout_option(None)
    }

    pub fn pause_write_timeout(&self, timeout: Duration) -> Result<PausedNativeSendHalf<W>> {
        self.pause_write_timeout_option(Some(timeout))
    }

    fn pause_write_timeout_option(
        &self,
        timeout: Option<Duration>,
    ) -> Result<PausedNativeSendHalf<W>> {
        Ok(PausedNativeHalf {
            owner: Arc::clone(&self.send),
            current: self.send.pause(timeout)?,
            resumed: false,
        })
    }

    pub fn replace_recv(&self, recv: R) -> Result<Option<R>> {
        self.recv.replace(Some(recv))
    }

    pub fn replace_send(&self, send: W) -> Result<Option<W>> {
        self.send.replace(Some(send))
    }

    pub fn detach_recv(&self) -> Result<Option<R>> {
        self.recv.replace(None)
    }

    pub fn detach_send(&self) -> Result<Option<W>> {
        self.send.replace(None)
    }
}

impl<R, W> DuplexStream<R, W>
where
    R: RecvStreamHandle,
    W: SendStreamHandle,
{
    pub fn read_stream_id(&self) -> u64 {
        self.recv.with_current_or(0, |recv| recv.stream_id())
    }

    pub fn write_stream_id(&self) -> u64 {
        self.send.with_current_or(0, |send| send.stream_id())
    }
}

#[must_use]
pub fn join_streams<R, W>(recv: R, send: W) -> DuplexStream<R, W> {
    DuplexStream::new(recv, send)
}

#[must_use]
pub fn join_optional_streams<R, W>(recv: Option<R>, send: Option<W>) -> DuplexStream<R, W> {
    DuplexStream::from_parts(recv, send)
}

impl<R, W> Read for DuplexStream<R, W>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv
            .with_current_io(joined_read_half_missing_error, |recv| {
                let n = recv.read(buf)?;
                validate_io_read_progress(n, buf.len())
            })
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        let requested = checked_io_vectored_read_len(bufs)?;
        self.recv
            .with_current_io(joined_read_half_missing_error, |recv| {
                let n = recv.read_vectored(bufs)?;
                validate_io_read_progress(n, requested)
            })
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.recv
            .with_current_io(joined_read_half_missing_error, |recv| {
                Read::read_exact(recv, buf)
            })
    }
}

impl<R, W> Read for &DuplexStream<R, W>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.recv
            .with_current_io(joined_read_half_missing_error, |recv| {
                let n = recv.read(buf)?;
                validate_io_read_progress(n, buf.len())
            })
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        let requested = checked_io_vectored_read_len(bufs)?;
        self.recv
            .with_current_io(joined_read_half_missing_error, |recv| {
                let n = recv.read_vectored(bufs)?;
                validate_io_read_progress(n, requested)
            })
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        self.recv
            .with_current_io(joined_read_half_missing_error, |recv| {
                Read::read_exact(recv, buf)
            })
    }
}

impl<R, W> Write for DuplexStream<R, W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send
            .with_current_io(joined_write_half_missing_error, |send| {
                let n = send.write(buf)?;
                validate_io_write_progress(n, buf.len())
            })
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let requested = checked_io_vectored_len(bufs)?;
        self.send
            .with_current_io(joined_write_half_missing_error, |send| {
                let n = send.write_vectored(bufs)?;
                validate_io_write_progress(n, requested)
            })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send
            .with_current_io(joined_write_half_missing_error, |send| send.flush())
    }
}

impl<R, W> Write for &DuplexStream<R, W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.send
            .with_current_io(joined_write_half_missing_error, |send| {
                let n = send.write(buf)?;
                validate_io_write_progress(n, buf.len())
            })
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let requested = checked_io_vectored_len(bufs)?;
        self.send
            .with_current_io(joined_write_half_missing_error, |send| {
                let n = send.write_vectored(bufs)?;
                validate_io_write_progress(n, requested)
            })
    }

    fn flush(&mut self) -> io::Result<()> {
        self.send
            .with_current_io(joined_write_half_missing_error, |send| send.flush())
    }
}

impl<R, W> StreamHandle for DuplexStream<R, W>
where
    R: RecvStreamHandle,
    W: SendStreamHandle,
{
    fn stream_id(&self) -> u64 {
        match self.info_side {
            DuplexInfoSide::Read => self.recv.with_current_or(0, |recv| recv.stream_id()),
            DuplexInfoSide::Write => self.send.with_current_or(0, |send| send.stream_id()),
        }
    }

    fn is_opened_locally(&self) -> bool {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(false, |recv| recv.is_opened_locally()),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(false, |send| send.is_opened_locally()),
        }
    }

    fn is_bidirectional(&self) -> bool {
        true
    }

    fn open_info_len(&self) -> usize {
        match self.info_side {
            DuplexInfoSide::Read => self.recv.with_current_or(0, |recv| recv.open_info_len()),
            DuplexInfoSide::Write => self.send.with_current_or(0, |send| send.open_info_len()),
        }
    }

    fn has_open_info(&self) -> bool {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(false, |recv| recv.has_open_info()),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(false, |send| send.has_open_info()),
        }
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        match self.info_side {
            DuplexInfoSide::Read => {
                self.recv
                    .with_current_or((), |recv| recv.append_open_info_to(dst));
            }
            DuplexInfoSide::Write => {
                self.send
                    .with_current_or((), |send| send.append_open_info_to(dst));
            }
        }
    }

    fn open_info(&self) -> Vec<u8> {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(Vec::new(), |recv| recv.open_info()),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(Vec::new(), |send| send.open_info()),
        }
    }

    fn metadata(&self) -> StreamMetadata {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(StreamMetadata::default(), |recv| recv.metadata()),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(StreamMetadata::default(), |send| send.metadata()),
        }
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(None, |recv| recv.local_addr())
                .or_else(|| self.send.with_current_or(None, |send| send.local_addr())),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(None, |send| send.local_addr())
                .or_else(|| self.recv.with_current_or(None, |recv| recv.local_addr())),
        }
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        match self.info_side {
            DuplexInfoSide::Read => self
                .recv
                .with_current_or(None, |recv| recv.peer_addr())
                .or_else(|| self.send.with_current_or(None, |send| send.peer_addr())),
            DuplexInfoSide::Write => self
                .send
                .with_current_or(None, |send| send.peer_addr())
                .or_else(|| self.recv.with_current_or(None, |recv| recv.peer_addr())),
        }
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        let read = <Self as RecvStreamHandle>::set_read_deadline(self, deadline);
        let write = <Self as SendStreamHandle>::set_write_deadline(self, deadline);
        read.and(write)
    }

    fn close(&self) -> Result<()> {
        let send = self.send.close_detached();
        let recv = self.recv.close_detached();
        let same_identity = send
            .as_ref()
            .zip(recv.as_ref())
            .is_some_and(|(send, recv)| {
                same_close_identity(send.close_identity(), recv.close_identity())
            });

        let write = send.as_ref().map_or(Ok(()), |send| send.close());
        let read = if same_identity {
            Ok(())
        } else {
            recv.as_ref().map_or(Ok(()), |recv| recv.close())
        };
        write.and(read)
    }

    fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        let send = self.send.close_detached();
        let recv = self.recv.close_detached();
        let same_identity = send
            .as_ref()
            .zip(recv.as_ref())
            .is_some_and(|(send, recv)| {
                same_close_identity(send.close_identity(), recv.close_identity())
            });

        let write = send
            .as_ref()
            .map_or(Ok(()), |send| send.close_with_error(code, reason));
        let read = if same_identity {
            Ok(())
        } else {
            recv.as_ref()
                .map_or(Ok(()), |recv| recv.close_with_error(code, reason))
        };
        write.and(read)
    }
}

impl<R, W> RecvStreamHandle for DuplexStream<R, W>
where
    R: RecvStreamHandle,
    W: SendStreamHandle,
{
    fn is_read_closed(&self) -> bool {
        self.recv
            .with_current_or(true, |recv| recv.is_read_closed())
    }

    fn read_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<usize> {
        self.recv
            .with_current_result(joined_read_half_missing_error, |recv| {
                let n = recv.read_timeout(dst, timeout)?;
                validate_read_progress(n, dst.len())
            })
    }

    fn read_vectored_timeout(
        &self,
        dsts: &mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        let requested = checked_vectored_read_len(dsts)?;
        self.recv
            .with_current_result(joined_read_half_missing_error, |recv| {
                let n = recv.read_vectored_timeout(dsts, timeout)?;
                validate_read_progress(n, requested)
            })
    }

    fn read_exact_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<()> {
        self.recv
            .with_current_result(joined_read_half_missing_error, |recv| {
                recv.read_exact_timeout(dst, timeout)
            })
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        NativeJoinedHalf::set_deadline(&self.recv, deadline, apply_native_read_deadline::<R>)
    }

    fn close_read(&self) -> Result<()> {
        match self
            .recv
            .with_current_result_or((), |recv| recv.close_read())
        {
            Err(err) if err.is_session_closed() => Ok(()),
            result => result,
        }
    }

    fn cancel_read(&self, code: u64) -> Result<()> {
        self.recv
            .with_current_result(joined_read_half_missing_error, |recv| {
                recv.cancel_read(code)
            })
    }
}

impl<R, W> SendStreamHandle for DuplexStream<R, W>
where
    R: RecvStreamHandle,
    W: SendStreamHandle,
{
    fn is_write_closed(&self) -> bool {
        self.send
            .with_current_or(true, |send| send.is_write_closed())
    }

    fn update_metadata(&self, update: MetadataUpdate) -> Result<()> {
        self.send
            .with_current_result(joined_write_half_missing_error, |send| {
                send.update_metadata(update)
            })
    }

    fn write_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        self.send
            .with_current_result(joined_write_half_missing_error, |send| {
                let n = send.write_timeout(src, timeout)?;
                validate_write_progress(n, src.len())
            })
    }

    fn write_all_timeout(&self, src: &[u8], timeout: Duration) -> Result<()> {
        self.send
            .with_current_result(joined_write_half_missing_error, |send| {
                send.write_all_timeout(src, timeout)
            })
    }

    fn write_vectored(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        let requested = checked_vectored_len(parts)?;
        self.send
            .with_current_result(joined_write_half_missing_error, |send| {
                let n = send.write_vectored(parts)?;
                validate_write_progress(n, requested)
            })
    }

    fn write_vectored_timeout(&self, parts: &[IoSlice<'_>], timeout: Duration) -> Result<usize> {
        let requested = checked_vectored_len(parts)?;
        self.send
            .with_current_result(joined_write_half_missing_error, |send| {
                let n = send.write_vectored_timeout(parts, timeout)?;
                validate_write_progress(n, requested)
            })
    }

    fn write_final(&self, src: &[u8]) -> Result<usize> {
        self.send
            .with_current_result(joined_write_half_missing_error, |send| {
                let n = send.write_final(src)?;
                validate_write_progress(n, src.len())
            })
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        let requested = checked_vectored_len(parts)?;
        self.send
            .with_current_result(joined_write_half_missing_error, |send| {
                let n = send.write_vectored_final(parts)?;
                validate_write_progress(n, requested)
            })
    }

    fn write_final_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        self.send
            .with_current_result(joined_write_half_missing_error, |send| {
                let n = send.write_final_timeout(src, timeout)?;
                validate_write_progress(n, src.len())
            })
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        let requested = checked_vectored_len(parts)?;
        self.send
            .with_current_result(joined_write_half_missing_error, |send| {
                let n = send.write_vectored_final_timeout(parts, timeout)?;
                validate_write_progress(n, requested)
            })
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        NativeJoinedHalf::set_deadline(&self.send, deadline, apply_native_write_deadline::<W>)
    }

    fn close_write(&self) -> Result<()> {
        match self
            .send
            .with_current_result_or((), |send| send.close_write())
        {
            Err(err) if err.is_session_closed() => Ok(()),
            result => result,
        }
    }

    fn cancel_write(&self, code: u64) -> Result<()> {
        self.send
            .with_current_result(joined_write_half_missing_error, |send| {
                send.cancel_write(code)
            })
    }
}

impl<R, W> DuplexStreamHandle for DuplexStream<R, W>
where
    R: RecvStreamHandle,
    W: SendStreamHandle,
{
}

pub trait Session: Send + Sync {
    fn accept_stream(&self) -> Result<BoxStream>;
    fn accept_stream_timeout(&self, timeout: Duration) -> Result<BoxStream>;
    fn accept_uni_stream(&self) -> Result<BoxRecvStream>;
    fn accept_uni_stream_timeout(&self, timeout: Duration) -> Result<BoxRecvStream>;
    fn open_stream(&self) -> Result<BoxStream> {
        self.open_stream_with(OpenRequest::new())
    }
    fn open_uni_stream(&self) -> Result<BoxSendStream> {
        self.open_uni_stream_with(OpenRequest::new())
    }
    fn open_stream_with(&self, request: OpenRequest) -> Result<BoxStream>;
    fn open_uni_stream_with(&self, request: OpenRequest) -> Result<BoxSendStream>;
    fn open_and_send(&self, request: OpenSend<'_>) -> Result<(BoxStream, usize)> {
        let (opts, payload, timeout) = request.into_parts();
        let start = Instant::now();
        let mut open = OpenRequest::new().with_options(opts);
        if let Some(timeout) = timeout {
            ensure_positive_open_timeout(timeout)?;
            open = open.with_timeout(timeout);
        }
        let mut stream = self.open_stream_with(open)?;
        let write_timeout = timeout
            .map(|timeout| remaining_write_timeout(start, timeout))
            .transpose()?;
        let n = write_open_payload_native(stream.as_mut(), payload, write_timeout, false, true)?;
        Ok((stream, n))
    }
    fn open_uni_and_send(&self, request: OpenSend<'_>) -> Result<(BoxSendStream, usize)> {
        let (opts, payload, timeout) = request.into_parts();
        let start = Instant::now();
        let mut open = OpenRequest::new().with_options(opts);
        if let Some(timeout) = timeout {
            ensure_positive_open_timeout(timeout)?;
            open = open.with_timeout(timeout);
        }
        let mut stream = self.open_uni_stream_with(open)?;
        let write_timeout = timeout
            .map(|timeout| remaining_write_timeout(start, timeout))
            .transpose()?;
        let n = write_open_payload_native(stream.as_mut(), payload, write_timeout, true, false)?;
        Ok((stream, n))
    }
    fn ping(&self, echo: &[u8]) -> Result<Duration>;
    fn ping_timeout(&self, echo: &[u8], timeout: Duration) -> Result<Duration>;
    fn go_away(&self, last_accepted_bidi: u64, last_accepted_uni: u64) -> Result<()>;
    fn go_away_with_error(
        &self,
        last_accepted_bidi: u64,
        last_accepted_uni: u64,
        code: u64,
        reason: &str,
    ) -> Result<()>;
    fn close(&self) -> Result<()>;
    fn close_with_error(&self, code: u64, reason: &str) -> Result<()>;
    fn wait(&self) -> Result<()>;
    fn wait_timeout(&self, timeout: Duration) -> Result<bool>;
    fn is_closed(&self) -> bool;
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn peer_addr(&self) -> Option<SocketAddr> {
        None
    }
    fn close_error(&self) -> Option<Error>;
    fn state(&self) -> SessionState;
    fn stats(&self) -> SessionStats;
    fn peer_go_away_error(&self) -> Option<PeerGoAwayError>;
    fn peer_close_error(&self) -> Option<PeerCloseError>;
    fn local_preface(&self) -> Preface;
    fn peer_preface(&self) -> Preface;
    fn negotiated(&self) -> Negotiated;
}

/// A permanently closed blocking session.
///
/// Use this as a no-op fallback when upper-layer code wants a session
/// handle but no transport/session is available.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClosedSession;

/// Create a permanently closed blocking session.
#[must_use]
pub fn closed_session() -> ClosedSession {
    ClosedSession
}

fn closed_session_error(operation: ErrorOperation) -> Error {
    Error::session_closed().with_session_context(operation)
}

fn closed_session_result<T>(operation: ErrorOperation) -> Result<T> {
    Err(closed_session_error(operation))
}

fn zero_session_settings() -> Settings {
    Settings {
        initial_max_stream_data_bidi_locally_opened: 0,
        initial_max_stream_data_bidi_peer_opened: 0,
        initial_max_stream_data_uni: 0,
        initial_max_data: 0,
        max_incoming_streams_bidi: 0,
        max_incoming_streams_uni: 0,
        max_frame_payload: 0,
        idle_timeout_millis: 0,
        keepalive_hint_millis: 0,
        max_control_payload_bytes: 0,
        max_extension_payload_bytes: 0,
        scheduler_hints: SchedulerHint::UnspecifiedOrBalanced,
        ping_padding_key: 0,
    }
}

fn zero_session_preface() -> Preface {
    Preface {
        preface_version: 0,
        role: Role::Initiator,
        tie_breaker_nonce: 0,
        min_proto: 0,
        max_proto: 0,
        capabilities: 0,
        settings: zero_session_settings(),
    }
}

fn zero_session_negotiated() -> Negotiated {
    Negotiated {
        proto: 0,
        capabilities: 0,
        local_role: Role::Initiator,
        peer_role: Role::Initiator,
        peer_settings: zero_session_settings(),
    }
}

impl Session for ClosedSession {
    fn accept_stream(&self) -> Result<BoxStream> {
        closed_session_result(ErrorOperation::Accept)
    }

    fn accept_stream_timeout(&self, _timeout: Duration) -> Result<BoxStream> {
        closed_session_result(ErrorOperation::Accept)
    }

    fn accept_uni_stream(&self) -> Result<BoxRecvStream> {
        closed_session_result(ErrorOperation::Accept)
    }

    fn accept_uni_stream_timeout(&self, _timeout: Duration) -> Result<BoxRecvStream> {
        closed_session_result(ErrorOperation::Accept)
    }

    fn open_stream_with(&self, _request: OpenRequest) -> Result<BoxStream> {
        closed_session_result(ErrorOperation::Open)
    }

    fn open_uni_stream_with(&self, _request: OpenRequest) -> Result<BoxSendStream> {
        closed_session_result(ErrorOperation::Open)
    }

    fn open_and_send(&self, _request: OpenSend<'_>) -> Result<(BoxStream, usize)> {
        closed_session_result(ErrorOperation::Open)
    }

    fn open_uni_and_send(&self, _request: OpenSend<'_>) -> Result<(BoxSendStream, usize)> {
        closed_session_result(ErrorOperation::Open)
    }

    fn ping(&self, _echo: &[u8]) -> Result<Duration> {
        closed_session_result(ErrorOperation::Ping)
    }

    fn ping_timeout(&self, _echo: &[u8], _timeout: Duration) -> Result<Duration> {
        closed_session_result(ErrorOperation::Ping)
    }

    fn go_away(&self, _last_accepted_bidi: u64, _last_accepted_uni: u64) -> Result<()> {
        closed_session_result(ErrorOperation::Close)
    }

    fn go_away_with_error(
        &self,
        _last_accepted_bidi: u64,
        _last_accepted_uni: u64,
        _code: u64,
        _reason: &str,
    ) -> Result<()> {
        closed_session_result(ErrorOperation::Close)
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }

    fn close_with_error(&self, _code: u64, _reason: &str) -> Result<()> {
        Ok(())
    }

    fn wait(&self) -> Result<()> {
        Ok(())
    }

    fn wait_timeout(&self, _timeout: Duration) -> Result<bool> {
        Ok(true)
    }

    fn is_closed(&self) -> bool {
        true
    }

    fn close_error(&self) -> Option<Error> {
        None
    }

    fn state(&self) -> SessionState {
        SessionState::Closed
    }

    fn stats(&self) -> SessionStats {
        SessionStats::empty(SessionState::Closed)
    }

    fn peer_go_away_error(&self) -> Option<PeerGoAwayError> {
        None
    }

    fn peer_close_error(&self) -> Option<PeerCloseError> {
        None
    }

    fn local_preface(&self) -> Preface {
        zero_session_preface()
    }

    fn peer_preface(&self) -> Preface {
        zero_session_preface()
    }

    fn negotiated(&self) -> Negotiated {
        zero_session_negotiated()
    }
}

macro_rules! impl_stream_info_forward {
    ($target:ty) => {
        impl<T> StreamHandle for $target
        where
            T: StreamHandle + ?Sized,
        {
            fn stream_id(&self) -> u64 {
                (**self).stream_id()
            }

            fn is_opened_locally(&self) -> bool {
                (**self).is_opened_locally()
            }

            fn is_bidirectional(&self) -> bool {
                (**self).is_bidirectional()
            }

            fn open_info_len(&self) -> usize {
                (**self).open_info_len()
            }

            fn has_open_info(&self) -> bool {
                (**self).has_open_info()
            }

            fn append_open_info_to(&self, dst: &mut Vec<u8>) {
                (**self).append_open_info_to(dst)
            }

            fn open_info(&self) -> Vec<u8> {
                (**self).open_info()
            }

            fn metadata(&self) -> StreamMetadata {
                (**self).metadata()
            }

            fn local_addr(&self) -> Option<SocketAddr> {
                (**self).local_addr()
            }

            fn peer_addr(&self) -> Option<SocketAddr> {
                (**self).peer_addr()
            }

            fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
                (**self).set_deadline(deadline)
            }

            fn close_identity(&self) -> *const () {
                (**self).close_identity()
            }

            fn close(&self) -> Result<()> {
                (**self).close()
            }

            fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
                (**self).close_with_error(code, reason)
            }
        }
    };
}

impl_stream_info_forward!(&T);
impl_stream_info_forward!(&mut T);
impl_stream_info_forward!(Box<T>);
impl_stream_info_forward!(Arc<T>);

macro_rules! impl_recv_stream_api_forward {
    ($target:ty) => {
        impl<T> RecvStreamHandle for $target
        where
            T: RecvStreamHandle + ?Sized,
        {
            fn is_read_closed(&self) -> bool {
                (**self).is_read_closed()
            }

            fn read_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<usize> {
                (**self).read_timeout(dst, timeout)
            }

            fn read_vectored_timeout(
                &self,
                dsts: &mut [IoSliceMut<'_>],
                timeout: Duration,
            ) -> Result<usize> {
                (**self).read_vectored_timeout(dsts, timeout)
            }

            fn read_exact_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<()> {
                (**self).read_exact_timeout(dst, timeout)
            }

            fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
                (**self).set_read_deadline(deadline)
            }

            fn close_read(&self) -> Result<()> {
                (**self).close_read()
            }

            fn cancel_read(&self, code: u64) -> Result<()> {
                (**self).cancel_read(code)
            }
        }
    };
}

impl_recv_stream_api_forward!(&mut T);
impl_recv_stream_api_forward!(Box<T>);

impl<T> RecvStreamHandle for &T
where
    T: RecvStreamHandle + ?Sized,
    for<'a> &'a T: Read,
{
    fn is_read_closed(&self) -> bool {
        (**self).is_read_closed()
    }

    fn read_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<usize> {
        (**self).read_timeout(dst, timeout)
    }

    fn read_vectored_timeout(
        &self,
        dsts: &mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        (**self).read_vectored_timeout(dsts, timeout)
    }

    fn read_exact_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<()> {
        (**self).read_exact_timeout(dst, timeout)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        (**self).set_read_deadline(deadline)
    }

    fn close_read(&self) -> Result<()> {
        (**self).close_read()
    }

    fn cancel_read(&self, code: u64) -> Result<()> {
        (**self).cancel_read(code)
    }
}

macro_rules! impl_send_stream_api_forward {
    ($target:ty) => {
        impl<T> SendStreamHandle for $target
        where
            T: SendStreamHandle + ?Sized,
        {
            fn is_write_closed(&self) -> bool {
                (**self).is_write_closed()
            }

            fn update_metadata(&self, update: MetadataUpdate) -> Result<()> {
                (**self).update_metadata(update)
            }

            fn write_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
                (**self).write_timeout(src, timeout)
            }

            fn write_all_timeout(&self, src: &[u8], timeout: Duration) -> Result<()> {
                (**self).write_all_timeout(src, timeout)
            }

            fn write_vectored(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
                (**self).write_vectored(parts)
            }

            fn write_vectored_timeout(
                &self,
                parts: &[IoSlice<'_>],
                timeout: Duration,
            ) -> Result<usize> {
                (**self).write_vectored_timeout(parts, timeout)
            }

            fn write_final(&self, src: &[u8]) -> Result<usize> {
                (**self).write_final(src)
            }

            fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
                (**self).write_vectored_final(parts)
            }

            fn write_final_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
                (**self).write_final_timeout(src, timeout)
            }

            fn write_vectored_final_timeout(
                &self,
                parts: &[IoSlice<'_>],
                timeout: Duration,
            ) -> Result<usize> {
                (**self).write_vectored_final_timeout(parts, timeout)
            }

            fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
                (**self).set_write_deadline(deadline)
            }

            fn close_write(&self) -> Result<()> {
                (**self).close_write()
            }

            fn cancel_write(&self, code: u64) -> Result<()> {
                (**self).cancel_write(code)
            }
        }
    };
}

impl_send_stream_api_forward!(&mut T);
impl_send_stream_api_forward!(Box<T>);

impl<T> SendStreamHandle for &T
where
    T: SendStreamHandle + ?Sized,
    for<'a> &'a T: Write,
{
    fn is_write_closed(&self) -> bool {
        (**self).is_write_closed()
    }

    fn update_metadata(&self, update: MetadataUpdate) -> Result<()> {
        (**self).update_metadata(update)
    }

    fn write_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        (**self).write_timeout(src, timeout)
    }

    fn write_vectored(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        (**self).write_vectored(parts)
    }

    fn write_vectored_timeout(&self, parts: &[IoSlice<'_>], timeout: Duration) -> Result<usize> {
        (**self).write_vectored_timeout(parts, timeout)
    }

    fn write_final(&self, src: &[u8]) -> Result<usize> {
        (**self).write_final(src)
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        (**self).write_vectored_final(parts)
    }

    fn write_final_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        (**self).write_final_timeout(src, timeout)
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        (**self).write_vectored_final_timeout(parts, timeout)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        (**self).set_write_deadline(deadline)
    }

    fn close_write(&self) -> Result<()> {
        (**self).close_write()
    }

    fn cancel_write(&self, code: u64) -> Result<()> {
        (**self).cancel_write(code)
    }
}

impl<T> DuplexStreamHandle for &mut T where T: DuplexStreamHandle + ?Sized {}
impl<T> DuplexStreamHandle for &T
where
    T: DuplexStreamHandle + ?Sized,
    for<'a> &'a T: Read,
    for<'a> &'a T: Write,
{
}
impl<T> DuplexStreamHandle for Box<T> where T: DuplexStreamHandle + ?Sized {}

macro_rules! impl_session_forward {
    ($target:ty) => {
        impl<T> Session for $target
        where
            T: Session + ?Sized,
        {
            fn accept_stream(&self) -> Result<BoxStream> {
                (**self).accept_stream()
            }

            fn accept_stream_timeout(&self, timeout: Duration) -> Result<BoxStream> {
                (**self).accept_stream_timeout(timeout)
            }

            fn accept_uni_stream(&self) -> Result<BoxRecvStream> {
                (**self).accept_uni_stream()
            }

            fn accept_uni_stream_timeout(&self, timeout: Duration) -> Result<BoxRecvStream> {
                (**self).accept_uni_stream_timeout(timeout)
            }

            fn open_stream_with(&self, request: OpenRequest) -> Result<BoxStream> {
                (**self).open_stream_with(request)
            }

            fn open_uni_stream_with(&self, request: OpenRequest) -> Result<BoxSendStream> {
                (**self).open_uni_stream_with(request)
            }

            fn open_and_send(&self, request: OpenSend<'_>) -> Result<(BoxStream, usize)> {
                (**self).open_and_send(request)
            }

            fn open_uni_and_send(&self, request: OpenSend<'_>) -> Result<(BoxSendStream, usize)> {
                (**self).open_uni_and_send(request)
            }

            fn ping(&self, echo: &[u8]) -> Result<Duration> {
                (**self).ping(echo)
            }

            fn ping_timeout(&self, echo: &[u8], timeout: Duration) -> Result<Duration> {
                (**self).ping_timeout(echo, timeout)
            }

            fn go_away(&self, last_accepted_bidi: u64, last_accepted_uni: u64) -> Result<()> {
                (**self).go_away(last_accepted_bidi, last_accepted_uni)
            }

            fn go_away_with_error(
                &self,
                last_accepted_bidi: u64,
                last_accepted_uni: u64,
                code: u64,
                reason: &str,
            ) -> Result<()> {
                (**self).go_away_with_error(last_accepted_bidi, last_accepted_uni, code, reason)
            }

            fn close(&self) -> Result<()> {
                (**self).close()
            }

            fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
                (**self).close_with_error(code, reason)
            }

            fn wait(&self) -> Result<()> {
                (**self).wait()
            }

            fn wait_timeout(&self, timeout: Duration) -> Result<bool> {
                (**self).wait_timeout(timeout)
            }

            fn is_closed(&self) -> bool {
                (**self).is_closed()
            }

            fn local_addr(&self) -> Option<SocketAddr> {
                (**self).local_addr()
            }

            fn peer_addr(&self) -> Option<SocketAddr> {
                (**self).peer_addr()
            }

            fn close_error(&self) -> Option<Error> {
                (**self).close_error()
            }

            fn state(&self) -> SessionState {
                (**self).state()
            }

            fn stats(&self) -> SessionStats {
                (**self).stats()
            }

            fn peer_go_away_error(&self) -> Option<PeerGoAwayError> {
                (**self).peer_go_away_error()
            }

            fn peer_close_error(&self) -> Option<PeerCloseError> {
                (**self).peer_close_error()
            }

            fn local_preface(&self) -> Preface {
                (**self).local_preface()
            }

            fn peer_preface(&self) -> Preface {
                (**self).peer_preface()
            }

            fn negotiated(&self) -> Negotiated {
                (**self).negotiated()
            }
        }
    };
}

impl_session_forward!(&T);
impl_session_forward!(&mut T);
impl_session_forward!(Box<T>);
impl_session_forward!(Arc<T>);

impl StreamHandle for Stream {
    fn stream_id(&self) -> u64 {
        Stream::stream_id(self)
    }

    fn is_opened_locally(&self) -> bool {
        Stream::is_opened_locally(self)
    }

    fn is_bidirectional(&self) -> bool {
        Stream::is_bidirectional(self)
    }

    fn open_info_len(&self) -> usize {
        Stream::open_info_len(self)
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        Stream::append_open_info_to(self, dst)
    }

    fn open_info(&self) -> Vec<u8> {
        self.open_info()
    }

    fn metadata(&self) -> StreamMetadata {
        Stream::metadata(self)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Stream::local_addr(self)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        Stream::peer_addr(self)
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        Stream::set_deadline(self, deadline)
    }

    fn close_identity(&self) -> *const () {
        Stream::close_identity(self)
    }

    fn close(&self) -> Result<()> {
        Stream::close(self)
    }

    fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        Stream::close_with_error(self, code, reason)
    }
}

impl RecvStreamHandle for Stream {
    fn is_read_closed(&self) -> bool {
        Stream::is_read_closed(self)
    }

    fn read_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<usize> {
        Stream::read_timeout(self, dst, timeout)
    }

    fn read_vectored_timeout(
        &self,
        dsts: &mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        Stream::read_vectored_timeout(self, dsts, timeout)
    }

    fn read_exact_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<()> {
        Stream::read_exact_timeout(self, dst, timeout)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        Stream::set_read_deadline(self, deadline)
    }

    fn close_read(&self) -> Result<()> {
        Stream::close_read(self)
    }

    fn cancel_read(&self, code: u64) -> Result<()> {
        Stream::cancel_read(self, code)
    }
}

impl SendStreamHandle for Stream {
    fn is_write_closed(&self) -> bool {
        Stream::is_write_closed(self)
    }

    fn update_metadata(&self, update: MetadataUpdate) -> Result<()> {
        Stream::update_metadata(self, update)
    }

    fn write_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        Stream::write_timeout(self, src, timeout)
    }

    fn write_all_timeout(&self, src: &[u8], timeout: Duration) -> Result<()> {
        Stream::write_all_timeout(self, src, timeout)
    }

    fn write_vectored(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        Stream::write_vectored(self, parts)
    }

    fn write_vectored_timeout(&self, parts: &[IoSlice<'_>], timeout: Duration) -> Result<usize> {
        Stream::write_vectored_timeout(self, parts, timeout)
    }

    fn write_final(&self, src: &[u8]) -> Result<usize> {
        Stream::write_final(self, src)
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        Stream::write_vectored_final(self, parts)
    }

    fn write_final_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        Stream::write_final_timeout(self, src, timeout)
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        Stream::write_vectored_final_timeout(self, parts, timeout)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        Stream::set_write_deadline(self, deadline)
    }

    fn close_write(&self) -> Result<()> {
        Stream::close_write(self)
    }

    fn cancel_write(&self, code: u64) -> Result<()> {
        Stream::cancel_write(self, code)
    }
}

impl DuplexStreamHandle for Stream {}

impl StreamHandle for SendStream {
    fn stream_id(&self) -> u64 {
        SendStream::stream_id(self)
    }

    fn is_opened_locally(&self) -> bool {
        SendStream::is_opened_locally(self)
    }

    fn is_bidirectional(&self) -> bool {
        SendStream::is_bidirectional(self)
    }

    fn open_info_len(&self) -> usize {
        SendStream::open_info_len(self)
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        SendStream::append_open_info_to(self, dst)
    }

    fn open_info(&self) -> Vec<u8> {
        self.open_info()
    }

    fn metadata(&self) -> StreamMetadata {
        SendStream::metadata(self)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        SendStream::local_addr(self)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        SendStream::peer_addr(self)
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        SendStream::set_deadline(self, deadline)
    }

    fn close_identity(&self) -> *const () {
        SendStream::close_identity(self)
    }

    fn close(&self) -> Result<()> {
        SendStream::close(self)
    }

    fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        SendStream::close_with_error(self, code, reason)
    }
}

impl SendStreamHandle for SendStream {
    fn is_write_closed(&self) -> bool {
        SendStream::is_write_closed(self)
    }

    fn update_metadata(&self, update: MetadataUpdate) -> Result<()> {
        SendStream::update_metadata(self, update)
    }

    fn write_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        SendStream::write_timeout(self, src, timeout)
    }

    fn write_all_timeout(&self, src: &[u8], timeout: Duration) -> Result<()> {
        SendStream::write_all_timeout(self, src, timeout)
    }

    fn write_vectored(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        SendStream::write_vectored(self, parts)
    }

    fn write_vectored_timeout(&self, parts: &[IoSlice<'_>], timeout: Duration) -> Result<usize> {
        SendStream::write_vectored_timeout(self, parts, timeout)
    }

    fn write_final(&self, src: &[u8]) -> Result<usize> {
        SendStream::write_final(self, src)
    }

    fn write_vectored_final(&self, parts: &[IoSlice<'_>]) -> Result<usize> {
        SendStream::write_vectored_final(self, parts)
    }

    fn write_final_timeout(&self, src: &[u8], timeout: Duration) -> Result<usize> {
        SendStream::write_final_timeout(self, src, timeout)
    }

    fn write_vectored_final_timeout(
        &self,
        parts: &[IoSlice<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        SendStream::write_vectored_final_timeout(self, parts, timeout)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        SendStream::set_write_deadline(self, deadline)
    }

    fn close_write(&self) -> Result<()> {
        SendStream::close_write(self)
    }

    fn cancel_write(&self, code: u64) -> Result<()> {
        SendStream::cancel_write(self, code)
    }
}

impl StreamHandle for RecvStream {
    fn stream_id(&self) -> u64 {
        RecvStream::stream_id(self)
    }

    fn is_opened_locally(&self) -> bool {
        RecvStream::is_opened_locally(self)
    }

    fn is_bidirectional(&self) -> bool {
        RecvStream::is_bidirectional(self)
    }

    fn open_info_len(&self) -> usize {
        RecvStream::open_info_len(self)
    }

    fn append_open_info_to(&self, dst: &mut Vec<u8>) {
        RecvStream::append_open_info_to(self, dst)
    }

    fn open_info(&self) -> Vec<u8> {
        self.open_info()
    }

    fn metadata(&self) -> StreamMetadata {
        RecvStream::metadata(self)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        RecvStream::local_addr(self)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        RecvStream::peer_addr(self)
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        RecvStream::set_deadline(self, deadline)
    }

    fn close_identity(&self) -> *const () {
        RecvStream::close_identity(self)
    }

    fn close(&self) -> Result<()> {
        RecvStream::close(self)
    }

    fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        RecvStream::close_with_error(self, code, reason)
    }
}

impl RecvStreamHandle for RecvStream {
    fn is_read_closed(&self) -> bool {
        RecvStream::is_read_closed(self)
    }

    fn read_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<usize> {
        RecvStream::read_timeout(self, dst, timeout)
    }

    fn read_vectored_timeout(
        &self,
        dsts: &mut [IoSliceMut<'_>],
        timeout: Duration,
    ) -> Result<usize> {
        RecvStream::read_vectored_timeout(self, dsts, timeout)
    }

    fn read_exact_timeout(&self, dst: &mut [u8], timeout: Duration) -> Result<()> {
        RecvStream::read_exact_timeout(self, dst, timeout)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> Result<()> {
        RecvStream::set_read_deadline(self, deadline)
    }

    fn close_read(&self) -> Result<()> {
        RecvStream::close_read(self)
    }

    fn cancel_read(&self, code: u64) -> Result<()> {
        RecvStream::cancel_read(self, code)
    }
}

impl Session for Conn {
    fn accept_stream(&self) -> Result<BoxStream> {
        Ok(Box::new(Conn::accept_stream(self)?))
    }

    fn accept_stream_timeout(&self, timeout: Duration) -> Result<BoxStream> {
        Ok(Box::new(Conn::accept_stream_timeout(self, timeout)?))
    }

    fn accept_uni_stream(&self) -> Result<BoxRecvStream> {
        Ok(Box::new(Conn::accept_uni_stream(self)?))
    }

    fn accept_uni_stream_timeout(&self, timeout: Duration) -> Result<BoxRecvStream> {
        Ok(Box::new(Conn::accept_uni_stream_timeout(self, timeout)?))
    }

    fn open_stream_with(&self, request: OpenRequest) -> Result<BoxStream> {
        Ok(Box::new(Conn::open_stream_with(self, request)?))
    }

    fn open_uni_stream_with(&self, request: OpenRequest) -> Result<BoxSendStream> {
        Ok(Box::new(Conn::open_uni_stream_with(self, request)?))
    }

    fn open_and_send(&self, request: OpenSend<'_>) -> Result<(BoxStream, usize)> {
        let (stream, n) = Conn::open_and_send(self, request)?;
        Ok((Box::new(stream), n))
    }

    fn open_uni_and_send(&self, request: OpenSend<'_>) -> Result<(BoxSendStream, usize)> {
        let (stream, n) = Conn::open_uni_and_send(self, request)?;
        Ok((Box::new(stream), n))
    }

    fn ping(&self, echo: &[u8]) -> Result<Duration> {
        Conn::ping(self, echo)
    }

    fn ping_timeout(&self, echo: &[u8], timeout: Duration) -> Result<Duration> {
        Conn::ping_timeout(self, echo, timeout)
    }

    fn go_away(&self, last_accepted_bidi: u64, last_accepted_uni: u64) -> Result<()> {
        Conn::go_away(self, last_accepted_bidi, last_accepted_uni)
    }

    fn go_away_with_error(
        &self,
        last_accepted_bidi: u64,
        last_accepted_uni: u64,
        code: u64,
        reason: &str,
    ) -> Result<()> {
        Conn::go_away_with_error(self, last_accepted_bidi, last_accepted_uni, code, reason)
    }

    fn close(&self) -> Result<()> {
        Conn::close(self)
    }

    fn close_with_error(&self, code: u64, reason: &str) -> Result<()> {
        Conn::close_with_error(self, code, reason)
    }

    fn wait(&self) -> Result<()> {
        Conn::wait(self)
    }

    fn wait_timeout(&self, timeout: Duration) -> Result<bool> {
        Conn::wait_timeout(self, timeout)
    }

    fn is_closed(&self) -> bool {
        Conn::is_closed(self)
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Conn::local_addr(self)
    }

    fn peer_addr(&self) -> Option<SocketAddr> {
        Conn::peer_addr(self)
    }

    fn close_error(&self) -> Option<Error> {
        Conn::close_error(self)
    }

    fn state(&self) -> SessionState {
        Conn::state(self)
    }

    fn stats(&self) -> SessionStats {
        Conn::stats(self)
    }

    fn peer_go_away_error(&self) -> Option<PeerGoAwayError> {
        Conn::peer_go_away_error(self)
    }

    fn peer_close_error(&self) -> Option<PeerCloseError> {
        Conn::peer_close_error(self)
    }

    fn local_preface(&self) -> Preface {
        Conn::local_preface(self)
    }

    fn peer_preface(&self) -> Preface {
        Conn::peer_preface(self)
    }

    fn negotiated(&self) -> Negotiated {
        Conn::negotiated(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ops::Deref;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct AppendOnlyStreamHandle {
        appends: AtomicUsize,
    }

    impl StreamHandle for AppendOnlyStreamHandle {
        fn stream_id(&self) -> u64 {
            7
        }

        fn is_opened_locally(&self) -> bool {
            true
        }

        fn is_bidirectional(&self) -> bool {
            true
        }

        fn open_info_len(&self) -> usize {
            3
        }

        fn append_open_info_to(&self, dst: &mut Vec<u8>) {
            self.appends.fetch_add(1, Ordering::Relaxed);
            dst.extend_from_slice(b"abc");
        }

        fn metadata(&self) -> StreamMetadata {
            StreamMetadata {
                open_info: b"abc".to_vec(),
                ..StreamMetadata::default()
            }
        }

        fn set_deadline(&self, _deadline: Option<Instant>) -> Result<()> {
            Ok(())
        }

        fn close(&self) -> Result<()> {
            Ok(())
        }

        fn close_with_error(&self, _code: u64, _reason: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn default_open_info_builds_from_append_method() {
        let info = AppendOnlyStreamHandle {
            appends: AtomicUsize::new(0),
        };

        assert_eq!(info.open_info(), b"abc");
        assert_eq!(info.appends.load(Ordering::Relaxed), 1);

        let mut dst = Vec::with_capacity(16);
        dst.extend_from_slice(b"pre:");
        info.append_open_info_to(&mut dst);
        assert_eq!(dst, b"pre:abc");
        assert!(dst.capacity() >= 16);
        assert_eq!(info.appends.load(Ordering::Relaxed), 2);
    }

    struct CustomInfoWrapper {
        inner: AppendOnlyStreamHandle,
    }

    impl Deref for CustomInfoWrapper {
        type Target = AppendOnlyStreamHandle;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl StreamHandle for CustomInfoWrapper {
        fn stream_id(&self) -> u64 {
            99
        }

        fn is_opened_locally(&self) -> bool {
            false
        }

        fn is_bidirectional(&self) -> bool {
            false
        }

        fn open_info_len(&self) -> usize {
            7
        }

        fn append_open_info_to(&self, dst: &mut Vec<u8>) {
            dst.extend_from_slice(b"wrapped");
        }

        fn metadata(&self) -> StreamMetadata {
            StreamMetadata {
                open_info: b"wrapped".to_vec(),
                ..StreamMetadata::default()
            }
        }

        fn set_deadline(&self, _deadline: Option<Instant>) -> Result<()> {
            Ok(())
        }

        fn close(&self) -> Result<()> {
            Ok(())
        }

        fn close_with_error(&self, _code: u64, _reason: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn custom_deref_wrapper_can_define_its_own_stream_info_surface() {
        let info = CustomInfoWrapper {
            inner: AppendOnlyStreamHandle {
                appends: AtomicUsize::new(0),
            },
        };

        assert_eq!(info.stream_id(), 99);
        assert!(!info.is_opened_locally());
        assert!(!info.is_bidirectional());
        assert_eq!(info.open_info(), b"wrapped");
        assert_eq!(info.inner.appends.load(Ordering::Relaxed), 0);
    }
}
