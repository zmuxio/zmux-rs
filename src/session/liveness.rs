use super::state::fail_session_with_close;
use super::types::{CanceledPingPayload, ConnState, Inner, KeepalivePing, SessionState};
use crate::config::{DEFAULT_PING_PADDING_MAX_BYTES, DEFAULT_PING_PADDING_MIN_BYTES};
use crate::error::{Error, ErrorCode, ErrorSource, Result};
use crate::frame::{Frame, FrameType};
use crate::payload::build_code_payload;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const KEEPALIVE_JITTER_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
const RTT_ADAPTIVE_SLACK: Duration = Duration::from_millis(50);
const MIN_DERIVED_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DERIVED_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(60);
const MIN_SEND_RATE_SAMPLE_BYTES: usize = 4 << 10;
const MIN_SEND_RATE_SAMPLE_DURATION: Duration = Duration::from_millis(25);
const PING_NONCE_BYTES: usize = 8;
const PING_NONCE_BYTES_U64: u64 = 8;
const PING_PADDING_TAG_BYTES: usize = 8;
const PING_PADDING_TAG_BYTES_U64: u64 = 8;
const PING_PADDING_TAG_SALT: u64 = 0x6d1d_9f6d_33f9_772d;
const PING_PAYLOAD_HASH_OFFSET64: u64 = 14_695_981_039_346_656_037;
const PING_PAYLOAD_HASH_PRIME64: u64 = 1_099_511_628_211;

static KEEPALIVE_JITTER_SEED_COUNTER: AtomicU64 = AtomicU64::new(0);

pub(super) fn init_keepalive_jitter_state(seed: u64) -> u64 {
    if seed != 0 {
        seed
    } else {
        KEEPALIVE_JITTER_SEED_COUNTER
            .fetch_add(KEEPALIVE_JITTER_GAMMA, Ordering::Relaxed)
            .wrapping_add(KEEPALIVE_JITTER_GAMMA)
    }
}

pub(super) fn configured_keepalive_timeout(interval: Duration, configured: Duration) -> Duration {
    if interval.is_zero() {
        Duration::ZERO
    } else {
        configured
    }
}

pub(super) fn initialize_keepalive_schedules(inner: &Arc<Inner>, now: Instant) {
    let mut state = inner.state.lock().unwrap();
    reset_keepalive_schedules_locked(inner, &mut state, now);
}

pub(super) fn record_inbound_activity_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    now: Instant,
) {
    state.last_inbound_at = now;
    state.last_control_progress_at = now;
    reset_read_idle_ping_due_locked(inner, state, now);
}

pub(super) fn record_outbound_activity(
    inner: &Arc<Inner>,
    bytes: usize,
    write_duration: Duration,
    frames: u64,
    data_bytes: u64,
) {
    let mut state = inner.state.lock().unwrap();
    let now = Instant::now();
    state.sent_frames = state.sent_frames.saturating_add(frames);
    state.sent_data_bytes = state.sent_data_bytes.saturating_add(data_bytes);
    state.flush_count = state.flush_count.saturating_add(1);
    state.last_flush_at = Some(now);
    state.last_flush_frames = frames;
    state.last_flush_bytes = bytes;
    if let Some(sample) = send_rate_sample(bytes, write_duration) {
        state.send_rate_estimate = if state.send_rate_estimate == 0 {
            sample
        } else {
            average_u64_floor(state.send_rate_estimate, sample)
        };
    }
    state.last_outbound_at = now;
    reset_write_idle_ping_due_locked(inner, &mut state, now);
    inner.cond.notify_all();
}

pub(super) fn record_stream_application_progress(inner: &Arc<Inner>, now: Instant) {
    let mut state = inner.state.lock().unwrap();
    state.last_stream_progress_at = Some(now);
    state.last_application_progress_at = Some(now);
}

pub(super) fn note_blocked_write_locked(state: &mut ConnState, blocked: Duration) {
    if blocked.is_zero() {
        return;
    }
    state.blocked_write_total = state.blocked_write_total.saturating_add(blocked);
}

fn send_rate_sample(bytes: usize, elapsed: Duration) -> Option<u64> {
    if bytes == 0 || elapsed.is_zero() {
        return None;
    }
    if bytes < MIN_SEND_RATE_SAMPLE_BYTES && elapsed < MIN_SEND_RATE_SAMPLE_DURATION {
        return None;
    }
    Some(rate_bytes_per_second(bytes, elapsed).max(1))
}

fn rate_bytes_per_second(bytes: usize, elapsed: Duration) -> u64 {
    let nanos = elapsed.as_nanos();
    if nanos == 0 {
        return 0;
    }
    let bytes = u128::try_from(bytes).unwrap_or(u128::MAX);
    let rate = bytes
        .saturating_mul(1_000_000_000)
        .checked_div(nanos)
        .unwrap_or(u128::from(u64::MAX))
        .min(u128::from(u64::MAX));
    u64::try_from(rate).unwrap_or(u64::MAX)
}

fn average_u64_floor(a: u64, b: u64) -> u64 {
    if a <= b {
        a + (b - a) / 2
    } else {
        b + (a - b) / 2
    }
}

pub(super) fn note_local_ping_sent_locked(inner: &Arc<Inner>, state: &mut ConnState, now: Instant) {
    state.last_ping_sent_at = Some(now);
    reset_max_ping_due_locked(inner, state, now);
}

pub(super) fn note_matching_pong_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    now: Instant,
    sent_at: Instant,
) {
    state.last_pong_at = Some(now);
    state.last_ping_rtt = Some(now.saturating_duration_since(sent_at));
    reset_read_idle_ping_due_locked(inner, state, now);
    reset_write_idle_ping_due_locked(inner, state, now);
}

pub(super) fn reset_keepalive_idle_schedules_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    now: Instant,
) {
    reset_read_idle_ping_due_locked(inner, state, now);
    reset_write_idle_ping_due_locked(inner, state, now);
}

pub(super) fn clear_unsent_keepalive_ping(inner: &Arc<Inner>) {
    let mut state = inner.state.lock().unwrap();
    if state.keepalive_ping.is_none() {
        return;
    }
    state.keepalive_ping = None;
    reset_keepalive_idle_schedules_locked(inner, &mut state, Instant::now());
    inner.cond.notify_all();
}

pub(super) fn next_session_ping_token_locked(state: &mut ConnState) -> u64 {
    next_nonce(&mut state.ping_nonce_state)
}

pub(super) fn ping_payload_limit(inner: &Inner) -> u64 {
    let local = inner.local_preface.settings.max_control_payload_bytes;
    let peer = inner.peer_preface.settings.max_control_payload_bytes;
    match (local, peer) {
        (0, 0) => 0,
        (0, peer) => peer,
        (local, 0) => local,
        (local, peer) => local.min(peer),
    }
}

pub(super) fn ping_payload_len(echo_len: usize) -> Option<u64> {
    let total = echo_len.checked_add(PING_NONCE_BYTES)?;
    u64::try_from(total).ok()
}

pub(super) fn build_ping_payload_locked(
    inner: &Inner,
    state: &mut ConnState,
    echo: &[u8],
    nonce: u64,
) -> Result<(Vec<u8>, bool)> {
    let padding_len = outbound_ping_padding_len_locked(inner, state, echo.len())?;
    let accepts_padded_pong = padding_len.is_some();
    let payload_len = PING_NONCE_BYTES
        .checked_add(echo.len())
        .and_then(|len| len.checked_add(padding_len.unwrap_or(0)))
        .ok_or_else(|| Error::frame_size("PING payload length overflows usize"))?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(payload_len)
        .map_err(|_| Error::local("zmux: PING payload allocation failed"))?;
    if let Some(padding_len) = padding_len {
        payload.resize(payload_len, 0);
        payload[..PING_NONCE_BYTES].copy_from_slice(&nonce.to_be_bytes());
        fill_ping_padding_from_state(
            &mut payload[PING_NONCE_BYTES..PING_NONCE_BYTES + PING_PADDING_TAG_BYTES],
            &mut state.ping_nonce_state,
        );
        payload[PING_NONCE_BYTES..PING_NONCE_BYTES + PING_PADDING_TAG_BYTES].copy_from_slice(
            &ping_padding_tag(inner.local_preface.settings.ping_padding_key, nonce).to_be_bytes(),
        );
        let echo_start = PING_NONCE_BYTES + PING_PADDING_TAG_BYTES;
        let echo_end = echo_start + echo.len();
        payload[echo_start..echo_end].copy_from_slice(echo);
        fill_ping_padding_from_state(&mut payload[echo_end..], &mut state.ping_nonce_state);
        debug_assert_eq!(payload_len, PING_NONCE_BYTES + echo.len() + padding_len);
    } else {
        payload.extend_from_slice(&nonce.to_be_bytes());
        payload.extend_from_slice(echo);
    }
    Ok((payload, accepts_padded_pong))
}

pub(super) fn pong_payload_for_ping_locked(
    inner: &Inner,
    state: &mut ConnState,
    mut payload: Vec<u8>,
) -> Result<Vec<u8>> {
    if !has_ping_padding_tag(&payload, inner.peer_preface.settings.ping_padding_key) {
        return Ok(payload);
    }
    let max_payload = ping_payload_limit(inner);
    let payload_len = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    if payload_len >= max_payload {
        return Ok(payload);
    }
    let max_allowed = max_payload
        .saturating_sub(payload_len)
        .min(usize_to_u64_saturating(
            usize::MAX.saturating_sub(payload.len()),
        ));
    let Some(padding_len) = choose_ping_padding_len_locked(inner, state, max_allowed, 0)? else {
        return Ok(payload);
    };
    let old_len = payload.len();
    payload
        .try_reserve(padding_len)
        .map_err(|_| Error::local("zmux: PONG payload allocation failed"))?;
    payload.resize(old_len + padding_len, 0);
    fill_ping_padding_from_state(&mut payload[old_len..], &mut state.ping_nonce_state);
    Ok(payload)
}

pub(super) fn pong_payload_matches_ping(pong: &[u8], ping: &[u8], allow_padding: bool) -> bool {
    if allow_padding {
        pong.len() >= ping.len() && &pong[..ping.len()] == ping
    } else {
        pong == ping
    }
}

pub(super) fn canceled_ping_payload(
    payload: &[u8],
    accepts_padded_pong: bool,
) -> Option<CanceledPingPayload> {
    if payload.len() < PING_NONCE_BYTES {
        return None;
    }
    Some(CanceledPingPayload {
        nonce: ping_payload_nonce(payload),
        hash: ping_payload_hash(payload),
        len: payload.len(),
        accepts_padded_pong,
    })
}

pub(super) fn canceled_ping_payload_matches(pong: &[u8], canceled: &CanceledPingPayload) -> bool {
    if pong.len() < PING_NONCE_BYTES || ping_payload_nonce(pong) != canceled.nonce {
        return false;
    }
    if canceled.accepts_padded_pong {
        pong.len() >= canceled.len && ping_payload_hash(&pong[..canceled.len]) == canceled.hash
    } else {
        pong.len() == canceled.len && ping_payload_hash(pong) == canceled.hash
    }
}

pub(super) fn effective_keepalive_timeout_locked(inner: &Inner, state: &ConnState) -> Duration {
    effective_keepalive_timeout(
        inner.keepalive_interval,
        inner.keepalive_timeout,
        state.last_ping_rtt,
    )
}

fn effective_keepalive_timeout(
    interval: Duration,
    configured: Duration,
    last_ping_rtt: Option<Duration>,
) -> Duration {
    if interval.is_zero() {
        return Duration::ZERO;
    }

    let mut timeout = configured;
    if timeout.is_zero() {
        timeout = interval
            .checked_mul(2)
            .unwrap_or(Duration::MAX)
            .max(MIN_DERIVED_KEEPALIVE_TIMEOUT)
            .min(MAX_DERIVED_KEEPALIVE_TIMEOUT);
        if let Some(rtt) = last_ping_rtt {
            timeout = timeout
                .max(rtt_floor(rtt))
                .min(MAX_DERIVED_KEEPALIVE_TIMEOUT);
        }
        return timeout;
    }

    if let Some(rtt) = last_ping_rtt {
        timeout = timeout.max(rtt_floor(rtt));
    }
    timeout
}

pub(super) enum KeepaliveAction {
    SendPing(Vec<u8>),
    Timeout,
    Wait(Option<Duration>),
}

pub(super) fn poll_keepalive(inner: &Arc<Inner>, now: Instant) -> Result<KeepaliveAction> {
    let mut state = inner.state.lock().unwrap();
    poll_keepalive_locked(inner, &mut state, now)
}

fn poll_keepalive_locked(
    inner: &Arc<Inner>,
    state: &mut ConnState,
    now: Instant,
) -> Result<KeepaliveAction> {
    if inner.keepalive_interval.is_zero()
        || matches!(
            state.state,
            SessionState::Closing | SessionState::Closed | SessionState::Failed
        )
    {
        return Ok(KeepaliveAction::Wait(None));
    }

    if let Some(sent_at) = outstanding_ping_sent_at(state) {
        let timeout = effective_keepalive_timeout_locked(inner, state);
        let elapsed = now.saturating_duration_since(sent_at);
        if !timeout.is_zero() && elapsed > timeout {
            return Ok(KeepaliveAction::Timeout);
        }
        let remaining = timeout.saturating_sub(elapsed);
        let wait = if remaining.is_zero() {
            inner.keepalive_interval
        } else {
            remaining
        };
        return Ok(KeepaliveAction::Wait(Some(wait)));
    }

    ensure_keepalive_schedules_locked(inner, state, now);
    let Some(next_due) = earliest_due(state) else {
        return Ok(KeepaliveAction::Wait(Some(inner.keepalive_interval)));
    };
    if next_due > now {
        return Ok(KeepaliveAction::Wait(Some(
            next_due.saturating_duration_since(now),
        )));
    }

    let nonce = next_session_ping_token_locked(state);
    let (payload, accepts_padded_pong) = build_ping_payload_locked(inner, state, &[], nonce)?;
    state.keepalive_ping = Some(KeepalivePing {
        payload: payload.clone(),
        sent_at: now,
        accepts_padded_pong,
    });
    note_local_ping_sent_locked(inner, state, now);
    Ok(KeepaliveAction::SendPing(payload))
}

fn reset_keepalive_schedules_locked(inner: &Arc<Inner>, state: &mut ConnState, now: Instant) {
    reset_read_idle_ping_due_locked(inner, state, now);
    reset_write_idle_ping_due_locked(inner, state, now);
    reset_max_ping_due_locked(inner, state, now);
}

fn ensure_keepalive_schedules_locked(inner: &Arc<Inner>, state: &mut ConnState, now: Instant) {
    if inner.keepalive_interval.is_zero() {
        clear_keepalive_schedules_locked(state);
        return;
    }
    if state.read_idle_ping_due_at.is_none() {
        let base = if state.last_inbound_at > now {
            now
        } else {
            state.last_inbound_at
        };
        reset_read_idle_ping_due_locked(inner, state, base);
    }
    if state.write_idle_ping_due_at.is_none() {
        let base = if state.last_outbound_at > now {
            now
        } else {
            state.last_outbound_at
        };
        reset_write_idle_ping_due_locked(inner, state, base);
    }
    if state.max_ping_due_at.is_none() {
        reset_max_ping_due_locked(inner, state, now);
    }
}

fn clear_keepalive_schedules_locked(state: &mut ConnState) {
    state.read_idle_ping_due_at = None;
    state.write_idle_ping_due_at = None;
    state.max_ping_due_at = None;
}

fn reset_read_idle_ping_due_locked(inner: &Arc<Inner>, state: &mut ConnState, now: Instant) {
    state.read_idle_ping_due_at = next_due_at(
        inner.keepalive_interval,
        &mut state.keepalive_jitter_state,
        now,
    );
}

fn reset_write_idle_ping_due_locked(inner: &Arc<Inner>, state: &mut ConnState, now: Instant) {
    state.write_idle_ping_due_at = next_due_at(
        inner.keepalive_interval,
        &mut state.keepalive_jitter_state,
        now,
    );
}

fn reset_max_ping_due_locked(inner: &Arc<Inner>, state: &mut ConnState, now: Instant) {
    let interval = if inner.keepalive_interval.is_zero() {
        Duration::ZERO
    } else {
        inner.keepalive_max_ping_interval
    };
    state.max_ping_due_at = next_due_at(interval, &mut state.keepalive_jitter_state, now);
}

fn next_due_at(interval: Duration, jitter_state: &mut u64, now: Instant) -> Option<Instant> {
    if interval.is_zero() {
        return None;
    }
    now.checked_add(keepalive_lead_jittered_delay(interval, jitter_state))
}

fn keepalive_lead_jittered_delay(base: Duration, state: &mut u64) -> Duration {
    if base.is_zero() {
        return Duration::ZERO;
    }
    let jitter = next_keepalive_jitter(base, state);
    let delay = base.saturating_sub(jitter);
    if delay.is_zero() {
        base
    } else {
        delay
    }
}

fn next_keepalive_jitter(base: Duration, state: &mut u64) -> Duration {
    let window = base / 8;
    if window.is_zero() {
        return Duration::ZERO;
    }
    let nanos = u64::try_from(window.as_nanos().min(u128::from(u64::MAX))).unwrap_or(u64::MAX);
    Duration::from_nanos(next_nonce(state) % nanos.saturating_add(1))
}

fn outbound_ping_padding_len_locked(
    inner: &Inner,
    state: &mut ConnState,
    echo_len: usize,
) -> Result<Option<usize>> {
    if !inner.ping_padding {
        return Ok(None);
    }
    let limit = ping_payload_limit(inner);
    let Some(min_payload_len_usize) = echo_len
        .checked_add(PING_NONCE_BYTES)
        .and_then(|len| len.checked_add(PING_PADDING_TAG_BYTES))
    else {
        return Ok(None);
    };
    let Ok(min_payload_len) = u64::try_from(min_payload_len_usize) else {
        return Ok(None);
    };
    if limit < min_payload_len {
        return Ok(None);
    }
    let echo_len_u64 = u64::try_from(echo_len).unwrap_or(u64::MAX);
    let max_allowed = (limit - echo_len_u64 - PING_NONCE_BYTES_U64).min(usize_to_u64_saturating(
        usize::MAX
            .saturating_sub(echo_len)
            .saturating_sub(PING_NONCE_BYTES),
    ));
    let (_, max_padding) = ping_padding_bounds(
        max_allowed,
        inner.ping_padding_min_bytes,
        inner.ping_padding_max_bytes,
    );
    if max_padding < PING_PADDING_TAG_BYTES_U64 {
        return Ok(None);
    }
    let key = inner.local_preface.settings.ping_padding_key;
    if key == 0 {
        return Ok(None);
    }
    choose_ping_padding_len_locked(inner, state, max_allowed, PING_PADDING_TAG_BYTES_U64)
}

fn choose_ping_padding_len_locked(
    inner: &Inner,
    state: &mut ConnState,
    max_allowed: u64,
    min_required: u64,
) -> Result<Option<usize>> {
    if !inner.ping_padding {
        return Ok(None);
    }
    let (mut min_padding, max_padding) = ping_padding_bounds(
        max_allowed,
        inner.ping_padding_min_bytes,
        inner.ping_padding_max_bytes,
    );
    if max_padding == 0 || min_required > max_padding {
        return Ok(None);
    }
    if min_padding < min_required {
        min_padding = min_required;
    }

    let span = max_padding - min_padding + 1;
    let mut padding_len = min_padding;
    if span > 1 {
        padding_len += next_uint64n_from_state(&mut state.ping_nonce_state, span);
        if padding_len == state.last_ping_padding_len {
            padding_len = min_padding + ((padding_len - min_padding + 1) % span);
        }
    }
    state.last_ping_padding_len = padding_len;

    let padding_len = usize::try_from(padding_len)
        .map_err(|_| Error::frame_size("PING padding length exceeds platform capacity"))?;
    Ok(Some(padding_len))
}

fn ping_padding_bounds(max_allowed: u64, configured_min: u64, configured_max: u64) -> (u64, u64) {
    let mut max_padding = configured_max;
    if max_padding == 0 {
        max_padding = DEFAULT_PING_PADDING_MAX_BYTES;
    }
    max_padding = max_padding
        .min(max_allowed)
        .min(usize_to_u64_saturating(usize::MAX));
    if max_padding == 0 {
        return (0, 0);
    }

    let mut min_padding = configured_min;
    if min_padding == 0 {
        min_padding = DEFAULT_PING_PADDING_MIN_BYTES;
    }
    if min_padding > max_padding {
        min_padding = max_padding;
    }
    (min_padding, max_padding)
}

fn next_uint64n_from_state(state: &mut u64, n: u64) -> u64 {
    if n <= 1 {
        return 0;
    }
    let limit = u64::MAX - (u64::MAX % n);
    loop {
        let v = next_nonce(state);
        if v < limit {
            return v % n;
        }
    }
}

fn fill_ping_padding_from_state(mut dst: &mut [u8], state: &mut u64) {
    while !dst.is_empty() {
        let block = next_nonce(state).to_be_bytes();
        let n = dst.len().min(block.len());
        dst[..n].copy_from_slice(&block[..n]);
        dst = &mut dst[n..];
    }
}

fn ping_padding_tag(key: u64, nonce: u64) -> u64 {
    let mut z = key ^ nonce ^ PING_PADDING_TAG_SALT;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn has_ping_padding_tag(payload: &[u8], key: u64) -> bool {
    if key == 0 || payload.len() < PING_NONCE_BYTES + PING_PADDING_TAG_BYTES {
        return false;
    }
    let nonce = ping_payload_nonce(payload);
    let tag = u64::from_be_bytes(
        payload[PING_NONCE_BYTES..PING_NONCE_BYTES + PING_PADDING_TAG_BYTES]
            .try_into()
            .unwrap(),
    );
    tag == ping_padding_tag(key, nonce)
}

fn ping_payload_nonce(payload: &[u8]) -> u64 {
    u64::from_be_bytes(payload[..PING_NONCE_BYTES].try_into().unwrap())
}

fn ping_payload_hash(payload: &[u8]) -> u64 {
    payload
        .iter()
        .fold(PING_PAYLOAD_HASH_OFFSET64, |hash, byte| {
            (hash ^ u64::from(*byte)).wrapping_mul(PING_PAYLOAD_HASH_PRIME64)
        })
}

fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn next_nonce(state: &mut u64) -> u64 {
    let mut x = *state;
    if x == 0 {
        x = init_keepalive_jitter_state(0);
    }
    x = x.wrapping_add(KEEPALIVE_JITTER_GAMMA);
    *state = x;

    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn earliest_due(state: &ConnState) -> Option<Instant> {
    [
        state.read_idle_ping_due_at,
        state.write_idle_ping_due_at,
        state.max_ping_due_at,
    ]
        .into_iter()
        .flatten()
        .min()
}

fn outstanding_ping_sent_at(state: &ConnState) -> Option<Instant> {
    state
        .keepalive_ping
        .as_ref()
        .map(|ping| ping.sent_at)
        .or_else(|| state.ping_waiter.as_ref().map(|ping| ping.slot.sent_at))
}

fn rtt_floor(rtt: Duration) -> Duration {
    if rtt.is_zero() {
        return Duration::ZERO;
    }
    rtt.checked_mul(4)
        .and_then(|duration| duration.checked_add(RTT_ADAPTIVE_SLACK))
        .unwrap_or(Duration::MAX)
}

pub(super) fn close_for_idle_timeout(inner: &Arc<Inner>) {
    let err = Error::application(ErrorCode::IdleTimeout.as_u64(), "zmux: keepalive timeout")
        .with_source(ErrorSource::Local);
    {
        let mut state = inner.state.lock().unwrap();
        state.keepalive_timeout_count = state.keepalive_timeout_count.saturating_add(1);
    }
    let close_frame = Frame {
        frame_type: FrameType::Close,
        flags: 0,
        stream_id: 0,
        payload: build_code_payload(
            ErrorCode::IdleTimeout.as_u64(),
            "zmux: keepalive timeout",
            inner.peer_preface.settings.max_control_payload_bytes,
        )
            .unwrap_or_default(),
    };
    fail_session_with_close(inner, err, close_frame);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_rate_sample_ignores_small_fast_flushes() {
        assert_eq!(send_rate_sample(1024, Duration::from_millis(1)), None);
        assert_eq!(send_rate_sample(4096, Duration::from_secs(1)), Some(4096));
    }

    #[test]
    fn send_rate_average_matches_go_floor_average() {
        assert_eq!(average_u64_floor(4096, 8192), 6144);
        assert_eq!(average_u64_floor(8193, 4096), 6144);
    }

    #[test]
    fn send_rate_sample_uses_wide_math_and_saturates_cleanly() {
        assert_eq!(send_rate_sample(8192, Duration::from_secs(2)), Some(4096));
        assert_eq!(send_rate_sample(8192, Duration::from_secs(1)), Some(8192));

        let large_bytes = usize::try_from(50_000_000_000_000u64).unwrap();
        assert_eq!(
            rate_bytes_per_second(large_bytes, Duration::from_millis(200)),
            250_000_000_000_000
        );
        assert_eq!(
            rate_bytes_per_second(usize::MAX, Duration::from_nanos(1)),
            u64::MAX
        );
        assert_eq!(average_u64_floor(u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn keepalive_jitter_state_preserves_explicit_and_allocates_distinct_defaults() {
        assert_eq!(init_keepalive_jitter_state(123), 123);

        let first = init_keepalive_jitter_state(0);
        let second = init_keepalive_jitter_state(0);

        assert_ne!(first, 0);
        assert_ne!(second, 0);
        assert_ne!(first, second);
    }

    #[test]
    fn keepalive_jitter_stays_in_lead_window_and_advances_state() {
        let mut state = 1;
        let base = Duration::from_millis(80);
        let window = base / 8;
        let mut samples = Vec::new();

        for _ in 0..16 {
            let jitter = next_keepalive_jitter(base, &mut state);
            assert!(jitter <= window);
            samples.push(jitter);
        }

        assert!(samples.windows(2).any(|pair| pair[0] != pair[1]));
    }

    #[test]
    fn keepalive_lead_delay_stays_within_configured_window() {
        let mut state = 1;
        let base = Duration::from_millis(80);
        let min_delay = base - (base / 8);

        for _ in 0..16 {
            let delay = keepalive_lead_jittered_delay(base, &mut state);
            assert!(delay >= min_delay);
            assert!(delay <= base);
        }
    }

    #[test]
    fn distinct_keepalive_jitter_states_desynchronize_deadlines() {
        let base = Duration::from_secs(1);
        let mut first_state = 1;
        let mut second_state = 2;

        let desynchronized = (0..4).any(|_| {
            keepalive_lead_jittered_delay(base, &mut first_state)
                != keepalive_lead_jittered_delay(base, &mut second_state)
        });

        assert!(desynchronized);
    }

    #[test]
    fn effective_keepalive_timeout_saturates_before_caps_and_requires_interval() {
        assert_eq!(
            effective_keepalive_timeout(
                Duration::ZERO,
                Duration::ZERO,
                Some(Duration::from_secs(30)),
            ),
            Duration::ZERO
        );
        assert_eq!(
            effective_keepalive_timeout(Duration::MAX, Duration::ZERO, None),
            MAX_DERIVED_KEEPALIVE_TIMEOUT
        );
        assert_eq!(
            effective_keepalive_timeout(
                Duration::from_millis(500),
                Duration::ZERO,
                Some(Duration::MAX)
            ),
            MAX_DERIVED_KEEPALIVE_TIMEOUT
        );
        assert_eq!(
            effective_keepalive_timeout(
                Duration::from_secs(1),
                Duration::from_millis(500),
                Some(Duration::MAX),
            ),
            Duration::MAX
        );
        assert_eq!(
            effective_keepalive_timeout(
                Duration::from_secs(1),
                Duration::from_millis(10),
                Some(Duration::ZERO),
            ),
            Duration::from_millis(10)
        );
        assert_eq!(rtt_floor(Duration::MAX), Duration::MAX);
    }

    #[test]
    fn ping_payload_len_rejects_overflow() {
        assert_eq!(ping_payload_len(0), Some(8));
        assert_eq!(ping_payload_len(usize::MAX), None);
    }

    #[test]
    fn ping_nonce_uses_splitmix_state_advance() {
        fn splitmix64_after_increment(state: u64) -> u64 {
            let mut z = state.wrapping_add(KEEPALIVE_JITTER_GAMMA);
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        let mut state = 1;
        assert_eq!(next_nonce(&mut state), splitmix64_after_increment(1));
        assert_eq!(state, 1u64.wrapping_add(KEEPALIVE_JITTER_GAMMA));
        assert_eq!(
            next_nonce(&mut state),
            splitmix64_after_increment(1u64.wrapping_add(KEEPALIVE_JITTER_GAMMA))
        );
    }
}
