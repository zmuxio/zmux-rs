use crate::settings::Settings;
use crate::varint::MAX_VARINT62;

#[inline]
pub(super) fn negotiated_frame_payload(local: &Settings, peer: &Settings) -> u64 {
    min_nonzero(local.max_frame_payload, peer.max_frame_payload)
        .unwrap_or(Settings::DEFAULT.max_frame_payload)
}

#[inline]
pub(super) fn session_window_target(local: &Settings, session_data_high_watermark: usize) -> u64 {
    local
        .initial_max_data
        .max(scaled_high_watermark(session_data_high_watermark, 4))
}

#[inline]
pub(super) fn stream_window_target(
    initial_receive_window: u64,
    per_stream_data_high_watermark: usize,
) -> u64 {
    initial_receive_window.max(scaled_high_watermark(per_stream_data_high_watermark, 2))
}

#[inline]
pub(super) fn session_emergency_threshold(payload: u64) -> u64 {
    payload.saturating_mul(2)
}

#[inline]
pub(super) fn stream_emergency_threshold(target: u64, payload: u64) -> u64 {
    let threshold = quarter_threshold(target);
    if payload == 0 {
        threshold
    } else {
        payload.min(threshold)
    }
}

#[inline]
pub(super) fn replenish_min_pending(target: u64, payload: u64) -> u64 {
    let min_pending = quarter_threshold(target);
    if payload == 0 {
        min_pending
    } else {
        min_pending.min(payload)
    }
}

#[inline]
pub(super) fn receive_window_exceeded(received: u64, advertised: u64, amount: u64) -> bool {
    amount > advertised.saturating_sub(received)
}

#[inline]
pub(super) fn should_flush_receive_credit(
    advertised: u64,
    received: u64,
    pending: u64,
    target: u64,
    emergency_threshold: u64,
    min_pending: u64,
    force: bool,
) -> bool {
    if pending == 0 {
        return false;
    }
    if force {
        return true;
    }
    let remaining = advertised.saturating_sub(received);
    if remaining <= emergency_threshold {
        return true;
    }
    if remaining <= quarter_threshold(target) && advertised >= target {
        return true;
    }
    pending >= min_pending
}

#[inline]
pub(super) fn next_credit_limit(
    advertised: u64,
    pending: u64,
    received: u64,
    target: u64,
    standing_growth_allowed: bool,
) -> u64 {
    let floor = advertised.saturating_add(pending);
    let desired = if standing_growth_allowed {
        floor.max(received.saturating_add(target))
    } else {
        floor
    };
    desired.min(MAX_VARINT62)
}

#[inline]
pub(super) fn session_standing_growth_allowed(
    memory_pressure_high: bool,
    buffered: u64,
    pending: u64,
    session_data_high_watermark: usize,
) -> bool {
    standing_growth_allowed(
        memory_pressure_high,
        buffered,
        pending,
        session_data_high_watermark,
    )
}

#[inline]
pub(super) fn stream_standing_growth_allowed(
    memory_pressure_high: bool,
    buffered: u64,
    pending: u64,
    per_stream_data_high_watermark: usize,
) -> bool {
    standing_growth_allowed(
        memory_pressure_high,
        buffered,
        pending,
        per_stream_data_high_watermark,
    )
}

#[inline]
fn quarter_threshold(value: u64) -> u64 {
    if value <= 4 {
        1
    } else {
        value / 4
    }
}

#[inline]
fn standing_growth_allowed(
    memory_pressure_high: bool,
    buffered: u64,
    pending: u64,
    high_watermark: usize,
) -> bool {
    if memory_pressure_high {
        return false;
    }
    let high_watermark = usize_to_u64_saturating(high_watermark);
    buffered < high_watermark && pending < high_watermark - buffered
}

#[inline]
fn min_nonzero(a: u64, b: u64) -> Option<u64> {
    match (a, b) {
        (0, 0) => None,
        (0, b) => Some(b),
        (a, 0) => Some(a),
        (a, b) => Some(a.min(b)),
    }
}

#[inline]
fn scaled_high_watermark(value: usize, scale: u64) -> u64 {
    usize_to_u64_saturating(value)
        .saturating_mul(scale)
        .min(MAX_VARINT62)
}

#[inline]
fn usize_to_u64_saturating(value: usize) -> u64 {
    value.min(u64::MAX as usize) as u64
}

#[cfg(test)]
mod tests {
    use super::{
        negotiated_frame_payload, next_credit_limit, receive_window_exceeded,
        session_emergency_threshold, session_standing_growth_allowed, session_window_target,
        should_flush_receive_credit, stream_emergency_threshold, stream_standing_growth_allowed,
        stream_window_target,
    };
    use crate::settings::Settings;
    use crate::varint::MAX_VARINT62;

    #[test]
    fn next_credit_limit_can_preserve_standing_window_when_memory_allows() {
        assert_eq!(next_credit_limit(64, 8, 60, 128, true), 188);
        assert_eq!(next_credit_limit(64, 8, 60, 128, false), 72);
    }

    #[test]
    fn quarter_threshold_matches_receive_flow_boundaries() {
        assert_eq!(super::quarter_threshold(0), 1);
        assert_eq!(super::quarter_threshold(1), 1);
        assert_eq!(super::quarter_threshold(4), 1);
        assert_eq!(super::quarter_threshold(8), 2);
    }

    #[test]
    fn negotiated_frame_payload_uses_min_nonzero_or_default() {
        let local = Settings {
            max_frame_payload: 4096,
            ..Settings::default()
        };
        let peer = Settings {
            max_frame_payload: 2048,
            ..Settings::default()
        };

        assert_eq!(negotiated_frame_payload(&local, &peer), 2048);
        assert_eq!(
            negotiated_frame_payload(&Settings::default(), &Settings::default()),
            Settings::default().max_frame_payload
        );
    }

    #[test]
    fn credit_limit_clamps_to_varint62() {
        assert_eq!(
            next_credit_limit(MAX_VARINT62 - 2, 10, MAX_VARINT62 - 1, 16, true),
            MAX_VARINT62
        );
    }

    #[test]
    fn receive_credit_flush_uses_supplied_emergency_and_min_pending() {
        assert!(should_flush_receive_credit(100, 98, 1, 64, 2, 16, false));
        assert!(!should_flush_receive_credit(100, 10, 15, 64, 2, 16, false));
        assert!(should_flush_receive_credit(100, 10, 16, 64, 2, 16, false));
    }

    #[test]
    fn receive_window_exceeded_uses_remaining_credit_and_saturates() {
        assert!(!receive_window_exceeded(8, 10, 2));
        assert!(receive_window_exceeded(8, 10, 3));
        assert!(receive_window_exceeded(u64::MAX - 1, u64::MAX, 2));
    }

    #[test]
    fn stream_emergency_is_bounded_by_quarter_target() {
        assert_eq!(session_emergency_threshold(64), 128);
        assert_eq!(session_emergency_threshold(u64::MAX), u64::MAX);
        assert_eq!(stream_emergency_threshold(1024, 256), 256);
        assert_eq!(stream_emergency_threshold(64, 256), 16);
        assert_eq!(stream_emergency_threshold(1024, 0), 256);
    }

    #[test]
    fn zero_target_replenishment_thresholds_match_repository_policy() {
        assert_eq!(stream_emergency_threshold(0, 16_384), 1);
        assert_eq!(super::replenish_min_pending(0, 16_384), 1);
    }

    #[test]
    fn standing_growth_respects_buffer_pressure() {
        assert!(session_standing_growth_allowed(false, 32, 16, 128));
        assert!(!session_standing_growth_allowed(true, 32, 16, 128));
        assert!(!stream_standing_growth_allowed(false, 128, 0, 128));
        assert!(!stream_standing_growth_allowed(false, 120, 8, 128));
    }

    #[test]
    fn window_targets_follow_repo_defaults() {
        let settings = Settings {
            initial_max_data: 4096,
            ..Settings::default()
        };
        assert_eq!(session_window_target(&settings, 2048), 8192);
        assert_eq!(stream_window_target(1024, 2048), 4096);
    }

    #[test]
    fn window_targets_clamp_high_watermarks_to_varint62() {
        assert_eq!(
            session_window_target(&Settings::default(), usize::MAX),
            MAX_VARINT62
        );
        assert_eq!(stream_window_target(1024, usize::MAX), MAX_VARINT62);
    }
}
