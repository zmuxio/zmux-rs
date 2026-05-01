use crate::config::DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GracefulInput {
    pub(super) recv_abortive: bool,
    pub(super) needs_local_opener: bool,
    pub(super) local_opened: bool,
    pub(super) send_committed: bool,
    pub(super) queued_data_bytes: u64,
    pub(super) inflight_queued: u64,
    pub(super) fragment_cap: u64,
    pub(super) send_rate_estimate: u64,
    pub(super) explicit_tail_cap: Option<u64>,
    pub(super) drain_window: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct GracefulDecision {
    pub(super) attempt: bool,
    pub(super) tail_budget: u64,
    pub(super) committed_tail: u64,
    pub(super) inflight_tail: u64,
    pub(super) queued_only_tail: u64,
}

pub(super) fn evaluate_graceful(input: GracefulInput) -> GracefulDecision {
    let committed_tail = committed_tail(input.queued_data_bytes, input.inflight_queued);
    let inflight_tail = input.inflight_queued;
    let queued_only_tail = queued_only_tail(input.queued_data_bytes, input.inflight_queued);
    let tail_budget = tail_budget(
        input.fragment_cap,
        input.explicit_tail_cap,
        input.send_rate_estimate,
        drain_window(input.drain_window),
    );

    let mut attempt = false;
    if !input.recv_abortive && !input.needs_local_opener {
        if committed_tail == 0 {
            attempt = input.local_opened && input.send_committed;
        } else if inflight_tail > 0 {
            attempt = input.send_committed && inflight_tail <= tail_budget;
        } else {
            attempt = input.send_committed && queued_only_tail <= tail_budget;
        }
    }

    GracefulDecision {
        attempt,
        tail_budget,
        committed_tail,
        inflight_tail,
        queued_only_tail,
    }
}

fn committed_tail(queued_data_bytes: u64, inflight_queued: u64) -> u64 {
    queued_data_bytes.max(inflight_queued)
}

fn queued_only_tail(queued_data_bytes: u64, inflight_queued: u64) -> u64 {
    queued_data_bytes.saturating_sub(inflight_queued)
}

fn tail_budget(
    fragment_cap: u64,
    explicit_tail_cap: Option<u64>,
    send_rate_estimate: u64,
    drain_window: Duration,
) -> u64 {
    if let Some(cap) = explicit_tail_cap.filter(|cap| *cap > 0) {
        return cap;
    }
    static_tail_cap(fragment_cap).max(rate_budget(send_rate_estimate, drain_window))
}

fn static_tail_cap(fragment_cap: u64) -> u64 {
    if fragment_cap == 0 {
        return 0;
    }
    (fragment_cap / 4).clamp(1, 512)
}

fn rate_budget(rate_bytes_per_second: u64, window: Duration) -> u64 {
    if rate_bytes_per_second == 0 || window.is_zero() {
        return 0;
    }
    const NANOS_PER_SECOND: u128 = 1_000_000_000;

    let raw_budget =
        u128::from(rate_bytes_per_second).saturating_mul(window.as_nanos()) / NANOS_PER_SECOND;
    let budget = u128_to_u64_saturating(raw_budget);
    if budget == 0 {
        1
    } else {
        budget
    }
}

fn u128_to_u64_saturating(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

fn drain_window(window: Duration) -> Duration {
    if window.is_zero() {
        DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW
    } else {
        window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_abortive_or_unopened_paths() {
        for input in [
            GracefulInput {
                recv_abortive: true,
                local_opened: true,
                send_committed: true,
                ..base_input()
            },
            GracefulInput {
                needs_local_opener: true,
                local_opened: true,
                send_committed: true,
                ..base_input()
            },
        ] {
            assert!(!evaluate_graceful(input).attempt);
        }
    }

    #[test]
    fn allows_committed_empty_tail() {
        let decision = evaluate_graceful(GracefulInput {
            local_opened: true,
            send_committed: true,
            ..base_input()
        });
        assert!(decision.attempt);
        assert_eq!(decision.committed_tail, 0);
    }

    #[test]
    fn uses_inflight_tail_without_rate_budget() {
        let decision = evaluate_graceful(GracefulInput {
            local_opened: true,
            send_committed: true,
            queued_data_bytes: 1024,
            inflight_queued: 64,
            fragment_cap: 256,
            ..base_input()
        });
        assert!(decision.attempt);
        assert_eq!(decision.tail_budget, 64);
    }

    #[test]
    fn uses_committed_tail_with_rate_budget() {
        let decision = evaluate_graceful(GracefulInput {
            local_opened: true,
            send_committed: true,
            queued_data_bytes: 768,
            fragment_cap: 256,
            send_rate_estimate: 16 << 10,
            drain_window: Duration::from_millis(100),
            ..base_input()
        });
        assert!(decision.attempt);
        assert_eq!(decision.queued_only_tail, 768);
        assert!(decision.tail_budget >= 768);
    }

    #[test]
    fn explicit_tail_cap_wins() {
        let decision = evaluate_graceful(GracefulInput {
            local_opened: true,
            send_committed: true,
            queued_data_bytes: 384,
            fragment_cap: 256,
            send_rate_estimate: 16 << 10,
            explicit_tail_cap: Some(256),
            drain_window: Duration::from_millis(100),
            ..base_input()
        });
        assert!(!decision.attempt);
        assert_eq!(decision.tail_budget, 256);
    }

    #[test]
    fn uses_inflight_tail_even_when_rate_budget_allows_less_queued_only_tail() {
        let decision = evaluate_graceful(GracefulInput {
            local_opened: true,
            send_committed: true,
            queued_data_bytes: 768,
            inflight_queued: 64,
            fragment_cap: 256,
            send_rate_estimate: 1024,
            drain_window: Duration::from_millis(100),
            ..base_input()
        });
        assert!(decision.attempt);
        assert_eq!(decision.inflight_tail, 64);
        assert_eq!(decision.queued_only_tail, 704);
        assert!(decision.tail_budget < decision.queued_only_tail);
    }

    #[test]
    fn uses_inflight_tail_with_explicit_tail_cap() {
        let decision = evaluate_graceful(GracefulInput {
            local_opened: true,
            send_committed: true,
            queued_data_bytes: 384,
            inflight_queued: 64,
            fragment_cap: 256,
            send_rate_estimate: 16 << 10,
            explicit_tail_cap: Some(256),
            drain_window: Duration::from_millis(100),
            ..base_input()
        });
        assert!(decision.attempt);
        assert_eq!(decision.tail_budget, 256);
        assert_eq!(decision.inflight_tail, 64);
    }

    #[test]
    fn drain_window_uses_override_or_default() {
        assert_eq!(
            drain_window(Duration::ZERO),
            DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW
        );
        assert_eq!(
            drain_window(Duration::from_millis(250)),
            Duration::from_millis(250)
        );
    }

    #[test]
    fn budget_edges_are_bounded() {
        assert_eq!(static_tail_cap(0), 0);
        assert_eq!(static_tail_cap(1), 1);
        assert_eq!(static_tail_cap(u64::MAX), 512);

        assert_eq!(rate_budget(1, Duration::from_nanos(1)), 1);
        assert_eq!(rate_budget(u64::MAX, Duration::MAX), u64::MAX);
    }

    fn base_input() -> GracefulInput {
        GracefulInput {
            recv_abortive: false,
            needs_local_opener: false,
            local_opened: false,
            send_committed: false,
            queued_data_bytes: 0,
            inflight_queued: 0,
            fragment_cap: 0,
            send_rate_estimate: 0,
            explicit_tail_cap: None,
            drain_window: Duration::ZERO,
        }
    }
}
