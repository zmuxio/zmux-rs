//! The queueing-delay bound of the datagram queues (CoDel, RFC 8289): the
//! send queue, the session receive queue and each stream's receive queue
//! record when each datagram was queued; the sojourn of the datagram that
//! leaves decides whether it is dropped instead
//! ([`Config::datagram_queue_delay`](super::Config::datagram_queue_delay)).

use std::time::{Duration, Instant};

/// The CoDel interval: a queue whose sojourns stay above the target this
/// long starts dropping.
const INTERVAL: Duration = Duration::from_millis(100);

/// The default target of the datagram queues
/// ([`Config::datagram_queue_delay`](super::Config::datagram_queue_delay)): 20 ms.
pub(super) const DEFAULT_DATAGRAM_QUEUE_DELAY: Duration = Duration::from_millis(20);

/// The CoDel state of one datagram queue (RFC 8289, Section 5): a datagram
/// condemned is dropped instead of delivered, and the drop rate of a
/// dropping state grows with the square root of its drops.
#[derive(Debug, Default, Clone)]
pub(crate) struct Codel {
    /// When a sojourn above the target first counts; `None`: below it.
    first_above: Option<Instant>,
    /// The next drop of the dropping state (the last one's once it ended).
    drop_next: Option<Instant>,
    count: u32,
    last_count: u32,
    dropping: bool,
}

impl Codel {
    /// The state of a queue that never held a datagram.
    pub(crate) const fn new() -> Self {
        Self {
            first_above: None,
            drop_next: None,
            count: 0,
            last_count: 0,
            dropping: false,
        }
    }

    /// Whether a datagram queued at `at` may be dropped at `now`: sojourns
    /// have been above `target` for an interval. A datagram alone in its
    /// queue is never condemned.
    fn ok_to_drop(&mut self, at: Instant, now: Instant, target: Duration, alone: bool) -> bool {
        if alone || now.saturating_duration_since(at) < target {
            self.first_above = None;
            return false;
        }
        match self.first_above {
            None => {
                self.first_above = Some(now + INTERVAL);
                false
            }
            Some(t) => now >= t,
        }
    }

    /// Decides on a datagram, queued at `at`, that leaves its queue at
    /// `now`, `alone` when no other datagram is queued: `true` drops it.
    /// `target` `None` turns the bound off. A queue that empties calls
    /// [`Codel::idle`].
    pub(super) fn drop(
        &mut self,
        at: Instant,
        now: Instant,
        target: Option<Duration>,
        alone: bool,
    ) -> bool {
        let Some(target) = target else {
            return false;
        };
        let ok = self.ok_to_drop(at, now, target, alone);
        if self.dropping {
            if !ok {
                self.dropping = false;
                return false;
            }
            let next = self.drop_next.unwrap_or(now);
            if now < next {
                return false;
            }
            self.count = self.count.saturating_add(1);
            self.drop_next = Some(control_law(next, self.count));
            return true;
        }
        if !ok {
            return false;
        }
        self.dropping = true;
        // Back to dropping soon after leaving it: resume near the last rate.
        let delta = self.count.wrapping_sub(self.last_count);
        let recent = self
            .drop_next
            .is_some_and(|t| now.saturating_duration_since(t) < 16 * INTERVAL);
        self.count = if delta > 1 && recent { delta } else { 1 };
        self.drop_next = Some(control_law(now, self.count));
        self.last_count = self.count;
        true
    }

    /// Ends the standing-queue state of a queue that emptied.
    pub(super) fn idle(&mut self) {
        self.first_above = None;
        self.dropping = false;
    }
}

/// The time of the next drop of a dropping state: interval / sqrt(count)
/// after `t`.
fn control_law(t: Instant, count: u32) -> Instant {
    t + INTERVAL.div_f64(f64::from(count.max(1)).sqrt())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// No drop below the target or for a moment above it; drops once the
    /// sojourn has stood above it for an interval, faster the longer it
    /// stands; none at once when the delay falls; a lone datagram is kept.
    #[test]
    fn codel_state_machine() {
        let target = Some(Duration::from_millis(20));
        let ms = Duration::from_millis;
        let mut c = Codel::new();
        let start = Instant::now();
        let mut now = start + Duration::from_secs(1);
        let leave = |c: &mut Codel, now: Instant, sojourn: Duration, alone: bool| {
            c.drop(now.checked_sub(sojourn).unwrap(), now, target, alone)
        };
        assert!(!leave(&mut c, now, ms(10), false) && !leave(&mut c, now, ms(19), false));
        assert!(
            !leave(&mut c, now, ms(30), false),
            "the first sojourn above"
        );
        now += ms(99);
        assert!(!leave(&mut c, now, ms(30), false), "before an interval");
        now += ms(1);
        assert!(
            !leave(&mut c, now, ms(30), true),
            "the only datagram queued"
        );
        assert!(!leave(&mut c, now, ms(30), false), "a lone datagram resets");
        now += INTERVAL;
        assert!(leave(&mut c, now, ms(30), false), "an interval above");
        assert!(!leave(&mut c, now, ms(30), false), "before the control law");
        now += INTERVAL;
        assert!(leave(&mut c, now, ms(30), false));
        assert_eq!(c.count, 2);
        let gap = c.drop_next.unwrap() - now;
        assert!(
            gap.abs_diff(Duration::from_nanos(70_710_678)) < ms(1),
            "{gap:?}"
        );
        assert!(
            !leave(&mut c, now, ms(5), false) && !c.dropping,
            "below the target"
        );
        c.idle();
        assert!(c.first_above.is_none() && !c.dropping);
        assert!(!Codel::new().drop(start, now + Duration::from_secs(10), None, false));
    }
}
