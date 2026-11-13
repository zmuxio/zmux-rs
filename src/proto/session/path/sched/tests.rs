//! Choices of the spreading policies between two pipes whose estimates a
//! test sets (5 and 6): two cores joined by
//! in-memory pipes, then the estimates of A's outbound pipes replaced.

use std::time::{Duration, Instant};

use crate::proto::frame::{Dir, Priority};
use crate::proto::listener::{Classified, ListenerConfig, ListenerCore};
use crate::proto::record::Framing;
use crate::proto::seal::RecordMode;
use crate::proto::seal::join::JoinHello;
use crate::proto::session::pipes::{Estimator, INITIAL_RTT};
use crate::proto::session::{
    ClaimedHello, Config, ConfirmedJoin, JoinStep, OpenedHello, PeerCarrier, PipeAuth, PipeId,
    PipeOptions, Policy, Role, SessionCore, StreamKey, TransmitBuf,
};

const BS: Framing = Framing::ByteStream;
const MS: Duration = Duration::from_millis(1);
/// 100 Mbit/s.
pub(in crate::proto::session) const FAST: u64 = 12_500_000;

fn config(policy: Policy) -> Config {
    let mut c = Config {
        max_pipes: 4,
        pipe_auth: PipeAuth::psk(*b"0123456789abcdef0123456789abcdef").with_end_to_end(),
        scheduler: policy,
        max_idle_timeout: Some(Duration::from_secs(600)),
        probation: None,
        ..Config::default()
    };
    c.liveness.probe_jitter = 0.0;
    c
}

/// Runs the handshake of pipe 2 on in-memory bytes: Hello through B's listener, Reply,
/// Confirm. Records on it start after that.
fn join(a: &mut SessionCore, b: &mut SessionCore, l: &mut ListenerCore, now: Instant) {
    let id = PipeId(2);
    a.join_prepare(id, now).unwrap().expect("not deferred");
    let plan = crate::shaping::UnitPlan::default();
    let hello = a.join_hello(id, (BS, 0), &plan, now).unwrap();
    let c = l.open(None, BS, now);
    let Classified::Join { hello, .. } = l.data(c, &hello, now) else {
        panic!("not a Hello");
    };
    let parsed = JoinHello::parse(BS, &hello).unwrap();
    let OpenedHello::Verified(mut peer) = b.open_hello(&parsed, &[], now) else {
        panic!("Hello not verified");
    };
    let carrier = PeerCarrier {
        inbound: Some(BS),
        outbound: Some(BS),
        looped: false,
        overhead: 0,
        received: 0,
    };
    let ClaimedHello::Accept(reply) = b.claim_hello(&mut peer, carrier, &plan, now) else {
        panic!("Hello not accepted");
    };
    let JoinStep::Verified { .. } = a.verify_reply(id, &reply, now) else {
        panic!("Reply not verified");
    };
    let confirm = a.join_finish(id, &plan, now).unwrap().confirm;
    assert!(peer.read_confirm(&confirm).unwrap().is_some());
    let confirmed = b.confirm_join(*peer, carrier, now);
    assert!(matches!(confirmed, ConfirmedJoin::Attached { pipe, .. } if pipe == id));
    l.done(c);
}

/// Moves every byte both ways until nothing is left.
fn pump(a: &mut SessionCore, b: &mut SessionCore, ids: &[u64], now: Instant) {
    let mut out = TransmitBuf::default();
    for _ in 0..64 {
        let mut moved = false;
        for &id in ids {
            while a.wants_write(PipeId(id)) {
                a.poll_transmit(PipeId(id), now, &mut out);
                let mut v = Vec::new();
                out.copy_to_vec(&mut v);
                if v.is_empty() {
                    break;
                }
                a.pipe_written(PipeId(id), v.len() as u64, now);
                moved = true;
                b.receive(PipeId(id), &v, now);
            }
            while b.wants_write(PipeId(id)) {
                b.poll_transmit(PipeId(id), now, &mut out);
                let mut v = Vec::new();
                out.copy_to_vec(&mut v);
                if v.is_empty() {
                    break;
                }
                b.pipe_written(PipeId(id), v.len() as u64, now);
                moved = true;
                a.receive(PipeId(id), &v, now);
            }
        }
        while a.poll_event().is_some() {}
        while b.poll_event().is_some() {}
        if !moved {
            break;
        }
    }
}

/// A multipath session with pipes 0 and 2 usable; pipe 0 has measured
/// 100 Mbit/s, pipe 2 (`second`) only what `second` says, both 10 ms
/// round trips; and a stream of A with `ready` bytes written.
pub(in crate::proto::session) fn two_pipes(
    policy: Policy,
    second: Option<u64>,
    ready: usize,
) -> (SessionCore, StreamKey) {
    let mut now = Instant::now();
    let mut a = SessionCore::new(config(policy.clone()), Role::Client, None, now).unwrap();
    let mut b_cfg = config(policy);
    b_cfg.locator = b"server".to_vec();
    let mut b = SessionCore::new(b_cfg, Role::Server, None, now).unwrap();
    let mut l = ListenerCore::new(ListenerConfig::default());
    a.attach_pipe(PipeId(0), BS, now);
    b.attach_pipe(PipeId(0), BS, now);
    pump(&mut a, &mut b, &[0], now);
    let id = a
        .add_pipe(
            Some(BS),
            Some(BS),
            &PipeOptions::default(),
            RecordMode::Trusted,
            None,
            now,
        )
        .unwrap();
    assert_eq!(id, PipeId(2));
    join(&mut a, &mut b, &mut l, now);
    for _ in 0..20 {
        pump(&mut a, &mut b, &[0, 2], now);
        now += 5 * MS;
        a.handle_timeout(now);
        b.handle_timeout(now);
    }
    for i in 0..a.atts.len() {
        let att = a.atts.at_mut(i);
        let id = att.id();
        let est = att.out_mut().unwrap().est_mut();
        *est = Estimator::new(INITIAL_RTT, now);
        est.rtt_sample(10 * MS, Duration::ZERO, false, now);
        match (id, second) {
            (0, _) => est.rate_sample(FAST, false, now),
            (_, Some(rate)) => est.rate_sample(rate, false, now),
            (_, None) => {}
        }
    }
    a.views_changed();
    let k = a.open(Dir::Bidi).unwrap();
    assert_eq!(a.write(k, &vec![7; ready]).unwrap(), ready);
    (a, k)
}

/// Whether the next chunk of `k` goes on pipe `id` at a write
/// opportunity there.
fn takes(a: &SessionCore, id: u64, k: StreamKey) -> bool {
    let d = a.decision(id, a.gate());
    a.stream_on_pipe(&d, k)
}

#[test]
fn a_joined_pipe_is_placed_as_fast_as_its_tier_for_four_round_trips() {
    // Pipe 2 has no bottleneck sample, its rate the initial 1 MB/s, and
    // the same one-way delay as pipe 0: without the placement rate BLEST
    // refuses it the bulk stream (the reorder budget is one chunk).
    let (mut a, k) = two_pipes(Policy::SpreadEta, None, 1 << 20);
    assert!(takes(&a, 0, k));
    assert!(takes(&a, 2, k));
    let i = a.att_index(2).unwrap();
    let round = a.atts.at(i).out().unwrap().est().round;
    assert_eq!(
        a.atts.at(i).out().unwrap().est().placed_from.get(),
        Some(round)
    );
    std::sync::Arc::make_mut(&mut a.config)
        .hooks
        .no_placement_rate = true;
    assert!(!takes(&a, 2, k));
    std::sync::Arc::make_mut(&mut a.config)
        .hooks
        .no_placement_rate = false;
    // Three of its round trips later it still counts as fast, after the
    // fourth no longer.
    a.atts.at_mut(i).out_mut().unwrap().est_mut().round += 3;
    assert!(takes(&a, 2, k));
    a.atts.at_mut(i).out_mut().unwrap().est_mut().round += 1;
    assert!(!takes(&a, 2, k));

    // Its first bottleneck sample ends it at once.
    let (mut a, k) = two_pipes(Policy::SpreadEta, None, 1 << 20);
    let now = a.now;
    let i = a.att_index(2).unwrap();
    a.atts
        .at_mut(i)
        .out_mut()
        .unwrap()
        .est_mut()
        .rate_sample(1_000_000, false, now);
    assert!(!takes(&a, 2, k));

    // So does a penalty.
    let (mut a, k) = two_pipes(Policy::SpreadEta, None, 1 << 20);
    a.atts.at_mut(i).out_mut().unwrap().est_mut().penalize();
    assert!(!takes(&a, 2, k));

    // In probation the pipe is not usable: its round trips do not count
    // yet.
    let (mut a, _) = two_pipes(Policy::SpreadEta, None, 1 << 20);
    a.atts
        .at_mut(i)
        .out_mut()
        .unwrap()
        .start_probation(0, true, false, now);
    a.views_changed();
    let (att, o) = (a.atts.at(i), a.atts.at(i).out().unwrap());
    assert_eq!(a.placement_rate(att, o), 1_000_000);
    assert_eq!(o.est().placed_from.get(), None);
}

#[test]
fn rate_weights_use_the_placement_rate() {
    let (a, k) = two_pipes(Policy::SpreadRateWeighted, None, 1 << 20);
    let gate = a.gate().unwrap();
    let w: Vec<(u64, f64)> = a.rr_weights(k, &gate, 0).collect();
    assert_eq!(w, [(0, FAST as f64), (2, FAST as f64)]);
}

#[test]
fn an_eta_tie_goes_to_the_pipe_with_the_write_opportunity() {
    // Equal pipes and a small write: pipe 0, the first of the tie, is f,
    // and pipe 2 sends the bytes itself rather than leave them for pipe
    // 0's next opportunity.
    let (a, k) = two_pipes(Policy::SpreadEta, Some(FAST), 512);
    assert!(takes(&a, 2, k));
    assert!(takes(&a, 0, k));
}

/// Gives pipe 2 of [`two_pipes`] a measured `rate` and a round trip of
/// `rtt`.
fn slow_second(a: &mut SessionCore, rate: u64, rtt: Duration) {
    let now = a.now;
    let i = a.att_index(2).unwrap();
    let est = a.atts.at_mut(i).out_mut().unwrap().est_mut();
    *est = Estimator::new(INITIAL_RTT, now);
    est.rtt_sample(rtt, Duration::ZERO, false, now);
    est.rate_sample(rate, false, now);
    a.views_changed();
}

/// Opens `n` more streams of A with `ready` bytes written each.
fn more_streams(a: &mut SessionCore, n: usize, ready: usize) -> Vec<StreamKey> {
    (0..n)
        .map(|_| {
            let k = a.open(Dir::Bidi).unwrap();
            assert_eq!(a.write(k, &vec![7; ready]).unwrap(), ready);
            k
        })
        .collect()
}

fn hooks(a: &mut SessionCore) -> &mut crate::proto::session::config::TestHooks {
    &mut std::sync::Arc::make_mut(&mut a.config).hooks
}

/// ECF's backlog for an incremental direction is what the round robin of
/// its level serves before its last ready byte: a
/// short stream beside long ones of its level waits for its share of them,
/// not for all of them, and stays off a slower pipe that a long one takes.
#[test]
fn ecf_counts_the_round_robins_share_of_the_level() {
    let setup = || {
        let (mut a, short) = two_pipes(Policy::SpreadEta, Some(FAST), 20_000);
        slow_second(&mut a, FAST / 4, 40 * MS);
        let long = more_streams(&mut a, 4, 200_000);
        (a, short, long)
    };
    let (mut a, short, long) = setup();
    assert!(!takes(&a, 2, short));
    assert!(takes(&a, 2, long[0]));
    assert!(takes(&a, 0, short));
    // The whole level (`no_ecf_share`).
    hooks(&mut a).no_ecf_share = true;
    assert!(takes(&a, 2, short));
    assert!(takes(&a, 2, long[0]));
    // Non-incremental directions of the level are served before the round
    // robin's turns and count in full (N_u); the short stream is then the
    // only sharer of f, so it gets credit for all of F.
    let (mut a, short, long) = setup();
    for k in long {
        a.set_priority(k, Priority::new(3, false).unwrap()).unwrap();
    }
    let s = a.streams.send_mut(short).unwrap();
    s.max_data = s.offset + (1 << 20);
    assert!(takes(&a, 2, short));
    // A non-incremental direction, served first come, takes the whole
    // level too (with credit for all of F, since it does not share f).
    let (mut a, short, _) = setup();
    a.set_priority(short, Priority::new(3, false).unwrap())
        .unwrap();
    let s = a.streams.send_mut(short).unwrap();
    s.max_data = s.offset + (1 << 20);
    assert!(takes(&a, 2, short));
    hooks(&mut a).no_ecf_share = true;
    assert!(takes(&a, 2, short));
}

/// BLEST's stream term takes F / n, the direction's share of the fast pipe
/// among the incremental directions of its level with data ready; the session's
/// credit and the reorder budget take all of F.
#[test]
fn blest_checks_the_streams_share_of_f_against_its_credit() {
    // F is about 440 KB: more than one stream's 256 KiB of credit, less
    // than a fifth of it times five.
    let (mut a, k) = two_pipes(Policy::SpreadEta, Some(FAST), 200_000);
    slow_second(&mut a, FAST / 4, 40 * MS);
    assert!(!takes(&a, 2, k));
    more_streams(&mut a, 4, 200_000);
    assert!(takes(&a, 2, k));
    // All of F against the stream's credit (`no_blest_share`).
    hooks(&mut a).no_blest_share = true;
    assert!(!takes(&a, 2, k));
    hooks(&mut a).no_blest_share = false;
    // A non-incremental direction does not share f: n = 1.
    a.set_priority(k, Priority::new(3, false).unwrap()).unwrap();
    assert!(!takes(&a, 2, k));
}

#[test]
fn bytes_wait_only_for_the_one_pipe_neither_suspect_nor_penalized() {
    // With two pipes that may carry the ready data neither is waited
    // for; a penalized pipe neither counts as a carrier nor is waited
    // for itself.
    let (mut a, _) = two_pipes(Policy::SpreadEta, Some(FAST), 1 << 20);
    assert!(!a.bytes_wait_for(0) && !a.bytes_wait_for(2));
    let mut out = TransmitBuf::default();
    let now = a.now;
    a.poll_transmit(PipeId(2), now, &mut out);
    assert!(!out.is_empty(), "pipe 2 took stream data");
    let i = a.att_index(2).unwrap();
    assert!(a.atts.at_mut(i).out_mut().unwrap().penalize().is_some());
    assert!(a.bytes_wait_for(0), "the only pipe that may carry the data");
    assert!(!a.bytes_wait_for(2), "a penalized pipe is not waited for");
}

/// T_suspect includes queue_p on a carrier that reports no unsent count:
/// the oldest ack-eliciting batch went out behind a batch whose write call
/// on another lane had not returned.
#[test]
fn t_suspect_includes_the_write_calls_in_progress_ahead() {
    let (mut a, _) = two_pipes(Policy::SpreadEta, Some(100_000), 0);
    let now = Instant::now();
    let mad = a.mp().peer_mad();
    let o = a.out_mut(2).unwrap();
    assert!(o.oldest_eliciting_batch().is_none());
    assert_eq!(o.request_lane(), 1);
    assert!(o.lane_attached(1, BS, now));
    o.lanes_mut().unwrap().wrote_first(1, 23);
    o.batch_sent(0, 50_000, 1, None);
    o.mp_batch_sent(0, false, mad, now);
    o.batch_sent(1, 1000, 1, Some(1000));
    o.mp_batch_sent(1, true, mad, now);
    let o = a.out_ref(2).unwrap();
    assert_eq!(o.oldest_eliciting_batch().unwrap().unsent_ahead, 50_000);
    let queue = Duration::from_secs_f64(50_000.0 / o.est().rate as f64).min(Duration::from_secs(1));
    assert!(queue >= 100 * MS, "{queue:?}");
    let pto = o.est().pto(mad);
    let floor = o.detection().0;
    let (t_suspect, t_fail, _) = a.limits(o);
    assert_eq!(t_suspect, floor.max((pto + queue) * 2));
    assert!(t_suspect > floor.max(pto * 2));
    assert_eq!(t_fail, Duration::from_secs(2).max((pto + queue) * 8));
}
