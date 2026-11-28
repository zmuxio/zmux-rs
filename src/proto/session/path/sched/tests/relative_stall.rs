use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::{BS, MS, config, join, pump};
use crate::proto::frame::Dir;
use crate::proto::listener::{ListenerConfig, ListenerCore};
use crate::proto::seal::RecordMode;
use crate::proto::session::estimator::ReplayEstimates;
use crate::proto::session::pipes::{DirectionState, OutPipe};
use crate::proto::session::{
    CoreEvent, OutboundState, PipeEnd, PipeHalf, PipeHealthReason, PipeId, PipeOptions, PipeWrite,
    Role, Scheduler, SessionCore, StreamKey, TransmitBuf,
};
use std::time::{Duration, Instant};

fn us(value: &Value) -> Duration {
    Duration::from_micros(value.as_u64().expect("microseconds"))
}

struct Replay {
    core: SessionCore,
    start: Instant,
    now: Instant,
    ids: BTreeMap<String, PipeId>,
    positions: BTreeMap<String, (PipeId, u64)>,
    prefix: Option<StreamKey>,
    events: Vec<Value>,
    member_faults: BTreeMap<PipeId, u64>,
    base_probes: BTreeMap<PipeId, u64>,
    base_suspects: BTreeMap<PipeId, u64>,
}

impl Replay {
    fn new(setup: &Value) -> Self {
        let resume = setup["resume"].as_bool().unwrap_or(true);
        let idle = setup
            .get("idle_timeout_us")
            .map_or(Duration::from_secs(30), us);
        let pipes = setup["pipes"].as_array().unwrap();
        let mut cfg = config(Scheduler::SessionAffinity);
        cfg.liveness.probe_interval = None;
        cfg.liveness.standby_probe = None;
        cfg.liveness.keep_alive_period = None;
        cfg.redundancy = crate::Redundancy::Off;
        cfg.probation = Some(crate::Cap::Fixed(Duration::from_secs(2)));
        cfg.max_idle_timeout = Some(idle);
        cfg.resume_timeout = resume.then_some(Duration::from_secs(30));
        cfg.hooks.unpaced = true;
        cfg.hooks.no_first_ping = true;
        cfg.hooks.probe_seed = Some(0);
        cfg.hooks.session_nonce = Some([1; 16]);
        cfg.hooks.role_nonce = Some(1);
        cfg.hooks.ping_seq_start = Some(1);
        cfg.hooks.grease_tlv = Some((0x21, Vec::new()));
        let start = Instant::now();
        let mut core = SessionCore::new(cfg.clone(), Role::Client, None, start).unwrap();
        cfg.locator = b"server".to_vec();
        cfg.hooks.session_nonce = Some([2; 16]);
        cfg.hooks.role_nonce = Some(2);
        let mut peer = SessionCore::new(cfg, Role::Server, None, start).unwrap();
        let mut listener = ListenerCore::new(ListenerConfig::default());
        core.attach_pipe(PipeId(0), BS, start);
        peer.attach_pipe(PipeId(0), BS, start);
        pump(&mut core, &mut peer, &[0], start);
        let mut ids = BTreeMap::from([("p".into(), PipeId(0))]);
        for pipe in &pipes[1..] {
            let id = core
                .add_pipe(
                    Some(BS),
                    Some(BS),
                    &PipeOptions::default(),
                    RecordMode::Trusted,
                    None,
                    start,
                )
                .unwrap();
            join(&mut core, &mut peer, &mut listener, id, start);
            ids.insert(pipe["id"].as_str().unwrap().into(), id);
        }
        let pipe_ids: Vec<_> = ids.values().map(|id| id.get()).collect();
        // Drive real confirmation and probe ACKs until both directions
        // finish initial probation and Settle.
        for tick in 0..=240 {
            let now = start + 25 * MS * tick;
            if tick == 10 {
                for &id in &pipe_ids {
                    core.out_mut(id).unwrap().want_ping(now);
                }
            }
            core.handle_timeout(now);
            peer.handle_timeout(now);
            pump(&mut core, &mut peer, &pipe_ids, now);
        }
        let start = start + Duration::from_secs(6);
        let mut replay = Self {
            core,
            start,
            now: start,
            ids,
            positions: BTreeMap::new(),
            prefix: None,
            events: Vec::new(),
            member_faults: BTreeMap::new(),
            base_probes: BTreeMap::new(),
            base_suspects: BTreeMap::new(),
        };
        assert_eq!(
            replay.core.mp().peer_mad(),
            us(&setup["peer_max_ack_delay_us"])
        );
        for pipe in pipes {
            let id = replay.id(&pipe["id"]);
            assert!(
                replay.core.pipe_health(id).unwrap().send.settled,
                "{:?}",
                replay.core.pipe_health(id)
            );
            replay
                .base_probes
                .insert(id, replay.core.out_ref(id.get()).unwrap().pings_sent());
            replay
                .base_suspects
                .insert(id, replay.core.pipe_info(id).unwrap().suspect_count);
            replay.estimates(id, pipe);
        }
        replay
    }

    fn id(&self, name: &Value) -> PipeId {
        self.ids[name.as_str().unwrap()]
    }

    fn estimates(&mut self, id: PipeId, args: &Value) {
        let srtt = us(&args["srtt_us"]);
        let jitter = us(&args["rttvar_us"]);
        let eta = us(&args["eta_us"]);
        let est = self.core.out_mut(id.get()).unwrap().est_mut();
        est.srtt = srtt;
        est.rttvar = jitter;
        let deviation = args
            .get("deviation_us")
            .map_or_else(|| est.replay.map_or(jitter, |prior| prior.deviation), us);
        est.replay = Some(ReplayEstimates {
            srtt,
            rttvar: jitter,
            eta,
            deviation,
        });
        self.core.views_changed();
    }

    fn collect_health(&mut self) {
        let mut reason = BTreeMap::new();
        while let Some(ev) = self.core.poll_event() {
            match ev {
                CoreEvent::PipeHealthChanged(change) if change.half == PipeHalf::Outbound => {
                    if change.reason.is_fault() && !change.before.reason.is_fault() {
                        *self.member_faults.entry(change.pipe).or_default() += 1;
                    }
                    reason.insert(change.pipe, change.reason);
                }
                CoreEvent::PipeState {
                    pipe,
                    state: DirectionState::Outbound(state),
                    previous,
                } if previous != Some(state) => {
                    let name = match (state, previous) {
                        (OutboundState::Suspect, _) => "PipeSuspect",
                        (OutboundState::Failed, _) => "PipeFailed",
                        (OutboundState::Active, Some(OutboundState::Suspect)) => "PipeRecovered",
                        _ => continue,
                    };
                    let label = self.ids.iter().find(|(_, id)| **id == pipe).unwrap().0;
                    let mut event = json!({"name":name, "pipe":label, "at_us":self.now.duration_since(self.start).as_micros()});
                    if name != "PipeRecovered" {
                        event["reason"] = json!(match reason[&pipe] {
                            PipeHealthReason::AckStall => "ack_stalled",
                            PipeHealthReason::WriteStall => "write_stalled",
                            PipeHealthReason::UnexpectedEof => "unexpected_eof",
                            other => panic!("unexpected reason {other:?}"),
                        });
                    }
                    self.events.push(event);
                }
                _ => {}
            }
        }
    }

    fn handoff(&mut self, id: PipeId) -> bool {
        let mut tx = TransmitBuf::default();
        let opt = self.core.mp().counters.bytes_opportunistic;
        let prior = self.core.out_ref(id.get()).map_or(0, OutPipe::sent);
        self.core.poll_transmit(id, self.now, &mut tx);
        self.core.pipe_written(id, tx.stream_len(), self.now);
        let new = self.core.out_ref(id.get()).map_or(0, OutPipe::sent);
        if let Some(key) = self.prefix
            && self.positions.contains_key("s")
            && let Some(copy) = self.core.streams.send(key).unwrap().mp().copies.back()
            && copy.pipe == id.get()
            && copy.pos > prior
            && copy.pos <= new
        {
            let source = self.positions["s"].0;
            let mode = if self.core.mp().counters.bytes_opportunistic > opt {
                "opportunistic"
            } else if self.core.pipe_state(source, PipeHalf::Outbound)
                == Some(DirectionState::Outbound(OutboundState::Suspect))
            {
                "suspect_reinjection"
            } else {
                "failure_reinjection"
            };
            let label = self.ids.iter().find(|(_, pipe)| **pipe == id).unwrap().0;
            self.events.push(json!({
                "name":"PrefixDispatched", "stream":"s", "pipe":label,
                "at_us":self.now.duration_since(self.start).as_micros(),
                "length":copy.end-copy.off, "mode":mode,
            }));
            self.positions.insert("copy".into(), (id, copy.pos));
        }
        new > prior
    }

    fn quiesce(&mut self) {
        self.core.handle_timeout(self.now);
        self.collect_health();
        for _ in 0..32 {
            let mut progressed = false;
            for id in self.ids.values().copied().collect::<Vec<_>>() {
                if self.core.wants_write(id) {
                    progressed |= self.handoff(id);
                    self.collect_health();
                }
            }
            if !progressed {
                return;
            }
        }
        panic!("replay did not quiesce");
    }

    fn advance(&mut self, to: Instant) {
        while let Some(t) = self.core.poll_timeout().filter(|&t| t < to) {
            assert!(t >= self.now, "timer reverted: {t:?} < {:?}", self.now);
            self.now = t;
            self.quiesce();
            assert_ne!(
                self.core.poll_timeout(),
                Some(t),
                "timer did not consume deadline"
            );
        }
        self.now = to;
        self.core.tick(to);
    }

    fn ack(&mut self, id: PipeId, record: &str, through_probe: bool) {
        let (pipe, mut pos) = self.positions[record];
        assert_eq!(pipe, id);
        if through_probe {
            pos = self.core.out_ref(id.get()).unwrap().sent();
        }
        self.core.rx = id.get();
        self.core
            .process_ack(id.get(), 0, pos, Duration::ZERO, self.now);
    }

    fn input(&mut self, step: &Value) {
        let args = &step["args"];
        let action = step["action"].as_str().unwrap();
        if action == "open_stream_with_prefix" {
            let id = self.id(&args["source"]);
            let preamble = crate::Preamble::new().with_info(bytes::Bytes::from_static(b"open"));
            let key = self.core.open_with(Dir::Bidi, &preamble).unwrap();
            self.core.set_redundant(key, Some(false)).unwrap();
            let len = args["prefix_bytes"].as_u64().unwrap();
            let app = usize::try_from(len).unwrap() - self.core.preamble_len(key);
            assert_eq!(self.core.write(key, &vec![42; app]).unwrap(), app);
            for backup in self.ids.values().copied().filter(|&pipe| pipe != id) {
                self.core.set_pipe_send_standby(backup, Some(true)).unwrap();
            }
            let queue = us(&args["queue_delay_us"]);
            let rate = self.core.out_ref(id.get()).unwrap().est().rate;
            self.core.set_pipe_unsent(
                id,
                u64::try_from(queue.as_micros()).unwrap() * rate / 1_000_000,
                self.now,
            );
            assert!(self.handoff(id));
            for backup in self.ids.values().copied().filter(|&pipe| pipe != id) {
                self.core.set_pipe_send_standby(backup, None).unwrap();
            }
            self.core.set_pipe_unsent(id, 0, self.now);
            self.prefix = Some(key);
            self.positions.insert(
                "s".into(),
                (id, self.core.out_ref(id.get()).unwrap().sent()),
            );
            assert_eq!(self.core.streams.send(key).unwrap().offset, len);
            return;
        }
        let id = self.id(&step["target"]);
        match action {
            "path_estimator_inputs" => self.estimates(id, args),
            "handoff_ack_eliciting" => {
                self.core.out_mut(id.get()).unwrap().want_ping(self.now);
                assert!(self.handoff(id));
                self.positions.insert(
                    args["record"].as_str().unwrap().into(),
                    (id, self.core.out_ref(id.get()).unwrap().sent()),
                );
            }
            "ack_record" | "ack_record_and_recovery_probe" => {
                self.ack(
                    id,
                    args["record"].as_str().unwrap(),
                    action == "ack_record_and_recovery_probe",
                );
            }
            "ack_prefix_copy" => {
                assert_eq!(args["stream"], "s");
                self.ack(id, "copy", false);
            }
            "unexpected_eof" => self.core.pipe_ended(id, PipeEnd::Eof, self.now),
            "set_writer_ready" => {
                self.core.pipe_write(
                    id,
                    PipeWrite::returned(
                        self.now,
                        self.now,
                        0,
                        0,
                        !args["ready"].as_bool().unwrap(),
                    ),
                    self.now,
                );
            }
            _ => panic!("unhandled input {action}"),
        }
    }
}

fn slow_prefix_setup() -> Value {
    json!({
        "peer_max_ack_delay_us": 25_000,
        "pipes": [
            {"id":"p", "srtt_us":6_000_000, "rttvar_us":118_750, "eta_us":3_100_000},
            {"id":"q", "srtt_us":80_000, "rttvar_us":3_750, "eta_us":55_000}
        ],
    })
}

fn three_paths() -> Value {
    let mut setup = slow_prefix_setup();
    setup["pipes"].as_array_mut().unwrap().push(json!({
        "id":"r", "srtt_us":100_000, "rttvar_us":6_250, "eta_us":35_000
    }));
    setup
}

fn open_prefix(replay: &mut Replay) {
    replay.input(&json!({
        "action":"open_stream_with_prefix",
        "args":{"source":"p", "prefix_bytes":16, "queue_delay_us":0}
    }));
}

fn probe(replay: &mut Replay, pipe: &str, record: &str) {
    replay.input(&json!({
        "target":pipe, "action":"handoff_ack_eliciting", "args":{"record":record}
    }));
}

#[test]
fn relative_stall_and_repair_rank_different_paths_with_queued_bytes() {
    let mut replay = Replay::new(&three_paths());
    let p = replay.ids["p"];
    let q = replay.ids["q"];
    let r = replay.ids["r"];
    open_prefix(&mut replay);
    probe(&mut replay, "q", "q1");
    probe(&mut replay, "r", "r1");
    replay.advance(replay.start + MS * 80);
    replay.ack(q, "q1", false);
    replay.ack(r, "r1", false);
    let rate = replay.core.out_ref(q.get()).unwrap().est().rate;
    replay.core.set_pipe_unsent(q, rate * 15 / 1000, replay.now);
    probe(&mut replay, "q", "q2");
    replay.core.set_pipe_unsent(q, 0, replay.now);
    let out = replay.core.out_ref(p.get()).unwrap();
    assert_eq!(
        replay.core.suspect_deadline(p.get(), out, true, replay.now),
        Some((replay.start + MS * 405, PipeHealthReason::AckStall))
    );
    replay.quiesce();
    replay.advance(replay.start + MS * 110);
    replay.quiesce();
    assert_eq!(replay.events[0]["pipe"], "r");
    assert_eq!(replay.events[0]["mode"], "opportunistic");
}

#[test]
fn relative_stall_drops_a_reference_with_a_same_cut_write_stall() {
    let mut replay = Replay::new(&slow_prefix_setup());
    let (p, q) = (replay.ids["p"], replay.ids["q"]);
    open_prefix(&mut replay);
    probe(&mut replay, "q", "q1");
    replay.advance(replay.start + MS * 80);
    replay.ack(q, "q1", false);
    replay.quiesce();
    replay.advance(replay.start + MS * 110);
    replay
        .core
        .pipe_write(q, PipeWrite::started(replay.now, 0), replay.now);
    replay.quiesce();
    // A recent proof keeps q in the window at p's 360 ms deadline.
    replay.advance(replay.start + MS * 200);
    probe(&mut replay, "q", "q2");
    replay.advance(replay.start + MS * 280);
    replay.ack(q, "q2", false);
    replay.quiesce();
    replay.advance(replay.start + MS * 360);
    replay.quiesce();
    let q = replay.core.pipe_health(q).unwrap();
    assert_eq!(q.send.reason, PipeHealthReason::WriteStall);
    assert_eq!(
        replay.core.pipe_state(p, PipeHalf::Outbound),
        Some(DirectionState::Outbound(OutboundState::Active))
    );
}

#[test]
fn relative_stall_repair_is_reused_until_its_own_destination_fails() {
    let mut replay = Replay::new(&three_paths());
    let (p, q, r) = (replay.ids["p"], replay.ids["q"], replay.ids["r"]);
    open_prefix(&mut replay);
    probe(&mut replay, "q", "q1");
    replay.advance(replay.start + MS * 80);
    replay.ack(q, "q1", false);
    replay.quiesce();
    replay.advance(replay.start + MS * 120);
    replay.quiesce();
    assert_eq!(replay.positions["copy"].0, q);
    replay.advance(replay.start + MS * 150);
    replay.core.pipe_ended(p, PipeEnd::Eof, replay.now);
    replay.quiesce();
    assert_eq!(
        replay.events.len(),
        2,
        "source failure must reuse the outstanding copy"
    );
    replay.advance(replay.start + MS * 180);
    replay.core.pipe_ended(q, PipeEnd::Eof, replay.now);
    replay.quiesce();
    assert_eq!(replay.positions["copy"].0, r);
    assert_eq!(replay.events.len(), 4);
    assert_eq!(replay.events[3]["mode"], "failure_reinjection");
}

#[test]
fn relative_stall_requires_a_live_ack_return_and_uses_the_local_write_limit() {
    let mut replay = Replay::new(&slow_prefix_setup());
    let p = replay.ids["p"];
    open_prefix(&mut replay);
    let o = replay.core.out_ref(p.get()).unwrap();
    assert_eq!(
        replay.core.suspect_deadline(p.get(), o, false, replay.now),
        None
    );
    replay
        .core
        .pipe_write(p, PipeWrite::started(replay.now, 0), replay.now);
    let o = replay.core.out_ref(p.get()).unwrap();
    let due = replay.start + Duration::from_secs(13);
    assert_eq!(
        replay.core.suspect_deadline(p.get(), o, false, replay.now),
        Some((due, PipeHealthReason::WriteStall))
    );
    assert_eq!(
        replay.core.suspect_deadline(p.get(), o, true, replay.now),
        Some((due, PipeHealthReason::AckStall))
    );
}

#[test]
fn relative_stall_prefix_waits_for_copy_budget_and_keeps_its_cap() {
    let mut replay = Replay::new(&slow_prefix_setup());
    let q = replay.ids["q"];
    let reserved = replay.core.open(Dir::Bidi).unwrap();
    let budget = replay.core.copy_bound();
    replay
        .core
        .streams
        .send_mut(reserved)
        .unwrap()
        .mp_mut()
        .copy(0, budget);
    open_prefix(&mut replay);
    probe(&mut replay, "q", "q1");
    replay.advance(replay.start + MS * 80);
    replay.ack(q, "q1", false);
    replay.quiesce();
    assert_eq!(replay.core.opp_deadline(), Some(replay.start + MS * 120));
    replay.advance(replay.start + MS * 120);
    replay.quiesce();
    assert_eq!(replay.events, [] as [Value; 0]);
    assert_eq!(replay.core.opp_deadline(), None);
    replay.advance(replay.start + MS * 150);
    replay
        .core
        .streams
        .send_mut(reserved)
        .unwrap()
        .mp_mut()
        .uncopy(0, budget);
    replay.quiesce();
    assert_eq!(replay.events.len(), 1);
    assert_eq!(replay.events[0]["at_us"], 150_000);
}

#[test]
fn relative_stall_scheduling_penalty_preserves_health_and_stable_coverage() {
    let mut replay = Replay::new(&slow_prefix_setup());
    let p = replay.ids["p"];
    open_prefix(&mut replay);
    let before = replay.core.pipe_health(p).unwrap();
    let covered = replay.core.coverage_except(&[]);
    replay.core.out_mut(p.get()).unwrap().penalize().unwrap();
    replay.core.sync_pipe_health(p.get());
    let after = replay.core.pipe_health(p).unwrap();
    assert_eq!(before.send, after.send);
    assert!(before.eligible_for_new_data);
    assert!(!after.eligible_for_new_data);
    assert_eq!(replay.core.coverage_except(&[]), covered);
    replay.collect_health();
    assert_eq!(replay.events, [] as [Value; 0]);
    assert!(replay.member_faults.is_empty());
}

#[test]
fn relative_stall_repair_uses_the_frozen_source_confirmation_deadline() {
    let mut setup = slow_prefix_setup();
    let slow = setup["pipes"][0].clone();
    setup["pipes"][0] = json!({
        "id":"p", "srtt_us":50_000, "rttvar_us":5_000, "eta_us":40_000, "deviation_us":0
    });
    let mut replay = Replay::new(&setup);
    let (p, q) = (replay.ids["p"], replay.ids["q"]);
    open_prefix(&mut replay);
    probe(&mut replay, "q", "q1");
    replay.advance(replay.start + MS * 40);
    replay.estimates(p, &slow);
    replay.advance(replay.start + MS * 80);
    replay.ack(q, "q1", false);
    replay.quiesce();
    assert_eq!(replay.core.opp_deadline(), Some(replay.start + MS * 90));
    replay.advance(replay.start + MS * 90);
    replay.quiesce();
    assert_eq!(replay.events[0]["mode"], "opportunistic");
    assert_eq!(replay.events[0]["at_us"], 90_000);
}

// Loaded with include! so rustfmt does not require the development-only file.
#[cfg(zmux_dev_contracts)]
mod vectors {
    include!("relative_stall_vectors.rs");
}
