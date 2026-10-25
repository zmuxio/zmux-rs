//! Carrier lifecycle of multipath pipes, sans IO: every carrier half a core
//! was given is eventually closed by it — through `Transmit::Shutdown` or
//! `CoreEvent::ClosePipe` for an outbound half, `CoreEvent::ClosePipe` or the
//! carrier's own end for an inbound half — no later than the attachment's
//! retirement. A driver closes nothing else on its own while the session
//! lives, so a half the core forgets stays open (a thread, a task and a
//! socket) until the session ends.
//!
//! Seeded random runs of joins, graceful and abrupt removals by either end,
//! carrier failures, traffic and delivery orders; the invariant is checked
//! after every step and a failure names its seed (`ZMUX_SEED=<n>` replays
//! it, `ZMUX_SOAK=<k>` runs k times the seeds).

use std::collections::BTreeSet;
use std::time::Duration;

#[path = "common/basics.rs"]
mod basics;
#[path = "common/mp_net.rs"]
mod mp_net;

use basics::{Rng, seeds};
use mp_net::{A, B, MpNet};
use zmux::proto::frame::Dir;
use zmux::proto::session::{
    Config, CoreEvent, PipeAuth, PipeHalf, PipeId, PipeOptions, PipeState, StreamKey,
};

/// What the test saw besides the carriers.
struct Seen {
    /// Inbound halves each end closed (`ClosePipe`).
    in_closed: [BTreeSet<u64>; 2],
    /// Halves each end reported retired: (pipe, outbound).
    retired: [BTreeSet<(u64, bool)>; 2],
    streams: Vec<StreamKey>,
    rng: Rng,
    log: Vec<String>,
}

type Net = MpNet<(), Seen>;

fn config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"0123456789abcdef0123456789abcdef");
    c.max_idle_timeout = Duration::from_secs(60);
    c.suspect_floor = Duration::from_millis(100);
    c
}

fn net(seed: u64) -> Net {
    let mut b_cfg = config();
    b_cfg.test_hooks().locator = b"server".to_vec();
    let seen = Seen {
        in_closed: Default::default(),
        retired: Default::default(),
        streams: Vec::new(),
        rng: Rng::new(seed),
        log: Vec::new(),
    };
    let mut n = Net::new(config(), b_cfg, seen);
    for _ in 0..10 {
        n.step(usize::MAX);
    }
    n.observe();
    assert!(n.ends[A].is_multipath() && n.ends[B].is_multipath());
    n
}

impl Net {
    /// Takes every event of both ends.
    fn observe(&mut self) {
        self.handle_events();
        for side in [A, B] {
            let end = ["A", "B"][side];
            for e in self.events[side].drain(..) {
                match e {
                    CoreEvent::ClosePipe { pipe, half, abort } => {
                        let id = pipe.0;
                        self.s
                            .log
                            .push(format!("{end} {id} ClosePipe {half:?} abort={abort}"));
                        if half == PipeHalf::Inbound {
                            self.s.in_closed[side].insert(id);
                        }
                    }
                    CoreEvent::PipeState { pipe, half, state } => {
                        self.s
                            .log
                            .push(format!("{end} {} {half:?} {state:?}", pipe.0));
                        if state == PipeState::Retired {
                            self.s.retired[side].insert((pipe.0, half == PipeHalf::Outbound));
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// End `side` closed its half of pipe `id` (`outbound`: the sending
    /// one), or was told the carrier ended it.
    fn closed_half(&self, side: usize, id: u64, outbound: bool) -> bool {
        let Some(l) = self.links.get(&id) else {
            return false;
        };
        if outbound {
            let f = &l.flows[side];
            f.writer_closed || f.write_err_reported
        } else {
            self.s.in_closed[side].contains(&id) || l.flows[1 - side].end_reported
        }
    }

    /// A random operation.
    fn op(&mut self) {
        let live: Vec<u64> = self
            .links
            .keys()
            .copied()
            .filter(|&id| {
                self.ends[A]
                    .pipe_info(PipeId(id))
                    .is_some_and(|p| p.outbound.is_some())
            })
            .collect();
        let pick = |rng: &mut Rng, v: &[u64]| v[rng.below(v.len() as u64) as usize];
        match self.s.rng.below(12) {
            0 | 1 if live.len() < 4 => {
                if let Some(id) = self.add_pipe(&PipeOptions::default()) {
                    self.s.log.push(format!("add {id}"));
                }
            }
            2 if live.len() > 1 => {
                let id = pick(&mut self.s.rng, &live);
                let side = self.s.rng.below(2) as usize;
                let graceful = self.s.rng.below(3) > 0;
                self.s
                    .log
                    .push(format!("remove {id} side {side} graceful {graceful}"));
                let _ = self.ends[side].remove_pipe(PipeId(id), graceful, self.now);
            }
            3 if live.len() > 1 && self.s.rng.below(3) == 0 => {
                let id = pick(&mut self.s.rng, &live);
                self.s.log.push(format!("fail {id}"));
                self.fail(id);
            }
            4..=6 => {
                // Traffic: a new stream or more on an open one.
                let len = 1 + self.s.rng.below(64 * 1024) as usize;
                let data = vec![7u8; len];
                let k = match self.s.streams.len() {
                    n if n < 4 || self.s.rng.below(2) == 0 => {
                        let Ok(k) = self.ends[A].open(Dir::Uni) else {
                            return;
                        };
                        self.s.streams.push(k);
                        k
                    }
                    n => self.s.streams[self.s.rng.below(n as u64) as usize],
                };
                let _ = self.ends[A].write(k, &data);
                if self.s.rng.below(4) == 0 {
                    let _ = self.ends[A].finish(k);
                }
            }
            7 => {
                let ms = 1 + self.s.rng.below(400);
                self.advance(ms);
            }
            _ => {
                let limit = [64, 1500, 16 * 1024, usize::MAX][self.s.rng.below(4) as usize];
                self.step(limit);
            }
        }
        // B reads everything.
        while let Ok(Some(k)) = self.ends[B].accept(Dir::Uni) {
            let mut buf = vec![0u8; 64 * 1024];
            while let Ok(Some((n, fin))) = self.ends[B].read(k, &mut buf) {
                if fin || n == 0 {
                    break;
                }
            }
            self.ends[B].release(k);
        }
        self.observe();
    }

    /// Every retired half was closed.
    fn check(&self, seed: u64) {
        if !self.alive() {
            return;
        }
        for side in [A, B] {
            for &(id, outbound) in &self.s.retired[side] {
                if self.closed_half(side, id, outbound) {
                    continue;
                }
                let tag = format!(" {id} ");
                let history: Vec<&String> = self
                    .s
                    .log
                    .iter()
                    .filter(|l| format!(" {l} ").contains(&tag))
                    .collect();
                panic!(
                    "seed {seed}: {} retired pipe {id} without closing its {} half\n  pipe history: {history:?}\n  carrier: {:?}",
                    ["A", "B"][side],
                    if outbound { "outbound" } else { "inbound" },
                    self.links.get(&id).map(|l| &l.flows),
                );
            }
        }
    }
}

fn run(seed: u64, steps: usize) {
    let mut n = net(seed);
    for _ in 0..steps {
        n.op();
        n.check(seed);
        if !n.alive() {
            return;
        }
    }
    n.converge(seed);
}

impl Net {
    /// Once the churn stops, every attachment that failed or ended is
    /// retired: none holds its state for good (an exit
    /// path that never retires).
    fn converge(&mut self, seed: u64) {
        for _ in 0..200 {
            self.step(usize::MAX);
            self.advance(50);
            self.observe();
            if !self.alive() {
                return;
            }
        }
        self.check(seed);
        let ended = |s: Option<PipeState>| {
            matches!(
                s,
                Some(PipeState::Failed | PipeState::Closed | PipeState::Ended)
            )
        };
        for side in [A, B] {
            for p in self.ends[side].pipes() {
                assert!(
                    !ended(p.outbound) && !ended(p.inbound),
                    "seed {seed}: {} keeps pipe {} ({:?} / {:?}) after the churn",
                    ["A", "B"][side],
                    p.pipe.0,
                    p.outbound,
                    p.inbound,
                );
            }
        }
    }
}

/// Seeded random runs: every retired half was closed, a drained
/// outbound half too (its shutdown reported before the attachment retires
/// or fails).
#[test]
fn retired_pipes_close_their_carriers() {
    for seed in seeds(60) {
        run(seed, 300);
    }
}
