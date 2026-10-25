//! Deterministic simulation of the tokio driver (CONFORMANCE.md): a seeded
//! single-threaded runtime with a paused clock drives two
//! sessions over in-memory carriers with random API calls — opens,
//! accepts, writes, reads, finishes, resets, stops, dropped handles,
//! cancelled calls, datagrams, pings, carrier stalls and failures, pipes
//! joined and lost, GOAWAY and closes. After every step the invariants of
//! Section 4.4 that the API shows are checked; at the end every resource
//! returns to its baseline.
//!
//! A failure names its seed: `ZMUX_SEED=<n> cargo test --test sim` replays
//! it (with `ZMUX_SIM_LOG=1` it prints each step). `ZMUX_SOAK=<k>` runs
//! k times the seeds.

mod common;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use common::*;
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeHint, PipeOptions, RecvStream, SendStream,
    Session, StreamError, VarInt,
};

/// The byte at `off` of a stream direction.
fn pattern(id: u64, dir: usize, off: u64) -> u8 {
    (id.wrapping_mul(31) ^ (dir as u64).wrapping_mul(101) ^ off.wrapping_mul(7) ^ (off >> 8)) as u8
}

/// One direction of a stream.
#[derive(Default)]
struct Half {
    /// The writing end (A = 0, B = 1).
    writer: usize,
    send: Option<SendStream>,
    recv: Option<RecvStream>,
    written: u64,
    finished: bool,
    reset: bool,
    /// The reader stopped (or dropped) it: what follows is discarded.
    stopped: bool,
    read: u64,
    fin_seen: bool,
    reset_seen: bool,
}

struct Sim {
    seed: u64,
    rng: Rng,
    ends: [Session; 2],
    ctl: Vec<Arc<Ctl>>,
    /// (stream ID, direction): direction 0 is from the opener.
    halves: BTreeMap<(u64, usize), Half>,
    listener: Option<Listener>,
    pipes: Vec<(zmux::Pipe, Arc<Ctl>)>,
    shutdowns: Vec<tokio::task::JoinHandle<()>>,
    log: bool,
    step: usize,
}

fn config(multipath: bool, rng: &mut Rng) -> Config {
    let mut c = Config::default();
    c.enable_datagrams = true;
    c.max_idle_timeout = Duration::from_secs(5);
    c.max_incoming_streams = 4 + rng.below(5);
    c.max_incoming_uni_streams = Some(1 + rng.below(8));
    if rng.below(2) == 0 {
        c = small_windows(c);
    }
    // The values the core draws at random, fixed: a seed replays exactly.
    let h = c.test_hooks();
    h.grease_tp = zmux::proto::params::grease_id(5).map(|id| (id, vec![1, 2, 3]));
    h.grease_tlv = zmux::proto::payload::grease_tlv_type(3).map(|t| (t, vec![4]));
    h.ping_seq_start = Some(1000);
    h.session_nonce = Some([9; 16]);
    if multipath {
        c.test_hooks().locator = b"sim".to_vec();
        c.max_pipes = 4;
        c.pipe_auth = PipeAuth::psk(*b"sim-test-psk-0123456789abcdef!!!");
        c.suspect_floor = Duration::from_millis(100);
    }
    c
}

impl Sim {
    async fn new(seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let multipath = rng.below(3) == 0;
        let cfg = config(multipath, &mut rng);
        let (ends, ctl, listener) = if multipath {
            let listener = Listener::new(cfg.clone(), ListenerConfig::default());
            let ((a, ca), (b, _)) = duplex(1 << (12 + rng.below(6)));
            let l = listener.clone();
            tokio::spawn(async move {
                let _ = l.handle_pipe(b, PipeHint::default()).await;
            });
            let client = Session::connect(a, cfg).await.expect("connect");
            let server = listener.accept().await.expect("server session");
            ([client, server], vec![ca], Some(listener))
        } else {
            let ((a, ca), (b, cb)) = duplex(1 << (12 + rng.below(6)));
            let (c, s) = connect(a, b, cfg.clone(), cfg).await;
            ([c, s], vec![ca, cb], None)
        };
        Self {
            seed,
            rng,
            ends,
            ctl,
            halves: BTreeMap::new(),
            listener,
            pipes: Vec::new(),
            shutdowns: Vec::new(),
            log: std::env::var("ZMUX_SIM_LOG").is_ok(),
            step: 0,
        }
    }

    fn note(&self, what: impl FnOnce() -> String) {
        if self.log {
            eprintln!("seed {} step {}: {}", self.seed, self.step, what());
        }
    }

    /// A random short timeout: some calls complete, some are cancelled.
    fn timeout(&mut self) -> Duration {
        Duration::from_micros([0, 10, 500, 3000, 20_000][self.rng.below(5) as usize])
    }

    /// Picks a half matching `f`.
    fn pick(&mut self, f: impl Fn(&Half) -> bool) -> Option<(u64, usize)> {
        let keys: Vec<(u64, usize)> = self
            .halves
            .iter()
            .filter(|(_, h)| f(h))
            .map(|(k, _)| *k)
            .collect();
        (!keys.is_empty()).then(|| keys[self.rng.below(keys.len() as u64) as usize])
    }

    async fn op(&mut self) {
        self.step += 1;
        match self.rng.below(100) {
            0..=9 => self.open().await,
            10..=19 => self.accept().await,
            20..=39 => self.write().await,
            40..=59 => self.read().await,
            60..=63 => {
                if let Some(k) = self.pick(|h| h.send.is_some() && !h.finished && !h.reset) {
                    self.note(|| format!("finish {k:?}"));
                    let h = self.halves.get_mut(&k).unwrap();
                    if h.send.as_mut().unwrap().finish().is_ok() {
                        h.finished = true;
                    }
                }
            }
            64..=66 => {
                if let Some(k) = self.pick(|h| h.send.is_some() && !h.finished && !h.reset) {
                    self.note(|| format!("reset {k:?}"));
                    let h = self.halves.get_mut(&k).unwrap();
                    if h.send.as_mut().unwrap().reset(VarInt::from_u32(7)).is_ok() {
                        h.reset = true;
                    }
                }
            }
            67..=68 => {
                if let Some(k) = self.pick(|h| h.recv.is_some()) {
                    self.note(|| format!("stop {k:?}"));
                    let h = self.halves.get_mut(&k).unwrap();
                    let _ = h.recv.as_mut().unwrap().stop(VarInt::from_u32(8));
                    h.recv = None;
                    h.stopped = true;
                }
            }
            69..=71 => {
                // Handles dropped: a sending part without finish resets.
                if let Some(k) = self.pick(|h| h.send.is_some() || h.recv.is_some()) {
                    self.note(|| format!("drop {k:?}"));
                    let h = self.halves.get_mut(&k).unwrap();
                    if h.send.take().is_some() && !h.finished {
                        h.reset = true;
                    }
                    if h.recv.take().is_some() {
                        h.stopped = true;
                    }
                }
            }
            72..=75 => {
                let side = self.rng.below(2) as usize;
                let len = 1 + self.rng.below(1000) as usize;
                let d = Bytes::from(vec![len as u8; len]);
                let _ = self.ends[side].send_datagram(d);
            }
            76..=78 => {
                let side = self.rng.below(2) as usize;
                let t = self.timeout();
                if let Ok(Ok(d)) = tokio::time::timeout(t, self.ends[side].read_datagram()).await {
                    assert!(
                        d.iter().all(|&b| b == d.len() as u8),
                        "seed {}: datagram corrupted",
                        self.seed
                    );
                }
            }
            79 => {
                // Polled once: the request goes out, the wait is dropped.
                let ping = self.ends[self.rng.below(2) as usize].ping();
                let _ = tokio::time::timeout(Duration::ZERO, ping).await;
            }
            80..=86 => {
                let ms = [1, 10, 100, 700][self.rng.below(4) as usize];
                self.note(|| format!("sleep {ms} ms"));
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            87..=88 => {
                // A carrier stalls for a while.
                let i = self.rng.below(self.ctl.len() as u64) as usize;
                let ctl = self.ctl[i].clone();
                let ms = self.rng.below(800);
                self.note(|| format!("stall carrier {i} for {ms} ms"));
                ctl.stall(true);
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    ctl.stall(false);
                });
            }
            89..=92 if self.listener.is_some() => self.pipe_op().await,
            93 if self.rng.below(40) == 0 => {
                let side = self.rng.below(2) as usize;
                self.note(|| format!("shutdown side {side}"));
                let s = self.ends[side].clone();
                self.shutdowns.push(tokio::spawn(async move {
                    let _ = s.shutdown(VarInt::from_u32(0), b"").await;
                }));
            }
            94 if self.rng.below(20) == 0 => {
                let i = self.rng.below(self.ctl.len() as u64) as usize;
                self.note(|| format!("fail carrier {i}"));
                self.ctl[i].fail();
            }
            95 if self.rng.below(30) == 0 => {
                let side = self.rng.below(2) as usize;
                self.note(|| format!("close side {side}"));
                self.ends[side].close(VarInt::from_u32(3), b"sim");
            }
            _ => tokio::task::yield_now().await,
        }
        self.check();
    }

    async fn open(&mut self) {
        let side = self.rng.below(2) as usize;
        let bidi = self.rng.below(2) == 0;
        let t = self.timeout();
        let s = &self.ends[side];
        let opened = if bidi {
            match tokio::time::timeout(t, s.open_bi()).await {
                Ok(Ok((send, recv))) => Some((send, Some(recv))),
                _ => None,
            }
        } else {
            match tokio::time::timeout(t, s.open_uni()).await {
                Ok(Ok(send)) => Some((send, None)),
                _ => None,
            }
        };
        let Some((send, recv)) = opened else {
            return;
        };
        // Pinning the identifier sends the opening frame.
        let Ok(id) = send.pin_id() else {
            return;
        };
        let id = id.into_inner();
        self.note(|| format!("open {id} side {side} bidi {bidi}"));
        self.halves.insert(
            (id, 0),
            Half {
                writer: side,
                send: Some(send),
                ..Half::default()
            },
        );
        if let Some(recv) = recv {
            self.halves.insert(
                (id, 1),
                Half {
                    writer: 1 - side,
                    recv: Some(recv),
                    ..Half::default()
                },
            );
        }
    }

    async fn accept(&mut self) {
        let side = self.rng.below(2) as usize;
        let t = self.timeout();
        let s = &self.ends[side];
        if self.rng.below(2) == 0 {
            if let Ok(Ok((send, recv))) = tokio::time::timeout(t, s.accept_bi()).await {
                let id = recv.pin_id().expect("accepted id").into_inner();
                self.note(|| format!("accept bi {id} side {side}"));
                let h = self.halves.entry((id, 0)).or_default();
                h.recv = Some(recv);
                let h = self.halves.entry((id, 1)).or_default();
                h.writer = side;
                h.send = Some(send);
            }
        } else if let Ok(Ok(recv)) = tokio::time::timeout(t, s.accept_uni()).await {
            let id = recv.pin_id().expect("accepted id").into_inner();
            self.note(|| format!("accept uni {id} side {side}"));
            self.halves.entry((id, 0)).or_default().recv = Some(recv);
        }
    }

    async fn write(&mut self) {
        let Some(k) = self.pick(|h| h.send.is_some() && !h.finished && !h.reset) else {
            return;
        };
        let len = 1 + self.rng.below(40 * 1024);
        let t = self.timeout();
        let h = self.halves.get_mut(&k).unwrap();
        let data: Vec<u8> = (h.written..h.written + len)
            .map(|o| pattern(k.0, k.1, o))
            .collect();
        let send = h.send.as_mut().unwrap();
        // Cancel-safe: a write that times out wrote nothing.
        if let Ok(Ok(n)) = tokio::time::timeout(t, send.write(&data)).await {
            h.written += n as u64;
        }
    }

    async fn read(&mut self) {
        let Some(k) = self.pick(|h| h.recv.is_some()) else {
            return;
        };
        let t = self.timeout();
        let seed = self.seed;
        let size = 1 + self.rng.below(32 * 1024) as usize;
        let reads = 1 + self.rng.below(8);
        for _ in 0..reads {
            let h = self.halves.get_mut(&k).unwrap();
            let mut buf = vec![0u8; size];
            let Some(recv) = h.recv.as_mut() else {
                return;
            };
            let Ok(r) = tokio::time::timeout(t, recv.read(&mut buf)).await else {
                return;
            };
            Self::got(seed, k, h, r, &buf);
        }
    }

    /// Checks what a read returned against what was written.
    fn got(
        seed: u64,
        k: (u64, usize),
        h: &mut Half,
        r: Result<Option<usize>, StreamError>,
        buf: &[u8],
    ) {
        match r {
            Ok(Some(n)) => {
                for (i, &b) in buf[..n].iter().enumerate() {
                    let off = h.read + i as u64;
                    assert_eq!(
                        b,
                        pattern(k.0, k.1, off),
                        "seed {seed}: stream {k:?} byte {off} wrong (lost, duplicated or reordered data)"
                    );
                }
                h.read += n as u64;
            }
            Ok(None) => {
                h.fin_seen = true;
                h.recv = None;
            }
            Err(StreamError::Reset { .. }) => {
                h.reset_seen = true;
                h.recv = None;
            }
            Err(_) => h.recv = None,
        }
    }

    async fn pipe_op(&mut self) {
        let listener = self.listener.clone().expect("multipath");
        match self.rng.below(3) {
            0 if self.pipes.len() < 3 => {
                let ((a, ca), (b, _)) = duplex(1 << (12 + self.rng.below(6)));
                tokio::spawn(async move {
                    let _ = listener.handle_pipe(b, PipeHint::default()).await;
                });
                if let Ok(p) = self.ends[0].add_pipe(a, PipeOptions::default()) {
                    self.note(|| format!("add pipe {}", p.id()));
                    self.ctl.push(ca.clone());
                    self.pipes.push((p, ca));
                }
            }
            1 if !self.pipes.is_empty() => {
                let i = self.rng.below(self.pipes.len() as u64) as usize;
                let (p, ctl) = self.pipes.swap_remove(i);
                self.note(|| format!("fail pipe {}", p.id()));
                ctl.fail();
            }
            2 if !self.pipes.is_empty() => {
                let i = self.rng.below(self.pipes.len() as u64) as usize;
                let (p, _) = self.pipes.swap_remove(i);
                self.note(|| format!("abort pipe {}", p.id()));
                let _ = p.abort();
            }
            _ => {}
        }
    }

    /// The invariants of CONFORMANCE.md Section 4.3 the API shows.
    fn check(&self) {
        let seed = self.seed;
        for (k, h) in &self.halves {
            assert!(
                h.read <= h.written,
                "seed {seed}: stream {k:?} read {} of {} written",
                h.read,
                h.written
            );
            if h.fin_seen {
                assert!(
                    h.finished && !h.reset && h.read == h.written,
                    "seed {seed}: stream {k:?} complete with {} of {} bytes (finished {}, reset {})",
                    h.read,
                    h.written,
                    h.finished,
                    h.reset
                );
                assert!(
                    !h.reset_seen,
                    "seed {seed}: stream {k:?} both complete and reset"
                );
            }
        }
        for s in &self.ends {
            let st = s.stats();
            if s.multipath() != zmux::Multipath::InUse {
                assert_eq!(
                    st.retained, 0,
                    "seed {seed}: retained data without multipath"
                );
            }
            let t = s.debug_tables();
            // Every call of this harness ends before the next: only the
            // shutdowns wait.
            assert!(
                t.waits <= self.shutdowns.len(),
                "seed {seed}: {} waits registered: {t:?}",
                t.waits
            );
            assert!(t.pipe_events <= 256, "seed {seed}: pipe events unbounded");
        }
    }

    /// Ends both sessions and checks every resource is released.
    async fn finish(mut self, base: Snapshot) {
        if std::env::var("ZMUX_SIM_STATS").is_ok() {
            let h = self.halves.values();
            eprintln!(
                "seed {}: mp {} streams {} bytes read {} fin {} reset {} state {:?}/{:?}",
                self.seed,
                self.listener.is_some(),
                self.halves.len(),
                h.clone().map(|h| h.read).sum::<u64>(),
                h.clone().filter(|h| h.fin_seen).count(),
                h.filter(|h| h.reset_seen).count(),
                self.ends[0].close_reason(),
                self.ends[1].close_reason(),
            );
        }
        for s in &self.ends {
            s.close(VarInt::from_u32(0), b"end");
        }
        for s in &self.ends {
            watchdog(30, "closed", s.closed()).await;
        }
        for h in self.shutdowns.drain(..) {
            watchdog(30, "shutdown", h).await.unwrap();
        }
        if let Some(l) = self.listener.take() {
            l.close();
        }
        let seed = self.seed;
        drop(self);
        settle(base, 30, &format!("seed {seed}: end")).await;
    }
}

#[test]
fn deterministic_simulation() {
    for seed in seeds(48) {
        paused(async move {
            let base = snapshot();
            let mut sim = Sim::new(seed).await;
            for _ in 0..300 {
                watchdog(120, &format!("seed {seed}: step"), sim.op()).await;
            }
            sim.finish(base).await;
        });
    }
}
