//! The CPU cost of the multipath scheduler with many streams, sans IO: two
//! cores joined by in-memory pipes of fixed rate and delay, the sender
//! keeping every stream's send buffer full. Reports the sender's time per
//! STREAM frame it writes (the chunk decisions, with everything else
//! `wants_write` and `poll_transmit` do) and per PIPE_ACK it processes,
//! and the receiver's time per MB of stream data: its reads of the pipes
//! into read buffers of 128 KiB that received data references, as the
//! driver's, and apart the application's reads (`MPSCHED_RECV=copy`: received
//! data copied, `SessionCore::receive`).
//!
//! Run: `cargo bench --bench mpsched [-- <policy>...]` with `eta`,
//! `affinity`, `session-affinity`; `MPSCHED_STREAMS` (default 1000),
//! `MPSCHED_STEPS` (1 ms steps, default 3000) and `MPSCHED_PIPES` (2 or 4,
//! default both). Costs are the thread's CPU time, so that a busy machine
//! does not count in them.

// Reading the thread CPU clock is a libc call.
#![allow(unsafe_code)]

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

#[path = "../tests/common/join.rs"]
mod join;

use bytes::BytesMut;
use join::{Joined, feed_join};
use zmux::proto::frame::{Dir, Frame, Gates};
use zmux::proto::listener::{ListenerConfig, ListenerCore};
use zmux::proto::record::{Event as R, Framing, RecordReader};
use zmux::proto::session::{
    Backing, Config, PipeAuth, PipeId, PipeOptions, PipeWrite, Policy, RoleConfig, SessionCore,
    StreamKey, TransmitBuf,
};

const BS: Framing = Framing::ByteStream;

/// The CPU time of the calling thread.
fn cpu() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid timespec for the call to write.
    unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}
const STEP: Duration = Duration::from_millis(1);
/// The carrier's low-water mark: the sender writes while less is unsent.
const LOWAT: usize = 32 * 1024;

/// One direction of a pipe: a FIFO of `rate` bytes per step and a delay.
struct Line {
    rate: usize,
    delay: u32,
    queue: VecDeque<u8>,
    flight: VecDeque<(u64, Vec<u8>)>,
}

impl Line {
    fn new(mbit: usize, delay_ms: u32) -> Self {
        Self {
            rate: mbit * 1_000_000 / 8 / 1000,
            delay: delay_ms,
            queue: VecDeque::new(),
            flight: VecDeque::new(),
        }
    }

    /// Moves a step's worth of bytes onto the wire; returns what arrives.
    fn step(&mut self, step: u64) -> Vec<u8> {
        let n = self.queue.len().min(self.rate);
        if n > 0 {
            let bytes: Vec<u8> = self.queue.drain(..n).collect();
            self.flight.push_back((step + u64::from(self.delay), bytes));
        }
        let mut out = Vec::new();
        while self.flight.front().is_some_and(|f| f.0 <= step) {
            out.extend(self.flight.pop_front().unwrap().1);
        }
        out
    }
}

struct Pipe {
    id: u64,
    fwd: Line,
    rev: Line,
    b_attached: bool,
    carrier: Option<zmux::proto::listener::CarrierId>,
    reader: RecordReader,
    rev_reader: RecordReader,
    /// The receiver's read buffer and its identity.
    rbuf: BytesMut,
    rid: u64,
}

/// The receiver's read buffer (the driver's `READ_BUFFER`).
const READ_BUFFER: usize = 128 * 1024;

#[derive(Default)]
struct Cost {
    send: Duration,
    ack: Duration,
    timers: Duration,
    chunks: u64,
    acks: u64,
    data: u64,
    recv: Duration,
    app_read: Duration,
    read_bytes: u64,
}

struct Net {
    a: SessionCore,
    b: SessionCore,
    start: Instant,
    step: u64,
    pipes: Vec<Pipe>,
    listener: ListenerCore,
    out: TransmitBuf,
    keys: Vec<StreamKey>,
    b_keys: Vec<StreamKey>,
    chunk: Vec<u8>,
    cost: Cost,
    /// Received data copied instead of referenced.
    copy: bool,
    next_buffer: u64,
}

fn config(policy: &Policy) -> Config {
    let mut c = Config::default();
    c.max_pipes = 8;
    c.pipe_auth = PipeAuth::psk(*b"0123456789abcdef0123456789abcdef");
    c.scheduler = policy.clone();
    c.max_idle_timeout = Duration::from_secs(600);
    c.max_incoming_streams = 1 << 16;
    c
}

impl Net {
    fn new(policy: &Policy, specs: &[(usize, u32)], streams: usize) -> Self {
        let start = Instant::now();
        let mut b_cfg = config(policy);
        b_cfg.test_hooks().locator = b"server".to_vec();
        let mut a = SessionCore::new(config(policy), RoleConfig::Initiator, None, start).unwrap();
        let mut b = SessionCore::new(b_cfg, RoleConfig::Responder, None, start).unwrap();
        a.attach_pipe(PipeId(0), BS, start);
        b.attach_pipe(PipeId(0), BS, start);
        a.set_pipe_low_water(PipeId(0), true);
        b.set_pipe_low_water(PipeId(0), true);
        let pipe = |id, (mbit, delay): (usize, u32), b_attached| Pipe {
            id,
            fwd: Line::new(mbit, delay),
            rev: Line::new(mbit, delay),
            b_attached,
            carrier: None,
            reader: RecordReader::new(1 << 20),
            rev_reader: RecordReader::new(1 << 20),
            rbuf: BytesMut::new(),
            rid: 0,
        };
        let mut n = Self {
            a,
            b,
            start,
            step: 0,
            pipes: vec![pipe(0, specs[0], true)],
            listener: ListenerCore::new(ListenerConfig::default()),
            out: TransmitBuf::default(),
            keys: Vec::new(),
            b_keys: Vec::new(),
            chunk: vec![0x5a; 64 * 1024],
            cost: Cost::default(),
            copy: std::env::var("MPSCHED_RECV").is_ok_and(|v| v == "copy"),
            next_buffer: 1,
        };
        n.run(200);
        assert!(n.a.is_multipath(), "multipath negotiated");
        for &spec in &specs[1..] {
            let id =
                n.a.add_pipe(
                    Some(BS),
                    Some(BS),
                    &PipeOptions::default(),
                    false,
                    None,
                    n.now(),
                )
                .unwrap();
            n.a.set_pipe_low_water(id, true);
            n.pipes.push(pipe(id.0, spec, false));
        }
        n.run(2000);
        for _ in 0..streams {
            n.keys.push(n.a.open(Dir::Bidi).unwrap());
        }
        n.cost = Cost::default();
        n
    }

    fn now(&self) -> Instant {
        self.start + STEP * self.step as u32
    }

    fn run(&mut self, steps: u64) {
        for _ in 0..steps {
            self.one_step();
        }
    }

    fn one_step(&mut self) {
        let now = self.now();
        for k in self.keys.clone() {
            while let Ok(n) = self.a.write(k, &self.chunk) {
                if n == 0 {
                    break;
                }
            }
        }
        for i in 0..self.pipes.len() {
            let id = PipeId(self.pipes[i].id);
            // A's writes, timed.
            loop {
                let unsent = self.pipes[i].fwd.queue.len();
                self.a.set_pipe_unsent(id, unsent as u64, now);
                if unsent >= LOWAT {
                    self.a
                        .pipe_write(id, PipeWrite::returned(now, now, 0, 0, true), now);
                    break;
                }
                self.a
                    .pipe_write(id, PipeWrite::returned(now, now, 0, 0, false), now);
                let t = cpu();
                let wants = self.a.wants_write(id);
                if wants {
                    self.a.poll_transmit(id, now, &mut self.out);
                }
                self.cost.send += cpu() - t;
                if !wants || self.out.is_empty() {
                    break;
                }
                let mut v = Vec::new();
                self.out.copy_to_vec(&mut v);
                let p = &mut self.pipes[i];
                let mut input = &v[..];
                while let Ok(Some(ev)) = p.reader.read(&mut input, &Gates::ALL) {
                    if let R::Frame(Frame::Stream(f)) = ev {
                        self.cost.chunks += 1;
                        self.cost.data += f.data.len() as u64;
                    }
                }
                p.fwd.queue.extend(v);
            }
            // B's writes (acknowledgements and credit).
            if self.pipes[i].b_attached {
                for _ in 0..16 {
                    if !self.b.wants_write(id) {
                        break;
                    }
                    self.b.poll_transmit(id, now, &mut self.out);
                    if self.out.is_empty() {
                        break;
                    }
                    let mut v = Vec::new();
                    self.out.copy_to_vec(&mut v);
                    self.pipes[i].rev.queue.extend(v);
                }
            }
            let fwd = self.pipes[i].fwd.step(self.step);
            if !fwd.is_empty() {
                self.feed_b(i, &fwd, now);
            }
            let rev = self.pipes[i].rev.step(self.step);
            if !rev.is_empty() {
                let p = &mut self.pipes[i];
                let mut input = &rev[..];
                while let Ok(Some(ev)) = p.rev_reader.read(&mut input, &Gates::ALL) {
                    if let R::Frame(Frame::PipeAck(_)) = ev {
                        self.cost.acks += 1;
                    }
                }
                let t = cpu();
                self.a.receive(id, &rev, now);
                self.cost.ack += cpu() - t;
            }
        }
        self.read_b();
        self.step += 1;
        let now = self.now();
        let t = cpu();
        self.a.handle_timeout(now);
        self.cost.timers += cpu() - t;
        self.b.handle_timeout(now);
        while self.a.poll_event().is_some() {}
    }

    fn feed_b(&mut self, i: usize, bytes: &[u8], now: Instant) {
        let p = &mut self.pipes[i];
        if p.b_attached {
            let t = cpu();
            if self.copy {
                self.b.receive(PipeId(p.id), bytes, now);
            } else {
                // Reads of at most 64 KiB into the pipe's read buffer, a
                // fresh one when it has no room; an incomplete record stays
                // for the next read.
                for part in bytes.chunks(64 * 1024) {
                    if p.rbuf.capacity() - p.rbuf.len() < part.len() {
                        let mut fresh = BytesMut::with_capacity(READ_BUFFER);
                        fresh.extend_from_slice(&p.rbuf);
                        p.rbuf = fresh;
                        p.rid = self.next_buffer;
                        self.next_buffer += 1;
                    }
                    p.rbuf.extend_from_slice(part);
                    let data = p.rbuf.split().freeze();
                    let backing = Backing {
                        id: p.rid,
                        size: READ_BUFFER,
                    };
                    let used = self.b.receive_shared(PipeId(p.id), &data, backing, now);
                    p.rbuf.extend_from_slice(&data[used..]);
                }
            }
            self.cost.recv += cpu() - t;
            return;
        }
        let fed = feed_join(
            &mut self.listener,
            &mut self.b,
            &mut p.carrier,
            p.id,
            bytes,
            now,
        );
        if let Joined::Attached(id) = fed.joined {
            p.b_attached = true;
            self.b.set_pipe_low_water(id, true);
        }
    }

    fn read_b(&mut self) {
        while let Ok(Some(k)) = self.b.accept(Dir::Bidi) {
            self.b_keys.push(k);
        }
        let mut buf = vec![0u8; 64 * 1024];
        let t = cpu();
        for &k in &self.b_keys {
            while let Ok(Some((n, _))) = self.b.read(k, &mut buf) {
                if n == 0 {
                    break;
                }
                self.cost.read_bytes += n as u64;
            }
        }
        self.cost.app_read += cpu() - t;
        while self.b.poll_event().is_some() {}
    }
}

fn main() {
    let args: Vec<String> = std::env::args()
        .skip(1)
        .filter(|a| !a.starts_with("--"))
        .collect();
    let env = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<u64>().ok());
    let streams = env("MPSCHED_STREAMS").unwrap_or(1000) as usize;
    let steps = env("MPSCHED_STEPS").unwrap_or(3000);
    let policies = [
        ("eta", Policy::SpreadEta),
        ("affinity", Policy::Affinity),
        ("session-affinity", Policy::SessionAffinity),
    ];
    let specs: BTreeMap<usize, Vec<(usize, u32)>> = BTreeMap::from([
        (2, vec![(400, 5), (200, 20)]),
        (4, vec![(400, 5), (200, 20), (100, 10), (100, 40)]),
    ]);
    for (name, policy) in &policies {
        if !args.is_empty() && !args.iter().any(|a| a == name) {
            continue;
        }
        for (pipes, spec) in &specs {
            if env("MPSCHED_PIPES").is_some_and(|p| p as usize != *pipes) {
                continue;
            }
            let mut n = Net::new(policy, spec, streams);
            n.run(steps);
            let c = &n.cost;
            println!(
                "MPSCHED policy={name} pipes={pipes} streams={streams} chunks={} acks={} \
                 data_MB={:.0} send_ns_per_chunk={:.0} ack_ns_per_pipe_ack={:.0} \
                 timers_ms={:.1} cpu_ms={:.0} recv_us_per_MB={:.1} read_us_per_MB={:.1}",
                c.chunks,
                c.acks,
                c.data as f64 / 1e6,
                c.send.as_nanos() as f64 / c.chunks.max(1) as f64,
                c.ack.as_nanos() as f64 / c.acks.max(1) as f64,
                c.timers.as_secs_f64() * 1e3,
                (c.send + c.ack + c.timers).as_secs_f64() * 1e3,
                c.recv.as_secs_f64() * 1e12 / c.read_bytes.max(1) as f64,
                c.app_read.as_secs_f64() * 1e12 / c.read_bytes.max(1) as f64,
            );
        }
    }
}
