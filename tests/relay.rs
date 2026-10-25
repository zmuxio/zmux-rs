//! Stream carriers and relays (CONFORMANCE.md): a
//! nested multipath session over a direct carrier and pipes relayed by
//! splicing relays, three sessions per relay hop (X to the relay, the
//! relay to Y, and the nested one), in one process.
//!
//! (a) The events of the splice table and of the stream-carrier mapping,
//! at random points of a bulk transfer: the codes and ends reach every
//! stream as specified, the nested session reinjects and continues, and
//! nothing leaks. (b) A relay's downstream stalls: the relay holds at most
//! the upstream window, what the downstream holds unsent within its peer's
//! credit, and one chunk; the nested pipe fails; every hop releases its
//! session credit. (c) Splices cancelled at random points with limiters
//! that wait: nothing survives, and the bytes charged are the bytes
//! forwarded.

mod common;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use common::{
    Ctl, Rng, connect, duplex, eventually, multi_thread, settle, snapshot, soak, watchdog,
};
use tokio::task::JoinHandle;
use zmux::helpers::{SpliceEnd, SpliceError, SpliceOptions, Spliced, splice};
use zmux::proto::ApplicationErrorCode;
use zmux::{
    Cap, Config, Limiter, Listener, ListenerConfig, Pipe, PipeAuth, PipeHint, PipeIo, PipeOptions,
    PipeState, Policy, Session, VarInt,
};

fn carrier_failed() -> VarInt {
    VarInt::from_u64(ApplicationErrorCode::ZMUX_CARRIER_FAILED.0).unwrap()
}

fn nested_config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 8;
    c.pipe_auth = PipeAuth::psk(*b"relay-psk-------0123456789abcdef");
    // Every pipe carries data: a relayed pipe fails with data in flight.
    c.scheduler = Policy::SpreadRoundRobin;
    c
}

/// The relay hops' sessions: stream windows of at most 256 KiB, so that
/// the relay's bound is known.
fn hop_config() -> Config {
    let mut c = Config::default();
    c.max_stream_receive_window = Cap::Fixed(256 * 1024);
    c
}

/// The nested session: X dials over a direct carrier, Y is behind a
/// nested listener.
struct Nested {
    x: Session,
    y: Session,
    listener: Listener,
}

impl Nested {
    async fn new() -> Self {
        let listener = Listener::new(nested_config(), ListenerConfig::default());
        let ((a, _), (b, _)) = duplex(1 << 20);
        let l = listener.clone();
        tokio::spawn(async move {
            let _ = l.handle_pipe(b, PipeHint::default()).await;
        });
        let x = Session::connect(a, nested_config()).await.unwrap();
        let y = listener.accept().await.unwrap();
        Self { x, y, listener }
    }
}

/// A limiter that waits whenever the test says so, counting its charges.
#[derive(Default)]
struct Gate {
    shut: AtomicBool,
    waker: Mutex<Option<Waker>>,
    charged: AtomicU64,
}

impl Gate {
    fn set(&self, shut: bool) {
        self.shut.store(shut, Ordering::SeqCst);
        if let Some(w) = self.waker.lock().unwrap().take() {
            w.wake();
        }
    }
}

impl Limiter for Gate {
    fn poll_ready(&self, cx: &mut Context<'_>, _: usize, max: usize) -> Poll<usize> {
        let mut w = self.waker.lock().unwrap();
        if self.shut.load(Ordering::SeqCst) {
            *w = Some(cx.waker().clone());
            return Poll::Pending;
        }
        Poll::Ready(max)
    }
    fn try_ready(&self, max: usize) -> usize {
        if self.shut.load(Ordering::SeqCst) {
            0
        } else {
            max
        }
    }
    fn charge(&self, n: usize) {
        self.charged.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// A splice running in a task.
type Splicing = JoinHandle<Result<Spliced, SpliceError>>;

/// One relay: X's outer session to it, and its outer session to Y. It
/// splices every stream X opens into a stream it opens towards Y, which Y
/// joins to the nested session.
struct Relay {
    /// X's end of X–R.
    xr: Session,
    /// R's end of X–R.
    rx: Session,
    /// R's end of R–Y.
    ry: Session,
    /// The R–Y carrier's controls.
    ry_ctl: [Arc<Ctl>; 2],
    /// The splices running, with their results.
    splices: Arc<Mutex<Vec<Splicing>>>,
    gate: Arc<Gate>,
    tasks: Vec<JoinHandle<()>>,
}

impl Relay {
    async fn new(n: &Nested) -> Self {
        let ((a, _), (b, _)) = duplex(1 << 20);
        let (xr, rx) = connect(a, b, hop_config(), hop_config()).await;
        let ((a, c0), (b, c1)) = duplex(1 << 20);
        let (ry, yr) = connect(a, b, hop_config(), hop_config()).await;
        let splices = Arc::new(Mutex::new(Vec::new()));
        let gate = Arc::new(Gate::default());
        let relay = {
            let (rx, ry, splices, gate) = (rx.clone(), ry.clone(), splices.clone(), gate.clone());
            tokio::spawn(async move {
                while let Ok((s_in, r_in)) = rx.accept_bi().await {
                    // The whole preamble goes on: PIPE_CARRIER, TLVs.
                    let Ok((s_out, r_out)) = ry.open_bi_with(&r_in.preamble()).await else {
                        return;
                    };
                    let mut opts = SpliceOptions::default();
                    opts.a_to_b = Some(gate.clone());
                    let h = tokio::spawn(splice((s_in, r_in), (s_out, r_out), opts));
                    splices.lock().unwrap().push(h);
                }
            })
        };
        let joiner = {
            let l = n.listener.clone();
            tokio::spawn(async move {
                while let Ok((send, recv)) = yr.accept_bi().await {
                    let pre = recv.preamble();
                    assert!(pre.is_pipe_carrier(), "the relay passed PIPE_CARRIER on");
                    assert_eq!(pre.tlvs().count(), 1, "and the TLVs");
                    let l = l.clone();
                    tokio::spawn(async move {
                        let _ = l
                            .handle_pipe(PipeIo::from_stream(send, recv), PipeHint::default())
                            .await;
                    });
                }
            })
        };
        Self {
            xr,
            rx,
            ry,
            ry_ctl: [c0, c1],
            splices,
            gate,
            tasks: vec![relay, joiner],
        }
    }

    /// Joins a pipe of X through this relay.
    async fn join(&self, x: &Session) -> Pipe {
        let pipe = self
            .xr
            .open_pipe_stream(&zmux::Preamble::new().with_tlv(0x1002, [8]))
            .await
            .unwrap();
        let p = x.add_pipe(pipe, PipeOptions::default()).unwrap();
        eventually(10, "relayed pipe active", || {
            p.stats()
                .is_some_and(|i| i.outbound == Some(PipeState::Active) && !i.in_probation)
        })
        .await;
        p
    }

    /// The last splice's result.
    async fn last(&self) -> Option<Spliced> {
        let h = self.splices.lock().unwrap().pop()?;
        watchdog(20, "splice ends", h).await.ok()?.ok()
    }

    async fn close(self) {
        self.xr.close(VarInt::ZERO, b"");
        self.ry.close(VarInt::ZERO, b"");
        let handles: Vec<_> = self.splices.lock().unwrap().drain(..).collect();
        for h in handles {
            let _ = watchdog(10, "splices end", h).await;
        }
        for t in self.tasks {
            let _ = watchdog(10, "relay tasks end", t).await;
        }
    }
}

fn failed(p: &Pipe) -> bool {
    p.stats().is_none_or(|i| {
        matches!(
            i.outbound,
            Some(PipeState::Failed | PipeState::Retired | PipeState::Closed) | None
        )
    })
}

/// Echoes `len` bytes on a new nested stream.
async fn echo(x: &Session, y: &Session, len: usize, seed: usize) {
    let server = {
        let y = y.clone();
        tokio::spawn(async move {
            let (mut send, mut recv) = y.accept_bi().await.unwrap();
            let data = recv.read_to_end(len).await.unwrap();
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
        })
    };
    let (mut send, mut recv) = x.open_bi().await.unwrap();
    let data: Vec<u8> = (0..len).map(|i| (i * 13 + seed + i / 4093) as u8).collect();
    let writer = {
        let data = data.clone();
        tokio::spawn(async move {
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
            send
        })
    };
    let back = recv.read_to_end(len).await.unwrap();
    assert!(back == data, "the nested stream's bytes");
    drop(writer.await.unwrap());
    server.await.unwrap();
}

/// A bulk transfer that runs until stopped, echo after echo.
fn bulk(x: &Session, y: &Session, stop: Arc<AtomicBool>) -> JoinHandle<usize> {
    let (x, y) = (x.clone(), y.clone());
    tokio::spawn(async move {
        let mut rounds = 0;
        while !stop.load(Ordering::SeqCst) {
            echo(&x, &y, 512 << 10, rounds).await;
            rounds += 1;
        }
        rounds
    })
}

#[derive(Debug, Clone, Copy)]
enum Event {
    /// X aborts the relayed pipe: its stream is reset and stopped with
    /// ZMUX_CARRIER_FAILED, which the relay forwards.
    PipeAborted,
    /// The relay's session with X ends.
    UpstreamLost,
    /// The relay's carrier towards Y fails.
    DownstreamLost,
    /// The relay's splice is cancelled.
    Cancelled,
}

#[test]
fn relay_events_at_random_points_of_a_bulk_transfer() {
    multi_thread(async {
        let base = snapshot();
        {
            let n = Nested::new().await;
            let stop = Arc::new(AtomicBool::new(false));
            // A second relay keeps a relayed pipe up throughout.
            let steady = Relay::new(&n).await;
            let _steady_pipe = steady.join(&n.x).await;
            let transfer = bulk(&n.x, &n.y, stop.clone());
            let mut rng = Rng::new(0x5eed_0010);
            let events = [
                Event::PipeAborted,
                Event::UpstreamLost,
                Event::DownstreamLost,
                Event::Cancelled,
            ];
            for round in 0..soak(8) {
                let event = events[round % events.len()];
                let relay = Relay::new(&n).await;
                let pipe = relay.join(&n.x).await;
                tokio::time::sleep(Duration::from_millis(rng.below(150))).await;
                let cf = carrier_failed();
                // Each direction ends by the event at the relay, or by the
                // nested session's own reaction to the failed pipe when that
                // reaches the relay first: the far nested end learns of the
                // failure over the other pipes and aborts its halves of the
                // carrier stream (EXTENSIONS.md Section 10.2), a reset or a
                // stop with ZMUX_CARRIER_FAILED racing the event's own end.
                let ends = |s: &Spliced, a_to_b: [SpliceEnd; 2], b_to_a: [SpliceEnd; 2]| {
                    assert!(
                        a_to_b.contains(&s.a_to_b.end),
                        "{event:?}: a to b {:?}",
                        s.a_to_b.end
                    );
                    assert!(
                        b_to_a.contains(&s.b_to_a.end),
                        "{event:?}: b to a {:?}",
                        s.b_to_a.end
                    );
                };
                match event {
                    Event::PipeAborted => {
                        // X resets and stops its carrier stream; Y aborts
                        // its halves once it learns of the failure.
                        pipe.abort().unwrap();
                        let s = relay.last().await.expect("a result");
                        ends(
                            &s,
                            [SpliceEnd::Reset(cf), SpliceEnd::Stopped(cf)],
                            [SpliceEnd::Stopped(cf), SpliceEnd::Reset(cf)],
                        );
                    }
                    Event::UpstreamLost => {
                        relay.rx.close(VarInt::from_u32(1), b"");
                        let s = relay.last().await.expect("a result");
                        ends(
                            &s,
                            [SpliceEnd::UpstreamLost, SpliceEnd::Stopped(cf)],
                            [SpliceEnd::DownstreamLost, SpliceEnd::Reset(cf)],
                        );
                    }
                    Event::DownstreamLost => {
                        relay.ry_ctl[0].fail();
                        let s = relay.last().await.expect("a result");
                        ends(
                            &s,
                            [SpliceEnd::DownstreamLost, SpliceEnd::Reset(cf)],
                            [SpliceEnd::UpstreamLost, SpliceEnd::Stopped(cf)],
                        );
                    }
                    Event::Cancelled => {
                        let h = relay.splices.lock().unwrap().pop().expect("a splice");
                        h.abort();
                        let _ = h.await;
                    }
                }
                // Both nested ends see the pipe fail; the transfer goes on.
                eventually(20, "the relayed pipe failed", || failed(&pipe)).await;
                assert!(n.x.close_reason().is_none() && n.y.close_reason().is_none());
                relay.close().await;
            }
            stop.store(true, Ordering::SeqCst);
            let rounds = watchdog(60, "bulk transfer", transfer).await.unwrap();
            assert!(rounds > 0);
            let reinjected = n.x.stats().bytes_reinjected + n.y.stats().bytes_reinjected;
            assert!(reinjected > 0, "the nested session reinjected");
            steady.close().await;
            n.x.close(VarInt::ZERO, b"");
            n.listener.close();
        }
        settle(base, 20, "relay events").await;
    });
}

#[test]
fn a_stalled_downstream_fails_the_relayed_pipe_and_every_hop_releases_its_credit() {
    multi_thread(async {
        let base = snapshot();
        {
            let n = Nested::new().await;
            let relay = Relay::new(&n).await;
            let pipe = relay.join(&n.x).await;
            let stop = Arc::new(AtomicBool::new(false));
            let transfer = bulk(&n.x, &n.y, stop.clone());
            tokio::time::sleep(Duration::from_millis(100)).await;
            // Y's carrier from the relay stops taking bytes.
            relay.ry_ctl[0].stall(true);
            let mut peak = 0;
            let bound = 256 * 1024 + 256 * 1024 + 64 * 1024;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            while !failed(&pipe) {
                let held = relay.rx.debug_tables().held_bytes + relay.ry.debug_tables().held_bytes;
                peak = peak.max(held);
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "the relayed pipe did not fail"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            // The upstream window, the downstream's unsent bytes within its
            // peer's credit, one chunk.
            assert!(peak > 0 && peak <= bound, "the relay held {peak} bytes");
            // The abort of whichever nested end failed the pipe first reached
            // the relay, which forwarded it at once: X's reset of the stream
            // it sends on, or Y's stop of the one it reads (Y finds its
            // inbound pipe silent while X finds its data unacknowledged).
            let ends = {
                let h = relay.splices.lock().unwrap().pop().unwrap();
                relay.ry_ctl[0].stall(false);
                watchdog(20, "splice", h).await.unwrap().unwrap()
            };
            let cf = carrier_failed();
            assert!(
                matches!(ends.a_to_b.end, SpliceEnd::Reset(c) | SpliceEnd::Stopped(c) if c == cf),
                "{:?}",
                ends.a_to_b.end
            );
            // Every hop released its session credit.
            eventually(10, "credit released", || {
                relay.rx.debug_tables().held_bytes == 0
                    && relay.ry.debug_tables().held_bytes == 0
                    && relay.rx.stats().streams_active == 0
                    && relay.ry.stats().streams_active == 0
            })
            .await;
            stop.store(true, Ordering::SeqCst);
            watchdog(60, "bulk transfer", transfer).await.unwrap();
            relay.close().await;
            n.x.close(VarInt::ZERO, b"");
            n.listener.close();
        }
        settle(base, 20, "stall").await;
    });
}

#[test]
fn splices_cancelled_in_limiter_waits_leave_nothing_and_charge_what_they_forwarded() {
    multi_thread(async {
        let base = snapshot();
        {
            let n = Nested::new().await;
            let stop = Arc::new(AtomicBool::new(false));
            let transfer = bulk(&n.x, &n.y, stop.clone());
            let mut rng = Rng::new(0x5eed_0011);
            for _ in 0..soak(6) {
                let relay = Relay::new(&n).await;
                let pipe = relay.join(&n.x).await;
                // The limiter waits now and then; the splice is cancelled
                // at a random point, waiting or not.
                for _ in 0..rng.below(4) {
                    relay.gate.set(true);
                    tokio::time::sleep(Duration::from_millis(rng.below(30))).await;
                    relay.gate.set(false);
                    tokio::time::sleep(Duration::from_millis(rng.below(30))).await;
                }
                relay.gate.set(rng.below(2) == 0);
                let h = relay.splices.lock().unwrap().pop().unwrap();
                h.abort();
                let _ = h.await;
                // Charged exactly what went from X towards Y: the relay's
                // session towards Y carries nothing else.
                assert_eq!(
                    relay.gate.charged.load(Ordering::Relaxed),
                    relay.ry.meter().bytes_written()
                );
                eventually(20, "the relayed pipe failed", || failed(&pipe)).await;
                relay.close().await;
            }
            stop.store(true, Ordering::SeqCst);
            watchdog(60, "bulk transfer", transfer).await.unwrap();
            n.x.close(VarInt::ZERO, b"");
            n.listener.close();
        }
        settle(base, 20, "cancelled splices").await;
    });
}
