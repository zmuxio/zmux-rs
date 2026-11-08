//! Carriers through a faulty relay in the middle, on a paused clock: idle
//! cut-offs, black holes, cuts of the last pipe with resume, refused
//! redials, a silently cut downlink of a split pool and a lifetime limit.
//! The pipe pool keeps the pipes up (redials on pipe events, rotates make
//! before break); idle probes keep idle carriers alive and find dead ones.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream};
use tokio::sync::Notify;
use tokio::time::{Instant, sleep, sleep_until};
use zmux::helpers::{Backoff, PipePool, PoolDecision, PoolView, RotatePolicy, maintain_pipes};
use zmux::{
    Config, InboundState, Listener, ListenerConfig, OutboundState, PipeAuth, PipeDirection,
    PipeHint, PipeIo, PipeOptions, Session, SessionError, SessionState,
};

fn config(edit: impl FnOnce(&mut Config)) -> Config {
    let mut c = Config::default();
    c.max_pipes = 6;
    c.pipe_auth = PipeAuth::psk(*b"fault-relay-psk-0123456789abcdef").with_end_to_end();
    c.max_idle_timeout = None;
    c.resume_timeout = Some(Duration::from_secs(120));
    edit(&mut c);
    c
}

/// How the relay treats a connection.
#[derive(Default)]
struct Faults {
    /// A connection without bytes either way for this long is dropped
    /// silently: nothing more is forwarded, neither end is told.
    idle_cut: Option<Duration>,
    /// A connection is dropped (both ends see its end) this long after it
    /// opened.
    lifetime: Option<Duration>,
    /// New connections are refused.
    refuse: AtomicBool,
}

/// One relayed connection's switches.
#[derive(Default)]
struct Conn {
    /// Forwards nothing more, ends stay open (a black hole).
    blackhole: AtomicBool,
    /// Ended at once: both ends see the end.
    cut: Notify,
    cut_flag: AtomicBool,
    /// Silently cut by the idle rule.
    idled: AtomicBool,
    /// Ended by the lifetime rule.
    expired: AtomicBool,
    /// The direction the dial asked for.
    direction: Mutex<Option<PipeDirection>>,
}

impl Conn {
    fn cut(&self) {
        self.cut_flag.store(true, Ordering::SeqCst);
        self.cut.notify_waiters();
    }
}

#[derive(Clone)]
struct Relay {
    listener: Listener,
    faults: Arc<Faults>,
    conns: Arc<Mutex<Vec<Arc<Conn>>>>,
    dials: Arc<Mutex<Vec<Instant>>>,
}

/// Copies `from` to `to` until either ends, the relay drops it or `conn`
/// is cut; `last` is the time of the last byte either way.
async fn pump(
    mut from: impl AsyncRead + Unpin,
    mut to: impl AsyncWrite + Unpin,
    conn: Arc<Conn>,
    last: Arc<Mutex<Instant>>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if conn.blackhole.load(Ordering::SeqCst) || conn.idled.load(Ordering::SeqCst) {
            continue;
        }
        *last.lock().unwrap() = Instant::now();
        if to.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

impl Relay {
    fn new(listener: &Listener, faults: Faults) -> Self {
        Self {
            listener: listener.clone(),
            faults: Arc::new(faults),
            conns: Arc::default(),
            dials: Arc::default(),
        }
    }

    /// A connection through the relay: the dialer's end, the listener's
    /// end, and its switches.
    fn connect(&self) -> (DuplexStream, DuplexStream, Arc<Conn>) {
        let (near, relay_a) = tokio::io::duplex(256 * 1024);
        let (relay_b, far) = tokio::io::duplex(256 * 1024);
        let conn = Arc::new(Conn::default());
        self.conns.lock().unwrap().push(conn.clone());
        let faults = self.faults.clone();
        let c = conn.clone();
        tokio::spawn(async move {
            let opened = Instant::now();
            let last = Arc::new(Mutex::new(opened));
            let (ar, aw) = tokio::io::split(relay_a);
            let (br, bw) = tokio::io::split(relay_b);
            let mut up = tokio::spawn(pump(ar, bw, c.clone(), last.clone()));
            let mut down = tokio::spawn(pump(br, aw, c.clone(), last.clone()));
            while !c.cut_flag.load(Ordering::SeqCst) {
                let mut wake = opened + Duration::from_secs(3600);
                if let Some(l) = faults.lifetime {
                    wake = wake.min(opened + l);
                }
                if let Some(i) = faults.idle_cut
                    && !c.idled.load(Ordering::SeqCst)
                {
                    wake = wake.min(*last.lock().unwrap() + i);
                }
                tokio::select! {
                    () = c.cut.notified() => break,
                    _ = &mut up => break,
                    _ = &mut down => break,
                    () = sleep_until(wake) => {}
                }
                if c.cut_flag.load(Ordering::SeqCst) {
                    break;
                }
                let now = Instant::now();
                if faults.lifetime.is_some_and(|l| now >= opened + l) {
                    c.expired.store(true, Ordering::SeqCst);
                    break;
                }
                if let Some(i) = faults.idle_cut
                    && now >= *last.lock().unwrap() + i
                {
                    c.idled.store(true, Ordering::SeqCst);
                }
            }
            // Dropping the copies drops the relay's ends: both ends see the
            // end of their stream.
            up.abort();
            down.abort();
        });
        (near, far, conn)
    }

    fn hint() -> PipeHint {
        PipeHint::from_peer(([127, 0, 0, 1], 0).into())
    }

    /// A bidirectional carrier through the relay.
    fn carrier(&self) -> io::Result<PipeIo> {
        self.dials.lock().unwrap().push(Instant::now());
        if self.faults.refuse.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"));
        }
        let (near, far, _) = self.connect();
        let l = self.listener.clone();
        tokio::spawn(async move {
            let _ = l.handle_pipe(PipeIo::new(far), Self::hint()).await;
        });
        Ok(PipeIo::new(near))
    }

    /// A one-way carrier through the relay of a split pool's member, paired at the
    /// listener by `token`.
    fn one_way(&self, direction: PipeDirection, token: [u8; 16]) -> io::Result<PipeIo> {
        self.dials.lock().unwrap().push(Instant::now());
        if self.faults.refuse.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"));
        }
        let (near, far, conn) = self.connect();
        *conn.direction.lock().unwrap() = Some(direction);
        let l = self.listener.clone();
        let mut hint = Self::hint();
        hint.pair = Some(token.to_vec());
        match direction {
            PipeDirection::Out => {
                tokio::spawn(async move {
                    let _ = l.handle_pipe(PipeIo::reader(far), hint).await;
                });
                Ok(PipeIo::writer(near))
            }
            PipeDirection::In => {
                tokio::spawn(async move {
                    let _ = l.handle_pipe(PipeIo::writer(far), hint).await;
                });
                Ok(PipeIo::reader(near))
            }
            PipeDirection::Bidi => unreachable!("a split pool dials one-way carriers"),
        }
    }

    fn pool(&self, count: usize, options: PipeOptions) -> PipePool {
        let r = self.clone();
        PipePool::new(count, move |_| std::future::ready(r.carrier()))
            .with_options(options)
            .with_backoff(Backoff::new(
                Duration::from_millis(500),
                Duration::from_secs(5),
            ))
    }

    /// A pool of split members: a downlink and an uplink joined together.
    fn split_pool(&self, options: PipeOptions) -> PipePool {
        let r = self.clone();
        PipePool::join(1, move |session: Session, options| {
            let r = r.clone();
            async move {
                let mut token = [0; 16];
                getrandom::fill(&mut token).map_err(io::Error::other)?;
                let up = r.one_way(PipeDirection::Out, token)?;
                let down = r.one_way(PipeDirection::In, token)?;
                let pipe = session
                    .begin_add_pipe(PipeIo::paired_join(up, down), options)
                    .map_err(io::Error::other)?;
                Ok(vec![pipe])
            }
        })
        .with_options(options)
        .with_backoff(Backoff::new(
            Duration::from_millis(500),
            Duration::from_secs(5),
        ))
    }

    fn dial_count(&self) -> usize {
        self.dials.lock().unwrap().len()
    }

    fn count(&self, f: impl Fn(&Conn) -> bool) -> usize {
        self.conns.lock().unwrap().iter().filter(|c| f(c)).count()
    }
}

/// A session over a direct carrier (not relayed) and its peer.
async fn direct(listener: &Listener, cfg: Config) -> (Session, Session) {
    let (a, b) = tokio::io::duplex(256 * 1024);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.handle_pipe(PipeIo::new(b), Relay::hint()).await;
    });
    let client = Session::connect(PipeIo::new(a), cfg).await.unwrap();
    let server = listener.accept().await.unwrap();
    (client, server)
}

/// A session over a relayed carrier and its peer.
async fn relayed(relay: &Relay, cfg: Config) -> (Session, Session) {
    let client = Session::connect(relay.carrier().unwrap(), cfg)
        .await
        .unwrap();
    let server = relay.listener.accept().await.unwrap();
    (client, server)
}

/// Waits (on the paused clock, in 1 ms steps) until `f` holds; fails after
/// `limit`. Returns the time it held.
async fn until(what: &str, limit: Duration, mut f: impl FnMut() -> bool) -> Instant {
    let end = Instant::now() + limit;
    while !f() {
        assert!(Instant::now() < end, "timed out: {what}");
        sleep(Duration::from_millis(1)).await;
    }
    Instant::now()
}

/// Pool pipes of the client (not pipe 0) whose outbound is ACTIVE.
fn active(s: &Session) -> usize {
    s.pipe_stats()
        .iter()
        .filter(|p| p.pipe.get() != 0 && p.outbound == Some(OutboundState::Active))
        .count()
}

/// The pool's first pipe (the lowest ID above 0) of the client.
fn pool_pipe(s: &Session) -> zmux::PipeId {
    s.pipe_stats()
        .iter()
        .map(|p| p.pipe)
        .filter(|p| p.get() != 0)
        .min()
        .expect("a pool pipe")
}

/// The pipe is gone or its outbound failed.
fn lost(s: &Session, id: zmux::PipeId) -> bool {
    s.pipe_stats()
        .iter()
        .find(|p| p.pipe == id)
        .is_none_or(|p| p.outbound == Some(OutboundState::Failed))
}

fn failed(s: &Session) -> usize {
    s.pipe_stats()
        .iter()
        .filter(|p| p.outbound == Some(OutboundState::Failed) || p.failure.is_some())
        .count()
}

/// Checks a numbered byte stream: every byte once, in order.
fn check(data: &[u8], from: usize) -> usize {
    for (i, b) in data.iter().enumerate() {
        assert_eq!(*b, ((from + i) % 251) as u8, "byte {} wrong", from + i);
    }
    from + data.len()
}

/// The idle rule of a middlebox (8 s): probes every 5 s with 30% jitter
/// keep a quiet pipe alive for 10 minutes; at 12 s the relay drops it
/// silently, the probe finds it within k + T_fail and the pool redials on
/// the failure at once.
#[tokio::test(start_paused = true)]
async fn probes_keep_an_idle_relay_open() {
    // Only the pool pipe's own probes may cross the relay. A session is
    // busy for the first 15 s after it was established, and while it is
    // busy the answer to a probe of the direct pipe 0 also goes, as the
    // redundant PIPE_ACK copy, on the second live pipe: the relayed one.
    // Pipe 0's first
    // probe wait is drawn from [0, k], so such a copy fell inside the 8 s
    // the idle cut below needs about one run in five; with k = 1 h, still
    // about one in 300 (a draw below 12 s at either end). Pipe 0 probes
    // without jitter, first after 1 h, beyond the test's window.
    let quiet = |c: &mut Config| {
        c.probe_interval = Some(Duration::from_secs(3600));
        c.probe_jitter = 0.0;
    };
    let listener = Listener::new(config(quiet), ListenerConfig::default())
        .expect("valid listener configuration");
    let relay = Relay::new(
        &listener,
        Faults {
            idle_cut: Some(Duration::from_secs(8)),
            ..Faults::default()
        },
    );
    let (client, _server) = direct(&listener, config(quiet)).await;
    let opts = PipeOptions::new()
        .with_probe_interval(Duration::from_secs(5))
        .with_probe_jitter(0.3);
    let handle = maintain_pipes(&client, relay.pool(1, opts)).expect("valid pool");
    until("a pool pipe", Duration::from_secs(10), || {
        active(&client) == 1
    })
    .await;
    sleep(Duration::from_secs(600)).await;
    assert_eq!(relay.count(|c| c.idled.load(Ordering::SeqCst)), 0);
    assert_eq!(relay.dial_count(), 1);
    assert_eq!(failed(&client), 0);
    drop(handle);
    client.close(0u32.into(), b"").await;

    let relay = Relay::new(
        &listener,
        Faults {
            idle_cut: Some(Duration::from_secs(8)),
            ..Faults::default()
        },
    );
    let (client, _server) = direct(&listener, config(quiet)).await;
    // A fixed schedule: the pool pipe's first probe goes 12 s after the
    // join, so the cut comes 8 s after it, and the probe 4 s later.
    let opts = PipeOptions::new()
        .with_probe_interval(Duration::from_secs(12))
        .with_probe_jitter(0.0);
    let handle = maintain_pipes(&client, relay.pool(1, opts)).expect("valid pool");
    until("a pool pipe", Duration::from_secs(10), || {
        active(&client) == 1
    })
    .await;
    let id = pool_pipe(&client);
    let cut = until("an idle cut", Duration::from_secs(20), || {
        relay.count(|c| c.idled.load(Ordering::SeqCst)) == 1
    })
    .await;
    let found = until("the dead pipe found", Duration::from_secs(20), || {
        lost(&client, id)
    })
    .await;
    // The probe goes at most 12 s after the last byte, 4 s after the cut;
    // T_fail follows.
    assert!(
        found - cut <= Duration::from_secs(4 + 5),
        "{:?}",
        found - cut
    );
    until("a redial", Duration::from_millis(20), || {
        relay.dial_count() == 2
    })
    .await;
    until("a new pool pipe", Duration::from_secs(5), || {
        active(&client) == 1
    })
    .await;
    drop(handle);
    client.close(0u32.into(), b"").await;
}

/// A relay that takes bytes and forwards none: the idle pipe fails within
/// k + T_fail.
#[tokio::test(start_paused = true)]
async fn a_black_hole_is_found_by_the_probe() {
    let listener = Listener::new(config(|_| {}), ListenerConfig::default())
        .expect("valid listener configuration");
    let relay = Relay::new(&listener, Faults::default());
    let (client, _server) = direct(&listener, config(|_| {})).await;
    let opts = PipeOptions::new().with_probe_interval(Duration::from_secs(5));
    let handle = maintain_pipes(&client, relay.pool(1, opts)).expect("valid pool");
    until("a pool pipe", Duration::from_secs(10), || {
        active(&client) == 1
    })
    .await;
    sleep(Duration::from_secs(20)).await;
    let id = pool_pipe(&client);
    let start = Instant::now();
    relay.conns.lock().unwrap()[0]
        .blackhole
        .store(true, Ordering::SeqCst);
    let found = until("the black hole found", Duration::from_secs(20), || {
        lost(&client, id)
    })
    .await;
    assert!(
        found - start <= Duration::from_secs(5 + 5),
        "{:?}",
        found - start
    );
    drop(handle);
    client.close(0u32.into(), b"").await;
}

/// The policy of the resume tests: redial 1 s after the last dial, reduced
/// by up to 30% drawn once per wait; records when it was asked.
fn redial_policy(
    asked: Arc<Mutex<Vec<(Instant, SessionState)>>>,
) -> impl FnMut(&PoolView<'_>, &mut PoolDecision) + Send {
    let mut wait: Option<(u32, f64)> = None;
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    move |v: &PoolView<'_>, d: &mut PoolDecision| {
        asked
            .lock()
            .unwrap()
            .push((Instant::now(), v.session_state));
        let u = match wait {
            Some((f, u)) if f == v.redial_failures => u,
            _ => {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                let u = (seed >> 11) as f64 / (1u64 << 53) as f64;
                wait = Some((v.redial_failures, u));
                u
            }
        };
        let after = Duration::from_secs_f64(1.0 - 0.3 * u);
        d.next_dial_at = v.last_dial_at.map(|t| t + after);
    }
}

/// The last pipe is cut with resume on: the pool decides on the
/// suspension at once, redials by its policy, the session resumes and the
/// stream's bytes arrive once each, in order.
#[tokio::test(start_paused = true)]
async fn the_last_pipe_cut_resumes_without_loss() {
    let listener = Listener::new(config(|_| {}), ListenerConfig::default())
        .expect("valid listener configuration");
    let relay = Relay::new(&listener, Faults::default());
    let (client, server) = relayed(&relay, config(|_| {})).await;
    let asked = Arc::new(Mutex::new(Vec::new()));
    let pool = relay
        .pool(1, PipeOptions::new())
        .with_policy(redial_policy(asked.clone()));
    let handle = maintain_pipes(&client, pool).expect("valid pool");
    until("a pool pipe", Duration::from_secs(10), || {
        active(&client) == 1
    })
    .await;
    let total = 4 << 20;
    let (mut tx, _rx) = client.open_bi().await.unwrap();
    let writer = tokio::spawn(async move {
        let mut sent = 0;
        while sent < total {
            let chunk: Vec<u8> = (sent..sent + 16 * 1024).map(|i| (i % 251) as u8).collect();
            tx.write_all(&chunk).await.unwrap();
            sent += chunk.len();
            sleep(Duration::from_millis(5)).await;
        }
        tx.finish().unwrap();
    });
    let peer = server.clone();
    let reader = tokio::spawn(async move {
        let (_t, mut r) = peer.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let mut got = 0;
        while let Some(n) = r.read(&mut buf).await.unwrap() {
            got = check(&buf[..n], got);
        }
        got
    });
    sleep(Duration::from_millis(300)).await;
    for c in relay.conns.lock().unwrap().iter() {
        c.cut();
    }
    let suspended = until("suspended", Duration::from_secs(10), || {
        client.state() == SessionState::Suspended
    })
    .await;
    // A decision saw the suspension within 10 ms (polled here in 1 ms
    // steps).
    let saw = asked
        .lock()
        .unwrap()
        .iter()
        .find(|(_, st)| *st == SessionState::Suspended)
        .map(|(t, _)| *t)
        .expect("a decision during the suspension");
    assert!(
        saw <= suspended + Duration::from_millis(10),
        "{:?}",
        saw - suspended
    );
    until("resumed", Duration::from_secs(10), || {
        client.state() != SessionState::Suspended
    })
    .await;
    assert_eq!(reader.await.unwrap(), total);
    writer.await.unwrap();
    assert!(client.close_reason().is_none());
    drop(handle);
    client.close(0u32.into(), b"").await;
}

/// The relay refuses every redial during the grace period: the session
/// ends with RESUME_TIMEOUT when it expires, and the pool with it.
#[tokio::test(start_paused = true)]
async fn refused_redials_end_in_resume_timeout() {
    let cfg = || config(|c| c.resume_timeout = Some(Duration::from_secs(20)));
    let listener =
        Listener::new(cfg(), ListenerConfig::default()).expect("valid listener configuration");
    let relay = Relay::new(&listener, Faults::default());
    let (client, _server) = relayed(&relay, cfg()).await;
    let handle = maintain_pipes(&client, relay.pool(1, PipeOptions::new())).expect("valid pool");
    until("a pool pipe", Duration::from_secs(10), || {
        active(&client) == 1
    })
    .await;
    relay.faults.refuse.store(true, Ordering::SeqCst);
    for c in relay.conns.lock().unwrap().iter() {
        c.cut();
    }
    let start = Instant::now();
    let e = tokio::time::timeout(Duration::from_secs(30), client.closed())
        .await
        .expect("the grace period ends");
    assert!(matches!(e, SessionError::ResumeTimeout { .. }), "{e:?}");
    assert!(Instant::now() - start >= Duration::from_secs(19));
    // It kept dialling while suspended.
    assert!(relay.dial_count() > 3, "{}", relay.dial_count());
    until("the pool stopped", Duration::from_secs(1), || {
        handle.is_finished()
    })
    .await;
}

/// A split pool whose downlink the relay cuts silently: the pipe fails
/// within the inbound silence limit, and both directions are redialled in
/// parallel; the session carries on.
#[tokio::test(start_paused = true)]
async fn a_silent_downlink_cut_is_found_and_redialled() {
    let listener = Listener::new(config(|_| {}), ListenerConfig::default())
        .expect("valid listener configuration");
    let relay = Relay::new(&listener, Faults::default());
    let (client, server) = relayed(&relay, config(|_| {})).await;
    let handle = maintain_pipes(&client, relay.split_pool(PipeOptions::new())).expect("valid pool");
    let halves = |s: &Session| {
        let p = s.pipe_stats();
        let up = p
            .iter()
            .filter(|p| p.pipe.get() != 0 && p.outbound == Some(OutboundState::Active))
            .count();
        let down = p
            .iter()
            .filter(|p| p.pipe.get() != 0 && p.inbound == Some(InboundState::Open))
            .count();
        (up, down)
    };
    until("an uplink and a downlink", Duration::from_secs(10), || {
        halves(&client) == (1, 1)
    })
    .await;
    // The session runs on the split pipes alone.
    relay.conns.lock().unwrap()[0].cut();
    sleep(Duration::from_secs(2)).await;
    let down = relay
        .conns
        .lock()
        .unwrap()
        .iter()
        .find(|c| *c.direction.lock().unwrap() == Some(PipeDirection::In))
        .cloned()
        .unwrap();
    let dials = relay.dial_count();
    let start = Instant::now();
    down.blackhole.store(true, Ordering::SeqCst);
    until("redialled", Duration::from_secs(25), || {
        relay.dial_count() >= dials + 2
    })
    .await;
    let times = relay.dials.lock().unwrap().clone();
    // The inbound silence limit is 15 s plus a small slack.
    assert!(
        times[dials] - start <= Duration::from_secs(20),
        "{:?}",
        times[dials] - start
    );
    assert!(
        times[dials + 1] - times[dials] <= Duration::from_millis(20),
        "{times:?}"
    );
    until("both halves again", Duration::from_secs(10), || {
        halves(&client) == (1, 1)
    })
    .await;
    let (mut tx, _rx) = client.open_bi().await.unwrap();
    tx.write_all(b"after").await.unwrap();
    tx.finish().unwrap();
    let (_t, mut r) = server.accept_bi().await.unwrap();
    assert_eq!(r.read_to_end(64).await.unwrap(), b"after");
    assert!(client.close_reason().is_none());
    drop(handle);
    client.close(0u32.into(), b"").await;
}

/// A relay that ends each connection 30 s after it opened (a load
/// balancer's connection lifetime): rotation by age, 25 s less up to 10%,
/// replaces each pipe before, make before break, and a stream running all
/// along never stalls.
#[tokio::test(start_paused = true)]
async fn age_rotation_beats_a_lifetime_limit() {
    let listener = Listener::new(config(|_| {}), ListenerConfig::default())
        .expect("valid listener configuration");
    let relay = Relay::new(
        &listener,
        Faults {
            lifetime: Some(Duration::from_secs(30)),
            ..Faults::default()
        },
    );
    let (client, server) = direct(&listener, config(|_| {})).await;
    // Pipe 0 is the fallback tier: the data goes on the pool's pipes.
    client
        .pipe(zmux::PipeId::new(0))
        .unwrap()
        .set_send_priority(10)
        .unwrap();
    let pool = relay.pool(1, PipeOptions::new()).with_rotate(
        RotatePolicy::new()
            .with_max_age(Duration::from_secs(25))
            .with_jitter(0.1),
    );
    let handle = maintain_pipes(&client, pool).expect("valid pool");
    until("a pool pipe", Duration::from_secs(10), || {
        active(&client) == 1
    })
    .await;
    let stalls = Arc::new(AtomicUsize::new(0));
    let (mut tx, _rx) = client.open_bi().await.unwrap();
    let total = 180 * 50 * 4096;
    let writer = tokio::spawn(async move {
        let mut sent = 0;
        while sent < total {
            let chunk: Vec<u8> = (sent..sent + 4096).map(|i| (i % 251) as u8).collect();
            tx.write_all(&chunk).await.unwrap();
            sent += chunk.len();
            sleep(Duration::from_millis(20)).await;
        }
        tx.finish().unwrap();
    });
    let s = stalls.clone();
    let reader = tokio::spawn(async move {
        let (_t, mut r) = server.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 64 * 1024];
        let mut got = 0;
        loop {
            match tokio::time::timeout(Duration::from_millis(500), r.read(&mut buf)).await {
                Err(_) => {
                    s.fetch_add(1, Ordering::SeqCst);
                }
                Ok(r) => match r.unwrap() {
                    Some(n) => got = check(&buf[..n], got),
                    None => return got,
                },
            }
        }
    });
    assert_eq!(reader.await.unwrap(), total);
    writer.await.unwrap();
    assert_eq!(stalls.load(Ordering::SeqCst), 0);
    assert!(relay.dial_count() >= 6, "{}", relay.dial_count());
    // No pipe lived to the relay's limit while it carried the stream: each
    // was replaced first (the last one may still run).
    assert!(relay.count(|c| c.expired.load(Ordering::SeqCst)) <= 1);
    assert_eq!(client.stats().bytes_reinjected, 0);
    drop(handle);
    client.close(0u32.into(), b"").await;
}
