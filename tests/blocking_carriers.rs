//! The std driver and the carriers handed to it: each is released exactly once on every
//! failure path of `connect`, `accept`, `add_pipe` and a listener's new session; the close's
//! linger runs from the delivery of CONNECTION_CLOSE to a carrier whose writes block; and
//! the redial hook replaces a lost pipe. Every test runs under a watchdog.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use zmux::blocking::{Dial, Listener, PipeHint, PipeIo, Session};
use zmux::{
    Config, ConnectError, HandleError, ListenerConfig, PipeAuth, PipeError, PipeId, PipeOptions,
    SessionEvent, SessionState, VarInt,
};

const PSK: [u8; 32] = *b"blocking-carriers-0123456789abcd";

/// Runs `f` on a thread and fails when it does not finish within `secs`.
fn watchdog<T: Send + 'static>(secs: u64, what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(v) => v,
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("{what}: did not resolve within {secs} s"),
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("{what}: panicked"),
    }
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (b, _) = l.accept().unwrap();
    (a, b)
}

fn multipath() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(PSK).with_end_to_end();
    c
}

// ---- a counted carrier ----------------------------------------------------------------

/// What happened to one carrier: its halves dropped and its closer's calls.
#[derive(Default)]
struct Counts {
    reader_dropped: AtomicUsize,
    writer_dropped: AtomicUsize,
    closer_dropped: AtomicUsize,
    /// The carrier is muted: reads wait for the closer and writes take [`Counts::slow`].
    muted: AtomicBool,
    /// Writes block until the closer runs.
    blocked: AtomicBool,
    shut: Mutex<bool>,
    shut_changed: Condvar,
    /// When the last write of a muted carrier completed.
    last_write: Mutex<Option<Instant>>,
}

impl Counts {
    /// Every part of the carrier went.
    fn released(&self) -> bool {
        self.reader_dropped.load(Ordering::SeqCst) == 1
            && self.writer_dropped.load(Ordering::SeqCst) == 1
            && self.closer_dropped.load(Ordering::SeqCst) == 1
    }

    fn wait_shut(&self) {
        let mut s = self.shut.lock().unwrap();
        while !*s {
            s = self.shut_changed.wait(s).unwrap();
        }
    }

    fn is_shut(&self) -> bool {
        *self.shut.lock().unwrap()
    }
}

/// Fails unless `c` is released within 5 s, and checks that nothing is released twice.
fn released(c: &Counts, what: &str) {
    let end = Instant::now() + Duration::from_secs(5);
    while !c.released() && Instant::now() < end {
        thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        (
            c.reader_dropped.load(Ordering::SeqCst),
            c.writer_dropped.load(Ordering::SeqCst),
            c.closer_dropped.load(Ordering::SeqCst),
        ),
        (1, 1, 1),
        "{what}: reader, writer and closer each released once"
    );
}

struct CountedRead(TcpStream, Arc<Counts>);

impl Read for CountedRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.1.muted.load(Ordering::SeqCst) {
            // A peer that goes silent: nothing arrives until the carrier is shut down.
            self.1.wait_shut();
            return Ok(0);
        }
        self.0.read(buf)
    }
}

impl Drop for CountedRead {
    fn drop(&mut self) {
        self.1.reader_dropped.fetch_add(1, Ordering::SeqCst);
    }
}

/// How long each write of a muted carrier takes.
/// Shorter than the linger timeout (250 ms at least), which bounds the wait for a
/// carrier that does not take CONNECTION_CLOSE.
const SLOW: Duration = Duration::from_millis(200);

struct CountedWrite(TcpStream, Arc<Counts>);

impl Write for CountedWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.1.blocked.load(Ordering::SeqCst) {
            self.1.wait_shut();
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if self.1.muted.load(Ordering::SeqCst) {
            thread::sleep(SLOW);
            if self.1.is_shut() {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            *self.1.last_write.lock().unwrap() = Some(Instant::now());
            // The bytes go nowhere: the peer is silent.
            return Ok(buf.len());
        }
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Drop for CountedWrite {
    fn drop(&mut self) {
        self.1.writer_dropped.fetch_add(1, Ordering::SeqCst);
    }
}

struct Closer(TcpStream, Arc<Counts>);

impl Closer {
    fn shut(&self, how: Shutdown) {
        if how != Shutdown::Write {
            *self.1.shut.lock().unwrap() = true;
            self.1.shut_changed.notify_all();
        }
        let _ = self.0.shutdown(how);
    }
}

impl Drop for Closer {
    fn drop(&mut self) {
        self.1.closer_dropped.fetch_add(1, Ordering::SeqCst);
    }
}

/// A carrier on `s` whose parts count their release.
fn counted(s: TcpStream) -> (PipeIo, Arc<Counts>) {
    let c = Arc::new(Counts::default());
    let closer = Closer(s.try_clone().unwrap(), c.clone());
    let io = PipeIo::from_halves(
        CountedRead(s.try_clone().unwrap(), c.clone()),
        CountedWrite(s, c.clone()),
    )
    .with_closer(move |how| closer.shut(how));
    (io, c)
}

// ---- release on the failure paths -----------------------------------------------------

/// `connect` and `accept`: an invalid configuration, a peer that is not zmux, a peer that
/// ends and a handshake timeout each release the carrier once.
#[test]
fn connect_and_accept_release_a_failed_carrier_once() {
    watchdog(30, "connect and accept", || {
        type Start = fn(PipeIo, Config) -> Result<Session, ConnectError>;
        let starts: [(&str, Start); 2] = [
            ("connect", |p, c| Session::connect(p, c)),
            ("accept", |p, c| Session::accept(p, c)),
        ];
        for (name, start) in starts {
            // An invalid configuration: refused before anything runs.
            let (a, _b) = tcp_pair();
            let (io, c) = counted(a);
            let mut bad = Config::default();
            bad.max_pipes = 0;
            assert!(matches!(
                start(io, bad),
                Err(ConnectError::InvalidConfig(_))
            ));
            released(&c, &format!("{name}: invalid configuration"));
            // Not zmux.
            let (a, mut b) = tcp_pair();
            let (io, c) = counted(a);
            b.write_all(&[0xff; 64]).unwrap();
            assert!(start(io, Config::default()).is_err());
            released(&c, &format!("{name}: not zmux"));
            // The peer ends.
            let (a, b) = tcp_pair();
            let (io, c) = counted(a);
            drop(b);
            assert!(start(io, Config::default()).is_err());
            released(&c, &format!("{name}: the peer ended"));
            // A silent peer: the handshake timeout.
            let (a, _b) = tcp_pair();
            let (io, c) = counted(a);
            let mut quick = Config::default();
            quick.handshake_timeout = Some(Duration::from_millis(100));
            assert!(start(io, quick).is_err());
            released(&c, &format!("{name}: handshake timeout"));
        }
    });
}

/// A blocking listener with `serve` on a loopback port, accepted sessions kept.
fn listening(config: Config) -> (Listener, std::net::SocketAddr) {
    let l = Listener::new(config, ListenerConfig::default(), None).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let ll = l.clone();
    thread::spawn(move || ll.serve(&tcp));
    (l, addr)
}

/// `add_pipe`: a session without multipath, a join refused by the peer and a join that
/// times out each release the carrier once.
#[test]
fn add_pipe_releases_a_failed_carrier_once() {
    watchdog(30, "add_pipe", || {
        // Without multipath: refused at once.
        let (a, b) = tcp_pair();
        let server = thread::spawn(move || Session::accept(PipeIo::tcp(b), Config::default()));
        let client = Session::connect(PipeIo::tcp(a), Config::default()).unwrap();
        let _server = server.join().unwrap().unwrap();
        let (x, _y) = tcp_pair();
        let (io, c) = counted(x);
        assert_eq!(
            client.add_pipe(io, PipeOptions::default()).err(),
            Some(PipeError::NotNegotiated)
        );
        released(&c, "add_pipe without multipath");
        client.close(VarInt::from_u32(0), b"");
        // A multipath session on a listener.
        let mut quick = multipath();
        quick.join_timeout = Duration::from_millis(300);
        let (l, addr) = listening(multipath());
        let client =
            Session::connect(PipeIo::tcp(TcpStream::connect(addr).unwrap()), quick).unwrap();
        let _server = l.accept(Some(Duration::from_secs(5))).unwrap();
        // A join the listener closes: the carrier reaches a peer that is not zmux.
        let (x, mut y) = tcp_pair();
        let (io, c) = counted(x);
        let silent = thread::spawn(move || {
            let mut buf = [0; 256];
            let _ = y.read(&mut buf);
            drop(y);
        });
        assert!(client.add_pipe(io, PipeOptions::default()).is_err());
        released(&c, "add_pipe: the peer closed the join");
        silent.join().unwrap();
        // A join nobody answers: the join timeout.
        let (x, _y) = tcp_pair();
        let (io, c) = counted(x);
        assert_eq!(
            client.add_pipe(io, PipeOptions::default()).err(),
            Some(PipeError::TimedOut)
        );
        released(&c, "add_pipe: the join timed out");
        // No live pipe stays behind (a failed one awaits its retirement).
        let live: Vec<_> = client
            .pipes()
            .iter()
            .filter_map(|p| p.stats())
            .filter(|p| p.outbound != Some(zmux::OutboundState::Failed))
            .map(|p| p.pipe)
            .collect();
        assert_eq!(live, [PipeId::new(0)]);
        client.close(VarInt::from_u32(0), b"");
        l.close();
    });
}

/// A listener's new session: not zmux, a silent carrier, a carrier after `close`, and a
/// session whose handshake fails each release the carrier once.
#[test]
fn a_listener_releases_a_failed_carrier_once() {
    watchdog(30, "listener", || {
        let mut limits = ListenerConfig::default();
        limits.first_record_timeout = Duration::from_millis(100);
        let mut config = Config::default();
        config.handshake_timeout = Some(Duration::from_millis(200));
        let l = Listener::new(config, limits, None).unwrap();
        // Not zmux.
        let (a, mut b) = tcp_pair();
        b.write_all(&[0xff; 64]).unwrap();
        let (io, c) = counted(a);
        assert_eq!(
            l.handle_pipe(io, PipeHint::default()),
            Err(HandleError::Rejected)
        );
        released(&c, "listener: not zmux");
        // Silent past the first-record timeout.
        let (a, _b) = tcp_pair();
        let (io, c) = counted(a);
        assert_eq!(
            l.handle_pipe(io, PipeHint::default()),
            Err(HandleError::TimedOut)
        );
        released(&c, "listener: silent");
        // A client whose session handshake stops after its first record.
        let (a, b) = tcp_pair();
        let (io, c) = counted(a);
        let client = thread::spawn(move || {
            let mut quick = Config::default();
            quick.handshake_timeout = Some(Duration::from_millis(50));
            // The client gives up first and closes; the listener's session fails.
            let _ = Session::connect(PipeIo::tcp(b), quick);
        });
        let r = l.handle_pipe(io, PipeHint::default());
        client.join().unwrap();
        if r.is_ok() {
            // Started, then failed: the session's threads release the carrier.
            let s = l.accept(Some(Duration::from_secs(5)));
            drop(s);
        }
        released(&c, "listener: the session's handshake failed");
        // After close.
        l.close();
        let (a, _b) = tcp_pair();
        let (io, c) = counted(a);
        assert_eq!(
            l.handle_pipe(io, PipeHint::default()),
            Err(HandleError::Refused)
        );
        released(&c, "listener: closed");
    });
}

// ---- the close's linger ---------------------------------------------------------------

/// A session on a counted carrier to a blocking peer.
fn counted_session() -> (Session, Session, Arc<Counts>) {
    let (a, b) = tcp_pair();
    let server = thread::spawn(move || Session::accept(PipeIo::tcp(b), Config::default()));
    let (io, counts) = counted(a);
    let client = Session::connect(io, Config::default()).unwrap();
    (client, server.join().unwrap().unwrap(), counts)
}

fn wait_closed(s: &Session, secs: u64) -> Instant {
    let end = Instant::now() + Duration::from_secs(secs);
    while s.state() != SessionState::Closed {
        assert!(Instant::now() < end, "the session did not end");
        thread::sleep(Duration::from_millis(1));
    }
    Instant::now()
}

/// The peer reading: `close` returns as soon as the carrier took CONNECTION_CLOSE.
#[test]
fn close_returns_at_once_while_the_peer_reads() {
    watchdog(20, "close while the peer reads", || {
        let (client, server, counts) = counted_session();
        let begun = Instant::now();
        client.close(VarInt::from_u32(7), b"bye");
        assert!(
            begun.elapsed() < Duration::from_millis(300),
            "{:?}",
            begun.elapsed()
        );
        assert!(server.closed(Some(Duration::from_secs(5))).is_ok());
        drop(client);
        released(&counts, "close while the peer reads");
    });
}

/// Writes that block: CONNECTION_CLOSE waits at most the linger timeout for the carrier
/// and the linger follows, so `close` returns within its 1 s bound and the session ends.
#[test]
fn close_is_bounded_while_writes_block() {
    watchdog(20, "close while writes block", || {
        let (client, _server, counts) = counted_session();
        counts.blocked.store(true, Ordering::SeqCst);
        let begun = Instant::now();
        client.close(VarInt::from_u32(7), b"bye");
        let took = begun.elapsed();
        // Two linger periods of at least 250 ms each, never beyond the hand-off bound.
        assert!(took >= Duration::from_millis(240), "{took:?}");
        assert!(took < Duration::from_millis(1300), "{took:?}");
        wait_closed(&client, 5);
        drop(client);
        released(&counts, "close while writes block");
    });
}

/// A slow carrier delivers CONNECTION_CLOSE late, to a peer that stays silent: the linger
/// (250 ms at least) runs from that delivery, not from the call.
#[test]
fn the_linger_runs_from_the_delivery() {
    watchdog(20, "linger from delivery", || {
        let (client, _server, counts) = counted_session();
        counts.muted.store(true, Ordering::SeqCst);
        let begun = Instant::now();
        client.close(VarInt::from_u32(7), b"bye");
        let returned = Instant::now();
        let ended = wait_closed(&client, 5);
        let delivered = counts
            .last_write
            .lock()
            .unwrap()
            .expect("CONNECTION_CLOSE written");
        // `close` returned at the delivery, the slow write's time after the call.
        assert!(returned - begun >= SLOW - Duration::from_millis(50));
        assert!(returned >= delivered);
        assert!(
            ended - delivered >= Duration::from_millis(240),
            "the linger ended {:?} after the delivery",
            ended - delivered
        );
        assert!(ended - delivered < Duration::from_millis(2500));
        drop(client);
        released(&counts, "linger from delivery");
    });
}

// ---- the redial hook ------------------------------------------------------------------

/// A lost pipe of a dialling session with resume is replaced by the redial hook, without
/// `ResumeUnattended`; a session a listener accepted runs no hook.
#[test]
fn the_redial_hook_replaces_a_lost_pipe() {
    watchdog(30, "redial", || {
        let mut server = multipath();
        server.resume_timeout = Some(Duration::from_secs(10));
        // A hook of the accepting side is never run.
        let ran = Arc::new(AtomicUsize::new(0));
        let r = ran.clone();
        server.blocking_redial = Some(Dial::new(move |_| {
            r.fetch_add(1, Ordering::SeqCst);
            Err(io::ErrorKind::Unsupported.into())
        }));
        let (l, addr) = listening(server);
        let dials = Arc::new(AtomicUsize::new(0));
        let d = dials.clone();
        let mut client = multipath();
        client.resume_timeout = Some(Duration::from_secs(10));
        client.redial_min_backoff = Duration::from_millis(50);
        client.blocking_redial = Some(Dial::new(move |_| {
            d.fetch_add(1, Ordering::SeqCst);
            Ok(PipeIo::tcp(TcpStream::connect(addr)?))
        }));
        let c = Session::connect(PipeIo::tcp(TcpStream::connect(addr).unwrap()), client).unwrap();
        let s = l.accept(Some(Duration::from_secs(5))).unwrap();
        c.pipe(PipeId::new(0)).unwrap().abort().unwrap();
        let mut seen = Vec::new();
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match c.next_event(Some(left)) {
                Ok(Some(e)) => {
                    let done = matches!(e, SessionEvent::SessionResumed);
                    seen.push(e);
                    if done {
                        break;
                    }
                }
                other => panic!("{other:?} after {seen:?}"),
            }
        }
        assert!(
            !seen
                .iter()
                .any(|e| matches!(e, SessionEvent::ResumeUnattended)),
            "{seen:?}"
        );
        assert!(dials.load(Ordering::SeqCst) >= 1);
        // The session works over the replacement.
        let (mut w, mut rd) = c.open_bi().unwrap();
        w.write_all(b"after the redial").unwrap();
        w.finish().unwrap();
        let (mut sw, mut sr) = s.accept_bi().unwrap();
        let got = sr.read_to_end(1 << 10).unwrap();
        sw.write_all(&got).unwrap();
        sw.finish().unwrap();
        assert_eq!(rd.read_to_end(1 << 10).unwrap(), b"after the redial");
        assert_eq!(ran.load(Ordering::SeqCst), 0);
        c.close(VarInt::from_u32(0), b"");
        l.close();
    });
}

// ---- dropped handles --------------------------------------------------------------

fn streams_active(s: &Session) -> u64 {
    s.stats().streams_active
}

/// Waits until neither session has an active stream, at most 3 s.
fn all_released(a: &Session, b: &Session, what: &str) {
    let end = Instant::now() + Duration::from_secs(3);
    while streams_active(a) + streams_active(b) > 0 {
        assert!(
            Instant::now() < end,
            "{what}: {} and {} streams still active",
            streams_active(a),
            streams_active(b)
        );
        thread::sleep(Duration::from_millis(2));
    }
}

/// Dropped stream handles are released by the session, promptly and without blocking the
/// dropping thread, also after pipe 0 was replaced: the release is not tied to a pipe.
#[test]
fn dropped_streams_are_released_after_pipe_0_went() {
    watchdog(30, "dropped streams", || {
        let (l, addr) = listening(multipath());
        let c =
            Session::connect(PipeIo::tcp(TcpStream::connect(addr).unwrap()), multipath()).unwrap();
        let s = l.accept(Some(Duration::from_secs(5))).unwrap();
        let p1 = c
            .add_pipe(
                PipeIo::tcp(TcpStream::connect(addr).unwrap()),
                PipeOptions::default(),
            )
            .unwrap();
        c.pipe(PipeId::new(0)).unwrap().abort().unwrap();
        let end = Instant::now() + Duration::from_secs(5);
        while s.pipe(PipeId::new(0)).is_some_and(|p| {
            p.stats()
                .is_some_and(|i| i.outbound != Some(zmux::OutboundState::Failed))
        }) {
            assert!(Instant::now() < end, "pipe 0 still serves the server");
            thread::sleep(Duration::from_millis(2));
        }
        // Every kind of handle, each dropped unfinished, on both sides.
        for round in 0..3 {
            let (mut w, r) = c.open_bi().unwrap();
            w.write_all(b"unfinished").unwrap();
            let (sw, mut sr) = s.accept_bi().unwrap();
            let mut buf = [0; 10];
            sr.read_exact(&mut buf).unwrap();
            let begun = Instant::now();
            match round {
                0 => drop((w, r, sw, sr)),
                1 => drop((sr, sw, r, w)),
                _ => {
                    drop((w, r));
                    // The peer's handles end with the reset and the stop.
                    assert!(sr.read_to_end(1 << 10).is_err());
                    drop((sw, sr));
                }
            }
            assert!(
                begun.elapsed() < Duration::from_millis(100),
                "a drop blocked"
            );
            all_released(&c, &s, &format!("round {round}"));
        }
        assert!(p1.stats().is_some());
        c.close(VarInt::from_u32(0), b"");
        l.close();
    });
}
