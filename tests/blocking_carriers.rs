//! The std driver and the carriers handed to it: each is released exactly once on every
//! failure path of `connect`, `accept`, `add_pipe` and a listener's new session; the close's
//! linger runs from the delivery of `CONNECTION_CLOSE` to a carrier whose writes block; and
//! the redial hook replaces a lost pipe. Every test runs under a watchdog.

#![allow(
    clippy::many_single_char_names,
    reason = "short conventional names in scenario code"
)]
#![allow(
    clippy::large_stack_arrays,
    reason = "scenario code: buffers and futures stay on the stack on purpose, long scripted scenarios read top to bottom"
)]

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use zmux::blocking::{Listener, PipeHint, PipeIo, Session, WaitError};
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
        // A read already blocked on the socket when the carrier is muted must not deliver
        // what the peer does afterwards (its own close included): every return checks
        // for the mute, so the silence does not depend on when the reader re-entered.
        loop {
            if self.1.muted.load(Ordering::SeqCst) {
                // A peer that goes silent: nothing arrives until the carrier is shut down.
                self.1.wait_shut();
                return Ok(0);
            }
            // A shutdown does not end a read blocked in another thread on every platform
            // (not on Windows, for a peer that sends nothing): the read wakes up to look.
            match self.0.read(buf) {
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    if self.1.is_shut() {
                        return Ok(0);
                    }
                }
                r => {
                    if self.1.muted.load(Ordering::SeqCst) {
                        continue;
                    }
                    return r;
                }
            }
        }
    }
}

impl Drop for CountedRead {
    fn drop(&mut self) {
        self.1.reader_dropped.fetch_add(1, Ordering::SeqCst);
    }
}

/// How long each write of a muted carrier takes. `CONNECTION_CLOSE` is the second write
/// (a frame of 10 bytes goes first), and the wait for a carrier that does not take it is
/// bounded by two linger timeouts (250 ms at least each): both writes together stay well
/// within the first one, so a late scheduler does not end the wait before the delivery.
const SLOW: Duration = Duration::from_millis(100);

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
    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
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
        type Start = fn(PipeIo, Config) -> Result<Session, WaitError<ConnectError>>;
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
                Err(WaitError::Failed(ConnectError::InvalidConfig(_)))
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
        let server = thread::spawn(move || Session::accept(PipeIo::from_tcp(b), Config::default()));
        let client = Session::connect(PipeIo::from_tcp(a), Config::default()).unwrap();
        let _server = server.join().unwrap().unwrap();
        let (x, _y) = tcp_pair();
        let (io, c) = counted(x);
        assert!(matches!(
            client.add_pipe(io, PipeOptions::default()).err(),
            Some(WaitError::Failed(PipeError::NotNegotiated))
        ));
        released(&c, "add_pipe without multipath");
        client.close();
        // A multipath session on a listener.
        let mut quick = multipath();
        quick.join_timeout = Duration::from_millis(300);
        let (l, addr) = listening(multipath());
        let client =
            Session::connect(PipeIo::from_tcp(TcpStream::connect(addr).unwrap()), quick).unwrap();
        let _server = l
            .accept_timeout(Duration::from_secs(5))
            .ok()
            .flatten()
            .unwrap();
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
        assert!(matches!(
            client.add_pipe(io, PipeOptions::default()).err(),
            Some(WaitError::Failed(PipeError::Failed(
                zmux::PipeFailure::JoinTimedOut
            )))
        ));
        released(&c, "add_pipe: the join timed out");
        // No live pipe stays behind (a failed one awaits its retirement).
        let live: Vec<_> = client
            .pipes()
            .iter()
            .filter_map(zmux::blocking::Pipe::stats)
            .filter(|p| p.outbound != Some(zmux::OutboundState::Failed))
            .map(|p| p.pipe)
            .collect();
        assert_eq!(live, [PipeId::new(0)]);
        client.close();
        l.close();
    });
}

struct ReplyWriter {
    buffered: io::BufWriter<TcpStream>,
    gate: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
}

impl Write for ReplyWriter {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.buffered.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        if let Some((entered, release)) = self.gate.take() {
            entered.send(()).unwrap();
            release.recv_timeout(Duration::from_secs(3)).unwrap();
        }
        self.buffered.flush()
    }
}

#[test]
// HS-04
fn authenticated_refusal_returns_before_reply_flush() {
    watchdog(10, "authenticated refusal", || {
        let mut config = multipath();
        config.max_pipes = 2;
        config.pipe_headroom = 0;
        let reports = |config: &mut Config| {
            let (tx, rx) = mpsc::channel();
            config.join_outcome = Some(zmux::JoinOutcome::new(move |_, pipe, error| {
                tx.send((pipe, error)).unwrap();
                zmux::Decision::Now(())
            }));
            rx
        };
        let incoming = reports(&mut config);
        let (listener, addr) = listening(config);
        let dial = || PipeIo::from_tcp(TcpStream::connect(addr).unwrap());
        let mut config = multipath();
        let outgoing = reports(&mut config);
        let client = Session::connect(dial(), config).unwrap();
        let _server = listener.accept().unwrap();
        let first = client.add_pipe(dial(), PipeOptions::default()).unwrap();
        for rx in [&incoming, &outgoing] {
            assert!(
                matches!(rx.recv_timeout(Duration::from_secs(3)), Ok((id, None)) if id == first.id())
            );
        }
        let mut limits = listener.limits();
        limits.max_pending = Some(1);
        listener.set_limits(limits).unwrap();
        let (near, far) = tcp_pair();
        let (entered, flushing) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let (result, setup) = mpsc::channel();
        let writer = ReplyWriter {
            buffered: io::BufWriter::new(far.try_clone().unwrap()),
            gate: Some((entered, gate)),
        };
        let closer = far.try_clone().unwrap();
        let io = PipeIo::from_halves(far, writer).with_closer(move |how| {
            let _ = closer.shutdown(how);
        });
        let l = listener.clone();
        thread::spawn(move || {
            result.send(l.handle_pipe(io, PipeHint::default())).unwrap();
        });
        let refused = client
            .begin_add_pipe(PipeIo::from_tcp(near), PipeOptions::default())
            .unwrap();
        flushing.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(
            setup.recv_timeout(Duration::from_secs(1)).unwrap(),
            Err(HandleError::Refused)
        );
        // An EOF carrier reaches first-record classification only with a slot.
        let probe = || {
            let entered = Arc::new(AtomicBool::new(false));
            let seen = entered.clone();
            let (local, peer) = tcp_pair();
            drop(peer);
            let io = PipeIo::from_tcp(local).with_exporter_async(move |_| {
                seen.store(true, Ordering::SeqCst);
                std::future::ready(Ok(vec![0; 32]))
            });
            let _ = listener.handle_pipe(io, PipeHint::default());
            entered.load(Ordering::SeqCst)
        };
        assert!(!probe());
        let mut limits = listener.limits();
        limits.max_pending = Some(4);
        limits.max_pending_per_source = 2;
        listener.set_limits(limits).unwrap();
        let (local, _peer) = tcp_pair();
        let (started, waiting) = mpsc::channel();
        let second = PipeIo::from_tcp(local).with_exporter_async(move |_| {
            started.send(()).unwrap();
            std::future::pending()
        });
        let other = listener.clone();
        let held = thread::spawn(move || other.handle_pipe(second, PipeHint::default()));
        waiting.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!probe());
        release.send(()).unwrap();
        assert!(matches!(
            refused.joined(),
            Err(WaitError::Failed(PipeError::Failed(
                zmux::PipeFailure::JoinRefused
            )))
        ));
        for rx in [&incoming, &outgoing] {
            assert!(
                matches!(rx.recv_timeout(Duration::from_secs(3)), Ok((id, Some(zmux::JoinError::Refused))) if id == refused.id())
            );
            assert!(rx.try_recv().is_err());
        }
        let until = Instant::now() + Duration::from_secs(1);
        while !probe() {
            assert!(Instant::now() < until, "the refusal still holds the slot");
            thread::yield_now();
        }
        listener.close();
        assert_eq!(held.join().unwrap(), Err(HandleError::Refused));
    });
}

/// Retirement wakes the reader; releasing it can finish later.
#[test]
fn pipe_closed_waits_for_the_blocking_reader() {
    struct Reader {
        stream: TcpStream,
        ending: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }
    impl Read for Reader {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.stream.read(b)
        }
    }
    impl Drop for Reader {
        fn drop(&mut self) {
            let _ = self.ending.send(());
            let _ = self.release.recv_timeout(Duration::from_secs(5));
        }
    }
    watchdog(10, "pipe reader cleanup", || {
        let (listener, addr) = listening(multipath());
        let client = Session::connect(
            PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
            multipath(),
        )
        .unwrap();
        let _server = listener.accept().unwrap();
        let stream = TcpStream::connect(addr).unwrap();
        let (ending, at_drop) = mpsc::channel();
        let (release, gate) = mpsc::channel();
        let reader = Reader {
            stream: stream.try_clone().unwrap(),
            ending,
            release: gate,
        };
        let closer = stream.try_clone().unwrap();
        let io = PipeIo::from_halves(reader, stream).with_closer(move |how| {
            let _ = closer.shutdown(how);
        });
        let pipe = client.add_pipe(io, PipeOptions::default()).unwrap();
        pipe.abort().unwrap();
        at_drop.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(matches!(
            pipe.closed_timeout(Duration::ZERO),
            Err(WaitError::TimedOut)
        ));
        release.send(()).unwrap();
        assert!(matches!(
            pipe.closed_timeout(Duration::from_secs(3)),
            Err(WaitError::Failed(PipeError::Failed(
                zmux::PipeFailure::Aborted
            )))
        ));
        listener.close();
    });
}

/// A listener's new session: not zmux, a silent carrier, a carrier after `close`, and a
/// session whose handshake fails each release the carrier once.
#[test]
fn a_listener_releases_a_failed_carrier_once() {
    watchdog(30, "listener", || {
        let mut limits = ListenerConfig::default();
        limits.limits.first_record_timeout = Duration::from_millis(100);
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
            let _ = Session::connect(PipeIo::from_tcp(b), quick);
        });
        let r = l.handle_pipe(io, PipeHint::default());
        client.join().unwrap();
        if r.is_ok() {
            // Started, then failed: the session's threads release the carrier.
            let s = l.accept_timeout(Duration::from_secs(5)).ok().flatten();
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

/// A later `on_reject` is dropped when the listener closes, as on the tokio
/// listener: the handler ends with the close, not at the handshake timeout.
#[test]
fn a_later_reject_policy_ends_with_the_listener() {
    watchdog(30, "later reject", || {
        let mut limits = ListenerConfig::default();
        limits.handshake_timeout = Duration::from_secs(30);
        limits.on_reject = Some(zmux::OnReject::new_async(|_| std::future::pending()));
        let l = Listener::new(Config::default(), limits, None).unwrap();
        let (a, mut b) = tcp_pair();
        b.write_all(&[0xff; 64]).unwrap();
        let handler = {
            let l = l.clone();
            thread::spawn(move || l.handle_pipe(PipeIo::from_tcp(a), PipeHint::default()))
        };
        thread::sleep(Duration::from_millis(100));
        let started = Instant::now();
        l.close();
        assert!(handler.join().unwrap().is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
    });
}

// ---- the close's linger ---------------------------------------------------------------

/// A session on a counted carrier to a blocking peer.
fn counted_session() -> (Session, Session, Arc<Counts>) {
    counted_session_with(Config::default())
}

/// [`counted_session`] with the client's own configuration.
fn counted_session_with(client: Config) -> (Session, Session, Arc<Counts>) {
    let (a, b) = tcp_pair();
    let server = thread::spawn(move || Session::accept(PipeIo::from_tcp(b), Config::default()));
    let (io, counts) = counted(a);
    let client = Session::connect(io, client).unwrap();
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

/// The peer reading: `close` returns as soon as the carrier took `CONNECTION_CLOSE`. The
/// hand-off and linger timers last an hour, so a close that returns (within the watchdog)
/// waited for neither.
#[test]
fn close_returns_at_once_while_the_peer_reads() {
    watchdog(20, "close while the peer reads", || {
        let hour = Duration::from_secs(3600);
        let mut c = Config::default();
        c.test_hooks().close_handoff_limit = Some(hour);
        c.test_hooks().linger_timeout = Some(hour);
        let (client, server, counts) = counted_session_with(c);
        client.abort(VarInt::from_u32(7), b"bye");
        assert!(server.closing_timeout(Duration::from_secs(5)).is_ok());
        drop(client);
        released(&counts, "close while the peer reads");
    });
}

/// A coded close: what was written reaches the peer ahead of the code, the peer sees the
/// code and the reason, and `wait` returns once the peer ended its side, well before the
/// linger timeout; a later plain close changes nothing.
#[test]
fn a_coded_close_delivers_its_code_and_the_wait_confirms_it() {
    watchdog(20, "a coded close", || {
        let mut c = Config::default();
        c.test_hooks().linger_timeout = Some(Duration::from_secs(3600));
        let (client, server, _counts) = counted_session_with(c);
        let (mut w, _r) = client.open_bi().unwrap();
        w.write_all(&[5; 100_000]).unwrap();
        w.finish().unwrap();
        // Accepted before the close: a later accept fails with the session's error.
        let (_sw, mut r) = server.accept_bi_timeout(Duration::from_secs(5)).unwrap();
        client.close_with_error(VarInt::from_u32(0x2a), b"bye");
        client.close();
        let got = r.read_to_end(200_000).unwrap();
        assert_eq!(got, [5; 100_000]);
        let e = server.closing_timeout(Duration::from_secs(5)).unwrap();
        assert!(
            matches!(&e, zmux::SessionError::ApplicationClosed { code, reason, remote: true }
                if *code == VarInt::from_u32(0x2a) && reason.as_ref() == b"bye"),
            "{e:?}"
        );
        assert!(
            client.closed_timeout(Duration::from_secs(5)).is_ok(),
            "the wait confirmed the delivery"
        );
    });
}

/// Writes that block: `CONNECTION_CLOSE` waits at most the linger timeout for the carrier
/// and the linger follows, so `close` returns within its 1 s bound and the session ends.
#[test]
fn close_is_bounded_while_writes_block() {
    watchdog(20, "close while writes block", || {
        let (client, _server, counts) = counted_session();
        counts.blocked.store(true, Ordering::SeqCst);
        let begun = Instant::now();
        client.close();
        let took = begun.elapsed();
        // Two linger periods of at least 250 ms each, never beyond the hand-off bound.
        assert!(took >= Duration::from_millis(240), "{took:?}");
        // A guard against a hang only: three hand-off bounds and a second.
        assert!(took < Duration::from_secs(4), "{took:?}");
        wait_closed(&client, 5);
        drop(client);
        released(&counts, "close while writes block");
    });
}

/// Writes that block: an abort queues `CONNECTION_CLOSE` behind a write the carrier never
/// completes; the hand-off limit (1 s) and the linger still end the session, closing the
/// carrier, which releases the stuck write.
#[test]
fn abort_ends_while_writes_block() {
    watchdog(20, "abort while writes block", || {
        let (client, _server, counts) = counted_session();
        counts.blocked.store(true, Ordering::SeqCst);
        // A write the carrier never completes, ahead of CONNECTION_CLOSE.
        let (mut w, _r) = client.open_bi().unwrap();
        let _ = w.write_all(&[1; 1000]);
        thread::sleep(Duration::from_millis(50));
        let begun = Instant::now();
        client.abort(VarInt::from_u32(3), b"gone");
        let ended = wait_closed(&client, 5);
        assert!(
            ended - begun < Duration::from_secs(3),
            "{:?}",
            ended - begun
        );
        drop(w);
        drop(client);
        released(&counts, "abort while writes block");
    });
}

/// Writes that block: the idle timeout's `CONNECTION_CLOSE` never reaches the carrier, and
/// the session still ends within the close bounds.
#[test]
fn idle_close_ends_while_writes_block() {
    watchdog(20, "idle close while writes block", || {
        let mut c = Config::default();
        c.max_idle_timeout = Some(Duration::from_millis(300));
        c.liveness.keep_alive_period = None;
        let (client, _server, counts) = counted_session_with(c);
        counts.blocked.store(true, Ordering::SeqCst);
        let (mut w, _r) = client.open_bi().unwrap();
        let _ = w.write_all(&[1; 1000]);
        let begun = Instant::now();
        let ended = wait_closed(&client, 8);
        assert!(
            ended - begun < Duration::from_secs(4),
            "{:?}",
            ended - begun
        );
        drop(w);
        drop(client);
        released(&counts, "idle close while writes block");
    });
}

/// A slow carrier delivers `CONNECTION_CLOSE` late, to a peer that stays silent: the linger
/// (250 ms at least) runs from that delivery, not from the call.
#[test]
fn the_linger_runs_from_the_delivery() {
    watchdog(20, "linger from delivery", || {
        let (client, _server, counts) = counted_session();
        counts.muted.store(true, Ordering::SeqCst);
        let begun = Instant::now();
        client.close();
        let returned = Instant::now();
        let ended = wait_closed(&client, 5);
        let delivered = counts
            .last_write
            .lock()
            .unwrap()
            .expect("CONNECTION_CLOSE written");
        // `close` returned at the delivery, the slow write's time after the call.
        assert!(returned - begun >= SLOW.saturating_sub(Duration::from_millis(50)));
        assert!(returned >= delivered);
        assert!(
            ended - delivered >= Duration::from_millis(240),
            "the linger ended {:?} after the delivery",
            ended - delivered
        );
        // A guard against a hang only, above three linger periods and a second.
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
        server.redial = Some(zmux::Redial::blocking(move |_| {
            r.fetch_add(1, Ordering::SeqCst);
            Err(io::ErrorKind::Unsupported.into())
        }));
        let (l, addr) = listening(server);
        let dials = Arc::new(AtomicUsize::new(0));
        let d = dials.clone();
        let mut client = multipath();
        client.resume_timeout = Some(Duration::from_secs(10));
        client.redial_backoff.min = Duration::from_millis(50);
        client.redial = Some(zmux::Redial::blocking(move |_| {
            d.fetch_add(1, Ordering::SeqCst);
            Ok(PipeIo::from_tcp(TcpStream::connect(addr)?))
        }));
        let c =
            Session::connect(PipeIo::from_tcp(TcpStream::connect(addr).unwrap()), client).unwrap();
        let s = l
            .accept_timeout(Duration::from_secs(5))
            .ok()
            .flatten()
            .unwrap();
        c.pipe(PipeId::new(0)).unwrap().abort().unwrap();
        let mut seen = Vec::new();
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match c.next_event_timeout(left) {
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
        c.close();
        l.close();
    });
}

/// `replace_pipes` advances the epoch and replaces every pipe, make before break, with one
/// dialled through the redial hook and joined in the new epoch; without the hook it is the
/// configuration error.
#[test]
// HS-21
fn replace_pipes_replaces_every_pipe() {
    watchdog(30, "replace_pipes", || {
        let manual = || {
            let mut c = multipath();
            c.epoch_policy = zmux::EpochPolicy::MANUAL;
            c
        };
        let (l, addr) = listening(manual());
        let none = Session::connect(
            PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
            manual(),
        )
        .unwrap();
        assert!(matches!(
            none.replace_pipes_timeout(Duration::from_secs(5)),
            Err(WaitError::Failed(PipeError::InvalidOptions(e))) if e.field() == "redial"
        ));
        none.close();
        let _ = l
            .accept_timeout(Duration::from_secs(5))
            .ok()
            .flatten()
            .unwrap();
        let dials = Arc::new(AtomicUsize::new(0));
        let d = dials.clone();
        let mut client = manual();
        client.redial = Some(zmux::Redial::blocking(move |_| {
            d.fetch_add(1, Ordering::SeqCst);
            Ok(PipeIo::from_tcp(TcpStream::connect(addr)?))
        }));
        let c =
            Session::connect(PipeIo::from_tcp(TcpStream::connect(addr).unwrap()), client).unwrap();
        let s = l
            .accept_timeout(Duration::from_secs(5))
            .ok()
            .flatten()
            .unwrap();
        assert_eq!(c.epoch(), Some(0));
        // The exchange runs over a pipe joined Sealed or Bound.
        c.add_pipe(
            PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
            PipeOptions::new(),
        )
        .unwrap();
        let before: Vec<_> = c.pipes().iter().map(zmux::blocking::Pipe::id).collect();
        c.replace_pipes_timeout(Duration::from_secs(20)).unwrap();
        assert_eq!(c.epoch(), Some(1));
        assert!(dials.load(Ordering::SeqCst) >= before.len());
        let live: Vec<_> = c
            .pipe_stats()
            .into_iter()
            .filter(|p| p.outbound == Some(zmux::OutboundState::Active))
            .collect();
        assert_ne!(live, Vec::new());
        for p in &live {
            assert!(!before.contains(&p.pipe), "{p:?}");
            assert_eq!(p.epoch, Some(1), "{p:?}");
        }
        let (mut w, mut rd) = c.open_bi().unwrap();
        w.write_all(b"after the replacement").unwrap();
        w.finish().unwrap();
        let (mut sw, mut sr) = s.accept_bi().unwrap();
        let got = sr.read_to_end(1 << 10).unwrap();
        sw.write_all(&got).unwrap();
        sw.finish().unwrap();
        assert_eq!(rd.read_to_end(1 << 10).unwrap(), b"after the replacement");
        c.close();
        l.close();
    });
}

// ---- dropped handles --------------------------------------------------------------

/// Runs `f` while no carrier can write, then opens the gate again.
fn gate_shut(gate: &Gate, f: impl FnOnce()) {
    gate.set(true);
    f();
    gate.set(false);
}

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

/// Every carrier's writes, on both sides, wait while the gate is shut.
#[derive(Default)]
struct Gate {
    shut: Mutex<bool>,
    changed: Condvar,
}

impl Gate {
    fn set(&self, shut: bool) {
        *self.shut.lock().unwrap() = shut;
        self.changed.notify_all();
    }
}

#[derive(Clone)]
struct SharedSocket(Arc<TcpStream>);

impl Read for SharedSocket {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        (&*self.0).read(b)
    }
}

impl Write for SharedSocket {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        (&*self.0).write(b)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&*self.0).flush()
    }
}

struct GatedWrite(SharedSocket, Arc<Gate>);

impl Write for GatedWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut shut = self.1.shut.lock().unwrap();
        while *shut {
            shut = self.1.changed.wait(shut).unwrap();
        }
        drop(shut);
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// A carrier on `s` whose writes pass `gate`.
fn gated(s: TcpStream, gate: &Arc<Gate>) -> PipeIo {
    let socket = SharedSocket(Arc::new(s));
    let closer = PipeIo::tcp_closer(socket.0.clone());
    PipeIo::from_halves(socket.clone(), GatedWrite(socket, gate.clone())).with_closer(closer)
}

/// Dropped stream handles are released by the session, promptly and without blocking the
/// dropping thread, also after pipe 0 was replaced: the release is not tied to a pipe. The
/// drops run while no carrier can write, so a drop that returns waited for no write.
#[test]
fn dropped_streams_are_released_after_pipe_0_went() {
    watchdog(30, "dropped streams", || {
        let gate = Arc::new(Gate::default());
        let l = Listener::new(multipath(), ListenerConfig::default(), None).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();
        {
            let (l, gate) = (l.clone(), gate.clone());
            thread::spawn(move || {
                while let Ok((s, peer)) = tcp.accept() {
                    let (l, io) = (l.clone(), gated(s, &gate));
                    thread::spawn(move || l.handle_pipe(io, PipeHint { source: Some(peer) }));
                }
            });
        }
        let dial = || gated(TcpStream::connect(addr).unwrap(), &gate);
        let c = Session::connect(dial(), multipath()).unwrap();
        let s = l
            .accept_timeout(Duration::from_secs(5))
            .ok()
            .flatten()
            .unwrap();
        let p1 = c.add_pipe(dial(), PipeOptions::default()).unwrap();
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
            match round {
                0 => gate_shut(&gate, || drop((w, r, sw, sr))),
                1 => gate_shut(&gate, || drop((sr, sw, r, w))),
                _ => {
                    gate_shut(&gate, || drop((w, r)));
                    // The peer's handles end with the reset and the stop.
                    assert!(sr.read_to_end(1 << 10).is_err());
                    gate_shut(&gate, || drop((sw, sr)));
                }
            }
            all_released(&c, &s, &format!("round {round}"));
        }
        assert!(p1.stats().is_some());
        c.close();
        l.close();
    });
}

#[test]
fn closing_listener_interrupts_pending_blocking_exporter() {
    watchdog(5, "blocking exporter cancellation", || {
        let mut limits = ListenerConfig::default();
        limits.handshake_timeout = Duration::MAX;
        let listener = Listener::new(multipath(), limits, None).unwrap();
        let (local, mut peer) = tcp_pair();
        let (entered, started) = mpsc::channel();
        let io = PipeIo::from_tcp(local).with_exporter_async(move |_| {
            entered.send(()).unwrap();
            std::future::pending()
        });
        let l = listener.clone();
        let handler = thread::spawn(move || l.handle_pipe(io, PipeHint::default()));
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        listener.close();
        assert_eq!(handler.join().unwrap(), Err(HandleError::Refused));
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    });
}

#[test]
fn one_way_handoff_ends_only_the_unused_tcp_direction() {
    watchdog(8, "directional TCP handoff", || {
        let (listener, addr) = listening(multipath());
        let client = Session::connect(
            PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
            multipath(),
        )
        .unwrap();
        let server = listener.accept().unwrap();
        let (near, far) = tcp_pair();
        let mut eof = near.try_clone().unwrap();
        let (done, handled) = mpsc::channel();
        let l = listener.clone();
        thread::spawn(move || {
            done.send(l.handle_pipe(PipeIo::from_tcp(far), PipeHint::default()))
                .unwrap();
        });
        let mut options = PipeOptions::new();
        options.direction = zmux::PipeDirection::Out;
        // Keep the probe's socket read side open when the client retires
        // its unused reader. EOF can now come only from the server's FIN.
        let closer = near.try_clone().unwrap();
        let observed =
            PipeIo::from_halves(near.try_clone().unwrap(), near).with_closer(move |how| {
                if how != Shutdown::Read {
                    let _ = closer.shutdown(how);
                }
            });
        let added = client.add_pipe(observed, options).unwrap();
        handled
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap();
        eof.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        assert_eq!(eof.read(&mut [0]).unwrap(), 0);
        let mut reverse = PipeOptions::new();
        reverse.direction = zmux::PipeDirection::In;
        let _reverse = client
            .add_pipe(PipeIo::from_tcp(TcpStream::connect(addr).unwrap()), reverse)
            .unwrap();
        added.attached().unwrap();
        client.pipe(PipeId::new(0)).unwrap().abort().unwrap();
        let payload = vec![83; 32768];
        let before = added.stats().unwrap().bytes_sent;
        let mut send = client.open_uni().unwrap();
        send.write_all(&payload).unwrap();
        send.finish().unwrap();
        let mut recv = server.accept_uni().unwrap();
        assert_eq!(recv.read_to_end(payload.len()).unwrap(), payload);
        assert!(added.stats().unwrap().bytes_sent - before >= payload.len() as u64);
        listener.close();
    });
}

#[test]
fn confirmed_blocking_join_returns_while_unused_half_drops() {
    struct Half {
        stream: TcpStream,
        gate: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
    }
    impl Read for Half {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.stream.read(b)
        }
    }
    impl Write for Half {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.stream.write(b)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }
    impl Drop for Half {
        fn drop(&mut self) {
            if let Some((entered, gate)) = self.gate.take() {
                let _ = entered.send(());
                let _ = gate.recv_timeout(Duration::from_secs(4));
            }
        }
    }
    watchdog(12, "one-way half cleanup", || {
        let (listener, addr) = listening(multipath());
        let client = Session::connect(
            PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
            multipath(),
        )
        .unwrap();
        let _server = listener.accept().unwrap();
        for direction in [zmux::PipeDirection::Out, zmux::PipeDirection::In] {
            let (near, far) = tcp_pair();
            let (entered, dropping) = mpsc::channel();
            let (release, gate) = mpsc::channel();
            let mut latch = Some((entered, gate));
            let r = Half {
                stream: far.try_clone().unwrap(),
                gate: if direction == zmux::PipeDirection::In {
                    latch.take()
                } else {
                    None
                },
            };
            let w = Half {
                stream: far.try_clone().unwrap(),
                gate: latch,
            };
            let io = PipeIo::from_halves(r, w).with_closer(move |how| {
                let _ = far.shutdown(how);
            });
            let l = listener.clone();
            let (done, handled) = mpsc::channel();
            thread::spawn(move || done.send(l.handle_pipe(io, PipeHint::default())).unwrap());
            let mut options = PipeOptions::new();
            options.direction = direction;
            let _pipe = client
                .begin_add_pipe(PipeIo::from_tcp(near), options)
                .unwrap();
            dropping.recv_timeout(Duration::from_secs(3)).unwrap();
            handled
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .unwrap();
            release.send(()).unwrap();
        }
        listener.close();
    });
}

#[test]
fn replacement_carrier_receives_setup_interrupts() {
    struct Reading(SharedSocket, mpsc::Sender<()>);
    impl Read for Reading {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            self.1.send(()).unwrap();
            self.0.read(b)
        }
    }
    watchdog(8, "replacement closer", || {
        for stop in [true, false] {
            let (input, _peer) = tcp_pair();
            let (output, mut actual_peer) = tcp_pair();
            let (at_read, entered) = mpsc::channel();
            let output = SharedSocket(Arc::new(output));
            let closer = PipeIo::tcp_closer(output.0.clone());
            let replacement = Mutex::new(Some(
                PipeIo::from_halves(Reading(output.clone(), at_read), output).with_closer(closer),
            ));
            let transform = zmux::blocking::InboundTransform::new(move |_, _| {
                Ok(replacement.lock().unwrap().take().unwrap())
            });
            let mut limits = ListenerConfig::default();
            limits.limits.first_record_timeout = if stop {
                Duration::from_secs(30)
            } else {
                Duration::from_millis(250)
            };
            let listener = Listener::new(multipath(), limits, Some(transform)).unwrap();
            let l = listener.clone();
            let task =
                thread::spawn(move || l.handle_pipe(PipeIo::from_tcp(input), PipeHint::default()));
            entered.recv_timeout(Duration::from_secs(2)).unwrap();
            if stop {
                listener.close();
            }
            assert!(task.join().unwrap().is_err());
            assert_eq!(actual_peer.read(&mut [0]).unwrap(), 0);
        }
    });
}

#[test]
fn listener_close_before_accept_uses_application_zero() {
    watchdog(5, "closing a queued session", || {
        let listener = Listener::new(Config::default(), ListenerConfig::default(), None).unwrap();
        let (a, b) = tcp_pair();
        let client = thread::spawn(move || {
            Session::connect(PipeIo::from_tcp(a), Config::default()).unwrap()
        });
        listener
            .handle_pipe(PipeIo::from_tcp(b), PipeHint::default())
            .unwrap();
        let client = client.join().unwrap();
        listener.close();
        assert!(matches!(
            client.closing().unwrap(),
            zmux::SessionError::ApplicationClosed {
                code: VarInt::ZERO,
                remote: true,
                ..
            }
        ));
    });
}

#[test]
// HS-35
fn close_during_bootstrap_transport_handoff() {
    struct Gate(TcpStream, Option<Listener>);
    impl Write for Gate {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if let Some(listener) = self.1.take() {
                listener.close();
            }
            self.0.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }
    watchdog(5, "closing while the session writes its bootstrap", || {
        let listener = Listener::new(Config::default(), ListenerConfig::default(), None).unwrap();
        let (a, b) = tcp_pair();
        let client =
            thread::spawn(move || Session::connect(PipeIo::from_tcp(a), Config::default()));
        let closer = b.try_clone().unwrap();
        let reader = b.try_clone().unwrap();
        let pipe =
            PipeIo::from_halves(reader, Gate(b, Some(listener.clone()))).with_closer(move |how| {
                let _ = closer.shutdown(how);
            });
        let _ = listener.handle_pipe(pipe, PipeHint::default());
        match client.join().unwrap() {
            Ok(session) => assert!(matches!(
                session.closing().unwrap(),
                zmux::SessionError::ApplicationClosed {
                    code: VarInt::ZERO,
                    remote: true,
                    ..
                }
            )),
            Err(WaitError::Failed(ConnectError::SessionLost(
                zmux::SessionError::ApplicationClosed {
                    code: VarInt::ZERO,
                    remote: true,
                    ..
                },
            ))) => {}
            Err(e) => panic!("peer did not see an application close: {e:?}"),
        }
    });
}

#[test]
fn shutdown_codes_distinguish_queued_and_accepted_sessions() {
    watchdog(8, "closing queued and accepted sessions", || {
        let listener = Listener::new(Config::default(), ListenerConfig::default(), None).unwrap();
        let mut clients = Vec::new();
        let mut accepted = Vec::new();
        for i in 0..2 {
            let (near, far) = tcp_pair();
            let l = listener.clone();
            let setup =
                thread::spawn(move || l.handle_pipe(PipeIo::from_tcp(far), PipeHint::default()));
            clients.push(Session::connect(PipeIo::from_tcp(near), Config::default()).unwrap());
            setup.join().unwrap().unwrap();
            if i == 0 {
                accepted.push(listener.accept().unwrap());
            }
        }
        listener.shutdown(VarInt::from_u32(79), b"maintenance");
        for (client, want) in clients.iter().zip([79, 0]) {
            let error = client.closing_timeout(Duration::from_secs(3)).unwrap();
            assert!(
                matches!(error, zmux::SessionError::ApplicationClosed {code, remote: true, ..} if code == VarInt::from_u32(want)),
                "{error:?}"
            );
        }
    });
}

#[test]
// HS-26
fn a_join_callback_can_wait_for_its_own_session_to_close() {
    watchdog(8, "callback waits for blocking session", || {
        let (entered, entering) = mpsc::channel();
        let (left, leaving) = mpsc::channel();
        let mut cfg = multipath();
        cfg.join_outcome = Some(zmux::JoinOutcome::new(move |session, _, why| {
            assert!(why.is_none());
            let s = match session {
                zmux::JoinSession::Blocking(s) => s,
                #[cfg(feature = "tokio")]
                zmux::JoinSession::Tokio(_) => unreachable!(),
            };
            entered.send(()).unwrap();
            left.send(s.closed().unwrap()).unwrap();
            zmux::Decision::Now(())
        }));
        let listener = Listener::new(cfg.clone(), ListenerConfig::default(), None).unwrap();
        let incoming = || {
            let (a, b) = tcp_pair();
            let l = listener.clone();
            (
                PipeIo::from_tcp(a),
                thread::spawn(move || l.handle_pipe(PipeIo::from_tcp(b), PipeHint::default())),
            )
        };
        let (bootstrap, setup) = incoming();
        let client = Session::connect(bootstrap, cfg).unwrap();
        setup.join().unwrap().unwrap();
        let _server = listener.accept().unwrap();
        let (next, setup) = incoming();
        let pipe = client.add_pipe(next, PipeOptions::default()).unwrap();
        setup.join().unwrap().unwrap();
        entering.recv().unwrap();
        entering.recv().unwrap();
        client.close();
        leaving.recv().unwrap();
        leaving.recv().unwrap();
        pipe.attached().unwrap();
    });
}

#[test]
// HS-24
fn replacement_preserves_the_callers_deadline_in_its_join_outcome() {
    watchdog(10, "join with caller deadline", || {
        let mut cfg = multipath();
        cfg.epoch_policy = zmux::EpochPolicy::MANUAL;
        let (listener, addr) = listening(cfg.clone());
        let (silent, _peer) = tcp_pair();
        let carrier = Mutex::new(Some(silent));
        cfg.redial = Some(zmux::Redial::blocking(move |_| {
            Ok(PipeIo::from_tcp(carrier.lock().unwrap().take().unwrap()))
        }));
        let (tx, rx) = mpsc::channel();
        cfg.join_outcome = Some(zmux::JoinOutcome::new(move |_, id, error| {
            tx.send((id, error)).unwrap();
            zmux::Decision::Now(())
        }));
        let client =
            Session::connect(PipeIo::from_tcp(TcpStream::connect(addr).unwrap()), cfg).unwrap();
        let _server = listener.accept().unwrap();
        client
            .add_pipe(
                PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
                PipeOptions::new(),
            )
            .unwrap();
        assert!(rx.recv().unwrap().1.is_none());
        assert!(matches!(
            client.replace_pipes_timeout(Duration::from_secs(1)),
            Err(WaitError::TimedOut)
        ));
        let (id, outcome) = rx.recv().unwrap();
        assert_ne!(id, PipeId::UNASSIGNED);
        assert!(
            matches!(outcome, Some(zmux::JoinError::CallerDeadline)),
            "{outcome:?}"
        );
    });
}

/// Confirm traverses a real TCP carrier, but the first record cannot reach the
/// peer until after the caller's deadline. Keep a public handle across cleanup.
#[test]
// HS-23
fn caller_deadline_aborts_a_locally_installed_replacement() {
    struct RecordsGate {
        stream: SharedSocket,
        handshakes: u8,
        entered: Option<mpsc::Sender<()>>,
        release: mpsc::Receiver<()>,
    }
    impl Write for RecordsGate {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.handshakes > 0 {
                self.handshakes -= 1;
            } else if let Some(entered) = self.entered.take() {
                entered.send(()).unwrap();
                let _ = self.release.recv();
            }
            self.stream.write_all(bytes)?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    watchdog(10, "deadline after replacement Confirm", || {
        let mut cfg = multipath();
        cfg.epoch_policy = zmux::EpochPolicy::MANUAL;
        let (listener, addr) = listening(cfg.clone());
        let stream = SharedSocket(Arc::new(TcpStream::connect(addr).unwrap()));
        let closer = PipeIo::tcp_closer(stream.0.clone());
        let (notify, entered) = mpsc::channel();
        let (release, signal) = mpsc::channel();
        let io = PipeIo::from_halves(
            stream.clone(),
            RecordsGate {
                stream,
                handshakes: 2,
                entered: Some(notify),
                release: signal,
            },
        )
        .with_closer(closer);
        let carrier = Mutex::new(Some(io));
        cfg.redial = Some(zmux::Redial::blocking(move |_| {
            Ok(carrier.lock().unwrap().take().unwrap())
        }));
        let (tx, rx) = mpsc::channel();
        cfg.join_outcome = Some(zmux::JoinOutcome::new(move |_, id, error| {
            tx.send((id, error)).unwrap();
            zmux::Decision::Now(())
        }));
        let client =
            Session::connect(PipeIo::from_tcp(TcpStream::connect(addr).unwrap()), cfg).unwrap();
        let _server = listener.accept().unwrap();
        let old = client
            .add_pipe(
                PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
                PipeOptions::new(),
            )
            .unwrap();
        assert!(rx.recv().unwrap().1.is_none());
        let replacing = client.clone();
        let task = thread::spawn(move || replacing.replace_pipes_timeout(Duration::from_secs(2)));
        entered.recv().unwrap();
        let pipe = client
            .pipes()
            .into_iter()
            .find(|p| p.id() != PipeId::new(0) && p.id() != old.id())
            .unwrap();
        pipe.joined().unwrap();
        assert!(!pipe.stats().unwrap().peer_attached);
        assert!(matches!(task.join().unwrap(), Err(WaitError::TimedOut)));
        assert!(matches!(
            pipe.attached(),
            Err(WaitError::Failed(PipeError::Failed(
                zmux::PipeFailure::CallerDeadline
            )))
        ));
        let (id, reason) = rx.recv().unwrap();
        assert_eq!(id, pipe.id());
        assert!(client.pipes().iter().all(|live| live.id() != id));
        assert!(matches!(reason, Some(zmux::JoinError::CallerDeadline)));
        release.send(()).unwrap();
        assert!(matches!(
            pipe.closed(),
            Err(WaitError::Failed(PipeError::Failed(
                zmux::PipeFailure::CallerDeadline
            )))
        ));
        assert!(matches!(
            pipe.attached(),
            Err(WaitError::Failed(PipeError::Failed(
                zmux::PipeFailure::CallerDeadline
            )))
        ));
        assert!(rx.try_recv().is_err());
    });
}
