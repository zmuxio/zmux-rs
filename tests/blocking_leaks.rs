//! Leak and liveness tests of the std driver (`zmux::blocking`) over TCP:
//! every way a session ends, carriers stuck in a blocked write, and each
//! kind of wait raced against close, reset, STOP_SENDING, GOAWAY,
//! shutdown, deadline and carrier failure. Driver threads, sessions and
//! the process's open file descriptors return to their baseline
//! (`zmux::test_hooks`).
//!
//! The counts are process-wide: the tests of this binary run one at a
//! time ([`serial`]). Each runs under a watchdog. `ZMUX_SOAK=<k>`
//! multiplies the rounds.

#[path = "common/basics.rs"]
mod basics;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use basics::{Rng, open_fds, serial, small_windows, soak, tcp};
use bytes::Bytes;
use zmux::blocking::{PipeIo, RecvStream, SendStream, Session};
use zmux::test_hooks::{Resources, resources};
use zmux::{Config, ConnectError, SessionError, VarInt};

// ---- harness -----------------------------------------------------------------------

/// Runs `f` on a thread, holding [`serial`], and fails when it does not
/// finish within `secs`.
fn watchdog<T: Send + 'static>(secs: u64, what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let _g = serial();
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Snapshot {
    res: Resources,
    fds: usize,
}

fn snapshot() -> Snapshot {
    Snapshot {
        res: resources(),
        fds: open_fds(),
    }
}

/// Waits until everything is back at `base`, at most `secs` seconds.
fn settle(base: Snapshot, secs: u64, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        let now = snapshot();
        if now == base {
            return;
        }
        if Instant::now() >= deadline {
            panic!("{what}: resources not released\n  baseline {base:?}\n  now      {now:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn timeouts(mut c: Config) -> Config {
    c.max_idle_timeout = Duration::from_millis(400);
    c.handshake_timeout = Duration::from_millis(300);
    c
}

fn connect(a: TcpStream, b: TcpStream, client: Config, server: Config) -> (Session, Session) {
    let server = thread::spawn(move || Session::accept(PipeIo::tcp(b).unwrap(), server).unwrap());
    let client = Session::connect(PipeIo::tcp(a).unwrap(), client).unwrap();
    (client, server.join().unwrap())
}

// ---- serving -------------------------------------------------------------------------

const ECHO: u8 = b'e';
const REJECT: u8 = b'r';
const RESET_BACK: u8 = b'R';
const STOP: u8 = b's';
const DROP: u8 = b'd';
const HOLD: u8 = b'h';

fn serve_stream(mut send: SendStream, mut recv: RecvStream) {
    let cmd = recv
        .preamble()
        .info()
        .and_then(|p| p.first().copied())
        .unwrap_or(ECHO);
    let mut buf = vec![0u8; 16 * 1024];
    match cmd {
        REJECT => {
            let _ = recv.reject();
        }
        RESET_BACK => {
            let _ = send.reset(VarInt::from_u32(9));
            while let Ok(Some(_)) = recv.read(&mut buf) {}
        }
        STOP => {
            let _ = recv.read(&mut buf);
            let _ = recv.stop(VarInt::from_u32(5));
            let _ = send.finish();
        }
        DROP => {}
        HOLD => thread::sleep(Duration::from_millis(2)),
        _ => {
            loop {
                match recv.read(&mut buf) {
                    Ok(Some(n)) => {
                        if send.write_all(&buf[..n]).is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return,
                }
            }
            let _ = send.finish();
        }
    }
}

/// Serves every stream of `server` until it ends; joins its stream threads.
fn serve(server: Session) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let s = server.clone();
        let uni = thread::spawn(move || {
            let mut threads = Vec::new();
            while let Ok(mut r) = s.accept_uni() {
                threads.push(thread::spawn(move || {
                    let mut buf = vec![0u8; 16 * 1024];
                    while let Ok(Some(_)) = r.read(&mut buf) {}
                }));
            }
            for t in threads {
                let _ = t.join();
            }
        });
        let mut threads = Vec::new();
        while let Ok((send, recv)) = server.accept_bi() {
            threads.push(thread::spawn(move || serve_stream(send, recv)));
        }
        drop(server);
        for t in threads {
            let _ = t.join();
        }
        let _ = uni.join();
    })
}

fn open_cmd(session: &Session, cmd: u8) -> Option<(SendStream, RecvStream)> {
    session
        .open_bi_with(&zmux::Preamble::new().with_info(vec![cmd]))
        .ok()
}

// ---- sessions ------------------------------------------------------------------------

/// A TCP relay that forwards until it stalls (it then holds both sockets
/// and reads nothing), and ends both sockets when dropped... or cut.
struct Relay {
    addr: SocketAddr,
    stall: Arc<AtomicBool>,
    cut: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Relay {
    fn new(target: SocketAddr) -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let stall = Arc::new(AtomicBool::new(false));
        let cut = Arc::new(AtomicBool::new(false));
        let (st, ct) = (stall.clone(), cut.clone());
        let thread = thread::spawn(move || {
            let Ok((a, _)) = l.accept() else {
                return;
            };
            drop(l);
            let b = TcpStream::connect(target).unwrap();
            let pump =
                |mut r: TcpStream, mut w: TcpStream, st: Arc<AtomicBool>, ct: Arc<AtomicBool>| {
                    thread::spawn(move || {
                        r.set_read_timeout(Some(Duration::from_millis(5))).unwrap();
                        let mut buf = vec![0u8; 16 * 1024];
                        loop {
                            if ct.load(Ordering::SeqCst) {
                                let _ = r.shutdown(Shutdown::Both);
                                let _ = w.shutdown(Shutdown::Both);
                                return;
                            }
                            if st.load(Ordering::SeqCst) {
                                thread::sleep(Duration::from_millis(5));
                                continue;
                            }
                            match r.read(&mut buf) {
                                Ok(0) => {
                                    let _ = w.shutdown(Shutdown::Write);
                                    return;
                                }
                                Ok(n) => {
                                    if w.write_all(&buf[..n]).is_err() {
                                        return;
                                    }
                                }
                                Err(e)
                                    if matches!(
                                        e.kind(),
                                        std::io::ErrorKind::WouldBlock
                                            | std::io::ErrorKind::TimedOut
                                    ) => {}
                                Err(_) => return,
                            }
                        }
                    })
                };
            let t1 = pump(
                a.try_clone().unwrap(),
                b.try_clone().unwrap(),
                st.clone(),
                ct.clone(),
            );
            let t2 = pump(b, a, st, ct);
            let _ = t1.join();
            let _ = t2.join();
        });
        Self {
            addr,
            stall,
            cut,
            thread: Some(thread),
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.stall.store(false, Ordering::SeqCst);
        self.cut.store(true, Ordering::SeqCst);
        // Unblocks an accept that never came.
        let _ = TcpStream::connect(self.addr);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum End {
    ClientClose,
    ServerClose,
    Shutdown,
    CarrierFails,
    IdleTimeout,
    DropAll,
    StuckClose,
}

const ENDS: [End; 7] = [
    End::ClientClose,
    End::ServerClose,
    End::Shutdown,
    End::CarrierFails,
    End::IdleTimeout,
    End::DropAll,
    End::StuckClose,
];

fn session_life(end: End) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = l.local_addr().unwrap();
    let relay = Relay::new(target);
    let cfg = small_windows(timeouts(Config::default()));
    let scfg = cfg.clone();
    let server = thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        Session::accept(PipeIo::tcp(c).unwrap(), scfg).unwrap()
    });
    let carrier = TcpStream::connect(relay.addr).unwrap();
    let control = carrier.try_clone().unwrap();
    let client = Session::connect(PipeIo::tcp(carrier).unwrap(), cfg).unwrap();
    let server = server.join().unwrap();
    let served = serve(server.clone());
    let (mut send, mut recv) = open_cmd(&client, ECHO).unwrap();
    send.write_all(&[1u8; 1000]).unwrap();
    let mut got = [0u8; 1000];
    recv.read_exact(&mut got).unwrap();
    let blocked = {
        let c = client.clone();
        thread::spawn(move || {
            let (mut s, _r) = open_cmd(&c, HOLD)?;
            s.write_all(&[2u8; 256 * 1024]).ok()
        })
    };
    let reader = thread::spawn(move || {
        let mut buf = [0u8; 64];
        let _ = recv.read(&mut buf);
    });
    thread::sleep(Duration::from_millis(1));
    match end {
        End::ClientClose => client.close(VarInt::from_u32(1), b"client"),
        End::ServerClose => server.close(VarInt::from_u32(2), b"server"),
        End::Shutdown => {
            let c = client.clone();
            let sd = thread::spawn(move || c.shutdown(VarInt::from_u32(0), b""));
            let _ = send.finish();
            // The blocked writer's stream must end too: the server holds it
            // only briefly.
            let _ = sd.join().unwrap();
        }
        End::CarrierFails => {
            let _ = control.shutdown(Shutdown::Both);
        }
        End::IdleTimeout => {
            // Nothing flows: the blocked writer's stream ended at the server.
        }
        End::DropAll => {}
        End::StuckClose => {
            relay.stall.store(true, Ordering::SeqCst);
            client.close(VarInt::from_u32(4), b"stuck");
        }
    }
    drop(send);
    if matches!(end, End::IdleTimeout) {
        let e = client.closed().unwrap();
        assert!(
            matches!(
                e,
                SessionError::IdleTimeout { .. } | SessionError::ApplicationClosed { .. }
            ),
            "{e:?}"
        );
    }
    if !matches!(end, End::DropAll) {
        client.closed().unwrap();
        server.closed().unwrap();
    } else {
        drop((client.clone(), server.clone()));
    }
    let _ = blocked.join();
    let _ = reader.join();
    drop((client, server, control));
    served.join().unwrap();
    drop(relay);
}

fn failed_handshakes() {
    // A silent peer.
    let (a, b) = tcp();
    let r = Session::connect(PipeIo::tcp(a).unwrap(), timeouts(Config::default()));
    assert!(
        matches!(r, Err(ConnectError::Closed(SessionError::HandshakeTimeout))),
        "{r:?}"
    );
    drop(b);
    // The peer's carrier ends.
    let (a, b) = tcp();
    drop(b);
    let r = Session::accept(PipeIo::tcp(a).unwrap(), timeouts(Config::default()));
    assert!(r.is_err(), "{r:?}");
    // Garbage.
    let (a, mut b) = tcp();
    b.write_all(&[0xff; 64]).unwrap();
    let r = Session::accept(PipeIo::tcp(a).unwrap(), timeouts(Config::default()));
    assert!(r.is_err(), "{r:?}");
    drop(b);
}

/// Every way a session ends ends its threads and closes its sockets.
#[test]
fn session_churn_returns_to_baseline() {
    watchdog(240, "session churn", || {
        let base = snapshot();
        for round in 0..soak(1) {
            for end in ENDS {
                session_life(end);
                settle(base, 10, &format!("round {round}: {end:?}"));
            }
            failed_handshakes();
            settle(base, 10, &format!("round {round}: failed handshakes"));
        }
    });
}

// ---- stuck carriers ------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Stuck {
    HandshakeTimeout,
    IdleTimeout,
    AppClose,
    PeerEndsPipe,
    ReadFails,
}

/// The bound after CLOSING starts: the
/// linger (at most 2 s), then the final write (1 s), with slack for a
/// loaded machine.
const RELEASE_BOUND: Duration = Duration::from_millis(4500);

/// A carrier whose writes block (the relay stopped reading) while the
/// session ends: CLOSED, and every thread and socket released within the
/// bound, the thread blocked in `write` included.
fn stuck_carrier(how: Stuck) {
    let base = snapshot();
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let relay = Relay::new(l.local_addr().unwrap());
    let mut cfg = timeouts(Config::default());
    // Windows larger than the socket buffers: the writer thread blocks in
    // `write`, not on credit.
    cfg.initial_stream_receive_window = 16 << 20;
    cfg.max_stream_receive_window = zmux::Cap::Fixed(16 << 20);
    cfg.initial_connection_receive_window = 16 << 20;
    cfg.max_connection_receive_window = zmux::Cap::Fixed(32 << 20);
    cfg.send_buffer = 16 << 20;
    let scfg = cfg.clone();
    let start;
    if let Stuck::HandshakeTimeout = how {
        relay.stall.store(true, Ordering::SeqCst);
        let peer = thread::spawn(move || l.accept().map(|(c, _)| c));
        let r = Session::connect(
            PipeIo::tcp(TcpStream::connect(relay.addr).unwrap()).unwrap(),
            cfg,
        );
        assert!(
            matches!(r, Err(ConnectError::Closed(SessionError::HandshakeTimeout))),
            "{r:?}"
        );
        start = Instant::now();
        drop(peer.join().unwrap());
    } else {
        let server = thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            Session::accept(PipeIo::tcp(c).unwrap(), scfg).unwrap()
        });
        let carrier = TcpStream::connect(relay.addr).unwrap();
        let control = carrier.try_clone().unwrap();
        let client = Session::connect(PipeIo::tcp(carrier).unwrap(), cfg).unwrap();
        let server = server.join().unwrap();
        relay.stall.store(true, Ordering::SeqCst);
        // Writes the relay never takes: the writer thread blocks in
        // `write` once the socket buffers are full.
        let (mut send, _recv) = client.open_bi().unwrap();
        send.set_write_timeout(Some(Duration::from_millis(300)));
        let _ = send.write_all(&vec![5u8; 8 << 20]);
        start = Instant::now();
        match how {
            Stuck::IdleTimeout => {}
            Stuck::AppClose => client.close(VarInt::from_u32(1), b"app"),
            Stuck::PeerEndsPipe => {
                // The relay ends the client's socket.
                relay.cut.store(true, Ordering::SeqCst);
            }
            Stuck::ReadFails => {
                let _ = control.shutdown(Shutdown::Read);
            }
            Stuck::HandshakeTimeout => unreachable!(),
        }
        let e = client.closed().unwrap();
        if matches!(how, Stuck::IdleTimeout) {
            assert!(matches!(e, SessionError::IdleTimeout { .. }), "{e:?}");
        }
        server.closed().unwrap();
        drop((send, client, server, control));
    }
    let deadline = start + RELEASE_BOUND;
    loop {
        // The relay's own sockets are not the session's.
        let now = snapshot();
        if now.res == base.res {
            break;
        }
        assert!(
            Instant::now() <= deadline,
            "{how:?}: not released within the bound\n  baseline {base:?}\n  now      {now:?}"
        );
        thread::sleep(Duration::from_millis(5));
    }
    drop(relay);
    settle(base, 10, &format!("{how:?}: end"));
}

#[test]
fn stuck_carriers_release_within_bound() {
    watchdog(120, "stuck carriers", || {
        for how in [
            Stuck::HandshakeTimeout,
            Stuck::IdleTimeout,
            Stuck::AppClose,
            Stuck::PeerEndsPipe,
            Stuck::ReadFails,
        ] {
            if std::env::var("STUCK_ONLY").is_ok_and(|v| v != format!("{how:?}")) {
                continue;
            }
            stuck_carrier(how);
        }
    });
}

// ---- close races -----------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Read,
    Write,
    OpenBi,
    AcceptBi,
    AcceptUni,
    Datagram,
    StreamDatagram,
    DatagramSpace,
    SessionEvent,
    Closed,
    Shutdown,
    Stopped,
    ReceivedReset,
}

const KINDS: [Kind; 13] = [
    Kind::Read,
    Kind::Write,
    Kind::OpenBi,
    Kind::AcceptBi,
    Kind::AcceptUni,
    Kind::Datagram,
    Kind::StreamDatagram,
    Kind::DatagramSpace,
    Kind::SessionEvent,
    Kind::Closed,
    Kind::Shutdown,
    Kind::Stopped,
    Kind::ReceivedReset,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Race {
    LocalClose,
    PeerClose,
    StreamReset,
    StopSending,
    PeerGoAway,
    LocalShutdown,
    /// The wait's own timeout (the std driver's cancellation).
    Deadline,
    CarrierFails,
}

const RACES: [Race; 8] = [
    Race::LocalClose,
    Race::PeerClose,
    Race::StreamReset,
    Race::StopSending,
    Race::PeerGoAway,
    Race::LocalShutdown,
    Race::Deadline,
    Race::CarrierFails,
];

fn race_config() -> Config {
    let mut c = small_windows(Config::default());
    c.enable_datagrams = true;
    c.max_incoming_streams = 4;
    c.max_incoming_uni_streams = Some(1);
    c.max_idle_timeout = Duration::from_secs(5);
    c
}

/// One race of the std driver: a thread blocks in a wait of `kind`; at a
/// random point `race` happens; the wait returns.
fn race_once(kind: Kind, race: Race, seed: u64) {
    let mut rng = Rng::new(seed);
    let (a, b) = tcp();
    let control = a.try_clone().unwrap();
    let (local, peer) = connect(a, b, race_config(), race_config());
    let (mut l_send, mut l_recv) = local.open_bi().unwrap();
    l_send.write_all(b"x").unwrap();
    let (mut p_send, mut p_recv) = peer.accept_bi().unwrap();
    let mut one = [0u8; 1];
    p_recv.read_exact(&mut one).unwrap();
    p_send.write_all(b"y").unwrap();
    l_recv.read_exact(&mut one).unwrap();
    let deadline = (race == Race::Deadline).then(|| Duration::from_micros(1 + rng.below(3000)));
    let mut l_send = Some(l_send);
    let mut l_recv = Some(l_recv);
    let s = local.clone();
    let wait: thread::JoinHandle<String> = match kind {
        Kind::Read => {
            let mut r = l_recv.take().unwrap();
            r.set_read_timeout(deadline);
            thread::spawn(move || {
                let mut buf = [0u8; 64];
                format!("{:?}", r.read(&mut buf))
            })
        }
        Kind::Write => {
            let mut w = l_send.take().unwrap();
            w.set_write_timeout(deadline);
            thread::spawn(move || format!("{:?}", w.write_all(&vec![1u8; 256 * 1024])))
        }
        Kind::OpenBi => thread::spawn(move || format!("{:?}", s.open_bi().map(|_| ()))),
        Kind::AcceptBi => thread::spawn(move || format!("{:?}", s.accept_bi().map(|_| ()))),
        Kind::AcceptUni => thread::spawn(move || format!("{:?}", s.accept_uni().map(|_| ()))),
        Kind::Datagram => thread::spawn(move || format!("{:?}", s.read_datagram())),
        Kind::StreamDatagram => {
            let r = l_recv.take().unwrap();
            thread::spawn(move || format!("{:?}", r.read_datagram()))
        }
        Kind::DatagramSpace => thread::spawn(move || {
            for _ in 0..2000 {
                let _ = s.send_datagram(Bytes::from_static(b"d"));
            }
            format!("{:?}", s.send_datagram_wait(Bytes::from_static(b"w")))
        }),
        Kind::SessionEvent => thread::spawn(move || format!("{:?}", s.next_event(deadline))),
        Kind::Closed => thread::spawn(move || format!("{:?}", s.closed())),
        Kind::Shutdown => {
            thread::spawn(move || format!("{:?}", s.shutdown(VarInt::from_u32(0), b"")))
        }
        Kind::Stopped => {
            let w = l_send.take().unwrap();
            thread::spawn(move || format!("{:?}", w.stopped()))
        }
        Kind::ReceivedReset => {
            let mut r = l_recv.take().unwrap();
            r.set_read_timeout(deadline);
            thread::spawn(move || format!("{:?}", r.received_reset()))
        }
    };
    if rng.below(2) == 0 {
        thread::sleep(Duration::from_micros(rng.below(2000)));
    }
    match race {
        Race::LocalClose => local.close(VarInt::from_u32(1), b"local"),
        Race::PeerClose => peer.close(VarInt::from_u32(2), b"peer"),
        Race::StreamReset => {
            let _ = p_send.reset(VarInt::from_u32(3));
        }
        Race::StopSending => {
            let _ = p_recv.stop(VarInt::from_u32(4));
        }
        Race::PeerGoAway => {
            let p = peer.clone();
            thread::spawn(move || p.shutdown(VarInt::from_u32(5), b"goaway"));
        }
        Race::LocalShutdown => {
            let s = local.clone();
            thread::spawn(move || s.shutdown(VarInt::from_u32(6), b"shutdown"));
        }
        Race::Deadline => {}
        Race::CarrierFails => {
            let _ = control.shutdown(Shutdown::Both);
        }
    }
    // Waits the race does not end end with the session.
    let grace = Instant::now() + Duration::from_millis(30);
    while !wait.is_finished() && Instant::now() < grace {
        thread::sleep(Duration::from_millis(1));
    }
    if !wait.is_finished() {
        assert!(
            !matches!(
                race,
                Race::LocalClose | Race::PeerClose | Race::CarrierFails
            ),
            "seed {seed}: {kind:?} raced with {race:?}: the session ended, the wait did not"
        );
        local.close(VarInt::from_u32(9), b"end");
    }
    let limit = Instant::now() + Duration::from_secs(10);
    while !wait.is_finished() {
        assert!(
            Instant::now() < limit,
            "seed {seed}: {kind:?} raced with {race:?}: the wait did not resolve after the close"
        );
        thread::sleep(Duration::from_millis(1));
    }
    if let Err(e) = wait.join() {
        std::panic::resume_unwind(e);
    }
    local.close(VarInt::from_u32(0), b"");
    peer.close(VarInt::from_u32(0), b"");
    local.closed().unwrap();
    peer.closed().unwrap();
    drop((l_send, l_recv, p_send, p_recv, control));
}

/// Every wait kind of the std driver against every race; threads and
/// sockets back at their baseline.
#[test]
fn every_wait_resolves_against_every_race() {
    watchdog(600, "close races", || {
        let base = snapshot();
        let n = soak(3);
        for i in 0..n * KINDS.len() * RACES.len() {
            let seed = i as u64;
            let kind = KINDS[i % KINDS.len()];
            let race = RACES[(i / KINDS.len()) % RACES.len()];
            race_once(kind, race, seed);
            if i % 100 == 99 {
                settle(base, 30, &format!("after seed {seed}"));
            }
        }
        settle(base, 30, "close races: end");
    });
}
