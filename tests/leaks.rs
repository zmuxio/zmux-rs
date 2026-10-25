//! Resource-leak and liveness tests of the tokio driver: stream churn over
//! TCP (descriptors, driver tables, memory), every way a session ends
//! (tasks, timers, carriers), pipes joined, lost and removed and a session
//! resumed (pipe tasks, listener tables), listener shutdown, and carriers
//! stuck in a blocked write. Each phase ends with every count back at its
//! baseline: live sessions, session tasks, pipes, listeners and their
//! tasks (`zmux::test_hooks`), open file descriptors, test carriers and
//! runtime tasks alive.
//!
//! The counts are process-wide: the tests of this binary run one at a
//! time (`common::serial`). Each runs under a watchdog. `ZMUX_SOAK=<k>`
//! multiplies the rounds.

mod common;

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::*;
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;
use zmux::test_hooks::{Tables, resources};
use zmux::{
    Config, ConnectError, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, PipeOptions,
    RecvStream, SendStream, Session, SessionError, VarInt,
};

// ---- streams -------------------------------------------------------------------------

/// What the server does with a stream, from its preamble's first byte.
const ECHO: u8 = b'e';
const REJECT: u8 = b'r';
const RESET_BACK: u8 = b'R';
const STOP: u8 = b's';
const DROP: u8 = b'd';
const HOLD: u8 = b'h';

async fn serve_stream(mut send: SendStream, mut recv: RecvStream) {
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
            while let Ok(Some(_)) = recv.read(&mut buf).await {}
        }
        STOP => {
            let _ = recv.read(&mut buf).await;
            let _ = recv.stop(VarInt::from_u32(5));
            let _ = send.finish();
        }
        DROP => {}
        HOLD => {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        _ => {
            loop {
                match recv.read(&mut buf).await {
                    Ok(Some(n)) => {
                        if send.write_all(&buf[..n]).await.is_err() {
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

/// Serves every stream of `server` until it ends.
fn serve(server: Session) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let s = server.clone();
        let uni = tokio::spawn(async move {
            while let Ok(mut r) = s.accept_uni().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    while let Ok(Some(_)) = r.read(&mut buf).await {}
                });
            }
        });
        while let Ok((send, recv)) = server.accept_bi().await {
            tokio::spawn(serve_stream(send, recv));
        }
        let _ = uni.await;
    })
}

async fn open_cmd(session: &Session, cmd: u8) -> Option<(SendStream, RecvStream)> {
    session
        .open_bi_with(&zmux::Preamble::new().with_info(vec![cmd]))
        .await
        .ok()
}

/// One random stream operation, with every way a stream can end.
async fn stream_op(session: &Session, rng: &mut Rng) {
    let len = 1 + rng.below(48 * 1024) as usize;
    let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
    match rng.below(11) {
        // Echoed in full.
        0 | 1 => {
            let Some((mut send, mut recv)) = open_cmd(session, ECHO).await else {
                return;
            };
            let w = tokio::spawn(async move {
                if send.write_all(&data).await.is_ok() {
                    let _ = send.finish();
                }
            });
            if let Ok(got) = recv.read_to_end(len + 1).await {
                assert_eq!(got.len(), len, "echo lost or duplicated data");
            }
            let _ = w.await;
        }
        // Reset after a write.
        2 => {
            let Some((mut send, _recv)) = open_cmd(session, ECHO).await else {
                return;
            };
            let _ = send.write(&data).await;
            let _ = send.reset(VarInt::from_u32(3));
        }
        // Dropped without finish, data in flight.
        3 => {
            let Some((mut send, recv)) = open_cmd(session, ECHO).await else {
                return;
            };
            let _ = send.write(&data).await;
            drop(send);
            drop(recv);
        }
        // Stopped locally while the echo comes back.
        4 => {
            let Some((mut send, mut recv)) = open_cmd(session, ECHO).await else {
                return;
            };
            let _ = send.write(&data).await;
            let _ = recv.stop(VarInt::from_u32(1));
            let _ = send.finish();
        }
        // Rejected by the peer.
        5 => {
            let Some((mut send, mut recv)) = open_cmd(session, REJECT).await else {
                return;
            };
            let _ = send.write(&data).await;
            let _ = send.finish();
            let _ = recv.read_to_end(len).await;
        }
        // The peer resets its side / stops ours.
        6 => {
            let cmd = if rng.below(2) == 0 { RESET_BACK } else { STOP };
            let Some((mut send, mut recv)) = open_cmd(session, cmd).await else {
                return;
            };
            let _ = send.write_all(&data).await;
            let _ = send.finish();
            let _ = recv.read_to_end(len).await;
            let _ = send.stopped().await;
        }
        // The peer drops or holds the stream.
        7 => {
            let cmd = if rng.below(2) == 0 { DROP } else { HOLD };
            let Some((mut send, mut recv)) = open_cmd(session, cmd).await else {
                return;
            };
            let _ = send.write_all(&data).await;
            let _ = send.finish();
            let _ = recv.read_to_end(len).await;
        }
        // A read cancelled mid-wait.
        8 => {
            let Some((mut send, mut recv)) = open_cmd(session, HOLD).await else {
                return;
            };
            let _ = send.write(&data[..len.min(100)]).await;
            let mut buf = [0u8; 64];
            let t = Duration::from_micros(rng.below(2000));
            let _ = tokio::time::timeout(t, recv.read(&mut buf)).await;
        }
        // A write cancelled while it waits for credit.
        9 => {
            let Some((mut send, _recv)) = open_cmd(session, HOLD).await else {
                return;
            };
            let big = vec![1u8; 512 * 1024];
            let t = Duration::from_micros(rng.below(3000));
            let _ = tokio::time::timeout(t, send.write_all(&big)).await;
        }
        // A unidirectional stream, finished or dropped.
        _ => {
            let Ok(mut send) = session.open_uni().await else {
                return;
            };
            let _ = send.write_all(&data).await;
            if rng.below(2) == 0 {
                let _ = send.finish();
            }
        }
    }
}

/// Openers cancelled while they wait for stream credit.
async fn cancelled_opens(session: &Session, rng: &mut Rng) {
    let mut held = Vec::new();
    // Use up the credit (the server allows 8 bidirectional streams).
    let hold = zmux::Preamble::new().with_info(&[HOLD][..]);
    while let Ok(Ok(s)) =
        tokio::time::timeout(Duration::from_millis(20), session.open_bi_with(&hold)).await
    {
        let (mut send, recv) = s;
        let _ = send.write(b"x").await;
        held.push((send, recv));
        if held.len() > 64 {
            break;
        }
    }
    let mut tasks = Vec::new();
    for _ in 0..8 {
        let s = session.clone();
        let t = Duration::from_micros(rng.below(5000));
        tasks.push(tokio::spawn(async move {
            let _ = tokio::time::timeout(t, s.open_bi()).await;
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    drop(held);
}

/// The driver tables of both ends at rest: no stream, no held byte, no wait
/// but the server's two accept loops.
async fn tables_at_rest(client: &Session, server: &Session, what: &str) -> (Tables, Tables) {
    let last;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (c, s) = (client.debug_tables(), server.debug_tables());
        let rest = |t: &Tables, waits: usize| {
            t.streams == 0
                && t.held_bytes == 0
                && t.waits == waits
                && t.pipe_events == 0
                && t.oob == 0
                && t.closing == 0
                && t.new_pipes == 0
        };
        if rest(&c, 0) && rest(&s, 2) {
            return (c, s);
        }
        if Instant::now() >= deadline {
            last = (c, s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!(
        "{what}: tables not at rest\n  client {:?}\n  server {:?}",
        last.0, last.1
    );
}

async fn stream_churn(tcp_carrier: bool, seed: u64) {
    let base = snapshot();
    let mut server_cfg = small_windows(Config::default());
    server_cfg.max_incoming_streams = 8;
    let client_cfg = small_windows(Config::default());
    let (client, server, _ctl) = pair(tcp_carrier, client_cfg, server_cfg).await;
    let served = serve(server.clone());
    let mut rng = Rng::new(seed);
    let mut memory = None;
    for phase in 0..soak(4) {
        let mut tasks = Vec::new();
        for t in 0..8 {
            let c = client.clone();
            let mut r = Rng::new(rng.next() ^ t);
            tasks.push(tokio::spawn(async move {
                for _ in 0..25 {
                    stream_op(&c, &mut r).await;
                }
            }));
        }
        cancelled_opens(&client, &mut rng).await;
        for t in tasks {
            t.await.unwrap();
        }
        let what = format!("tcp={tcp_carrier} seed={seed} phase={phase}");
        let (c, s) = tables_at_rest(&client, &server, &what).await;
        let now = (c.memory_usage, s.memory_usage);
        if std::env::var("LEAK_DEBUG").is_ok() {
            eprintln!("{what}: memory {now:?}");
        }
        // The tables keep some capacity; they must not grow with the
        // phases (the soak run checks this over many).
        // Capacity settles in the first two phases (buffer pools and
        // tables grow in steps); after them it must not keep growing.
        let warm = memory.get_or_insert((0, 0));
        if phase < 2 {
            *warm = (warm.0.max(now.0), warm.1.max(now.1));
        } else {
            let bound = |w: usize| 2 * w + 64 * 1024;
            assert!(
                now.0 <= bound(warm.0) && now.1 <= bound(warm.1),
                "{what}: memory grew from {warm:?} to {now:?}"
            );
        }
    }
    client.close(VarInt::from_u32(0), b"");
    drop(client);
    drop(server);
    watchdog(10, "server loop", served).await.unwrap();
    settle(base, 10, &format!("tcp={tcp_carrier} seed={seed}: end")).await;
}

#[test]
fn stream_churn_returns_to_baseline() {
    // Over TCP: descriptors are part of the baseline.
    multi_thread(watchdog(120, "stream churn", stream_churn(true, 1)));
}

// ---- sessions ------------------------------------------------------------------------

/// How a session ends.
#[derive(Debug, Clone, Copy)]
enum End {
    ClientClose,
    ServerClose,
    /// GOAWAY, then CONNECTION_CLOSE once the open streams finished.
    Shutdown,
    /// The client's carrier fails (reads and writes error).
    CarrierFails,
    /// Both ends idle out.
    IdleTimeout,
    /// Every handle of both ends is dropped with streams open.
    DropAll,
    /// The client stops writing (its carrier stalls) and closes.
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

fn timeouts(mut c: Config) -> Config {
    c.max_idle_timeout = Duration::from_millis(400);
    c.handshake_timeout = Duration::from_millis(300);
    c
}

/// A session pair with some streams in flight, ended by `end`; returns
/// once both ends are closed and every handle is gone.
async fn session_life(end: End, tcp_carrier: bool) {
    let cfg = small_windows(timeouts(Config::default()));
    let (client, server, ctl) = pair(tcp_carrier, cfg.clone(), cfg).await;
    // Without a control (TCP), failures and stalls are left to the
    // in-memory runs and the std driver's relay tests.
    let ca = ctl.first().cloned().unwrap_or_default();
    let served = serve(server.clone());
    // Streams in flight: one echoing, one blocked on credit, one open.
    let (mut send, mut recv) = open_cmd(&client, ECHO).await.unwrap();
    send.write_all(&[1u8; 1000]).await.unwrap();
    let mut got = [0u8; 1000];
    recv.read_exact(&mut got).await.unwrap();
    let blocked = {
        let c = client.clone();
        tokio::spawn(async move {
            let (mut s, _r) = open_cmd(&c, HOLD).await?;
            s.write_all(&[2u8; 256 * 1024]).await.ok()
        })
    };
    let reader = tokio::spawn(async move {
        let mut buf = [0u8; 64];
        let _ = recv.read(&mut buf).await;
        recv
    });
    tokio::time::sleep(Duration::from_millis(1)).await;
    match end {
        End::ClientClose => client.close(VarInt::from_u32(1), b"client"),
        End::ServerClose => server.close(VarInt::from_u32(2), b"server"),
        End::Shutdown => {
            let c = client.clone();
            let sd = tokio::spawn(async move { c.shutdown(VarInt::from_u32(0), b"").await });
            // The streams end; the shutdown completes.
            let _ = send.finish();
            blocked.abort();
            let _ = watchdog(10, "shutdown", sd).await.unwrap();
        }
        End::CarrierFails => ca.fail(),
        End::IdleTimeout => {
            drop(send);
            blocked.abort();
            reader.abort();
            let e = watchdog(10, "idle timeout", client.closed()).await;
            assert!(
                matches!(e, SessionError::IdleTimeout { .. }),
                "idle timeout ended with {e:?}"
            );
            watchdog(10, "server idle timeout", server.closed()).await;
            served.abort();
            return;
        }
        End::DropAll => {}
        End::StuckClose => {
            ca.stall(true);
            client.close(VarInt::from_u32(4), b"stuck");
        }
    }
    drop(send);
    if !matches!(end, End::DropAll) {
        watchdog(10, &format!("{end:?}: client closed"), client.closed()).await;
        watchdog(10, &format!("{end:?}: server closed"), server.closed()).await;
    }
    blocked.abort();
    reader.abort();
    let _ = blocked.await;
    let _ = reader.await;
    drop((client, server));
    let _ = watchdog(10, "server loop", served).await;
}

/// Handshakes that never complete: the peer stays silent, or its carrier
/// ends, or it sends garbage.
async fn failed_handshakes() {
    // A silent peer: the handshake times out.
    let ((a, _ca), (b, _cb)) = duplex(16 * 1024);
    let r = watchdog(
        10,
        "silent peer",
        Session::connect(a, timeouts(Config::default())),
    )
    .await;
    assert!(
        matches!(r, Err(ConnectError::Closed(SessionError::HandshakeTimeout))),
        "{r:?}"
    );
    drop(b);
    // The peer's carrier ends.
    let ((a, _ca), (b, _cb)) = duplex(16 * 1024);
    drop(b);
    let r = watchdog(
        10,
        "ended peer",
        Session::accept(a, timeouts(Config::default())),
    )
    .await;
    assert!(r.is_err(), "{r:?}");
    // Garbage.
    let (a, mut b) = tokio::io::duplex(16 * 1024);
    let (a, _ca) = Carrier::new(a);
    b.write_all(&[0xff; 64]).await.unwrap();
    let r = watchdog(
        10,
        "garbage",
        Session::accept(PipeIo::new(a), timeouts(Config::default())),
    )
    .await;
    assert!(r.is_err(), "{r:?}");
    drop(b);
}

/// Every way a session ends releases its task, pipes and carriers, on a
/// seeded single-threaded runtime with a virtual clock.
#[test]
fn session_churn_returns_to_baseline() {
    paused(async {
        let base = snapshot();
        for round in 0..soak(3) {
            for end in ENDS {
                watchdog(60, &format!("{end:?}"), session_life(end, false)).await;
                settle(base, 10, &format!("round {round}: {end:?}")).await;
            }
            watchdog(60, "handshakes", failed_handshakes()).await;
            settle(base, 10, &format!("round {round}: failed handshakes")).await;
        }
    });
}

// ---- multipath and resume ------------------------------------------------------------

fn mp_config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"leak-test-psk-0123456789abcdef!!");
    c.suspect_floor = Duration::from_millis(100);
    c.resume_timeout = Some(Duration::from_secs(5));
    c
}

/// A listener whose sessions are handed to the test.
fn mp_listener() -> (Listener, tokio::sync::mpsc::UnboundedReceiver<Session>) {
    let listener = Listener::new(mp_config(), ListenerConfig::default());
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let l = listener.clone();
    tokio::spawn(async move {
        while let Some(s) = l.accept().await {
            if tx.send(s).is_err() {
                return;
            }
        }
    });
    (listener, rx)
}

/// A carrier to `listener`: the client's end and its control; the
/// listener handles the other end.
fn dial(listener: &Listener, hint: PipeHint) -> (PipeIo, Arc<Ctl>) {
    let ((a, ca), (b, _cb)) = duplex(64 * 1024);
    let l = listener.clone();
    tokio::spawn(async move {
        let _ = l.handle_pipe(b, hint).await;
    });
    (a, ca)
}

async fn echo(session: &Session, len: usize) {
    let (mut send, mut recv) = open_cmd(session, ECHO).await.expect("open");
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let d = data.clone();
    let w = tokio::spawn(async move {
        send.write_all(&d).await.expect("write");
        send.finish().expect("finish");
    });
    let got = recv.read_to_end(len + 1).await.expect("read");
    w.await.unwrap();
    assert!(got == data, "echo differs");
}

/// Reads every queued pipe event.
async fn drain_events(s: &Session) {
    while let Ok(Some(_)) = tokio::time::timeout(Duration::ZERO, s.next_event()).await {}
}

/// `n` pipes alive on each end (tasks and carriers), and both ends'
/// tables at rest.
async fn expect_pipes(client: &Session, server: &Session, n: usize, what: &str) {
    eventually(30, what, || {
        resources().pipes == 2 * n && CARRIERS.load(Ordering::SeqCst) == 2 * n
    })
    .await;
    drain_events(client).await;
    drain_events(server).await;
    tables_at_rest(client, server, what).await;
}

fn progress(what: &str) {
    if std::env::var("LEAK_DEBUG").is_ok() {
        eprintln!("-- {what}");
    }
}

async fn mp_churn() {
    let base = snapshot();
    let (listener, mut sessions) = mp_listener();
    let (a, _bootstrap) = dial(&listener, PipeHint::default());
    let client = Session::connect(a, mp_config()).await.expect("connect");
    let server = sessions.recv().await.expect("server session");
    assert!(client.multipath() == zmux::Multipath::InUse);
    let served = serve(server.clone());
    let opts = PipeOptions::default();

    progress("Joins, then grace");
    // Joins, then graceful removes.
    let mut pipes = Vec::new();
    for _ in 0..3 {
        let (io, _) = dial(&listener, PipeHint::default());
        pipes.push(client.add_pipe(io, opts.clone()).expect("add"));
    }
    echo(&client, 256 * 1024).await;
    expect_pipes(&client, &server, 4, "joined").await;
    for p in pipes.drain(..) {
        p.close().expect("close pipe");
    }
    echo(&client, 64 * 1024).await;
    expect_pipes(&client, &server, 1, "removed").await;

    progress("A failed carrier ");
    // A failed carrier and an aborted pipe.
    let (io, ctl) = dial(&listener, PipeHint::default());
    let failing = client.add_pipe(io, opts.clone()).expect("add");
    let (io, _) = dial(&listener, PipeHint::default());
    let aborted = client.add_pipe(io, opts.clone()).expect("add");
    echo(&client, 128 * 1024).await;
    ctl.fail();
    echo(&client, 128 * 1024).await;
    aborted.abort().expect("abort");
    echo(&client, 64 * 1024).await;
    drop((failing, aborted));
    expect_pipes(&client, &server, 1, "failed and aborted").await;

    progress("Joins the listene");
    // Joins the listener does not route: an unknown session, a closed
    // listener.
    let (stranger, _none) = mp_listener();
    let (io, _) = dial(&stranger, PipeHint::default());
    let rejected = client.add_pipe(io, opts.clone()).expect("add");
    let (closed, _none2) = mp_listener();
    closed.close();
    let (io, _) = dial(&closed, PipeHint::default());
    let refused = client.add_pipe(io, opts.clone()).expect("add");
    echo(&client, 64 * 1024).await;
    stranger.close();
    drop((rejected, refused, stranger, closed));
    expect_pipes(&client, &server, 1, "failed joins").await;

    progress("Out-of-band joins");
    // Out-of-band joins: a reservation given up, one attached.
    let r = client
        .reserve_pipe(zmux::PipeDirection::Bidi, opts.clone())
        .expect("reserve");
    r.cancel();
    let r = client
        .reserve_pipe(zmux::PipeDirection::Bidi, opts.clone())
        .expect("reserve");
    let mut hint = PipeHint::default();
    hint.join = Some(r.frame().to_vec());
    let (io, _) = dial(&listener, hint);
    let oob = r.attach(io).expect("attach");
    echo(&client, 128 * 1024).await;
    oob.close().expect("close");
    echo(&client, 16 * 1024).await;
    expect_pipes(&client, &server, 1, "out-of-band").await;
    drop(oob);

    progress("Every pipe lost");
    // Every pipe lost: suspended, then resumed on a new pipe.
    let (io, ctl) = dial(&listener, PipeHint::default());
    let p = client.add_pipe(io, opts.clone()).expect("add");
    echo(&client, 16 * 1024).await;
    ctl.fail();
    _bootstrap.fail();
    eventually(30, "suspended", || {
        client.state() == zmux::SessionState::Suspended
    })
    .await;
    let (io, resumed_ctl) = dial(&listener, PipeHint::default());
    let resumed = client.add_pipe(io, opts.clone()).expect("resume");
    eventually(30, "resumed", || {
        client.state() == zmux::SessionState::Active
    })
    .await;
    echo(&client, 128 * 1024).await;
    drop(p);
    expect_pipes(&client, &server, 1, "resumed").await;

    progress("Lost again and ne");
    // Lost again and never resumed: the resume timeout ends both ends.
    let (io, ctl) = dial(&listener, PipeHint::default());
    let extra = client.add_pipe(io, opts.clone()).expect("add");
    echo(&client, 16 * 1024).await;
    ctl.fail();
    resumed_ctl.fail();
    drop((resumed, extra));
    let e = watchdog(30, "client resume timeout", client.closed()).await;
    // The end names the expiry and why the last pipe was lost.
    assert!(
        matches!(
            e,
            SessionError::ResumeTimeout {
                last: Some(zmux::PipeFailure::Carrier(_))
            }
        ),
        "{e:?}"
    );
    watchdog(30, "server resume timeout", server.closed()).await;
    drop((client, server));
    watchdog(30, "server loop", served).await.unwrap();
    // The accept loop holds a clone: closing ends it, and the listener.
    listener.close();
    drop(listener);
    drop(sessions);
    settle(base, 30, "multipath churn: end").await;
}

/// Pipes joined, removed, failed, aborted, refused, reserved and lost,
/// and a session resumed: every pipe's task and carriers go with it.
#[test]
fn multipath_churn_returns_to_baseline() {
    paused(async {
        for _ in 0..soak(2) {
            watchdog(120, "multipath churn", mp_churn()).await;
        }
    });
}

// ---- listener shutdown ---------------------------------------------------------------

/// Closing a listener releases what it holds: carriers waiting for their
/// first record, sessions established but never accepted, and sessions
/// that complete their handshake after the close.
async fn listener_shutdown(accept_some: bool) {
    let base = snapshot();
    let listener = Listener::new(Config::default(), ListenerConfig::default());
    let mut handlers = Vec::new();
    let mut dial = |l: &Listener| {
        let ((a, _), (b, _)) = duplex(16 * 1024);
        let l = l.clone();
        handlers.push(tokio::spawn(async move {
            l.handle_pipe(b, PipeHint::default()).await
        }));
        a
    };
    // Carriers that never send a record.
    let silent: Vec<PipeIo> = (0..3).map(|_| dial(&listener)).collect();
    // Sessions the application never accepts.
    let mut clients = Vec::new();
    for _ in 0..2 {
        let a = dial(&listener);
        clients.push(
            Session::connect(a, Config::default())
                .await
                .expect("connect"),
        );
    }
    if accept_some {
        let s = watchdog(10, "accept", listener.accept())
            .await
            .expect("session");
        drop(s);
    }
    // A session whose handshake completes after the close.
    let late = dial(&listener);
    listener.close();
    assert!(listener.accept().await.is_none(), "accept after close");
    let late = tokio::spawn(Session::connect(late, Config::default()));
    drop(listener);
    // Every handler ends: refused or closed.
    for h in handlers {
        let _ = watchdog(10, "handler after close", h).await.unwrap();
    }
    for c in &clients {
        let e = watchdog(10, "unaccepted session closed", c.closed()).await;
        assert!(matches!(e, SessionError::ApplicationClosed { .. }), "{e:?}");
    }
    let _ = watchdog(10, "late session", late).await.unwrap();
    drop(silent);
    drop(clients);
    settle(
        base,
        10,
        &format!("listener shutdown (accept_some={accept_some})"),
    )
    .await;
}

#[test]
fn listener_shutdown_releases_pending_carriers_and_sessions() {
    paused(async {
        for accept_some in [false, true] {
            watchdog(60, "listener shutdown", listener_shutdown(accept_some)).await;
        }
    });
}

// ---- stuck carriers ------------------------------------------------------------------

/// How a session with a stuck carrier ends.
#[derive(Debug, Clone, Copy)]
enum Stuck {
    HandshakeTimeout,
    IdleTimeout,
    AppClose,
    PeerEndsPipe,
    ReadFails,
}

/// The bound after CLOSING starts: the
/// linger (at most 2 s), then the final write (1 s).
const RELEASE_BOUND: Duration = Duration::from_millis(3500);

/// A carrier whose writes block (the peer stopped reading) while the
/// session ends: it reaches CLOSED and releases everything within the
/// bound, its stuck write included.
async fn stuck_carrier(how: Stuck) {
    let base = snapshot();
    let ((a, ca), (b, cb)) = duplex(16 * 1024);
    let cfg = timeouts(Config::default());
    let start;
    match how {
        Stuck::HandshakeTimeout => {
            // The client's very first write blocks.
            ca.stall(true);
            let r = Session::connect(a, cfg).await;
            assert!(
                matches!(r, Err(ConnectError::Closed(SessionError::HandshakeTimeout))),
                "{r:?}"
            );
            start = Instant::now();
            drop(b);
        }
        _ => {
            let (client, server) = connect(a, b, cfg.clone(), cfg).await;
            // A write the carrier never takes.
            ca.stall(true);
            let (mut send, _recv) = client.open_bi().await.unwrap();
            let _ =
                tokio::time::timeout(Duration::from_millis(1), send.write_all(&[5u8; 128 * 1024]))
                    .await;
            start = Instant::now();
            let mut server = Some(server);
            match how {
                Stuck::IdleTimeout => {
                    // Both ends go silent: the server's writes block too.
                    cb.stall(true);
                }
                Stuck::AppClose => client.close(VarInt::from_u32(1), b"app"),
                // The peer's handles go: it closes and ends its carrier.
                Stuck::PeerEndsPipe => drop(server.take()),
                Stuck::ReadFails => ca.fail_reads(),
                Stuck::HandshakeTimeout => unreachable!(),
            }
            let e = watchdog(30, &format!("{how:?}: closed"), client.closed()).await;
            if matches!(how, Stuck::IdleTimeout) {
                assert!(matches!(e, SessionError::IdleTimeout { .. }), "{e:?}");
            }
            if let Some(s) = server.take() {
                watchdog(30, &format!("{how:?}: server closed"), s.closed()).await;
            }
            drop(send);
            drop(client);
        }
    }
    let deadline = start
        + RELEASE_BOUND
        + match how {
            Stuck::IdleTimeout => Duration::from_millis(400),
            _ => Duration::ZERO,
        };
    loop {
        if snapshot() == base {
            break;
        }
        assert!(
            Instant::now() <= deadline,
            "{how:?}: not released within the bound\n  baseline {base:?}\n  now      {:?}",
            snapshot()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[test]
fn stuck_carriers_release_within_bound() {
    paused(async {
        for how in [
            Stuck::HandshakeTimeout,
            Stuck::IdleTimeout,
            Stuck::AppClose,
            Stuck::PeerEndsPipe,
            Stuck::ReadFails,
        ] {
            watchdog(60, &format!("{how:?}"), stuck_carrier(how)).await;
        }
    });
}
