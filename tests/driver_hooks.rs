//! Hooks whose answers the core needs run outside every lock
//! (CONFORMANCE.md):
//! a custom scheduling policy on the driver's task or thread, and
//! `allow_connection_window_increase` on the session's hook task or thread.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use zmux::proto::session::{FrameInfo, Pick, PickAnswer, PipeSnapshot, WindowIncrease};
use zmux::{
    Config, ConnectError, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, PipeOptions,
    Policy, Session,
};

/// What a test policy does besides answering.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Plain,
    Panic,
    Sleep,
    Blocking,
}

/// The writable eligible pipe with the fewest unsent bytes.
struct LeastUnsent {
    mode: Mode,
    calls: AtomicU64,
    refused: AtomicBool,
    spare: SocketAddr,
}

impl Pick for LeastUnsent {
    fn pick(&self, reqs: &[FrameInfo], pipes: &[PipeSnapshot], out: &mut [PickAnswer]) {
        let n = self.calls.fetch_add(1, Ordering::Relaxed);
        match self.mode {
            Mode::Panic if n.is_multiple_of(2) => panic!("policy panics"),
            Mode::Sleep => std::thread::sleep(Duration::from_millis(1)),
            Mode::Blocking if n == 0 => {
                // A blocking zmux call on the driver's task fails at once.
                let tcp = std::net::TcpStream::connect(self.spare).unwrap();
                let r = zmux::blocking::Session::connect(
                    zmux::blocking::PipeIo::tcp(tcp).unwrap(),
                    Config::default(),
                );
                self.refused.store(
                    matches!(r, Err(ConnectError::OnDriverThread)),
                    Ordering::SeqCst,
                );
            }
            _ => {}
        }
        let best = pipes
            .iter()
            .enumerate()
            .filter(|(_, p)| p.writable && p.eligible)
            .min_by_key(|(_, p)| p.unsent)
            .or_else(|| pipes.iter().enumerate().next())
            .map(|(i, _)| i);
        // One chunk per answer, so that the policy keeps being asked.
        for answer in out.iter_mut().take(reqs.len()) {
            if let Some(index) = best {
                *answer = PickAnswer::Pipe {
                    index,
                    bytes: 16 * 1024,
                };
            }
        }
    }
}

fn mp_config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"hooks-test-psk--0123456789abcdef");
    c
}

/// A listener whose sessions read every unidirectional stream to its end.
async fn sink() -> (SocketAddr, Listener) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let listener = Listener::new(mp_config(), ListenerConfig::default());
    let l = listener.clone();
    tokio::spawn(async move {
        while let Ok((c, peer)) = tcp.accept().await {
            let l = l.clone();
            tokio::spawn(async move {
                let _ = l
                    .handle_pipe(PipeIo::tcp(c), PipeHint::from_addr(peer.ip()))
                    .await;
            });
        }
    });
    let l = listener.clone();
    tokio::spawn(async move {
        while let Some(s) = l.accept().await {
            tokio::spawn(async move {
                while let Ok(mut r) = s.accept_uni().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 256 * 1024];
                        while let Ok(Some(_)) = r.read(&mut buf).await {}
                    });
                }
            });
        }
    });
    (addr, listener)
}

/// Sends `len` bytes over two pipes with a custom policy; the client's
/// statistics and the policy afterwards.
async fn custom_transfer(mode: Mode, len: usize) -> (zmux::SessionStats, Arc<LeastUnsent>) {
    let spare = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let policy = Arc::new(LeastUnsent {
        mode,
        calls: AtomicU64::new(0),
        refused: AtomicBool::new(false),
        spare: spare.local_addr().unwrap(),
    });
    let (addr, _listener) = sink().await;
    let mut config = mp_config();
    config.scheduler = Policy::Custom(policy.clone());
    let client = Session::connect(PipeIo::tcp(TcpStream::connect(addr).await.unwrap()), config)
        .await
        .unwrap();
    client
        .add_pipe(
            PipeIo::tcp(TcpStream::connect(addr).await.unwrap()),
            PipeOptions::default(),
        )
        .unwrap();
    let mut send = client.open_uni().await.unwrap();
    let chunk = vec![7u8; 64 * 1024];
    let mut sent = 0;
    while sent < len {
        send.write_all(&chunk).await.unwrap();
        sent += chunk.len();
    }
    send.finish().unwrap();
    tokio::time::timeout(Duration::from_secs(30), send.stopped())
        .await
        .expect("the transfer completes")
        .unwrap();
    let stats = client.stats();
    assert!(
        client.close_reason().is_none(),
        "{:?}",
        client.close_reason()
    );
    client.close(0u32.into(), b"");
    (stats, policy)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn custom_policy_answers_are_applied() {
    let (stats, policy) = custom_transfer(Mode::Plain, 16 << 20).await;
    let answers = stats.scheduler_answers;
    let total = answers + stats.scheduler_fallbacks;
    assert!(answers > 0, "{stats:?}");
    assert!(
        answers * 100 >= total * 99,
        "applied {answers} of {total} ({} calls)",
        policy.calls.load(Ordering::Relaxed)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_policy_falls_back() {
    let (stats, _) = custom_transfer(Mode::Panic, 4 << 20).await;
    assert!(stats.scheduler_fallbacks > 0, "{stats:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_policy_trips_no_timer() {
    let (stats, _) = custom_transfer(Mode::Sleep, 2 << 20).await;
    assert_eq!(stats.pipe_failures, 0, "{stats:?}");
    assert!(stats.scheduler_answers > 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_blocking_call_in_the_policy_fails_at_once() {
    let (_, policy) = custom_transfer(Mode::Blocking, 1 << 20).await;
    assert!(policy.refused.load(Ordering::SeqCst));
}

/// A predicate that counts its calls and answers by `mode`; it may call
/// into the session it belongs to (through `session`).
fn predicate(
    approve: bool,
    panic: bool,
    calls: Arc<AtomicU64>,
    session: Arc<Mutex<Option<Session>>>,
) -> WindowIncrease {
    WindowIncrease(Arc::new(move |delta| {
        assert!(delta > 0);
        calls.fetch_add(1, Ordering::SeqCst);
        let s = session.lock().unwrap().clone();
        if let Some(s) = s {
            // Runs outside every lock: no deadlock.
            let _ = s.stats();
            let _ = s.window_growth();
        }
        assert!(!panic, "predicate panics");
        approve
    }))
}

/// One stream of `len` bytes into a receiver whose session window growth
/// goes through the predicate; the receiver's window growth.
async fn window_transfer(approve: bool, panic: bool) -> (u64, u64) {
    let calls = Arc::new(AtomicU64::new(0));
    // Cleared at the end: the session's own predicate holds a handle.
    let slot = Arc::new(Mutex::new(None));
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let mut config = Config::default();
    config.allow_connection_window_increase =
        Some(predicate(approve, panic, calls.clone(), slot.clone()));
    // A long RTT for auto-tuning, so that the windows want to grow.
    config.test_hooks().rtt = Some(Duration::from_millis(5));
    let receiver = tokio::spawn(async move {
        let (c, _) = tcp.accept().await.unwrap();
        Session::accept(PipeIo::tcp(c), config).await.unwrap()
    });
    let sender = Session::connect(
        PipeIo::tcp(TcpStream::connect(addr).await.unwrap()),
        Config::default(),
    )
    .await
    .unwrap();
    let receiver = receiver.await.unwrap();
    *slot.lock().unwrap() = Some(receiver.clone());
    // Bidirectional: a unidirectional opener would wait for the credit
    // that the receiver's first accept grants.
    let (mut send, _r) = sender.open_bi().await.unwrap();
    let writer = tokio::spawn(async move {
        let chunk = vec![1u8; 256 * 1024];
        for _ in 0..128 {
            send.write_all(&chunk).await.unwrap();
        }
        send.finish().unwrap();
    });
    let (_s, mut recv) = receiver.accept_bi().await.unwrap();
    let mut buf = vec![0u8; 1 << 20];
    let mut got = 0;
    while let Some(n) = recv.read(&mut buf).await.unwrap() {
        got += n;
    }
    assert_eq!(got, 32 << 20);
    writer.await.unwrap();
    let growth = receiver.window_growth();
    slot.lock().unwrap().take();
    sender.close(0u32.into(), b"");
    receiver.closed().await;
    (growth, calls.load(Ordering::SeqCst))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn approved_window_increases_grow_the_window() {
    let (growth, calls) = window_transfer(true, false).await;
    assert!(calls > 0);
    assert!(growth > 0, "growth {growth} after {calls} calls");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_window_increases_keep_the_window() {
    let (growth, calls) = window_transfer(false, false).await;
    assert!(calls > 0);
    assert_eq!(growth, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_panicking_predicate_refuses() {
    let (growth, calls) = window_transfer(true, true).await;
    assert!(calls > 0);
    assert_eq!(growth, 0);
}

#[test]
fn blocking_driver_runs_hooks_outside_the_lock() {
    // A custom policy on a writer thread, and the predicate on the hook
    // thread: a blocking call fails at once in both, nothing deadlocks.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (addr, listener) = rt.block_on(sink());
    let spare = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let policy = Arc::new(LeastUnsent {
        mode: Mode::Blocking,
        calls: AtomicU64::new(0),
        refused: AtomicBool::new(false),
        spare: spare.local_addr().unwrap(),
    });
    let mut config = mp_config();
    config.scheduler = Policy::Custom(policy.clone());
    let client = zmux::blocking::Session::connect(
        zmux::blocking::PipeIo::tcp(std::net::TcpStream::connect(addr).unwrap()).unwrap(),
        config,
    )
    .unwrap();
    client
        .add_pipe(
            zmux::blocking::PipeIo::tcp(std::net::TcpStream::connect(addr).unwrap()).unwrap(),
            PipeOptions::default(),
        )
        .unwrap();
    let mut send = client.open_uni().unwrap();
    let chunk = vec![3u8; 64 * 1024];
    for _ in 0..64 {
        send.write_all(&chunk).unwrap();
    }
    send.finish().unwrap();
    send.stopped().unwrap();
    let stats = client.stats();
    assert!(stats.scheduler_answers > 0, "{stats:?}");
    assert!(policy.refused.load(Ordering::SeqCst));
    client.close(0u32.into(), b"");
    drop(listener);

    // The predicate on the blocking receiver's hook thread.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let calls = Arc::new(AtomicU64::new(0));
    let blocked = Arc::new(AtomicBool::new(false));
    let slot: Arc<Mutex<Option<zmux::blocking::Session>>> = Arc::default();
    let mut config = Config::default();
    config.test_hooks().rtt = Some(Duration::from_millis(5));
    {
        let calls = calls.clone();
        let blocked = blocked.clone();
        let slot = slot.clone();
        config.allow_connection_window_increase = Some(WindowIncrease(Arc::new(move |_| {
            calls.fetch_add(1, Ordering::SeqCst);
            let s = slot.lock().unwrap().clone();
            if let Some(s) = s {
                blocked.store(
                    s.closed() == Err(zmux::blocking::WaitError::OnDriverThread),
                    Ordering::SeqCst,
                );
            }
            true
        })));
    }
    let receiver = std::thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        zmux::blocking::Session::accept(zmux::blocking::PipeIo::tcp(c).unwrap(), config).unwrap()
    });
    let sender = zmux::blocking::Session::connect(
        zmux::blocking::PipeIo::tcp(std::net::TcpStream::connect(addr).unwrap()).unwrap(),
        Config::default(),
    )
    .unwrap();
    let receiver = receiver.join().unwrap();
    *slot.lock().unwrap() = Some(receiver.clone());
    let (mut send, _r) = sender.open_bi().unwrap();
    let w = std::thread::spawn(move || {
        let chunk = vec![1u8; 256 * 1024];
        for _ in 0..64 {
            send.write_all(&chunk).unwrap();
        }
        send.finish().unwrap();
    });
    let (_s, mut recv) = receiver.accept_bi().unwrap();
    let got = recv.read_to_end(usize::MAX).unwrap();
    assert_eq!(got.len(), 16 << 20);
    w.join().unwrap();
    assert!(calls.load(Ordering::SeqCst) > 0);
    assert!(receiver.window_growth() > 0);
    assert!(blocked.load(Ordering::SeqCst));
    slot.lock().unwrap().take();
    sender.close(0u32.into(), b"");
    receiver.closed().unwrap();
    drop(rt);
}
