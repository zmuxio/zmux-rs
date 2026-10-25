//! The drivers' tasks and threads end with their sessions, however the
//! session ends (feature `test-hooks` counters). One test function: the
//! counters are process-wide.

use std::time::{Duration, Instant};

use std::sync::Arc;

use zmux::helpers::PipePool;
use zmux::proto::session::WindowIncrease;
use zmux::test_hooks::resources;
use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, Session};

/// A receiver config whose window growth goes through a predicate, with a
/// long auto-tuning RTT so that it wants to grow.
fn hooked() -> Config {
    let mut c = Config::default();
    c.allow_connection_window_increase = Some(WindowIncrease(Arc::new(|_| true)));
    c.test_hooks().rtt = Some(Duration::from_millis(5));
    // A small window that a transfer outgrows, so that the first proposal
    // (which starts the hook task) comes early.
    c.initial_connection_receive_window = 16 * 1024;
    c.initial_stream_receive_window = 16 * 1024;
    c
}

fn settle(what: &str, want: usize, now: impl Fn() -> usize) {
    let start = Instant::now();
    while now() != want {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{what}: {} alive, want {want}",
            now()
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn tasks_and_threads_end_with_their_sessions() {
    // The tokio driver: closed, dropped, and peer-ended sessions.
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let base = resources().session_tasks;
    rt.block_on(async {
        for i in 0..20 {
            let (a, b) = tokio::io::duplex(64 * 1024);
            let server =
                tokio::spawn(
                    async move { Session::accept(PipeIo::new(b), Config::default()).await },
                );
            let client = Session::connect(PipeIo::new(a), Config::default())
                .await
                .unwrap();
            let server = server.await.unwrap().unwrap();
            let (mut send, _recv) = client.open_bi().await.unwrap();
            send.write_all(b"x").await.unwrap();
            match i % 3 {
                0 => client.close(0u32.into(), b""),
                1 => drop((client, send)),
                _ => server.close(1u32.into(), b"bye"),
            }
        }
    });
    settle("session tasks", base, || resources().session_tasks);

    // Hook tasks (started by the first window proposal) and pipe
    // maintainers (stopped, dropped, or ended with their session).
    let hooks = resources().hooks;
    let maintainers = resources().maintainers;
    rt.block_on(async {
        for i in 0..4u32 {
            let (a, b) = tokio::io::duplex(1 << 20);
            let receiver =
                tokio::spawn(async move { Session::accept(PipeIo::new(b), hooked()).await });
            let sender = Session::connect(PipeIo::new(a), Config::default())
                .await
                .unwrap();
            let receiver = receiver.await.unwrap().unwrap();
            let (mut send, _r) = sender.open_bi().await.unwrap();
            tokio::spawn(async move {
                let chunk = vec![0u8; 256 * 1024];
                for _ in 0..128 {
                    if send.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
                let _ = send.finish();
            });
            let (s2, mut recv) = receiver.accept_bi().await.unwrap();
            let _ = recv.read_to_end(usize::MAX).await;
            assert!(resources().hooks > hooks, "a hook task runs");
            if i.is_multiple_of(2) {
                receiver.close(0u32.into(), b"");
            } else {
                // The last handle gone closes the session.
                drop((receiver, recv, s2));
                sender.closed().await;
            }
        }
        let mut c = Config::default();
        c.max_pipes = 4;
        c.pipe_auth = PipeAuth::psk(*b"leaks-test-psk--0123456789abcdef");
        let listener = Listener::new(c.clone(), ListenerConfig::default());
        let carrier = {
            let listener = listener.clone();
            move || {
                let (a, b) = tokio::io::duplex(64 * 1024);
                let l = listener.clone();
                tokio::spawn(async move {
                    let _ = l
                        .handle_pipe(PipeIo::new(b), PipeHint::from_addr([127, 0, 0, 1].into()))
                        .await;
                });
                PipeIo::new(a)
            }
        };
        for i in 0..3 {
            let client = Session::connect(carrier(), c.clone()).await.unwrap();
            let dial = carrier.clone();
            let handle = zmux::helpers::maintain_pipes(
                &client,
                PipePool::new(2, move |_| std::future::ready(Ok(dial()))),
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
            assert!(resources().maintainers > maintainers);
            match i {
                0 => drop(handle),
                1 => handle.stop(),
                _ => {
                    client.close(0u32.into(), b"");
                    drop(client);
                    while !handle.is_finished() {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    continue;
                }
            }
            client.close(0u32.into(), b"");
        }
        drop(listener);
    });
    settle("hook tasks", hooks, || resources().hooks);
    settle("maintainers", maintainers, || resources().maintainers);
    settle("session tasks", base, || resources().session_tasks);
    drop(rt);

    // The std driver: closed and dropped sessions; the reader, writer and
    // timer threads all end.
    let base = resources().threads;
    for i in 0..10u32 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (c, _) = l.accept().unwrap();
            zmux::blocking::Session::accept(
                zmux::blocking::PipeIo::tcp(c).unwrap(),
                Config::default(),
            )
            .unwrap()
        });
        let c = std::net::TcpStream::connect(addr).unwrap();
        let client = zmux::blocking::Session::connect(
            zmux::blocking::PipeIo::tcp(c).unwrap(),
            Config::default(),
        )
        .unwrap();
        let server = server.join().unwrap();
        // Reader, writer and timer threads of both sessions (they count
        // themselves once running).
        let start = Instant::now();
        while resources().threads < base + 6 {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(1));
        }
        if i.is_multiple_of(2) {
            client.close(0u32.into(), b"");
            drop(server);
        } else {
            drop(client);
            server.closed().unwrap();
        }
    }
    settle("driver threads", base, || resources().threads);

    // The std driver's hook thread ends with its session.
    let base = resources().threads;
    let hooks = resources().hooks;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let receiver = std::thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        zmux::blocking::Session::accept(zmux::blocking::PipeIo::tcp(c).unwrap(), hooked()).unwrap()
    });
    let c = std::net::TcpStream::connect(addr).unwrap();
    let sender = zmux::blocking::Session::connect(
        zmux::blocking::PipeIo::tcp(c).unwrap(),
        Config::default(),
    )
    .unwrap();
    let receiver = receiver.join().unwrap();
    let (mut send, _r) = sender.open_bi().unwrap();
    let w = std::thread::spawn(move || {
        let chunk = vec![0u8; 256 * 1024];
        for _ in 0..32 {
            send.write_all(&chunk).unwrap();
        }
        send.finish().unwrap();
    });
    let (_s, mut recv) = receiver.accept_bi().unwrap();
    recv.read_to_end(usize::MAX).unwrap();
    w.join().unwrap();
    assert!(resources().hooks > hooks, "a hook thread runs");
    sender.close(0u32.into(), b"");
    receiver.closed().unwrap();
    drop((receiver, recv));
    settle("hook threads", hooks, || resources().hooks);
    settle("driver threads", base, || resources().threads);
}
