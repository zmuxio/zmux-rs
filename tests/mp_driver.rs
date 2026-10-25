//! Multipath over real TCP with the tokio driver: a listener routes joins
//! to sessions, data spreads over the pipes, and a severed pipe fails over
//! without losing a byte.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::relay;
use tokio::net::{TcpListener, TcpStream};
use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeIo, PipeOptions, Policy, Session};

fn config(policy: Policy) -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"driver-test-psk-0123456789abcdef");
    c.scheduler = policy;
    c
}

async fn server(policy: Policy) -> (std::net::SocketAddr, Listener) {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let listener = Listener::new(config(policy), ListenerConfig::default());
    let l = listener.clone();
    tokio::spawn(async move { l.serve(tcp).await });
    // Echo every stream of every session.
    let l = listener.clone();
    tokio::spawn(async move {
        while let Some(s) = l.accept().await {
            tokio::spawn(async move {
                while let Ok((mut send, mut recv)) = s.accept_bi().await {
                    tokio::spawn(async move {
                        let mut buf = vec![0u8; 64 * 1024];
                        while let Ok(Some(n)) = recv.read(&mut buf).await {
                            if send.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                        let _ = send.finish();
                    });
                }
            });
        }
    });
    (addr, listener)
}

async fn echo(session: &Session, len: usize) {
    let (mut send, mut recv) = session.open_bi().await.unwrap();
    let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    let writer = {
        let data = data.clone();
        tokio::spawn(async move {
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
            send
        })
    };
    let got = recv.read_to_end(len + 1).await.unwrap();
    let _ = writer.await;
    assert_eq!(got.len(), data.len());
    assert!(got == data, "echoed data differs");
}

/// Every pipe has a handle at both ends, pipe 0 and
/// the peer's joins included, all named by one `PipeId`; adding a pipe
/// never waits and `joined` waits for the join or its failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn every_pipe_has_a_handle_and_joins_are_awaited() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let listener = Listener::new(config(Policy::Affinity), ListenerConfig::default());
    let l = listener.clone();
    let serving = tokio::spawn(async move { l.serve(tcp).await });
    let first = TcpStream::connect(addr).await.unwrap();
    let client = Session::connect(PipeIo::tcp(first), config(Policy::Affinity))
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    assert_eq!(client.multipath(), zmux::Multipath::InUse);
    let second = TcpStream::connect(addr).await.unwrap();
    let pipe = client
        .add_pipe(
            PipeIo::tcp(second),
            PipeOptions::new().with_priority(5).with_label("second"),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), pipe.joined())
        .await
        .expect("joined in time")
        .unwrap();
    let ids = |s: &Session| s.pipes().iter().map(zmux::Pipe::id).collect::<Vec<_>>();
    assert_eq!(ids(&client), [zmux::PipeId(0), pipe.id()]);
    let stats = pipe.stats().unwrap();
    assert_eq!(stats.label.as_deref(), Some("second"));
    assert_eq!((stats.send_priority, stats.receive_priority), (5, 5));
    // The server holds handles of pipe 0 and of the pipe the client
    // joined, and can change them.
    common::eventually(10, "server sees the join", || ids(&server).len() == 2).await;
    let joined = server.pipe(pipe.id()).expect("the peer's pipe");
    joined.set_send_priority(1).unwrap();
    assert_eq!(joined.stats().unwrap().send_priority, 1);
    assert!(server.pipe(zmux::PipeId(0)).is_some());
    // A join over a carrier that is gone fails, and says why; the session
    // goes on.
    let (dead, far) = tokio::io::duplex(1024);
    drop(far);
    let lost = client
        .add_pipe(PipeIo::new(dead), PipeOptions::new())
        .unwrap();
    let e = tokio::time::timeout(Duration::from_secs(10), lost.joined())
        .await
        .expect("failed in time")
        .unwrap_err();
    assert!(
        matches!(e, zmux::PipeError::Failed(zmux::PipeFailure::Carrier(_))),
        "{e:?}"
    );
    assert!(client.close_reason().is_none());
    listener.close();
    serving.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_pipes_spread() {
    let (addr, _l) = server(Policy::SpreadEta).await;
    let c = TcpStream::connect(addr).await.unwrap();
    let s = Session::connect(PipeIo::tcp(c), config(Policy::SpreadEta))
        .await
        .unwrap();
    assert!(s.multipath() == zmux::Multipath::InUse);
    let c2 = TcpStream::connect(addr).await.unwrap();
    let pipe = s.add_pipe(PipeIo::tcp(c2), PipeOptions::default()).unwrap();
    echo(&s, 4 << 20).await;
    let info = s.pipes();
    assert_eq!(info.len(), 2, "{info:?}");
    let p = pipe.stats().unwrap();
    assert!(p.bytes_sent > 0, "{p:?}");
    s.close(0u32.into(), b"");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn severed_pipe_fails_over() {
    let (addr, _l) = server(Policy::SpreadEta).await;
    let c = TcpStream::connect(addr).await.unwrap();
    let mut cfg = config(Policy::SpreadEta);
    cfg.suspect_floor = Duration::from_millis(100);
    let s = Session::connect(PipeIo::tcp(c), cfg).await.unwrap();
    let (raddr, cut) = relay(addr).await;
    let c2 = TcpStream::connect(raddr).await.unwrap();
    s.add_pipe(PipeIo::tcp(c2), PipeOptions::default()).unwrap();
    let s2 = s.clone();
    let job = tokio::spawn(async move { echo(&s2, 8 << 20).await });
    tokio::time::sleep(Duration::from_millis(30)).await;
    cut.store(true, Ordering::SeqCst);
    if std::env::var("MP_DEBUG").is_ok() {
        let s3 = s.clone();
        tokio::spawn(async move {
            for _ in 0..40 {
                tokio::time::sleep(Duration::from_millis(500)).await;
                eprintln!("{:?} {:?}", s3.state(), s3.pipes());
                eprintln!("  stats {:?}", s3.stats());
            }
        });
    }
    tokio::time::timeout(Duration::from_secs(30), job)
        .await
        .expect("transfer finishes")
        .unwrap();
    s.close(0u32.into(), b"");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_client_two_pipes() {
    let (addr, _l) = server(Policy::SpreadEta).await;
    // A plain thread: blocking calls inside the runtime, `spawn_blocking`
    // included, fail at once.
    let (done, finished) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let c = std::net::TcpStream::connect(addr).unwrap();
        let s = zmux::blocking::Session::connect(
            zmux::blocking::PipeIo::tcp(c).unwrap(),
            config(Policy::SpreadEta),
        )
        .unwrap();
        assert!(s.multipath() == zmux::Multipath::InUse);
        let c2 = std::net::TcpStream::connect(addr).unwrap();
        s.add_pipe(
            zmux::blocking::PipeIo::tcp(c2).unwrap(),
            PipeOptions::default(),
        )
        .unwrap();
        let (mut send, mut recv) = s.open_bi().unwrap();
        let len = 2 << 20;
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let d2 = data.clone();
        let w = std::thread::spawn(move || {
            send.write_all(&d2).unwrap();
            send.finish().unwrap();
            send
        });
        let got = recv.read_to_end(len + 1).unwrap();
        let _ = w.join();
        assert!(got == data);
        assert_eq!(s.pipes().len(), 2);
        s.close(0u32.into(), b"");
        let _ = done.send(());
    });
    finished.await.expect("the blocking client finished");
}
