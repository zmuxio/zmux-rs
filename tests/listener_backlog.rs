//! A listener's backlog of sessions nobody accepted is bounded
//! (`ListenerConfig::max_unaccepted`), in both drivers; the blocking
//! listener's graceful shutdown starts closing all its sessions together;
//! a listener whose memory hook needs a runtime is refused
//! outside one.

use std::time::{Duration, Instant};

use zmux::{Config, ListenerConfig, VarInt};

fn limits(max: usize) -> ListenerConfig {
    let mut l = ListenerConfig::default();
    l.max_unaccepted = Some(max);
    l
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tokio_refuses_sessions_beyond_the_backlog() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let listener = zmux::Listener::new(Config::default(), limits(1)).unwrap();
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        tokio::spawn(listener.clone().serve(tcp));
        let dial = || async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            zmux::Session::connect(zmux::PipeIo::from_tcp(tcp), Config::default()).await
        };
        let first = dial().await.unwrap();
        // Queued, not accepted: the second session is refused.
        let second = dial().await;
        if let Ok(s) = &second {
            let e = s.closing().await;
            assert!(
                matches!(e, zmux::SessionError::TransportClosed { remote: true, .. }),
                "{e:?}"
            );
        }
        while listener.stats().refused == 0 {
            tokio::task::yield_now().await;
        }
        // Accepting frees the place.
        let _a = listener.accept().await.unwrap();
        let third = dial().await.unwrap();
        let _b = listener.accept().await.unwrap();
        drop((first, third));
    })
    .await
    .unwrap();
}

#[test]
fn a_memory_hook_outside_a_runtime_is_a_configuration_error() {
    let mut l = ListenerConfig::default();
    l.on_memory_pressure = Some(zmux::OnMemoryPressure::new(|_| {}));
    assert!(matches!(
        zmux::Listener::new(Config::default(), l),
        Err(zmux::ConnectError::InvalidConfig(_))
    ));
}

#[cfg(feature = "blocking")]
mod blocking {
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use zmux::blocking::{Listener, PipeHint, PipeIo, Session};

    use super::*;

    fn serve(l: &Listener) -> std::net::SocketAddr {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = tcp.local_addr().unwrap();
        let l = l.clone();
        thread::spawn(move || {
            while let Ok((s, peer)) = tcp.accept() {
                let l = l.clone();
                thread::spawn(move || {
                    let _ = l.handle_pipe(PipeIo::from_tcp(s), PipeHint { source: Some(peer) });
                });
            }
        });
        addr
    }

    fn dial(addr: std::net::SocketAddr) -> Session {
        Session::connect(
            PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
            Config::default(),
        )
        .unwrap()
    }

    #[test]
    fn blocking_refuses_sessions_beyond_the_backlog() {
        let l = Listener::new(Config::default(), limits(1), None).unwrap();
        let addr = serve(&l);
        let _first = dial(addr);
        let second = dial(addr);
        let _ = second.closing_timeout(Duration::from_secs(10));
        let until = Instant::now() + Duration::from_secs(10);
        while l.stats().refused == 0 {
            assert!(Instant::now() < until, "the second session was not refused");
            thread::yield_now();
        }
        assert!(l.accept_timeout(Duration::from_secs(5)).unwrap().is_some());
        let _third = dial(addr);
        assert!(l.accept_timeout(Duration::from_secs(5)).unwrap().is_some());
    }

    /// Every peer receives GOAWAY before any of the active streams can drain.
    #[test]
    fn blocking_shutdown_starts_every_session_before_waiting_for_drain() {
        let watchdog = Duration::from_secs(60);
        let l = Listener::new(Config::default(), ListenerConfig::default(), None).unwrap();
        let addr = serve(&l);
        let mut clients = Vec::new();
        let mut held = Vec::new();
        for _ in 0..8 {
            let c = dial(addr);
            let server = l.accept_timeout(watchdog).unwrap().unwrap();
            let (mut s, r) = c.open_bi().unwrap();
            std::io::Write::write_all(&mut s, b"x").unwrap();
            let pair = server.accept_bi_timeout(watchdog).unwrap();
            held.push((s, r, server, pair));
            clients.push(c);
        }
        let (finished, result) = std::sync::mpsc::sync_channel(1);
        let shutdown = thread::spawn(move || {
            l.shutdown(VarInt::ZERO, b"bye");
            finished.send(()).unwrap();
        });
        for client in &clients {
            loop {
                let event = client.next_event_timeout(watchdog).unwrap();
                let event = event.expect("the session ended before GOAWAY");
                if matches!(event, zmux::SessionEvent::GoAwayReceived(_)) {
                    break;
                }
            }
        }
        assert!(result.try_recv().is_err());
        drop(held);
        result
            .recv_timeout(watchdog)
            .expect("shutdown did not finish");
        shutdown.join().unwrap();
    }
}
