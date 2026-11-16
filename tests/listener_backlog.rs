//! A listener's backlog of sessions nobody accepted is bounded
//! (`ListenerConfig::max_unaccepted`), in both drivers; the blocking
//! listener's graceful shutdown closes its sessions together within one
//! deadline; a listener whose memory hook needs a runtime is refused
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

    /// Sessions whose peers never answer the GOAWAY: the shutdown ends at
    /// its one deadline, not at the sum of the sessions' waits.
    #[test]
    fn blocking_shutdown_ends_all_sessions_within_one_deadline() {
        let l = Listener::new(Config::default(), ListenerConfig::default(), None).unwrap();
        let addr = serve(&l);
        // Eight sessions: waited one after another they would take 2.4 s.
        let clients: Vec<_> = (0..8).map(|_| dial(addr)).collect();
        let mut held = Vec::new();
        for c in &clients {
            // A stream both ends hold keeps each graceful close waiting.
            let (mut s, r) = c.open_bi().unwrap();
            std::io::Write::write_all(&mut s, b"x").unwrap();
            let server = l.accept_timeout(Duration::from_secs(5)).unwrap().unwrap();
            let pair = server.accept_bi().unwrap();
            held.push((s, r, server, pair));
        }
        let start = Instant::now();
        l.shutdown_timeout(VarInt::from_u32(0), b"bye", Duration::from_millis(300));
        // One deadline, with room for scheduling: under 2.5 deadlines.
        assert!(
            start.elapsed() < Duration::from_millis(750),
            "{:?}",
            start.elapsed()
        );
        drop((held, clients));
    }
}
