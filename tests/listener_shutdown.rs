//! A listener's graceful shutdown refuses new sessions at once and goes
//! on taking the joins of its live sessions until they ended; its close
//! refuses everything at once.

use std::time::Duration;

use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeIo, PipeOptions, Session, VarInt};

const LIMIT: Duration = Duration::from_secs(10);

fn config() -> Config {
    let mut config = Config::default();
    config.max_pipes = 8;
    config.pipe_auth =
        PipeAuth::psk(b"a pre-shared key, 16 bytes or more".to_vec()).with_end_to_end();
    config
}

async fn serve() -> (Listener, std::net::SocketAddr) {
    let listener =
        Listener::new(config(), ListenerConfig::default()).expect("valid listener configuration");
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(listener.clone().serve(tcp));
    (listener, addr)
}

/// A session, or `None` when the server did not take it in time.
async fn connect(addr: std::net::SocketAddr) -> Option<Session> {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        Session::connect(PipeIo::from_tcp(tcp), config()),
    )
    .await
    .ok()?
    .ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
// HS-34
async fn shutdown_takes_joins_until_the_sessions_end() {
    tokio::time::timeout(LIMIT, async {
        let (listener, addr) = serve().await;
        let client = connect(addr).await.unwrap();
        let server = listener.accept().await.unwrap();
        // A stream both ends hold keeps the session's graceful close waiting
        // (a session with none ends as soon as its GOAWAY completes, and the
        // listener with it).
        let (mut send, recv) = client.open_bi().await.unwrap();
        send.write_all(b"x").await.unwrap();
        let held = server.accept_bi().await.unwrap();
        let l = listener.clone();
        let shutdown = tokio::spawn(async move {
            l.shutdown(VarInt::from_u32(0), b"bye").await;
        });
        // Draining: no new session ...
        assert!(listener.accept().await.is_none());
        listener.undrain();
        let (dial, arrival) = tokio::io::duplex(65536);
        let (client_result, setup) = tokio::join!(
            Session::connect(PipeIo::new(dial), config()),
            listener.handle_pipe(PipeIo::new(arrival), zmux::PipeHint::default())
        );
        assert_eq!(setup, Err(zmux::HandleError::Refused));
        let reason = match client_result {
            Ok(session) => session.closing().await,
            Err(zmux::ConnectError::SessionLost(reason)) => reason,
            Err(error) => panic!("unexpected handshake error: {error}"),
        };
        assert!(
            matches!(reason, zmux::SessionError::TransportClosed {code, remote: true, ..}
            if code == zmux::proto::TransportErrorCode::CONNECTION_REFUSED)
        );
        assert_eq!(listener.stats().refused, 1);
        let joins = listener.stats().joins;
        let (dial, arrival) = tokio::io::duplex(65536);
        let (joined, setup) = tokio::join!(
            client.add_pipe(PipeIo::new(dial), PipeOptions::default()),
            listener.handle_pipe(PipeIo::new(arrival), zmux::PipeHint::default())
        );
        joined.unwrap();
        setup.unwrap();
        assert_eq!(listener.stats().joins, joins + 1);
        assert!(!shutdown.is_finished());
        // The session ends: the listener closes.
        drop((send, recv, held));
        drop(server);
        drop(client);
        shutdown.await.unwrap();
        listener.adapter().closed().await;
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_refuses_joins_too() {
    tokio::time::timeout(LIMIT, async {
        let (listener, addr) = serve().await;
        let client = connect(addr).await.unwrap();
        let _server = listener.accept().await.unwrap();
        listener.close();
        // The serve loop ended: nothing is accepted any more.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(tokio::net::TcpStream::connect(addr).await.is_err());
        drop(client);
    })
    .await
    .unwrap();
}

/// A shutdown cancelled at its deadline closes the listener at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shutdown_past_its_deadline_closes() {
    tokio::time::timeout(LIMIT, async {
        let (listener, addr) = serve().await;
        let client = connect(addr).await.unwrap();
        let server = listener.accept().await.unwrap();
        // Holding streams open keeps the session's graceful close waiting.
        let (_send, _recv) = client.open_bi().await.unwrap();
        let r = tokio::time::timeout(
            Duration::from_millis(100),
            listener.shutdown(VarInt::from_u32(0), b""),
        )
        .await;
        drop(r);
        listener.adapter().closed().await;
        drop((client, server));
    })
    .await
    .unwrap();
}

/// The config hook is entered after classification and before parameter exchange.
#[tokio::test]
// HS-30, HS-31, HS-32, HS-33
async fn bootstrap_keeps_its_drain_decision_through_the_handshake() {
    use std::sync::Arc;
    use tokio::sync::Notify;
    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let mut limits = ListenerConfig::default();
    let (seen, gate) = (entered.clone(), resume.clone());
    limits.session_config = Some(zmux::SessionConfigFn::new_async(move |_| {
        seen.notify_one();
        let gate = gate.clone();
        async move {
            gate.notified().await;
            Ok(None)
        }
    }));
    let listener = Listener::new(config(), limits).unwrap();
    listener.drain(b"first");
    tokio::time::timeout(LIMIT, async {
        for refusal in [Some(&b"first"[..]), None, Some(b"replacement")] {
            let (near, far) = tokio::io::duplex(65536);
            let l = listener.clone();
            let handle = tokio::spawn(async move {
                l.handle_pipe(PipeIo::new(far), zmux::PipeHint::default()).await
            });
            let dial = tokio::spawn(Session::connect(PipeIo::new(near), config()));
            entered.notified().await;
            if refusal.is_some() {
                listener.undrain();
            } else {
                listener.drain(b"obsolete");
                listener.drain(b"replacement");
            }
            resume.notify_one();
            if let Some(expected) = refusal {
                assert_eq!(handle.await.unwrap(), Err(zmux::HandleError::Refused));
                let e = match dial.await.unwrap() {
                    Ok(s) => s.closing().await,
                    Err(zmux::ConnectError::SessionLost(e)) => e,
                    Err(e) => panic!("unexpected dial result: {e}"),
                };
                assert!(matches!(e, zmux::SessionError::TransportClosed { code, ref reason, remote: true, .. }
                    if code == zmux::proto::TransportErrorCode::CONNECTION_REFUSED && reason.as_ref() == expected), "{e:?}");
            } else {
                handle.await.unwrap().unwrap();
                let client = dial.await.unwrap().unwrap();
                let server = listener.accept().await.unwrap();
                let (a, b) = tokio::io::duplex(65536);
                let (joined, handled) = tokio::join!(
                    client.add_pipe(PipeIo::new(a), PipeOptions::default()),
                    listener.handle_pipe(PipeIo::new(b), zmux::PipeHint::default())
                );
                handled.unwrap();
                joined.unwrap();
                drop(server);
            }
        }
    }).await.unwrap();
    assert_eq!(listener.stats().refused, 2);
    assert_eq!(listener.stats().sessions, 1);
}

#[tokio::test]
// HS-35
async fn shutdown_assigns_the_application_code_only_to_accepted_sessions() {
    let listener = Listener::new(config(), ListenerConfig::default()).unwrap();
    let mut clients = Vec::new();
    let mut accepted = Vec::new();
    for i in 0..2 {
        let (near, far) = tokio::io::duplex(65536);
        let (client, setup) = tokio::join!(
            Session::connect(PipeIo::new(near), config()),
            listener.handle_pipe(PipeIo::new(far), zmux::PipeHint::default())
        );
        setup.unwrap();
        clients.push(client.unwrap());
        if i == 0 {
            accepted.push(listener.accept().await.unwrap());
        }
    }
    let shutdown = listener.shutdown(VarInt::from_u32(79), b"maintenance");
    let observe = async {
        for (client, want) in clients.iter().zip([79, 0]) {
            let error = client.closing().await;
            assert!(
                matches!(error, zmux::SessionError::ApplicationClosed {code, remote: true, ..} if code == VarInt::from_u32(want)),
                "{error:?}"
            );
        }
    };
    tokio::time::timeout(LIMIT, async {
        tokio::join!(shutdown, observe);
    })
    .await
    .unwrap();
}

// HS-35. Hold the establishing session's first parameters until the accepted
// client's protocol close proves that shutdown has chosen both close codes.
#[tokio::test]
async fn shutdown_while_the_first_parameter_write_is_blocked() {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::AsyncWrite;
    use tokio::sync::oneshot;

    struct FirstWrite<W> {
        writer: W,
        entered: Option<oneshot::Sender<()>>,
        release: Option<oneshot::Receiver<()>>,
    }
    impl<W: AsyncWrite + Unpin> AsyncWrite for FirstWrite<W> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if let Some(entered) = self.entered.take() {
                entered.send(()).unwrap();
            }
            if let Some(release) = &mut self.release {
                std::task::ready!(Pin::new(release).poll(cx)).unwrap();
                self.release = None;
            }
            Pin::new(&mut self.writer).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.writer).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.writer).poll_shutdown(cx)
        }
    }

    let check = async {
        use tokio::io::AsyncReadExt;
        use zmux::proto::ident::{Classifier, FirstRecord, Verdict};

        let listener = Listener::new(config(), ListenerConfig::default()).unwrap();
        let (a, b) = tokio::io::duplex(65536);
        let (accepted, setup) = tokio::join!(
            Session::connect(PipeIo::new(a), config()),
            listener.handle_pipe(PipeIo::new(b), zmux::PipeHint::default())
        );
        setup.unwrap();
        let accepted = accepted.unwrap();
        let _server = listener.accept().await.unwrap();

        let (a, b) = tokio::io::duplex(65536);
        let dial = tokio::spawn(Session::connect(PipeIo::new(a), config()));
        let (mut read, writer) = tokio::io::split(b);
        // A blocked write alone cannot prevent establishment: the peer's entire
        // parameters may already be buffered. Deliver just the classifier prefix.
        let mut classifier = Classifier::bootstrap(u64::MAX);
        let mut prefix = Vec::new();
        while classifier.verdict() == Verdict::NeedMore {
            let byte = read.read_u8().await.unwrap();
            prefix.push(byte);
            classifier.push(&[byte]);
        }
        assert_eq!(classifier.verdict(), Verdict::Accept(FirstRecord::Session));
        let (hold, waiting) = tokio::io::duplex(1);
        let (entered, start) = oneshot::channel();
        let (go, release) = oneshot::channel();
        let arriving = PipeIo::from_halves(
            waiting.chain(read),
            FirstWrite {
                writer,
                entered: Some(entered),
                release: Some(release),
            },
        )
        .with_prefix(prefix);
        let during_shutdown = async {
            start.await.unwrap();
            assert_eq!(listener.stats().sessions, 1);
            let code = VarInt::from_u32(79);
            tokio::join!(listener.shutdown(code, b"maintenance"), async {
                assert!(
                    matches!(accepted.closing().await, zmux::SessionError::ApplicationClosed { code: c, remote: true, .. } if c == code)
                );
                drop(hold);
                go.send(()).unwrap();
            });
        };
        let ((), setup) = tokio::join!(
            during_shutdown,
            listener.handle_pipe(arriving, zmux::PipeHint::default())
        );
        assert!(setup.is_err());
        let ended = match dial.await.unwrap() {
            Ok(s) => s.closing().await,
            Err(zmux::ConnectError::SessionLost(e)) => e,
            Err(e) => panic!("unexpected handshake error: {e:?}"),
        };
        assert!(
            matches!(
                ended,
                zmux::SessionError::ApplicationClosed {
                    code: VarInt::ZERO,
                    remote: true,
                    ..
                }
            ),
            "{ended:?}"
        );
    };
    tokio::time::timeout(LIMIT, check)
        .await
        .expect("both peers receive their protocol close");
}

#[cfg(feature = "test-hooks")]
#[tokio::test]
// HS-33
async fn a_refused_bootstrap_cannot_replace_a_live_join_route() {
    let mut cfg = config();
    cfg.test_hooks().locator = b"fixed-server-locator".to_vec();
    let listener = Listener::new(cfg, ListenerConfig::default()).unwrap();
    let connect = || async {
        let (a, b) = tokio::io::duplex(65536);
        tokio::join!(
            Session::connect(PipeIo::new(a), config()),
            listener.handle_pipe(PipeIo::new(b), zmux::PipeHint::default())
        )
    };
    tokio::time::timeout(LIMIT, async {
        let (client, first) = connect().await;
        first.unwrap();
        let (_accepted, client) = (listener.accept().await.unwrap(), client.unwrap());
        listener.drain(b"moving");
        let (_refused_peer, refused) = connect().await;
        assert_eq!(refused, Err(zmux::HandleError::Refused));
        let (a, b) = tokio::io::duplex(65536);
        let (joined, handled) = tokio::join!(
            client.add_pipe(PipeIo::new(a), PipeOptions::default()),
            listener.handle_pipe(PipeIo::new(b), zmux::PipeHint::default())
        );
        handled.unwrap();
        joined.unwrap().attached().await.unwrap();
    })
    .await
    .unwrap();
}
