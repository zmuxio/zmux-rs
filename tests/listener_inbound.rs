//! A listener's inbound transform, the admission's value on sessions and
//! pipes, and the answer to joins that name no session.

use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use zmux::{
    Admission, AdmittedValue, Config, InboundTransform, Listener, ListenerConfig, PipeAuth,
    PipeFailure, PipeHint, PipeIo, PipeOptions, Session, Verdict,
};

const LIMIT: Duration = Duration::from_secs(10);

fn config() -> Config {
    let mut config = Config::default();
    config.max_pipes = 8;
    config.pipe_auth = PipeAuth::psk(b"a pre-shared key, 16 bytes or more".to_vec());
    config
}

async fn serve(limits: ListenerConfig) -> (Listener, std::net::SocketAddr) {
    let listener = Listener::new(config(), limits);
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(listener.clone().serve(tcp));
    (listener, addr)
}

async fn eventually(f: impl Fn() -> bool) {
    tokio::time::timeout(LIMIT, async {
        while !f() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

fn value_of(v: Option<AdmittedValue>) -> Option<u32> {
    v.and_then(|v| v.downcast_ref::<u32>().copied())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_transform_sees_every_carrier_and_the_value_travels() {
    tokio::time::timeout(LIMIT, async {
        let next = Arc::new(AtomicUsize::new(7));
        let n = next.clone();
        let mut limits = ListenerConfig::default();
        limits.admission = Some(Admission::new(0, move |_, _| {
            let v = u32::try_from(n.fetch_add(1, Relaxed)).unwrap();
            Verdict::accept(0).with_value(Arc::new(v))
        }));
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        limits.inbound_transform =
            Some(InboundTransform::new(move |io: PipeIo, hint: &PipeHint| {
                s.lock().unwrap().push(value_of(hint.admitted().cloned()));
                io.wrap(|stream| async move { Ok(stream) })
            }));
        let (listener, addr) = serve(limits).await;
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let client = Session::connect(PipeIo::tcp(tcp), config()).await.unwrap();
        let server = listener.accept().await.unwrap();
        assert_eq!(value_of(server.admitted()), Some(7));
        assert!(client.admitted().is_none());
        // A join: its own value, the session's unchanged.
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let pipe = client
            .add_pipe(PipeIo::tcp(tcp), PipeOptions::default())
            .unwrap();
        pipe.joined().await.unwrap();
        eventually(|| server.pipes().len() == 2).await;
        let mut values: Vec<_> = server
            .pipes()
            .iter()
            .map(|p| value_of(p.admitted()))
            .collect();
        values.sort();
        assert_eq!(values, vec![Some(7), Some(8)]);
        assert_eq!(value_of(server.admitted()), Some(7));
        assert_eq!(*seen.lock().unwrap(), vec![Some(7), Some(8)]);
        // The wrapped carriers carry the session.
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        let (mut ss, mut sr) = server.accept_bi().await.unwrap();
        assert_eq!(sr.read_to_end(64).await.unwrap(), b"ping");
        ss.write_all(b"pong").await.unwrap();
        ss.finish().unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"pong");
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_or_kind_changing_transform_is_a_setup_failure() {
    tokio::time::timeout(LIMIT, async {
        for kind_change in [false, true] {
            let mut limits = ListenerConfig::default();
            limits.inbound_transform = Some(InboundTransform::new(
                move |io: PipeIo, _: &PipeHint| async move {
                    if kind_change {
                        // Message framing on a byte stream: refused.
                        Ok(io.records())
                    } else {
                        drop(io);
                        Err(std::io::Error::other("no"))
                    }
                },
            ));
            let (listener, addr) = serve(limits).await;
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let r = tokio::time::timeout(
                Duration::from_secs(3),
                Session::connect(PipeIo::tcp(tcp), config()),
            )
            .await;
            assert!(!matches!(r, Ok(Ok(_))));
            eventually(|| listener.stats().setup_failures == 1).await;
            assert_eq!(listener.stats().sessions, 0);
        }
    })
    .await
    .unwrap();
}

/// A carrier end that records what the listener writes on it.
struct Tee {
    io: DuplexStream,
    wrote: Arc<Mutex<Vec<u8>>>,
}

impl AsyncRead for Tee {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Tee {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let r = Pin::new(&mut self.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            self.wrote.lock().unwrap().extend_from_slice(&buf[..n]);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// A join of a session of listener A sent to listener B: what B wrote, and
/// how the join ended at the client.
async fn join_elsewhere(
    answer: bool,
    ids: (&[u8], &[u8]),
) -> (Vec<u8>, Option<PipeFailure>, Session, Session) {
    let mut a = ListenerConfig::default();
    a.instance_id = ids.0.to_vec();
    let (la, addr) = serve(a).await;
    let mut b = ListenerConfig::default();
    b.instance_id = ids.1.to_vec();
    b.answer_unknown_joins = answer;
    let lb = Listener::new(config(), b);
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let client = Session::connect(PipeIo::tcp(tcp), config()).await.unwrap();
    let server = la.accept().await.unwrap();
    let (ours, theirs) = tokio::io::duplex(4096);
    let wrote = Arc::new(Mutex::new(Vec::new()));
    let tee = Tee {
        io: theirs,
        wrote: wrote.clone(),
    };
    let l = lb.clone();
    let handled =
        tokio::spawn(async move { l.handle_pipe(PipeIo::new(tee), PipeHint::default()).await });
    let pipe = client
        .add_pipe(PipeIo::new(ours), PipeOptions::default())
        .unwrap();
    let joined = tokio::time::timeout(Duration::from_secs(3), pipe.joined()).await;
    assert!(!matches!(joined, Ok(Ok(()))));
    let _ = handled.await;
    assert_eq!(lb.stats().rejected, 1);
    let failure = pipe.stats().and_then(|s| s.failure);
    let w = wrote.lock().unwrap().clone();
    (w, failure, client, server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_join_is_answered_only_when_asked() {
    tokio::time::timeout(LIMIT, async {
        let (wrote, failure, client, _server) = join_elsewhere(true, (b"i1", b"i1")).await;
        assert_eq!(wrote, [0x07, 0x1c, 0x8f, 0x05, 0xf7, 0x4e, 0x00, 0x00]);
        assert_eq!(
            failure,
            Some(PipeFailure::JoinClosed(zmux::VarInt::from_u32(0x0f05_f74e)))
        );
        // Only the join failed, and further joins back off.
        assert!(client.close_reason().is_none());
        assert_eq!(client.stats().join_refusals, 1);
        // Off by default, and for another instance's locators: silent.
        for (answer, ids) in [(false, (&b"i1"[..], &b"i1"[..])), (true, (b"i1", b"i2"))] {
            let (wrote, _, client, _server) = join_elsewhere(answer, ids).await;
            assert!(wrote.is_empty(), "{wrote:?}");
            assert!(client.close_reason().is_none());
        }
    })
    .await
    .unwrap();
}

/// A suspended session whose resumption is answered ends at once with
/// ZMUX_RESUME_FAILED instead of at the end of its grace period.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_answered_resumption_ends_the_suspended_session_at_once() {
    tokio::time::timeout(LIMIT, async {
        let mut cfg = config();
        cfg.resume_timeout = Some(Duration::from_secs(30));
        let la = Listener::new(cfg.clone(), ListenerConfig::default());
        let mut b = ListenerConfig::default();
        b.answer_unknown_joins = true;
        let lb = Listener::new(cfg.clone(), b);
        let (ours, theirs) = tokio::io::duplex(1 << 16);
        let l = la.clone();
        tokio::spawn(async move {
            l.handle_pipe(PipeIo::new(theirs), PipeHint::default())
                .await
        });
        let client = Session::connect(PipeIo::new(ours), cfg.clone())
            .await
            .unwrap();
        let _server = la.accept().await.unwrap();
        client.pipes()[0].abort().unwrap();
        eventually(|| client.state() == zmux::SessionState::Suspended).await;
        let (ours, theirs) = tokio::io::duplex(4096);
        let l = lb.clone();
        tokio::spawn(async move {
            l.handle_pipe(PipeIo::new(theirs), PipeHint::default())
                .await
        });
        let _ = client.add_pipe(PipeIo::new(ours), PipeOptions::default());
        tokio::time::timeout(Duration::from_secs(3), client.closed())
            .await
            .expect("closed long before the grace period");
        match client.close_reason() {
            Some(zmux::SessionError::TransportClosed { code, remote, .. }) => {
                assert_eq!(code.0, 0x0f05_f74e);
                assert!(!remote);
            }
            r => panic!("{r:?}"),
        }
    })
    .await
    .unwrap();
}
