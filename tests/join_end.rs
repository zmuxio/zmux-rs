//! How a Join's handshake ends with its session and listener: an Unconfirmed carrier does not
//! outlive them, what ended it is no authentication failure, and nothing starts on a carrier
//! whose Confirm was written after the end.

#[path = "common/clock.rs"]
mod clock;

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::task::{Context, Poll};
use std::time::Duration;

use clock::ManualClock;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::sync::{Notify, oneshot};
use tokio::time::timeout;
use zmux::proto::session::AllowRecordMode;
use zmux::{ClockDomain, MonotonicClock};
use zmux::{
    Config, HandleError, Listener, ListenerConfig, OnReject, PipeAuth, PipeDirection, PipeIo,
    PipeOptions, RejectAction, Session,
};

fn config() -> Config {
    let mut c =
        Config::multipath(PipeAuth::psk(*b"a pre-shared key of 32 bytes....").with_end_to_end());
    c.allow_record_mode = Some(AllowRecordMode::new(|_, _, _| true));
    c
}

async fn sessions(rejects: Arc<AtomicUsize>) -> (Session, Session, Listener) {
    let (a, b) = duplex(1 << 20);
    let mut limits = ListenerConfig::default();
    limits.on_reject = Some(OnReject::new(move |_| {
        rejects.fetch_add(1, SeqCst);
        RejectAction::Close
    }));
    let listener = Listener::new(config(), limits).expect("valid listener configuration");
    let l = listener.clone();
    tokio::spawn(async move {
        l.handle_pipe(PipeIo::new(b), zmux::PipeHint::default())
            .await
    });
    let client = Session::connect(PipeIo::new(a), config()).await.unwrap();
    let server = listener.accept().await.unwrap();
    client.established().await.unwrap();
    (client, server, listener)
}

/// The carrier already belongs to setup before the first poll.
#[tokio::test]
// HS-01
async fn dropping_setup_releases_the_carrier_before_and_during_classification() {
    let listener = Listener::new(config(), ListenerConfig::default()).unwrap();
    for started in [false, true] {
        let (local, mut peer) = duplex(64);
        let closed = Arc::new(AtomicUsize::new(0));
        let count = closed.clone();
        let io = PipeIo::new(local).with_close_code(move |_| {
            count.fetch_add(1, SeqCst);
        });
        let mut setup = Box::pin(listener.handle_pipe(io, zmux::PipeHint::default()));
        if started {
            assert!(
                setup
                    .as_mut()
                    .poll(&mut Context::from_waker(std::task::Waker::noop()))
                    .is_pending()
            );
        }
        drop(setup);
        assert_eq!(closed.load(SeqCst), 1);
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    }
}

#[tokio::test]
async fn unpolled_setup_keeps_its_entry_until_the_host_worker_exits() {
    let mut config = ListenerConfig::default();
    config.limits.max_pending = Some(1);
    let listener = Listener::new(Config::default(), config).unwrap();
    let addr = (std::net::Ipv4Addr::LOCALHOST, 0).into();
    let entry = listener.adapter().enter(addr, None).unwrap();
    let (local, mut peer) = duplex(64);
    let mut io = PipeIo::new(local);
    let worker = io.worker_guard();
    drop(listener.handle_pipe(io, zmux::PipeHint::from_entry(entry)));
    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    assert!(listener.adapter().enter(addr, None).is_none());
    drop(worker);
    assert!(listener.adapter().enter(addr, None).is_some());
}

#[tokio::test(start_paused = true)]
// HS-58
async fn admission_credentials_belong_to_the_issuing_listener() {
    let mut limits = ListenerConfig::default();
    limits.limits.max_pending = Some(1);
    let issuing = Listener::new(Config::default(), limits).unwrap();
    let mut policy = ListenerConfig::default();
    policy.admission = Some(zmux::Admission::new(0, |_, _| {
        zmux::AdmissionVerdict::Close
    }));
    let receiving = Listener::new(Config::default(), policy).unwrap();
    let addr = (std::net::Ipv4Addr::LOCALHOST, 0).into();
    let mut entry = issuing.adapter().enter(addr, None).unwrap();
    let verdict = entry
        .decide_request(zmux::CarrierInfo::new(), None::<&mut tokio::io::Empty>)
        .await;
    assert!(matches!(verdict, zmux::adapter::Admit::Accept(_)));
    let credential = entry.admitted().unwrap();
    for hint in [
        zmux::PipeHint::from_entry(entry),
        zmux::PipeHint::from_admitted(credential),
    ] {
        let (local, mut peer) = duplex(64);
        assert_eq!(
            receiving.handle_pipe(PipeIo::new(local), hint).await,
            Err(HandleError::Refused)
        );
        assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
        assert!(issuing.adapter().enter(addr, None).is_some());
    }
    assert_eq!(receiving.stats().refused, 2);
}

#[tokio::test]
async fn a_join_without_a_reply_writer_releases_its_carrier() {
    let (client, server, listener) = sessions(Arc::default()).await;
    let (near, far) = duplex(1 << 16);
    let pipe = client
        .test_begin_join(PipeIo::new(near), PipeOptions::default())
        .unwrap();
    let result = timeout(
        Duration::from_secs(3),
        listener.handle_pipe(PipeIo::reader(far), zmux::PipeHint::default()),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    assert!(
        timeout(Duration::from_secs(3), pipe.joined())
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(server.pipe_stats().len(), 1);
}

/// A relay that passes the Hello and the Reply and keeps the Confirm back: `far` stays
/// Unconfirmed. `replied` is notified when the Reply passed.
fn hold_confirm(mut near: DuplexStream, mut far: DuplexStream, replied: Arc<Notify>) {
    tokio::spawn(async move {
        let (mut up, mut down) = ([0u8; 8192], [0u8; 8192]);
        let mut hello = false;
        loop {
            tokio::select! {
                r = near.read(&mut up) => {
                    let Ok(n @ 1..) = r else { return };
                    if !hello {
                        hello = true;
                        if far.write_all(&up[..n]).await.is_err() { return }
                    }
                }
                r = far.read(&mut down) => {
                    let Ok(n @ 1..) = r else { return };
                    if near.write_all(&down[..n]).await.is_err() { return }
                    replied.notify_one();
                }
            }
        }
    });
}

#[tokio::test]
async fn acceptor_join_deadline_expires_while_confirm_is_held() {
    timeout(Duration::from_secs(30), async {
        let wait = Duration::from_secs(37);
        let (clock, domain) = ManualClock::domain(Duration::from_secs(120));
        let mut timers = clock.registrations();
        let deadline = domain.now() + wait;
        let mut accepting = config();
        accepting.join_timeout = wait;
        accepting.clock_domain = domain;
        let listener = Listener::new(accepting, ListenerConfig::default()).unwrap();
        let mut dialing = config();
        dialing.join_timeout = Duration::from_secs(60);
        let (near, far) = duplex(64 * 1024);
        let (client, established) = tokio::join!(
            Session::connect(PipeIo::new(near), dialing),
            listener.handle_pipe(PipeIo::new(far), zmux::PipeHint::default())
        );
        established.unwrap();
        let client = client.unwrap();
        let server = listener.accept().await.unwrap();

        let (client_io, up) = duplex(64 * 1024);
        let (down, server_io) = duplex(64 * 1024);
        let replied = Arc::new(Notify::new());
        hold_confirm(up, down, replied.clone());
        let _pipe = client
            .test_begin_join(PipeIo::new(client_io), PipeOptions::default())
            .unwrap();
        let accepting = listener.clone();
        let handled = tokio::spawn(async move {
            accepting
                .handle_pipe(PipeIo::new(server_io), zmux::PipeHint::default())
                .await
        });
        while timers.recv().await.unwrap() != deadline {}
        replied.notified().await;
        clock.advance(wait);
        assert_eq!(handled.await.unwrap(), Err(HandleError::TimedOut));
        assert_eq!(server.pipe_stats().len(), 1);
        assert_eq!(listener.stats().timed_out, 1);
    })
    .await
    .expect("acceptor Join timeout test watchdog");
}

#[tokio::test]
async fn an_unconfirmed_carrier_ends_with_session_and_listener() {
    for session_ends in [true, false] {
        let rejects = Arc::new(AtomicUsize::new(0));
        let (client, server, listener) = sessions(rejects.clone()).await;
        let (near, relay_a) = duplex(1 << 16);
        let (relay_b, far) = duplex(1 << 16);
        let replied = Arc::new(Notify::new());
        hold_confirm(relay_a, relay_b, replied.clone());
        let l = listener.clone();
        let handled = tokio::spawn(async move {
            l.handle_pipe(PipeIo::new(far), zmux::PipeHint::default())
                .await
        });
        let _pipe = client
            .test_begin_join(PipeIo::new(near), PipeOptions::new())
            .unwrap();
        timeout(Duration::from_secs(5), replied.notified())
            .await
            .unwrap();
        if session_ends {
            server.close().await;
        } else {
            listener.close();
        }
        // Long before the handshake timeout.
        let r = timeout(Duration::from_secs(3), handled)
            .await
            .expect("the carrier's handler ended")
            .unwrap();
        assert_eq!(r.err(), Some(HandleError::Refused));
        assert_eq!(rejects.load(SeqCst), 0, "no authentication failure");
        assert_eq!(listener.stats().rejected, 0);
    }
}

/// A carrier evicted for the session's bound of Unconfirmed carriers ends as
/// refused (a limit of the session), counted in `refused`, not as rejected,
/// and it counts no join.
#[tokio::test]
// HS-24
async fn an_evicted_unconfirmed_carrier_counts_as_refused() {
    let (a, b) = duplex(1 << 20);
    let limits = ListenerConfig::default();
    let mut cfg = config();
    cfg.session_policy.limits.pending_peer_joins = std::num::NonZeroUsize::MIN;
    let listener = Listener::new(cfg, limits).expect("valid listener configuration");
    let l = listener.clone();
    tokio::spawn(async move {
        l.handle_pipe(PipeIo::new(b), zmux::PipeHint::default())
            .await
    });
    let client = Session::connect(PipeIo::new(a), config()).await.unwrap();
    let _server = listener.accept().await.unwrap();
    client.established().await.unwrap();
    let mut handled = Vec::new();
    let mut pipes = Vec::new();
    for _ in 0..2 {
        let (near, relay_a) = duplex(1 << 16);
        let (relay_b, far) = duplex(1 << 16);
        let replied = Arc::new(Notify::new());
        hold_confirm(relay_a, relay_b, replied.clone());
        let l = listener.clone();
        handled.push(tokio::spawn(async move {
            l.handle_pipe(PipeIo::new(far), zmux::PipeHint::default())
                .await
        }));
        pipes.push(
            client
                .test_begin_join(PipeIo::new(near), PipeOptions::new())
                .unwrap(),
        );
        timeout(Duration::from_secs(5), replied.notified())
            .await
            .unwrap();
    }
    // The second Hello took the room: the first, Unconfirmed longest, ends.
    let first = handled.remove(0);
    let r = timeout(Duration::from_secs(3), first)
        .await
        .expect("the evicted carrier's handler ended")
        .unwrap();
    assert_eq!(r.err(), Some(HandleError::Refused));
    let st = listener.stats();
    assert_eq!((st.refused, st.rejected, st.joins), (1, 0, 0));
    listener.close();
}

#[derive(Default)]
struct ConfirmGate {
    open: AtomicBool,
    writer: atomic_waker::AtomicWaker,
}

impl ConfirmGate {
    fn wait(&self, cx: &Context<'_>) -> bool {
        self.writer.register(cx.waker());
        !self.open.load(SeqCst)
    }

    fn release(&self) {
        self.open.store(true, SeqCst);
        self.writer.wake();
    }
}

/// A carrier whose write of the Confirm waits for a gate, and which records its drop.
struct Gated {
    inner: DuplexStream,
    writes: usize,
    gate: Arc<ConfirmGate>,
    at_gate: Arc<Notify>,
    dropped: Arc<Notify>,
}

impl Drop for Gated {
    fn drop(&mut self) {
        self.dropped.notify_one();
    }
}

impl AsyncRead for Gated {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Gated {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        // The first write is the Hello, the second the Confirm.
        if self.writes == 1 && self.gate.wait(cx) {
            self.at_gate.notify_one();
            return Poll::Pending;
        }
        let r = Pin::new(&mut self.inner).poll_write(cx, b);
        if matches!(r, Poll::Ready(Ok(_))) {
            self.writes += 1;
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The end of the session or of the attachment while the Confirm is written starts nothing.
#[tokio::test]
async fn no_pipe_starts_after_its_end_during_the_confirm() {
    for abort in [false, true] {
        let (client, _server, listener) = sessions(Arc::default()).await;
        let (near, far) = duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move {
            l.handle_pipe(PipeIo::new(far), zmux::PipeHint::default())
                .await
        });
        let gate = Arc::new(ConfirmGate::default());
        let at_gate = Arc::new(Notify::new());
        let dropped = Arc::new(Notify::new());
        let carrier = Gated {
            inner: near,
            writes: 0,
            gate: gate.clone(),
            at_gate: at_gate.clone(),
            dropped: dropped.clone(),
        };
        let pipe = client
            .test_begin_join(PipeIo::new(carrier), PipeOptions::new())
            .unwrap();
        timeout(Duration::from_secs(5), at_gate.notified())
            .await
            .unwrap();
        if abort {
            pipe.abort().unwrap();
        } else {
            client.close().await;
        }
        gate.release();
        assert!(
            timeout(Duration::from_secs(5), pipe.joined())
                .await
                .unwrap()
                .is_err()
        );
        timeout(Duration::from_secs(30), dropped.notified())
            .await
            .expect("carrier left open");
        listener.close();
    }
}

/// Buffers the Reply until its flush is allowed.
struct ReplyWriter {
    buffered: tokio::io::BufWriter<tokio::io::WriteHalf<DuplexStream>>,
    entered: Option<oneshot::Sender<()>>,
    release: oneshot::Receiver<()>,
}

impl AsyncWrite for ReplyWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.buffered).poll_write(cx, b)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(entered) = self.entered.take() {
            entered.send(()).unwrap();
        }
        std::task::ready!(Pin::new(&mut self.release).poll(cx)).unwrap();
        Pin::new(&mut self.buffered).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.buffered).poll_shutdown(cx)
    }
}

#[tokio::test(start_paused = true)]
// HS-04
async fn authenticated_refusal_returns_before_reply_flush() {
    let mut acceptor = config();
    let dialer = config();
    acceptor.session_policy.limits.steady_attachments = 2;
    acceptor.session_policy.limits.join_headroom = 0;
    let listener = Listener::new(acceptor, ListenerConfig::default()).unwrap();
    let mut limits = listener.limits();
    limits.max_pending = Some(1);
    listener.set_limits(limits).unwrap();
    let carrier = || {
        let (near, far) = duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move {
            l.handle_pipe(PipeIo::new(far), zmux::PipeHint::default())
                .await
        });
        PipeIo::new(near)
    };
    let client = Session::connect(carrier(), dialer).await.unwrap();
    let _server = listener.accept().await.unwrap();
    client
        .test_join(carrier(), PipeOptions::default())
        .await
        .unwrap();
    let (near, far) = duplex(1 << 16);
    let (reader, write) = tokio::io::split(far);
    let (entered, flushing) = oneshot::channel();
    let (release, gate) = oneshot::channel();
    let writer = ReplyWriter {
        buffered: tokio::io::BufWriter::new(write),
        entered: Some(entered),
        release: gate,
    };
    let refused = client
        .test_begin_join(PipeIo::new(near), PipeOptions::default())
        .unwrap();
    let observer = listener.clone();
    let setup = tokio::spawn(async move {
        listener
            .handle_pipe(
                PipeIo::from_halves(reader, writer),
                zmux::PipeHint::default(),
            )
            .await
    });
    flushing.await.unwrap();
    let before = tokio::time::Instant::now();
    assert_eq!(setup.await.unwrap(), Err(HandleError::Refused));
    assert_eq!(tokio::time::Instant::now(), before);
    let peer = (std::net::Ipv4Addr::LOCALHOST, 0).into();
    assert!(observer.adapter().enter(peer, None).is_none());
    let mut limits = observer.limits();
    limits.max_pending = Some(4);
    limits.max_pending_per_source = 2;
    observer.set_limits(limits).unwrap();
    let source = (std::net::Ipv4Addr::UNSPECIFIED, 0).into();
    let _second = observer.adapter().enter(source, None).unwrap();
    assert!(observer.adapter().enter(source, None).is_none());
    assert!(observer.adapter().enter(peer, None).is_some());
    release.send(()).unwrap();
    assert!(matches!(
        refused.joined().await,
        Err(zmux::PipeError::Failed(zmux::PipeFailure::JoinRefused))
    ));
    assert!(observer.adapter().enter(source, None).is_some());
}

/// A carrier whose shutdown never completes; it says when it is first asked to.
struct StalledShutdown {
    inner: tokio::io::WriteHalf<DuplexStream>,
    asked: Option<oneshot::Sender<()>>,
    _held: oneshot::Sender<()>,
}

impl AsyncWrite for StalledShutdown {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, b)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(asked) = self.asked.take() {
            let _ = asked.send(());
        }
        Poll::Pending
    }
}

/// A stalled shutdown of the unused half is independent of join handoff.
#[tokio::test(start_paused = true)]
// HS-51
async fn one_way_join_returns_with_unused_shutdown_pending() {
    let (client, server, listener) = sessions(Arc::default()).await;
    let (near, far) = duplex(1 << 16);
    let (asked, at_shutdown) = oneshot::channel();
    let (held, mut released) = oneshot::channel();
    let l = listener.clone();
    let handler = tokio::spawn(async move {
        let (read, write) = tokio::io::split(far);
        let carrier = StalledShutdown {
            _held: held,
            inner: write,
            asked: Some(asked),
        };
        l.handle_pipe(
            PipeIo::from_halves(read, carrier),
            zmux::PipeHint::default(),
        )
        .await
    });
    // The client only sends: the acceptor's sending half is unused.
    let mut only_out = PipeOptions::new();
    only_out.direction = PipeDirection::Out;
    let _pipe = client.test_begin_join(PipeIo::new(near), only_out).unwrap();
    timeout(Duration::from_secs(5), at_shutdown)
        .await
        .expect("the handler reached the end of the unused half")
        .unwrap();
    let stats = server.pipe_stats();
    assert_eq!(stats.len(), 2, "the join attached its pipe");
    assert!(stats.iter().all(|p| p.failure.is_none()));
    let before = tokio::time::Instant::now();
    handler.await.unwrap().unwrap();
    assert_eq!(tokio::time::Instant::now(), before);
    assert_eq!(
        released.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    );
    tokio::time::advance(zmux::adapter::DRAIN_LIMIT).await;
    assert!(released.await.is_err());
    assert_eq!(before.elapsed(), zmux::adapter::DRAIN_LIMIT);
    assert!(server.pipe_stats().iter().all(|p| p.failure.is_none()));
    listener.close();
}

#[tokio::test(start_paused = true)]
// HS-01
async fn closing_listener_interrupts_exporter() {
    let mut limits = ListenerConfig::default();
    limits.handshake_timeout = Duration::MAX;
    let listener = Listener::new(config(), limits).unwrap();
    let (local, mut peer) = duplex(64);
    let entered = Arc::new(Notify::new());
    let gate = entered.clone();
    let io = PipeIo::new(local).with_exporter_async(move |_| {
        gate.notify_one();
        std::future::pending()
    });
    let l = listener.clone();
    let setup = tokio::spawn(async move { l.handle_pipe(io, zmux::PipeHint::default()).await });
    entered.notified().await;
    let before = tokio::time::Instant::now();
    listener.close();
    assert_eq!(setup.await.unwrap(), Err(HandleError::Refused));
    assert_eq!(peer.read(&mut [0]).await.unwrap(), 0);
    assert_eq!(tokio::time::Instant::now(), before);
}

/// A joiner whose carrier task is dropped in its handshake (here by the end of the runtime
/// it runs on, while the session lives on another) fails the join at once, rather than
/// leaving the pipe to the handshake timeout.
#[test]
fn a_dropped_joiner_fails_its_join_at_once() {
    let session_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let joiner_rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let (pipe, _alive) = session_rt.block_on(async {
        let (client, server, listener) = sessions(Arc::default()).await;
        let (near, mut far) = duplex(1 << 16);
        // The carrier task of the join runs on the joiner's runtime.
        let pipe = {
            let _on_joiner_rt = joiner_rt.enter();
            client
                .test_begin_join(PipeIo::new(near), PipeOptions::new())
                .unwrap()
        };
        // The joiner's Hello is out, and nobody answers it.
        timeout(Duration::from_secs(5), far.read_u8())
            .await
            .expect("the joiner started")
            .unwrap();
        (pipe, (client, server, listener, far))
    });
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(
        std::pin::pin!(pipe.joined()).poll(&mut cx).is_pending(),
        "the join waits for its handshake"
    );
    drop(joiner_rt);
    let joined = std::pin::pin!(pipe.joined()).poll(&mut cx);
    assert!(
        matches!(joined, Poll::Ready(Err(zmux::PipeError::Failed(_)))),
        "{joined:?}"
    );
}

#[tokio::test]
async fn confirmed_join_returns_while_unused_reader_drops() {
    struct Reader {
        inner: tokio::io::ReadHalf<DuplexStream>,
        entered: Option<oneshot::Sender<()>>,
        gate: std::sync::mpsc::Receiver<()>,
    }
    impl AsyncRead for Reader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            b: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, b)
        }
    }
    impl Drop for Reader {
        fn drop(&mut self) {
            let _ = self.entered.take().unwrap().send(());
            let _ = self.gate.recv_timeout(Duration::from_secs(3));
        }
    }
    let (client, _server, l) = sessions(Arc::default()).await;
    let (near, far) = duplex(1 << 16);
    let (inner, writer) = tokio::io::split(far);
    let (entered, dropping) = oneshot::channel();
    let (release, gate) = std::sync::mpsc::channel();
    let io = PipeIo::from_halves(
        Reader {
            inner,
            entered: Some(entered),
            gate,
        },
        writer,
    );
    let handler = tokio::spawn(async move { l.handle_pipe(io, zmux::PipeHint::default()).await });
    let mut opt = PipeOptions::new();
    opt.direction = PipeDirection::In;
    let _pipe = client.test_begin_join(PipeIo::new(near), opt).unwrap();
    dropping.await.unwrap();
    handler.await.unwrap().unwrap();
    release.send(()).unwrap();
}

#[tokio::test(start_paused = true)]
// HS-22
async fn an_expired_join_cannot_be_revived_by_a_late_confirm() {
    {
        let mut cfg = config();
        cfg.join_timeout = Duration::from_secs(2);
        let listener = Listener::new(config(), ListenerConfig::default()).unwrap();
        let (a, b) = duplex(65536);
        let (client, setup) = tokio::join!(
            Session::connect(PipeIo::new(a), cfg),
            listener.handle_pipe(PipeIo::new(b), zmux::PipeHint::default())
        );
        setup.unwrap();
        let client = client.unwrap();
        let server = listener.accept().await.unwrap();
        let (near, far) = duplex(65536);
        let gate = Arc::new(ConfirmGate::default());
        let carrier = Gated {
            inner: near,
            gate: gate.clone(),
            writes: 0,
            at_gate: Arc::default(),
            dropped: Arc::default(),
        };
        let entered = carrier.at_gate.clone();
        let l = listener.clone();
        let handler = tokio::spawn(async move {
            l.handle_pipe(PipeIo::new(far), zmux::PipeHint::default())
                .await
        });
        let joining = client.clone();
        let adding = tokio::spawn(async move {
            joining
                .test_join(PipeIo::new(carrier), PipeOptions::new())
                .await
        });
        entered.notified().await;
        let pipe = client
            .pipes()
            .into_iter()
            .find(|p| p.id().get() != 0)
            .unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        let timed_out = |r| {
            matches!(
                r,
                Err(zmux::PipeError::Failed(zmux::PipeFailure::JoinTimedOut))
            )
        };
        assert!(timed_out(adding.await.unwrap().map(|_| ())));
        assert!(timed_out(pipe.attached().await));
        gate.release();
        assert!(handler.await.unwrap().is_err());
        assert!(timed_out(pipe.attached().await));
        assert_eq!(server.pipe_stats().len(), 1);
    }
}

// HS-02. The only transport is the one whose setup caller withdraws.
#[tokio::test]
// HS-02
async fn cancellation_after_handoff_delivers_the_sessions_close() {
    let listener = Listener::new(config(), ListenerConfig::default()).unwrap();
    let (a, b) = duplex(65536);
    let peer = (std::net::Ipv4Addr::LOCALHOST, 0).into();
    let (cancel, setup) = listener
        .adapter()
        .cancellable_setup(PipeIo::new(b), peer, None);
    // HS-02a. Hold the result after the publication closure has returned.
    let (published, ready) = tokio::sync::oneshot::channel();
    let (release, deliver) = tokio::sync::oneshot::channel();
    let caller = tokio::spawn(async move {
        let result = setup.await;
        published.send(()).unwrap();
        deliver.await.unwrap();
        result
    });
    let client = Session::connect(PipeIo::new(a), config()).await.unwrap();
    ready.await.unwrap();
    assert!(!cancel.cancel());
    release.send(()).unwrap();
    caller.await.unwrap().unwrap();
    let server = listener.accept().await.unwrap();
    client.ping().await.unwrap();
    let code = zmux::VarInt::from_u32(23);
    server.close_with_error(code, b"handed off").await;
    assert!(
        matches!(client.closing().await, zmux::SessionError::ApplicationClosed {remote:true, code:c, reason,..} if c==code && reason.as_ref()==b"handed off")
    );
}

struct ReplyReceipt {
    late_bytes: Option<usize>,
    started: Option<oneshot::Sender<()>>,
    released: oneshot::Receiver<()>,
    dropped: Option<oneshot::Sender<usize>>,
    accepted: usize,
}

impl ReplyReceipt {
    fn entered(&mut self) {
        if let Some(started) = self.started.take() {
            started.send(()).unwrap();
        }
    }
}

impl AsyncWrite for ReplyReceipt {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.entered();
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl zmux::adapter::ChunkWrite for ReplyReceipt {
    fn poll_write_chunks(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        chunks: &mut [zmux::Chunk],
    ) -> Poll<io::Result<usize>> {
        self.entered();
        std::task::ready!(Pin::new(&mut self.released).poll(cx)).unwrap();
        let [chunk] = chunks else {
            panic!("one Join buffer")
        };
        let n = chunk.len().min(self.late_bytes.expect("submitted write"));
        bytes::Buf::advance(chunk, n);
        self.accepted += n;
        Poll::Ready(Ok(n))
    }

    fn has_submitted_write(&self) -> bool {
        self.late_bytes.is_some()
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for ReplyReceipt {
    fn drop(&mut self) {
        let _ = self.dropped.take().unwrap().send(self.accepted);
    }
}

#[tokio::test]
async fn g4_cancelled_join_settles_only_a_submitted_adapters_late_prefix() {
    timeout(Duration::from_secs(5), async {
        for (chunked, late_bytes) in [
            (false, None),
            (true, None),
            (true, Some(1)),
            (true, Some(usize::MAX)),
        ] {
            use zmux::shaping::{HandshakeShaper, UnitPlan};

            let wait = Duration::from_secs(2);
            let (clock, domain) = ManualClock::domain(Duration::from_secs(120));
            let mut cfg = config();
            cfg.join_timeout = wait;
            cfg.clock_domain = domain;
            cfg.handshake_shaper = Some(HandshakeShaper::new(|v| {
                (v.message == "reply").then_some(UnitPlan::new(1024, 0, 0))
            }));
            let listener = Listener::new(cfg, ListenerConfig::default()).unwrap();
            let (near, far) = duplex(1 << 16);
            let (client, setup) = tokio::join!(
                Session::connect(PipeIo::new(near), config()),
                listener.handle_pipe(PipeIo::new(far), zmux::PipeHint::default())
            );
            setup.unwrap();
            let client = client.unwrap();
            let server = listener.accept().await.unwrap();
            let (near, far) = duplex(1 << 16);
            let (reader, _writer) = tokio::io::split(far);
            let (started, entered) = oneshot::channel();
            let (release, released) = oneshot::channel();
            let (dropped, finished) = oneshot::channel();
            let writer = ReplyReceipt {
                late_bytes,
                started: Some(started),
                released,
                dropped: Some(dropped),
                accepted: 0,
            };
            let io = if chunked {
                PipeIo::from_chunk_halves(reader, writer)
            } else {
                PipeIo::from_halves(reader, writer)
            };
            let _join = client
                .test_begin_join(PipeIo::new(near), PipeOptions::default())
                .unwrap();
            let handle =
                tokio::spawn(
                    async move { listener.handle_pipe(io, zmux::PipeHint::default()).await },
                );

            entered.await.unwrap();
            let reserved = server.shaping_stats().handshake_reserved_bytes;
            assert!(reserved > 0);
            clock.advance(wait);
            assert_eq!(handle.await.unwrap(), Err(HandleError::TimedOut));
            let before = server.shaping_stats();
            if late_bytes.is_some() {
                assert_eq!(before.handshake_reserved_bytes, reserved);
                release.send(()).unwrap();
            }
            let accepted = u64::try_from(finished.await.unwrap()).unwrap();
            let stats = server.shaping_stats();
            assert_eq!(stats.handshake_reserved_bytes, 0);
            assert_eq!(stats.handshake_unresolved_bytes, 0);
            let proved = match late_bytes {
                None => {
                    assert_eq!(accepted, 0);
                    0
                }
                Some(1) => {
                    // The byte-stream Size field is ordinary baseline.
                    assert_eq!(accepted, 1);
                    0
                }
                Some(_) => {
                    assert!(accepted > reserved);
                    reserved
                }
            };
            assert_eq!(stats.handshake_measured_bytes, proved);
            assert!(
                stats.ledger.baseline_bytes - before.ledger.baseline_bytes >= accepted - proved
            );
            assert_eq!(server.pipe_stats().len(), 1);
        }
    })
    .await
    .unwrap();
}
