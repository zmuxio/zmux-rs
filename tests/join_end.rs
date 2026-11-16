//! How a Join's handshake ends with its session and listener: an Unconfirmed carrier does not
//! outlive them, what ended it is no authentication failure, and nothing starts on a carrier
//! whose Confirm was written after the end.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
};
use tokio::sync::{Notify, oneshot};
use tokio::time::timeout;
use zmux::proto::session::AllowRecordMode;
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
            .begin_add_pipe(PipeIo::new(near), PipeOptions::new())
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

/// A carrier whose write of the Confirm waits for a gate, and which records its drop.
struct Gated {
    inner: DuplexStream,
    writes: usize,
    release: Arc<AtomicBool>,
    gate: Arc<Notify>,
    at_gate: Arc<Notify>,
    dropped: Arc<AtomicBool>,
}

impl Drop for Gated {
    fn drop(&mut self) {
        self.dropped.store(true, SeqCst);
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
        if self.writes == 1 && !self.release.load(SeqCst) {
            self.at_gate.notify_one();
            let gate = self.gate.clone();
            let w = cx.waker().clone();
            tokio::spawn(async move {
                gate.notified().await;
                w.wake();
            });
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
        let (release, gate, at_gate, dropped) = (
            Arc::new(AtomicBool::new(false)),
            Arc::new(Notify::new()),
            Arc::new(Notify::new()),
            Arc::new(AtomicBool::new(false)),
        );
        let carrier = Gated {
            inner: near,
            writes: 0,
            release: release.clone(),
            gate: gate.clone(),
            at_gate: at_gate.clone(),
            dropped: dropped.clone(),
        };
        let pipe = client
            .begin_add_pipe(PipeIo::new(carrier), PipeOptions::new())
            .unwrap();
        timeout(Duration::from_secs(5), at_gate.notified())
            .await
            .unwrap();
        if abort {
            pipe.abort().unwrap();
        } else {
            client.close().await;
        }
        release.store(true, SeqCst);
        gate.notify_waiters();
        assert!(
            timeout(Duration::from_secs(5), pipe.joined())
                .await
                .unwrap()
                .is_err()
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while !dropped.load(SeqCst) {
            assert!(tokio::time::Instant::now() < deadline, "carrier left open");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        listener.close();
    }
}

/// A carrier whose shutdown never completes; it says when it is first asked to.
struct StalledShutdown {
    inner: DuplexStream,
    asked: Option<oneshot::Sender<()>>,
}

impl AsyncRead for StalledShutdown {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
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

/// The handler's future dropped after the join attached its pipe, while it ends the
/// unused sending half, takes the pipe with it: the session keeps no pipe without a
/// carrier task.
#[tokio::test]
async fn a_dropped_handler_leaves_no_attached_pipe_behind() {
    let (client, server, listener) = sessions(Arc::default()).await;
    let (near, far) = duplex(1 << 16);
    let (asked, at_shutdown) = oneshot::channel();
    let l = listener.clone();
    let handler = tokio::spawn(async move {
        let carrier = StalledShutdown {
            inner: far,
            asked: Some(asked),
        };
        l.handle_pipe(PipeIo::new(carrier), zmux::PipeHint::default())
            .await
    });
    // The client only sends: the acceptor's sending half is unused.
    let mut only_out = PipeOptions::new();
    only_out.direction = PipeDirection::Out;
    let _pipe = client.begin_add_pipe(PipeIo::new(near), only_out).unwrap();
    timeout(Duration::from_secs(5), at_shutdown)
        .await
        .expect("the handler reached the end of the unused half")
        .unwrap();
    let stats = server.pipe_stats();
    assert_eq!(stats.len(), 2, "the join attached its pipe");
    assert!(stats.iter().all(|p| p.failure.is_none()));
    handler.abort();
    assert!(handler.await.unwrap_err().is_cancelled());
    let failed = server
        .pipe_stats()
        .iter()
        .filter(|p| p.failure.is_some())
        .count();
    assert_eq!(failed, 1, "the pipe of the dropped handler failed");
    listener.close();
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
                .begin_add_pipe(PipeIo::new(near), PipeOptions::new())
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
