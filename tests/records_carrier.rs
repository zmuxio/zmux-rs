//! A message-framed carrier (SPEC.md Section 3.4) with the tokio driver: the
//! application's write-through writes whole messages, which may pass its
//! byte budget (a regression: the budget arithmetic underflowed).

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use zmux::{Config, PipeIo, Session};

/// One direction of an in-memory message pipe.
#[derive(Default)]
struct Queue {
    messages: VecDeque<Vec<u8>>,
    reader: Option<Waker>,
    closed: bool,
}

/// One end: writes become messages of the peer's queue; reads return one
/// whole message each.
struct End {
    rx: Arc<Mutex<Queue>>,
    tx: Arc<Mutex<Queue>>,
}

fn pair() -> (End, End) {
    let a = Arc::new(Mutex::new(Queue::default()));
    let b = Arc::new(Mutex::new(Queue::default()));
    (
        End {
            rx: a.clone(),
            tx: b.clone(),
        },
        End { rx: b, tx: a },
    )
}

impl AsyncRead for End {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut q = self.rx.lock().unwrap();
        match q.messages.pop_front() {
            Some(m) => {
                assert!(m.len() <= buf.remaining(), "a message must fit");
                buf.put_slice(&m);
                Poll::Ready(Ok(()))
            }
            None if q.closed => Poll::Ready(Ok(())),
            None => {
                q.reader = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for End {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut q = self.tx.lock().unwrap();
        q.messages.push_back(buf.to_vec());
        if let Some(w) = q.reader.take() {
            w.wake();
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut q = self.tx.lock().unwrap();
        q.closed = true;
        if let Some(w) = q.reader.take() {
            w.wake();
        }
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_through_on_a_message_carrier() {
    let (a, b) = pair();
    let server =
        tokio::spawn(
            async move { Session::accept(PipeIo::new(b).records(), Config::default()).await },
        );
    let client = Session::connect(PipeIo::new(a).records(), Config::default())
        .await
        .unwrap();
    let server = server.await.unwrap().unwrap();
    let data: Vec<u8> = (0..4 << 20).map(|i: u32| (i * 7) as u8).collect();
    let expect = data.clone();
    let writer = tokio::spawn(async move {
        let (mut send, _r) = client.open_bi().await.unwrap();
        // Writes of many records each: every write-through takes whole
        // messages past its budget.
        for c in data.chunks(256 * 1024) {
            send.write_all(c).await.unwrap();
        }
        send.finish().unwrap();
        client
    });
    let (_s, mut recv) = server.accept_bi().await.unwrap();
    let got = recv.read_to_end(8 << 20).await.unwrap();
    assert_eq!(got, expect);
    writer.await.unwrap().close(0u32.into(), b"");
}
