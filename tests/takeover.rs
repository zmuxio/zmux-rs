//! The listener's fallback and what it takes over ([`Takeover`]): the
//! verdict's value, detaching, who closes each half (once), the typed
//! halves of a message-framed carrier, and a fallback's future that its
//! entry's cancellation does not end.

#![allow(
    clippy::many_single_char_names,
    reason = "short conventional names in scenario code"
)]

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use zmux::adapter::{AdmitIo, Entry};
use zmux::{
    Admission, AdmissionVerdict, CarrierInfo, Config, Fallback, Listener, ListenerConfig, PipeIo,
    Takeover, TakeoverReturned,
};

const LIMIT: Duration = Duration::from_secs(10);

fn listener(verdict: AdmissionVerdict, fallback: Fallback) -> Listener {
    let mut limits = ListenerConfig::default();
    limits.admission =
        Some(Admission::new(4, move |_, _| verdict.clone()).with_peek_timeout(LIMIT));
    limits.fallback = Some(fallback);
    Listener::new(Config::default(), limits).expect("valid listener configuration")
}

fn enter(l: &Listener) -> Entry {
    l.adapter()
        .enter("192.0.2.1:7".parse().unwrap(), None)
        .unwrap()
}

/// How often the halves of a carrier were shut down and dropped.
#[derive(Default)]
struct Closes {
    shutdowns: AtomicUsize,
    reader_drops: AtomicUsize,
    writer_drops: AtomicUsize,
}

impl Closes {
    fn get(&self) -> (usize, usize, usize) {
        (
            self.shutdowns.load(Ordering::SeqCst),
            self.reader_drops.load(Ordering::SeqCst),
            self.writer_drops.load(Ordering::SeqCst),
        )
    }
}

/// A receiving half that reads `data`, then waits, counting its drop.
struct Reader(Vec<u8>, Arc<Closes>);

impl AsyncRead for Reader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.0.is_empty() {
            return Poll::Pending;
        }
        let n = self.0.len().min(buf.remaining());
        buf.put_slice(&self.0[..n]);
        self.0.drain(..n);
        Poll::Ready(Ok(()))
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        self.1.reader_drops.fetch_add(1, Ordering::SeqCst);
    }
}

/// A sending half that records each write as one unit, counting its
/// shutdowns and its drop.
struct Writer(mpsc::UnboundedSender<Vec<u8>>, Arc<Closes>);

impl AsyncWrite for Writer {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        let _ = self.0.send(b.to_vec());
        Poll::Ready(Ok(b.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.1.shutdowns.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.1.writer_drops.fetch_add(1, Ordering::SeqCst);
    }
}

/// A carrier sending `data`, its writes and its closes observed.
fn carrier(data: &[u8]) -> (PipeIo, mpsc::UnboundedReceiver<Vec<u8>>, Arc<Closes>) {
    let closes = Arc::new(Closes::default());
    let (tx, rx) = mpsc::unbounded_channel();
    let io = PipeIo::from_halves(
        Reader(data.to_vec(), closes.clone()),
        Writer(tx, closes.clone()),
    );
    (io, rx, closes)
}

/// A fallback that hands each takeover to the test, as it is.
fn handing() -> (Fallback, mpsc::UnboundedReceiver<Takeover>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let f = Fallback::new(move |t: Takeover| {
        let _ = tx.send(t);
        async {}
    });
    (f, rx)
}

#[tokio::test]
async fn the_fallback_verdicts_value_reaches_the_takeover() {
    let value: zmux::AdmittedValue = Arc::new("service b");
    let (f, mut rx) = handing();
    let l = listener(AdmissionVerdict::fallback().with_value(value.clone()), f);
    let (io, _, _) = carrier(b"GET / HTTP/1.1\r\n");
    assert!(enter(&l).admit(CarrierInfo::new(), io).await.is_none());
    let t = rx.recv().await.unwrap();
    assert!(Arc::ptr_eq(t.value().unwrap(), &value));
    assert_eq!(
        t.value().unwrap().downcast_ref::<&str>(),
        Some(&"service b")
    );
    assert_eq!(l.stats().admission.fallback, 1);
    // A verdict without one gives none.
    let (f, mut rx) = handing();
    let l = listener(AdmissionVerdict::fallback(), f);
    let (io, _, _) = carrier(b"GET / HTTP/1.1\r\n");
    assert!(enter(&l).admit(CarrierInfo::new(), io).await.is_none());
    assert!(rx.recv().await.unwrap().value().is_none());
}

#[tokio::test]
async fn a_detached_carrier_outlives_the_future_and_closes_once() {
    let (tx, rx) = oneshot::channel();
    let tx = std::sync::Mutex::new(Some(tx));
    let f = Fallback::new(move |t: Takeover| {
        let tx = tx.lock().unwrap().take();
        async move {
            t.detach().unwrap();
            // A second detach is no error.
            t.detach().unwrap();
            assert!(t.is_detached());
            let _ = tx.unwrap().send(t.into_pipe().into_stream());
        }
    });
    let l = listener(AdmissionVerdict::fallback(), f);
    let (io, mut written, closes) = carrier(b"hello world");
    let mut e = enter(&l);
    assert!(e.admit(CarrierInfo::new(), io).await.is_none());
    assert!(e.is_detached());
    // The future completed; nothing of the carrier was closed.
    let mut s = rx.await.unwrap();
    assert_eq!(closes.get(), (0, 0, 0));
    let mut got = [0; 11];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello world");
    s.write_all(b"served later").await.unwrap();
    assert_eq!(written.recv().await.unwrap(), b"served later");
    s.shutdown().await.unwrap();
    drop(s);
    assert_eq!(closes.get(), (1, 1, 1));
}

#[tokio::test]
async fn without_a_detach_the_future_closes_what_it_holds() {
    // Nothing taken: dropped with the future, each half once.
    let f = Fallback::new(|_t: Takeover| async {});
    let l = listener(AdmissionVerdict::fallback(), f);
    let (io, _, closes) = carrier(b"data");
    let mut e = enter(&l);
    assert!(e.admit(CarrierInfo::new(), io).await.is_none());
    assert!(!e.is_detached());
    assert_eq!(closes.get(), (0, 1, 1));
    // Shut down and dropped by the host in the call: not again after.
    let f = Fallback::new(|t: Takeover| async move {
        let mut s = t.into_pipe().into_stream();
        s.shutdown().await.unwrap();
    });
    let l = listener(AdmissionVerdict::fallback(), f);
    let (io, _, closes) = carrier(b"data");
    assert!(enter(&l).admit(CarrierInfo::new(), io).await.is_none());
    assert_eq!(closes.get(), (1, 1, 1));
    // A panicking fallback: closed once, the process lives on.
    let f = Fallback::new(|_t: Takeover| async { panic!("the host's bug") });
    let l = listener(AdmissionVerdict::fallback(), f);
    let (io, _, closes) = carrier(b"data");
    assert!(enter(&l).admit(CarrierInfo::new(), io).await.is_none());
    assert_eq!(closes.get(), (0, 1, 1));
}

#[tokio::test]
async fn a_detach_after_the_future_completed_fails() {
    let (f, mut rx) = handing();
    let l = listener(AdmissionVerdict::fallback(), f);
    let (io, _, _) = carrier(b"data");
    let mut e = enter(&l);
    assert!(e.admit(CarrierInfo::new(), io).await.is_none());
    assert!(!e.is_detached());
    let t = rx.recv().await.unwrap();
    assert_eq!(t.detach(), Err(TakeoverReturned));
    assert!(!t.is_detached());
}

/// A message-framed receiving half: one message per read.
struct Messages(Vec<Vec<u8>>);

impl AsyncRead for Messages {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.0.is_empty() {
            return Poll::Ready(Ok(()));
        }
        let m = self.0.remove(0);
        if m.len() > buf.remaining() {
            return Poll::Ready(Err(zmux::adapter::message_too_large()));
        }
        buf.put_slice(&m);
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn a_message_carrier_is_taken_over_by_whole_messages() {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let f = Fallback::new(move |t: Takeover| {
        let tx = tx.clone();
        async move {
            let mut m = t.into_messages().expect("message-framed");
            let mut read = Vec::new();
            while let Some(msg) = m.read_message(64).await.unwrap() {
                read.push(msg);
            }
            m.write_message(b"one").await.unwrap();
            m.write_message(b"two").await.unwrap();
            m.shutdown().await.unwrap();
            let _ = tx.send(read);
        }
    });
    let mut limits = ListenerConfig::default();
    // A peek above 0: the first message is read and decided on.
    limits.admission = Some(Admission::new(1, |_, _| AdmissionVerdict::fallback()));
    limits.fallback = Some(f);
    let l = Listener::new(Config::default(), limits).unwrap();
    let (wtx, mut written) = mpsc::unbounded_channel();
    let closes = Arc::new(Closes::default());
    let io = PipeIo::from_halves(
        Messages(vec![b"first".to_vec(), b"second".to_vec()]),
        Writer(wtx, closes.clone()),
    )
    .records();
    assert!(enter(&l).admit(CarrierInfo::new(), io).await.is_none());
    let read = rx.recv().await.unwrap();
    assert_eq!(read, [b"first".to_vec(), b"second".to_vec()]);
    assert_eq!(written.recv().await.unwrap(), b"one");
    assert_eq!(written.recv().await.unwrap(), b"two");
    assert_eq!(closes.get(), (1, 0, 1));
    // A byte stream has no messages.
    let (f, mut rx) = handing();
    let l = listener(AdmissionVerdict::fallback(), f);
    let (io, _, _) = carrier(b"data");
    assert!(enter(&l).admit(CarrierInfo::new(), io).await.is_none());
    let t = rx.recv().await.unwrap();
    let t = t.into_messages().expect_err("a byte stream");
    assert!(t.into_stream().is_err(), "a pipe, not one stream");
}

#[tokio::test]
async fn the_fallback_runs_on_when_its_entry_is_cancelled() {
    let (go_tx, go_rx) = oneshot::channel::<()>();
    let (started_tx, started_rx) = oneshot::channel();
    let (done_tx, done_rx) = oneshot::channel();
    let slots = std::sync::Mutex::new(Some((go_rx, started_tx, done_tx)));
    let f = Fallback::new(move |t: Takeover| {
        let (go, started, done) = slots.lock().unwrap().take().unwrap();
        async move {
            let _ = started.send(());
            let _ = go.await;
            let mut s = t.into_pipe().into_stream();
            let mut b = [0; 4];
            s.read_exact(&mut b).await.unwrap();
            let _ = done.send(b);
        }
    });
    let l = listener(AdmissionVerdict::fallback(), f);
    let (io, _, closes) = carrier(b"data");
    let mut e = enter(&l);
    let admitting = tokio::spawn(async move { e.admit(CarrierInfo::new(), io).await.is_none() });
    started_rx.await.unwrap();
    // The entry's task ends; the fallback's future does not.
    admitting.abort();
    assert!(admitting.await.unwrap_err().is_cancelled());
    assert_eq!(closes.get(), (0, 0, 0));
    go_tx.send(()).unwrap();
    let got = tokio::time::timeout(LIMIT, done_rx).await.unwrap().unwrap();
    assert_eq!(&got, b"data");
    assert_eq!(closes.get(), (0, 1, 1));
}

#[tokio::test]
async fn a_tcp_takeover_keeps_its_stream_type() {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let client = tokio::spawn(async move {
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(b"GET /").await.unwrap();
        let mut got = Vec::new();
        c.read_to_end(&mut got).await.unwrap();
        got
    });
    let (conn, _) = tcp.accept().await.unwrap();
    let (f, mut rx) = handing();
    let l = listener(AdmissionVerdict::fallback(), f);
    let io = AdmitIo::stream(conn, PipeIo::from_tcp);
    assert!(enter(&l).admit(CarrierInfo::new(), io).await.is_none());
    let t = rx.recv().await.unwrap();
    // Its own type before it is taken, and after.
    assert!(t.stream::<tokio::net::TcpStream>().is_some());
    let mut s = t.into_stream().expect("one stream");
    let any: &dyn std::any::Any = &**s.get_ref();
    assert!(any.downcast_ref::<tokio::net::TcpStream>().is_some());
    let mut b = [0; 5];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"GET /");
    s.write_all(b"bye").await.unwrap();
    drop(s);
    assert_eq!(client.await.unwrap(), b"bye");
}
