//! `EarlyData::hold_first_flight`: nothing is written before the release,
//! then the parameters and the streams written leave in one carrier write.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use zmux::{Config, EarlyData, PipeIo, Session};

/// A byte stream recording each write call, a vectored one as one.
struct Log {
    io: DuplexStream,
    writes: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl AsyncRead for Log {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl AsyncWrite for Log {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.io).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = r {
            self.writes.lock().unwrap().push(buf[..n].to_vec());
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

fn held() -> Config {
    let mut c = Config::default();
    c.early_data = EarlyData::for_zmux_peer().with_hold_first_flight(true);
    c
}

async fn pair(
    cfg: Config,
) -> (
    Session,
    tokio::task::JoinHandle<Session>,
    Arc<Mutex<Vec<Vec<u8>>>>,
) {
    let (a, b) = tokio::io::duplex(1 << 20);
    let writes = Arc::new(Mutex::new(Vec::new()));
    let log = Log {
        io: a,
        writes: writes.clone(),
    };
    let server = tokio::spawn(async move {
        Session::accept(PipeIo::new(b), Config::default())
            .await
            .unwrap()
    });
    let client = Session::connect(PipeIo::new(log), cfg).await.unwrap();
    (client, server, writes)
}

#[tokio::test]
async fn nothing_before_the_release_then_one_write() {
    let (c, server, writes) = pair(held()).await;
    let (mut send, mut recv) = c.open_bi().await.unwrap();
    send.write_all(b"HELLO, first flight").await.unwrap();
    // The flush of a held flight returns at once.
    tokio::time::timeout(Duration::from_secs(1), send.flush())
        .await
        .expect("flush waits while held")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(writes.lock().unwrap().is_empty());
    assert_eq!(c.stats().first_flight_timeouts, 0);
    c.release_first_flight();
    c.release_first_flight();
    let s = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    let first = writes.lock().unwrap()[0].clone();
    assert!(
        first.windows(19).any(|w| w == b"HELLO, first flight"),
        "first write {first:02x?}"
    );
    let (mut ss, mut sr) = s.accept_bi().await.unwrap();
    let mut got = [0; 19];
    sr.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"HELLO, first flight");
    ss.write_all(b"ok").await.unwrap();
    ss.finish().unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(16).await.unwrap(), b"ok");
    assert_eq!(c.stats().first_flight_timeouts, 0);
}

#[tokio::test]
async fn the_handshake_timeout_releases_it() {
    let mut cfg = held();
    cfg.handshake_timeout = Some(Duration::from_millis(200));
    let (c, server, writes) = pair(cfg).await;
    let s = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert!(!writes.lock().unwrap().is_empty());
    assert_eq!(c.stats().first_flight_timeouts, 1);
    let (mut send, _recv) = c.open_bi().await.unwrap();
    send.write_all(b"x").await.unwrap();
    send.finish().unwrap();
    let (_ss, mut sr) = s.accept_bi().await.unwrap();
    assert_eq!(sr.read_to_end(16).await.unwrap(), b"x");
}

#[tokio::test]
async fn a_close_does_not_wait_for_the_release() {
    let (c, server, writes) = pair(held()).await;
    c.abort(9u32.into(), b"bye");
    tokio::time::timeout(Duration::from_secs(5), c.closing())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!writes.lock().unwrap().is_empty());
    server.abort();
}

#[test]
fn it_needs_client_early_data() {
    let mut cfg = Config::default();
    cfg.early_data = EarlyData::default().with_hold_first_flight(true);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let (a, _b) = tokio::io::duplex(64);
        assert!(Session::connect(PipeIo::new(a), cfg).await.is_err());
        let (a, _b) = tokio::io::duplex(64);
        assert!(Session::accept(PipeIo::new(a), held()).await.is_err());
    });
}
