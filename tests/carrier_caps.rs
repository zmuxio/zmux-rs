//! Optional carrier capabilities passed through to the core: the write
//! overhead a shaper factory sees, and the carrier's retransmission count
//! behind a pipe's loss statistics.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zmux::shaping::{Factory, RecordPlan, RecordView, ShapedPipe, Shaper};
use zmux::{Config, PipeIo, Session};

const LIMIT: Duration = Duration::from_secs(10);

/// Records what it sees; plans nothing.
struct Seen(Arc<Mutex<Vec<bool>>>);

impl Shaper for Seen {
    fn capabilities(&self) -> zmux::shaping::Caps {
        zmux::shaping::Caps::PLAN
    }
    fn plan(&mut self, v: &RecordView, _: &mut RecordPlan) {
        self.0.lock().unwrap().push(v.write_start);
    }
}

#[tokio::test]
async fn the_write_overhead_reaches_the_shaper_factory() {
    tokio::time::timeout(LIMIT, async {
        let pipes = Arc::new(Mutex::new(Vec::new()));
        let starts = Arc::new(Mutex::new(Vec::new()));
        let (p, s) = (pipes.clone(), starts.clone());
        let factory: Arc<dyn Factory> = Arc::new(move |pipe: &ShapedPipe| {
            p.lock().unwrap().push(pipe.write_overhead);
            Some(Box::new(Seen(s.clone())) as Box<dyn Shaper>)
        });
        let mut config = Config::default();
        config.shaper = Some(factory);
        let (a, b) = tokio::io::duplex(1 << 16);
        let server = tokio::spawn(Session::accept(PipeIo::new(b), Config::default()));
        let client = Session::connect(PipeIo::new(a).with_write_overhead(29), config)
            .await
            .unwrap();
        let server = server.await.unwrap().unwrap();
        let (mut send, _recv) = client.open_bi().await.unwrap();
        send.write_all(&[7; 200_000]).await.unwrap();
        send.finish().unwrap();
        let (_s, mut r) = server.accept_bi().await.unwrap();
        assert_eq!(r.read_to_end(1 << 20).await.unwrap().len(), 200_000);
        assert_eq!(*pipes.lock().unwrap(), vec![29]);
        let starts = starts.lock().unwrap();
        // Records in batches: the first of each starts a write.
        assert!(starts[0]);
        assert!(starts.iter().any(|s| !s), "{starts:?}");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn bytes_retransmitted_come_from_the_carrier() {
    tokio::time::timeout(LIMIT, async {
        let (a, b) = tokio::io::duplex(1 << 16);
        let server = tokio::spawn(Session::accept(PipeIo::new(b), Config::default()));
        let retrans = Arc::new(AtomicU64::new(0));
        let r = retrans.clone();
        let client = Session::connect(
            PipeIo::new(a).with_retransmitted(move || Some(r.load(Relaxed))),
            Config::default(),
        )
        .await
        .unwrap();
        let server = server.await.unwrap().unwrap();
        // The server's carrier reports none.
        assert_eq!(server.pipes()[0].stats().unwrap().bytes_retransmitted, None);
        let stats = || client.pipes()[0].stats().unwrap();
        // Queried at most once a second, on the session's write path.
        retrans.store(1000, Relaxed);
        let mut seen = None;
        for _ in 0..40 {
            client.send_datagram(bytes::Bytes::from_static(b"x")).ok();
            let (mut send, _r) = client.open_bi().await.unwrap();
            send.write_all(&[1; 10_000]).await.unwrap();
            send.finish().unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
            let s = stats();
            if s.loss_rate.is_some() {
                seen = Some(s);
                break;
            }
        }
        let s = seen.expect("a loss-rate sample within 4 s");
        assert_eq!(s.bytes_retransmitted, Some(1000));
        assert!(s.loss_rate.unwrap() >= 0.0);
        // A live pipe has lost nothing.
        assert!(s.bytes_lost.is_none_or(|n| n == 0));
        drop(server);
    })
    .await
    .unwrap();
}
