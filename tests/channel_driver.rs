//! The tokio driver's datagram channels over an in-memory carrier: a
//! channel that is a pair of in-process queues, so that what the driver
//! sends and how it hands received datagrams to the session can be seen.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use zmux::adapter::{ChannelDemux, ChannelReceiver, ChannelRegistration, DatagramChannel};
use zmux::{Config, PipeIo, Session};

/// One end's channel: what it sends goes to the peer's demux.
struct Fake {
    id: u64,
    own: ChannelDemux,
    peer: Arc<Mutex<Option<ChannelDemux>>>,
}

impl DatagramChannel for Fake {
    fn channel_id(&self) -> Option<u64> {
        Some(self.id)
    }

    fn max_datagram_size(&self) -> usize {
        1200
    }

    fn send(&self, d: Bytes) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        let peer = self.peer.lock().unwrap().clone();
        Box::pin(async move {
            if let Some(p) = peer {
                p.deliver(d);
            }
            Ok(())
        })
    }

    fn receive(&self, r: ChannelReceiver) -> ChannelRegistration {
        self.own.register(self.id, r)
    }
}

async fn pair() -> (Session, Session, ChannelDemux) {
    let (a, b) = tokio::io::duplex(1 << 20);
    let (da, db) = (ChannelDemux::new(), ChannelDemux::new());
    let ca = Fake {
        id: 0,
        own: da.clone(),
        peer: Arc::new(Mutex::new(Some(db.clone()))),
    };
    let cb = Fake {
        id: 0,
        own: db.clone(),
        peer: Arc::new(Mutex::new(Some(da))),
    };
    let mut c = Config::default();
    c.enable_datagrams = true;
    let (x, y) = tokio::join!(
        Session::connect(
            PipeIo::new(a).with_datagram_channel(Arc::new(ca)),
            c.clone()
        ),
        Session::accept(PipeIo::new(b).with_datagram_channel(Arc::new(cb)), c)
    );
    (x.unwrap(), y.unwrap(), db)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagrams_go_on_the_channel_both_ways() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (a, b, _) = pair().await;
        for i in 0..10u8 {
            a.send_datagram(Bytes::from(vec![i; 10])).unwrap();
            assert_eq!(b.read_datagram().await.unwrap()[..], [i; 10]);
            b.send_datagram(Bytes::from(vec![i; 20])).unwrap();
            assert_eq!(a.read_datagram().await.unwrap()[..], [i; 20]);
        }
        assert_eq!(a.stats().datagrams_sent_channel, 10);
        assert_eq!(b.stats().datagrams_received_channel, 10);
    })
    .await
    .unwrap();
}

/// A carrier's receive loop hands datagrams over without waiting for the
/// session: a burst beyond the pipe's queue is dropped and counted rather
/// than processed in the loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_beyond_the_pipe_queue_is_dropped_and_counted() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (_a, b, db) = pair().await;
        let frame = zmux::proto::frame::channel::encode(Some(0), &[0, 7]);
        // From a thread that is no task: nothing runs meanwhile.
        let n = std::thread::spawn(move || {
            (0..1000)
                .filter(|_| db.deliver(Bytes::from(frame.clone())))
                .count()
        })
        .join()
        .unwrap();
        assert_eq!(n, 1000, "every one routed");
        let mut got = 0;
        while let Ok(Ok(_)) =
            tokio::time::timeout(Duration::from_millis(500), b.read_datagram()).await
        {
            got += 1;
        }
        let s = b.stats();
        assert!(got < 1000, "{got}");
        assert_eq!(s.datagrams_dropped_recv + got, 1000, "{s:?}");
    })
    .await
    .unwrap();
}
