//! The tokio driver's datagram channels over an in-memory carrier: a
//! channel that is a pair of in-process queues, so that what the driver
//! sends and how it hands received datagrams to the session can be seen.

#![allow(
    clippy::many_single_char_names,
    reason = "short conventional names in scenario code"
)]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use zmux::adapter::{
    ChannelDemux, ChannelReceiver, ChannelRegistration, DatagramChannel, DatagramChannelPrefix,
};
use zmux::{Config, PipeIo, Session};

/// One end's channel: what it sends goes to the peer's demux.
struct Fake {
    id: u64,
    own: ChannelDemux,
    peer: Arc<Mutex<Option<ChannelDemux>>>,
}

impl DatagramChannel for Fake {
    fn channel_prefix(&self) -> DatagramChannelPrefix {
        DatagramChannelPrefix::Pipe(self.id)
    }

    fn datagram_capacity(&self) -> (usize, usize) {
        (1200, 1200)
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

struct Completion(tokio::sync::mpsc::UnboundedSender<()>);

impl zmux::shaping::Shaper for Completion {
    fn capabilities(&self) -> zmux::shaping::Caps {
        zmux::shaping::Caps::OUTBOUND
    }

    fn on_event(&mut self, event: &zmux::shaping::Event, _: &mut zmux::shaping::Effects) {
        if event.kind == zmux::shaping::EventKind::Outbound
            && event.unit == zmux::shaping::UnitKind::NativeDatagram
        {
            let _ = self.0.send(());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagrams_go_on_the_channel_both_ways() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let (a, b, _) = pair().await;
        let (completed, mut results) = tokio::sync::mpsc::unbounded_channel();
        a.set_shaper(
            Some(Arc::new(move |_: &zmux::shaping::ShapedPipe| {
                Some(Box::new(Completion(completed.clone())) as Box<dyn zmux::shaping::Shaper>)
            })),
            None,
        )
        .unwrap();
        for i in 0..10u8 {
            a.send_datagram(Bytes::from(vec![i; 10])).unwrap();
            assert_eq!(b.read_datagram().await.unwrap()[..], [i; 10]);
            b.send_datagram(Bytes::from(vec![i; 20])).unwrap();
            assert_eq!(a.read_datagram().await.unwrap()[..], [i; 20]);
        }
        for _ in 0..10 {
            results.recv().await.expect("native completion");
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
#[tokio::test]
async fn a_burst_beyond_the_pipe_queue_is_dropped_and_counted() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (_a, b, db) = pair().await;
        // The current-thread executor cannot poll the receive task until
        // the full burst has been put into the inbox.
        for sequence in 0..1000 {
            use zmux::proto::frame::{DatagramPrefix, channel};
            use zmux::proto::payload::Flow;
            let mut data = [0; 24];
            let n = DatagramPrefix::Sequenced {
                sequence,
                flow: Flow::Session,
            }
            .encode(&mut data)
            .unwrap();
            assert!(db.deliver(Bytes::from(channel::encode(Some(0), &data[..n]))));
        }
        let _ = b.read_datagram().await.unwrap();
        let stats = b.stats();
        assert_eq!(stats.datagrams_received_channel, 256);
        assert_eq!(stats.datagrams_dropped_recv, 1000 - 128);
    })
    .await
    .unwrap();
}

type ScriptedSend = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

struct ScriptedChannel {
    capacity: Box<dyn Fn() + Send + Sync>,
    send: Box<dyn Fn(Bytes) -> ScriptedSend + Send + Sync>,
    stopped: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
}

impl DatagramChannel for ScriptedChannel {
    fn channel_prefix(&self) -> DatagramChannelPrefix {
        DatagramChannelPrefix::None
    }

    fn datagram_capacity(&self) -> (usize, usize) {
        (self.capacity)();
        (1200, 1200)
    }

    fn send(&self, data: Bytes) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + '_>> {
        (self.send)(data)
    }

    fn receive(&self, _: ChannelReceiver) -> ChannelRegistration {
        let stopped = self.stopped.lock().unwrap().take();
        ChannelRegistration::new(move || {
            if let Some(stopped) = stopped {
                let _ = stopped.send(());
            }
        })
    }
}

async fn scripted_pair(channel: ScriptedChannel) -> (Session, Session) {
    let (a, b) = tokio::io::duplex(1 << 20);
    let peer = ScriptedChannel {
        capacity: Box::new(|| {}),
        send: Box::new(|_| Box::pin(async { Ok(()) })),
        stopped: Mutex::new(None),
    };
    let mut config = Config::default();
    config.enable_datagrams = true;
    let (a, b) = tokio::join!(
        Session::connect(
            PipeIo::new(a).with_datagram_channel(Arc::new(channel)),
            config.clone()
        ),
        Session::accept(PipeIo::new(b).with_datagram_channel(Arc::new(peer)), config)
    );
    (a.unwrap(), b.unwrap())
}

#[tokio::test]
async fn g4_a_pending_native_receipt_does_not_hold_the_next_send() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (first, started) = tokio::sync::oneshot::channel();
        let first = Mutex::new(Some(first));
        let (release, held) = tokio::sync::oneshot::channel();
        let held = Mutex::new(Some(held));
        let (completed, mut results) = tokio::sync::mpsc::unbounded_channel();
        let (client, _peer) = scripted_pair(ScriptedChannel {
            capacity: Box::new(|| {}),
            send: Box::new(move |data| {
                if data.ends_with(b"first") {
                    let first = first.lock().unwrap().take().unwrap();
                    let held = held.lock().unwrap().take().unwrap();
                    Box::pin(async move {
                        first.send(()).unwrap();
                        held.await.unwrap();
                        Ok(())
                    })
                } else {
                    assert!(data.ends_with(b"second"));
                    Box::pin(async { Ok(()) })
                }
            }),
            stopped: Mutex::new(None),
        })
        .await;
        client
            .set_shaper(
                Some(Arc::new(move |_: &zmux::shaping::ShapedPipe| {
                    Some(Box::new(Completion(completed.clone())) as Box<dyn zmux::shaping::Shaper>)
                })),
                None,
            )
            .unwrap();
        client.send_datagram(Bytes::from_static(b"first")).unwrap();
        started.await.unwrap();
        client.send_datagram(Bytes::from_static(b"second")).unwrap();
        results.recv().await.unwrap();
        assert_eq!(client.datagram_stats().native.originals_accepted, 1);
        release.send(()).unwrap();
        results.recv().await.unwrap();
        assert_eq!(client.datagram_stats().native.originals_accepted, 2);
    })
    .await
    .unwrap();
}

struct NativePad;

impl zmux::shaping::Shaper for NativePad {
    fn capabilities(&self) -> zmux::shaping::Caps {
        zmux::shaping::Caps::DATAGRAM_PLAN
    }

    fn plan_datagram(
        &mut self,
        _: &zmux::shaping::DatagramView,
        plan: &mut zmux::shaping::DatagramPlan,
    ) {
        plan.unit = zmux::shaping::UnitPlan::new(0, 0, 16);
    }
}

#[tokio::test]
async fn g4_native_receipts_are_settled_on_adapter_failure_and_shutdown() {
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Clone, Copy)]
    enum End {
        CapacityPanic,
        SendPanic,
        Shutdown,
    }

    tokio::time::timeout(Duration::from_secs(5), async {
        for end in [End::CapacityPanic, End::SendPanic, End::Shutdown] {
            let (stopped, unregistered) = tokio::sync::oneshot::channel();
            let (started, submitted) = tokio::sync::oneshot::channel();
            let started = Mutex::new(Some(started));
            let armed = Arc::new(AtomicBool::new(false));
            let fault = armed.clone();
            let (client, _peer) = scripted_pair(ScriptedChannel {
                capacity: Box::new(move || {
                    assert!(!fault.load(Ordering::Relaxed), "capacity query failed");
                }),
                send: Box::new(move |_| {
                    let started = started.lock().unwrap().take().unwrap();
                    let armed = armed.clone();
                    Box::pin(async move {
                        started.send(()).unwrap();
                        match end {
                            End::CapacityPanic => {
                                armed.store(true, Ordering::Relaxed);
                                Ok(())
                            }
                            End::SendPanic => panic!("carrier submission failed after it began"),
                            End::Shutdown => std::future::pending().await,
                        }
                    })
                }),
                stopped: Mutex::new(Some(stopped)),
            })
            .await;
            client
                .set_shaper(
                    Some(Arc::new(|_: &zmux::shaping::ShapedPipe| {
                        Some(Box::new(NativePad) as Box<dyn zmux::shaping::Shaper>)
                    })),
                    None,
                )
                .unwrap();
            let before = client.shaping_stats().ledger;
            client
                .send_datagram(Bytes::from_static(b"native receipt"))
                .unwrap();
            submitted.await.unwrap();
            if matches!(end, End::Shutdown) {
                client.abort(zmux::VarInt::ZERO, b"");
            }
            unregistered.await.unwrap();
            let stats = client.datagram_stats().native;
            let ledger = client.shaping_stats().ledger;
            assert_eq!(stats.originals, 1);
            match end {
                End::CapacityPanic => {
                    assert_eq!(stats.originals_accepted, 1);
                    assert_eq!(ledger.measured_bytes - before.measured_bytes, 16);
                    assert_eq!(ledger.policy.unwrap().reserved_bytes, 0);
                }
                End::SendPanic => {
                    assert_eq!(stats.originals_failed, 1);
                    assert_eq!(ledger.measured_bytes, before.measured_bytes);
                    assert_eq!(ledger.policy.unwrap().reserved_bytes, 16);
                }
                End::Shutdown => {
                    assert_eq!(stats.originals_failed, 1);
                    assert_eq!(ledger.measured_bytes, before.measured_bytes);
                    assert_eq!(ledger.policy.unwrap().reserved_bytes, 0);
                }
            }
        }
    })
    .await
    .unwrap();
}

#[test]
fn g4_unregister_panic_allows_carrier_cleanup() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct CarrierLease(Arc<AtomicBool>);
    impl Drop for CarrierLease {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let released = Arc::new(AtomicBool::new(false));
    let release = released.clone();
    let result = std::panic::catch_unwind(move || {
        let lease = CarrierLease(release);
        let registration = ChannelRegistration::new(|| panic!("unregister failed"));
        drop(registration);
        drop(lease);
    });
    assert!(result.is_ok());
    assert!(released.load(Ordering::Relaxed));
}
