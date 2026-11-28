//! Optional carrier capabilities passed through to the core: the write
//! overhead a shaper factory sees and the carrier's connection counters.

#![allow(
    clippy::many_single_char_names,
    reason = "short conventional names in scenario code"
)]
#![allow(
    clippy::large_stack_arrays,
    reason = "scenario code: buffers and futures stay on the stack on purpose, long scripted scenarios read top to bottom"
)]

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
async fn pipe_stats_start_native_sampling_on_explicit_read() {
    use zmux::{CarrierCounts, CarrierSource, PipeDirection};

    let (a, b) = tokio::io::duplex(1 << 16);
    let calls = Arc::new(AtomicU64::new(0));
    let count = calls.clone();
    let owner = Arc::new(());
    let io = PipeIo::new(a)
        .with_carrier_conn(zmux::CarrierConnId::new(&owner))
        .with_carrier_counters(CarrierSource::Quinn, move || {
            Some(CarrierCounts::Quic {
                packets_sent: count.fetch_add(1, Relaxed),
                packets_lost: 0,
            })
        });
    let (client, server) = tokio::join!(
        Session::connect(io, Config::default()),
        Session::accept(PipeIo::new(b), Config::default()),
    );
    let client = client.unwrap();
    let server = server.unwrap();
    assert_eq!(calls.load(Relaxed), 0);
    assert!(server.pipe_stats().remove(0).carrier_sample.is_none());

    let pipe = client.pipes().remove(0);
    assert!(pipe.stats().unwrap().carrier_sample.is_none());
    let initial = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(sample) = pipe.stats().unwrap().carrier_sample {
                break sample;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the requested native sample was never published");
    assert_eq!(initial.direction, PipeDirection::Out);
    assert_eq!(initial.generation, 0);
    assert_eq!(
        initial.counts,
        Some(CarrierCounts::Quic {
            packets_sent: 0,
            packets_lost: 0,
        })
    );
}

#[tokio::test]
async fn receive_only_pipes_never_register_or_query() {
    use zmux::{
        CarrierSource, Listener, ListenerConfig, PipeAuth, PipeDirection, PipeHint, PipeOptions,
    };

    tokio::time::timeout(LIMIT, async {
        let mut cfg = Config::default();
        cfg.session_policy.limits.steady_attachments = 4;
        cfg.pipe_auth = PipeAuth::psk([7; 32]).with_end_to_end();
        let listener = Listener::new(cfg.clone(), ListenerConfig::default()).unwrap();
        let (a, b) = tokio::io::duplex(65536);
        let (client, setup) = tokio::join!(
            Session::connect(PipeIo::new(a), cfg),
            listener.handle_pipe(PipeIo::new(b), PipeHint::default()),
        );
        setup.unwrap();
        let client = client.unwrap();
        let server = listener.accept().await.unwrap();
        for direction in [PipeDirection::In, PipeDirection::Out] {
            let receive_calls = Arc::new(AtomicU64::new(0));
            let count = receive_calls.clone();
            let owner = Arc::new(());
            let identify = |io| PipeIo::new(io).with_carrier_conn(zmux::CarrierConnId::new(&owner));
            let (a, b) = tokio::io::duplex(65536);
            let (mut near, mut far) = (identify(a), identify(b));
            let query = move || {
                count.fetch_add(1, Relaxed);
                None
            };
            if direction == PipeDirection::In {
                near = near.with_carrier_counters(CarrierSource::Quinn, query);
            } else {
                far = far.with_carrier_counters(CarrierSource::Quinn, query);
            }
            let mut options = PipeOptions::default();
            options.direction = direction;
            let (added, setup) = tokio::join!(
                client.test_join(near, options),
                listener.handle_pipe(far, PipeHint::default()),
            );
            setup.unwrap();
            let added = added.unwrap();
            let receive = if direction == PipeDirection::In {
                added
            } else {
                server.pipe(added.id()).unwrap()
            };
            let stats = receive.stats().unwrap();
            assert!(stats.outbound.is_none());
            assert!(stats.carrier_sample.is_none());
            assert_eq!(receive_calls.load(Relaxed), 0);
        }
    })
    .await
    .unwrap();
}
