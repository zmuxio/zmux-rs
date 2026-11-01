//! The carrier kind: carried from `PipeIo::with_carrier` to the shaper
//! factory (`ShapedPipe::carrier`), pipe statistics and pipe events, on
//! both ends and for joined pipes; `Config::shaper` shapes an accepted
//! session from its first record.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use zmux::shaping::{Caps, Factory, RecordPlan, RecordView, ShapedPipe, Shaper};
use zmux::{
    Candidate, CarrierKind, Config, Listener, ListenerConfig, PipeAuth, PipeHint, PipeId, PipeIo,
    PipeOptions, Session, SessionEvent,
};

/// Records every pipe it is asked for and counts the records it plans.
#[derive(Default)]
struct Recording {
    seen: Mutex<Vec<ShapedPipe>>,
    planned: Arc<Mutex<HashMap<u64, u64>>>,
}

struct Counting {
    planned: Arc<Mutex<HashMap<u64, u64>>>,
}

impl Shaper for Counting {
    fn capabilities(&self) -> Caps {
        Caps::PLAN
    }

    fn plan(&mut self, view: &RecordView, _: &mut RecordPlan) {
        *self
            .planned
            .lock()
            .unwrap()
            .entry(view.pipe.get())
            .or_default() += 1;
    }
}

impl Factory for Recording {
    fn shaper(&self, pipe: &ShapedPipe) -> Option<Box<dyn Shaper>> {
        self.seen.lock().unwrap().push(*pipe);
        Some(Box::new(Counting {
            planned: self.planned.clone(),
        }))
    }
}

impl Recording {
    fn kind_of(&self, id: PipeId) -> Option<Option<CarrierKind>> {
        let seen = self.seen.lock().unwrap();
        seen.iter().find(|p| p.id == id).map(|p| p.carrier)
    }

    fn planned(&self, id: PipeId) -> u64 {
        self.planned
            .lock()
            .unwrap()
            .get(&id.get())
            .copied()
            .unwrap_or(0)
    }
}

fn config(shaper: Option<Arc<Recording>>) -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"carrier-kind-psk-0123456789abcde");
    c.shaper = shaper.map(|s| s as Arc<dyn Factory>);
    c
}

/// A TCP port of `listener` whose carriers it labels `kind`.
async fn port(listener: &Listener, kind: Option<CarrierKind>) -> std::net::SocketAddr {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let l = listener.clone();
    tokio::spawn(async move {
        while let Ok((c, _)) = tcp.accept().await {
            let io = PipeIo::tcp(c);
            let io = match kind {
                Some(k) => io.with_carrier(k),
                None => io,
            };
            let l = l.clone();
            tokio::spawn(async move { l.handle_pipe(io, PipeHint::default()).await });
        }
    });
    addr
}

async fn exchange(session: &Session) {
    let (mut send, mut recv) = session.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let got = recv.read_to_end(64).await.unwrap();
    assert_eq!(got, b"ping");
}

fn echo(server: Session) {
    tokio::spawn(async move {
        while let Ok((mut send, mut recv)) = server.accept_bi().await {
            let got = recv.read_to_end(64).await.unwrap();
            send.write_all(&got).await.unwrap();
            send.finish().unwrap();
        }
    });
}

/// The listener's configured factory shapes an accepted session from its
/// first record, and both ends' factories see each pipe's own kind, a
/// joined pipe's included; statistics and events carry it too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kinds_reach_the_factories_of_both_ends() {
    let server_shaper = Arc::new(Recording::default());
    let client_shaper = Arc::new(Recording::default());
    let listener = Listener::new(
        config(Some(server_shaper.clone())),
        ListenerConfig::default(),
    );
    let ws = port(&listener, Some(CarrierKind::WebSocket)).await;
    let quic = port(&listener, Some(CarrierKind::Quic)).await;

    let first =
        PipeIo::tcp(TcpStream::connect(ws).await.unwrap()).with_carrier(CarrierKind::WebSocket);
    assert_eq!(first.carrier(), Some(CarrierKind::WebSocket));
    let client = Session::connect(first, config(Some(client_shaper.clone())))
        .await
        .unwrap();
    let server = listener.accept().await.unwrap();
    let server_events = server.clone();
    echo(server.clone());
    exchange(&client).await;

    let zero = PipeId::new(0);
    // Every record the server sent on pipe 0 was planned by its shaper:
    // installed before the first one.
    let sent = server.pipe(zero).unwrap().stats().unwrap().records_sent;
    assert!(sent > 0);
    assert_eq!(server_shaper.planned(zero), sent);
    assert_eq!(
        server_shaper.kind_of(zero),
        Some(Some(CarrierKind::WebSocket))
    );
    assert_eq!(
        client_shaper.kind_of(zero),
        Some(Some(CarrierKind::WebSocket))
    );

    let joined = client
        .add_pipe(
            PipeIo::tcp(TcpStream::connect(quic).await.unwrap()).with_carrier(CarrierKind::Quic),
            PipeOptions::new(),
        )
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), joined.joined())
        .await
        .expect("joined in time")
        .unwrap();
    let id = joined.id();
    assert_eq!(joined.stats().unwrap().carrier, Some(CarrierKind::Quic));
    common::eventually(10, "server sees the join", || server.pipe(id).is_some()).await;
    let theirs = server.pipe(id).unwrap();
    assert_eq!(theirs.stats().unwrap().carrier, Some(CarrierKind::Quic));
    assert_eq!(
        server.pipe(zero).unwrap().stats().unwrap().carrier,
        Some(CarrierKind::WebSocket)
    );
    // Records go both ways on the joined pipe until both shapers saw it.
    common::eventually(10, "both ends shape the joined pipe", || {
        server_shaper.kind_of(id).is_some() && client_shaper.kind_of(id).is_some()
    })
    .await;
    assert_eq!(server_shaper.kind_of(id), Some(Some(CarrierKind::Quic)));
    assert_eq!(client_shaper.kind_of(id), Some(Some(CarrierKind::Quic)));

    // A pipe event names the pipe's kind.
    joined.close().unwrap();
    let kind = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match server_events.next_event().await {
                Some(SessionEvent::PipeState { pipe, carrier, .. }) if pipe == id => {
                    break carrier;
                }
                Some(_) => {}
                None => panic!("no event of the joined pipe"),
            }
        }
    })
    .await
    .expect("an event in time");
    assert_eq!(kind, Some(CarrierKind::Quic));
    client.close(0u32.into(), b"");
    listener.close();
}

/// A raw TCP carrier has no kind, on either end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn raw_tcp_has_no_kind() {
    let server_shaper = Arc::new(Recording::default());
    let client_shaper = Arc::new(Recording::default());
    let listener = Listener::new(
        config(Some(server_shaper.clone())),
        ListenerConfig::default(),
    );
    let addr = port(&listener, None).await;
    let client = Session::connect(
        PipeIo::tcp(TcpStream::connect(addr).await.unwrap()),
        config(Some(client_shaper.clone())),
    )
    .await
    .unwrap();
    let server = listener.accept().await.unwrap();
    echo(server.clone());
    exchange(&client).await;
    let zero = PipeId::new(0);
    assert_eq!(server_shaper.kind_of(zero), Some(None));
    assert_eq!(client_shaper.kind_of(zero), Some(None));
    assert_eq!(server.pipe(zero).unwrap().stats().unwrap().carrier, None);
    client.close(0u32.into(), b"");
    listener.close();
}

/// A mode candidate's carriers have its kind, whatever the dial set: a
/// pipe a mode upgrade adds is shaped as its new kind.
#[tokio::test]
async fn candidates_label_their_carriers() {
    let c = Candidate::new(CarrierKind::Http3, || async {
        let (a, _b) = tokio::io::duplex(64);
        Ok(PipeIo::new(a).with_carrier(CarrierKind::Streaming))
    });
    assert_eq!(c.dial().await.unwrap().carrier(), Some(CarrierKind::Http3));
}
