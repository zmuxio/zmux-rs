//! Host hooks that answer later, and the observing hooks' subscription.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use zmux::{Config, HostEvent, Listener, ListenerConfig, PipeIo, SessionConfigFn, TraceRecord};

const LIMIT: Duration = Duration::from_secs(10);

async fn serve(config: Config, limits: ListenerConfig) -> (Listener, String) {
    let listener = Listener::new(config, limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap().to_string();
    tokio::spawn(listener.clone().serve(tcp));
    (listener, addr)
}

#[tokio::test]
async fn a_later_session_config_is_awaited() {
    let asked = Arc::new(AtomicUsize::new(0));
    let mut limits = ListenerConfig::default();
    let a = asked.clone();
    limits.session_config = Some(SessionConfigFn::new_async(move |c| {
        a.fetch_add(1, Ordering::Relaxed);
        async move {
            assert!(c.peer.is_some());
            tokio::time::sleep(Duration::from_millis(20)).await;
            Ok(None)
        }
    }));
    let (listener, addr) = serve(Config::default(), limits).await;
    let tcp = TcpStream::connect(&addr).await.unwrap();
    let session = tokio::time::timeout(
        LIMIT,
        zmux::Session::connect(PipeIo::from_tcp(tcp), Config::default()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        tokio::time::timeout(LIMIT, listener.accept())
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(asked.load(Ordering::Relaxed), 1);
    drop(session);
    listener.close();
}

#[tokio::test]
async fn a_session_config_past_the_handshake_deadline_rejects() {
    let mut limits = ListenerConfig::default();
    limits.handshake_timeout = Duration::from_millis(100);
    limits.session_config = Some(SessionConfigFn::new_async(|_| std::future::pending()));
    let mut server = Config::default();
    server.handshake_timeout = Some(Duration::from_millis(100));
    let (listener, addr) = serve(server, limits).await;
    let tcp = TcpStream::connect(&addr).await.unwrap();
    let mut client = Config::default();
    client.handshake_timeout = Some(Duration::from_secs(5));
    let r = tokio::time::timeout(LIMIT, zmux::Session::connect(PipeIo::from_tcp(tcp), client))
        .await
        .unwrap();
    assert!(r.is_err());
    tokio::time::timeout(LIMIT, async {
        while listener.stats().rejected == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    listener.close();
}

#[tokio::test]
async fn events_report_a_session_from_start_to_end() {
    let mut client = Config::default();
    // Two subscriptions: each reads every event.
    let first = client.events(64);
    let events = client.events(64);
    let (listener, addr) = serve(Config::default(), ListenerConfig::default()).await;
    let tcp = TcpStream::connect(&addr).await.unwrap();
    let session = zmux::Session::connect(PipeIo::from_tcp(tcp), client.clone())
        .await
        .unwrap();
    let tcp = TcpStream::connect(&addr).await.unwrap();
    let other = zmux::Session::connect(PipeIo::from_tcp(tcp), client)
        .await
        .unwrap();
    assert_ne!(session.id(), other.id());
    let next = |events: &zmux::HostEvents| {
        let events = events.clone();
        async move {
            tokio::time::timeout(LIMIT, events.next())
                .await
                .unwrap()
                .expect("open")
        }
    };
    let id = session.id();
    let established = |e: &HostEvent| matches!(e, HostEvent::Trace { session, record: TraceRecord::Established } if *session == id);
    while !established(&next(&events).await) {}
    while !established(&next(&first).await) {}
    let () = session.close().await;
    let closed = |e: &HostEvent| matches!(e, HostEvent::Trace { session, record: TraceRecord::Closed(_) } if *session == id);
    while !closed(&next(&events).await) {}
    // Closed by the reader: nothing more, at once.
    events.close();
    assert!(
        tokio::time::timeout(LIMIT, events.next())
            .await
            .unwrap()
            .is_none()
    );
    drop((session, other));
    listener.close();
}

#[tokio::test]
async fn an_exporter_answering_later_gives_the_session_secret_input() {
    let value = |label: &str| {
        let mut v = vec![0u8; 32];
        v[..label.len().min(32)].copy_from_slice(&label.as_bytes()[..label.len().min(32)]);
        v
    };
    let (near, far) = tokio::io::duplex(1 << 16);
    let (ar, aw) = tokio::io::split(near);
    let (br, bw) = tokio::io::split(far);
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let later = PipeIo::from_halves(ar, aw).with_exporter_async(move |r| {
        c.fetch_add(1, Ordering::Relaxed);
        let v = value(&r.label);
        async move {
            tokio::task::yield_now().await;
            Ok(v)
        }
    });
    let now = PipeIo::from_halves(br, bw).with_exporter(move |label, _, out| {
        out.copy_from_slice(&value(label));
        true
    });
    let (client, server) = tokio::join!(
        zmux::Session::connect(later, Config::default()),
        zmux::Session::accept(now, Config::default())
    );
    let (client, server) = (client.unwrap(), server.unwrap());
    // Both read the same exporter input: the session is established and
    // carries streams.
    let (mut send, _) = client.open_bi().await.unwrap();
    send.write_all(b"hi").await.unwrap();
    let (_, mut recv) = server.accept_bi().await.unwrap();
    let mut buf = [0u8; 2];
    tokio::io::AsyncReadExt::read_exact(&mut recv, &mut buf)
        .await
        .unwrap();
    assert_eq!(&buf, b"hi");
    assert!(calls.load(Ordering::Relaxed) >= 1, "asked off the lock");
}

/// A later `on_reject` is dropped when the listener closes: the carrier's
/// handler ends with the close, not at the handshake timeout.
#[tokio::test]
async fn a_later_reject_policy_ends_with_the_listener() {
    let mut limits = ListenerConfig::default();
    limits.handshake_timeout = Duration::from_secs(30);
    limits.on_reject = Some(zmux::OnReject::new_async(|_| std::future::pending()));
    let listener = Listener::new(Config::default(), limits).unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let (client, server) = tokio::join!(TcpStream::connect(addr), tcp.accept());
    let mut client = client.unwrap();
    tokio::io::AsyncWriteExt::write_all(&mut client, &[0xff; 64])
        .await
        .unwrap();
    let l = listener.clone();
    let handled = tokio::spawn(async move {
        l.handle_pipe(
            PipeIo::from_tcp(server.unwrap().0),
            zmux::PipeHint::default(),
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = tokio::time::Instant::now();
    listener.close();
    let r = tokio::time::timeout(Duration::from_secs(5), handled)
        .await
        .expect("ended with the close")
        .unwrap();
    assert!(r.is_err());
    assert!(started.elapsed() < Duration::from_secs(2));
}
