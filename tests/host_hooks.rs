//! Host hooks that answer later, and the observing hooks' subscription.

#[path = "common/clock.rs"]
mod clock;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use clock::ManualClock;
use tokio::net::{TcpListener, TcpStream};
use zmux::{ClockDomain, MonotonicClock};
use zmux::{
    Config, HandleError, HostEvent, Listener, ListenerConfig, PipeHint, PipeIo, SessionConfigFn,
    TraceRecord,
};

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
            tokio::task::yield_now().await;
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
    tokio::time::timeout(LIMIT, async {
        let wait = Duration::from_secs(90);
        let (clock, domain) = ManualClock::domain(Duration::from_secs(120));
        let mut timers = clock.registrations();
        let deadline = domain.now() + wait;
        let mut limits = ListenerConfig::default();
        limits.handshake_timeout = wait;
        limits.session_config = Some(SessionConfigFn::new_async(|_| std::future::pending()));
        let mut config = Config::default();
        config.clock_domain = domain;
        let listener = Listener::new(config, limits).unwrap();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let client = tokio::spawn(zmux::Session::connect(
            PipeIo::new(client),
            Config::default(),
        ));
        let accepting = listener.clone();
        let handled = tokio::spawn(async move {
            accepting
                .handle_pipe(PipeIo::new(server), PipeHint::default())
                .await
        });
        // The first-record read can also register before the client writes.
        while timers.recv().await.unwrap() != deadline {}
        clock.advance(wait);
        assert_eq!(handled.await.unwrap(), Err(HandleError::Rejected));
        assert!(client.await.unwrap().is_err());
        assert_eq!(listener.stats().rejected, 1);
        listener.close();
    })
    .await
    .expect("session-config timeout test watchdog");
}

#[tokio::test]
async fn events_report_a_session_from_start_to_end() {
    let mut client = Config::default();
    // Two subscriptions: each reads every event.
    let first = client.events();
    let events = client.events();
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

/// A pending reject callback ends with the listener or its clock deadline.
#[tokio::test]
async fn a_later_reject_policy_ends_with_close_or_timeout() {
    tokio::time::timeout(LIMIT, async {
        for close in [false, true] {
            let wait = Duration::from_secs(90);
            let (clock, domain) = ManualClock::domain(Duration::from_secs(120));
            let mut timers = clock.registrations();
            let deadline = domain.now() + wait;
            let mut config = Config::default();
            config.clock_domain = domain;
            let mut limits = ListenerConfig::default();
            limits.handshake_timeout = wait;
            limits.on_reject = Some(zmux::OnReject::new_async(|_| std::future::pending()));
            let listener = Listener::new(config, limits).unwrap();
            let (mut client, server) = tokio::io::duplex(64);
            tokio::io::AsyncWriteExt::write_all(&mut client, &[0xff; 64])
                .await
                .unwrap();
            let accepting = listener.clone();
            let handled = tokio::spawn(async move {
                accepting
                    .handle_pipe(PipeIo::new(server), PipeHint::default())
                    .await
            });
            assert_eq!(timers.recv().await.unwrap(), deadline);
            if close {
                listener.close();
            } else {
                clock.advance(wait);
            }
            assert_eq!(handled.await.unwrap(), Err(HandleError::Rejected));
        }
    })
    .await
    .expect("reject policy test watchdog");
}
