//! A split bootstrap through the listener: an
//! uplink and a downlink carrier paired by their token, in either order;
//! a third carrier with the token, two of one direction, and a half whose
//! partner never comes are refused.

#![allow(
    clippy::many_single_char_names,
    reason = "short conventional names in scenario code"
)]

#[path = "common/clock.rs"]
mod clock;

use std::task::{Context, Waker};
use std::time::Duration;

use clock::ManualClock;
use tokio::io::{DuplexStream, duplex};
use zmux::{ClockDomain, MonotonicClock};
use zmux::{Config, HandleError, Listener, ListenerConfig, PipeHint, PipeIo, Session};

const TOKEN: &str = "AAECAwQFBgcICQoLDA0ODw";

/// The two carriers of a split bootstrap: the client's pipe, and the
/// server's uplink (it reads) and downlink (it writes).
fn carriers() -> (PipeIo, DuplexStream, DuplexStream) {
    let (up_client, up_server) = duplex(1 << 16);
    let (down_server, down_client) = duplex(1 << 16);
    let (down_read, _) = tokio::io::split(down_client);
    let (_, up_write) = tokio::io::split(up_client);
    (
        PipeIo::from_halves(down_read, up_write),
        up_server,
        down_server,
    )
}

fn hint() -> PipeHint {
    PipeHint::from_peer("192.0.2.1:0".parse().unwrap()).with_pair_header(TOKEN)
}

async fn run(downlink_first: bool) {
    let listener = Listener::new(Config::default(), ListenerConfig::default())
        .expect("valid listener configuration");
    let (client, up, down) = carriers();
    let (up_read, _keep_up) = tokio::io::split(up);
    let (_keep_down, down_write) = tokio::io::split(down);
    let uplink = PipeIo::reader(up_read);
    let downlink = PipeIo::writer(down_write);
    let (l1, l2) = (listener.clone(), listener.clone());
    let (first, second) = if downlink_first {
        (downlink, uplink)
    } else {
        (uplink, downlink)
    };
    let mut first = Box::pin(l1.handle_pipe(first, hint()));
    assert!(
        first
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    let b = tokio::spawn(async move { l2.handle_pipe(second, hint()).await });
    let session = Session::connect(client, Config::default()).await.unwrap();
    let server = listener.accept().await.unwrap();
    first.await.unwrap();
    b.await.unwrap().unwrap();
    let (mut s, mut r) = session.open_bi().await.unwrap();
    s.write_all(b"over two carriers").await.unwrap();
    s.finish().unwrap();
    let (mut ss, mut sr) = server.accept_bi().await.unwrap();
    let got = sr.read_to_end(1 << 10).await.unwrap();
    ss.write_all(&got).await.unwrap();
    ss.finish().unwrap();
    assert_eq!(r.read_to_end(1 << 10).await.unwrap(), b"over two carriers");
    session.close().await;
    server.closing().await;
    // The two halves are one pipe input.
    let st = listener.stats();
    assert_eq!(
        (st.sessions, st.joins, st.rejected, st.refused, st.timed_out),
        (1, 0, 0, 0, 0)
    );
    listener.close();
}

#[tokio::test]
// HS-40
async fn uplink_first() {
    tokio::time::timeout(Duration::from_secs(20), run(false))
        .await
        .unwrap();
}

#[tokio::test]
// HS-40
async fn downlink_first() {
    tokio::time::timeout(Duration::from_secs(20), run(true))
        .await
        .unwrap();
}

#[tokio::test]
async fn stopping_the_listener_ends_both_paired_setup_waits() {
    let l = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
    let (_peer, up, down) = carriers();
    let mut up = Box::pin(l.handle_pipe(PipeIo::reader(up), hint()));
    let mut down = Box::pin(l.handle_pipe(PipeIo::writer(down), hint()));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(up.as_mut().poll(&mut cx).is_pending());
    assert!(down.as_mut().poll(&mut cx).is_pending());
    l.close();
    let both = tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(up, down) })
        .await
        .unwrap();
    assert_eq!(both, (Err(HandleError::Refused), Err(HandleError::Refused)));
}

/// An attachment keeps its token during asynchronous carrier drain. Either
/// request may withdraw before handoff without cancelling its partner.
#[tokio::test]
async fn split_drain_owns_token_until_cleanup() {
    tokio::time::timeout(Duration::from_secs(8), async {
        let l = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
        let (client, up, down) = carriers();
        let (draining, started) = tokio::sync::oneshot::channel();
        let (release, gate) = tokio::sync::oneshot::channel();
        let (retired, done) = tokio::sync::oneshot::channel();
        let down = PipeIo::writer(down).with_drain(
            async move {
                draining.send(()).unwrap();
                gate.await.unwrap();
                retired.send(()).unwrap();
            },
            Duration::from_secs(8),
        );
        let mut cx = Context::from_waker(Waker::noop());
        let mut first = Box::pin(l.handle_pipe(PipeIo::reader(up), hint()));
        assert!(first.as_mut().poll(&mut cx).is_pending());
        let mut second = Box::pin(l.handle_pipe(down, hint()));
        assert!(second.as_mut().poll(&mut cx).is_pending());
        drop(first);
        let client = Session::connect(client, Config::default()).await.unwrap();
        second.await.unwrap();
        let server = l.accept().await.unwrap();
        client.close().await;
        server.closed().await;
        started.await.unwrap();
        assert_eq!(
            l.handle_pipe(PipeIo::writer(tokio::io::sink()), hint())
                .await,
            Err(HandleError::Rejected)
        );
        release.send(()).unwrap();
        done.await.unwrap();
        let mut next = Box::pin(l.handle_pipe(PipeIo::writer(tokio::io::sink()), hint()));
        assert!(next.as_mut().poll(&mut cx).is_pending());
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn bad_pairs_are_refused() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let limits = ListenerConfig::default();
        let pairing = limits.handshake_timeout;
        let (clock, domain) = ManualClock::domain(Duration::from_secs(120));
        let mut timers = clock.registrations();
        let expected = domain.now() + pairing;
        let mut config = Config::default();
        config.clock_domain = domain;
        let listener = Listener::new(config.clone(), limits).unwrap();
        // Two downlinks with one token: the second is refused, the first
        // times out without a partner.
        let (a, _ka) = duplex(64);
        let (b, _kb) = duplex(64);
        let handler = listener.clone();
        let first =
            tokio::spawn(async move { handler.handle_pipe(PipeIo::writer(a), hint()).await });
        assert_eq!(timers.recv().await.unwrap(), expected);
        let second = listener.handle_pipe(PipeIo::writer(b), hint()).await;
        assert_eq!(second, Err(HandleError::Rejected));
        clock.advance(pairing);
        assert_eq!(first.await.unwrap(), Err(HandleError::TimedOut));
        // A malformed token, and a carrier with both halves, are refused.
        let (c, _kc) = duplex(64);
        let bad = PipeHint::default().with_pair_header("not base64!");
        assert_eq!(
            listener.handle_pipe(PipeIo::writer(c), bad).await,
            Err(HandleError::Rejected)
        );
        let (d, _kd) = duplex(64);
        let two = PipeHint::default().with_pair_header("AQIDBAUGBwgJCgsMDQ4PEA");
        assert_eq!(
            listener.handle_pipe(PipeIo::new(d), two).await,
            Err(HandleError::Rejected)
        );
        // A pair whose uplink sends no first record times out, and nothing is read of a
        // half before its partner arrives.
        let mut limits = ListenerConfig::default();
        let first_record = Duration::from_secs(3);
        limits.limits.first_record_timeout = first_record;
        let now = config.clock_domain.now();
        let deadline = now + first_record;
        let l = Listener::new(config, limits).unwrap();
        let (e, _ke) = duplex(64);
        let (er, _) = tokio::io::split(e);
        let (g, _kg) = duplex(64);
        let late = l.clone();
        let lone = tokio::spawn(async move { late.handle_pipe(PipeIo::reader(er), hint()).await });
        assert_eq!(timers.recv().await.unwrap(), now + pairing);
        let partner = l.clone();
        let paired =
            tokio::spawn(async move { partner.handle_pipe(PipeIo::writer(g), hint()).await });
        assert_eq!(timers.recv().await.unwrap(), deadline);
        clock.advance(first_record);
        assert_eq!(paired.await.unwrap(), Err(HandleError::TimedOut));
        assert_eq!(lone.await.unwrap(), Err(HandleError::TimedOut));
        // A third carrier with a used token is refused.
        let (client, up, down) = carriers();
        let (up_read, _ku) = tokio::io::split(up);
        let (_kd2, down_write) = tokio::io::split(down);
        let l3 = Listener::new(Config::default(), ListenerConfig::default())
            .expect("valid listener configuration");
        let (x, y) = (l3.clone(), l3.clone());
        tokio::spawn(async move { x.handle_pipe(PipeIo::reader(up_read), hint()).await });
        tokio::spawn(async move { y.handle_pipe(PipeIo::writer(down_write), hint()).await });
        let session = Session::connect(client, Config::default()).await.unwrap();
        let (f, _kf) = duplex(64);
        assert_eq!(
            l3.handle_pipe(PipeIo::writer(f), hint()).await,
            Err(HandleError::Rejected)
        );
        drop(session);
        listener.close();
        l.close();
        l3.close();
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
// HS-44
async fn refused_split_join_retains_token_through_reply_drain() {
    let config = Config::multipath(zmux::PipeAuth::psk([9; 32]).with_end_to_end());
    let mut acceptor = config.clone();
    acceptor.session_policy.limits.steady_attachments = 2;
    acceptor.session_policy.limits.join_headroom = 0;
    let listener = Listener::new(acceptor, ListenerConfig::default()).unwrap();
    let ordinary = || {
        let (near, far) = duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move { l.handle_pipe(PipeIo::new(far), PipeHint::default()).await });
        PipeIo::new(near)
    };
    let session = Session::connect(ordinary(), config).await.unwrap();
    let _server = listener.accept().await.unwrap();
    let _first = session
        .test_join(ordinary(), zmux::PipeOptions::new())
        .await
        .unwrap();
    let (client, up, down) = carriers();
    let (entered, started) = tokio::sync::oneshot::channel();
    let (release, gate) = tokio::sync::oneshot::channel();
    let (retired, done) = tokio::sync::oneshot::channel();
    let down = PipeIo::writer(down).with_drain(
        async move {
            entered.send(()).unwrap();
            gate.await.unwrap();
            retired.send(()).unwrap();
        },
        Duration::from_secs(8),
    );
    let join = session
        .test_begin_join(client, zmux::PipeOptions::new())
        .unwrap();
    let result = tokio::join!(
        listener.handle_pipe(PipeIo::reader(up), hint()),
        listener.handle_pipe(down, hint())
    );
    assert_eq!(
        result,
        (Err(HandleError::Refused), Err(HandleError::Refused))
    );
    assert!(matches!(
        join.joined().await,
        Err(zmux::PipeError::Failed(zmux::PipeFailure::JoinRefused))
    ));
    started.await.unwrap();
    assert_eq!(
        listener
            .handle_pipe(PipeIo::writer(tokio::io::sink()), hint())
            .await,
        Err(HandleError::Rejected)
    );
    release.send(()).unwrap();
    done.await.unwrap();
    let mut next = Box::pin(listener.handle_pipe(PipeIo::writer(tokio::io::sink()), hint()));
    assert!(
        next.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
}

#[tokio::test(start_paused = true)]
async fn split_bootstrap_resolves_both_exporters_before_classification() {
    fn exported(io: PipeIo, value: u8) -> PipeIo {
        io.with_exporter_async(move |q| std::future::ready(Ok(vec![value; q.length])))
    }
    let config = Config::multipath(zmux::PipeAuth::exporter());
    let mut limits = ListenerConfig::default();
    limits.limits.max_pending_per_source = 1;
    assert!(Listener::new(config.clone(), limits.clone()).is_err());
    limits.limits.max_pending_per_source = 2;
    let listener = Listener::new(config.clone(), limits).unwrap();
    let (cu, su) = duplex(1 << 16);
    let (sd, cd) = duplex(1 << 16);
    let client = PipeIo::split_bootstrap(
        exported(PipeIo::writer(cu), 17),
        exported(PipeIo::reader(cd), 29),
    );
    let (up, down, session) = tokio::join!(
        listener.handle_pipe(exported(PipeIo::reader(su), 17), hint()),
        listener.handle_pipe(exported(PipeIo::writer(sd), 29), hint()),
        Session::connect(client, config)
    );
    up.unwrap();
    down.unwrap();
    let session = session.unwrap();
    let server = listener.accept().await.unwrap();
    assert!(session.session_binding().is_some());
    assert_eq!(session.session_binding(), server.session_binding());
}

#[tokio::test(start_paused = true)]
// HS-01
async fn split_exporter_ends_on_listener_stop_or_last_withdrawal() {
    for stop in [false, true] {
        let listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
        let (_client, up, down) = carriers();
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let gate = entered.clone();
        let mut reader = PipeIo::reader(up).with_exporter_async(move |_| {
            gate.notify_one();
            std::future::pending()
        });
        let (alive, released) = tokio::sync::oneshot::channel::<()>();
        reader = reader.with_abort(move || drop(alive));
        let l = listener.clone();
        let first = tokio::spawn(async move { l.handle_pipe(reader, hint()).await });
        let l = listener.clone();
        let second = tokio::spawn(async move { l.handle_pipe(PipeIo::writer(down), hint()).await });
        entered.notified().await;
        let at = tokio::time::Instant::now();
        if stop {
            listener.close();
            assert_eq!(first.await.unwrap(), Err(HandleError::Refused));
            assert_eq!(second.await.unwrap(), Err(HandleError::Refused));
        } else {
            first.abort();
            assert!(first.await.unwrap_err().is_cancelled());
            assert!(!second.is_finished());
            second.abort();
            assert!(second.await.unwrap_err().is_cancelled());
        }
        assert!(released.await.is_err());
        assert_eq!(at.elapsed(), Duration::ZERO);
    }
}

#[tokio::test]
// HS-44
async fn unmatched_token_stays_reserved_while_worker_is_alive() {
    let listener =
        zmux::Listener::new(zmux::Config::default(), zmux::ListenerConfig::default()).unwrap();
    let mut first = zmux::PipeIo::reader(tokio::io::empty());
    let worker = first.worker_guard();
    let hint = || zmux::PipeHint::default().with_pair_header(TOKEN);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut first_setup = Box::pin(listener.handle_pipe(first, hint()));
    assert!(first_setup.as_mut().poll(&mut cx).is_pending());
    drop(first_setup);
    let mut replacement =
        Box::pin(listener.handle_pipe(zmux::PipeIo::reader(tokio::io::empty()), hint()));
    assert!(matches!(
        replacement.as_mut().poll(&mut cx),
        std::task::Poll::Ready(Err(zmux::HandleError::Rejected))
    ));
    drop(worker);
}

#[tokio::test(start_paused = true)]
// HS-41
async fn expired_split_half_releases_token_after_worker() {
    let config = zmux::ListenerConfig::default();
    let deadline = config.handshake_timeout;
    let listener = zmux::Listener::new(zmux::Config::default(), config).unwrap();
    let mut half = PipeIo::reader(tokio::io::empty());
    let guard = half.worker_guard();
    let make = || PipeIo::reader(tokio::io::empty());
    let hint = || zmux::PipeHint::default().with_pair_header(TOKEN);
    let mut first = Box::pin(listener.handle_pipe(half, hint()));
    assert!(
        first
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
            .is_pending()
    );
    tokio::time::advance(deadline).await;
    assert!(first.await.is_err());
    assert_eq!(
        listener.handle_pipe(make(), hint()).await,
        Err(HandleError::Rejected)
    );
    drop(guard);
    let mut next = Box::pin(listener.handle_pipe(make(), hint()));
    assert!(
        next.as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop()))
            .is_pending()
    );
}

// HS-30. Both split handlers see the same protocol refusal after pairing.
#[tokio::test]
// HS-30
async fn a_drained_split_bootstrap_receives_the_captured_reason() {
    let l = zmux::Listener::new(zmux::Config::default(), zmux::ListenerConfig::default()).unwrap();
    l.drain(b"split drain");
    let (client, up, down) = carriers();
    let (up, _) = tokio::io::split(up);
    let (_, down) = tokio::io::split(down);
    let (dial, first, second) = tokio::join!(
        Session::connect(client, zmux::Config::default()),
        l.handle_pipe(PipeIo::reader(up), hint()),
        l.handle_pipe(PipeIo::writer(down), hint())
    );
    assert_eq!(first, Err(zmux::HandleError::Refused));
    assert_eq!(first, second);
    let end = match dial {
        Ok(s) => s.closing().await,
        Err(zmux::ConnectError::SessionLost(e)) => e,
        Err(e) => panic!("{e:?}"),
    };
    assert!(
        matches!(end, zmux::SessionError::TransportClosed {code, reason, remote: true, ..} if code == zmux::proto::TransportErrorCode::CONNECTION_REFUSED && reason.as_ref()==b"split drain")
    );
}

// HS-42. The matching half survives withdrawal of its partner after pairing.
#[tokio::test]
// HS-42
async fn one_remaining_split_caller_can_publish_a_duplex_session() {
    let l = zmux::Listener::new(zmux::Config::default(), zmux::ListenerConfig::default()).unwrap();
    let (client, up, down) = carriers();
    let (up, _) = tokio::io::split(up);
    let (_, down) = tokio::io::split(down);
    let mut a = Box::pin(l.handle_pipe(PipeIo::reader(up), hint()));
    let mut b = Box::pin(l.handle_pipe(PipeIo::writer(down), hint()));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(a.as_mut().poll(&mut cx).is_pending());
    assert!(b.as_mut().poll(&mut cx).is_pending());
    drop(a);
    let (c, r) = tokio::join!(Session::connect(client, zmux::Config::default()), b);
    r.unwrap();
    let c = c.unwrap();
    let s = l.accept().await.unwrap();
    let (mut tx, mut rx) = c.open_bi().await.unwrap();
    tx.write_all(b"up").await.unwrap();
    tx.finish().unwrap();
    let (mut tx, mut request) = s.accept_bi().await.unwrap();
    assert_eq!(request.read_to_end(8).await.unwrap(), b"up");
    tx.write_all(b"down").await.unwrap();
    tx.finish().unwrap();
    assert_eq!(rx.read_to_end(8).await.unwrap(), b"down");
}
