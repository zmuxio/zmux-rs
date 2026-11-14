//! Carrier admission, the listener's one admission at every entry:
//! accepted carriers reach the listener without the accepted prefix,
//! others reach the fallback with every byte read replayed, or are
//! stalled; each outcome is counted once in the admission statistics.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use zmux::adapter::{Admit, Fallback, JoinPrefix};
use zmux::{
    Admission, AdmissionStats, AdmissionVerdict, CarrierInfo, Config, Decide, DecideFuture,
    HandleError, Listener, ListenerConfig, PipeHint, PipeIo, PrefixAuth, PrefixAuthVerifier,
    Session,
};

const LIMIT: Duration = Duration::from_secs(10);

fn limits(admission: Admission, fallback: Option<Fallback>) -> ListenerConfig {
    let mut limits = ListenerConfig::default();
    limits.admission = Some(admission);
    limits.fallback = fallback;
    limits
}

async fn serve_with(limits: ListenerConfig) -> (Listener, String) {
    let listener = Listener::new(Config::default(), limits).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap().to_string();
    tokio::spawn(listener.clone().serve(tcp));
    (listener, addr)
}

async fn serve(admission: Admission, fallback: Option<Fallback>) -> (Listener, String) {
    serve_with(limits(admission, fallback)).await
}

/// Waits up to the test limit for `f`.
async fn eventually(f: impl Fn() -> bool) {
    tokio::time::timeout(LIMIT, async {
        while !f() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

/// Reads until the server ends the connection; what it sent.
async fn ended(tcp: &mut TcpStream) -> Vec<u8> {
    let mut got = Vec::new();
    let _ = tokio::time::timeout(LIMIT, tcp.read_to_end(&mut got))
        .await
        .unwrap();
    got
}

#[tokio::test]
async fn prefix_auth_token_then_session() {
    let auth = PrefixAuth::new(b"psk", Duration::from_secs(30), false).unwrap();
    let verifier = Arc::new(PrefixAuthVerifier::new(auth.clone(), 1, 1024));
    let (listener, addr) = serve(Admission::prefix_auth(verifier), None).await;
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tcp.write_all(&auth.token(None).unwrap()).await.unwrap();
    let session = tokio::time::timeout(
        LIMIT,
        Session::connect(PipeIo::from_tcp(tcp), Config::default()),
    )
    .await
    .unwrap()
    .unwrap();
    let accepted = tokio::time::timeout(LIMIT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    let (mut send, _recv) = session.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let (_s, mut recv) = accepted.accept_bi().await.unwrap();
    assert_eq!(recv.read_to_end(16).await.unwrap(), b"ping");
    let st = listener.stats();
    assert_eq!((st.admission.accepted, st.sessions, st.rejected), (1, 1, 0));
    listener.close();
}

#[tokio::test]
async fn fallback_receives_every_byte_read() {
    let auth = PrefixAuth::new(b"psk", Duration::from_secs(30), false).unwrap();
    let wrong = PrefixAuth::new(b"other", Duration::from_secs(30), false).unwrap();
    let verifier = Arc::new(PrefixAuthVerifier::new(auth, 1, 1024));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let fallback = Fallback::new(move |mut conn, source: SocketAddr| {
        let tx = tx.clone();
        async move {
            let mut got = Vec::new();
            let _ = conn.read_to_end(&mut got).await;
            let _ = conn.write_all(b"fallback").await;
            let _ = tx.send((got, source));
        }
    });
    let (listener, addr) = serve(Admission::prefix_auth(verifier), Some(fallback)).await;
    let mut sent = wrong.token(None).unwrap().to_vec();
    sent.extend_from_slice(b"and the rest of the stream");
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tcp.write_all(&sent).await.unwrap();
    tcp.shutdown().await.unwrap();
    let (got, source) = tokio::time::timeout(LIMIT, rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, sent);
    assert_eq!(source, tcp.local_addr().unwrap());
    assert_eq!(ended(&mut tcp).await, b"fallback");
    let st = listener.stats();
    // Counted by the admission only.
    assert_eq!((st.sessions, st.rejected, st.setup_failures), (0, 0, 0));
    assert_eq!(st.admission.fallback, 1);
    listener.close();
}

#[tokio::test]
async fn stall_sends_nothing_and_ends_with_the_peer() {
    let admission = Admission::new(4, |_, _| AdmissionVerdict::Stall)
        .with_stall_interval(Duration::from_secs(60), Duration::from_secs(60));
    let (listener, addr) = serve(admission, None).await;
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tcp.write_all(b"0123456789").await.unwrap();
    tcp.shutdown().await.unwrap();
    assert!(
        ended(&mut tcp).await.is_empty(),
        "graceful end, nothing sent"
    );
    // Counted when the stall started.
    assert_eq!(listener.stats().admission.stalled, 1);
    listener.close();
}

#[tokio::test]
async fn fallback_without_a_target_stalls() {
    let admission = Admission::new(4, |_, _| AdmissionVerdict::Fallback)
        .with_stall_interval(Duration::from_millis(50), Duration::from_millis(100));
    let (listener, addr) = serve(admission, None).await;
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tcp.write_all(b"0123").await.unwrap();
    assert!(ended(&mut tcp).await.is_empty());
    let st = listener.stats();
    assert_eq!(
        (st.admission.fallback, st.admission.stalled, st.rejected),
        (1, 0, 0)
    );
    listener.close();
}

#[tokio::test]
async fn every_outcome_is_counted_once() {
    // Close, an Accept beyond the prefix, and a decision that panics are
    // all closed.
    for decide in [
        (|_: &CarrierInfo<'_>, _: &[u8]| AdmissionVerdict::Close)
            as fn(&CarrierInfo<'_>, &[u8]) -> AdmissionVerdict,
        |_, _| AdmissionVerdict::accept(5),
        |_, _| panic!("a failing decision"),
    ] {
        let (listener, addr) = serve(Admission::new(4, decide), None).await;
        let mut tcp = TcpStream::connect(&addr).await.unwrap();
        tcp.write_all(b"0123").await.unwrap();
        assert!(ended(&mut tcp).await.is_empty());
        eventually(|| listener.stats().admission.closed == 1).await;
        let st = listener.stats();
        assert_eq!(
            (
                st.sessions,
                st.rejected,
                st.refused,
                st.timed_out,
                st.setup_failures
            ),
            (0, 0, 0, 0, 0)
        );
        let a = st.admission;
        assert_eq!(
            (
                a.accepted,
                a.fallback,
                a.stalled,
                a.stall_overflow,
                a.peek_timed_out,
                a.handshake_failed
            ),
            (0, 0, 0, 0, 0, 0)
        );
        listener.close();
    }
}

/// A decision that waits, as a lookup would.
struct Slow(Duration, AdmissionVerdict);

impl Decide for Slow {
    fn decide<'a>(&'a self, _: &'a CarrierInfo<'a>, _: &'a [u8]) -> DecideFuture<'a> {
        Box::pin(async move {
            tokio::time::sleep(self.0).await;
            self.1.clone().into()
        })
    }
}

#[tokio::test]
async fn an_async_decision_within_the_peek_timeout() {
    let admission = Admission::with_decider(
        1,
        Slow(Duration::from_millis(20), AdmissionVerdict::accept(1)),
    )
    .with_peek_timeout(LIMIT);
    let (listener, addr) = serve(admission, None).await;
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tcp.write_all(b"z").await.unwrap();
    let session = tokio::time::timeout(
        LIMIT,
        Session::connect(PipeIo::from_tcp(tcp), Config::default()),
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
    assert_eq!(listener.stats().admission.accepted, 1);
    drop(session);
    listener.close();
}

#[tokio::test]
async fn a_late_decision_is_a_peek_timeout() {
    // The peek timeout covers the prefix and the decision.
    let admission = Admission::with_decider(
        0,
        Slow(Duration::from_secs(3600), AdmissionVerdict::accept(0)),
    )
    .with_peek_timeout(Duration::from_millis(50));
    let (listener, addr) = serve(admission, None).await;
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    assert!(ended(&mut tcp).await.is_empty());
    eventually(|| listener.stats().admission.peek_timed_out == 1).await;
    assert_eq!(listener.stats().admission.closed, 0);
    listener.close();
}

#[tokio::test]
async fn a_late_prefix_is_closed_or_falls_back() {
    // Two of four bytes, then silence: the decision is never asked.
    let never =
        |_: &CarrierInfo<'_>, _: &[u8]| -> AdmissionVerdict { panic!("decided a late prefix") };
    let late = || Admission::new(4, never).with_peek_timeout(Duration::from_millis(50));
    let (listener, addr) = serve(late(), None).await;
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tcp.write_all(b"ab").await.unwrap();
    assert!(ended(&mut tcp).await.is_empty());
    let a = listener.stats().admission;
    assert_eq!((a.peek_timed_out, a.fallback, a.closed), (1, 0, 0));
    listener.close();

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let fallback = Fallback::new(move |mut conn, _| {
        let tx = tx.clone();
        async move {
            let mut got = Vec::new();
            let _ = conn.read_to_end(&mut got).await;
            let _ = tx.send(got);
        }
    });
    let (listener, addr) = serve(late().with_fallback_on_peek_timeout(true), Some(fallback)).await;
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tcp.write_all(b"ab").await.unwrap();
    eventually(|| listener.stats().admission.fallback == 1).await;
    tcp.write_all(b"cdef").await.unwrap();
    tcp.shutdown().await.unwrap();
    let got = tokio::time::timeout(LIMIT, rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(got, b"abcdef");
    let a = listener.stats().admission;
    assert_eq!((a.peek_timed_out, a.fallback, a.closed), (1, 1, 0));
    listener.close();
}

#[tokio::test]
async fn closing_the_listener_cancels_a_decision() {
    let admission = Admission::with_decider(
        0,
        Slow(Duration::from_secs(3600), AdmissionVerdict::accept(0)),
    )
    .with_peek_timeout(Duration::from_secs(3600));
    let (listener, addr) = serve(admission, None).await;
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    listener.close();
    assert!(ended(&mut tcp).await.is_empty());
    eventually(|| listener.stats().admission.closed == 1).await;
}

#[tokio::test]
async fn the_source_slot_is_taken_before_any_handshake() {
    let mut limits = limits(
        Admission::with_decider(0, Slow(Duration::from_secs(3600), AdmissionVerdict::Close))
            .with_peek_timeout(Duration::from_secs(3600)),
        None,
    );
    limits.max_pending_per_source = 2;
    let (listener, addr) = serve_with(limits).await;
    let peer = "127.0.0.1:1".parse().unwrap();
    // One slot of the source held by the host.
    let held = listener.adapter().enter(peer, None).unwrap();
    // One by a carrier under decision.
    let mut first = TcpStream::connect(&addr).await.unwrap();
    eventually(|| listener.adapter().enter(peer, None).is_none()).await;
    // Beyond the share: closed at once, refused, never decided.
    let mut second = TcpStream::connect(&addr).await.unwrap();
    assert!(ended(&mut second).await.is_empty());
    eventually(|| listener.stats().refused >= 2).await;
    // Another source has its own share.
    assert!(
        listener
            .adapter()
            .enter("192.0.2.1:1".parse().unwrap(), None)
            .is_some()
    );
    // An IPv6 source counts by its /64.
    let v6 = listener
        .adapter()
        .enter("[2001:db8::1]:1".parse().unwrap(), None);
    let v6b = listener
        .adapter()
        .enter("[2001:db8::2]:1".parse().unwrap(), None);
    assert!(v6.is_some() && v6b.is_some());
    assert!(
        listener
            .adapter()
            .enter("[2001:db8::3]:1".parse().unwrap(), None)
            .is_none()
    );
    drop(held);
    listener.close();
    assert!(ended(&mut first).await.is_empty());
}

#[tokio::test(start_paused = true)]
async fn stall_duration_is_a_function_of_the_source() {
    let (min, max) = (Duration::from_secs(1), Duration::from_secs(1000));
    let admission = Admission::new(0, |_, _| AdmissionVerdict::Stall).with_stall_interval(min, max);
    let listener = Listener::new(Config::default(), limits(admission, None))
        .expect("valid listener configuration");
    let d = async |s: &str| {
        let mut e = listener.adapter().enter(s.parse().unwrap(), None).unwrap();
        let start = tokio::time::Instant::now();
        e.stall(None::<&mut tokio::io::Empty>).await;
        start.elapsed()
    };
    for s in ["192.0.2.1:1", "198.51.100.7:1", "[2001:db8::1]:1"] {
        let a = d(s).await;
        assert!((min..=max + Duration::from_millis(1)).contains(&a));
        assert_eq!(a, d(s).await);
    }
    assert_eq!(d("[2001:db8::1]:1").await, d("[2001:db8::ffff:2]:7").await);
    assert_eq!(d("[::ffff:192.0.2.1]:1").await, d("192.0.2.1:9").await);
    listener.close();
}

#[tokio::test(start_paused = true)]
async fn a_source_stalls_at_most_its_share_less_one() {
    let admission = Admission::new(0, |_, _| AdmissionVerdict::Stall)
        .with_stall_interval(Duration::from_secs(1), Duration::from_secs(1));
    let mut config = limits(admission, None);
    config.max_pending_per_source = 3;
    let listener = Listener::new(Config::default(), config).expect("valid listener configuration");
    let none = || None::<&mut tokio::io::Empty>;
    let enter = |s: &str| listener.adapter().enter(s.parse().unwrap(), None).unwrap();
    async fn admit(e: &mut zmux::adapter::Entry) -> Admit {
        e.admit(CarrierInfo::new(), None::<&mut tokio::io::Empty>)
            .await
    }
    let counts = || {
        let a = listener.stats().admission;
        (a.stalled, a.stall_overflow)
    };
    // One /64: two stall, the third is closed at once.
    let mut a = enter("[2001:db8::1]:1");
    let mut b = enter("[2001:db8::ffff:2]:2");
    assert!(matches!(admit(&mut a).await, Admit::Stall));
    assert!(matches!(admit(&mut b).await, Admit::Stall));
    let mut c = enter("[2001:db8::3]:3");
    assert!(matches!(admit(&mut c).await, Admit::Close));
    assert_eq!(counts(), (2, 1));
    // A stall after a fallback without target returns at once too.
    let start = tokio::time::Instant::now();
    c.stall(none()).await;
    assert_eq!(start.elapsed(), Duration::ZERO);
    drop(c);
    // Another source is not affected.
    let mut other = enter("[2001:db8:0:1::1]:1");
    assert!(matches!(admit(&mut other).await, Admit::Stall));
    assert_eq!(counts(), (3, 1));
    // The end of a stall gives its place back.
    a.stall(none()).await;
    let mut d = enter("[2001:db8::4]:4");
    assert!(matches!(admit(&mut d).await, Admit::Stall));
    assert_eq!(counts(), (4, 1));
    drop((a, b, d, other));
    listener.close();
}

/// With `source_prefix_v4` 24 and `source_prefix_v6` 56, two sources of one
/// /24 or one /56 share the per-source bound, the stalled-carrier count and
/// the stall duration, while sources of different prefixes do not; 33, 129
/// and 0 are the configuration error.
#[tokio::test(start_paused = true)]
async fn source_prefixes_aggregate_every_per_source_limit() {
    for (v4, v6) in [(0, 64), (33, 64), (32, 0), (32, 129)] {
        let mut c = ListenerConfig::default();
        c.source_prefix_v4 = v4;
        c.source_prefix_v6 = v6;
        assert!(Listener::new(Config::default(), c).is_err(), "{v4} {v6}");
    }
    let (min, max) = (Duration::from_secs(1), Duration::from_secs(1000));
    let admission = Admission::new(0, |_, _| AdmissionVerdict::Stall).with_stall_interval(min, max);
    let mut config = limits(admission, None);
    config.max_pending_per_source = 3;
    config.source_prefix_v4 = 24;
    config.source_prefix_v6 = 56;
    let listener = Listener::new(Config::default(), config).expect("valid listener configuration");
    let enter = |s: &str| listener.adapter().enter(s.parse().unwrap(), None);
    async fn admit(e: &mut zmux::adapter::Entry) -> Admit {
        e.admit(CarrierInfo::new(), None::<&mut tokio::io::Empty>)
            .await
    }
    let d = async |s: &str| {
        let mut e = listener.adapter().enter(s.parse().unwrap(), None).unwrap();
        let start = tokio::time::Instant::now();
        e.stall(None::<&mut tokio::io::Empty>).await;
        start.elapsed()
    };
    for (a, b, c, other) in [
        (
            "192.0.2.1:1",
            "192.0.2.77:2",
            "192.0.2.200:3",
            "192.0.3.1:1",
        ),
        (
            "[2001:db8:0:a1::1]:1",
            "[2001:db8:0:a2::1]:2",
            "[2001:db8:0:ff::1]:3",
            "[2001:db8:0:1a1::1]:1",
        ),
    ] {
        // One stall duration per prefix.
        assert_eq!(d(a).await, d(b).await);
        assert_eq!(d(a).await, d(c).await);
        // The stalled-carrier count: two of the prefix stall, the third is
        // closed at once.
        let overflow = || listener.stats().admission.stall_overflow;
        let before = overflow();
        let mut ea = enter(a).unwrap();
        let mut eb = enter(b).unwrap();
        assert!(matches!(admit(&mut ea).await, Admit::Stall));
        assert!(matches!(admit(&mut eb).await, Admit::Stall));
        let mut ec = enter(c).unwrap();
        assert!(matches!(admit(&mut ec).await, Admit::Close));
        assert_eq!(overflow(), before + 1);
        // The bound: the prefix's three slots are taken.
        assert!(enter(a).is_none() && enter(c).is_none());
        // Another prefix has its own share, stalls and duration.
        let mut eo = enter(other).unwrap();
        assert!(matches!(admit(&mut eo).await, Admit::Stall));
        drop((ea, eb, ec, eo));
    }
    // The defaults, /32 and /64, tell these apart.
    let listener = Listener::new(Config::default(), ListenerConfig::default())
        .expect("valid listener configuration");
    let mut held = Vec::new();
    for s in ["192.0.2.1:1", "[2001:db8:0:a1::1]:1"] {
        for _ in 0..8 {
            held.push(listener.adapter().enter(s.parse().unwrap(), None).unwrap());
        }
    }
    assert!(
        listener
            .adapter()
            .enter("192.0.2.2:1".parse().unwrap(), None)
            .is_some()
    );
    assert!(
        listener
            .adapter()
            .enter("[2001:db8:0:a2::1]:1".parse().unwrap(), None)
            .is_some()
    );
    assert!(
        listener
            .adapter()
            .enter("192.0.2.1:2".parse().unwrap(), None)
            .is_none()
    );
    drop(held);
    listener.close();
}

/// A share of one per source is a configuration error: a split bootstrap
/// holds two slots.
#[test]
fn a_share_below_two_is_invalid() {
    for share in [0, 1] {
        let mut config = ListenerConfig::default();
        config.max_pending_per_source = share;
        assert!(Listener::new(Config::default(), config).is_err(), "{share}");
    }
    let mut config = ListenerConfig::default();
    config.max_pending_per_source = 2;
    assert!(Listener::new(Config::default(), config).is_ok());
}

/// The listener's bound holds every carrier from its entry: stalls take at most half of
/// it (beyond, `stall_overflow`); with every slot taken a new carrier evicts the stall
/// that began first and proceeds, or is refused, counted as rejected, when none is
/// stalled. A released entry gives its slots back without counting anything.
#[tokio::test(start_paused = true)]
async fn the_global_bound_evicts_the_oldest_stall() {
    let admission = Admission::new(0, |_, _| AdmissionVerdict::Stall)
        .with_stall_interval(Duration::from_secs(3600), Duration::from_secs(3600));
    let mut config = limits(admission, None);
    config.max_pending = Some(4);
    let listener = Listener::new(Config::default(), config).expect("valid listener configuration");
    let enter = |n: u8| {
        listener
            .adapter()
            .enter(SocketAddr::from(([192, 0, 2, n], 1)), None)
    };
    async fn admit(e: &mut zmux::adapter::Entry) -> Admit {
        e.admit(CarrierInfo::new(), None::<&mut tokio::io::Empty>)
            .await
    }
    let none = || None::<&mut tokio::io::Empty>;
    let mut a = enter(1).unwrap();
    let mut b = enter(2).unwrap();
    assert!(matches!(admit(&mut a).await, Admit::Stall));
    assert!(matches!(admit(&mut b).await, Admit::Stall));
    let mut c = enter(3).unwrap();
    assert!(matches!(admit(&mut c).await, Admit::Close));
    assert_eq!(listener.stats().admission.stall_overflow, 1);
    // `a` stalls first, then `b`; `c` and `d` hold the other slots.
    let sa = tokio::spawn(async move { a.stall(none()).await });
    tokio::task::yield_now().await;
    let sb = tokio::spawn(async move { b.stall(none()).await });
    tokio::task::yield_now().await;
    let d = enter(4).unwrap();
    // Every slot taken: the oldest stall ends, and the new carrier holds its slot.
    let e = enter(5).unwrap();
    tokio::time::timeout(LIMIT, sa).await.unwrap().unwrap();
    assert!(!sb.is_finished());
    let f = enter(6).unwrap();
    tokio::time::timeout(LIMIT, sb).await.unwrap().unwrap();
    let before = listener.stats();
    assert!(enter(7).is_none());
    assert_eq!(listener.stats().rejected, before.rejected + 1);
    // Released, a slot is free again, and nothing is counted.
    c.release();
    let g = enter(8).unwrap();
    let after = listener.stats();
    assert_eq!(
        (after.admission.handshake_failed, after.setup_failures),
        (before.admission.handshake_failed, before.setup_failures)
    );
    drop((d, e, f, g));
    listener.close();
}

#[tokio::test]
async fn accept_keeps_the_bytes_after_the_skipped_ones() {
    // Accept(1) of a one-byte marker: the session's records follow it.
    let admission = Admission::new(1, |_, p| {
        if p == b"z" {
            AdmissionVerdict::accept(1)
        } else {
            AdmissionVerdict::Close
        }
    });
    let (listener, addr) = serve(admission, None).await;
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tcp.write_all(b"z").await.unwrap();
    let session = tokio::time::timeout(
        LIMIT,
        Session::connect(PipeIo::from_tcp(tcp), Config::default()),
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
    drop(session);
    listener.close();
}

/// A carrier the host hands over directly is admitted too: its own first
/// bytes are the prefix, and a join or resumption goes through it like a
/// new session.
#[tokio::test]
async fn handle_pipe_applies_the_admission() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let admission = Admission::new(1, move |info, p| {
        let _ = tx.send((info.source, info.peer));
        if p == b"z" {
            AdmissionVerdict::accept(1)
        } else {
            AdmissionVerdict::Close
        }
    });
    let listener = Listener::new(Config::default(), limits(admission, None))
        .expect("valid listener configuration");
    let (a, b) = tokio::io::duplex(1 << 16);
    let source: SocketAddr = "198.51.100.7:4000".parse().unwrap();
    let peer: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let l = listener.clone();
    tokio::spawn(async move {
        l.handle_pipe(
            PipeIo::new(b),
            PipeHint::from_peer(peer).with_source(source),
        )
        .await
    });
    let mut a = a;
    a.write_all(b"z").await.unwrap();
    let session = tokio::time::timeout(LIMIT, Session::connect(PipeIo::new(a), Config::default()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(rx.recv().await.unwrap(), (Some(source), Some(peer)));
    assert!(listener.accept().await.is_some());
    drop(session);
    // Not admitted: closed, counted by the admission only.
    let (mut a, b) = tokio::io::duplex(1 << 16);
    a.write_all(b"x").await.unwrap();
    let r = listener
        .handle_pipe(PipeIo::new(b), PipeHint::from_peer(peer))
        .await;
    assert_eq!(r, Err(HandleError::NotAdmitted));
    // Without a source, the source is the peer.
    assert_eq!(rx.recv().await.unwrap(), (Some(peer), Some(peer)));
    let st = listener.stats();
    assert_eq!(
        (st.admission.accepted, st.admission.closed, st.rejected),
        (1, 1, 0)
    );
    listener.close();
}

#[tokio::test]
async fn no_admission_counts_nothing() {
    let listener = Listener::new(Config::default(), ListenerConfig::default())
        .expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(listener.clone().serve(tcp));
    let tcp = TcpStream::connect(addr).await.unwrap();
    let session = tokio::time::timeout(
        LIMIT,
        Session::connect(PipeIo::from_tcp(tcp), Config::default()),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(listener.accept().await.is_some());
    assert_eq!(listener.stats().admission, AdmissionStats::default());
    drop(session);
    listener.close();
}

/// More reads on from the carrier in the listener's own serve loop, and the
/// bytes past the accepted ones reach the session.
#[tokio::test]
async fn more_reads_on_in_the_serve_loop() {
    let admission = Admission::new(2, |_, p| {
        if p.len() < 5 {
            AdmissionVerdict::More { need: 5 }
        } else if p == b"token" {
            AdmissionVerdict::accept(5)
        } else {
            AdmissionVerdict::Close
        }
    })
    .with_max_peek(8);
    let (listener, addr) = serve(admission, None).await;
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tcp.write_all(b"to").await.unwrap();
    tcp.flush().await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    tcp.write_all(b"ken").await.unwrap();
    let session = tokio::time::timeout(
        LIMIT,
        Session::connect(PipeIo::from_tcp(tcp), Config::default()),
    )
    .await
    .unwrap()
    .unwrap();
    let accepted = tokio::time::timeout(LIMIT, listener.accept())
        .await
        .unwrap()
        .unwrap();
    let (mut send, _recv) = session.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    send.finish().unwrap();
    let (_s, mut recv) = accepted.accept_bi().await.unwrap();
    assert_eq!(recv.read_to_end(16).await.unwrap(), b"ping");
    let st = listener.stats().admission;
    assert_eq!((st.accepted, st.closed), (1, 0));
    listener.close();
}

/// A carrier that ends short of what More asked for is decided once more on
/// what it sent; another More then closes it.
#[tokio::test]
async fn more_past_the_end_of_the_carrier_closes() {
    let admission = Admission::new(2, |_, p| {
        if p.len() < 5 {
            AdmissionVerdict::More { need: 5 }
        } else {
            AdmissionVerdict::accept(5)
        }
    })
    .with_max_peek(8);
    let (listener, addr) = serve(admission, None).await;
    let mut tcp = TcpStream::connect(&addr).await.unwrap();
    tcp.write_all(b"tok").await.unwrap();
    tcp.shutdown().await.unwrap();
    assert!(ended(&mut tcp).await.is_empty());
    let l = listener.clone();
    eventually(move || l.stats().admission.closed == 1).await;
    assert_eq!(listener.stats().admission.accepted, 0);
    listener.close();
}

#[test]
fn join_prefix_reads_the_hello_head() {
    let listener = Listener::new(Config::default(), ListenerConfig::default()).unwrap();
    // 02, Suite 1, ModeByte Sealed, LocatorLen 16, Locator, R (32 bytes).
    let mut hello = vec![0x02, 0x01, 0x00, 16];
    hello.extend_from_slice(&[7; 16]);
    hello.extend_from_slice(&[9; 32]);
    assert_eq!(
        listener.adapter().join_prefix(&hello[..1]),
        JoinPrefix::Need(2)
    );
    assert_eq!(
        listener.adapter().join_prefix(&hello[..4]),
        JoinPrefix::Need(20)
    );
    assert_eq!(
        listener.adapter().join_prefix(&hello[..30]),
        JoinPrefix::Need(52)
    );
    assert_eq!(listener.adapter().join_prefix(&hello), JoinPrefix::Unknown);
    assert_eq!(
        listener.adapter().join_prefix(b"GET / HTTP/1.1"),
        JoinPrefix::NotJoin
    );
    assert_eq!(
        listener.adapter().join_prefix(&[0x02, 0x01, 0x7c]),
        JoinPrefix::NotJoin
    );
}
