//! Establish over zmux carriers: trust, the credential rules of the secure
//! carrier, and a session with a joined Sealed pipe on top.

use std::net::SocketAddr;
use std::sync::Arc;

use std::time::Duration;
use zmux::shaping::{HandshakeShaper, Limits, UnitPlan};

use tokio::io::duplex;
use zmux::proto::seal::{Framing, RecordMode, cut_unit};
use zmux::{
    AdmittedValue, Config, Listener, ListenerConfig, PipeAuth, PipeIo, PipeOptions, Session,
};
use zmux_seal::*;

const NODE: [u8; 32] = [0x11; 32];

struct TestGate {
    psk: Vec<u8>,
    cred: Option<Credential>,
}

impl Gate for TestGate {
    fn resolve<'a>(
        &'a self,
        _: &'a [u8],
        _: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<Vec<u8>, VerifyError>> {
        Box::pin(async { Ok(self.psk.clone()) })
    }
    fn credential<'a>(
        &'a self,
        _: &'a [u8],
        _profile: Profile,
        _: &'a [u8],
        _: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<Option<Credential>, VerifyError>> {
        Box::pin(async { Ok(self.cred.clone()) })
    }
    fn commit<'a>(
        &'a self,
        _: Admission<'a>,
        _: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<AdmittedValue, VerifyError>> {
        Box::pin(async { Ok(Arc::new("client 1") as AdmittedValue) })
    }
}

fn node_public() -> Vec<u8> {
    static_public(&NODE).to_vec()
}

fn keys() -> HandlePsk {
    derive_handle_psk(&[9; 32], b"tests", b"").unwrap()
}

fn listener(cred: Option<Credential>, psk: Vec<u8>) -> Listener {
    let server = ServerConfig::new(
        Arc::new(TestGate { psk, cred }),
        NODE,
        ServerOptions::default(),
    )
    .expect("valid server configuration");
    let mut lc = ListenerConfig::default();
    lc.inbound_transform = Some(server.transform());
    Listener::new(config(), lc).expect("valid listener configuration")
}

fn config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::none();
    c
}

fn client(verifier: Arc<dyn Verifier>) -> ClientConfig {
    let k = keys();
    ClientConfig {
        verifier: Some(verifier),
        handle: k.handle,
        psk: k.psk,
        ..Default::default()
    }
}

async fn run(l: &Listener, cfg: &ClientConfig) -> std::io::Result<(PipeIo, Peer)> {
    let (a, b) = duplex(1 << 20);
    let l = l.clone();
    tokio::spawn(async move { l.handle_pipe(PipeIo::new(b), Default::default()).await });
    tokio::time::timeout(Duration::from_secs(5), establish(PipeIo::new(a), cfg))
        .await
        .expect("in time")
}

#[tokio::test]
async fn a_pinned_key_needs_no_credential_and_a_wrong_one_fails() {
    let l = listener(None, keys().psk);
    let pin = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
    let (_, peer) = run(&l, &pin).await.expect("message 2 without credentials");
    assert_eq!(peer.static_key, node_public());
    assert!(matches!(
        peer.verdict.map(|v| v.principal),
        Some(Principal::StaticKey(_))
    ));
    let wrong = client(Arc::new(PinVerifier::new([0; 32])));
    let e = run(&l, &wrong).await.unwrap_err();
    assert!(
        e.to_string().contains("credentials") || e.kind() == std::io::ErrorKind::PermissionDenied
    );
}

#[tokio::test]
async fn a_wrong_key_is_refused_without_an_answer() {
    let l = listener(None, vec![7; 32]);
    let mut pin = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
    // The server stalls a refusal before authentication by default.
    pin.reply_timeout = Some(Duration::from_millis(300));
    let e = run(&l, &pin).await.unwrap_err();
    assert!(e.get_ref().is_some_and(|e| e.is::<NoReply>()), "{e}");
    assert_eq!(l.stats().sessions, 0);
}

/// A session on the secure carrier: its secret from the exporter, with no configuration of a
/// source, a Sealed join on top, both Profile families.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_joins_a_sealed_pipe() {
    for profile in [1, 3] {
        let l = listener(None, keys().psk);
        let mut cfg = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
        cfg.allowed_profiles = vec![profile];
        let (p, _) = run(&l, &cfg).await.unwrap();
        let c = Session::connect(p, config()).await.unwrap();
        let s = l.accept().await.unwrap();
        c.established().await.unwrap();
        assert_eq!(c.weakest_record_mode(), RecordMode::Sealed);
        let admitted = s.admitted().expect("the gate's value");
        assert_eq!(admitted.downcast_ref::<&str>(), Some(&"client 1"));
        let (a, b) = duplex(1 << 20);
        let ll = l.clone();
        tokio::spawn(async move { ll.handle_pipe(PipeIo::new(b), Default::default()).await });
        let pipe = c
            .begin_add_pipe(
                PipeIo::new(a),
                PipeOptions::new().with_record_mode(RecordMode::Sealed),
            )
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), pipe.joined())
            .await
            .unwrap()
            .unwrap();
        c.close().await;
    }
}

/// A carrier without an Establish is refused for a secure-carrier configuration, and a
/// session on the secure carrier refuses another source.
#[tokio::test]
async fn the_source_goes_with_the_carrier() {
    let (a, _b) = duplex(1024);
    assert!(Session::connect(PipeIo::new(a), config()).await.is_err());
}

const PAIR: &str = "AAECAwQFBgcICQoLDA0ODw";

/// A split carrier's two carriers: the client's pipe, and the server's halves. Each half
/// has its own exporter value when given one.
fn split(exporters: Option<(u8, u8)>, secure: bool) -> (PipeIo, PipeIo, PipeIo) {
    let (up_client, up_server) = duplex(1 << 16);
    let (down_server, down_client) = duplex(1 << 16);
    let half = |p: PipeIo, v: Option<u8>| {
        let p = match v {
            Some(v) => p.with_exporter(move |_, _, out| {
                out.fill(v);
                true
            }),
            None => p,
        };
        if secure { p.with_carrier_secure() } else { p }
    };
    let (u, d) = (exporters.map(|e| e.0), exporters.map(|e| e.1));
    let (up_read, keep_up) = tokio::io::split(up_server);
    let (keep_down, down_write) = tokio::io::split(down_server);
    let (down_read, keep_a) = tokio::io::split(down_client);
    let (keep_b, up_write) = tokio::io::split(up_client);
    drop((keep_up, keep_down, keep_a, keep_b));
    (
        PipeIo::split_bootstrap(
            half(PipeIo::writer(up_write), u),
            half(PipeIo::reader(down_read), d),
        ),
        half(PipeIo::reader(up_read), u),
        half(PipeIo::writer(down_write), d),
    )
}

fn hand_over(l: &Listener, half: PipeIo) -> tokio::task::JoinHandle<Result<(), zmux::HandleError>> {
    let l = l.clone();
    let hint = zmux::PipeHint::default().with_pair_header(PAIR);
    tokio::spawn(async move { l.handle_pipe(half, hint).await })
}

async fn echo_once(c: &Session, s: &Session) {
    let (mut w, mut r) = c.open_bi().await.unwrap();
    w.write_all(b"over the pair").await.unwrap();
    w.finish().unwrap();
    let (mut sw, mut sr) = s.accept_bi().await.unwrap();
    let got = sr.read_to_end(1 << 10).await.unwrap();
    sw.write_all(&got).await.unwrap();
    sw.finish().unwrap();
    assert_eq!(r.read_to_end(1 << 10).await.unwrap(), b"over the pair");
}

/// Establish runs on a split carrier once paired, in either order of arrival, with Sealed
/// records on both directions.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_split_carrier_is_established_after_pairing() {
    for downlink_first in [false, true] {
        let l = listener(None, keys().psk);
        let (client_pipe, up, down) = split(None, false);
        let (a, b) = if downlink_first {
            (down, up)
        } else {
            (up, down)
        };
        let first = hand_over(&l, a);
        tokio::time::sleep(Duration::from_millis(20)).await;
        let second = hand_over(&l, b);
        let cfg = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
        let (p, peer) = tokio::time::timeout(Duration::from_secs(5), establish(client_pipe, &cfg))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer.record_mode, RecordMode::Sealed);
        let c = Session::connect(p, config()).await.unwrap();
        let s = l.accept().await.unwrap();
        assert_eq!(s.weakest_record_mode(), RecordMode::Sealed);
        assert!(s.admitted().is_some(), "the gate decided on the pair");
        echo_once(&c, &s).await;
        c.close().await;
        s.closing().await;
        let _ = tokio::time::timeout(Duration::from_secs(5), first)
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .unwrap();
        assert_eq!(l.stats().sessions, 1);
    }
}

/// The security property: halves of a split carrier do not pass a server that requires
/// Establish. A plain session on them starts nothing.
#[tokio::test]
async fn a_split_carrier_without_establish_starts_no_session() {
    // A session configuration that would run on any carrier: only the transform stands
    // in the way.
    let server = ServerConfig::new(
        Arc::new(TestGate {
            psk: keys().psk,
            cred: None,
        }),
        NODE,
        ServerOptions {
            allow_record_mode: None,
            shaper: None,
            shaping_limits: None,
            ..Default::default()
        },
    )
    .expect("valid server configuration");
    let mut lc = ListenerConfig::default();
    lc.inbound_transform = Some(server.transform());
    let l = Listener::new(Config::default(), lc).expect("valid listener configuration");
    let (client_pipe, up, down) = split(None, false);
    let first = hand_over(&l, up);
    let second = hand_over(&l, down);
    let mut plain = Config::default();
    plain.handshake_timeout = Some(Duration::from_millis(500));
    let dial = tokio::spawn(async move { Session::connect(client_pipe, plain).await.map(drop) });
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), first)
            .await
            .unwrap()
            .unwrap(),
        Err(zmux::HandleError::Rejected)
    );
    let _ = tokio::time::timeout(Duration::from_secs(5), second)
        .await
        .unwrap();
    assert_eq!(l.stats().sessions, 0);
    let _ = tokio::time::timeout(Duration::from_secs(5), dial).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), l.accept())
            .await
            .is_err(),
        "nothing to accept"
    );
}

fn bound_listener() -> Listener {
    let server = ServerConfig::new(
        Arc::new(TestGate {
            psk: keys().psk,
            cred: None,
        }),
        NODE,
        ServerOptions {
            allow_record_mode: Some(Arc::new(|_, _| true)),
            shaper: None,
            shaping_limits: None,
            ..Default::default()
        },
    )
    .expect("valid server configuration");
    let mut lc = ListenerConfig::default();
    lc.inbound_transform = Some(server.transform());
    Listener::new(config(), lc).expect("valid listener configuration")
}

/// Bound on a split carrier mixes both halves' exporters by role: the
/// same values agree, others fail, and a half without the contract is refused before a
/// byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bound_on_a_split_carrier_binds_both_halves() {
    let mut cfg = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
    cfg.record_mode = RecordMode::Bound;
    // A refused carrier is stalled: the client stops waiting first.
    cfg.reply_timeout = Some(Duration::from_millis(500));
    // Agreeing exporters.
    let l = bound_listener();
    let (pipe, up, down) = split(Some((1, 2)), true);
    let (_a, _b) = (hand_over(&l, up), hand_over(&l, down));
    let (p, peer) = tokio::time::timeout(Duration::from_secs(5), establish(pipe, &cfg))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer.record_mode, RecordMode::Bound);
    let c = Session::connect(p, config()).await.unwrap();
    let s = l.accept().await.unwrap();
    assert_eq!(s.weakest_record_mode(), RecordMode::Bound);
    echo_once(&c, &s).await;
    c.close().await;
    // The server's halves swapped by a relay: a third party, and auth.
    let l = bound_listener();
    let (mine, up, down) = {
        // One client, a server that sees other exporter values.
        let (up_client, up_server) = duplex(1 << 16);
        let (down_server, down_client) = duplex(1 << 16);
        let (ur, _) = tokio::io::split(up_server);
        let (_, dw) = tokio::io::split(down_server);
        let (dr, _) = tokio::io::split(down_client);
        let (_, uw) = tokio::io::split(up_client);
        let e = |v: u8, p: PipeIo| {
            p.with_exporter(move |_, _, out| {
                out.fill(v);
                true
            })
            .with_carrier_secure()
        };
        (
            PipeIo::split_bootstrap(e(1, PipeIo::writer(uw)), e(2, PipeIo::reader(dr))),
            e(2, PipeIo::reader(ur)),
            e(1, PipeIo::writer(dw)),
        )
    };
    let (_a, _b) = (hand_over(&l, up), hand_over(&l, down));
    let r = tokio::time::timeout(Duration::from_secs(5), establish(mine, &cfg))
        .await
        .unwrap();
    assert!(r.is_err(), "another Binding fails");
    assert_eq!(l.stats().sessions, 0);
    // No contract, or an exporter on one half only: refused before a byte.
    let (pipe, _u, _d) = split(Some((1, 2)), false);
    assert_eq!(
        establish(pipe, &cfg).await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    let (up_c, _us) = duplex(64);
    let (_ds, down_c) = duplex(64);
    let one = PipeIo::split_bootstrap(
        PipeIo::writer(up_c)
            .with_exporter(|_, _, out| {
                out.fill(1);
                true
            })
            .with_carrier_secure(),
        PipeIo::reader(down_c).with_carrier_secure(),
    );
    assert_eq!(
        establish(one, &cfg).await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}

/// Each message is asked for by name, reaches the length planned on the wire, and its delay
/// is waited; a handshake so shaped completes. Limits apply to the plans.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_handshake_shaper_plans_each_message() {
    use std::sync::Mutex;
    type Log = Arc<Mutex<Vec<&'static str>>>;
    const TARGET: usize = 2000;
    let shaper = |log: Log, delay: Duration| {
        HandshakeShaper::new(move |v| {
            assert_eq!(v.handshake, "establish");
            log.lock().unwrap().push(v.message);
            Some(UnitPlan::new(TARGET, 0, 0).with_delay(delay))
        })
    };
    for (creds, no_padding) in [(false, false), (true, false), (false, true)] {
        // An opaque credential of 112 bytes, as large as a signed one.
        let list = creds.then(|| (1, vec![0x5a; 112]));
        let server_log: Log = Arc::default();
        let client_log: Log = Arc::default();
        let server = ServerConfig::new(
            Arc::new(TestGate {
                psk: keys().psk,
                cred: list.clone(),
            }),
            NODE,
            ServerOptions {
                shaper: Some(shaper(server_log.clone(), Duration::ZERO)),
                ..Default::default()
            },
        )
        .expect("valid server configuration");
        let mut lc = ListenerConfig::default();
        lc.inbound_transform = Some(server.transform());
        let l = Listener::new(config(), lc).expect("valid listener configuration");
        let mut cfg = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
        cfg.credential = list.clone();
        cfg.shaper = Some(shaper(client_log.clone(), Duration::from_millis(30)));
        if no_padding {
            let mut limits = Limits::default();
            limits.no_padding = true;
            cfg.shaping_limits = Some(limits);
        }
        // A relay that keeps each read: one may join a unit with what follows it.
        let (a, b) = duplex(1 << 20);
        let (c, d) = duplex(1 << 20);
        let up: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let down: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let relay = |mut from: tokio::io::ReadHalf<tokio::io::DuplexStream>,
                     mut to: tokio::io::WriteHalf<tokio::io::DuplexStream>,
                     log: Arc<Mutex<Vec<Vec<u8>>>>| {
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0; 1 << 16];
                while let Ok(n @ 1..) = from.read(&mut buf).await {
                    log.lock().unwrap().push(buf[..n].to_vec());
                    if to.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            })
        };
        let (br, bw) = tokio::io::split(b);
        let (cr, cw) = tokio::io::split(c);
        relay(br, cw, up.clone());
        relay(cr, bw, down.clone());
        let ll = l.clone();
        tokio::spawn(async move { ll.handle_pipe(PipeIo::new(d), Default::default()).await });
        let begun = std::time::Instant::now();
        let (p, _) = tokio::time::timeout(Duration::from_secs(5), establish(PipeIo::new(a), &cfg))
            .await
            .unwrap()
            .unwrap();
        assert!(
            begun.elapsed() >= Duration::from_millis(60),
            "both of the client's delays"
        );
        let c = Session::connect(p, config()).await.unwrap();
        let s = l.accept().await.unwrap();
        echo_once(&c, &s).await;
        c.close().await;
        assert_eq!(*client_log.lock().unwrap(), ["hello", "finish"]);
        assert_eq!(*server_log.lock().unwrap(), ["reply"]);
        let unit_len =
            |reads: &[Vec<u8>]| cut_unit(Framing::ByteStream, &reads.concat()).unwrap().1;
        let sent = up.lock().unwrap().clone();
        // Nothing follows the hello before its reply; the later messages are framed.
        let hello = sent[0].len();
        let finish = unit_len(&sent[1..]);
        let reply = unit_len(&down.lock().unwrap());
        assert_eq!(reply, TARGET, "the server's plan");
        if no_padding {
            // The KEM key of the Hello, then little more.
            assert!(hello < 1400 && finish < 400, "{hello} {finish}");
        } else {
            assert_eq!((hello, finish), (TARGET, TARGET));
        }
    }
}

/// A message sent without a key has random padding, and a panicking hook is no plan.
#[tokio::test]
async fn padding_without_a_key_is_random() {
    use tokio::io::AsyncReadExt;
    let (a, mut b) = duplex(1 << 16);
    let cfg = ClientConfig {
        verifier: Some(Arc::new(PinVerifier::new(key_id(1, &node_public())))),
        shaper: Some(HandshakeShaper::new(|_| Some(UnitPlan::new(2000, 0, 0)))),
        ..ClientConfig::default()
    };
    let run = tokio::spawn(async move { establish(PipeIo::new(a), &cfg).await.map(|_| ()) });
    let mut buf = vec![0; 1 << 12];
    let mut got = 0;
    while got < 2000 {
        got += b.read(&mut buf[got..]).await.unwrap();
    }
    assert_eq!(got, 2000);
    // Past the KEM key of an XXhfs Hello: the padding.
    assert!(buf[1300..2000].iter().filter(|x| **x != 0).count() > 600);
    drop(b);
    assert!(run.await.unwrap().is_err());

    let (a, mut b) = duplex(1 << 16);
    let mut cfg = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
    cfg.shaper = Some(HandshakeShaper::new(|_| panic!("hook")));
    let run = tokio::spawn(async move { establish(PipeIo::new(a), &cfg).await.map(|_| ()) });
    let mut n = 0;
    while n < 1250 {
        let got = b.read(&mut buf[n..]).await.unwrap();
        assert_ne!(got, 0, "the Hello, unshaped, after {n} bytes");
        n += got;
    }
    assert!(n < 1400, "{n}");
    assert!(buf[..n].iter().any(|x| *x != 0));
    drop(b);
    assert!(run.await.unwrap().is_err());
}

/// A Join asks the hook for its messages by name, on both ends, waits, and goes on after a
/// hook that panics or has no plan.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_join_is_shaped_by_the_handshake_shaper() {
    use std::sync::Mutex;
    type Log = Arc<Mutex<Vec<&'static str>>>;
    let hook = |log: Log, plan: Option<UnitPlan>, fail: bool| {
        HandshakeShaper::new(move |v| {
            if v.handshake == "join" {
                log.lock().unwrap().push(v.message);
                assert!(!fail, "the hook fails");
                return plan;
            }
            None
        })
    };
    let plan = UnitPlan::new(900, 0, 0).with_delay(Duration::from_millis(10));
    for (plan, fail) in [(Some(plan), false), (None, false), (Some(plan), true)] {
        let (client_log, server_log): (Log, Log) = Default::default();
        let mut server_config = config();
        server_config.handshake_shaper = Some(hook(server_log.clone(), plan, fail));
        let server = ServerConfig::new(
            Arc::new(TestGate {
                psk: keys().psk,
                cred: None,
            }),
            NODE,
            ServerOptions {
                allow_record_mode: None,
                shaper: None,
                shaping_limits: None,
                ..Default::default()
            },
        )
        .expect("valid server configuration");
        let mut lc = ListenerConfig::default();
        lc.inbound_transform = Some(server.transform());
        let l = Listener::new(server_config, lc).expect("valid listener configuration");
        let cfg = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
        let (p, _) = run(&l, &cfg).await.unwrap();
        let mut client_config = config();
        client_config.handshake_shaper = Some(hook(client_log.clone(), plan, fail));
        let c = Session::connect(p, client_config).await.unwrap();
        let s = l.accept().await.unwrap();
        c.established().await.unwrap();
        let (a, b) = duplex(1 << 20);
        let ll = l.clone();
        tokio::spawn(async move { ll.handle_pipe(PipeIo::new(b), Default::default()).await });
        let pipe = c
            .begin_add_pipe(
                PipeIo::new(a),
                PipeOptions::new().with_record_mode(RecordMode::Sealed),
            )
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), pipe.joined())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(*client_log.lock().unwrap(), ["hello", "confirm"]);
        assert_eq!(*server_log.lock().unwrap(), ["reply"]);
        let st = c.shaping_stats();
        match (plan, fail) {
            (Some(_), false) => assert!(st.wire_spent > 500, "{st:?}"),
            (None, _) => assert_eq!(st.handshake_unplanned, 2, "{st:?}"),
            (Some(_), true) => assert_eq!(st.faults, 2, "{st:?}"),
        }
        echo_once(&c, &s).await;
        c.close().await;
    }
}

/// An Establish over a stream of another session: its exporter is the handshake's and
/// holds on the stream carrier, at both ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_establish_on_a_stream_carrier_keeps_its_exporter() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (a, b) = duplex(1 << 20);
        let outer_server = tokio::spawn(Session::accept(PipeIo::new(b), Config::default()));
        let outer = Session::connect(PipeIo::new(a), Config::default())
            .await
            .unwrap();
        let outer_server = outer_server.await.unwrap().unwrap();
        let l = listener(None, keys().psk);
        let ll = l.clone();
        tokio::spawn(async move {
            let (send, recv) = outer_server.accept_bi().await.unwrap();
            let _ = ll
                .handle_pipe(PipeIo::from_stream(send, recv), Default::default())
                .await;
            outer_server
        });
        let pipe = outer
            .open_pipe_stream(&zmux::Preamble::new())
            .await
            .unwrap();
        let cfg = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
        let (p, _) = establish(pipe, &cfg).await.unwrap();
        let c = Session::connect(p, config()).await.unwrap();
        let s = l.accept().await.unwrap();
        let there = s.export_keying_material("test", b"", 32).unwrap();
        assert_eq!(c.export_keying_material("test", b"", 32).unwrap(), there);
    })
    .await
    .unwrap();
}

/// A server's configuration is checked when it is made: the default set holds no Profile
/// without a pre-shared key, and an unknown Profile anywhere in the list is refused.
#[test]
fn a_server_configuration_is_checked_when_it_is_made() {
    let gate = || -> Arc<dyn Gate> {
        Arc::new(TestGate {
            psk: Vec::new(),
            cred: None,
        })
    };
    let made = |profiles: Vec<u64>| {
        ServerConfig::new(
            gate(),
            NODE,
            ServerOptions {
                accepted_profiles: profiles,
                ..Default::default()
            },
        )
    };
    let default = ServerOptions::default().accepted_profiles;
    assert_eq!(made(default).unwrap().accepted_profiles(), &[1, 3]);
    assert!(made(Vec::new()).is_err(), "no Profile");
    assert_eq!(made(vec![4, 5]).unwrap().accepted_profiles(), &[4, 5]);
    assert!(
        made(vec![1, 6]).is_err(),
        "an unassigned Profile after a known one"
    );
    assert!(made(vec![2]).is_err(), "Join is no Establish Profile");
    assert!(made(vec![9]).is_err(), "an unknown Profile");
    assert!(ServerConfig::new(gate(), [0; 32], ServerOptions::default()).is_err());
}

/// A client's local mistakes are named, before any byte; an unknown Profile anywhere in
/// its list is refused, not only the first one tried.
#[tokio::test]
async fn a_client_configuration_names_its_mistake() {
    let l = listener(None, keys().psk);
    let mut cfg = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
    cfg.psk = Vec::new();
    let e = run(&l, &cfg).await.unwrap_err();
    assert!(
        e.to_string()
            .contains("Handle set without a pre-shared key"),
        "{e}"
    );
    let mut cfg = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
    cfg.allowed_profiles = vec![1, 6];
    let e = run(&l, &cfg).await.unwrap_err();
    assert!(e.to_string().contains("unknown or reserved Profile"), "{e}");
    cfg.allowed_profiles = Vec::new();
    let e = run(&l, &cfg).await.unwrap_err();
    assert!(e.to_string().contains("allowed_profiles is empty"), "{e}");
}

/// Profile 4 is refused by default and accepted once listed; the client of a refused
/// Profile gets no reply.
#[tokio::test]
async fn a_profile_without_a_key_is_accepted_only_when_listed() {
    let anchor = || Arc::new(PinVerifier::new(key_id(1, &node_public()))) as Arc<dyn Verifier>;
    let mut cfg = ClientConfig {
        verifier: Some(anchor()),
        reply_timeout: Some(Duration::from_millis(300)),
        ..Default::default()
    };
    cfg.allowed_profiles = vec![4];
    let l = listener(None, keys().psk);
    let e = run(&l, &cfg).await.unwrap_err();
    let no_reply = e.get_ref().and_then(|e| e.downcast_ref::<NoReply>());
    assert!(no_reply.is_some(), "{e}");
    assert!(e.to_string().contains("the Profile is not accepted"), "{e}");
    let server = ServerConfig::new(
        Arc::new(TestGate {
            psk: Vec::new(),
            cred: None,
        }),
        NODE,
        ServerOptions {
            accepted_profiles: vec![4, 5],
            ..Default::default()
        },
    )
    .unwrap();
    let mut lc = ListenerConfig::default();
    lc.inbound_transform = Some(server.transform());
    let l = Listener::new(config(), lc).unwrap();
    run(&l, &cfg).await.expect("listed");
}

/// A client uses Profile 1 or 3 with a pre-shared key, PQ confidential; a refused Profile
/// is not followed by another.
#[tokio::test]
async fn profiles_pq_facts_and_no_fallback() {
    let pin = || Arc::new(PinVerifier::new(key_id(1, &node_public())));
    let l = listener(None, keys().psk);
    let (_, peer) = run(&l, &client(pin())).await.unwrap();
    assert!(peer.profile == 1 || peer.profile == 3, "{}", peer.profile);
    assert!(peer.pq_confidential && !peer.pq_authenticated);
    // A pin of the static key alone can never give PQ authentication.
    let mut pq = client(pin());
    pq.require_pq_auth = true;
    let e = run(&l, &pq).await.unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::InvalidInput, "{e}");
    let mut c = client(pin());
    c.allowed_profiles = vec![3, 1];
    assert_eq!(run(&l, &c).await.unwrap().1.profile, 3);
    // A Profile without a key that the server does not list is refused, and the client
    // does not try another.
    let mut c = ClientConfig {
        verifier: Some(pin()),
        allowed_profiles: vec![4, 1],
        reply_timeout: Some(Duration::from_millis(300)),
        ..Default::default()
    };
    assert!(run(&l, &c).await.is_err());
    c.allowed_profiles = vec![1];
    assert_eq!(
        run(&l, &c).await.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput,
        "no Profile without a key listed"
    );
}

/// A credential travels to the verifier with the PSK identity and the local context; a
/// rejection and a temporary failure are told apart, and a panic is temporary.
#[tokio::test]
async fn the_verifier_sees_one_credential_and_tells_its_errors_apart() {
    struct Check(bool);
    impl Verifier for Check {
        fn verify<'a>(
            &'a self,
            i: VerifyInput<'a>,
        ) -> BoxFuture<'a, Result<VerifyVerdict, VerifyError>> {
            Box::pin(async move {
                assert_eq!(i.role, zmux::Role::Server);
                assert_eq!(i.credential, Some((7, &[1, 2][..])));
                assert_eq!(i.psk_identity, Some(&keys().handle[..]));
                assert_eq!(i.local_context, b"ctx");
                if self.0 {
                    let mut v = VerifyVerdict::new(Principal::Other(1, vec![1, 2]));
                    v.value = Some(Arc::new(7u32));
                    Ok(v)
                } else {
                    Err(VerifyError::unavailable("down"))
                }
            })
        }
    }
    struct Panics;
    impl Verifier for Panics {
        fn verify<'a>(
            &'a self,
            _: VerifyInput<'a>,
        ) -> BoxFuture<'a, Result<VerifyVerdict, VerifyError>> {
            panic!("a host's bug")
        }
    }
    let l = listener(Some((7, vec![1, 2])), keys().psk);
    let mut c = client(Arc::new(Check(true)));
    c.local_context = b"ctx".to_vec();
    let (_, peer) = run(&l, &c).await.unwrap();
    assert_eq!(peer.credential, Some((7, vec![1, 2])));
    let verdict = peer.verdict.expect("the verdict");
    assert_eq!(verdict.principal, Principal::Other(1, vec![1, 2]));
    assert_eq!(
        verdict.value.and_then(|v| v.downcast_ref::<u32>().copied()),
        Some(7)
    );
    c.verifier = Some(Arc::new(Check(false)));
    let e = run(&l, &c).await.unwrap_err();
    assert_ne!(e.kind(), std::io::ErrorKind::PermissionDenied);
    let wrong = client(Arc::new(PinVerifier::new([0; 32])));
    assert_eq!(
        run(&l, &wrong).await.unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    let e = run(&l, &client(Arc::new(Panics))).await.unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(e.to_string().contains("panicked"), "{e}");
}

/// Application data: the client's messages 1 and 3 and the server's message 2 carry it,
/// each piece marked with its message and protection; the server's source sees the
/// client's message 1 data, the client verifier all of the client's; too long is refused.
#[tokio::test]
async fn application_data_in_messages_1_2_and_3() {
    struct SeesClientData;
    impl Verifier for SeesClientData {
        fn verify<'a>(
            &'a self,
            i: VerifyInput<'a>,
        ) -> BoxFuture<'a, Result<VerifyVerdict, VerifyError>> {
            Box::pin(async move {
                let got: Vec<(u8, &[u8], bool)> = i
                    .peer_app_data
                    .iter()
                    .map(|a| (a.message, a.data.as_slice(), a.forward_secret))
                    .collect();
                // Nothing is authenticated while the verification runs.
                assert!(i.peer_app_data.iter().all(|a| !a.authenticated));
                assert_eq!(got, vec![(1, &b"m1"[..], false), (3, &b"m3"[..], true)]);
                Ok(VerifyVerdict::new(Principal::StaticKey(
                    i.peer_static.to_vec(),
                )))
            })
        }
    }
    let server_source: AppDataSource = Arc::new(|r: &AppDataRequest<'_>| {
        assert_eq!(r.message, 2);
        let peer = r.peer.expect("what is known of the client");
        assert_eq!(peer.peer_app_data[0].data, b"m1");
        assert!(peer.peer_static.is_empty());
        Box::pin(async { Ok(b"m2".to_vec()) })
    });
    // The gate's Admission holds the client's data, authenticated once it passed.
    struct SeesAdmission(std::sync::Mutex<Vec<AppData>>);
    impl Gate for SeesAdmission {
        fn resolve<'a>(
            &'a self,
            _: &'a [u8],
            _: Option<SocketAddr>,
        ) -> BoxFuture<'a, Result<Vec<u8>, VerifyError>> {
            Box::pin(async { Ok(keys().psk) })
        }
        fn credential<'a>(
            &'a self,
            _: &'a [u8],
            _: Profile,
            _: &'a [u8],
            _: Option<SocketAddr>,
        ) -> BoxFuture<'a, Result<Option<Credential>, VerifyError>> {
            Box::pin(async { Ok(None) })
        }
        fn commit<'a>(
            &'a self,
            a: Admission<'a>,
            _: Option<SocketAddr>,
        ) -> BoxFuture<'a, Result<AdmittedValue, VerifyError>> {
            *self.0.lock().unwrap() = a.peer.app_data.clone();
            Box::pin(async { Ok(Arc::new(()) as AdmittedValue) })
        }
    }
    let gate = Arc::new(SeesAdmission(std::sync::Mutex::new(Vec::new())));
    let server = ServerConfig::new(
        gate.clone(),
        NODE,
        ServerOptions {
            app_data: Some(server_source),
            client_verifier: Some(Arc::new(SeesClientData)),
            ..Default::default()
        },
    )
    .expect("valid server configuration");
    let mut lc = ListenerConfig::default();
    lc.inbound_transform = Some(server.transform());
    let l = Listener::new(config(), lc).expect("valid listener configuration");
    let mut c = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
    c.app_data = Some(Arc::new(|r: &AppDataRequest<'_>| {
        let data = match r.message {
            1 => b"m1".to_vec(),
            3 => {
                let verdict = r.verdict.expect("the server's verdict");
                assert_eq!(verdict.principal, Principal::StaticKey(node_public()));
                let judged = r.peer.expect("the server").peer_app_data;
                assert_eq!(judged[0].data, b"m2");
                assert!(!judged[0].authenticated);
                b"m3".to_vec()
            }
            m => panic!("message {m}"),
        };
        Box::pin(async move { Ok(data) })
    }));
    let (_, peer) = run(&l, &c).await.expect("handshake with application data");
    assert_eq!(
        peer.app_data,
        vec![AppData {
            message: 2,
            data: b"m2".to_vec(),
            forward_secret: true,
            authenticated: true,
        }]
    );
    let admitted = || gate.0.lock().unwrap().clone();
    for _ in 0..500 {
        if !admitted().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let seen: Vec<(u8, bool, bool)> = admitted()
        .iter()
        .map(|a| (a.message, a.forward_secret, a.authenticated))
        .collect();
    assert_eq!(seen, [(1, false, false), (3, true, true)]);
    // No bound beyond the message.
    c.max_app_data = None;
    run(&l, &c).await.expect("no bound beyond the message");
    // The server's data above this client's bound fails the handshake.
    c.max_app_data = Some(1);
    assert!(run(&l, &c).await.is_err());
}

/// A client verifier that panics, as it makes its future or while it runs, rejects the
/// client, as a client's verifier that panics rejects the server.
#[tokio::test]
async fn panicking_client_verifier_rejects() {
    struct Panics;
    impl Verifier for Panics {
        fn verify<'a>(
            &'a self,
            _: VerifyInput<'a>,
        ) -> BoxFuture<'a, Result<VerifyVerdict, VerifyError>> {
            panic!("a host's bug")
        }
    }
    struct PanicsLater;
    impl Verifier for PanicsLater {
        fn verify<'a>(
            &'a self,
            _: VerifyInput<'a>,
        ) -> BoxFuture<'a, Result<VerifyVerdict, VerifyError>> {
            Box::pin(async { panic!("a host's bug") })
        }
    }
    let c = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
    for v in [Arc::new(Panics) as Arc<dyn Verifier>, Arc::new(PanicsLater)] {
        let server = ServerConfig::new(
            Arc::new(TestGate {
                psk: keys().psk,
                cred: None,
            }),
            NODE,
            ServerOptions {
                client_verifier: Some(v),
                ..Default::default()
            },
        )
        .expect("valid server configuration");
        let reasons = Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut lc = ListenerConfig::default();
        lc.inbound_transform = Some(server.transform());
        lc.on_reject = Some(zmux::proto::listener::OnReject(Arc::new({
            let reasons = reasons.clone();
            move |i| {
                reasons.lock().unwrap().push(i.reason);
                zmux::proto::listener::RejectAction::Close
            }
        })));
        let l = Listener::new(config(), lc).expect("valid listener configuration");
        let (a, b) = duplex(1 << 20);
        let served = tokio::spawn({
            let l = l.clone();
            async move { l.handle_pipe(PipeIo::new(b), Default::default()).await }
        });
        // Message 3 is sent; the server's refusal comes after it.
        drop(
            establish(PipeIo::new(a), &c)
                .await
                .expect("message 3 is sent"),
        );
        let r = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("in time")
            .expect("no panic escapes");
        assert!(r.is_err());
        assert_eq!(*reasons.lock().unwrap(), ["credentials_failed"]);
        assert_eq!(l.stats().sessions, 0);
    }
}

/// A listener whose server proves message 2 with `signer` and verifies clients with
/// `client_verifier`.
fn proving_listener(
    signer: Option<Arc<dyn Signer>>,
    client_verifier: Option<Arc<dyn Verifier>>,
    require_pq_auth: bool,
) -> Listener {
    let server = ServerConfig::new(
        Arc::new(TestGate {
            psk: keys().psk,
            cred: Some((77, b"node".to_vec())),
        }),
        NODE,
        ServerOptions {
            signer,
            client_verifier,
            require_pq_auth,
            ..Default::default()
        },
    )
    .expect("valid server configuration");
    let mut lc = ListenerConfig::default();
    lc.inbound_transform = Some(server.transform());
    Listener::new(config(), lc).expect("valid listener configuration")
}

/// Trusts any peer and names this proof key.
struct NamesProofKey(KeyId);

impl Verifier for NamesProofKey {
    fn verify<'a>(
        &'a self,
        i: VerifyInput<'a>,
    ) -> BoxFuture<'a, Result<VerifyVerdict, VerifyError>> {
        Box::pin(async move {
            Ok(VerifyVerdict {
                principal: Principal::StaticKey(i.peer_static.to_vec()),
                proof_key: Some(self.0),
                value: None,
            })
        })
    }
}

/// Both ends prove their messages with ML-DSA-44 and are PQ-authenticated; a verdict
/// naming another key, or a proof key with no proof, fails as a rejection.
#[tokio::test]
async fn proofs_give_pq_authentication_both_ways() {
    let server_key = SigningKey::generate(KEYALG_MLDSA44).unwrap();
    let client_key = SigningKey::generate(KEYALG_MLDSA44).unwrap();
    let (server_id, client_id) = (server_key.key_id(), client_key.key_id());
    let l = proving_listener(
        Some(Arc::new(KeySigner(server_key))),
        Some(Arc::new(NamesProofKey(client_id))),
        true,
    );
    let mut c = client(Arc::new(PinVerifier::with_proof_key(
        key_id(KEYALG_X25519, &node_public()),
        server_id,
    )));
    c.require_pq_auth = true;
    c.signer = Some(Arc::new(KeySigner(client_key)));
    let (_, peer) = run(&l, &c).await.expect("mutual proofs");
    assert!(peer.pq_authenticated);

    let mut other = c.clone();
    other.verifier = Some(Arc::new(NamesProofKey([0; 32])));
    let e = run(&l, &other).await.unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied, "{e}");

    // A client that does not sign fails the server's verdict: the server closes.
    let mut silent = c.clone();
    silent.signer = None;
    run(&l, &silent).await.expect("message 3 is sent");
    assert_eq!(l.stats().sessions, 0);

    // Without a proof key named, a proof is not looked at and gives nothing.
    let unsigned = proving_listener(
        Some(Arc::new(KeySigner(SigningKey::generate(3).unwrap()))),
        None,
        false,
    );
    let plain = client(Arc::new(PinVerifier::new(key_id(
        KEYALG_X25519,
        &node_public(),
    ))));
    let (_, peer) = run(&unsigned, &plain).await.unwrap();
    assert!(!peer.pq_authenticated);
}

/// A server that requires PQ authentication of clients needs a verifier, and not a pin
/// of a static key alone.
#[test]
fn pq_authentication_needs_a_proof_key() {
    let made = |v: Option<Arc<dyn Verifier>>| {
        ServerConfig::new(
            Arc::new(TestGate {
                psk: Vec::new(),
                cred: None,
            }),
            NODE,
            ServerOptions {
                client_verifier: v,
                require_pq_auth: true,
                ..Default::default()
            },
        )
    };
    assert!(made(None).is_err());
    assert!(made(Some(Arc::new(PinVerifier::new([1; 32])))).is_err());
    assert!(
        made(Some(Arc::new(PinVerifier::with_proof_key(
            [1; 32], [2; 32]
        ))))
        .is_ok()
    );
}

/// The public key of a static secret is X25519's, and its KeyId the pin's.
#[test]
fn the_public_key_of_a_static_secret() {
    let public = static_public(&NODE);
    assert_eq!(
        public,
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(NODE)).as_bytes()
    );
    assert_eq!(static_key_id(&public), key_id(KEYALG_X25519, &public));
}

/// The refusals a reject policy saw: reason and record mode.
type Seen = Arc<std::sync::Mutex<Vec<(&'static str, Option<RecordMode>)>>>;

/// A Bound listener whose reject policy records each refusal and answers
/// `action`, or the default for it.
fn mismatch_listener(action: Option<zmux::RejectAction>, seen: Seen) -> Listener {
    let server = ServerConfig::new(
        Arc::new(TestGate {
            psk: keys().psk,
            cred: None,
        }),
        NODE,
        ServerOptions {
            allow_record_mode: Some(Arc::new(|_, _| true)),
            ..Default::default()
        },
    )
    .expect("valid server configuration");
    let mut lc = ListenerConfig::default();
    lc.inbound_transform = Some(server.transform());
    lc.handshake_timeout = Duration::from_millis(1500);
    lc.on_reject = Some(zmux::OnReject(Arc::new(move |i| {
        seen.lock().unwrap().push((i.reason, i.record_mode));
        action.unwrap_or_else(|| zmux::RejectAction::default_for(i))
    })));
    Listener::new(config(), lc).expect("valid listener configuration")
}

/// A Bound Establish whose two ends see different exporters (a terminating
/// intermediary): refused as `auth` in Bound, and by default stalled
/// without a byte, the carrier still open after the decision and ended
/// within the stall bound; with the policy's Close, closed at once without
/// a byte and counted as rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_establish_with_another_binding_is_refused_by_the_policy() {
    let mut cfg = client(Arc::new(PinVerifier::new(key_id(1, &node_public()))));
    cfg.record_mode = RecordMode::Bound;
    cfg.reply_timeout = Some(Duration::from_millis(300));
    let exporter = |v: u8, io: PipeIo| {
        io.with_carrier_secure().with_exporter(move |_, _, out| {
            out.fill(v);
            true
        })
    };
    for action in [None, Some(zmux::RejectAction::Close)] {
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let l = mismatch_listener(action, seen.clone());
        let (a, b) = duplex(1 << 20);
        let start = tokio::time::Instant::now();
        let served = {
            let l = l.clone();
            tokio::spawn(async move {
                let r = l
                    .handle_pipe(exporter(2, PipeIo::new(b)), Default::default())
                    .await;
                (r, start.elapsed())
            })
        };
        let e = establish(exporter(1, PipeIo::new(a)), &cfg)
            .await
            .unwrap_err();
        // No byte came back either way.
        assert!(e.get_ref().is_some_and(|e| e.is::<NoReply>()), "{e}");
        let gave_up = start.elapsed();
        match action {
            None => {
                // The client gave up at its reply timeout, and the carrier
                // is still held.
                assert!(gave_up >= Duration::from_millis(290), "{gave_up:?}");
                assert!(!served.is_finished(), "a stall holds the carrier");
                let (r, took) = tokio::time::timeout(Duration::from_secs(5), served)
                    .await
                    .unwrap()
                    .unwrap();
                assert!(r.is_err());
                assert!(
                    took >= Duration::from_millis(1400) && took < Duration::from_secs(4),
                    "{took:?}"
                );
            }
            Some(_) => {
                // The carrier ended before the client's reply timeout.
                assert!(gave_up < Duration::from_millis(290), "{gave_up:?}");
                let (r, took) = tokio::time::timeout(Duration::from_secs(1), served)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(r, Err(zmux::HandleError::Rejected));
                assert!(took < Duration::from_millis(500), "{took:?}");
            }
        }
        assert_eq!(*seen.lock().unwrap(), [("auth", Some(RecordMode::Bound))]);
        assert_eq!(l.stats().sessions, 0);
        if action.is_some() {
            assert_eq!(l.stats().rejected, 1);
        }
    }
}
