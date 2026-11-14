//! Establish and the listener of the std driver, together and against the tokio driver.

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zmux::blocking::{self, InboundTransform, PipeHint, PipeIo};
use zmux::proto::listener::{OnReject, RejectAction};
use zmux::proto::seal::RecordMode;
use zmux::{AdmittedValue, Config, HandleError, ListenerConfig, PipeAuth, PipeOptions};
use zmux_seal::{
    Admission, BoxFuture, ClientConfig, Credential, Gate, HandlePsk, Peer, PinVerifier,
    ServerConfig, VerifyError, derive_handle_psk, establish, key_id,
};

const NODE: [u8; 32] = [0x11; 32];

struct TestGate(Vec<u8>);

impl Gate for TestGate {
    fn resolve<'a>(
        &'a self,
        _: &'a [u8],
        _: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<Vec<u8>, VerifyError>> {
        Box::pin(async { Ok(self.0.clone()) })
    }
    fn credential<'a>(
        &'a self,
        _: &'a [u8],
        _: zmux_seal::Profile,
        _: &'a [u8],
        _: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<Option<Credential>, VerifyError>> {
        Box::pin(async { Ok(None) })
    }
    fn commit<'a>(
        &'a self,
        _: Admission<'a>,
        _: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<AdmittedValue, VerifyError>> {
        Box::pin(async { Ok(Arc::new("client 1") as AdmittedValue) })
    }
}

fn keys() -> HandlePsk {
    derive_handle_psk(&[9; 32], b"tests", b"").unwrap()
}

fn config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::none();
    c
}

fn server(psk: Vec<u8>) -> ServerConfig {
    ServerConfig::new(Arc::new(TestGate(psk)), NODE, Default::default())
        .expect("valid server configuration")
}

fn client_config() -> ClientConfig {
    let node = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(NODE));
    let k = keys();
    ClientConfig {
        verifier: Some(Arc::new(PinVerifier::new(key_id(1, node.as_bytes())))),
        handle: k.handle,
        psk: k.psk,
        ..Default::default()
    }
}

/// A listener serving on a loopback port; the thread ends with it.
fn serving(
    transform: Option<InboundTransform>,
    limits: ListenerConfig,
) -> (blocking::Listener, SocketAddr, std::thread::JoinHandle<()>) {
    let l =
        blocking::Listener::new(config(), limits, transform).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = tcp.local_addr().unwrap();
    let ll = l.clone();
    let t = std::thread::spawn(move || ll.serve(&tcp).unwrap());
    (l, addr, t)
}

fn echo(c: &blocking::Session, s: &blocking::Session, data: &[u8]) {
    let (mut w, mut r) = c.open_bi().unwrap();
    w.write_all(data).unwrap();
    w.finish().unwrap();
    let (mut sw, mut sr) = s.accept_bi().unwrap();
    let got = sr.read_to_end(1 << 20).unwrap();
    sw.write_all(&got).unwrap();
    sw.finish().unwrap();
    assert_eq!(r.read_to_end(1 << 20).unwrap(), data);
}

/// Establish, a session, and a Sealed Join, all on threads.
#[test]
fn establish_and_join_on_threads() {
    let (l, addr, t) = serving(
        Some(server(keys().psk).blocking_transform()),
        ListenerConfig::default(),
    );
    let (p, peer) = blocking_establish(addr).unwrap();
    assert_eq!(peer.record_mode, RecordMode::Sealed);
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = asked.clone();
    let mut with_hook = config();
    with_hook.handshake_shaper = Some(zmux::shaping::HandshakeShaper::new(move |v| {
        log.lock().unwrap().push(v.message);
        Some(zmux::shaping::UnitPlan::new(900, 0, 0).with_delay(Duration::from_millis(5)))
    }));
    let c = blocking::Session::connect(p, with_hook).unwrap();
    let s = l
        .accept_timeout(Duration::from_secs(5))
        .ok()
        .flatten()
        .expect("a session");
    assert_eq!(c.weakest_record_mode(), RecordMode::Sealed);
    assert_eq!(
        s.admitted().unwrap().downcast_ref::<&str>(),
        Some(&"client 1")
    );
    echo(&c, &s, b"on pipe 0");
    let pipe = c
        .begin_add_pipe(
            PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
            PipeOptions::new().with_record_mode(RecordMode::Sealed),
        )
        .unwrap();
    pipe.joined().unwrap();
    assert_eq!(*asked.lock().unwrap(), ["hello", "confirm"]);
    assert!(c.shaping_stats().wire_spent > 500);
    // Joined here is before the acceptor read the confirmation.
    let begun = Instant::now();
    while s.pipe(pipe.id()).is_none() {
        assert!(begun.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(1));
    }
    c.pipe(zmux::PipeId::new(0)).unwrap().abort().unwrap();
    echo(&c, &s, &vec![7; 64 << 10]);
    let st = l.stats();
    assert_eq!((st.sessions, st.joins), (1, 1));
    c.close();
    l.close();
    t.join().unwrap();
}

/// Without a transform, a plain session; a carrier silent past the first-record timeout,
/// and a refused Establish, end as the counters say, and the reject policy is asked.
#[test]
fn timeouts_and_refusals() {
    let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = asked.clone();
    let mut limits = ListenerConfig::default();
    limits.first_record_timeout = Duration::from_millis(100);
    limits.on_reject = Some(OnReject::new(move |_| {
        seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        RejectAction::Close
    }));
    let (l, addr, t) = serving(Some(server(vec![7; 32]).blocking_transform()), limits);
    // A wrong key: refused without an answer.
    let e = blocking_establish(addr).unwrap_err();
    assert_ne!(e.kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), 1);
    // Counted once its handler returns, after the carrier closed.
    let end = Instant::now() + Duration::from_secs(5);
    while l.stats().rejected == 0 && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(l.stats().rejected, 1);
    assert_eq!(l.stats().sessions, 0);
    l.close();
    t.join().unwrap();
    // A carrier that says nothing.
    let mut limits = ListenerConfig::default();
    limits.first_record_timeout = Duration::from_millis(100);
    let l = blocking::Listener::new(config(), limits, None).expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let silent = TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
    let (accepted, _) = tcp.accept().unwrap();
    let begun = Instant::now();
    assert_eq!(
        l.handle_pipe(PipeIo::from_tcp(accepted), PipeHint::default()),
        Err(HandleError::TimedOut)
    );
    assert!(begun.elapsed() < Duration::from_secs(2));
    assert_eq!(l.stats().timed_out, 1);
    drop(silent);
    // Closed: refused, and accept ends.
    l.close();
    assert!(l.accept().is_none());
    let tcp2 = TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
    assert_eq!(
        l.handle_pipe(PipeIo::from_tcp(tcp2), PipeHint::default()),
        Err(HandleError::Refused)
    );
}

fn blocking_establish(addr: SocketAddr) -> std::io::Result<(PipeIo, Peer)> {
    let tcp = TcpStream::connect(addr)?;
    zmux_seal::blocking::establish(
        PipeIo::from_tcp(tcp),
        &client_config(),
        Some(Duration::from_secs(5)),
    )
}

/// A server that never answers: the client's bound ends the handshake.
#[test]
fn a_client_timeout_ends_the_handshake() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let conn = TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
    let (_kept, _) = tcp.accept().unwrap();
    let begun = Instant::now();
    let e = zmux_seal::blocking::establish(
        PipeIo::from_tcp(conn),
        &client_config(),
        Some(Duration::from_millis(100)),
    )
    .unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
    assert!(begun.elapsed() < Duration::from_secs(2));
}

/// A server that never answers, and no bound of the caller's: the reply timeout ends the
/// handshake with `NoReply`, the carrier shut down.
#[test]
fn the_reply_timeout_ends_a_silent_handshake() {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let conn = TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
    let (_kept, _) = tcp.accept().unwrap();
    let mut cfg = client_config();
    cfg.reply_timeout = Some(Duration::from_millis(150));
    let begun = Instant::now();
    let e = zmux_seal::blocking::establish(PipeIo::from_tcp(conn), &cfg, None).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
    assert!(
        e.get_ref().is_some_and(|e| e.is::<zmux_seal::NoReply>()),
        "{e}"
    );
    assert!(begun.elapsed() >= Duration::from_millis(140));
    assert!(begun.elapsed() < Duration::from_secs(2));
}

/// By default a blocking listener stalls a refused Establish: the client hears nothing and
/// its reply timeout ends the handshake, the carrier held until then.
#[test]
fn a_refused_establish_is_stalled_by_default() {
    let mut limits = ListenerConfig::default();
    limits.handshake_timeout = Duration::from_secs(5);
    let (l, addr, t) = serving(Some(server(vec![7; 32]).blocking_transform()), limits);
    let mut cfg = client_config();
    cfg.reply_timeout = Some(Duration::from_millis(400));
    let begun = Instant::now();
    let e = zmux_seal::blocking::establish(
        PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
        &cfg,
        None,
    )
    .unwrap_err();
    assert!(
        e.get_ref().is_some_and(|e| e.is::<zmux_seal::NoReply>()),
        "{e}"
    );
    assert_eq!(
        e.kind(),
        std::io::ErrorKind::TimedOut,
        "stalled, not closed"
    );
    assert!(begun.elapsed() >= Duration::from_millis(390));
    l.close();
    t.join().unwrap();
}

/// The drivers agree on the wire: a blocking client on a tokio listener's Establish and a
/// tokio client on a blocking one's.
#[test]
fn drivers_interoperate() {
    // Tokio client, blocking server.
    let (l, addr, t) = serving(
        Some(server(keys().psk).blocking_transform()),
        ListenerConfig::default(),
    );
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let c = rt.block_on(async {
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (p, _) = establish(zmux::PipeIo::from_tcp(tcp), &client_config())
            .await
            .unwrap();
        zmux::Session::connect(p, config()).await.unwrap()
    });
    let s = l
        .accept_timeout(Duration::from_secs(5))
        .ok()
        .flatten()
        .expect("a session");
    let (mut sw, mut sr) = {
        let (cw, cr) = rt.block_on(async {
            let (mut w, r) = c.open_bi().await.unwrap();
            w.write_all(b"hi").await.unwrap();
            w.finish().unwrap();
            (w, r)
        });
        std::mem::forget((cw, cr));
        s.accept_bi().unwrap()
    };
    assert_eq!(sr.read_to_end(16).unwrap(), b"hi");
    sw.finish().unwrap();
    rt.block_on(c.close());
    l.close();
    t.join().unwrap();
    // Blocking client, tokio server.
    let mut lc = ListenerConfig::default();
    lc.inbound_transform = Some(server(keys().psk).transform());
    let tl = zmux::Listener::new(config(), lc).expect("valid listener configuration");
    let addr = rt.block_on(async {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = tcp.local_addr().unwrap();
        tokio::spawn(tl.clone().serve(tcp));
        a
    });
    let (p, _) = blocking_establish(addr).unwrap();
    let c = blocking::Session::connect(p, config()).unwrap();
    let s = rt.block_on(tl.accept()).unwrap();
    assert_eq!(s.weakest_record_mode(), RecordMode::Sealed);
    c.close();
    tl.close();
    drop(s);
}

/// A shaper's wait ends with the handshake's timeout, with a closer to shut the carrier and
/// without one.
#[test]
fn a_shaper_wait_ends_with_the_timeout() {
    let shaper = zmux::shaping::HandshakeShaper::new(|_| {
        Some(zmux::shaping::UnitPlan::new(0, 0, 0).with_delay(Duration::from_secs(60)))
    });
    let mut cfg = client_config();
    cfg.shaper = Some(shaper.clone());
    // The carrier has a closer: the watchdog shuts it during the wait.
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let carrier = TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
    let began = Instant::now();
    let r = zmux_seal::blocking::establish(
        PipeIo::from_tcp(carrier),
        &cfg,
        Some(Duration::from_millis(100)),
    );
    assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert!(began.elapsed() < Duration::from_secs(10));
    // Without a closer: the wait is cut at the timeout, and the write that follows fails
    // (a pair of Unix sockets with one end dropped fails the write at once).
    #[cfg(unix)]
    {
        let (x, y) = std::os::unix::net::UnixStream::pair().unwrap();
        drop(y);
        let x2 = x.try_clone().unwrap();
        let began = Instant::now();
        let r = zmux_seal::blocking::establish(
            PipeIo::from_halves(x, x2),
            &cfg,
            Some(Duration::from_millis(100)),
        );
        assert!(r.is_err());
        assert!(began.elapsed() < Duration::from_secs(10));
    }
}
