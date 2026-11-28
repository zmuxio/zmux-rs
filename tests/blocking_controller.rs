//! Native controller ownership without an asynchronous runtime.
#![cfg(feature = "blocking")]

use std::net::{TcpListener, TcpStream};
use std::sync::Mutex;
use std::time::Duration;
use zmux::blocking::{Candidate, ControllerOptions, Listener, PipeIo, SessionController};
use zmux::{
    CarrierKind, ClockDomain, Config, ControllerError, Directions, GroupTarget, MemberQuota,
    MonotonicClock, PipeAuth, SessionTarget, TargetCandidate,
};

#[path = "common/clock.rs"]
mod clock;

#[test]
fn native_controller_opens_transfers_and_releases() {
    let (clock, domain) = clock::ManualClock::domain(Duration::ZERO);
    let mut config = Config::default();
    config.session_policy.limits.steady_attachments = 4;
    config.pipe_auth = PipeAuth::psk([42; 32]).with_end_to_end();
    config.clock_domain = domain.clone();
    let socket = TcpListener::bind("127.0.0.1:0").unwrap();
    let outgoing = Mutex::new(Some(
        TcpStream::connect(socket.local_addr().unwrap()).unwrap(),
    ));
    let peer_io = socket.accept().unwrap().0;
    let listener = Listener::new(config.clone(), zmux::ListenerConfig::default(), None).unwrap();
    let acceptor = listener.clone();
    let handler = std::thread::spawn(move || {
        acceptor.handle_pipe(
            PipeIo::from_tcp(peer_io),
            zmux::blocking::PipeHint::default(),
        )
    });
    let candidate = Candidate::new(CarrierKind::WebSocket, move || {
        Ok(PipeIo::from_tcp(
            outgoing.lock().unwrap().take().expect("one bootstrap"),
        ))
    })
    .with_identity("primary", "uplink");
    let make_controller = |name: &str| {
        let mut opts = ControllerOptions::new(name, vec![candidate.clone()]);
        opts.clock_domain = domain.clone();
        SessionController::new(opts).unwrap()
    };
    let first = make_controller("native-first");
    let next = make_controller("native-next");
    let target = SessionTarget {
        revision: 1,
        groups: vec![GroupTarget {
            id: "active".into(),
            quotas: vec![MemberQuota {
                id: "both".into(),
                count: 1,
                directions: Directions::BOTH,
                candidates: vec![TargetCandidate {
                    id: "primary".into(),
                    send: None,
                    receive: None,
                }],
            }],
            rotation: zmux::RotationPolicy::default(),
        }],
        ..SessionTarget::default()
    };
    let (session, old) = first.open(config, target.clone()).unwrap();
    let old = old.unwrap();
    let peer = listener.accept().unwrap();
    handler.join().unwrap().unwrap();
    let successor = next.take_over(&old, target.clone()).unwrap();
    assert_eq!(
        successor.snapshot().predecessor,
        Some(old.snapshot().generation)
    );
    assert!(matches!(old.release(), Err(ControllerError::StaleBinding)));
    old.done_blocking().unwrap();
    clock.advance(Duration::from_millis(1));
    successor.release().unwrap();
    successor.done_blocking().unwrap();
    let managed = next.manage(&session, target).unwrap();
    assert!(managed.snapshot().generation > successor.snapshot().generation);
    managed.release().unwrap();
    first.close();
    next.close();
    first.done_blocking().unwrap();
    next.done_blocking().unwrap();
    session.abort(zmux::VarInt::ZERO, b"");
    peer.abort(zmux::VarInt::ZERO, b"");
    listener.close();
}

#[test]
fn native_open_timeout_keeps_the_key_until_host_return() {
    use std::sync::mpsc;
    let (clock, domain) = clock::ManualClock::domain(Duration::ZERO);
    let mut cache_options = zmux::CarrierCacheConfig::default();
    cache_options.clock_domain = domain.clone();
    let cache = zmux::CarrierCache::new(cache_options).unwrap();
    let (entered, started) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let released = Mutex::new(released);
    let kind = CarrierKind::WebSocket;
    let candidate = Candidate::new(kind, move || {
        entered.send(()).unwrap();
        released.lock().unwrap().recv().unwrap();
        Err(std::io::Error::other("cancelled host returned"))
    })
    .with_identity("primary", "uplink");
    let mut options = ControllerOptions::new("native-timeout", vec![candidate]);
    options.clock_domain = domain;
    options.cache = Some(cache.clone());
    options.limits.attempt_timeout = Duration::from_secs(3);
    let controller = SessionController::new(options).unwrap();
    let host = controller.clone();
    let opening =
        std::thread::spawn(move || host.open(Config::default(), SessionTarget::default()));
    started.recv().unwrap();
    clock.advance(Duration::from_secs(3));
    assert!(opening.join().unwrap().is_err());
    assert_eq!(
        cache.retry_admission("uplink", kind, ""),
        Err(zmux::RetryAdmission::AlreadyInFlight)
    );
    release.send(()).unwrap();
    controller.close();
    controller.done_blocking().unwrap();
    assert_eq!(
        cache.retry_admission("uplink", kind, ""),
        Err(zmux::RetryAdmission::Cooling)
    );
}
