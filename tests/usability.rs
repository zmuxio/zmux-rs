//! The configuration rules of the usability revision: secret sources, bounds, join
//! timeout, and the warning of a resume nothing redials.

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{connect, duplex};
use zmux::proto::seal::Mode;
use zmux::{
    Cap, Config, ConnectError, Listener, ListenerConfig, LogLevel, Logger, PipeAuth, PipeIo,
    Session, SessionEvent,
};

const PSK: [u8; 32] = *b"a pre-shared key of 32 bytes....";

fn invalid(r: Result<Session, ConnectError>) -> &'static str {
    match r {
        Err(ConnectError::InvalidConfig(why)) => why,
        Err(e) => panic!("{e}"),
        Ok(_) => panic!("a session"),
    }
}

async fn connect_alone(pipe: PipeIo, mut c: Config) -> Result<Session, ConnectError> {
    c.handshake_timeout = Some(Duration::from_millis(300));
    tokio::time::timeout(Duration::from_secs(5), Session::connect(pipe, c))
        .await
        .expect("in time")
}

/// Multipath or resume without a secret source fails before a byte; EndToEnd is no source.
#[tokio::test]
async fn no_secret_source_is_a_configuration_error() {
    for auth in [PipeAuth::none(), PipeAuth::none().with_end_to_end()] {
        let mut c = Config::multipath(auth.clone());
        let ((a, _), _b) = duplex(1 << 16);
        assert!(invalid(connect_alone(a, c.clone()).await).contains("secret source"));
        c.max_pipes = 1;
        c.resume_timeout = Some(Duration::from_secs(5));
        let ((a, _), _b) = duplex(1 << 16);
        assert!(invalid(connect_alone(a, c).await).contains("secret source"));
    }
}

/// On a secure first pipe the carrier is the source: any other is a configuration error,
/// and EndToEnd is accepted.
#[tokio::test]
async fn a_secure_first_pipe_takes_no_other_source() {
    for auth in [
        PipeAuth::psk(PSK),
        PipeAuth::deferred_psk(),
        PipeAuth::exporter(),
    ] {
        let ((a, _), _b) = duplex(1 << 16);
        let a = a.with_secure_first_pipe(Mode::Sealed);
        invalid(connect_alone(a, Config::multipath(auth)).await);
    }
    let ((a, _), _b) = duplex(1 << 16);
    let a = a.with_secure_first_pipe(Mode::Sealed);
    let r = connect_alone(a, Config::multipath(PipeAuth::none().with_end_to_end())).await;
    assert!(
        !matches!(r, Err(ConnectError::InvalidConfig(_)) | Ok(_)),
        "{r:?}"
    );
}

/// Out of range is an error, never corrected.
#[tokio::test]
async fn bounds_are_errors() {
    type Case = (&'static str, fn(&mut Config));
    let cases: [Case; 5] = [
        ("send_buffer_max", |c| {
            c.send_buffer_max = Cap::Fixed(c.send_buffer - 1)
        }),
        ("join_timeout", |c| c.join_timeout = Duration::ZERO),
        ("redial_min_backoff", |c| {
            c.redial_min_backoff = c.redial_max_backoff + Duration::from_secs(1);
        }),
        ("resume_timeout", |c| {
            c.pipe_auth = PipeAuth::psk(PSK);
            c.resume_timeout = Some(Duration::ZERO);
        }),
        ("replay_window", |c| {
            c.pipe_auth = PipeAuth::psk(PSK);
            c.max_pipes = 8;
            c.replay_window = Some(15);
        }),
    ];
    for (name, f) in cases {
        let mut c = Config::default();
        f(&mut c);
        let ((a, _), _b) = duplex(1 << 16);
        assert!(
            invalid(connect_alone(a, c.clone()).await).contains(name),
            "{name}"
        );
        assert!(
            Listener::new(c, ListenerConfig::default()).is_err(),
            "{name}"
        );
    }
    let mut limits = ListenerConfig::default();
    limits.instance_id = vec![0; 9];
    assert!(Listener::new(Config::default(), limits).is_err());
}

/// Without a listener, an accepting or symmetric session cannot resume.
#[tokio::test]
async fn resume_needs_a_listener_to_accept() {
    let mut c = Config::default();
    c.pipe_auth = PipeAuth::psk(PSK);
    c.resume_timeout = Some(Duration::from_secs(5));
    let ((a, _), (b, _)) = duplex(1 << 16);
    invalid(Session::accept(a, c.clone()).await);
    invalid(Session::peer(b, c).await);
}

type Logs = Arc<Mutex<Vec<(LogLevel, String)>>>;

fn logged() -> (Logs, Logger) {
    let logs: Logs = Arc::default();
    let l = logs.clone();
    (
        logs,
        Logger::new(move |level, m| l.lock().unwrap().push((level, m.to_owned()))),
    )
}

/// A suspension that nothing will redial is reported and logged; with a redial hook it is
/// not, and the hook's carrier resumes the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_suspension_without_a_redial_source_is_reported() {
    for hooked in [false, true] {
        let (logs, logger) = logged();
        let mut server = Config::default();
        server.pipe_auth = PipeAuth::psk(PSK).with_end_to_end();
        server.resume_timeout = Some(Duration::from_secs(10));
        let listener = Listener::new(server, ListenerConfig::default()).unwrap();
        let mut client = Config::default();
        client.pipe_auth = PipeAuth::psk(PSK).with_end_to_end();
        client.resume_timeout = Some(Duration::from_secs(10));
        client.redial_min_backoff = Duration::from_millis(50);
        client.logger = Some(logger);
        if hooked {
            let l = listener.clone();
            client.redial = Some(zmux::Dial::new(move |_| {
                let l = l.clone();
                async move {
                    let ((a, _), (b, _)) = duplex(1 << 16);
                    tokio::spawn(async move { l.handle_pipe(b, Default::default()).await });
                    Ok(a)
                }
            }));
        }
        let ((a, ca), (b, _cb)) = duplex(1 << 16);
        let l = listener.clone();
        tokio::spawn(async move { l.handle_pipe(b, Default::default()).await });
        let c = Session::connect(a, client).await.unwrap();
        let _s = listener.accept().await.unwrap();
        ca.fail();
        let mut seen = Vec::new();
        let r = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(e) = c.next_event().await {
                let done = matches!(
                    e,
                    SessionEvent::ResumeUnattended | SessionEvent::SessionResumed
                );
                seen.push(e);
                if done {
                    break;
                }
            }
        })
        .await;
        assert!(r.is_ok(), "{seen:?}");
        let unattended = seen
            .iter()
            .any(|e| matches!(e, SessionEvent::ResumeUnattended));
        assert_eq!(unattended, !hooked, "{seen:?}");
        assert!(
            seen.iter()
                .any(|e| matches!(e, SessionEvent::SessionSuspended))
        );
        // The logger runs after the session's lock, so it may follow the event.
        let warned = || {
            logs.lock()
                .unwrap()
                .iter()
                .any(|(l, m)| *l == LogLevel::Warn && m.contains("redial"))
        };
        if !hooked {
            for _ in 0..200 {
                if warned() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        assert_eq!(warned(), !hooked);
        c.close(0u32.into(), b"").await;
        listener.close();
    }
}

/// Removing the last pipe while streams are open is logged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removing_the_last_pipe_with_open_streams_is_logged() {
    let (logs, logger) = logged();
    let mut c = Config::multipath(PipeAuth::psk(PSK));
    c.logger = Some(logger);
    let ((a, _), (b, _)) = duplex(1 << 16);
    let (client, _server) = connect(a, b, c.clone(), c).await;
    let (_s, _r) = client.open_bi().await.unwrap();
    client.pipes()[0].abort().unwrap();
    assert!(
        logs.lock()
            .unwrap()
            .iter()
            .any(|(l, m)| *l == LogLevel::Warn && m.contains("streams are open"))
    );
}
