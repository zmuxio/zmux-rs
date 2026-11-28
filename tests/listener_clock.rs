//! Listener protocol deadlines are driven by the injected clock.

#[path = "common/clock.rs"]
mod clock;

use std::future::poll_fn;
use std::pin::pin;
use std::task::Poll;
use std::time::Duration;

use clock::ManualClock;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use zmux::{
    Admission, AdmissionVerdict, Config, Fallback, Listener, ListenerConfig, PipeHint, PipeIo,
    Takeover,
};
use zmux::{ClockDomain, MonotonicClock};

#[tokio::test]
async fn peek_timeout_replays_the_partial_prefix_to_fallback() {
    tokio::time::timeout(Duration::from_secs(30), async {
        let wait = Duration::from_secs(65);
        let (clock, domain) = ManualClock::domain(Duration::from_secs(120));
        let mut timers = clock.registrations();
        let deadline = domain.now() + wait;
        let (replayed, mut received) = tokio::sync::mpsc::unbounded_channel();
        let admission = Admission::new(4, |_, _| -> AdmissionVerdict {
            panic!("a partial prefix must not reach the decider")
        })
        .with_peek_timeout(wait)
        .with_fallback_on_peek_timeout(true);
        let mut limits = ListenerConfig::default();
        limits.admission = Some(admission);
        limits.fallback = Some(Fallback::new(move |takeover: Takeover| {
            let replayed = replayed.clone();
            async move {
                let mut stream = takeover.into_pipe().into_stream();
                let mut prefix = [0; 2];
                stream.read_exact(&mut prefix).await.unwrap();
                replayed.send(prefix).unwrap();
            }
        }));
        let mut config = Config::default();
        config.clock_domain = domain;
        let listener = Listener::new(config, limits).unwrap();
        let (mut peer, carrier) = duplex(64);
        peer.write_all(b"ab").await.unwrap();
        let mut setup = pin!(listener.handle_pipe(PipeIo::new(carrier), PipeHint::default()));
        assert!(poll_fn(|cx| Poll::Ready(setup.as_mut().poll(cx).is_pending())).await);
        assert_eq!(timers.recv().await.unwrap(), deadline);

        let tick = Duration::from_nanos(1);
        clock.advance(wait.checked_sub(tick).unwrap());
        assert!(poll_fn(|cx| Poll::Ready(setup.as_mut().poll(cx).is_pending())).await);
        assert!(timers.try_recv().is_err());
        assert!(received.try_recv().is_err());

        clock.advance(tick);
        assert_eq!(setup.await, Ok(()));
        assert_eq!(&received.recv().await.unwrap(), b"ab");
        assert_eq!(listener.stats().admission.fallback, 1);
    })
    .await
    .expect("peek timeout test watchdog");
}

#[cfg(unix)]
#[tokio::test]
async fn blocking_listener_interrupts_carrier_io_on_its_clock() {
    use std::os::unix::net::UnixStream;
    use zmux::blocking as b;

    let wait = Duration::from_secs(80);
    let (clock, domain) = ManualClock::domain(Duration::from_secs(120));
    let mut timers = clock.registrations();
    let deadline = domain.now() + wait;
    let mut config = Config::default();
    config.clock_domain = domain;
    let mut limits = ListenerConfig::default();
    limits.limits.first_record_timeout = wait;
    let listener = b::Listener::new(config, limits, None).unwrap();
    let (_peer, carrier) = UnixStream::pair().unwrap();
    let reader = carrier.try_clone().unwrap();
    let interrupt = carrier.try_clone().unwrap();
    let pipe = b::PipeIo::from_halves(reader, carrier).with_closer(move |how| {
        let _ = interrupt.shutdown(how);
    });
    let (done, result) = tokio::sync::oneshot::channel();
    let accepting = listener.clone();
    let thread = std::thread::spawn(move || {
        let _ = done.send(accepting.handle_pipe(pipe, b::PipeHint::default()));
    });
    let handled = tokio::time::timeout(Duration::from_secs(30), async {
        while timers.recv().await.unwrap() != deadline {}
        clock.advance(wait);
        result.await.unwrap()
    })
    .await;
    listener.close();
    thread.join().unwrap();
    assert_eq!(handled.unwrap(), Err(zmux::HandleError::TimedOut));
    assert_eq!(listener.stats().timed_out, 1);
}
