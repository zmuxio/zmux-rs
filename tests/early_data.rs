//! The bootstrap carrier supplies its exporter after its handshake.

mod common;

use common::{duplex, multi_thread, watchdog};
use zmux::{Config, Session};

/// A server carrier that accepted early data: its exporter gives no value
/// until the handshake.
fn exporter_config() -> Config {
    Config::multipath(zmux::PipeAuth::exporter())
}

fn fixed_exporter(_: &str, _: &[u8], out: &mut [u8]) -> bool {
    out.fill(7);
    true
}

/// Serves `io` behind a listener; returns the listener.
fn exporter_server(io: zmux::PipeIo) -> zmux::Listener {
    let l = zmux::Listener::new(exporter_config(), zmux::ListenerConfig::default())
        .expect("valid listener configuration");
    let handler = l.clone();
    tokio::spawn(async move {
        let _ = handler
            .handle_pipe(io, zmux::PipeHint::from_peer(([127, 0, 0, 1], 1).into()))
            .await;
    });
    l
}

/// Parameters that arrive before the handshake gives the exporter wait for
/// it, and only the read path does: the server's own parameters leave.
#[test]
fn parameters_wait_for_the_handshake_that_gives_the_exporter() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    multi_thread(async {
        let ((a, _), (b, _)) = duplex(1 << 20);
        let complete = Arc::new(AtomicBool::new(false));
        let (done, finished) = tokio::sync::watch::channel(false);
        let c2 = complete.clone();
        let listener = exporter_server(
            b.with_exporter(move |_, _, out| {
                c2.load(Ordering::SeqCst) && {
                    out.fill(7);
                    true
                }
            })
            .with_early_data_in(move || {
                let mut finished = finished.clone();
                async move {
                    let _ = finished.wait_for(|d| *d).await;
                }
            }),
        );
        let client = Session::connect(a.with_exporter(fixed_exporter), exporter_config())
            .await
            .unwrap();
        let (mut send, _recv) = client.open_bi().await.unwrap();
        send.write_all(b"early").await.unwrap();
        send.finish().unwrap();
        watchdog(20, "the server's parameters", client.established())
            .await
            .unwrap();
        assert!(
            std::future::poll_fn(|cx| {
                use std::future::Future;
                let mut accepting = std::pin::pin!(listener.accept());
                std::task::Poll::Ready(accepting.as_mut().poll(cx).is_pending())
            })
            .await
        );
        complete.store(true, Ordering::SeqCst);
        done.send_replace(true);
        let server = watchdog(5, "accept", listener.accept()).await.unwrap();
        let (_s, mut r) = watchdog(5, "accept_bi", server.accept_bi()).await.unwrap();
        assert_eq!(r.read_to_end(16).await.unwrap(), b"early");
        client.close().await;
        listener.close();
    });
}

/// A handshake that fails is a carrier failure, no internal error.
#[test]
fn a_failed_handshake_under_the_exporter_wait_is_no_internal_error() {
    multi_thread(async {
        let ((a, _), (b, _)) = duplex(1 << 20);
        let (settle, settled) = tokio::sync::watch::channel(false);
        let listener = exporter_server(b.with_exporter(|_, _, _| false).with_early_data_in(
            move || {
                let mut settled = settled.clone();
                async move {
                    settled.wait_for(|done| *done).await.unwrap();
                }
            },
        ));
        let client = Session::connect(a.with_exporter(fixed_exporter), exporter_config())
            .await
            .unwrap();
        settle.send_replace(true);
        let e = watchdog(20, "closed", client.closing()).await;
        assert!(!format!("{e:?}").contains("xporter"), "{e:?}");
        listener.close();
    });
}
