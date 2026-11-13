//! A split bootstrap through the listener: an
//! uplink and a downlink carrier paired by their token, in either order;
//! a third carrier with the token, two of one direction, and a half whose
//! partner never comes are refused.

use std::time::Duration;

use tokio::io::{DuplexStream, duplex};
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
    let a = tokio::spawn(async move { l1.handle_pipe(first, hint()).await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let b = tokio::spawn(async move { l2.handle_pipe(second, hint()).await });
    let session = Session::connect(client, Config::default()).await.unwrap();
    let server = listener.accept().await.unwrap();
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
    // Both halves' handlers end with the session.
    assert!(a.await.unwrap().is_ok());
    assert!(b.await.unwrap().is_ok());
    // The two halves are one pipe input.
    let st = listener.stats();
    assert_eq!(
        (st.sessions, st.joins, st.rejected, st.refused, st.timed_out),
        (1, 0, 0, 0, 0)
    );
    listener.close();
}

#[tokio::test]
async fn uplink_first() {
    tokio::time::timeout(Duration::from_secs(20), run(false))
        .await
        .unwrap();
}

#[tokio::test]
async fn downlink_first() {
    tokio::time::timeout(Duration::from_secs(20), run(true))
        .await
        .unwrap();
}

#[tokio::test]
async fn bad_pairs_are_refused() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let mut limits = ListenerConfig::default();
        limits.handshake_timeout = Duration::from_millis(300);
        let listener =
            Listener::new(Config::default(), limits).expect("valid listener configuration");
        // Two downlinks with one token: the second is refused, the first
        // times out without a partner.
        let (a, _ka) = duplex(64);
        let (b, _kb) = duplex(64);
        let (l1, l2) = (listener.clone(), listener.clone());
        let first = tokio::spawn(async move { l1.handle_pipe(PipeIo::writer(a), hint()).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        let second = l2.handle_pipe(PipeIo::writer(b), hint()).await;
        assert_eq!(second, Err(HandleError::Rejected));
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
        limits.first_record_timeout = Duration::from_millis(100);
        let l = Listener::new(Config::default(), limits).expect("valid listener configuration");
        let (e, _ke) = duplex(64);
        let (er, _) = tokio::io::split(e);
        let (g, _kg) = duplex(64);
        let late = l.clone();
        let lone = tokio::spawn(async move { late.handle_pipe(PipeIo::reader(er), hint()).await });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!lone.is_finished(), "a lone half waits for its partner");
        let _ = l.handle_pipe(PipeIo::writer(g), hint()).await;
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
