//! The source of a TCP connection from a trusted intermediary is the
//! client its PROXY protocol header reports.

use std::time::Duration;

use tokio::io::{AsyncWriteExt, duplex};
use zmux::TrustedProxies;

#[tokio::test]
async fn proxy_protocol_source() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let trusted = TrustedProxies::new()
            .with_net("127.0.0.0/8".parse().unwrap())
            .with_proxy_protocol(true);
        let peer = "127.0.0.1:9".parse().unwrap();
        let (mut a, mut b) = duplex(256);
        a.write_all(b"PROXY TCP4 198.51.100.7 10.0.0.1 4000 443\r\nhello")
            .await
            .unwrap();
        let source = zmux::adapter::proxied_source(&mut b, peer, &trusted)
            .await
            .unwrap();
        assert_eq!(source.to_string(), "198.51.100.7:4000");
        // Nothing after the header was read.
        let mut rest = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut b, &mut rest)
            .await
            .unwrap();
        assert_eq!(&rest, b"hello");
        // An untrusted peer's header is not read: it is the peer's data.
        let other = "192.0.2.9:9".parse().unwrap();
        assert_eq!(
            zmux::adapter::proxied_source(&mut b, other, &trusted)
                .await
                .unwrap(),
            other
        );
        // A trusted peer without a header is an error.
        a.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        assert!(
            zmux::adapter::proxied_source(&mut b, peer, &trusted)
                .await
                .is_err()
        );
    })
    .await
    .unwrap();
}

/// An admitted TCP listener reads the PROXY protocol header of a trusted
/// intermediary before its admission, which sees the client reported;
/// from an untrusted peer the source is the peer itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admitted_tcp_reads_the_proxy_header() {
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    tokio::time::timeout(Duration::from_secs(10), async {
        for (net, expect) in [("127.0.0.0/8", "198.51.100.7:4000"), ("10.0.0.0/8", "")] {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<SocketAddr>();
            let tx = Arc::new(Mutex::new(tx));
            let admission = zmux::Admission::new(0, move |info, _| {
                let _ = tx.lock().unwrap().send(info.source.unwrap());
                zmux::AdmissionVerdict::Close
            });
            let mut limits = zmux::ListenerConfig::default();
            limits.trusted_proxies = TrustedProxies::new()
                .with_net(net.parse().unwrap())
                .with_proxy_protocol(true);
            limits.admission = Some(admission);
            let listener = zmux::Listener::new(zmux::Config::default(), limits)
                .expect("valid listener configuration");
            let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = tcp.local_addr().unwrap();
            let serving = tokio::spawn(listener.clone().serve(tcp));
            let mut conn = tokio::net::TcpStream::connect(addr).await.unwrap();
            conn.write_all(b"PROXY TCP4 198.51.100.7 10.0.0.1 4000 443\r\n")
                .await
                .unwrap();
            let seen = rx.recv().await.unwrap();
            if expect.is_empty() {
                assert_eq!(seen, conn.local_addr().unwrap(), "trusting {net}");
            } else {
                assert_eq!(seen.to_string(), expect, "trusting {net}");
            }
            listener.close();
            serving.abort();
        }
    })
    .await
    .unwrap();
}
