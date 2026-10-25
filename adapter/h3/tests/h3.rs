//! HTTP/3 request carriers over loopback: one-step `connect` and `serve`
//! with streams both ways and a close the peer sees, client lanes on
//! further requests and a second pipe on another request of the same
//! connection (each pipe a request body paired with its response body),
//! and a lost connection that is a failure of its pipes, never their clean
//! end.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zmux::{
    Config, Listener, ListenerConfig, PipeAuth, PipeFailure, PipeOptions, Session, SessionError,
};
use zmux_h3::{H3Client, Options};

/// A served HTTP/3 endpoint and a client endpoint for it over loopback.
struct H3 {
    client: quinn::Endpoint,
    addr: std::net::SocketAddr,
    uri: http::Uri,
    listener: Listener,
    serving: tokio::task::JoinHandle<()>,
}

impl H3 {
    fn new(config: Config, opts: &Options) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        // The configuration helpers add `h3`.
        let server_config = zmux_h3::server_config(tls, opts).unwrap();
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = server.local_addr().unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let client_config = zmux_h3::client_config(tls, opts).unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(client_config);
        let listener = Listener::new(config, ListenerConfig::default());
        let serving = tokio::spawn(zmux_h3::serve(listener.clone(), server, opts.clone()));
        Self {
            client,
            addr,
            uri: format!("https://127.0.0.1:{}/zmux", addr.port())
                .parse()
                .unwrap(),
            listener,
            serving,
        }
    }

    /// A client of a new connection.
    async fn h3_client(&self, opts: &Options) -> H3Client {
        let conn = self
            .client
            .connect(self.addr, "127.0.0.1")
            .unwrap()
            .await
            .unwrap();
        H3Client::new(conn, self.uri.clone(), opts).await.unwrap()
    }

    async fn stop(self) {
        self.listener.close();
        self.serving.await.unwrap();
    }
}

/// Sends `n` streams of `len` bytes each from `from` to `to` at once and
/// checks every byte.
async fn transfer(from: &Session, to: &Session, n: usize, len: usize) {
    let receiver = {
        let to = to.clone();
        tokio::spawn(async move {
            let mut readers = Vec::new();
            for _ in 0..n {
                let mut recv = to.accept_uni().await.unwrap();
                readers.push(tokio::spawn(async move {
                    recv.read_to_end(len + 1).await.unwrap()
                }));
            }
            for r in readers {
                let data = r.await.unwrap();
                assert_eq!(data.len(), len);
                assert!(data.iter().enumerate().all(|(i, &b)| b == (i % 251) as u8));
            }
        })
    };
    let data = bytes::Bytes::from((0..len).map(|i| (i % 251) as u8).collect::<Vec<_>>());
    let mut writers = Vec::new();
    for _ in 0..n {
        let mut send = from.open_uni().await.unwrap();
        let data = data.clone();
        writers.push(tokio::spawn(async move {
            send.write_chunk(data).await.unwrap();
            send.finish().unwrap();
            send
        }));
    }
    for w in writers {
        drop(w.await.unwrap());
    }
    receiver.await.unwrap();
}

/// One step from an endpoint to a session and from an endpoint to its
/// sessions: streams go both ways over the request body and the response
/// body of one request, and a close reaches the peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connect_and_serve() {
    let opts = Options::default();
    let h3 = H3::new(Config::default(), &opts);
    let client = zmux_h3::connect(
        &h3.client,
        h3.addr,
        h3.uri.clone(),
        &opts,
        Config::default(),
    )
    .await
    .unwrap();
    let server = h3.listener.accept().await.unwrap();
    transfer(&client, &server, 2, 256 << 10).await;
    transfer(&server, &client, 2, 256 << 10).await;
    client.close(0u32.into(), b"bye");
    let e = tokio::time::timeout(Duration::from_secs(10), server.closed())
        .await
        .expect("closed");
    assert!(
        matches!(e, SessionError::ApplicationClosed { remote: true, .. }),
        "{e:?}"
    );
    h3.stop().await;
}

/// The client opens lanes as further requests of its connection, which
/// the listener routes to the pipe; the server, which cannot open
/// requests, keeps its direction on the pipe's own response body. A second
/// pipe on another request of the connection joins the session.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_lanes_and_a_second_pipe_on_further_requests() {
    let opts = Options::default();
    let config = Config::multipath(PipeAuth::psk(*b"zmux-h3-adapter-test-psk-0123456"));
    let h3 = H3::new(config.clone(), &opts);
    let client = h3.h3_client(&opts).await;
    let cs = Session::connect(client.open_pipe().await.unwrap(), config)
        .await
        .unwrap();
    let ss = h3.listener.accept().await.unwrap();
    assert_eq!(cs.multipath(), zmux::Multipath::InUse);
    transfer(&cs, &ss, 8, 1 << 20).await;
    assert!(cs.pipe_stats()[0].lanes_out > 1, "no lane was opened");
    assert!(ss.pipe_stats()[0].lanes_in > 1, "no lane was accepted");
    assert_eq!(ss.pipe_stats()[0].lanes_out, 1, "a server opens no lanes");
    let pipe = cs
        .add_pipe(client.open_pipe().await.unwrap(), PipeOptions::new())
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), pipe.joined())
        .await
        .expect("joined in time")
        .unwrap();
    transfer(&ss, &cs, 4, 256 << 10).await;
    cs.close(0u32.into(), b"");
    h3.stop().await;
}

/// A connection lost under the session is a failure of its pipe at both
/// ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lost_connection_is_a_failure_not_a_clean_end() {
    let opts = Options::default();
    let h3 = H3::new(Config::default(), &opts);
    let client = h3.h3_client(&opts).await;
    let cs = Session::connect(client.open_pipe().await.unwrap(), Config::default())
        .await
        .unwrap();
    let ss = h3.listener.accept().await.unwrap();
    transfer(&cs, &ss, 2, 64 << 10).await;
    client.connection().close(7u32.into(), b"gone");
    for s in [&cs, &ss] {
        let e = tokio::time::timeout(Duration::from_secs(10), s.closed())
            .await
            .expect("ended");
        assert!(
            matches!(
                e,
                SessionError::PipesLost {
                    last: Some(PipeFailure::Carrier(_))
                }
            ),
            "{e:?}"
        );
    }
    h3.stop().await;
}
