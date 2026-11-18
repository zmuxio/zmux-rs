//! `serve_connection` hands one established connection to a listener
//! without holding its caller beyond the connection: a connection refused
//! at a limit is closed, counted and the call succeeds; a closed listener
//! fails the call with `NotConnected`; the call resolves when the connection
//! ends; dropping it stops the delivery of streams and leaves the connection.

#![allow(
    clippy::many_single_char_names,
    reason = "c, s, l and o name the client and server connection, listener and options throughout"
)]

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use zmux::{Admission, AdmissionVerdict, Config, Listener, ListenerConfig, Session};
use zmux_quinn::{Carrier, Options, serve_connection};

const LIMIT: Duration = Duration::from_secs(20);

struct Rig {
    server: quinn::Endpoint,
    client: quinn::Endpoint,
    addr: std::net::SocketAddr,
    listener: Listener,
    opts: Options,
}

impl Rig {
    fn new(admission: Option<Admission>, per_source: usize) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = zmux_testcert::self_signed(vec!["localhost".into()]).unwrap();
        let der = CertificateDer::from(cert.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
        let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![der.clone()], key)
            .unwrap();
        tls.alpn_protocols = zmux::alpn_protocols(&[]);
        let opts = Options::default();
        let server = quinn::Endpoint::server(
            zmux_quinn::server_config(tls, &opts).unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let addr = server.local_addr().unwrap();
        let mut lc = ListenerConfig::default();
        lc.admission = admission;
        lc.max_pending_per_source = per_source;
        let listener = Listener::new(Config::default(), lc).expect("valid listener configuration");
        let mut roots = rustls::RootCertStore::empty();
        roots.add(der).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = zmux::alpn_protocols(&[]);
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(zmux_quinn::client_config(tls, &opts).unwrap());
        Self {
            server,
            client,
            addr,
            listener,
            opts,
        }
    }

    /// A connection: the client's and the server's side of it.
    async fn connect(&self) -> (quinn::Connection, quinn::Connection) {
        let connecting = self.client.connect(self.addr, "localhost").unwrap();
        let incoming = self.server.accept().await.unwrap();
        let (c, s) = tokio::join!(connecting, incoming);
        (c.unwrap(), s.unwrap())
    }
}

/// A listener at a limit closes the connection, counts it as refused and
/// the call succeeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_refused_at_a_limit_is_closed_counted_and_ok() {
    // The source's two slots, held by entries of the same source.
    let admission = Admission::new(4, |_, _| AdmissionVerdict::Close);
    let rig = Rig::new(Some(admission), 2);
    let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let _held = [
        rig.listener.adapter().enter(peer, None).unwrap(),
        rig.listener.adapter().enter(peer, None).unwrap(),
    ];
    assert_eq!(rig.listener.stats().refused, 0);
    let (c, s) = rig.connect().await;
    let r = tokio::time::timeout(LIMIT, serve_connection(&rig.listener, s, &rig.opts, None))
        .await
        .expect("the refused connection ends the call");
    r.expect("refused at a limit is not an error");
    tokio::time::timeout(LIMIT, c.closed()).await.unwrap();
    assert_eq!(rig.listener.stats().refused, 1);
}

/// A closed listener closes the connection and fails the call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_listener_fails_the_call_with_not_connected() {
    let rig = Rig::new(None, 8);
    let (c, s) = rig.connect().await;
    rig.listener.close();
    let r = serve_connection(&rig.listener, s, &rig.opts, None).await;
    assert_eq!(r.unwrap_err().kind(), std::io::ErrorKind::NotConnected);
    tokio::time::timeout(LIMIT, c.closed()).await.unwrap();
}

/// The call resolves when the connection ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_call_resolves_when_the_connection_ends() {
    let rig = Rig::new(None, 8);
    let (c, s) = rig.connect().await;
    let (l, o) = (rig.listener.clone(), rig.opts.clone());
    let call = tokio::spawn(async move { serve_connection(&l, s, &o, None).await });
    c.close(0u32.into(), b"");
    tokio::time::timeout(LIMIT, call)
        .await
        .expect("resolves with the connection")
        .unwrap()
        .unwrap();
}

/// Dropping the call stops handing streams to the listener; the connection
/// and the session it carried go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_call_stops_the_delivery_and_keeps_the_connection() {
    let rig = Rig::new(None, 8);
    let (c, s) = rig.connect().await;
    let (l, o) = (rig.listener.clone(), rig.opts.clone());
    let call = tokio::spawn(async move { serve_connection(&l, s, &o, None).await });
    let carrier = Carrier::new(c.clone(), Options::default());
    let client = Session::connect(carrier.open_pipe().await.unwrap(), Config::default())
        .await
        .unwrap();
    let accepted = tokio::time::timeout(LIMIT, rig.listener.accept())
        .await
        .unwrap()
        .unwrap();
    call.abort();
    let _ = call.await;
    // The session of the connection goes on.
    let (mut send, _r) = client.open_bi().await.unwrap();
    send.write_all(b"x").await.unwrap();
    let (_s, mut recv) = accepted.accept_bi().await.unwrap();
    let mut b = [0u8; 1];
    recv.read_exact(&mut b).await.unwrap();
    // A further session on the connection is not delivered: nobody
    // answers its pipe.
    assert!(c.close_reason().is_none());
    let stray = carrier.open_pipe().await.unwrap();
    let r = tokio::time::timeout(
        Duration::from_millis(300),
        Session::connect(stray, Config::default()),
    )
    .await;
    assert!(r.is_err(), "no listener took the pipe");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), rig.listener.accept())
            .await
            .is_err()
    );
}
