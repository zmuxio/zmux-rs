//! Joins on message carriers: a Join in each record mode to a server that runs Establish,
//! a failover to the joined pipe, and a Hello whose first batch is larger than a byte
//! carrier's first read.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::time::timeout;
use zmux::proto::seal::Mode;
use zmux::proto::session::AllowRecordMode;
use zmux::{
    AdmittedValue, Config, Listener, ListenerConfig, PipeAuth, PipeId, PipeOptions, Session,
};
use zmux_seal::{
    BoxFuture, ClientConfig, Gate, PinVerifier, ServerConfig, VerifyError, derive_handle_psk,
    establish, key_id,
};

const NODE: [u8; 32] = [0x11; 32];
const LIMIT: Duration = Duration::from_secs(20);

struct OneKey(Vec<u8>);

impl Gate for OneKey {
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
    ) -> BoxFuture<'a, Result<Option<zmux_seal::Credential>, VerifyError>> {
        Box::pin(async { Ok(None) })
    }
    fn commit<'a>(
        &'a self,
        _: zmux_seal::Admission<'a>,
        _: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<AdmittedValue, VerifyError>> {
        Box::pin(async { Ok(Arc::new("client") as AdmittedValue) })
    }
}

fn config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.resume_timeout = Some(LIMIT);
    c.pipe_auth = PipeAuth::none();
    c.allow_record_mode = Some(AllowRecordMode(Arc::new(|_, _, _| true)));
    c
}

/// A session over Establish on a WebSocket, and the server's end of it.
async fn established(url: &str, listener: &Listener) -> (Session, Session) {
    let keys = derive_handle_psk(&[9; 32], b"tests", b"").unwrap();
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(NODE));
    let client = ClientConfig {
        verifier: Some(Arc::new(PinVerifier::new(key_id(1, public.as_bytes())))),
        handle: keys.handle,
        psk: keys.psk,
        ..Default::default()
    };
    let io = zmux_websocket::dial(url, &Default::default())
        .await
        .unwrap();
    let (io, _) = establish(io, &client).await.unwrap();
    let session = Session::connect(io, config()).await.unwrap();
    (session, listener.accept().await.unwrap())
}

/// `data` to the server and back, the server reading all of it first.
async fn echo(client: &Session, server: &Session, data: &[u8]) {
    let (mut send, mut recv) = client.open_bi().await.unwrap();
    let written = {
        let data = data.to_vec();
        tokio::spawn(async move {
            send.write_all(&data).await.unwrap();
            send.finish().unwrap();
            send
        })
    };
    let (mut s, mut r) = server.accept_bi().await.unwrap();
    let got = r.read_to_end(1 << 24).await.unwrap();
    assert_eq!(got, data);
    s.write_all(&got).await.unwrap();
    s.finish().unwrap();
    assert_eq!(recv.read_to_end(1 << 24).await.unwrap(), data);
    drop((s, r, written.await.unwrap()));
}

/// Over a server with Establish, a joined pipe carries the session once the first is
/// aborted, whichever way the Join's Confirm travels.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_joined_pipe_takes_over_after_the_first_is_aborted() {
    for mode in [Mode::Sealed, Mode::Trusted] {
        let keys = derive_handle_psk(&[9; 32], b"tests", b"").unwrap();
        let mut limits = ListenerConfig::default();
        limits.inbound_transform = Some(
            ServerConfig::new(
                Arc::new(OneKey(keys.psk)),
                NODE,
                zmux_seal::ServerOptions {
                    allow_record_mode: None,
                    shaper: None,
                    shaping_limits: None,
                    ..Default::default()
                },
            )
            .expect("valid server configuration")
            .transform(),
        );
        let listener = Listener::new(config(), limits).expect("valid listener configuration");
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}/zmux", tcp.local_addr().unwrap());
        let serving = tokio::spawn(zmux_websocket::serve(
            listener.clone(),
            tcp,
            Default::default(),
        ));
        timeout(LIMIT, async {
            let (client, server) = established(&url, &listener).await;
            let io = zmux_websocket::dial(url.as_str(), &Default::default())
                .await
                .unwrap();
            let pipe = client
                .begin_add_pipe(io, PipeOptions::new().with_mode(mode))
                .unwrap();
            pipe.joined().await.unwrap();
            client.pipe(PipeId::new(0)).unwrap().abort().unwrap();
            echo(&client, &server, &[5; 128 << 10]).await;
            assert_eq!(listener.stats().joins, 1, "{mode:?}");
            assert_eq!(listener.stats().rejected, 0, "{mode:?}");
            client.close(0u32.into(), b"").await;
        })
        .await
        .unwrap_or_else(|_| panic!("{mode:?} within the limit"));
        listener.close();
        serving.abort();
    }
}

/// A Hello holding a first batch of more than 16 KiB arrives as one message, and a listener
/// without a transform reads it whole.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_first_message_is_read_whole() {
    let mut config = Config::default();
    config.max_pipes = 4;
    config.resume_timeout = Some(LIMIT);
    config.pipe_auth = PipeAuth::psk(vec![7u8; 32]).with_end_to_end();
    config.allow_record_mode = Some(AllowRecordMode(Arc::new(|_, _, _| true)));
    let listener = Listener::new(config.clone(), ListenerConfig::default())
        .expect("valid listener configuration");
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/zmux", tcp.local_addr().unwrap());
    let serving = tokio::spawn(zmux_websocket::serve(
        listener.clone(),
        tcp,
        Default::default(),
    ));
    let mut joining = config.clone();
    joining.join_early_hello = Some(32 << 10);
    timeout(LIMIT, async {
        let client = zmux_websocket::connect(url.as_str(), &Default::default(), joining)
            .await
            .unwrap();
        let server = listener.accept().await.unwrap();
        let pipe = client.pipe(PipeId::new(0)).unwrap();
        // Data waits for a pipe, so that the Hello takes it.
        let (mut a, mut b) = client.open_bi().await.unwrap();
        pipe.abort().unwrap();
        a.write_all(&[3; 24 << 10]).await.unwrap();
        a.finish().unwrap();
        let io = zmux_websocket::dial(url.as_str(), &Default::default())
            .await
            .unwrap();
        client
            .begin_add_pipe(io, PipeOptions::new().with_mode(Mode::Sealed))
            .unwrap()
            .joined()
            .await
            .unwrap();
        let (mut s, mut r) = server.accept_bi().await.unwrap();
        assert_eq!(r.read_to_end(1 << 20).await.unwrap().len(), 24 << 10);
        s.finish().unwrap();
        assert!(b.read_to_end(16).await.unwrap().is_empty());
        client.close(0u32.into(), b"").await;
    })
    .await
    .expect("within the limit");
    listener.close();
    serving.abort();
}
