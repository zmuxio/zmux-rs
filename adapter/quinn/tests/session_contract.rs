use std::io::{IoSlice, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls;
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use zmux::{MetadataUpdate, OpenOptions};
use zmux_quinn::{QuinnRecvStream, QuinnSession, QuinnStream, SessionOptions};

const APPLICATION_PROTOCOL: &str = "zmux-rust-quinn-session-contract";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_TIMEOUT: Duration = Duration::from_secs(5);
const SHORT_TIMEOUT: Duration = Duration::from_millis(150);
const MAX_DATA: u32 = 2 << 20;

struct Pair {
    client_endpoint: quinn::Endpoint,
    server_endpoint: quinn::Endpoint,
    client_conn: quinn::Connection,
    server_conn: quinn::Connection,
    client: QuinnSession,
    server: QuinnSession,
}

impl Pair {
    async fn new() -> Self {
        Self::new_with_server_options(SessionOptions::default()).await
    }

    async fn new_with_server_options(server_options: SessionOptions) -> Self {
        Self::new_with_server_options_and_max_data(server_options, MAX_DATA).await
    }

    async fn new_with_server_options_and_max_data(
        server_options: SessionOptions,
        max_data: u32,
    ) -> Self {
        let (server_config, cert) = server_config(max_data);
        let server_endpoint = quinn::Endpoint::server(
            server_config,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        )
        .unwrap();
        let server_addr = server_endpoint.local_addr().unwrap();
        let mut client_endpoint =
            quinn::Endpoint::client(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).unwrap();
        client_endpoint.set_default_client_config(client_config(cert));

        let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
        let incoming = tokio::time::timeout(CONNECT_TIMEOUT, server_endpoint.accept())
            .await
            .unwrap()
            .unwrap();
        let (client_conn, server_conn) = tokio::join!(
            async {
                tokio::time::timeout(CONNECT_TIMEOUT, connecting)
                    .await
                    .unwrap()
                    .unwrap()
            },
            async {
                tokio::time::timeout(CONNECT_TIMEOUT, incoming)
                    .await
                    .unwrap()
                    .unwrap()
            }
        );
        let client_addr = client_endpoint.local_addr().unwrap();
        let client = QuinnSession::with_options(
            client_conn.clone(),
            SessionOptions::new().local_addr(client_addr),
        );
        let server_options = if server_options.local_addr.is_none() {
            server_options.local_addr(server_addr)
        } else {
            server_options
        };
        let server = QuinnSession::with_options(server_conn.clone(), server_options);
        Self {
            client_endpoint,
            server_endpoint,
            client_conn,
            server_conn,
            client,
            server,
        }
    }

    async fn close(self) {
        let _ = self.client.close().await;
        let _ = self.server.close().await;
        self.client_endpoint.close(quinn::VarInt::from_u32(0), b"");
        self.server_endpoint.close(quinn::VarInt::from_u32(0), b"");
        let _ = tokio::time::timeout(Duration::from_millis(200), self.client_endpoint.wait_idle())
            .await;
        let _ = tokio::time::timeout(Duration::from_millis(200), self.server_endpoint.wait_idle())
            .await;
        drop(self.client_conn);
        drop(self.server_conn);
    }
}

fn server_config(max_data: u32) -> (quinn::ServerConfig, CertificateDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der.into())
        .unwrap();
    tls_config.alpn_protocols = vec![APPLICATION_PROTOCOL.as_bytes().to_vec()];

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls_config).unwrap()));
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
        .receive_window(max_data.into())
        .stream_receive_window(max_data.into())
        .max_concurrent_bidi_streams(64_u8.into())
        .max_concurrent_uni_streams(64_u8.into());
    (server_config, cert_der)
}

fn client_config(cert: CertificateDer<'static>) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![APPLICATION_PROTOCOL.as_bytes().to_vec()];
    quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls_config).unwrap()))
}

async fn read_all_stream(stream: &QuinnStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(STREAM_TIMEOUT, stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buffer[..n]);
    }
}

async fn read_until_stream_error(stream: &QuinnStream) -> zmux::Error {
    let mut buffer = [0u8; 1024];
    loop {
        match tokio::time::timeout(STREAM_TIMEOUT, stream.read(&mut buffer))
            .await
            .unwrap()
        {
            Ok(0) => panic!("stream closed gracefully before error"),
            Ok(_) => {}
            Err(err) => return err,
        }
    }
}

async fn write_until_stream_error(stream: &QuinnStream, payload: &[u8]) -> zmux::Error {
    let deadline = Instant::now() + STREAM_TIMEOUT;
    loop {
        match tokio::time::timeout(STREAM_TIMEOUT, stream.write_all(payload))
            .await
            .unwrap()
        {
            Ok(()) => {
                assert!(
                    Instant::now() < deadline,
                    "timed out waiting for stream write error"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(err) => return err,
        }
    }
}

async fn read_all_recv(stream: &QuinnRecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let n = tokio::time::timeout(STREAM_TIMEOUT, stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        if n == 0 {
            return out;
        }
        out.extend_from_slice(&buffer[..n]);
    }
}

async fn read_all_async<S>(stream: &S) -> zmux::Result<Vec<u8>>
where
    S: zmux::AsyncRecvStreamHandle + ?Sized,
{
    let mut out = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        let n =
            zmux::AsyncRecvStreamHandle::read_timeout(stream, &mut buffer, STREAM_TIMEOUT).await?;
        if n == 0 {
            return Ok(out);
        }
        out.extend_from_slice(&buffer[..n]);
    }
}

async fn exercise_common_async_session<S>(client: &S, server: &S) -> zmux::Result<()>
where
    S: zmux::AsyncSession + ?Sized,
{
    assert!(!zmux::AsyncSession::is_closed(client));
    assert!(!zmux::AsyncSession::is_closed(server));
    assert_eq!(
        zmux::AsyncSession::state(client),
        zmux::AsyncSession::stats(client).state
    );
    assert_eq!(
        zmux::AsyncSession::state(server),
        zmux::AsyncSession::stats(server).state
    );

    let outbound = zmux::AsyncSession::open_stream(client).await?;
    zmux::AsyncSendStreamHandle::write_final(
        &outbound,
        zmux::WritePayload::from(&b"client-to-server"[..]),
    )
    .await?;
    let inbound = zmux::AsyncSession::accept_stream_timeout(server, STREAM_TIMEOUT).await?;
    assert_eq!(read_all_async(&inbound).await?, b"client-to-server");

    zmux::AsyncSendStreamHandle::write_final(
        &inbound,
        zmux::WritePayload::from(&b"server-to-client"[..]),
    )
    .await?;
    assert_eq!(read_all_async(&outbound).await?, b"server-to-client");
    zmux::AsyncStreamHandle::close(&outbound).await?;
    zmux::AsyncStreamHandle::close(&inbound).await?;

    let (outbound, n) =
        zmux::AsyncSession::open_and_send(client, zmux::OpenSend::new(b"open-and-send")).await?;
    assert_eq!(n, b"open-and-send".len());
    zmux::AsyncSendStreamHandle::close_write(&outbound).await?;
    let inbound = zmux::AsyncSession::accept_stream_timeout(server, STREAM_TIMEOUT).await?;
    assert_eq!(read_all_async(&inbound).await?, b"open-and-send");
    zmux::AsyncStreamHandle::close(&outbound).await?;
    zmux::AsyncStreamHandle::close(&inbound).await?;

    let parts = [IoSlice::new(b"open-"), IoSlice::new(b"vectored")];
    let (outbound, n) =
        zmux::AsyncSession::open_and_send(client, zmux::OpenSend::vectored(&parts)).await?;
    assert_eq!(n, b"open-vectored".len());
    zmux::AsyncSendStreamHandle::close_write(&outbound).await?;
    let inbound = zmux::AsyncSession::accept_stream_timeout(server, STREAM_TIMEOUT).await?;
    assert_eq!(read_all_async(&inbound).await?, b"open-vectored");
    zmux::AsyncStreamHandle::close(&outbound).await?;
    zmux::AsyncStreamHandle::close(&inbound).await?;

    let (outbound, n) =
        zmux::AsyncSession::open_uni_and_send(server, zmux::OpenSend::new(b"server-uni")).await?;
    assert_eq!(n, b"server-uni".len());
    let inbound = zmux::AsyncSession::accept_uni_stream_timeout(client, STREAM_TIMEOUT).await?;
    assert_eq!(read_all_async(&inbound).await?, b"server-uni");
    zmux::AsyncStreamHandle::close(&outbound).await?;
    zmux::AsyncStreamHandle::close(&inbound).await?;

    let parts = [IoSlice::new(b"server-"), IoSlice::new(b"uni-vectored")];
    let (outbound, n) =
        zmux::AsyncSession::open_uni_and_send(server, zmux::OpenSend::vectored(&parts)).await?;
    assert_eq!(n, b"server-uni-vectored".len());
    let inbound = zmux::AsyncSession::accept_uni_stream_timeout(client, STREAM_TIMEOUT).await?;
    assert_eq!(read_all_async(&inbound).await?, b"server-uni-vectored");
    zmux::AsyncStreamHandle::close(&outbound).await?;
    zmux::AsyncStreamHandle::close(&inbound).await?;

    zmux::AsyncSession::close(client).await?;
    zmux::AsyncSession::close(server).await?;
    assert!(zmux::AsyncSession::wait_timeout(client, STREAM_TIMEOUT).await?);
    assert!(zmux::AsyncSession::wait_timeout(server, STREAM_TIMEOUT).await?);
    assert!(zmux::AsyncSession::is_closed(client));
    assert!(zmux::AsyncSession::is_closed(server));
    Ok(())
}

async fn wait_until_stats(
    session: &QuinnSession,
    predicate: impl Fn(&zmux::SessionStats) -> bool,
) -> zmux::SessionStats {
    let deadline = Instant::now() + STREAM_TIMEOUT;
    loop {
        let stats = session.stats();
        if predicate(&stats) {
            return stats;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for stats: {stats:?}"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn assert_local_stream_error(
    err: &zmux::Error,
    operation: zmux::ErrorOperation,
    direction: zmux::ErrorDirection,
) {
    assert_eq!(err.scope(), zmux::ErrorScope::Stream);
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    assert_eq!(err.operation(), operation);
    assert_eq!(err.direction(), direction);
}

#[tokio::test]
async fn common_async_session_code_works_with_quinn_session() {
    let pair = Pair::new().await;
    exercise_common_async_session(&pair.client, &pair.server)
        .await
        .unwrap();
    pair.close().await;
}

#[tokio::test]
async fn common_async_session_code_works_with_erased_quinn_session() {
    let pair = Pair::new().await;
    let sessions: Vec<zmux::BoxAsyncSession> = vec![
        zmux::box_async_session(pair.client.clone()),
        zmux::box_async_session(pair.server.clone()),
    ];
    exercise_common_async_session(sessions[0].as_ref(), sessions[1].as_ref())
        .await
        .unwrap();
    pair.close().await;
}

#[tokio::test]
async fn native_only_controls_are_exposed_as_adapter_unsupported() {
    let pair = Pair::new().await;
    let err = zmux::AsyncSession::ping(&pair.client, b"ping")
        .await
        .unwrap_err();
    assert!(err.is_adapter_unsupported());
    assert_eq!(err.operation(), zmux::ErrorOperation::Ping);
    assert!(zmux::AsyncSession::peer_go_away_error(&pair.client).is_none());
    assert!(zmux::AsyncSession::peer_close_error(&pair.client).is_none());
    assert_eq!(
        zmux::AsyncSession::local_preface(&pair.client).capabilities,
        0
    );
    assert_eq!(
        zmux::AsyncSession::peer_preface(&pair.client).capabilities,
        0
    );
    assert_eq!(zmux::AsyncSession::negotiated(&pair.client).proto, 0);
    pair.close().await;
}

#[tokio::test]
async fn open_and_send_uses_one_write_under_flow_control() {
    let pair = Pair::new_with_server_options_and_max_data(SessionOptions::default(), 4096).await;
    let payload = vec![0x5a; 256 * 1024];

    let (stream, n) = pair
        .client
        .open_and_send(zmux::OpenSend::new(payload.as_slice()).with_timeout(STREAM_TIMEOUT))
        .await
        .unwrap();
    assert!(n > 0);
    assert!(
        n < payload.len(),
        "open_and_send wrote the whole payload; expected one write bounded by flow control"
    );

    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    let mut received = Vec::with_capacity(n);
    let mut buffer = [0; 1024];
    while received.len() < n {
        let remaining = n - received.len();
        let len = remaining.min(buffer.len());
        let read = accepted
            .read_timeout(&mut buffer[..len], STREAM_TIMEOUT)
            .await
            .unwrap();
        assert_ne!(read, 0);
        received.extend_from_slice(&buffer[..read]);
    }
    assert_eq!(received, payload[..n]);

    stream.close_write().await.unwrap();
    pair.close().await;
}

#[tokio::test]
async fn shared_session_and_stream_api_exposes_addresses_and_deadlines() {
    let pair = Pair::new().await;
    assert_eq!(
        pair.client.local_addr(),
        Some(pair.client_endpoint.local_addr().unwrap())
    );
    assert_eq!(
        pair.server.local_addr(),
        Some(pair.server_endpoint.local_addr().unwrap())
    );
    assert_eq!(
        pair.client.peer_addr(),
        Some(pair.server_endpoint.local_addr().unwrap())
    );

    let stream = pair.client.open_stream().await.unwrap();
    assert_eq!(stream.local_addr(), pair.client.local_addr());
    assert_eq!(stream.peer_addr(), pair.client.peer_addr());
    zmux::AsyncStreamHandle::set_deadline(&stream, Some(Instant::now() + STREAM_TIMEOUT)).unwrap();
    zmux::AsyncStreamHandle::clear_deadline(&stream).unwrap();
    stream.set_timeout(Some(STREAM_TIMEOUT)).unwrap();
    stream.set_read_timeout(None).unwrap();
    zmux::AsyncSendStreamHandle::set_write_timeout(&stream, Some(STREAM_TIMEOUT)).unwrap();
    stream.set_write_timeout(None).unwrap();

    zmux::AsyncSendStreamHandle::set_write_deadline(&stream, Some(Instant::now() - SHORT_TIMEOUT))
        .unwrap();
    let err = stream.write(b"x").await.unwrap_err();
    assert!(err.is_timeout());

    pair.close().await;
}

#[tokio::test]
async fn bidi_open_accept_round_trips_payload() {
    let pair = Pair::new().await;
    let stream = pair
        .client
        .open_stream_with(
            OpenOptions::new()
                .priority(7)
                .group(11)
                .with_open_info(b"client-open"),
        )
        .await
        .unwrap();
    assert!(stream.is_opened_locally());
    assert!(stream.is_bidirectional());
    assert!(!stream.is_read_closed());
    assert!(!stream.is_write_closed());
    assert!(stream.has_open_info());
    assert_eq!(stream.open_info_len(), b"client-open".len());
    stream.write_final(b"hello server").await.unwrap();
    assert!(stream.is_write_closed());

    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert!(!accepted.is_opened_locally());
    assert!(accepted.is_bidirectional());
    assert!(!accepted.is_read_closed());
    assert!(!accepted.is_write_closed());
    assert_eq!(accepted.metadata().priority, Some(7));
    assert_eq!(accepted.metadata().group, Some(11));
    assert_eq!(accepted.open_info(), b"client-open");
    assert!(accepted.has_open_info());
    assert_eq!(accepted.open_info_len(), b"client-open".len());
    let mut open_info = b"pre:".to_vec();
    accepted.append_open_info_to(&mut open_info);
    assert_eq!(open_info, b"pre:client-open");
    assert_eq!(read_all_stream(&accepted).await, b"hello server");
    assert!(accepted.is_read_closed());

    accepted.write_final(b"hello client").await.unwrap();
    assert!(accepted.is_write_closed());
    assert_eq!(read_all_stream(&stream).await, b"hello client");
    assert!(stream.is_read_closed());
    pair.close().await;
}

#[tokio::test]
async fn uni_open_accept_round_trips_payload_and_empty_final() {
    let pair = Pair::new().await;
    let uni = pair.client.open_uni_stream().await.unwrap();
    assert!(uni.is_opened_locally());
    assert!(!uni.is_bidirectional());
    assert!(!uni.is_write_closed());
    assert_eq!(pair.client.stats().active_streams.local_uni, 1);
    assert_eq!(
        uni.write_vectored_timeout(&[IoSlice::new(b"terminal ")], STREAM_TIMEOUT)
            .await
            .unwrap(),
        9
    );
    assert_eq!(
        uni.write_final_timeout(b"uni", STREAM_TIMEOUT)
            .await
            .unwrap(),
        3
    );
    assert!(uni.is_write_closed());
    assert_eq!(pair.client.stats().active_streams.local_uni, 0);
    let accepted = pair
        .server
        .accept_uni_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert!(!accepted.is_opened_locally());
    assert!(!accepted.is_bidirectional());
    assert!(!accepted.is_read_closed());
    assert_eq!(pair.server.stats().active_streams.peer_uni, 1);
    let mut received = Vec::new();
    let mut empty = [0u8; 0];
    let mut first = [0u8; 16];
    let n = accepted
        .read_vectored_timeout(
            &mut [IoSliceMut::new(&mut empty), IoSliceMut::new(&mut first)],
            STREAM_TIMEOUT,
        )
        .await
        .unwrap();
    assert!(n > 0);
    received.extend_from_slice(&first[..n]);
    received.extend_from_slice(&read_all_recv(&accepted).await);
    assert_eq!(received, b"terminal uni");
    assert!(accepted.is_read_closed());
    assert_eq!(pair.server.stats().active_streams.peer_uni, 0);

    let (stream, n) = pair
        .client
        .open_uni_and_send(zmux::OpenSend::new(b"hello uni"))
        .await
        .unwrap();
    assert_eq!(n, 9);
    let accepted = pair
        .server
        .accept_uni_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(accepted.metadata(), zmux::StreamMetadata::default());
    assert_eq!(read_all_recv(&accepted).await, b"hello uni");
    drop(stream);

    let (_empty, n) = pair
        .client
        .open_uni_and_send(zmux::OpenSend::new(b""))
        .await
        .unwrap();
    assert_eq!(n, 0);
    let accepted = pair
        .server
        .accept_uni_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert!(read_all_recv(&accepted).await.is_empty());
    pair.close().await;
}

#[tokio::test]
async fn uni_open_metadata_prelude_is_visible_on_accept() {
    let pair = Pair::new().await;
    let stream = pair
        .client
        .open_uni_stream_with(
            OpenOptions::new()
                .priority(3)
                .group(21)
                .with_open_info(b"rpc"),
        )
        .await
        .unwrap();
    assert!(stream.has_open_info());
    assert_eq!(stream.open_info_len(), b"rpc".len());

    let accepted = pair
        .server
        .accept_uni_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    let metadata = accepted.metadata();
    assert_eq!(metadata.priority, Some(3));
    assert_eq!(metadata.group, Some(21));
    assert_eq!(metadata.open_info(), b"rpc");
    assert_eq!(accepted.open_info(), b"rpc");
    assert!(accepted.has_open_info());
    assert_eq!(accepted.open_info_len(), b"rpc".len());
    let mut open_info = b"pre:".to_vec();
    accepted.append_open_info_to(&mut open_info);
    assert_eq!(open_info, b"pre:rpc");
    drop(stream);
    pair.close().await;
}

#[tokio::test]
async fn join_streams_combines_quinn_uni_halves() {
    let pair = Pair::new().await;
    let client_send = pair
        .client
        .open_uni_stream_with(OpenOptions::new().with_open_info(b"\0route"))
        .await
        .unwrap();
    client_send.write_all(b"ping ").await.unwrap();
    let server_recv = pair
        .server
        .accept_uni_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();

    let server_send = pair.server.open_uni_stream().await.unwrap();
    server_send.write_all(b"pong ").await.unwrap();
    let client_recv = pair
        .client
        .accept_uni_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();

    let client: zmux::AsyncDuplexStream<_, _> = zmux::join_async_streams(client_recv, client_send)
        .with_info_side(zmux::DuplexInfoSide::Write);
    let server: zmux::AsyncDuplexStream<_, _> = zmux::join_async_streams(server_recv, server_send);

    assert!(zmux::AsyncStreamHandle::is_bidirectional(&client));
    assert!(zmux::AsyncStreamHandle::is_bidirectional(&server));
    assert_eq!(zmux::AsyncStreamHandle::open_info(&client), b"\0route");
    assert_eq!(zmux::AsyncStreamHandle::open_info(&server), b"\0route");
    assert_ne!(client.read_stream_id(), client.write_stream_id());
    assert_ne!(server.read_stream_id(), server.write_stream_id());

    zmux::AsyncSendStreamHandle::write_final(
        &client,
        zmux::WritePayload::from(&b"from-client"[..]),
    )
    .await
    .unwrap();
    zmux::AsyncSendStreamHandle::write_final(
        &server,
        zmux::WritePayload::from(&b"from-server"[..]),
    )
    .await
    .unwrap();

    assert_eq!(read_all_async(&server).await.unwrap(), b"ping from-client");
    assert_eq!(read_all_async(&client).await.unwrap(), b"pong from-server");
    zmux::AsyncStreamHandle::close(&client).await.unwrap();
    zmux::AsyncStreamHandle::close(&server).await.unwrap();
    pair.close().await;
}

#[tokio::test]
async fn write_vectored_final_combines_payload_and_closes_stream() {
    let pair = Pair::new().await;
    let stream = pair.client.open_stream().await.unwrap();
    let parts = [
        IoSlice::new(b"alpha"),
        IoSlice::new(b""),
        IoSlice::new(b"-beta"),
        IoSlice::new(b"-gamma"),
    ];
    assert_eq!(
        stream
            .write_vectored_final_timeout(&parts, STREAM_TIMEOUT)
            .await
            .unwrap(),
        16
    );
    assert!(stream.is_write_closed());

    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(read_all_stream(&accepted).await, b"alpha-beta-gamma");
    pair.close().await;
}

#[tokio::test]
async fn stream_timeout_vectored_methods_match_native_surface() {
    let pair = Pair::new().await;
    let stream = pair.client.open_stream().await.unwrap();

    assert_eq!(
        stream
            .write_timeout(b"hello ", STREAM_TIMEOUT)
            .await
            .unwrap(),
        6
    );
    assert_eq!(
        stream
            .write_vectored_timeout(&[IoSlice::new(b"world")], STREAM_TIMEOUT)
            .await
            .unwrap(),
        5
    );
    assert_eq!(
        stream
            .write_vectored_final_timeout(&[IoSlice::new(b"!")], STREAM_TIMEOUT)
            .await
            .unwrap(),
        1
    );

    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    let mut received = Vec::new();
    let mut exact = [0u8; 5];
    accepted
        .read_exact_timeout(&mut exact, STREAM_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(&exact, b"hello");
    received.extend_from_slice(&exact);

    let mut empty = [0u8; 0];
    let mut first = [0u8; 16];
    let n = {
        let mut bufs = [IoSliceMut::new(&mut empty), IoSliceMut::new(&mut first)];
        accepted
            .read_vectored_timeout(&mut bufs, STREAM_TIMEOUT)
            .await
            .unwrap()
    };
    assert!(n > 0);
    received.extend_from_slice(&first[..n]);
    received.extend_from_slice(&read_all_stream(&accepted).await);
    assert_eq!(received, b"hello world!");
    pair.close().await;
}

#[tokio::test]
async fn large_write_vectored_final_keeps_payload_and_close_semantics() {
    let pair = Pair::new().await;
    let stream = pair.client.open_stream().await.unwrap();
    let a = vec![b'a'; 128 * 1024];
    let b = vec![b'b'; 128 * 1024];
    let parts = [IoSlice::new(&a), IoSlice::new(&b)];
    assert_eq!(
        stream.write_vectored_final(&parts).await.unwrap(),
        a.len() + b.len()
    );

    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    let payload = read_all_stream(&accepted).await;
    assert_eq!(payload.len(), a.len() + b.len());
    assert!(payload[..a.len()].iter().all(|byte| *byte == b'a'));
    assert!(payload[a.len()..].iter().all(|byte| *byte == b'b'));
    pair.close().await;
}

#[tokio::test]
async fn zero_length_write_does_not_submit_adapter_prelude() {
    let pair = Pair::new().await;
    let stream = pair.client.open_stream().await.unwrap();
    stream.write_all(b"").await.unwrap();

    let err = match pair.server.accept_stream_timeout(SHORT_TIMEOUT).await {
        Ok(_) => panic!("zero-length write published a stream before payload"),
        Err(err) => err,
    };
    assert!(
        err.is_timeout(),
        "expected local accept timeout, got {err:?}"
    );

    stream.write_final(b"after zero").await.unwrap();
    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(read_all_stream(&accepted).await, b"after zero");
    pair.close().await;
}

#[tokio::test]
async fn open_and_send_empty_payload_does_not_submit_adapter_prelude() {
    let pair = Pair::new().await;
    let (stream, written) = pair
        .client
        .open_and_send(zmux::OpenSend::new(b""))
        .await
        .unwrap();
    assert_eq!(written, 0);

    let err = match pair.server.accept_stream_timeout(SHORT_TIMEOUT).await {
        Ok(_) => panic!("empty open_and_send published a stream before payload"),
        Err(err) => err,
    };
    assert!(
        err.is_timeout(),
        "expected local accept timeout, got {err:?}"
    );

    stream.write_final(b"after empty open").await.unwrap();
    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(read_all_stream(&accepted).await, b"after empty open");
    pair.close().await;
}

#[tokio::test]
async fn close_read_uses_cancelled_code_and_fresh_close_read_submits_prelude() {
    let pair = Pair::new().await;
    let stream = pair.client.open_stream().await.unwrap();
    stream.write_all(b"p").await.unwrap();
    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    accepted.close_read().await.unwrap();

    let err = write_until_stream_error(&stream, b"x").await;
    assert_eq!(
        err.application_code(),
        Some(zmux::ErrorCode::Cancelled.as_u64())
    );
    assert_eq!(err.source(), zmux::ErrorSource::Remote);
    assert_eq!(err.direction(), zmux::ErrorDirection::Write);
    assert_eq!(err.termination_kind(), zmux::TerminationKind::Stopped);

    let fresh = pair.client.open_stream().await.unwrap();
    fresh.close_read().await.unwrap();
    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(accepted.metadata(), zmux::StreamMetadata::default());
    let err = write_until_stream_error(&accepted, b"y").await;
    assert_eq!(
        err.application_code(),
        Some(zmux::ErrorCode::Cancelled.as_u64())
    );
    assert_eq!(err.source(), zmux::ErrorSource::Remote);
    assert_eq!(err.direction(), zmux::ErrorDirection::Write);
    pair.close().await;
}

#[tokio::test]
async fn local_close_read_and_close_write_return_sticky_closed_errors() {
    let pair = Pair::new().await;
    let stream = pair.client.open_stream().await.unwrap();
    stream.write_all(b"x").await.unwrap();
    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    accepted.close_read().await.unwrap();
    let mut buf = [0u8; 1];
    let err = accepted.read(&mut buf).await.unwrap_err();
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    assert_eq!(err.direction(), zmux::ErrorDirection::Read);
    assert_eq!(err.termination_kind(), zmux::TerminationKind::Stopped);

    stream.close_write().await.unwrap();
    stream.write_all(b"").await.unwrap();
    let err = stream.write_all(b"y").await.unwrap_err();
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    assert_eq!(err.direction(), zmux::ErrorDirection::Write);
    assert!(err.message().contains("write side closed"));
    let err = stream.cancel_write(77).await.unwrap_err();
    assert!(err.message().contains("write side closed"));
    pair.close().await;
}

#[tokio::test]
async fn local_cancel_write_and_close_with_error_fail_local_ops_immediately() {
    let pair = Pair::new().await;
    let stream = pair.client.open_stream().await.unwrap();
    stream.cancel_write(91).await.unwrap();
    let err = stream.write_all(b"x").await.unwrap_err();
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    assert_eq!(err.direction(), zmux::ErrorDirection::Write);
    assert_eq!(err.application_code(), Some(91));
    assert_eq!(err.termination_kind(), zmux::TerminationKind::Reset);

    let stream = pair.client.open_stream().await.unwrap();
    stream.close_with_error(77, "local abort").await.unwrap();
    let mut buf = [0u8; 1];
    let err = stream.read(&mut buf).await.unwrap_err();
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    assert_eq!(err.direction(), zmux::ErrorDirection::Both);
    assert_eq!(err.application_code(), Some(77));
    assert_eq!(err.reason(), Some("local abort"));
    assert_eq!(err.termination_kind(), zmux::TerminationKind::Abort);
    let err = stream.write_all(b"x").await.unwrap_err();
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    assert_eq!(err.direction(), zmux::ErrorDirection::Both);
    assert_eq!(err.application_code(), Some(77));
    assert_eq!(err.reason(), Some("local abort"));
    assert_eq!(err.termination_kind(), zmux::TerminationKind::Abort);

    let send = pair.client.open_uni_stream().await.unwrap();
    send.close_with_error(88, "local abort").await.unwrap();
    let err = send.write_all(b"x").await.unwrap_err();
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    assert_eq!(err.direction(), zmux::ErrorDirection::Write);
    assert_eq!(err.application_code(), Some(88));
    assert_eq!(err.reason(), Some("local abort"));
    assert_eq!(err.termination_kind(), zmux::TerminationKind::Abort);
    pair.close().await;
}

#[tokio::test]
async fn stats_track_active_streams_progress_and_byte_totals() {
    let pair = Pair::new().await;
    let stream = pair.client.open_stream().await.unwrap();
    assert_eq!(pair.client.stats().active_streams.local_bidi, 1);
    stream.write_final(b"client payload").await.unwrap();

    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(pair.server.stats().accepted_streams, 1);
    assert_eq!(pair.server.stats().active_streams.peer_bidi, 1);
    assert_eq!(read_all_stream(&accepted).await, b"client payload");
    accepted.write_final(b"server payload").await.unwrap();
    assert_eq!(read_all_stream(&stream).await, b"server payload");

    let client_stats = wait_until_stats(&pair.client, |stats| {
        stats.sent_data_bytes >= 14
            && stats.received_data_bytes >= 14
            && stats.active_streams.total == 0
            && stats.flush.count > 0
            && stats.progress.transport_write_at.is_some()
            && stats.progress.stream_progress_at.is_some()
    })
    .await;
    assert_eq!(client_stats.hidden.refused, 0);

    let server_stats = wait_until_stats(&pair.server, |stats| {
        stats.sent_data_bytes >= 14
            && stats.received_data_bytes >= 14
            && stats.active_streams.total == 0
            && stats.progress.inbound_frame_at.is_some()
    })
    .await;
    assert_eq!(server_stats.hidden.refused, 0);
    pair.close().await;
}

#[tokio::test]
async fn accepted_stream_stats_count_user_accepts_not_prepared_backlog() {
    let pair = Pair::new().await;

    let first = pair.client.open_stream().await.unwrap();
    first.write_all(b"first").await.unwrap();
    let accepted_first = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(pair.server.stats().accepted_streams, 1);

    let second = pair.client.open_stream().await.unwrap();
    second.write_all(b"second").await.unwrap();
    let queued_stats =
        wait_until_stats(&pair.server, |stats| stats.active_streams.peer_bidi >= 2).await;
    assert_eq!(queued_stats.accepted_streams, 1);

    let accepted_second = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(pair.server.stats().accepted_streams, 2);

    let _ = first
        .close_with_error(zmux::ErrorCode::Cancelled.as_u64(), "")
        .await;
    let _ = second
        .close_with_error(zmux::ErrorCode::Cancelled.as_u64(), "")
        .await;
    let _ = accepted_first
        .close_with_error(zmux::ErrorCode::Cancelled.as_u64(), "")
        .await;
    let _ = accepted_second
        .close_with_error(zmux::ErrorCode::Cancelled.as_u64(), "")
        .await;
    pair.close().await;
}

#[tokio::test]
async fn metadata_update_before_visibility_uses_prelude_and_after_visibility_is_unsupported() {
    let pair = Pair::new().await;
    let stream = pair.client.open_stream().await.unwrap();
    stream
        .update_metadata(MetadataUpdate::new().with_priority(5).with_group(9))
        .await
        .unwrap();
    stream.write_all(b"visible").await.unwrap();
    let err = stream
        .update_metadata(MetadataUpdate::new().with_priority(6))
        .await
        .unwrap_err();
    assert_local_stream_error(
        &err,
        zmux::ErrorOperation::Write,
        zmux::ErrorDirection::Write,
    );
    stream.write_final(b"-done").await.unwrap();

    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    let mut metadata = accepted.metadata();
    assert_eq!(metadata.priority, Some(5));
    assert_eq!(metadata.group, Some(9));
    metadata.priority = Some(99);
    assert_eq!(accepted.metadata().priority, Some(5));
    assert_eq!(read_all_stream(&accepted).await, b"visible-done");
    pair.close().await;
}

#[tokio::test]
async fn duplicate_accepted_prelude_metadata_is_dropped_without_hiding_stream() {
    let pair = Pair::new().await;
    let (mut send, _recv) = pair.client_conn.open_bi().await.unwrap();
    let metadata = [
        zmux::METADATA_STREAM_PRIORITY as u8,
        1,
        5,
        zmux::METADATA_STREAM_PRIORITY as u8,
        1,
        6,
    ];
    let mut prelude = Vec::new();
    zmux::append_varint(&mut prelude, metadata.len() as u64).unwrap();
    prelude.extend_from_slice(&metadata);
    prelude.extend_from_slice(b"raw");
    send.write_all(&prelude).await.unwrap();
    send.finish().unwrap();

    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(accepted.metadata(), zmux::StreamMetadata::default());
    assert_eq!(read_all_stream(&accepted).await, b"raw");
    assert_eq!(pair.server.stats().hidden.refused, 0);
    pair.close().await;
}

#[tokio::test]
async fn ready_accepted_stream_bypasses_stalled_prelude_and_counts_hidden_refused() {
    let pair = Pair::new_with_server_options(
        SessionOptions::new()
            .accepted_prelude_read_timeout(Duration::from_millis(100))
            .accepted_prelude_max_concurrent(2),
    )
    .await;
    let (mut stalled_send, _stalled_recv) = pair.client_conn.open_bi().await.unwrap();
    stalled_send.write_all(&[0x40]).await.unwrap();

    let ready = pair.client.open_stream().await.unwrap();
    ready.write_final(b"ready").await.unwrap();
    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(read_all_stream(&accepted).await, b"ready");

    let stats = wait_until_stats(&pair.server, |stats| stats.hidden.refused >= 1).await;
    assert_eq!(stats.hidden.refused, 1);
    let _ = stalled_send.reset(quinn::VarInt::from_u32(0));
    pair.close().await;
}

#[tokio::test]
async fn concurrent_accepts_allow_ready_streams_to_bypass_stalled_prelude() {
    let pair = Pair::new_with_server_options(
        SessionOptions::new()
            .accepted_prelude_read_timeout(Duration::from_millis(100))
            .accepted_prelude_max_concurrent(3),
    )
    .await;
    let (mut stalled_send, _stalled_recv) = pair.client_conn.open_bi().await.unwrap();
    stalled_send.write_all(&[0x40]).await.unwrap();

    let first_ready = pair.client.open_stream().await.unwrap();
    first_ready.write_final(b"x").await.unwrap();
    let second_ready = pair.client.open_stream().await.unwrap();
    second_ready.write_final(b"y").await.unwrap();

    let first_accept = pair.server.accept_stream_timeout(STREAM_TIMEOUT);
    let second_accept = pair.server.accept_stream_timeout(STREAM_TIMEOUT);
    let (first, second) = tokio::join!(first_accept, second_accept);
    let first = first.unwrap();
    let second = second.unwrap();
    let mut accepted_ids = [first.stream_id(), second.stream_id()];
    accepted_ids.sort_unstable();
    let mut ready_ids = [first_ready.stream_id(), second_ready.stream_id()];
    ready_ids.sort_unstable();
    assert_eq!(accepted_ids, ready_ids);
    let mut payloads = [
        read_all_stream(&first).await,
        read_all_stream(&second).await,
    ];
    payloads.sort();
    assert_eq!(payloads, [b"x".to_vec(), b"y".to_vec()]);

    let _ = stalled_send.reset(quinn::VarInt::from_u32(0));
    pair.close().await;
}

#[tokio::test]
async fn stream_error_controls_reject_codes_above_quic_varint_without_closing() {
    let pair = Pair::new().await;
    let invalid = quinn::VarInt::MAX.into_inner() + 1;
    let stream = pair.client.open_stream().await.unwrap();
    let err = stream
        .close_with_error(invalid, "too large")
        .await
        .unwrap_err();
    assert_local_stream_error(
        &err,
        zmux::ErrorOperation::Close,
        zmux::ErrorDirection::Both,
    );
    stream.write_final(b"still open").await.unwrap();
    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    assert_eq!(read_all_stream(&accepted).await, b"still open");

    let stream = pair.client.open_stream().await.unwrap();
    stream.write_final(b"readable").await.unwrap();
    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    let err = accepted.cancel_read(invalid).await.unwrap_err();
    assert_local_stream_error(&err, zmux::ErrorOperation::Read, zmux::ErrorDirection::Read);
    assert_eq!(read_all_stream(&accepted).await, b"readable");

    let send = pair.client.open_uni_stream().await.unwrap();
    send.close_write().await.unwrap();
    let err = send
        .close_with_error(invalid, "already closed")
        .await
        .unwrap_err();
    assert_local_stream_error(
        &err,
        zmux::ErrorOperation::Write,
        zmux::ErrorDirection::Write,
    );
    assert!(err.message().contains("write side closed"));
    pair.close().await;
}

#[tokio::test]
async fn remote_stream_reset_updates_reason_stats_on_both_sides() {
    let pair = Pair::new().await;
    let stream = pair.client.open_stream().await.unwrap();
    stream.write_all(b"before reset").await.unwrap();
    let accepted = pair
        .server
        .accept_stream_timeout(STREAM_TIMEOUT)
        .await
        .unwrap();
    stream.cancel_write(41).await.unwrap();

    let err = read_until_stream_error(&accepted).await;
    assert_eq!(err.application_code(), Some(41));
    assert_eq!(err.source(), zmux::ErrorSource::Remote);
    assert_eq!(err.direction(), zmux::ErrorDirection::Read);
    assert_eq!(err.termination_kind(), zmux::TerminationKind::Reset);

    let client_stats = wait_until_stats(&pair.client, |stats| {
        stats.reasons.reset.get(&41) == Some(&1)
    })
    .await;
    assert_eq!(client_stats.reasons.reset.get(&41), Some(&1));

    let server_stats = wait_until_stats(&pair.server, |stats| {
        stats.reasons.reset.get(&41) == Some(&1)
    })
    .await;
    assert_eq!(server_stats.reasons.reset.get(&41), Some(&1));
    pair.close().await;
}

#[tokio::test]
async fn session_abort_propagates_application_error_to_peer() {
    let pair = Pair::new().await;
    pair.client
        .close_with_error(1234, "client abort")
        .await
        .unwrap();
    let err = tokio::time::timeout(STREAM_TIMEOUT, pair.server.wait())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.scope(), zmux::ErrorScope::Session);
    assert_eq!(err.source(), zmux::ErrorSource::Remote);
    assert_eq!(err.operation(), zmux::ErrorOperation::Close);
    assert_eq!(err.application_code(), Some(1234));
    assert_eq!(err.reason(), Some("client abort"));
    pair.server_endpoint.close(quinn::VarInt::from_u32(0), b"");
    pair.client_endpoint.close(quinn::VarInt::from_u32(0), b"");
}

#[tokio::test]
async fn session_close_with_error_rejects_invalid_code_without_closing() {
    let pair = Pair::new().await;
    let err = pair
        .client
        .close_with_error(zmux::MAX_VARINT62 + 1, "too large")
        .await
        .unwrap_err();
    assert_eq!(err.scope(), zmux::ErrorScope::Session);
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    assert_eq!(err.operation(), zmux::ErrorOperation::Close);
    assert!(!pair.client.is_closed());
    pair.close().await;
}

#[tokio::test]
async fn graceful_session_close_waits_successfully_and_blocks_new_opens() {
    let pair = Pair::new().await;
    pair.client.close().await.unwrap();
    tokio::time::timeout(STREAM_TIMEOUT, pair.client.wait())
        .await
        .unwrap()
        .unwrap();
    pair.client.close().await.unwrap();

    let err = match pair.client.open_stream().await {
        Ok(_) => panic!("open_stream succeeded after local session close"),
        Err(err) => err,
    };
    assert_eq!(err.scope(), zmux::ErrorScope::Session);
    assert_eq!(err.source(), zmux::ErrorSource::Local);
    pair.server_endpoint.close(quinn::VarInt::from_u32(0), b"");
    pair.client_endpoint.close(quinn::VarInt::from_u32(0), b"");
}
