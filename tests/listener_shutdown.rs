//! A listener's graceful shutdown refuses new sessions at once and goes
//! on taking the joins of its live sessions until they ended; its close
//! refuses everything at once.

use std::time::Duration;

use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeIo, PipeOptions, Session, VarInt};

const LIMIT: Duration = Duration::from_secs(10);

fn config() -> Config {
    let mut config = Config::default();
    config.max_pipes = 8;
    config.pipe_auth = PipeAuth::psk(b"a pre-shared key, 16 bytes or more".to_vec());
    config
}

async fn serve() -> (Listener, std::net::SocketAddr) {
    let listener = Listener::new(config(), ListenerConfig::default());
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    tokio::spawn(listener.clone().serve(tcp));
    (listener, addr)
}

/// A session, or `None` when the server did not take it in time.
async fn connect(addr: std::net::SocketAddr) -> Option<Session> {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        Session::connect(PipeIo::tcp(tcp), config()),
    )
    .await
    .ok()?
    .ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_takes_joins_until_the_sessions_end() {
    tokio::time::timeout(LIMIT, async {
        let (listener, addr) = serve().await;
        let client = connect(addr).await.unwrap();
        let server = listener.accept().await.unwrap();
        let l = listener.clone();
        let shutdown = tokio::spawn(async move {
            l.shutdown(VarInt::from_u32(0), b"bye").await;
        });
        // Draining: no new session ...
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(listener.accept().await.is_none());
        assert!(connect(addr).await.is_none());
        // Counted when the listener's handling of the carrier returns,
        // which may come after the client saw the carrier close.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while listener.stats().refused == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(listener.stats().refused >= 1);
        // ... but a join of the live session is taken.
        let joins = listener.stats().joins;
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _pipe = client
            .add_pipe(PipeIo::tcp(tcp), PipeOptions::default())
            .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while listener.stats().joins == joins && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(listener.stats().joins, joins + 1);
        assert!(!shutdown.is_finished());
        // The session ends: the listener closes.
        drop(server);
        drop(client);
        shutdown.await.unwrap();
        listener.closed().await;
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_refuses_joins_too() {
    tokio::time::timeout(LIMIT, async {
        let (listener, addr) = serve().await;
        let client = connect(addr).await.unwrap();
        let _server = listener.accept().await.unwrap();
        listener.close();
        // The serve loop ended: nothing is accepted any more.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(tokio::net::TcpStream::connect(addr).await.is_err());
        drop(client);
    })
    .await
    .unwrap();
}

/// A shutdown cancelled at its deadline closes the listener at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_shutdown_past_its_deadline_closes() {
    tokio::time::timeout(LIMIT, async {
        let (listener, addr) = serve().await;
        let client = connect(addr).await.unwrap();
        let server = listener.accept().await.unwrap();
        // Holding streams open keeps the session's graceful close waiting.
        let (_send, _recv) = client.open_bi().await.unwrap();
        let r = tokio::time::timeout(
            Duration::from_millis(100),
            listener.shutdown(VarInt::from_u32(0), b""),
        )
        .await;
        drop(r);
        listener.closed().await;
        drop((client, server));
    })
    .await
    .unwrap();
}
