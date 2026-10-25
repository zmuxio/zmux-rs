//! TCP_NOTSENT_LOWAT of TCP carriers: at idle the floors, 128 KiB on a single pipe
//! and 32 KiB per pipe once a session is multipath, the bootstrap pipe
//! included, in both drivers.

// Reading a socket option back needs `getsockopt`, which is unsafe.
#![allow(unsafe_code)]
#![cfg(any(target_os = "linux", target_os = "android", target_vendor = "apple"))]

use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use zmux::{Config, Listener, ListenerConfig, PipeAuth, PipeHint, PipeIo, PipeOptions, Session};

#[cfg(target_vendor = "apple")]
const NOTSENT_LOWAT: libc::c_int = 0x201;
#[cfg(any(target_os = "linux", target_os = "android"))]
const NOTSENT_LOWAT: libc::c_int = libc::TCP_NOTSENT_LOWAT;

/// The socket's TCP_NOTSENT_LOWAT.
fn lowat(socket: &impl AsRawFd) -> u32 {
    let mut value: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>()).unwrap();
    // SAFETY: `value` is a valid c_int of `len` bytes for the kernel to
    // write, and the descriptor is open for the call.
    let r = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            NOTSENT_LOWAT,
            (&raw mut value).cast(),
            &raw mut len,
        )
    };
    assert_eq!(r, 0, "getsockopt: {}", std::io::Error::last_os_error());
    u32::try_from(value).unwrap()
}

/// Waits until the socket's low-water mark is `want`.
async fn expect_lowat(socket: &impl AsRawFd, want: u32) {
    let start = Instant::now();
    loop {
        let got = lowat(socket);
        if got == want {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "TCP_NOTSENT_LOWAT {got}, want {want}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

fn mp_config() -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"lowat-test-psk-0123456789abcdef!");
    c
}

/// A TCP connection as a tokio stream, and a handle on the same socket to
/// read its options.
async fn connect(addr: std::net::SocketAddr) -> (tokio::net::TcpStream, std::net::TcpStream) {
    let s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let probe = s.into_std().unwrap();
    let handle = probe.try_clone().unwrap();
    (tokio::net::TcpStream::from_std(probe).unwrap(), handle)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn multipath_pipes_get_32_kib() {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let listener = Listener::new(mp_config(), ListenerConfig::default());
    let l = listener.clone();
    tokio::spawn(async move {
        while let Ok((c, peer)) = tcp.accept().await {
            let l = l.clone();
            tokio::spawn(async move {
                let _ = l
                    .handle_pipe(PipeIo::tcp(c), PipeHint::from_addr(peer.ip()))
                    .await;
            });
        }
    });
    let (stream, bootstrap) = connect(addr).await;
    let session = Session::connect(PipeIo::tcp(stream), mp_config())
        .await
        .unwrap();
    assert!(session.multipath() == zmux::Multipath::InUse);
    expect_lowat(&bootstrap, 32 * 1024).await;
    let (stream, added) = connect(addr).await;
    session
        .add_pipe(PipeIo::tcp(stream), PipeOptions::default())
        .unwrap();
    expect_lowat(&added, 32 * 1024).await;
    session.close(0u32.into(), b"");
    drop(listener);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_pipe_keeps_128_kib() {
    let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (c, _) = tcp.accept().await.unwrap();
        Session::accept(PipeIo::tcp(c), Config::default())
            .await
            .unwrap()
    });
    let (stream, socket) = connect(addr).await;
    let session = Session::connect(PipeIo::tcp(stream), Config::default())
        .await
        .unwrap();
    let _server = server.await.unwrap();
    assert!(session.multipath() != zmux::Multipath::InUse);
    // Established, and it stays at the single-pipe value.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(lowat(&socket), 128 * 1024);
}

#[test]
fn blocking_multipath_pipes_get_32_kib() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let addr = rt.block_on(async {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let listener = Listener::new(mp_config(), ListenerConfig::default());
        tokio::spawn(async move {
            while let Ok((c, peer)) = tcp.accept().await {
                let l = listener.clone();
                tokio::spawn(async move {
                    let _ = l
                        .handle_pipe(PipeIo::tcp(c), PipeHint::from_addr(peer.ip()))
                        .await;
                });
            }
        });
        addr
    });
    let stream = std::net::TcpStream::connect(addr).unwrap();
    let bootstrap = stream.try_clone().unwrap();
    let session =
        zmux::blocking::Session::connect(zmux::blocking::PipeIo::tcp(stream).unwrap(), mp_config())
            .unwrap();
    assert!(session.multipath() == zmux::Multipath::InUse);
    let start = Instant::now();
    // The writer thread lowers it when it next writes, at most every 20 ms: make it write.
    while lowat(&bootstrap) != 32 * 1024 {
        session.ping().unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "bootstrap {}",
            lowat(&bootstrap)
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let stream = std::net::TcpStream::connect(addr).unwrap();
    let added = stream.try_clone().unwrap();
    session
        .add_pipe(
            zmux::blocking::PipeIo::tcp(stream).unwrap(),
            PipeOptions::default(),
        )
        .unwrap();
    assert_eq!(lowat(&added), 32 * 1024);
    session.close(0u32.into(), b"");
    rt.shutdown_timeout(Duration::from_secs(2));
}
