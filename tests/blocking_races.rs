//! Failure tests of the std driver's I/O threads: carriers that end or fail
//! in the middle of a batch, and a multipath session that loses a pipe
//! during traffic. (The waits are the shared handle layer's: their close
//! races are in `blocking_leaks.rs` and `close_races.rs`.) Every test runs
//! under a watchdog: it fails, rather than hangs, when anything does not
//! resolve in time.

#[path = "common/basics.rs"]
mod basics;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Duration;

use basics::{small_windows, tcp};
use zmux::blocking::{PipeIo, Session};
use zmux::{Config, PipeAuth, PipeOptions, Policy, VarInt};

/// Runs `f` on a thread and fails when it does not finish within `secs`.
fn watchdog<T: Send + 'static>(secs: u64, what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(v) => v,
        Err(mpsc::RecvTimeoutError::Timeout) => panic!("{what}: did not resolve within {secs} s"),
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("{what}: panicked"),
    }
}

/// Echoes every bidirectional stream until the session ends.
fn serve(server: Session) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        while let Ok((mut send, mut recv)) = server.accept_bi() {
            thread::spawn(move || {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match recv.read(&mut buf) {
                        Ok(Some(n)) => {
                            if send.write_all(&buf[..n]).is_err() {
                                return;
                            }
                        }
                        Ok(None) => break,
                        Err(_) => return,
                    }
                }
                let _ = send.finish();
            });
        }
    })
}

fn echo_once(session: &Session, len: usize, seed: u8) -> bool {
    let Ok((mut send, mut recv)) = session.open_bi() else {
        return false;
    };
    let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_add(seed)).collect();
    let w = {
        let data = data.clone();
        thread::spawn(move || {
            if send.write_all(&data).is_ok() {
                let _ = send.finish();
            }
        })
    };
    let got = recv.read_to_end(len + 1);
    let _ = w.join();
    matches!(got, Ok(g) if g == data)
}

/// A writer that fails after `left` bytes.
struct Failing<W> {
    inner: W,
    left: usize,
}

impl<W: Write> Write for Failing<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        let n = self.inner.write(&buf[..buf.len().min(self.left)])?;
        self.left -= n;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Transfers in both directions on many streams while the carrier ends
/// (`eof`) or its writes fail: every thread on both sides finishes.
fn carrier_ends_mid_batch(eof: bool) {
    let (a, b) = tcp();
    let shut = a.try_clone().unwrap();
    let client_pipe = if eof {
        PipeIo::tcp(a).unwrap()
    } else {
        let reader = a.try_clone().unwrap();
        PipeIo::from_halves(
            reader,
            Failing {
                inner: a,
                left: 2 * 1024 * 1024 + 333,
            },
        )
    };
    let server =
        thread::spawn(move || Session::accept(PipeIo::tcp(b).unwrap(), Config::default()).unwrap());
    let client = Session::connect(client_pipe, Config::default()).unwrap();
    let server = server.join().unwrap();
    let server_task = serve(server.clone());
    let jobs: Vec<_> = (0..6u8)
        .map(|i| {
            let c = client.clone();
            thread::spawn(move || {
                let Ok((mut send, mut recv)) = c.open_bi() else {
                    return;
                };
                let w = thread::spawn(move || {
                    let data = vec![i; 16 * 1024 + usize::from(i)];
                    while send.write_all(&data).is_ok() {}
                });
                let mut buf = vec![0u8; 32 * 1024];
                while let Ok(Some(_)) = recv.read(&mut buf) {}
                let _ = w.join();
            })
        })
        .collect();
    if eof {
        thread::sleep(Duration::from_millis(200));
        let _ = shut.shutdown(std::net::Shutdown::Both);
    }
    for j in jobs {
        j.join().expect("no panic");
    }
    client.closed().unwrap();
    // A failed carrier from halves keeps its reader until the peer ends it
    // (nothing interrupts a generic read): the server closes rather than
    // waiting for its idle timeout.
    server.close(VarInt::from_u32(0), b"");
    server.closed().unwrap();
    let _ = server_task.join();
}

#[test]
fn carrier_eof_mid_batch() {
    watchdog(60, "test", || carrier_ends_mid_batch(true));
}

#[test]
fn carrier_write_error_mid_batch() {
    watchdog(60, "test", || carrier_ends_mid_batch(false));
}

// ---- multipath --------------------------------------------------------------------

fn mp_config() -> Config {
    let mut c = small_windows(Config::default());
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"blocking-race-psk-0123456789abcd");
    c.scheduler = Policy::SpreadEta;
    c.suspect_floor = Duration::from_millis(100);
    c
}

/// A TCP relay that can be cut: both sockets are shut down.
fn relay(target: SocketAddr) -> (SocketAddr, Arc<AtomicBool>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let cut = Arc::new(AtomicBool::new(false));
    let c = cut.clone();
    thread::spawn(move || {
        let Ok((a, _)) = l.accept() else {
            return;
        };
        let b = TcpStream::connect(target).unwrap();
        let pump = |mut r: TcpStream, mut w: TcpStream, cut: Arc<AtomicBool>| {
            thread::spawn(move || {
                r.set_read_timeout(Some(Duration::from_millis(10))).unwrap();
                let mut buf = vec![0u8; 16 * 1024];
                while !cut.load(Ordering::SeqCst) {
                    match r.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if w.write_all(&buf[..n]).is_err() {
                                break;
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) => {}
                        Err(_) => break,
                    }
                }
                let _ = r.shutdown(std::net::Shutdown::Both);
                let _ = w.shutdown(std::net::Shutdown::Both);
            })
        };
        let t1 = pump(a.try_clone().unwrap(), b.try_clone().unwrap(), c.clone());
        let t2 = pump(b, a, c);
        let _ = t1.join();
        let _ = t2.join();
    });
    (addr, cut)
}

/// A multipath server on a tokio listener (the std driver has none):
/// echoes every bidirectional stream of every session.
fn mp_server(rt: &tokio::runtime::Runtime) -> SocketAddr {
    rt.block_on(async {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let listener = zmux::Listener::new(mp_config(), zmux::ListenerConfig::default());
        let l = listener.clone();
        tokio::spawn(async move {
            while let Ok((c, peer)) = tcp.accept().await {
                let l = l.clone();
                tokio::spawn(async move {
                    let _ = l
                        .handle_pipe(zmux::PipeIo::tcp(c), zmux::PipeHint::from_addr(peer.ip()))
                        .await;
                });
            }
        });
        tokio::spawn(async move {
            while let Some(s) = listener.accept().await {
                tokio::spawn(async move {
                    while let Ok((mut send, mut recv)) = s.accept_bi().await {
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 16 * 1024];
                            while let Ok(Some(n)) = recv.read(&mut buf).await {
                                if send.write_all(&buf[..n]).await.is_err() {
                                    return;
                                }
                            }
                            let _ = send.finish();
                        });
                    }
                });
            }
        });
        addr
    })
}

/// Two pipes, one severed during concurrent echoes: no echo loses a byte,
/// and closing ends every thread.
#[test]
fn multipath_pipe_loss_during_traffic() {
    watchdog(60, "test", || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let addr = mp_server(&rt);
        let client = Session::connect(
            PipeIo::tcp(TcpStream::connect(addr).unwrap()).unwrap(),
            mp_config(),
        )
        .unwrap();
        assert!(client.multipath() == zmux::Multipath::InUse);
        let (raddr, cut) = relay(addr);
        let pipe = client
            .add_pipe(
                PipeIo::tcp(TcpStream::connect(raddr).unwrap()).unwrap(),
                PipeOptions::default(),
            )
            .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let jobs: Vec<_> = (0..6u8)
            .map(|i| {
                let c = client.clone();
                let stop = stop.clone();
                thread::spawn(move || {
                    let mut n = 0;
                    while !stop.load(Ordering::SeqCst) {
                        assert!(echo_once(&c, 256 * 1024, i), "echo {i} lost data");
                        n += 1;
                    }
                    n
                })
            })
            .collect();
        thread::sleep(Duration::from_millis(150));
        cut.store(true, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(400));
        let _ = pipe.abort();
        thread::sleep(Duration::from_millis(100));
        stop.store(true, Ordering::SeqCst);
        let echoes: usize = jobs.into_iter().map(|j| j.join().expect("echo")).sum();
        assert!(echoes > 0);
        client.close(VarInt::from_u32(0), b"");
        client.closed().unwrap();
        rt.shutdown_timeout(Duration::from_secs(5));
    });
}

/// A reader thread whose carrier stayed idle
/// gives its read buffer back and waits in a small one; the next records,
/// split across the small read and the buffer taken again, arrive intact
/// on both sides.
#[test]
fn idle_readers_resume_with_a_new_buffer() {
    watchdog(30, "idle readers", || {
        let (a, b) = tcp();
        let server = thread::spawn(move || {
            Session::accept(PipeIo::tcp(b).unwrap(), Config::default()).unwrap()
        });
        let client = Session::connect(PipeIo::tcp(a).unwrap(), Config::default()).unwrap();
        let server = server.join().unwrap();
        let task = serve(server.clone());
        assert!(echo_once(&client, 64 * 1024, 1));
        for seed in 2..4 {
            thread::sleep(Duration::from_millis(1300));
            assert!(client.ping().is_ok());
            assert!(echo_once(&client, 300 * 1024 + 7, seed));
        }
        client.close(VarInt::from_u32(0), b"");
        let _ = server.closed();
        task.join().unwrap();
    });
}
