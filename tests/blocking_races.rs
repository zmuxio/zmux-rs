//! Failure tests of the std driver's I/O threads: carriers that end or fail
//! in the middle of a batch, and a multipath session that loses a pipe
//! during traffic. (The waits are the shared handle layer's: their close
//! races are in `blocking_leaks.rs` and `close_races.rs`.) Every test runs
//! under a watchdog: it fails, rather than hangs, when anything does not
//! resolve in time.

#![allow(
    clippy::cast_possible_truncation,
    reason = "test and bench values are small and bounded; checked conversions would only add noise"
)]
#![allow(
    clippy::many_single_char_names,
    clippy::similar_names,
    reason = "short conventional names in scenario code"
)]

#[path = "common/basics.rs"]
mod basics;

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use basics::{small_windows, tcp};
use zmux::blocking::{PipeIo, Session};
use zmux::sched::Scheduler;
use zmux::{ClockDomain, Config, MonotonicClock, PipeAuth, PipeOptions};

#[path = "common/clock.rs"]
mod clock;

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
    prefix: Option<mpsc::Sender<()>>,
    after_prefix: Option<mpsc::Receiver<()>>,
}

impl<W: Write> Write for Failing<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.left == 0 {
            if let Some(cut) = self.after_prefix.take() {
                cut.recv().unwrap();
            }
            return Err(std::io::ErrorKind::BrokenPipe.into());
        }
        let n = self.inner.write(&buf[..buf.len().min(self.left)])?;
        self.left -= n;
        if self.left == 0
            && let Some(prefix) = self.prefix.take()
        {
            prefix.send(()).unwrap();
        }
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
    let closer = a.try_clone().unwrap();
    let (prefix, written) = mpsc::channel();
    let (cut, cutting) = mpsc::channel();
    let client_pipe = PipeIo::from_halves(
        a.try_clone().unwrap(),
        Failing {
            inner: a,
            left: 2 * 1024 * 1024 + 333,
            prefix: eof.then_some(prefix),
            after_prefix: eof.then_some(cutting),
        },
    )
    .with_closer(move |how| {
        let _ = closer.shutdown(how);
    });
    let server =
        thread::spawn(move || Session::accept(PipeIo::from_tcp(b), Config::default()).unwrap());
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
        written.recv().unwrap();
        shut.shutdown(Shutdown::Both).unwrap();
        cut.send(()).unwrap();
    }
    for j in jobs {
        j.join().expect("no panic");
    }
    client.closing().unwrap();
    // A failed carrier from halves keeps its reader until the peer ends it
    // (nothing interrupts a generic read): the server closes rather than
    // waiting for its idle timeout.
    server.close();
    server.closing().unwrap();
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
    c.session_policy.limits.steady_attachments = 4;
    c.pipe_auth = PipeAuth::psk(*b"blocking-race-psk-0123456789abcd").with_end_to_end();
    c.scheduler = Scheduler::SpreadEta;
    c.liveness.suspect_floor = Duration::from_millis(100);
    c
}

/// A TCP relay that can be cut: both sockets are shut down.
fn relay(
    target: SocketAddr,
) -> (
    SocketAddr,
    mpsc::Receiver<(TcpStream, TcpStream)>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (opened, awaiting) = mpsc::channel();
    let task = thread::spawn(move || {
        let (left, _) = listener.accept().unwrap();
        let right = TcpStream::connect(target).unwrap();
        opened
            .send((left.try_clone().unwrap(), right.try_clone().unwrap()))
            .unwrap();
        let mut from = left.try_clone().unwrap();
        let mut to = right.try_clone().unwrap();
        let upstream = thread::spawn(move || {
            let _ = std::io::copy(&mut from, &mut to);
        });
        let _ = std::io::copy(&mut &right, &mut &left);
        let _ = left.shutdown(Shutdown::Both);
        let _ = right.shutdown(Shutdown::Both);
        upstream.join().unwrap();
    });
    (addr, awaiting, task)
}

/// A multipath server on a tokio listener (the std driver has none):
/// echoes every bidirectional stream of every session.
fn mp_server(rt: &tokio::runtime::Runtime) -> SocketAddr {
    rt.block_on(async {
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let listener = zmux::Listener::new(mp_config(), zmux::ListenerConfig::default())
            .expect("valid listener configuration");
        let l = listener.clone();
        tokio::spawn(async move {
            while let Ok((c, peer)) = tcp.accept().await {
                let l = l.clone();
                tokio::spawn(async move {
                    let _ = l
                        .handle_pipe(zmux::PipeIo::from_tcp(c), zmux::PipeHint::from_peer(peer))
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
            PipeIo::from_tcp(TcpStream::connect(addr).unwrap()),
            mp_config(),
        )
        .unwrap();
        assert_eq!(client.multipath(), zmux::Multipath::InUse);
        let (raddr, connected, relay_task) = relay(addr);
        let pipe = client
            .test_begin_join(
                PipeIo::from_tcp(TcpStream::connect(raddr).unwrap()),
                PipeOptions::default(),
            )
            .unwrap();
        let (left, right) = connected.recv().unwrap();
        let (opened, streams_ready) = mpsc::channel();
        let jobs: Vec<_> = (0..6u8)
            .map(|seed| {
                let client = client.clone();
                let opened = opened.clone();
                let (resume, continuing) = mpsc::channel();
                let job = thread::spawn(move || {
                    let (mut send, mut recv) = client.open_bi().unwrap();
                    let prefix = [seed; 1024];
                    send.write_all(&prefix).unwrap();
                    let mut echoed = [0; 1024];
                    recv.read_exact(&mut echoed).unwrap();
                    assert_eq!(echoed, prefix);
                    opened.send(()).unwrap();
                    continuing.recv().unwrap();
                    let suffix = vec![seed; 256 * 1024];
                    let writer = thread::spawn(move || {
                        send.write_all(&suffix).unwrap();
                        send.finish().unwrap();
                    });
                    let data = recv.read_to_end(256 * 1024).unwrap();
                    writer.join().unwrap();
                    assert_eq!(data, vec![seed; 256 * 1024]);
                });
                (resume, job)
            })
            .collect();
        for _ in &jobs {
            streams_ready.recv().unwrap();
        }
        // Cutting either side lets the relay shut down both sockets itself, so
        // the second shutdown can find the socket already disconnected
        // (macOS reports ENOTCONN there; Linux reports success).
        for side in [&left, &right] {
            match side.shutdown(Shutdown::Both) {
                Err(error) if error.kind() != std::io::ErrorKind::NotConnected => {
                    panic!("relay shutdown: {error}")
                }
                _ => {}
            }
        }
        relay_task.join().unwrap();
        let _ = pipe.abort();
        for (resume, _) in &jobs {
            resume.send(()).unwrap();
        }
        for (_, job) in jobs {
            job.join().unwrap();
        }
        client.close();
        client.closing().unwrap();
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
        struct ObserveReads {
            socket: TcpStream,
            at_boundary: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
            after_idle: Option<mpsc::Sender<()>>,
            check_small_read: bool,
        }

        impl Read for ObserveReads {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if std::mem::take(&mut self.check_small_read) {
                    assert_eq!(
                        buf.len(),
                        256,
                        "an idle read must give back the large buffer"
                    );
                    self.after_idle.take().unwrap().send(()).unwrap();
                    // Split the next record at a prescribed byte, independently of TCP read size.
                    return self.socket.read(&mut buf[..1]);
                }
                // A read into the entire large buffer starts at a record boundary.
                if buf.len() == 128 * 1024
                    && let Some((entered, resume)) = self.at_boundary.take()
                {
                    entered.send(()).unwrap();
                    resume.recv().unwrap();
                    self.check_small_read = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                self.socket.read(buf)
            }
        }

        let (a, b) = tcp();
        let server =
            thread::spawn(move || Session::accept(PipeIo::from_tcp(b), Config::default()).unwrap());
        let (entered, waiting) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let (after_idle, small_read) = mpsc::channel();
        let closer = a.try_clone().unwrap();
        let reader = ObserveReads {
            socket: a.try_clone().unwrap(),
            at_boundary: Some((entered, resume)),
            after_idle: Some(after_idle),
            check_small_read: false,
        };
        let pipe = PipeIo::from_halves(reader, a).with_closer(move |how| {
            let _ = closer.shutdown(how);
        });
        let (clock, domain) = clock::ManualClock::domain(Duration::ZERO);
        let mut config = Config::default();
        config.clock_domain = domain;
        config.test_hooks().unpaced = true;
        let client = Session::connect(pipe, config).unwrap();
        let server = server.join().unwrap();
        let task = serve(server.clone());
        let warming = {
            let client = client.clone();
            thread::spawn(move || echo_once(&client, 64 * 1024, 1))
        };
        waiting
            .recv_timeout(Duration::from_secs(5))
            .expect("the reader reached a record boundary with the large buffer");
        clock.advance(Duration::from_secs(1));
        release.send(()).unwrap();
        small_read
            .recv_timeout(Duration::from_secs(5))
            .expect("the reader resumed with its small buffer");
        assert!(warming.join().unwrap());
        assert!(echo_once(&client, 300 * 1024 + 7, 2));
        client.close();
        let _ = server.closing();
        task.join().unwrap();
    });
}
