//! Blocking calls on threads that drive sessions fail at once
//! (CONFORMANCE.md):
//! inside a tokio runtime, and on the std driver's own threads (here a
//! carrier's `Read`, which runs on the session's reader thread). Calls that
//! never wait still work there, nothing deadlocks, and the session keeps
//! working afterwards.

use std::io::{self, Read};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zmux::blocking::{PipeIo, Session};
use zmux::{Config, ConnectError, OpenError, StreamError};

type Hook = Arc<Mutex<Option<Box<dyn FnOnce() + Send>>>>;

/// A carrier reader that runs a hook before its next read, on the
/// session's reader thread.
struct HookRead {
    inner: TcpStream,
    hook: Hook,
}

impl Read for HookRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let hook = self.hook.lock().unwrap().take();
        if let Some(f) = hook {
            f();
        }
        self.inner.read(buf)
    }
}

/// A session pair over TCP; the client's carrier runs `hook`.
fn pair(hook: Option<Hook>) -> (Session, Session) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (c, _) = l.accept().unwrap();
        Session::accept(PipeIo::tcp(c).unwrap(), Config::default()).unwrap()
    });
    let c = TcpStream::connect(addr).unwrap();
    let pipe = match hook {
        Some(hook) => PipeIo::from_halves(
            HookRead {
                inner: c.try_clone().unwrap(),
                hook,
            },
            c,
        ),
        None => PipeIo::tcp(c).unwrap(),
    };
    let client = Session::connect(pipe, Config::default()).unwrap();
    (client, server.join().unwrap())
}

/// The session still carries a stream both ways.
fn still_works(client: &Session, server: &Session) {
    let (mut send, mut recv) = client.open_bi().unwrap();
    send.write_all(b"ping").unwrap();
    send.finish().unwrap();
    let (mut s2, mut r2) = server.accept_bi().unwrap();
    assert_eq!(r2.read_to_end(16).unwrap(), b"ping");
    s2.write_all(b"pong").unwrap();
    s2.finish().unwrap();
    assert_eq!(recv.read_to_end(16).unwrap(), b"pong");
}

#[test]
fn blocking_calls_on_a_reader_thread_fail_at_once() {
    let hook: Hook = Arc::default();
    let (client, server) = pair(Some(hook.clone()));
    let (mut send, mut recv) = client.open_bi().unwrap();
    let (tx, rx) = mpsc::channel();
    let c = client.clone();
    *hook.lock().unwrap() = Some(Box::new(move || {
        let mut buf = [0u8; 16];
        let r = (
            c.open_bi().err(),
            c.accept_bi().err(),
            c.accept_uni().err(),
            c.read_datagram().err(),
            recv.read(&mut buf).err(),
            send.write(b"x").err(),
            send.write_all(b"x").err(),
            send.stopped().err(),
            c.closed().err(),
            c.next_event(None).err(),
            c.shutdown(0u32.into(), b"").err(),
        );
        // What never waits works on any thread.
        let nonblocking = (
            // An event, or none in time: not refused.
            matches!(
                c.next_event(Some(Duration::ZERO)),
                Ok(_) | Err(zmux::blocking::WaitError::TimedOut)
            ),
            c.try_open_bi().is_ok(),
            c.add_pipe(
                PipeIo::from_halves(io::empty(), io::sink()),
                Default::default(),
            )
            .is_err(),
            {
                recv.set_read_timeout(Some(Duration::ZERO));
                recv.read(&mut buf) == Err(StreamError::TimedOut)
            },
        );
        tx.send((r, nonblocking)).unwrap();
    }));
    // The server's ping makes the client's reader thread read again.
    server.ping().unwrap();
    let (r, nonblocking) = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("the hook ran");
    assert_eq!(r.0, Some(OpenError::OnDriverThread));
    assert_eq!(r.1, Some(zmux::blocking::WaitError::OnDriverThread));
    assert_eq!(r.2, Some(zmux::blocking::WaitError::OnDriverThread));
    assert_eq!(r.3, Some(zmux::blocking::WaitError::OnDriverThread));
    assert_eq!(r.4, Some(StreamError::OnDriverThread));
    assert_eq!(r.5, Some(StreamError::OnDriverThread));
    assert_eq!(r.6, Some(StreamError::OnDriverThread));
    assert_eq!(r.7, Some(StreamError::OnDriverThread));
    assert_eq!(r.8, Some(zmux::blocking::WaitError::OnDriverThread));
    assert_eq!(r.9, Some(zmux::blocking::WaitError::OnDriverThread));
    assert_eq!(r.10, Some(zmux::blocking::WaitError::OnDriverThread));
    assert_eq!(nonblocking, (true, true, true, true));
    // The refused shutdown did nothing.
    assert!(client.close_reason().is_none());
    still_works(&client, &server);
    assert_eq!(
        io::Error::from(StreamError::OnDriverThread).kind(),
        io::ErrorKind::Deadlock
    );
    client.close(0u32.into(), b"");
    server.closed().unwrap();
}

#[test]
fn blocking_calls_inside_a_tokio_runtime_fail_at_once() {
    let (client, server) = pair(None);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    // A carrier for `connect`: a listener that never answers (a connect
    // refused before it could block would prove nothing).
    let spare = TcpListener::bind("127.0.0.1:0").unwrap();
    let spare_addr = spare.local_addr().unwrap();
    let c = client.clone();
    let check = move || {
        let (mut send, mut recv) = c.try_open_bi().unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(c.open_uni().err(), Some(OpenError::OnDriverThread));
        assert_eq!(
            c.accept_bi().err(),
            Some(zmux::blocking::WaitError::OnDriverThread)
        );
        assert_eq!(recv.read(&mut buf), Err(StreamError::OnDriverThread));
        assert_eq!(send.write(b"x"), Err(StreamError::OnDriverThread));
        assert_eq!(c.closed(), Err(zmux::blocking::WaitError::OnDriverThread));
        assert_eq!(
            c.shutdown(0u32.into(), b""),
            Err(zmux::blocking::WaitError::OnDriverThread)
        );
        let tcp = TcpStream::connect(spare_addr).unwrap();
        assert!(matches!(
            Session::connect(PipeIo::tcp(tcp).unwrap(), Config::default()),
            Err(ConnectError::OnDriverThread)
        ));
    };
    let c2 = check.clone();
    let c3 = client.clone();
    rt.block_on(async move {
        // A task, the runtime's own thread, and `spawn_blocking` (the
        // runtime context is entered there too).
        c2();
        tokio::spawn(async move { check() }).await.unwrap();
        tokio::task::spawn_blocking(move || {
            assert_eq!(c3.closed(), Err(zmux::blocking::WaitError::OnDriverThread));
        })
        .await
        .unwrap();
    });
    drop(rt);
    drop(spare);
    still_works(&client, &server);
    client.close(0u32.into(), b"");
}
