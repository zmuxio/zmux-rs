//! Zmux calls a datagram limiter outside every lock
//! of the session, on both drivers. A limiter is application code: one
//! shared by a group of sessions takes a lock of its own and may call into
//! a session, so a call under the session's lock could deadlock against a
//! thread that holds the limiter's lock and calls the session.

use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::task::{Context, Poll};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bytes::Bytes;
use zmux::{Config, Limiter, PipeIo, Session};

/// The helper's request and reply channels.
type Calls = (mpsc::Sender<()>, mpsc::Receiver<()>);

/// A limiter that, holding a lock of its own, calls into the session it
/// limits from `try_ready` and `charge`. The call runs on a helper thread
/// the limiter waits for: called under the session's lock, the helper
/// cannot finish, and the limiter records that instead of deadlocking.
#[derive(Default)]
struct CallsSession {
    calls: Mutex<Option<Calls>>,
    under_lock: AtomicBool,
    used: AtomicUsize,
}

impl CallsSession {
    /// Starts the helper thread, which runs `call` for each request.
    fn attach(&self, call: impl Fn() + Send + 'static) -> JoinHandle<()> {
        let (req_tx, req_rx) = mpsc::channel();
        let (rep_tx, rep_rx) = mpsc::channel();
        *self.calls.lock().unwrap() = Some((req_tx, rep_rx));
        thread::spawn(move || {
            for () in req_rx {
                call();
                if rep_tx.send(()).is_err() {
                    return;
                }
            }
        })
    }

    /// Ends the helper thread (and the reference cycle through it).
    fn detach(&self) {
        self.calls.lock().unwrap().take();
    }

    fn touch(&self) {
        self.used.fetch_add(1, Ordering::Relaxed);
        let calls = self.calls.lock().unwrap();
        if let Some((req, rep)) = calls.as_ref() {
            req.send(()).unwrap();
            if rep.recv_timeout(Duration::from_secs(2)).is_err() {
                self.under_lock.store(true, Ordering::Relaxed);
            }
        }
    }

    fn check(&self, what: &str) {
        assert!(self.used.load(Ordering::Relaxed) >= 4, "{what}: not called");
        assert!(
            !self.under_lock.load(Ordering::Relaxed),
            "{what}: called under the session's lock"
        );
    }
}

impl Limiter for CallsSession {
    fn poll_ready(&self, _: &mut Context<'_>, _: usize, max: usize) -> Poll<usize> {
        Poll::Ready(max)
    }

    fn try_ready(&self, max: usize) -> usize {
        self.touch();
        max
    }

    fn charge(&self, _: usize) {
        self.touch();
    }
}

/// Client and server configurations with datagrams: the client's send
/// limiter and the server's receive limiter.
fn configs(send: &Arc<CallsSession>, receive: &Arc<CallsSession>) -> (Config, Config) {
    let mut client = Config::default();
    client.enable_datagrams = true;
    client.datagram_limiter.send = Some(send.clone());
    let mut server = Config::default();
    server.enable_datagrams = true;
    server.datagram_limiter.receive = Some(receive.clone());
    (client, server)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagram_limiters_run_outside_the_session_lock() {
    let (send, receive) = (Arc::<CallsSession>::default(), Arc::default());
    let (c, s) = configs(&send, &receive);
    let (a, b) = tokio::io::duplex(256 * 1024);
    let server = tokio::spawn(Session::accept(PipeIo::new(b), s));
    let client = Session::connect(PipeIo::new(a), c).await.unwrap();
    let server = server.await.unwrap().unwrap();
    let helpers = [
        send.attach({
            let c = client.clone();
            move || {
                let _ = c.stats();
            }
        }),
        receive.attach({
            let s = server.clone();
            move || {
                let _ = s.stats();
            }
        }),
    ];

    client.send_datagram(Bytes::from_static(b"one")).unwrap();
    assert_eq!(server.read_datagram().await.unwrap(), &b"one"[..]);
    let (mut tx, _rx) = client.open_bi().await.unwrap();
    tx.write_all(b"open").await.unwrap();
    tx.send_datagram(1, Bytes::from_static(b"two")).unwrap();
    let (_stx, srx) = server.accept_bi().await.unwrap();
    assert_eq!(
        srx.read_datagram().await.unwrap(),
        (1, Bytes::from_static(b"two"))
    );

    send.detach();
    receive.detach();
    for h in helpers {
        h.join().unwrap();
    }
    send.check("send limiter");
    receive.check("receive limiter");
}

#[test]
fn blocking_datagram_limiters_run_outside_the_session_lock() {
    use zmux::blocking::{PipeIo, Session};

    let (send, receive) = (Arc::<CallsSession>::default(), Arc::default());
    let (c, s) = configs(&send, &receive);
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let a = TcpStream::connect(l.local_addr().unwrap()).unwrap();
    let (b, _) = l.accept().unwrap();
    let server = thread::spawn(move || Session::accept(PipeIo::tcp(b).unwrap(), s).unwrap());
    let client = Session::connect(PipeIo::tcp(a).unwrap(), c).unwrap();
    let server = server.join().unwrap();
    let helpers = [
        send.attach({
            let c = client.clone();
            move || {
                let _ = c.stats();
            }
        }),
        receive.attach({
            let s = server.clone();
            move || {
                let _ = s.stats();
            }
        }),
    ];

    client.send_datagram(Bytes::from_static(b"one")).unwrap();
    assert_eq!(server.read_datagram().unwrap(), &b"one"[..]);
    let (mut tx, _rx) = client.open_bi().unwrap();
    tx.write_all(b"open").unwrap();
    tx.send_datagram(1, Bytes::from_static(b"two")).unwrap();
    let (_stx, srx) = server.accept_bi().unwrap();
    assert_eq!(
        srx.read_datagram().unwrap(),
        (1, Bytes::from_static(b"two"))
    );

    send.detach();
    receive.detach();
    for h in helpers {
        h.join().unwrap();
    }
    send.check("send limiter");
    receive.check("receive limiter");
}
