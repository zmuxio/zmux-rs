//! The carrier contract (`zmux::test_hooks::carrier_conformance`) on a
//! client's HTTP/2 request pipes and the server's halves of their requests.

use std::sync::Arc;

use http::{Request, Response};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::sync::{Mutex, mpsc};
use zmux::PipeIo;

use crate::Options;
use crate::body::{self, BodyReader, PipeBody};
use crate::client::Http2Connection;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn http2_request_pipes_keep_the_carrier_contract() {
    let (a, b) = tokio::io::duplex(1 << 20);
    let (pipes, served) = mpsc::unbounded_channel::<PipeIo>();
    let service = service_fn(move |req: Request<Incoming>| {
        let pipes = pipes.clone();
        async move {
            let reader = BodyReader::new(req.into_body());
            let (writer, resp, abort) = body::body();
            let io = PipeIo::from_chunk_halves(reader, writer).with_abort(move || abort.run());
            let _ = pipes.send(io);
            Ok::<_, std::convert::Infallible>(Response::<PipeBody>::new(resp))
        }
    });
    let serving = tokio::spawn(async move {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(b), service)
            .await;
    });
    let client = Http2Connection::handshake(a, "localhost", Options::default())
        .await
        .unwrap();
    let served = Arc::new(Mutex::new(served));
    zmux::test_hooks::carrier_conformance("http2", || {
        let (client, served) = (client.clone(), served.clone());
        async move {
            let a = client.open_pipe().await.unwrap();
            let b = served.lock().await.recv().await.unwrap();
            (a, b, 0)
        }
    })
    .await;
    serving.abort();
}
