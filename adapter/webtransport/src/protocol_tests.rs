use super::*;
use crate::Options;
use crate::tests::common::Wt;
use std::time::Duration;

async fn connected(wt: &Wt) -> (Connection, Connection) {
    let server = wt.server.as_ref().unwrap();
    let (client, server) = tokio::join!(
        wt.client_ep
            .connect_with(
                wt.client_config.clone(),
                server.local_addr().unwrap(),
                wt.url.host_str().unwrap(),
            )
            .unwrap(),
        async { server.accept().await.unwrap().await },
    );
    (client.unwrap(), server.unwrap())
}

#[tokio::test]
async fn nonzero_connect_uses_full_stream_id_and_quarter_datagram_id() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let wt = Wt::new(&Options::default());
        let (client, server) = connected(&wt).await;
        let mut reserved = Vec::new();
        for _ in 0..64 {
            reserved.push(client.open_bi().await.unwrap());
        }
        let (client, server) = tokio::join!(Session::connect(client, wt.url), async {
            Request::accept(server).await.unwrap().ok().await
        },);
        let (client, server) = (client.unwrap(), server.unwrap());
        assert_eq!(client.id(), 256);
        assert_eq!(server.id(), 256);

        let mut uni = client.open_uni().await.unwrap();
        uni.write_all(b"uni").await.unwrap();
        uni.finish().unwrap();
        assert_eq!(
            server
                .accept_uni()
                .await
                .unwrap()
                .read_to_end(8)
                .await
                .unwrap(),
            b"uni"
        );

        let (mut send, mut recv) = server.open_bi().await.unwrap();
        send.write_all(b"bidi").await.unwrap();
        send.finish().unwrap();
        let (mut reply, mut request) = client.accept_bi().await.unwrap();
        assert_eq!(request.read_to_end(8).await.unwrap(), b"bidi");
        reply.write_all(b"ok").await.unwrap();
        reply.finish().unwrap();
        assert_eq!(recv.read_to_end(8).await.unwrap(), b"ok");

        client
            .send_datagram_wait(Bytes::from_static(b"udp"))
            .await
            .unwrap();
        let raw = Connection::read_datagram(&server).await.unwrap();
        assert_eq!(&raw[..], b"\x40\x40udp");
        Connection::send_datagram(&server, Bytes::from_static(b"\x41\x00wrong")).unwrap();
        Connection::send_datagram(&server, Bytes::from_static(b"\x40\x40echo")).unwrap();
        assert_eq!(client.read_datagram().await.unwrap(), b"echo"[..]);

        client.close(42, b"done");
        drop(client);
        assert_eq!(
            server.closed().await,
            SessionEnd::Closed {
                code: 42,
                reason: "done".into(),
                remote: true
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn unknown_frames_and_capsules_are_ignored_and_drain_notifies() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let wt = Wt::new(&Options::default());
        let (client, server) = connected(&wt).await;
        let client = tokio::spawn(Session::connect(client, wt.url));
        let mut request = Request::accept(server).await.unwrap();
        h3::write_response(&mut request.connect.0, StatusCode::NO_CONTENT)
            .await
            .unwrap();
        let client = client.await.unwrap().unwrap();
        let mut existing = client.open_uni().await.unwrap();
        h3::write_frame(&mut request.setup.h3.send, 0x21, b"unknown control frame")
            .await
            .unwrap();
        h3::write_frame(&mut request.connect.0, 0x21, b"unknown request frame")
            .await
            .unwrap();
        let mut body = Vec::new();
        // WT_MAX_DATA, an unknown capsule, then DRAIN, each fragmented
        // across individual HTTP/3 DATA frames.
        for ty in [0x190b_4d3d, 0x1234] {
            h3::put(&mut body, ty);
            body.extend_from_slice(&[1, 0]);
        }
        h3::put(&mut body, WT_DRAIN_SESSION);
        body.push(0);
        for encoded in body {
            h3::write_frame(&mut request.connect.0, h3::DATA, [encoded])
                .await
                .unwrap();
        }
        client.draining().await.unwrap();
        let _after_drain = client.open_bi().await.unwrap();
        existing.write_all(b"still live").await.unwrap();
        existing.finish().unwrap();
        let (mut incoming, kind, id) = request.setup.uni.next(&request.setup.conn.0).await.unwrap();
        assert_eq!((kind, id), (h3::WT_UNI, Some(request.id())));
        assert_eq!(incoming.read_to_end(32).await.unwrap(), b"still live");
        // Drain leaves the session and its datagrams alive.
        client
            .send_datagram_wait(Bytes::from_static(b"after drain"))
            .await
            .unwrap();
        let received = request.conn().read_datagram().await.unwrap();
        assert_eq!(&received[..], b"\x00after drain");

        let mut close = Vec::new();
        h3::put(&mut close, WT_CLOSE_SESSION);
        close.extend_from_slice(&[5, 0, 0, 0, 17, b'x']);
        for encoded in close {
            h3::write_frame(&mut request.connect.0, h3::DATA, [encoded])
                .await
                .unwrap();
        }
        request.connect.0.finish().unwrap();
        assert_eq!(
            client.closed().await,
            SessionEnd::Closed {
                code: 17,
                reason: "x".into(),
                remote: true
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ordinary_reset_and_stop_sending_keep_webtransport_error_codes() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, server) = Wt::new(&Options::default()).pair().await;
        let (mut send, _recv) = client.open_bi().await.unwrap();
        send.write_all(b"visible").await.unwrap();
        let (mut reply, mut request) = server.accept_bi().await.unwrap();
        let reset = application_code(42);
        let stop = application_code(17);
        send.reset(reset).unwrap();
        assert_eq!(request.received_reset().await.unwrap(), Some(reset));

        let (mut send, _recv) = server.open_bi().await.unwrap();
        send.write_all(b"visible").await.unwrap();
        let (_reply, mut recv) = client.accept_bi().await.unwrap();
        recv.stop(stop).unwrap();
        assert_eq!(send.stopped().await.unwrap(), Some(stop));
        // A per-stream reset leaves the session alive.
        reply.write_all(b"still live").await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn legacy_connect_is_accepted_and_http_refusals_keep_the_status() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let wt = Wt::new(&Options::default());
        let (client, server) = connected(&wt).await;
        let incoming = tokio::spawn(Request::accept(server));
        let mut control = client.open_uni().await.unwrap();
        control.write_all(&[0, 4, 2, 0x33, 1]).await.unwrap();
        let mut server_settings = client.accept_uni().await.unwrap();
        assert_eq!(h3::read(&mut server_settings).await.unwrap(), Some(0));
        assert!(
            h3::receive_settings(&mut server_settings, true)
                .await
                .unwrap()
        );
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        let fields = [
            qpack::HeaderField::new(&b":method"[..], &b"CONNECT"[..]),
            qpack::HeaderField::new(&b":scheme"[..], &b"https"[..]),
            qpack::HeaderField::new(&b":authority"[..], &b"example.org"[..]),
            qpack::HeaderField::new(&b":path"[..], &b"/carrier"[..]),
            qpack::HeaderField::new(&b":protocol"[..], &b"webtransport"[..]),
        ];
        let mut encoded = Vec::new();
        qpack::encode_stateless(&mut encoded, fields).unwrap();
        h3::write_frame(&mut send, h3::HEADERS, encoded)
            .await
            .unwrap();
        let request = incoming.await.unwrap().unwrap();
        assert_eq!(request.url.as_str(), "https://example.org/carrier");
        let session = request.ok().await.unwrap();
        assert_eq!(h3::read_response(&mut recv).await.unwrap(), StatusCode::OK);
        drop((control, server_settings, session));

        let (client, server) = connected(&wt).await;
        let (client, server) = tokio::join!(Session::connect(client, wt.url), async {
            Request::accept(server)
                .await
                .unwrap()
                .reject(StatusCode::TOO_MANY_REQUESTS)
                .await
        },);
        server.unwrap();
        let error = client.unwrap_err();
        let refused = error
            .get_ref()
            .unwrap()
            .downcast_ref::<ConnectRejected>()
            .unwrap();
        assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn webtransport_requires_the_quic_datagram_parameter() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let options = Options::default();
        let mut wt = Wt::new(&options);
        let mut transport = options.transport_config();
        transport.datagram_receive_buffer_size(None);
        wt.client_config.transport_config(Arc::new(transport));
        let (_client, server) = connected(&wt).await;
        let Err(error) = Request::accept(server).await else {
            panic!("WebTransport without QUIC DATAGRAM");
        };
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connect_validates_origin_and_processes_informational_and_final_responses() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = Wt::new(&Options::default());
        for (origin, response) in [
            (
                fixture.url.origin().ascii_serialization(),
                StatusCode::NO_CONTENT,
            ),
            (
                fixture.url.origin().ascii_serialization(),
                StatusCode::FOUND,
            ),
            ("https://elsewhere.example".into(), StatusCode::FORBIDDEN),
        ] {
            let (client, server) = connected(&fixture).await;
            let mut connect = ConnectRequest::new(fixture.url.clone());
            connect
                .headers
                .insert(http::header::ORIGIN, origin.parse().unwrap());
            let client = tokio::spawn(Session::connect(client, connect));
            let mut accepted = None;
            if response == StatusCode::FORBIDDEN {
                match Request::accept(server).await {
                    Err(error) => assert_eq!(error.kind(), io::ErrorKind::PermissionDenied),
                    Ok(_) => panic!("cross-origin CONNECT was accepted"),
                }
            } else {
                let mut request = Request::accept(server).await.unwrap();
                h3::write_response(&mut request.connect.0, StatusCode::EARLY_HINTS)
                    .await
                    .unwrap();
                h3::write_response(&mut request.connect.0, response)
                    .await
                    .unwrap();
                accepted = Some(request);
            }
            let outcome = client.await.unwrap();
            if response.is_success() {
                assert_eq!(outcome.unwrap().id(), 0);
            } else {
                let error = outcome.unwrap_err();
                let refusal = error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<ConnectRejected>()
                    .unwrap();
                assert_eq!(refusal.status, response);
            }
            drop(accepted);
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn session_rejects_a_second_connect_and_an_invalid_association_id() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (client, server) = Wt::new(&Options::default()).pair().await;
        let (mut send, mut recv) = Connection::open_bi(&client).await.unwrap();
        h3::write_request(&mut send, &client.request().url, &HeaderMap::new()).await.unwrap();
        let duplicate = async {
            assert_eq!(recv.received_reset().await.unwrap(), Some(H3_REQUEST_REJECTED));
            let (mut valid, _) = client.open_bi().await.unwrap();
            valid.write_all(b"valid").await.unwrap();
            valid.finish().unwrap();
        };
        let ((), accepted) = tokio::join!(duplicate, server.accept_bi());
        let (_send, mut accepted) = accepted.unwrap();
        assert_eq!(accepted.read_to_end(8).await.unwrap(), b"valid");

        let mut invalid = Connection::open_uni(&client).await.unwrap();
        invalid.write_all(&h3::prefix(h3::WT_UNI, 2)).await.unwrap();
        let (incoming, closed) = tokio::join!(server.accept_uni(), Connection::closed(&client));
        assert!(incoming.is_err());
        assert!(matches!(closed, quinn::ConnectionError::ApplicationClosed(close) if close.error_code == H3_ID_ERROR));
    }).await.unwrap();
}

#[tokio::test]
async fn clean_connect_fin_and_extra_payload_after_close() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = Wt::new(&Options::default());
        for extra in [false, true] {
            let (client, server) = connected(&fixture).await;
            let client = tokio::spawn(Session::connect(client, fixture.url.clone()));
            let mut request = Request::accept(server).await.unwrap();
            h3::write_response(&mut request.connect.0, StatusCode::OK).await.unwrap();
            let session = client.await.unwrap().unwrap();
            if extra {
                let mut body = Vec::new();
                h3::put(&mut body, WT_CLOSE_SESSION);
                body.extend_from_slice(&[4, 0, 0, 0, 42, 1]);
                h3::write_frame(&mut request.connect.0, h3::DATA, body).await.unwrap();
            }
            request.connect.0.finish().unwrap();
            let end = session.closed().await;
            if extra {
                assert_eq!(end, SessionEnd::Failed("payload after WebTransport CLOSE capsule".into()));
                let closed = Connection::closed(request.conn()).await;
                assert!(matches!(closed, quinn::ConnectionError::ApplicationClosed(close) if close.error_code == H3_MESSAGE_ERROR));
            } else {
                assert_eq!(end, SessionEnd::Finished);
            }
        }
    }).await.unwrap();
}

#[tokio::test]
async fn close_aborts_active_stream_halves_with_wt_session_gone() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = Wt::new(&Options::default());
        let (client, server) = connected(&fixture).await;
        let client = tokio::spawn(Session::connect(client, fixture.url.clone()));
        let mut request = Request::accept(server).await.unwrap();
        h3::write_response(&mut request.connect.0, StatusCode::OK)
            .await
            .unwrap();
        let client = client.await.unwrap().unwrap();

        let (mut active, _recv) = client.open_bi().await.unwrap();
        active.write_all(b"open").await.unwrap();
        let ((send, mut recv), ty, id) =
            request.setup.bi.next(&request.setup.conn.0).await.unwrap();
        assert_eq!((ty, id), (h3::WT_BIDI, Some(0)));
        let mut data = [0; 4];
        recv.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"open");

        client.close(42, b"bye");
        let mut capsules = Capsules::default();
        let (drain, _) = watch::channel(false);
        let (reset, stop, close) = tokio::join!(
            recv.received_reset(),
            send.stopped(),
            capsules.receive(&mut request.connect.1, &drain),
        );
        assert_eq!(reset.unwrap(), Some(WT_SESSION_GONE));
        assert_eq!(stop.unwrap(), Some(WT_SESSION_GONE));
        assert_eq!(
            close.unwrap(),
            SessionEnd::Closed {
                code: 42,
                reason: "bye".into(),
                remote: true
            }
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn early_wt_stream_is_delivered_after_connect() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let fixture = Wt::new(&Options::default());
        let (client, server) = connected(&fixture).await;
        let incoming = tokio::spawn(Request::accept(server));
        let setup = Setup::new(client, true).await.unwrap();
        let (mut connect, mut response) = setup.conn.0.open_bi().await.unwrap();
        let (mut early, _recv) = setup.conn.0.open_bi().await.unwrap();
        early.write_all(&h3::prefix(h3::WT_BIDI, 0)).await.unwrap();
        early.write_all(b"early").await.unwrap();
        early.finish().unwrap();
        // The entire data stream reaches the server before CONNECT is written.
        assert_eq!(early.stopped().await.unwrap(), None);
        h3::write_request(&mut connect, &fixture.url, &HeaderMap::new())
            .await
            .unwrap();
        let server = incoming.await.unwrap().unwrap().ok().await.unwrap();
        assert_eq!(
            h3::read_response(&mut response).await.unwrap(),
            StatusCode::OK
        );
        let (_send, mut recv) = server.accept_bi().await.unwrap();
        assert_eq!(recv.read_to_end(8).await.unwrap(), b"early");
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn finished_streams_return_real_quic_credit() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let options = Options::default();
        let mut fixture = Wt::new(&options);
        let mut transport = options.transport_config();
        transport.max_concurrent_bidi_streams(VarInt::from_u32(1));
        fixture.client_config.transport_config(Arc::new(transport));
        let (client, server) = connected(&fixture).await;
        let (client, server) = tokio::join!(Session::connect(client, fixture.url), async {
            Request::accept(server).await.unwrap().ok().await
        });
        let (client, server) = (client.unwrap(), server.unwrap());
        let (mut send, mut recv) = server.open_bi().await.unwrap();
        let (mut reply, mut inbound) = client.accept_bi().await.unwrap();
        let mut next = std::pin::pin!(server.open_bi());
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(next.as_mut().poll(cx).is_pending()))
                .await
        );
        send.write_all(b"fin").await.unwrap();
        send.finish().unwrap();
        assert_eq!(inbound.read_to_end(8).await.unwrap(), b"fin");
        reply.write_all(b"ack").await.unwrap();
        reply.finish().unwrap();
        assert_eq!(recv.read_to_end(8).await.unwrap(), b"ack");
        drop((send, recv, reply, inbound));
        assert!(next.await.is_ok());
    })
    .await
    .unwrap();
}
