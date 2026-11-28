//! Completed records and source attribution through the carrier I/O owners.

use std::sync::Arc;
use std::time::Duration;

use zmux::{
    AccountingTickets, CarrierHalfSource, CarrierHalfSources, CarrierKind, Config, Listener,
    ListenerConfig, PipeAuth, PipeHint, PipeId, PipeIo, PipeOptions, Session, SessionId,
};

fn source(route: &'static str) -> CarrierHalfSource {
    let mut source = CarrierHalfSource::new(CarrierKind::Streaming, None);
    source.route = Some(Arc::from(route));
    source
}

#[tokio::test(start_paused = true)]
async fn the_bootstrap_ticket_outlives_the_session_and_matches_the_peer_records() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (a, b) = tokio::io::duplex(64 << 10);
        let tickets = AccountingTickets::default();
        let config = Config::default().with_accounting_tickets(&tickets);
        let client = PipeIo::new(a).with_accounting_sources(CarrierHalfSources {
            send: source("client-send"),
            receive: source("client-receive"),
        });
        let server = PipeIo::new(b).with_accounting_sources(CarrierHalfSources {
            send: source("server-send"),
            receive: source("server-receive"),
        });
        let (client, server) = tokio::join!(
            Session::connect(client, config.clone()),
            Session::accept(server, config),
        );
        let (client, server) = (client.unwrap(), server.unwrap());
        let bootstrap = PipeId::new(0);
        let (client_number, server_id) = (client.id().get(), server.id());

        let (mut write, mut read) = client.open_bi().await.unwrap();
        write.write_all(b"record accounting").await.unwrap();
        write.finish().unwrap();
        let (mut echo, mut request) = server.accept_bi().await.unwrap();
        let payload = request.read_to_end(1024).await.unwrap();
        echo.write_all(&payload).await.unwrap();
        echo.finish().unwrap();
        assert_eq!(read.read_to_end(1024).await.unwrap(), b"record accounting");

        let active = client
            .pipe(bootstrap)
            .unwrap()
            .stats()
            .unwrap()
            .accounting
            .unwrap();
        assert_eq!(active.send[0].source, source("client-send"));
        assert_eq!(active.receive[0].source, source("client-receive"));
        assert!(active.send[0].records > 0 && active.receive[0].records > 0);
        client.close().await;
        server.closed().await;
        drop((client, server));

        assert_eq!(SessionId::from_raw(0), None);
        let client_id = SessionId::from_raw(client_number).unwrap();
        let client_ticket = tickets.take(client_id, bootstrap).unwrap();
        assert!(tickets.take(client_id, bootstrap).is_none());
        let [(returned_session, returned_pipe, server_ticket)] =
            tickets.drain().try_into().unwrap();
        assert_eq!((returned_session, returned_pipe), (server_id, bootstrap));
        assert!(tickets.drain().is_empty());
        let (a, b) = tokio::join!(client_ticket.wait(), server_ticket.wait());
        assert_eq!(a, client_ticket.wait().await);
        assert!(a.send[0].bytes >= active.send[0].bytes);
        assert!(a.receive[0].bytes >= active.receive[0].bytes);
        assert_eq!(a.send[0].source, source("client-send"));
        assert_eq!(b.receive[0].source, source("server-receive"));
        // The data has crossed both directions before close. A peer may
        // still have transport control in flight when its reader stops.
        assert!(b.receive[0].bytes >= active.send[0].bytes);
        assert!(b.send[0].bytes >= active.receive[0].bytes);
        assert_eq!(a.send[0].partial_bytes, 0);
        assert_eq!(b.receive[0].partial_bytes, 0);
    })
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn both_join_tickets_are_available_after_retirement() {
    tokio::time::timeout(Duration::from_secs(60), async {
        let tickets = AccountingTickets::default();
        let config = Config::multipath(PipeAuth::psk([9; 32]).with_end_to_end())
            .with_accounting_tickets(&tickets);
        let listener = Listener::new(config.clone(), ListenerConfig::default()).unwrap();
        let (client_io, server_io) = tokio::io::duplex(64 << 10);
        let (client, server) =
            tokio::join!(Session::connect(PipeIo::new(client_io), config), async {
                listener
                    .handle_pipe(PipeIo::new(server_io), PipeHint::default())
                    .await
                    .unwrap();
                listener.accept().await.unwrap()
            },);
        let client = client.unwrap();
        client.established().await.unwrap();
        server.established().await.unwrap();

        let (client_io, server_io) = tokio::io::duplex(64 << 10);
        let join = client
            .test_begin_join(PipeIo::new(client_io), PipeOptions::default())
            .unwrap();
        listener
            .handle_pipe(PipeIo::new(server_io), PipeHint::default())
            .await
            .unwrap();
        join.attached().await.unwrap();
        let id = join.id();
        let remote = server.pipe(id).unwrap();
        join.close().unwrap();
        let (local_end, remote_end) = tokio::join!(join.closed(), remote.closed());
        local_end.unwrap();
        remote_end.unwrap();
        assert!(client.pipe(id).is_none() && server.pipe(id).is_none());
        drop((join, remote));

        let local = tickets.take(client.id(), id).unwrap().wait().await;
        let peer = tickets.take(server.id(), id).unwrap().wait().await;
        assert_eq!((local.pipe, peer.pipe), (id, id));
        assert!(tickets.take(client.id(), id).is_none());
    })
    .await
    .unwrap();
}
