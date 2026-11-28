//! Bootstrap write ownership before the handshake releases the first flight.

#[path = "common/core_pair.rs"]
mod core_pair;

use std::time::Duration;

use core_pair::{CorePair, P0};
use zmux::proto::frame::Dir;
use zmux::{Config, EarlyData};

fn held() -> Config {
    let mut config = Config::default();
    config.early_data = EarlyData::default().with_hold_first_flight(true);
    config
}

#[test]
fn release_sends_parameters_then_application_waits_for_the_peer() {
    let mut pair = CorePair::attached(held(), Config::default());
    let stream = pair.a.open(Dir::Bidi).unwrap();
    pair.a.write(stream, b"request").unwrap();

    assert_eq!(pair.send(true), 0);
    pair.a.release_first_flight(pair.now);
    pair.a.release_first_flight(pair.now);
    assert!(pair.send(true) > 0);
    assert!(pair.b.accept(Dir::Bidi).unwrap().is_none());

    pair.pump();
    let stream = pair.b.accept(Dir::Bidi).unwrap().unwrap();
    let mut buf = [0; 7];
    assert_eq!(pair.b.read(stream, &mut buf).unwrap(), Some((7, false)));
    assert_eq!(&buf, b"request");
    assert_eq!(pair.a.stats().first_flight_timeouts, 0);
}

#[test]
fn the_handshake_timeout_releases_the_first_flight() {
    let mut config = held();
    let wait = Duration::from_secs(5);
    config.handshake_timeout = Some(wait);
    let mut pair = CorePair::attached(config, Config::default());
    pair.a
        .handle_timeout(pair.now + wait.saturating_sub(Duration::from_nanos(1)));
    assert_eq!(pair.send(true), 0);

    pair.now += wait;
    pair.a.handle_timeout(pair.now);
    pair.pump();
    assert!(pair.a.is_established());
    assert_eq!(pair.a.stats().first_flight_timeouts, 1);
}

#[test]
fn abort_releases_the_first_flight() {
    let mut pair = CorePair::attached(held(), Config::default());
    pair.a.abort(9u32.into(), b"bye", pair.now);
    pair.a.poll_transmit(P0, pair.now, &mut pair.out);
    assert!(!pair.out.is_empty());
}
