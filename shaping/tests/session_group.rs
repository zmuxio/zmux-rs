//! Session targets compiled from a shaping profile.

#![cfg(feature = "tokio")]

use std::time::Duration;

use zmux::{Directions, TargetCandidate};
use zmux_shaping::{Bundle, Options};

#[test]
fn session_group_resolves_count_and_chooses_strongest_rotation_limits() {
    let bundle = Bundle::from_json(
        br#"{
        
        "kinds":{"default":[{"pool":{
            "count":2,
            "retire":[
                {"metric":"age","above":5000000},
                {"metric":"age","above":2000000},
                {"metric":"bytes_sent","above":4096},
                {"metric":"bytes_received","above":2048}
            ]
        }}]}
    }"#,
        &Options::default(),
    )
    .unwrap();
    let profile = bundle.resolve("default").unwrap();
    let group = profile.session_group(
        "paths",
        vec![TargetCandidate {
            id: "direct".into(),
            send: None,
            receive: None,
        }],
    );
    assert_eq!(group.id, "paths");
    assert_eq!(group.quotas[0].count, 2);
    assert_eq!(group.quotas[0].directions, Directions::BOTH);
    assert_eq!(group.quotas[0].candidates[0].id, "direct".into());
    assert_eq!(group.rotation.max_age, Some(Duration::from_secs(2)));
    assert_eq!(group.rotation.send_bytes, Some(4096));
    assert_eq!(group.rotation.receive_bytes, Some(2048));
}
