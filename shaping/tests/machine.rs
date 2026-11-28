//! Tests for machine compilation and installation.

#[path = "../../tests/common/core_pair.rs"]
mod core_pair;

use std::sync::Arc;
use std::time::Duration;

use zmux::PipeId;
use zmux::shaping::{Caps, Effects, Event, EventKind, Shaper};
use zmux_shaping::{Bundle, MachineFactory, Options, parse_limits};

#[test]
fn limits_and_budget_require_a_bounded_account() {
    let limits = parse_limits(
        br#"{"wire":{"ceiling":100,"initial":20},"profile":{
        "window_seconds":10,"floor_bytes":540,"extra_bytes_ppm":50000,"max_added_delay":250}}"#,
    )
    .unwrap();
    assert_eq!(limits.wire.unwrap().ceiling, 100);
    assert_eq!(
        limits.profile.unwrap().max_added_delay,
        Duration::from_micros(250)
    );
    assert!(parse_limits(br#"{"wire":{"initial":1}}"#).is_err());
    assert!(parse_limits(br#"{"wire":{"ceiling":0,"initial":1}}"#).is_err());

    let invalid = br#"{"schema":2,"kinds":{"default":[{"budget":{"wire":{
        "ceiling":{"t":[[1,2,3]],"scope":"session"},"initial":{"t":[[1,1,3]],"scope":"session"}}}}]}}"#;
    assert!(Bundle::from_json(invalid, &Options::default()).is_err());
    let valid = br#"{"schema":2,"kinds":{"default":[{"budget":{"wire":{
        "ceiling":100,"initial":{"t":[[1,20,20]],"scope":"session"}}}}]}}"#;
    let bundle = Bundle::from_json(valid, &Options::default()).unwrap();
    let budget = bundle
        .resolve("default")
        .unwrap()
        .budget()
        .unwrap()
        .ask()
        .unwrap();
    assert_eq!(budget.wire.unwrap().initial, 20);
}

#[test]
fn outbound_and_native_planning_use_distinct_machine_entrances() {
    use zmux::shaping::{DatagramPlan, DatagramView};
    let definition = br#"{"include_control":true,"machines":[{"start":0,"states":[
        {"record":{"pad":7},"datagram":{"pad_to":17},"next":[{"on":"datagram_plan","to":1}]},
        {"record":{"pad":11},"enter":[{"op":"inject","after":0,"len":9}],
         "next":[{"on":"outbound","to":2}]},
        {"enter":[{"op":"inject","after":0,"len":5}],
         "next":[{"on":"injection_rejected","to":1}]}]}]}"#;
    let factory = MachineFactory::from_json(definition, Options::default()).unwrap();
    assert!(
        factory
            .capabilities()
            .contains(Caps::OUTBOUND | Caps::INCLUDE_CONTROL | Caps::DATAGRAM_PLAN)
    );
    let mut shaper = factory.shaper();
    let pipe = PipeId::new(0);
    shaper.on_event(
        &Event::new(EventKind::Start, pipe, 0),
        &mut Effects::default(),
    );
    let mut plan = DatagramPlan::default();
    shaper.plan_datagram(&DatagramView::new(pipe, 0, 8, 1280, 1280), &mut plan);
    assert_eq!(plan.unit.pad_to, 17);
    assert_eq!(plan.effects.inject, None);
    let mut effects = Effects::default();
    let mut outbound = Event::new(EventKind::Outbound, pipe, 1);
    outbound.data = true;
    shaper.on_event(&outbound, &mut effects);
    let request = effects.inject.flatten().unwrap();
    assert_eq!(request.pad_bytes, 5);

    let mut reject = Event::new(EventKind::InjectionRejected, pipe, 1);
    reject.request_id = request.id;
    effects = Effects::default();
    shaper.on_event(&reject, &mut effects);
    assert_eq!(effects.inject, Some(None));
}

#[test]
fn a_rate_conflict_preserves_the_published_policy() {
    let definition = |rate: u32| {
        serde_json::json!({"machines":[{
            "start":0,"states":[{"enter":[{"op":"rate","rate":rate,"burst":64}]}]
        }]})
        .to_string()
    };
    let compile = |rate| MachineFactory::from_json(definition(rate).as_bytes(), Options::default());
    assert_eq!(compile(31_999).unwrap_err().class(), "conflict");
    let mut pair = core_pair::CorePair::new(zmux::Config::default(), zmux::Config::default());
    pair.a
        .set_shaper(Some(Arc::new(compile(3_000_000).unwrap())))
        .unwrap();
    let prior = pair.a.shaping_stats();
    // The standalone bucket can recover in 2 ms. The session has a longer
    // indivisible preamble and must reject this same rate at publication.
    let rejected = pair
        .a
        .set_shaper(Some(Arc::new(compile(32_000).unwrap())))
        .unwrap_err();
    assert!(rejected.reason().contains("conflict"));
    assert_eq!(pair.a.shaping_stats(), prior);
}
