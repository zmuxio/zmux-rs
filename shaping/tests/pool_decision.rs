//! A machine pool policy evaluates to its values as they are and the
//! `PoolDecision` built from them refuses one out of range: the refusal is
//! the error `decide` returns, which the pool takes as its rejection.

#![cfg(feature = "tokio")]

use zmux::helpers::{PoolDecision, PoolPolicy, PoolView};
use zmux_shaping::{MemberDecision, Options, pool_policy};

#[test]
fn an_interval_below_one_second_is_evaluated_and_refused_by_the_decision() {
    // 0.2 s, in microseconds as the policy file gives it.
    let json = br#"{"probe_interval": 200000}"#;
    let mut p = pool_policy(json, Options::default()).unwrap();
    // The evaluation outputs it, unchanged.
    let mut out = MemberDecision::default();
    p.decide_members(0, None, &[], &mut out);
    assert_eq!(out.probe_interval, Some(200_000));
    // Building the PoolDecision refuses it: `decide` fails.
    let mut d = PoolDecision::default();
    let e = p.decide(&PoolView::default(), &mut d).unwrap_err();
    assert!(e.to_string().contains("probe_interval"), "{e}");
    assert!(d.liveness().is_none(), "nothing of it was set");
}

#[test]
fn an_interval_of_zero_or_at_least_one_second_builds() {
    for (json, interval) in [
        (&br#"{"probe_interval": 0}"#[..], None),
        (
            br#"{"probe_interval": 1000000}"#,
            Some(std::time::Duration::from_secs(1)),
        ),
    ] {
        let mut p = pool_policy(json, Options::default()).unwrap();
        let mut d = PoolDecision::default();
        p.decide(&PoolView::default(), &mut d).unwrap();
        let l = d.liveness().expect("the probe settings are set");
        assert_eq!(l.probe_interval, zmux::Inherit::Set(interval));
    }
}
