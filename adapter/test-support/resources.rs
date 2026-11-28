use std::time::Duration;

/// Runtime resource snapshots have no completion signal.
pub(crate) async fn wait_for_resources<T: std::fmt::Debug>(
    describe: &str,
    observe: impl Fn() -> T,
    ready: impl Fn(&T) -> bool,
) {
    let observed = tokio::time::timeout(Duration::from_secs(60), async {
        let mut tick = tokio::time::interval(Duration::from_millis(20));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if ready(&observe()) {
                return;
            }
            tick.tick().await;
        }
    })
    .await;
    assert!(
        observed.is_ok(),
        "{describe}, last observation: {:?}",
        observe()
    );
}
