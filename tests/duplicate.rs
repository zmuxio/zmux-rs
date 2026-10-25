//! `helpers::resolve_duplicate` (EXTENSIONS.md Section 11): two endpoints that
//! dialed each other keep the same session at
//! both ends, by identities, by the dialers' Session Nonces or by their
//! role nonces, and drain the other one: no new streams, GOAWAY, and a
//! close with NO_ERROR once its streams have ended.

mod common;

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{connect, duplex, eventually, multi_thread, settle, snapshot, watchdog};

use zmux::helpers::{DuplicateError, DuplicateRule, resolve_duplicate};
use zmux::{Config, OpenError, PipeAuth, Session, SessionError, VarInt};

use zmux::helpers::DuplicateOptions;

/// One endpoint's view of the two sessions: `mine` it dialed, `theirs`
/// the peer dialed.
struct End {
    mine: Session,
    theirs: Session,
}

/// Two sessions between endpoints 1 and 2, one dialed by each: endpoint
/// 1's view and endpoint 2's.
async fn race(c1: Config, c2: Config) -> (End, End) {
    let ((a, _), (b, _)) = duplex(1 << 20);
    let (dialed_by_1, accepted_by_2) = connect(a, b, c1.clone(), c2.clone()).await;
    let ((a, _), (b, _)) = duplex(1 << 20);
    let (dialed_by_2, accepted_by_1) = connect(a, b, c2, c1).await;
    (
        End {
            mine: dialed_by_1,
            theirs: accepted_by_1,
        },
        End {
            mine: dialed_by_2,
            theirs: accepted_by_2,
        },
    )
}

/// Resolves at both ends and checks that they keep the same session:
/// returns whether that is the one endpoint 1 dialed, and whether endpoint
/// 1 started a rejoin of its route.
fn both_ends(
    e1: &End,
    e2: &End,
    o1: &DuplicateOptions,
    o2: &DuplicateOptions,
    rule: DuplicateRule,
) -> (bool, bool) {
    let r1 = resolve_duplicate(&e1.mine, &e1.theirs, o1).unwrap();
    // Endpoint 2 lists them the other way round.
    let r2 = resolve_duplicate(&e2.theirs, &e2.mine, o2).unwrap();
    assert_eq!((r1.rule, r2.rule), (rule, rule));
    let kept_1s = r1.survivor.stable_id() == e1.mine.stable_id();
    let kept_1s_at_2 = r2.survivor.stable_id() == e2.theirs.stable_id();
    assert_eq!(kept_1s, kept_1s_at_2, "both ends keep the same session");
    assert!(!r2.rejoin_started, "endpoint 2 has no dial function");
    (kept_1s, r1.rejoin_started)
}

async fn drained(e1: &End, e2: &End, kept_1s: bool) {
    let (keep, lose) = if kept_1s {
        ([&e1.mine, &e2.theirs], [&e1.theirs, &e2.mine])
    } else {
        ([&e1.theirs, &e2.mine], [&e1.mine, &e2.theirs])
    };
    for s in lose {
        let e = watchdog(10, "the loser closes", s.closed()).await;
        assert!(
            matches!(e, SessionError::ApplicationClosed { code, .. } if code == VarInt::ZERO),
            "{e:?}"
        );
    }
    for s in keep {
        assert!(
            s.close_reason().is_none(),
            "the survivor stays: {:?}",
            s.close_reason()
        );
        s.close(VarInt::ZERO, b"");
    }
}

fn multipath(nonce: u8) -> Config {
    let mut c = Config::default();
    c.max_pipes = 4;
    c.pipe_auth = PipeAuth::psk(*b"duplicate-psk---0123456789abcdef");
    c.test_hooks().session_nonce = Some([nonce; 16]);
    c
}

#[test]
fn identities_decide_first() {
    multi_thread(async {
        let base = snapshot();
        for (id1, id2) in [(b"alice", b"bob00"), (b"zed00", b"bob00")] {
            let (e1, e2) = race(Config::default(), Config::default()).await;
            let o1 = DuplicateOptions::with_identities(*id1, *id2);
            let o2 = DuplicateOptions::with_identities(*id2, *id1);
            let (kept, _) = both_ends(&e1, &e2, &o1, &o2, DuplicateRule::Identity);
            assert_eq!(kept, id1 < id2, "the smaller identity's dial survives");
            drained(&e1, &e2, kept).await;
        }
        settle(base, 10, "identities").await;
    });
}

#[test]
fn session_nonces_decide_between_multipath_sessions() {
    multi_thread(async {
        let base = snapshot();
        for (n1, n2) in [(1, 2), (9, 3)] {
            let (e1, e2) = race(multipath(n1), multipath(n2)).await;
            assert!(e1.mine.multipath() == zmux::Multipath::InUse);
            let none = DuplicateOptions::default();
            let (dials, o1) = failing_rejoin();
            let (kept, rejoin) = both_ends(&e1, &e2, &o1, &none, DuplicateRule::SessionNonce);
            assert_eq!(kept, n1 < n2, "the smaller dialer nonce survives");
            // The loser's dialer rejoins its route to the survivor, in the
            // background; the dial fails, which undoes nothing.
            assert_eq!(rejoin, !kept, "endpoint 1 dialed the loser");
            eventually(5, "the dial ran", || {
                dials.load(Ordering::Relaxed) == usize::from(rejoin)
            })
            .await;
            drained(&e1, &e2, kept).await;
        }
        settle(base, 10, "session nonces").await;
    });
}

/// Rejoin options whose dial fails, and how often it ran.
fn failing_rejoin() -> (Arc<AtomicUsize>, DuplicateOptions) {
    let dials = Arc::new(AtomicUsize::new(0));
    let counted = dials.clone();
    let dial = zmux::Dial::new(move |_req| {
        counted.fetch_add(1, Ordering::Relaxed);
        async { Err(io::Error::from(io::ErrorKind::ConnectionRefused)) }
    });
    (dials, DuplicateOptions::default().with_rejoin(dial))
}

/// `rejoin` is a hint, skipped (and reported as not
/// started) when the survivor has no room for a pipe of its own: here its
/// one attachment is all its `max_pipes` allows.
#[test]
fn a_rejoin_without_room_is_not_started() {
    multi_thread(async {
        let base = snapshot();
        {
            let one_pipe = |n| {
                let mut c = multipath(n);
                c.max_pipes = 1;
                c.resume_timeout = Some(std::time::Duration::from_secs(5));
                c
            };
            let (e1, e2) = race(one_pipe(9), one_pipe(3)).await;
            assert!(e1.mine.multipath() == zmux::Multipath::InUse);
            let none = DuplicateOptions::default();
            let (dials, o1) = failing_rejoin();
            let (kept, rejoin) = both_ends(&e1, &e2, &o1, &none, DuplicateRule::SessionNonce);
            assert!(!kept, "endpoint 1 dialed the loser");
            assert!(!rejoin, "no room on the survivor");
            assert_eq!(dials.load(Ordering::Relaxed), 0);
            drained(&e1, &e2, kept).await;
        }
        settle(base, 10, "rejoin without room").await;
    });
}

#[test]
fn role_nonces_decide_between_symmetric_sessions() {
    multi_thread(async {
        let base = snapshot();
        for (r1, r2) in [(5u64, 7u64), (8, 6)] {
            let mut c1 = Config::default();
            c1.test_hooks().role_nonce = Some(r1);
            let mut c2 = Config::default();
            c2.test_hooks().role_nonce = Some(r2);
            // Symmetric carriers: each endpoint designates the dialer.
            let peer = |a, b, x: Config, y: Config| async move {
                let other = tokio::spawn(Session::peer(b, y));
                let s = Session::peer(a, x).await.unwrap();
                (s, other.await.unwrap().unwrap())
            };
            let ((a, _), (b, _)) = duplex(1 << 20);
            let (dialed_by_1, at_2) = peer(a, b, c1.clone(), c2.clone()).await;
            let ((a, _), (b, _)) = duplex(1 << 20);
            let (dialed_by_2, at_1) = peer(a, b, c2, c1).await;
            let e1 = End {
                mine: dialed_by_1,
                theirs: at_1,
            };
            let e2 = End {
                mine: dialed_by_2,
                theirs: at_2,
            };
            let none = DuplicateOptions::default();
            assert_eq!(
                resolve_duplicate(&e1.mine, &e1.theirs, &none).err(),
                Some(DuplicateError::DialerUnknown)
            );
            for (s, d) in [
                (&e1.mine, true),
                (&e1.theirs, false),
                (&e2.mine, true),
                (&e2.theirs, false),
            ] {
                s.set_dialer(d);
            }
            let (kept, rejoin) = both_ends(&e1, &e2, &none, &none, DuplicateRule::RoleNonce);
            assert!(!rejoin, "single-pipe survivor");
            assert_eq!(kept, r1 < r2);
            drained(&e1, &e2, kept).await;
        }
        settle(base, 10, "role nonces").await;
    });
}

#[test]
fn the_loser_opens_nothing_new_and_closes_once_its_streams_ended() {
    multi_thread(async {
        let base = snapshot();
        {
            let (e1, e2) = race(Config::default(), Config::default()).await;
            // A stream in use on the session that will lose.
            let (mut send, mut recv) = e1.theirs.open_bi().await.unwrap();
            send.write_all(b"in flight").await.unwrap();
            let (mut far_send, mut far_recv) = e2.mine.accept_bi().await.unwrap();
            let o1 = DuplicateOptions::with_identities(*b"a", *b"b");
            let o2 = DuplicateOptions::with_identities(*b"b", *b"a");
            assert!(both_ends(&e1, &e2, &o1, &o2, DuplicateRule::Identity).0);
            assert!(matches!(
                e1.theirs.open_bi().await,
                Err(OpenError::GoingAway)
            ));
            eventually(5, "GOAWAY received", || e1.theirs.goaway().is_some()).await;
            assert!(
                e1.theirs.close_reason().is_none(),
                "kept while its stream lives"
            );
            // The stream completes, then the session closes.
            send.finish().unwrap();
            assert_eq!(far_recv.read_to_end(64).await.unwrap(), b"in flight");
            far_send.write_all(b"done").await.unwrap();
            far_send.finish().unwrap();
            assert_eq!(recv.read_to_end(64).await.unwrap(), b"done");
            drop((send, recv, far_send, far_recv));
            drained(&e1, &e2, true).await;
        }
        settle(base, 10, "drain").await;
    });
}

#[test]
fn the_rule_does_not_apply_without_a_race_or_a_deciding_value() {
    multi_thread(async {
        let (e1, e2) = race(Config::default(), Config::default()).await;
        let none = DuplicateOptions::default();
        // Same dialer: not a race.
        assert_eq!(
            resolve_duplicate(&e1.mine, &e2.mine, &none).err(),
            Some(DuplicateError::SameDialer)
        );
        // Fixed roles, one pipe, no identities: nothing decides.
        assert_eq!(
            resolve_duplicate(&e1.mine, &e1.theirs, &none).err(),
            Some(DuplicateError::Undecided)
        );
        // Equal identities: the endpoint reached itself.
        let same = DuplicateOptions::with_identities(*b"me", *b"me");
        assert_eq!(
            resolve_duplicate(&e1.mine, &e1.theirs, &same).err(),
            Some(DuplicateError::SelfConnection)
        );
        // Nothing changed.
        let all = [&e1.mine, &e1.theirs, &e2.mine, &e2.theirs];
        for s in all {
            assert!(s.goaway().is_none() && s.close_reason().is_none());
            assert!(s.open_bi().await.is_ok());
        }
        for s in all {
            s.close(VarInt::ZERO, b"");
        }
    });
}
