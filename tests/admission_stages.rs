//! Admission stages: the decision an upgrade's head defers to its carrier
//! ([`AdmissionVerdict::Defer`], [`Entry::admit_first`]), the first message
//! of a message-framed carrier and its bound, verdicts where they do not
//! apply, the listener's fallback of every carrier, and the counts, each
//! carrier's outcome counted once.

#![allow(
    clippy::items_after_statements,
    reason = "test-local helpers sit next to their only use"
)]

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, ReadBuf};
use zmux::adapter::{Admit, AdmitIo, Entry, Framing};
use zmux::{
    Admission, AdmissionStage, AdmissionVerdict, CarrierInfo, Config, Fallback, Listener,
    ListenerConfig, MAX_ADMISSION_MESSAGE, PipeIo, Takeover,
};

const LIMIT: Duration = Duration::from_secs(10);

/// A message-framed receiving half: one message per read, one longer than
/// the read's room refused whole; an empty message read is the end.
struct Messages(VecDeque<io::Result<Vec<u8>>>);

impl AsyncRead for Messages {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.0.pop_front() {
            None => Poll::Pending,
            Some(Err(e)) => Poll::Ready(Err(e)),
            Some(Ok(m)) if m.len() > buf.remaining() => {
                Poll::Ready(Err(zmux::adapter::message_too_large()))
            }
            Some(Ok(m)) => {
                buf.put_slice(&m);
                Poll::Ready(Ok(()))
            }
        }
    }
}

/// A message-framed carrier receiving `msgs`.
fn messages(msgs: Vec<io::Result<Vec<u8>>>) -> PipeIo {
    PipeIo::from_halves(Messages(msgs.into()), tokio::io::sink()).records()
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "an element of a list of read results"
)]
fn msg(b: &[u8]) -> io::Result<Vec<u8>> {
    Ok(b.to_vec())
}

/// What the decisions were called with: stage, framing, upgrade, source,
/// prefix.
type Calls = Arc<Mutex<Vec<(AdmissionStage, Framing, bool, Option<SocketAddr>, Vec<u8>)>>>;

/// An admission of `peek` recording its calls into the returned list,
/// deciding with `decide`.
fn recorded(
    peek: usize,
    decide: impl Fn(&CarrierInfo, &[u8]) -> AdmissionVerdict + Send + Sync + 'static,
) -> (Admission, Calls) {
    let calls = Calls::default();
    let c = calls.clone();
    let adm = Admission::new(peek, move |info: CarrierInfo, p: &[u8]| {
        c.lock().unwrap().push((
            info.stage,
            info.framing,
            info.upgrade,
            info.source,
            p.to_vec(),
        ));
        decide(&info, p)
    })
    .with_peek_timeout(Duration::from_secs(1))
    .with_stall_interval(Duration::from_millis(10), Duration::from_millis(10));
    (adm, calls)
}

fn listener(adm: Admission, fallback: Option<Fallback>) -> Listener {
    let mut limits = ListenerConfig::default();
    limits.admission = Some(adm);
    limits.fallback = fallback;
    limits.limits.max_pending_per_source = 2;
    Listener::new(Config::default(), limits).expect("valid listener configuration")
}

const PEER: &str = "192.0.2.1:7";

fn enter(l: &Listener) -> Entry {
    l.adapter().enter(PEER.parse().unwrap(), None).unwrap()
}

/// accepted, fallback, stalled, closed, stall overflow, too large, timed
/// out, failed handshake.
fn counts(l: &Listener) -> [u64; 8] {
    let a = l.stats().admission;
    [
        a.accepted,
        a.fallback,
        a.stalled,
        a.closed,
        a.stall_overflow,
        a.too_large,
        a.peek_timed_out,
        a.handshake_failed,
    ]
}

/// The decision that defers on an upgrade's head and accepts `ok` as the
/// first message.
fn defer_then(ok: &'static [u8]) -> impl Fn(&CarrierInfo, &[u8]) -> AdmissionVerdict {
    move |info, p| {
        if info.is_head() {
            AdmissionVerdict::Defer
        } else if p == ok {
            AdmissionVerdict::accept(0)
        } else {
            AdmissionVerdict::fallback()
        }
    }
}

/// A carrier that comes at once.
fn now(io: PipeIo) -> std::future::Ready<io::Result<AdmitIo>> {
    std::future::ready(Ok(AdmitIo::pipe(io)))
}

/// The next unit of `p`.
async fn unit(p: &mut PipeIo) -> Vec<u8> {
    let mut b = Vec::new();
    tokio::time::timeout(LIMIT, p.read_handshake(&mut b))
        .await
        .unwrap()
        .unwrap();
    b
}

#[tokio::test]
async fn a_deferred_upgrade_is_decided_on_its_first_message() {
    let (adm, calls) = recorded(0, defer_then(b"hello"));
    let l = listener(adm, None);
    let mut e = enter(&l);
    assert_eq!(e.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
    // The deferral itself is no outcome.
    assert_eq!(counts(&l), [0; 8]);
    let carrier = messages(vec![msg(b"hello"), msg(b"next")]);
    let mut p = e
        .admit_first(CarrierInfo::new(), now(carrier))
        .await
        .expect("accepted");
    let source = Some(PEER.parse().unwrap());
    assert_eq!(
        *calls.lock().unwrap(),
        [
            (
                AdmissionStage::Head,
                Framing::ByteStream,
                true,
                source,
                vec![]
            ),
            (
                AdmissionStage::Carrier,
                Framing::Records,
                true,
                source,
                b"hello".to_vec()
            ),
        ]
    );
    assert_eq!(counts(&l), [1, 0, 0, 0, 0, 0, 0, 0]);
    // The first message stays the carrier's.
    assert_eq!(unit(&mut p).await, b"hello");
    assert_eq!(unit(&mut p).await, b"next");
    assert!(e.is_admitted());
}

#[tokio::test]
async fn a_deferred_carrier_falls_back_with_its_first_message() {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let fallback = Fallback::new(move |t: Takeover| {
        let tx = tx.clone();
        async move {
            let info = (
                t.info().stage,
                t.framing(),
                t.info().upgrade,
                t.replayed().to_vec(),
                t.has_stream(),
            );
            let mut p = t.into_pipe();
            let first = unit(&mut p).await;
            let second = unit(&mut p).await;
            let _ = tx.send((info, first, second));
        }
    });
    let (adm, _) = recorded(0, defer_then(b"zmux"));
    let l = listener(adm, Some(fallback));
    let mut e = enter(&l);
    assert_eq!(e.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
    let carrier = messages(vec![msg(b"tunnel hello"), msg(b"more")]);
    assert!(
        e.admit_first(CarrierInfo::new(), now(carrier))
            .await
            .is_none()
    );
    let (info, first, second) = rx.recv().await.unwrap();
    assert_eq!(
        info,
        (
            AdmissionStage::Carrier,
            Framing::Records,
            true,
            b"tunnel hello".to_vec(),
            false
        )
    );
    assert_eq!(
        (first, second),
        (b"tunnel hello".to_vec(), b"more".to_vec())
    );
    assert_eq!(counts(&l), [0, 1, 0, 0, 0, 0, 0, 0]);
    // The slots went back before the fallback: the source has its whole
    // share while the entry lives on.
    let held = (enter(&l), enter(&l));
    held.0.release();
    held.1.release();
    drop(e);
    assert_eq!(counts(&l), [0, 1, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test]
async fn defer_and_more_where_they_do_not_apply_close() {
    // Defer on a request head, and on a carrier no upgrade's head deferred.
    let (adm, calls) = recorded(0, |_, _| AdmissionVerdict::Defer);
    let l = listener(adm, None);
    let none = None::<&mut tokio::io::Empty>;
    assert_eq!(
        enter(&l).decide_request(CarrierInfo::new(), none).await,
        Admit::Close
    );
    let (_a, b) = tokio::io::duplex(64);
    let carrier = PipeIo::new(b);
    assert!(enter(&l).admit(CarrierInfo::new(), carrier).await.is_none());
    let carrier = messages(vec![msg(b"m")]);
    assert!(enter(&l).admit(CarrierInfo::new(), carrier).await.is_none());
    assert_eq!(calls.lock().unwrap().len(), 3);
    assert_eq!(counts(&l), [0, 0, 0, 3, 0, 0, 0, 0]);

    // More on an upgrade's head and on a first message.
    let (adm, calls) = recorded(1, |_, _| AdmissionVerdict::More { need: 8 });
    let l = listener(adm.with_max_peek(16), None);
    assert_eq!(
        enter(&l).decide_upgrade(CarrierInfo::new()).await,
        Admit::Close
    );
    let carrier = messages(vec![msg(b"abc"), msg(b"defgh")]);
    assert!(enter(&l).admit(CarrierInfo::new(), carrier).await.is_none());
    assert_eq!(calls.lock().unwrap().len(), 2);
    assert_eq!(counts(&l), [0, 0, 0, 2, 0, 0, 0, 0]);
    // On a byte stream it reads on.
    let (mut a, b) = tokio::io::duplex(64);
    tokio::io::AsyncWriteExt::write_all(&mut a, b"0123456789")
        .await
        .unwrap();
    let carrier = PipeIo::new(b);
    assert!(enter(&l).admit(CarrierInfo::new(), carrier).await.is_none());
    let lens: Vec<usize> = calls.lock().unwrap()[2..]
        .iter()
        .map(|c| c.4.len())
        .collect();
    assert_eq!(lens, [1, 8], "then a More not above the prefix closes");
    assert_eq!(counts(&l), [0, 0, 0, 3, 0, 0, 0, 0]);
}

#[tokio::test]
async fn a_first_message_is_bounded_by_max_message() {
    // The default: the largest record.
    let (adm, calls) = recorded(1, |_, _| AdmissionVerdict::Close);
    let l = listener(adm, None);
    for len in [MAX_ADMISSION_MESSAGE, MAX_ADMISSION_MESSAGE + 1] {
        let carrier = messages(vec![Ok(vec![7; len])]);
        assert!(enter(&l).admit(CarrierInfo::new(), carrier).await.is_none());
    }
    assert_eq!(calls.lock().unwrap().len(), 1, "the longer one undecided");
    assert_eq!(counts(&l), [0, 0, 0, 2, 0, 0, 0, 0]);

    // A bound of the host's; max_peek bounds byte streams only.
    let (adm, calls) = recorded(1, |_, _| AdmissionVerdict::Close);
    let l = listener(adm.with_max_message(8).with_max_peek(2), None);
    for len in [8, 9, 1000] {
        let carrier = messages(vec![Ok(vec![7; len])]);
        assert!(enter(&l).admit(CarrierInfo::new(), carrier).await.is_none());
    }
    assert_eq!(calls.lock().unwrap()[0].4.len(), 8);
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(counts(&l), [0, 0, 0, 3, 0, 0, 0, 0]);

    let (adm, calls) = recorded(0, defer_then(b"ok"));
    let l = listener(adm.with_max_message(8), None);
    let mut entry = enter(&l);
    assert_eq!(entry.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
    let carrier = messages(vec![msg(b"too large")]);
    assert!(
        entry
            .admit_first(CarrierInfo::new(), now(carrier))
            .await
            .is_none()
    );
    drop(entry);
    assert_eq!(calls.lock().unwrap().len(), 1);
    assert_eq!(counts(&l), [0, 0, 0, 0, 0, 1, 0, 0]);

    // Above the largest record: an invalid configuration.
    let mut limits = ListenerConfig::default();
    limits.admission = Some(
        Admission::new(1, |_, _| AdmissionVerdict::Close)
            .with_max_message(MAX_ADMISSION_MESSAGE + 1),
    );
    assert!(Listener::new(Config::default(), limits).is_err());
}

#[tokio::test]
async fn no_first_message_closes_without_a_decision() {
    let (adm, calls) = recorded(1, |_, _| AdmissionVerdict::accept(0));
    let l = listener(adm, None);
    // A text message (the reader's error), the end, an empty message.
    let firsts = [
        Err(io::Error::new(io::ErrorKind::InvalidData, "a text message")),
        Ok(Vec::new()),
        Err(zmux::adapter::empty_message()),
    ];
    for first in firsts {
        let carrier = messages(vec![first, msg(b"later")]);
        assert!(enter(&l).admit(CarrierInfo::new(), carrier).await.is_none());
    }
    assert!(calls.lock().unwrap().is_empty());
    assert_eq!(counts(&l), [0, 0, 0, 3, 0, 0, 0, 0]);
}

#[tokio::test(start_paused = true)]
async fn a_deferral_is_bounded_by_the_peek_timeout_from_the_head() {
    let (adm, _) = recorded(0, defer_then(b"x"));
    let l = listener(adm, None);
    // Never comes.
    let mut e = enter(&l);
    assert_eq!(e.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
    let started = tokio::time::Instant::now();
    let first = std::future::pending::<io::Result<AdmitIo>>();
    assert!(e.admit_first(CarrierInfo::new(), first).await.is_none());
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    drop(e);
    assert_eq!(counts(&l), [0, 0, 0, 0, 0, 0, 1, 0]);
    // The timeout runs on from the head's decision.
    let mut e = enter(&l);
    assert_eq!(e.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
    tokio::time::sleep(Duration::from_millis(600)).await;
    let first = async {
        tokio::time::sleep(Duration::from_millis(600)).await;
        now(messages(vec![msg(b"x")])).await
    };
    assert!(e.admit_first(CarrierInfo::new(), first).await.is_none());
    assert_eq!(counts(&l), [0, 0, 0, 0, 0, 0, 2, 0]);
    // A first message that does not come in time either.
    let mut e = enter(&l);
    assert_eq!(e.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
    let carrier = now(messages(vec![]));
    assert!(e.admit_first(CarrierInfo::new(), carrier).await.is_none());
    assert_eq!(counts(&l), [0, 0, 0, 0, 0, 0, 3, 0]);
}

#[tokio::test(start_paused = true)]
async fn an_unconsumed_deferral_counts_once() {
    let (adm, _) = recorded(0, defer_then(b"x"));
    let l = listener(adm, None);
    let mut e = enter(&l);
    assert_eq!(e.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
    // Its carrier ended first.
    drop(e);
    assert_eq!(counts(&l), [0, 0, 0, 1, 0, 0, 0, 0]);
    let mut e = enter(&l);
    assert_eq!(e.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
    tokio::time::sleep(Duration::from_secs(2)).await;
    drop(e);
    assert_eq!(counts(&l), [0, 0, 0, 1, 0, 0, 1, 0]);
    // A failed upgrade after a deferral is a failed handshake alone.
    let mut e = enter(&l);
    assert_eq!(e.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
    let failed = async { Err(io::Error::other("the upgrade failed")) };
    assert!(e.admit_first(CarrierInfo::new(), failed).await.is_none());
    drop(e);
    assert_eq!(counts(&l), [0, 0, 0, 1, 0, 0, 1, 1]);
}

#[tokio::test]
async fn closing_the_listener_ends_the_wait_and_the_read() {
    let (adm, calls) = recorded(1, defer_then(b"x"));
    let adm = adm.with_peek_timeout(Duration::from_secs(3600));
    let l = listener(adm, None);
    let mut waiting = enter(&l);
    assert_eq!(
        waiting.decide_upgrade(CarrierInfo::new()).await,
        Admit::Defer
    );
    let mut reading = enter(&l);
    let w = tokio::spawn(async move {
        let first = std::future::pending::<io::Result<AdmitIo>>();
        waiting
            .admit_first(CarrierInfo::new(), first)
            .await
            .is_none()
    });
    let r = tokio::spawn(async move {
        let carrier = messages(vec![]);
        reading.admit(CarrierInfo::new(), carrier).await.is_none()
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    l.close();
    assert!(tokio::time::timeout(LIMIT, w).await.unwrap().unwrap());
    assert!(tokio::time::timeout(LIMIT, r).await.unwrap().unwrap());
    assert_eq!(calls.lock().unwrap().len(), 1, "the head's decision only");
    assert_eq!(counts(&l), [0, 0, 0, 2, 0, 0, 0, 0]);
}

#[tokio::test]
async fn panics_in_the_decision_and_the_fallback_close_the_carrier() {
    // The decision on the carrier panics.
    let (adm, _) = recorded(0, |info, _| {
        assert!(info.is_head(), "a failing decision");
        AdmissionVerdict::Defer
    });
    let l = listener(adm, None);
    let mut e = enter(&l);
    assert_eq!(e.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
    let carrier = now(messages(vec![msg(b"m")]));
    assert!(e.admit_first(CarrierInfo::new(), carrier).await.is_none());
    assert_eq!(counts(&l), [0, 0, 0, 1, 0, 0, 0, 0]);

    // The fallback panics, when called and while it runs.
    let calls = Arc::new(Mutex::new(0));
    let c = calls.clone();
    let fallback = Fallback::new(move |t: Takeover| {
        let n = {
            let mut n = c.lock().unwrap();
            *n += 1;
            *n
        };
        assert!(n != 1, "a failing fallback");
        async move {
            drop(t);
            panic!("a failing fallback's future");
        }
    });
    let l = listener(
        Admission::new(1, |_, _| AdmissionVerdict::fallback()),
        Some(fallback),
    );
    for _ in 0..2 {
        let carrier = messages(vec![msg(b"m")]);
        assert!(enter(&l).admit(CarrierInfo::new(), carrier).await.is_none());
    }
    assert_eq!(*calls.lock().unwrap(), 2);
    assert_eq!(counts(&l), [0, 2, 0, 0, 0, 0, 0, 0]);
}

#[tokio::test]
async fn an_accepted_head_hands_its_carrier_on_as_it_comes() {
    let (adm, calls) = recorded(1, |_, _| AdmissionVerdict::accept(0));
    let l = listener(adm, None);
    let mut e = enter(&l);
    assert_eq!(
        e.decide_upgrade(CarrierInfo::new()).await,
        Admit::Accept(Vec::new())
    );
    let carrier = now(messages(vec![msg(b"first record")]));
    let mut p = e
        .admit_first(CarrierInfo::new(), carrier)
        .await
        .expect("accepted");
    assert_eq!(calls.lock().unwrap().len(), 1, "decided on the head alone");
    assert_eq!(unit(&mut p).await, b"first record");
    // A failed upgrade after it is a setup failure, not a second outcome.
    let mut e = enter(&l);
    assert!(matches!(
        e.decide_upgrade(CarrierInfo::new()).await,
        Admit::Accept(_)
    ));
    let failed = async { Err(io::Error::other("the upgrade failed")) };
    assert!(e.admit_first(CarrierInfo::new(), failed).await.is_none());
    drop(e);
    assert_eq!(counts(&l), [2, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(l.stats().setup_failures, 1);
}

#[tokio::test]
async fn a_stalled_message_carrier_discards_its_messages() {
    let (adm, _) = recorded(1, |_, _| AdmissionVerdict::Stall);
    let adm = adm.with_stall_interval(Duration::from_secs(3600), Duration::from_secs(3600));
    let l = listener(adm, None);
    let mut e = enter(&l);
    // Long messages are read past; the carrier's end ends the stall.
    let carrier = messages(vec![
        msg(b"m"),
        Ok(vec![1; 4096]),
        msg(b"x"),
        Ok(Vec::new()),
    ]);
    let stalled = tokio::time::timeout(LIMIT, e.admit(CarrierInfo::new(), carrier)).await;
    assert!(stalled.unwrap().is_none());
    assert_eq!(counts(&l), [0, 0, 1, 0, 0, 0, 0, 0]);
}

#[tokio::test(start_paused = true)]
async fn targetless_deferred_handoffs_and_setup_outcomes_reconcile() {
    for verdict in [AdmissionVerdict::fallback(), AdmissionVerdict::takeover()] {
        let adm = Admission::new(0, move |info: CarrierInfo, _| {
            if info.upgrade && info.is_head() {
                AdmissionVerdict::Defer
            } else if info.upgrade {
                verdict.clone()
            } else {
                AdmissionVerdict::Stall
            }
            .labelled("route")
        });
        let l = listener(adm, None);
        let mut held = enter(&l);
        assert_eq!(
            held.decide_request(CarrierInfo::new(), None::<&mut tokio::io::Empty>)
                .await,
            Admit::Stall
        );
        for _ in 0..2 {
            let mut entry = enter(&l);
            assert_eq!(entry.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
            assert!(
                entry
                    .admit_first(CarrierInfo::new(), now(messages(vec![msg(b"ok")])))
                    .await
                    .is_none()
            );
            drop(entry);
        }
        drop(held);
        assert_eq!(counts(&l), [0, 0, 1, 0, 2, 0, 0, 0]);
        assert_eq!(l.stats().admission.takeover, 0);
        assert_eq!(l.variant_stats().variants["route"].stalled, 3);
    }

    let (adm, _) = recorded(0, defer_then(b"ok"));
    let l = listener(adm, None);
    for expired in [false, true] {
        let mut entry = enter(&l);
        assert_eq!(entry.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
        if expired {
            assert!(
                entry
                    .admit_first(CarrierInfo::new(), std::future::pending())
                    .await
                    .is_none()
            );
        } else {
            assert!(
                entry
                    .admit_first(
                        CarrierInfo::new(),
                        std::future::ready(Err(io::Error::other("upgrade failed")))
                    )
                    .await
                    .is_none()
            );
        }
    }
    let mut entry = enter(&l);
    assert_eq!(entry.decide_upgrade(CarrierInfo::new()).await, Admit::Defer);
    drop(entry);
    assert_eq!(counts(&l), [0, 0, 0, 1, 0, 0, 1, 1]);
    assert_eq!(l.stats().setup_failures, 0);
    assert_eq!(l.stats().rejected, 0);
}

#[tokio::test]
async fn labelled_admission_outcomes_reconcile_with_variant_overflow() {
    let adm = Admission::new(1, |_, prefix| {
        AdmissionVerdict::Close.labelled(format!("variant-{}", prefix[0]))
    });
    let l = listener(adm, None);
    for i in 0..70u8 {
        let carrier = messages(vec![Ok(vec![i])]);
        assert!(enter(&l).admit(CarrierInfo::new(), carrier).await.is_none());
    }
    let variants = l.variant_stats();
    assert_eq!(variants.variants.len(), 64);
    assert_eq!(variants.overflow.closed, 6);
    let dedicated: u64 = variants.variants.values().map(|v| v.closed).sum();
    assert_eq!(
        dedicated + variants.overflow.closed,
        l.stats().admission.closed
    );
    assert_eq!(counts(&l), [0, 0, 0, 70, 0, 0, 0, 0]);
}

#[tokio::test]
async fn closing_a_pending_handshake_counts_as_cancellation() {
    let (adm, calls) = recorded(0, |_, _| AdmissionVerdict::accept(0));
    let l = listener(adm, None);
    drop(enter(&l));
    assert_eq!(counts(&l), [0, 0, 0, 0, 0, 0, 0, 1]);

    let cancelled = enter(&l);
    l.close();
    drop(cancelled);
    assert_eq!(counts(&l), [0, 0, 0, 1, 0, 0, 0, 1]);
    assert_eq!(*calls.lock().unwrap(), []);
    assert_eq!(l.stats().setup_failures, 0);
}
