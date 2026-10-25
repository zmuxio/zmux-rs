//! Two session cores joined by pipe 0, without I/O and without time
//! passing: the shared harness of the core tests and benches. Each batch
//! moves whole (a batch is whole records) and allocates nothing once the
//! buffers reached their size.

#![allow(dead_code)]

use std::time::Instant;

use zmux::proto::record::Framing;
use zmux::proto::session::{Config, CoreEvent, PipeId, RoleConfig, SessionCore, TransmitBuf};

pub(crate) const P0: PipeId = PipeId(0);

pub(crate) struct CorePair {
    pub(crate) a: SessionCore,
    pub(crate) b: SessionCore,
    pub(crate) out: TransmitBuf,
    pub(crate) wire: Vec<u8>,
    pub(crate) now: Instant,
    /// The events each side emitted, when kept ([`CorePair::keep_events`]).
    pub(crate) events_a: Vec<CoreEvent>,
    pub(crate) events_b: Vec<CoreEvent>,
    keep_events: bool,
}

impl CorePair {
    /// A pair established on pipe 0 (A dials). The pump moves bytes without
    /// time passing: a carrier that takes them all at once, as one with a
    /// low-water mark, which the carrier queue limiter does not pace.
    pub(crate) fn new(a: Config, b: Config) -> Self {
        let mut p = Self::attached(a, b);
        p.pump();
        assert!(p.a.is_established() && p.b.is_established());
        p
    }

    /// [`CorePair::new`] that keeps every event the sides emit.
    pub(crate) fn with_events(a: Config, b: Config) -> Self {
        let mut p = Self::attached(a, b).keep_events();
        p.pump();
        assert!(p.a.is_established() && p.b.is_established());
        p
    }

    /// The pair with pipe 0 attached, before anything moved.
    pub(crate) fn attached(a: Config, b: Config) -> Self {
        let now = Instant::now();
        let mut a = SessionCore::new(a, RoleConfig::Initiator, None, now).unwrap();
        let mut b = SessionCore::new(b, RoleConfig::Responder, None, now).unwrap();
        a.attach_pipe(P0, Framing::ByteStream, now);
        b.attach_pipe(P0, Framing::ByteStream, now);
        a.set_pipe_low_water(P0, true);
        b.set_pipe_low_water(P0, true);
        Self {
            a,
            b,
            out: TransmitBuf::default(),
            wire: Vec::with_capacity(512 * 1024),
            now,
            events_a: Vec::new(),
            events_b: Vec::new(),
            keep_events: false,
        }
    }

    /// Keeps the events the sides emit from now on.
    pub(crate) fn keep_events(mut self) -> Self {
        self.keep_events = true;
        self
    }

    /// Moves every batch one side has for pipe 0 to the other (`a_to_b`:
    /// from A), showing each to `inspect`; returns the bytes moved.
    pub(crate) fn send_with(&mut self, a_to_b: bool, mut inspect: impl FnMut(&[u8])) -> usize {
        let (from, to) = if a_to_b {
            (&mut self.a, &mut self.b)
        } else {
            (&mut self.b, &mut self.a)
        };
        let mut moved = 0;
        while from.wants_write(P0) {
            from.poll_transmit(P0, self.now, &mut self.out);
            if self.out.is_empty() {
                break;
            }
            self.wire.clear();
            self.out.copy_to_vec(&mut self.wire);
            inspect(&self.wire);
            let used = to.receive_in_place(P0, &self.wire, self.now);
            assert_eq!(used, self.wire.len(), "a batch is whole records");
            moved += self.wire.len();
        }
        moved
    }

    /// [`CorePair::send_with`] without looking.
    pub(crate) fn send(&mut self, a_to_b: bool) -> usize {
        self.send_with(a_to_b, |_| {})
    }

    /// Takes the events of both sides (kept or dropped).
    pub(crate) fn drain_events(&mut self) {
        while let Some(e) = self.a.poll_event() {
            if self.keep_events {
                self.events_a.push(e);
            }
        }
        while let Some(e) = self.b.poll_event() {
            if self.keep_events {
                self.events_b.push(e);
            }
        }
    }

    /// Moves everything both sides have to send until nothing is left;
    /// returns the bytes moved.
    pub(crate) fn pump(&mut self) -> usize {
        let mut moved = 0;
        for _ in 0..100_000 {
            let n = self.send(true) + self.send(false);
            self.drain_events();
            moved += n;
            if n == 0 {
                return moved;
            }
        }
        panic!("pump runaway");
    }
}
