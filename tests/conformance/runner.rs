//! The trace runner (TRACES.md Section 7): executes every trace of the
//! single-pipe groups against the sans-IO session core with a virtual
//! clock, and lists the multipath and resume traces it skips.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde_json::{Value, json};
use zmux::proto::error::{APPLICATION_ERRORS, TRANSPORT_ERRORS};
use zmux::proto::frame::{Dir, Priority};
use zmux::proto::keys::lane_key_eq;
use zmux::proto::listener::{
    CarrierId, Classified, ListenerConfig, ListenerCore, Opened, Paired, source_name,
};
use zmux::proto::params::{Features, Role, TransportParameters};
use zmux::proto::record::{self, Framing};
use zmux::proto::session::{
    Config, CoreEvent, DEFAULT_OVERFLOW_DELAY, DatagramError, JoinVerdict, LaneAccept, LaneId,
    OpenError, PipeAuth, PipeEnd, PipeError, PipeHalf, PipeId, PipeOptions, PipeWrite, Policy,
    Preamble, Redundancy, RoleConfig, SessionCore, SessionError, State, StreamError, StreamKey,
    Transmit, TransmitBuf,
};
use zmux::proto::{Gates, VarInt, varint};

use crate::model::{
    Call, CloseSpec, ClosedHow, Direction, DownHow, ErrorSpace, EventName, Feature, FramingName,
    Op, ParamId, ParamSpec, ParamValue, PipeState as PipeStateName, Profile, RoleName,
    StatePattern, Step, StreamRef, Trace, TransportRole,
};
use crate::support::{read_json, to_hex};
use crate::wire;

/// The groups this version runs.
const RUN_GROUPS: &[&str] = &["core", "ext", "compat", "regression", "multipath", "resume"];

/// What the local endpoint wrote on one outbound lane of a pipe (lane 0
/// is the pipe's own carrier, TRACES.md Section 5.1.1).
#[derive(Default)]
struct OutIo {
    /// Written bytes not yet decoded into records.
    out_bytes: Vec<u8>,
    /// Frames written since the last expectation on this lane.
    pending: Vec<Value>,
    pending_records: Vec<Vec<Value>>,
    /// Every frame written, for `first`.
    all: Vec<Value>,
    /// Bytes written (byte-stream form).
    sent: u64,
    closed: Option<ClosedHow>,
}

/// One pipe as the runner sees it: the carrier halves attached to it and
/// what the local endpoint wrote.
#[derive(Default)]
struct PipeIo {
    /// The halves the runner attached (from the local endpoint's view).
    inbound: bool,
    outbound: bool,
    in_framing: Option<Framing>,
    out_framing: Option<Framing>,
    writable: bool,
    /// Unconsumed bytes of the inbound pipe (in-place receiving).
    inbuf: Vec<u8>,
    /// Lane 0, and the lanes the local endpoint opened.
    out: OutIo,
    lanes: BTreeMap<u64, OutIo>,
    in_closed: Option<ClosedHow>,
    /// The carrier names attached to the pipe.
    carriers: Vec<String>,
    /// The connection of its lane 0 (TRACES.md Section 5.1.1).
    conn: Option<String>,
}

impl PipeIo {
    fn lane(&self, lane: u64) -> Option<&OutIo> {
        if lane == 0 {
            Some(&self.out)
        } else {
            self.lanes.get(&lane)
        }
    }

    fn lane_mut(&mut self, lane: u64) -> &mut OutIo {
        if lane == 0 {
            &mut self.out
        } else {
            self.lanes.entry(lane).or_default()
        }
    }

    /// Every outbound lane, lane 0 first.
    fn outs_mut(&mut self) -> impl Iterator<Item = &mut OutIo> {
        std::iter::once(&mut self.out).chain(self.lanes.values_mut())
    }
}

/// A carrier that came through the listener.
struct Carrier {
    pipe: Option<u64>,
    can_read: bool,
    can_write: bool,
    framing: Framing,
    id: Option<CarrierId>,
    binding: Vec<u8>,
    /// A join waiting for establishment: frame, bytes, in band.
    waiting: Option<(Vec<u8>, Vec<u8>, bool)>,
    /// Closed by the local endpoint without writing.
    rejected: bool,
    pairing: Option<[u8; 16]>,
    /// Bytes received while the carrier waits for its pairing.
    held: Vec<Vec<u8>>,
    /// Its connection (TRACES.md Section 5.1.1).
    conn: Option<String>,
    /// A new stream of a connection (`via: "lane"`): the lane it turned
    /// out to be, once accepted, with its unconsumed bytes.
    lane: Option<LaneId>,
    inbuf: Vec<u8>,
}

/// One running trace.
struct Runner {
    session: SessionCore,
    base: Instant,
    ms: u64,
    pipes: BTreeMap<u64, PipeIo>,
    carriers: HashMap<String, Carrier>,
    listener: ListenerCore,
    out: TransmitBuf,
    /// Every CONNECTION_CLOSE written.
    closes: Vec<Value>,
    /// Events not consumed by an expectation.
    events: Vec<CoreEvent>,
    handles: HashMap<String, StreamKey>,
    close_covered: bool,
    /// Feed inbound bytes with `receive` (copying) instead of
    /// `receive_in_place`.
    copy: bool,
}

fn pipe_auth(a: &crate::model::PipeAuth) -> PipeAuth {
    a.psk
        .as_ref()
        .map_or_else(PipeAuth::none, |p| PipeAuth::psk(p.0.clone()))
}

fn policy(name: &str) -> Result<Policy, String> {
    Ok(match name {
        "affinity" => Policy::Affinity,
        "spread-eta" => Policy::SpreadEta,
        "spread-rate-weighted" => Policy::SpreadRateWeighted,
        "spread-round-robin" => Policy::SpreadRoundRobin,
        "session-affinity" => Policy::SessionAffinity,
        other => return Err(format!("unknown scheduler {other}")),
    })
}

fn state_name(s: zmux::proto::session::PipeState) -> PipeStateName {
    use zmux::proto::session::PipeState as P;
    match s {
        P::Joining => PipeStateName::Joining,
        P::Active => PipeStateName::Active,
        P::Suspect => PipeStateName::Suspect,
        P::Draining => PipeStateName::Draining,
        P::Failed => PipeStateName::Failed,
        P::Closed => PipeStateName::Closed,
        P::Open => PipeStateName::Open,
        P::Ended => PipeStateName::Ended,
        P::Retired => PipeStateName::Retired,
    }
}

fn state_matches(p: &StatePattern, s: PipeStateName) -> bool {
    match p {
        StatePattern::One(x) => *x == s,
        StatePattern::OneOf(o) => o.oneof.contains(&s),
    }
}

impl Runner {
    fn new(
        trace: &Trace,
        profiles: &BTreeMap<String, Profile>,
        copy: bool,
    ) -> Result<Self, String> {
        let h = &trace.header;
        let profile = profiles
            .get(&h.profile)
            .ok_or_else(|| format!("unknown profile {}", h.profile))?;
        // Transport parameters: the profile's, with overrides.
        let mut tp: BTreeMap<String, Option<ParamValue>> = profile.tp.clone();
        for (k, v) in &h.overrides.tp {
            tp.insert(k.clone(), v.clone());
        }
        let list: Vec<ParamSpec> = tp
            .into_iter()
            .map(|(name, value)| ParamSpec {
                id: ParamId::Name(name),
                value,
                raw: None,
            })
            .collect();
        let tp = TransportParameters::decode(&wire::param_block(&list))
            .map_err(|e| format!("profile parameters: {e:?}"))?;
        let tp_uni = tp.initial_max_streams_uni.unwrap_or(0);
        let mut cfg = profile.config.clone();
        let o = &h.overrides.config;
        macro_rules! over {
            ($($f:ident),*) => { $( if o.$f.is_some() { cfg.$f = o.$f.clone(); } )* };
        }
        over!(
            keep_alive_period,
            handshake_timeout,
            enable_datagrams,
            role,
            max_pipes,
            scheduler,
            sender,
            resume_timeout,
            max_incoming_uni_streams,
            suspect_floor,
            dead_timeout,
            probation,
            overflow_delay,
            redundancy,
            standby_probe,
            pipe_auth,
            early_data
        );
        let mut hooks = profile.test.clone();
        let t = &h.overrides.test;
        macro_rules! hook {
            ($($f:ident),*) => { $( if t.$f.is_some() { hooks.$f = t.$f.clone(); } )* };
        }
        hook!(
            grease_tp,
            grease_tlv,
            role_nonce,
            ping_seq_start,
            rtt_ms,
            session_nonce,
            pipe_rtt_ms,
            pipe_cap,
            lane_key
        );

        let mut config = Config::default();
        config.handshake_timeout = Duration::from_millis(cfg.handshake_timeout.unwrap_or(10_000));
        config.keep_alive_period = cfg
            .keep_alive_period
            .filter(|&k| k > 0)
            .map(Duration::from_millis);
        config.max_idle_timeout = Duration::from_millis(tp.max_idle_timeout.unwrap_or(0));
        config.enable_datagrams = cfg.enable_datagrams.unwrap_or(false);
        // Absent from the profile means configured eagerly (the traces of
        // earlier revisions); `null` means unset, lazy.
        config.max_incoming_uni_streams = match cfg.max_incoming_uni_streams {
            Some(v) => v,
            None => Some(tp_uni),
        };
        if let Some(m) = cfg.max_pipes {
            config.max_pipes = m;
        }
        // The test-mode sender (TRACES.md Section 3.4): the ETA choice,
        // no probation, no redundant copies, standby pipes probed at 15 s.
        match cfg.sender.as_deref() {
            None => {}
            Some("test-mode") => {
                cfg.scheduler.get_or_insert_with(|| "spread-eta".into());
                cfg.probation.get_or_insert(Some(0));
                cfg.redundancy.get_or_insert_with(|| "off".into());
                cfg.standby_probe.get_or_insert(0);
            }
            Some(other) => return Err(format!("unknown sender {other}")),
        }
        if let Some(s) = &cfg.scheduler {
            config.scheduler = policy(s)?;
        }
        if let Some(a) = &cfg.pipe_auth {
            config.pipe_auth = pipe_auth(a);
        }
        config.resume_timeout = cfg.resume_timeout.map(Duration::from_millis);
        if let Some(f) = cfg.suspect_floor {
            config.suspect_floor = Duration::from_millis(f);
        }
        config.dead_timeout = cfg.dead_timeout.map(Duration::from_millis);
        config.probation = cfg.probation.flatten().map(Duration::from_millis);
        if let Some(d) = cfg.overflow_delay {
            config.overflow_delay = d.map_or(DEFAULT_OVERFLOW_DELAY, Duration::from_millis);
        }
        if let Some(r) = &cfg.redundancy {
            config.redundancy = match r.as_str() {
                "urgent" => Redundancy::Urgent,
                "off" => Redundancy::Off,
                other => return Err(format!("unknown redundancy {other}")),
            };
        }
        if let Some(p) = cfg.standby_probe {
            config.standby_probe = Duration::from_millis(p);
        }
        if let Some(e) = &cfg.early_data {
            config.early_data =
                zmux::EarlyData::for_zmux_peer().with_carrier_early_data(e.replayable);
            config.early_data.zmux_peer = e.zmux_peer;
        }
        if let Some(m) = &tp.zmux_multipath {
            config.test_hooks().locator = m.locator.as_bytes().to_vec();
        }

        let th = config.test_hooks();
        th.transport_parameters = Some(tp);
        th.grease_tp = hooks.grease_tp.map(|g| (g.id, g.value.0));
        th.grease_tlv = hooks.grease_tlv.map(|g| (g.ty, g.value.0));
        th.role_nonce = hooks.role_nonce;
        th.ping_seq_start = hooks.ping_seq_start;
        th.rtt = hooks.rtt_ms.map(Duration::from_millis);
        th.no_first_ping = true;
        th.unpaced = true;
        // Probes at the specified intervals, without a random phase.
        th.probe_phase = Some(0.0);
        th.session_nonce = hooks
            .session_nonce
            .map(|n| n.0.try_into().map_err(|_| "session_nonce length"))
            .transpose()?;
        th.pipe_rtt = hooks
            .pipe_rtt_ms
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| {
                Ok((
                    k.parse::<u64>().map_err(|_| "pipe_rtt_ms key")?,
                    Duration::from_millis(v),
                ))
            })
            .collect::<Result<_, &str>>()?;
        th.pipe_cap = hooks.pipe_cap.map(|c| c as usize);
        th.lane_key = hooks
            .lane_key
            .map(|k| k.0.try_into().map_err(|_| "lane_key length"))
            .transpose()?;
        let transport = match h.local_role {
            TransportRole::Initiator => Role::Initiator,
            TransportRole::Responder => Role::Responder,
        };
        let role = match cfg.role {
            Some(RoleName::Auto) => RoleConfig::Auto,
            Some(RoleName::Initiator) => RoleConfig::Initiator,
            Some(RoleName::Responder) => RoleConfig::Responder,
            None => match transport {
                Role::Initiator => RoleConfig::Initiator,
                Role::Responder => RoleConfig::Responder,
            },
        };
        let base = Instant::now();
        let session = SessionCore::new(config, role, Some(transport), base)
            .map_err(|e| format!("session: {e}"))?;
        Ok(Self {
            session,
            base,
            ms: 0,
            pipes: BTreeMap::new(),
            carriers: HashMap::new(),
            listener: ListenerCore::new(ListenerConfig::default()),
            out: TransmitBuf::default(),
            closes: Vec::new(),
            events: Vec::new(),
            handles: HashMap::new(),
            close_covered: false,
            copy,
        })
    }

    fn now(&self) -> Instant {
        self.base + Duration::from_millis(self.ms)
    }

    fn drain_events(&mut self) {
        while let Some(e) = self.session.poll_event() {
            match &e {
                CoreEvent::ClosePipe { pipe, half, abort } => {
                    let how = if *abort {
                        ClosedHow::Abort
                    } else {
                        ClosedHow::Graceful
                    };
                    if let Some(p) = self.pipes.get_mut(&pipe.0) {
                        match half {
                            PipeHalf::Inbound => {
                                p.in_closed.get_or_insert(how);
                            }
                            PipeHalf::Outbound => {
                                for o in p.outs_mut() {
                                    o.closed.get_or_insert(how);
                                }
                            }
                        }
                    }
                }
                CoreEvent::OpenLane(lane) => {
                    // A carrier with `conn` opens lanes at once, its stream
                    // credit never running out (TRACES.md Section 3.3).
                    let now = self.now();
                    let framing = self
                        .pipes
                        .get(&lane.pipe.0)
                        .and_then(|p| p.out_framing)
                        .unwrap_or(Framing::ByteStream);
                    self.pipe_mut(lane.pipe.0).lane_mut(lane.lane.0);
                    self.session.lane_opened(*lane, framing, now);
                }
                CoreEvent::ResetLane(lane) => {
                    self.pipe_mut(lane.pipe.0)
                        .lane_mut(lane.lane.0)
                        .closed
                        .get_or_insert(ClosedHow::Abort);
                }
                _ => {}
            }
            self.events.push(e);
        }
    }

    fn pipe_mut(&mut self, id: u64) -> &mut PipeIo {
        self.pipes.entry(id).or_insert_with(|| PipeIo {
            writable: true,
            ..PipeIo::default()
        })
    }

    /// Writes everything the core has for every writable pipe (TRACES.md
    /// 5.4), pipe by pipe in ID order until nothing more comes out.
    fn flush(&mut self) -> Result<(), String> {
        let now = self.now();
        let mut rounds = 0;
        loop {
            let mut progress = false;
            let ids: Vec<(u64, u64)> = self
                .pipes
                .iter()
                .flat_map(|(&id, p)| {
                    std::iter::once((id, 0)).chain(p.lanes.keys().map(move |&l| (id, l)))
                })
                .collect();
            for (id, lane) in ids {
                let at = PipeId(id).lane(lane);
                loop {
                    rounds += 1;
                    if rounds > 100_000 {
                        return Err("transmit does not settle".into());
                    }
                    let p = &self.pipes[&id];
                    if !p.outbound || !p.writable || p.lane(lane).is_none_or(|o| o.closed.is_some())
                    {
                        break;
                    }
                    if !self.session.wants_write(at) {
                        break;
                    }
                    let infos = self.session.is_multipath().then(|| self.session.pipes());
                    let before = self.pipes[&id].out.all.len();
                    let t = self.session.poll_transmit(at, now, &mut self.out);
                    let mut bytes = Vec::new();
                    self.out.copy_to_vec(&mut bytes);
                    let lens = self.out.message_lens().to_vec();
                    let stream_len = self.out.stream_len();
                    if !bytes.is_empty() {
                        progress = true;
                    }
                    self.decode_out(id, lane, &bytes, &lens, stream_len)?;
                    if let Some(infos) = infos
                        && lane == 0
                    {
                        self.scheduling_oracle(id, &infos, before)?;
                    }
                    match t {
                        Transmit::Shutdown => {
                            self.pipe_mut(id)
                                .lane_mut(lane)
                                .closed
                                .get_or_insert(ClosedHow::Graceful);
                            progress = true;
                            break;
                        }
                        Transmit::Idle if bytes.is_empty() => {
                            // A batch that
                            // writes nothing leaves no write interest behind.
                            if self.session.wants_write(at) {
                                return Err(format!(
                                    "pipe {id} lane {lane} keeps asking for a write it does not make"
                                ));
                            }
                            break;
                        }
                        _ => {}
                    }
                }
                self.drain_events();
            }
            if !progress {
                break;
            }
        }
        if self.session.state() == State::Closed {
            for p in self.pipes.values_mut() {
                if p.outbound {
                    for o in p.outs_mut() {
                        o.closed.get_or_insert(ClosedHow::Abort);
                    }
                }
            }
        }
        self.drain_events();
        Ok(())
    }

    /// CONFORMANCE.md: stream data appears on a JOINING
    /// pipe only while no other outbound pipe is usable, and then at most
    /// one `spread_chunk`; never on a pipe in probation while another pipe
    /// out of probation is usable. `infos` is the state before the batch,
    /// `before` the pipe's frame count before it.
    fn scheduling_oracle(
        &mut self,
        id: u64,
        infos: &[zmux::proto::session::PipeStats],
        before: usize,
    ) -> Result<(), String> {
        let stream_bytes: usize = self.pipes[&id].out.all[before..]
            .iter()
            .filter(|f| f["type"] == "STREAM")
            .map(|f| f["data"].as_str().map_or(0, |d| d.len() / 2))
            .sum();
        let Some(me) = infos.iter().find(|i| i.pipe.0 == id) else {
            return Ok(());
        };
        if stream_bytes == 0 {
            return Ok(());
        }
        let others = || {
            infos.iter().filter(move |i| {
                i.pipe.0 != id && i.outbound == Some(zmux::proto::session::PipeState::Active)
            })
        };
        if me.outbound == Some(zmux::proto::session::PipeState::Joining)
            && let Some(o) = others().next()
        {
            return Err(format!(
                "oracle (S1): stream data on JOINING pipe {id} while pipe {} is usable",
                o.pipe.0
            ));
        }
        if me.in_probation
            && let Some(o) = others().find(|i| !i.in_probation)
        {
            return Err(format!(
                "oracle (11.9): stream data on pipe {id} in probation while pipe {} is out of probation",
                o.pipe.0
            ));
        }
        Ok(())
    }

    fn decode_out(
        &mut self,
        id: u64,
        lane: u64,
        bytes: &[u8],
        lens: &[usize],
        stream_len: u64,
    ) -> Result<(), String> {
        let framing = self.pipes[&id].out_framing.unwrap_or(Framing::ByteStream);
        self.pipe_mut(id).lane_mut(lane).sent += stream_len;
        match framing {
            Framing::ByteStream => {
                self.pipe_mut(id)
                    .lane_mut(lane)
                    .out_bytes
                    .extend_from_slice(bytes);
                loop {
                    let p = self.pipe_mut(id).lane_mut(lane);
                    let Some((size, width)) = varint::decode(&p.out_bytes) else {
                        return Ok(());
                    };
                    let end = width + size as usize;
                    if p.out_bytes.len() < end {
                        return Ok(());
                    }
                    let body = p.out_bytes[width..end].to_vec();
                    p.out_bytes.drain(..end);
                    if size == 0 {
                        return Err("the local endpoint wrote an empty record".into());
                    }
                    self.decode_record(id, lane, &body)?;
                }
            }
            Framing::Records => {
                let mut at = 0;
                for &len in lens {
                    let body = bytes[at..at + len].to_vec();
                    at += len;
                    self.decode_record(id, lane, &body)?;
                }
                Ok(())
            }
        }
    }

    fn decode_record(&mut self, id: u64, lane: u64, body: &[u8]) -> Result<(), String> {
        let frames = wire::decode_body(body, Gates::ALL)
            .map_err(|e| format!("the local endpoint wrote an undecodable record: {e:?}"))?;
        for f in &frames {
            if f["type"] == "CONNECTION_CLOSE" {
                self.closes.push(f.clone());
            }
        }
        let p = self.pipe_mut(id).lane_mut(lane);
        p.pending.extend(frames.iter().cloned());
        p.all.extend(frames.iter().cloned());
        p.pending_records.push(frames);
        Ok(())
    }

    /// One read from an inbound lane's carrier (in place, or copied).
    fn read_lane(&mut self, name: &str, data: &[u8]) {
        let now = self.now();
        let Some(c) = self.carriers.get_mut(name) else {
            return;
        };
        let Some(lane) = c.lane else {
            return;
        };
        if self.copy {
            self.session.receive(lane, data, now);
        } else {
            c.inbuf.extend_from_slice(data);
            let buf = std::mem::take(&mut c.inbuf);
            let used = self.session.receive_in_place(lane, &buf, now);
            let c = self.carriers.get_mut(name).expect("carrier");
            c.inbuf = buf;
            c.inbuf.drain(..used.min(c.inbuf.len()));
        }
        self.drain_events();
    }

    /// The first bytes of a new stream of a connection: the listener tells
    /// a lane by its first record, which goes to the session whose Lane
    /// Key it carries when the pipe it names has its lane 0 on the same
    /// connection (MULTIPATH.md Section 5.8); anything else is rejected.
    fn lane_bytes(&mut self, name: &str, bytes: &[u8]) {
        let now = self.now();
        let Some(c) = self.carriers.get(name) else {
            return;
        };
        if c.rejected {
            return;
        }
        if c.lane.is_some() {
            self.read_lane(name, bytes);
            return;
        }
        let (Some(id), framing, conn) = (c.id, c.framing, c.conn.clone()) else {
            return;
        };
        let reject = |r: &mut Self| {
            if let Some(c) = r.carriers.get_mut(name) {
                c.rejected = true;
                c.id = None;
            }
        };
        match self.listener.data(id, bytes, now) {
            Classified::NeedMore => {}
            Classified::Lane {
                lane_key,
                pipe,
                lane,
                bytes,
            } => {
                let ours = self
                    .session
                    .lane_key()
                    .is_some_and(|k| lane_key_eq(&k, &lane_key));
                let same_conn =
                    conn.is_some() && self.pipes.get(&pipe).is_some_and(|p| p.conn == conn);
                if !ours || !same_conn {
                    reject(self);
                    return;
                }
                let at = PipeId(pipe).lane(lane);
                match self.session.accept_lane(at, framing, now) {
                    LaneAccept::Accepted => {
                        if let Some(c) = self.carriers.get_mut(name) {
                            c.lane = Some(at);
                            c.id = None;
                        }
                        self.read_lane(name, &bytes);
                    }
                    _ => {
                        self.drain_events();
                        reject(self);
                    }
                }
            }
            _ => reject(self),
        }
    }

    /// Feeds inbound bytes of a pipe, split into reads.
    fn deliver(&mut self, id: u64, bytes: &[u8], chunks: Option<&[usize]>) {
        let mut rest = bytes;
        let sizes: Vec<usize> = chunks.map(<[usize]>::to_vec).unwrap_or_default();
        for n in sizes {
            let n = n.min(rest.len());
            let (a, b) = rest.split_at(n);
            self.read(id, a);
            rest = b;
        }
        if !rest.is_empty() || bytes.is_empty() {
            self.read(id, rest);
        }
    }

    /// One read from a pipe's carrier: in place (the drivers' path), or
    /// copied into the core.
    fn read(&mut self, id: u64, data: &[u8]) {
        let now = self.now();
        if self.copy {
            self.session.receive(PipeId(id), data, now);
        } else {
            let p = self.pipe_mut(id);
            p.inbuf.extend_from_slice(data);
            let buf = std::mem::take(&mut p.inbuf);
            let used = self.session.receive_in_place(PipeId(id), &buf, now);
            let p = self.pipe_mut(id);
            p.inbuf = buf;
            p.inbuf.drain(..used.min(p.inbuf.len()));
        }
        self.drain_events();
    }

    fn message(&mut self, id: u64, m: &[u8]) {
        let now = self.now();
        self.session.receive_message(PipeId(id), m, now);
        self.drain_events();
    }

    /// Moves the clock, firing every due timer and writing what it causes.
    fn advance(&mut self, ms: u64) -> Result<(), String> {
        let target = self.ms + ms;
        loop {
            let due = [self.session.poll_timeout(), self.listener.poll_timeout()]
                .into_iter()
                .flatten()
                .min()
                .map(|t| t.saturating_duration_since(self.base).as_millis() as u64);
            match due {
                Some(t) if t <= target => {
                    self.ms = self.ms.max(t);
                    let now = self.now();
                    self.session.handle_timeout(now);
                    self.listener_timeouts(now);
                    self.flush()?;
                    // A timer at the same instant may stay armed; avoid a
                    // busy loop on an unchanged deadline.
                    let again = [self.session.poll_timeout(), self.listener.poll_timeout()]
                        .into_iter()
                        .flatten()
                        .min()
                        .map(|x| x.saturating_duration_since(self.base).as_millis() as u64);
                    if again == Some(t) && t <= self.ms {
                        self.ms += 1;
                        if self.ms > target {
                            break;
                        }
                    }
                }
                _ => break,
            }
        }
        self.ms = target;
        let now = self.now();
        self.session.handle_timeout(now);
        self.listener_timeouts(now);
        self.drain_events();
        Ok(())
    }

    fn listener_timeouts(&mut self, now: Instant) {
        for id in self.listener.expired(now) {
            for c in self.carriers.values_mut() {
                if c.id == Some(id) && c.pipe.is_none() {
                    c.rejected = true;
                    c.waiting = None;
                }
            }
        }
    }

    fn key(&self, r: &StreamRef) -> Result<StreamKey, String> {
        match r {
            StreamRef::Handle(h) => self
                .handles
                .get(h)
                .copied()
                .ok_or_else(|| format!("unknown handle {h}")),
            StreamRef::Id(id) => self
                .session
                .stream_key(*id)
                .ok_or_else(|| format!("no stream {id}")),
        }
    }

    // ---- carriers and the listener -----------------------------------------------

    /// Attaches the halves of a carrier to a pipe.
    fn attach(&mut self, pipe: u64, name: Option<&str>, read: bool, write: bool, framing: Framing) {
        let conn = name
            .and_then(|n| self.carriers.get(n))
            .and_then(|c| c.conn.clone());
        let p = self.pipe_mut(pipe);
        if conn.is_some() {
            p.conn = conn;
        }
        if read {
            p.inbound = true;
            p.in_framing = Some(framing);
        }
        if write {
            p.outbound = true;
            p.out_framing = Some(framing);
        }
        if let Some(n) = name {
            p.carriers.push(n.to_string());
        }
        if write && p.conn.is_some() {
            // A stream of a multi-stream connection offers lanes (TRACES.md
            // Section 3.3).
            self.session.set_pipe_lanes(PipeId(pipe), true);
        }
    }

    /// Offers a join the listener extracted to the session.
    fn offer(&mut self, name: &str, frame: &[u8], bytes: &[u8], inband: bool) {
        let now = self.now();
        let Some(c) = self.carriers.get(name) else {
            return;
        };
        let framing = c.framing;
        let inbound = c.can_read.then_some(framing);
        let outbound = c.can_write.then_some(framing);
        let binding = c.binding.clone();
        let v = self
            .session
            .offer_join(frame, &binding, inbound, outbound, inband, now);
        self.drain_events();
        let c = self.carriers.get_mut(name).expect("carrier");
        match v {
            JoinVerdict::Wait => {
                c.waiting = Some((frame.to_vec(), bytes.to_vec(), inband));
            }
            JoinVerdict::Accepted(pipe) => {
                c.waiting = None;
                c.pipe = Some(pipe.0);
                if let Some(id) = c.id.take() {
                    self.listener.done(id);
                }
                let (read, write) = (c.can_read, c.can_write);
                self.attach(pipe.0, Some(name), read, write, framing);
                if !bytes.is_empty() {
                    match framing {
                        Framing::ByteStream => self.deliver(pipe.0, bytes, None),
                        Framing::Records => self.message(pipe.0, bytes),
                    }
                }
            }
            _ => {
                c.waiting = None;
                c.rejected = true;
                if let Some(id) = c.id.take() {
                    self.listener.done(id);
                }
            }
        }
    }

    /// Joins that waited for establishment are offered again.
    fn retry_waiting(&mut self) {
        if self.session.state() == State::Establishing {
            return;
        }
        let names: Vec<String> = self
            .carriers
            .iter()
            .filter(|(_, c)| c.waiting.is_some())
            .map(|(n, _)| n.clone())
            .collect();
        for n in names {
            if let Some((frame, bytes, inband)) =
                self.carriers.get_mut(&n).and_then(|c| c.waiting.take())
            {
                self.offer(&n, &frame, &bytes, inband);
            }
        }
    }

    /// Bytes from the peer on a carrier that is not attached yet.
    fn carrier_bytes(&mut self, name: &str, bytes: &[u8], messages: &[Vec<u8>]) {
        let now = self.now();
        let Some(c) = self.carriers.get_mut(name) else {
            return;
        };
        if c.rejected {
            return;
        }
        if c.pairing.is_some() {
            // A split-bootstrap carrier waiting for its pair.
            c.held.push(bytes.to_vec());
            return;
        }
        if c.waiting.is_some() {
            if let Some(w) = c.waiting.as_mut() {
                w.1.extend_from_slice(bytes);
            }
            return;
        }
        let Some(id) = c.id else {
            return;
        };
        let result = if c.framing == Framing::Records {
            let mut r = Classified::NeedMore;
            let mut rest: Vec<Vec<u8>> = Vec::new();
            for m in messages {
                if matches!(r, Classified::NeedMore) {
                    r = self.listener.message(id, m, now);
                } else {
                    rest.push(m.clone());
                }
            }
            if let Classified::Join {
                locator,
                frame,
                bytes,
                inband,
            } = r
            {
                // The first message is fed after acceptance; later ones too.
                let name = name.to_string();
                self.join_found(&name, &locator, &frame, &bytes, inband);
                if let Some(pipe) = self.carriers.get(&name).and_then(|c| c.pipe) {
                    for m in rest {
                        self.message(pipe, &m);
                    }
                }
                return;
            }
            r
        } else {
            self.listener.data(id, bytes, now)
        };
        match result {
            Classified::NeedMore => {}
            // A listener carrier is never a lane (that is a stream of a
            // connection carrying a pipe, `lane_bytes`).
            Classified::Reject | Classified::NewSession { .. } | Classified::Lane { .. } => {
                if let Some(c) = self.carriers.get_mut(name) {
                    c.rejected = true;
                    c.id = None;
                }
            }
            Classified::Join {
                locator,
                frame,
                bytes,
                inband,
            } => {
                let name = name.to_string();
                self.join_found(&name, &locator, &frame, &bytes, inband);
            }
        }
    }

    fn join_found(&mut self, name: &str, locator: &[u8], frame: &[u8], bytes: &[u8], inband: bool) {
        // Step 3: the session lookup by locator.
        if locator != self.session.local_locator() {
            if let Some(c) = self.carriers.get_mut(name) {
                c.rejected = true;
                if let Some(id) = c.id.take() {
                    self.listener.done(id);
                }
            }
            return;
        }
        self.offer(name, frame, bytes, inband);
    }

    // ---- steps ---------------------------------------------------------------

    fn step(&mut self, step: &Step) -> Result<(), String> {
        let r = self.step_inner(step);
        self.retry_waiting();
        r
    }

    fn step_inner(&mut self, step: &Step) -> Result<(), String> {
        match &step.op {
            Op::PipeUp {
                pipe,
                carrier,
                dir,
                via,
                oob_join,
                carrier_binding,
                pairing,
                framing,
                source,
                conn,
            } => {
                let framing = match framing {
                    Some(FramingName::Records) => Framing::Records,
                    _ => Framing::ByteStream,
                };
                let read = matches!(dir, Direction::In | Direction::Bidi);
                let write = matches!(dir, Direction::Out | Direction::Bidi);
                let now = self.now();
                if *via == Some(crate::model::Via::Lane) {
                    // A new stream the peer opened on connection `conn`.
                    let name = carrier.clone().ok_or("lane pipe_up without a carrier")?;
                    let id = self.listener.open_stream(framing, now);
                    self.carriers.insert(
                        name,
                        Carrier {
                            pipe: None,
                            can_read: read,
                            can_write: false,
                            framing,
                            id: Some(id),
                            binding: Vec::new(),
                            waiting: None,
                            rejected: false,
                            pairing: None,
                            held: Vec::new(),
                            conn: conn.clone(),
                            lane: None,
                            inbuf: Vec::new(),
                        },
                    );
                    return Ok(());
                }
                if *via != Some(crate::model::Via::Listener) {
                    let pipe = pipe.ok_or("pipe_up without a pipe")?;
                    if pipe == 0 {
                        self.session.attach_bootstrap(
                            read.then_some(framing),
                            write.then_some(framing),
                            now,
                        );
                    }
                    if conn.is_some() {
                        self.pipe_mut(pipe).conn = conn.clone();
                    }
                    self.attach(pipe, None, read, write, framing);
                    // A driver writes the first record at once.
                    return self.flush();
                }
                let name = carrier
                    .clone()
                    .ok_or("listener pipe_up without a carrier")?;
                let mut c = Carrier {
                    pipe: None,
                    can_read: read,
                    can_write: write,
                    framing,
                    id: None,
                    binding: carrier_binding
                        .as_ref()
                        .map(|b| b.0.clone())
                        .unwrap_or_default(),
                    waiting: None,
                    rejected: false,
                    pairing: None,
                    held: Vec::new(),
                    conn: conn.clone(),
                    lane: None,
                    inbuf: Vec::new(),
                };
                if let Some(token) = pairing {
                    let token: [u8; 16] =
                        token.0.clone().try_into().map_err(|_| "pairing length")?;
                    // The pairing table lives in the listener; carriers that
                    // are paired form pipe 0 (SPEC.md 6.1.1).
                    let fake = CarrierId(u64::MAX - self.carriers.len() as u64);
                    match self.listener.pair(token, fake, read, now) {
                        Paired::Waiting => {
                            c.pairing = Some(token);
                            c.id = Some(fake);
                            self.carriers.insert(name, c);
                        }
                        Paired::Complete(other) => {
                            c.pairing = None;
                            c.pipe = Some(0);
                            self.carriers.insert(name.clone(), c);
                            let other_name = self
                                .carriers
                                .iter()
                                .find(|(_, x)| x.id == Some(other))
                                .map(|(n, _)| n.clone())
                                .ok_or("paired carrier unknown")?;
                            let (oread, owrite, held) = {
                                let o = self.carriers.get_mut(&other_name).expect("paired");
                                o.pairing = None;
                                o.pipe = Some(0);
                                o.id = None;
                                (o.can_read, o.can_write, std::mem::take(&mut o.held))
                            };
                            let inbound = (read || oread).then_some(framing);
                            let outbound = (write || owrite).then_some(framing);
                            self.session.attach_bootstrap(inbound, outbound, now);
                            self.attach(0, Some(&name), read, write, framing);
                            self.attach(0, Some(&other_name), oread, owrite, framing);
                            for b in held {
                                self.deliver(0, &b, None);
                            }
                            return self.flush();
                        }
                        Paired::Reject => {
                            c.rejected = true;
                            self.carriers.insert(name, c);
                        }
                    }
                    return Ok(());
                }
                let src = source_name(source.as_deref().unwrap_or("default"));
                match self.listener.open(src, framing, now) {
                    Opened::Accepted { id, evicted } => {
                        c.id = Some(id);
                        if let Some(e) = evicted {
                            for x in self.carriers.values_mut() {
                                if x.id == Some(e) {
                                    x.rejected = true;
                                    x.id = None;
                                }
                            }
                        }
                    }
                    Opened::Refused => c.rejected = true,
                }
                let oob = oob_join.as_ref().map(|h| h.0.clone());
                let id = c.id;
                self.carriers.insert(name.clone(), c);
                if let (Some(frame), Some(id)) = (oob, id) {
                    match self.listener.oob(id, &frame, now) {
                        Classified::Join {
                            locator,
                            frame,
                            bytes,
                            inband,
                        } => self.join_found(&name, &locator, &frame, &bytes, inband),
                        _ => {
                            if let Some(c) = self.carriers.get_mut(&name) {
                                c.rejected = true;
                                c.id = None;
                            }
                        }
                    }
                }
                self.flush()
            }
            Op::PipeDown {
                pipe,
                carrier,
                lane,
                dir,
                how,
            } => {
                let now = self.now();
                let end = match how {
                    DownHow::Eof => PipeEnd::Eof,
                    DownHow::Error => PipeEnd::Error(std::io::ErrorKind::ConnectionReset),
                };
                let at = match (pipe, carrier) {
                    (Some(p), _) => PipeId(*p).lane(lane.unwrap_or(0)),
                    (None, Some(c)) => {
                        // A stream of a connection: the lane it is, if any.
                        let c = self
                            .carriers
                            .get(c)
                            .ok_or_else(|| format!("no carrier {c}"))?;
                        match c.lane {
                            Some(l) => l,
                            None => return Ok(()),
                        }
                    }
                    _ => return Err("pipe_down without a pipe".into()),
                };
                if matches!(dir, Direction::In | Direction::Bidi) {
                    self.session.pipe_ended(at, end, now);
                }
                if matches!(dir, Direction::Out | Direction::Bidi) && *how == DownHow::Error {
                    self.session
                        .write_failed(at, std::io::ErrorKind::BrokenPipe, now);
                    self.pipe_mut(at.pipe.0)
                        .lane_mut(at.lane.0)
                        .closed
                        .get_or_insert(ClosedHow::Abort);
                }
                self.drain_events();
                Ok(())
            }
            Op::SetWritable { pipe, writable } => {
                let now = self.now();
                self.pipe_mut(*pipe).writable = *writable;
                let lanes: Vec<u64> = std::iter::once(0)
                    .chain(self.pipes[pipe].lanes.keys().copied())
                    .collect();
                for lane in lanes {
                    self.session.pipe_write(
                        PipeId(*pipe).lane(lane),
                        PipeWrite::returned(now, now, 0, 0, !*writable),
                        now,
                    );
                }
                Ok(())
            }
            Op::PeerSend {
                pipe,
                carrier,
                records,
                hex,
                messages,
                messages_hex,
                chunks,
                ..
            } => {
                let sent: BTreeMap<(u64, u64), u64> = self
                    .pipes
                    .iter()
                    .flat_map(|(&k, v)| {
                        std::iter::once(((k, 0), v.out.sent))
                            .chain(v.lanes.iter().map(move |(&l, o)| ((k, l), o.sent)))
                    })
                    .collect();
                let resolve = move |p: u64, lane: u64| sent.get(&(p, lane)).copied().unwrap_or(0);
                let target = match (pipe, carrier) {
                    (Some(p), _) => Some(*p),
                    (None, Some(c)) => self.carriers.get(c).and_then(|c| c.pipe),
                    _ => None,
                };
                let framing = match (pipe, carrier) {
                    (Some(p), _) => self
                        .pipes
                        .get(p)
                        .and_then(|x| x.in_framing)
                        .unwrap_or(Framing::ByteStream),
                    (None, Some(c)) => self
                        .carriers
                        .get(c)
                        .map_or(Framing::ByteStream, |c| c.framing),
                    _ => Framing::ByteStream,
                };
                if framing == Framing::Records {
                    let msgs: Vec<Vec<u8>> = match (messages_hex, messages) {
                        (Some(h), _) => h.iter().map(|m| m.0.clone()).collect(),
                        (None, Some(m)) => {
                            m.iter().map(|f| wire::encode_frames(f, &resolve)).collect()
                        }
                        _ => return Err("peer_send without messages".into()),
                    };
                    match (target, carrier) {
                        (Some(p), _) => {
                            for m in msgs {
                                self.message(p, &m);
                            }
                        }
                        (None, Some(c)) => {
                            let c = c.clone();
                            self.carrier_bytes(&c, &[], &msgs);
                        }
                        _ => return Err("peer_send without a target".into()),
                    }
                    return Ok(());
                }
                let bytes = match (hex, records) {
                    (Some(h), _) => h.0.clone(),
                    (None, Some(r)) => r
                        .iter()
                        .flat_map(|f| wire::encode_record(f, &resolve))
                        .collect(),
                    _ => return Err("peer_send without bytes".into()),
                };
                match (target, carrier) {
                    (Some(p), _) => self.deliver(p, &bytes, chunks.as_deref()),
                    (None, Some(c))
                        if self.carriers.get(c).is_some_and(|c| {
                            c.conn.is_some() && c.pipe.is_none() && !c.can_write
                        }) =>
                    {
                        let c = c.clone();
                        self.lane_bytes(&c, &bytes);
                    }
                    (None, Some(c)) => {
                        let c = c.clone();
                        self.carrier_bytes(&c, &bytes, &[]);
                    }
                    _ => return Err("peer_send without a target".into()),
                }
                Ok(())
            }
            Op::Api(api) => {
                let raw_expect = step.raw.get("expect").cloned();
                let result = self.api(&api.call, api.bind.as_deref())?;
                self.drain_events();
                if let Some(expected) = raw_expect {
                    match_result(&expected, &result)
                        .map_err(|e| format!("result {result}: {e}"))?;
                }
                Ok(())
            }
            Op::ExpectFrames {
                pipe,
                lane,
                frames: _,
                mode,
                one_credit_per_record,
            } => {
                self.flush()?;
                let patterns = step.raw["frames"].as_array().cloned().unwrap_or_default();
                let (frames, records, all) = self.take_frames(pipe, *lane);
                let result = match mode {
                    crate::model::MatchMode::First => match_exact(&patterns, &all),
                    crate::model::MatchMode::Exact => match_exact(&patterns, &frames),
                    crate::model::MatchMode::Contains => match_contains(&patterns, &frames),
                    crate::model::MatchMode::Unordered => match_unordered(&patterns, &frames),
                };
                result.map_err(|e| format!("{e}\n    frames: {}", summarise(&frames)))?;
                if *one_credit_per_record {
                    check_one_credit(&records)?;
                }
                Ok(())
            }
            Op::ExpectNoFrames { pipe, lane, types } => {
                self.flush()?;
                // A lane not opened has written nothing.
                let (frames, _, _) = self.take_frames(pipe, *lane);
                let bad: Vec<&Value> = frames
                    .iter()
                    .filter(|f| f["type"] != "PADDING")
                    .filter(|f| {
                        types.as_ref().is_none_or(|t| {
                            t.iter().any(|t| f["type"].as_str() == Some(t.as_str()))
                        })
                    })
                    .collect();
                if bad.is_empty() {
                    Ok(())
                } else {
                    Err(format!("unexpected frames: {}", summarise_refs(&bad)))
                }
            }
            Op::ExpectClose { error, wire } => {
                self.flush()?;
                self.close_covered = true;
                let e =
                    self.session.error().cloned().ok_or_else(|| {
                        format!("session open (state {:?})", self.session.state())
                    })?;
                if self.session.state() < State::Closing {
                    return Err(format!("error {e:?} but state {:?}", self.session.state()));
                }
                match_close(error, &e)?;
                match wire {
                    Some(true) => {
                        let app = error.space == ErrorSpace::Application;
                        let code = code_value(error.space, &error.code);
                        let found = self.closes.iter().any(|c| {
                            c["app"] == json!(app) && code.is_none_or(|v| c["code"] == json!(v))
                        });
                        if !found {
                            return Err(format!(
                                "no CONNECTION_CLOSE with that code; written: {:?}",
                                self.closes
                            ));
                        }
                    }
                    Some(false) if !self.closes.is_empty() => {
                        return Err(format!("CONNECTION_CLOSE written: {:?}", self.closes));
                    }
                    _ => {}
                }
                Ok(())
            }
            Op::ExpectOpen => {
                self.flush()?;
                if self.session.state() >= State::Closing {
                    return Err(format!("session closing: {:?}", self.session.error()));
                }
                Ok(())
            }
            Op::ExpectState {
                session,
                pipe,
                dir,
                state,
            } => {
                self.flush()?;
                if let Some(want) = session {
                    let have = format!("{:?}", self.session.state()).to_uppercase();
                    let want = format!("{want:?}").to_uppercase();
                    if have != want {
                        return Err(format!("state {have}, expected {want}"));
                    }
                }
                if let (Some(pipe), Some(dir), Some(state)) = (pipe, dir, state) {
                    let half = match dir {
                        Direction::In => PipeHalf::Inbound,
                        _ => PipeHalf::Outbound,
                    };
                    let have = self
                        .session
                        .pipe_state(PipeId(*pipe), half)
                        .map(state_name)
                        .ok_or_else(|| format!("pipe {pipe} {dir:?} has no state"))?;
                    if !state_matches(state, have) {
                        return Err(format!(
                            "pipe {pipe} {dir:?} is {have:?}, expected {state:?}"
                        ));
                    }
                }
                Ok(())
            }
            Op::ExpectEvent { event, fields } => {
                self.flush()?;
                let raw_fields = step.raw.get("fields").cloned().unwrap_or(json!({}));
                let matching: Vec<CoreEvent> = self
                    .events
                    .iter()
                    .filter(|e| event_name(e) == Some(*event))
                    .cloned()
                    .collect();
                self.events.retain(|e| event_name(e) != Some(*event));
                if *event == EventName::DatagramDropped {
                    let total: u64 = matching
                        .iter()
                        .map(|e| match e {
                            CoreEvent::DatagramsDropped { count } => *count,
                            _ => 0,
                        })
                        .sum();
                    if total == 0 {
                        return Err("no datagram_dropped event".into());
                    }
                    if let Some(c) = fields.count
                        && c != total
                    {
                        return Err(format!("datagram_dropped count {total}, expected {c}"));
                    }
                    return Ok(());
                }
                if matching.is_empty() {
                    return Err(format!("no {event:?} event"));
                }
                let mut errors = Vec::new();
                for e in &matching {
                    match match_event(e, fields, &raw_fields) {
                        Ok(()) => return Ok(()),
                        Err(err) => errors.push(err),
                    }
                }
                Err(errors.join("; "))
            }
            Op::ExpectNoEvent { event } => {
                self.flush()?;
                let n = self
                    .events
                    .iter()
                    .filter(|e| event_name(e) == Some(*event))
                    .count();
                self.events.retain(|e| event_name(e) != Some(*event));
                if n > 0 {
                    return Err(format!("{n} {event:?} events"));
                }
                Ok(())
            }
            Op::ExpectPipeClosed {
                pipe,
                lane,
                dir,
                how,
            } => {
                self.flush()?;
                let p = self
                    .pipes
                    .get(pipe)
                    .ok_or_else(|| format!("no pipe {pipe}"))?;
                let have = match (dir, lane) {
                    (Direction::In, _) => p.in_closed,
                    (_, Some(l)) => p.lane(*l).and_then(|o| o.closed),
                    // Every lane of it.
                    (_, None) => {
                        let all: Vec<Option<ClosedHow>> = std::iter::once(&p.out)
                            .chain(p.lanes.values())
                            .map(|o| o.closed)
                            .collect();
                        if all.iter().all(|c| *c == all[0]) {
                            all[0]
                        } else {
                            None
                        }
                    }
                };
                match (have, how) {
                    (Some(_), ClosedHow::Any) => Ok(()),
                    (Some(h), want) if h == *want => Ok(()),
                    (h, want) => Err(format!("pipe {pipe} closed {h:?}, expected {want:?}")),
                }
            }
            Op::ExpectRejectCarrier { carrier } => {
                self.flush()?;
                let c = self
                    .carriers
                    .get(carrier)
                    .ok_or_else(|| format!("no carrier {carrier}"))?;
                if !c.rejected {
                    return Err(format!(
                        "carrier {carrier} not rejected (pipe {:?}, waiting {})",
                        c.pipe,
                        c.waiting.is_some()
                    ));
                }
                Ok(())
            }
            Op::Advance { ms } => self.advance(*ms),
            Op::Note { .. } => Ok(()),
        }
    }

    /// The frames written since the last expectation on a pipe (or on every
    /// pipe), consumed.
    fn take_frames(
        &mut self,
        sel: &crate::model::PipeSelector,
        lane: Option<u64>,
    ) -> (Vec<Value>, Vec<Vec<Value>>, Vec<Value>) {
        match sel {
            crate::model::PipeSelector::Id(id) => {
                let Some(p) = self.pipes.get_mut(id) else {
                    return Default::default();
                };
                let lane = lane.unwrap_or(0);
                if lane != 0 && !p.lanes.contains_key(&lane) {
                    return Default::default();
                }
                let o = p.lane_mut(lane);
                (
                    std::mem::take(&mut o.pending),
                    std::mem::take(&mut o.pending_records),
                    o.all.clone(),
                )
            }
            crate::model::PipeSelector::All => {
                let mut f = Vec::new();
                let mut r = Vec::new();
                let mut a = Vec::new();
                for p in self.pipes.values_mut() {
                    for o in p.outs_mut() {
                        f.append(&mut o.pending);
                        r.append(&mut o.pending_records);
                        a.extend(o.all.iter().cloned());
                    }
                }
                (f, r, a)
            }
        }
    }

    fn api(&mut self, call: &Call, bind: Option<&str>) -> Result<Value, String> {
        let now = self.now();
        let s = &mut self.session;
        let ok = json!({"ok": true});
        Ok(match call {
            Call::OpenBidi(a) | Call::OpenUni(a) => {
                let dir = if matches!(call, Call::OpenBidi(_)) {
                    Dir::Bidi
                } else {
                    Dir::Uni
                };
                let preamble = match &a.open_info {
                    Some(info) => Preamble::new().with_info(info.0.clone()),
                    None => Preamble::new(),
                };
                match s.open_with(dir, &preamble) {
                    Ok(key) => {
                        if let Some(b) = bind {
                            self.handles.insert(b.to_string(), key);
                        }
                        if let Some(p) = a.priority {
                            let p =
                                Priority::new(p.urgency, p.incremental).ok_or("bad priority")?;
                            if let Err(e) = s.set_peer_priority(key, p) {
                                return Ok(stream_error(&e));
                            }
                        }
                        ok
                    }
                    Err(e) => open_error(&e),
                }
            }
            Call::AcceptBidi(_) | Call::AcceptUni(_) => {
                let dir = if matches!(call, Call::AcceptBidi(_)) {
                    Dir::Bidi
                } else {
                    Dir::Uni
                };
                match s.accept(dir) {
                    Ok(Some(key)) => {
                        if let Some(b) = bind {
                            self.handles.insert(b.to_string(), key);
                        }
                        let mut r = json!({"stream": s.peek_stream_id(key)});
                        let preamble = s.preamble(key);
                        if let Some(info) = preamble.info() {
                            r["open_info"] = json!(to_hex(info));
                        }
                        if let Some(p) = s.requested_priority(key) {
                            r["priority"] =
                                json!({"urgency": p.urgency(), "incremental": p.incremental()});
                        }
                        r["pipe_carrier"] = json!(preamble.is_pipe_carrier());
                        r["app_tlvs"] = preamble
                            .tlvs()
                            .map(|(ty, v)| json!({"type": ty, "value": to_hex(&v)}))
                            .collect();
                        r
                    }
                    Ok(None) => json!({"pending": true}),
                    Err(e) => session_error(&e),
                }
            }
            Call::Write(a) => {
                let key = self.key(&a.stream)?;
                let s = &mut self.session;
                let data = match (&a.data, &a.fill) {
                    (Some(d), _) => d.0.clone(),
                    (None, Some(f)) => vec![f.byte; f.len],
                    _ => Vec::new(),
                };
                match s.write(key, &data) {
                    Ok(n) => {
                        if a.fin
                            && n == data.len()
                            && let Err(e) = s.finish(key)
                        {
                            return Ok(stream_error(&e));
                        }
                        json!({"accepted": n})
                    }
                    Err(e) => stream_error(&e),
                }
            }
            Call::StreamId(a) => {
                let key = self.key(&a.stream)?;
                match self.session.stream_id(key) {
                    Ok(id) => json!({"stream": id}),
                    Err(e) => stream_error(&e),
                }
            }
            Call::SetReliableBoundary(a) => {
                let key = self.key(&a.stream)?;
                unit(self.session.set_reliable_boundary(key))
            }
            Call::Finish(a) => {
                let key = self.key(&a.stream)?;
                unit(self.session.finish(key))
            }
            Call::Reset(a) => {
                let key = self.key(&a.stream)?;
                unit(
                    self.session
                        .reset(key, VarInt::from_u64(a.code).map_err(|_| "code")?),
                )
            }
            Call::Stop(a) => {
                let key = self.key(&a.stream)?;
                unit(
                    self.session
                        .stop(key, VarInt::from_u64(a.code).map_err(|_| "code")?),
                )
            }
            Call::Read(a) => {
                let key = self.key(&a.stream)?;
                match self.session.read_chunk(key, a.max) {
                    Ok(Some((data, fin))) => json!({"data": to_hex(&data), "fin": fin}),
                    Ok(None) => json!({"pending": true}),
                    Err(e) => stream_error(&e),
                }
            }
            Call::Release(a) => {
                let key = self.key(&a.stream)?;
                self.session.release(key);
                ok
            }
            Call::Reject(a) => {
                let key = self.key(&a.stream)?;
                unit(self.session.reject(key))
            }
            Call::SetPriority(a) => {
                let key = self.key(&a.stream)?;
                let p = Priority::new(a.urgency, a.incremental).ok_or("bad priority")?;
                unit(self.session.set_priority(key, p))
            }
            Call::SetPeerPriority(a) => {
                let key = self.key(&a.stream)?;
                let p = Priority::new(a.urgency, a.incremental).ok_or("bad priority")?;
                unit(self.session.set_peer_priority(key, p))
            }
            Call::SendDatagram(a) => {
                let data = Bytes::from(a.data.0.clone());
                let r = match &a.stream {
                    Some(st) => {
                        let key = self.key(st)?;
                        self.session
                            .send_stream_datagram(key, a.context.unwrap_or(0), data, true)
                    }
                    None => self.session.send_datagram(data, true),
                };
                match r {
                    Ok(_) => ok,
                    Err(e) => datagram_error(&e),
                }
            }
            Call::RecvDatagram(a) => match &a.stream {
                Some(st) => {
                    let key = self.key(st)?;
                    match self.session.recv_stream_datagram(key) {
                        Ok(Some((ctx, d))) => json!({"data": to_hex(&d), "context": ctx}),
                        Ok(None) => json!({"pending": true}),
                        Err(e) => stream_error(&e),
                    }
                }
                None => match self.session.recv_datagram() {
                    Ok(Some(d)) => json!({"data": to_hex(&d)}),
                    Ok(None) => json!({"pending": true}),
                    Err(e) => session_error(&e),
                },
            },
            Call::Ping(_) => match s.ping() {
                Ok(_) => ok,
                Err(e) => session_error(&e),
            },
            Call::Shutdown(a) => {
                s.shutdown(VarInt::from_u64(a.code).map_err(|_| "code")?, b"", now);
                ok
            }
            Call::Close(a) => {
                if !a.app {
                    return Err("transport close by the application is not an API".into());
                }
                s.close(
                    VarInt::from_u64(a.code).map_err(|_| "code")?,
                    &a.reason.0,
                    now,
                );
                ok
            }
            Call::AddPipe(a) => {
                let read = matches!(a.dir, Direction::In | Direction::Bidi);
                let write = matches!(a.dir, Direction::Out | Direction::Bidi);
                let framing = Framing::ByteStream;
                let mut opts = PipeOptions::default();
                opts.fate_group = a.fate_group;
                opts.send_priority = a.send_priority;
                opts.receive_priority = a.receive_priority.unwrap_or(0);
                opts.send_standby = a.send_standby.or(a.standby);
                opts.receive_standby = a.receive_standby.or(a.standby).unwrap_or(false);
                if let Some(w) = a.weight {
                    opts.weight = w;
                }
                opts.probation = a.probation.map(Duration::from_millis);
                let binding = a.carrier_bound.then_some(&[0u8; 32][..]);
                match s.add_pipe(
                    read.then_some(framing),
                    write.then_some(framing),
                    &opts,
                    a.oob,
                    binding,
                    now,
                ) {
                    Ok(id) => {
                        if id.0 != a.pipe {
                            return Err(format!(
                                "add_pipe gave pipe {}, expected {}",
                                id.0, a.pipe
                            ));
                        }
                        let waiting = s.join_deferred(id);
                        self.attach(id.0, None, read, write, framing);
                        if waiting {
                            json!({"pending": true})
                        } else {
                            ok
                        }
                    }
                    Err(e) => pipe_error(&e),
                }
            }
            Call::RemovePipe(a) => match s.remove_pipe(PipeId(a.pipe), a.graceful, now) {
                Ok(()) => ok,
                Err(e) => pipe_error(&e),
            },
            Call::SetPipeStatus(a) => {
                let p = PipeId(a.pipe);
                let r = (|| {
                    if let Some(v) = a.send_priority {
                        s.set_pipe_send_priority(p, v)?;
                    }
                    if let Some(v) = a.send_standby {
                        s.set_pipe_send_standby(p, v)?;
                    }
                    // The request: one PIPE_STATUS for the call.
                    let standby = a.receive_standby.or(a.standby);
                    match (a.receive_priority, standby) {
                        (Some(v), Some(b)) => s.set_pipe_receive_status(p, b, v)?,
                        (Some(v), None) => s.set_pipe_receive_priority(p, v)?,
                        (None, Some(b)) => s.set_pipe_receive_standby(p, b)?,
                        (None, None) => {}
                    }
                    if let Some(v) = a.standby {
                        s.set_pipe_send_standby(p, Some(v))?;
                    }
                    if let Some(v) = a.weight {
                        s.set_pipe_weight(p, v)?;
                    }
                    Ok(())
                })();
                match r {
                    Ok(()) => ok,
                    Err(e) => pipe_error(&e),
                }
            }
            Call::SetScheduler(a) => {
                let p = policy(&a.policy)?;
                match &a.stream {
                    Some(st) => {
                        let key = self.key(st)?;
                        match self.session.set_stream_scheduler(key, Some(p)) {
                            Ok(()) => ok,
                            Err(e) => stream_error(&e),
                        }
                    }
                    None => {
                        self.session.set_scheduler(p);
                        ok
                    }
                }
            }
            Call::SetRedundant(a) => {
                let key = self.key(&a.stream)?;
                match self.session.set_redundant(key, a.redundant) {
                    Ok(()) => ok,
                    Err(e) => stream_error(&e),
                }
            }
            Call::RevalidatePipes(a) => {
                let now = self.now();
                match self.session.revalidate_pipes(a.pipe.map(PipeId), now) {
                    Ok(()) => ok,
                    Err(e) => pipe_error(&e),
                }
            }
        })
    }
}

fn pipe_error(e: &PipeError) -> Value {
    match e {
        PipeError::NotNegotiated => json!({"error": {"kind": "unsupported"}}),
        PipeError::SessionLost(s) => session_error(s),
        other => json!({"error": {"kind": format!("{other:?}")}}),
    }
}

// ---- results ---------------------------------------------------------------------

fn unit(r: Result<(), StreamError>) -> Value {
    match r {
        Ok(()) => json!({"ok": true}),
        Err(e) => stream_error(&e),
    }
}

fn stream_error(e: &StreamError) -> Value {
    let inner = match e {
        StreamError::Reset { code: c, .. } => {
            json!({"kind": "stream_reset", "code": c.into_inner(), "remote": true})
        }
        StreamError::Stopped(c) => {
            json!({"kind": "stream_stopped", "code": c.into_inner(), "remote": true})
        }
        StreamError::Rejected => json!({"kind": "stream_rejected"}),
        StreamError::GoingAway => json!({"kind": "going_away"}),
        StreamError::ClosedLocally => json!({"kind": "closed_locally"}),
        StreamError::NotNegotiated => json!({"kind": "unsupported"}),
        StreamError::SessionLost(s) => return session_error(s),
        StreamError::NotEstablished | StreamError::Blocked => return json!({"pending": true}),
        other => json!({"kind": format!("{other:?}")}),
    };
    json!({ "error": inner })
}

fn open_error(e: &OpenError) -> Value {
    match e {
        OpenError::Blocked => json!({"pending": true}),
        OpenError::GoingAway => json!({"error": {"kind": "going_away"}}),
        OpenError::NotNegotiated => json!({"error": {"kind": "unsupported"}}),
        OpenError::TooLarge => json!({"error": {"kind": "too_large"}}),
        OpenError::SessionLost(s) => session_error(s),
        other => json!({"error": {"kind": format!("{other:?}")}}),
    }
}

fn datagram_error(e: &DatagramError) -> Value {
    match e {
        DatagramError::NotNegotiated => json!({"error": {"kind": "unsupported"}}),
        DatagramError::TooLarge { .. } => json!({"error": {"kind": "too_large"}}),
        DatagramError::ClosedStream => json!({"error": {"kind": "closed_locally"}}),
        DatagramError::SessionLost(s) => session_error(s),
        other => json!({"error": {"kind": format!("{other:?}")}}),
    }
}

/// The session error as `{space, code, remote}` with a numeric or local
/// code.
fn session_fields(e: &SessionError) -> (ErrorSpace, Value, bool) {
    match e {
        SessionError::ApplicationClosed { code, remote, .. } => {
            (ErrorSpace::Application, json!(code.into_inner()), *remote)
        }
        SessionError::TransportClosed { code, remote, .. } => {
            (ErrorSpace::Transport, json!(code.0), *remote)
        }
        SessionError::IdleTimeout { remote } => (ErrorSpace::Local, json!("IDLE_TIMEOUT"), *remote),
        SessionError::HandshakeTimeout => (ErrorSpace::Local, json!("HANDSHAKE_TIMEOUT"), false),
        SessionError::EarlyDataRejected => (ErrorSpace::Local, json!("EARLY_DATA_REJECTED"), false),
        SessionError::PipesLost { .. } => (ErrorSpace::Local, json!("PIPES_LOST"), false),
        // Locally, CONNECTION_CLOSE(ZMUX_RESUME_TIMEOUT) (RESUME.md Section 8).
        SessionError::ResumeTimeout { .. } => (
            ErrorSpace::Transport,
            json!(zmux::proto::TransportErrorCode::ZMUX_RESUME_TIMEOUT.0),
            false,
        ),
        other => (ErrorSpace::Local, json!(format!("{other:?}")), false),
    }
}

fn session_error(e: &SessionError) -> Value {
    let (space, code, remote) = session_fields(e);
    let space = match space {
        ErrorSpace::Application => "application",
        ErrorSpace::Transport => "transport",
        ErrorSpace::Local => "local",
    };
    json!({"error": {"kind": "session", "space": space, "code": code, "remote": remote}})
}

/// A code as the number it stands for (registry names resolved), or the
/// local reason name.
fn code_value(space: ErrorSpace, code: &crate::model::CodeRef) -> Option<u64> {
    match code {
        crate::model::CodeRef::Value(v) => Some(*v),
        crate::model::CodeRef::Name(n) => match space {
            ErrorSpace::Transport => TRANSPORT_ERRORS
                .iter()
                .find(|(_, name, _)| name == n)
                .map(|(c, ..)| c.0),
            ErrorSpace::Application => APPLICATION_ERRORS
                .iter()
                .find(|(_, name, _)| name == n)
                .map(|(c, ..)| c.0),
            ErrorSpace::Local => None,
        },
    }
}

fn code_json(space: Option<&str>, code: &Value) -> Value {
    let Some(name) = code.as_str() else {
        return code.clone();
    };
    let table = match space {
        Some("transport") => TRANSPORT_ERRORS
            .iter()
            .find(|(_, n, _)| *n == name)
            .map(|(c, ..)| c.0),
        Some("application") => APPLICATION_ERRORS
            .iter()
            .find(|(_, n, _)| *n == name)
            .map(|(c, ..)| c.0),
        _ => None,
    };
    table.map_or_else(|| code.clone(), |v| json!(v))
}

/// Compares an API result with the expected object: every expected field
/// must be present and equal; error codes may be registry names.
fn match_result(expected: &Value, actual: &Value) -> Result<(), String> {
    let mut expected = expected.clone();
    if let Some(err) = expected.get_mut("error")
        && let Some(code) = err.get("code").cloned()
    {
        let space = err.get("space").and_then(Value::as_str).map(str::to_string);
        err["code"] = code_json(space.as_deref(), &code);
    }
    wire::json_subset(&expected, actual, "")
}

fn match_close(spec: &CloseSpec, e: &SessionError) -> Result<(), String> {
    let (space, code, remote) = session_fields(e);
    if space != spec.space {
        return Err(format!("closed with {e:?}, expected {spec:?}"));
    }
    let want = match (&spec.code, space) {
        (crate::model::CodeRef::Name(n), ErrorSpace::Local) => json!(n),
        (c, s) => json!(code_value(s, c).ok_or_else(|| format!("unknown code {c:?}"))?),
    };
    if code != want {
        return Err(format!("closed with {e:?}, expected {spec:?}"));
    }
    if spec.remote.is_some_and(|r| r != remote) {
        return Err(format!(
            "closed with {e:?} (remote {remote}), expected {spec:?}"
        ));
    }
    Ok(())
}

// ---- events ------------------------------------------------------------------------

fn event_name(e: &CoreEvent) -> Option<EventName> {
    Some(match e {
        CoreEvent::Established { .. } => EventName::Established,
        CoreEvent::GoAway { .. } => EventName::GoawayReceived,
        CoreEvent::DatagramsDropped { .. } => EventName::DatagramDropped,
        CoreEvent::Closed(_) => EventName::Closed,
        CoreEvent::OobJoin { .. } => EventName::OobJoin,
        CoreEvent::JoinAuthFailed { .. } => EventName::JoinAuthFailed,
        CoreEvent::Suspended => EventName::Suspended,
        CoreEvent::Resumed => EventName::Resumed,
        CoreEvent::PipeState { .. } => EventName::PipeState,
        _ => return None,
    })
}

fn features_list(f: Features) -> Vec<Feature> {
    let mut v = Vec::new();
    for (on, name) in [
        (f.role, Feature::Role),
        (f.goaway, Feature::Goaway),
        (f.preamble, Feature::Preamble),
        (f.priority, Feature::Priority),
        (f.datagram_flows, Feature::DatagramFlows),
        (f.multipath, Feature::Multipath),
        (f.pipe_ack, Feature::PipeAck),
        (f.resume, Feature::Resume),
    ] {
        if on {
            v.push(name);
        }
    }
    v
}

fn match_event(
    e: &CoreEvent,
    fields: &crate::model::EventFields,
    raw: &Value,
) -> Result<(), String> {
    let _ = raw;
    match e {
        CoreEvent::Established { role, features, .. } => {
            if let Some(want) = fields.role {
                let have = match role {
                    Role::Initiator => TransportRole::Initiator,
                    Role::Responder => TransportRole::Responder,
                };
                if have != want {
                    return Err(format!("role {have:?}, expected {want:?}"));
                }
            }
            if let Some(want) = &fields.features {
                let mut have = features_list(*features);
                let mut want = want.clone();
                have.sort_by_key(|f| format!("{f:?}"));
                want.sort_by_key(|f| format!("{f:?}"));
                if have != want {
                    return Err(format!("features {have:?}, expected {want:?}"));
                }
            }
            Ok(())
        }
        CoreEvent::GoAway {
            max_bidi,
            max_uni,
            code,
        } => {
            for (have, want, name) in [
                (*max_bidi, fields.max_bidi, "max_bidi"),
                (*max_uni, fields.max_uni, "max_uni"),
                (*code, fields.code, "code"),
            ] {
                if want.is_some_and(|w| w != have) {
                    return Err(format!("goaway {name} {have}, expected {want:?}"));
                }
            }
            Ok(())
        }
        CoreEvent::Closed(err) => match &fields.error {
            Some(spec) => match_close(spec, err),
            None => Ok(()),
        },
        CoreEvent::OobJoin { pipe, frame } => {
            if fields.pipe.is_some_and(|p| p != pipe.0) {
                return Err(format!("oob_join pipe {}", pipe.0));
            }
            if let Some(f) = &fields.frame
                && f.0 != frame[..]
            {
                return Err(format!("oob_join frame {}", to_hex(frame)));
            }
            Ok(())
        }
        CoreEvent::JoinAuthFailed { carrier_bound } => match fields.reason {
            Some(crate::model::AuthFailure::Mac) if *carrier_bound => {
                Err("join_auth_failed reason mac_carrier_bound".into())
            }
            Some(crate::model::AuthFailure::MacCarrierBound) if !*carrier_bound => {
                Err("join_auth_failed reason mac".into())
            }
            _ => Ok(()),
        },
        CoreEvent::Suspended | CoreEvent::Resumed => Ok(()),
        CoreEvent::PipeState { pipe, half, state } => {
            if fields.pipe.is_some_and(|p| p != pipe.0) {
                return Err(format!("pipe_state pipe {}", pipe.0));
            }
            if let Some(d) = fields.dir {
                let want = match d {
                    Direction::In => PipeHalf::Inbound,
                    _ => PipeHalf::Outbound,
                };
                if want != *half {
                    return Err(format!("pipe_state dir {half:?}"));
                }
            }
            if let Some(p) = &fields.state
                && !state_matches(p, state_name(*state))
            {
                return Err(format!("pipe_state {state:?}"));
            }
            Ok(())
        }
        other => Err(format!("unexpected event {other:?}")),
    }
}

// ---- frame patterns ------------------------------------------------------------------

fn summarise(frames: &[Value]) -> String {
    summarise_refs(&frames.iter().collect::<Vec<_>>())
}

fn summarise_refs(frames: &[&Value]) -> String {
    let parts: Vec<String> = frames
        .iter()
        .map(|f| {
            let mut f = (*f).clone();
            if let Some(d) = f.get_mut("data")
                && let Some(s) = d.as_str()
                && s.len() > 40
            {
                *d = json!(format!("{}..({} bytes)", &s[..40], s.len() / 2));
            }
            if f["type"] == "QX_TRANSPORT_PARAMETERS" {
                return "QX_TRANSPORT_PARAMETERS".to_string();
            }
            f.to_string()
        })
        .collect();
    format!("[{}]", parts.join(", "))
}

fn type_matches(pattern: &Value, frame: &Value) -> bool {
    match pattern {
        Value::String(s) if s == "*" => true,
        Value::String(s) => frame["type"] == json!(s),
        Value::Object(o) => o
            .get("oneof")
            .and_then(Value::as_array)
            .is_some_and(|names| names.iter().any(|n| frame["type"] == *n)),
        _ => false,
    }
}

fn value_matches(pattern: &Value, actual: Option<&Value>) -> bool {
    let Some(actual) = actual else {
        return false;
    };
    match pattern {
        Value::String(s) if s == "*" => true,
        Value::Object(o) if o.contains_key("min") || o.contains_key("max") => {
            let Some(v) = actual.as_u64() else {
                return false;
            };
            o.get("min").and_then(Value::as_u64).is_none_or(|m| v >= m)
                && o.get("max").and_then(Value::as_u64).is_none_or(|m| v <= m)
        }
        Value::Object(o) if o.contains_key("len") => {
            let n = o["len"].as_u64().unwrap_or(0) as usize;
            actual.as_str().is_some_and(|s| s.len() == 2 * n)
        }
        Value::Object(o) if o.contains_key("prefix") => {
            let p = o["prefix"].as_str().unwrap_or("");
            actual.as_str().is_some_and(|s| s.starts_with(p))
        }
        Value::Array(items) => actual.as_array().is_some_and(|a| {
            a.len() == items.len() && items.iter().zip(a).all(|(p, v)| value_matches(p, Some(v)))
        }),
        Value::Object(o) => actual
            .as_object()
            .is_some_and(|a| o.iter().all(|(k, p)| value_matches(p, a.get(k)))),
        _ => pattern == actual,
    }
}

const META: &[&str] = &[
    "type",
    "count",
    "params_include",
    "params_exclude",
    "grease",
];

/// Whether one frame matches a (non-STREAM_DATA) pattern.
fn frame_matches(pattern: &Value, frame: &Value) -> bool {
    if !type_matches(&pattern["type"], frame) {
        return false;
    }
    let Some(obj) = pattern.as_object() else {
        return false;
    };
    for (k, v) in obj {
        if META.contains(&k.as_str()) {
            continue;
        }
        if !value_matches(v, frame.get(k)) {
            return false;
        }
    }
    if frame["type"] == "QX_TRANSPORT_PARAMETERS" {
        let params = frame["params"].as_array().cloned().unwrap_or_default();
        let find = |name: &str| params.iter().find(|p| p["id"] == json!(name));
        if let Some(inc) = pattern.get("params_include").and_then(Value::as_object) {
            for (name, want) in inc {
                let Some(p) = find(name) else {
                    return false;
                };
                if want != "*" && p.get("value").unwrap_or(&Value::Null) != want {
                    return false;
                }
            }
        }
        if let Some(exc) = pattern.get("params_exclude").and_then(Value::as_array)
            && exc
                .iter()
                .any(|n| n.as_str().is_some_and(|n| find(n).is_some()))
        {
            return false;
        }
        if pattern.get("grease") == Some(&json!(true)) {
            let grease = params.iter().any(|p| {
                p["id"]
                    .as_u64()
                    .is_some_and(zmux::proto::params::is_grease_id)
            });
            if !grease {
                return false;
            }
        }
    }
    true
}

/// Matches a STREAM_DATA pseudo-frame against the STREAM frames of its
/// stream at indices `from..`; returns the index of the last frame it
/// covers.
fn stream_data_match(pattern: &Value, frames: &[Value], from: usize) -> Result<usize, String> {
    let id = pattern["id"].as_u64().ok_or("STREAM_DATA without id")?;
    let off = pattern.get("off").and_then(Value::as_u64).unwrap_or(0);
    let (want_len, want_data): (usize, Option<Vec<u8>>) = match &pattern["data"] {
        Value::String(h) => {
            let d = crate::support::hex(h);
            (d.len(), Some(d))
        }
        Value::Object(o) if o.contains_key("len") => {
            (o["len"].as_u64().unwrap_or(0) as usize, None)
        }
        _ => return Err("STREAM_DATA without data".into()),
    };
    let end = off + want_len as u64;
    let mut at = off;
    let mut got = Vec::new();
    let mut last = None;
    let mut fin = false;
    for (i, f) in frames.iter().enumerate().skip(from) {
        if f["type"] != "STREAM" || f["id"] != json!(id) {
            continue;
        }
        let fo = f["off"].as_u64().unwrap_or(0);
        let data = crate::support::hex(f["data"].as_str().unwrap_or(""));
        let fe = fo + data.len() as u64;
        if last.is_none() {
            if fo != off {
                continue;
            }
        } else if fo != at {
            break;
        }
        if fe > end {
            return Err(format!("STREAM {id} frame at {fo} runs past {end}"));
        }
        got.extend_from_slice(&data);
        at = fe;
        last = Some(i);
        fin = f["fin"] == json!(true);
        if at == end
            && !(want_len == 0
                && data.is_empty()
                && pattern.get("fin") == Some(&json!(true))
                && !fin)
        {
            break;
        }
    }
    let Some(last) = last else {
        return Err(format!("no STREAM frame of stream {id} at offset {off}"));
    };
    if at != end {
        return Err(format!(
            "STREAM {id} data covers {off}..{at}, expected ..{end}"
        ));
    }
    if let Some(d) = want_data
        && d != got
    {
        let first = got
            .iter()
            .zip(&d)
            .position(|(a, b)| a != b)
            .unwrap_or(got.len().min(d.len()));
        return Err(format!(
            "STREAM {id} data differs at byte {first} ({} bytes, expected {})",
            got.len(),
            d.len()
        ));
    }
    if let Some(f) = pattern.get("fin").and_then(Value::as_bool)
        && f != fin
    {
        return Err(format!("STREAM {id} fin {fin}, expected {f}"));
    }
    Ok(last)
}

fn is_stream_data(p: &Value) -> bool {
    p["type"] == "STREAM_DATA"
}

fn match_exact(patterns: &[Value], frames: &[Value]) -> Result<(), String> {
    let frames: Vec<Value> = frames
        .iter()
        .filter(|f| f["type"] != "PADDING")
        .cloned()
        .collect();
    if patterns.iter().any(is_stream_data) {
        return match_contains(patterns, &frames);
    }
    if frames.len() < patterns.len() {
        return Err(format!(
            "{} frames, expected {}",
            frames.len(),
            patterns.len()
        ));
    }
    for (i, p) in patterns.iter().enumerate() {
        if !frame_matches(p, &frames[i]) {
            return Err(format!("frame {i} {} does not match {p}", frames[i]));
        }
    }
    Ok(())
}

fn match_contains(patterns: &[Value], frames: &[Value]) -> Result<(), String> {
    let mut at = 0;
    for p in patterns {
        if is_stream_data(p) {
            at = stream_data_match(p, frames, at)? + 1;
            continue;
        }
        match frames
            .iter()
            .enumerate()
            .skip(at)
            .find(|(_, f)| frame_matches(p, f))
        {
            Some((i, _)) => at = i + 1,
            None => return Err(format!("no frame matches {p} after position {at}")),
        }
    }
    Ok(())
}

fn match_unordered(patterns: &[Value], frames: &[Value]) -> Result<(), String> {
    for p in patterns {
        if is_stream_data(p) {
            stream_data_match(p, frames, 0)?;
            continue;
        }
        let n = frames.iter().filter(|f| frame_matches(p, f)).count();
        match p.get("count") {
            Some(c) if c.is_u64() => {
                if n as u64 != c.as_u64().unwrap_or(0) {
                    return Err(format!("{n} frames match {p}"));
                }
            }
            Some(c) if c.is_object() => {
                if !value_matches(c, Some(&json!(n))) {
                    return Err(format!("{n} frames match {p}"));
                }
            }
            _ => {
                if n == 0 {
                    return Err(format!("no frame matches {p}"));
                }
            }
        }
    }
    Ok(())
}

/// SPEC.md Section 8.3 rule 5: at most one MAX_DATA, one MAX_STREAM_DATA
/// per stream and one MAX_STREAMS per type in a record.
fn check_one_credit(records: &[Vec<Value>]) -> Result<(), String> {
    for r in records {
        let mut seen = std::collections::HashSet::new();
        for f in r {
            let key = match f["type"].as_str() {
                Some("MAX_DATA") => "MAX_DATA".to_string(),
                Some("MAX_STREAM_DATA") => format!("MAX_STREAM_DATA {}", f["id"]),
                Some("MAX_STREAMS") => format!("MAX_STREAMS {}", f["bidi"]),
                _ => continue,
            };
            if !seen.insert(key.clone()) {
                return Err(format!("two {key} in one record: {}", summarise(r)));
            }
        }
    }
    Ok(())
}

// ---- running -------------------------------------------------------------------------

fn run_trace(
    trace: &Trace,
    profiles: &BTreeMap<String, Profile>,
    copy: bool,
) -> Result<(), String> {
    let mut r = Runner::new(trace, profiles, copy)?;
    for step in &trace.steps {
        if let Err(e) = r.step(step) {
            if std::env::var("ZMUX_TRACE_DUMP").is_ok() {
                for (id, p) in &r.pipes {
                    eprintln!("pipe {id} (sent {}): {}", p.out.sent, summarise(&p.out.all));
                    for (l, o) in &p.lanes {
                        eprintln!("  lane {l} (sent {}): {}", o.sent, summarise(&o.all));
                    }
                }
            }
            return Err(format!("step {}: {e}", step.number));
        }
    }
    r.flush()?;
    if let Some(e) = r.session.error()
        && !r.close_covered
    {
        return Err(format!(
            "the session ended ({e:?}) and no expect_close covered it"
        ));
    }
    Ok(())
}

fn profiles() -> BTreeMap<String, Profile> {
    serde_json::from_value(read_json("profiles.json")).expect("profiles")
}

#[test]
fn traces_run_against_the_core() {
    let profiles = profiles();
    let only = std::env::var("ZMUX_TRACE").ok();
    let mut passed: BTreeMap<String, usize> = BTreeMap::new();
    let mut failed = Vec::new();
    let mut skipped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let all = crate::traces::load_all()
        .into_iter()
        .chain(crate::traces::load_local());
    for (_rel, trace) in all {
        let group = trace.header.groups.first().cloned().unwrap_or_default();
        if !RUN_GROUPS.contains(&group.as_str()) {
            skipped
                .entry(group)
                .or_default()
                .push(trace.header.id.clone());
            continue;
        }
        if only
            .as_deref()
            .is_some_and(|o| !trace.header.id.contains(o))
        {
            continue;
        }
        let id = trace.header.id.clone();
        // Both receive paths: in place (the drivers') and copying.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_trace(&trace, &profiles, false)?;
            run_trace(&trace, &profiles, true).map_err(|e| format!("(copying receive) {e}"))
        }))
        .unwrap_or_else(|p| {
            let msg = p
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            Err(format!("panicked: {msg}"))
        });
        match result {
            Ok(()) => *passed.entry(group).or_default() += 1,
            Err(e) if KNOWN_SPEC_ISSUES.iter().any(|(t, _)| *t == id) => {
                let why = KNOWN_SPEC_ISSUES
                    .iter()
                    .find(|(t, _)| *t == id)
                    .map_or("", |k| k.1);
                eprintln!("IGNORED {id}: {e} (known spec issue: {why})");
            }
            Err(e) => failed.push(format!("{id}: {e}")),
        }
    }
    for (g, n) in &passed {
        eprintln!("trace group {g}: {n} passed");
    }
    for (g, ids) in &skipped {
        eprintln!(
            "trace group {g}: {} skipped (not in this version)",
            ids.len()
        );
    }
    if !failed.is_empty() {
        for f in &failed {
            eprintln!("FAILED {f}");
        }
        panic!("{} traces failed", failed.len());
    }
}

/// Traces that fail because of an open issue in the trace itself, reported
/// to the spec author, or because the vendored fixtures predate a decided
/// specification change that the code already implements; they still
/// run, and a pass is reported normally.
const KNOWN_SPEC_ISSUES: &[(&str, &str)] = &[];

#[allow(dead_code)]
fn unused(_: &record::Event<'_>) {}
