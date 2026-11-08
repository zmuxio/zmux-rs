//! The trace runner: executes every trace of the
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
use zmux::proto::seal::{self, join as seal_join};
use zmux::proto::session::{
    ClaimedHello, Config, ConfirmedJoin, CoreEvent, DEFAULT_OVERFLOW_DELAY, DatagramError,
    JoinStep, LaneAccept, LaneId, OpenError, OpenedHello, PeerCarrier, PipeAuth, PipeEnd,
    PipeError, PipeHalf, PipeId, PipeOptions, PipeWrite, Policy, Preamble, Redundancy, RoleConfig,
    SessionCore, SessionError, State, StreamError, StreamKey, Transmit, TransmitBuf,
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
const RUN_GROUPS: &[&str] = &["core", "ext", "compat", "findings", "multipath", "resume"];

/// What the local endpoint wrote on one outbound lane of a pipe (lane 0
/// is the pipe's own carrier).
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
    /// The connection of its lane 0.
    conn: Option<String>,
    /// A local join: JOINING until the Reply, with the Hello it wrote and the scripted
    /// acceptor reading it.
    joining: bool,
    hello: Option<Vec<u8>>,
    /// The key phase of that Hello.
    hello_phase: Option<u8>,
    acceptor: Option<seal_join::Unconfirmed>,
    reply_in: Vec<u8>,
    framing: Option<Framing>,
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
    /// A Hello held until establishment or the join keys.
    waiting: Option<Vec<u8>>,
    /// An Unconfirmed carrier's join; the carrier's bytes until Confirmed.
    join: Option<Box<zmux::proto::session::PeerJoin>>,
    buf: Vec<u8>,
    msgs: Vec<Vec<u8>>,
    /// The scripted peer's handshake.
    joiner: Option<seal_join::HelloSent>,
    proven: Option<seal_join::Proven>,
    confirm: bool,
    reply: Option<Vec<u8>>,
    decision: Option<bool>,
    outcome: Option<&'static str>,
    /// Its handshake timeout.
    deadline: Option<Instant>,
    /// Closed by the local endpoint without writing.
    rejected: bool,
    pairing: Option<[u8; 16]>,
    /// Bytes received while the carrier waits for its pairing.
    held: Vec<Vec<u8>>,
    /// Its connection.
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
    /// The peer's side of the epoch exchanges.
    epochs: EpochPeer,
}

/// The scripted peer's epoch exchanges: every epoch secret it
/// derived, the frames both ends wrote.
#[derive(Default)]
struct EpochPeer {
    secrets: BTreeMap<u64, Vec<u8>>,
    /// The first frame of each phase and epoch the local endpoint wrote, as JSON.
    local_first: BTreeMap<(String, u64), Value>,
    /// The latest such frame: body and share.
    local_last: BTreeMap<(String, u64), (Vec<u8>, Vec<u8>)>,
    /// The peer's offers awaiting the local answer: private values and body.
    offers: BTreeMap<u64, (seal::GroupInitiator, Vec<u8>)>,
    /// The bytes of each frame the peer wrote, by phase and epoch.
    written: BTreeMap<(String, u64), Vec<u8>>,
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

fn state_name(s: zmux::proto::session::DirectionState) -> PipeStateName {
    use zmux::proto::session::{DirectionState as D, InboundState as I, OutboundState as O};
    match s {
        D::Outbound(O::Joining) | D::Inbound(I::Joining) => PipeStateName::Joining,
        D::Outbound(O::Active) => PipeStateName::Active,
        D::Outbound(O::Suspect) => PipeStateName::Suspect,
        D::Outbound(O::Draining) => PipeStateName::Draining,
        D::Outbound(O::Failed) => PipeStateName::Failed,
        D::Outbound(O::Closed) => PipeStateName::Closed,
        D::Inbound(I::Open) => PipeStateName::Open,
        D::Inbound(I::Ended) => PipeStateName::Ended,
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
            probe_jitter,
            pipe_auth,
            early_data,
            declared_end_to_end,
            record_modes
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
            lane_key,
            epoch_locator_prefix
        );

        let mut config = Config::default();
        // Exchanges start only when a trace asks for one.
        config.epoch_policy = zmux::proto::session::EpochPolicy::MANUAL;
        // A trace's 0 (and an absent keep-alive or idle timeout) is off.
        let period = |ms: u64| (ms != 0).then(|| Duration::from_millis(ms));
        if let Some(ms) = cfg.handshake_timeout {
            config.handshake_timeout = Some(Duration::from_millis(ms));
        }
        config.keep_alive_period = period(cfg.keep_alive_period.unwrap_or(0));
        config.max_idle_timeout = period(tp.max_idle_timeout.unwrap_or(0));
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
        // The test-mode sender : the ETA choice,
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
        if cfg.declared_end_to_end.unwrap_or(true) {
            config.pipe_auth = config.pipe_auth.clone().with_end_to_end();
        }
        if let Some(c) = &tp.zmux_session_crypto {
            config.session_crypto = c.clone();
        }
        let modes = cfg.record_modes.clone().unwrap_or_default();
        config.allow_record_mode = Some(zmux::proto::session::AllowRecordMode(
            std::sync::Arc::new(move |_, m, _| {
                let name = match m {
                    seal::Mode::Sealed => "sealed",
                    seal::Mode::Bound => "bound",
                    seal::Mode::Trusted => "trusted",
                };
                modes.iter().any(|x| x == name)
            }),
        ));
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
            config.standby_probe = period(p);
        }
        if let Some(j) = cfg.probe_jitter {
            config.probe_jitter = j;
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
        th.epoch_locator_prefix = hooks.epoch_locator_prefix.map(|p| p.0);
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
            epochs: EpochPeer::default(),
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
                    if let Some(p) = self.pipes.get_mut(&pipe.get()) {
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
                    // credit never running out.
                    let now = self.now();
                    let framing = self
                        .pipes
                        .get(&lane.pipe.get())
                        .and_then(|p| p.out_framing)
                        .unwrap_or(Framing::ByteStream);
                    self.pipe_mut(lane.pipe.get()).lane_mut(lane.lane.get());
                    self.session.lane_opened(*lane, framing, now);
                }
                CoreEvent::ResetLane(lane) => {
                    self.pipe_mut(lane.pipe.get())
                        .lane_mut(lane.lane.get())
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

    /// Writes everything the core has for every writable pipe,
    /// pipe by pipe in ID order until nothing more comes out.
    fn flush(&mut self) -> Result<(), String> {
        self.write_hellos();
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
                let at = PipeId::new(id).lane(lane);
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

    /// Stream data appears on a JOINING
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
        let Some(me) = infos.iter().find(|i| i.pipe.get() == id) else {
            return Ok(());
        };
        if stream_bytes == 0 {
            return Ok(());
        }
        let others = || {
            infos.iter().filter(move |i| {
                i.pipe.get() != id
                    && i.outbound == Some(zmux::proto::session::OutboundState::Active)
            })
        };
        if me.outbound == Some(zmux::proto::session::OutboundState::Joining)
            && let Some(o) = others().next()
        {
            return Err(format!(
                "oracle (S1): stream data on JOINING pipe {id} while pipe {} is usable",
                o.pipe.get()
            ));
        }
        if me.in_probation
            && let Some(o) = others().find(|i| !i.in_probation)
        {
            return Err(format!(
                "oracle (11.9): stream data on pipe {id} in probation while pipe {} is out of probation",
                o.pipe.get()
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
        let mut frames = wire::decode_body(body, Gates::ALL)
            .map_err(|e| format!("the local endpoint wrote an undecodable record: {e:?}"))?;
        for f in &mut frames {
            if f["type"] == "SESSION_EPOCH" {
                self.local_epoch_frame(f)?;
            }
        }
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
    /// connection ; anything else is rejected.
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
                let at = PipeId::new(pipe).lane(lane);
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
            self.session.receive(PipeId::new(id), data, now);
        } else {
            let p = self.pipe_mut(id);
            p.inbuf.extend_from_slice(data);
            let buf = std::mem::take(&mut p.inbuf);
            let used = self.session.receive_in_place(PipeId::new(id), &buf, now);
            let p = self.pipe_mut(id);
            p.inbuf = buf;
            p.inbuf.drain(..used.min(p.inbuf.len()));
        }
        self.drain_events();
    }

    fn message(&mut self, id: u64, m: &[u8]) {
        let now = self.now();
        self.session.receive_message(PipeId::new(id), m, now);
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
                    c.outcome = Some("reject");
                    c.waiting = None;
                    c.join = None;
                    c.id = None;
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
            // A stream of a multi-stream connection offers lanes.
            self.session.set_pipe_lanes(PipeId::new(pipe), true);
        }
    }

    /// Hellos held until establishment or the join keys are offered again.
    fn retry_waiting(&mut self) {
        let names: Vec<String> = self
            .carriers
            .iter()
            .filter(|(_, c)| c.waiting.is_some() && !c.rejected)
            .map(|(n, _)| n.clone())
            .collect();
        for n in names {
            if let Some(hello) = self.carriers.get(&n).and_then(|c| c.waiting.clone()) {
                self.offer_hello(&n, &hello);
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
        if c.join.is_some() || c.waiting.is_some() {
            c.buf.extend_from_slice(bytes);
            c.msgs.extend_from_slice(messages);
            return;
        }
        let Some(id) = c.id else {
            return;
        };
        let results: Vec<Classified> = if c.framing == Framing::Records {
            let mut out = Vec::new();
            for m in messages {
                out.push(self.listener.message(id, m, now));
            }
            out
        } else {
            vec![self.listener.data(id, bytes, now)]
        };
        for result in results {
            match result {
                Classified::NeedMore => {}
                // A listener carrier is never a lane (that is a stream of a
                // connection carrying a pipe, `lane_bytes`).
                Classified::Reject | Classified::NewSession { .. } | Classified::Lane { .. } => {
                    if let Some(c) = self.carriers.get_mut(name) {
                        c.rejected = true;
                        c.outcome = Some("reject");
                        c.id = None;
                    }
                }
                // Closed: a stall of the reject policy writes nothing either.
                Classified::BadHello { .. } => self.close_carrier(name, "reject"),
                Classified::Join { hello, .. } => self.offer_hello(name, &hello),
            }
        }
    }

    fn close_carrier(&mut self, name: &str, outcome: &'static str) {
        if let Some(c) = self.carriers.get_mut(name) {
            c.rejected = true;
            c.outcome = Some(outcome);
            c.buf.clear();
            c.msgs.clear();
            c.waiting = None;
            c.join = None;
            if let Some(id) = c.id.take() {
                self.listener.done(id);
            }
        }
    }

    fn peer_carrier(&self, name: &str) -> PeerCarrier {
        let c = &self.carriers[name];
        PeerCarrier {
            inbound: c.can_read.then_some(c.framing),
            outbound: c.can_write.then_some(c.framing),
            looped: false,
            overhead: 0,
            received: 0,
        }
    }

    /// The listener's handshake from a Hello on, up to its confirmation. A
    /// held join stays pending and is offered again.
    fn offer_hello(&mut self, name: &str, hello: &[u8]) {
        let now = self.now();
        let timeout = self.session.config().handshake_wait();
        let Some(c) = self.carriers.get_mut(name) else {
            return;
        };
        c.deadline
            .get_or_insert_with(|| now.checked_add(timeout).unwrap_or(now));
        let framing = c.framing;
        let binding = c.binding.clone();
        let Ok(parsed) = seal_join::JoinHello::parse(framing, hello) else {
            return self.close_carrier(name, "reject");
        };
        if !self.session.accepts_locator(parsed.locator()) {
            return self.close_carrier(name, "reject");
        }
        let opened = self.session.open_hello(&parsed, &binding, now);
        self.drain_events();
        let mut join = match opened {
            OpenedHello::Hold | OpenedHello::KeyWait => {
                self.carriers.get_mut(name).expect("carrier").waiting = Some(hello.to_vec());
                return;
            }
            OpenedHello::Verified(j) => j,
            OpenedHello::Fatal => return self.close_carrier(name, "fatal"),
            OpenedHello::AuthFailed
            | OpenedHello::UnknownSuite
            | OpenedHello::UnknownLocator
            | OpenedHello::Close => {
                return self.close_carrier(name, "reject");
            }
        };
        self.carriers.get_mut(name).expect("carrier").waiting = None;
        let allowed = self
            .session
            .config()
            .allow_record_mode
            .clone()
            .is_none_or(|f| {
                (f.0)(
                    &zmux::proto::session::CarrierDescription::default(),
                    join.mode(),
                    None,
                )
            });
        if !allowed {
            return self.close_carrier(name, "reject"); // the Pipe ID's bit stays clear
        }
        let carrier = self.peer_carrier(name);
        let claimed = self
            .session
            .claim_hello(&mut join, carrier, &Default::default(), now);
        self.drain_events();
        match claimed {
            ClaimedHello::Accept(reply) => {
                let c = self.carriers.get_mut(name).expect("carrier");
                c.reply = Some(reply);
                c.join = Some(join);
                c.outcome = Some("accept");
                self.peer_reads_reply(name);
                let c = self.carriers.get_mut(name).expect("carrier");
                if c.proven.is_some() && c.confirm {
                    self.write_confirm(name);
                }
            }
            ClaimedHello::Refuse(reply) => {
                self.carriers.get_mut(name).expect("carrier").reply = Some(reply);
                self.peer_reads_reply(name);
                self.close_carrier(name, "refuse");
            }
            ClaimedHello::Close => self.close_carrier(name, "reject"),
        }
    }

    /// The scripted peer verifies the Reply.
    fn peer_reads_reply(&mut self, name: &str) {
        let c = self.carriers.get_mut(name).expect("carrier");
        let (Some(sent), Some(reply)) = (c.joiner.take(), c.reply.as_ref()) else {
            return;
        };
        let Ok((proven, _)) = sent.read_reply(reply) else {
            panic!("carrier {name}: the peer cannot read the Reply");
        };
        c.decision = proven.payload().join_accepted();
        c.proven = Some(proven);
    }

    /// The scripted peer writes its confirmation; the carrier is Confirmed by it.
    fn write_confirm(&mut self, name: &str) {
        let c = self.carriers.get_mut(name).expect("carrier");
        let Some(proven) = c.proven.take() else {
            return;
        };
        let (confirm, _) = proven.write_confirm(0).expect("confirmation");
        self.read_confirm(name, &confirm);
    }

    fn read_confirm(&mut self, name: &str, confirm: &[u8]) {
        let now = self.now();
        let carrier = self.peer_carrier(name);
        let c = self.carriers.get_mut(name).expect("carrier");
        let Some(mut join) = c.join.take() else {
            return;
        };
        let framing = c.framing;
        match join.read_confirm(confirm) {
            Ok(Some(_)) => {}
            Ok(None) => {
                c.join = Some(join);
                return;
            }
            Err(_) => return self.close_carrier(name, "reject"),
        }
        let pipe = join.pipe().id;
        let direction = join.pipe().direction;
        let confirmed = self.session.confirm_join(*join, carrier, now);
        self.drain_events();
        match confirmed {
            ConfirmedJoin::Attached { .. } => {
                let c = self.carriers.get_mut(name).expect("carrier");
                c.pipe = Some(pipe);
                c.deadline = None;
                let (read, write) = (c.can_read && direction != 1, c.can_write && direction != 0);
                if let Some(id) = c.id.take() {
                    self.listener.done(id);
                }
                self.attach(pipe, Some(name), read, write, framing);
                let c = self.carriers.get_mut(name).expect("carrier");
                let (buf, msgs) = (std::mem::take(&mut c.buf), std::mem::take(&mut c.msgs));
                if !buf.is_empty() {
                    self.deliver(pipe, &buf, None);
                }
                for m in msgs {
                    self.message(pipe, &m);
                }
            }
            ConfirmedJoin::Refused | ConfirmedJoin::Close => {
                let outcome = self.carriers[name].outcome.unwrap_or("reject");
                self.close_carrier(name, outcome);
            }
        }
    }

    /// `join_psk` of a role from the session secret of the local parameters and the
    /// peer's, as both ends compute it. The wire examples give the nonces of a
    /// Hello written before the peer's parameters reached the session.
    /// `join_psk` of the latest epoch of key phase `phase` the runner derived.
    fn join_psk_of(&self, initiator_role: bool, phase: u8) -> Vec<u8> {
        let (secret0, encoded) = self.session_basics();
        let secret = self
            .epochs
            .secrets
            .iter()
            .rev()
            .find(|(e, _)| *e & 1 == u64::from(phase))
            .map(|(_, s)| s.clone())
            .unwrap_or(secret0);
        let suite = seal_join::Suite::from_value(1).expect("Suite 1");
        let role = if initiator_role {
            seal::JoinRole::Initiator
        } else {
            seal::JoinRole::Responder
        };
        seal::derive_join_psk(suite, &secret, role, &encoded).expect("psk")
    }

    /// The secret of an epoch the runner derived; epoch 0 is the session secret.
    fn epoch_secret(&self, e: u64) -> Option<Vec<u8>> {
        if e == 0 {
            return Some(self.session_basics().0);
        }
        self.epochs.secrets.get(&e).cloned()
    }

    /// A local SESSION_EPOCH: marks whether it repeats the first of its phase and epoch,
    /// and derives the epoch an answer completes.
    fn local_epoch_frame(&mut self, f: &mut Value) -> Result<(), String> {
        let phase = f["phase"].as_str().unwrap_or("").to_string();
        let epoch = f["epoch"].as_u64().unwrap_or(0);
        let key = (phase.clone(), epoch);
        let same = self
            .epochs
            .local_first
            .get(&key)
            .is_some_and(|first| first == f);
        self.epochs
            .local_first
            .entry(key.clone())
            .or_insert_with(|| f.clone());
        let hx = |k: &str| crate::support::hex(f[k].as_str().unwrap_or(""));
        let (share, locator) = (hx("share"), hx("locator"));
        let body = zmux::proto::frame::SessionEpoch {
            phase: wire::epoch_phase(&phase),
            epoch,
            share: &share,
            locator: &locator,
            raw: &[],
        }
        .body();
        f["same_as_previous"] = json!(same);
        self.epochs
            .local_last
            .insert(key, (body.clone(), share.clone()));
        if phase == "answer"
            && let Some((kex, offer_body)) = self.epochs.offers.remove(&epoch)
        {
            let ss = kex
                .finish(&share)
                .map_err(|e| format!("answer share: {e}"))?;
            self.derive_epoch(epoch, &offer_body, &body, ss.as_slice())?;
        }
        Ok(())
    }

    fn derive_epoch(
        &mut self,
        epoch: u64,
        offer: &[u8],
        answer: &[u8],
        ss: &[seal::Secret],
    ) -> Result<(), String> {
        let prev = self
            .epoch_secret(epoch - 1)
            .ok_or(format!("epoch {}: no secret", epoch - 1))?;
        let (_, sc) = self.session_basics();
        let (_, secret) = seal::derive_epoch_secret(&prev, epoch, &sc, offer, answer, ss)
            .map_err(|e| e.to_string())?;
        self.epochs.secrets.insert(epoch, secret.to_vec());
        Ok(())
    }

    /// The session secret of the local parameters and the peer's, and `session_crypto`.
    fn session_basics(&self) -> (Vec<u8>, Vec<u8>) {
        const INIT_NONCE: [u8; 16] =
            *b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
        const RESP_NONCE: [u8; 16] =
            *b"\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00";
        let local = self.session.local_parameters();
        let own = local.zmux_multipath.expect("multipath").session_nonce;
        let own_set = local.zmux_session_crypto.clone().expect("multipath");
        let local_init = self.session.role() == Role::Initiator;
        let (their, their_set) = match (
            self.session.session_nonces(),
            self.session.peer_session_crypto(),
        ) {
            (Some((_, n)), Some(set)) => (n, set.clone()),
            _ => (
                if local_init { RESP_NONCE } else { INIT_NONCE },
                seal::SessionCrypto {
                    suites: vec![1],
                    groups: vec![2],
                },
            ),
        };
        let (i_nonce, r_nonce, i_set, r_set) = if local_init {
            (own, their, own_set, their_set)
        } else {
            (their, own, their_set, own_set)
        };
        let encoded = seal::session_crypto(&i_set, &r_set).expect("sets");
        let key = self.session.config().pipe_auth.psk_bytes();
        let secret = zmux::proto::keys::session_secret(&i_nonce, &r_nonce, &[], key);
        (secret.to_vec(), encoded)
    }

    fn peer_is_initiator(&self) -> bool {
        self.session.role() != Role::Initiator
    }

    fn check_outcome(&self, name: &str, want: &str) -> Result<(), String> {
        let c = &self.carriers[name];
        let got = c.outcome.unwrap_or("none");
        if got != want {
            return Err(format!("carrier {name}: outcome {got:?}, want {want:?}"));
        }
        match want {
            "accept" | "refuse" => {
                if c.decision == Some(want == "refuse") {
                    return Err(format!("carrier {name}: decision, want {want}"));
                }
            }
            _ => {
                if c.reply.is_some() {
                    return Err(format!("carrier {name}: wrote a Reply, want {want}"));
                }
            }
        }
        Ok(())
    }

    /// Every local join writes its Hello once allowed.
    fn write_hellos(&mut self) {
        let now = self.now();
        let ids: Vec<u64> = self
            .pipes
            .iter()
            .filter(|(_, p)| p.joining && p.hello.is_none())
            .map(|(&i, _)| i)
            .collect();
        for id in ids {
            let framing = self.pipes[&id].framing.unwrap_or(Framing::ByteStream);
            let pipe = PipeId::new(id);
            let r = self.session.join_prepare(pipe, now).map(|ready| {
                ready.map(|_| {
                    self.session
                        .join_hello(pipe, (framing, 0), &Default::default(), now)
                })
            });
            self.drain_events();
            match r {
                Ok(Some(Ok(hello))) => self.pipes.get_mut(&id).expect("pipe").hello = Some(hello),
                Ok(None) => {}
                Ok(Some(Err(_))) | Err(_) => self.pipes.get_mut(&id).expect("pipe").joining = false,
            }
        }
    }

    /// The scripted peer reads the Hello of a local join.
    fn read_hello(&mut self, id: u64) -> Result<(u8, Vec<u8>, seal::Payload), String> {
        self.write_hellos();
        let local_init = !self.peer_is_initiator();
        let p = self.pipes.get(&id).ok_or(format!("no pipe {id}"))?;
        let hello = p
            .hello
            .clone()
            .ok_or(format!("pipe {id}: no Hello written"))?;
        let framing = p.framing.unwrap_or(Framing::ByteStream);
        let phase = seal_join::JoinHello::parse(framing, &hello)
            .map_err(|e| format!("pipe {id}: Hello: {e}"))?
            .phase();
        let psk = self.join_psk_of(local_init, phase);
        let p = self.pipes.get_mut(&id).ok_or(format!("no pipe {id}"))?;
        let parsed = seal_join::JoinHello::parse(framing, &hello)
            .map_err(|e| format!("pipe {id}: Hello: {e}"))?;
        let (acc, payload) = seal_join::Acceptor::open(
            &parsed,
            seal_join::AcceptorKeys {
                psk: &psk,
                binding: &[],
                groups: &[1, 2],
            },
        )
        .map_err(|e| format!("pipe {id}: Hello does not verify: {e}"))?;
        let mode = parsed.mode().byte();
        let locator = parsed.locator().to_vec();
        p.hello_phase = Some(parsed.phase());
        p.acceptor = Some(acc);
        Ok((mode, locator, payload))
    }

    /// Feeds bytes to a JOINING carrier.
    fn joiner_feed(&mut self, id: u64, data: &[u8]) -> Result<(), String> {
        let now = self.now();
        let p = self.pipes.get_mut(&id).ok_or(format!("no pipe {id}"))?;
        p.reply_in.extend_from_slice(data);
        while self.pipes[&id].joining {
            let input = self.pipes[&id].reply_in.clone();
            let step = self.session.verify_reply(PipeId::new(id), &input, now);
            self.drain_events();
            let p = self.pipes.get_mut(&id).expect("pipe");
            match step {
                JoinStep::More { consumed, .. } => {
                    p.reply_in.drain(..consumed);
                    if consumed == 0 {
                        return Ok(());
                    }
                }
                JoinStep::Verified { consumed, .. } => {
                    let pipe = PipeId::new(id);
                    let done = self.session.join_finish(pipe, &Default::default(), now);
                    self.drain_events();
                    assert!(done.is_ok(), "pipe {id}: join_finish");
                    let p = self.pipes.get_mut(&id).expect("pipe");
                    p.joining = false;
                    p.reply_in.drain(..consumed);
                    let rest = std::mem::take(&mut p.reply_in);
                    if !rest.is_empty() {
                        self.deliver(id, &rest, None);
                    }
                }
                JoinStep::Declined | JoinStep::Failed => {
                    p.joining = false;
                    p.reply_in.clear();
                }
            }
        }
        Ok(())
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
                            join: None,
                            buf: Vec::new(),
                            msgs: Vec::new(),
                            joiner: None,
                            proven: None,
                            confirm: true,
                            reply: None,
                            decision: None,
                            outcome: None,
                            deadline: None,
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
                    join: None,
                    buf: Vec::new(),
                    msgs: Vec::new(),
                    joiner: None,
                    proven: None,
                    confirm: true,
                    reply: None,
                    decision: None,
                    outcome: None,
                    deadline: None,
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
                    // are paired form pipe 0.
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
                self.carriers.insert(name, c);
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
                    (Some(p), _) => PipeId::new(*p).lane(lane.unwrap_or(0)),
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
                    self.pipe_mut(at.pipe.get())
                        .lane_mut(at.lane.get())
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
                        PipeId::new(*pipe).lane(lane),
                        PipeWrite::returned(now, now, 0, 0, !*writable),
                        now,
                    );
                }
                Ok(())
            }
            Op::PeerJoin {
                carrier,
                pipe,
                direction,
                fate_group,
                priority,
                standby,
                locator,
                mode,
                outcome,
                batch,
                bad_key,
                binding,
                hold,
                confirm,
                group,
                key_share,
                phase,
            } => {
                let mut psk = self.join_psk_of(self.peer_is_initiator(), *phase);
                if *bad_key {
                    psk[0] ^= 0xff;
                }
                let c = self.carriers.get(carrier).ok_or("unknown carrier")?;
                let framing = c.framing;
                let mode = match mode.as_deref() {
                    Some("sealed") => seal::Mode::Sealed,
                    Some("bound") => seal::Mode::Bound,
                    _ => seal::Mode::Trusted,
                };
                let suite = seal_join::Suite::from_value(1).expect("Suite 1");
                let empty = Vec::new();
                let binding = binding.as_ref().map_or(&empty, |b| &b.0);
                let group = seal::Group::from_value(group.unwrap_or(2)).ok_or("unknown group")?;
                let joiner = seal_join::Joiner::new(seal_join::JoinConfig {
                    suite,
                    group,
                    mode,
                    phase: *phase,
                    framing,
                    locator: &locator.0,
                    psk: &psk,
                    binding,
                })
                .map_err(|e| e.to_string())?;
                let item = seal::JoinPipe {
                    id: *pipe,
                    direction: match direction.as_str() {
                        "up" => 0,
                        "down" => 1,
                        _ => 2,
                    },
                    fate_group: *fate_group,
                    priority: *priority,
                    standby: *standby,
                }
                .encode();
                let frames: Vec<u8> = batch
                    .as_ref()
                    .map(|f| wire::encode_frames(f, &|_, _| 0))
                    .unwrap_or_default();
                let mut items: Vec<(u64, &[u8])> = vec![(5, &item)];
                if !frames.is_empty() {
                    items.push((6, &frames));
                }
                let payload = seal::encode_payload(&items);
                let share = key_share_override(group, key_share.as_deref())?;
                let (hello, sent) = joiner
                    .write_hello_with_unknown(&payload, share)
                    .map_err(|e| e.to_string())?;
                let c = self.carriers.get_mut(carrier).expect("carrier");
                c.joiner = Some(sent);
                c.confirm = confirm.unwrap_or(true);
                if c.rejected {
                    return self.check_outcome(carrier, outcome);
                }
                if framing == Framing::Records {
                    self.carrier_bytes(carrier, &[], std::slice::from_ref(&hello));
                } else {
                    self.carrier_bytes(carrier, &hello, &[]);
                }
                if *hold {
                    return if self.carriers[carrier].waiting.is_some() {
                        Ok(())
                    } else {
                        Err(format!("carrier {carrier}: the join was not held"))
                    };
                }
                self.check_outcome(carrier, outcome)
            }
            Op::PeerJoinFinish { carrier, outcome } => {
                self.retry_waiting();
                if self
                    .carriers
                    .get(carrier)
                    .is_some_and(|c| c.waiting.is_some())
                {
                    return Err(format!("carrier {carrier}: the join is still held"));
                }
                self.check_outcome(carrier, outcome)
            }
            Op::PeerConfirm { carrier } => {
                if self.carriers.get(carrier).is_none_or(|c| c.join.is_none()) {
                    return Err(format!("carrier {carrier} is not Unconfirmed"));
                }
                self.write_confirm(carrier);
                Ok(())
            }
            Op::ExpectJoinHello {
                pipe,
                direction,
                fate_group,
                priority,
                standby,
                locator,
                mode,
                batch: _,
                group,
                phase,
            } => {
                self.flush()?;
                let (got_mode, got_locator, payload) = self.read_hello(*pipe)?;
                if let Some(g) = group
                    && payload.key_share().map(|k| k.0) != Some(*g)
                {
                    return Err(format!(
                        "Hello key share {:?}, want Group {g}",
                        payload.key_share().map(|k| k.0)
                    ));
                }
                if let Some(ph) = phase
                    && self.pipes[pipe].hello_phase != Some(*ph)
                {
                    return Err(format!(
                        "Hello key phase {:?}, want {ph}",
                        self.pipes[pipe].hello_phase
                    ));
                }
                let (frames, _, _) = self.take_frames(&crate::model::PipeSelector::Id(*pipe), None);
                if !frames.is_empty() {
                    return Err(format!("frames besides the Hello: {}", summarise(&frames)));
                }
                let item = payload.join_pipe().ok_or("no join pipe")?;
                let dir = ["up", "down", "bidi"][usize::from(item.direction)];
                if item.id != *pipe
                    || dir != direction
                    || item.fate_group != *fate_group
                    || item.priority != *priority
                    || item.standby != *standby
                {
                    return Err(format!("Hello fields {item:?}"));
                }
                if got_locator != locator.0 {
                    return Err(format!("Hello locator {}", to_hex(&got_locator)));
                }
                let want = match mode.as_str() {
                    "sealed" => 0,
                    "bound" => 1,
                    _ => 2,
                };
                if got_mode != want {
                    return Err(format!("Hello mode {got_mode}"));
                }
                if let Some(patterns) = step.raw["batch"].as_array() {
                    let gates = Gates::ALL;
                    let mut frames: Vec<Value> = Vec::new();
                    let mut b = payload.frames().unwrap_or_default();
                    while !b.is_empty() {
                        let (f, n) = zmux::proto::frame::Frame::decode(b, &gates)
                            .map_err(|e| format!("first batch: {e}"))?;
                        frames.push(wire::frame_json(&f));
                        b = &b[n..];
                    }
                    match_exact(patterns, &frames).map_err(|e| {
                        format!("first batch: {e}\n    frames: {}", summarise(&frames))
                    })?;
                }
                Ok(())
            }
            Op::PeerJoinReply {
                pipe,
                decision,
                leading_parameters,
            } => {
                self.flush()?;
                if self.pipes.get(pipe).is_none_or(|p| p.acceptor.is_none()) {
                    self.read_hello(*pipe)?;
                }
                let p = self.pipes.get_mut(pipe).ok_or("no pipe")?;
                let acc = p.acceptor.take().ok_or("no Hello read")?;
                let framing = p.framing.unwrap_or(Framing::ByteStream);
                let payload = seal::encode_payload(&[(7, &[*decision])]);
                let (mut reply, _) = acc.write_reply(&payload).map_err(|e| e.to_string())?;
                if *leading_parameters {
                    let mut block = vec![0u8; 512];
                    let tp = self.session.local_parameters();
                    let n = tp
                        .encode_frame(None, &mut block)
                        .map_err(|e| e.to_string())?;
                    block.truncate(n);
                    if framing == Framing::Records {
                        self.joiner_feed(*pipe, &block)?;
                    } else {
                        let mut rec = vec![0u8; 8];
                        let w = varint::encode(n as u64, &mut rec).map_err(|e| e.to_string())?;
                        rec.truncate(w);
                        rec.extend_from_slice(&block);
                        rec.append(&mut reply);
                        reply = rec;
                    }
                }
                self.joiner_feed(*pipe, &reply)
            }
            Op::PeerSend {
                pipe: Some(p),
                records,
                hex,
                ..
            } if self.pipes.get(p).is_some_and(|x| x.joining) => {
                let data = match (hex, records) {
                    (Some(h), _) => h.0.clone(),
                    (None, Some(r)) => r
                        .iter()
                        .flat_map(|f| wire::encode_record(f, &|_, _| 0))
                        .collect(),
                    _ => return Err("peer_send without bytes".into()),
                };
                self.joiner_feed(*p, &data)
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
            Op::PeerEpoch {
                pipe,
                phase,
                epoch,
                locator,
                share_len,
                repeat,
            } => {
                let key = (phase.clone(), *epoch);
                let frame = if *repeat {
                    self.epochs
                        .written
                        .get(&key)
                        .cloned()
                        .ok_or("peer_epoch repeat without an earlier frame")?
                } else {
                    let group = seal::Group::from_value(2).expect("Group 2");
                    let mut derive = None;
                    let share = match (phase.as_str(), share_len) {
                        (_, Some(n)) => vec![0x5a; *n],
                        ("offer", None) => {
                            let (share, kex) = group.initiate().map_err(|e| e.to_string())?;
                            derive = Some(kex);
                            share
                        }
                        ("answer", None) => {
                            match self.epochs.local_last.get(&("offer".into(), *epoch)) {
                                Some((_, offer_share)) => {
                                    let (share, ss) =
                                        group.respond(offer_share).map_err(|e| e.to_string())?;
                                    let offer_body =
                                        self.epochs.local_last[&("offer".into(), *epoch)].0.clone();
                                    let body = zmux::proto::frame::SessionEpoch {
                                        phase: zmux::proto::frame::EpochPhase::Answer,
                                        epoch: *epoch,
                                        share: &share,
                                        locator: &locator.0,
                                        raw: &[],
                                    }
                                    .body();
                                    self.derive_epoch(*epoch, &offer_body, &body, ss.as_slice())?;
                                    share
                                }
                                None => vec![0x5a; group.responder_share_len()],
                            }
                        }
                        (p, _) => return Err(format!("peer_epoch phase {p}")),
                    };
                    let f = zmux::proto::frame::SessionEpoch {
                        phase: wire::epoch_phase(phase),
                        epoch: *epoch,
                        share: &share,
                        locator: &locator.0,
                        raw: &[],
                    };
                    if let Some(kex) = derive {
                        self.epochs.offers.insert(*epoch, (kex, f.body()));
                    }
                    let mut buf = vec![0; zmux::proto::frame::Frame::SessionEpoch(f).encoded_len()];
                    zmux::proto::frame::Frame::SessionEpoch(f)
                        .encode(&mut buf)
                        .map_err(|e| e.to_string())?;
                    self.epochs.written.insert(key, buf.clone());
                    buf
                };
                let framing = self
                    .pipes
                    .get(pipe)
                    .and_then(|x| x.in_framing)
                    .unwrap_or(Framing::ByteStream);
                if framing == Framing::Records {
                    self.message(*pipe, &frame);
                } else {
                    let mut rec = vec![0u8; 8];
                    let w =
                        varint::encode(frame.len() as u64, &mut rec).map_err(|e| e.to_string())?;
                    rec.truncate(w);
                    rec.extend_from_slice(&frame);
                    self.deliver(*pipe, &rec, None);
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
                    let id = PipeId::new(*pipe);
                    let have = match self.session.pipe_state(id, half) {
                        Some(s) => state_name(s),
                        None if self.session.pipe_retired(id) => PipeStateName::Retired,
                        None => return Err(format!("pipe {pipe} {dir:?} has no state")),
                    };
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
                match s.add_pipe(
                    read.then_some(framing),
                    write.then_some(framing),
                    &opts,
                    seal::Mode::Trusted,
                    None,
                    now,
                ) {
                    Ok(id) => {
                        if id.get() != a.pipe {
                            return Err(format!(
                                "add_pipe gave pipe {}, expected {}",
                                id.get(),
                                a.pipe
                            ));
                        }
                        let waiting = s.join_deferred(id);
                        self.attach(id.get(), None, read, write, framing);
                        let p = self.pipe_mut(id.get());
                        p.joining = true;
                        p.framing = Some(framing);
                        if waiting {
                            json!({"pending": true})
                        } else {
                            ok
                        }
                    }
                    Err(e) => pipe_error(&e),
                }
            }
            Call::RemovePipe(a) => match s.remove_pipe(PipeId::new(a.pipe), a.graceful, now) {
                Ok(()) => ok,
                Err(e) => pipe_error(&e),
            },
            Call::SetPipeStatus(a) => {
                let p = PipeId::new(a.pipe);
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
                match self.session.set_redundant(key, Some(a.redundant)) {
                    Ok(()) => ok,
                    Err(e) => stream_error(&e),
                }
            }
            Call::AdvanceEpoch(_) => {
                let now = self.now();
                match self.session.advance_epoch(now) {
                    Ok(()) => ok,
                    Err(e) => pipe_error(&e),
                }
            }
            Call::RevalidatePipes(a) => {
                let now = self.now();
                match self.session.revalidate_pipes(a.pipe.map(PipeId::new), now) {
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
        OpenError::PreambleTooLarge => json!({"error": {"kind": "too_large"}}),
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
        // Locally, CONNECTION_CLOSE(ZMUX_RESUME_TIMEOUT) (the resume deadline passed).
        SessionError::ResumeTimeout { .. } => (
            ErrorSpace::Transport,
            json!(zmux::proto::TransportErrorCode::ZMUX_RESUME_TIMEOUT.0),
            false,
        ),
        // CONNECTION_CLOSE(ZMUX_RESUME_FAILED), sent or received.
        SessionError::ResumeFailed { remote, .. } => (
            ErrorSpace::Transport,
            json!(zmux::proto::TransportErrorCode::ZMUX_RESUME_FAILED.0),
            *remote,
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
        CoreEvent::JoinAuthFailed { .. } => EventName::JoinAuthFailed,
        CoreEvent::Suspended => EventName::Suspended,
        CoreEvent::Resumed => EventName::Resumed,
        CoreEvent::PipeState { .. } | CoreEvent::PipeRetired { .. } => EventName::PipeState,
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
        CoreEvent::JoinAuthFailed { reason } => {
            let want = fields.reason.map_or("auth", |r| r.name());
            if *reason == want {
                Ok(())
            } else {
                Err(format!("join_auth_failed reason {reason}, want {want}"))
            }
        }
        CoreEvent::Suspended | CoreEvent::Resumed => Ok(()),
        CoreEvent::PipeRetired { pipe } => {
            if fields.pipe.is_some_and(|p| p != pipe.get()) {
                return Err(format!("pipe_state pipe {}", pipe.get()));
            }
            if let Some(p) = &fields.state
                && !state_matches(p, PipeStateName::Retired)
            {
                return Err("pipe_state retired".into());
            }
            Ok(())
        }
        CoreEvent::PipeState { pipe, state } => {
            let half = &state.half();
            if fields.pipe.is_some_and(|p| p != pipe.get()) {
                return Err(format!("pipe_state pipe {}", pipe.get()));
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

/// Credit coalescing: at most one MAX_DATA, one MAX_STREAM_DATA
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
    let all = crate::traces::load_all();
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

/// The key share a `peer_join` writes instead of its own: none, one byte short, or an
/// X25519 share of a small-order point.
fn key_share_override(
    group: &'static seal::Group,
    how: Option<&str>,
) -> Result<Option<seal_join::ShareOverride>, String> {
    let fresh = || -> Result<Vec<u8>, String> {
        let (share, _) = group.initiate().map_err(|e| e.to_string())?;
        let mut v = Vec::new();
        seal::put_varint(&mut v, group.value());
        v.extend_from_slice(&share);
        Ok(v)
    };
    Ok(match how {
        None => None,
        Some("missing") => Some(seal_join::ShareOverride::Missing),
        Some("bad_length") => {
            let mut v = fresh()?;
            v.pop();
            Some(seal_join::ShareOverride::Value(v))
        }
        Some("low_order") => {
            let mut v = fresh()?;
            v[1..33].fill(0);
            Some(seal_join::ShareOverride::Value(v))
        }
        Some(other) => return Err(format!("key_share {other}")),
    })
}
