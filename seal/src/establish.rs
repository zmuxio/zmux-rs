//! The client's Establish.

use std::sync::{Arc, OnceLock};
use std::{fmt, io};

use zmux::proto::seal::{Framing, RecordMode, cut_unit};
use zmux::shaping::{
    HandshakeShaper, HandshakeView, Limits, PlanAnswer, UnitPlan, ask_handshake,
    establish_hello_len, item_size, message_len, pad_item,
};
use zmux::{CarrierKind, PipeIo};
use zmux_seal_proto::{Error, Initiator, InitiatorConfig, Profile};

use crate::carrier::Carrier;
use crate::profiles::{client_default, has_psk};
use crate::trust::{
    AppData, AppDataRequest, AppDataSource, ConfigError, Credential, Signer, Verifier, VerifyError,
    VerifyInput, VerifyVerdict, ask_app_data, check_pq_auth, judge,
};
use crate::{MAX_UNIT, credential_value, handshake_payload, message_items, proof_placeholder};

/// Asks the hook about a message and waits as it says.
/// Each handshake family has its own name: a plan made for the lengths of one is never
/// applied to another.
pub(crate) async fn plan_of<C: Carrier>(
    wait: &C::Wait,
    kind: Option<CarrierKind>,
    (shaper, profile): (Option<&HandshakeShaper>, Profile),
    limits: Option<&Limits>,
    message: &'static str,
) -> UnitPlan {
    let Some(shaper) = shaper else {
        return UnitPlan::default();
    };
    let view = HandshakeView::new(kind, profile.handshake_name(), message);
    let none = Limits::default();
    let PlanAnswer::Plan(plan) = ask_handshake(shaper, &view, limits.unwrap_or(&none)) else {
        return UnitPlan::default();
    };
    if !plan.delay.is_zero() {
        C::sleep(wait, plan.delay).await;
    }
    plan
}

/// The payload of message `seq` under `plan`. `head` gives the wire length of a unit of so
/// many Noise bytes. A message sent without a key has random padding. `padded` counts the
/// bytes the padding took.
pub(crate) fn shaped_payload(
    plan: &UnitPlan,
    (seq, profile): (usize, Profile),
    items: &[(u64, &[u8])],
    head: impl Fn(usize) -> usize,
    padded: &mut u64,
) -> Result<Vec<u8>, Error> {
    let psk = has_psk(profile);
    // The plaintext of the items, whatever their types.
    let noise = profile.empty_message_len(seq) + zmux::proto::seal::encode_payload(items).len();
    let w = head(noise);
    let room = (u16::MAX as usize).saturating_sub(noise);
    let value = pad_item(plan.pad_for(w) as isize - w as isize, room);
    *padded += value.map_or(0, |v| item_size(v) as u64);
    let random = seq == 0 && !psk;
    handshake_payload(value, items, random)
}

/// What an Establish learned of the other end.
#[derive(Debug, Clone)]
pub struct Peer {
    /// The peer's static key.
    pub static_key: Vec<u8>,
    /// The peer's credential, when its message carried one: (type, bytes).
    pub credential: Option<Credential>,
    /// The verifier's verdict on the peer, when it was verified.
    pub verdict: Option<VerifyVerdict>,
    /// The Profile of the handshake.
    pub profile: u64,
    /// The record mode.
    pub record_mode: RecordMode,
    /// The application data the peer sent, in message order.
    pub app_data: Vec<AppData>,
    /// The handshake's confidentiality resists a passive quantum adversary.
    pub pq_confidential: bool,
    /// The peer's authentication resists an active quantum adversary: the verdict named a
    /// proof key, the proof verified, and its KeyAlg is post-quantum.
    pub pq_authenticated: bool,
}

/// The carrier ended, or the reply timeout passed, before the server's message 2. A server
/// says nothing about a failed handshake: this is the client's own reading of the silence.
/// It wraps the end of stream or the timeout.
#[derive(Debug)]
pub struct NoReply(pub io::Error);

impl std::fmt::Display for NoReply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no reply from the server ({}): the Profile is not accepted, the Handle is unknown, \
             the pre-shared key is wrong, or the record mode is not allowed",
            self.0
        )
    }
}

impl std::error::Error for NoReply {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Where a client's static key comes from.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum StaticSecret {
    /// A key generated once per process and shared by its clients.
    #[default]
    Process,
    /// This X25519 private scalar.
    Given([u8; 32]),
}

impl fmt::Debug for StaticSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Process => f.write_str("Process"),
            Self::Given(_) => f.write_str("Given(..)"),
        }
    }
}

/// The default of [`ClientConfig::reply_timeout`].
pub const DEFAULT_REPLY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The client's side of [`establish`].
#[derive(Clone)]
pub struct ClientConfig {
    /// Judges the server; required unless `allow_psk_only`.
    pub verifier: Option<Arc<dyn Verifier>>,
    /// Accepts any server that knows the pre-shared key: an explicit bootstrap that must
    /// not override trust the host already holds.
    pub allow_psk_only: bool,
    /// The Handle, with `psk`, selects a Profile with a pre-shared key; both empty select
    /// one without.
    pub handle: Vec<u8>,
    /// The pre-shared key.
    pub psk: Vec<u8>,
    /// The client's static key (default [`StaticSecret::Process`]).
    pub static_secret: StaticSecret,
    /// The Profiles this client may use, the first that fits the pre-shared key being
    /// used (default: both ciphers, the one with hardware support first; an empty list
    /// is the configuration error). A refusal never makes a client choose another
    /// Profile.
    pub allowed_profiles: Vec<u64>,
    /// The record mode; the default is Sealed.
    pub record_mode: RecordMode,
    /// The credential sent in message 3, (type, bytes), if any.
    pub credential: Option<Credential>,
    /// The local application's label of this dial, handed to the verifier.
    pub local_context: Vec<u8>,
    /// Supplies the application data of message 1 (Profiles 1 and 3) and message 3.
    pub app_data: Option<AppDataSource>,
    /// The largest application data of the server's message, in bytes (default
    /// [`DEFAULT_MAX_APP_DATA`](crate::DEFAULT_MAX_APP_DATA), 256; `None`: no bound beyond
    /// the message): a local safety bound, not a protocol limit.
    pub max_app_data: Option<usize>,
    /// Requires the server's post-quantum authentication: a verifier is then required, and
    /// not a pin of a static key alone.
    pub require_pq_auth: bool,
    /// Proves message 3 with this key, for a server whose verdict names it.
    pub signer: Option<Arc<dyn Signer>>,
    /// Plans the handshake's messages; unset: none.
    pub shaper: Option<HandshakeShaper>,
    /// Applied to the plans, and not counted: there is no session yet.
    pub shaping_limits: Option<Limits>,
    /// How long the client waits for message 2 before it fails with [`NoReply`] (default
    /// [`DEFAULT_REPLY_TIMEOUT`], 10 s; `None`: no limit). A server that stalls a refused
    /// carrier leaves the client waiting this long.
    pub reply_timeout: Option<std::time::Duration>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            verifier: None,
            allow_psk_only: false,
            handle: Vec::new(),
            psk: Vec::new(),
            static_secret: StaticSecret::Process,
            allowed_profiles: client_default().to_vec(),
            record_mode: RecordMode::Sealed,
            credential: None,
            local_context: Vec::new(),
            app_data: None,
            max_app_data: Some(crate::DEFAULT_MAX_APP_DATA),
            require_pq_auth: false,
            signer: None,
            shaper: None,
            shaping_limits: None,
            reply_timeout: Some(DEFAULT_REPLY_TIMEOUT),
        }
    }
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("handle", &self.handle)
            .field("allow_psk_only", &self.allow_psk_only)
            .field("record_mode", &self.record_mode)
            .finish_non_exhaustive()
    }
}

fn process_secret() -> Result<[u8; 32], Error> {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    if let Some(k) = KEY.get() {
        return Ok(*k);
    }
    let mut k = [0; 32];
    zmux::proto::seal::fill_random(&mut k)?;
    Ok(*KEY.get_or_init(|| k))
}

impl ClientConfig {
    /// The Profile this client uses: the first allowed one that fits whether it has a
    /// pre-shared key. Every listed Profile must be a known Establish Profile.
    fn profile(&self) -> Result<Profile, ConfigError> {
        if !self.handle.is_empty() && self.psk.is_empty() {
            return Err(ConfigError("Handle set without a pre-shared key"));
        }
        if self.handle.is_empty() && !self.psk.is_empty() {
            return Err(ConfigError("pre-shared key set without a Handle"));
        }
        if self
            .allowed_profiles
            .iter()
            .any(|&v| Profile::from_value(v).is_none())
        {
            return Err(ConfigError(
                "allowed_profiles holds an unknown or reserved Profile",
            ));
        }
        if self.allowed_profiles.is_empty() {
            return Err(ConfigError("allowed_profiles is empty"));
        }
        let with_psk = !self.psk.is_empty();
        self.allowed_profiles
            .iter()
            .filter_map(|&v| Profile::from_value(v))
            .find(|&p| has_psk(p) == with_psk)
            .ok_or(ConfigError(if with_psk {
                "allowed_profiles holds no Profile with a pre-shared key"
            } else {
                "allowed_profiles holds no Profile without a pre-shared key"
            }))
    }

    /// Runs the verifier on the server, if any.
    async fn judge(&self, input: VerifyInput<'_>) -> Result<Option<VerifyVerdict>, VerifyError> {
        match &self.verifier {
            None => Ok(None),
            Some(verifier) => judge(verifier.as_ref(), input).await.map(Some),
        }
    }
}

/// Reads one unit from the carrier; `rest` keeps what is beyond it.
pub(crate) async fn read_frame<C: Carrier>(
    p: &mut C,
    framing: Framing,
    buf: &mut Vec<u8>,
) -> Result<Vec<u8>, io::Error> {
    loop {
        if !buf.is_empty() || framing == Framing::Records {
            match cut_unit(framing, buf) {
                Ok((unit, used)) if framing == Framing::ByteStream || !unit.is_empty() => {
                    let out = unit.to_vec();
                    buf.drain(..used);
                    return Ok(out);
                }
                Ok(_) | Err(Error::Incomplete { .. }) => {}
                Err(e) => return Err(io::Error::new(io::ErrorKind::InvalidData, e)),
            }
        }
        if buf.len() > MAX_UNIT {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if p.read(buf).await? == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
    }
}

pub(crate) fn binding_of<C: Carrier>(p: &C, mode: RecordMode) -> Result<Vec<u8>, Error> {
    if mode != RecordMode::Bound {
        return Ok(Vec::new());
    }
    p.binding().ok_or(Error::InvalidConfig)
}

/// Runs the client's handshake on `p` and returns the carrier for `Session::connect`, with
/// what it learned of the server. On a failure the carrier is dropped, and nothing is
/// retried: a different choice is a new carrier. A caller bounds it with a timeout.
pub async fn establish(p: PipeIo, cfg: &ClientConfig) -> Result<(PipeIo, Peer), io::Error> {
    run_client(p, cfg).await
}

/// The client's handshake, on either driver's carrier.
pub(crate) async fn run_client<C: Carrier>(
    mut p: C,
    cfg: &ClientConfig,
) -> Result<(C, Peer), io::Error> {
    let invalid = |e: Error| io::Error::new(io::ErrorKind::InvalidInput, e);
    let misconfigured = |e: ConfigError| io::Error::new(io::ErrorKind::InvalidInput, e);
    if cfg.verifier.is_none() && !cfg.allow_psk_only {
        return Err(misconfigured(ConfigError(
            "no verifier: set one, or allow_psk_only with a pre-shared key",
        )));
    }
    let profile = cfg.profile().map_err(misconfigured)?;
    check_pq_auth(cfg.require_pq_auth, cfg.verifier.as_ref()).map_err(misconfigured)?;
    if cfg.allow_psk_only && !has_psk(profile) {
        return Err(misconfigured(ConfigError(
            "allow_psk_only without a pre-shared key",
        )));
    }
    let secret = match cfg.static_secret {
        StaticSecret::Given(s) => s,
        StaticSecret::Process => process_secret().map_err(invalid)?,
    };
    let mode = cfg.record_mode;
    let binding = binding_of(&p, mode).map_err(invalid)?;
    let framing = p.framing();
    let init = Initiator::new(InitiatorConfig {
        profile,
        mode,
        framing,
        handle: &cfg.handle,
        psk: &cfg.psk,
        static_secret: &secret,
        binding: &binding,
        max_app_data: cfg.max_app_data,
    })
    .map_err(invalid)?;
    let psk = has_psk(profile);
    let refused = |e: VerifyError| {
        let kind = if e.is_rejection() {
            io::ErrorKind::PermissionDenied
        } else {
            io::ErrorKind::Other
        };
        io::Error::new(kind, e)
    };
    // Message 1 carries data only under a pre-shared key, which encrypts it.
    let early = if psk {
        ask_app_data(
            cfg.app_data.as_ref(),
            AppDataRequest {
                message: 1,
                peer: None,
                verdict: None,
            },
        )
        .await
        .map_err(refused)?
    } else {
        Vec::new()
    };
    let shaper = (cfg.shaper.as_ref(), profile);
    let limits = cfg.shaping_limits.as_ref();
    let stream = framing == Framing::ByteStream;
    let over = usize::from(p.overhead());
    let mut padded = 0;
    let plan = plan_of::<C>(&p.wait(), p.kind(), shaper, limits, "hello").await;
    let handle = psk;
    let payload = shaped_payload(
        &plan,
        (0, profile),
        &message_items(&[], &early, &[]),
        |noise| establish_hello_len(profile.value(), handle, stream, noise, over),
        &mut padded,
    )
    .map_err(invalid)?;
    let (hello, wait) = init.write_hello(&payload).map_err(invalid)?;
    p.write(&hello).await?;
    let mut buf = Vec::new();
    let reply = {
        let r = match cfg.reply_timeout {
            None => read_frame(&mut p, framing, &mut buf).await,
            Some(t) => p.read_unit_within(framing, &mut buf, t).await,
        };
        // The server's silence: an end, a failure or a timeout before message 2.
        r.map_err(|e| match e.kind() {
            io::ErrorKind::InvalidData => e,
            kind => io::Error::new(kind, NoReply(e)),
        })?
    };
    let auth = |e: Error| io::Error::new(io::ErrorKind::PermissionDenied, e);
    let verify = wait.read_reply(&reply).map_err(auth)?;
    let peer_key = verify.peer_static().to_vec();
    let credential = verify
        .payload()
        .credential()
        .map(|e| (e.kind, e.credential.to_vec()));
    let app_data: Vec<AppData> = AppData::of(2, verify.payload().app_data())
        .into_iter()
        .collect();
    // The server is judged before anything of this client is written.
    let input = VerifyInput {
        role: zmux::Role::Server,
        profile,
        peer_static: &peer_key,
        psk_identity: psk.then_some(cfg.handle.as_slice()),
        credential: credential.as_ref().map(|(k, c)| (*k, c.as_slice())),
        peer_app_data: &app_data,
        local_context: &cfg.local_context,
    };
    let verdict = cfg.judge(input).await.map_err(refused)?;
    // The core checks the proof the verdict names.
    let pq_authenticated = match &verdict {
        Some(v) => verify
            .check_proof(v.proof_key.as_ref(), cfg.require_pq_auth)
            .map_err(auth)?,
        None => false,
    };
    // The data is the verified server's only once its verifier passed.
    let mut judged = app_data.clone();
    if verdict.is_some() {
        AppData::mark_authenticated(&mut judged);
    }
    let late = ask_app_data(
        cfg.app_data.as_ref(),
        AppDataRequest {
            message: 3,
            peer: Some(&input),
            verdict: verdict.as_ref(),
        },
    )
    .await
    .map_err(refused)?;
    let value = credential_value(cfg.credential.as_ref());
    let proof = proof_placeholder(cfg.signer.as_ref());
    let plan = plan_of::<C>(&p.wait(), p.kind(), shaper, limits, "finish").await;
    let payload = shaped_payload(
        &plan,
        (2, profile),
        &message_items(&value, &late, &proof),
        |noise| message_len(stream, noise, over),
        &mut padded,
    )
    .map_err(invalid)?;
    let finish = verify.accept();
    let (finish, complete) = match &cfg.signer {
        None => finish.write_finish(&payload).map_err(invalid)?,
        Some(signer) => {
            let pending = finish.write_finish_signed(&payload).map_err(invalid)?;
            let sig = signer.sign(pending.message()).await?;
            pending.finish(&sig).map_err(invalid)?
        }
    };
    p.write(&finish).await?;
    let peer = Peer {
        static_key: peer_key,
        credential,
        verdict,
        profile: profile.value(),
        record_mode: mode,
        app_data: judged,
        pq_confidential: profile.pq_confidentiality(),
        pq_authenticated,
    };
    Ok((p.finish(buf, complete, mode).padded(padded), peer))
}
