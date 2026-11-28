//! The server's Establish, as a listener's inbound transform.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use zmux::proto::listener::RejectError;
use zmux::proto::seal::{Dispatch, Framing, RecordMode, Secret, dispatch};
use zmux::shaping::{HandshakeShaper, Limits, message_len};
use zmux::{Decision, InboundTransform};
use zmux_seal_proto::{Error, Hello, Profile, Responder, ResponderKeys};

use crate::carrier::Carrier;
use crate::establish::{Peer, StaticKey, binding_of, plan_of, read_frame, shaped_payload};
use crate::profiles::{SERVER_DEFAULT, has_psk};
use crate::trust::{
    Admission, AppData, AppDataRequest, AppDataSource, ConfigError, Gate, Signer, Verifier,
    VerifyError, VerifyInput, ask_app_data, check_pq_auth, guarded, host_panicked, judge,
    signer_panicked,
};
use crate::{
    CredentialFailure, CredentialFailureReason as Reason, credential_value, message_items,
    proof_placeholder,
};

/// The check of [`ServerOptions::allow_record_mode`]: asked outside every
/// lock while the Hello is answered; a later answer is bounded as the
/// handshake is, and one that panics refuses.
#[derive(Clone)]
pub struct ModeCheck(Arc<ModeCheckFn>);

/// The callable behind a [`ModeCheck`].
pub type ModeCheckFn = dyn Fn(RecordMode, &Peer) -> Decision<bool> + Send + Sync;

impl ModeCheck {
    /// The check `f`.
    pub fn new(f: impl Fn(RecordMode, &Peer) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(move |m, p| Decision::Now(f(m, p))))
    }

    /// The check `f`, answering when its future completes; it is given its
    /// own copy of the peer.
    pub fn new_async<F>(f: impl Fn(RecordMode, Peer) -> F + Send + Sync + 'static) -> Self
    where
        F: Future<Output = bool> + Send + 'static,
    {
        Self(Arc::new(move |m, p| Decision::later(f(m, p.clone()))))
    }

    /// Whether `mode` is allowed for `peer`; a panic refuses.
    async fn allows(&self, mode: RecordMode, peer: &Peer) -> bool {
        let f = &self.0;
        match Decision::catch(|| f(mode, peer)) {
            Some(d) => d.settle().await == Some(true),
            None => false,
        }
    }
}

impl std::fmt::Debug for ModeCheck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ModeCheck(..)")
    }
}

/// Concurrent message 2 construction limits and counters.
/// Clone the same object into each configuration that shares a budget.
#[derive(Debug, Clone)]
pub struct HandshakeLimits {
    total: usize,
    anonymous: usize,
    active: Arc<Mutex<ActiveReplies>>,
}

impl HandshakeLimits {
    /// Sets the total and anonymous limits. A zero anonymous limit disables
    /// anonymous replies. At least one permit is reserved for PSK handshakes.
    ///
    /// # Errors
    ///
    /// The anonymous limit must be below the total limit.
    pub fn new(total: usize, anonymous: usize) -> Result<Self, ConfigError> {
        if anonymous >= total {
            return Err(ConfigError(
                "anonymous handshake limit must be below the total",
            ));
        }
        Ok(Self {
            total,
            anonymous,
            active: Arc::default(),
        })
    }
}

impl Default for HandshakeLimits {
    fn default() -> Self {
        let total = std::thread::available_parallelism().map_or(2, |n| n.get().max(2));
        Self {
            total,
            anonymous: total.div_ceil(2),
            active: Arc::default(),
        }
    }
}

#[derive(Debug, Default)]
struct ActiveReplies {
    total: usize,
    anonymous: usize,
}

struct ReplyPermit {
    active: Arc<Mutex<ActiveReplies>>,
    anonymous: bool,
}

impl Drop for ReplyPermit {
    fn drop(&mut self) {
        let mut active = self
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        active.total -= 1;
        active.anonymous -= usize::from(self.anonymous);
    }
}

/// The options of a [`ServerConfig`]; the default accepts Profiles 1 and 3.
#[derive(Clone)]
pub struct ServerOptions {
    /// The accepted Establish Profiles (default 1 and 3, which hold no Profile without a
    /// pre-shared key; an empty list is the configuration error). Listing 4 or 5 is the
    /// only way to accept a Profile without one, which sends the node's credentials to
    /// anonymous clients.
    pub accepted_profiles: Vec<u64>,
    /// Concurrent reply construction. Defaults to available parallelism
    /// (at least two), with half rounded up available to anonymous clients.
    /// Use clones of one limit object to share permits across configurations.
    pub handshake_limits: HandshakeLimits,
    /// The check of a Hello's mode; unset passes only Sealed. Joins have their own,
    /// `Config::allow_record_mode`.
    pub allow_record_mode: Option<ModeCheck>,
    /// Plans the handshake's messages; unset: none.
    pub shaper: Option<HandshakeShaper>,
    /// Bounds each outbound handshake plan before it is written.
    pub shaping_limits: Option<Limits>,
    /// Verifies clients from message 3; unset: clients are not verified, and only
    /// [`Gate::commit`] admits them.
    pub client_verifier: Option<Arc<dyn Verifier>>,
    /// The local application's label of this listener, handed to the Gate and verifier.
    pub local_context: Vec<u8>,
    /// Requires the client's post-quantum authentication: a client verifier is then
    /// required, and not a pin of a static key alone.
    pub require_pq_auth: bool,
    /// Proves message 2 with this key, for clients whose verdict names it. It signs every
    /// Reply that passes message 1: rate-limit there what it costs.
    pub signer: Option<Arc<dyn Signer>>,
    /// Supplies the application data of message 2. Its request holds the PSK identity,
    /// the client's data of message 1 and the local context: the client's static key
    /// comes only with message 3.
    pub app_data: Option<AppDataSource>,
    /// The largest application data of a client's message, in bytes (default
    /// [`DEFAULT_MAX_APP_DATA`](crate::DEFAULT_MAX_APP_DATA), 256; `None`: no bound beyond
    /// the message): a local safety bound, not a protocol limit.
    pub max_app_data: Option<usize>,
}

impl Default for ServerOptions {
    fn default() -> Self {
        Self {
            accepted_profiles: SERVER_DEFAULT.to_vec(),
            handshake_limits: HandshakeLimits::default(),
            allow_record_mode: None,
            shaper: None,
            shaping_limits: None,
            client_verifier: None,
            local_context: Vec::new(),
            require_pq_auth: false,
            signer: None,
            app_data: None,
            max_app_data: Some(crate::DEFAULT_MAX_APP_DATA),
        }
    }
}

impl ServerOptions {
    /// Uses a preselected session configuration's shaping limits for Reply.
    /// Use that configuration (or a clone) for sessions admitted by this transform.
    /// Select these limits before the reply, even if admission chooses other
    /// session settings after authenticating the client.
    ///
    /// # Errors
    ///
    /// The local limits or session budget cannot be resolved.
    pub fn use_session_shaping(
        &mut self,
        session: &mut zmux::Config,
    ) -> Result<(), zmux::InvalidConfig> {
        self.shaping_limits = Some(crate::establish::session_shaping_limits(
            session,
            self.shaping_limits,
        )?);
        Ok(())
    }
}

impl std::fmt::Debug for ServerOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerOptions")
            .field("accepted_profiles", &self.accepted_profiles)
            .field("handshake_limits", &self.handshake_limits)
            .field("allow_record_mode", &self.allow_record_mode.is_some())
            .field("shaper", &self.shaper.is_some())
            .field("shaping_limits", &self.shaping_limits.is_some())
            .field("client_verifier", &self.client_verifier.is_some())
            .field("local_context", &self.local_context)
            .field("require_pq_auth", &self.require_pq_auth)
            .field("signer", &self.signer.is_some())
            .field("app_data", &self.app_data.is_some())
            .field("max_app_data", &self.max_app_data)
            .finish()
    }
}

/// The server's side of Establish, validated when it is made ([`ServerConfig::new`]).
#[derive(Clone)]
pub struct ServerConfig {
    gate: Arc<dyn Gate>,
    static_key: StaticKey,
    accepted: Vec<u64>,
    options: ServerOptions,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("accepted", &self.accepted)
            .finish_non_exhaustive()
    }
}

impl ServerConfig {
    /// A server with `gate`, its static key and `options`.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for an all-zero static key, an unknown or reserved Profile
    /// among the accepted ones, and `require_pq_auth` without a client verifier or with a
    /// pin of a static key alone.
    pub fn new(
        gate: Arc<dyn Gate>,
        static_key: StaticKey,
        options: ServerOptions,
    ) -> Result<Self, ConfigError> {
        if *static_key.scalar() == [0; 32] {
            return Err(ConfigError("ServerConfig without a static key"));
        }
        let listed = &options.accepted_profiles;
        if listed.is_empty() {
            return Err(ConfigError("accepted_profiles is empty"));
        }
        if listed.iter().any(|&v| Profile::from_value(v).is_none()) {
            return Err(ConfigError(
                "accepted_profiles holds an unknown or reserved Profile",
            ));
        }
        check_pq_auth(options.require_pq_auth, options.client_verifier.as_ref())?;
        let accepted = listed.clone();
        Ok(Self {
            gate,
            static_key,
            accepted,
            options,
        })
    }

    /// The accepted Profiles.
    #[must_use]
    pub fn accepted_profiles(&self) -> &[u64] {
        &self.accepted
    }
}

/// The error class of a refusal, as the secure carrier names refusals.
#[must_use]
pub fn reject_reason(e: &Error) -> &'static str {
    e.class()
}

fn reject(profile: Option<u64>, mode: Option<RecordMode>, reason: &'static str) -> io::Error {
    io::Error::other(RejectError::establish(profile, mode, reason))
}

impl ServerConfig {
    /// The transform of a `ListenerConfig`: a carrier whose first byte is 02 is a Join and a
    /// carrier that begins a record a lane; they pass on untouched. Establish runs on the
    /// others, a split carrier's once its halves are paired.
    #[must_use]
    pub fn transform(self) -> InboundTransform {
        let this = Arc::new(self);
        InboundTransform::new(move |p, hint| {
            let this = this.clone();
            let source = hint.source.or(hint.peer);
            let clock = hint.clock_domain().clone();
            let deadline = hint.transform_deadline();
            async move { this.accept(p, source, &clock, deadline).await }
        })
    }

    fn try_reply(&self, anonymous: bool) -> Option<ReplyPermit> {
        let limits = &self.options.handshake_limits;
        let mut active = limits
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active.total >= limits.total || (anonymous && active.anonymous >= limits.anonymous) {
            return None;
        }
        active.total += 1;
        active.anonymous += usize::from(anonymous);
        Some(ReplyPermit {
            active: limits.active.clone(),
            anonymous,
        })
    }

    /// Establish on `p`: a refusal hands the carrier back with its [`RejectError`], so
    /// that the listener can stall it.
    pub(crate) async fn accept<C: Carrier + 'static>(
        &self,
        p: C,
        source: Option<SocketAddr>,
        clock: &zmux::ClockDomain,
        deadline: Option<std::time::Instant>,
    ) -> io::Result<C> {
        let mut slot = Some(p);
        let result = tokio::select! {
            biased;
            result = self.accept_in(&mut slot, source, clock, deadline) => result,
            () = clock.sleep_until(deadline) => Err(reject(None, None, "handshake_timeout")),
        };
        match result {
            Ok(p) => Ok(p),
            Err(e) => {
                let refusal = e
                    .get_ref()
                    .and_then(|e| e.downcast_ref::<RejectError>())
                    .cloned();
                match (refusal, slot.take()) {
                    (Some(r), Some(p)) => Err(zmux::proto::listener::Refused::error(r, p)),
                    _ => Err(e),
                }
            }
        }
    }

    async fn accept_in<C: Carrier>(
        &self,
        slot: &mut Option<C>,
        source: Option<SocketAddr>,
        clock: &zmux::ClockDomain,
        deadline: Option<std::time::Instant>,
    ) -> io::Result<C> {
        let Some(p) = slot.as_mut() else {
            return Err(io::ErrorKind::NotConnected.into());
        };
        let framing = p.framing();
        let mut buf = Vec::new();
        loop {
            match dispatch(framing, &buf) {
                Dispatch::Establish => break,
                Dispatch::Join => return Ok(take(slot)?.replay(buf)),
                Dispatch::Record if lane_first(&buf, framing) => {
                    return Ok(take(slot)?.replay(buf));
                }
                Dispatch::Other | Dispatch::Reserved | Dispatch::Record if !buf.is_empty() => {
                    return Err(reject(None, None, "unknown_profile"));
                }
                _ => {}
            }
            if framing == Framing::Records {
                buf.clear();
            }
            if p.read(&mut buf).await? == 0 {
                return Err(reject(None, None, "incomplete"));
            }
        }
        let hello = loop {
            match Hello::parse(framing, &buf) {
                Ok(_) => break buf,
                Err(Error::Incomplete { .. }) => {
                    if p.read(&mut buf).await? == 0 {
                        return Err(reject(None, None, "incomplete"));
                    }
                }
                Err(e) => return Err(reject(None, None, e.class())),
            }
        };
        let parsed = Hello::parse(framing, &hello).map_err(|e| reject(None, None, e.class()))?;
        let profile = parsed.profile();
        let mode = parsed.mode();
        let refuse = |reason: &'static str| reject(Some(profile.value()), Some(mode), reason);
        let gate_error = |reason: &'static str, e: VerifyError| {
            io::Error::other(
                RejectError::establish(Some(profile.value()), Some(mode), reason).with_source(e),
            )
        };
        let with_psk = has_psk(profile);
        if !self.accepted.contains(&profile.value()) {
            return Err(refuse("profile_disabled"));
        }
        if mode != RecordMode::Sealed && self.options.allow_record_mode.is_none() {
            return Err(refuse("record_mode"));
        }
        let handle = parsed.handle().to_vec();
        let psk = if with_psk {
            // Held as a Secret from here: cleared when the handshake ends.
            Secret::from(
                guarded(|| self.gate.resolve(&handle, source), host_panicked)
                    .await
                    .map_err(|e| gate_error("unknown_handle", e))?,
            )
        } else {
            Secret::default()
        };
        // A Hello in Bound is never carrier early data. A carrier without the Bound contract
        // has no Binding to check it with.
        if mode == RecordMode::Bound && p.early_data_possible() {
            return Err(refuse("early_data"));
        }
        let binding =
            Secret::from(binding_of(&*p, mode).map_err(|_| refuse("binding_unavailable"))?);
        let (reply, first) = Responder::read_hello(
            &parsed,
            ResponderKeys {
                psk: &psk,
                static_key: self.static_key.scalar(),
                binding: &binding,
                max_app_data: self.options.max_app_data,
            },
        )
        .map_err(|e| refuse(e.class()))?;
        drop(psk);
        drop(binding);
        reply.check_reply_key().map_err(|e| refuse(e.class()))?;
        let permit = self
            .try_reply(!with_psk)
            .ok_or_else(|| refuse("handshake_capacity"))?;
        let permit = Arc::new(permit);
        let mut app_data: Vec<AppData> = AppData::of(1, first.app_data()).into_iter().collect();
        let known = VerifyInput {
            role: zmux::Role::Client,
            profile,
            peer_static: &[],
            psk_identity: with_psk.then_some(handle.as_slice()),
            credential: None,
            peer_app_data: &app_data,
            local_context: &self.options.local_context,
        };
        let own = ask_app_data(
            self.options.app_data.as_ref(),
            AppDataRequest {
                message: 2,
                peer: Some(&known),
                verdict: None,
            },
        )
        .await
        .map_err(|e| gate_error("app_data", e))?;
        let credential = guarded(
            || {
                self.gate
                    .credential(&handle, profile, &self.options.local_context, source)
            },
            host_panicked,
        )
        .await
        .map_err(|e| gate_error("gate_error", e))?;
        let value = credential_value(credential.as_ref());
        let proof = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            proof_placeholder(self.options.signer.as_ref())
        }))
        .map_err(|_| refuse("signer_error"))?;
        let plan = plan_of::<C>(
            &p.wait(clock),
            p.kind(),
            (self.options.shaper.as_ref(), profile),
            self.options.shaping_limits.as_ref(),
            "reply",
        )
        .await;
        let stream = framing == Framing::ByteStream;
        let over = usize::from(p.overhead());
        let (payload, mut receipt) = shaped_payload(
            &plan,
            (1, profile),
            &message_items(&value, &own, &proof),
            (|noise| message_len(stream, noise, over), over),
        )
        .map_err(|e| refuse(e.class()))?;
        let (msg, wait) = match &self.options.signer {
            None => reply.write_reply(&payload).map_err(|e| refuse(e.class()))?,
            Some(signer) => {
                let pending = reply
                    .write_reply_signed(&payload)
                    .map_err(|e| refuse(e.class()))?;
                let sig = sign_reply(signer, pending.message(), permit.clone())
                    .await
                    .map_err(|e| {
                        io::Error::other(
                            RejectError::establish(
                                Some(profile.value()),
                                Some(mode),
                                "signer_error",
                            )
                            .with_source(e),
                        )
                    })?;
                pending.finish(&sig).map_err(|e| refuse(e.class()))?
            }
        };
        drop(permit);
        if deadline.is_some_and(|at| clock.now() >= at) {
            return Err(refuse("handshake_timeout"));
        }
        receipt.at = clock.now();
        debug_assert_eq!(msg.len() as u64, receipt.baseline + receipt.extra);
        p.write(&msg).await?;
        let mut rest = Vec::new();
        // Framing errors and an incomplete Finish use the same refusal
        // as a failed message 3 proof.
        let finish = read_frame(p, framing, &mut rest)
            .await
            .map_err(|e| framing_refusal(e).map_or_else(|e| e, refuse))?;
        let (complete, payload) = wait.read_finish(&finish).map_err(|e| refuse(e.class()))?;
        let client = complete.peer_static().unwrap_or_default().to_vec();
        app_data.extend(AppData::of(3, payload.app_data()));
        let refuse_credentials = |error: CredentialFailure| {
            io::Error::other(
                RejectError::establish(Some(profile.value()), Some(mode), error.class().class())
                    .with_source(error),
            )
        };
        let verdict = match &self.options.client_verifier {
            None => None,
            Some(v) => {
                let credential = payload.credential();
                let input = VerifyInput {
                    role: zmux::Role::Client,
                    profile,
                    peer_static: &client,
                    psk_identity: with_psk.then_some(handle.as_slice()),
                    credential: credential.map(|e| (e.kind, e.credential)),
                    peer_app_data: &app_data,
                    local_context: &self.options.local_context,
                };
                let verdict = judge(v.as_ref(), input).await.map_err(|e| {
                    let rejected = e.is_rejection();
                    let failure = CredentialFailure::new(Reason::Verifier).with_cause(e);
                    if rejected {
                        refuse_credentials(failure)
                    } else {
                        io::Error::other(failure)
                    }
                })?;
                Some(verdict)
            }
        };
        let pq_authenticated = crate::trust::verify_application_data(
            verdict.as_ref(),
            self.options.require_pq_auth,
            |key| complete.check_proof(key, false),
            &mut app_data,
        )
        .map_err(refuse_credentials)?;
        let peer = Peer {
            static_key: client.clone(),
            credential: payload
                .credential()
                .map(|e| (e.kind, e.credential.to_vec())),
            verdict: verdict.clone(),
            profile: profile.value(),
            record_mode: mode,
            app_data: app_data.clone(),
            pq_confidential: profile.pq_confidentiality(),
            pq_authenticated,
        };
        if let Some(allow) = &self.options.allow_record_mode
            && !allow.allows(mode, &peer).await
        {
            return Err(refuse("record_mode"));
        }
        let value = guarded(
            || {
                self.gate.commit(
                    Admission {
                        handle: &handle,
                        peer: &peer,
                    },
                    source,
                )
            },
            host_panicked,
        )
        .await
        .map_err(|e| gate_error("gate_error", e))?;
        if deadline.is_some_and(|at| clock.now() >= at) {
            return Err(refuse("handshake_timeout"));
        }
        Ok(take(slot)?
            .finish(rest, complete, mode)
            .with_establish_receipts([Some(receipt), None])
            .admitted(value))
    }
}

async fn sign_reply(
    signer: &Arc<dyn Signer>,
    message: &[u8],
    permit: Arc<ReplyPermit>,
) -> io::Result<Vec<u8>> {
    let Ok(runtime) = tokio::runtime::Handle::try_current() else {
        return guarded(|| signer.sign_with_worker(message, permit), signer_panicked).await;
    };
    let signer = signer.clone();
    let message = message.to_vec();
    runtime
        .spawn(async move {
            guarded(
                || signer.sign_with_worker(&message, permit),
                signer_panicked,
            )
            .await
        })
        .await
        .map_err(io::Error::other)?
}

/// The class of a unit that does not frame (`Ok`), or the carrier's own error (`Err`).
fn framing_refusal(e: io::Error) -> Result<&'static str, io::Error> {
    if e.kind() != io::ErrorKind::InvalidData {
        return if e.kind() == io::ErrorKind::UnexpectedEof {
            Ok("incomplete")
        } else {
            Err(e)
        };
    }
    Ok(e.get_ref()
        .and_then(|e| e.downcast_ref::<Error>())
        .map_or("too_large", |e| e.class()))
}

/// The carrier out of its slot.
fn take<C>(slot: &mut Option<C>) -> io::Result<C> {
    slot.take()
        .ok_or_else(|| io::ErrorKind::NotConnected.into())
}

/// Whether a carrier's first bytes begin `PIPE_LANE`.
fn lane_first(buf: &[u8], framing: Framing) -> bool {
    let lane = zmux::proto::ident::LANE_PREFIX;
    match framing {
        Framing::Records => buf.starts_with(&lane),
        Framing::ByteStream => {
            let width = buf.first().map_or(1, |b| 1usize << (b >> 6));
            buf.get(width) == Some(&lane[0])
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
    use zmux::proto::listener::Refused;
    use zmux::{AdmittedValue, CarrierKind};

    use super::*;
    use crate::establish::run_client;
    use crate::key_id;
    use crate::trust::{Admission, BoxFuture, Credential, PinVerifier, Verifier, VerifyVerdict};
    use crate::{ClientConfig, ServerOptions, derive_handle_psk};

    /// A message carrier over channels whose second write, the client's Finish, can be
    /// replaced by a unit over the message carriers' 65535-byte limit.
    struct Chan {
        tx: UnboundedSender<Vec<u8>>,
        rx: UnboundedReceiver<Vec<u8>>,
        writes: usize,
        oversize_finish: bool,
        framing: Framing,
        binding: Option<Vec<u8>>,
    }

    fn pair() -> (Chan, Chan) {
        let (a_tx, a_rx) = unbounded_channel();
        let (b_tx, b_rx) = unbounded_channel();
        let end = |tx, rx| Chan {
            tx,
            rx,
            writes: 0,
            oversize_finish: false,
            framing: Framing::Records,
            binding: None,
        };
        (end(a_tx, b_rx), end(b_tx, a_rx))
    }

    #[allow(
        clippy::unused_async_trait_impl,
        reason = "the trait is async; the channel completes writes in place"
    )]
    impl Carrier for Chan {
        fn framing(&self) -> Framing {
            self.framing
        }
        fn kind(&self) -> Option<CarrierKind> {
            None
        }
        fn overhead(&self) -> u16 {
            0
        }
        async fn read(&mut self, into: &mut Vec<u8>) -> io::Result<usize> {
            let Some(m) = self.rx.recv().await else {
                return Ok(0);
            };
            into.extend_from_slice(&m);
            Ok(m.len())
        }
        async fn write(&mut self, unit: &[u8]) -> io::Result<()> {
            self.writes += 1;
            let unit = if self.oversize_finish && self.writes == 2 {
                vec![0; u16::MAX as usize + 1]
            } else {
                unit.to_vec()
            };
            self.tx
                .send(unit)
                .map_err(|_| io::ErrorKind::BrokenPipe.into())
        }
        fn binding(&self) -> Option<Vec<u8>> {
            self.binding.clone()
        }
        fn early_data_possible(&self) -> bool {
            false
        }
        type Wait = zmux::ClockDomain;
        fn wait(&self, clock: &zmux::ClockDomain) -> Self::Wait {
            clock.clone()
        }
        async fn sleep(clock: &zmux::ClockDomain, d: Duration) {
            clock.sleep_until(clock.now().checked_add(d)).await;
        }
        fn finish(self, _: Vec<u8>, _: zmux_seal_proto::Complete, _: RecordMode) -> Self {
            self
        }
        fn admitted(self, _: AdmittedValue) -> Self {
            self
        }
        fn with_establish_receipts(self, _: zmux::shaping::EstablishReceipts) -> Self {
            self
        }
        fn replay(self, _: Vec<u8>) -> Self {
            self
        }
    }

    struct OneKey(Vec<u8>);

    impl Gate for OneKey {
        fn resolve<'a>(
            &'a self,
            _: &'a [u8],
            _: Option<SocketAddr>,
        ) -> BoxFuture<'a, Result<Vec<u8>, VerifyError>> {
            Box::pin(async { Ok(self.0.clone()) })
        }
        fn credential<'a>(
            &'a self,
            _: &'a [u8],
            _: Profile,
            _: &'a [u8],
            _: Option<SocketAddr>,
        ) -> BoxFuture<'a, Result<Option<Credential>, VerifyError>> {
            Box::pin(async { Ok(None) })
        }
        fn commit<'a>(
            &'a self,
            _: Admission<'a>,
            _: Option<SocketAddr>,
        ) -> BoxFuture<'a, Result<AdmittedValue, VerifyError>> {
            Box::pin(async { Ok(Arc::new(()) as AdmittedValue) })
        }
    }

    struct UnavailableVerifier;

    impl Verifier for UnavailableVerifier {
        fn verify<'a>(
            &'a self,
            _: VerifyInput<'a>,
        ) -> BoxFuture<'a, Result<VerifyVerdict, VerifyError>> {
            Box::pin(async { Err(VerifyError::unavailable("verifier offline")) })
        }
    }

    fn hex(value: &serde_json::Value) -> Vec<u8> {
        value
            .as_str()
            .unwrap()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }

    fn anonymous_hello(
        case: &serde_json::Value,
        vector: &serde_json::Value,
        framing: Framing,
    ) -> Vec<u8> {
        let first = &vector["messages"][0];
        let mut noise = hex(&first["noise"]);
        if let Some(n) = case["truncate_noise_msg1_to"].as_u64() {
            noise.truncate(usize::try_from(n).unwrap());
        }
        if case["append_to_noise_msg1_hex"].is_string() {
            noise.extend(hex(&case["append_to_noise_msg1_hex"]));
        }
        if let Some(q) = case["replace_first_kem_coefficient"].as_u64() {
            let [lo, hi] = u16::try_from(q).unwrap().to_le_bytes();
            noise[32] = lo;
            noise[33] = (noise[33] & 0xf0) | hi;
        }
        let mut wire = hex(&first["wire_message"])[..2].to_vec();
        zmux::proto::seal::frame(framing, &mut wire, &noise).unwrap();
        if case["append_to_hello_hex"].is_string() {
            wire.extend(hex(&case["append_to_hello_hex"]));
        }
        wire
    }

    #[tokio::test]
    async fn first_message_anonymous_vectors_observe_the_reply_boundary() {
        let cases: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/spec/secure-carrier/vectors/first_message_cases.json"
        ))
        .unwrap();
        let handshakes: serde_json::Value = serde_json::from_str(include_str!(
            "../../testdata/spec/secure-carrier/vectors/handshake.json"
        ))
        .unwrap();
        for case in cases["anonymous"]["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let handshake = case["handshake"]
                .as_str()
                .unwrap_or("profile4-sealed-empty");
            let vector = handshakes
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == handshake)
                .unwrap();
            for framing in [Framing::Records, Framing::ByteStream] {
                if case["framing"] == "stream" && framing != Framing::ByteStream {
                    continue;
                }
                let accepted = case["accept_profile"].as_bool().unwrap_or(true);
                let capacity = usize::from(case["capacity_available"].as_bool().unwrap_or(true));
                let config = ServerConfig::new(
                    Arc::new(OneKey(Vec::new())),
                    StaticKey::from_scalar(hex(&vector["responder_static"]).try_into().unwrap()),
                    ServerOptions {
                        accepted_profiles: if accepted { vec![4, 5] } else { vec![1, 3] },
                        allow_record_mode: Some(ModeCheck::new(|_, _| true)),
                        handshake_limits: HandshakeLimits::new(2, capacity).unwrap(),
                        ..ServerOptions::default()
                    },
                )
                .unwrap();
                let (mut c, mut s) = pair();
                s.framing = framing;
                s.binding = Some(hex(&vector["binding"]));
                c.tx.send(anonymous_hello(case, vector, framing)).unwrap();
                drop(c.tx);
                let error = config
                    .accept(s, None, &zmux::ClockDomain::default(), None)
                    .await
                    .err()
                    .unwrap();
                let refused = error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<Refused<Chan>>()
                    .unwrap();
                let wants_reply = case["expect_flights"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|f| f == "reply");
                assert_eq!(c.rx.try_recv().is_ok(), wants_reply, "{name}, {framing:?}");
                assert_eq!(
                    zmux::RejectAction::default_for(&zmux::RejectInfo::from_error(
                        refused.error.clone(),
                        None
                    )),
                    zmux::RejectAction::Stall
                );
            }
        }
    }

    #[tokio::test]
    async fn first_message_reply_permit_survives_cancelling_a_signer_wait() {
        use tokio::sync::oneshot;

        struct Sign {
            started: UnboundedSender<oneshot::Sender<()>>,
        }

        impl Signer for Sign {
            fn proof_key(&self) -> (u64, &[u8]) {
                (0, &[])
            }

            fn sign(&self, _: &[u8]) -> BoxFuture<'_, io::Result<Vec<u8>>> {
                let (finished, waiting) = oneshot::channel();
                self.started.send(finished).unwrap();
                Box::pin(async {
                    waiting.await.unwrap();
                    Ok(Vec::new())
                })
            }
        }

        let limits = HandshakeLimits::default();
        assert!(limits.total >= 2);
        assert_eq!(limits.anonymous, limits.total.div_ceil(2));
        assert!(HandshakeLimits::new(2, 2).is_err());
        let limits = HandshakeLimits::new(2, 1).unwrap();
        let make_config = || {
            ServerConfig::new(
                Arc::new(OneKey(Vec::new())),
                StaticKey::from_scalar([7; 32]),
                ServerOptions {
                    handshake_limits: limits.clone(),
                    ..ServerOptions::default()
                },
            )
            .unwrap()
        };
        let config = make_config();
        let another = make_config();
        let permit = Arc::new(config.try_reply(true).unwrap());
        let weak = Arc::downgrade(&permit);
        let (started, mut signers) = unbounded_channel();
        let signer: Arc<dyn Signer> = Arc::new(Sign { started });
        let wait = tokio::spawn(async move { sign_reply(&signer, b"transcript", permit).await });
        let finished = signers.recv().await.unwrap();
        assert!(another.try_reply(true).is_none());
        let psk = another.try_reply(false).unwrap();
        assert!(config.try_reply(true).is_none());
        assert!(another.try_reply(false).is_none());
        wait.abort();
        assert!(wait.await.unwrap_err().is_cancelled());
        assert!(weak.upgrade().is_some());
        assert!(config.try_reply(true).is_none());
        drop(psk);
        assert!(config.try_reply(false).is_some());
        finished.send(()).unwrap();
        while weak.upgrade().is_some() {
            tokio::task::yield_now().await;
        }
        assert!(config.try_reply(true).is_some());
    }

    /// A Finish that does not frame is the client's protocol error: refused, so that the
    /// listener's reject policy applies, rather than closed at once.
    #[tokio::test]
    async fn an_unframed_finish_is_refused() {
        let node = [0x11; 32];
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(node));
        let k = derive_handle_psk(&[9; 32], b"tests", b"").unwrap();
        let server = ServerConfig::new(
            Arc::new(OneKey(k.psk.to_vec())),
            StaticKey::from_scalar(node),
            ServerOptions::default(),
        )
        .unwrap();
        let cfg = ClientConfig {
            verifier: Some(Arc::new(PinVerifier::new(key_id(1, public.as_bytes())))),
            handle: k.handle,
            psk: k.psk,
            ..Default::default()
        };
        let (mut c, s) = pair();
        c.oversize_finish = true;
        let client = tokio::spawn(async move { run_client(c, &cfg).await.map(|_| ()) });
        let e = tokio::time::timeout(
            Duration::from_secs(5),
            server.accept(s, None, &zmux::ClockDomain::default(), None),
        )
        .await
        .expect("in time")
        .err()
        .expect("refused");
        let refused = e
            .get_ref()
            .and_then(|e| e.downcast_ref::<Refused<Chan>>())
            .expect("a refusal, not a close");
        assert_eq!(refused.error.reason, "too_large");
        client.abort();
    }

    #[tokio::test]
    async fn unavailable_client_verifier_closes_the_carrier() {
        let node = StaticKey::from_scalar([0x11; 32]);
        let verify = Arc::new(PinVerifier::new(key_id(1, &node.public_key())));
        let k = derive_handle_psk(&[9; 32], b"tests", b"").unwrap();
        let server = ServerConfig::new(
            Arc::new(OneKey(k.psk.to_vec())),
            node,
            ServerOptions {
                client_verifier: Some(Arc::new(UnavailableVerifier)),
                ..ServerOptions::default()
            },
        )
        .unwrap();
        let cfg = ClientConfig {
            verifier: Some(verify),
            handle: k.handle,
            psk: k.psk,
            ..Default::default()
        };
        let (c, s) = pair();
        let client = async {
            let (mut carrier, _) = run_client(c, &cfg).await.unwrap();
            assert_eq!(carrier.read(&mut Vec::new()).await.unwrap(), 0);
        };
        let server = async {
            let error = server
                .accept(s, None, &zmux::ClockDomain::default(), None)
                .await
                .err()
                .expect("verification failed");
            let failure = error
                .get_ref()
                .and_then(|e| e.downcast_ref::<CredentialFailure>())
                .expect("a credential failure without a carrier refusal");
            assert_eq!(failure.class(), crate::Error::CredentialsFailed);
            assert_eq!(failure.reason, Reason::Verifier);
            assert_eq!(
                std::error::Error::source(failure).and_then(|e| e.downcast_ref::<VerifyError>()),
                Some(&VerifyError::unavailable("verifier offline"))
            );
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(client, server);
        })
        .await
        .expect("handshake completes");
    }
}
