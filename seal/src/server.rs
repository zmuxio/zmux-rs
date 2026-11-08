//! The server's Establish, as a listener's inbound transform.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use zmux::InboundTransform;
use zmux::proto::listener::RejectError;
use zmux::proto::seal::{Dispatch, Framing, Mode, dispatch};
use zmux::shaping::{HandshakeShaper, Limits, message_len};
use zmux_seal_proto::{Error, Hello, Profile, Responder, ResponderKeys};

use crate::carrier::Carrier;
use crate::establish::{Peer, binding_of, plan_of, read_frame, shaped_payload};
use crate::profiles::{SERVER_DEFAULT, has_psk};
use crate::trust::{
    Admission, AppData, AppDataRequest, AppDataSource, ConfigError, Gate, PeerRole, Signer,
    Verifier, VerifyError, VerifyInput, ask_app_data, check_pq_auth, judge,
};
use crate::{credential_value, message_items, proof_placeholder};

/// The callable of [`ServerOptions::allow_record_mode`].
pub type ModeCheck = dyn Fn(Mode, &Peer) -> bool + Send + Sync;

/// The options of a [`ServerConfig`]; the default accepts Profiles 1 and 3.
#[derive(Clone, Default)]
pub struct ServerOptions {
    /// The accepted Establish Profiles; empty is the default set, 1 and 3, which holds no
    /// Profile without a pre-shared key. Listing 4 or 5 is the only way to accept a
    /// Profile without one, which sends the node's credentials to anonymous clients.
    pub accepted_profiles: Vec<u64>,
    /// The check of a Hello's mode; unset passes only Sealed. Joins have their own,
    /// `Config::allow_record_mode`.
    pub allow_record_mode: Option<Arc<ModeCheck>>,
    /// Plans the handshake's messages; unset: none.
    pub shaper: Option<HandshakeShaper>,
    /// Applied to the plans, and not counted: there is no session yet.
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
    /// The largest application data of a client's message; 0 is
    /// [`DEFAULT_MAX_APP_DATA`](crate::DEFAULT_MAX_APP_DATA), and `usize::MAX` sets no
    /// bound beyond the message: a local safety bound, not a protocol limit.
    pub max_app_data: usize,
}

/// The server's side of Establish, validated when it is made ([`ServerConfig::new`]).
#[derive(Clone)]
pub struct ServerConfig {
    gate: Arc<dyn Gate>,
    static_secret: [u8; 32],
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
    /// A server with `gate`, its static secret and `options`.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] for an all-zero static secret, an unknown or reserved Profile
    /// among the accepted ones, and `require_pq_auth` without a client verifier or with a
    /// pin of a static key alone.
    pub fn new(
        gate: Arc<dyn Gate>,
        static_secret: [u8; 32],
        options: ServerOptions,
    ) -> Result<Self, ConfigError> {
        if static_secret == [0; 32] {
            return Err(ConfigError("ServerConfig without a static secret"));
        }
        let listed: &[u64] = if options.accepted_profiles.is_empty() {
            &SERVER_DEFAULT
        } else {
            &options.accepted_profiles
        };
        if listed.iter().any(|&v| Profile::from_value(v).is_none()) {
            return Err(ConfigError(
                "accepted_profiles holds an unknown or reserved Profile",
            ));
        }
        check_pq_auth(options.require_pq_auth, options.client_verifier.as_ref())?;
        let accepted = listed.to_vec();
        Ok(Self {
            gate,
            static_secret,
            accepted,
            options,
        })
    }

    /// The accepted Profiles.
    pub fn accepted_profiles(&self) -> &[u64] {
        &self.accepted
    }
}

/// The error class of a refusal, as the secure carrier names refusals.
pub fn reject_reason(e: &Error) -> &'static str {
    e.class()
}

fn reject(profile: Option<u64>, mode: Option<Mode>, reason: &'static str) -> io::Error {
    io::Error::other(RejectError::new(profile, mode, reason))
}

impl ServerConfig {
    /// The transform of a `ListenerConfig`: a carrier whose first byte is 02 is a Join and a
    /// carrier that begins a record a lane; they pass on untouched. Establish runs on the
    /// others, a split carrier's once its halves are paired.
    pub fn transform(self) -> InboundTransform {
        let this = Arc::new(self);
        InboundTransform::new(move |p, hint| {
            let this = this.clone();
            let source = hint.source.or(hint.peer);
            async move { this.accept(p, source).await }
        })
    }

    /// Establish on `p`: a refusal hands the carrier back with its [`RejectError`], so
    /// that the listener can stall it.
    pub(crate) async fn accept<C: Carrier + 'static>(
        &self,
        p: C,
        source: Option<SocketAddr>,
    ) -> io::Result<C> {
        let mut slot = Some(p);
        match self.accept_in(&mut slot, source).await {
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
                Dispatch::Incomplete { .. } => {}
                Dispatch::Other | Dispatch::Reserved | Dispatch::Record if !buf.is_empty() => {
                    return Err(reject(None, None, "unknown_profile"));
                }
                _ => {}
            }
            if framing == Framing::Records {
                buf.clear();
            }
            if p.read(&mut buf).await? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
        let hello = loop {
            match Hello::parse(framing, &buf) {
                Ok(_) => break buf,
                Err(Error::Incomplete { .. }) => {
                    if p.read(&mut buf).await? == 0 {
                        return Err(io::ErrorKind::UnexpectedEof.into());
                    }
                }
                Err(e) => return Err(reject(None, None, e.class())),
            }
        };
        let parsed = Hello::parse(framing, &hello).map_err(|e| reject(None, None, e.class()))?;
        let profile = parsed.profile();
        let mode = parsed.mode();
        let refuse = |reason: &'static str| reject(Some(profile.value()), Some(mode), reason);
        // A rejection goes to the reject policy; a temporary failure closes the carrier
        // without counting against the peer.
        let gate_error = |reason: &'static str, e: VerifyError| {
            if e.is_rejection() {
                io::Error::other(
                    RejectError::new(Some(profile.value()), Some(mode), reason).with_source(e),
                )
            } else {
                io::Error::other(e)
            }
        };
        let with_psk = has_psk(profile);
        if !self.accepted.contains(&profile.value()) {
            return Err(refuse("profile_disabled"));
        }
        if mode != Mode::Sealed && self.options.allow_record_mode.is_none() {
            return Err(refuse("record_mode"));
        }
        let handle = parsed.handle().to_vec();
        let psk = if with_psk {
            self.gate
                .resolve(&handle, source)
                .await
                .map_err(|e| gate_error("unknown_handle", e))?
        } else {
            Vec::new()
        };
        // A Hello in Bound is never carrier early data. A carrier without the Bound contract
        // has no Binding to check it with.
        if mode == Mode::Bound && p.early_data_possible() {
            return Err(refuse("early_data"));
        }
        let binding = binding_of(&*p, mode).map_err(|_| refuse("binding_unavailable"))?;
        let (reply, first) = Responder::read_hello(
            &parsed,
            ResponderKeys {
                psk: &psk,
                static_secret: &self.static_secret,
                binding: &binding,
                max_app_data: self.options.max_app_data,
            },
        )
        .map_err(|e| refuse(e.class()))?;
        let mut app_data: Vec<AppData> = AppData::of(1, first.app_data()).into_iter().collect();
        let known = VerifyInput {
            role: PeerRole::Client,
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
        let credential = self
            .gate
            .credential(&handle, profile, &self.options.local_context, source)
            .await
            .map_err(|e| gate_error("gate_error", e))?;
        let value = credential_value(credential.as_ref());
        let proof = proof_placeholder(self.options.signer.as_ref());
        let plan = plan_of::<C>(
            &p.wait(),
            p.kind(),
            (self.options.shaper.as_ref(), profile),
            self.options.shaping_limits.as_ref(),
            "reply",
        )
        .await;
        let stream = framing == Framing::ByteStream;
        let over = usize::from(p.overhead());
        let mut padded = 0;
        let payload = shaped_payload(
            &plan,
            (1, profile),
            &message_items(&value, &own, &proof),
            |noise| message_len(stream, noise, over),
            &mut padded,
        )
        .map_err(|e| refuse(e.class()))?;
        let (msg, wait) = match &self.options.signer {
            None => reply.write_reply(&payload).map_err(|e| refuse(e.class()))?,
            Some(signer) => {
                let pending = reply
                    .write_reply_signed(&payload)
                    .map_err(|e| refuse(e.class()))?;
                let sig = signer.sign(pending.message()).await?;
                pending.finish(&sig).map_err(|e| refuse(e.class()))?
            }
        };
        p.write(&msg).await?;
        let mut rest = Vec::new();
        // A unit that does not frame is the client's protocol error, refused like a failed
        // Finish; an end of the carrier, a failure of it or a timeout closes it.
        let finish = read_frame(p, framing, &mut rest)
            .await
            .map_err(|e| framing_refusal(e).map_or_else(|e| e, refuse))?;
        let (complete, payload) = wait.read_finish(&finish).map_err(|e| refuse(e.class()))?;
        let client = complete.peer_static().unwrap_or_default().to_vec();
        app_data.extend(AppData::of(3, payload.app_data()));
        let mut pq_authenticated = false;
        let verdict = match &self.options.client_verifier {
            None => None,
            Some(v) => {
                let credential = payload.credential();
                let input = VerifyInput {
                    role: PeerRole::Client,
                    profile,
                    peer_static: &client,
                    psk_identity: with_psk.then_some(handle.as_slice()),
                    credential: credential.map(|e| (e.kind, e.credential)),
                    peer_app_data: &app_data,
                    local_context: &self.options.local_context,
                };
                let verdict = judge(v.as_ref(), input)
                    .await
                    .map_err(|e| gate_error("credentials_failed", e))?;
                // The core checks the proof the verdict names.
                pq_authenticated = complete
                    .check_proof(verdict.proof_key.as_ref(), self.options.require_pq_auth)
                    .map_err(|e| refuse(e.class()))?;
                Some(verdict)
            }
        };
        // The data is the verified client's only once its verifier passed.
        if verdict.is_some() {
            AppData::mark_authenticated(&mut app_data);
        }
        let peer = Peer {
            static_key: client.clone(),
            credential: payload
                .credential()
                .map(|e| (e.kind, e.credential.to_vec())),
            verdict: verdict.clone(),
            profile: profile.value(),
            mode,
            app_data: app_data.clone(),
            pq_confidential: profile.pq_confidentiality(),
            pq_authenticated,
        };
        if let Some(allow) = &self.options.allow_record_mode
            && !allow(mode, &peer)
        {
            return Err(refuse("record_mode"));
        }
        let value = self
            .gate
            .commit(
                Admission {
                    handle: &handle,
                    peer: &peer,
                },
                source,
            )
            .await
            .map_err(|e| gate_error("gate_error", e))?;
        Ok(take(slot)?
            .finish(rest, complete, mode)
            .padded(padded)
            .admitted(value))
    }
}

/// The class of a unit that does not frame (`Ok`), or the carrier's own error (`Err`).
fn framing_refusal(e: io::Error) -> Result<&'static str, io::Error> {
    if e.kind() != io::ErrorKind::InvalidData {
        return Err(e);
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

/// Whether a carrier's first bytes begin PIPE_LANE.
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
    use crate::trust::{Admission, BoxFuture, Credential, PinVerifier};
    use crate::{ClientConfig, ServerOptions, derive_handle_psk};

    /// A message carrier over channels whose second write, the client's Finish, can be
    /// replaced by a unit over the message carriers' 65535-byte limit.
    struct Chan {
        tx: UnboundedSender<Vec<u8>>,
        rx: UnboundedReceiver<Vec<u8>>,
        writes: usize,
        oversize_finish: bool,
    }

    fn pair() -> (Chan, Chan) {
        let (a_tx, a_rx) = unbounded_channel();
        let (b_tx, b_rx) = unbounded_channel();
        let end = |tx, rx| Chan {
            tx,
            rx,
            writes: 0,
            oversize_finish: false,
        };
        (end(a_tx, b_rx), end(b_tx, a_rx))
    }

    impl Carrier for Chan {
        fn framing(&self) -> Framing {
            Framing::Records
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
            None
        }
        fn early_data_possible(&self) -> bool {
            false
        }
        type Wait = ();
        fn wait(&self) {}
        async fn sleep((): &(), d: Duration) {
            tokio::time::sleep(d).await;
        }
        async fn read_unit_within(
            &mut self,
            framing: Framing,
            buf: &mut Vec<u8>,
            limit: Duration,
        ) -> io::Result<Vec<u8>> {
            tokio::time::timeout(limit, read_frame(self, framing, buf))
                .await
                .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
        }
        fn finish(self, _: Vec<u8>, _: zmux_seal_proto::Complete, _: Mode) -> Self {
            self
        }
        fn admitted(self, _: AdmittedValue) -> Self {
            self
        }
        fn padded(self, _: u64) -> Self {
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

    /// A Finish that does not frame is the client's protocol error: refused, so that the
    /// listener's reject policy applies, rather than closed at once.
    #[tokio::test]
    async fn an_unframed_finish_is_refused() {
        let node = [0x11; 32];
        let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(node));
        let k = derive_handle_psk(&[9; 32], b"tests", b"").unwrap();
        let server = ServerConfig::new(
            Arc::new(OneKey(k.psk.clone())),
            node,
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
        let e = tokio::time::timeout(Duration::from_secs(5), server.accept(s, None))
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
}
