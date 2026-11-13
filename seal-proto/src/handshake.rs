//! The handshake as states that consume themselves.

use zmux::proto::seal::{
    Error, Framing, Opener, Payload, RecordMode, Sealer, Secret, export, frame, put_varint,
};

use crate::derive::exporter_secret;
use crate::keyalg::{KeyAlg, KeyId, KeyUse};
use crate::noise::{Engine, Finished, ReceivedProof};
use crate::wire::{handle_fits, write_hello};
use crate::{Hello, Profile};

const BINDING_LEN: usize = 32;

/// The Noise prologue. A sender's `binding` is present exactly when `mode` is Bound;
/// a responder mixes what it has, and any disagreement is `auth`.
pub fn prologue(profile: Profile, mode: RecordMode, handle: &[u8], binding: &[u8]) -> Vec<u8> {
    let mut out = b"zmux-seal".to_vec();
    put_varint(&mut out, profile.value());
    out.push(mode.byte());
    out.extend_from_slice(handle);
    out.extend_from_slice(binding);
    out
}

/// Writes the next message of `engine` with `payload`, which holds no proof: a proof is
/// written by the signing steps.
fn write_plain(engine: &mut Engine, payload: &[u8]) -> Result<Vec<u8>, Error> {
    Payload::check_outgoing(payload, engine.known_types())?;
    if Payload::validate(payload.to_vec(), engine.known_types())?
        .proof()
        .is_some()
    {
        return Err(Error::InvalidConfig);
    }
    engine.write_message(payload)
}

/// A message whose tokens are written and whose payload waits for the signature of its
/// proof.
struct Pending {
    tokens: Vec<u8>,
    payload: Vec<u8>,
    sig_len: usize,
    message: Vec<u8>,
}

impl Pending {
    /// Writes the tokens of the next message of `engine`. `payload` ends with a proof item
    /// whose KeyAlg is a proof key's and whose signature has its length, any bytes: they
    /// give the message its length and are replaced by the signature.
    fn begin(engine: &mut Engine, payload: &[u8]) -> Result<Pending, Error> {
        Payload::check_outgoing(payload, engine.known_types())?;
        let parsed = Payload::validate(payload.to_vec(), engine.known_types())?;
        let proof = parsed.proof().ok_or(Error::InvalidConfig)?;
        let alg = KeyAlg::from_value(proof.key_alg)
            .filter(|a| a.key_use() == KeyUse::Proof)
            .ok_or(Error::InvalidConfig)?;
        if proof.key.len() != alg.key_len() || proof.sig.len() != alg.sig_len() {
            return Err(Error::InvalidConfig);
        }
        // A message's highest known type is the proof: its signature ends the payload.
        let index = engine.message_index();
        let tokens = engine.write_tokens()?;
        if engine.message_len(tokens.len(), payload.len()) > u16::MAX as usize {
            return Err(Error::TooLarge);
        }
        Ok(Pending {
            tokens,
            payload: payload.to_vec(),
            sig_len: alg.sig_len(),
            message: crate::proof::proof_message(index, engine.h_p()),
        })
    }

    /// Encrypts the payload with `sig` in place.
    fn finish(self, engine: &mut Engine, sig: &[u8]) -> Result<Vec<u8>, Error> {
        if sig.len() != self.sig_len {
            return Err(Error::InvalidConfig);
        }
        let mut payload = self.payload;
        let at = payload.len() - sig.len();
        payload[at..].copy_from_slice(sig);
        engine.write_payload(self.tokens, &payload)
    }
}

/// The core's check of a received proof against the verdict.
fn check_received(
    proof: Option<&ReceivedProof>,
    proof_key: Option<&KeyId>,
    require_pq_auth: bool,
) -> Result<bool, Error> {
    crate::proof::check_proof(
        proof_key,
        proof.map(ReceivedProof::proof),
        proof.map_or(&[][..], |p| &p.message),
        require_pq_auth,
    )
}

/// A sender's inputs: anything absent, of another length or surplus is refused
/// before any byte is sent.
fn check_sender(
    profile: Profile,
    mode: RecordMode,
    handle: &[u8],
    psk: &[u8],
    static_secret: &[u8],
    binding: &[u8],
) -> Result<(), Error> {
    let binding_len = if mode == RecordMode::Bound {
        BINDING_LEN
    } else {
        0
    };
    let fits = handle_fits(profile, handle)
        && psk.len() == profile.psk_len().unwrap_or(0)
        && static_secret.len() == profile.0.dh.private_len
        && binding.len() == binding_len;
    fits.then_some(()).ok_or(Error::InvalidConfig)
}

/// A fixed KEM input of a test: the seed of an initiator, the randomness of a
/// responder.
#[cfg(feature = "test-vectors")]
fn fixed_kem(profile: Profile, bytes: &[u8], initiator: bool) -> Result<Option<Secret>, Error> {
    let kem = profile.0.kem;
    let len = if initiator {
        kem.seed_len
    } else {
        kem.random_len
    };
    (bytes.len() == len)
        .then(|| Some(bytes.into()))
        .ok_or(Error::InvalidConfig)
}

/// What a client brings to a handshake.
#[derive(Clone, Copy)]
pub struct InitiatorConfig<'a> {
    /// The Profile.
    pub profile: Profile,
    /// The record mode.
    pub mode: RecordMode,
    /// The carrier's framing.
    pub framing: Framing,
    /// The Handle, empty for a Profile without one.
    pub handle: &'a [u8],
    /// The pre-shared key, empty for a Profile without one.
    pub psk: &'a [u8],
    /// The static private key, empty for a Profile that sends none.
    pub static_secret: &'a [u8],
    /// The Binding in Bound mode, otherwise empty.
    pub binding: &'a [u8],
    /// The largest application data of a received message, in bytes; `None` sets no
    /// bound beyond the message. A local safety bound, not a protocol limit; the usual
    /// value is [`DEFAULT_MAX_APP_DATA`](crate::DEFAULT_MAX_APP_DATA).
    pub max_app_data: Option<usize>,
}

/// A client before its Hello.
pub struct Initiator {
    engine: Engine,
    profile: Profile,
    mode: RecordMode,
    framing: Framing,
    handle: Vec<u8>,
}

impl Initiator {
    /// Checks the configuration and prepares the handshake.
    pub fn new(config: InitiatorConfig<'_>) -> Result<Initiator, Error> {
        Self::build(config, None, None)
    }

    /// As [`Initiator::new`] with a fixed ephemeral key and, in a hybrid
    /// Profile, a fixed KEM seed `(d, z)`, for the vectors.
    #[cfg(feature = "test-vectors")]
    pub fn with_ephemeral(
        config: InitiatorConfig<'_>,
        e: &[u8],
        kem_seed: &[u8],
    ) -> Result<Initiator, Error> {
        Self::build(
            config,
            Some(e.into()),
            fixed_kem(config.profile, kem_seed, true)?,
        )
    }

    fn build(
        config: InitiatorConfig<'_>,
        e: Option<Secret>,
        kem: Option<Secret>,
    ) -> Result<Initiator, Error> {
        let InitiatorConfig {
            profile,
            mode,
            framing,
            handle,
            psk,
            static_secret,
            binding,
            max_app_data,
        } = config;
        check_sender(profile, mode, handle, psk, static_secret, binding)?;
        let prologue = prologue(profile, mode, handle, binding);
        let mut engine = Engine::new(
            profile.0,
            true,
            &prologue,
            psk.into(),
            static_secret.into(),
            e,
            kem,
        );
        engine.set_max_app_data(max_app_data);
        Ok(Initiator {
            engine,
            profile,
            mode,
            framing,
            handle: handle.to_vec(),
        })
    }

    /// Writes the Hello. `payload` is an encoded payload (see
    /// [`encode_payload`](crate::encode_payload)).
    pub fn write_hello(mut self, payload: &[u8]) -> Result<(Vec<u8>, AwaitReply), Error> {
        let noise = write_plain(&mut self.engine, payload)?;
        let wire = write_hello(self.framing, self.profile, self.mode, &self.handle, &noise)?;
        let next = AwaitReply {
            engine: self.engine,
            mode: self.mode,
            framing: self.framing,
        };
        Ok((wire, next))
    }
}

/// A client waiting for the Reply.
pub struct AwaitReply {
    engine: Engine,
    mode: RecordMode,
    framing: Framing,
}

impl AwaitReply {
    /// Reads Noise message 2, already cut from its frame.
    pub fn read_reply(mut self, message: &[u8]) -> Result<Verify, Error> {
        let known = self.engine.known_types();
        let raw = self.engine.read_message(message)?;
        let payload = self.engine.validate(raw, known)?;
        Ok(Verify {
            engine: self.engine,
            mode: self.mode,
            framing: self.framing,
            payload,
        })
    }

    #[cfg(feature = "test-vectors")]
    /// `h` and `ck` so far.
    pub fn transcript(&self) -> (&[u8], &[u8]) {
        self.engine.transcript()
    }
}

/// A client holding the server's static key and credentials, unverified. The
/// carrier first bytes of the payload may be used after [`Verify::accept`].
/// Dropping this value rejects the server.
pub struct Verify {
    engine: Engine,
    mode: RecordMode,
    framing: Framing,
    payload: Payload,
}

impl Verify {
    /// The server's static public key.
    pub fn peer_static(&self) -> &[u8] {
        self.engine
            .peer_static()
            .expect("message 2 carries the static key")
    }

    /// The payload of message 2, to read the credential from.
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    /// The core's check of message 2's proof against the verdict: with
    /// `proof_key`, the proof must be under that key and verify. Returns PQ
    /// authentication; with `require_pq_auth` its absence fails. Failures are
    /// `credentials_failed`.
    pub fn check_proof(
        &self,
        proof_key: Option<&KeyId>,
        require_pq_auth: bool,
    ) -> Result<bool, Error> {
        check_received(self.engine.peer_proof(), proof_key, require_pq_auth)
    }

    /// The host has verified the server.
    pub fn accept(self) -> Finish {
        Finish {
            engine: self.engine,
            mode: self.mode,
            framing: self.framing,
        }
    }

    #[cfg(feature = "test-vectors")]
    /// `h` and `ck` so far.
    pub fn transcript(&self) -> (&[u8], &[u8]) {
        self.engine.transcript()
    }
}

/// A client ready to write the third message.
pub struct Finish {
    engine: Engine,
    mode: RecordMode,
    framing: Framing,
}

impl Finish {
    #[cfg(feature = "test-vectors")]
    /// Sets the handshake's nonce to the reserved value.
    pub fn force_n(&mut self) {
        self.engine.force_n();
    }

    /// Writes the Finish and completes the handshake.
    pub fn write_finish(mut self, payload: &[u8]) -> Result<(Vec<u8>, Complete), Error> {
        let noise = write_plain(&mut self.engine, payload)?;
        let mut wire = Vec::new();
        frame(self.framing, &mut wire, &noise)?;
        Ok((wire, Complete::new(self.engine, self.mode, true)?))
    }

    /// Starts a Finish with a proof: `payload` ends with a proof item whose signature is
    /// a placeholder of the KeyAlg's length, replaced by [`SignFinish::finish`].
    pub fn write_finish_signed(mut self, payload: &[u8]) -> Result<SignFinish, Error> {
        let pending = Pending::begin(&mut self.engine, payload)?;
        Ok(SignFinish {
            engine: self.engine,
            mode: self.mode,
            framing: self.framing,
            pending,
        })
    }
}

/// A Finish waiting for the signature of its proof.
pub struct SignFinish {
    engine: Engine,
    mode: RecordMode,
    framing: Framing,
    pending: Pending,
}

impl SignFinish {
    /// What the proof signs: `"zmux-seal proof i" ‖ 0x00 ‖ h_p`.
    pub fn message(&self) -> &[u8] {
        &self.pending.message
    }

    /// Writes the Finish with `sig` and completes the handshake.
    pub fn finish(mut self, sig: &[u8]) -> Result<(Vec<u8>, Complete), Error> {
        let noise = self.pending.finish(&mut self.engine, sig)?;
        let mut wire = Vec::new();
        frame(self.framing, &mut wire, &noise)?;
        Ok((wire, Complete::new(self.engine, self.mode, true)?))
    }
}

/// What a server looks up once it has parsed a Hello.
#[derive(Clone, Copy)]
pub struct ResponderKeys<'a> {
    /// The pre-shared key, empty for a Profile without one.
    pub psk: &'a [u8],
    /// The static private key, empty for a Profile that sends none.
    pub static_secret: &'a [u8],
    /// The Binding in Bound mode, otherwise empty.
    pub binding: &'a [u8],
    /// The largest application data of a received message, in bytes; `None` sets no
    /// bound beyond the message. A local safety bound, not a protocol limit; the usual
    /// value is [`DEFAULT_MAX_APP_DATA`](crate::DEFAULT_MAX_APP_DATA).
    pub max_app_data: Option<usize>,
}

impl Default for ResponderKeys<'_> {
    /// No keys and the default bound on application data.
    fn default() -> Self {
        ResponderKeys {
            psk: &[],
            static_secret: &[],
            binding: &[],
            max_app_data: Some(crate::DEFAULT_MAX_APP_DATA),
        }
    }
}

/// A redacted `Debug` of a handshake state: its mode and framing, never its keys.
macro_rules! redacted_debug {
    ($($t:ident { $($f:ident),* }),* $(,)?) => {$(
        impl std::fmt::Debug for $t {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct(stringify!($t))
                    $(.field(stringify!($f), &self.$f))*
                    .finish_non_exhaustive()
            }
        }
    )*};
}

redacted_debug! {
    Initiator { profile, mode, framing },
    AwaitReply { mode, framing },
    Verify { mode, framing },
    Finish { mode, framing },
    SignFinish { mode, framing },
    ResponderReply { mode, framing },
    SignReply { mode, framing },
    AwaitFinish { mode },
    Complete { mode, initiator },
}

impl std::fmt::Debug for InitiatorConfig<'_> {
    /// The pre-shared key and the static key are redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiatorConfig")
            .field("profile", &self.profile)
            .field("mode", &self.mode)
            .field("framing", &self.framing)
            .field("handle", &self.handle)
            .field("binding", &self.binding)
            .field("max_app_data", &self.max_app_data)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for ResponderKeys<'_> {
    /// The pre-shared key and the static key are redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponderKeys")
            .field("binding", &self.binding)
            .field("max_app_data", &self.max_app_data)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for HandshakeExporter {
    /// The exporter secret is redacted.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeExporter").finish_non_exhaustive()
    }
}

/// A server entrance.
#[derive(Debug)]
pub struct Responder;

impl Responder {
    /// Reads Noise message 1 of a parsed Hello.
    pub fn read_hello(
        hello: &Hello<'_>,
        keys: ResponderKeys<'_>,
    ) -> Result<(ResponderReply, Payload), Error> {
        Self::build(hello, keys, None, None)
    }

    /// As [`Responder::read_hello`] with a fixed ephemeral key and, in a hybrid
    /// Profile, a fixed encapsulation randomness `m`, for the vectors.
    #[cfg(feature = "test-vectors")]
    pub fn read_hello_with_ephemeral(
        hello: &Hello<'_>,
        keys: ResponderKeys<'_>,
        e: &[u8],
        kem_random: &[u8],
    ) -> Result<(ResponderReply, Payload), Error> {
        let kem = fixed_kem(hello.profile, kem_random, false)?;
        Self::build(hello, keys, Some(e.into()), kem)
    }

    fn build(
        hello: &Hello<'_>,
        keys: ResponderKeys<'_>,
        e: Option<Secret>,
        kem: Option<Secret>,
    ) -> Result<(ResponderReply, Payload), Error> {
        let (profile, mode) = (hello.profile, hello.mode);
        // A Binding is empty or BINDING_LEN bytes; whether it suits the received Mode
        // is not judged here, and any disagreement is auth.
        if keys.psk.len() != profile.psk_len().unwrap_or(keys.psk.len())
            || keys.static_secret.len() != profile.0.dh.private_len
            || !matches!(keys.binding.len(), 0 | BINDING_LEN)
        {
            return Err(Error::InvalidConfig);
        }
        // A first message in Bound and no Binding here: refused, unread.
        if mode == RecordMode::Bound && keys.binding.is_empty() {
            return Err(Error::Auth);
        }
        let prologue = prologue(profile, mode, hello.handle, keys.binding);
        let mut engine = Engine::new(
            profile.0,
            false,
            &prologue,
            keys.psk.into(),
            keys.static_secret.into(),
            e,
            kem,
        );
        engine.set_max_app_data(keys.max_app_data);
        let known = engine.known_types();
        let raw = engine.read_message(hello.noise)?;
        let payload = engine.validate(raw, known)?;
        Ok((
            ResponderReply {
                engine,
                mode,
                framing: hello.framing,
            },
            payload,
        ))
    }
}

/// A server ready to write the Reply.
pub struct ResponderReply {
    engine: Engine,
    mode: RecordMode,
    framing: Framing,
}

impl ResponderReply {
    /// Starts a Reply with a proof: `payload` ends with a proof item whose signature is
    /// a placeholder of the KeyAlg's length, replaced by [`SignReply::finish`].
    pub fn write_reply_signed(mut self, payload: &[u8]) -> Result<SignReply, Error> {
        let pending = Pending::begin(&mut self.engine, payload)?;
        Ok(SignReply {
            engine: self.engine,
            mode: self.mode,
            framing: self.framing,
            pending,
        })
    }

    /// Writes the Reply.
    pub fn write_reply(mut self, payload: &[u8]) -> Result<(Vec<u8>, AwaitFinish), Error> {
        let noise = write_plain(&mut self.engine, payload)?;
        let mut wire = Vec::new();
        frame(self.framing, &mut wire, &noise)?;
        Ok((
            wire,
            AwaitFinish {
                engine: self.engine,
                mode: self.mode,
            },
        ))
    }

    #[cfg(feature = "test-vectors")]
    /// `h` and `ck` so far.
    pub fn transcript(&self) -> (&[u8], &[u8]) {
        self.engine.transcript()
    }
}

/// A Reply waiting for the signature of its proof.
pub struct SignReply {
    engine: Engine,
    mode: RecordMode,
    framing: Framing,
    pending: Pending,
}

impl SignReply {
    /// What the proof signs: `"zmux-seal proof r" ‖ 0x00 ‖ h_p`.
    pub fn message(&self) -> &[u8] {
        &self.pending.message
    }

    /// Writes the Reply with `sig`.
    pub fn finish(mut self, sig: &[u8]) -> Result<(Vec<u8>, AwaitFinish), Error> {
        let noise = self.pending.finish(&mut self.engine, sig)?;
        let mut wire = Vec::new();
        frame(self.framing, &mut wire, &noise)?;
        Ok((
            wire,
            AwaitFinish {
                engine: self.engine,
                mode: self.mode,
            },
        ))
    }
}

/// A server waiting for the Finish.
pub struct AwaitFinish {
    engine: Engine,
    mode: RecordMode,
}

impl AwaitFinish {
    #[cfg(feature = "test-vectors")]
    /// Sets the handshake's nonce to the reserved value.
    pub fn force_n(&mut self) {
        self.engine.force_n();
    }

    /// Reads Noise message 3, already cut from its frame. The client's identity
    /// and first bytes are delivered only through this success.
    pub fn read_finish(mut self, message: &[u8]) -> Result<(Complete, Payload), Error> {
        let known = self.engine.known_types();
        let raw = self.engine.read_message(message)?;
        let payload = self.engine.validate(raw, known)?;
        Ok((Complete::new(self.engine, self.mode, false)?, payload))
    }

    #[cfg(feature = "test-vectors")]
    /// `h` and `ck` so far.
    pub fn transcript(&self) -> (&[u8], &[u8]) {
        self.engine.transcript()
    }
}

/// A finished handshake: the exporter, the peer, and the record keys if Sealed.
pub struct Complete {
    finished: Finished,
    exporter_secret: Secret,
    mode: RecordMode,
    initiator: bool,
}

impl Complete {
    fn new(engine: Engine, mode: RecordMode, initiator: bool) -> Result<Complete, Error> {
        let finished = engine.finish();
        let exporter_secret = Secret::from(exporter_secret(
            Profile(finished.params),
            &finished.ck,
            &finished.h,
        )?);
        Ok(Complete {
            finished,
            exporter_secret,
            mode,
            initiator,
        })
    }

    /// The record mode.
    pub fn mode(&self) -> RecordMode {
        self.mode
    }

    /// The peer's static public key, if the pattern sends one.
    pub fn peer_static(&self) -> Option<&[u8]> {
        self.finished.peer_static.as_deref()
    }

    /// The core's check of the proof of the peer's last message against the verdict, as
    /// [`Verify::check_proof`]: at a server, message 3's.
    pub fn check_proof(
        &self,
        proof_key: Option<&KeyId>,
        require_pq_auth: bool,
    ) -> Result<bool, Error> {
        check_received(
            self.finished.peer_proof.as_ref(),
            proof_key,
            require_pq_auth,
        )
    }

    /// The handshake hash.
    pub fn handshake_hash(&self) -> &[u8] {
        &self.finished.h
    }

    /// `Export(label, context, n)` of this handshake.
    pub fn export(&self, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        export(
            self.finished.params.hash,
            &self.exporter_secret,
            label,
            context,
            len,
        )
    }

    /// The exporter alone, kept after [`Complete::into_records`].
    pub fn exporter_only(&self) -> HandshakeExporter {
        HandshakeExporter {
            hash: self.finished.params.hash,
            secret: self.exporter_secret.clone(),
        }
    }

    /// The record keys in Sealed mode; `None` otherwise, where records are raw.
    pub fn into_records(self) -> Option<(Sealer, Opener)> {
        if self.mode != RecordMode::Sealed {
            return None;
        }
        let cipher = (self.finished.params.cipher)();
        let (send, recv) = if self.initiator {
            (self.finished.c1, self.finished.c2)
        } else {
            (self.finished.c2, self.finished.c1)
        };
        Some((Sealer::new(cipher, send), Opener::new(cipher, recv)))
    }

    #[cfg(feature = "test-vectors")]
    /// `h` and `ck` after the last message.
    pub fn transcript(&self) -> (&[u8], &[u8]) {
        (&self.finished.h, &self.finished.ck)
    }

    #[cfg(feature = "test-vectors")]
    /// `(c1, c2)` of the split.
    pub fn split(&self) -> (&[u8], &[u8]) {
        (&self.finished.c1, &self.finished.c2)
    }

    #[cfg(feature = "test-vectors")]
    /// The exporter secret.
    pub fn exporter_secret(&self) -> &[u8] {
        &self.exporter_secret
    }
}

/// The exporter of a finished handshake.
pub struct HandshakeExporter {
    hash: &'static zmux::proto::seal::Hash,
    secret: Secret,
}

impl HandshakeExporter {
    /// `Export(label, context, n)` of the handshake.
    pub fn export(&self, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        export(self.hash, &self.secret, label, context, len)
    }
}
