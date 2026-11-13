//! Who a peer is: a [`Verifier`] judges the one opaque credential of a message, and a
//! [`Gate`] is the server's host. Credential formats, roots, revocation and time are the
//! host's: the core carries the credential and hands it over with what it knows of the
//! handshake.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;

use zmux::Role;
use zmux_seal_proto::{KEYALG_X25519, KeyId, Profile, SigningKey, key_id};

/// A boxed future of a host's trust decision.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A credential: its type and its bytes, opaque to the core. Type 0 is reserved.
pub type Credential = (u64, Vec<u8>);

/// What a [`Verifier`] is told about a peer.
#[derive(Debug, Clone, Copy)]
pub struct VerifyInput<'a> {
    /// The role expected of the peer: [`Role::Server`] when a client verifies message 2,
    /// [`Role::Client`] when a server verifies message 3; never [`Role::Auto`].
    pub role: Role,
    /// The Profile of the handshake.
    pub profile: Profile,
    /// The peer's static key of the handshake.
    pub peer_static: &'a [u8],
    /// The identity of the pre-shared key, the Handle, when the Profile has one.
    pub psk_identity: Option<&'a [u8]>,
    /// The peer's credential, when its message carried one: (type, bytes).
    pub credential: Option<(u64, &'a [u8])>,
    /// The application data the peer sent so far, in message order.
    pub peer_app_data: &'a [AppData],
    /// The local application's label of the listener or the dial, as SNI or ALPN would
    /// select: the host's own, never sent.
    pub local_context: &'a [u8],
}

/// Application handshake data of one message: opaque bytes with the message that
/// carried them and what that message protects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppData {
    /// Message 1, 2 or 3.
    pub message: u8,
    /// The bytes.
    pub data: Vec<u8>,
    /// Encrypted under keys with forward secrecy. Message 1 (Profiles 1 and 3) is under
    /// the pre-shared key alone: whoever learns it later reads the data, and it can be
    /// replayed like early data.
    pub forward_secret: bool,
    /// The sender passed this end's verification, so the data is that of the peer the
    /// verdict names. It is false in every [`VerifyInput`], since the verification is
    /// still running, and true in a [`Peer`](crate::Peer)'s data of messages 2 and 3 once
    /// the peer passed. Data of message 3 is not to be acted on with side effects before
    /// the server has admitted the client.
    pub authenticated: bool,
}

impl AppData {
    /// The data of message `message`, `None` when it had none: an empty item is no data.
    pub(crate) fn of(message: u8, data: Option<&[u8]>) -> Option<AppData> {
        let data = data.filter(|d| !d.is_empty())?;
        Some(AppData {
            message,
            data: data.to_vec(),
            forward_secret: message > 1,
            authenticated: false,
        })
    }

    /// Marks the data of messages 2 and 3 as the verified peer's; message 1 data
    /// authenticates no more than knowledge of the pre-shared key.
    pub(crate) fn mark_authenticated(data: &mut [AppData]) {
        for d in data {
            d.authenticated = d.message > 1;
        }
    }
}

/// What an [`AppDataSource`] knows when asked for the data of a message: the message
/// (1, 2 or 3) and, for messages 2 and 3, what is known of the peer by then (for message
/// 3, the input its verifier judged; for message 2, no static key yet).
#[derive(Debug, Clone, Copy)]
pub struct AppDataRequest<'a> {
    /// The message: a client's 1 (Profiles 1 and 3) and 3, a server's 2.
    pub message: u8,
    /// What is known of the peer.
    pub peer: Option<&'a VerifyInput<'a>>,
    /// For the client's message 3, the verdict of its verifier on the server; `None`
    /// otherwise, and without a verifier.
    pub verdict: Option<&'a VerifyVerdict>,
}

/// Supplies the application data of the messages an end sends. An error ends the
/// handshake; empty data sends nothing. It runs within the handshake's time limit.
pub type AppDataSource = std::sync::Arc<
    dyn Fn(&AppDataRequest<'_>) -> BoxFuture<'static, Result<Vec<u8>, VerifyError>> + Send + Sync,
>;

/// Asks `source` for the data of a request; none without a source.
pub(crate) async fn ask_app_data(
    source: Option<&AppDataSource>,
    request: AppDataRequest<'_>,
) -> Result<Vec<u8>, VerifyError> {
    match source {
        Some(f) => f(&request).await,
        None => Ok(Vec::new()),
    }
}

/// Who a verified peer is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Principal {
    /// A peer named by its static key.
    StaticKey(Vec<u8>),
    /// A host's own kind.
    Other(u16, Vec<u8>),
}

/// A verifier's acceptance.
#[derive(Clone)]
pub struct VerifyVerdict {
    /// Who the peer is.
    pub principal: Principal,
    /// The KeyId of the peer's proof key: the message must then carry a proof under it
    /// that verifies over the transcript, or the handshake fails. `None`: a proof is not
    /// looked at.
    pub proof_key: Option<KeyId>,
    /// The verifier's own result, for the host: it comes back on the [`Peer`](crate::Peer).
    pub value: Option<zmux::AdmittedValue>,
}

impl std::fmt::Debug for VerifyVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyVerdict")
            .field("principal", &self.principal)
            .field("proof_key", &self.proof_key)
            .field("value", &self.value.as_ref().map(|_| ".."))
            .finish()
    }
}

impl VerifyVerdict {
    /// A verdict on `principal` that names no proof key and holds no value.
    pub fn new(principal: Principal) -> Self {
        Self {
            principal,
            proof_key: None,
            value: None,
        }
    }
}

/// Why a verifier did not accept a peer. Both close the carrier; only a rejection is a
/// failure of the peer and goes to the reject policy.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyError {
    /// The peer is not trusted.
    Rejected(String),
    /// The verifier could not decide now, for example its own service is unreachable: no
    /// fault of the peer.
    Unavailable(String),
}

impl VerifyError {
    /// A rejection with a reason.
    pub fn rejected(why: impl Into<String>) -> Self {
        Self::Rejected(why.into())
    }

    /// A temporary failure, the verifier unavailable, with a reason.
    pub fn unavailable(why: impl Into<String>) -> Self {
        Self::Unavailable(why.into())
    }

    /// Whether this is a rejection of the peer.
    pub fn is_rejection(&self) -> bool {
        matches!(self, Self::Rejected(_))
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(why) => write!(f, "peer rejected: {why}"),
            Self::Unavailable(why) => write!(f, "verification unavailable: {why}"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Decides whether a peer is trusted: called once per handshake message that identifies
/// the peer. It does not see the transcript: the handshake checks the proof the verdict
/// names. A panic counts as a rejection.
pub trait Verifier: Send + Sync {
    /// Judges a peer.
    fn verify<'a>(
        &'a self,
        input: VerifyInput<'a>,
    ) -> BoxFuture<'a, Result<VerifyVerdict, VerifyError>>;

    /// Whether this verifier trusts an X25519 static key alone, naming no proof key: an
    /// end that requires PQ authentication refuses it as a configuration error.
    fn pins_static_key_alone(&self) -> bool {
        false
    }
}

/// Runs `verifier` on `input`; a panic, when the future is made or while it runs, is a
/// rejection.
pub(crate) async fn judge(
    verifier: &dyn Verifier,
    input: VerifyInput<'_>,
) -> Result<VerifyVerdict, VerifyError> {
    let panicked = || VerifyError::rejected("the verifier panicked");
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| verifier.verify(input))) {
        Ok(f) => CatchUnwind(f).await.unwrap_or_else(|| Err(panicked())),
        Err(_) => Err(panicked()),
    }
}

/// A future whose panic is caught: `None`.
struct CatchUnwind<F>(F);

impl<F: Future + Unpin> Future for CatchUnwind<F> {
    type Output = Option<F::Output>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let f = &mut self.0;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| Pin::new(f).poll(cx))) {
            Ok(std::task::Poll::Ready(v)) => std::task::Poll::Ready(Some(v)),
            Ok(std::task::Poll::Pending) => std::task::Poll::Pending,
            Err(_) => std::task::Poll::Ready(None),
        }
    }
}

/// Trusts the one static key with this KeyId (of KeyAlg 1, X25519): the key itself; a
/// credential is not looked at. With a proof key, the peer must also prove the transcript
/// with that key.
#[derive(Debug, Clone, Copy)]
pub struct PinVerifier {
    pin: KeyId,
    proof_key: Option<KeyId>,
}

impl PinVerifier {
    /// Trusts the key of `pin`.
    pub fn new(pin: KeyId) -> Self {
        Self {
            pin,
            proof_key: None,
        }
    }

    /// Trusts the key of `pin` with a proof under the key of `proof_key`.
    pub fn with_proof_key(pin: KeyId, proof_key: KeyId) -> Self {
        Self {
            pin,
            proof_key: Some(proof_key),
        }
    }
}

impl Verifier for PinVerifier {
    fn verify<'a>(
        &'a self,
        input: VerifyInput<'a>,
    ) -> BoxFuture<'a, Result<VerifyVerdict, VerifyError>> {
        Box::pin(async move {
            if static_key_id(input.peer_static) != self.pin {
                return Err(VerifyError::rejected(
                    "the static key is not the pinned one",
                ));
            }
            Ok(VerifyVerdict {
                principal: Principal::StaticKey(input.peer_static.to_vec()),
                proof_key: self.proof_key,
                value: None,
            })
        })
    }

    fn pins_static_key_alone(&self) -> bool {
        self.proof_key.is_none()
    }
}

/// Makes the proof of a handshake message (a signature over its transcript) once per
/// handshake; the key may live in another process. Signatures are hedged.
pub trait Signer: Send + Sync {
    /// The KeyAlg and the public key of the signing key.
    fn proof_key(&self) -> (u64, &[u8]);

    /// Signs `message`, the M of the proof; the signature has the KeyAlg's length.
    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, std::io::Result<Vec<u8>>>;
}

/// A [`Signer`] of a key in this process.
#[derive(Debug)]
pub struct KeySigner(pub SigningKey);

impl Signer for KeySigner {
    fn proof_key(&self) -> (u64, &[u8]) {
        (self.0.key_alg(), self.0.public())
    }

    fn sign<'a>(&'a self, message: &'a [u8]) -> BoxFuture<'a, std::io::Result<Vec<u8>>> {
        let sig = self.0.sign(message).map_err(std::io::Error::other);
        Box::pin(async move { sig })
    }
}

/// The rule of an end that requires PQ authentication of its peer: it verifies the peer,
/// and not with a pin of a static key alone.
pub(crate) fn check_pq_auth(
    require: bool,
    verifier: Option<&std::sync::Arc<dyn Verifier>>,
) -> Result<(), ConfigError> {
    if !require {
        return Ok(());
    }
    match verifier {
        None => Err(ConfigError("require_pq_auth without a verifier")),
        Some(v) => zmux_seal_proto::check_pin_pq_auth(true, !v.pins_static_key_alone())
            .map_err(|_| ConfigError("require_pq_auth with a pin that names no proof key")),
    }
}

/// The X25519 public key of a static secret, as the peer sees it and
/// [`static_key_id`] names it.
pub fn static_public(secret: &[u8; 32]) -> [u8; 32] {
    zmux::proto::seal::kex::x25519_public(secret)
        .ok()
        .and_then(|k| k.try_into().ok())
        .expect("a 32-byte X25519 secret has a 32-byte public key")
}

/// The KeyId of a static key (KeyAlg 1), for a pin.
pub fn static_key_id(public: &[u8]) -> KeyId {
    key_id(KEYALG_X25519, public)
}

/// What a server admits after message 3 verified.
#[derive(Debug, Clone, Copy)]
pub struct Admission<'a> {
    /// The Handle of the handshake, empty for a Profile without a pre-shared key.
    pub handle: &'a [u8],
    /// What the handshake learned of the client: its static key, credential, verdict (when
    /// the server verifies clients), application data and the post-quantum facts.
    pub peer: &'a crate::Peer,
}

/// The server's host: who may establish.
pub trait Gate: Send + Sync {
    /// The pre-shared key of a Handle. It runs before any authentication and has no side
    /// effect; a host negatively caches what it looks up.
    fn resolve<'a>(
        &'a self,
        handle: &'a [u8],
        source: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<Vec<u8>, VerifyError>>;

    /// The server's credential for message 2, if any, chosen by the Handle, the Profile and
    /// the local context.
    fn credential<'a>(
        &'a self,
        handle: &'a [u8],
        profile: Profile,
        local_context: &'a [u8],
        source: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<Option<Credential>, VerifyError>>;

    /// Admits a client after message 3 verified: every server state that may land only
    /// after a handshake passed is committed here. An error closes the carrier.
    fn commit<'a>(
        &'a self,
        admission: Admission<'a>,
        source: Option<SocketAddr>,
    ) -> BoxFuture<'a, Result<zmux::AdmittedValue, VerifyError>>;
}

/// A local configuration mistake, named: nothing was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigError(pub &'static str);

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid secure carrier configuration: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}
