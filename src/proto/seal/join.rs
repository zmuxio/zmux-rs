//! Join: proves that a carrier belongs to an existing session.
//!
//! ```text
//! joiner:   Joiner::new -> write_hello -> HelloSent::read_reply
//!             -> Proven::write_confirm -> Joined
//! acceptor: JoinHello::parse -> Acceptor::open -> Unconfirmed::write_reply
//!             -> AwaitConfirm::read_confirm -> Confirmed
//! ```

use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use super::cipher::AES_256_GCM;
#[cfg(feature = "seal-chacha")]
use super::cipher::chacha::CHACHA20_POLY1305;
use super::crypto::session_crypto_hash;
use super::group::{Group, GroupInitiator, SharedSecrets, combine};
use super::payload::{
    JOIN_HELLO_KNOWN, JOIN_HELLO_REQUIRED, JOIN_REPLY_KNOWN, JOIN_REPLY_REQUIRED, KEY_SHARE_ITEM,
};
use super::wire::{cut_frame, cut_unit, frame, put_varint, read_shortest};
use super::{
    Cipher, Error, Framing, Hash, Opener, Payload, RecordMode, SHA256, Sealer, Secret, export,
    fill_random,
};

const HELLO_TYPE: u8 = 0x02;
/// The first byte of a Reply.
pub const REPLY_TYPE: u8 = 0x03;
const MAX_UNIT: usize = u16::MAX as usize;
const BINDING_LEN: usize = 32;

/// One row of the Suite table.
#[derive(Debug)]
pub struct Suite {
    value: u64,
    cipher: &'static Cipher,
    hash: &'static Hash,
    r_len: usize,
}

static SUITES: &[Suite] = &[
    Suite {
        value: 1,
        cipher: &AES_256_GCM,
        hash: &SHA256,
        r_len: 32,
    },
    #[cfg(feature = "seal-chacha")]
    Suite {
        value: 2,
        cipher: &CHACHA20_POLY1305,
        hash: &SHA256,
        r_len: 32,
    },
];

impl Suite {
    /// The AEAD's tag length.
    pub fn tag_len(&self) -> usize {
        self.cipher.tag_len()
    }

    /// The hash output's length.
    pub fn hash_len(&self) -> usize {
        self.hash.out_len()
    }

    /// The Suite with this value, if this build declares it.
    pub fn from_value(value: u64) -> Option<&'static Suite> {
        SUITES.iter().find(|s| s.value == value)
    }

    /// Every Suite of this build.
    pub fn all() -> impl Iterator<Item = &'static Suite> {
        SUITES.iter()
    }

    /// The Suite value.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// The AEAD.
    pub fn cipher(&self) -> &'static Cipher {
        self.cipher
    }

    /// The hash.
    pub fn hash(&self) -> &'static Hash {
        self.hash
    }

    /// The length of R.
    pub fn r_len(&self) -> usize {
        self.r_len
    }
}

/// Whether this machine has AES hardware, by which a joiner prefers a Suite.
pub fn has_aes_hardware() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
            && std::arch::is_x86_feature_detected!("pclmulqdq")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// The joiner's role in the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JoinRole {
    /// The session's initiator.
    Initiator,
    /// The session's responder.
    Responder,
}

/// `join_psk[e]_x` of a role from the secret of epoch e and `session_crypto`: always
/// HKDF-Expand with SHA-256, to the Suite's `HashLen`, the Suite in the info.
pub fn derive_join_psk(
    suite: &Suite,
    epoch_secret: &[u8],
    role: JoinRole,
    session_crypto: &[u8],
) -> Result<Vec<u8>, Error> {
    expand_join_psk(
        suite.value,
        epoch_secret,
        role,
        session_crypto,
        suite.hash.out_len(),
    )
}

/// The Expand of [`derive_join_psk`] for a Suite value and an output length: what a
/// Suite with another `HashLen` would take.
pub fn expand_join_psk(
    suite: u64,
    epoch_secret: &[u8],
    role: JoinRole,
    session_crypto: &[u8],
    len: usize,
) -> Result<Vec<u8>, Error> {
    let label: &[u8] = match role {
        JoinRole::Initiator => b"zmux join i",
        JoinRole::Responder => b"zmux join r",
    };
    let mut info = [label, &session_crypto_hash(session_crypto)].concat();
    put_varint(&mut info, suite);
    SHA256.expand(epoch_secret, &info, len)
}

/// `R`, bound to the message it goes in: `head` is the bytes before R and `payload`
/// the plaintext. Every message takes a new one.
pub fn join_r(
    suite: &Suite,
    psk: &[u8],
    attempt: u64,
    random: &[u8],
    head: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let message = suite.hash.hash(&[head, payload]);
    let mut r = suite.hash.hmac(
        psk,
        &[b"zmux join nonce", &attempt.to_be_bytes(), random, &message],
    );
    r.truncate(suite.r_len);
    r
}

static ATTEMPT: AtomicU64 = AtomicU64::new(0);

/// The attempt counter and random bytes of one R.
fn fresh_random(suite: &Suite) -> Result<(u64, Vec<u8>), Error> {
    let mut random = vec![0; suite.r_len];
    fill_random(&mut random)?;
    Ok((ATTEMPT.fetch_add(1, Ordering::Relaxed), random))
}

fn with_tag<T>(suite: &Suite, ciphertext: &[u8], open: impl FnOnce() -> T) -> Result<T, Error> {
    if ciphertext.len() < suite.cipher.tag_len() {
        return Err(Error::Malformed);
    }
    Ok(open())
}

fn expand_labeled(suite: &Suite, prk: &[u8], label: &[u8], th: &[u8], len: usize) -> Secret {
    suite
        .hash
        .expand(prk, &[label, th].concat(), len)
        .expect("PRK length and output length come from the table")
        .into()
}

fn transcript_start(suite: &Suite, prefix: &[u8], binding: &[u8]) -> Vec<u8> {
    suite.hash.hash(&[prefix, binding])
}

/// The Join key schedule after the Reply.
#[derive(Clone)]
struct Keys {
    #[cfg(feature = "test-hooks")]
    th2: Vec<u8>,
    th3: Vec<u8>,
    #[cfg(feature = "test-hooks")]
    k1: Secret,
    #[cfg(feature = "test-hooks")]
    hs: Secret,
    #[cfg(feature = "test-hooks")]
    ss: Vec<Secret>,
    key_i2r: Secret,
    key_r2i: Secret,
    mac_key: Secret,
    exporter_secret: Secret,
}

impl Keys {
    fn new(
        suite: &Suite,
        psk: &[u8],
        th2: Vec<u8>,
        k1: Secret,
        reply_ct: &[u8],
        secrets: SharedSecrets,
    ) -> Keys {
        let (key_len, hash_len) = (suite.cipher.key_len(), suite.hash.out_len());
        let th3 = suite.hash.hash(&[&th2, reply_ct]);
        let hs = combine(suite.hash, psk, secrets.as_slice());
        // Kept only for the test hooks; wiped here otherwise.
        #[cfg(not(feature = "test-hooks"))]
        drop((k1, secrets));
        Keys {
            key_i2r: expand_labeled(suite, &hs, b"i2r", &th3, key_len),
            key_r2i: expand_labeled(suite, &hs, b"r2i", &th3, key_len),
            mac_key: expand_labeled(suite, &hs, b"mac", &th3, hash_len),
            exporter_secret: expand_labeled(suite, &hs, b"exporter", &th3, hash_len),
            #[cfg(feature = "test-hooks")]
            th2,
            th3,
            #[cfg(feature = "test-hooks")]
            k1,
            #[cfg(feature = "test-hooks")]
            hs,
            #[cfg(feature = "test-hooks")]
            ss: secrets.as_slice().to_vec(),
        }
    }

    fn confirm_tag(&self, suite: &Suite) -> Vec<u8> {
        suite.hash.hmac(&self.mac_key, &[b"confirm", &self.th3])
    }
}

/// The inner values of a Join, for the vectors.
#[cfg(feature = "test-hooks")]
#[derive(Clone, Debug)]
pub struct Schedule {
    /// `th`.
    pub th: Vec<u8>,
    /// `th2`.
    pub th2: Vec<u8>,
    /// `th3`.
    pub th3: Vec<u8>,
    /// `k0`.
    pub k0: Vec<u8>,
    /// `k1`.
    pub k1: Vec<u8>,
    /// The shared secrets of the Group, in order.
    pub ss: Vec<Vec<u8>>,
    /// `hs`.
    pub hs: Vec<u8>,
    /// `key_i2r`.
    pub key_i2r: Vec<u8>,
    /// `key_r2i`.
    pub key_r2i: Vec<u8>,
    /// `mac_key`.
    pub mac_key: Vec<u8>,
    /// `exporter_secret`.
    pub exporter_secret: Vec<u8>,
    /// `confirm_tag`.
    pub confirm_tag: Vec<u8>,
}

/// The ModeByte of a Hello: the Mode in bits 0-1 and the key phase in bit 7.
pub fn mode_byte(mode: RecordMode, phase: u8) -> u8 {
    mode.byte() | (phase & 1) << 7
}

/// Parses a ModeByte: bits 2-6 set, or a reserved Mode, is `bad_flags`.
pub fn parse_mode_byte(byte: u8) -> Result<(RecordMode, u8), Error> {
    Ok((RecordMode::from_byte(byte & 0x7f)?, byte >> 7))
}

/// The key share item a message carries in place of its own, for the vectors and the
/// conformance runner: only the test hooks take one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShareOverride {
    /// No key share item.
    Missing,
    /// This value of the item, `Group ‖ Share`, as it is.
    Value(Vec<u8>),
    /// The payload given already holds the key share item, wherever it is.
    InPayload,
}

/// Appends the key share item of `group` and `share`: its type is above every other type a
/// Hello or a Reply knows.
fn push_key_share(payload: &[u8], group: u64, share: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(share.len() + 8);
    put_varint(&mut value, group);
    value.extend_from_slice(share);
    push_item(payload, &value)
}

fn push_item(payload: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = payload.to_vec();
    put_varint(&mut out, KEY_SHARE_ITEM);
    put_varint(&mut out, value.len() as u64);
    out.extend_from_slice(value);
    out
}

/// The key share of a received payload: `missing_field` when absent; `bad_field` when its
/// Group is not among `usable` or its share is not the length of that Group and the
/// sender's role (`initiator` for a Hello).
fn received_share<'p>(
    payload: &'p Payload,
    usable: &[u64],
    initiator: bool,
) -> Result<(&'static Group, &'p [u8]), Error> {
    let (value, share) = payload.key_share().ok_or(Error::MissingField)?;
    let group = usable
        .contains(&value)
        .then(|| Group::from_value(value))
        .flatten()
        .ok_or(Error::BadField)?;
    if share.len() != group.share_len(initiator) {
        return Err(Error::BadField);
    }
    Ok((group, share))
}

/// What a joiner brings.
#[derive(Clone, Copy)]
pub struct JoinConfig<'a> {
    /// The Suite.
    pub suite: &'static Suite,
    /// The Group of the key share.
    pub group: &'static Group,
    /// The record mode.
    pub mode: RecordMode,
    /// The key phase: the parity of the epoch whose `join_psk` this is.
    pub phase: u8,
    /// The carrier's framing.
    pub framing: Framing,
    /// The session's Locator, 1 to 255 bytes.
    pub locator: &'a [u8],
    /// `join_psk` of the joiner's role.
    pub psk: &'a [u8],
    /// The Binding exactly when Mode is Bound, otherwise empty.
    pub binding: &'a [u8],
}

/// A joiner before its Hello.
pub struct Joiner {
    suite: &'static Suite,
    group: &'static Group,
    mode: RecordMode,
    phase: u8,
    framing: Framing,
    locator: Vec<u8>,
    psk: Secret,
    binding: Vec<u8>,
    fixed_random: Option<(u64, Vec<u8>)>,
    #[cfg(feature = "test-hooks")]
    fixed_kex: Option<(Vec<u8>, Vec<u8>)>,
}

impl Joiner {
    /// Checks the configuration.
    pub fn new(config: JoinConfig<'_>) -> Result<Joiner, Error> {
        let JoinConfig {
            suite,
            group,
            mode,
            phase,
            framing,
            locator,
            psk,
            binding,
        } = config;
        let locator_fits = (1..=usize::from(u8::MAX)).contains(&locator.len());
        let binding_fits = if mode == RecordMode::Bound {
            binding.len() == BINDING_LEN
        } else {
            binding.is_empty()
        };
        if !locator_fits
            || !binding_fits
            || !mode.joinable()
            || psk.len() != suite.hash.out_len()
            || phase > 1
        {
            return Err(Error::InvalidConfig);
        }
        Ok(Joiner {
            suite,
            group,
            mode,
            phase,
            framing,
            locator: locator.to_vec(),
            psk: psk.into(),
            binding: binding.to_vec(),
            fixed_random: None,
            #[cfg(feature = "test-hooks")]
            fixed_kex: None,
        })
    }

    /// As [`Joiner::new`] with a fixed attempt and random bytes, for the vectors.
    #[cfg(feature = "test-hooks")]
    pub fn with_random(
        config: JoinConfig<'_>,
        attempt: u64,
        random: &[u8],
    ) -> Result<Joiner, Error> {
        let mut joiner = Joiner::new(config)?;
        joiner.fixed_random = Some((attempt, random.to_vec()));
        Ok(joiner)
    }

    /// Fixes the X25519 private key and, in Group 2, the ML-KEM seed `(d, z)` of the share,
    /// for the vectors.
    #[cfg(feature = "test-hooks")]
    #[must_use]
    pub fn with_kex(mut self, x: &[u8], kem_seed: &[u8]) -> Joiner {
        self.fixed_kex = Some((x.to_vec(), kem_seed.to_vec()));
        self
    }

    /// Writes the Hello with the key share of its Group after the items of `payload`,
    /// which must hold the join pipe.
    pub fn write_hello(self, payload: &[u8]) -> Result<(Vec<u8>, HelloSent), Error> {
        Payload::check_outgoing(payload, JOIN_HELLO_KNOWN)?;
        self.write_hello_payload(payload, None)
    }

    /// As [`Joiner::write_hello`], also with items of types a sender does
    /// not send (unassigned ones), which the vectors use to show that a
    /// receiver skips them, and optionally another key share item.
    #[cfg(feature = "test-hooks")]
    pub fn write_hello_with_unknown(
        self,
        payload: &[u8],
        share: Option<ShareOverride>,
    ) -> Result<(Vec<u8>, HelloSent), Error> {
        self.write_hello_payload(payload, share)
    }

    #[cfg(feature = "test-hooks")]
    fn initiate(&self) -> Result<(Vec<u8>, GroupInitiator), Error> {
        match &self.fixed_kex {
            Some((x, seed)) => self.group.initiate_with(x, seed),
            None => self.group.initiate(),
        }
    }

    #[cfg(not(feature = "test-hooks"))]
    fn initiate(&self) -> Result<(Vec<u8>, GroupInitiator), Error> {
        self.group.initiate()
    }

    fn write_hello_payload(
        self,
        payload: &[u8],
        #[cfg_attr(not(feature = "test-hooks"), allow(unused_variables))] share: Option<
            ShareOverride,
        >,
    ) -> Result<(Vec<u8>, HelloSent), Error> {
        let (own_share, kex) = self.initiate()?;
        #[cfg(feature = "test-hooks")]
        let given = payload;
        let payload = push_key_share(payload, self.group.value(), &own_share);
        #[cfg(feature = "test-hooks")]
        let payload = match share {
            None => payload,
            Some(ShareOverride::InPayload) => given.to_vec(),
            Some(ShareOverride::Missing) => {
                payload[..payload.len() - item_len(&own_share, self.group)].to_vec()
            }
            Some(ShareOverride::Value(v)) => {
                let head = &payload[..payload.len() - item_len(&own_share, self.group)];
                push_item(head, &v)
            }
        };
        let parsed = Payload::validate(payload.clone(), JOIN_HELLO_KNOWN)?;
        if !parsed.has(JOIN_HELLO_REQUIRED) {
            return Err(Error::InvalidConfig);
        }
        let suite = self.suite;
        let (attempt, random) = match self.fixed_random {
            Some(fixed) => fixed,
            None => fresh_random(suite)?,
        };
        let mut wire = vec![HELLO_TYPE];
        put_varint(&mut wire, suite.value);
        wire.push(mode_byte(self.mode, self.phase));
        wire.push(self.locator.len() as u8);
        wire.extend_from_slice(&self.locator);
        let r = join_r(suite, &self.psk, attempt, &random, &wire, &payload);
        wire.extend_from_slice(&r);
        let th = transcript_start(suite, &wire, &self.binding);
        let k0 = expand_labeled(suite, &self.psk, b"hello", &th, suite.cipher.key_len());
        let ciphertext = suite.cipher.seal(&k0, 0, b"", &payload);
        frame(self.framing, &mut wire, &ciphertext)?;
        let next = HelloSent {
            suite,
            mode: self.mode,
            framing: self.framing,
            psk: self.psk,
            th,
            #[cfg(feature = "test-hooks")]
            k0,
            hello_ct: ciphertext,
            kex,
        };
        Ok((wire, next))
    }
}

/// The encoded length of a key share item.
#[cfg(feature = "test-hooks")]
fn item_len(share: &[u8], group: &Group) -> usize {
    let mut value = Vec::new();
    put_varint(&mut value, group.value());
    let len = value.len() + share.len();
    let mut head = Vec::new();
    put_varint(&mut head, KEY_SHARE_ITEM);
    put_varint(&mut head, len as u64);
    head.len() + len
}

/// The encoded length of the key share item of `group` for a role: what a message of that
/// role adds for it.
pub fn key_share_item_len(group: &Group, initiator: bool) -> usize {
    let mut value = Vec::new();
    put_varint(&mut value, group.value());
    let len = value.len() + group.share_len(initiator);
    let mut head = Vec::new();
    put_varint(&mut head, KEY_SHARE_ITEM);
    put_varint(&mut head, len as u64);
    head.len() + len
}

/// Cuts a Reply: `R_r`, the ciphertext and the bytes consumed.
pub fn parse_reply<'a>(
    suite: &Suite,
    framing: Framing,
    input: &'a [u8],
) -> Result<(&'a [u8], &'a [u8], usize), Error> {
    let stream = framing == Framing::ByteStream;
    let cut = |need| {
        if stream {
            Error::Incomplete { need }
        } else {
            Error::Malformed
        }
    };
    if *input.first().ok_or(cut(1))? != REPLY_TYPE {
        return Err(Error::Malformed);
    }
    let header = 1 + suite.r_len;
    let r = input.get(1..header).ok_or(cut(header))?;
    let (ciphertext, consumed) = if stream {
        cut_frame(input, header)?
    } else {
        if input.len() - header > MAX_UNIT {
            return Err(Error::TooLarge);
        }
        (&input[header..], input.len())
    };
    Ok((r, ciphertext, consumed))
}

/// A joiner waiting for the Reply. It holds the private values of its key share.
pub struct HelloSent {
    suite: &'static Suite,
    mode: RecordMode,
    framing: Framing,
    psk: Secret,
    th: Vec<u8>,
    #[cfg(feature = "test-hooks")]
    k0: Secret,
    hello_ct: Vec<u8>,
    kex: GroupInitiator,
}

impl HelloSent {
    /// Whether `input` holds a whole Reply: `Incomplete` while it wants more. Any other
    /// error is what [`HelloSent::read_reply`] would return.
    pub fn ready(&self, input: &[u8]) -> Result<(), Error> {
        parse_reply(self.suite, self.framing, input).map(|_| ())
    }

    /// Reads the Reply at the start of `input`: its AEAD, its payload with the key share
    /// of the Hello's Group, and only then the key exchange, whose refusal is `kex`.
    /// Returns the proven state and the bytes consumed; records may follow on a byte
    /// stream.
    pub fn read_reply(self, input: &[u8]) -> Result<(Proven, usize), Error> {
        let suite = self.suite;
        let (r, ciphertext, consumed) = parse_reply(suite, self.framing, input)?;
        let th2 = suite.hash.hash(&[&self.th, &self.hello_ct, r]);
        let k1 = expand_labeled(suite, &self.psk, b"reply", &th2, suite.cipher.key_len());
        let raw = with_tag(suite, ciphertext, || {
            suite.cipher.open(&k1, 0, b"", ciphertext)
        })??;
        let payload = Payload::validate(raw, JOIN_REPLY_KNOWN)?;
        if !payload.has(JOIN_REPLY_REQUIRED) {
            return Err(Error::MissingField);
        }
        let group = self.kex.group();
        let (_, share) = received_share(&payload, &[group.value()], false)?;
        let secrets = self.kex.finish(share)?;
        let keys = Keys::new(suite, &self.psk, th2, k1, ciphertext, secrets);
        let proven = Proven {
            suite,
            mode: self.mode,
            framing: self.framing,
            #[cfg(feature = "test-hooks")]
            th: self.th,
            #[cfg(feature = "test-hooks")]
            k0: self.k0,
            keys,
            payload,
        };
        Ok((proven, consumed))
    }
}

/// A joiner whose Reply passed. Confirm comes next, after any local delay.
pub struct Proven {
    suite: &'static Suite,
    mode: RecordMode,
    framing: Framing,
    #[cfg(feature = "test-hooks")]
    th: Vec<u8>,
    #[cfg(feature = "test-hooks")]
    k0: Secret,
    keys: Keys,
    payload: Payload,
}

impl Proven {
    /// The record mode.
    pub fn mode(&self) -> RecordMode {
        self.mode
    }

    /// The Reply's payload, with the decision and return frames.
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Writes Confirm with `zeros` zero bytes: nothing in Bound.
    pub fn write_confirm(self, zeros: usize) -> Result<(Vec<u8>, Finished), Error> {
        let suite = self.suite;
        let mut wire = Vec::new();
        let mut records = None;
        match self.mode {
            RecordMode::Sealed => {
                let mut sealer = Sealer::new(suite.cipher, self.keys.key_i2r.clone());
                frame(self.framing, &mut wire, &sealer.seal(&vec![0; zeros])?)?;
                records = Some((sealer, Opener::new(suite.cipher, self.keys.key_r2i.clone())));
            }
            RecordMode::Trusted => {
                let mut body = self.keys.confirm_tag(suite);
                body.resize(body.len() + zeros, 0);
                frame(self.framing, &mut wire, &body)?;
            }
            // Unmanaged never reaches a join: `Joiner::new` refuses it and
            // no Hello parses to it.
            RecordMode::Bound | RecordMode::Unmanaged => {}
        }
        let done = Finished {
            suite,
            mode: self.mode,
            #[cfg(feature = "test-hooks")]
            th: self.th,
            #[cfg(feature = "test-hooks")]
            k0: self.k0,
            keys: self.keys,
            records,
        };
        Ok((wire, done))
    }
}

/// A finished Join on either end: the exporter, and the record keys if Sealed.
pub struct Finished {
    suite: &'static Suite,
    mode: RecordMode,
    #[cfg(feature = "test-hooks")]
    th: Vec<u8>,
    #[cfg(feature = "test-hooks")]
    k0: Secret,
    keys: Keys,
    records: Option<(Sealer, Opener)>,
}

impl Finished {
    /// The record mode.
    pub fn mode(&self) -> RecordMode {
        self.mode
    }

    /// `Export(label, context, n)` of this Join.
    pub fn export(&self, label: &[u8], context: &[u8], len: usize) -> Result<Vec<u8>, Error> {
        export(
            self.suite.hash,
            &self.keys.exporter_secret,
            label,
            context,
            len,
        )
    }

    /// Takes the record directions in Sealed, past Confirm; the exporter stays.
    pub fn take_records(&mut self) -> Option<(Sealer, Opener)> {
        self.records.take()
    }

    /// The record directions in Sealed, past Confirm; `None` otherwise.
    pub fn into_records(self) -> Option<(Sealer, Opener)> {
        self.records
    }

    /// The inner values, for the vectors.
    #[cfg(feature = "test-hooks")]
    pub fn schedule(&self) -> Schedule {
        let keys = self.keys.clone();
        Schedule {
            th: self.th.clone(),
            k0: self.k0.to_vec(),
            confirm_tag: keys.confirm_tag(self.suite),
            th2: keys.th2,
            th3: keys.th3,
            k1: keys.k1.to_vec(),
            ss: keys.ss.iter().map(|s| s.to_vec()).collect(),
            hs: keys.hs.to_vec(),
            key_i2r: keys.key_i2r.to_vec(),
            key_r2i: keys.key_r2i.to_vec(),
            mac_key: keys.mac_key.to_vec(),
            exporter_secret: keys.exporter_secret.to_vec(),
        }
    }
}

/// The clear head of a Join Hello, through the nonce R.
struct HelloHead<'a> {
    suite: &'static Suite,
    mode: RecordMode,
    phase: u8,
    locator: &'a [u8],
    /// The head's length.
    len: usize,
}

impl<'a> HelloHead<'a> {
    /// The head `input` starts with; a cut one is `Incomplete` on a byte
    /// stream (`stream`), `Malformed` otherwise.
    fn parse(stream: bool, input: &'a [u8]) -> Result<Self, Error> {
        let cut = |need| {
            if stream {
                Error::Incomplete { need }
            } else {
                Error::Malformed
            }
        };
        let first = *input.first().ok_or(cut(1))?;
        if first != HELLO_TYPE {
            return Err(Error::UnknownProfile);
        }
        let rest = &input[1..];
        let Some((value, used, shortest)) = read_shortest(rest) else {
            let width = rest.first().map_or(1, |b| 1usize << (b >> 6));
            return Err(cut(1 + width));
        };
        if !shortest {
            return Err(Error::Malformed);
        }
        let suite = Suite::from_value(value).ok_or(Error::UnknownSuite)?;
        let mut at = 1 + used;
        let (mode, phase) = parse_mode_byte(*input.get(at).ok_or(cut(at + 1))?)?;
        at += 1;
        let locator_len = usize::from(*input.get(at).ok_or(cut(at + 1))?);
        at += 1;
        if locator_len == 0 {
            return Err(Error::BadHandle);
        }
        let locator_end = at + locator_len;
        let locator = input.get(at..locator_end).ok_or(cut(locator_end))?;
        let len = locator_end + suite.r_len;
        if input.len() < len {
            return Err(cut(len));
        }
        Ok(Self {
            suite,
            mode,
            phase,
            locator,
            len,
        })
    }
}

/// A parsed Join Hello: nothing is authenticated yet.
#[derive(Clone, Copy, Debug)]
pub struct JoinHello<'a> {
    suite: &'static Suite,
    mode: RecordMode,
    phase: u8,
    locator: &'a [u8],
    prefix: &'a [u8],
    ciphertext: &'a [u8],
    framing: Framing,
    consumed: usize,
}

impl<'a> JoinHello<'a> {
    /// Parses a Hello in wire order. On a byte stream a byte past the Hello is
    /// `trailing_bytes`.
    pub fn parse(framing: Framing, input: &'a [u8]) -> Result<JoinHello<'a>, Error> {
        let stream = framing == Framing::ByteStream;
        let head = HelloHead::parse(stream, input)?;
        let prefix_end = head.len;
        let (ciphertext, consumed) = if stream {
            let (unit, total) = cut_frame(input, prefix_end)?;
            if total != input.len() {
                return Err(Error::TrailingBytes);
            }
            (unit, total)
        } else {
            if input.len() - prefix_end > MAX_UNIT {
                return Err(Error::TooLarge);
            }
            (&input[prefix_end..], input.len())
        };
        Ok(JoinHello {
            suite: head.suite,
            mode: head.mode,
            phase: head.phase,
            locator: head.locator,
            prefix: &input[..prefix_end],
            ciphertext,
            framing,
            consumed,
        })
    }

    /// The Locator of the Hello that `input` starts with, from its clear
    /// head (through the nonce R) alone: [`Error::Incomplete`] with the
    /// head's whole length while `input` is shorter.
    pub fn head_locator(input: &'a [u8]) -> Result<&'a [u8], Error> {
        HelloHead::parse(true, input).map(|h| h.locator)
    }

    /// The Suite.
    pub fn suite(&self) -> &'static Suite {
        self.suite
    }

    /// The Mode the joiner chose.
    pub fn mode(&self) -> RecordMode {
        self.mode
    }

    /// The key phase: the parity of the epoch of the joiner's key.
    pub fn phase(&self) -> u8 {
        self.phase
    }

    /// What the session table finds.
    pub fn locator(&self) -> &'a [u8] {
        self.locator
    }

    /// The bytes of the Hello.
    pub fn consumed(&self) -> usize {
        self.consumed
    }
}

/// What an acceptor looks up by Locator.
#[derive(Clone, Copy)]
pub struct AcceptorKeys<'a> {
    /// `join_psk` of the joiner's role in the session, of the epoch the key phase selects.
    pub psk: &'a [u8],
    /// The Binding this end has. It is mixed as it is: any disagreement with the
    /// joiner, the received Mode included, is `auth`.
    pub binding: &'a [u8],
    /// The usable Groups of the session.
    pub groups: &'a [u64],
}

/// An acceptor entrance.
pub struct Acceptor;

impl Acceptor {
    /// Opens a Hello and parses its payload, the key share's Group and length included.
    /// The session layer has refused a Suite outside the session's set before this call.
    /// No key exchange runs here: it waits for [`Unconfirmed::write_reply`], after the
    /// session's replay check. The payload's effects are the caller's, after success.
    pub fn open(
        hello: &JoinHello<'_>,
        keys: AcceptorKeys<'_>,
    ) -> Result<(Unconfirmed, Payload), Error> {
        let suite = hello.suite;
        if keys.psk.len() != suite.hash.out_len() {
            return Err(Error::InvalidConfig);
        }
        // A Hello in Bound and no Binding here: refused, unopened.
        if hello.mode() == RecordMode::Bound && keys.binding.is_empty() {
            return Err(Error::Auth);
        }
        let th = transcript_start(suite, hello.prefix, keys.binding);
        let k0 = expand_labeled(suite, keys.psk, b"hello", &th, suite.cipher.key_len());
        let ciphertext = hello.ciphertext;
        let raw = with_tag(suite, ciphertext, || {
            suite.cipher.open(&k0, 0, b"", ciphertext)
        })??;
        let payload = Payload::validate(raw, JOIN_HELLO_KNOWN)?;
        if !payload.has(JOIN_HELLO_REQUIRED) {
            return Err(Error::MissingField);
        }
        let (group, share) = received_share(&payload, keys.groups, true)?;
        let next = Unconfirmed {
            suite,
            mode: hello.mode,
            framing: hello.framing,
            psk: keys.psk.into(),
            th,
            #[cfg(feature = "test-hooks")]
            k0,
            hello_ct: ciphertext.to_vec(),
            group,
            share: share.to_vec(),
            #[cfg(feature = "test-hooks")]
            fixed_kex: None,
        };
        Ok((next, payload))
    }
}

/// An acceptor that opened a Hello and owes a Reply.
pub struct Unconfirmed {
    suite: &'static Suite,
    mode: RecordMode,
    framing: Framing,
    psk: Secret,
    th: Vec<u8>,
    #[cfg(feature = "test-hooks")]
    k0: Secret,
    hello_ct: Vec<u8>,
    group: &'static Group,
    share: Vec<u8>,
    #[cfg(feature = "test-hooks")]
    fixed_kex: Option<(Vec<u8>, Vec<u8>)>,
}

impl Unconfirmed {
    /// The Group of the joiner's key share.
    pub fn group(&self) -> &'static Group {
        self.group
    }

    /// Fixes the X25519 private key and, in Group 2, the encapsulation randomness `m` of
    /// the responder's share, for the vectors.
    #[cfg(feature = "test-hooks")]
    #[must_use]
    pub fn with_kex(mut self, x: &[u8], m: &[u8]) -> Unconfirmed {
        self.fixed_kex = Some((x.to_vec(), m.to_vec()));
        self
    }

    /// Performs this end's side of the key exchange and writes the Reply with its share
    /// after the items of `payload`, which must hold the decision. A refused share is
    /// `kex`, and nothing is written.
    pub fn write_reply(self, payload: &[u8]) -> Result<(Vec<u8>, AwaitConfirm), Error> {
        Payload::check_outgoing(payload, JOIN_REPLY_KNOWN)?;
        let (attempt, random) = fresh_random(self.suite)?;
        self.reply_with(payload, attempt, &random, None)
    }

    /// As [`Unconfirmed::write_reply`] with a fixed attempt and random bytes, for the
    /// vectors; the payload may also hold items of types a sender does not send
    /// (unassigned ones), which the vectors use to show that a receiver skips them, and
    /// the key share item may be replaced.
    #[cfg(feature = "test-hooks")]
    pub fn write_reply_with_random(
        self,
        payload: &[u8],
        attempt: u64,
        random: &[u8],
        share: Option<ShareOverride>,
    ) -> Result<(Vec<u8>, AwaitConfirm), Error> {
        self.reply_with(payload, attempt, random, share)
    }

    #[cfg(feature = "test-hooks")]
    fn respond(&self) -> Result<(Vec<u8>, SharedSecrets), Error> {
        match &self.fixed_kex {
            Some((x, m)) => self.group.respond_with(&self.share, x, m),
            None => self.group.respond(&self.share),
        }
    }

    #[cfg(not(feature = "test-hooks"))]
    fn respond(&self) -> Result<(Vec<u8>, SharedSecrets), Error> {
        self.group.respond(&self.share)
    }

    fn reply_with(
        self,
        payload: &[u8],
        attempt: u64,
        random: &[u8],
        #[cfg_attr(not(feature = "test-hooks"), allow(unused_variables))] share: Option<
            ShareOverride,
        >,
    ) -> Result<(Vec<u8>, AwaitConfirm), Error> {
        let (own_share, secrets) = self.respond()?;
        #[cfg(feature = "test-hooks")]
        let given = payload;
        let payload = push_key_share(payload, self.group.value(), &own_share);
        #[cfg(feature = "test-hooks")]
        let payload = match share {
            None => payload,
            Some(ShareOverride::InPayload) => given.to_vec(),
            Some(ShareOverride::Missing) => {
                payload[..payload.len() - item_len(&own_share, self.group)].to_vec()
            }
            Some(ShareOverride::Value(v)) => {
                let head = &payload[..payload.len() - item_len(&own_share, self.group)];
                push_item(head, &v)
            }
        };
        let parsed = Payload::validate(payload.clone(), JOIN_REPLY_KNOWN)?;
        if !parsed.has(JOIN_REPLY_REQUIRED) {
            return Err(Error::InvalidConfig);
        }
        let suite = self.suite;
        let r = join_r(suite, &self.psk, attempt, random, &[REPLY_TYPE], &payload);
        let th2 = suite.hash.hash(&[&self.th, &self.hello_ct, &r]);
        let k1 = expand_labeled(suite, &self.psk, b"reply", &th2, suite.cipher.key_len());
        let ciphertext = suite.cipher.seal(&k1, 0, b"", &payload);
        let mut wire = vec![REPLY_TYPE];
        wire.extend_from_slice(&r);
        frame(self.framing, &mut wire, &ciphertext)?;
        let keys = Keys::new(suite, &self.psk, th2, k1, &ciphertext, secrets);
        let next = AwaitConfirm {
            suite,
            mode: self.mode,
            framing: self.framing,
            #[cfg(feature = "test-hooks")]
            th: self.th,
            #[cfg(feature = "test-hooks")]
            k0: self.k0,
            keys,
        };
        Ok((wire, next))
    }
}

/// An acceptor waiting for Confirm. It is what the cap check, eviction and the
/// acceptor's records wait for.
pub struct AwaitConfirm {
    suite: &'static Suite,
    mode: RecordMode,
    framing: Framing,
    #[cfg(feature = "test-hooks")]
    th: Vec<u8>,
    #[cfg(feature = "test-hooks")]
    k0: Secret,
    keys: Keys,
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && black_box(a.iter().zip(b).fold(0, |acc, (x, y)| acc | (x ^ y))) == 0
}

impl AwaitConfirm {
    /// A Trusted `Len` under a tag fails as soon as it is read.
    fn short_trusted(&self, input: &[u8]) -> Result<(), Error> {
        match input {
            [a, b, ..]
                if self.framing == Framing::ByteStream
                    && usize::from(u16::from_be_bytes([*a, *b])) < self.suite.hash_len() =>
            {
                Err(Error::Malformed)
            }
            _ => Ok(()),
        }
    }

    /// Whether `input` holds the whole confirmation: `Incomplete` while it wants more.
    pub fn ready(&self, input: &[u8]) -> Result<(), Error> {
        match (self.mode, self.framing) {
            (RecordMode::Bound | RecordMode::Unmanaged, _) => Ok(()),
            // The message has not been read yet: nothing on a message carrier is no message.
            (_, Framing::Records) if input.is_empty() => Err(Error::Incomplete { need: 1 }),
            (_, Framing::Records) => Ok(()),
            (RecordMode::Trusted, Framing::ByteStream) => {
                self.short_trusted(input)?;
                cut_unit(self.framing, input).map(|_| ())
            }
            (RecordMode::Sealed, Framing::ByteStream) => cut_unit(self.framing, input).map(|_| ()),
        }
    }

    /// Reads Confirm at the start of `input`, returning the bytes consumed. In
    /// Bound there is none and the Join is confirmed at once.
    pub fn read_confirm(self, input: &[u8]) -> Result<(Finished, usize), Error> {
        let suite = self.suite;
        let mut records = None;
        let consumed = match self.mode {
            RecordMode::Bound | RecordMode::Unmanaged => 0,
            RecordMode::Trusted => {
                self.short_trusted(input)?;
                let (unit, consumed) = cut_unit(self.framing, input)?;
                let tag = self.keys.confirm_tag(suite);
                let (received, rest) = unit.split_at_checked(tag.len()).ok_or(Error::Malformed)?;
                if !constant_time_eq(received, &tag) {
                    return Err(Error::Auth);
                }
                if rest.iter().any(|&b| b != 0) {
                    return Err(Error::BadConfirm);
                }
                consumed
            }
            RecordMode::Sealed => {
                let (unit, consumed) = cut_unit(self.framing, input)?;
                let mut opener = Opener::new(suite.cipher, self.keys.key_i2r.clone());
                if opener.open(unit)?.iter().any(|&b| b != 0) {
                    return Err(Error::BadConfirm);
                }
                records = Some((Sealer::new(suite.cipher, self.keys.key_r2i.clone()), opener));
                consumed
            }
        };
        let done = Finished {
            suite,
            mode: self.mode,
            #[cfg(feature = "test-hooks")]
            th: self.th,
            #[cfg(feature = "test-hooks")]
            k0: self.k0,
            keys: self.keys,
            records,
        };
        Ok((done, consumed))
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for JoinConfig<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JoinConfig").finish_non_exhaustive()
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for Joiner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Joiner").finish_non_exhaustive()
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for HelloSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelloSent").finish_non_exhaustive()
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for Proven {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Proven").finish_non_exhaustive()
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for Finished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Finished").finish_non_exhaustive()
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for AcceptorKeys<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptorKeys").finish_non_exhaustive()
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for Acceptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Acceptor").finish_non_exhaustive()
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for Unconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unconfirmed").finish_non_exhaustive()
    }
}

/// Shows no state: it may hold keys or locks.
impl std::fmt::Debug for AwaitConfirm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AwaitConfirm").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(group: u64, usable: &[u64]) -> Result<(), Error> {
        let suite = Suite::from_value(1).unwrap();
        let psk = [7u8; 32];
        let joiner = Joiner::new(JoinConfig {
            suite,
            group: Group::from_value(group).unwrap(),
            mode: RecordMode::Trusted,
            phase: 1,
            framing: Framing::ByteStream,
            locator: b"L",
            psk: &psk,
            binding: &[],
        })?;
        let pipe = super::super::JoinPipe {
            id: 2,
            direction: 2,
            fate_group: 0,
            priority: 0,
            standby: false,
        }
        .encode();
        let (hello, sent) = joiner.write_hello(&super::super::encode_payload(&[(5, &pipe)]))?;
        let parsed = JoinHello::parse(Framing::ByteStream, &hello)?;
        assert_eq!(parsed.phase(), 1);
        let (u, _) = Acceptor::open(
            &parsed,
            AcceptorKeys {
                psk: &psk,
                binding: &[],
                groups: usable,
            },
        )?;
        let (reply, wait) = u.write_reply(&super::super::encode_payload(&[(7, &[0])]))?;
        let (proven, _) = sent.read_reply(&reply)?;
        let (confirm, j) = proven.write_confirm(0)?;
        let (a, _) = wait.read_confirm(&confirm)?;
        assert_eq!(j.export(b"x", b"", 32)?, a.export(b"x", b"", 32)?);
        Ok(())
    }

    #[test]
    fn both_groups_join() {
        round_trip(1, &[1, 2]).unwrap();
        round_trip(2, &[1, 2]).unwrap();
        assert_eq!(round_trip(1, &[2]), Err(Error::BadField));
    }

    #[test]
    fn mode_byte_bounds() {
        for ok in [0x00, 0x01, 0x02, 0x80, 0x81, 0x82] {
            assert!(parse_mode_byte(ok).is_ok(), "{ok:#x}");
        }
        for bad in [0x03, 0x04, 0x40, 0x7f, 0x83] {
            assert_eq!(parse_mode_byte(bad), Err(Error::BadFlags), "{bad:#x}");
        }
    }
}
