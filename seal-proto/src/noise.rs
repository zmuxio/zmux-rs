//! The Noise symmetric state and the token engine.

use zmux::proto::seal::{Error, Payload, Proof, Secret};

use zmux::proto::seal::fill_random;

use crate::Profile;
use crate::profile::{KemFn, Params, Token};

const MAX_UNIT: usize = u16::MAX as usize;
/// The payload type of application data.
const APP_DATA: u64 = 2;

struct Symmetric {
    params: &'static Params,
    ck: Secret,
    h: Vec<u8>,
    key: Option<Secret>,
    n: u64,
}

impl Symmetric {
    fn new(params: &'static Params, prologue: &[u8]) -> Symmetric {
        // Noise Section 5.2: a name that fits the hash output is used as it is,
        // padded with zeros; a longer one is hashed.
        let name = params.noise_name.as_bytes();
        let h = if name.len() <= params.hash.out_len() {
            let mut h = name.to_vec();
            h.resize(params.hash.out_len(), 0);
            h
        } else {
            params.hash.hash(&[name])
        };
        let mut state = Symmetric {
            params,
            ck: Secret::from(h.clone()),
            h,
            key: None,
            n: 0,
        };
        state.mix_hash(prologue);
        state
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = self.params.hash.hash(&[&self.h, data]);
    }

    /// Noise HKDF on ck with `outputs` hash-length results, the first replacing ck.
    fn hkdf(&mut self, ikm: &[u8], outputs: usize) -> Vec<Secret> {
        let hash = self.params.hash;
        let prk = Secret::from(hash.extract(&self.ck, ikm));
        let okm = Secret::from(
            hash.expand(&prk, b"", hash.out_len() * outputs)
                .expect("at most three outputs"),
        );
        let mut parts: Vec<Secret> = okm.chunks(hash.out_len()).map(Secret::from).collect();
        self.ck = parts.remove(0);
        parts
    }

    fn set_key(&mut self, mut key: Secret) {
        key.truncate((self.params.cipher)().key_len());
        self.key = Some(key);
        self.n = 0;
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let mut parts = self.hkdf(ikm, 2);
        self.set_key(parts.remove(0));
    }

    fn mix_key_and_hash(&mut self, ikm: &[u8]) {
        let mut parts = self.hkdf(ikm, 3);
        let key = parts.remove(1);
        self.mix_hash(&parts[0]);
        self.set_key(key);
    }

    fn encrypt_and_hash(&mut self, plain: &[u8]) -> Result<Vec<u8>, Error> {
        let out = match &self.key {
            Some(_) if self.n == u64::MAX => return Err(Error::Exhausted),
            Some(key) => {
                let out = (self.params.cipher)().seal(key, self.n, &self.h, plain);
                self.n += 1;
                out
            }
            None => plain.to_vec(),
        };
        self.mix_hash(&out);
        Ok(out)
    }

    fn decrypt_and_hash(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let out = match &self.key {
            Some(_) if self.n == u64::MAX => return Err(Error::Exhausted),
            Some(key) => {
                let out = (self.params.cipher)().open(key, self.n, &self.h, data)?;
                self.n += 1;
                out
            }
            None => data.to_vec(),
        };
        self.mix_hash(data);
        Ok(out)
    }
}

/// The outcome of the last message.
pub(crate) struct Finished {
    pub(crate) params: &'static Params,
    pub(crate) h: Vec<u8>,
    pub(crate) ck: Secret,
    pub(crate) c1: Secret,
    pub(crate) c2: Secret,
    pub(crate) peer_static: Option<Vec<u8>>,
    pub(crate) peer_proof: Option<ReceivedProof>,
}

/// The proof of the peer's last message, with the M it signs.
pub(crate) struct ReceivedProof {
    key_alg: u64,
    key: Vec<u8>,
    sig: Vec<u8>,
    pub(crate) message: Vec<u8>,
}

impl ReceivedProof {
    pub(crate) fn proof(&self) -> Proof<'_> {
        Proof {
            key_alg: self.key_alg,
            key: &self.key,
            sig: &self.sig,
        }
    }
}

pub(crate) struct Engine {
    sym: Symmetric,
    initiator: bool,
    next_message: usize,
    psk: Secret,
    s: Secret,
    e: Option<Secret>,
    fixed_e: Option<Secret>,
    rs: Option<Vec<u8>>,
    re: Option<Vec<u8>>,
    /// The initiator's KEM decapsulation key: new for every handshake, a retry
    /// included, never cached, used for one ciphertext.
    dk: Option<Secret>,
    /// The encapsulation key a responder received, judged when it writes.
    re1: Option<Vec<u8>>,
    /// A fixed KEM seed (initiator) or encapsulation randomness (responder).
    fixed_kem: Option<Secret>,
    /// The largest application data of a received message; `None`: no bound.
    max_app_data: Option<usize>,
    /// `h` after the last token of the message being read or written: `h_p`.
    h_p: Vec<u8>,
    /// The proof of the peer's last message.
    peer_proof: Option<ReceivedProof>,
}

/// Fresh randomness for a KEM, or the fixed one of a test.
fn kem_random(fixed: &mut Option<Secret>, len: usize) -> Result<Secret, Error> {
    if let Some(f) = fixed.take() {
        return Ok(f);
    }
    let mut out = vec![0; len];
    fill_random(&mut out)?;
    Ok(Secret::from(out))
}

impl Engine {
    pub(crate) fn new(
        params: &'static Params,
        initiator: bool,
        prologue: &[u8],
        psk: Secret,
        s: Secret,
        fixed_e: Option<Secret>,
        fixed_kem: Option<Secret>,
    ) -> Engine {
        Engine {
            sym: Symmetric::new(params, prologue),
            initiator,
            next_message: 0,
            psk,
            s,
            e: None,
            fixed_e,
            rs: None,
            re: None,
            dk: None,
            re1: None,
            fixed_kem,
            max_app_data: Some(crate::DEFAULT_MAX_APP_DATA),
            h_p: Vec::new(),
            peer_proof: None,
        }
    }

    fn kem(&self) -> &'static KemFn {
        self.sym.params.kem
    }

    /// The length of a value of `n` bytes sent under the current key.
    fn keyed_len(&self, n: usize) -> usize {
        n + if self.sym.key.is_some() {
            (self.sym.params.cipher)().tag_len()
        } else {
            0
        }
    }

    fn has_psk(&self) -> bool {
        self.sym.params.shape.messages[0].contains(&Token::Psk)
    }

    pub(crate) fn known_types(&self) -> &'static [u64] {
        self.sym.params.shape.known[self.next_message]
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.next_message == self.sym.params.shape.messages.len()
    }

    /// The private and public halves of a DH token, seen from this end. The
    /// first letter of the token is the initiator's key.
    fn dh(&mut self, token: Token) -> Result<(), Error> {
        let (initiator_static, responder_static) = match token {
            Token::Ee => (false, false),
            Token::Es => (false, true),
            Token::Se => (true, false),
            _ => unreachable!("not a DH token"),
        };
        let (local_static, remote_static) = if self.initiator {
            (initiator_static, responder_static)
        } else {
            (responder_static, initiator_static)
        };
        let private = if local_static {
            Some(&self.s)
        } else {
            self.e.as_ref()
        };
        let public = if remote_static {
            self.rs.as_ref()
        } else {
            self.re.as_ref()
        };
        let private = private.expect("patterns write a key before using it");
        let public = public.expect("patterns read a key before using it");
        let shared = (self.sym.params.dh.dh)(private, public)?;
        self.sym.mix_key(&shared);
        Ok(())
    }

    pub(crate) fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let tokens = self.write_tokens()?;
        self.write_payload(tokens, payload)
    }

    /// The index of the next message.
    pub(crate) fn message_index(&self) -> usize {
        self.next_message
    }

    /// `h_p` of the message being written or last read.
    pub(crate) fn h_p(&self) -> &[u8] {
        &self.h_p
    }

    /// The length of a message of `tokens` bytes and a payload of `payload` bytes.
    pub(crate) fn message_len(&self, tokens: usize, payload: usize) -> usize {
        tokens + self.keyed_len(payload)
    }

    /// Processes the tokens of the next message and returns their bytes; `h_p` is then
    /// the hash a proof of the message signs. [`Engine::write_payload`] completes it.
    pub(crate) fn write_tokens(&mut self) -> Result<Vec<u8>, Error> {
        let params = self.sym.params;
        let mut out = Vec::new();
        for &token in params.shape.messages[self.next_message] {
            match token {
                Token::Psk => {
                    let psk = std::mem::take(&mut self.psk);
                    self.sym.mix_key_and_hash(&psk);
                }
                Token::E => {
                    let e = match self.fixed_e.take() {
                        Some(e) => e,
                        None => (params.dh.generate)()?,
                    };
                    let public = (params.dh.public)(&e);
                    self.sym.mix_hash(&public);
                    if self.has_psk() {
                        self.sym.mix_key(&public);
                    }
                    out.extend_from_slice(&public);
                    self.e = Some(e);
                }
                Token::S => {
                    let public = (params.dh.public)(&self.s);
                    out.extend(self.sym.encrypt_and_hash(&public)?);
                }
                Token::E1 => {
                    let kem = self.kem();
                    let seed = kem_random(&mut self.fixed_kem, kem.seed_len)?;
                    let (dk, ek) = (kem.generate)(&seed);
                    out.extend(self.sym.encrypt_and_hash(&ek)?);
                    self.dk = Some(dk);
                }
                Token::Ekem1 => {
                    // The received key is judged here, before this end sends anything.
                    let kem = self.kem();
                    let ek = self.re1.take().expect("message 1 carries the key");
                    let m = kem_random(&mut self.fixed_kem, kem.random_len)?;
                    let (ct, ss) = (kem.encapsulate)(&ek, &m)?;
                    out.extend(self.sym.encrypt_and_hash(&ct)?);
                    self.sym.mix_key(&ss);
                }
                dh => self.dh(dh)?,
            }
        }
        self.h_p = self.sym.h.clone();
        Ok(out)
    }

    /// Encrypts the payload after [`Engine::write_tokens`].
    pub(crate) fn write_payload(
        &mut self,
        mut out: Vec<u8>,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if self.message_len(out.len(), payload.len()) > MAX_UNIT {
            return Err(Error::TooLarge);
        }
        out.extend(self.sym.encrypt_and_hash(payload)?);
        if out.len() > MAX_UNIT {
            return Err(Error::TooLarge);
        }
        self.next_message += 1;
        Ok(out)
    }

    /// The shortest valid form of the message about to be read.
    fn min_len(&self) -> usize {
        Profile(self.sym.params).empty_message_len(self.next_message)
    }

    pub(crate) fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, Error> {
        if message.len() > MAX_UNIT {
            return Err(Error::TooLarge);
        }
        if message.len() < self.min_len() {
            return Err(Error::Malformed);
        }
        let params = self.sym.params;
        let mut rest = message;
        for &token in params.shape.messages[self.next_message] {
            match token {
                Token::Psk => {
                    let psk = std::mem::take(&mut self.psk);
                    self.sym.mix_key_and_hash(&psk);
                }
                Token::E => {
                    let (public, after) = rest.split_at(params.dh.public_len);
                    rest = after;
                    self.sym.mix_hash(public);
                    if self.has_psk() {
                        self.sym.mix_key(public);
                    }
                    self.re = Some(public.to_vec());
                }
                Token::S => {
                    let (sealed, after) = rest.split_at(self.keyed_len(params.dh.public_len));
                    rest = after;
                    let peer = self.sym.decrypt_and_hash(sealed)?;
                    if !self.s.is_empty() && peer == (params.dh.public)(&self.s) {
                        return Err(Error::PeerIsSelf);
                    }
                    self.rs = Some(peer);
                }
                Token::E1 => {
                    let (sealed, after) = rest.split_at(self.keyed_len(self.kem().encap_key_len));
                    rest = after;
                    // Judged at ekem1, when this end writes.
                    self.re1 = Some(self.sym.decrypt_and_hash(sealed)?);
                }
                Token::Ekem1 => {
                    let kem = self.kem();
                    let (sealed, after) = rest.split_at(self.keyed_len(kem.ciphertext_len));
                    rest = after;
                    let ct = self.sym.decrypt_and_hash(sealed)?;
                    let dk = self.dk.take().expect("message 1 made the key");
                    let ss = (kem.decapsulate)(&dk, &ct);
                    self.sym.mix_key(&ss);
                }
                dh => self.dh(dh)?,
            }
        }
        self.h_p = self.sym.h.clone();
        let payload = self.sym.decrypt_and_hash(rest)?;
        self.next_message += 1;
        Ok(payload)
    }

    /// Sets the largest application data of a received message; `None`: no bound
    /// beyond the message.
    pub(crate) fn set_max_app_data(&mut self, max: Option<usize>) {
        self.max_app_data = max;
    }

    /// Validates a received payload: the types its message knows, application data
    /// within the limit (`too_large` above it) and none in a message 1 without a key
    /// (`malformed`), and the proof's M recorded.
    pub(crate) fn validate(&mut self, raw: Vec<u8>, known: &[u64]) -> Result<Payload, Error> {
        // read_message has advanced: the message read is the one before.
        let index = self.next_message - 1;
        let unkeyed = index == 0 && !self.has_psk();
        let max = self.max_app_data;
        let payload = Payload::validate_with(raw, known, |kind, value| match kind {
            APP_DATA if unkeyed => Err(Error::Malformed),
            APP_DATA if known.contains(&APP_DATA) && max.is_some_and(|m| value.len() > m) => {
                Err(Error::TooLarge)
            }
            _ => Ok(()),
        })?;
        // A proof counts only in a message that knows the type: elsewhere it is an
        // unknown even item, skipped unparsed.
        let proof = known
            .contains(&Proof::ITEM)
            .then(|| payload.proof())
            .flatten();
        self.peer_proof = proof.map(|p| ReceivedProof {
            key_alg: p.key_alg,
            key: p.key.to_vec(),
            sig: p.sig.to_vec(),
            message: crate::proof::proof_message(index, &self.h_p),
        });
        Ok(payload)
    }

    /// The proof of the peer's last message.
    pub(crate) fn peer_proof(&self) -> Option<&ReceivedProof> {
        self.peer_proof.as_ref()
    }

    pub(crate) fn peer_static(&self) -> Option<&[u8]> {
        self.rs.as_deref()
    }

    #[cfg(feature = "test-vectors")]
    pub(crate) fn force_n(&mut self) {
        self.sym.n = u64::MAX;
    }

    #[cfg(feature = "test-vectors")]
    pub(crate) fn transcript(&self) -> (&[u8], &[u8]) {
        (&self.sym.h, &self.sym.ck[..])
    }

    pub(crate) fn finish(self) -> Finished {
        debug_assert!(self.is_finished());
        let params = self.sym.params;
        let (hash, key_len) = (params.hash, (params.cipher)().key_len());
        let prk = Secret::from(hash.extract(&self.sym.ck, b""));
        let okm = Secret::from(
            hash.expand(&prk, b"", hash.out_len() * 2)
                .expect("two outputs"),
        );
        let (c1, c2) = okm.split_at(hash.out_len());
        Finished {
            params,
            h: self.sym.h,
            ck: self.sym.ck,
            c1: Secret::from(&c1[..key_len]),
            c2: Secret::from(&c2[..key_len]),
            peer_static: self.rs,
            peer_proof: self.peer_proof,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Engine;
    use crate::Profile;
    use zmux::proto::seal::Proof;

    fn engine() -> Engine {
        let params = Profile::all().next().unwrap().0;
        let mut engine = Engine::new(params, true, b"", vec![].into(), vec![].into(), None, None);
        // As after reading message 2.
        engine.next_message = 2;
        engine
    }

    #[test]
    fn a_proof_is_read_only_where_its_message_knows_the_type() {
        // Item 8, a proof: KeyAlg 3, a one-byte Pub and a one-byte Sig.
        let payload = vec![8, 4, 3, 1, 0xaa, 0xbb];
        for (known, read) in [(&[][..], false), (&[Proof::ITEM][..], true)] {
            let mut engine = engine();
            engine.validate(payload.clone(), known).unwrap();
            assert_eq!(engine.peer_proof().is_some(), read);
        }
        // An unknown proof is skipped unparsed, malformed or not.
        let mut engine = engine();
        engine.validate(vec![8, 1, 0x40], &[]).unwrap();
        assert!(engine.peer_proof().is_none());
    }
}
