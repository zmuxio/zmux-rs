//! First-message carrier admission under secure-carrier §3.4.

mod store;

pub use store::{
    MemoryPrefixStore, PrefixClaim, PrefixDeadline, PrefixGeneration, PrefixSchedule, PrefixStore,
    PrefixStoreFuture, PrefixTicket, PrefixWindow,
};

use std::fmt;
use std::io;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::admission::{CarrierCredential, CarrierInfo};
use super::oob;
use crate::util::{HmacSha256, wipe};

/// Binary length of a ticket presentation.
pub const PREFIX_TOKEN_LEN: usize = 64;
/// Request field for a head-stage presentation.
pub const PREFIX_AUTH_HEADER: &str = "Zmux-Prefix-Auth";
/// Label of the completed carrier handshake's exporter.
pub use super::keys::PREFIX_AUTH_EXPORTER_LABEL;
/// Length of the bound form's exporter.
pub const PREFIX_AUTH_BINDING_LEN: usize = 32;
/// Default verifier ceiling on slot tolerance.
pub const DEFAULT_MAX_SKEW: u32 = 2;

#[cfg(all(feature = "tokio", not(loom)))]
const HEADER_VALUE_LEN: usize = oob::encoded_len(PREFIX_TOKEN_LEN);

/// Invalid prefix authentication configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPrefixAuth(&'static str);

impl fmt::Display for InvalidPrefixAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for InvalidPrefixAuth {}

/// Validates a custom field shared by HTTP adapters and prefix admission.
#[doc(hidden)]
pub fn check_custom_header(name: &str) -> Result<(), &'static str> {
    const RESERVED: &[&str] = &[
        "content-length",
        "content-type",
        "content-encoding",
        "transfer-encoding",
        "host",
        "connection",
        "upgrade",
        "keep-alive",
        "te",
        "trailer",
        "authorization",
        "cookie",
        "expect",
        "date",
        "early-data",
        "forwarded",
        "via",
        "location",
        "origin",
        "cache-control",
        "pragma",
        "accept",
        "user-agent",
        "referer",
        "range",
    ];
    const PREFIXES: &[&str] = &["proxy-", "sec-", "x-forwarded-", "accept-", "if-"];
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_|~".contains(&b) || b == 0x60)
    {
        return Err("is not a header field name");
    }
    let lower = name.to_ascii_lowercase();
    if name.eq_ignore_ascii_case(PREFIX_AUTH_HEADER)
        || RESERVED.contains(&lower.as_str())
        || PREFIXES.iter().any(|p| lower.starts_with(p))
    {
        return Err("is reserved");
    }
    Ok(())
}

fn prefix_header(name: Arc<str>) -> Result<Arc<str>, InvalidPrefixAuth> {
    if name.is_empty() || name.eq_ignore_ascii_case(PREFIX_AUTH_HEADER) {
        return Ok(PREFIX_AUTH_HEADER.into());
    }
    if check_custom_header(&name).is_err() || name.eq_ignore_ascii_case(oob::PAIR_HEADER) {
        return Err(InvalidPrefixAuth(
            "reserved or invalid prefix-authentication header",
        ));
    }
    Ok(name)
}

struct Key([u8; 32]);

impl Key {
    fn shared(mut bytes: [u8; 32]) -> Arc<Self> {
        let key = Arc::new(Self(bytes));
        wipe(&mut bytes);
        key
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(..)")
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Deployment policy for the carrier that carries a ticket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrefixBinding {
    /// Bind to the 1-RTT TLS 1.3 or QUIC exporter of this carrier.
    Bound,
    /// A bearer ticket on an encrypted carrier.
    Encrypted,
    /// Also allow cleartext binary presentation. Use only where theft of a
    /// presentation can cause denial of service and grants no authority.
    AllowCleartext,
}

impl PrefixBinding {
    fn export(self, info: &CarrierInfo, header: bool) -> io::Result<super::seal::Secret> {
        let denied = || io::Error::from(io::ErrorKind::PermissionDenied);
        if info.is_early_data()
            || (!info.is_encrypted() && (header || self != Self::AllowCleartext))
        {
            return Err(denied());
        }
        if self != Self::Bound {
            return Ok(super::seal::Secret::default());
        }
        if !info.has_prefix_binding() {
            return Err(denied());
        }
        info.export(PREFIX_AUTH_EXPORTER_LABEL, &[], PREFIX_AUTH_BINDING_LEN)
            .filter(|bytes| bytes.len() == PREFIX_AUTH_BINDING_LEN)
            .map(Into::into)
            .ok_or_else(denied)
    }
}

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn nonce() -> io::Result<[u8; 16]> {
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(io::Error::other)?;
    Ok(nonce)
}

fn first_tag(mac: &HmacSha256, parts: &[&[u8]]) -> [u8; 16] {
    let mut full = mac.mac(parts);
    let tag = *full.first_chunk().expect("SHA-256 output");
    wipe(&mut full);
    tag
}

fn masked_id(outer: &HmacSha256, n: &[u8], id: &[u8; 16]) -> [u8; 16] {
    let mut mask = first_tag(outer, &[&[0], n]);
    let result = std::array::from_fn(|i| id[i] ^ mask[i]);
    wipe(&mut mask);
    result
}

fn ticket_mac<'a>(
    id: &'a [u8; 16],
    envelope: &'a [u8],
    slot: &'a [u8; 8],
    len: &'a [u8; 1],
    binding: &'a [u8],
) -> [&'a [u8]; 6] {
    [&[2], id, envelope, slot, len, binding]
}

/// A ticket presenter and its locally installed outer key schedule.
#[derive(Clone)]
pub struct PrefixAuth {
    ticket: PrefixTicket,
    schedule: Arc<PrefixSchedule>,
    seconds: std::num::NonZeroU64,
    binding: PrefixBinding,
    header: Arc<str>,
}

impl fmt::Debug for PrefixAuth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrefixAuth")
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

impl PrefixAuth {
    /// Constructs a presenter.
    ///
    /// # Errors
    ///
    /// The agreed slot length must be positive.
    pub fn new(
        ticket: PrefixTicket,
        schedule: Arc<PrefixSchedule>,
        slot_seconds: u64,
        binding: PrefixBinding,
    ) -> Result<Self, InvalidPrefixAuth> {
        let seconds =
            std::num::NonZeroU64::new(slot_seconds).ok_or(InvalidPrefixAuth("zero slot length"))?;
        Ok(Self {
            ticket,
            schedule,
            seconds,
            binding,
            header: PREFIX_AUTH_HEADER.into(),
        })
    }

    /// Selects the agreed name of the field on a request head.
    ///
    /// # Errors
    ///
    /// The field name is invalid or reserved. An empty name selects the default.
    pub fn with_header(mut self, name: impl Into<Arc<str>>) -> Result<Self, InvalidPrefixAuth> {
        self.header = prefix_header(name.into())?;
        Ok(self)
    }

    /// Canonical unpadded base64url for a binary presentation.
    #[must_use]
    pub fn header_value(token: &[u8; PREFIX_TOKEN_LEN]) -> String {
        oob::encode_string(token)
    }

    /// Generates a fresh binary presentation on this carrier.
    ///
    /// # Errors
    ///
    /// Carrier or ticket policy prevents presenting, or the random source fails.
    pub fn token(&self, info: &CarrierInfo) -> io::Result<[u8; PREFIX_TOKEN_LEN]> {
        self.present(info, false)
    }

    /// Generates an unbound fixture presentation at a fixed Unix time.
    #[cfg(feature = "test-hooks")]
    #[doc(hidden)]
    #[must_use]
    pub fn fixture_token(
        &self,
        unix_seconds: u64,
        nonce: [u8; 16],
    ) -> Option<[u8; PREFIX_TOKEN_LEN]> {
        if self.binding != PrefixBinding::AllowCleartext {
            return None;
        }
        self.token_at(unix_seconds / self.seconds, nonce, &[])
    }

    fn present(&self, info: &CarrierInfo, header: bool) -> io::Result<[u8; PREFIX_TOKEN_LEN]> {
        let binding = self
            .binding
            .export(info, header)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let slot = unix_now().ok_or(io::ErrorKind::InvalidData)? / self.seconds;
        self.token_at(slot, nonce()?, &binding)
            .ok_or_else(|| io::ErrorKind::PermissionDenied.into())
    }

    fn token_at(
        &self,
        slot: u64,
        nonce: [u8; 16],
        binding: &[u8],
    ) -> Option<[u8; PREFIX_TOKEN_LEN]> {
        let generation = self.schedule.eligible(&(slot..=slot)).first()?;
        if !self.ticket.slots.contains(&slot) {
            return None;
        }
        let outer = HmacSha256::new(&generation.key.0);
        let mut token = [0; PREFIX_TOKEN_LEN];
        token[..16].copy_from_slice(&nonce);
        token[16..32].copy_from_slice(&masked_id(&outer, &nonce, &self.ticket.id));
        let tag = first_tag(&outer, &[&[1], &token[..32]]);
        token[32..48].copy_from_slice(&tag);
        let key = HmacSha256::new(&self.ticket.key.0);
        let tag = first_tag(
            &key,
            &ticket_mac(
                &self.ticket.id,
                &token[..48],
                &slot.to_be_bytes(),
                &binding_length(binding),
                binding,
            ),
        );
        token[48..].copy_from_slice(&tag);
        Some(token)
    }
}

impl CarrierCredential for PrefixAuth {
    fn prefix_ticket_header(&self) -> Option<&str> {
        Some(&self.header)
    }

    fn prefix(&self, info: &CarrierInfo) -> io::Result<Vec<u8>> {
        Ok(self.token(info)?.into())
    }

    fn header(&self, info: &CarrierInfo) -> io::Result<(String, String)> {
        Ok((
            self.header.to_string(),
            Self::header_value(&self.present(info, true)?),
        ))
    }
}

fn binding_length(binding: &[u8]) -> [u8; 1] {
    [if binding.is_empty() { 0 } else { 32 }]
}

#[cfg(all(feature = "tokio", not(loom)))]
struct CancelAttempt(PrefixDeadline);

#[cfg(all(feature = "tokio", not(loom)))]
impl Drop for CancelAttempt {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

/// Verifies and redeems presentations using a shared admission-domain authority.
#[cfg(all(feature = "tokio", not(loom)))]
pub struct PrefixAuthVerifier {
    store: Arc<dyn PrefixStore>,
    window: PrefixWindow,
    binding: PrefixBinding,
    header: Arc<str>,
    clock: Arc<dyn Fn() -> Option<u64> + Send + Sync>,
}

#[cfg(all(feature = "tokio", not(loom)))]
impl fmt::Debug for PrefixAuthVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrefixAuthVerifier")
            .field("window", &self.window)
            .field("binding", &self.binding)
            .finish_non_exhaustive()
    }
}

#[cfg(all(feature = "tokio", not(loom)))]
impl PrefixAuthVerifier {
    /// Configures a verifier with the domain's immutable slot parameters.
    ///
    /// # Errors
    ///
    /// The store's tolerance exceeds [`DEFAULT_MAX_SKEW`].
    pub fn new(
        store: Arc<dyn PrefixStore>,
        binding: PrefixBinding,
    ) -> Result<Self, InvalidPrefixAuth> {
        Self::with_max_skew(store, binding, DEFAULT_MAX_SKEW)
    }

    /// Configures a verifier with an explicit ceiling on the store's slot tolerance.
    ///
    /// # Errors
    ///
    /// The store's tolerance exceeds the configured ceiling.
    pub fn with_max_skew(
        store: Arc<dyn PrefixStore>,
        binding: PrefixBinding,
        max_skew: u32,
    ) -> Result<Self, InvalidPrefixAuth> {
        let window = store.window();
        if window.skew() > max_skew {
            return Err(InvalidPrefixAuth("skew exceeds verifier limit"));
        }
        Ok(Self {
            window,
            store,
            binding,
            header: PREFIX_AUTH_HEADER.into(),
            clock: Arc::new(unix_now),
        })
    }

    /// Selects the agreed request field.
    ///
    /// # Errors
    ///
    /// The field name is invalid or reserved. An empty name selects the default.
    pub fn with_header(mut self, name: impl Into<Arc<str>>) -> Result<Self, InvalidPrefixAuth> {
        self.header = prefix_header(name.into())?;
        Ok(self)
    }

    /// The agreed request field for ticket presentations.
    #[must_use]
    pub fn header_name(&self) -> &str {
        &self.header
    }

    /// Supplies the verifier's UTC clock in whole Unix seconds.
    #[must_use]
    pub fn with_clock(mut self, clock: impl Fn() -> Option<u64> + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    fn token(&self, info: &CarrierInfo, prefix: &[u8]) -> Option<[u8; PREFIX_TOKEN_LEN]> {
        if !info.is_head() {
            if info.framing == super::record::Framing::Records && prefix.len() != PREFIX_TOKEN_LEN {
                return None;
            }
            return prefix.first_chunk().copied();
        }
        let mut field = None;
        let mut repeated = false;
        info.for_each_header(|name, value| {
            if name.eq_ignore_ascii_case(&self.header) {
                repeated |= field.is_some();
                let mut token = [0; PREFIX_TOKEN_LEN];
                field = Some(
                    (value.len() == HEADER_VALUE_LEN
                        && oob::decode(value, &mut token) == Ok(PREFIX_TOKEN_LEN))
                    .then_some(token),
                );
            }
        });
        if repeated { None } else { field.flatten() }
    }

    pub(crate) async fn redeem(
        &self,
        info: &CarrierInfo,
        prefix: &[u8],
        attempt: PrefixDeadline,
        worker: Box<dyn Send + Sync>,
    ) -> Option<(usize, Option<[u8; 16]>)> {
        let _cancel = CancelAttempt(attempt.clone());
        if attempt.ended() {
            return None;
        }
        let token = self.token(info, prefix)?;
        let binding = self.binding.export(info, info.is_head()).ok()?;
        let local = (self.clock)()? / self.window.slot_seconds();
        let (schedule, hint) = self.store.local_schedule();
        let initial = schedule.eligible(&self.window.slots(local.max(hint)));
        let mut generation = outer_match(initial, &token)?;
        let current = local.max(self.store.floor(attempt.clone()).await.ok()?);
        let eligible = schedule.eligible(&self.window.slots(current));
        if !std::ptr::eq(initial, eligible) {
            generation = outer_match(eligible, &token)?;
        }
        let id = masked_id(
            &HmacSha256::new(&generation.key.0),
            &token[..16],
            token[16..32].try_into().ok()?,
        );
        let ticket = self.store.lookup(attempt.clone(), id).await.ok()??;
        if ticket.id != id || !ticket.slots.contains(&current) {
            return None;
        }
        let issue_slot = match_slot(
            &ticket,
            &token,
            &binding,
            generation,
            current,
            self.window.skew,
        )?;
        let claim = PrefixClaim {
            id,
            nonce: *token.first_chunk()?,
            commit_id: nonce().ok()?,
            version: ticket.version,
            schedule: schedule.version(),
            generation: generation.first(),
            issue_slot,
            checked_slot: current,
            local_slot: local,
        };
        drop(ticket);
        drop(schedule);
        drop(binding);
        if attempt.ended() {
            return None;
        }
        let committed = self.commit(attempt, claim, worker).await;
        committed.then_some((
            if info.is_head() { 0 } else { PREFIX_TOKEN_LEN },
            (self.binding == PrefixBinding::Bound).then_some(id),
        ))
    }

    async fn commit(
        &self,
        attempt: PrefixDeadline,
        mut claim: PrefixClaim,
        worker: Box<dyn Send + Sync>,
    ) -> bool {
        // Dropping the admission signals cancellation without losing a receipt
        // query for an operation already dispatched to the authority.
        let store = self.store.clone();
        let utc = self.clock.clone();
        let slot_seconds = self.window.slot_seconds();
        let (result, wait) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _worker = worker;
            if attempt.ended() {
                return;
            }
            let Some(Some(unix)) = super::decision::host(|| utc()) else {
                return;
            };
            claim.local_slot = unix / slot_seconds;
            let mut result = result;
            let received = tokio::select! {
                result = super::decision::host_future(|| store.claim(attempt.clone(), claim)) => result,
                () = attempt.clock.sleep_until(attempt.at) => {
                    attempt.cancel();
                    None
                },
                () = result.closed() => {
                    attempt.cancel();
                    None
                },
            };
            let accepted = if let Some(Ok(accepted)) = received {
                accepted
            } else {
                let Some(at) = attempt
                    .clock
                    .now()
                    .checked_add(std::time::Duration::from_secs(1))
                else {
                    return;
                };
                let resolve = PrefixDeadline::new(attempt.clock.clone(), Some(at));
                tokio::select! {
                    result = super::decision::host_future(|| store.resolve(resolve.clone(), claim)) => {
                        result.is_some_and(|answer| matches!(answer, Ok(true))) && !resolve.ended()
                    },
                    () = resolve.clock.sleep_until(Some(at)) => false,
                }
            };
            let _ = result.send(accepted && !attempt.ended());
        });
        wait.await.unwrap_or(false)
    }
}

#[cfg(all(feature = "tokio", not(loom)))]
fn outer_match<'a>(
    generations: &'a [PrefixGeneration],
    token: &[u8; PREFIX_TOKEN_LEN],
) -> Option<&'a PrefixGeneration> {
    let mut selected = None;
    let mut unique = true;
    for generation in generations {
        let mac = HmacSha256::new(&generation.key.0);
        if mac.verify(&[&[1], &token[..32]], &token[32..48]) {
            unique &= selected.is_none();
            selected = Some(generation);
        }
    }
    if unique { selected } else { None }
}

#[cfg(all(feature = "tokio", not(loom)))]
fn match_slot(
    ticket: &PrefixTicket,
    token: &[u8; PREFIX_TOKEN_LEN],
    binding: &[u8],
    generation: &PrefixGeneration,
    current: u64,
    skew: u32,
) -> Option<u64> {
    let mac = HmacSha256::new(&ticket.key.0);
    let len = binding_length(binding);
    slot_trials(current, skew, generation, |slot| {
        mac.verify(
            &ticket_mac(&ticket.id, &token[..48], &slot.to_be_bytes(), &len, binding),
            &token[48..],
        )
    })
}

#[cfg(all(feature = "tokio", not(loom)))]
fn slot_trials(
    current: u64,
    skew: u32,
    generation: &PrefixGeneration,
    mut verify: impl FnMut(u64) -> bool,
) -> Option<u64> {
    let mut matched = None;
    for offset in -i64::from(skew)..=i64::from(skew) {
        let candidate = current.checked_add_signed(offset);
        let valid = std::hint::black_box(verify(candidate.unwrap_or(0)));
        if valid && let Some(slot) = candidate.filter(|s| generation.contains(*s)) {
            matched = Some(slot);
        }
    }
    matched
}

#[cfg(all(test, feature = "tokio", not(loom)))]
mod tests;
