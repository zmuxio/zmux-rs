//! The carrier cache of carrier modes and its interchange form: which
//! carrier kinds worked, per server and local network, exported and
//! imported as versioned JSON with wall-clock times.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::proto::session::CarrierKind;

/// Which carrier kinds worked, per server and local network
/// ([`CarrierChoicePolicy::key`](crate::CarrierChoicePolicy::key)): a usable kind is
/// remembered for its success TTL (6 h), a failed one is skipped for a
/// backoff that doubles with every failure in a row, from 1 min to 6 h. A
/// kind that fails soon after it was chosen
/// ([`CarrierChoicePolicy::drop_window`](crate::CarrierChoicePolicy::drop_window)) counts as
/// failed, so that a path that lets a kind through only briefly is not
/// tried again at once. Cheap to clone: clones share the cache, which is
/// safe for concurrent use, [`snapshot`](Self::snapshot) and
/// [`restore`](Self::restore) included.
#[derive(Debug, Clone)]
pub struct CarrierCache(Arc<CacheInner>);

/// A server and local network, a carrier kind and a variant.
type CacheKey = (String, CarrierKind, Option<Arc<str>>);

#[derive(Debug)]
struct CacheInner {
    success_ttl: Duration,
    backoff: (Duration, Duration),
    entries: Mutex<HashMap<CacheKey, CacheEntry>>,
}

#[derive(Debug, Default, Clone)]
struct CacheEntry {
    good_until: Option<Instant>,
    fail_until: Option<Instant>,
    backoff: Duration,
    url: String,
}

impl CacheEntry {
    /// The later of its two times: entries recorded later are newer.
    fn latest(&self) -> Option<Instant> {
        self.good_until.max(self.fail_until)
    }

    /// It tells nothing any more at `now`: neither usable nor failed, and
    /// its backoff history older than the longest backoff.
    fn expired(&self, now: Instant, backoff_max: Duration) -> bool {
        let past = |t: Option<Instant>| t.is_none_or(|t| t <= now);
        past(self.good_until)
            && past(self.fail_until)
            && past(self.fail_until.and_then(|t| t.checked_add(backoff_max)))
    }
}

/// What a host learnt of a candidate after dialling it
/// ([`CarrierCache::report`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CacheOutcome {
    /// Usable, as a chosen candidate.
    Usable,
    /// An ordinary failure: the backoff doubles.
    Failed,
    /// A definite verdict of the host (a binding check that proves the path
    /// unsuitable): skipped for the longest backoff.
    Rejected,
}

impl Default for CarrierCache {
    fn default() -> Self {
        Self::new(
            Duration::from_secs(6 * 3600),
            Duration::from_secs(60),
            Duration::from_secs(6 * 3600),
        )
    }
}

/// What a cache knows of a kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Known {
    Unknown,
    Usable,
    /// Failed: skipped until then.
    Failed(Instant),
}

impl CarrierCache {
    /// A cache that remembers a usable kind for `success_ttl` and backs a
    /// failed one off from `backoff_min` to `backoff_max`.
    pub fn new(success_ttl: Duration, backoff_min: Duration, backoff_max: Duration) -> Self {
        Self(Arc::new(CacheInner {
            success_ttl,
            backoff: (backoff_min, backoff_max.max(backoff_min)),
            entries: Mutex::default(),
        }))
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<CacheKey, CacheEntry>> {
        self.0
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn state(
        &self,
        key: &str,
        kind: CarrierKind,
        variant: Option<&Arc<str>>,
        now: Instant,
    ) -> Known {
        match self
            .entries()
            .get(&(key.to_owned(), kind, variant.cloned()))
        {
            Some(e) if e.fail_until.is_some_and(|t| now < t) => {
                Known::Failed(e.fail_until.unwrap_or(now))
            }
            Some(e) if e.good_until.is_some_and(|t| now < t) => Known::Usable,
            _ => Known::Unknown,
        }
    }

    /// Records an outcome. A usable kind keeps the URL remembered for it;
    /// a failed one starts at its base URL again.
    /// Records an outcome the host learnt after a dial: `key` the
    /// [`CarrierChoicePolicy::key`](crate::CarrierChoicePolicy::key) in use, `variant` the
    /// candidate's ([`Candidate::with_variant`](crate::Candidate::with_variant)).
    /// The same table as the automatic results and under the same rules.
    pub fn report(
        &self,
        key: &str,
        kind: CarrierKind,
        variant: Option<&str>,
        outcome: CacheOutcome,
    ) {
        let variant = variant.map(Arc::from);
        let now = Instant::now();
        match outcome {
            CacheOutcome::Usable => self.record(key, kind, variant.as_ref(), None, true, now),
            CacheOutcome::Failed => self.record(key, kind, variant.as_ref(), None, false, now),
            CacheOutcome::Rejected => {
                let hi = self.0.backoff.1;
                let mut entries = self.entries();
                let e = entries.entry((key.to_owned(), kind, variant)).or_default();
                e.backoff = hi;
                e.good_until = None;
                e.fail_until = now.checked_add(hi);
                e.url.clear();
            }
        }
    }

    pub(crate) fn record(
        &self,
        key: &str,
        kind: CarrierKind,
        variant: Option<&Arc<str>>,
        target: Option<&crate::HttpTarget>,
        usable: bool,
        now: Instant,
    ) {
        let mut entries = self.entries();
        let e = entries
            .entry((key.to_owned(), kind, variant.cloned()))
            .or_default();
        if usable {
            // A kind with a target keeps the URL its redirects led to; an
            // outcome without one keeps the URL known.
            let url = match target {
                Some(t) => {
                    let u = t.url();
                    if u == t.base() { String::new() } else { u }
                }
                None => std::mem::take(&mut e.url),
            };
            *e = CacheEntry {
                good_until: now.checked_add(self.0.success_ttl),
                url,
                ..CacheEntry::default()
            };
            return;
        }
        if let Some(t) = target {
            t.reset();
        }
        let (lo, hi) = self.0.backoff;
        e.backoff = (e.backoff * 2).clamp(lo, hi);
        e.good_until = None;
        e.fail_until = now.checked_add(e.backoff);
        e.url.clear();
    }

    /// Whether `kind` with `variant` is held as usable under `key` now.
    pub fn is_usable(&self, key: &str, kind: CarrierKind, variant: Option<&str>) -> bool {
        let variant = variant.map(Arc::from);
        self.state(key, kind, variant.as_ref(), Instant::now()) == Known::Usable
    }

    /// Until when `kind` with `variant` is skipped under `key`, if it is
    /// backing off.
    pub fn failed_until(
        &self,
        key: &str,
        kind: CarrierKind,
        variant: Option<&str>,
    ) -> Option<Instant> {
        let variant = variant.map(Arc::from);
        match self.state(key, kind, variant.as_ref(), Instant::now()) {
            Known::Failed(t) => Some(t),
            _ => None,
        }
    }

    /// The URL redirects last led a usable `kind` with `variant` to under
    /// `key`, where its carriers start (`None`: its base URL).
    pub fn url(&self, key: &str, kind: CarrierKind, variant: Option<&str>) -> Option<String> {
        let variant = variant.map(Arc::from);
        self.entries()
            .get(&(key.to_owned(), kind, variant))
            .map(|e| e.url.clone())
            .filter(|u| !u.is_empty())
    }

    /// Starts `cand`'s target at the URL the cache remembers for it under
    /// `key`.
    pub(crate) fn prime(&self, key: &str, cand: &crate::Candidate) {
        let Some(t) = cand.target() else { return };
        let variant = cand.variant().map(|v| &**v);
        if let Some(u) = self.url(key, cand.kind(), variant) {
            t.redirected(&u);
        }
    }

    /// What the cache knows, with its times on the wall clock, to be
    /// [restored](Self::restore) later, such as in the next run of the
    /// process ([`CacheSnapshot::to_json`]). Expired entries (both times
    /// past, and the failure time plus the longest backoff past too) are
    /// left out.
    pub fn snapshot(&self) -> CacheSnapshot {
        let (now, wall) = (Instant::now(), WallTime::now());
        let hi = self.0.backoff.1;
        let mut entries: Vec<CacheSnapshotEntry> = self
            .entries()
            .iter()
            .filter(|(_, e)| !e.expired(now, hi))
            .map(|((key, kind, variant), e)| CacheSnapshotEntry {
                key: key.clone(),
                kind: *kind,
                variant: variant.as_deref().map(str::to_owned),
                good_until: e.good_until.map(|t| to_wall(t, now, wall)),
                fail_until: e.fail_until.map(|t| to_wall(t, now, wall)),
                backoff: e.backoff,
                url: e.url.clone(),
            })
            .collect();
        entries.sort_by(|a, b| {
            (&a.key, a.kind.name(), &a.variant).cmp(&(&b.key, b.kind.name(), &b.variant))
        });
        CacheSnapshot { entries }
    }

    /// Merges a snapshot into the cache: for a key and kind that the cache
    /// already holds, or that the snapshot holds more than once, the newer
    /// entry (the later of its two times is later) is kept. A nonzero
    /// backoff outside this cache's bounds is brought within them (the
    /// snapshot may come from another configuration), a time further
    /// ahead than the success TTL (`good_until`) or the longest backoff
    /// (`fail_until`) is brought back to it, and expired entries are
    /// dropped. The cache's configuration is unchanged.
    pub fn restore(&self, snapshot: &CacheSnapshot) {
        let (now, wall) = (Instant::now(), WallTime::now());
        let (lo, hi) = self.0.backoff;
        let bound = |t: WallTime, ahead: Duration| {
            let t = to_mono(t, now, wall);
            now.checked_add(ahead).map_or(t, |b| t.min(b))
        };
        let mut merged: HashMap<CacheKey, CacheEntry> = HashMap::new();
        for s in &snapshot.entries {
            let e = CacheEntry {
                good_until: s.good_until.map(|t| bound(t, self.0.success_ttl)),
                fail_until: s.fail_until.map(|t| bound(t, hi)),
                // 0: no failure in a row.
                backoff: if s.backoff.is_zero() {
                    Duration::ZERO
                } else {
                    s.backoff.clamp(lo, hi)
                },
                url: s.url.clone(),
            };
            if e.expired(now, hi) {
                continue;
            }
            merge(
                &mut merged,
                (s.key.clone(), s.kind, s.variant.as_deref().map(Arc::from)),
                e,
            );
        }
        let mut entries = self.entries();
        for (k, e) in merged {
            merge(&mut entries, k, e);
        }
    }
}

/// Keeps the newer of `e` and the entry at `k`.
fn merge(m: &mut HashMap<CacheKey, CacheEntry>, k: CacheKey, e: CacheEntry) {
    match m.get(&k) {
        Some(o) if e.latest() <= o.latest() => {}
        _ => {
            m.insert(k, e);
        }
    }
}

/// `t` on the wall clock, by its distance from `now` (`wall`).
fn to_wall(t: Instant, now: Instant, wall: WallTime) -> WallTime {
    let n = |d: Duration| d.as_nanos() as i128;
    if t >= now {
        WallTime(wall.0.saturating_add(n(t - now)))
    } else {
        WallTime(wall.0.saturating_sub(n(now - t)))
    }
}

/// The wall-clock time `t` on the monotonic clock; one before the
/// monotonic clock's range is its earliest representable time near `now`.
fn to_mono(t: WallTime, now: Instant, wall: WallTime) -> Instant {
    let d = t.0.saturating_sub(wall.0);
    let span = nanos(d.unsigned_abs());
    if d >= 0 {
        now.checked_add(span)
            .or_else(|| now.checked_add(Duration::from_secs(100 * 365 * 86_400)))
            .unwrap_or(now)
    } else {
        now.checked_sub(span).unwrap_or(now)
    }
}

/// `n` nanoseconds, saturated to the longest [`Duration`].
fn nanos(n: u128) -> Duration {
    let secs = u64::try_from(n / NANOS as u128).unwrap_or(u64::MAX);
    Duration::new(secs, (n % NANOS as u128) as u32)
}

const NANOS: i128 = 1_000_000_000;

/// A wall-clock time of a [`CacheSnapshot`]: nanoseconds since the Unix
/// epoch (negative before it). Exact on every platform, so that the
/// interchange form round-trips whatever the resolution of
/// [`SystemTime`] where it is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WallTime(i128);

impl WallTime {
    /// The current time of the system clock.
    pub fn now() -> Self {
        SystemTime::now().into()
    }

    /// The time `n` nanoseconds after the Unix epoch.
    pub const fn from_unix_nanos(n: i128) -> Self {
        Self(n)
    }

    /// Nanoseconds since the Unix epoch.
    pub const fn unix_nanos(self) -> i128 {
        self.0
    }

    /// The time as a [`SystemTime`], at that clock's resolution; `None`
    /// outside its range.
    pub fn to_system_time(self) -> Option<SystemTime> {
        let span = nanos(self.0.unsigned_abs());
        if self.0 >= 0 {
            UNIX_EPOCH.checked_add(span)
        } else {
            UNIX_EPOCH.checked_sub(span)
        }
    }

    /// `d` later, saturated.
    #[must_use]
    pub fn saturating_add(self, d: Duration) -> Self {
        Self(self.0.saturating_add(d.as_nanos() as i128))
    }

    /// `d` earlier, saturated.
    #[must_use]
    pub fn saturating_sub(self, d: Duration) -> Self {
        Self(self.0.saturating_sub(d.as_nanos() as i128))
    }
}

impl From<SystemTime> for WallTime {
    fn from(t: SystemTime) -> Self {
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => Self(d.as_nanos() as i128),
            Err(e) => Self(-(e.duration().as_nanos() as i128)),
        }
    }
}

/// The content of a [`CarrierCache`] with wall-clock times
/// ([`CarrierCache::snapshot`], [`CarrierCache::restore`]), and its JSON
/// interchange form, the same in every language:
///
/// ```json
/// {"version":1,"entries":[{"key":"…","kind":"websocket",
///   "good_until":"2026-11-01T12:00:00Z","fail_until":"","backoff_ms":60000,"url":""}]}
/// ```
///
/// zmux stores nothing itself; the host keeps the JSON.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct CacheSnapshot {
    /// The entries, in no meaningful order.
    pub entries: Vec<CacheSnapshotEntry>,
}

/// One entry of a [`CacheSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CacheSnapshotEntry {
    /// The server and local network ([`CarrierChoicePolicy::key`](crate::CarrierChoicePolicy::key)).
    pub key: String,
    /// The carrier kind.
    pub kind: CarrierKind,
    /// The candidate's variant.
    pub variant: Option<String>,
    /// Until when the kind is held as usable.
    pub good_until: Option<WallTime>,
    /// Until when the kind is skipped as failed.
    pub fail_until: Option<WallTime>,
    /// The current backoff (zero: no failure in a row).
    pub backoff: Duration,
    /// The final URL that redirects led the kind to (empty: its base).
    pub url: String,
}

impl CacheSnapshotEntry {
    /// An entry of `kind` under `key` that holds nothing yet.
    pub fn new(key: impl Into<String>, kind: CarrierKind) -> Self {
        Self {
            key: key.into(),
            kind,
            variant: None,
            good_until: None,
            fail_until: None,
            backoff: Duration::ZERO,
            url: String::new(),
        }
    }
}

/// The version of the interchange form.
const SNAPSHOT_VERSION: i64 = 1;

/// A [`CacheSnapshot`]'s JSON was rejected: it does not parse, is of
/// another version, has a field of the wrong type, or a negative backoff.
/// Nothing of it is imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotError(String);

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid carrier cache snapshot: {}", self.0)
    }
}

impl std::error::Error for SnapshotError {}

fn invalid(e: impl Into<String>) -> SnapshotError {
    SnapshotError(e.into())
}

impl CacheSnapshot {
    /// The JSON interchange form: times in RFC 3339 UTC, the backoff in
    /// milliseconds, absent fields for no time, no backoff and the base
    /// URL.
    pub fn to_json(&self) -> String {
        let mut out = format!("{{\"version\":{SNAPSHOT_VERSION},\"entries\":[");
        for (i, e) in self.entries.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"key\":");
            json::write_str(&mut out, &e.key);
            out.push_str(",\"kind\":");
            json::write_str(&mut out, e.kind.name());
            for (name, t) in [("good_until", e.good_until), ("fail_until", e.fail_until)] {
                if let Some(t) = t {
                    out.push_str(",\"");
                    out.push_str(name);
                    out.push_str("\":");
                    json::write_str(&mut out, &rfc3339::format(t));
                }
            }
            let ms = e.backoff.as_millis();
            if ms > 0 {
                out.push_str(&format!(",\"backoff_ms\":{}", ms.min(i64::MAX as u128)));
            }
            if !e.url.is_empty() {
                out.push_str(",\"url\":");
                json::write_str(&mut out, &e.url);
            }
            if let Some(v) = &e.variant {
                out.push_str(",\"variant\":");
                json::write_str(&mut out, v);
            }
            out.push('}');
        }
        out.push_str("]}");
        out
    }

    /// Parses the JSON interchange form. Unknown fields are ignored, and
    /// so are entries of a kind this version does not know; empty or
    /// absent times are none. Malformed JSON, a version other than 1, a
    /// field of the wrong type (times are RFC 3339 strings, `backoff_ms` a
    /// non-negative integer) is a [`SnapshotError`].
    pub fn from_json(text: &str) -> Result<Self, SnapshotError> {
        use json::Value;
        let Value::Object(top) = json::parse(text).map_err(invalid)? else {
            return Err(invalid("not an object"));
        };
        match json::field(&top, "version") {
            Some(Value::Int(SNAPSHOT_VERSION)) => {}
            Some(Value::Int(v)) => return Err(invalid(format!("version {v}"))),
            _ => return Err(invalid("no integer version")),
        }
        let list = match json::field(&top, "entries") {
            None | Some(Value::Null) => &[][..],
            Some(Value::Array(a)) => a.as_slice(),
            Some(_) => return Err(invalid("entries not an array")),
        };
        let mut entries = Vec::new();
        for v in list {
            let Value::Object(o) = v else {
                return Err(invalid("an entry not an object"));
            };
            let s = |name: &str| match json::field(o, name) {
                None | Some(Value::Null) => Ok(String::new()),
                Some(Value::Str(s)) => Ok(s.clone()),
                Some(_) => Err(invalid(format!("{name} not a string"))),
            };
            let (key, kind, url) = (s("key")?, s("kind")?, s("url")?);
            let variant = Some(s("variant")?).filter(|v| !v.is_empty());
            let time = |name: &str| -> Result<Option<WallTime>, SnapshotError> {
                let t = s(name)?;
                if t.is_empty() {
                    return Ok(None);
                }
                rfc3339::parse(&t)
                    .map(Some)
                    .ok_or_else(|| invalid(format!("{name} {t:?} not an RFC 3339 time")))
            };
            let (good_until, fail_until) = (time("good_until")?, time("fail_until")?);
            let backoff = match json::field(o, "backoff_ms") {
                None | Some(Value::Null) => Duration::ZERO,
                Some(Value::Int(ms)) if *ms >= 0 => Duration::from_millis(ms.unsigned_abs()),
                Some(_) => return Err(invalid("backoff_ms not a non-negative integer")),
            };
            // A kind of a later version is skipped.
            let Some(kind) = CarrierKind::from_name(&kind) else {
                continue;
            };
            entries.push(CacheSnapshotEntry {
                key,
                kind,
                variant,
                good_until,
                fail_until,
                backoff,
                url,
            });
        }
        Ok(Self { entries })
    }
}

/// RFC 3339 times in UTC.
mod rfc3339 {
    use super::{NANOS, WallTime};

    /// Days since 1970-01-01 of a civil date (proleptic Gregorian).
    fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = y.div_euclid(400);
        let yoe = y - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    fn civil_from_days(z: i64) -> (i64, i64, i64) {
        let z = z + 719_468;
        let era = z.div_euclid(146_097);
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        (yoe + era * 400 + i64::from(m <= 2), m, d)
    }

    /// `t` as `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, the fraction without
    /// trailing zeros.
    pub(super) fn format(t: WallTime) -> String {
        let n = t.unix_nanos();
        let secs =
            i64::try_from(n.div_euclid(NANOS)).unwrap_or(if n < 0 { i64::MIN } else { i64::MAX });
        let nanos = n.rem_euclid(NANOS) as u32;
        let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
        let (y, m, d) = civil_from_days(days);
        let mut s = format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
            rem / 3600,
            rem / 60 % 60,
            rem % 60
        );
        if nanos > 0 {
            let f = format!("{nanos:09}");
            s.push('.');
            s.push_str(f.trim_end_matches('0'));
        }
        s.push('Z');
        s
    }

    fn num(b: &[u8]) -> Option<i64> {
        if b.is_empty() || !b.iter().all(u8::is_ascii_digit) {
            return None;
        }
        Some(b.iter().fold(0, |n, &c| n * 10 + i64::from(c - b'0')))
    }

    /// Parses `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)`.
    pub(super) fn parse(s: &str) -> Option<WallTime> {
        let b = s.as_bytes();
        if b.len() < 20
            || b[4] != b'-'
            || b[7] != b'-'
            || !matches!(b[10], b'T' | b't')
            || b[13] != b':'
            || b[16] != b':'
        {
            return None;
        }
        let (y, mo, d) = (num(&b[0..4])?, num(&b[5..7])?, num(&b[8..10])?);
        let (h, mi, se) = (num(&b[11..13])?, num(&b[14..16])?, num(&b[17..19])?);
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let dim = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        if !(1..=12).contains(&mo)
            || d < 1
            || d > dim[(mo - 1) as usize]
            || h > 23
            || mi > 59
            || se > 59
        {
            return None;
        }
        let mut rest = &b[19..];
        let mut nanos = 0u32;
        if rest.first() == Some(&b'.') {
            let n = rest[1..].iter().take_while(|c| c.is_ascii_digit()).count();
            if n == 0 || n > 9 {
                return None;
            }
            nanos = (num(&rest[1..=n])? * 10i64.pow(9 - n as u32)) as u32;
            rest = &rest[1 + n..];
        }
        let offset = match rest {
            [b'Z' | b'z'] => 0,
            [sign @ (b'+' | b'-'), oh @ .., b':', _, _] if oh.len() == 2 => {
                let (oh, om) = (num(oh)?, num(&rest[4..6])?);
                if oh > 23 || om > 59 {
                    return None;
                }
                let o = oh * 3600 + om * 60;
                if *sign == b'-' { -o } else { o }
            }
            _ => return None,
        };
        let secs = days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + se - offset;
        Some(WallTime::from_unix_nanos(
            i128::from(secs) * NANOS + i128::from(nanos),
        ))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn round_trips() {
            for s in [
                "1970-01-01T00:00:00Z",
                "2026-11-01T12:00:00Z",
                "2026-11-01T12:00:00.5Z",
                // Finer than `SystemTime` on Windows (100 ns).
                "2000-02-29T23:59:59.123456789Z",
                "1969-12-31T23:59:59.25Z",
                "2999-06-01T00:00:00.001Z",
            ] {
                assert_eq!(format(parse(s).unwrap()), s);
            }
            assert_eq!(
                format(parse("2026-11-01T23:30:00+10:00").unwrap()),
                "2026-11-01T13:30:00Z"
            );
            for bad in [
                "tomorrow",
                "2026-11-01",
                "2026-11-01T12:00:00",
                "2026-02-30T12:00:00Z",
                "2026-11-01T24:00:00Z",
                "2026-11-01T12:00:00.Z",
                "2026-11-01 12:00:00Z",
            ] {
                assert!(parse(bad).is_none(), "{bad}");
            }
        }
    }
}

/// The JSON subset of the interchange form: values are parsed whole, so
/// that unknown fields of any type are skipped; integers are kept apart
/// from other numbers.
mod json {
    pub(super) enum Value {
        Null,
        Bool,
        Int(i64),
        /// A number that is not an integer of `i64`.
        Number,
        Str(String),
        Array(Vec<Value>),
        Object(Vec<(String, Value)>),
    }

    /// The last value of `name` (as for duplicate names elsewhere).
    pub(super) fn field<'a>(o: &'a [(String, Value)], name: &str) -> Option<&'a Value> {
        o.iter().rev().find(|(k, _)| k == name).map(|(_, v)| v)
    }

    pub(super) fn write_str(out: &mut String, s: &str) {
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }

    /// Nesting beyond this is refused (no recursion without a bound).
    const MAX_DEPTH: usize = 64;

    pub(super) fn parse(text: &str) -> Result<Value, String> {
        let mut p = Parser {
            b: text.as_bytes(),
            i: 0,
        };
        let v = p.value(0)?;
        p.ws();
        if p.i != p.b.len() {
            return Err(format!("trailing data at {}", p.i));
        }
        Ok(v)
    }

    struct Parser<'a> {
        b: &'a [u8],
        i: usize,
    }

    impl Parser<'_> {
        fn ws(&mut self) {
            while self
                .b
                .get(self.i)
                .is_some_and(|c| matches!(c, b' ' | b'\t' | b'\n' | b'\r'))
            {
                self.i += 1;
            }
        }

        fn err<T>(&self, what: &str) -> Result<T, String> {
            Err(format!("{what} at {}", self.i))
        }

        fn lit(&mut self, word: &[u8], v: Value) -> Result<Value, String> {
            if self.b[self.i..].starts_with(word) {
                self.i += word.len();
                Ok(v)
            } else {
                self.err("unexpected token")
            }
        }

        fn value(&mut self, depth: usize) -> Result<Value, String> {
            if depth > MAX_DEPTH {
                return self.err("nesting too deep");
            }
            self.ws();
            match self.b.get(self.i) {
                None => self.err("unexpected end"),
                Some(b'n') => self.lit(b"null", Value::Null),
                Some(b't') => self.lit(b"true", Value::Bool),
                Some(b'f') => self.lit(b"false", Value::Bool),
                Some(b'"') => self.string().map(Value::Str),
                Some(b'[') => {
                    self.i += 1;
                    let mut a = Vec::new();
                    self.ws();
                    if self.b.get(self.i) == Some(&b']') {
                        self.i += 1;
                        return Ok(Value::Array(a));
                    }
                    loop {
                        a.push(self.value(depth + 1)?);
                        self.ws();
                        match self.b.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b']') => {
                                self.i += 1;
                                return Ok(Value::Array(a));
                            }
                            _ => return self.err("expected , or ]"),
                        }
                    }
                }
                Some(b'{') => {
                    self.i += 1;
                    let mut o = Vec::new();
                    self.ws();
                    if self.b.get(self.i) == Some(&b'}') {
                        self.i += 1;
                        return Ok(Value::Object(o));
                    }
                    loop {
                        self.ws();
                        if self.b.get(self.i) != Some(&b'"') {
                            return self.err("expected a name");
                        }
                        let k = self.string()?;
                        self.ws();
                        if self.b.get(self.i) != Some(&b':') {
                            return self.err("expected :");
                        }
                        self.i += 1;
                        let v = self.value(depth + 1)?;
                        o.push((k, v));
                        self.ws();
                        match self.b.get(self.i) {
                            Some(b',') => self.i += 1,
                            Some(b'}') => {
                                self.i += 1;
                                return Ok(Value::Object(o));
                            }
                            _ => return self.err("expected , or }"),
                        }
                    }
                }
                Some(b'-' | b'0'..=b'9') => self.number(),
                Some(_) => self.err("unexpected character"),
            }
        }

        fn number(&mut self) -> Result<Value, String> {
            let start = self.i;
            let digits = |p: &mut Self| {
                let s = p.i;
                while p.b.get(p.i).is_some_and(u8::is_ascii_digit) {
                    p.i += 1;
                }
                p.i - s
            };
            if self.b.get(self.i) == Some(&b'-') {
                self.i += 1;
            }
            let first = self.i;
            let n = digits(self);
            if n == 0 || (n > 1 && self.b[first] == b'0') {
                return self.err("bad number");
            }
            let mut integer = true;
            if self.b.get(self.i) == Some(&b'.') {
                self.i += 1;
                integer = false;
                if digits(self) == 0 {
                    return self.err("bad number");
                }
            }
            if matches!(self.b.get(self.i), Some(b'e' | b'E')) {
                self.i += 1;
                integer = false;
                if matches!(self.b.get(self.i), Some(b'+' | b'-')) {
                    self.i += 1;
                }
                if digits(self) == 0 {
                    return self.err("bad number");
                }
            }
            let text = std::str::from_utf8(&self.b[start..self.i]).unwrap_or_default();
            Ok(match integer.then(|| text.parse::<i64>().ok()).flatten() {
                Some(v) => Value::Int(v),
                None => Value::Number,
            })
        }

        fn hex4(&mut self) -> Result<u32, String> {
            let h = self
                .b
                .get(self.i..self.i + 4)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u32::from_str_radix(h, 16).ok());
            match h {
                Some(v) => {
                    self.i += 4;
                    Ok(v)
                }
                None => self.err("bad \\u escape"),
            }
        }

        fn string(&mut self) -> Result<String, String> {
            self.i += 1;
            let mut out = Vec::new();
            loop {
                let Some(&c) = self.b.get(self.i) else {
                    return self.err("unterminated string");
                };
                self.i += 1;
                match c {
                    b'"' => break,
                    b'\\' => {
                        let Some(&e) = self.b.get(self.i) else {
                            return self.err("unterminated string");
                        };
                        self.i += 1;
                        let ch = match e {
                            b'"' => '"',
                            b'\\' => '\\',
                            b'/' => '/',
                            b'b' => '\u{8}',
                            b'f' => '\u{c}',
                            b'n' => '\n',
                            b'r' => '\r',
                            b't' => '\t',
                            b'u' => {
                                let hi = self.hex4()?;
                                let cp = if (0xD800..0xDC00).contains(&hi)
                                    && self.b[self.i..].starts_with(b"\\u")
                                {
                                    let save = self.i;
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if (0xDC00..0xE000).contains(&lo) {
                                        0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                    } else {
                                        self.i = save;
                                        0xFFFD
                                    }
                                } else {
                                    hi
                                };
                                char::from_u32(cp).unwrap_or('\u{FFFD}')
                            }
                            _ => return self.err("bad escape"),
                        };
                        let mut buf = [0; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    }
                    c if c < 0x20 => return self.err("control character in string"),
                    c => out.push(c),
                }
            }
            // The input is a &str: unescaped bytes are whole characters.
            String::from_utf8(out).map_err(|_| "bad UTF-8".to_owned())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(t: Instant, now: Instant) -> Duration {
        t.saturating_duration_since(now)
    }

    #[test]
    fn snapshot_round_trips_and_drops_expired() {
        let c = CarrierCache::default();
        let now = Instant::now();
        c.record("k", CarrierKind::Streaming, None, None, false, now);
        c.record("k", CarrierKind::Streaming, None, None, false, now); // 2 min
        c.record("k2", CarrierKind::Streaming, None, None, true, now);
        if let Some(old) = now.checked_sub(Duration::from_secs(7 * 3600)) {
            c.record("old", CarrierKind::Split, None, None, false, old);
        }
        let snap = c.snapshot();
        assert_eq!(snap.entries.len(), 2);
        let json = snap.to_json();
        let back = CacheSnapshot::from_json(&json).unwrap();
        let r = CarrierCache::default();
        r.restore(&back);
        let Known::Failed(t) = r.state("k", CarrierKind::Streaming, None, now) else {
            panic!("backoff not restored");
        };
        assert!(at(t, now).abs_diff(Duration::from_secs(120)) < Duration::from_millis(50));
        assert!(r.is_usable("k2", CarrierKind::Streaming, None));
        assert_eq!(
            r.state("old", CarrierKind::Split, None, now),
            Known::Unknown
        );
        // The restored backoff doubles on the next failure.
        r.record("k", CarrierKind::Streaming, None, None, false, now);
        let Known::Failed(t) = r.state("k", CarrierKind::Streaming, None, now) else {
            panic!();
        };
        assert!(at(t, now).abs_diff(Duration::from_secs(240)) < Duration::from_millis(50));
    }

    /// A reported URL stays while the kind is usable, travels in the
    /// snapshot, and is dropped once the kind fails.
    #[test]
    fn a_redirect_url_is_kept_while_usable() {
        let c = CarrierCache::default();
        let (k, kind) = ("k", CarrierKind::WebSocket);
        let t = crate::HttpTarget::new("wss://a.example/old");
        let cand = crate::Candidate::new(kind, || async {
            Err::<crate::PipeIo, _>(std::io::Error::other("unused"))
        })
        .with_target(Arc::new(crate::HttpTarget::new("wss://a.example/old")));
        let now = Instant::now();
        assert_eq!(c.url(k, kind, None), None);
        t.redirected("wss://a.example/new");
        c.record(k, kind, None, Some(&t), true, now);
        assert_eq!(c.url(k, kind, None).as_deref(), Some("wss://a.example/new"));
        assert_eq!(c.url(k, kind, Some("v")), None);
        // An outcome the host reports keeps it.
        c.report(k, kind, None, CacheOutcome::Usable);
        assert_eq!(c.url(k, kind, None).as_deref(), Some("wss://a.example/new"));
        // A later candidate starts there, in this run or the next.
        let r = CarrierCache::default();
        r.restore(&CacheSnapshot::from_json(&c.snapshot().to_json()).unwrap());
        r.prime(k, &cand);
        assert_eq!(cand.target().unwrap().url(), "wss://a.example/new");
        // A failure forgets it and starts the target at its base again.
        c.record(k, kind, None, Some(&t), false, now);
        assert_eq!(c.url(k, kind, None), None);
        assert_eq!(t.url(), "wss://a.example/old");
    }

    #[test]
    fn restore_bounds_times() {
        let wall = WallTime::now();
        let far = wall.saturating_add(Duration::from_secs(10 * 365 * 86_400));
        let mut s = CacheSnapshot::default();
        let mut good = CacheSnapshotEntry::new("g", CarrierKind::Split);
        good.good_until = Some(far);
        let mut bad = CacheSnapshotEntry::new("f", CarrierKind::Split);
        bad.fail_until = Some(far);
        bad.backoff = Duration::from_secs(60);
        s.entries = vec![good, bad];
        let c = CarrierCache::default();
        // Judged on the monotonic clock the cache keeps: a snapshot's wall
        // times come from a second pair of clock reads, whose skew is no
        // bound of `restore`.
        let ahead = Duration::from_secs(6 * 3600);
        let before = Instant::now();
        c.restore(&s);
        let after = Instant::now();
        for (k, e) in c.entries().iter() {
            for t in [e.good_until, e.fail_until].into_iter().flatten() {
                assert!(
                    t >= before + ahead && t <= after + ahead,
                    "{k:?} not at its bound"
                );
            }
        }
        assert!(c.is_usable("g", CarrierKind::Split, None));
        assert!(c.failed_until("f", CarrierKind::Split, None).is_some());
    }

    #[test]
    fn json_rejects_whole() {
        for bad in [
            r#"{"version":2,"entries":[]}"#,
            r#"{"entries":[]}"#,
            "not json",
            r#"{"version":"1","entries":[]}"#,
            r#"{"version":1,"entries":[{"key":"z","kind":"split","backoff_ms":-1}]}"#,
            r#"{"version":1,"entries":[{"key":"z","kind":"split","backoff_ms":1.5}]}"#,
            r#"{"version":1,"entries":[{"key":"z","kind":"split","backoff_ms":1e3}]}"#,
            r#"{"version":1,"entries":[{"key":"z","kind":"split","good_until":3}]}"#,
            r#"{"version":1,"entries":[{"key":"z","kind":"split","good_until":"tomorrow"}]}"#,
            r#"{"version":1,"entries":[{"key":3,"kind":"split"}]}"#,
            r#"{"version":1,"entries":{}}"#,
            r#"{"version":1,"entries":[]} x"#,
        ] {
            assert!(CacheSnapshot::from_json(bad).is_err(), "{bad}");
        }
        let ok = CacheSnapshot::from_json(
            r#"{"version":1,"x":[{"y":null}],"entries":[{"key":"ké","kind":"split","n":1e9},{"key":"k","kind":"later"}]}"#,
        )
        .unwrap();
        assert_eq!(
            ok.entries,
            [CacheSnapshotEntry::new("ké", CarrierKind::Split)]
        );
    }
}
