//! A pool policy read from configuration. Times are microseconds, proportions parts per
//! million.

use std::collections::HashMap;
use std::fmt;

use crate::error::{Error, err};
use crate::json::{Json, parse};
use crate::machine::Options;
use crate::value::{
    ALL_SCOPES, FREE_SCOPES, Family, Reader, Sampler, Scope, Value, int, jitter_with, parse_value,
};

/// A member of a pool as a [`MachinePoolPolicy`] sees it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct PoolMember {
    /// The member's ID; values of scope `pipe` are kept per ID.
    pub id: u64,
    /// Microseconds since it was added.
    pub age: u64,
    /// Microseconds since it last carried traffic.
    pub idle: u64,
    /// Pipes it carries.
    pub pipes: u64,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
}

impl PoolMember {
    /// The member `id`, every metric zero.
    #[must_use]
    pub fn new(id: u64) -> Self {
        Self {
            id,
            ..Self::default()
        }
    }
}

/// The answer of [`MachinePoolPolicy::decide_members`]; `None` and an empty list keep the
/// pool's own behaviour.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MemberDecision {
    /// Members to keep.
    pub count: Option<u64>,
    /// Earliest next dial after the last one, microseconds.
    pub dial_after: Option<u64>,
    /// IDs of members to retire, in the order given, each once.
    pub retire: Vec<u64>,
    /// Decide again within this many microseconds, even if nothing changes; never 0.
    pub recheck: Option<u64>,
    /// The idle-probe interval of the pipes added from now on, microseconds; 0: none.
    pub probe_interval: Option<u64>,
    /// Their idle-probe jitter, parts per million.
    pub probe_jitter: Option<u32>,
}

impl MemberDecision {
    /// Whether the decision is valid: an idle-probe interval, if set, of 0 or in
    /// \[10^6, 10^15\] microseconds. A pool rejects one that is not as a whole.
    pub fn validate(&self) -> Result<(), Error> {
        match self.probe_interval {
            Some(x) if x != 0 && !(1_000_000..=1_000_000_000_000_000).contains(&x) => {
                Err(err("range", format!("pool probe_interval: {x}")))
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Metric {
    Age,
    Idle,
    Pipes,
    BytesSent,
    BytesReceived,
    Bytes,
}

impl Metric {
    const fn timed(self) -> bool {
        matches!(self, Self::Age | Self::Idle)
    }

    const fn of(self, m: &PoolMember) -> u64 {
        match self {
            Self::Age => m.age,
            Self::Idle => m.idle,
            Self::Pipes => m.pipes,
            Self::BytesSent => m.bytes_sent,
            Self::BytesReceived => m.bytes_received,
            Self::Bytes => m.bytes_sent.saturating_add(m.bytes_received),
        }
    }
}

#[derive(Debug, Clone)]
struct Rule {
    metric: Metric,
    above: Value,
    jitter: u32,
}

/// A pool's configuration.
#[derive(Debug, Clone, Default)]
pub(crate) struct PoolSpec {
    count: Option<Value>,
    dial_after: Vec<Value>,
    dial_jitter: u32,
    rules: Vec<Rule>,
    probe_interval: Option<Value>,
    probe_jitter: Option<u32>,
    pipe_slots: usize,
}

fn jitter(x: &Json, what: &str) -> Result<u32, Error> {
    let v = int(x).ok_or_else(|| err("type", what.to_owned()))?;
    if !(0..1_000_000).contains(&v) {
        return Err(err("range", what.to_owned()));
    }
    Ok(v as u32)
}

impl PoolSpec {
    pub(crate) fn parse(x: &Json, tables: &Reader<'_>) -> Result<Self, Error> {
        let Json::Obj(m) = x else {
            return Err(err("type", "pool"));
        };
        let allowed = [
            "count",
            "dial_after",
            "dial_jitter",
            "retire",
            "probe_interval",
            "probe_jitter",
        ];
        if let Some((k, _)) = m.iter().find(|(k, _)| !allowed.contains(&k.as_str())) {
            return Err(err("unknown_member", format!("pool.{k}")));
        }
        let mut s = Self::default();
        if let Some(c) = x.get("count") {
            s.count = Some(parse_value(
                c,
                Family::PoolCount,
                tables,
                FREE_SCOPES,
                "count",
            )?);
        }
        if let Some(d) = x.get("dial_after") {
            let Json::Arr(d) = d else {
                return Err(err("type", "dial_after"));
            };
            for v in d {
                s.dial_after.push(parse_value(
                    v,
                    Family::Time,
                    tables,
                    FREE_SCOPES,
                    "dial_after",
                )?);
            }
        }
        if let Some(j) = x.get("dial_jitter") {
            s.dial_jitter = jitter(j, "dial_jitter")?;
            if s.dial_after.is_empty() {
                return Err(err("conflict", "dial_jitter without dial_after"));
            }
        }
        if let Some(r) = x.get("retire") {
            let Json::Arr(r) = r else {
                return Err(err("type", "retire"));
            };
            for q in r {
                s.rules.push(Self::rule(q, tables)?);
            }
        }
        if let Some(p) = x.get("probe_interval") {
            s.probe_interval = Some(parse_value(
                p,
                Family::Time,
                tables,
                FREE_SCOPES,
                "probe_interval",
            )?);
        }
        if let Some(j) = x.get("probe_jitter") {
            s.probe_jitter = Some(jitter(j, "probe_jitter")?);
            if s.probe_interval.is_none() {
                return Err(err("conflict", "probe_jitter without probe_interval"));
            }
        }
        Ok(s)
    }

    fn rule(q: &Json, tables: &Reader<'_>) -> Result<Rule, Error> {
        let Json::Obj(m) = q else {
            return Err(err("type", "retire"));
        };
        if let Some((k, _)) = m
            .iter()
            .find(|(k, _)| !["metric", "above", "jitter"].contains(&k.as_str()))
        {
            return Err(err("unknown_member", format!("retire.{k}")));
        }
        let metric = match q.get("metric") {
            Some(Json::Str(s)) => match s.as_str() {
                "age" => Metric::Age,
                "idle" => Metric::Idle,
                "pipes" => Metric::Pipes,
                "bytes_sent" => Metric::BytesSent,
                "bytes_received" => Metric::BytesReceived,
                "bytes" => Metric::Bytes,
                _ => return Err(err("type", "metric")),
            },
            _ => return Err(err("type", "metric")),
        };
        let fam = if metric.timed() {
            Family::Time
        } else {
            Family::Counter
        };
        let above = q.get("above").ok_or_else(|| err("type", "retire.above"))?;
        Ok(Rule {
            metric,
            above: parse_value(above, fam, tables, ALL_SCOPES, "above")?,
            jitter: q.get("jitter").map_or(Ok(0), |j| jitter(j, "jitter"))?,
        })
    }

    /// Settles `shared` values and places `pipe` ones.
    pub(crate) fn settle(&mut self, s: &mut Sampler, shared: &mut Vec<u64>) {
        if let Some(v) = &mut self.count {
            v.settle(s, shared);
        }
        for v in &mut self.dial_after {
            v.settle(s, shared);
        }
        let mut slots = 0;
        for r in &mut self.rules {
            if r.above.scope == Scope::Pipe {
                r.above.slot = slots;
                slots += 1;
            } else {
                r.above.settle(s, shared);
            }
        }
        self.pipe_slots = slots;
        if let Some(v) = &mut self.probe_interval {
            v.settle(s, shared);
        }
    }
}

/// The wait for the next dial that a `dial_jitter` draw belongs to.
#[derive(Clone, Copy)]
struct DialWait {
    failures: u32,
    since_dial: Option<u64>,
    u: u64,
}

/// What is kept per member: its `pipe` values, and the draw of each rule's jitter.
struct Kept {
    values: Vec<Option<u64>>,
    jitter: Vec<u64>,
}

/// A pool policy: each decision sets the count, the delay of the next dial from the entry
/// of `dial_after` for the number of consecutive failures (the last entry for any higher
/// number), and lists the members for which a `retire` rule's metric exceeds its threshold.
pub struct MachinePoolPolicy {
    spec: PoolSpec,
    sampler: Sampler,
    wait: Option<DialWait>,
    members: HashMap<u64, Kept>,
}

impl fmt::Debug for MachinePoolPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachinePoolPolicy")
            .field("members", &self.members.len())
            .finish_non_exhaustive()
    }
}

/// Reads a pool policy: a JSON object with the optional members `count`, `dial_after`,
/// `dial_jitter`, `retire` (`metric`, `above`, `jitter`), `probe_interval`, `probe_jitter`.
pub fn pool_policy(json: &[u8], options: Options) -> Result<MachinePoolPolicy, Error> {
    MachinePoolPolicy::from_json(json, options)
}

impl MachinePoolPolicy {
    /// See [`pool_policy`].
    pub fn from_json(json: &[u8], options: Options) -> Result<Self, Error> {
        options.limits.input(json.len())?;
        let mut spec = PoolSpec::parse(&parse(json)?, &Reader::new(None, options.limits))?;
        let mut sampler = options.sampler();
        spec.settle(&mut sampler, &mut Vec::new());
        Ok(Self {
            spec,
            sampler,
            wait: None,
            members: HashMap::new(),
        })
    }

    pub(crate) fn from_spec(spec: PoolSpec, options: &Options) -> Self {
        Self {
            spec,
            sampler: options.sampler(),
            wait: None,
            members: HashMap::new(),
        }
    }

    /// Decides for a pool whose members are `members`, whose dials failed `failures` times
    /// in a row and whose last dial started `since_dial` microseconds ago. Values kept for
    /// IDs not in `members` are dropped; a member seen for the first time draws its rules'
    /// jitter.
    pub fn decide_members(
        &mut self,
        failures: u32,
        since_dial: Option<u64>,
        members: &[PoolMember],
        out: &mut MemberDecision,
    ) {
        let mut recheck: Option<u64> = None;
        let mut soon = |x: u64| recheck = Some(recheck.map_or(x, |r: u64| r.min(x)));
        self.members
            .retain(|id, _| members.iter().any(|m| m.id == *id));
        if let Some(v) = &self.spec.count {
            out.count = Some(self.sampler.draw(v));
        }
        if !self.spec.dial_after.is_empty() {
            let k = (failures as usize).min(self.spec.dial_after.len() - 1);
            let x = self.sampler.draw(&self.spec.dial_after[k]);
            let u = self.wait_draw(failures, since_dial);
            let x = if self.spec.dial_jitter > 0 {
                jitter_with(u, x, self.spec.dial_jitter)
            } else {
                x
            };
            out.dial_after = Some(x);
            if let Some(left) = since_dial.map(|s| x.saturating_sub(s)).filter(|l| *l > 0) {
                soon(left);
            }
        }
        if let Some(v) = &self.spec.probe_interval {
            out.probe_interval = Some(self.sampler.draw(v));
            out.probe_jitter = self.spec.probe_jitter;
        }
        for m in members {
            if !self.members.contains_key(&m.id) {
                let jitter = (0..self.spec.rules.len())
                    .map(|r| {
                        if self.spec.rules[r].jitter > 0 {
                            self.sampler.next_u64()
                        } else {
                            0
                        }
                    })
                    .collect();
                let values = vec![None; self.spec.pipe_slots];
                self.members.insert(m.id, Kept { values, jitter });
            }
            let mut fires: Option<u64> = None;
            let mut retired = false;
            for r in 0..self.spec.rules.len() {
                let t = self.threshold(r, m.id);
                let rule = &self.spec.rules[r];
                let x = rule.metric.of(m);
                if x > t {
                    if !out.retire.contains(&m.id) {
                        out.retire.push(m.id);
                    }
                    retired = true;
                    break;
                }
                if rule.metric.timed() {
                    let left = (t - x).max(1);
                    fires = Some(fires.map_or(left, |f| f.min(left)));
                }
            }
            if let Some(f) = fires.filter(|_| !retired) {
                soon(f);
            }
        }
        out.recheck = recheck;
    }

    fn threshold(&mut self, r: usize, id: u64) -> u64 {
        let rule = &self.spec.rules[r];
        let kept = self.members.get_mut(&id).expect("seen above");
        let v = if rule.above.scope == Scope::Pipe {
            *kept.values[rule.above.slot].get_or_insert_with(|| self.sampler.draw(&rule.above))
        } else {
            self.sampler.draw(&rule.above)
        };
        if rule.jitter > 0 {
            jitter_with(kept.jitter[r], v, rule.jitter)
        } else {
            v
        }
    }

    /// The `dial_jitter` draw of the current wait: the previous decision's, unless a new
    /// wait started.
    fn wait_draw(&mut self, failures: u32, since_dial: Option<u64>) -> u64 {
        if self.spec.dial_jitter == 0 {
            return 0;
        }
        let same = self.wait.is_some_and(|w| {
            w.failures == failures
                && match (w.since_dial, since_dial) {
                    (None, None) => true,
                    (Some(a), Some(b)) => b >= a,
                    _ => false,
                }
        });
        let u = match self.wait {
            Some(w) if same => w.u,
            _ => self.sampler.next_u64(),
        };
        self.wait = Some(DialWait {
            failures,
            since_dial,
            u,
        });
        u
    }
}

#[cfg(feature = "tokio")]
impl zmux::helpers::PoolPolicy for MachinePoolPolicy {
    /// Members are the view's members (ID = their first pipe's, idle for the least
    /// `since_last_traffic` of their pipes, bytes summed); failures are the consecutive
    /// failed redials; the next dial is at the start of the last dial (or of the pool) plus
    /// the delay; retired members are replaced now. A decision that is not
    /// [valid](MemberDecision::validate) is rejected.
    fn decide(
        &mut self,
        view: &zmux::helpers::PoolView<'_>,
        out: &mut zmux::helpers::PoolDecision,
    ) {
        use std::time::Duration;
        let micros = |d: Duration| u64::try_from(d.as_micros()).unwrap_or(u64::MAX);
        let now = view.now;
        let members: Vec<PoolMember> = view
            .members
            .iter()
            .map(|m| PoolMember {
                id: m.id.get(),
                age: micros(m.age()),
                idle: m.since_last_traffic().map_or(0, micros),
                pipes: m.pipes.len() as u64,
                bytes_sent: m.bytes_sent(),
                bytes_received: m.bytes_received(),
            })
            .collect();
        let mut d = MemberDecision::default();
        let since = view
            .last_dial_at
            .map(|t| micros(now.saturating_duration_since(t)));
        self.decide_members(view.redial_failures, since, &members, &mut d);
        if let Err(e) = d.validate() {
            out.reject(e.to_string());
            return;
        }
        if let Some(c) = d.count {
            out.count = Some(usize::try_from(c).unwrap_or(usize::MAX));
        }
        if let Some(after) = d.dial_after {
            let after = Duration::from_micros(after);
            out.next_dial_at = view.last_dial_at.unwrap_or(view.started).checked_add(after);
        }
        out.rotate
            .extend(d.retire.into_iter().map(|id| (zmux::PipeId::new(id), now)));
        if let Some(r) = d.recheck {
            let r = Duration::from_micros(r);
            out.recheck = Some(out.recheck.map_or(r, |o| o.min(r)));
        }
        // Both are within bounds: the interval was validated above, the jitter when the
        // policy was built. A file's 0 turns the probes off.
        if let Some(i) = d.probe_interval {
            let _ = out.set_probe_interval(if i == 0 {
                zmux::proto::session::Period::Off
            } else {
                zmux::proto::session::Period::Every(Duration::from_micros(i))
            });
        }
        if let Some(j) = d.probe_jitter {
            let _ = out.set_probe_jitter(f64::from(j) / 1e6);
        }
    }
}
