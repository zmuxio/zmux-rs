//! A pool policy read from a JSON object of values.

use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use serde::Deserialize;

use crate::bound::Family;
use crate::def::{Error, Scope, Value, err};
use crate::machine::Options;
use crate::random::Rand;
use crate::value::{Draw, Keep, Num, compile};

/// A member of a pool as a [`MachinePoolPolicy`] sees it.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct PoolMember {
    /// The member's ID; values of scope `pipe` are kept per ID.
    pub id: u64,
    /// Time since it was added.
    pub age: Duration,
    /// Time since it last carried traffic: for a pipe, its
    /// `since_last_traffic` (probes, acknowledgements and padding do not
    /// count); the pool computes it.
    pub idle: Duration,
    /// Pipes it carries.
    pub pipes: u64,
    /// Bytes sent.
    pub bytes_sent: u64,
    /// Bytes received.
    pub bytes_received: u64,
}

impl PoolMember {
    /// The member `id`, every metric zero.
    pub fn new(id: u64) -> Self {
        Self {
            id,
            ..Self::default()
        }
    }
}

/// The answer of [`MachinePoolPolicy::decide_members`]; `None` and an
/// empty list keep the pool's own behaviour.
#[derive(Debug, Clone, Default, PartialEq)]
#[non_exhaustive]
pub struct MemberDecision {
    /// Members to keep (at least 1); above 2^53 the decision is not
    /// [valid](Self::validate).
    pub count: Option<usize>,
    /// Earliest next dial after the last one, in seconds as drawn
    /// (reduced by the wait's `dial_jitter` draw); `None`: not set. A
    /// negative value makes the decision not [valid](Self::validate).
    pub dial_after: Option<f64>,
    /// IDs of members to retire, in the order given, each once.
    pub retire: Vec<u64>,
    /// Decide again within this, even if nothing changes: the soonest a
    /// time-based `retire` rule (`age`, `idle`) of a member not retired
    /// fires, or `dial_after` elapses after the last dial; `None`: no
    /// such time. Never zero (a rule at its threshold gives the smallest
    /// duration); pools bound it from below.
    pub recheck: Option<Duration>,
    /// The idle-probe interval of the pipes added from now on, in
    /// seconds as drawn (0: no idle probes); `None`: not set. Any other
    /// value below 1 s makes the decision not [valid](Self::validate).
    pub probe_interval: Option<f64>,
    /// Their idle-probe jitter; `None`: not set.
    pub probe_jitter: Option<f64>,
}

impl MemberDecision {
    /// Whether the decision is valid: a count, if set, of at most 2^53, an
    /// idle-probe interval, if set, of
    /// 0 or at least 1 s, and a dial delay, if set, of at least 0. A pool
    /// rejects one that is not as a whole.
    pub fn validate(&self) -> Result<(), Error> {
        if let Some(n) = self.count.filter(|n| *n as u64 > 1 << 53) {
            return Err(err(format!("pool count: {n}, above 2^53")));
        }
        if let Some(x) = self.dial_after.filter(|x| x.is_nan() || *x < 0.0) {
            return Err(err(format!("pool dial_after: {x} s, negative")));
        }
        match self.probe_interval {
            Some(x) if x != 0.0 && !(1.0..=1e9).contains(&x) => Err(err(format!(
                "pool probe_interval: {x} s, neither 0 nor in [1, 1e9]"
            ))),
            _ => Ok(()),
        }
    }
}

/// A metric of a member.
type Metric = fn(&PoolMember) -> f64;

/// The metrics that grow with time by themselves.
const TIMED: &[&str] = &["age", "idle"];

/// The metrics a `retire` rule may name, by name.
const METRICS: &[(&str, Metric)] = &[
    ("age", |m| m.age.as_secs_f64()),
    ("idle", |m| m.idle.as_secs_f64()),
    ("pipes", |m| m.pipes as f64),
    ("bytes_sent", |m| m.bytes_sent as f64),
    ("bytes_received", |m| m.bytes_received as f64),
    ("bytes", |m| m.bytes_sent as f64 + m.bytes_received as f64),
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Spec {
    count: Option<Value>,
    #[serde(default)]
    dial_after: Vec<Value>,
    dial_jitter: Option<f64>,
    #[serde(default)]
    retire: Vec<RuleSpec>,
    probe_interval: Option<Value>,
    probe_jitter: Option<f64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    metric: String,
    above: Value,
    jitter: Option<f64>,
}

struct Rule {
    metric: Metric,
    above: usize,
    /// The threshold is reduced by up to this fraction, per member.
    jitter: f64,
    /// The metric grows with time (see [`TIMED`]).
    timed: bool,
}

/// A jitter: a number, at least 0 and below 1.
fn jitter(j: Option<f64>, what: &str) -> Result<f64, Error> {
    match j {
        None => Ok(0.0),
        Some(j) if (0.0..1.0).contains(&j) => Ok(j),
        Some(j) => Err(err(format!("pool {what}: {j} outside [0, 1)"))),
    }
}

/// The wait for the next dial that a `dial_jitter` draw belongs to: the
/// failures and the time since the last dial of the decision that drew it.
#[derive(Clone, Copy)]
struct DialWait {
    failures: u32,
    since_dial: Option<Duration>,
    u: f64,
}

/// A pool policy read by [`pool_policy`].
///
/// Each decision sets the count from `count`, the delay of the next dial
/// from the entry of `dial_after` for the number of consecutive failures
/// (the last entry for any higher number), and lists the members for which
/// a `retire` rule's metric exceeds its threshold, and asks to decide again
/// when the next time-based rule fires or the dial delay elapses (see
/// [`MemberDecision::recheck`]). Values of scope
/// `shared` are drawn once per policy, of scope
/// `pipe` once per member ID while the member is in view, of any other
/// scope at each decision. A decision does not block and does not fail.
pub struct MachinePoolPolicy {
    nums: Vec<Num>,
    count: Option<usize>,
    dial_after: Vec<usize>,
    dial_jitter: f64,
    wait: Option<DialWait>,
    rules: Vec<Rule>,
    probe_interval: Option<usize>,
    probe_jitter: Option<f64>,
    d: Draw,
    shared: Vec<Option<f64>>,
    members: HashMap<u64, Kept>,
}

/// What is kept per member: its values of scope `pipe`, and the draw of
/// each rule's jitter.
struct Kept {
    values: Vec<Option<f64>>,
    jitter: Vec<f64>,
}

impl fmt::Debug for MachinePoolPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MachinePoolPolicy")
            .field("members", &self.members.len())
            .finish_non_exhaustive()
    }
}

/// Reads a pool policy: a JSON object with the optional fields `count`
/// (a value that cannot draw below 1: a distribution that can needs a
/// `min` of at least 1), `dial_after` (a list of values, one per number of
/// consecutive failures from 0, the last for any higher number),
/// `dial_jitter` (a number j in \[0, 1), only with `dial_after`: each wait
/// for a dial is reduced by its own random fraction of up to j), `retire`
/// (a list of `{"metric": name, "above": value, "jitter": j}`; names `age`,
/// `idle` (seconds), `pipes`, `bytes_sent`, `bytes_received`, `bytes`
/// (their sum); the optional jitter in \[0, 1) reduces the threshold by a
/// random fraction of up to j drawn once per member),
/// `probe_interval` (a value in seconds, for the pipes added
/// from then on) and `probe_jitter` (a number in \[0, 1), only with
/// `probe_interval`; a draw other than 0 below 1 s makes the decision not
/// valid). Values have the form and validation of a definition's;
/// scope `pipe` is accepted only in `retire`. Times are in seconds. An
/// absent field keeps the pool's own behaviour; an unknown field is an
/// error. The input is bounded by `options.limits.max_bytes`; values are
/// drawn from `options`' random source.
pub fn pool_policy(json: &[u8], options: Options) -> Result<MachinePoolPolicy, Error> {
    MachinePoolPolicy::from_json(json, options)
}

impl MachinePoolPolicy {
    /// See [`pool_policy`].
    pub fn from_json(json: &[u8], options: Options) -> Result<Self, Error> {
        options.limits.input("pool", json.len())?;
        let spec: Spec = crate::json::from_slice("pool", json)?;
        let mut nums = Vec::new();
        let member_free = |v: &Value, fam: Family, what: &str, nums: &mut Vec<Num>| {
            v.check(fam, &format!("pool {what}"))?;
            Ok::<usize, Error>(compile(nums, v))
        };
        let count = match &spec.count {
            Some(v) => Some(member_free(v, Family::PoolCount, "count", &mut nums)?),
            None => None,
        };
        let dial_after = spec
            .dial_after
            .iter()
            .map(|v| member_free(v, Family::PoolSeconds, "dial_after", &mut nums))
            .collect::<Result<Vec<_>, _>>()?;
        let dial_jitter = jitter(spec.dial_jitter, "dial_jitter")?;
        if spec.dial_jitter.is_some() && dial_after.is_empty() {
            return Err(err("pool dial_jitter: no dial_after"));
        }
        let probe_interval = match &spec.probe_interval {
            Some(v) => Some(member_free(
                v,
                Family::PoolProbe,
                "probe_interval",
                &mut nums,
            )?),
            None => None,
        };
        let probe_jitter = match spec.probe_jitter {
            Some(_) if probe_interval.is_none() => {
                return Err(err("pool probe_jitter: no probe_interval"));
            }
            j => j.map(|j| jitter(Some(j), "probe_jitter")).transpose()?,
        };
        let mut rules = Vec::new();
        for r in &spec.retire {
            let Some(&(_, metric)) = METRICS.iter().find(|(n, _)| *n == r.metric) else {
                return Err(err(format!("pool retire: unknown metric {:?}", r.metric)));
            };
            let timed = TIMED.contains(&r.metric.as_str());
            let fam = if timed {
                Family::RuleSeconds
            } else {
                Family::RuleCount
            };
            r.above.check(fam, &format!("pool retire {}", r.metric))?;
            rules.push(Rule {
                metric,
                above: compile(&mut nums, &r.above),
                jitter: jitter(r.jitter, &format!("retire {} jitter", r.metric))?,
                timed,
            });
        }
        let n = nums.len();
        Ok(Self {
            nums,
            count,
            dial_after,
            dial_jitter,
            wait: None,
            rules,
            probe_interval,
            probe_jitter,
            d: Draw::new(Rand(options.source()), n),
            shared: vec![None; n],
            members: HashMap::new(),
        })
    }

    /// Decides for a pool whose members are `members` (in view order),
    /// whose dials failed `failures` times in a row and whose last dial
    /// started `since_dial` ago (`None`: none), which the recheck uses and
    /// which with `failures` tells a new wait for a dial (other failures,
    /// a shorter or a first time since the last dial) from the one of the
    /// previous decision. Values kept for IDs not in `members` are dropped;
    /// a member seen for the first time draws its rules' jitter.
    pub fn decide_members(
        &mut self,
        failures: u32,
        since_dial: Option<Duration>,
        members: &[PoolMember],
        out: &mut MemberDecision,
    ) {
        let mut recheck: Option<f64> = None;
        let mut soon = |x: f64| recheck = Some(recheck.map_or(x, |r| r.min(x)));
        self.members
            .retain(|id, _| members.iter().any(|m| m.id == *id));
        if let Some(i) = self.count {
            // Validated at least 1.
            let x = self.sample(i, None).round();
            // Saturating: a draw above 2^53 makes the decision not valid.
            out.count = Some(x as usize);
        }
        for m in members {
            if !self.members.contains_key(&m.id) {
                let jitter = (0..self.rules.len())
                    .map(|r| {
                        if self.rules[r].jitter > 0.0 {
                            self.d.r.float()
                        } else {
                            0.0
                        }
                    })
                    .collect();
                let values = vec![None; self.nums.len()];
                self.members.insert(m.id, Kept { values, jitter });
            }
        }
        if !self.dial_after.is_empty() {
            let k = (failures as usize).min(self.dial_after.len() - 1);
            let x = self.sample(self.dial_after[k], None);
            let u = self.wait_draw(failures, since_dial);
            // A negative sample is passed on as it is: the decision fails
            // `validate` and the pool rejects it.
            let x = x * (1.0 - self.dial_jitter * u);
            out.dial_after = Some(x);
            if let Some(left) = since_dial
                .map(|s| x - s.as_secs_f64())
                .filter(|&l| x >= 0.0 && l > 0.0)
            {
                soon(left);
            }
        }
        if let Some(i) = self.probe_interval {
            let x = self.sample(i, None);
            out.probe_interval = Some(x);
            out.probe_jitter = self.probe_jitter;
        }
        for m in members {
            let mut fires: Option<f64> = None;
            let mut retired = false;
            for r in 0..self.rules.len() {
                let Rule {
                    metric,
                    above,
                    jitter,
                    timed,
                } = self.rules[r];
                let u = self.members.get(&m.id).map_or(0.0, |k| k.jitter[r]);
                let t = self.sample(above, Some(m.id)) * (1.0 - jitter * u);
                let x = metric(m);
                if x > t {
                    if !out.retire.contains(&m.id) {
                        out.retire.push(m.id);
                    }
                    retired = true;
                    break;
                }
                if timed {
                    fires = Some(fires.map_or(t - x, |f| f.min(t - x)));
                }
            }
            if let Some(f) = fires.filter(|_| !retired) {
                soon(f);
            }
        }
        out.recheck = recheck
            .map(|r| Duration::from_secs_f64(r.clamp(0.0, 1e9)).max(Duration::from_nanos(1)));
    }

    /// The `dial_jitter` draw of the current wait: the previous decision's,
    /// unless a new wait started.
    fn wait_draw(&mut self, failures: u32, since_dial: Option<Duration>) -> f64 {
        if self.dial_jitter <= 0.0 {
            return 0.0;
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
            _ => self.d.r.float(),
        };
        self.wait = Some(DialWait {
            failures,
            since_dial,
            u,
        });
        u
    }

    fn sample(&mut self, i: usize, member: Option<u64>) -> f64 {
        let n = self.nums.len();
        let kept = member.map(|id| {
            &mut self
                .members
                .entry(id)
                .or_insert_with(|| Kept {
                    values: vec![None; n],
                    jitter: Vec::new(),
                })
                .values
        });
        let mut k = PolicyKeep {
            shared: &mut self.shared,
            member: kept,
        };
        self.d.sample(&self.nums, i, &mut k)
    }
}

struct PolicyKeep<'a> {
    shared: &'a mut [Option<f64>],
    member: Option<&'a mut Vec<Option<f64>>>,
}

impl Keep for PolicyKeep<'_> {
    fn kept(&mut self, i: usize, scope: Scope) -> Option<f64> {
        match scope {
            Scope::Shared => self.shared[i],
            Scope::Pipe => self.member.as_ref().and_then(|m| m[i]),
            _ => None,
        }
    }

    fn keep(&mut self, i: usize, scope: Scope, x: f64) {
        match scope {
            Scope::Shared => self.shared[i] = Some(x),
            Scope::Pipe => {
                if let Some(m) = self.member.as_mut() {
                    m[i] = Some(x);
                }
            }
            _ => {}
        }
    }
}

#[cfg(feature = "tokio")]
impl zmux::helpers::PoolPolicy for MachinePoolPolicy {
    /// Members are the view's members (ID = their first pipe's, idle for
    /// the least `since_last_traffic` of their pipes, bytes summed);
    /// failures are the consecutive failed redials; the next dial is at
    /// the start of the last dial (or of the pool) plus the delay; retired
    /// members are replaced now; the recheck is
    /// [`MemberDecision::recheck`]; the idle-probe settings go to the pipes
    /// added from now on. A decision that is not
    /// [valid](MemberDecision::validate) is rejected
    /// ([`PoolDecision::reject`](zmux::helpers::PoolDecision::reject)): the
    /// pool keeps its own behaviour and reports it.
    fn decide(
        &mut self,
        view: &zmux::helpers::PoolView<'_>,
        out: &mut zmux::helpers::PoolDecision,
    ) {
        let now = view.now;
        let members: Vec<PoolMember> = view
            .members
            .iter()
            .map(|m| PoolMember {
                id: m.id.get(),
                age: m.age(),
                idle: m.since_last_traffic().unwrap_or_default(),
                pipes: m.pipes.len() as u64,
                bytes_sent: m.bytes_sent(),
                bytes_received: m.bytes_received(),
            })
            .collect();
        let mut d = MemberDecision::default();
        let since = view.last_dial_at.map(|t| now.saturating_duration_since(t));
        self.decide_members(view.redial_failures, since, &members, &mut d);
        if let Err(e) = d.validate() {
            out.reject(e.to_string());
            return;
        }
        if let Some(c) = d.count {
            out.count = Some(c);
        }
        if let Some(after) = d.dial_after {
            // Valid: at least 0; a delay beyond the clock's range never comes.
            let after = Duration::try_from_secs_f64(after).unwrap_or(Duration::MAX);
            out.next_dial_at = view.last_dial_at.unwrap_or(view.started).checked_add(after);
        }
        out.rotate
            .extend(d.retire.into_iter().map(|id| (zmux::PipeId::new(id), now)));
        if let Some(r) = d.recheck {
            out.recheck = Some(out.recheck.map_or(r, |o| o.min(r)));
        }
        // Both are within bounds: the interval was validated above, the
        // jitter when the policy was built. A file's 0 turns the probes off.
        if let Some(i) = d.probe_interval {
            let _ = out.set_probe_interval(if i == 0.0 {
                zmux::proto::session::Period::Off
            } else {
                zmux::proto::session::Period::Every(Duration::from_secs_f64(i))
            });
        }
        if let Some(j) = d.probe_jitter {
            let _ = out.set_probe_jitter(j);
        }
    }
}
