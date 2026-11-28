//! Pool profile values compiled into session controller targets.

use crate::error::{Error, err};
use crate::json::Json;
#[cfg(feature = "tokio")]
use crate::machine::Options;
use crate::value::{
    ALL_SCOPES, FREE_SCOPES, Family, Reader, Sampler, Scope, Value, int, parse_value, to_u32,
};

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
}

#[derive(Debug, Clone)]
struct Rule {
    #[cfg(feature = "tokio")]
    metric: Metric,
    above: Value,
    #[cfg(feature = "tokio")]
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
}

fn jitter(x: &Json, what: &str) -> Result<u32, Error> {
    let v = int(x).ok_or_else(|| err("type", what.to_owned()))?;
    if !(0..1_000_000).contains(&v) {
        return Err(err("range", what.to_owned()));
    }
    Ok(to_u32(v))
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
            let v = parse_value(p, Family::Time, tables, FREE_SCOPES, "probe_interval")?;
            s.probe_interval = Some(v);
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
        let jitter = q.get("jitter").map_or(Ok(0), |j| jitter(j, "jitter"))?;
        #[cfg(not(feature = "tokio"))]
        let _ = jitter;
        Ok(Rule {
            #[cfg(feature = "tokio")]
            metric,
            above: parse_value(above, fam, tables, ALL_SCOPES, "above")?,
            #[cfg(feature = "tokio")]
            jitter,
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
        for rule in &mut self.rules {
            if rule.above.scope != Scope::Pipe {
                rule.above.settle(s, shared);
            }
        }
        if let Some(v) = &mut self.probe_interval {
            v.settle(s, shared);
        }
    }
}

#[cfg(feature = "tokio")]
impl PoolSpec {
    pub(crate) fn session_group(
        &self,
        id: String,
        candidates: Vec<zmux::TargetCandidate>,
        options: &Options,
    ) -> zmux::GroupTarget {
        use std::time::Duration;
        use zmux::{Directions, GroupTarget, MemberQuota, RotationPolicy};

        let mut sampler = options.sampler();
        let count = self.count.as_ref().map_or(1, |count| sampler.draw(count));
        let mut rotation = RotationPolicy::default();
        for rule in &self.rules {
            let mut limit = sampler.draw(&rule.above);
            if rule.jitter != 0 {
                limit = crate::value::jitter_with(sampler.next_u64(), limit, rule.jitter);
            }
            if limit == 0 {
                continue;
            }
            match rule.metric {
                Metric::Age => {
                    let limit = Duration::from_micros(limit);
                    rotation.max_age = Some(rotation.max_age.map_or(limit, |age| age.min(limit)));
                }
                Metric::BytesSent => update_minimum(&mut rotation.send_bytes, limit),
                Metric::BytesReceived => update_minimum(&mut rotation.receive_bytes, limit),
                Metric::Idle | Metric::Pipes | Metric::Bytes => {}
            }
        }
        GroupTarget {
            id,
            quotas: vec![MemberQuota {
                id: "members".into(),
                count: crate::value::to_usize(count),
                directions: Directions::BOTH,
                candidates,
            }],
            rotation,
        }
    }
}

#[cfg(feature = "tokio")]
fn update_minimum(value: &mut Option<u64>, limit: u64) {
    *value = Some(value.map_or(limit, |current| current.min(limit)));
}
