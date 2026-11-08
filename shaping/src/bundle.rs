//! Configuration bundles: for each carrier kind a list of candidates, of which the first
//! whose required features this reader has is the kind's configuration.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use zmux::CarrierKind;
use zmux::shaping::{Factory, HandshakeShaper, ShapedPipe, Shaper, ShapingBudget, UnitPlan};

use crate::error::{Error, err};
use crate::json::{Json, parse};
use crate::limits::parse_budget;
use crate::machine::{MachineFactory, Options, compile, parse_machines};
use crate::pool::{MachinePoolPolicy, PoolSpec};
use crate::value::{FREE_SCOPES, Family, Reader, Sampler, Value, parse_value};

const KINDS: &[&str] = &[
    "default",
    "websocket",
    "streaming",
    "split",
    "exchange",
    "quic",
    "http3",
    "webtransport",
];

const MESSAGES: &[(&str, &[&str])] = &[
    ("establish", &["hello", "reply", "finish"]),
    ("join", &["hello", "hello_early", "reply", "confirm"]),
];

#[derive(Debug, Clone, Default)]
struct Entry {
    pad_to: Option<Value>,
    pad_multiple: Option<Value>,
    pad: Option<Value>,
    delay: Option<Value>,
}

impl Entry {
    fn fields(&mut self) -> [&mut Option<Value>; 4] {
        [
            &mut self.pad_to,
            &mut self.pad_multiple,
            &mut self.pad,
            &mut self.delay,
        ]
    }
}

type Plans = BTreeMap<(String, String), Entry>;

fn parse_handshakes(x: &Json, tables: &Reader<'_>) -> Result<Plans, Error> {
    let Json::Obj(m) = x else {
        return Err(err("type", "handshakes"));
    };
    let mut out = Plans::new();
    for (hs, v) in m {
        let Some((_, names)) = MESSAGES.iter().find(|(n, _)| n == hs) else {
            continue;
        };
        if matches!(v, Json::Null) {
            continue;
        }
        let Json::Obj(msgs) = v else {
            return Err(err("type", hs.clone()));
        };
        for (msg, e) in msgs {
            if !names.contains(&msg.as_str()) || matches!(e, Json::Null) {
                continue;
            }
            let Json::Obj(fields) = e else {
                return Err(err("type", "message"));
            };
            if let Some((k, _)) = fields
                .iter()
                .find(|(k, _)| !["pad_to", "pad_multiple", "pad", "delay"].contains(&k.as_str()))
            {
                return Err(err("unknown_member", format!("message.{k}")));
            }
            let read = |k: &str, fam| {
                e.get(k)
                    .map(|x| parse_value(x, fam, tables, FREE_SCOPES, k))
                    .transpose()
            };
            out.insert(
                (hs.clone(), msg.clone()),
                Entry {
                    pad_to: read("pad_to", Family::Length)?,
                    pad_multiple: read("pad_multiple", Family::Length)?,
                    pad: read("pad", Family::Length)?,
                    delay: read("delay", Family::Time)?,
                },
            );
        }
    }
    Ok(out)
}

/// The configuration of one kind, compiled.
pub struct Compiled {
    plans: Plans,
    source: Mutex<Sampler>,
    factory: Option<MachineFactory>,
    budget: Option<ShapingBudget>,
    /// The candidate's bound on one wait.
    max_delay: Option<Duration>,
    pool: Option<PoolSpec>,
    shared: Vec<u64>,
    options: Options,
}

impl std::fmt::Debug for Compiled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Compiled").finish_non_exhaustive()
    }
}

impl Compiled {
    fn new(c: &Json, tables: Option<&Json>, options: &Options) -> Result<Self, Error> {
        let allowed = ["requires", "handshakes", "machines", "budget", "pool"];
        let Json::Obj(m) = c else {
            return Err(err("type", "candidate"));
        };
        if let Some((k, _)) = m.iter().find(|(k, _)| !allowed.contains(&k.as_str())) {
            return Err(err("unknown_member", format!("candidate.{k}")));
        }
        let tables = Reader::new(tables, options.limits);
        let mut plans = c
            .get("handshakes")
            .map(|h| parse_handshakes(h, &tables))
            .transpose()?
            .unwrap_or_default();
        let machines = c
            .get("machines")
            .map(|x| parse_machines(x, &tables))
            .transpose()?;
        let budget = c
            .get("budget")
            .map(|b| parse_budget(b, &tables))
            .transpose()?;
        let mut pool = c
            .get("pool")
            .map(|p| PoolSpec::parse(p, &tables))
            .transpose()?;

        let mut s = options.sampler();
        let mut shared = Vec::new();
        for e in plans.values_mut() {
            for f in e.fields().into_iter().flatten() {
                f.settle(&mut s, &mut shared);
            }
        }
        let factory = machines
            .map(|m| MachineFactory(Arc::new(compile(m, &mut s, &mut shared, options.clone()))));
        if let Some(p) = &mut pool {
            p.settle(&mut s, &mut shared);
        }
        Ok(Self {
            plans,
            source: Mutex::new(s),
            factory,
            max_delay: budget.as_ref().and_then(|b| b.max_delay),
            budget: budget.map(|b| b.source(options.sampler())),
            pool,
            shared,
            options: options.clone(),
        })
    }

    /// The plan of a message; `None` without an entry.
    #[must_use]
    pub fn plan(&self, handshake: &str, message: &str) -> Option<UnitPlan> {
        let e = self
            .plans
            .get(&(handshake.to_owned(), message.to_owned()))?;
        let mut s = self.source.lock().unwrap_or_else(|p| p.into_inner());
        let mut draw = |v: &Option<Value>| v.as_ref().map_or(0, |v| s.draw(v));
        let pad_to = draw(&e.pad_to) as usize;
        let pad_multiple = draw(&e.pad_multiple) as usize;
        let pad = draw(&e.pad) as usize;
        let mut delay = Duration::from_micros(draw(&e.delay));
        if let Some(m) = self.max_delay {
            delay = delay.min(m);
        }
        Some(UnitPlan::new(pad_to, pad_multiple, pad).with_delay(delay))
    }

    /// The machines' factory; `None` without machines.
    #[must_use]
    pub fn factory(&self) -> Option<&MachineFactory> {
        self.factory.as_ref()
    }

    /// The source of the candidate's budget for `zmux::Config::shaping_budget`, which draws
    /// its values of scope `session` at each call; `None` without a budget.
    #[must_use]
    pub fn budget(&self) -> Option<ShapingBudget> {
        self.budget.clone()
    }

    /// A new pool policy; `None` without one.
    #[must_use]
    pub fn pool_policy(&self) -> Option<MachinePoolPolicy> {
        let p = self.pool.as_ref()?;
        Some(MachinePoolPolicy::from_spec(p.clone(), &self.options))
    }

    /// The `shared` values of the handshakes, the machines and the pool, in the order
    /// they were drawn.
    #[must_use]
    pub fn shared(&self) -> &[u64] {
        &self.shared
    }
}

/// A configuration bundle: the kinds this reader chose a candidate for, compiled.
#[derive(Debug)]
pub struct Bundle {
    kinds: BTreeMap<&'static str, (usize, Compiled)>,
    unshaped: Vec<&'static str>,
}

impl Bundle {
    /// Reads a bundle. Any error in what it reads fails the whole document: only a
    /// candidate requiring a feature this reader lacks is skipped, unread.
    pub fn from_json(b: &[u8], options: &Options) -> Result<Self, Error> {
        options.limits.input(b.len())?;
        let doc = parse(b)?;
        let Json::Obj(top) = &doc else {
            return Err(err("type", "bundle"));
        };
        let allowed = ["generated_at", "next_change", "tables", "kinds"];
        if let Some((k, _)) = top.iter().find(|(k, _)| !allowed.contains(&k.as_str())) {
            return Err(err("unknown_member", format!("bundle.{k}")));
        }
        for k in ["generated_at", "next_change"] {
            if doc.get(k).is_some_and(|v| !matches!(v, Json::Str(_))) {
                return Err(err("type", k));
            }
        }
        let tables = doc.get("tables");
        if tables.is_some_and(|t| !matches!(t, Json::Obj(_))) {
            return Err(err("type", "tables"));
        }
        let kinds = doc.get("kinds").ok_or_else(|| err("type", "kinds"))?;
        if !matches!(kinds, Json::Obj(_)) {
            return Err(err("type", "kinds"));
        }
        if kinds.get("default").is_none() {
            return Err(err("no_default", "kinds.default"));
        }
        let mut out = BTreeMap::new();
        let mut unshaped = Vec::new();
        for &kind in KINDS {
            let Some(list) = kinds.get(kind) else {
                continue;
            };
            let Json::Arr(list) = list else {
                return Err(err("type", kind));
            };
            let mut chosen = None;
            for (i, c) in list.iter().enumerate() {
                if !matches!(c, Json::Obj(_)) {
                    return Err(err("type", "candidate"));
                }
                if let Some(rq) = c.get("requires") {
                    let Json::Arr(rq) = rq else {
                        return Err(err("type", "requires"));
                    };
                    let mut have = true;
                    for r in rq {
                        let Json::Str(r) = r else {
                            return Err(err("type", "requires"));
                        };
                        have &= options.features.iter().any(|f| f == r);
                    }
                    if !have {
                        continue;
                    }
                }
                chosen = Some((i, Compiled::new(c, tables, options)?));
                break;
            }
            match chosen {
                Some(c) => {
                    out.insert(kind, c);
                }
                None if options.allow_unshaped => unshaped.push(kind),
                None => return Err(err("no_candidate", kind)),
            }
        }
        Ok(Self {
            kinds: out,
            unshaped,
        })
    }

    /// The index of the candidate chosen for `kind`.
    #[must_use]
    pub fn selected(&self, kind: &str) -> Option<usize> {
        self.kinds.get(kind).map(|(i, _)| *i)
    }

    /// The kinds whose candidates were all skipped ([`Options::allow_unshaped`]).
    #[must_use]
    pub fn unshaped(&self) -> &[&'static str] {
        &self.unshaped
    }

    /// The configuration of `kind`, or of `default` when it has none.
    #[must_use]
    pub fn resolve(&self, kind: &str) -> Option<&Compiled> {
        self.kinds
            .get(kind)
            .or_else(|| self.kinds.get("default"))
            .map(|(_, c)| c)
    }

    fn of(&self, kind: Option<CarrierKind>) -> Option<&Compiled> {
        self.resolve(kind.map_or("default", CarrierKind::name))
    }

    /// The configuration of carriers of `kind`.
    #[must_use]
    pub fn for_kind(&self, kind: Option<CarrierKind>) -> Option<&Compiled> {
        self.of(kind)
    }

    /// The hook that plans handshake messages by the view's kind.
    #[must_use]
    pub fn handshake_shaper(self: &Arc<Self>) -> HandshakeShaper {
        let this = self.clone();
        HandshakeShaper::new(move |v| this.of(v.kind)?.plan(v.handshake, v.message))
    }
}

/// Runs the machines of the pipe's kind.
impl Factory for Bundle {
    fn shaper(&self, pipe: &ShapedPipe) -> Option<Box<dyn Shaper>> {
        let f = self.of(pipe.carrier)?.factory()?;
        Some(Box::new(f.shaper()))
    }
}
