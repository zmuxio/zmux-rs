//! Runs the shaping vectors of the specification repository.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::Value as J;
use zmux::PipeId;
use zmux::shaping::{
    Account, Caps, Effects, Event, EventKind, Limits, Meters, RecordPlan, RecordView, RecordWire,
    Shaper, UnitPlan, establish_hello_len, first_batch_limit, fit_item, join_hello_len,
    join_reply_len, message_len, pad_fill, pad_item, reply_room,
};
use zmux_shaping::{
    Bundle, MachineFactory, MachinePoolPolicy, MachineShaper, MemberDecision, Options, PoolMember,
    Source, Value, parse_limits,
};

fn load(name: &str) -> J {
    let dir = std::env::var("ZMUX_SHAPING_VECTORS")
        .unwrap_or_else(|_| format!("{}/../testdata/shaping", env!("CARGO_MANIFEST_DIR")));
    serde_json::from_slice(&std::fs::read(format!("{dir}/{name}.json")).unwrap()).unwrap()
}

/// A source shared by everything a vector compiles and runs, counting its draws.
#[derive(Clone)]
struct Shared(Arc<Mutex<(Src, u64)>>);

enum Src {
    Mix(u64),
    List(Vec<u64>, usize),
}

impl Shared {
    fn new(spec: &J) -> Self {
        let src = if let Some(s) = spec["seed"].as_str() {
            Src::Mix(u64::from_str_radix(s, 16).unwrap())
        } else {
            let u = spec["u"].as_array().unwrap();
            let hex = |x: &J| u64::from_str_radix(x.as_str().unwrap(), 16).unwrap();
            Src::List(u.iter().map(hex).collect(), 0)
        };
        Self(Arc::new(Mutex::new((src, 0))))
    }

    fn consumed(&self) -> u64 {
        self.0.lock().unwrap().1
    }

    fn options(&self) -> Options {
        let me = self.clone();
        Options::default().with_source(move || Box::new(me.clone()) as Box<dyn Source>)
    }
}

impl Source for Shared {
    fn next_u64(&mut self) -> u64 {
        let mut g = self.0.lock().unwrap();
        g.1 += 1;
        match &mut g.0 {
            Src::Mix(s) => {
                *s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
                let mut z = *s;
                z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
                z ^ (z >> 31)
            }
            Src::List(u, i) => {
                *i += 1;
                u[*i - 1]
            }
        }
    }
}

fn u(x: &J, k: &str) -> usize {
    x[k].as_u64().unwrap_or(0) as usize
}

fn unit(p: &J) -> UnitPlan {
    UnitPlan::new(u(p, "pad_to"), u(p, "pad_multiple"), u(p, "pad"))
        .with_delay(Duration::from_micros(p["delay"].as_u64().unwrap_or(0)))
}

fn check_unit(got: &UnitPlan, want: &J, name: &str) {
    assert_eq!(*got, unit(want), "{name}");
}

fn ints(x: &J) -> Vec<u64> {
    x.as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_u64().unwrap())
        .collect()
}

#[test]
fn draw() {
    let d = load("draw");
    for c in d["splitmix64"].as_array().unwrap() {
        let mut s = Shared::new(&serde_json::json!({"seed":c["seed"]}));
        for f in c["first"].as_array().unwrap() {
            assert_eq!(
                s.next_u64(),
                u64::from_str_radix(f.as_str().unwrap(), 16).unwrap()
            );
        }
    }
    for c in d["values"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let sh = Shared::new(&c["source"]);
        let doc = serde_json::json!({"t": c["t"]}).to_string();
        let v = Value::from_json(doc.as_bytes()).unwrap();
        let mut s = zmux_shaping::Sampler::new(Box::new(sh.clone()));
        for want in ints(&c["draws"]) {
            assert_eq!(s.draw(&v), want, "{name}");
        }
        assert_eq!(sh.consumed(), c["consumed"].as_u64().unwrap(), "{name}");
    }
    for c in d["prob"].as_array().unwrap() {
        let sh = Shared::new(&c["source"]);
        let mut s = zmux_shaping::Sampler::new(Box::new(sh.clone()));
        let got = s.prob(c["p"].as_u64().unwrap());
        assert_eq!(got, c["result"].as_bool().unwrap(), "{}", c["name"]);
        assert_eq!(
            sh.consumed(),
            c["consumed"].as_u64().unwrap(),
            "{}",
            c["name"]
        );
    }
    for c in d["jitter"].as_array().unwrap() {
        let sh = Shared::new(&c["source"]);
        let mut s = zmux_shaping::Sampler::new(Box::new(sh.clone()));
        let got = s.jitter(
            c["value"].as_u64().unwrap(),
            c["jitter_ppm"].as_u64().unwrap() as u32,
        );
        assert_eq!(got, c["result"].as_u64().unwrap(), "{}", c["name"]);
        assert_eq!(
            sh.consumed(),
            c["consumed"].as_u64().unwrap(),
            "{}",
            c["name"]
        );
    }
    for c in d["compile_order"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let sh = Shared::new(&c["source"]);
        let mut doc = serde_json::json!({"kinds":{"default":[c["candidate"]]}});
        if !c["tables"].is_null() {
            doc["tables"] = c["tables"].clone();
        }
        let b = Bundle::from_json(doc.to_string().as_bytes(), &sh.options()).unwrap();
        let got = b.resolve("default").unwrap();
        assert_eq!(got.shared(), ints(&c["shared"]), "{name}");
        assert_eq!(sh.consumed(), c["consumed"].as_u64().unwrap(), "{name}");
    }
}

fn unit_len(m: &J) -> (usize, &'static str) {
    let stream = m["framing"] == "stream";
    let over = u(m, "overhead");
    match m["message"].as_str().unwrap() {
        "establish/hello" => {
            let handle = m["has_handle"].as_bool().unwrap();
            let w =
                establish_hello_len(u(m, "profile") as u64, handle, stream, u(m, "noise"), over);
            (w, "item")
        }
        "establish/reply" | "establish/finish" => {
            (message_len(stream, u(m, "noise"), over), "item")
        }
        "join/hello" | "join/hello_early" => (
            join_hello_len(
                u(m, "suite") as u64,
                u(m, "locator_len"),
                u(m, "r_len"),
                stream,
                u(m, "ciphertext"),
                over,
            ),
            "item",
        ),
        "join/reply" => (
            join_reply_len(u(m, "r_len"), stream, u(m, "ciphertext"), over),
            "item",
        ),
        "join/confirm" => {
            let body = if m["mode"] == "sealed" {
                u(m, "tag")
            } else {
                u(m, "hash_len")
            };
            (message_len(stream, body, over), "raw")
        }
        other => panic!("{other}"),
    }
}

fn max_delay(us: i64) -> Option<Duration> {
    match us {
        0 => None,
        n if n < 0 => Some(Duration::MAX),
        n => Some(Duration::from_micros(n as u64)),
    }
}

fn meters(m: &serde_json::Value) -> Meters {
    let or = |k: &str, d: u64| m[k].as_u64().unwrap_or(d);
    Meters::new(
        or("wire_left", u64::MAX),
        or("stall_left", u64::MAX),
        or("wire_spent", 0),
        or("sent_bytes", 0),
    )
}

#[test]
fn pad() {
    let d = load("pad");
    for c in d["pad_for"].as_array().unwrap() {
        assert_eq!(unit(&c["plan"]).pad_for(u(c, "n")), u(c, "result"), "{c}");
    }
    for c in d["limits"].as_array().unwrap() {
        let mut p = unit(&c["plan"]);
        let v = &c["limits"];
        let mut l = Limits::default();
        l.no_padding = v["no_padding"] == true;
        l.no_pause = v["no_pause"] == true;
        l.max_delay = max_delay(v["max_delay"].as_i64().unwrap_or(0));
        p.apply_limits(&l);
        check_unit(&p, &c["result"], "limits");
    }
    for c in d["item"].as_array().unwrap() {
        let v = pad_item(c["gap"].as_i64().unwrap() as isize, u(c, "room"));
        assert_eq!(v.map(|v| v as u64), c["value_len"].as_u64(), "{c}");
    }
    for c in d["raw_fill"].as_array().unwrap() {
        let fill = pad_fill(c["gap"].as_i64().unwrap() as isize, u(c, "room"));
        assert_eq!(fill, u(c, "fill"), "{c}");
    }
    for c in d["handshake_len"].as_array().unwrap() {
        assert_eq!(unit_len(&c["unit"]).0, u(c, "wire"), "{c}");
    }
    for c in d["unit"].as_array().unwrap() {
        let (w, filler) = unit_len(&c["unit"]);
        assert_eq!(w, u(c, "w"), "{c}");
        assert_eq!(filler, c["filler"].as_str().unwrap(), "{c}");
        let t = unit(&c["plan"]).pad_for(w);
        assert_eq!(t, u(c, "target"), "{c}");
        let gap = t as isize - w as isize;
        let added = if filler == "item" {
            let v = pad_item(gap, u(c, "room"));
            assert_eq!(v.map(|v| v as u64), c["value_len"].as_u64(), "{c}");
            v.map_or(0, |v| 1 + zmux::shaping::varint_len(v as u64) + v)
        } else {
            let f = pad_fill(gap, u(c, "room"));
            assert_eq!(f, u(c, "fill"), "{c}");
            f
        };
        assert_eq!(added, u(c, "added"), "{c}");
        assert_eq!(w + added, u(c, "wire"), "{c}");
    }
    for c in d["record"].as_array().unwrap() {
        let wire = RecordWire {
            size_field: c["size_field"] == true,
            overhead: if c["write_start"] == true {
                u(c, "write_overhead")
            } else {
                0
            },
        };
        let p = &c["plan"];
        let mut plan = RecordPlan::default();
        plan.max_len = u(p, "max_len");
        plan.pad_to = u(p, "pad_to");
        plan.pad_multiple = u(p, "pad_multiple");
        plan.pad = u(p, "pad");
        let (most, clamped) = wire.frames_max(&mut plan);
        let data = if most == 0 {
            u(c, "data")
        } else {
            u(c, "data").min(most)
        };
        let frames = wire.frames(data, &plan);
        let r = &c["result"];
        assert_eq!(most, u(r, "frames_max"), "{c}");
        assert_eq!(clamped, r["clamped"] == true, "{c}");
        assert_eq!(data, u(r, "data"), "{c}");
        assert_eq!(frames, u(r, "frames"), "{c}");
        assert_eq!(frames - data, u(r, "padding"), "{c}");
        assert_eq!(wire.wire(frames), u(r, "wire"), "{c}");
    }
    for c in d["reply_room"].as_array().unwrap() {
        let r = &c["result"];
        if c["mode"] == "trusted" {
            assert_eq!(u(c, "want_frames"), u(r, "frames_limit"), "{c}");
            assert!(r["padding_room"].is_null(), "{c}");
            continue;
        }
        let (limit, room) = reply_room(u(c, "received"), u(c, "base"), u(c, "want_frames"));
        assert_eq!(
            (limit, room),
            (u(r, "frames_limit"), u(r, "padding_room")),
            "{c}"
        );
    }
    for c in d["first_batch"].as_array().unwrap() {
        // A configured 0 takes the default, and a negative value is off, in this config.
        let early = match c["join_early_hello"].as_i64().unwrap() {
            0 => 8192,
            j if j < 0 => 0,
            j => j as usize,
        };
        let got = first_batch_limit(early, u(c, "pad_to"), u(c, "base"));
        assert_eq!(got, u(&c["result"], "limit"), "{c}");
    }
    assert_eq!(fit_item(1), None);
}

#[test]
fn format() {
    let d = load("format");
    for c in d["bundles"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let features = c["features"].as_array().map_or(Vec::new(), |f| {
            f.iter().map(|s| s.as_str().unwrap().to_owned()).collect()
        });
        let o = Options::default()
            .with_features(features)
            .with_allow_unshaped(c["allow_unshaped"] == true);
        let r = Bundle::from_json(c["bundle"].as_str().unwrap().as_bytes(), &o);
        if let Some(e) = c["error"].as_str() {
            let got = r.as_ref().err().map(zmux_shaping::Error::class);
            assert_eq!(got, Some(e), "{name}: {:?}", r.as_ref().err());
            continue;
        }
        let b = r.unwrap_or_else(|e| panic!("{name}: {e}"));
        for (k, v) in c["selected"].as_object().unwrap() {
            assert_eq!(b.selected(k).map(|i| i as u64), v.as_u64(), "{name}: {k}");
        }
        let want: Vec<&str> = c["unshaped"].as_array().map_or(Vec::new(), |a| {
            a.iter().map(|s| s.as_str().unwrap()).collect()
        });
        assert_eq!(b.unshaped(), want, "{name}");
    }
    for c in d["handshake"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        // Each kind compiles with its own source; the vector is of the one it resolves to.
        let made = Arc::new(Mutex::new(Vec::<Shared>::new()));
        let (log, spec) = (made.clone(), c["source"].clone());
        let o = Options::default().with_source(move || {
            let s = Shared::new(&spec);
            log.lock().unwrap().push(s.clone());
            Box::new(s) as Box<dyn Source>
        });
        let raw = c["bundle"].as_str().unwrap();
        let b = Bundle::from_json(raw.as_bytes(), &o).unwrap();
        let kind = c["kind"].as_str().unwrap();
        let got = b.resolve(kind).unwrap();
        let doc: J = serde_json::from_str(raw).unwrap();
        let order = [
            "default",
            "websocket",
            "streaming",
            "split",
            "exchange",
            "quic",
            "http3",
            "webtransport",
        ];
        let resolved = c["resolved"].as_str().unwrap();
        let index = order
            .iter()
            .filter(|k| !doc["kinds"][**k].is_null())
            .position(|k| *k == resolved)
            .unwrap();
        let sh = made.lock().unwrap()[index].clone();
        assert_eq!(got.shared(), ints(&c["shared"]), "{name}");
        for call in c["calls"].as_array().unwrap() {
            let p = got.plan(
                call["handshake"].as_str().unwrap(),
                call["message"].as_str().unwrap(),
            );
            match call["plan"].is_null() {
                true => assert!(p.is_none(), "{name}: {call}"),
                false => check_unit(&p.unwrap(), &call["plan"], name),
            }
            assert_eq!(
                sh.consumed(),
                call["consumed"].as_u64().unwrap(),
                "{name}: {call}"
            );
        }
    }
}

fn check_effects(got: &Effects, want: &J, name: &str, step: usize) {
    let at = format!("{name} step {step}");
    let w = want.as_object().unwrap();
    assert_eq!(
        got.inject.is_some(),
        w.contains_key("inject"),
        "{at}: {got:?} {want}"
    );
    if let Some(i) = got.inject {
        let x = i.map(|i| (i.at, i.len as u64));
        let y = want["inject"]
            .as_object()
            .map(|o| (o["at"].as_u64().unwrap(), o["len"].as_u64().unwrap()));
        assert_eq!(x, y, "{at}");
    }
    assert_eq!(
        got.wake.is_some(),
        w.contains_key("wake"),
        "{at}: {got:?} {want}"
    );
    if let Some(x) = got.wake {
        assert_eq!(x, want["wake"].as_u64(), "{at}");
    }
    assert_eq!(
        got.gate.is_some(),
        w.contains_key("gate"),
        "{at}: {got:?} {want}"
    );
    if let Some(g) = got.gate {
        let o = &want["gate"];
        let y = (
            o["pause_until"].as_u64(),
            o["rate"].as_u64(),
            o["burst"].as_u64(),
        );
        assert_eq!(
            (Some(g.pause_until), Some(g.rate), Some(g.burst)),
            y,
            "{at}"
        );
    }
    assert_eq!(got.weight.map(u64::from), want["weight"].as_u64(), "{at}");
    assert_eq!(got.stop, want["stop"] == true, "{at}");
}

#[test]
fn machine() {
    let d = load("machine");
    for c in d["invalid"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let r =
            MachineFactory::from_json(c["definition"].to_string().as_bytes(), Options::default());
        let got = r.as_ref().err().map(zmux_shaping::Error::class);
        assert_eq!(got, c["error"].as_str(), "{name}: {:?}", r.as_ref().err());
    }
    let mut steps_run = 0;
    for c in d["run"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let sh = Shared::new(&c["source"]);
        let mut def = c["definition"].clone();
        if !c["tables"].is_null() {
            def["tables"] = c["tables"].clone();
        }
        let f = MachineFactory::from_json(def.to_string().as_bytes(), sh.options())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let k = &c["compile"];
        assert_eq!(f.shared(), ints(&k["shared"]), "{name}");
        assert_eq!(sh.consumed(), k["consumed"].as_u64().unwrap(), "{name}");
        let caps = f.capabilities();
        for (cap, n) in [
            (Caps::PLAN, "plan"),
            (Caps::RECORD_IN, "record_in"),
            (Caps::STREAMS, "streams"),
            (Caps::BUDGET, "budget"),
        ] {
            let listed = k["caps"].as_array().unwrap().iter().any(|x| x == n);
            assert_eq!(caps.contains(cap), listed, "{name}: {n}");
        }
        let mut pipes: Vec<MachineShaper> = (0..c["pipes"].as_u64().unwrap_or(1))
            .map(|_| f.shaper())
            .collect();
        for (i, s) in c["steps"].as_array().unwrap().iter().enumerate() {
            steps_run += 1;
            let m = &mut pipes[s["pipe"].as_u64().unwrap_or(0) as usize];
            let now = s["now"].as_u64().unwrap();
            let op = s["op"].as_str().unwrap();
            let len = s["len"].as_u64().unwrap_or(0) as usize;
            let mut fx = Effects::default();
            if op == "plan" {
                let mut plan = RecordPlan::default();
                m.plan(
                    &RecordView::new(PipeId::new(0), 0, 0, 65535, now)
                        .with_meters(meters(&s["meters"])),
                    &mut plan,
                );
                let p = &s["plan"];
                let at = format!("{name} step {i}");
                assert_eq!(plan.max_len, u(p, "max_len"), "{at}");
                assert_eq!(plan.pad_to, u(p, "pad_to"), "{at}");
                assert_eq!(plan.pad_multiple, u(p, "pad_multiple"), "{at}");
                assert_eq!(plan.pad, u(p, "pad"), "{at}");
                assert_eq!(
                    plan.delay.as_micros() as u64,
                    p["delay"].as_u64().unwrap(),
                    "{at}"
                );
                assert_eq!(plan.flush, p["flush"] == true, "{at}");
                assert_eq!(plan.stop, p["stop"] == true, "{at}");
                fx = plan.effects;
            } else {
                let kind = match op {
                    "start" => EventKind::Start,
                    "record_in" | "padding_in" => EventKind::RecordIn,
                    "stream_open" => EventKind::StreamOpen,
                    "stream_end" => EventKind::StreamEnd,
                    "injected" => EventKind::Injected,
                    "inject_dropped" => EventKind::InjectDropped,
                    "wake" => EventKind::Wake,
                    other => panic!("{name}: {other}"),
                };
                let e = Event::new(kind, PipeId::new(0), now)
                    .with_len(len, op == "padding_in")
                    .with_meters(meters(&s["meters"]));
                m.on_event(&e, &mut fx);
            }
            check_effects(&fx, &s["effects"], name, i);
            assert_eq!(
                sh.consumed(),
                s["consumed"].as_u64().unwrap(),
                "{name} step {i}"
            );
            let st: Vec<u64> = m.states().iter().map(|x| u64::from(*x)).collect();
            assert_eq!(st, ints(&s["state"]), "{name} step {i}");
            for (j, want) in s["counters"].as_array().unwrap().iter().enumerate() {
                assert_eq!(m.counters(j), ints(want), "{name} step {i}");
            }
        }
    }
    println!("machine: {steps_run} steps");
}

#[test]
fn pool_decide() {
    let d = load("pool_policy");
    for c in d["decide"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let sh = Shared::new(&c["source"]);
        let mut doc = serde_json::json!({"kinds":{"default":[{"pool":c["policy"]}]}});
        if !c["tables"].is_null() {
            doc["tables"] = c["tables"].clone();
        }
        let b = Bundle::from_json(doc.to_string().as_bytes(), &sh.options())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let k = b.resolve("default").unwrap();
        assert_eq!(k.shared(), ints(&c["compile"]["shared"]), "{name}");
        assert_eq!(
            sh.consumed(),
            c["compile"]["consumed"].as_u64().unwrap(),
            "{name}"
        );
        let mut p: MachinePoolPolicy = k.pool_policy().unwrap();
        for (i, s) in c["steps"].as_array().unwrap().iter().enumerate() {
            let members: Vec<PoolMember> = s["members"].as_array().map_or(Vec::new(), |a| {
                a.iter()
                    .map(|m| {
                        let mut x = PoolMember::new(m["id"].as_u64().unwrap());
                        x.age = m["age"].as_u64().unwrap_or(0);
                        x.idle = m["idle"].as_u64().unwrap_or(0);
                        x.pipes = m["pipes"].as_u64().unwrap_or(0);
                        x.bytes_sent = m["bytes_sent"].as_u64().unwrap_or(0);
                        x.bytes_received = m["bytes_received"].as_u64().unwrap_or(0);
                        x
                    })
                    .collect()
            });
            let mut out = MemberDecision::default();
            let failures = s["failures"].as_u64().unwrap_or(0) as u32;
            p.decide_members(failures, s["since_dial"].as_u64(), &members, &mut out);
            let w = &s["want"];
            let at = format!("{name} step {i}");
            assert_eq!(out.count, w["count"].as_u64(), "{at}");
            assert_eq!(out.dial_after, w["dial_after"].as_u64(), "{at}");
            assert_eq!(out.retire, ints(&w["retire"]), "{at}");
            assert_eq!(out.probe_interval, w["probe_interval"].as_u64(), "{at}");
            assert_eq!(
                out.probe_jitter.map(u64::from),
                w["probe_jitter"].as_u64(),
                "{at}"
            );
            assert_eq!(out.recheck, w["recheck"].as_u64(), "{at}");
            assert_eq!(sh.consumed(), s["consumed"].as_u64().unwrap(), "{at}");
        }
    }
}

#[test]
fn limits_parse() {
    let d = load("budget");
    for c in d["parse"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let r = parse_limits(c["limits"].to_string().as_bytes());
        if let Some(e) = c["error"].as_str() {
            assert_eq!(r.err().map(|e| e.class()), Some(e), "{name}");
            continue;
        }
        let l = r.unwrap_or_else(|e| panic!("{name}: {e}"));
        let w = &c["want"];
        let f = |k: &str| w["wire"][k].as_u64().unwrap();
        let wire = Account::new(f("initial"), f("per_mb"), f("per_sec"));
        assert_eq!(l.wire, wire, "{name}");
        assert_eq!(
            l.max_delay,
            max_delay(w["max_delay"].as_i64().unwrap()),
            "{name}"
        );
        assert_eq!(l.no_padding, w["no_padding"] == true, "{name}");
        assert_eq!(l.no_pause, w["no_pause"] == true, "{name}");
        assert_eq!(l.no_injection, w["no_injection"] == true, "{name}");
    }
}

#[test]
fn budget_draws() {
    let d = load("format");
    for c in d["budget"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let sh = Shared::new(&c["source"]);
        let doc = serde_json::json!({"kinds":{"default":[{"budget":c["budget"]}]}});
        let b = Bundle::from_json(doc.to_string().as_bytes(), &sh.options())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        let source = b.resolve("default").unwrap().budget().unwrap();
        for (i, w) in c["draws"].as_array().unwrap().iter().enumerate() {
            let got = source.ask();
            let f = |k: &str| w["wire"][k].as_u64().unwrap();
            let wire = Account::new(f("initial"), f("per_mb"), f("per_sec"));
            assert_eq!(got.wire, wire, "{name} {i}");
            assert_eq!(got.no_injection, w["no_injection"] == true, "{name} {i}");
            let md = got.max_delay.map_or(0, |d| d.as_micros() as u64);
            assert_eq!(md, w["max_delay"].as_u64().unwrap(), "{name} {i}");
            assert_eq!(sh.consumed(), w["consumed"].as_u64().unwrap(), "{name} {i}");
        }
    }
}
