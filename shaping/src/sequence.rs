//! The compact sequence form.

use crate::def::{
    Action, Comparison, Cond, Definition, Dist, DistKind, Error, Machine, Op, Quantity, Record,
    Scope, State, Transition, Trigger, Value, err,
};

/// Placeholder targets, resolved once every step is known.
const NEXT: usize = usize::MAX;
const END: usize = usize::MAX - 1;

/// Reads the compact form of a single machine that runs its steps in
/// order, one record each, and then stops shaping the pipe:
///
/// ```text
/// sequence := step ("," step)*
/// step     := dist ("/" modifier)*
/// modifier := "delay=" dist | "scope=" scope | "until=" guard | "inject=" count ":" dist
/// dist     := number | number "-" number | name "(" number ("," number)* ")"
/// scope    := "each" | "pipe" | "shared"
/// guard    := ("seq" | "len" | "counter0" | "counter1") ("<" | "<=" | "==" | "!=" | ">=" | ">") number
/// ```
///
/// The step's dist is the record's frames length in bytes: shorter records
/// are padded to it, longer ones are cut at it. `delay` is in seconds.
/// `until` ends the sequence after the record when the guard holds.
/// `inject` waits for the next received record, then sends `count` records
/// of PADDING only of the dist's length. `name` is a [`DistKind`] with its
/// parameters.
pub fn parse_sequence(s: &str) -> Result<Definition, Error> {
    let mut states = Vec::new();
    // Each step: its state and its last state (whose moves go on).
    let mut links = Vec::new();
    for (i, raw) in split(s, ',').into_iter().enumerate() {
        let (st, extra) = parse_step(raw.trim(), states.len())
            .map_err(|e| err(format!("sequence: step {i}: {e}")))?;
        let at = states.len();
        states.push(st);
        states.extend(extra);
        links.push((at, states.len() - 1));
    }
    let end = states.len();
    states.push(State::new(None, vec![Action::new(Op::Stop)], Vec::new()));
    for (k, &(at, last)) in links.iter().enumerate() {
        let next = links.get(k + 1).map_or(end, |l| l.0);
        for t in &mut states[last].next {
            if t.to == NEXT {
                t.to = next;
            }
        }
        for t in &mut states[at].next {
            if t.to == END {
                t.to = end;
            }
        }
    }
    let d = Definition::new(vec![Machine::new(0, states)]);
    d.validate()?;
    Ok(d)
}

fn parse_step(s: &str, base: usize) -> Result<(State, Vec<State>), Error> {
    let parts = split(s, '/');
    let mut len = parse_dist(parts[0])?;
    let mut delay = None;
    let mut until = None;
    let mut inject = None;
    for p in &parts[1..] {
        let Some((k, v)) = p.trim().split_once('=') else {
            return Err(err(format!("modifier {p:?}: want name=value")));
        };
        match k {
            "delay" => delay = Some(parse_dist(v)?),
            "scope" => {
                let sc = match v {
                    "each" => Scope::Each,
                    "pipe" => Scope::Pipe,
                    "shared" => Scope::Shared,
                    _ => return Err(err(format!("unknown scope {v:?}"))),
                };
                len.scope = sc;
                if let Some(d) = &mut delay {
                    d.scope = sc;
                }
            }
            "until" => {
                until = Some(Transition {
                    cond: Some(parse_guard(v)?),
                    ..Transition::new(Trigger::RecordOut, END)
                })
            }
            "inject" => {
                let Some((n, l)) = v.split_once(':') else {
                    return Err(err(format!("inject {v:?}: want count:dist")));
                };
                let n: usize = n
                    .trim()
                    .parse()
                    .map_err(|_| err(format!("inject count {n:?}")))?;
                inject = Some((n, parse_dist(l)?));
            }
            _ => return Err(err(format!("unknown modifier {k:?}"))),
        }
    }
    let record = Record {
        max_len: Some(len.clone()),
        pad_to: Some(len),
        delay,
        one_len: true,
        ..Record::default()
    };
    let mut st = State::new(Some(record), Vec::new(), until.into_iter().collect());
    let Some((count, inj)) = inject.filter(|(n, _)| *n > 0) else {
        st.next.push(Transition::new(Trigger::RecordOut, NEXT));
        return Ok((st, Vec::new()));
    };
    let (w, a, b) = (base + 1, base + 2, base + 3);
    st.next.push(Transition::new(Trigger::RecordOut, w));
    let set = Action {
        slot: 1,
        value: Some(Value::constant(count as f64)),
        ..Action::new(Op::Set)
    };
    let send = Action {
        after: Some(Value::constant(0.0)),
        len: Some(inj),
        ..Action::new(Op::Inject)
    };
    let sub = Action {
        slot: 1,
        value: Some(Value::constant(1.0)),
        ..Action::new(Op::Sub)
    };
    let more = Transition {
        cond: Some(Cond::new(
            Quantity::Counter1,
            Comparison::Gt,
            Value::constant(0.0),
        )),
        ..Transition::new(Trigger::Injected, b)
    };
    let extra = vec![
        State::new(
            None,
            Vec::new(),
            vec![Transition::new(Trigger::RecordIn, a)],
        ),
        State::new(None, vec![set], vec![Transition::new(Trigger::Enter, b)]),
        State::new(
            None,
            vec![send, sub],
            vec![more, Transition::new(Trigger::Injected, NEXT)],
        ),
    ];
    Ok((st, extra))
}

fn parse_num(s: &str) -> Result<f64, Error> {
    match s.trim().parse::<f64>() {
        Ok(x) if x.is_finite() => Ok(x),
        _ => Err(err(format!("number {s:?}"))),
    }
}

fn parse_dist(s: &str) -> Result<Value, Error> {
    let s = s.trim();
    if let Some((name, args)) = s.split_once('(') {
        let Some(args) = args.strip_suffix(')') else {
            return Err(err(format!("dist {s:?}: missing )")));
        };
        let params = args
            .split(',')
            .map(parse_num)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| err(format!("dist {s:?}: {e}")))?;
        let v = Value::dist(Dist::new(DistKind::from_name(name.trim()), params));
        v.validate()?;
        return Ok(v);
    }
    // A range a-b; a leading sign belongs to a.
    let skip = s.len().min(1);
    if let Some((a, b)) = s[skip..].split_once('-') {
        let v = Value::range(parse_num(&s[..skip + a.len()])?, parse_num(b)?);
        v.validate()?;
        return Ok(v);
    }
    Ok(Value::constant(parse_num(s)?))
}

fn parse_guard(s: &str) -> Result<Cond, Error> {
    for (sym, cmp) in [
        ("<=", Comparison::Le),
        (">=", Comparison::Ge),
        ("==", Comparison::Eq),
        ("!=", Comparison::Ne),
        ("<", Comparison::Lt),
        (">", Comparison::Gt),
    ] {
        if let Some((w, v)) = s.split_once(sym) {
            let x = parse_num(v).map_err(|e| err(format!("guard {s:?}: {e}")))?;
            let what = match w.trim() {
                "seq" => Quantity::Seq,
                "len" => Quantity::Len,
                "counter0" => Quantity::Counter0,
                "counter1" => Quantity::Counter1,
                q => return Err(err(format!("guard {s:?}: unknown quantity {q:?}"))),
            };
            return Ok(Cond::new(what, cmp, Value::constant(x)));
        }
    }
    Err(err(format!("guard {s:?}: no comparison")))
}

/// Cuts `s` at `sep` outside parentheses.
fn split(s: &str, sep: char) -> Vec<&str> {
    let mut out = Vec::new();
    let (mut depth, mut start) = (0i32, 0);
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            c if c == sep && depth == 0 => {
                out.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&s[start..]);
    out
}
