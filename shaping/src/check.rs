//! Size bounds and structural checks of a definition.

use crate::def::{Definition, Error, Machine, Op, State, Trigger, Value, err};

/// Bounds of a definition's size. Each field is `None` by default, no
/// bound; a set one bounds as it is, zero allowing none.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SizeLimits {
    /// Input bytes (JSON or sequence form).
    pub max_bytes: Option<usize>,
    /// Machines.
    pub max_machines: Option<usize>,
    /// States per machine.
    pub max_states: Option<usize>,
    /// Actions per state.
    pub max_actions: Option<usize>,
    /// Transitions per state.
    pub max_transitions: Option<usize>,
    /// Points or components per distribution.
    pub max_points: Option<usize>,
}

fn over(n: usize, m: Option<usize>) -> bool {
    m.is_some_and(|m| n > m)
}

/// Displays a set bound.
fn lim(m: Option<usize>) -> usize {
    m.unwrap_or(usize::MAX)
}

impl SizeLimits {
    /// Whether `n` input bytes exceed `max_bytes`; the error names `what`.
    pub(crate) fn input(&self, what: &str, n: usize) -> Result<(), Error> {
        match self.max_bytes {
            Some(m) if n > m => Err(err(format!("{what}: {n} bytes, limit {m}"))),
            _ => Ok(()),
        }
    }
}

impl Definition {
    /// Validates the definition and bounds it by `l`.
    pub fn check(&self, l: &SizeLimits) -> Result<(), Error> {
        self.validate()?;
        if over(self.machines.len(), l.max_machines) {
            return Err(err(format!(
                "machine: {} machines, limit {}",
                self.machines.len(),
                lim(l.max_machines)
            )));
        }
        for (i, m) in self.machines.iter().enumerate() {
            if over(m.states.len(), l.max_states) {
                return Err(err(format!(
                    "machine {i}: {} states, limit {}",
                    m.states.len(),
                    lim(l.max_states)
                )));
            }
            for (j, st) in m.states.iter().enumerate() {
                if over(st.enter.len(), l.max_actions) || over(st.next.len(), l.max_transitions) {
                    return Err(err(format!(
                        "machine {i}: state {j}: actions or transitions over limit"
                    )));
                }
                let mut bad = false;
                st.values(&mut |v| {
                    if let Some(d) = &v.dist {
                        bad |= over(d.points.len(), l.max_points) || over(d.of.len(), l.max_points);
                    }
                });
                if bad {
                    return Err(err(format!(
                        "machine {i}: state {j}: distribution over limit"
                    )));
                }
            }
        }
        Ok(())
    }
}

impl State {
    /// Calls `f` for every value of the state, nested ones included.
    pub(crate) fn values(&self, f: &mut impl FnMut(&Value)) {
        fn walk(v: &Value, f: &mut impl FnMut(&Value)) {
            f(v);
            if let Some(d) = &v.dist {
                for c in &d.of {
                    walk(c, f);
                }
            }
        }
        if let Some(r) = &self.record {
            r.values().into_iter().flatten().for_each(|v| walk(v, f));
        }
        for a in &self.enter {
            a.values().into_iter().flatten().for_each(|v| walk(v, f));
        }
        for t in &self.next {
            if let Some(p) = &t.prob {
                walk(p, f);
            }
            if let Some(c) = &t.cond {
                walk(&c.value, f);
            }
        }
    }
}

impl Machine {
    /// Checks reachability, that the start state does not restart on entry,
    /// and that no injection whose delay has a zero
    /// lower bound lies on a cycle of unconditional enter, injected or
    /// counter transitions.
    pub(crate) fn structure(&self) -> Result<(), Error> {
        let n = self.states.len();
        let mut all = vec![Vec::new(); n];
        let mut fast = vec![Vec::new(); n];
        for (i, st) in self.states.iter().enumerate() {
            for t in &st.next {
                all[i].push(t.to);
                if matches!(
                    t.on,
                    Trigger::Enter | Trigger::Injected | Trigger::Zero0 | Trigger::Zero1
                ) && t.cond.is_none()
                {
                    fast[i].push(t.to);
                }
            }
            for a in &st.enter {
                if a.op == Op::Restart {
                    all[i].push(self.start);
                    fast[i].push(self.start);
                }
            }
        }
        // A start state that restarts on entry would enter itself again
        // without end.
        if self.states[self.start]
            .enter
            .iter()
            .any(|a| a.op == Op::Restart)
        {
            return Err(err(format!(
                "state {}: restart on entering the start state",
                self.start
            )));
        }
        if let Some(i) = reach(&all, self.start).iter().position(|s| !s) {
            return Err(err(format!("state {i} unreachable")));
        }
        for (i, st) in self.states.iter().enumerate() {
            for a in &st.enter {
                let zero = a.op == Op::Inject
                    && !a.cancel
                    && a.after.as_ref().is_some_and(|v| v.lower() <= 0.0);
                if zero && fast[i].iter().any(|&j| reach(&fast, j)[i]) {
                    return Err(err(format!(
                        "state {i}: injection with zero delay on a cycle of enter, injected or counter transitions"
                    )));
                }
            }
        }
        Ok(())
    }
}

fn reach(g: &[Vec<usize>], from: usize) -> Vec<bool> {
    let mut seen = vec![false; g.len()];
    let mut stack = vec![from];
    seen[from] = true;
    while let Some(i) = stack.pop() {
        for &j in &g[i] {
            if !seen[j] {
                seen[j] = true;
                stack.push(j);
            }
        }
    }
    seen
}
