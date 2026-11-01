# zmux-shaping

A `zmux::shaping::Shaper` driven by state machines read from a versioned
definition: a JSON form and a compact sequence form, a validator, number
sources and distributions, and an injectable random source.

```rust
let factory = zmux_shaping::Definition::from_json(json)?.factory(Default::default())?;
session.set_shaper(Some(std::sync::Arc::new(factory)));
```

A factory set as `zmux::Config::shaper` is installed when each session is
created instead, so that accepted sessions and joined pipes are shaped from
their first record. A factory of its own can pick a definition by
`ShapedPipe::carrier`, the carrier kind the adapters set
(`PipeIo::with_carrier`).

`pool_policy` reads a JSON object with the optional fields `count` (a
value), `dial_after` (a list of values; entry k applies after k consecutive
failed dials, the last entry to any higher number), `dial_jitter` (a number
in [0, 1), only with `dial_after`: each wait for a dial is reduced by its
own random fraction of up to it), `retire` (a list of
`{"metric": name, "above": value, "jitter": j}`, metrics `age`, `idle`,
`pipes`, `bytes_sent`, `bytes_received`, `bytes`; the optional jitter in
[0, 1) reduces the threshold by a random fraction of up to j, drawn once per
member), `probe_interval` (a value, for the pipes added from then on) and `probe_jitter` (a number in [0, 1), only with
`probe_interval`; a draw other than 0 or in [1 s, 1e9 s] makes the
decision invalid). Values have the definition's form; times are in seconds.
Values of scope `shared` are drawn once per policy, of scope `pipe` once per
member while it is in view, others at each decision. With the `tokio`
feature the result is a `zmux::helpers::PoolPolicy`: a member's `idle` is
the least `since_last_traffic` of its pipes, its bytes are summed, its
`pipes` is how many it has, and the next dial is `dial_after` after the start
of the last dial (of the pool before the first).

`session_limits` reads session limits (`max_padding_bytes`,
`max_padding_ratio`, `max_injected`, `max_pause_total`, `max_delay`) into a
`zmux::shaping::Limits`: an absent member is no limit, 0 allows none.

JSON is read strictly: unknown or duplicate members are errors at every
level, names and enumerations are case-sensitive, `null` is the same as an
absent member, integer members must be written as JSON integers (`1.0` is an
error), and numbers outside binary64 are errors. Every number a value
declares is bounded by what it stands for (lengths, seconds, rates, counts,
probabilities), and its draws by the derived lower and upper bounds.

License: Apache-2.0.
