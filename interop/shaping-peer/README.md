# Shaping peer

A zmux peer that runs one traffic-shaping definition over TCP, for the
interoperability tests of the other implementations. It reuses the public Rust
runtime and `zmux-shaping`; it does not implement another wire parser.

```
cargo build --release --locked -p zmux-shaping-peer
zmux-shaping-peer server            # prints LISTEN <addr>, serves one session
zmux-shaping-peer client <addr>
```

`SHAPE_DEF` points to a JSON definition in the `zmux-shaping` machine format.
With the variable unset or empty, the side runs unshaped. The client opens eight bidirectional
streams, stream `i` carrying `200000 + i * 7919` bytes of xorshift64 output
seeded with `i + 1`; the server echoes them and the client compares. Each side
prints `STATS wire_spent=<n> injected=<n> dropped=<n> clamped=<n> faults=<n>`
and `OK`; a shaped side fails when it added no wire bytes or counted a fault.
A 60-second deadline ends the process.

A driver starts the server, reads its `LISTEN` line, starts the client with the
address, and checks both exit statuses and the `OK` lines, for every
combination of shaped and unshaped sides and each definition. The Java test
`ShapingInterop` (`ZMUX_SHAPING_PEER`) drives the same contract; `cargo test
-p zmux-shaping-peer` drives the peer against itself.
