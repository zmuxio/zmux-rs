# Scripted zmux peer

Build with `cargo build --release --locked --manifest-path interop/peer/Cargo.toml`.
The standalone lockfile is committed. This helper reuses the public Rust runtime;
it does not implement another wire parser.

`zmux-interop-peer server|client|mp-server|mp-client [host:port]` has a 90-second
process deadline. Servers print `LISTEN <address>`; all modes print `ESTABLISHED`
and finally `CLOSED <reason>`. Multipath modes use four-pipe capacity and the
public test PSK `zmux interop pre-shared key 0123`. The MP client opens one extra
pipe and waits up to five seconds for its outbound half to become active.
The MP server retains its Listener and serving task until the session closes.

Bidirectional commands are OPEN_INFO values. See the module comment in
`src/main.rs` for echo, metadata, reset, stop, reverse opens, datagrams and close.
`dgram:<count>` echoes exactly count flow datagrams, increments their context,
and replies `dgram-done` after FIN. `schedule:round-robin` changes the session's
scheduler and replies `scheduled`. `drop-bootstrap` aborts pipe zero and replies
`dropped` over the remaining path. Uni streams and session datagrams are echoed.
These same commands are implemented by the Java test peer.

The `close` command waits for the request FIN and sends the requested session
close without a stream reply. Drivers assert that session close's remote code
and reason, then the child's exit status. There is no sleep or unacknowledged
response FIN whose delivery the session close could overtake.
