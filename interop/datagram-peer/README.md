# Datagram-channel peer

A zmux peer over QUIC for the interoperability tests of the datagram channel,
built on the `zmux-quinn` adapter.

```
cargo build --release --locked -p zmux-datagram-peer
zmux-datagram-peer server <cert.pem> <key.pem>   # prints LISTEN <addr>
zmux-datagram-peer client <addr> <n>
```

ALPN `qmux-02`; the client does not verify the server's certificate. The server
echoes every session datagram and every stream (bidirectional streams are
copied back until the peer's FIN) and prints `STATS sent=<n> sentch=<n>
recv=<n> recvch=<n>` when its session ends. The client sends `n` datagrams of
100 bytes (the index as a big-endian `u32` first), expects each echoed within
five seconds, prints the same `STATS` line and closes. `sentch` and `recvch`
count the datagrams that used the QUIC datagram channel instead of the
session's streams. A 60-second deadline ends the process.

The Java test `QuicChannelInteropTest` (`ZMUX_RS_QUIC_CHANNEL_PEER`) drives this
contract; `cargo test -p zmux-datagram-peer` drives
the peer against itself.
