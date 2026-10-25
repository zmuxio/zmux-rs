# qmux-peer

A scripted plain QMux peer built on the `qmux` crate (version 0.6.2, QMux
draft-02) for interoperability tests over TCP. It sends no zmux transport
parameters, so a zmux endpoint talking to it treats it as a plain QMux peer.
It does not depend on zmux.

```
cargo build --release --manifest-path interop/qmux-peer/Cargo.toml
interop/qmux-peer/target/release/qmux-peer server 127.0.0.1:0 [--rtt-ms 20]
interop/qmux-peer/target/release/qmux-peer client 127.0.0.1:4433
```

Options:

- `--rtt-ms <ms>`: the `qmux` crate's QX_PING cadence for RTT measurement
  (default 1000, `0` disables it).
- `--no-datagrams`: do not advertise `max_datagram_frame_size`.

The server accepts one connection. The peer uses the crate's defaults
otherwise: `max_record_size` 16382, `max_idle_timeout` 30 s, 100 streams of
each type, a 1 MB session window, 256 KB stream windows, and the
`reset_stream_at` parameter. No application protocol is negotiated.

## Output (stdout, one line each)

| Line | When |
|---|---|
| `LISTEN <addr>` | server mode, once listening |
| `ESTABLISHED` | the peer's transport parameters were processed |
| `RTT <microseconds>` or `RTT none` | when the session ends: the crate's smoothed RTT from its QX_PING requests |
| `CLOSED app <code> <reason>` | the other side closed with CONNECTION_CLOSE 0x1d |
| `CLOSED transport <code> <reason>` | the other side closed with CONNECTION_CLOSE 0x1c |
| `CLOSED other <error>` | any other end (idle timeout, carrier failure, a local protocol error) |
| `CLOSED handshake <error>` | establishment failed |

## Behaviour

- **Bidirectional streams** opened by the other side carry a command on their
  first line (up to `\n`, or the whole stream if it ends first); the bytes
  after the newline are the payload. Commands are below.
- **Unidirectional streams** opened by the other side are read to the end and
  echoed on a new unidirectional stream.
- **Datagrams** are echoed.
- A stream that the other side resets is reported on a new unidirectional
  stream as `reset:<code>`, with the full 62-bit code (`count` adds the byte
  count, see below).

| Command | Action |
|---|---|
| `echo` | echoes the payload and everything after it, then FIN |
| `count` | counts the bytes after the command line and replies `count=<n>` at FIN; if the stream is reset instead, reports `reset:<code>:<n>` on a new unidirectional stream, with the bytes delivered before the reset |
| `stop:<code>` | sends STOP_SENDING with `<code>` at once, then replies `stopped` and FIN |
| `flood` | after the opener's FIN, writes 1 KiB every millisecond until the opener's STOP_SENDING arrives, then reports `stopped:<code>` on a new unidirectional stream |
| `reset:<code>` | after the opener's FIN, writes 1000 bytes of `0x07`, waits 20 ms and resets with `<code>` |
| `open-bidi:<text>` | opens a bidirectional stream, writes `<text>` and FIN, reads the answer to the end and replies `opened=<answer>` |
| `open-uni:<text>` | opens a unidirectional stream carrying `<text>`, then replies `sent` |
| `rtt` | replies `rtt=<microseconds>` or `rtt=none` |
| `datagram-size` | replies `max=<n>`, the crate's maximum datagram payload |
| `close:<code>:<reason>` | replies `closing` and FIN, waits 50 ms and closes the session with `<code>` and `<reason>` |
| anything else | replies `unknown=<command>` |

Codes the peer sends are limited to 32 bits by the crate's API.
