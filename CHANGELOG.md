# Changelog

## 1.2.1

All crates of the workspace are released together at this version.

### Fixes

- Streams opened during early data accept a preamble and a requested
  priority: the preamble, with its PRIORITY TLV, is part of the assumed
  parameter set (SPEC.md Section 6.1.2), no longer "session not
  established".
- A pipe reserved for an out-of-band join takes its carrier's framing when
  the carrier is attached: over WebSocket (message framing) it no longer
  sends Size-prefixed records, which the peer rejected.

### Additions

- zmux-websocket: `wss://` with `dial_tls` and `connect_tls`, which take
  the application's `tokio_rustls::TlsConnector`, and `dial_over` for a
  WebSocket client handshake on an established stream.

## 1.2.0

All crates of the workspace are released together at this version.

### Breaking changes

- Stream preambles are values: `open_bi_with` / `open_uni_with` (and the
  `try_*_with` forms) take a `Preamble`, `RecvStream::preamble` reads it.
  The preamble setters and `TooLate` are gone; `OpenError` gains
  `NotNegotiated`, `TooLarge` and `InvalidArgument`.
- Renames: `Stats` is `SessionStats`, `PipeInfo` is `PipeStats`, `LaneInfo`
  is `LaneStats`, `State` is exported as `SessionState`, `PipeEvent` is
  `SessionEvent`. Pipes are identified by `PipeId` everywhere;
  `pipes()` returns `Vec<Pipe>`, with `pipe(PipeId)` and `pipe_stats()`.
- `SessionError::ResumeTimeout` and `SessionError::PipesLost` carry the last
  `PipeFailure`. `OnDriverThread` is no longer a `SessionError`: blocking
  waits return `blocking::WaitError`, and blocking `closed()` returns a
  `Result`.
- Multipath is configured with `Config::multipath(auth)`; multipath without
  pipe authentication, or offered by `Session::accept`, is
  `InvalidConfig`. Its state is the `Multipath` enum.
- One dial type: `zmux::Dial` (and `blocking::Dial`), with `DialRequest`
  at the crate root.
- Dropping a shutdown future closes the session.
- Configuration floors: `initial_stream_receive_window` at least 4 KiB,
  `initial_connection_receive_window` at least 16 KiB, and
  `max_incoming_streams` either 0 or at least 4. Lower values are
  `InvalidConfig`.
- `is_retryable` means on every error type that the peer did not act on
  the operation. `SessionError::EarlyDataRejected` is now retryable (on a
  new session, without early data), and so are the stream, open and
  connect errors that wrap it.
- `Session::peer` (role auto) refuses a configuration with early data.
- `zmux-quinn`: `QuicCarrier::new` takes the connection and `Options`
  (the flow-control windows come from `Options::transport_config`).

### Added

- Early data: `Config::early_data` (`EarlyData::for_zmux_peer`,
  `with_carrier_early_data`), `SessionError::is_early_data_rejected`,
  `SessionError::in_io` to find a session error inside an `io::Error`,
  `RecvStream::is_replayable`, `Session::parameters_to_remember`.
- Carrier adapters: `PipeIo::with_early_data` reports the carrier's verdict on
  its early data and `PipeIo::with_early_restart` gives the session the
  post-handshake byte stream after a rejection; a failing hook fails the
  session.
- `zmux-quinn`: QUIC 0-RTT with `Options::with_zero_rtt`;
  `connect_with_report` returns a `ZeroRtt` report (sent, accepted,
  rewritten); `ParameterMemory::with_capacity`, `len`, `is_empty`,
  `clear`.
- Hooks: `Config::tracer`, `Config::protocols` (application protocol
  negotiation), `ListenerConfig::on_memory_pressure`.
- `Listener::serve`, `serve_with`, `closed`, `limits` and `stats`.
- Carrier adapter crates: `zmux-rustls`, `zmux-http`
  (HTTP/1.1 and HTTP/2), `zmux-h3`, `zmux-webtransport`,
  `zmux-websocket`.
- `Priority::URGENT` and `Priority::BACKGROUND`; `PipeOptions` and
  `PipePool` builders.
