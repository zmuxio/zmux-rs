# Go and Rust WebTransport interop

Run the loopback tests with `bash interop/webtransport/run.sh /path/to/zmux-go`.

| Client | Server | Result |
| --- | --- | --- |
| Rust | Go | Supported |
| Go | Rust | Allowed difference. The Go peer requires QUIC partial delivery on stream reset (`RESET_STREAM_AT`), which the Rust peer's Quinn transport lacks. The connection stops during WebTransport setup. |
