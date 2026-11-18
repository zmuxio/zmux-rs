//! Stream preambles, datagram flow prefixes and the out-of-band encoding:
//! the parsers never panic, never read past their input and report only
//! `PROTOCOL_VIOLATION`.
//!
//! Input: two bytes of the preamble limit, then the bytes to parse.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zmux::proto::payload::{Flow, WirePreamble};
use zmux::proto::{TransportErrorCode, oob};

fuzz_target!(|data: &[u8]| {
    let [hi, lo, bytes @ ..] = data else {
        return;
    };
    let limit = u64::from(u16::from_be_bytes([*hi, *lo]));
    match WirePreamble::parse(bytes, limit) {
        Ok((_, size)) => assert!(size <= bytes.len() && size as u64 <= limit),
        Err(e) => assert_eq!(e.code(), TransportErrorCode::PROTOCOL_VIOLATION),
    }
    match Flow::parse(bytes) {
        Ok((flow, payload)) => assert!(flow.encoded_len() + payload.len() <= bytes.len()),
        Err(e) => assert_eq!(e.code(), TransportErrorCode::PROTOCOL_VIOLATION),
    }
    let mut out = [0u8; 256];
    let _ = oob::decode(bytes, &mut out);
});
