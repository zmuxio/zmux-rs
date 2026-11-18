//! Transport parameters: decoding never panics and reports only
//! `TRANSPORT_PARAMETER_ERROR`; what decodes re-encodes to an equal value.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zmux::proto::TransportErrorCode;
use zmux::proto::params::TransportParameters;

fuzz_target!(|data: &[u8]| {
    match TransportParameters::decode(data) {
        Ok(tp) => {
            let mut buf = vec![0u8; tp.encoded_len(None)];
            tp.encode(None, &mut buf).unwrap();
            assert_eq!(TransportParameters::decode(&buf).unwrap(), tp);
        }
        Err(e) => assert_eq!(e.code(), TransportErrorCode::TRANSPORT_PARAMETER_ERROR),
    }
});
