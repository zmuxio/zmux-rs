//! Variable-length integers: decoding never panics; a decoded value
//! re-encodes in its own width to the same bytes and in the shortest width
//! to a value that decodes back.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zmux::proto::varint;

fuzz_target!(|data: &[u8]| {
    if let Some((value, width)) = varint::decode(data) {
        assert!(value <= varint::MAX);
        assert!(width <= data.len());
        assert_eq!(width, varint::width(data[0]));
        let mut buf = [0u8; 8];
        assert_eq!(varint::encode_with_width(value, width, &mut buf), Ok(width));
        assert_eq!(&buf[..width], &data[..width]);
        let n = varint::encode(value, &mut buf).unwrap();
        assert_eq!(n, varint::len(value));
        assert!(n <= width);
        assert_eq!(varint::decode(&buf[..n]), Some((value, n)));
    } else {
        // Only a short input has no varint.
        assert!(data.is_empty() || data.len() < varint::width(data[0]));
    }
});
