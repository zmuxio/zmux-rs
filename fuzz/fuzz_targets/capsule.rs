//! The capsule decoder of packet streams: it never panics, never gives a
//! payload above its bound, and finds the same capsules, skips, fault and
//! end however the bytes are cut into reads.
//!
//! Input: one byte of the bound (payloads of at most that many bytes
//! times 16), one of the read size, then the bytes to decode.
#![no_main]

use libfuzzer_sys::fuzz_target;
use zmux::test_hooks::decode_capsules;

fuzz_target!(|data: &[u8]| {
    let [max, step, bytes @ ..] = data else {
        return;
    };
    let max = usize::from(*max) * 16;
    let whole = decode_capsules(max, bytes, bytes.len().max(1));
    assert!(whole.packets.iter().all(|(_, p)| p.len() <= max));
    assert_eq!(
        whole.fault.is_some(),
        !whole.at_boundary && whole.fault.is_some()
    );
    assert_eq!(
        decode_capsules(max, bytes, usize::from(*step).max(1)),
        whole
    );
    assert_eq!(decode_capsules(max, bytes, 1), whole);
});
