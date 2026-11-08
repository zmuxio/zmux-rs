//! The production entrance with random ephemerals.

use zmux::proto::seal::cut_frame;
use zmux_seal_proto::*;

#[test]
fn every_profile_round_trips_with_random_ephemerals() {
    const PSK: [u8; 32] = [7; 32];
    for profile in Profile::all() {
        let framing = Framing::ByteStream;
        let psk: &[u8] = if profile.psk_len().is_some() {
            &PSK
        } else {
            b""
        };
        let (hello, await_reply) = Initiator::new(InitiatorConfig {
            profile,
            mode: Mode::Sealed,
            framing,
            handle: if profile.has_handle() {
                b"0123456789abcdef"
            } else {
                b""
            },
            psk,
            static_secret: &[1; 32],
            binding: b"",
            max_app_data: 0,
        })
        .unwrap()
        .write_hello(b"")
        .unwrap();
        let parsed = Hello::parse(framing, &hello).unwrap();
        let keys = ResponderKeys {
            psk,
            static_secret: &[2; 32],
            binding: b"",
            max_app_data: 0,
        };
        let (reply, _) = Responder::read_hello(&parsed, keys).unwrap();
        let (wire, await_finish) = reply.write_reply(b"").unwrap();
        let verify = await_reply
            .read_reply(cut_frame(&wire, 0).unwrap().0)
            .unwrap();
        let (wire, client) = verify.accept().write_finish(b"").unwrap();
        let (server, _) = await_finish
            .read_finish(cut_frame(&wire, 0).unwrap().0)
            .unwrap();
        let label = b"EXPORTER-zmux-pipe";
        assert_eq!(client.export(label, b"", 32), server.export(label, b"", 32));
    }
}
