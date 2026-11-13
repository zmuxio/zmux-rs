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
            mode: RecordMode::Sealed,
            framing,
            handle: if profile.has_handle() {
                b"0123456789abcdef"
            } else {
                b""
            },
            psk,
            static_secret: &[1; 32],
            binding: b"",
            max_app_data: Some(DEFAULT_MAX_APP_DATA),
        })
        .unwrap()
        .write_hello(b"")
        .unwrap();
        let parsed = Hello::parse(framing, &hello).unwrap();
        let keys = ResponderKeys {
            psk,
            static_secret: &[2; 32],
            binding: b"",
            max_app_data: Some(DEFAULT_MAX_APP_DATA),
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

#[test]
fn a_responder_binding_of_another_length_is_invalid_config() {
    let profile = Profile::all().find(|p| p.psk_len().is_none()).unwrap();
    let (hello, _) = Initiator::new(InitiatorConfig {
        profile,
        mode: RecordMode::Sealed,
        framing: Framing::ByteStream,
        handle: if profile.has_handle() {
            b"0123456789abcdef"
        } else {
            b""
        },
        psk: b"",
        static_secret: &[1; 32],
        binding: b"",
        max_app_data: Some(DEFAULT_MAX_APP_DATA),
    })
    .unwrap()
    .write_hello(b"")
    .unwrap();
    let parsed = Hello::parse(Framing::ByteStream, &hello).unwrap();
    for (binding, ok) in [
        (&[0; 31][..], false),
        (&[0; 33][..], false),
        (&[0; 32][..], true),
    ] {
        let keys = ResponderKeys {
            static_secret: &[2; 32],
            binding,
            ..ResponderKeys::default()
        };
        match Responder::read_hello(&parsed, keys) {
            Err(Error::InvalidConfig) => assert!(!ok),
            // A Binding of the right length is mixed in, not judged; a disagreement is auth.
            Err(Error::Auth) => assert!(ok),
            Err(e) => panic!("{e:?}"),
            Ok(_) => assert!(ok),
        }
    }
}
