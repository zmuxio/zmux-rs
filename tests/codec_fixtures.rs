use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::{self, Read};
use zmux::*;

const WIRE_VALID_FIXTURES: &str = include_str!("../testdata/fixtures/wire_valid.ndjson");
const WIRE_INVALID_FIXTURES: &str = include_str!("../testdata/fixtures/wire_invalid.ndjson");
const STATE_CASE_FIXTURES: &str = include_str!("../testdata/fixtures/state_cases.ndjson");
const INVALID_CASE_FIXTURES: &str = include_str!("../testdata/fixtures/invalid_cases.ndjson");
const FIXTURE_INDEX: &str = include_str!("../testdata/fixtures/index.json");
const FIXTURE_CASE_SETS: &str = include_str!("../testdata/fixtures/case_sets.json");

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn fixture_values(name: &'static str, content: &'static str) -> impl Iterator<Item = Value> {
    serde_json::Deserializer::from_str(content)
        .into_iter::<Value>()
        .enumerate()
        .map(move |(idx, case)| {
            case.unwrap_or_else(|err| panic!("{name} line {} invalid JSON: {err}", idx + 1))
        })
}

fn fixture_ids(name: &'static str, content: &'static str) -> Vec<String> {
    fixture_values(name, content)
        .enumerate()
        .map(|(idx, case)| {
            case["id"]
                .as_str()
                .unwrap_or_else(|| panic!("{name} line {} missing string id", idx + 1))
                .to_owned()
        })
        .collect()
}

fn fixture_ids_matching(
    name: &'static str,
    content: &'static str,
    mut include: impl FnMut(&Value) -> bool,
) -> Vec<String> {
    fixture_values(name, content)
        .enumerate()
        .filter_map(|(idx, case)| {
            include(&case).then(|| {
                case["id"]
                    .as_str()
                    .unwrap_or_else(|| panic!("{name} line {} missing string id", idx + 1))
                    .to_owned()
            })
        })
        .collect()
}

fn parse_case_sets() -> Value {
    serde_json::from_str(FIXTURE_CASE_SETS).unwrap()
}

fn case_set_ids<'a>(case_sets: &'a Value, name: &str) -> Vec<&'a str> {
    let set = case_sets["sets"][name]
        .as_array()
        .unwrap_or_else(|| panic!("case_sets.{name} missing or not an array"));
    set.iter()
        .enumerate()
        .map(|(idx, id)| {
            id.as_str()
                .unwrap_or_else(|| panic!("case_sets.{name}[{idx}] is not a string"))
        })
        .collect()
}

fn assert_same_fixture_ids(name: &str, got: Vec<String>, want: Vec<&str>) {
    let mut got = got;
    let mut want: Vec<String> = want.into_iter().map(str::to_owned).collect();
    got.sort_unstable();
    want.sort_unstable();
    assert_eq!(got, want, "{name} fixture id set drifted");
}

fn assert_case_set_contains(case_sets: &Value, set_name: &str, expected: Vec<String>) {
    assert!(!expected.is_empty(), "{set_name} expected ids are empty");
    let actual: HashSet<&str> = case_set_ids(case_sets, set_name).into_iter().collect();
    for id in expected {
        assert!(
            actual.contains(id.as_str()),
            "case_sets.{set_name} is missing fixture id {id:?}"
        );
    }
}

fn expect_u64(expect: &Value, key: &str) -> Option<u64> {
    expect.get(key).and_then(Value::as_u64)
}

fn expect_str<'a>(expect: &'a Value, key: &str) -> Option<&'a str> {
    expect.get(key).and_then(Value::as_str)
}

fn expect_hex(expect: &Value, key: &str) -> Option<Vec<u8>> {
    expect_str(expect, key).map(hex_to_bytes)
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap()
}

fn frame_bytes(frame_type: FrameType, flags: u8, stream_id: u64, payload: &[u8]) -> Vec<u8> {
    let stream_id = encode_varint(stream_id).unwrap();
    let frame_len = 1 + usize_to_u64(stream_id.len()) + usize_to_u64(payload.len());
    let mut raw = encode_varint(frame_len).unwrap();
    raw.push(frame_type.as_u8() | flags);
    raw.extend_from_slice(&stream_id);
    raw.extend_from_slice(payload);
    raw
}

fn assert_preface_fixture(id: &str, preface: &Preface, expect: &Value) {
    if let Some(value) = expect_u64(expect, "preface_ver") {
        assert_eq!(
            u64::from(preface.preface_version),
            value,
            "{id} preface_ver"
        );
    }
    if let Some(value) = expect_str(expect, "role") {
        assert_eq!(preface.role.as_str(), value, "{id} role");
    }
    if let Some(value) = expect_u64(expect, "tie_breaker_nonce") {
        assert_eq!(preface.tie_breaker_nonce, value, "{id} tie_breaker_nonce");
    }
    if let Some(value) = expect_u64(expect, "min_proto") {
        assert_eq!(preface.min_proto, value, "{id} min_proto");
    }
    if let Some(value) = expect_u64(expect, "max_proto") {
        assert_eq!(preface.max_proto, value, "{id} max_proto");
    }
    if let Some(value) = expect_u64(expect, "capabilities") {
        assert_eq!(preface.capabilities, value, "{id} capabilities");
    }
    if let Some(value) = expect_u64(expect, "settings_len") {
        let encoded_len = usize_to_u64(preface.settings.encoded_tlv_len().unwrap());
        assert_eq!(encoded_len, value, "{id} settings_len");
    }
}

fn assert_frame_fixture(id: &str, bytes: &[u8], frame: &Frame, expect: &Value) {
    if let Some(value) = expect_u64(expect, "frame_length") {
        let (frame_len, _) = parse_varint(bytes).unwrap();
        assert_eq!(frame_len, value, "{id} frame_length");
    }
    if let Some(value) = expect_str(expect, "frame_type") {
        assert_eq!(frame.frame_type.to_string(), value, "{id} frame_type");
    }
    if let Some(value) = expect.get("flags") {
        let want: Vec<&str> = value
            .as_array()
            .unwrap_or_else(|| panic!("{id} flags is not an array"))
            .iter()
            .enumerate()
            .map(|(idx, flag)| {
                flag.as_str()
                    .unwrap_or_else(|| panic!("{id} flags[{idx}] is not a string"))
            })
            .collect();
        assert_eq!(frame_flag_names(frame.flags), want, "{id} flags");
    }
    if let Some(value) = expect_u64(expect, "stream_id") {
        assert_eq!(frame.stream_id, value, "{id} stream_id");
    }
    if let Some(value) = expect_hex(expect, "payload_hex") {
        assert_eq!(frame.payload, value, "{id} payload_hex");
    }
    assert_decoded_frame_fixture(id, frame, &expect["decoded"]);
}

fn assert_decoded_frame_fixture(id: &str, frame: &Frame, decoded: &Value) {
    if let Some(value) = expect_u64(decoded, "max_offset") {
        let (got, used) = parse_varint(&frame.payload).unwrap();
        assert_eq!(used, frame.payload.len(), "{id} max_offset payload width");
        assert_eq!(got, value, "{id} max_offset");
    }
    if let Some(value) = expect_u64(decoded, "blocked_at") {
        let (got, used) = parse_varint(&frame.payload).unwrap();
        assert_eq!(used, frame.payload.len(), "{id} blocked_at payload width");
        assert_eq!(got, value, "{id} blocked_at");
    }
    if let Some(value) = expect_u64(decoded, "error_code") {
        let (got, _) = parse_error_payload(&frame.payload).unwrap();
        assert_eq!(got, value, "{id} error_code");
    }
    if expect_str(decoded, "application_payload_hex").is_none()
        && expect_str(decoded, "ext_type").is_none()
        && decoded.get("stream_metadata_tlvs").is_none()
    {
        return;
    }

    match frame.frame_type {
        FrameType::Data => {
            let payload = parse_data_payload(&frame.payload, frame.flags).unwrap();
            assert_metadata_tlvs(id, &payload.metadata_tlvs, &decoded["stream_metadata_tlvs"]);
            if let Some(value) = expect_hex(decoded, "application_payload_hex") {
                assert_eq!(payload.app_data, value, "{id} application_payload_hex");
            }
        }
        FrameType::Ext => {
            let (ext_type, offset) = parse_varint(&frame.payload).unwrap();
            if let Some(value) = expect_str(decoded, "ext_type") {
                assert_eq!(ext_type_name(ext_type), value, "{id} ext_type");
            }
            let tlvs = parse_tlvs(&frame.payload[offset..]).unwrap();
            assert_metadata_tlvs(id, &tlvs, &decoded["stream_metadata_tlvs"]);
        }
        other => panic!("{id} decoded fixture unsupported for frame type {other}"),
    }
}

fn assert_metadata_tlvs(id: &str, actual: &[Tlv], expect: &Value) {
    let Some(expect) = expect.as_array() else {
        return;
    };
    assert_eq!(actual.len(), expect.len(), "{id} metadata tlv count");
    for (idx, (actual, expect)) in actual.iter().zip(expect).enumerate() {
        if let Some(value) = expect_str(expect, "type") {
            assert_eq!(metadata_type_name(actual.typ), value, "{id} tlv {idx} type");
        }
        if let Some(value) = expect_u64(expect, "value") {
            let (got, used) = parse_varint(&actual.value).unwrap();
            assert_eq!(used, actual.value.len(), "{id} tlv {idx} value width");
            assert_eq!(got, value, "{id} tlv {idx} value");
        }
        if let Some(value) = expect_hex(expect, "value_hex") {
            assert_eq!(actual.value, value, "{id} tlv {idx} value_hex");
        }
    }
}

fn frame_flag_names(flags: u8) -> Vec<&'static str> {
    let mut out = Vec::new();
    if flags & FRAME_FLAG_OPEN_METADATA != 0 {
        out.push("OPEN_METADATA");
    }
    if flags & FRAME_FLAG_FIN != 0 {
        out.push("FIN");
    }
    out
}

fn ext_type_name(value: u64) -> String {
    match value {
        EXT_PRIORITY_UPDATE => "PRIORITY_UPDATE".to_owned(),
        other => format!("ext_subtype({other})"),
    }
}

fn metadata_type_name(value: u64) -> String {
    match value {
        METADATA_STREAM_PRIORITY => "stream_priority".to_owned(),
        METADATA_STREAM_GROUP => "stream_group".to_owned(),
        METADATA_OPEN_INFO => "open_info".to_owned(),
        other => format!("stream_metadata_type({other})"),
    }
}

fn fixture_catalog() -> (HashMap<String, &'static str>, usize) {
    let sources = [
        ("wire_valid.ndjson", WIRE_VALID_FIXTURES),
        ("wire_invalid.ndjson", WIRE_INVALID_FIXTURES),
        ("state_cases.ndjson", STATE_CASE_FIXTURES),
        ("invalid_cases.ndjson", INVALID_CASE_FIXTURES),
    ];
    let mut catalog = HashMap::new();
    let mut total = 0usize;
    for (source, content) in sources {
        for id in fixture_ids(source, content) {
            total += 1;
            if let Some(prev) = catalog.insert(id.clone(), source) {
                panic!("fixture id {id:?} appears in both {prev} and {source}");
            }
        }
    }
    (catalog, total)
}

#[test]
fn wire_valid_fixtures_decode_and_round_trip() {
    for (idx, case) in fixture_values("wire_valid.ndjson", WIRE_VALID_FIXTURES).enumerate() {
        let id = case["id"].as_str().unwrap_or("<unknown>");
        let bytes = hex_to_bytes(case["hex"].as_str().unwrap());
        match case["category"].as_str().unwrap() {
            "preface_valid" => {
                let parsed = Preface::parse(&bytes).unwrap_or_else(|err| {
                    panic!("{id} parse preface failed at line {}: {err}", idx + 1)
                });
                assert_preface_fixture(id, &parsed, &case["expect"]);
                let encoded = parsed.marshal().unwrap();
                assert_eq!(encoded, bytes, "{id}");
            }
            "frame_valid" => {
                let (frame, used) = Frame::parse(&bytes, Limits::default()).unwrap_or_else(|err| {
                    panic!("{id} parse frame failed at line {}: {err}", idx + 1)
                });
                assert_eq!(used, bytes.len(), "{id}");
                assert_frame_fixture(id, &bytes, &frame, &case["expect"]);
                let encoded = frame.marshal().unwrap();
                assert_eq!(encoded, bytes, "{id}");
            }
            other => panic!("unexpected category {other} in {id}"),
        }
    }
}

#[test]
fn wire_invalid_fixtures_are_rejected() {
    for (idx, case) in fixture_values("wire_invalid.ndjson", WIRE_INVALID_FIXTURES).enumerate() {
        let id = case["id"].as_str().unwrap_or("<unknown>");
        let bytes = hex_to_bytes(case["hex"].as_str().unwrap());
        let err = if case["category"].as_str().unwrap() == "bytes_invalid" {
            parse_varint(&bytes).map(|_| ()).unwrap_err()
        } else {
            let limits = case
                .get("receiver_limits")
                .map(|limits| Limits {
                    max_frame_payload: limits["max_frame_payload"].as_u64().unwrap_or(0),
                    max_control_payload_bytes: limits["max_control_payload_bytes"]
                        .as_u64()
                        .unwrap_or(0),
                    max_extension_payload_bytes: limits["max_extension_payload_bytes"]
                        .as_u64()
                        .unwrap_or(0),
                })
                .unwrap_or_default();
            Frame::parse(&bytes, limits).map(|_| ()).unwrap_err()
        };
        let expected = case["expect_error"].as_str().unwrap();
        assert_eq!(
            err.code().map(|c| c.name()),
            Some(expected),
            "{id} at line {} got {err}",
            idx + 1
        );
    }
}

#[test]
fn role_resolution_and_settings_validation() {
    let mut local = Config::default().local_preface().unwrap();
    let mut peer = Config::default().local_preface().unwrap();
    local.role = Role::Auto;
    peer.role = Role::Auto;
    local.tie_breaker_nonce = 17;
    peer.tie_breaker_nonce = 17;
    let err = negotiate_prefaces(&local, &peer).unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::RoleConflict));

    peer.tie_breaker_nonce = 16;
    let negotiated = negotiate_prefaces(&local, &peer).unwrap();
    assert_eq!(negotiated.local_role, Role::Initiator);
    assert_eq!(negotiated.peer_role, Role::Responder);
}

#[test]
fn priority_update_parser_ignores_open_info_and_rejects_duplicates() {
    let mut payload = Vec::new();
    append_varint(&mut payload, EXT_PRIORITY_UPDATE).unwrap();
    append_tlv(&mut payload, METADATA_OPEN_INFO, b"ignored").unwrap();
    let (metadata, valid) = parse_priority_update_payload(&payload).unwrap();
    assert!(valid);
    assert_eq!(metadata.open_info, b"");

    let mut duplicate = Vec::new();
    append_varint(&mut duplicate, EXT_PRIORITY_UPDATE).unwrap();
    append_tlv(
        &mut duplicate,
        METADATA_STREAM_PRIORITY,
        &encode_varint(1).unwrap(),
    )
    .unwrap();
    append_tlv(
        &mut duplicate,
        METADATA_STREAM_PRIORITY,
        &encode_varint(2).unwrap(),
    )
    .unwrap();
    let (_, valid) = parse_priority_update_payload(&duplicate).unwrap();
    assert!(!valid);
}

#[test]
fn priority_update_parser_ignores_unknown_advisory_tlvs() {
    let mut payload = Vec::new();
    append_varint(&mut payload, EXT_PRIORITY_UPDATE).unwrap();
    append_tlv(
        &mut payload,
        METADATA_STREAM_PRIORITY,
        &encode_varint(5).unwrap(),
    )
    .unwrap();
    append_tlv(&mut payload, 99, b"ignored").unwrap();
    append_tlv(
        &mut payload,
        METADATA_STREAM_GROUP,
        &encode_varint(7).unwrap(),
    )
    .unwrap();

    let (metadata, valid) = parse_priority_update_payload(&payload).unwrap();

    assert!(valid);
    assert_eq!(metadata.priority, Some(5));
    assert_eq!(metadata.group, Some(7));
    assert!(metadata.open_info.is_empty());
}

#[test]
fn data_payload_view_borrows_open_info_and_app_data() {
    let mut raw =
        build_open_metadata_prefix(CAPABILITY_OPEN_METADATA, None, None, b"ssh", 1024).unwrap();
    let app_data_offset = raw.len();
    raw.extend_from_slice(b"payload");

    {
        let view = parse_data_payload_view(&raw, FRAME_FLAG_OPEN_METADATA).unwrap();
        assert!(view.metadata_valid);
        assert_eq!(view.metadata.open_info, b"ssh");
        assert_eq!(view.app_data, b"payload");
        assert_eq!(
            view.metadata.open_info.as_ptr(),
            raw[app_data_offset - 3..app_data_offset].as_ptr()
        );
        assert_eq!(view.app_data.as_ptr(), raw[app_data_offset..].as_ptr());
    }

    let owned = parse_data_payload(&raw, FRAME_FLAG_OPEN_METADATA).unwrap();
    raw[app_data_offset - 1] = b'x';
    assert_eq!(owned.metadata.open_info, b"ssh");
}

#[test]
fn open_metadata_parser_ignores_unknown_metadata_tlvs() {
    let mut metadata = Vec::new();
    append_tlv(
        &mut metadata,
        METADATA_STREAM_PRIORITY,
        &encode_varint(7).unwrap(),
    )
    .unwrap();
    append_tlv(&mut metadata, 99, b"ignored").unwrap();
    append_tlv(
        &mut metadata,
        METADATA_STREAM_GROUP,
        &encode_varint(11).unwrap(),
    )
    .unwrap();

    let (view, valid) = parse_stream_metadata_bytes_view(&metadata).unwrap();

    assert!(valid);
    assert_eq!(view.priority, Some(7));
    assert_eq!(view.group, Some(11));
    assert!(view.open_info.is_empty());
}

#[test]
fn stream_metadata_view_borrows_open_info_and_owned_metadata_copies() {
    let prefix = build_open_metadata_prefix(
        CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS | CAPABILITY_STREAM_GROUPS,
        Some(3),
        Some(7),
        b"ssh",
        1024,
    )
    .unwrap();
    let (metadata_len, metadata_offset) = parse_varint(&prefix).unwrap();
    let metadata_len = usize::try_from(metadata_len).unwrap();
    let mut metadata = prefix[metadata_offset..metadata_offset + metadata_len].to_vec();

    let owned = {
        let (view, valid) = parse_stream_metadata_bytes_view(&metadata).unwrap();
        assert!(valid);
        assert_eq!(view.priority, Some(3));
        assert_eq!(view.group, Some(7));
        assert_eq!(view.open_info, b"ssh");
        let base = metadata.as_ptr() as usize;
        let end = base + metadata.len();
        let ptr = view.open_info.as_ptr() as usize;
        assert!(ptr >= base && ptr + view.open_info.len() <= end);
        view.try_to_owned_metadata().unwrap()
    };

    metadata.fill(b'x');
    assert_eq!(owned.open_info, b"ssh");
}

#[test]
fn parse_tlvs_returns_owned_values_independent_from_source() {
    let mut raw = Vec::new();
    append_tlv(&mut raw, METADATA_OPEN_INFO, b"ssh").unwrap();

    let tlvs = parse_tlvs(&raw).unwrap();
    raw.fill(b'x');

    assert_eq!(tlvs.len(), 1);
    assert_eq!(tlvs[0].typ, METADATA_OPEN_INFO);
    assert_eq!(tlvs[0].value, b"ssh");
}

#[test]
fn duplicate_metadata_singletons_short_circuit_later_bad_tlvs() {
    let mut payload = Vec::new();
    append_varint(&mut payload, EXT_PRIORITY_UPDATE).unwrap();
    append_tlv(
        &mut payload,
        METADATA_STREAM_PRIORITY,
        &encode_varint(1).unwrap(),
    )
    .unwrap();
    append_tlv(
        &mut payload,
        METADATA_STREAM_PRIORITY,
        &encode_varint(2).unwrap(),
    )
    .unwrap();
    payload.extend_from_slice(&[0x40, 0x01, 0x00]);

    let (_, valid) = parse_priority_update_payload(&payload).unwrap();
    assert!(!valid);

    let (_, valid) =
        parse_stream_metadata_bytes_view(&payload[varint_len(EXT_PRIORITY_UPDATE).unwrap()..])
            .unwrap();
    assert!(!valid);
}

#[test]
fn diagnostic_reason_scans_for_later_standard_duplicates() {
    let mut diag = Vec::new();
    append_tlv(&mut diag, DIAG_DEBUG_TEXT, b"visible").unwrap();
    append_tlv(
        &mut diag,
        DIAG_RETRY_AFTER_MILLIS,
        &encode_varint(1).unwrap(),
    )
    .unwrap();
    append_tlv(
        &mut diag,
        DIAG_RETRY_AFTER_MILLIS,
        &encode_varint(2).unwrap(),
    )
    .unwrap();

    let mut payload = encode_varint(42).unwrap();
    payload.extend_from_slice(&diag);

    let (_, reason) = parse_error_payload(&payload).unwrap();
    assert_eq!(reason, "");
}

#[test]
fn diagnostic_reason_duplicate_debug_text_drops_reason() {
    let mut payload = encode_varint(ErrorCode::Protocol.as_u64()).unwrap();
    append_tlv(&mut payload, DIAG_DEBUG_TEXT, b"first").unwrap();
    append_tlv(&mut payload, DIAG_DEBUG_TEXT, b"second").unwrap();

    let (code, reason) = parse_error_payload(&payload).unwrap();

    assert_eq!(code, ErrorCode::Protocol.as_u64());
    assert_eq!(reason, "");
}

#[test]
fn goaway_diagnostic_duplicate_retry_after_drops_reason() {
    let mut payload = encode_varint(8).unwrap();
    payload.extend_from_slice(&encode_varint(12).unwrap());
    payload.extend_from_slice(&encode_varint(ErrorCode::Internal.as_u64()).unwrap());
    append_tlv(
        &mut payload,
        DIAG_RETRY_AFTER_MILLIS,
        &encode_varint(1).unwrap(),
    )
    .unwrap();
    append_tlv(
        &mut payload,
        DIAG_RETRY_AFTER_MILLIS,
        &encode_varint(2).unwrap(),
    )
    .unwrap();
    append_tlv(&mut payload, DIAG_DEBUG_TEXT, b"maintenance").unwrap();

    let parsed = parse_goaway_payload(&payload).unwrap();

    assert_eq!(parsed.last_accepted_bidi, 8);
    assert_eq!(parsed.last_accepted_uni, 12);
    assert_eq!(parsed.code, ErrorCode::Internal.as_u64());
    assert_eq!(parsed.reason, "");
}

#[test]
fn diagnostic_reason_invalid_utf8_drops_reason() {
    for value in [
        &[0xe2, 0x82][..],
        &[0xc0, 0xaf][..],
        &[0xed, 0xa0, 0x80][..],
    ] {
        let mut payload = encode_varint(ErrorCode::Protocol.as_u64()).unwrap();
        append_tlv(&mut payload, DIAG_DEBUG_TEXT, value).unwrap();

        let (code, reason) = parse_error_payload(&payload).unwrap();

        assert_eq!(code, ErrorCode::Protocol.as_u64());
        assert_eq!(reason, "");
    }

    let mut goaway = encode_varint(8).unwrap();
    goaway.extend_from_slice(&encode_varint(12).unwrap());
    goaway.extend_from_slice(&encode_varint(ErrorCode::Internal.as_u64()).unwrap());
    append_tlv(&mut goaway, DIAG_DEBUG_TEXT, &[0xe2, 0x82]).unwrap();

    let parsed = parse_goaway_payload(&goaway).unwrap();

    assert_eq!(parsed.last_accepted_bidi, 8);
    assert_eq!(parsed.last_accepted_uni, 12);
    assert_eq!(parsed.code, ErrorCode::Internal.as_u64());
    assert_eq!(parsed.reason, "");
}

#[test]
fn diagnostic_reason_truncated_tlv_is_protocol_error() {
    let mut payload = encode_varint(ErrorCode::Protocol.as_u64()).unwrap();
    payload.push(0x40);

    let err = parse_error_payload(&payload).unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert!(err.to_string().contains("truncated tlv"));
}

#[test]
fn diagnostic_reason_preserves_noncanonical_varint_error() {
    let mut payload = encode_varint(ErrorCode::Protocol.as_u64()).unwrap();
    payload.extend_from_slice(&[0x40, 0x01, 0x00]);

    let err = parse_error_payload(&payload).unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert!(err.to_string().contains("non-canonical varint62"));
}

#[test]
fn tlv_parser_preserves_noncanonical_varint_errors() {
    let err = parse_tlvs(&[0x40, 0x01, 0x00]).unwrap_err();
    assert!(err.to_string().contains("non-canonical varint62"));
}

#[test]
fn tlv_parser_maps_truncated_headers_to_protocol_tlv_error() {
    for raw in [&[0x40][..], &[METADATA_OPEN_INFO as u8, 0x40][..]] {
        let err = parse_tlvs(raw).unwrap_err();

        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert!(err.to_string().contains("truncated tlv"));
    }
}

#[test]
fn frame_validators_preserve_wrapped_varint_diagnostics() {
    let err = Frame::parse(&[0x04, 0x21, 0x04, 0x40, 0x01], Limits::default())
        .map(|_| ())
        .unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(err.to_string().contains("non-canonical varint62"));

    let err = Frame::parse(&[0x04, 0x02, 0x00, 0x40, 0x01], Limits::default())
        .map(|_| ())
        .unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(err.to_string().contains("non-canonical varint62"));
}

#[test]
fn buffered_frame_parse_checks_payload_limit_before_full_body_presence() {
    let err = Frame::parse(
        &[0x80, 0x00, 0x40, 0x03, 0x01, 0x04],
        Limits {
            max_frame_payload: 16_384,
            ..Limits::default()
        },
    )
    .map(|_| ())
    .unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(err.to_string().contains("payload exceeds configured limit"));
}

#[test]
fn buffered_frame_parse_rejects_short_stream_id_before_next_frame_bytes() {
    let raw = [
        0x02, 0x01, 0xc0, // frame_length=2, DATA, impossible 8-byte stream_id in body
        0, 0, 0, 0, 0, 0, 4, // bytes that must be treated as following data, not this frame
    ];

    let err = Frame::parse(&raw, Limits::default()).unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(err.to_string().contains("frame too short"));
}

struct OneByteReader {
    bytes: Vec<u8>,
    position: usize,
    reads: usize,
}

impl Read for OneByteReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let Some(&byte) = self.bytes.get(self.position) else {
            return Ok(0);
        };
        buffer[0] = byte;
        self.position += 1;
        self.reads += 1;
        Ok(1)
    }
}

struct GreedyReader {
    bytes: Vec<u8>,
    position: usize,
}

impl Read for GreedyReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = &self.bytes[self.position..];
        if remaining.is_empty() {
            return Ok(0);
        }
        let len = remaining.len().min(buffer.len());
        buffer[..len].copy_from_slice(&remaining[..len]);
        self.position += len;
        Ok(len)
    }
}

#[test]
fn direct_frame_read_rejects_short_stream_id_before_consuming_next_frame_bytes() {
    let mut reader = OneByteReader {
        bytes: vec![0x02, FrameType::Data.as_u8(), 0xc0, 99, 98, 97],
        position: 0,
        reads: 0,
    };

    let err = read_frame(&mut reader, Limits::default()).unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(err.to_string().contains("frame too short"));
    assert_eq!(reader.reads, 3);
}

#[test]
fn direct_frame_read_non_byte_reader_does_not_overread_next_frame() {
    let first = Frame::new(FrameType::Data, 4, b"one".to_vec())
        .marshal()
        .unwrap();
    let second = Frame::new(FrameType::Data, 8, b"two".to_vec())
        .marshal()
        .unwrap();
    let mut reader = GreedyReader {
        bytes: [first, second].concat(),
        position: 0,
    };

    let first = read_frame(&mut reader, Limits::default()).unwrap();
    assert_eq!(first.frame_type, FrameType::Data);
    assert_eq!(first.stream_id, 4);
    assert_eq!(first.payload, b"one");

    let second = read_frame(&mut reader, Limits::default()).unwrap();
    assert_eq!(second.frame_type, FrameType::Data);
    assert_eq!(second.stream_id, 8);
    assert_eq!(second.payload, b"two");
}

#[test]
fn direct_frame_read_rejects_oversized_frame_length_before_body_read() {
    let mut bytes = encode_varint(18).unwrap();
    bytes.extend_from_slice(&[FrameType::Ping.as_u8(), 0, 0, 0]);
    let mut reader = OneByteReader {
        bytes,
        position: 0,
        reads: 0,
    };

    let err = read_frame(
        &mut reader,
        Limits {
            max_frame_payload: 8,
            max_control_payload_bytes: 8,
            max_extension_payload_bytes: 8,
        },
    )
    .unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.direction(), ErrorDirection::Read);
    assert_eq!(reader.reads, 1);
}

#[test]
fn direct_preface_read_non_byte_reader_does_not_overread_following_frame() {
    let preface = Preface {
        preface_version: PREFACE_VERSION,
        role: Role::Initiator,
        tie_breaker_nonce: 1,
        min_proto: PROTO_VERSION,
        max_proto: PROTO_VERSION,
        capabilities: 0,
        settings: Settings::default(),
    }
    .marshal()
    .unwrap();
    let frame = Frame::new(FrameType::Data, 4, b"after-preface".to_vec())
        .marshal()
        .unwrap();
    let mut reader = GreedyReader {
        bytes: [preface, frame].concat(),
        position: 0,
    };

    let got = read_preface(&mut reader).unwrap();
    assert_eq!(got.role, Role::Initiator);
    assert_eq!(got.min_proto, PROTO_VERSION);
    assert_eq!(got.max_proto, PROTO_VERSION);

    let frame = read_frame(&mut reader, Limits::default()).unwrap();
    assert_eq!(frame.frame_type, FrameType::Data);
    assert_eq!(frame.stream_id, 4);
    assert_eq!(frame.payload, b"after-preface");
}

struct InvalidProgressReader {
    progress: usize,
}

impl Read for InvalidProgressReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Ok(self.progress)
    }
}

#[test]
fn direct_codec_reads_reject_invalid_reader_progress() {
    for progress in [2, 8193] {
        let mut varint_reader = InvalidProgressReader { progress };
        let err = read_varint(&mut varint_reader).unwrap_err();
        assert_eq!(err.source_io_error_kind(), Some(io::ErrorKind::InvalidData));

        let mut frame_reader = InvalidProgressReader { progress };
        let err = read_frame(&mut frame_reader, Limits::default()).unwrap_err();
        assert_eq!(err.source_io_error_kind(), Some(io::ErrorKind::InvalidData));
    }

    let mut preface_reader = InvalidProgressReader { progress: 8193 };
    let err = read_preface(&mut preface_reader).unwrap_err();
    assert_eq!(err.source_io_error_kind(), Some(io::ErrorKind::InvalidData));
}

#[test]
fn direct_frame_read_wraps_wire_errors_with_session_read_context() {
    let mut invalid_type = encode_varint(2).unwrap();
    invalid_type.push(0);
    invalid_type.extend_from_slice(&encode_varint(0).unwrap());
    let mut invalid_type = invalid_type.as_slice();

    let err = read_frame(&mut invalid_type, Limits::default()).unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.direction(), ErrorDirection::Read);
    assert_eq!(err.operation(), ErrorOperation::Read);

    let mut truncated_payload = encode_varint(3).unwrap();
    truncated_payload.push(FrameType::Ping.as_u8());
    truncated_payload.extend_from_slice(&encode_varint(0).unwrap());
    let mut truncated_payload = truncated_payload.as_slice();

    let err = read_frame(&mut truncated_payload, Limits::default()).unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.direction(), ErrorDirection::Read);
    assert!(err.to_string().contains("truncated frame"));
}

#[test]
fn direct_frame_read_wraps_malformed_payloads_as_frame_size() {
    let cases = [
        (
            frame_bytes(FrameType::Data, FRAME_FLAG_OPEN_METADATA, 4, &[]),
            "OPEN_METADATA",
        ),
        (
            frame_bytes(
                FrameType::Data,
                FRAME_FLAG_OPEN_METADATA,
                4,
                &[2, METADATA_STREAM_PRIORITY as u8],
            ),
            "OPEN_METADATA",
        ),
        (
            frame_bytes(FrameType::Reset, 0, 4, &[]),
            "invalid error_code",
        ),
        (
            frame_bytes(FrameType::GoAway, 0, 0, &[]),
            "malformed GOAWAY",
        ),
    ];

    for (raw, message) in cases {
        let mut input = raw.as_slice();
        let err = read_frame(&mut input, Limits::default()).unwrap_err();

        assert_eq!(err.code(), Some(ErrorCode::FrameSize));
        assert_eq!(err.scope(), ErrorScope::Session);
        assert_eq!(err.source(), ErrorSource::Remote);
        assert_eq!(err.direction(), ErrorDirection::Read);
        assert!(err.to_string().contains(message), "{err}");
    }
}

#[test]
fn direct_frame_read_rejects_invalid_frame_scopes_and_ext_subtypes() {
    let priority_update = build_priority_update_payload(
        CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS,
        MetadataUpdate {
            priority: Some(7),
            group: None,
        },
        Settings::default().max_extension_payload_bytes,
    )
    .unwrap();
    let cancelled = build_code_payload(
        ErrorCode::Cancelled.as_u64(),
        "",
        Settings::default().max_control_payload_bytes,
    )
    .unwrap();
    let close = build_code_payload(
        ErrorCode::Internal.as_u64(),
        "close",
        Settings::default().max_control_payload_bytes,
    )
    .unwrap();

    let protocol_cases = [
        frame_bytes(FrameType::Ping, 0, 4, &[0; 8]),
        frame_bytes(FrameType::Abort, 0, 0, &cancelled),
        frame_bytes(FrameType::Ext, 0, 0, &priority_update),
        frame_bytes(FrameType::Close, 0, 4, &close),
    ];

    for raw in protocol_cases {
        let mut input = raw.as_slice();
        let err = read_frame(&mut input, Limits::default()).unwrap_err();

        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert_eq!(err.source(), ErrorSource::Remote);
        assert_eq!(err.direction(), ErrorDirection::Read);
    }

    for raw in [
        frame_bytes(FrameType::Ext, 0, 4, &[]),
        frame_bytes(FrameType::Ext, 0, 4, &[0x40]),
    ] {
        let mut input = raw.as_slice();
        let err = read_frame(&mut input, Limits::default()).unwrap_err();

        assert_eq!(err.code(), Some(ErrorCode::FrameSize));
        assert_eq!(err.source(), ErrorSource::Remote);
        assert_eq!(err.direction(), ErrorDirection::Read);
    }
}

#[test]
fn direct_preface_read_wraps_wire_errors_with_session_read_context() {
    let mut invalid_role = b"ZMUX".to_vec();
    invalid_role.push(PREFACE_VERSION);
    invalid_role.push(99);
    let mut invalid_role = invalid_role.as_slice();

    let err = read_preface(&mut invalid_role).unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.direction(), ErrorDirection::Read);

    let mut truncated = &b"ZMU"[..];
    let err = read_preface(&mut truncated).unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.source(), ErrorSource::Remote);
    assert_eq!(err.direction(), ErrorDirection::Read);
    assert!(err.to_string().contains("truncated preface"));
}

#[test]
fn priority_update_builder_wraps_local_capability_failure() {
    let err = build_priority_update_payload(
        CAPABILITY_PRIORITY_UPDATE,
        MetadataUpdate {
            priority: None,
            group: Some(7),
        },
        Settings::default().max_extension_payload_bytes,
    )
    .unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert_eq!(err.scope(), ErrorScope::Session);
    assert_eq!(err.operation(), ErrorOperation::Write);
    assert_eq!(err.source(), ErrorSource::Local);
    assert_eq!(err.direction(), ErrorDirection::Write);
}

#[test]
fn buffered_frame_parse_rejects_truncated_stream_id_without_panic() {
    let err = Frame::parse(
        &[0x09, 0x01, 0xc0],
        Limits {
            max_frame_payload: 16_384,
            ..Limits::default()
        },
    )
    .unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(err.to_string().contains("truncated frame"));
}

#[test]
fn buffered_frame_parse_checks_stream_id_canonical_before_payload_limit() {
    let err = Frame::parse(
        &[0x0c, 0x01, 0x40, 0x01],
        Limits {
            max_frame_payload: 1,
            ..Limits::default()
        },
    )
    .unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert!(err.to_string().contains("non-canonical varint62"));
}

#[test]
fn direct_frame_read_checks_stream_id_canonical_before_payload_limit() {
    let mut raw = [0x0c, 0x01, 0x40, 0x01].as_slice();

    let err = read_frame(
        &mut raw,
        Limits {
            max_frame_payload: 1,
            ..Limits::default()
        },
    )
    .unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert!(err.to_string().contains("non-canonical varint62"));
}

#[test]
fn frame_view_parses_without_copying_payload() {
    let frame = Frame::new(FrameType::Data, 4, b"payload".to_vec());
    let encoded = frame.marshal().unwrap();

    let (view, used) = FrameView::parse(&encoded, Limits::default()).unwrap();

    assert_eq!(used, encoded.len());
    assert_eq!(view.frame_type, FrameType::Data);
    assert_eq!(view.stream_id, 4);
    assert_eq!(view.payload, b"payload");
    assert_eq!(view.to_owned_frame(), frame);
}

#[test]
fn priority_update_frame_validation_parses_metadata_values() {
    let err = Frame::parse(
        &[0x07, 0x0b, 0x04, 0x01, 0x01, 0x02, 0x01, 0x00],
        Limits::default(),
    )
    .map(|_| ())
    .unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(err.to_string().contains("tlv value overruns"));
}

#[test]
fn data_payload_metadata_tlvs_are_bounded_to_metadata_length() {
    for payload in [vec![1, 0x40, 0], vec![2, METADATA_OPEN_INFO as u8, 0x40, 0]] {
        let err = parse_data_payload_view(&payload, FRAME_FLAG_OPEN_METADATA).unwrap_err();

        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert!(err.to_string().contains("truncated tlv"));
    }
}

#[test]
fn metadata_parsers_bound_varints_to_tlv_values() {
    let metadata = [
        METADATA_STREAM_PRIORITY as u8,
        1,
        0x40,
        METADATA_OPEN_INFO as u8,
        1,
        b'x',
    ];
    let err = parse_stream_metadata_bytes_view(&metadata).unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert!(err.to_string().contains("truncated varint62"));

    let mut priority_update = vec![EXT_PRIORITY_UPDATE as u8];
    priority_update.extend_from_slice(&metadata);
    let err = parse_priority_update_payload(&priority_update).unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert!(err.to_string().contains("truncated varint62"));

    let trailing = [METADATA_STREAM_PRIORITY as u8, 2, 7, b'x'];
    let err = parse_stream_metadata_bytes_view(&trailing).unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert!(err.to_string().contains("tlv value overruns"));
}

#[test]
fn open_metadata_overrun_with_huge_length_is_frame_size() {
    let metadata_len = encode_varint(MAX_VARINT62).unwrap();
    let mut raw = encode_varint(1 + 1 + usize_to_u64(metadata_len.len())).unwrap();
    raw.push(FrameType::Data.as_u8() | FRAME_FLAG_OPEN_METADATA);
    raw.push(4);
    raw.extend_from_slice(&metadata_len);

    let err = Frame::parse(&raw, Limits::default()).unwrap_err();
    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(err.to_string().contains("OPEN_METADATA payload overrun"));
}

#[test]
fn public_open_metadata_parser_rejects_huge_length() {
    let payload = encode_varint(MAX_VARINT62).unwrap();

    let err = parse_data_payload_view(&payload, FRAME_FLAG_OPEN_METADATA).unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(err.to_string().contains("OPEN_METADATA payload overrun"));

    let err = parse_data_payload(&payload, FRAME_FLAG_OPEN_METADATA).unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::FrameSize));
    assert!(err.to_string().contains("OPEN_METADATA payload overrun"));
}

#[test]
fn tlv_parser_rejects_huge_value_length_without_truncation() {
    let mut raw = encode_varint(METADATA_OPEN_INFO).unwrap();
    raw.extend_from_slice(&encode_varint(MAX_VARINT62).unwrap());

    let err = parse_tlvs(&raw).unwrap_err();

    assert_eq!(err.code(), Some(ErrorCode::Protocol));
    assert!(err.to_string().contains("tlv value overruns"));
}

#[test]
fn stream_id_helpers_match_role_and_kind_semantics() {
    assert_eq!(first_local_stream_id(Role::Initiator, true), 4);
    assert_eq!(first_peer_stream_id(Role::Initiator, false), 3);
    assert_eq!(stream_kind_for_local(Role::Initiator, 4), (true, true));
    assert_eq!(stream_kind_for_local(Role::Initiator, 2), (true, false));
    assert_eq!(stream_kind_for_local(Role::Initiator, 3), (false, true));

    validate_local_open_id(Role::Initiator, 4, true).unwrap();
    validate_local_open_id(Role::Initiator, 2, false).unwrap();
    assert!(validate_stream_id_for_role(Role::Initiator, 0).is_err());
    assert_eq!(max_stream_id_for_class(4) % 4, 0);
    assert_eq!(projected_local_open_id(4, 2), 12);
    assert!(local_open_refused_by_goaway(20, true, 16, 15));
    assert!(peer_open_refused_by_goaway(23, 20, 19));
    assert_eq!(expected_next_peer_stream_id(23, 4, 7), 7);
    assert!(validate_local_open_id(Role::Initiator, 1, true)
        .unwrap_err()
        .to_string()
        .contains("not locally owned"));
    assert!(validate_local_open_id(Role::Initiator, 2, true)
        .unwrap_err()
        .to_string()
        .contains("not bidirectional"));
}

#[test]
fn extended_fixture_inventory_is_available() {
    for (name, content) in [
        ("state_cases.ndjson", STATE_CASE_FIXTURES),
        ("invalid_cases.ndjson", INVALID_CASE_FIXTURES),
    ] {
        let mut count = 0usize;
        for case in fixture_values(name, content) {
            assert!(case["id"].is_string(), "{name} fixture without id");
            count += 1;
        }
        assert!(count > 0, "{name} fixtures are empty");
    }

    let index: Value = serde_json::from_str(FIXTURE_INDEX).unwrap();
    assert_eq!(index["schema"], "zmux-fixture-bundle-v1");
    assert_eq!(index["generated_from"], "assets/golden_cases.json");

    let case_sets = parse_case_sets();
    assert_eq!(case_sets["schema"], "zmux-case-sets-v1");
    assert_eq!(case_sets["generated_from"], "assets/golden_cases.json");
    for name in [
        "codec_valid",
        "codec_invalid",
        "preface",
        "stream_lifecycle",
        "session_lifecycle",
        "flow_control",
        "unidirectional",
        "open_metadata",
        "priority_update",
    ] {
        assert!(
            case_sets["sets"]
                .get(name)
                .and_then(Value::as_array)
                .is_some(),
            "case_sets.{name} missing or not an array"
        );
    }
}

#[test]
fn fixture_index_counts_and_paths_match_vendored_bundle() {
    let index: Value = serde_json::from_str(FIXTURE_INDEX).unwrap();
    let files = index["files"]
        .as_array()
        .expect("fixture index files missing");
    let mut entries = HashMap::with_capacity(files.len());
    for entry in files {
        let kind = entry["kind"].as_str().expect("fixture index kind missing");
        assert!(
            entries.insert(kind, entry).is_none(),
            "duplicate fixture index kind {kind:?}"
        );
    }

    let expected = [
        (
            "wire_valid",
            "fixtures/wire_valid.ndjson",
            fixture_ids("wire_valid.ndjson", WIRE_VALID_FIXTURES).len(),
        ),
        (
            "wire_invalid",
            "fixtures/wire_invalid.ndjson",
            fixture_ids("wire_invalid.ndjson", WIRE_INVALID_FIXTURES).len(),
        ),
        (
            "state_cases",
            "fixtures/state_cases.ndjson",
            fixture_ids("state_cases.ndjson", STATE_CASE_FIXTURES).len(),
        ),
        (
            "invalid_cases",
            "fixtures/invalid_cases.ndjson",
            fixture_ids("invalid_cases.ndjson", INVALID_CASE_FIXTURES).len(),
        ),
    ];

    assert_eq!(
        entries.len(),
        expected.len(),
        "fixture index contains unexpected kinds"
    );
    for (kind, path, count) in expected {
        let entry = entries
            .get(kind)
            .unwrap_or_else(|| panic!("fixture index missing kind {kind:?}"));
        assert_eq!(entry["path"].as_str(), Some(path), "{kind} index path");
        assert_eq!(
            entry["count"].as_u64(),
            Some(usize_to_u64(count)),
            "{kind} index count"
        );
    }
}

#[test]
fn case_set_codec_ids_match_wire_fixtures() {
    let case_sets = parse_case_sets();
    assert_same_fixture_ids(
        "codec_valid",
        fixture_ids("wire_valid.ndjson", WIRE_VALID_FIXTURES),
        case_set_ids(&case_sets, "codec_valid"),
    );
    assert_same_fixture_ids(
        "codec_invalid",
        fixture_ids("wire_invalid.ndjson", WIRE_INVALID_FIXTURES),
        case_set_ids(&case_sets, "codec_invalid"),
    );
}

#[test]
fn case_sets_cover_fixture_categories() {
    let case_sets = parse_case_sets();

    assert_case_set_contains(
        &case_sets,
        "stream_lifecycle",
        fixture_ids_matching("state_cases.ndjson", STATE_CASE_FIXTURES, |case| {
            case["scope"].as_str() != Some("session")
        }),
    );
    assert_case_set_contains(
        &case_sets,
        "session_lifecycle",
        fixture_ids_matching("state_cases.ndjson", STATE_CASE_FIXTURES, |case| {
            case["scope"].as_str() == Some("session")
        }),
    );
    assert_case_set_contains(
        &case_sets,
        "preface",
        fixture_ids_matching("invalid_cases.ndjson", INVALID_CASE_FIXTURES, |case| {
            let id = case["id"].as_str().unwrap_or_default();
            id == "preface_duplicate_setting_id" || id.starts_with("preface_")
        }),
    );
    assert_case_set_contains(
        &case_sets,
        "open_metadata",
        fixture_ids_matching("invalid_cases.ndjson", INVALID_CASE_FIXTURES, |case| {
            case["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("frame_data_open_metadata_"))
        }),
    );
    assert_case_set_contains(
        &case_sets,
        "open_metadata",
        fixture_ids_matching("state_cases.ndjson", STATE_CASE_FIXTURES, |case| {
            case["id"]
                .as_str()
                .is_some_and(|id| id.contains("open_metadata"))
        }),
    );
    assert_case_set_contains(
        &case_sets,
        "priority_update",
        fixture_ids_matching("invalid_cases.ndjson", INVALID_CASE_FIXTURES, |case| {
            case["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("frame_priority_update_"))
        }),
    );
    assert_case_set_contains(
        &case_sets,
        "unidirectional",
        fixture_ids_matching("invalid_cases.ndjson", INVALID_CASE_FIXTURES, |case| {
            case["id"]
                .as_str()
                .is_some_and(|id| id.ends_with("_wrong_side_uni"))
        }),
    );
    assert_case_set_contains(
        &case_sets,
        "flow_control",
        fixture_ids_matching("invalid_cases.ndjson", INVALID_CASE_FIXTURES, |case| {
            matches!(
                case["id"].as_str(),
                Some(
                    "frame_data_exceeds_stream_max_data"
                        | "frame_data_exceeds_session_max_data"
                        | "late_data_after_close_read_exceeds_session_aggregate_cap"
                )
            )
        }),
    );
    assert_case_set_contains(
        &case_sets,
        "flow_control",
        fixture_ids_matching("state_cases.ndjson", STATE_CASE_FIXTURES, |case| {
            case["scope"].as_str() == Some("flow_control")
        }),
    );
}

#[test]
fn case_set_ids_resolve_to_known_unique_fixtures() {
    let (catalog, _) = fixture_catalog();
    let case_sets = parse_case_sets();
    let sets = case_sets["sets"]
        .as_object()
        .expect("case_sets sets missing or not an object");
    assert!(!sets.is_empty(), "case_sets.json contains no sets");

    for (set_name, ids) in sets {
        let ids = ids
            .as_array()
            .unwrap_or_else(|| panic!("case_sets.{set_name} is not an array"));
        let mut seen = HashSet::with_capacity(ids.len());
        for (idx, id) in ids.iter().enumerate() {
            let id = id
                .as_str()
                .unwrap_or_else(|| panic!("case_sets.{set_name}[{idx}] is not a string"));
            assert!(
                catalog.contains_key(id),
                "case_sets.{set_name} references unknown fixture id {id:?}"
            );
            assert!(
                seen.insert(id),
                "case_sets.{set_name} repeats fixture id {id:?}"
            );
        }
    }
}

#[test]
fn fixture_ids_are_globally_unique_across_bundles() {
    let (catalog, total) = fixture_catalog();
    assert_eq!(
        catalog.len(),
        total,
        "fixture catalog size should equal the number of loaded fixture ids"
    );
}

#[test]
fn retired_registry_aliases_are_public_and_stable() {
    assert_eq!(
        CAPABILITY_MULTILINK_BASIC,
        CAPABILITY_MULTILINK_BASIC_RETIRED
    );
    assert_eq!(CAPABILITY_MULTILINK_BASIC, 1 << 2);
    assert_eq!(EXT_ML_READY_RETIRED, 2);
    assert_eq!(EXT_ML_ATTACH_RETIRED, 3);
    assert_eq!(EXT_ML_ATTACH_ACK_RETIRED, 4);
    assert_eq!(EXT_ML_DRAIN_REQ_RETIRED, 5);
    assert_eq!(EXT_ML_DRAIN_ACK_RETIRED, 6);
}
