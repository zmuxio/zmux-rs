//! The codepoint tables of `zmux::proto` against assets/registry.json, in
//! both directions: a value added, removed or changed on either side fails.

use serde_json::Value;
use sha2::{Digest, Sha256};
use zmux::proto::error::{APPLICATION_ERRORS, ApplicationErrorCode, TRANSPORT_ERRORS};
use zmux::proto::frame::{
    FrameType, JOIN_TOKEN_LEN, JoinDirection, LANE_KEY_LEN, MAX_JOIN_FRAME_LEN, MAX_LOCATOR_LEN,
};
use zmux::proto::params;
use zmux::proto::payload::{self, PREAMBLE_TLVS, TlvStatus};
use zmux::proto::{ident, keys, oob};

use crate::support::read_json;

fn hex_u64(v: &Value) -> u64 {
    let s = v["hex"].as_str().expect("hex form");
    u64::from_str_radix(s.trim_start_matches("0x"), 16).expect("hex value")
}

#[test]
fn frame_types_match() {
    // The library keeps no copy of the registry: its frame type constants
    // and names are checked against every row, both ends of each range.
    let reg = read_json("registry.json");
    let rows = reg["frame_types"].as_array().unwrap();
    for row in rows {
        let name = row["name"].as_str().unwrap();
        for ty in [hex_u64(&row["first"]), hex_u64(&row["last"])] {
            assert_eq!(FrameType(ty).name(), Some(name), "{name}: {ty:#x}");
        }
    }
    // Every named type of the library is a registry row.
    let named = [
        FrameType::PADDING,
        FrameType::RESET_STREAM,
        FrameType::STOP_SENDING,
        FrameType::STREAM,
        FrameType::MAX_DATA,
        FrameType::MAX_STREAM_DATA,
        FrameType::MAX_STREAMS_BIDI,
        FrameType::MAX_STREAMS_UNI,
        FrameType::DATA_BLOCKED,
        FrameType::STREAM_DATA_BLOCKED,
        FrameType::STREAMS_BLOCKED_BIDI,
        FrameType::STREAMS_BLOCKED_UNI,
        FrameType::CONNECTION_CLOSE,
        FrameType::CONNECTION_CLOSE_APPLICATION,
        FrameType::RESET_STREAM_AT,
        FrameType::DATAGRAM,
        FrameType::DATAGRAM_LEN,
        FrameType::QX_TRANSPORT_PARAMETERS,
        FrameType::QX_PING_REQUEST,
        FrameType::QX_PING_RESPONSE,
        FrameType::GOAWAY,
        FrameType::PRIORITY_UPDATE,
        FrameType::PIPE_JOIN,
        FrameType::PIPE_ACK,
        FrameType::PIPE_LANE,
        FrameType::PIPE_PING,
        FrameType::PIPE_ABANDON,
        FrameType::PIPE_STATUS,
    ];
    for t in named {
        let name = t.name().unwrap_or_else(|| panic!("{:#x} unnamed", t.0));
        assert!(
            rows.iter().any(|r| r["name"] == name
                && (hex_u64(&r["first"])..=hex_u64(&r["last"])).contains(&t.0)),
            "{name} ({:#x}) not in the registry",
            t.0
        );
    }
}

#[test]
fn transport_parameters_match() {
    use params::id;
    // The library's parameter IDs, by registry name.
    let ids = [
        (
            "original_destination_connection_id",
            id::ORIGINAL_DESTINATION_CONNECTION_ID,
        ),
        ("max_idle_timeout", id::MAX_IDLE_TIMEOUT),
        ("stateless_reset_token", id::STATELESS_RESET_TOKEN),
        ("max_udp_payload_size", id::MAX_UDP_PAYLOAD_SIZE),
        ("initial_max_data", id::INITIAL_MAX_DATA),
        (
            "initial_max_stream_data_bidi_local",
            id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        ),
        (
            "initial_max_stream_data_bidi_remote",
            id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        ),
        (
            "initial_max_stream_data_uni",
            id::INITIAL_MAX_STREAM_DATA_UNI,
        ),
        ("initial_max_streams_bidi", id::INITIAL_MAX_STREAMS_BIDI),
        ("initial_max_streams_uni", id::INITIAL_MAX_STREAMS_UNI),
        ("ack_delay_exponent", id::ACK_DELAY_EXPONENT),
        ("max_ack_delay", id::MAX_ACK_DELAY),
        ("disable_active_migration", id::DISABLE_ACTIVE_MIGRATION),
        ("preferred_address", id::PREFERRED_ADDRESS),
        ("active_connection_id_limit", id::ACTIVE_CONNECTION_ID_LIMIT),
        (
            "initial_source_connection_id",
            id::INITIAL_SOURCE_CONNECTION_ID,
        ),
        ("retry_source_connection_id", id::RETRY_SOURCE_CONNECTION_ID),
        ("reset_stream_at", id::RESET_STREAM_AT),
        ("max_datagram_frame_size", id::MAX_DATAGRAM_FRAME_SIZE),
        ("max_record_size", id::MAX_RECORD_SIZE),
        ("zmux_role", id::ZMUX_ROLE),
        ("zmux_goaway", id::ZMUX_GOAWAY),
        ("zmux_preamble", id::ZMUX_PREAMBLE),
        ("zmux_priority", id::ZMUX_PRIORITY),
        ("zmux_datagram_flows", id::ZMUX_DATAGRAM_FLOWS),
        ("zmux_multipath", id::ZMUX_MULTIPATH),
        ("zmux_ack_threshold", id::ZMUX_ACK_THRESHOLD),
        ("zmux_pipe_ack", id::ZMUX_PIPE_ACK),
        ("zmux_max_ack_delay", id::ZMUX_MAX_ACK_DELAY),
        ("zmux_max_lanes", id::ZMUX_MAX_LANES),
        ("zmux_resume", id::ZMUX_RESUME),
        ("zmux_record_protection", id::ZMUX_RECORD_PROTECTION),
    ];
    let reg = read_json("registry.json");
    let rows = reg["transport_parameters"].as_array().unwrap();
    assert_eq!(rows.len(), ids.len(), "number of transport parameters");
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let (_, lib) = ids
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("{name}: not known to the library"));
        assert_eq!(hex_u64(&row["id"]), *lib, "{name}: id");
        assert_eq!(
            row["scope"].as_str() == Some("prohibited"),
            params::is_prohibited(*lib),
            "{name}: prohibited"
        );
        assert!(!params::is_grease_id(*lib), "{name} is a GREASE ID");
    }
}

#[test]
fn error_codes_match() {
    let reg = read_json("registry.json");
    let rows = reg["transport_errors"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        TRANSPORT_ERRORS.len(),
        "number of transport errors"
    );
    for (row, (code, name, wire)) in rows.iter().zip(TRANSPORT_ERRORS) {
        assert_eq!(row["name"].as_str(), Some(*name));
        assert_eq!(hex_u64(&row["code"]), code.0, "{name}");
        assert_eq!(row["wire"].as_bool(), Some(*wire), "{name}: wire");
        assert_eq!(code.is_sent_on_wire(), *wire, "{name}: is_sent_on_wire");
        assert_eq!(code.name(), Some(*name));
    }
    let rows = reg["application_errors"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        APPLICATION_ERRORS.len(),
        "number of application errors"
    );
    for (row, (code, name, rep)) in rows.iter().zip(APPLICATION_ERRORS) {
        assert_eq!(row["name"].as_str(), Some(*name));
        assert_eq!(hex_u64(&row["code"]), code.0, "{name}");
        assert_eq!(
            row["socks5_rep"].as_u64(),
            rep.map(u64::from),
            "{name}: SOCKS5"
        );
        assert_eq!(code.socks5_reply(), *rep);
    }
    let block = &reg["application_error_block"];
    let parse = |v: &Value| u64::from_str_radix(v.as_str().unwrap().trim_start_matches("0x"), 16);
    assert_eq!(
        parse(&block["first"]),
        Ok(ApplicationErrorCode::ZMUX_BLOCK_FIRST)
    );
    assert_eq!(
        parse(&block["last"]),
        Ok(ApplicationErrorCode::ZMUX_BLOCK_LAST)
    );
}

#[test]
fn preamble_tlvs_and_grease_match() {
    let reg = read_json("registry.json");
    let rows = reg["preamble_tlvs"].as_array().unwrap();
    assert_eq!(rows.len(), PREAMBLE_TLVS.len());
    for (row, (name, ty, status)) in rows.iter().zip(PREAMBLE_TLVS) {
        assert_eq!(row["name"].as_str(), Some(*name));
        assert_eq!(hex_u64(&row["type"]), *ty, "{name}");
        let want = match status {
            TlvStatus::Active => "active",
            TlvStatus::Reserved => "reserved",
        };
        assert_eq!(row["status"].as_str(), Some(want), "{name}: status");
        assert!(!payload::is_grease_tlv_type(*ty));
    }
    // EXTENSIONS.md Section 4.3: the application range, GREASE excluded.
    let range = &reg["preamble_tlv_application_range"];
    assert_eq!(
        range["first"],
        format!("{:#x}", payload::tlv::APPLICATION_FIRST)
    );
    assert_eq!(
        range["last"],
        format!("{:#x}", payload::tlv::APPLICATION_LAST)
    );
    for ty in [0x0fff, 0x4000] {
        assert!(!payload::is_application_tlv_type(ty));
    }
    for ty in [
        payload::tlv::APPLICATION_FIRST,
        payload::tlv::APPLICATION_LAST,
    ] {
        assert!(payload::is_application_tlv_type(ty));
    }
    let grease_in_range = (payload::tlv::APPLICATION_FIRST..=payload::tlv::APPLICATION_LAST)
        .filter(|&t| payload::is_grease_tlv_type(t))
        .inspect(|&t| assert!(!payload::is_application_tlv_type(t)))
        .count();
    assert!(grease_in_range > 0);
    assert_eq!(reg["grease"]["transport_parameter"], "31*N+27");
    assert_eq!(reg["grease"]["preamble_tlv"], "0x1f*N+0x21");
    for n in [0u64, 1, 2, 1000, 1 << 40] {
        let id = params::grease_id(n).unwrap();
        assert_eq!(id, 31 * n + 27);
        assert!(params::is_grease_id(id));
        let ty = payload::grease_tlv_type(n).unwrap();
        assert_eq!(ty, 0x1f * n + 0x21);
        assert!(payload::is_grease_tlv_type(ty));
    }
}

#[test]
fn fixed_values_labels_and_limits_match() {
    let reg = read_json("registry.json");
    let fixed = &reg["fixed_values"];
    for (bits, dir) in [
        (0, JoinDirection::Up),
        (1, JoinDirection::Down),
        (2, JoinDirection::Bidi),
    ] {
        assert_eq!(dir.to_bits(), bits);
        let name = fixed["pipe_join_direction"][bits.to_string()]
            .as_str()
            .unwrap();
        assert_eq!(name, format!("{dir:?}").to_lowercase());
    }
    assert_eq!(fixed["pipe_join_carrier_bound"], "0x04");
    assert_eq!(fixed["pipe_join_standby"], "0x08");
    assert_eq!(fixed["pipe_join_reserved_mask"], "0xf0");
    assert_eq!(fixed["pipe_status"]["0"], "available");
    assert_eq!(fixed["pipe_status"]["1"], "standby");
    assert_eq!(fixed["zmux_role"]["0"], "initiator");
    assert_eq!(fixed["zmux_role"]["1"], "responder");
    assert_eq!(fixed["zmux_role"]["2"], "auto");
    let flags = &fixed["multipath_secret_flags"];
    use keys::secret_flags::*;
    for (bit, letter) in [(EXPORTER, "E"), (PSK, "P"), (INSECURE, "I")] {
        let label = flags[format!("0x{bit:02x}")].as_str().unwrap();
        assert!(label.starts_with(letter), "secret flag {bit:#x}: {label}");
    }
    assert_eq!(flags.as_object().unwrap().len(), 3);
    assert_eq!(RESERVED, 0xf2);

    let labels = &reg["labels"];
    assert_eq!(labels["tls_exporter_session"], keys::EXPORTER_SESSION_LABEL);
    assert_eq!(labels["tls_exporter_pipe"], keys::EXPORTER_PIPE_LABEL);
    let bytes_label = |k: &str| labels[k].as_str().unwrap().as_bytes().to_vec();
    assert_eq!(bytes_label("hkdf_salt_prefix"), keys::SALT_PREFIX);
    assert_eq!(
        bytes_label("hkdf_join_initiator"),
        keys::JOIN_INITIATOR_LABEL
    );
    assert_eq!(
        bytes_label("hkdf_join_responder"),
        keys::JOIN_RESPONDER_LABEL
    );
    assert_eq!(labels["http_join_header"], oob::JOIN_HEADER);
    assert_eq!(labels["http_pair_header"], oob::PAIR_HEADER);

    // The limits that belong to the wire layer; the others are session
    // timers and budgets.
    let limits = &reg["limits"];
    let wire_limits = [
        ("max_join_frame_bytes", MAX_JOIN_FRAME_LEN as u64),
        ("max_locator_bytes", MAX_LOCATOR_LEN as u64),
        ("join_token_bytes", JOIN_TOKEN_LEN as u64),
        ("lane_key_bytes", LANE_KEY_LEN as u64),
        ("default_max_record_size", params::DEFAULT_MAX_RECORD_SIZE),
        ("zmux_max_record_size", params::ZMUX_MAX_RECORD_SIZE),
        ("max_preamble_tp_overhead", params::MAX_PREAMBLE_TP_OVERHEAD),
        ("pairing_token_bytes", oob::PAIRING_TOKEN_LEN as u64),
    ];
    for (name, value) in wire_limits {
        assert_eq!(limits[name].as_u64(), Some(value), "limit {name}");
    }

    let protocol = &reg["protocol"];
    assert_eq!(
        protocol["alpn_default"].as_str().map(str::as_bytes),
        Some(ident::DEFAULT_ALPN)
    );
    for alias in protocol["alpn_also_accepted"].as_array().unwrap() {
        assert!(ident::alpn_matches(
            ident::DEFAULT_ALPN,
            alias.as_str().unwrap().as_bytes()
        ));
    }
    // SPEC.md Section 6.2: the alias rule, byte-exact.
    let examples = protocol["alpn_alias_examples"].as_array().unwrap();
    assert!(!examples.is_empty());
    for ex in examples {
        let configured = ex["configured"].as_str().unwrap().as_bytes();
        let alias = ex["alias"].as_str().map(str::as_bytes);
        assert_eq!(ident::alpn_alias(configured).as_deref(), alias, "{ex}");
        if let Some(a) = alias {
            assert!(ident::alpn_matches(configured, a), "{ex}");
        }
        assert!(ident::alpn_matches(configured, configured));
        for no in ex["not_accepted"].as_array().unwrap() {
            assert!(
                !ident::alpn_matches(configured, no.as_str().unwrap().as_bytes()),
                "{ex}: {no}"
            );
        }
    }
}

/// REGISTRY.md Section 2.2: zmux values are
/// 2^14 + SHA-256("zmux <kind> <name>[#i]")[0..8] mod (2^30 - 2^14).
#[test]
fn zmux_codepoints_follow_the_allocation_method() {
    let reg = read_json("registry.json");
    let suffixes = reg["allocation"]["suffix"].as_object().unwrap();
    let alloc = |kind: &str, name: &str| {
        let suffix = suffixes
            .get(&format!("{kind}:{name}"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let mut s = format!("zmux {kind} {name}");
        if suffix != 0 {
            s.push_str(&format!("#{suffix}"));
        }
        let digest = Sha256::digest(s.as_bytes());
        let h = u64::from_be_bytes(digest[..8].try_into().unwrap());
        (1 << 14) + h % ((1 << 30) - (1 << 14))
    };
    let mut checked = 0;
    for f in reg["frame_types"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["kind"] == "zmux")
    {
        let name = f["name"].as_str().unwrap();
        let first = hex_u64(&f["first"]);
        assert_eq!(alloc("frame", name), first, "frame {name}");
        assert_eq!(FrameType(first).name(), Some(name), "frame {name}");
        checked += 1;
    }
    for p in reg["transport_parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["scope"] == "zmux" || p["scope"] == "zmux-reserved")
    {
        let name = p["name"].as_str().unwrap();
        assert_eq!(
            alloc("transport_parameter", name),
            hex_u64(&p["id"]),
            "parameter {name}"
        );
        checked += 1;
    }
    for (code, name, _) in TRANSPORT_ERRORS.iter().filter(|e| e.0.0 >= 1 << 14) {
        assert_eq!(alloc("transport_error", name), code.0, "error {name}");
        checked += 1;
    }
    assert!(checked >= 25);
}
