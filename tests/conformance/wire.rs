//! Conversions between the JSON frame objects of the assets and the proto
//! codec: encoding [`FrameSpec`]s with the proto encoders, and rendering
//! decoded frames back to JSON for comparison.

use serde_json::{Value, json};
use zmux::proto::frame::{
    ConnectionClose, DataBlocked, Datagram, Dir, Frame, FrameType, GoAwayFrame, JoinDirection,
    MaxData, MaxStreamData, MaxStreams, Padding, PipeAbandon, PipeJoin, PipeLane, PipeStatus,
    PipeStatusValue, Priority, PriorityUpdate, QxPing, QxTransportParameters, ResetStream,
    ResetStreamAt, StopSending, Stream, StreamDataBlocked, StreamsBlocked,
};
use zmux::proto::params::{
    Locator, MultipathParameter, RawParameters, RoleParameter, TransportParameters,
};
use zmux::proto::{Gates, record, varint};

use crate::model::{
    FrameSpec, Int, JoinDirectionName, ParamId, ParamSpec, ParamValue, PipeStatusName, RoleName,
};
use crate::support::to_hex;

/// Appends `frame` to `out`, checking that `encoded_len` is exact.
pub fn push(out: &mut Vec<u8>, frame: &Frame<'_>) {
    let n = frame.encoded_len();
    let start = out.len();
    out.resize(start + n, 0);
    let written = frame
        .encode(&mut out[start..])
        .unwrap_or_else(|e| panic!("encode {frame:?}: {e}"));
    assert_eq!(written, n, "encoded_len of {frame:?}");
}

/// A registry row: name, ID, value format, scope.
type ParamRow = (String, u64, Option<String>, String);

/// The registry's transport parameters.
fn registry_params() -> &'static [ParamRow] {
    static PARAMS: std::sync::OnceLock<Vec<ParamRow>> = std::sync::OnceLock::new();
    PARAMS.get_or_init(|| {
        let reg = crate::support::read_json("registry.json");
        reg["transport_parameters"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| {
                let hex = p["id"]["hex"].as_str().unwrap().trim_start_matches("0x");
                (
                    p["name"].as_str().unwrap().to_string(),
                    u64::from_str_radix(hex, 16).unwrap(),
                    p["format"].as_str().map(String::from),
                    p["scope"].as_str().unwrap_or_default().to_string(),
                )
            })
            .collect()
    })
}

fn param_id(id: &ParamId) -> u64 {
    match id {
        ParamId::Number(n) => *n,
        ParamId::Name(name) => {
            registry_params()
                .iter()
                .find(|p| p.0 == *name)
                .unwrap_or_else(|| panic!("unknown parameter {name}"))
                .1
        }
    }
}

/// Encodes a parameter value in its registry format.
pub fn param_value(id: u64, value: Option<&ParamValue>) -> Vec<u8> {
    let format = registry_params()
        .iter()
        .find(|p| p.1 == id)
        .and_then(|p| p.2.as_deref());
    let mut buf = [0u8; 64];
    let n = match (format, value) {
        (Some("empty"), None) => 0,
        (Some("varint"), Some(ParamValue::Int(v))) => varint::encode(*v, &mut buf).unwrap(),
        (Some("role"), Some(ParamValue::Role(r))) => {
            let role = match (r.role, r.nonce) {
                (RoleName::Initiator, None) => RoleParameter::Initiator,
                (RoleName::Responder, None) => RoleParameter::Responder,
                (RoleName::Auto, Some(nonce)) => RoleParameter::Auto { nonce },
                other => panic!("bad zmux_role {other:?}"),
            };
            role.encode(&mut buf).unwrap()
        }
        (Some("multipath"), Some(ParamValue::Multipath(m))) => MultipathParameter {
            secret_flags: m.flags,
            session_nonce: m.nonce.0.as_slice().try_into().expect("16-byte nonce"),
            locator: Locator::new(&m.locator.0).expect("locator"),
        }
        .encode(&mut buf)
        .unwrap(),
        // By hand: the traces also send the invalid Max Lanes 0.
        (Some("lanes"), Some(ParamValue::Lanes(l))) => {
            let n = varint::encode(l.max_lanes, &mut buf).unwrap();
            buf[n..n + l.lane_key.0.len()].copy_from_slice(&l.lane_key.0);
            n + l.lane_key.0.len()
        }
        other => panic!("parameter {id:#x}: unsupported value {other:?}"),
    };
    buf[..n].to_vec()
}

/// Encodes a transport-parameter block in list order.
pub fn param_block(list: &[ParamSpec]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in list {
        let id = param_id(&p.id);
        let value = match &p.raw {
            Some(raw) => raw.0.clone(),
            None => param_value(id, p.value.as_ref()),
        };
        let mut buf = [0u8; 16];
        let n = varint::encode(id, &mut buf).unwrap();
        out.extend_from_slice(&buf[..n]);
        let n = varint::encode(value.len() as u64, &mut buf).unwrap();
        out.extend_from_slice(&buf[..n]);
        out.extend_from_slice(&value);
    }
    out
}

/// Resolves a `$sent` placeholder: the bytes written on a lane of a pipe.
pub type Sent<'a> = &'a dyn Fn(u64, u64) -> u64;

/// Encodes one frame object; `sent` resolves `$sent` placeholders.
pub fn encode_frame(spec: &FrameSpec, out: &mut Vec<u8>, sent: Sent<'_>) {
    let dir = |bidi: bool| if bidi { Dir::Bidi } else { Dir::Uni };
    match spec {
        FrameSpec::Raw { bytes } => out.extend_from_slice(&bytes.0),
        FrameSpec::Repeat { count, frame } => {
            for _ in 0..*count {
                encode_frame(frame, out, sent);
            }
        }
        FrameSpec::Padding { count } => push(out, &Frame::Padding(Padding { len: *count })),
        FrameSpec::Stream {
            id,
            off,
            data,
            fin,
            has_off,
            has_len,
        } => push(
            out,
            &Frame::Stream(Stream {
                stream_id: *id,
                offset: *off,
                data: &data.0,
                fin: *fin,
                explicit_offset: has_off.unwrap_or(*off > 0),
                explicit_len: has_len.unwrap_or(true),
            }),
        ),
        FrameSpec::ResetStream {
            id,
            code,
            final_size,
        } => push(
            out,
            &Frame::ResetStream(ResetStream {
                stream_id: *id,
                error_code: *code,
                final_size: *final_size,
            }),
        ),
        FrameSpec::ResetStreamAt {
            id,
            code,
            final_size,
            reliable_size,
        } => push(
            out,
            &Frame::ResetStreamAt(ResetStreamAt {
                stream_id: *id,
                error_code: *code,
                final_size: *final_size,
                reliable_size: *reliable_size,
            }),
        ),
        FrameSpec::StopSending { id, code } => push(
            out,
            &Frame::StopSending(StopSending {
                stream_id: *id,
                error_code: *code,
            }),
        ),
        FrameSpec::MaxData { max } => push(out, &Frame::MaxData(MaxData { maximum: *max })),
        FrameSpec::MaxStreamData { id, max } => push(
            out,
            &Frame::MaxStreamData(MaxStreamData {
                stream_id: *id,
                maximum: *max,
            }),
        ),
        FrameSpec::MaxStreams { bidi, max } => push(
            out,
            &Frame::MaxStreams(MaxStreams {
                dir: dir(*bidi),
                maximum: *max,
            }),
        ),
        FrameSpec::DataBlocked { limit } => {
            push(out, &Frame::DataBlocked(DataBlocked { limit: *limit }))
        }
        FrameSpec::StreamDataBlocked { id, limit } => push(
            out,
            &Frame::StreamDataBlocked(StreamDataBlocked {
                stream_id: *id,
                limit: *limit,
            }),
        ),
        FrameSpec::StreamsBlocked { bidi, limit } => push(
            out,
            &Frame::StreamsBlocked(StreamsBlocked {
                dir: dir(*bidi),
                limit: *limit,
            }),
        ),
        FrameSpec::ConnectionClose {
            app,
            code,
            frame_type,
            reason,
        } => push(
            out,
            &Frame::ConnectionClose(ConnectionClose {
                application: *app,
                error_code: *code,
                frame_type: frame_type.unwrap_or(0),
                reason: &reason.0,
            }),
        ),
        FrameSpec::Datagram { data, has_len } => push(
            out,
            &Frame::Datagram(Datagram {
                data: &data.0,
                explicit_len: *has_len,
            }),
        ),
        FrameSpec::QxTransportParameters { params } => {
            let block = param_block(params);
            push(
                out,
                &Frame::TransportParameters(QxTransportParameters { block: &block }),
            );
        }
        FrameSpec::QxPing { response, seq } => push(
            out,
            &Frame::QxPing(QxPing {
                response: *response,
                sequence: *seq,
            }),
        ),
        FrameSpec::Goaway {
            max_bidi,
            max_uni,
            code,
        } => push(
            out,
            &Frame::GoAway(GoAwayFrame {
                max_bidi: *max_bidi,
                max_uni: *max_uni,
                error_code: *code,
            }),
        ),
        FrameSpec::PriorityUpdate {
            id,
            seq,
            urgency,
            incremental,
        } => push(
            out,
            &Frame::PriorityUpdate(PriorityUpdate {
                stream_id: *id,
                sequence: *seq,
                priority: Priority::new(*urgency, *incremental).expect("urgency"),
            }),
        ),
        FrameSpec::PipeJoin {
            locator,
            pipe,
            direction,
            carrier_bound,
            standby,
            fate_group,
            priority,
            token,
        } => push(
            out,
            &Frame::PipeJoin(PipeJoin {
                locator: &locator.0,
                pipe_id: *pipe,
                direction: match direction {
                    JoinDirectionName::Up => JoinDirection::Up,
                    JoinDirectionName::Down => JoinDirection::Down,
                    JoinDirectionName::Bidi => JoinDirection::Bidi,
                },
                carrier_bound: *carrier_bound,
                fate_group: *fate_group,
                standby: *standby,
                priority: *priority,
                token: token.0.as_slice().try_into().expect("16-byte token"),
            }),
        ),
        FrameSpec::PipeAck { entries } => {
            // Written by hand so that invalid entry orders can be encoded;
            // a `$sent` value is written as a 4-byte varint, so that the
            // record's length does not depend on it (TRACES.md Section
            // 6.1).
            let mut put = |v: u64, width: usize| {
                let start = out.len();
                out.resize(start + width, 0);
                varint::encode_with_width(v, width, &mut out[start..]).expect("varint");
            };
            put(FrameType::PIPE_ACK.0, varint::len(FrameType::PIPE_ACK.0));
            put(entries.len() as u64, varint::len(entries.len() as u64));
            for e in entries {
                put(e.pipe, varint::len(e.pipe));
                put(e.lane, varint::len(e.lane));
                match e.position {
                    Int::Value(v) => put(v, varint::len(v)),
                    Int::Sent(s) => put(sent(s.pipe, s.lane) + s.plus, 4),
                }
                put(e.delay, varint::len(e.delay));
            }
        }
        FrameSpec::PipeLane {
            lane_key,
            pipe,
            lane,
        } => push(
            out,
            &Frame::PipeLane(PipeLane {
                lane_key: lane_key.0.as_slice().try_into().expect("16-byte key"),
                pipe_id: *pipe,
                lane: *lane,
            }),
        ),
        FrameSpec::PipePing => push(out, &Frame::PipePing),
        FrameSpec::PipeAbandon { pipe, code } => push(
            out,
            &Frame::PipeAbandon(PipeAbandon {
                pipe_id: *pipe,
                error_code: *code,
            }),
        ),
        FrameSpec::PipeStatus {
            pipe,
            seq,
            status,
            priority,
        } => push(
            out,
            &Frame::PipeStatus(PipeStatus {
                pipe_id: *pipe,
                sequence: *seq,
                status: match status {
                    PipeStatusName::Available => PipeStatusValue::Available,
                    PipeStatusName::Standby => PipeStatusValue::Standby,
                },
                priority: *priority,
            }),
        ),
    }
}

/// Placeholder resolution for frames without placeholders.
pub fn no_placeholders(pipe: u64, lane: u64) -> u64 {
    panic!("unexpected $sent placeholder for pipe {pipe} lane {lane}")
}

/// Encodes a list of frames (a message, or a record body).
pub fn encode_frames(specs: &[FrameSpec], sent: Sent<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    for s in specs {
        encode_frame(s, &mut out, sent);
    }
    out
}

/// Encodes a record: the shortest Size, then the frames.
pub fn encode_record(specs: &[FrameSpec], sent: Sent<'_>) -> Vec<u8> {
    let body = encode_frames(specs, sent);
    let mut out = vec![0u8; record::size_len(body.len() as u64)];
    record::encode_size(body.len() as u64, &mut out).unwrap();
    out.extend_from_slice(&body);
    out
}

fn param_json(id: u64, value: &[u8], tp: &TransportParameters) -> Value {
    let Some(row) = registry_params().iter().find(|p| p.1 == id) else {
        return json!({"id": id, "raw": to_hex(value)});
    };
    if row.3 == "prohibited" || row.3 == "zmux-reserved" {
        return json!({"id": id, "raw": to_hex(value)});
    }
    let v = match row.2.as_deref() {
        Some("varint") => json!(varint::decode(value).expect("validated").0),
        Some("empty") => Value::Null,
        Some("role") => match tp.zmux_role.expect("validated") {
            RoleParameter::Initiator => json!({"role": "initiator"}),
            RoleParameter::Responder => json!({"role": "responder"}),
            RoleParameter::Auto { nonce } => json!({"role": "auto", "nonce": nonce}),
        },
        Some("multipath") => {
            let m = tp.zmux_multipath.expect("validated");
            json!({
                "flags": m.secret_flags,
                "nonce": to_hex(&m.session_nonce),
                "locator": to_hex(m.locator.as_bytes()),
            })
        }
        Some("lanes") => {
            let l = tp.zmux_max_lanes.expect("validated");
            json!({"max_lanes": l.max_lanes.get(), "lane_key": to_hex(&l.lane_key)})
        }
        _ => return json!({"id": id, "raw": to_hex(value)}),
    };
    json!({"id": row.0, "value": v})
}

/// Renders a decoded frame as a frame object of TRACES.md Section 6.
pub fn frame_json(frame: &Frame<'_>) -> Value {
    match frame {
        Frame::Padding(f) => json!({"type": "PADDING", "count": f.len}),
        Frame::Stream(f) => json!({
            "type": "STREAM", "id": f.stream_id, "off": f.offset, "data": to_hex(f.data),
            "fin": f.fin, "has_off": f.explicit_offset || f.offset != 0, "has_len": f.explicit_len,
        }),
        Frame::ResetStream(f) => json!({
            "type": "RESET_STREAM", "id": f.stream_id, "code": f.error_code,
            "final_size": f.final_size,
        }),
        Frame::StopSending(f) => {
            json!({"type": "STOP_SENDING", "id": f.stream_id, "code": f.error_code})
        }
        Frame::MaxData(f) => json!({"type": "MAX_DATA", "max": f.maximum}),
        Frame::MaxStreamData(f) => {
            json!({"type": "MAX_STREAM_DATA", "id": f.stream_id, "max": f.maximum})
        }
        Frame::MaxStreams(f) => {
            json!({"type": "MAX_STREAMS", "bidi": f.dir == Dir::Bidi, "max": f.maximum})
        }
        Frame::DataBlocked(f) => json!({"type": "DATA_BLOCKED", "limit": f.limit}),
        Frame::StreamDataBlocked(f) => {
            json!({"type": "STREAM_DATA_BLOCKED", "id": f.stream_id, "limit": f.limit})
        }
        Frame::StreamsBlocked(f) => {
            json!({"type": "STREAMS_BLOCKED", "bidi": f.dir == Dir::Bidi, "limit": f.limit})
        }
        Frame::ConnectionClose(f) if f.application => json!({
            "type": "CONNECTION_CLOSE", "app": true, "code": f.error_code,
            "reason": to_hex(f.reason),
        }),
        Frame::ConnectionClose(f) => json!({
            "type": "CONNECTION_CLOSE", "app": false, "code": f.error_code,
            "frame_type": f.frame_type, "reason": to_hex(f.reason),
        }),
        Frame::ResetStreamAt(f) => json!({
            "type": "RESET_STREAM_AT", "id": f.stream_id, "code": f.error_code,
            "final_size": f.final_size, "reliable_size": f.reliable_size,
        }),
        Frame::Datagram(f) => {
            json!({"type": "DATAGRAM", "data": to_hex(f.data), "has_len": f.explicit_len})
        }
        Frame::TransportParameters(f) => {
            let tp = f.parameters().expect("validated by decode");
            let list: Vec<Value> = RawParameters::new(f.block)
                .map(|p| {
                    let (id, value) = p.expect("validated by decode");
                    param_json(id, value, &tp)
                })
                .collect();
            json!({"type": "QX_TRANSPORT_PARAMETERS", "params": list})
        }
        Frame::QxPing(f) => json!({"type": "QX_PING", "response": f.response, "seq": f.sequence}),
        Frame::GoAway(f) => json!({
            "type": "GOAWAY", "max_bidi": f.max_bidi, "max_uni": f.max_uni, "code": f.error_code,
        }),
        Frame::PriorityUpdate(f) => json!({
            "type": "PRIORITY_UPDATE", "id": f.stream_id, "seq": f.sequence,
            "urgency": f.priority.urgency(), "incremental": f.priority.incremental(),
        }),
        Frame::PipeJoin(f) => json!({
            "type": "PIPE_JOIN", "locator": to_hex(f.locator), "pipe": f.pipe_id,
            "direction": match f.direction {
                JoinDirection::Up => "up",
                JoinDirection::Down => "down",
                JoinDirection::Bidi => "bidi",
            },
            "carrier_bound": f.carrier_bound, "standby": f.standby,
            "fate_group": f.fate_group, "priority": f.priority, "token": to_hex(&f.token),
        }),
        Frame::PipeAck(f) => {
            let entries: Vec<Value> = f
                .entries()
                .map(|e| {
                    json!({
                        "pipe": e.pipe_id, "lane": e.lane, "position": e.position,
                        "delay": e.ack_delay,
                    })
                })
                .collect();
            json!({"type": "PIPE_ACK", "entries": entries})
        }
        Frame::PipeLane(f) => json!({
            "type": "PIPE_LANE", "lane_key": to_hex(&f.lane_key), "pipe": f.pipe_id,
            "lane": f.lane,
        }),
        Frame::PipePing => json!({"type": "PIPE_PING"}),
        Frame::PipeAbandon(f) => {
            json!({"type": "PIPE_ABANDON", "pipe": f.pipe_id, "code": f.error_code})
        }
        Frame::PipeStatus(f) => json!({
            "type": "PIPE_STATUS", "pipe": f.pipe_id, "seq": f.sequence,
            "status": match f.status {
                PipeStatusValue::Available => "available",
                PipeStatusValue::Standby => "standby",
            },
            "priority": f.priority,
        }),
        other => panic!("no JSON form for {other:?}"),
    }
}

/// Checks that every field of `expected` appears in `actual` with the same
/// value (objects recursively; arrays element by element).
pub fn json_subset(expected: &Value, actual: &Value, path: &str) -> Result<(), String> {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for (k, ev) in e {
                let av = a.get(k).ok_or_else(|| format!("{path}.{k}: missing"))?;
                json_subset(ev, av, &format!("{path}.{k}"))?;
            }
            Ok(())
        }
        (Value::Array(e), Value::Array(a)) => {
            if e.len() != a.len() {
                return Err(format!("{path}: {} items, expected {}", a.len(), e.len()));
            }
            for (i, (ev, av)) in e.iter().zip(a).enumerate() {
                json_subset(ev, av, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        _ if expected == actual => Ok(()),
        _ => Err(format!("{path}: {actual} != expected {expected}")),
    }
}

/// Normalises an expected frame list for comparison with decoded frames:
/// REPEAT is expanded and adjacent PADDING runs are merged, as the decoder
/// reports a run of PADDING frames as one.
pub fn normalise(frames: &[Value]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut push = |v: Value| {
        if v["type"] == "PADDING"
            && let Some(last) = out.last_mut()
            && last["type"] == "PADDING"
        {
            let n = last["count"].as_u64().unwrap() + v["count"].as_u64().unwrap();
            last["count"] = json!(n);
            return;
        }
        out.push(v);
    };
    for f in frames {
        if f["type"] == "REPEAT" {
            for _ in 0..f["count"].as_u64().unwrap() {
                push(f["frame"].clone());
            }
        } else {
            push(f.clone());
        }
    }
    out
}

/// Decodes a record body into JSON frame objects.
pub fn decode_body(body: &[u8], gates: Gates) -> Result<Vec<Value>, zmux::proto::Error> {
    zmux::proto::Frames::new(body, gates)
        .map(|f| f.map(|f| frame_json(&f)))
        .collect()
}
