//! Framing for the dedicated HTTP/3 connection used by WebTransport.

use std::collections::{BTreeMap, BTreeSet};
use std::io;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use qpack::HeaderField;
use quinn::RecvStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use url::{Position, Url};
use zmux::proto::varint;

pub(super) const CONTROL: u64 = 0x00;
pub(super) const QPACK_ENCODER: u64 = 0x02;
pub(super) const QPACK_DECODER: u64 = 0x03;
pub(super) const DATA: u64 = 0x00;
pub(super) const HEADERS: u64 = 0x01;
pub(super) const SETTINGS: u64 = 0x04;
pub(super) const GOAWAY: u64 = 0x07;
pub(super) const WT_BIDI: u64 = 0x41;
pub(super) const WT_UNI: u64 = 0x54;
const EXTENDED_CONNECT: u64 = 0x08;
const H3_DATAGRAM: u64 = 0x33;
const LEGACY_WT_ENABLE: u64 = 0x2b60_3742;
const EARLY_WT_MAX_SESSIONS: u64 = 0x2b60_3743;
const CHROMIUM_WT_MAX_SESSIONS: u64 = 0x14e9_cd29;
const LEGACY_WT_MAX_SESSIONS: u64 = 0xc671_706a;
const WT_ENABLED: u64 = 0x2c7c_f000;
const MAX_FIELD_SECTION_SIZE: u64 = 0x06;
const FIELD_LIMIT: usize = 1 << 16;
const PROTOCOL: &[u8] = b"webtransport-h3";

pub(super) fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) fn put(buf: &mut Vec<u8>, value: u64) {
    let mut encoded = [0; 8];
    let len = varint::encode(value, &mut encoded).expect("QUIC varint");
    buf.extend_from_slice(&encoded[..len]);
}

pub(super) async fn read(recv: &mut RecvStream) -> io::Result<Option<u64>> {
    let mut encoded = [0; 8];
    if AsyncReadExt::read(recv, &mut encoded[..1]).await? == 0 {
        return Ok(None);
    }
    let len = 1 << (encoded[0] >> 6);
    AsyncReadExt::read_exact(recv, &mut encoded[1..len]).await?;
    Ok(varint::decode(&encoded).map(|(value, _)| value))
}

pub(super) fn required(value: Option<u64>) -> io::Result<u64> {
    value.ok_or_else(|| io::ErrorKind::UnexpectedEof.into())
}

pub(super) async fn skip(recv: &mut RecvStream, len: u64) -> io::Result<()> {
    if tokio::io::copy(&mut recv.take(len), &mut tokio::io::sink()).await? != len {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    Ok(())
}

pub(super) async fn frame(recv: &mut RecvStream) -> io::Result<Option<(u64, u64)>> {
    let Some(ty) = read(recv).await? else {
        return Ok(None);
    };
    Ok(Some((ty, required(read(recv).await?)?)))
}

pub(super) async fn write_frame(
    send: &mut quinn::SendStream,
    ty: u64,
    payload: impl AsRef<[u8]>,
) -> io::Result<()> {
    let payload = payload.as_ref();
    let mut head = Vec::with_capacity(16);
    put(&mut head, ty);
    put(&mut head, payload.len() as u64);
    AsyncWriteExt::write_all(send, &head).await?;
    AsyncWriteExt::write_all(send, payload).await
}

async fn bounded(recv: &mut RecvStream, len: u64) -> io::Result<Vec<u8>> {
    let len = usize::try_from(len)
        .ok()
        .filter(|&len| len <= FIELD_LIMIT)
        .ok_or_else(|| invalid("HTTP/3 field or SETTINGS section exceeds its limit"))?;
    let mut buf = vec![0; len];
    AsyncReadExt::read_exact(recv, &mut buf).await?;
    Ok(buf)
}

pub(super) async fn send_settings(
    conn: &quinn::Connection,
    server: bool,
) -> io::Result<quinn::SendStream> {
    let mut send = conn.open_uni().await.map_err(io::Error::other)?;
    AsyncWriteExt::write_all(&mut send, &[0]).await?;
    write_frame(&mut send, SETTINGS, settings(server)).await?;
    Ok(send)
}

pub(super) fn settings(server: bool) -> Vec<u8> {
    let mut body = Vec::new();
    // Advertise one session under both the current and historical WT settings.
    for (id, value) in [
        (WT_ENABLED, 1),
        (LEGACY_WT_ENABLE, 1),
        (EARLY_WT_MAX_SESSIONS, 1),
        (CHROMIUM_WT_MAX_SESSIONS, 1),
        (LEGACY_WT_MAX_SESSIONS, 1),
        (H3_DATAGRAM, 1),
        (MAX_FIELD_SECTION_SIZE, FIELD_LIMIT as u64),
    ] {
        put(&mut body, id);
        put(&mut body, value);
    }
    if server {
        put(&mut body, EXTENDED_CONNECT);
        put(&mut body, 1);
    }
    body
}

pub(super) async fn receive_settings(recv: &mut RecvStream, peer_server: bool) -> io::Result<bool> {
    let Some((SETTINGS, len)) = frame(recv).await? else {
        return Err(invalid("missing HTTP/3 SETTINGS"));
    };
    let body = bounded(recv, len).await?;
    check_settings(&body, peer_server)
}

fn check_settings(mut body: &[u8], peer_server: bool) -> io::Result<bool> {
    let mut seen = BTreeSet::new();
    let (mut wt, mut legacy_wt, mut datagrams, mut connect) = (false, false, false, false);
    while !body.is_empty() {
        let (id, used) = varint::decode(body).ok_or_else(|| invalid("truncated setting ID"))?;
        let (value, size) =
            varint::decode(&body[used..]).ok_or_else(|| invalid("truncated setting value"))?;
        body = &body[used + size..];
        if !seen.insert(id) || matches!(id, 0x02..=0x05) {
            return Err(invalid("invalid or duplicate HTTP/3 setting"));
        }
        match (id, value) {
            (WT_ENABLED, 0..=1) => wt = value == 1,
            (
                LEGACY_WT_ENABLE
                | EARLY_WT_MAX_SESSIONS
                | CHROMIUM_WT_MAX_SESSIONS
                | LEGACY_WT_MAX_SESSIONS,
                _,
            ) => {
                legacy_wt |= value > 0;
            }
            (H3_DATAGRAM, 0..=1) => datagrams = value == 1,
            (EXTENDED_CONNECT, 0..=1) => connect = value == 1,
            (WT_ENABLED | H3_DATAGRAM | EXTENDED_CONNECT, _) => {
                return Err(invalid("invalid HTTP/3 setting value"));
            }
            (0x2b64 | 0x2b65, value) if value > (1 << 60) => {
                return Err(invalid("invalid WebTransport stream credit"));
            }
            _ => {}
        }
    }
    let supported = wt || legacy_wt;
    if datagrams && (!peer_server || supported && connect) {
        Ok(supported)
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer did not enable HTTP/3 WebTransport",
        ))
    }
}

type Pseudo = BTreeMap<Vec<u8>, Vec<u8>>;

async fn fields(recv: &mut RecvStream, mut ty: u64) -> io::Result<(Pseudo, HeaderMap)> {
    let encoded = loop {
        let len = required(read(recv).await?)?;
        match ty {
            HEADERS => break bounded(recv, len).await?,
            DATA | SETTINGS | GOAWAY | WT_BIDI | 0x03 | 0x05 | 0x0d => {
                return Err(invalid("unexpected HTTP/3 frame before HEADERS"));
            }
            _ => skip(recv, len).await?,
        }
        ty = required(read(recv).await?)?;
    };
    let decoded = qpack::decode_stateless(&mut encoded.as_slice(), FIELD_LIMIT as u64)
        .map_err(io::Error::other)?;
    let mut pseudo = Pseudo::new();
    let mut headers = HeaderMap::new();
    for field in decoded.fields {
        let (name, value) = field.into_inner();
        if name.starts_with(b":") {
            if !headers.is_empty()
                || pseudo
                    .insert(name.into_owned(), value.into_owned())
                    .is_some()
            {
                return Err(invalid("duplicate or misplaced HTTP/3 pseudo-header"));
            }
        } else {
            let name = HeaderName::from_lowercase(&name).map_err(invalid)?;
            let value = HeaderValue::from_bytes(&value).map_err(invalid)?;
            validate_header(&name)?;
            headers.append(name, value);
        }
    }
    Ok((pseudo, headers))
}

fn validate_header(name: &HeaderName) -> io::Result<()> {
    if matches!(
        name.as_str(),
        "connection" | "keep-alive" | "proxy-connection" | "transfer-encoding" | "upgrade"
    ) {
        return Err(invalid("connection-specific header in HTTP/3"));
    }
    Ok(())
}

async fn write_fields(
    send: &mut quinn::SendStream,
    mut fields: Vec<HeaderField>,
    headers: &HeaderMap,
) -> io::Result<()> {
    for (name, value) in headers {
        validate_header(name)?;
        fields.push(HeaderField::new(name.as_str().as_bytes(), value.as_bytes()));
    }
    let mut buf = Vec::new();
    let size = qpack::encode_stateless(&mut buf, fields).map_err(io::Error::other)?;
    if size > FIELD_LIMIT as u64 || buf.len() > FIELD_LIMIT {
        return Err(invalid("HTTP/3 header section exceeds its limit"));
    }
    write_frame(send, HEADERS, buf).await
}

pub(super) async fn write_request(
    send: &mut quinn::SendStream,
    url: &Url,
    headers: &HeaderMap,
) -> io::Result<()> {
    if url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid WebTransport URL",
        ));
    }
    let authority = &url[Position::BeforeHost..Position::AfterPort];
    let path = &url[Position::BeforePath..Position::AfterQuery];
    write_fields(
        send,
        vec![
            HeaderField::new(&b":method"[..], &b"CONNECT"[..]),
            HeaderField::new(&b":scheme"[..], &b"https"[..]),
            HeaderField::new(&b":authority"[..], authority.as_bytes()),
            HeaderField::new(&b":path"[..], path.as_bytes()),
            HeaderField::new(&b":protocol"[..], PROTOCOL),
        ],
        headers,
    )
    .await
}

pub(super) async fn read_request(
    recv: &mut RecvStream,
    ty: u64,
) -> io::Result<(Url, HeaderMap, bool)> {
    let (mut pseudo, headers) = fields(recv, ty).await?;
    if pseudo.remove(b":method".as_slice()).as_deref() != Some(b"CONNECT")
        || pseudo.remove(b":scheme".as_slice()).as_deref() != Some(b"https")
    {
        return Err(invalid("expected an HTTPS Extended CONNECT"));
    }
    let protocol = pseudo
        .remove(b":protocol".as_slice())
        .ok_or_else(|| invalid("missing :protocol"))?;
    if !matches!(protocol.as_slice(), PROTOCOL | b"webtransport") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported Extended CONNECT protocol",
        ));
    }
    let authority = pseudo
        .remove(b":authority".as_slice())
        .ok_or_else(|| invalid("missing :authority"))?;
    let path = pseudo
        .remove(b":path".as_slice())
        .ok_or_else(|| invalid("missing :path"))?;
    let authority = str::from_utf8(&authority).map_err(invalid)?;
    let path = str::from_utf8(&path).map_err(invalid)?;
    let parsed = authority.parse::<http::uri::Authority>().map_err(invalid)?;
    if !pseudo.is_empty()
        || !path.starts_with('/')
        || authority.contains('@')
        || path.contains('#')
        || headers
            .get_all(http::header::HOST)
            .iter()
            .any(|host| host.as_bytes() != parsed.as_str().as_bytes())
    {
        return Err(invalid("malformed CONNECT authority or path"));
    }
    let url = Url::parse(&format!("https://{parsed}{path}")).map_err(invalid)?;
    Ok((url, headers, protocol == b"webtransport"))
}

pub(super) async fn write_response(
    send: &mut quinn::SendStream,
    status: StatusCode,
) -> io::Result<()> {
    write_fields(
        send,
        vec![HeaderField::new(
            &b":status"[..],
            status.as_str().as_bytes(),
        )],
        &HeaderMap::new(),
    )
    .await
}

pub(super) async fn read_response(recv: &mut RecvStream) -> io::Result<StatusCode> {
    loop {
        let ty = required(read(recv).await?)?;
        let (mut pseudo, _) = fields(recv, ty).await?;
        let status = pseudo
            .remove(b":status".as_slice())
            .ok_or_else(|| invalid("missing :status"))?;
        let status = StatusCode::from_bytes(&status).map_err(invalid)?;
        if !pseudo.is_empty() {
            return Err(invalid("unexpected response pseudo-header"));
        }
        if !status.is_informational() {
            return Ok(status);
        }
    }
}

pub(super) fn id(send: &quinn::SendStream) -> u64 {
    quinn::VarInt::from(send.id()).into_inner()
}

pub(super) fn prefix(ty: u64, id: u64) -> Bytes {
    let mut buf = Vec::with_capacity(16);
    put(&mut buf, ty);
    put(&mut buf, id);
    buf.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(values: &[(u64, u64)]) -> Vec<u8> {
        let mut body = Vec::new();
        for &(id, value) in values {
            put(&mut body, id);
            put(&mut body, value);
        }
        body
    }

    #[test]
    fn sends_and_accepts_draft16_and_legacy_settings() {
        let advertised = [
            (0x2c7c_f000, 1),
            (0x2b60_3742, 1),
            (0x2b60_3743, 1),
            (0x14e9_cd29, 1),
            (0xc671_706a, 1),
            (0x33, 1),
            (0x06, 65536),
        ];
        let client = pairs(&advertised);
        let mut server = client.clone();
        server.extend(pairs(&[(0x08, 1)]));
        assert_eq!(settings(false), client);
        assert_eq!(settings(true), server);
        check_settings(&client, false).unwrap();
        check_settings(&server, true).unwrap();
        check_settings(&pairs(&[(0x2c7c_f000, 1), (0x33, 1), (0x08, 1)]), true).unwrap();
        assert!(!check_settings(&pairs(&[(0x33, 1)]), false).unwrap());
        for key in [0x2b60_3742, 0x2b60_3743, 0x14e9_cd29, 0xc671_706a] {
            let mut legacy = pairs(&[(key, 3), (0x33, 1), (0x21, 123)]);
            assert!(check_settings(&legacy, false).unwrap());
            assert_eq!(
                check_settings(&legacy, true).unwrap_err().kind(),
                io::ErrorKind::Unsupported
            );
            legacy.extend(pairs(&[(0x08, 1)]));
            assert!(check_settings(&legacy, true).unwrap());
        }
        for malformed in [
            pairs(&[(0x2c7c_f000, 1), (0x33, 1), (0x33, 1)]),
            pairs(&[(0x2c7c_f000, 2), (0x33, 1)]),
            vec![0x33],
        ] {
            assert_eq!(
                check_settings(&malformed, false).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        assert_eq!(
            check_settings(&pairs(&[(0x2c7c_f000, 1)]), true)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }
}
