//! Retains the provenance of stream bytes decrypted with server 0-RTT keys.

use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bytes::{Buf, BytesMut};
use quinn::crypto::{self, HeaderKey, KeyPair, Keys, PacketKey, Session};
use quinn::{ConnectionId, Side, VarInt};
use quinn_proto::TransportError;
use quinn_proto::coding::Codec;
use quinn_proto::transport_parameters::TransportParameters;

/// Handshake metadata of a server using [`track_server_early_data`](crate::track_server_early_data).
pub struct ServerHandshake {
    /// Metadata supplied by the underlying QUIC crypto provider.
    pub inner: Option<Box<dyn Any>>,
    pub(crate) early: Arc<EarlyStreams>,
}

#[derive(Debug, Default)]
pub(crate) struct EarlyStreams(Mutex<Provenance>);

#[derive(Debug, Default)]
struct Provenance {
    offsets: HashMap<u64, u64>,
    unknown: bool,
}

impl EarlyStreams {
    pub(crate) fn contains(&self, stream: Option<u64>, before: u64) -> bool {
        let early = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        early.unknown
            || match stream {
                Some(id) => early
                    .offsets
                    .get(&id)
                    .is_some_and(|&offset| offset < before),
                None => !early.offsets.is_empty(),
            }
    }

    fn observe(&self, payload: &[u8]) {
        let mut early = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !early.unknown && scan_streams(payload, &mut early.offsets).is_none() {
            early.unknown = true;
        }
    }
}

// Quinn exposes its packet crypto but not the provenance of bytes in a
// receive stream after the handshake. Walk decrypted 0-RTT frames only
// far enough to record the first data offset on each client bidi stream.
// Quinn itself remains responsible for validating and processing the frames.
fn scan_streams(mut frames: &[u8], offsets: &mut HashMap<u64, u64>) -> Option<()> {
    while !frames.is_empty() {
        let ty = var(&mut frames)?;
        let skip = match ty {
            0x00 | 0x01 | 0x1f => 0, // PADDING, PING, IMMEDIATE_ACK
            0x08..=0x0f => {
                let id = var(&mut frames)?;
                let offset = if ty & 4 != 0 { var(&mut frames)? } else { 0 };
                let len = if ty & 2 != 0 {
                    usize::try_from(var(&mut frames)?).ok()?
                } else {
                    frames.len()
                };
                frames = frames.get(len..)?;
                // Client-initiated bidirectional streams have both low bits clear.
                if id.trailing_zeros() >= 2 && len != 0 {
                    let earliest = offsets.entry(id).or_insert(offset);
                    *earliest = (*earliest).min(offset);
                }
                continue;
            }
            // RESET_STREAM, STOP_SENDING, flow control, RETIRE_CONNECTION_ID,
            // and ACK_FREQUENCY have only varint fields.
            0x04 | 0xaf | 0x05 | 0x10..=0x17 | 0x19 => {
                let fields = match ty {
                    0xaf => 4,
                    0x04 => 3,
                    0x05 | 0x11 | 0x15 => 2,
                    _ => 1,
                };
                for _ in 0..fields {
                    var(&mut frames)?;
                }
                0
            }
            0x18 => {
                // NEW_CONNECTION_ID
                var(&mut frames)?;
                var(&mut frames)?;
                usize::from(frames.try_get_u8().ok()?) + 16
            }
            0x1a | 0x1b => 8, // PATH_CHALLENGE, PATH_RESPONSE
            0x1c | 0x1d => {
                // CONNECTION_CLOSE
                var(&mut frames)?;
                if ty == 0x1c {
                    var(&mut frames)?;
                }
                usize::try_from(var(&mut frames)?).ok()?
            }
            0x30 => frames.len(), // DATAGRAM without length
            0x31 => usize::try_from(var(&mut frames)?).ok()?,
            _ => return None,
        };
        frames = frames.get(skip..)?;
    }
    Some(())
}

fn var(frames: &mut &[u8]) -> Option<u64> {
    Some(VarInt::decode(frames).ok()?.into_inner())
}

struct EarlyKey {
    key: Box<dyn PacketKey>,
    early: Arc<EarlyStreams>,
}

impl PacketKey for EarlyKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        self.key.encrypt(packet, buf, header_len);
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), crypto::CryptoError> {
        self.key.decrypt(packet, header, payload)?;
        self.early.observe(payload);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        self.key.tag_len()
    }

    fn confidentiality_limit(&self) -> u64 {
        self.key.confidentiality_limit()
    }

    fn integrity_limit(&self) -> u64 {
        self.key.integrity_limit()
    }
}

struct TrackedConfig(Arc<dyn crypto::ServerConfig>);

pub(crate) fn track(crypto: Arc<dyn crypto::ServerConfig>) -> Arc<dyn crypto::ServerConfig> {
    Arc::new(TrackedConfig(crypto))
}

impl crypto::ServerConfig for TrackedConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, crypto::UnsupportedVersion> {
        self.0.initial_keys(version, dst_cid)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        self.0.retry_tag(version, orig_dst_cid, packet)
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn Session> {
        Box::new(TrackedSession {
            inner: self.0.clone().start_session(version, params),
            early: Arc::default(),
        })
    }
}

struct TrackedSession {
    inner: Box<dyn Session>,
    early: Arc<EarlyStreams>,
}

impl Session for TrackedSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, side: Side) -> Keys {
        self.inner.initial_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        let inner = self.inner.handshake_data();
        if inner.is_none() && self.inner.is_handshaking() {
            return None;
        }
        Some(Box::new(ServerHandshake {
            inner,
            early: self.early.clone(),
        }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.inner.peer_identity()
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        let (header, key) = self.inner.early_crypto()?;
        Some((
            header,
            Box::new(EarlyKey {
                key,
                early: self.early.clone(),
            }),
        ))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        self.inner.early_data_accepted()
    }

    fn is_handshaking(&self) -> bool {
        self.inner.is_handshaking()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        self.inner.read_handshake(buf)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        self.inner.transport_parameters()
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        self.inner.write_handshake(buf)
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        self.inner.next_1rtt_keys()
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        self.inner.is_valid_retry(orig_dst_cid, header, payload)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        self.inner.export_keying_material(output, label, context)
    }
}
