//! Transport parameters (SPEC.md Section 5, REGISTRY.md Section 4) and the
//! negotiation results derived from them (SPEC.md Section 5.5,
//! EXTENSIONS.md Section 2.3).

use std::fmt;
use std::num::NonZeroU64;

use super::codec::{Cursor, Writer, has_duplicates};
use super::error::{EncodeError, Error, TransportErrorCode};
use super::frame::{FrameType, Gates, LANE_KEY_LEN};
use super::keys;
use super::varint::{self, len as vlen};

/// Transport parameter identifiers.
pub mod id {
    /// original_destination_connection_id (prohibited).
    pub const ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
    /// max_idle_timeout.
    pub const MAX_IDLE_TIMEOUT: u64 = 0x01;
    /// stateless_reset_token (prohibited).
    pub const STATELESS_RESET_TOKEN: u64 = 0x02;
    /// max_udp_payload_size (prohibited).
    pub const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
    /// initial_max_data.
    pub const INITIAL_MAX_DATA: u64 = 0x04;
    /// initial_max_stream_data_bidi_local.
    pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
    /// initial_max_stream_data_bidi_remote.
    pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
    /// initial_max_stream_data_uni.
    pub const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
    /// initial_max_streams_bidi.
    pub const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
    /// initial_max_streams_uni.
    pub const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
    /// ack_delay_exponent (prohibited).
    pub const ACK_DELAY_EXPONENT: u64 = 0x0a;
    /// max_ack_delay (prohibited).
    pub const MAX_ACK_DELAY: u64 = 0x0b;
    /// disable_active_migration (prohibited).
    pub const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
    /// preferred_address (prohibited).
    pub const PREFERRED_ADDRESS: u64 = 0x0d;
    /// active_connection_id_limit (prohibited).
    pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
    /// initial_source_connection_id (prohibited).
    pub const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
    /// retry_source_connection_id (prohibited).
    pub const RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
    /// reset_stream_at.
    pub const RESET_STREAM_AT: u64 = 0x1d;
    /// max_datagram_frame_size.
    pub const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;
    /// max_record_size (QMux-02 Section 5.2; [`crate::proto::draft`]).
    pub const MAX_RECORD_SIZE: u64 = crate::proto::draft::CURRENT.max_record_size;
    /// zmux_role.
    pub const ZMUX_ROLE: u64 = 0x1724_0207;
    /// zmux_goaway.
    pub const ZMUX_GOAWAY: u64 = 0x0452_8a5f;
    /// zmux_preamble.
    pub const ZMUX_PREAMBLE: u64 = 0x0439_e07a;
    /// zmux_priority.
    pub const ZMUX_PRIORITY: u64 = 0x31e7_139d;
    /// zmux_datagram_flows.
    pub const ZMUX_DATAGRAM_FLOWS: u64 = 0x0af3_91ed;
    /// zmux_multipath.
    pub const ZMUX_MULTIPATH: u64 = 0x30dc_2978;
    /// zmux_ack_threshold.
    pub const ZMUX_ACK_THRESHOLD: u64 = 0x2762_c7e5;
    /// zmux_pipe_ack.
    pub const ZMUX_PIPE_ACK: u64 = 0x34b4_7621;
    /// zmux_max_ack_delay.
    pub const ZMUX_MAX_ACK_DELAY: u64 = 0x17fa_1ed6;
    /// zmux_max_lanes.
    pub const ZMUX_MAX_LANES: u64 = 0x2785_6ef0;
    /// zmux_resume.
    pub const ZMUX_RESUME: u64 = 0x0d57_78ce;
    /// zmux_record_protection (reserved: never sent, ignored on receipt).
    pub const ZMUX_RECORD_PROTECTION: u64 = 0x1dbe_26bc;
    /// The `qmux` crate's application_protocols parameter; zmux does not
    /// define it and ignores it unless an application opts in.
    pub const APPLICATION_PROTOCOLS: u64 = 0x3d4f_9c2a_8b1e_6075;
}

/// The names of an `application_protocols` value: length-prefixed, at
/// least one, consuming the whole value; `None` otherwise.
fn parse_names(mut value: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut names = Vec::new();
    while !value.is_empty() {
        let (len, w) = varint::decode(value)?;
        let end = usize::try_from(len)
            .ok()
            .and_then(|l| w.checked_add(l))
            .filter(|&e| e <= value.len())?;
        names.push(value[w..end].to_vec());
        value = &value[end..];
    }
    (!names.is_empty()).then_some(names)
}

/// Whether QMux-02 prohibits a QUIC version 1 parameter: receiving it is a
/// TRANSPORT_PARAMETER_ERROR (SPEC.md Section 5.2).
pub const fn is_prohibited(pid: u64) -> bool {
    matches!(
        pid,
        id::ORIGINAL_DESTINATION_CONNECTION_ID
            | id::STATELESS_RESET_TOKEN
            | id::MAX_UDP_PAYLOAD_SIZE
            | id::ACK_DELAY_EXPONENT..=id::RETRY_SOURCE_CONNECTION_ID
    )
}

/// The `max_record_size` an absent parameter stands for, and the smallest
/// valid value.
pub const DEFAULT_MAX_RECORD_SIZE: u64 = 16382;
/// The `max_record_size` zmux endpoints advertise.
pub const ZMUX_MAX_RECORD_SIZE: u64 = 65535;
/// The `zmux_ack_threshold` an absent parameter stands for.
pub const DEFAULT_ACK_THRESHOLD: u64 = 65536;
/// The `zmux_max_ack_delay` (milliseconds) an absent parameter stands for.
pub const DEFAULT_MAX_ACK_DELAY_MS: u64 = 25;
/// How much a `zmux_preamble` limit must stay below the sender's own
/// `max_record_size`.
pub const MAX_PREAMBLE_TP_OVERHEAD: u64 = 32;

/// The GREASE parameter ID 31 * `n` + 27 (RFC 9000 Section 18.1), or `None`
/// if it does not fit in a varint.
pub const fn grease_id(n: u64) -> Option<u64> {
    match n.checked_mul(31) {
        Some(v) if v <= varint::MAX - 27 => Some(v + 27),
        _ => None,
    }
}

/// Whether `id` is a GREASE parameter ID.
pub const fn is_grease_id(id: u64) -> bool {
    id % 31 == 27
}

/// The zmux_role value (EXTENSIONS.md Section 2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RoleParameter {
    /// Role 0.
    Initiator,
    /// Role 1.
    Responder,
    /// Role 2 with the session's random nonce.
    Auto {
        /// The 64-bit nonce.
        nonce: u64,
    },
}

impl RoleParameter {
    /// Length of the value.
    pub const fn encoded_len(&self) -> usize {
        match self {
            Self::Initiator | Self::Responder => 1,
            Self::Auto { .. } => 9,
        }
    }

    /// Writes the value and returns its length.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(buf);
        self.write(&mut w)?;
        Ok(w.pos())
    }

    fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        match self {
            Self::Initiator => w.varint(0),
            Self::Responder => w.varint(1),
            Self::Auto { nonce } => {
                w.varint(2)?;
                w.bytes(&nonce.to_be_bytes())
            }
        }
    }

    fn parse(value: &[u8]) -> Result<Self, Error> {
        let bad = Error::transport_parameter("invalid zmux_role");
        let mut c = Cursor::new(value);
        let role = c.varint().map_err(|_| bad)?;
        let role = match role {
            0 => Self::Initiator,
            1 => Self::Responder,
            2 => Self::Auto {
                nonce: u64::from_be_bytes(*c.array::<8>().map_err(|_| bad)?),
            },
            _ => return Err(bad),
        };
        if c.is_empty() { Ok(role) } else { Err(bad) }
    }
}

/// A Session Locator: 0 to 16 bytes chosen by the endpoint that accepts
/// joins. Empty means "accepts no joins".
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Locator {
    len: u8,
    bytes: [u8; 16],
}

impl Locator {
    /// The largest locator.
    pub const MAX_LEN: usize = 16;

    /// Creates a locator; `None` if `bytes` is longer than 16.
    pub fn new(bytes: &[u8]) -> Option<Self> {
        let mut out = Self::default();
        out.bytes.get_mut(..bytes.len())?.copy_from_slice(bytes);
        out.len = bytes.len() as u8;
        Some(out)
    }

    /// The locator bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or_default()
    }

    /// Whether the locator is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for Locator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Locator(")?;
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

/// The zmux_multipath value (MULTIPATH.md Section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MultipathParameter {
    /// Secret Flags ([`keys::secret_flags`]); reserved bits are ignored.
    pub secret_flags: u8,
    /// The 16-byte random Session Nonce.
    pub session_nonce: [u8; 16],
    /// Session Locator.
    pub locator: Locator,
}

impl MultipathParameter {
    /// Length of the value.
    pub fn encoded_len(&self) -> usize {
        18 + self.locator.as_bytes().len()
    }

    /// Writes the value and returns its length.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(buf);
        self.write(&mut w)?;
        Ok(w.pos())
    }

    fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        let locator = self.locator.as_bytes();
        w.u8(self.secret_flags)?;
        w.bytes(&self.session_nonce)?;
        w.u8(locator.len() as u8)?;
        w.bytes(locator)
    }

    fn parse(value: &[u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(value);
        let (Ok(flags), Ok(nonce), Ok(len)) = (c.u8(), c.array::<16>(), c.u8()) else {
            return Err(Error::transport_parameter("zmux_multipath too short"));
        };
        if usize::from(len) > Locator::MAX_LEN {
            return Err(Error::transport_parameter(
                "zmux_multipath locator above 16 bytes",
            ));
        }
        if c.remaining() != usize::from(len) {
            return Err(Error::transport_parameter("zmux_multipath length mismatch"));
        }
        Ok(Self {
            secret_flags: flags,
            session_nonce: *nonce,
            locator: Locator::new(c.rest()).unwrap_or_default(),
        })
    }
}

/// The zmux floor: what every zmux endpoint
/// advertises at least, and so what early data may use before the peer's
/// parameters arrive: 4 bidirectional streams, 4096 bytes of each
/// (preamble included), 16384 bytes in all, preambles of up to 1024
/// bytes. The values are in the units of the [`crate::Config`] fields
/// they bound (`u64` bytes or streams).
pub mod floor {
    /// `initial_max_data`.
    pub const MAX_DATA: u64 = 16384;
    /// `initial_max_streams_bidi`: 4, or 0 for an endpoint that accepts
    /// no bidirectional streams.
    pub const MAX_STREAMS_BIDI: u64 = 4;
    /// `initial_max_stream_data_bidi_remote`.
    pub const MAX_STREAM_DATA: u64 = 4096;
    /// `zmux_preamble` (Maximum Preamble Size).
    pub const MAX_PREAMBLE: u64 = 1024;
    /// `max_record_size` under the floor.
    pub const MAX_RECORD_SIZE: u64 = 16382;
}

/// The `max_lanes` zmux endpoints announce by default:
/// the default stream concurrency of 256, lane 0 and the copy lane
/// (MULTIPATH.md Section 3.6).
pub const DEFAULT_MAX_LANES: NonZeroU64 = NonZeroU64::new(258).expect("not 0");

/// The zmux_max_lanes value (MULTIPATH.md Section 3.6).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LanesParameter {
    /// Max Lanes L: the lanes, lane 0 included, the sender accepts on each
    /// of its inbound pipes (0 is invalid).
    pub max_lanes: NonZeroU64,
    /// The sender's random Lane Key for the session, which every PIPE_LANE
    /// toward it carries.
    pub lane_key: [u8; LANE_KEY_LEN],
}

impl fmt::Debug for LanesParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The key confines lanes to the session: it is not logged.
        f.debug_struct("LanesParameter")
            .field("max_lanes", &self.max_lanes)
            .finish_non_exhaustive()
    }
}

impl LanesParameter {
    /// Length of the value.
    pub const fn encoded_len(&self) -> usize {
        vlen(self.max_lanes.get()) + LANE_KEY_LEN
    }

    /// Writes the value and returns its length.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(buf);
        self.write(&mut w)?;
        Ok(w.pos())
    }

    fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.varint(self.max_lanes.get())?;
        w.bytes(&self.lane_key)
    }

    fn parse(value: &[u8]) -> Result<Self, Error> {
        let mut c = Cursor::new(value);
        let (Ok(max_lanes), Ok(key)) = (c.varint(), c.array::<LANE_KEY_LEN>()) else {
            return Err(Error::transport_parameter("zmux_max_lanes too short"));
        };
        if c.remaining() != 0 {
            return Err(Error::transport_parameter("zmux_max_lanes too long"));
        }
        let Some(max_lanes) = NonZeroU64::new(max_lanes) else {
            return Err(Error::transport_parameter("zmux_max_lanes is 0"));
        };
        Ok(Self {
            max_lanes,
            lane_key: *key,
        })
    }
}

/// A GREASE parameter to send (SPEC.md Section 5.2 rule 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grease<'a> {
    /// A GREASE ID, 31 * N + 27.
    pub id: u64,
    /// 0 to 16 random bytes.
    pub value: &'a [u8],
}

/// The transport parameters of one endpoint.
///
/// Each field holds what the endpoint sends (`None` or `false`: absent); the
/// `*_or_default` methods apply the meaning of an absent parameter. Unknown
/// and GREASE parameters are not kept.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportParameters {
    /// max_idle_timeout in milliseconds.
    pub max_idle_timeout: Option<u64>,
    /// initial_max_data.
    pub initial_max_data: Option<u64>,
    /// initial_max_stream_data_bidi_local.
    pub initial_max_stream_data_bidi_local: Option<u64>,
    /// initial_max_stream_data_bidi_remote.
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    /// initial_max_stream_data_uni.
    pub initial_max_stream_data_uni: Option<u64>,
    /// initial_max_streams_bidi (at most 2^60).
    pub initial_max_streams_bidi: Option<u64>,
    /// initial_max_streams_uni (at most 2^60).
    pub initial_max_streams_uni: Option<u64>,
    /// reset_stream_at.
    pub reset_stream_at: bool,
    /// max_datagram_frame_size.
    pub max_datagram_frame_size: Option<u64>,
    /// max_record_size (at least 16382).
    pub max_record_size: Option<u64>,
    /// zmux_role.
    pub zmux_role: Option<RoleParameter>,
    /// zmux_goaway.
    pub zmux_goaway: bool,
    /// zmux_preamble: the Maximum Preamble Size.
    pub zmux_preamble: Option<u64>,
    /// zmux_priority.
    pub zmux_priority: bool,
    /// zmux_datagram_flows.
    pub zmux_datagram_flows: bool,
    /// zmux_multipath.
    pub zmux_multipath: Option<MultipathParameter>,
    /// zmux_ack_threshold in bytes (1024 to 2^30).
    pub zmux_ack_threshold: Option<u64>,
    /// zmux_pipe_ack: pipe acknowledgement without multipath (MULTIPATH.md
    /// Section 3.5).
    pub zmux_pipe_ack: bool,
    /// zmux_max_ack_delay in milliseconds (below 2^14).
    pub zmux_max_ack_delay: Option<u64>,
    /// zmux_max_lanes: the lanes the sender accepts per inbound pipe and
    /// its Lane Key (MULTIPATH.md Section 3.6).
    pub zmux_max_lanes: Option<LanesParameter>,
    /// zmux_resume: Resume Grace in milliseconds (1 to 86400000).
    pub zmux_resume: Option<u64>,
    /// The `qmux` crate's `application_protocols`: names in preference
    /// order (SPEC.md Section 13.3); not a zmux parameter, sent only when
    /// the application configures `protocols`.
    pub application_protocols: Option<Vec<Vec<u8>>>,
}

/// A parameter value in the canonical encoding order.
enum Value<'a> {
    Varint(u64),
    Empty,
    Role(RoleParameter),
    Multipath(&'a MultipathParameter),
    Lanes(&'a LanesParameter),
    Raw(&'a [u8]),
    /// Length-prefixed names.
    Names(&'a [Vec<u8>]),
}

impl Value<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Varint(v) => vlen(*v),
            Self::Empty => 0,
            Self::Role(r) => r.encoded_len(),
            Self::Multipath(m) => m.encoded_len(),
            Self::Lanes(l) => l.encoded_len(),
            Self::Raw(b) => b.len(),
            Self::Names(n) => n.iter().map(|n| vlen(n.len() as u64) + n.len()).sum(),
        }
    }

    fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        match self {
            Self::Varint(v) => w.varint(*v),
            Self::Empty => Ok(()),
            Self::Role(r) => r.write(w),
            Self::Multipath(m) => m.write(w),
            Self::Lanes(l) => l.write(w),
            Self::Raw(b) => w.bytes(b),
            Self::Names(names) => {
                for n in *names {
                    w.varint(n.len() as u64)?;
                    w.bytes(n)?;
                }
                Ok(())
            }
        }
    }
}

impl TransportParameters {
    /// The effective `max_record_size`: 16382 when absent.
    pub fn max_record_size_or_default(&self) -> u64 {
        self.max_record_size.unwrap_or(DEFAULT_MAX_RECORD_SIZE)
    }

    /// The effective `zmux_ack_threshold`: 65536 when absent.
    pub fn ack_threshold_or_default(&self) -> u64 {
        self.zmux_ack_threshold.unwrap_or(DEFAULT_ACK_THRESHOLD)
    }

    /// The effective `zmux_max_ack_delay` in milliseconds: 25 when absent.
    pub fn max_ack_delay_or_default(&self) -> u64 {
        self.zmux_max_ack_delay.unwrap_or(DEFAULT_MAX_ACK_DELAY_MS)
    }

    /// Whether these are the parameters of a plain QMux peer: none of the
    /// zmux parameters of SPEC.md Section 5.4 is present (SPEC.md Section
    /// 13.1).
    pub fn is_plain_qmux(&self) -> bool {
        self.zmux_role.is_none()
            && !self.zmux_goaway
            && self.zmux_preamble.is_none()
            && !self.zmux_priority
            && !self.zmux_datagram_flows
            && self.zmux_multipath.is_none()
            && !self.zmux_pipe_ack
            && self.zmux_ack_threshold.is_none()
            && self.zmux_max_ack_delay.is_none()
            && self.zmux_max_lanes.is_none()
            && self.zmux_resume.is_none()
    }

    /// The Max Lanes L the sender announced: 1 (no lanes) when absent.
    pub fn max_lanes_or_default(&self) -> u64 {
        self.zmux_max_lanes.map_or(1, |l| l.max_lanes.get())
    }

    fn for_each<E>(
        &self,
        grease: Option<Grease<'_>>,
        mut f: impl FnMut(u64, Value<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        let varints = [
            (id::MAX_IDLE_TIMEOUT, self.max_idle_timeout),
            (id::INITIAL_MAX_DATA, self.initial_max_data),
            (
                id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
                self.initial_max_stream_data_bidi_local,
            ),
            (
                id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
                self.initial_max_stream_data_bidi_remote,
            ),
            (
                id::INITIAL_MAX_STREAM_DATA_UNI,
                self.initial_max_stream_data_uni,
            ),
            (id::INITIAL_MAX_STREAMS_BIDI, self.initial_max_streams_bidi),
            (id::INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni),
        ];
        for (pid, v) in varints {
            if let Some(v) = v {
                f(pid, Value::Varint(v))?;
            }
        }
        if self.reset_stream_at {
            f(id::RESET_STREAM_AT, Value::Empty)?;
        }
        if let Some(v) = self.max_datagram_frame_size {
            f(id::MAX_DATAGRAM_FRAME_SIZE, Value::Varint(v))?;
        }
        if let Some(r) = self.zmux_role {
            f(id::ZMUX_ROLE, Value::Role(r))?;
        }
        if self.zmux_goaway {
            f(id::ZMUX_GOAWAY, Value::Empty)?;
        }
        if let Some(v) = self.zmux_preamble {
            f(id::ZMUX_PREAMBLE, Value::Varint(v))?;
        }
        if self.zmux_priority {
            f(id::ZMUX_PRIORITY, Value::Empty)?;
        }
        if self.zmux_datagram_flows {
            f(id::ZMUX_DATAGRAM_FLOWS, Value::Empty)?;
        }
        if self.zmux_pipe_ack {
            f(id::ZMUX_PIPE_ACK, Value::Empty)?;
        }
        if let Some(l) = &self.zmux_max_lanes {
            f(id::ZMUX_MAX_LANES, Value::Lanes(l))?;
        }
        if let Some(m) = &self.zmux_multipath {
            f(id::ZMUX_MULTIPATH, Value::Multipath(m))?;
        }
        let multipath = [
            (id::ZMUX_ACK_THRESHOLD, self.zmux_ack_threshold),
            (id::ZMUX_MAX_ACK_DELAY, self.zmux_max_ack_delay),
            (id::ZMUX_RESUME, self.zmux_resume),
            (id::MAX_RECORD_SIZE, self.max_record_size),
        ];
        for (pid, v) in multipath {
            if let Some(v) = v {
                f(pid, Value::Varint(v))?;
            }
        }
        if let Some(names) = &self.application_protocols {
            f(id::APPLICATION_PROTOCOLS, Value::Names(names))?;
        }
        if let Some(g) = grease {
            f(g.id, Value::Raw(g.value))?;
        }
        Ok(())
    }

    /// Length of the encoded parameter block, including `grease`.
    pub fn encoded_len(&self, grease: Option<Grease<'_>>) -> usize {
        let mut n = 0;
        let _ = self.for_each::<()>(grease, |pid, v| {
            let len = v.len();
            n += vlen(pid) + vlen(len as u64) + len;
            Ok(())
        });
        n
    }

    /// Writes the parameter block in the canonical order (QUIC parameters,
    /// then zmux parameters, then `max_record_size` and the GREASE
    /// parameter last). Returns the number of bytes written. Parameters that
    /// [`TransportParameters::validate`] rejects are not encoded.
    pub fn encode(&self, grease: Option<Grease<'_>>, buf: &mut [u8]) -> Result<usize, EncodeError> {
        let mut w = Writer::new(buf);
        self.write(grease, &mut w)?;
        Ok(w.pos())
    }

    fn write(&self, grease: Option<Grease<'_>>, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        if self.validate().is_err() {
            return Err(EncodeError::ValueOutOfRange);
        }
        if let Some(g) = grease
            && (!is_grease_id(g.id) || g.value.len() > 16)
        {
            return Err(EncodeError::ValueOutOfRange);
        }
        self.for_each(grease, |pid, v| {
            w.varint(pid)?;
            w.varint(v.len() as u64)?;
            v.write(w)
        })
    }

    /// Length of a QX_TRANSPORT_PARAMETERS frame carrying these parameters.
    pub fn frame_len(&self, grease: Option<Grease<'_>>) -> usize {
        let block = self.encoded_len(grease);
        vlen(FrameType::QX_TRANSPORT_PARAMETERS.0) + vlen(block as u64) + block
    }

    /// Writes a QX_TRANSPORT_PARAMETERS frame carrying these parameters.
    pub fn encode_frame(
        &self,
        grease: Option<Grease<'_>>,
        buf: &mut [u8],
    ) -> Result<usize, EncodeError> {
        let mut w = Writer::new(buf);
        w.varint(FrameType::QX_TRANSPORT_PARAMETERS.0)?;
        w.varint(self.encoded_len(grease) as u64)?;
        self.write(grease, &mut w)?;
        Ok(w.pos())
    }

    /// Parses and validates a parameter block (SPEC.md Section 5.2): every
    /// violation is a TRANSPORT_PARAMETER_ERROR.
    pub fn decode(block: &[u8]) -> Result<Self, Error> {
        let mut tp = Self::default();
        for p in RawParameters::new(block) {
            let (pid, value) = p?;
            tp.set(pid, value)?;
        }
        if has_duplicates(RawParameters::new(block).map(|p| p.map_or(0, |(pid, _)| pid))) {
            return Err(Error::transport_parameter("duplicate transport parameter"));
        }
        tp.validate()?;
        Ok(tp)
    }

    pub(crate) fn validate_block(block: &[u8]) -> Result<(), Error> {
        Self::decode(block).map(drop)
    }

    fn set(&mut self, pid: u64, value: &[u8]) -> Result<(), Error> {
        if is_prohibited(pid) {
            return Err(Error::transport_parameter("prohibited transport parameter"));
        }
        let varint = || -> Result<u64, Error> {
            match varint::decode(value) {
                Some((v, n)) if n == value.len() => Ok(v),
                _ => Err(Error::transport_parameter("malformed varint parameter")),
            }
        };
        let empty = || -> Result<bool, Error> {
            if value.is_empty() {
                Ok(true)
            } else {
                Err(Error::transport_parameter(
                    "non-empty value for an empty parameter",
                ))
            }
        };
        match pid {
            id::MAX_IDLE_TIMEOUT => self.max_idle_timeout = Some(varint()?),
            id::INITIAL_MAX_DATA => self.initial_max_data = Some(varint()?),
            id::INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                self.initial_max_stream_data_bidi_local = Some(varint()?);
            }
            id::INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                self.initial_max_stream_data_bidi_remote = Some(varint()?);
            }
            id::INITIAL_MAX_STREAM_DATA_UNI => self.initial_max_stream_data_uni = Some(varint()?),
            id::INITIAL_MAX_STREAMS_BIDI => self.initial_max_streams_bidi = Some(varint()?),
            id::INITIAL_MAX_STREAMS_UNI => self.initial_max_streams_uni = Some(varint()?),
            id::RESET_STREAM_AT => self.reset_stream_at = empty()?,
            id::MAX_DATAGRAM_FRAME_SIZE => self.max_datagram_frame_size = Some(varint()?),
            id::MAX_RECORD_SIZE => self.max_record_size = Some(varint()?),
            id::ZMUX_ROLE => self.zmux_role = Some(RoleParameter::parse(value)?),
            id::ZMUX_GOAWAY => self.zmux_goaway = empty()?,
            id::ZMUX_PREAMBLE => self.zmux_preamble = Some(varint()?),
            id::ZMUX_PRIORITY => self.zmux_priority = empty()?,
            id::ZMUX_DATAGRAM_FLOWS => self.zmux_datagram_flows = empty()?,
            id::ZMUX_MULTIPATH => self.zmux_multipath = Some(MultipathParameter::parse(value)?),
            id::ZMUX_ACK_THRESHOLD => self.zmux_ack_threshold = Some(varint()?),
            id::ZMUX_PIPE_ACK => self.zmux_pipe_ack = empty()?,
            id::ZMUX_MAX_ACK_DELAY => self.zmux_max_ack_delay = Some(varint()?),
            id::ZMUX_MAX_LANES => self.zmux_max_lanes = Some(LanesParameter::parse(value)?),
            id::ZMUX_RESUME => self.zmux_resume = Some(varint()?),
            id::APPLICATION_PROTOCOLS => {
                // Not zmux's: a malformed value is ignored like any
                // unknown parameter (SPEC.md Section 13.2).
                self.application_protocols = parse_names(value);
            }
            _ => {}
        }
        Ok(())
    }

    /// Checks value ranges and dependencies between parameters (SPEC.md
    /// Sections 3.2 and 5.5, EXTENSIONS.md Section 4.1, MULTIPATH.md Section
    /// 3, RESUME.md Section 3).
    pub fn validate(&self) -> Result<(), Error> {
        let err = Error::transport_parameter;
        if self
            .max_record_size
            .is_some_and(|v| v < DEFAULT_MAX_RECORD_SIZE)
        {
            return Err(err("max_record_size below 16382"));
        }
        let max_streams = [self.initial_max_streams_bidi, self.initial_max_streams_uni];
        if max_streams.iter().flatten().any(|&v| v > 1 << 60) {
            return Err(err("initial_max_streams above 2^60"));
        }
        if let Some(preamble) = self.zmux_preamble {
            if !self.reset_stream_at {
                return Err(err("zmux_preamble without reset_stream_at"));
            }
            if preamble < 1 {
                return Err(err("zmux_preamble below 1"));
            }
            if preamble > self.max_record_size_or_default() - MAX_PREAMBLE_TP_OVERHEAD {
                return Err(err("zmux_preamble above max_record_size - 32"));
            }
            let windows = [
                self.initial_max_stream_data_bidi_remote,
                self.initial_max_stream_data_uni,
            ];
            if windows.iter().any(|w| preamble > w.unwrap_or(0)) {
                return Err(err("zmux_preamble above the stream windows"));
            }
        }
        let acks = self.zmux_ack_threshold.is_some()
            || self.zmux_max_ack_delay.is_some()
            || self.zmux_max_lanes.is_some();
        if acks && self.zmux_multipath.is_none() && !self.zmux_pipe_ack {
            return Err(err(
                "acknowledgement or lanes parameter without zmux_multipath or zmux_pipe_ack",
            ));
        }
        if self.zmux_resume.is_some() && self.zmux_multipath.is_none() {
            return Err(err("zmux_resume without zmux_multipath"));
        }
        if self.zmux_ack_threshold.is_some_and(|v| v < 1024) {
            return Err(err("zmux_ack_threshold below 1024"));
        }
        if self.zmux_max_ack_delay.is_some_and(|v| v >= 1 << 14) {
            return Err(err("zmux_max_ack_delay out of range"));
        }
        if self.zmux_resume == Some(0) {
            return Err(err("zmux_resume is 0"));
        }
        Ok(())
    }
}

/// Iterator over the (ID, value) pairs of a parameter block, including
/// unknown and GREASE parameters. Yields `Err` (TRANSPORT_PARAMETER_ERROR)
/// once for a truncated block and then stops.
#[derive(Debug, Clone)]
pub struct RawParameters<'a> {
    rest: &'a [u8],
}

impl<'a> RawParameters<'a> {
    /// Iterates over `block`.
    pub const fn new(block: &'a [u8]) -> Self {
        Self { rest: block }
    }
}

impl<'a> Iterator for RawParameters<'a> {
    type Item = Result<(u64, &'a [u8]), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let mut c = Cursor::new(self.rest);
        let parsed = (|| {
            let pid = c.varint()?;
            let len = c.varint()?;
            Ok((pid, c.bytes(len)?))
        })();
        match parsed {
            Ok(p) => {
                self.rest = c.rest();
                Some(Ok(p))
            }
            Err(crate::proto::codec::Short) => {
                self.rest = &[];
                Some(Err(Error::transport_parameter(
                    "truncated transport parameter",
                )))
            }
        }
    }
}

/// The two session roles (SPEC.md Section 5.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Uses client-initiated stream IDs and even pipe IDs.
    Initiator,
    /// Uses server-initiated stream IDs and odd pipe IDs.
    Responder,
}

/// Resolves the local role (EXTENSIONS.md Section 2.3).
///
/// `local` and `peer` are the `zmux_role` values sent by each endpoint;
/// `transport` is the local transport role (`None` for a symmetric carrier).
pub fn resolve_role(
    local: Option<RoleParameter>,
    peer: Option<RoleParameter>,
    transport: Option<Role>,
) -> Result<Role, Error> {
    use RoleParameter::{Auto, Initiator as I, Responder as R};
    let conflict = Error::new(TransportErrorCode::ZMUX_ROLE_CONFLICT, 0, "role conflict");
    match (local, peer) {
        (Some(l), Some(p)) => match (l, p) {
            (I, R) | (I, Auto { .. }) | (Auto { .. }, R) => Ok(Role::Initiator),
            (R, I) | (R, Auto { .. }) | (Auto { .. }, I) => Ok(Role::Responder),
            (Auto { nonce: a }, Auto { nonce: b }) if a > b => Ok(Role::Initiator),
            (Auto { nonce: a }, Auto { nonce: b }) if a < b => Ok(Role::Responder),
            _ => Err(conflict),
        },
        (Some(l), None) => match (l, transport) {
            (_, None) => Err(conflict),
            (I, Some(Role::Responder)) | (R, Some(Role::Initiator)) => Err(conflict),
            (_, Some(t)) => Ok(t),
        },
        (None, _) => transport.ok_or(conflict),
    }
}

/// The zmux features in use in a session (SPEC.md Section 5.5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Features {
    /// Role negotiation.
    pub role: bool,
    /// GOAWAY.
    pub goaway: bool,
    /// Stream preamble.
    pub preamble: bool,
    /// PRIORITY_UPDATE.
    pub priority: bool,
    /// Datagram flows.
    pub datagram_flows: bool,
    /// Multipath.
    pub multipath: bool,
    /// Pipe acknowledgement without multipath (MULTIPATH.md Section 3.5).
    pub pipe_ack: bool,
    /// Resume.
    pub resume: bool,
    /// Lanes are available toward the peer: the local endpoint may open
    /// lanes on its outbound pipes, as many as the peer's Max Lanes allows
    /// (MULTIPATH.md Section 3.6).
    pub lanes_out: bool,
    /// Lanes are available toward the local endpoint.
    pub lanes_in: bool,
}

impl Features {
    /// Computes the features in use from both endpoints' parameters.
    pub fn negotiate(local: &TransportParameters, peer: &TransportParameters) -> Self {
        let multipath = match (&local.zmux_multipath, &peer.zmux_multipath) {
            (Some(l), Some(p)) => {
                keys::select_secret_source(l.secret_flags, p.secret_flags).is_some()
            }
            _ => false,
        };
        let resume = multipath
            && local.zmux_resume.is_some()
            && peer.zmux_resume.is_some()
            && [&local.zmux_multipath, &peer.zmux_multipath]
                .into_iter()
                .flatten()
                .any(|m| !m.locator.is_empty());
        let pipe_ack = !multipath && local.zmux_pipe_ack && peer.zmux_pipe_ack;
        // One-directional: lanes toward an endpoint that announced L > 1,
        // while multipath or pipe acknowledgement is in use.
        let lanes =
            |tp: &TransportParameters| (multipath || pipe_ack) && tp.max_lanes_or_default() > 1;
        Self {
            role: local.zmux_role.is_some() && peer.zmux_role.is_some(),
            goaway: local.zmux_goaway && peer.zmux_goaway,
            preamble: local.zmux_preamble.is_some() && peer.zmux_preamble.is_some(),
            priority: local.zmux_priority && peer.zmux_priority,
            datagram_flows: local.zmux_datagram_flows && peer.zmux_datagram_flows,
            multipath,
            pipe_ack,
            resume,
            lanes_out: lanes(peer),
            lanes_in: lanes(local),
        }
    }

    /// The frames the local endpoint accepts: the zmux frames of features in
    /// use, plus RESET_STREAM_AT and DATAGRAM as its parameters announced
    /// them (`reset_stream_at`, `max_datagram_frame_size`, 0 when absent).
    pub fn receive_gates(&self, reset_stream_at: bool, max_datagram_frame_size: u64) -> Gates {
        Gates {
            reset_stream_at,
            max_datagram_frame_size,
            goaway: self.goaway,
            priority: self.priority,
            multipath: self.multipath,
            pipe_ack: self.pipe_ack,
            lanes: self.lanes_in,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zmux_default() -> TransportParameters {
        TransportParameters {
            max_idle_timeout: Some(30_000),
            initial_max_data: Some(1_048_576),
            initial_max_stream_data_bidi_local: Some(262_144),
            initial_max_stream_data_bidi_remote: Some(262_144),
            initial_max_stream_data_uni: Some(262_144),
            initial_max_streams_bidi: Some(256),
            initial_max_streams_uni: Some(256),
            reset_stream_at: true,
            zmux_goaway: true,
            zmux_preamble: Some(4096),
            zmux_priority: true,
            zmux_pipe_ack: true,
            zmux_max_lanes: Some(LanesParameter {
                max_lanes: DEFAULT_MAX_LANES,
                lane_key: [
                    0x8d, 0x2f, 0x6a, 0x01, 0xc7, 0xe4, 0xb3, 0x5a, 0x90, 0xf1, 0xd2, 0x6e, 0x4b,
                    0x7c, 0x0a, 0x39,
                ],
            }),
            max_record_size: Some(ZMUX_MAX_RECORD_SIZE),
            ..Default::default()
        }
    }

    #[test]
    fn default_parameters_match_wire_example() {
        // WIRE_EXAMPLES.md Section 1.1, without the record Size.
        let grease = Grease {
            id: grease_id(3).unwrap(),
            value: &[0x9a, 0x7b],
        };
        let tp = zmux_default();
        let mut buf = [0u8; 160];
        let n = tp.encode_frame(Some(grease), &mut buf).unwrap();
        assert_eq!(n, tp.frame_len(Some(grease)));
        let expected = "ff5153300d0a0d0a40670104800075300404801000000504800400000604\
                        8004000007048004000008024100090241001d0084528a5f008439e07a025000\
                        b1e7139d00b4b4762100a7856ef01241028d2f6a01c7e4b35a90f1d26e4b7c0a\
                        39c571c59429cd0845048000ffff4078029a7b";
        let hex: String = buf[..n].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, expected);
        let block = &buf[10..n];
        assert_eq!(TransportParameters::decode(block).unwrap(), tp);
    }

    #[test]
    fn roles() {
        use RoleParameter::*;
        let ok = |l, p, t| resolve_role(l, p, t).ok();
        assert_eq!(
            ok(Some(Initiator), Some(Responder), None),
            Some(Role::Initiator)
        );
        assert_eq!(
            ok(Some(Auto { nonce: 5 }), Some(Auto { nonce: 4 }), None),
            Some(Role::Initiator)
        );
        assert_eq!(
            ok(Some(Auto { nonce: 4 }), Some(Auto { nonce: 4 }), None),
            None
        );
        assert_eq!(ok(Some(Responder), Some(Responder), None), None);
        assert_eq!(
            ok(Some(Auto { nonce: 1 }), None, Some(Role::Responder)),
            Some(Role::Responder)
        );
        assert_eq!(ok(Some(Initiator), None, Some(Role::Responder)), None);
        assert_eq!(
            ok(None, Some(Initiator), Some(Role::Responder)),
            Some(Role::Responder)
        );
    }

    #[test]
    fn grease_ids() {
        assert_eq!(grease_id(0), Some(27));
        assert!(is_grease_id(grease_id(1 << 40).unwrap()));
        assert_eq!(grease_id(u64::MAX / 2), None);
    }
}
