use crate::error::{Error, ErrorDirection, ErrorOperation, ErrorScope, ErrorSource, Result};
use crate::frame::FRAME_FLAG_OPEN_METADATA;
use crate::protocol::*;
use crate::tlv::{append_tlv, parse_tlvs, tlv_views, visit_tlvs, Tlv};
use crate::varint::{append_varint, parse_varint, varint_len, MAX_VARINT62};
use std::str;

const DUPLICATE_METADATA_SINGLETON: &str = "duplicate metadata singleton";
const DUPLICATE_DIAG_SINGLETON: &str = "duplicate diagnostic singleton";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StreamMetadata {
    pub priority: Option<u64>,
    pub group: Option<u64>,
    pub open_info: Vec<u8>,
}

impl StreamMetadata {
    pub fn as_view(&self) -> StreamMetadataView<'_> {
        StreamMetadataView {
            priority: self.priority,
            group: self.group,
            open_info: &self.open_info,
        }
    }

    pub fn open_info(&self) -> &[u8] {
        &self.open_info
    }

    pub fn has_open_info(&self) -> bool {
        !self.open_info.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.priority.is_none() && self.group.is_none() && self.open_info.is_empty()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamMetadataView<'a> {
    pub priority: Option<u64>,
    pub group: Option<u64>,
    pub open_info: &'a [u8],
}

impl StreamMetadataView<'_> {
    pub fn open_info(&self) -> &[u8] {
        self.open_info
    }

    pub fn has_open_info(&self) -> bool {
        !self.open_info.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.priority.is_none() && self.group.is_none() && self.open_info.is_empty()
    }

    pub fn to_owned_metadata(self) -> StreamMetadata {
        StreamMetadata {
            priority: self.priority,
            group: self.group,
            open_info: self.open_info.to_vec(),
        }
    }

    pub fn try_to_owned_metadata(self) -> Result<StreamMetadata> {
        Ok(StreamMetadata {
            priority: self.priority,
            group: self.group,
            open_info: copy_payload_slice(self.open_info)?,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MetadataUpdate {
    pub priority: Option<u64>,
    pub group: Option<u64>,
}

impl MetadataUpdate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn priority(priority: u64) -> Self {
        Self::new().with_priority(priority)
    }

    pub fn group(group: u64) -> Self {
        Self::new().with_group(group)
    }

    pub fn with_priority(mut self, priority: u64) -> Self {
        self.priority = Some(priority);
        self
    }

    pub fn try_with_priority(mut self, priority: u64) -> Result<Self> {
        validate_metadata_update_varint(priority, "priority")?;
        self.priority = Some(priority);
        Ok(self)
    }

    pub fn with_group(mut self, group: u64) -> Self {
        self.group = Some(group);
        self
    }

    pub fn try_with_group(mut self, group: u64) -> Result<Self> {
        validate_metadata_update_varint(group, "group")?;
        self.group = Some(group);
        Ok(self)
    }

    pub fn is_empty(&self) -> bool {
        self.priority.is_none() && self.group.is_none()
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(priority) = self.priority {
            validate_metadata_update_varint(priority, "priority")?;
        }
        if let Some(group) = self.group {
            validate_metadata_update_varint(group, "group")?;
        }
        Ok(())
    }
}

fn validate_metadata_update_varint(value: u64, field: &str) -> Result<()> {
    if value > MAX_VARINT62 {
        return Err(Error::protocol(format!(
            "zmux metadata update {field} exceeds varint62"
        )));
    }
    Ok(())
}

pub(crate) fn normalize_stream_group(group: Option<u64>) -> Option<u64> {
    group.filter(|group| *group != 0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPayload {
    pub metadata_tlvs: Vec<Tlv>,
    pub metadata: StreamMetadata,
    pub app_data: Vec<u8>,
    pub metadata_valid: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPayloadView<'a> {
    pub metadata: StreamMetadataView<'a>,
    pub app_data: &'a [u8],
    pub metadata_valid: bool,
}

pub fn parse_data_payload(payload: &[u8], flags: u8) -> Result<DataPayload> {
    if flags & FRAME_FLAG_OPEN_METADATA == 0 {
        return Ok(DataPayload {
            metadata_tlvs: Vec::new(),
            metadata: StreamMetadata::default(),
            app_data: copy_payload_slice(payload)?,
            metadata_valid: true,
        });
    }
    let (metadata_len, n) = parse_open_metadata_len(payload)?;
    let metadata_raw = &payload[n..n + metadata_len];
    let app_data = &payload[n + metadata_len..];
    let tlvs = parse_tlvs(metadata_raw)?;
    let (metadata, valid) = parse_stream_metadata_tlvs(&tlvs)?;
    if !valid {
        return Ok(DataPayload {
            metadata_tlvs: Vec::new(),
            metadata: StreamMetadata::default(),
            app_data: copy_payload_slice(app_data)?,
            metadata_valid: false,
        });
    }
    Ok(DataPayload {
        metadata_tlvs: tlvs,
        metadata,
        app_data: copy_payload_slice(app_data)?,
        metadata_valid: true,
    })
}

pub fn parse_data_payload_view(payload: &[u8], flags: u8) -> Result<DataPayloadView<'_>> {
    if flags & FRAME_FLAG_OPEN_METADATA == 0 {
        return Ok(DataPayloadView {
            metadata: StreamMetadataView::default(),
            app_data: payload,
            metadata_valid: true,
        });
    }
    let (metadata_len, n) = parse_open_metadata_len(payload)?;
    let metadata_raw = &payload[n..n + metadata_len];
    let app_data = &payload[n + metadata_len..];
    let (metadata, valid) = parse_stream_metadata_bytes_view(metadata_raw)?;
    Ok(DataPayloadView {
        metadata,
        app_data,
        metadata_valid: valid,
    })
}

pub(crate) fn parse_data_payload_metadata_offset(
    payload: &[u8],
    flags: u8,
) -> Result<(StreamMetadata, bool, usize)> {
    if flags & FRAME_FLAG_OPEN_METADATA == 0 {
        return Ok((StreamMetadata::default(), true, 0));
    }
    let (metadata_len, n) = parse_open_metadata_len(payload)?;
    let metadata_raw = &payload[n..n + metadata_len];
    let (metadata, valid) = parse_stream_metadata_bytes_view(metadata_raw)?;
    Ok((metadata.try_to_owned_metadata()?, valid, n + metadata_len))
}

fn parse_open_metadata_len(payload: &[u8]) -> Result<(usize, usize)> {
    let (metadata_len, n) = parse_varint(payload)?;
    let metadata_len = usize::try_from(metadata_len)
        .map_err(|_| Error::frame_size("OPEN_METADATA payload overrun"))?;
    if payload.len() - n < metadata_len {
        return Err(Error::frame_size("OPEN_METADATA payload overrun"));
    }
    Ok((metadata_len, n))
}

pub fn parse_stream_metadata_tlvs(tlvs: &[Tlv]) -> Result<(StreamMetadata, bool)> {
    let mut metadata = StreamMetadata::default();
    let mut seen_priority = false;
    let mut seen_group = false;
    let mut seen_open_info = false;
    for tlv in tlvs {
        match tlv.typ {
            METADATA_STREAM_PRIORITY => {
                if seen_priority {
                    return Ok((StreamMetadata::default(), false));
                }
                seen_priority = true;
                metadata.priority = Some(parse_metadata_varint(&tlv.value)?);
            }
            METADATA_STREAM_GROUP => {
                if seen_group {
                    return Ok((StreamMetadata::default(), false));
                }
                seen_group = true;
                metadata.group = Some(parse_metadata_varint(&tlv.value)?);
            }
            METADATA_OPEN_INFO => {
                if seen_open_info {
                    return Ok((StreamMetadata::default(), false));
                }
                seen_open_info = true;
                metadata.open_info = copy_payload_slice(&tlv.value)?;
            }
            _ => {}
        }
    }
    Ok((metadata, true))
}

pub fn parse_stream_metadata_bytes_view(src: &[u8]) -> Result<(StreamMetadataView<'_>, bool)> {
    let mut metadata = StreamMetadataView::default();
    let mut seen_priority = false;
    let mut seen_group = false;
    let mut seen_open_info = false;
    let result = (|| {
        for tlv in tlv_views(src) {
            let tlv = tlv?;
            match tlv.typ {
                METADATA_STREAM_PRIORITY => {
                    if seen_priority {
                        return Err(Error::protocol(DUPLICATE_METADATA_SINGLETON));
                    }
                    seen_priority = true;
                    metadata.priority = Some(parse_metadata_varint(tlv.value)?);
                }
                METADATA_STREAM_GROUP => {
                    if seen_group {
                        return Err(Error::protocol(DUPLICATE_METADATA_SINGLETON));
                    }
                    seen_group = true;
                    metadata.group = Some(parse_metadata_varint(tlv.value)?);
                }
                METADATA_OPEN_INFO => {
                    if seen_open_info {
                        return Err(Error::protocol(DUPLICATE_METADATA_SINGLETON));
                    }
                    seen_open_info = true;
                    metadata.open_info = tlv.value;
                }
                _ => {}
            }
        }
        Ok(())
    })();
    if let Err(err) = result {
        if err.is_protocol_message(DUPLICATE_METADATA_SINGLETON) {
            return Ok((StreamMetadataView::default(), false));
        }
        return Err(err);
    }
    Ok((metadata, true))
}

fn parse_metadata_varint(value: &[u8]) -> Result<u64> {
    let (v, n) = parse_varint(value)?;
    if n != value.len() {
        return Err(Error::protocol("tlv value overruns containing payload"));
    }
    Ok(v)
}

pub fn build_open_metadata_prefix(
    caps: u64,
    priority: Option<u64>,
    group: Option<u64>,
    open_info: &[u8],
    max_frame_payload: u64,
) -> Result<Vec<u8>> {
    if !open_info.is_empty() && !capabilities_can_carry_open_info(caps) {
        return Err(
            Error::protocol("zmux: open_info requires negotiated open_metadata")
                .with_scope(ErrorScope::Stream)
                .with_operation(ErrorOperation::Open)
                .with_source(ErrorSource::Local)
                .with_direction(ErrorDirection::Write),
        );
    }
    if caps & CAPABILITY_OPEN_METADATA == 0 {
        return Ok(Vec::new());
    }

    let mut metadata_len = 0usize;
    if let Some(priority) = priority {
        if capabilities_can_carry_priority_on_open(caps) {
            metadata_len = checked_len_add(
                metadata_len,
                metadata_varint_tlv_len(METADATA_STREAM_PRIORITY, priority)?,
                "opening metadata too large",
            )?;
        }
    }
    if let Some(group) = group {
        if capabilities_can_carry_group_on_open(caps) {
            metadata_len = checked_len_add(
                metadata_len,
                metadata_varint_tlv_len(METADATA_STREAM_GROUP, group)?,
                "opening metadata too large",
            )?;
        }
    }
    if !open_info.is_empty() {
        metadata_len = checked_len_add(
            metadata_len,
            metadata_bytes_tlv_len(METADATA_OPEN_INFO, open_info.len())?,
            "opening metadata too large",
        )?;
    }
    if metadata_len == 0 {
        return Ok(Vec::new());
    }
    let metadata_len_u64 = usize_to_u64_len(metadata_len, "opening metadata too large")?;
    let total_len = checked_len_add(
        varint_len(metadata_len_u64)?,
        metadata_len,
        "opening metadata too large",
    )?;
    if usize_to_u64_len(total_len, "opening metadata too large")? > max_frame_payload {
        return Err(
            Error::protocol("zmux: opening metadata exceeds peer max_frame_payload")
                .with_scope(ErrorScope::Stream)
                .with_operation(ErrorOperation::Open)
                .with_source(ErrorSource::Local)
                .with_direction(ErrorDirection::Write),
        );
    }

    let mut out = payload_vec_with_capacity(total_len)?;
    append_varint(&mut out, metadata_len_u64)?;
    if let Some(priority) = priority {
        if capabilities_can_carry_priority_on_open(caps) {
            append_varint_tlv(&mut out, METADATA_STREAM_PRIORITY, priority)?;
        }
    }
    if let Some(group) = group {
        if capabilities_can_carry_group_on_open(caps) {
            append_varint_tlv(&mut out, METADATA_STREAM_GROUP, group)?;
        }
    }
    if !open_info.is_empty() {
        append_tlv(&mut out, METADATA_OPEN_INFO, open_info)?;
    }
    debug_assert_eq!(out.len(), total_len);
    Ok(out)
}

pub fn build_priority_update_payload(
    caps: u64,
    update: MetadataUpdate,
    max_payload: u64,
) -> Result<Vec<u8>> {
    if update.priority.is_none() && update.group.is_none() {
        return Err(Error::local("zmux: metadata update has no fields"));
    }
    let mut total_len = varint_len(EXT_PRIORITY_UPDATE)?;
    if let Some(priority) = update.priority {
        if !capabilities_can_carry_priority_update(caps) {
            return Err(metadata_update_capability_error());
        }
        total_len = checked_len_add(
            total_len,
            metadata_varint_tlv_len(METADATA_STREAM_PRIORITY, priority)?,
            "priority update too large",
        )?;
    }
    if let Some(group) = update.group {
        if !capabilities_can_carry_group_update(caps) {
            return Err(metadata_update_capability_error());
        }
        total_len = checked_len_add(
            total_len,
            metadata_varint_tlv_len(METADATA_STREAM_GROUP, group)?,
            "priority update too large",
        )?;
    }
    if usize_to_u64_len(total_len, "priority update too large")? > max_payload {
        return Err(Error::local(
            "zmux: priority update exceeds peer max_extension_payload_bytes",
        ));
    }
    let mut out = payload_vec_with_capacity(total_len)?;
    append_varint(&mut out, EXT_PRIORITY_UPDATE)?;
    if let Some(priority) = update.priority {
        append_varint_tlv(&mut out, METADATA_STREAM_PRIORITY, priority)?;
    }
    if let Some(group) = update.group {
        append_varint_tlv(&mut out, METADATA_STREAM_GROUP, group)?;
    }
    debug_assert_eq!(out.len(), total_len);
    Ok(out)
}

fn metadata_update_capability_error() -> Error {
    Error::protocol(
        "zmux: metadata update requires negotiated priority_update and matching semantic capability",
    )
        .with_scope(ErrorScope::Session)
        .with_operation(ErrorOperation::Write)
        .with_source(ErrorSource::Local)
        .with_direction(ErrorDirection::Write)
}

pub fn parse_priority_update_payload(payload: &[u8]) -> Result<(StreamMetadata, bool)> {
    let (subtype, n) = parse_varint(payload)?;
    if subtype != EXT_PRIORITY_UPDATE {
        return Ok((StreamMetadata::default(), false));
    }
    parse_priority_update_metadata(&payload[n..])
}

pub(crate) fn parse_priority_update_metadata(payload: &[u8]) -> Result<(StreamMetadata, bool)> {
    let mut metadata = StreamMetadata::default();
    let mut seen_priority = false;
    let mut seen_group = false;
    let result = visit_tlvs(payload, |typ, value| {
        match typ {
            METADATA_STREAM_PRIORITY => {
                if seen_priority {
                    return Err(Error::protocol(DUPLICATE_METADATA_SINGLETON));
                }
                seen_priority = true;
                metadata.priority = Some(parse_metadata_varint(value)?);
            }
            METADATA_STREAM_GROUP => {
                if seen_group {
                    return Err(Error::protocol(DUPLICATE_METADATA_SINGLETON));
                }
                seen_group = true;
                metadata.group = Some(parse_metadata_varint(value)?);
            }
            METADATA_OPEN_INFO => {}
            _ => {}
        }
        Ok(())
    });
    if let Err(err) = result {
        if err.is_protocol_message(DUPLICATE_METADATA_SINGLETON) {
            return Ok((StreamMetadata::default(), false));
        }
        return Err(err);
    }
    Ok((metadata, true))
}

fn append_varint_tlv(dst: &mut Vec<u8>, typ: u64, value: u64) -> Result<()> {
    append_varint(dst, typ)?;
    let value_len = usize_to_u64_len(varint_len(value)?, "metadata tlv too large")?;
    append_varint(dst, value_len)?;
    append_varint(dst, value)
}

fn metadata_varint_tlv_len(typ: u64, value: u64) -> Result<usize> {
    let value_len = varint_len(value)?;
    checked_len_sum3(
        varint_len(typ)?,
        varint_len(usize_to_u64_len(value_len, "metadata tlv too large")?)?,
        value_len,
        "metadata tlv too large",
    )
}

fn metadata_bytes_tlv_len(typ: u64, value_len: usize) -> Result<usize> {
    checked_len_sum3(
        varint_len(typ)?,
        varint_len(usize_to_u64_len(value_len, "metadata tlv too large")?)?,
        value_len,
        "metadata tlv too large",
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GoAwayPayload {
    pub last_accepted_bidi: u64,
    pub last_accepted_uni: u64,
    pub code: u64,
    pub reason: String,
}

pub fn build_goaway_payload(
    last_accepted_bidi: u64,
    last_accepted_uni: u64,
    code: u64,
    reason: &str,
) -> Result<Vec<u8>> {
    let mut out = payload_vec_with_capacity(goaway_payload_len(
        last_accepted_bidi,
        last_accepted_uni,
        code,
        reason,
    )?)?;
    append_varint(&mut out, last_accepted_bidi)?;
    append_varint(&mut out, last_accepted_uni)?;
    append_varint(&mut out, code)?;
    append_debug_text_tlv(&mut out, reason)?;
    Ok(out)
}

fn goaway_payload_len(
    last_accepted_bidi: u64,
    last_accepted_uni: u64,
    code: u64,
    reason: &str,
) -> Result<usize> {
    let mut len = checked_len_sum3(
        varint_len(last_accepted_bidi)?,
        varint_len(last_accepted_uni)?,
        varint_len(code)?,
        "goaway payload too large",
    )?;
    if !reason.is_empty() {
        len = checked_len_add(
            len,
            debug_text_tlv_len(reason.len())?,
            "goaway payload too large",
        )?;
    }
    Ok(len)
}

pub(crate) fn build_goaway_payload_capped(
    last_accepted_bidi: u64,
    last_accepted_uni: u64,
    code: u64,
    reason: &str,
    max_payload: u64,
) -> Result<Vec<u8>> {
    let mut out = build_goaway_payload(last_accepted_bidi, last_accepted_uni, code, "")?;
    append_debug_text_tlv_capped(&mut out, reason, max_payload)?;
    Ok(out)
}

pub fn parse_goaway_payload(payload: &[u8]) -> Result<GoAwayPayload> {
    let mut off = 0usize;
    let read = |off: &mut usize| -> Result<u64> {
        let (v, n) = parse_varint(&payload[*off..])?;
        *off += n;
        Ok(v)
    };
    let last_accepted_bidi = read(&mut off)?;
    let last_accepted_uni = read(&mut off)?;
    let code = read(&mut off)?;
    let reason = parse_diag_reason(&payload[off..])?;
    Ok(GoAwayPayload {
        last_accepted_bidi,
        last_accepted_uni,
        code,
        reason,
    })
}

pub fn build_code_payload(code: u64, reason: &str, max_payload: u64) -> Result<Vec<u8>> {
    let mut out = payload_vec_with_capacity(code_payload_capacity(code, reason, max_payload)?)?;
    append_varint(&mut out, code)?;
    if usize_to_u64_len(out.len(), "error payload too large")? < max_payload {
        append_debug_text_tlv_capped(&mut out, reason, max_payload)?;
    }
    Ok(out)
}

fn code_payload_capacity(code: u64, reason: &str, max_payload: u64) -> Result<usize> {
    let code_len = varint_len(code)?;
    let code_len_u64 = usize_to_u64_len(code_len, "error payload too large")?;
    if reason.is_empty() || code_len_u64 >= max_payload {
        return Ok(code_len);
    }
    let uncapped = checked_len_add(
        code_len,
        debug_text_tlv_len(reason.len())?,
        "error payload too large",
    )?;
    Ok(match usize::try_from(max_payload) {
        Ok(max_payload) => uncapped.min(max_payload),
        Err(_) => uncapped,
    })
}

fn debug_text_tlv_len(value_len: usize) -> Result<usize> {
    usize::try_from(debug_text_tlv_len_u64(value_len)?)
        .map_err(|_| Error::frame_size("diagnostic text too large"))
}

pub fn parse_error_payload(payload: &[u8]) -> Result<(u64, String)> {
    let (code, n) = parse_varint(payload)?;
    Ok((code, parse_diag_reason(&payload[n..])?))
}

fn parse_diag_reason(payload: &[u8]) -> Result<String> {
    let mut seen_debug = false;
    let mut seen_retry = false;
    let mut seen_stream = false;
    let mut seen_frame = false;
    let mut debug_text: Option<&[u8]> = None;
    let result = (|| {
        for tlv in tlv_views(payload) {
            let tlv = tlv?;
            match tlv.typ {
                DIAG_DEBUG_TEXT => {
                    if seen_debug {
                        return Err(Error::protocol(DUPLICATE_DIAG_SINGLETON));
                    }
                    seen_debug = true;
                    debug_text = Some(tlv.value);
                }
                DIAG_RETRY_AFTER_MILLIS => {
                    if seen_retry {
                        return Err(Error::protocol(DUPLICATE_DIAG_SINGLETON));
                    }
                    seen_retry = true;
                }
                DIAG_OFFENDING_STREAM_ID => {
                    if seen_stream {
                        return Err(Error::protocol(DUPLICATE_DIAG_SINGLETON));
                    }
                    seen_stream = true;
                }
                DIAG_OFFENDING_FRAME_TYPE => {
                    if seen_frame {
                        return Err(Error::protocol(DUPLICATE_DIAG_SINGLETON));
                    }
                    seen_frame = true;
                }
                _ => {}
            }
        }
        Ok(())
    })();
    if let Err(err) = result {
        if err.is_protocol_message(DUPLICATE_DIAG_SINGLETON) {
            return Ok(String::new());
        }
        if err.is_frame_size_message("truncated tlv") {
            return Err(Error::protocol("truncated tlv"));
        }
        return Err(err);
    }
    Ok(debug_text
        .and_then(|value| str::from_utf8(value).ok())
        .unwrap_or_default()
        .to_owned())
}

fn append_debug_text_tlv(dst: &mut Vec<u8>, reason: &str) -> Result<()> {
    if reason.is_empty() {
        return Ok(());
    }
    append_tlv(dst, DIAG_DEBUG_TEXT, reason.as_bytes())
}

fn append_debug_text_tlv_capped(dst: &mut Vec<u8>, reason: &str, max_payload: u64) -> Result<()> {
    if reason.is_empty() {
        return Ok(());
    }
    let used = usize_to_u64_len(dst.len(), "diagnostic text too large")?;
    if used >= max_payload {
        return Ok(());
    }
    let value_len = capped_debug_text_value_len(reason, max_payload - used)?;
    if value_len == 0 {
        return Ok(());
    }
    append_tlv(dst, DIAG_DEBUG_TEXT, &reason.as_bytes()[..value_len])?;
    Ok(())
}

fn capped_debug_text_value_len(reason: &str, remaining: u64) -> Result<usize> {
    let typ_len = usize_to_u64_len(varint_len(DIAG_DEBUG_TEXT)?, "diagnostic text too large")?;
    if remaining <= typ_len {
        return Ok(0);
    }
    let max_payload_value_len = usize::try_from(MAX_VARINT62).unwrap_or(usize::MAX);
    let max_remaining_value_len = usize::try_from(remaining - typ_len).unwrap_or(usize::MAX);
    let mut low = 0usize;
    let mut high = reason
        .len()
        .min(max_payload_value_len)
        .min(max_remaining_value_len);
    while low < high {
        let mid = low + (high - low).div_ceil(2);
        if debug_text_tlv_len_u64(mid)? <= remaining {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    while low > 0 && !reason.is_char_boundary(low) {
        low -= 1;
    }
    Ok(low)
}

fn debug_text_tlv_len_u64(value_len: usize) -> Result<u64> {
    let value_len = usize_to_u64_len(value_len, "diagnostic text too large")?;
    let typ_len = usize_to_u64_len(varint_len(DIAG_DEBUG_TEXT)?, "diagnostic text too large")?;
    let len_len = usize_to_u64_len(varint_len(value_len)?, "diagnostic text too large")?;
    typ_len
        .checked_add(len_len)
        .and_then(|n| n.checked_add(value_len))
        .ok_or_else(|| Error::frame_size("diagnostic text too large"))
}

fn checked_len_add(lhs: usize, rhs: usize, context: &'static str) -> Result<usize> {
    lhs.checked_add(rhs)
        .ok_or_else(|| Error::frame_size(context))
}

fn checked_len_sum3(a: usize, b: usize, c: usize, context: &'static str) -> Result<usize> {
    checked_len_add(checked_len_add(a, b, context)?, c, context)
}

fn usize_to_u64_len(value: usize, context: &'static str) -> Result<u64> {
    u64::try_from(value).map_err(|_| Error::frame_size(context))
}

fn payload_vec_with_capacity(capacity: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(capacity)
        .map_err(|_| Error::local("zmux: payload allocation failed"))?;
    Ok(out)
}

fn copy_payload_slice(value: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(value.len())
        .map_err(|_| Error::local("zmux: payload allocation failed"))?;
    out.extend_from_slice(value);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        build_code_payload, build_goaway_payload_capped, build_open_metadata_prefix,
        build_priority_update_payload, normalize_stream_group, parse_data_payload,
        parse_error_payload, parse_goaway_payload, parse_priority_update_payload,
        parse_stream_metadata_tlvs, MetadataUpdate, StreamMetadata, StreamMetadataView,
    };
    use crate::error::{ErrorCode, ErrorDirection, ErrorOperation, ErrorScope, ErrorSource};
    use crate::frame::FRAME_FLAG_OPEN_METADATA;
    use crate::protocol::{
        CAPABILITY_OPEN_METADATA, CAPABILITY_PRIORITY_HINTS, CAPABILITY_PRIORITY_UPDATE,
        CAPABILITY_STREAM_GROUPS, METADATA_OPEN_INFO, METADATA_STREAM_GROUP,
        METADATA_STREAM_PRIORITY,
    };
    use crate::tlv::Tlv;
    use crate::varint::{encode_varint, parse_varint, MAX_VARINT62};

    #[test]
    fn stream_metadata_owned_open_info_uses_value_semantics() {
        let mut source = vec![4, 5, 6];
        let metadata = StreamMetadata {
            priority: Some(3),
            group: Some(11),
            open_info: source.clone(),
        };
        source[0] = 0;

        assert_eq!(metadata.open_info, vec![4, 5, 6]);

        let mut cloned = metadata.clone();
        cloned.open_info[2] = 7;
        assert_eq!(metadata.open_info, vec![4, 5, 6]);
        assert_eq!(
            metadata,
            StreamMetadata {
                priority: Some(3),
                group: Some(11),
                open_info: vec![4, 5, 6],
            }
        );
        assert_ne!(metadata, cloned);
    }

    #[test]
    fn stream_metadata_as_view_borrows_open_info_without_copying() {
        let metadata = StreamMetadata {
            priority: Some(3),
            group: Some(11),
            open_info: vec![4, 5, 6],
        };
        let view = metadata.as_view();

        assert_eq!(view.priority, Some(3));
        assert_eq!(view.group, Some(11));
        assert_eq!(view.open_info, &[4, 5, 6]);
        assert_eq!(metadata.open_info(), &[4, 5, 6]);
        assert_eq!(view.open_info(), &[4, 5, 6]);
        assert_eq!(view.open_info.as_ptr(), metadata.open_info.as_ptr());
        assert!(metadata.has_open_info());
        assert!(view.has_open_info());
        assert!(!metadata.is_empty());
        assert!(!view.is_empty());
        assert!(!StreamMetadata::default().has_open_info());
        assert!(!StreamMetadataView::default().has_open_info());
        assert!(StreamMetadata::default().is_empty());
        assert!(StreamMetadataView::default().is_empty());
    }

    #[test]
    fn stream_metadata_tlvs_round_trip_and_copy_open_info() {
        let mut tlvs = vec![
            Tlv::new(METADATA_STREAM_PRIORITY, encode_varint(7).unwrap()).unwrap(),
            Tlv::new(METADATA_STREAM_GROUP, encode_varint(11).unwrap()).unwrap(),
            Tlv::new(METADATA_OPEN_INFO, b"ssh".to_vec()).unwrap(),
        ];

        let (metadata, valid) = parse_stream_metadata_tlvs(&tlvs).unwrap();
        assert!(valid);
        assert_eq!(metadata.priority, Some(7));
        assert_eq!(metadata.group, Some(11));
        assert_eq!(metadata.open_info, b"ssh");

        tlvs[2].value[2] = b'x';
        assert_eq!(metadata.open_info, b"ssh");
    }

    #[test]
    fn stream_metadata_tlvs_duplicate_singleton_is_invalid_not_error() {
        let tlvs = vec![
            Tlv::new(METADATA_OPEN_INFO, b"a".to_vec()).unwrap(),
            Tlv::new(METADATA_OPEN_INFO, b"b".to_vec()).unwrap(),
        ];

        let (metadata, valid) = parse_stream_metadata_tlvs(&tlvs).unwrap();

        assert!(!valid);
        assert!(metadata.is_empty());
    }

    #[test]
    fn data_payload_copies_metadata_tlvs_and_open_info_independently() {
        let mut raw = build_open_metadata_prefix(
            CAPABILITY_OPEN_METADATA | CAPABILITY_PRIORITY_HINTS,
            Some(7),
            None,
            b"ssh",
            1024,
        )
        .unwrap();
        let mut payload = parse_data_payload(&raw, FRAME_FLAG_OPEN_METADATA).unwrap();
        assert!(!payload.metadata_tlvs.is_empty());
        let values = payload
            .metadata_tlvs
            .iter()
            .map(|tlv| tlv.value.clone())
            .collect::<Vec<_>>();

        raw.fill(0xff);
        assert_eq!(payload.metadata.open_info, b"ssh");
        for (tlv, value) in payload.metadata_tlvs.iter().zip(values) {
            assert_eq!(tlv.value, value);
        }

        let open_info_tlv = payload
            .metadata_tlvs
            .iter_mut()
            .find(|tlv| tlv.typ == METADATA_OPEN_INFO)
            .expect("open info tlv");
        open_info_tlv.value[0] = b'x';
        assert_eq!(payload.metadata.open_info, b"ssh");
    }

    #[test]
    fn metadata_update_builders_match_struct_literal_semantics() {
        assert!(MetadataUpdate::new().is_empty());
        assert_eq!(
            MetadataUpdate::priority(7),
            MetadataUpdate {
                priority: Some(7),
                group: None,
            }
        );
        assert_eq!(
            MetadataUpdate::group(9),
            MetadataUpdate {
                priority: None,
                group: Some(9),
            }
        );
        assert_eq!(
            MetadataUpdate::new().with_priority(7).with_group(9),
            MetadataUpdate {
                priority: Some(7),
                group: Some(9),
            }
        );
        assert!(MetadataUpdate::new()
            .try_with_priority(MAX_VARINT62)
            .unwrap()
            .try_with_group(MAX_VARINT62)
            .is_ok());
        assert!(MetadataUpdate::new()
            .try_with_priority(MAX_VARINT62 + 1)
            .is_err());
        assert!(MetadataUpdate::new()
            .with_group(MAX_VARINT62 + 1)
            .validate()
            .is_err());
    }

    #[test]
    fn metadata_update_group_zero_remains_explicit_wire_field() {
        let caps = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_STREAM_GROUPS;
        let payload = build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: None,
                group: Some(0),
            },
            64,
        )
        .unwrap();
        let (metadata, valid) = parse_priority_update_payload(&payload).unwrap();

        assert!(valid);
        assert_eq!(metadata.group, Some(0));
        assert_eq!(normalize_stream_group(metadata.group), None);
    }

    #[test]
    fn priority_update_builder_validates_capability_and_payload_limit() {
        let caps = CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS;
        let err = build_priority_update_payload(caps, MetadataUpdate::default(), 1024).unwrap_err();
        assert!(err.to_string().contains("metadata update has no fields"));

        let err = build_priority_update_payload(
            CAPABILITY_PRIORITY_HINTS,
            MetadataUpdate {
                priority: Some(7),
                group: None,
            },
            1024,
        )
        .unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert_eq!(err.scope(), ErrorScope::Session);
        assert_eq!(err.operation(), ErrorOperation::Write);
        assert_eq!(err.source(), ErrorSource::Local);
        assert_eq!(err.direction(), ErrorDirection::Write);
        assert!(err
            .to_string()
            .contains("metadata update requires negotiated priority_update"));

        let err = build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: Some(7),
                group: None,
            },
            1,
        )
        .unwrap_err();
        assert!(err
            .to_string()
            .contains("priority update exceeds peer max_extension_payload_bytes"));
    }

    #[test]
    fn priority_update_builder_round_trips_priority_and_group() {
        let caps =
            CAPABILITY_PRIORITY_UPDATE | CAPABILITY_PRIORITY_HINTS | CAPABILITY_STREAM_GROUPS;
        let payload = build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: Some(5),
                group: Some(9),
            },
            1024,
        )
        .unwrap();

        let (subtype, n) = parse_varint(&payload).unwrap();
        assert_eq!(subtype, crate::protocol::EXT_PRIORITY_UPDATE);
        assert!(n < payload.len());

        let (metadata, valid) = parse_priority_update_payload(&payload).unwrap();
        assert!(valid);
        assert_eq!(metadata.priority, Some(5));
        assert_eq!(metadata.group, Some(9));
    }

    #[test]
    fn open_metadata_builder_copies_open_info_into_encoded_prefix() {
        let mut open_info = b"ssh".to_vec();
        let prefix =
            build_open_metadata_prefix(CAPABILITY_OPEN_METADATA, None, None, &open_info, 1024)
                .unwrap();

        open_info[0] = b'x';
        let payload = parse_data_payload(&prefix, FRAME_FLAG_OPEN_METADATA).unwrap();

        assert_eq!(payload.metadata.open_info, b"ssh");
    }

    #[test]
    fn open_metadata_builder_validates_capability_and_payload_limit() {
        let err = build_open_metadata_prefix(0, None, None, b"ssh", 1024).unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert_eq!(err.scope(), ErrorScope::Stream);
        assert_eq!(err.operation(), ErrorOperation::Open);
        assert_eq!(err.source(), ErrorSource::Local);
        assert_eq!(err.direction(), ErrorDirection::Write);
        assert!(err
            .to_string()
            .contains("open_info requires negotiated open_metadata"));

        let err = build_open_metadata_prefix(CAPABILITY_OPEN_METADATA, None, None, b"ssh", 1)
            .unwrap_err();
        assert_eq!(err.code(), Some(ErrorCode::Protocol));
        assert_eq!(err.scope(), ErrorScope::Stream);
        assert_eq!(err.operation(), ErrorOperation::Open);
        assert_eq!(err.source(), ErrorSource::Local);
        assert_eq!(err.direction(), ErrorDirection::Write);
        assert!(err
            .to_string()
            .contains("opening metadata exceeds peer max_frame_payload"));
    }

    #[test]
    fn metadata_wire_builders_reject_varint62_overflow_values() {
        let caps = CAPABILITY_OPEN_METADATA
            | CAPABILITY_PRIORITY_HINTS
            | CAPABILITY_STREAM_GROUPS
            | CAPABILITY_PRIORITY_UPDATE;
        let too_large = MAX_VARINT62 + 1;

        assert!(build_open_metadata_prefix(caps, Some(too_large), None, &[], 1024).is_err());
        assert!(build_open_metadata_prefix(caps, None, Some(too_large), &[], 1024).is_err());
        assert!(build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: Some(too_large),
                group: None,
            },
            1024,
        )
        .is_err());
        assert!(build_priority_update_payload(
            caps,
            MetadataUpdate {
                priority: None,
                group: Some(too_large),
            },
            1024,
        )
        .is_err());
    }

    #[test]
    fn capped_error_payload_omits_reason_when_cap_is_zero() {
        let payload = build_code_payload(7, "reason", 0).unwrap();
        let (code, reason) = parse_error_payload(&payload).unwrap();
        assert_eq!(code, 7);
        assert_eq!(reason, "");
    }

    #[test]
    fn capped_goaway_payload_omits_reason_when_cap_is_zero() {
        let payload = build_goaway_payload_capped(4, 8, 7, "reason", 0).unwrap();
        let parsed = parse_goaway_payload(&payload).unwrap();
        assert_eq!(parsed.code, 7);
        assert_eq!(parsed.reason, "");
    }

    #[test]
    fn capped_error_payload_accounts_for_length_varint_growth() {
        let reason = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
        let payload = build_code_payload(ErrorCode::Internal.as_u64(), reason, 66).unwrap();
        let (code, parsed) = parse_error_payload(&payload).unwrap();

        assert_eq!(code, ErrorCode::Internal.as_u64());
        assert_eq!(parsed.len(), 63);
        assert_eq!(parsed, reason[..63]);
        assert_eq!(payload.len(), 66);
    }

    #[test]
    fn capped_error_payload_trims_to_utf8_boundary() {
        let payload = build_code_payload(ErrorCode::Internal.as_u64(), "€€", 7).unwrap();
        let (code, parsed) = parse_error_payload(&payload).unwrap();

        assert_eq!(code, ErrorCode::Internal.as_u64());
        assert_eq!(parsed, "€");
        assert!(payload.len() <= 7);
    }

    #[test]
    fn capped_error_payload_skips_reason_when_no_tlv_room() {
        let payload = build_code_payload(ErrorCode::Internal.as_u64(), "x", 2).unwrap();
        let (code, parsed) = parse_error_payload(&payload).unwrap();

        assert_eq!(code, ErrorCode::Internal.as_u64());
        assert_eq!(parsed, "");
        assert_eq!(payload.len(), 1);
    }
}
