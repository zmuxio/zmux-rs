use crate::error::{Error, Result};
use crate::event::EventHandler;
use crate::preface::Preface;
use crate::protocol::{Role, PREFACE_VERSION, PROTO_VERSION};
use crate::settings::Settings;
use crate::varint::{varint_len, MAX_VARINT62};
use std::borrow::Cow;
use std::fmt;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

pub const DEFAULT_WRITE_QUEUE_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const DEFAULT_WRITE_BATCH_MAX_FRAMES: usize = 32;
pub const DEFAULT_URGENT_QUEUE_MAX_BYTES_FLOOR: usize = 64 * 1024;
pub const DEFAULT_PENDING_CONTROL_BYTES_BUDGET_FLOOR: usize = 64 * 1024;
pub const DEFAULT_PENDING_PRIORITY_BYTES_BUDGET_FLOOR: usize = 64 * 1024;
pub const DEFAULT_PER_STREAM_QUEUED_DATA_HIGH_WATERMARK_FLOOR: usize = 256 * 1024;
pub const DEFAULT_SESSION_QUEUED_DATA_HIGH_WATERMARK_FLOOR: usize = 4 * 1024 * 1024;
pub const DEFAULT_MAX_PROVISIONAL_STREAMS_BIDI: usize = 64;
pub const DEFAULT_MAX_PROVISIONAL_STREAMS_UNI: usize = 64;
pub const DEFAULT_TOMBSTONE_LIMIT: usize = 4096;
pub const DEFAULT_USED_MARKER_LIMIT: usize = 16_384;
pub const DEFAULT_LATE_DATA_AGGREGATE_CAP_FLOOR: u64 = 64 * 1024;
pub const DEFAULT_LATE_DATA_PER_STREAM_CAP_FLOOR: u64 = 1024;
pub const DEFAULT_IGNORED_CONTROL_BUDGET: u64 = 128;
pub const DEFAULT_NO_OP_ZERO_DATA_BUDGET: u64 = 128;
pub const DEFAULT_INBOUND_PING_BUDGET: u64 = 128;
pub const DEFAULT_NO_OP_MAX_DATA_BUDGET: u64 = 128;
pub const DEFAULT_NO_OP_BLOCKED_BUDGET: u64 = 128;
pub const DEFAULT_NO_OP_PRIORITY_UPDATE_BUDGET: u64 = 128;
pub const DEFAULT_ABUSE_WINDOW: Duration = Duration::from_secs(5);
pub const DEFAULT_INBOUND_CONTROL_FRAME_BUDGET: u64 = 2048;
pub const DEFAULT_INBOUND_EXT_FRAME_BUDGET: u64 = 1024;
pub const DEFAULT_INBOUND_CONTROL_BYTES_BUDGET_FLOOR: usize = 256 * 1024;
pub const DEFAULT_INBOUND_EXT_BYTES_BUDGET_FLOOR: usize = 256 * 1024;
pub const DEFAULT_GROUP_REBUCKET_CHURN_BUDGET: u64 = 256;
pub const DEFAULT_HIDDEN_ABORT_CHURN_WINDOW: Duration = Duration::from_secs(1);
pub const DEFAULT_HIDDEN_ABORT_CHURN_BUDGET: u64 = 128;
pub const DEFAULT_VISIBLE_TERMINAL_CHURN_WINDOW: Duration = Duration::from_secs(1);
pub const DEFAULT_VISIBLE_TERMINAL_CHURN_BUDGET: u64 = 128;
pub const DEFAULT_CLOSE_DRAIN_TIMEOUT: Duration = Duration::from_millis(500);
pub const DEFAULT_GO_AWAY_DRAIN_INTERVAL: Duration = Duration::from_millis(10);
pub const DEFAULT_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(60);
pub const DEFAULT_KEEPALIVE_MAX_PING_INTERVAL: Duration = Duration::from_secs(5 * 60);
pub const DEFAULT_KEEPALIVE_TIMEOUT: Duration = Duration::from_millis(0);
pub const DEFAULT_PREFACE_PADDING_MIN_BYTES: u64 = 16;
pub const DEFAULT_PREFACE_PADDING_MAX_BYTES: u64 = 256;
pub const DEFAULT_PING_PADDING_MIN_BYTES: u64 = 16;
pub const DEFAULT_PING_PADDING_MAX_BYTES: u64 = 64;
pub const DEFAULT_ACCEPT_BACKLOG_LIMIT: usize = 128;
pub const DEFAULT_ACCEPT_BACKLOG_BYTES_FLOOR: usize = 4 * 1024 * 1024;
pub const DEFAULT_ACCEPT_BACKLOG_PER_STREAM_BYTES_FLOOR: usize = 256 * 1024;
pub const DEFAULT_ACCEPT_BACKLOG_PER_STREAM_FRAMES: usize = 16;
pub const DEFAULT_ACCEPT_BACKLOG_SESSION_FACTOR: usize = 4;
pub const DEFAULT_RETAINED_OPEN_INFO_BYTES_BUDGET: usize = 64 * 1024;
pub const DEFAULT_RETAINED_PEER_REASON_BYTES_BUDGET: usize = 64 * 1024;
pub const DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW: Duration = Duration::from_millis(100);
pub const DEFAULT_STOP_SENDING_GRACEFUL_DRAIN_WINDOW_MAX: Duration = Duration::from_secs(2);
pub const DEFAULT_SESSION_MEMORY_HARD_CAP_FLOOR: usize = 8 * 1024 * 1024;

#[derive(Clone)]
pub struct Config {
    pub role: Role,
    pub tie_breaker_nonce: u64,
    pub min_proto: u64,
    pub max_proto: u64,
    pub capabilities: u64,
    pub settings: Settings,
    pub preface_padding: bool,
    pub preface_padding_min_bytes: u64,
    pub preface_padding_max_bytes: u64,
    pub ping_padding: bool,
    pub ping_padding_min_bytes: u64,
    pub ping_padding_max_bytes: u64,
    pub write_queue_max_bytes: usize,
    pub session_memory_cap: Option<usize>,
    pub urgent_queue_max_bytes: Option<usize>,
    pub per_stream_queued_data_high_watermark: Option<usize>,
    pub session_queued_data_high_watermark: Option<usize>,
    pub pending_control_bytes_budget: Option<usize>,
    pub pending_priority_bytes_budget: Option<usize>,
    pub write_batch_max_frames: usize,
    pub max_provisional_streams_bidi: usize,
    pub max_provisional_streams_uni: usize,
    pub tombstone_limit: usize,
    pub hidden_control_opened_limit: Option<usize>,
    pub marker_only_used_stream_limit: Option<usize>,
    pub used_marker_limit: usize,
    pub late_data_per_stream_cap: Option<u64>,
    pub late_data_aggregate_cap: Option<u64>,
    pub ignored_control_budget: u64,
    pub no_op_zero_data_budget: u64,
    pub inbound_ping_budget: u64,
    pub no_op_max_data_budget: u64,
    pub no_op_blocked_budget: u64,
    pub no_op_priority_update_budget: u64,
    pub abuse_window: Duration,
    pub inbound_control_frame_budget: u64,
    pub inbound_control_bytes_budget: Option<usize>,
    pub inbound_ext_frame_budget: u64,
    pub inbound_ext_bytes_budget: Option<usize>,
    pub inbound_mixed_frame_budget: Option<u64>,
    pub inbound_mixed_bytes_budget: Option<usize>,
    pub group_rebucket_churn_budget: u64,
    pub hidden_abort_churn_window: Duration,
    pub hidden_abort_churn_budget: u64,
    pub visible_terminal_churn_window: Duration,
    pub visible_terminal_churn_budget: u64,
    pub close_drain_timeout: Duration,
    pub go_away_drain_interval: Duration,
    pub stop_sending_graceful_drain_window: Option<Duration>,
    pub stop_sending_graceful_tail_cap: Option<u64>,
    pub keepalive_interval: Duration,
    pub keepalive_max_ping_interval: Duration,
    pub keepalive_timeout: Duration,
    pub accept_backlog_limit: Option<usize>,
    pub accept_backlog_bytes_limit: Option<usize>,
    pub retained_open_info_bytes_budget: Option<usize>,
    pub retained_peer_reason_bytes_budget: Option<usize>,
    pub event_handler: Option<EventHandler>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("role", &self.role)
            .field("tie_breaker_nonce", &self.tie_breaker_nonce)
            .field("min_proto", &self.min_proto)
            .field("max_proto", &self.max_proto)
            .field("capabilities", &self.capabilities)
            .field("settings", &self.settings)
            .field("preface_padding", &self.preface_padding)
            .field("preface_padding_min_bytes", &self.preface_padding_min_bytes)
            .field("preface_padding_max_bytes", &self.preface_padding_max_bytes)
            .field("ping_padding", &self.ping_padding)
            .field("ping_padding_min_bytes", &self.ping_padding_min_bytes)
            .field("ping_padding_max_bytes", &self.ping_padding_max_bytes)
            .field("write_queue_max_bytes", &self.write_queue_max_bytes)
            .field("session_memory_cap", &self.session_memory_cap)
            .field("urgent_queue_max_bytes", &self.urgent_queue_max_bytes)
            .field(
                "per_stream_queued_data_high_watermark",
                &self.per_stream_queued_data_high_watermark,
            )
            .field(
                "session_queued_data_high_watermark",
                &self.session_queued_data_high_watermark,
            )
            .field(
                "pending_control_bytes_budget",
                &self.pending_control_bytes_budget,
            )
            .field(
                "pending_priority_bytes_budget",
                &self.pending_priority_bytes_budget,
            )
            .field("write_batch_max_frames", &self.write_batch_max_frames)
            .field(
                "max_provisional_streams_bidi",
                &self.max_provisional_streams_bidi,
            )
            .field(
                "max_provisional_streams_uni",
                &self.max_provisional_streams_uni,
            )
            .field("tombstone_limit", &self.tombstone_limit)
            .field(
                "hidden_control_opened_limit",
                &self.hidden_control_opened_limit,
            )
            .field(
                "marker_only_used_stream_limit",
                &self.marker_only_used_stream_limit,
            )
            .field("used_marker_limit", &self.used_marker_limit)
            .field("late_data_per_stream_cap", &self.late_data_per_stream_cap)
            .field("late_data_aggregate_cap", &self.late_data_aggregate_cap)
            .field("ignored_control_budget", &self.ignored_control_budget)
            .field("no_op_zero_data_budget", &self.no_op_zero_data_budget)
            .field("inbound_ping_budget", &self.inbound_ping_budget)
            .field("no_op_max_data_budget", &self.no_op_max_data_budget)
            .field("no_op_blocked_budget", &self.no_op_blocked_budget)
            .field(
                "no_op_priority_update_budget",
                &self.no_op_priority_update_budget,
            )
            .field("abuse_window", &self.abuse_window)
            .field(
                "inbound_control_frame_budget",
                &self.inbound_control_frame_budget,
            )
            .field(
                "inbound_control_bytes_budget",
                &self.inbound_control_bytes_budget,
            )
            .field("inbound_ext_frame_budget", &self.inbound_ext_frame_budget)
            .field("inbound_ext_bytes_budget", &self.inbound_ext_bytes_budget)
            .field(
                "inbound_mixed_frame_budget",
                &self.inbound_mixed_frame_budget,
            )
            .field(
                "inbound_mixed_bytes_budget",
                &self.inbound_mixed_bytes_budget,
            )
            .field(
                "group_rebucket_churn_budget",
                &self.group_rebucket_churn_budget,
            )
            .field("hidden_abort_churn_window", &self.hidden_abort_churn_window)
            .field("hidden_abort_churn_budget", &self.hidden_abort_churn_budget)
            .field(
                "visible_terminal_churn_window",
                &self.visible_terminal_churn_window,
            )
            .field(
                "visible_terminal_churn_budget",
                &self.visible_terminal_churn_budget,
            )
            .field("close_drain_timeout", &self.close_drain_timeout)
            .field("go_away_drain_interval", &self.go_away_drain_interval)
            .field(
                "stop_sending_graceful_drain_window",
                &self.stop_sending_graceful_drain_window,
            )
            .field(
                "stop_sending_graceful_tail_cap",
                &self.stop_sending_graceful_tail_cap,
            )
            .field("keepalive_interval", &self.keepalive_interval)
            .field(
                "keepalive_max_ping_interval",
                &self.keepalive_max_ping_interval,
            )
            .field("keepalive_timeout", &self.keepalive_timeout)
            .field("accept_backlog_limit", &self.accept_backlog_limit)
            .field(
                "accept_backlog_bytes_limit",
                &self.accept_backlog_bytes_limit,
            )
            .field(
                "retained_open_info_bytes_budget",
                &self.retained_open_info_bytes_budget,
            )
            .field(
                "retained_peer_reason_bytes_budget",
                &self.retained_peer_reason_bytes_budget,
            )
            .field("event_handler", &self.event_handler.is_some())
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        default_config()
    }
}

static DEFAULT_CONFIG_TEMPLATE: OnceLock<RwLock<Config>> = OnceLock::new();

fn default_config_template() -> &'static RwLock<Config> {
    DEFAULT_CONFIG_TEMPLATE.get_or_init(|| RwLock::new(builtin_default_config()))
}

/// Return a copy of the process-wide default configuration template.
pub fn default_config() -> Config {
    default_config_template()
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Mutate the process-wide default configuration template.
///
/// Call this during process initialization before creating sessions. Existing
/// sessions are not affected. Concurrent calls are race-safe, but the last
/// completed update wins. Per-session random fields are cleared after the
/// closure returns so later sessions can generate fresh values.
pub fn configure_default_config(update: impl FnOnce(&mut Config)) {
    let mut next = default_config();
    update(&mut next);
    next = sanitize_default_config_template(next);

    let mut template = default_config_template()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *template = next;
}

/// Restore the built-in process-wide default configuration template.
pub fn reset_default_config() {
    let mut template = default_config_template()
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *template = builtin_default_config();
}

fn builtin_default_config() -> Config {
    Config {
        role: Role::Auto,
        tie_breaker_nonce: 0,
        min_proto: PROTO_VERSION,
        max_proto: PROTO_VERSION,
        capabilities: 0,
        settings: Settings::DEFAULT,
        preface_padding: false,
        preface_padding_min_bytes: DEFAULT_PREFACE_PADDING_MIN_BYTES,
        preface_padding_max_bytes: DEFAULT_PREFACE_PADDING_MAX_BYTES,
        ping_padding: false,
        ping_padding_min_bytes: DEFAULT_PING_PADDING_MIN_BYTES,
        ping_padding_max_bytes: DEFAULT_PING_PADDING_MAX_BYTES,
        write_queue_max_bytes: DEFAULT_WRITE_QUEUE_MAX_BYTES,
        session_memory_cap: None,
        urgent_queue_max_bytes: None,
        per_stream_queued_data_high_watermark: None,
        session_queued_data_high_watermark: None,
        pending_control_bytes_budget: None,
        pending_priority_bytes_budget: None,
        write_batch_max_frames: DEFAULT_WRITE_BATCH_MAX_FRAMES,
        max_provisional_streams_bidi: DEFAULT_MAX_PROVISIONAL_STREAMS_BIDI,
        max_provisional_streams_uni: DEFAULT_MAX_PROVISIONAL_STREAMS_UNI,
        tombstone_limit: DEFAULT_TOMBSTONE_LIMIT,
        hidden_control_opened_limit: None,
        marker_only_used_stream_limit: None,
        used_marker_limit: DEFAULT_USED_MARKER_LIMIT,
        late_data_per_stream_cap: None,
        late_data_aggregate_cap: None,
        ignored_control_budget: DEFAULT_IGNORED_CONTROL_BUDGET,
        no_op_zero_data_budget: DEFAULT_NO_OP_ZERO_DATA_BUDGET,
        inbound_ping_budget: DEFAULT_INBOUND_PING_BUDGET,
        no_op_max_data_budget: DEFAULT_NO_OP_MAX_DATA_BUDGET,
        no_op_blocked_budget: DEFAULT_NO_OP_BLOCKED_BUDGET,
        no_op_priority_update_budget: DEFAULT_NO_OP_PRIORITY_UPDATE_BUDGET,
        abuse_window: DEFAULT_ABUSE_WINDOW,
        inbound_control_frame_budget: DEFAULT_INBOUND_CONTROL_FRAME_BUDGET,
        inbound_control_bytes_budget: None,
        inbound_ext_frame_budget: DEFAULT_INBOUND_EXT_FRAME_BUDGET,
        inbound_ext_bytes_budget: None,
        inbound_mixed_frame_budget: None,
        inbound_mixed_bytes_budget: None,
        group_rebucket_churn_budget: DEFAULT_GROUP_REBUCKET_CHURN_BUDGET,
        hidden_abort_churn_window: DEFAULT_HIDDEN_ABORT_CHURN_WINDOW,
        hidden_abort_churn_budget: DEFAULT_HIDDEN_ABORT_CHURN_BUDGET,
        visible_terminal_churn_window: DEFAULT_VISIBLE_TERMINAL_CHURN_WINDOW,
        visible_terminal_churn_budget: DEFAULT_VISIBLE_TERMINAL_CHURN_BUDGET,
        close_drain_timeout: DEFAULT_CLOSE_DRAIN_TIMEOUT,
        go_away_drain_interval: DEFAULT_GO_AWAY_DRAIN_INTERVAL,
        stop_sending_graceful_drain_window: None,
        stop_sending_graceful_tail_cap: None,
        keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
        keepalive_max_ping_interval: DEFAULT_KEEPALIVE_MAX_PING_INTERVAL,
        keepalive_timeout: DEFAULT_KEEPALIVE_TIMEOUT,
        accept_backlog_limit: None,
        accept_backlog_bytes_limit: None,
        retained_open_info_bytes_budget: None,
        retained_peer_reason_bytes_budget: None,
        event_handler: None,
    }
}

fn sanitize_default_config_template(mut config: Config) -> Config {
    config.min_proto = nonzero_or_default(config.min_proto, PROTO_VERSION);
    config.max_proto = nonzero_or_default(config.max_proto, PROTO_VERSION);
    if config.settings == ZERO_SETTINGS {
        config.settings = Settings::DEFAULT;
    } else {
        normalize_settings_payload_limits(&mut config.settings);
    }
    config.tie_breaker_nonce = 0;
    config.settings.ping_padding_key = 0;
    config
}

const ZERO_SETTINGS: Settings = Settings {
    initial_max_stream_data_bidi_locally_opened: 0,
    initial_max_stream_data_bidi_peer_opened: 0,
    initial_max_stream_data_uni: 0,
    initial_max_data: 0,
    max_incoming_streams_bidi: 0,
    max_incoming_streams_uni: 0,
    max_frame_payload: 0,
    idle_timeout_millis: 0,
    keepalive_hint_millis: 0,
    max_control_payload_bytes: 0,
    max_extension_payload_bytes: 0,
    scheduler_hints: crate::settings::SchedulerHint::UnspecifiedOrBalanced,
    ping_padding_key: 0,
};

pub(crate) fn default_accept_backlog_bytes_limit(max_frame_payload: u64) -> usize {
    let max_frame_payload = max_frame_payload.min(usize::MAX as u64) as usize;
    let per_stream = max_frame_payload
        .saturating_mul(DEFAULT_ACCEPT_BACKLOG_PER_STREAM_FRAMES)
        .max(DEFAULT_ACCEPT_BACKLOG_PER_STREAM_BYTES_FLOOR);
    per_stream
        .saturating_mul(DEFAULT_ACCEPT_BACKLOG_SESSION_FACTOR)
        .max(DEFAULT_ACCEPT_BACKLOG_BYTES_FLOOR)
}

pub(crate) fn default_late_data_aggregate_cap(max_frame_payload: u64) -> u64 {
    DEFAULT_LATE_DATA_AGGREGATE_CAP_FLOOR.max(max_frame_payload.saturating_mul(4))
}

impl Config {
    #[must_use]
    pub fn initiator() -> Self {
        Self {
            role: Role::Initiator,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn responder() -> Self {
        Self {
            role: Role::Responder,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn role(mut self, role: Role) -> Self {
        self.role = role;
        if role != Role::Auto {
            self.tie_breaker_nonce = 0;
        }
        self
    }

    #[must_use]
    pub fn capabilities(mut self, capabilities: u64) -> Self {
        self.capabilities = capabilities;
        self
    }

    #[must_use]
    pub fn enable_capabilities(mut self, capabilities: u64) -> Self {
        self.capabilities |= capabilities;
        self
    }

    #[must_use]
    pub fn settings(mut self, settings: Settings) -> Self {
        self.settings = settings;
        self
    }

    #[must_use]
    pub fn event_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(crate::event::Event) + Send + Sync + 'static,
    {
        self.event_handler = Some(std::sync::Arc::new(handler));
        self
    }

    pub fn normalized(&self) -> Result<Self> {
        let mut cfg = self.clone();
        if cfg.tie_breaker_nonce > MAX_VARINT62 {
            return Err(Error::protocol(
                "zmux config tie_breaker_nonce exceeds varint62",
            ));
        }
        if cfg.capabilities > MAX_VARINT62 {
            return Err(Error::protocol("zmux config capabilities exceeds varint62"));
        }
        cfg.min_proto = normalize_protocol_version(cfg.min_proto, "min_proto")?;
        cfg.max_proto = normalize_protocol_version(cfg.max_proto, "max_proto")?;
        if cfg.min_proto > cfg.max_proto {
            return Err(Error::protocol(
                "zmux config min_proto must be <= max_proto",
            ));
        }
        if !cfg.ping_padding {
            cfg.settings.ping_padding_key = 0;
        }
        cfg.settings = normalize_config_settings(cfg.settings)?;
        Ok(cfg)
    }

    pub fn local_preface(&self) -> Result<Preface> {
        let mut cfg = self.normalized()?;
        match cfg.role {
            Role::Auto if cfg.tie_breaker_nonce == 0 => {
                cfg.tie_breaker_nonce = random_varint62()?;
            }
            Role::Auto => {}
            _ => cfg.tie_breaker_nonce = 0,
        }
        if cfg.ping_padding && cfg.settings.ping_padding_key == 0 {
            cfg.settings.ping_padding_key = random_varint62()?;
        }
        Ok(Preface {
            preface_version: PREFACE_VERSION,
            role: cfg.role,
            tie_breaker_nonce: cfg.tie_breaker_nonce,
            min_proto: cfg.min_proto,
            max_proto: cfg.max_proto,
            capabilities: cfg.capabilities,
            settings: cfg.settings,
        })
    }

    pub(crate) fn local_preface_payload(&self, local: &Preface) -> Result<Vec<u8>> {
        if !self.preface_padding {
            return local.marshal();
        }
        let padding = random_preface_padding(
            local.settings,
            self.preface_padding_min_bytes,
            self.preface_padding_max_bytes,
        )?;
        local.marshal_with_settings_padding(&padding)
    }
}

/// Options used when opening a stream.
///
/// `open_info` is opaque application metadata carried as bytes. ZMux does not
/// interpret it as text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OpenOptions {
    initial_priority: Option<u64>,
    initial_group: Option<u64>,
    open_info: Vec<u8>,
}

impl OpenOptions {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the initial peer-visible priority hint for the opened stream.
    #[must_use]
    pub fn priority(mut self, priority: u64) -> Self {
        self.initial_priority = Some(priority);
        self
    }

    /// Set the initial peer-visible stream group hint for the opened stream.
    #[must_use]
    pub fn group(mut self, group: u64) -> Self {
        self.initial_group = Some(group);
        self
    }

    /// Set opaque binary metadata sent with the stream open.
    ///
    /// Borrowed bytes are copied into the request options; owned `Vec<u8>` or
    /// `Cow::Owned` values are moved in without another copy.
    #[must_use]
    pub fn open_info<'a>(mut self, open_info: impl Into<Cow<'a, [u8]>>) -> Self {
        self.open_info = open_info.into().into_owned();
        self
    }

    pub fn initial_priority(&self) -> Option<u64> {
        self.initial_priority
    }

    pub fn initial_group(&self) -> Option<u64> {
        self.initial_group
    }

    /// Return the opaque binary metadata sent with the stream open.
    pub fn open_info_bytes(&self) -> &[u8] {
        &self.open_info
    }

    pub fn open_info_len(&self) -> usize {
        self.open_info.len()
    }

    pub fn has_open_info(&self) -> bool {
        !self.open_info.is_empty()
    }

    pub fn is_empty(&self) -> bool {
        self.initial_priority.is_none() && self.initial_group.is_none() && self.open_info.is_empty()
    }

    pub fn validate(&self) -> Result<()> {
        if let Some(priority) = self.initial_priority {
            validate_open_option_varint(priority, "initial_priority")?;
        }
        if let Some(group) = self.initial_group {
            validate_open_option_varint(group, "initial_group")?;
        }
        Ok(())
    }

    pub fn into_parts(self) -> (Option<u64>, Option<u64>, Vec<u8>) {
        (self.initial_priority, self.initial_group, self.open_info)
    }
}

fn validate_open_option_varint(value: u64, field: &str) -> Result<()> {
    if value > MAX_VARINT62 {
        return Err(Error::protocol(format!(
            "zmux open options {field} exceeds varint62"
        )));
    }
    Ok(())
}

fn random_varint62() -> Result<u64> {
    loop {
        let value = random_uint62()?;
        if value != 0 {
            return Ok(value);
        }
    }
}

fn random_uint62() -> Result<u64> {
    let mut bytes = [0u8; 8];
    fill_random(&mut bytes)?;
    Ok(u64::from_le_bytes(bytes) & MAX_VARINT62)
}

fn random_uint64n(n: u64) -> Result<u64> {
    if n <= 1 {
        return Ok(0);
    }
    if n > MAX_VARINT62 + 1 {
        return Err(Error::protocol(format!(
            "zmux random range {n} exceeds 62-bit source range"
        )));
    }
    let limit = (MAX_VARINT62 + 1) / n * n;
    loop {
        let v = random_uint62()?;
        if v < limit {
            return Ok(v % n);
        }
    }
}

fn fill_random(dst: &mut [u8]) -> Result<()> {
    getrandom::fill(dst)
        .map_err(|err| Error::local(format!("zmux: secure random source failed: {err}")))
}

fn random_preface_padding(
    settings: Settings,
    configured_min: u64,
    configured_max: u64,
) -> Result<Vec<u8>> {
    let max_payload = max_preface_padding_payload_bytes(settings, configured_max)?;
    if max_payload == 0 {
        return Ok(Vec::new());
    }
    let min_payload =
        nonzero_or_default(configured_min, DEFAULT_PREFACE_PADDING_MIN_BYTES).min(max_payload);
    let span = max_payload - min_payload + 1;
    let padding_len = min_payload + random_uint64n(span)?;
    let padding_len = u64_to_usize_len(padding_len, "preface padding too large")?;
    let mut padding = vec![0u8; padding_len];
    fill_random(&mut padding)?;
    Ok(padding)
}

fn max_preface_padding_payload_bytes(settings: Settings, configured_max: u64) -> Result<u64> {
    let settings_len = usize_to_u64_len(settings.encoded_tlv_len()?, "preface settings too large")?;
    if settings_len >= crate::protocol::MAX_PREFACE_SETTINGS_BYTES {
        return Ok(0);
    }

    let remaining = crate::protocol::MAX_PREFACE_SETTINGS_BYTES - settings_len;
    let mut max_payload = configured_max;
    if max_payload == 0 {
        max_payload = DEFAULT_PREFACE_PADDING_MAX_BYTES;
    }
    max_payload = max_payload.min(remaining);

    let type_len = usize_to_u64_len(
        varint_len(crate::protocol::SETTING_PREFACE_PADDING)?,
        "preface padding too large",
    )?;
    let mut low = 0;
    let mut high = max_payload;
    while low < high {
        let candidate = low + (high - low).div_ceil(2);
        let len_len = usize_to_u64_len(varint_len(candidate)?, "preface padding too large")?;
        let overhead = type_len + len_len;
        if overhead <= remaining && candidate <= remaining - overhead {
            low = candidate;
        } else {
            high = candidate - 1;
        }
    }
    Ok(low)
}

fn normalize_protocol_version(value: u64, field: &str) -> Result<u64> {
    let value = nonzero_or_default(value, PROTO_VERSION);
    if value > MAX_VARINT62 {
        return Err(Error::protocol(format!(
            "zmux config {field} exceeds varint62"
        )));
    }
    Ok(value)
}

fn normalize_config_settings(mut settings: Settings) -> Result<Settings> {
    validate_settings(settings)?;
    if settings == ZERO_SETTINGS {
        return Ok(Settings::DEFAULT);
    }
    normalize_settings_payload_limits(&mut settings);
    Ok(settings)
}

#[inline]
fn normalize_settings_payload_limits(settings: &mut Settings) {
    let defaults = Settings::DEFAULT;
    settings.max_frame_payload =
        nonzero_or_default(settings.max_frame_payload, defaults.max_frame_payload);
    settings.max_control_payload_bytes = nonzero_or_default(
        settings.max_control_payload_bytes,
        defaults.max_control_payload_bytes,
    );
    settings.max_extension_payload_bytes = nonzero_or_default(
        settings.max_extension_payload_bytes,
        defaults.max_extension_payload_bytes,
    );
}

#[inline]
fn nonzero_or_default(value: u64, default: u64) -> u64 {
    if value == 0 {
        default
    } else {
        value
    }
}

fn validate_settings(settings: Settings) -> Result<()> {
    let fields = [
        (
            "initial_max_stream_data_bidi_locally_opened",
            settings.initial_max_stream_data_bidi_locally_opened,
        ),
        (
            "initial_max_stream_data_bidi_peer_opened",
            settings.initial_max_stream_data_bidi_peer_opened,
        ),
        (
            "initial_max_stream_data_uni",
            settings.initial_max_stream_data_uni,
        ),
        ("initial_max_data", settings.initial_max_data),
        (
            "max_incoming_streams_bidi",
            settings.max_incoming_streams_bidi,
        ),
        (
            "max_incoming_streams_uni",
            settings.max_incoming_streams_uni,
        ),
        ("max_frame_payload", settings.max_frame_payload),
        ("idle_timeout_millis", settings.idle_timeout_millis),
        ("keepalive_hint_millis", settings.keepalive_hint_millis),
        (
            "max_control_payload_bytes",
            settings.max_control_payload_bytes,
        ),
        (
            "max_extension_payload_bytes",
            settings.max_extension_payload_bytes,
        ),
        ("ping_padding_key", settings.ping_padding_key),
    ];
    for (field, value) in fields {
        if value > MAX_VARINT62 {
            return Err(Error::protocol(format!(
                "zmux settings {field} exceeds varint62"
            )));
        }
    }
    Ok(())
}

fn usize_to_u64_len(value: usize, context: &'static str) -> Result<u64> {
    if value > u64::MAX as usize {
        Err(Error::frame_size(context))
    } else {
        Ok(value as u64)
    }
}

fn u64_to_usize_len(value: u64, context: &'static str) -> Result<usize> {
    if value > usize::MAX as u64 {
        Err(Error::frame_size(context))
    } else {
        Ok(value as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventHandler;
    use crate::settings::{SchedulerHint, Settings};
    use std::sync::Arc;

    fn sample_config() -> Config {
        let handler: EventHandler = Arc::new(|_| {});
        Config {
            role: Role::Responder,
            tie_breaker_nonce: 123_456_789,
            min_proto: 1,
            max_proto: 2,
            capabilities: 0x55aa,
            settings: Settings {
                initial_max_data: 777_777,
                max_incoming_streams_bidi: 17,
                max_incoming_streams_uni: 19,
                max_frame_payload: 32_768,
                idle_timeout_millis: 9_000,
                keepalive_hint_millis: 1_500,
                max_control_payload_bytes: 8_192,
                max_extension_payload_bytes: 8_192,
                scheduler_hints: SchedulerHint::Latency,
                ping_padding_key: 123,
                ..Settings::DEFAULT
            },
            preface_padding: true,
            preface_padding_min_bytes: 3,
            preface_padding_max_bytes: 9,
            ping_padding: true,
            ping_padding_min_bytes: 5,
            ping_padding_max_bytes: 13,
            write_queue_max_bytes: 10_240,
            session_memory_cap: Some(9_999),
            urgent_queue_max_bytes: Some(3_333),
            per_stream_queued_data_high_watermark: Some(1_111),
            session_queued_data_high_watermark: Some(2_222),
            pending_control_bytes_budget: Some(4_444),
            pending_priority_bytes_budget: Some(5_555),
            write_batch_max_frames: 7,
            max_provisional_streams_bidi: 11,
            max_provisional_streams_uni: 13,
            tombstone_limit: 71,
            hidden_control_opened_limit: Some(31),
            marker_only_used_stream_limit: Some(73),
            used_marker_limit: 79,
            late_data_per_stream_cap: Some(1_313),
            late_data_aggregate_cap: Some(13_131),
            ignored_control_budget: 37,
            no_op_zero_data_budget: 47,
            inbound_ping_budget: 61,
            no_op_max_data_budget: 41,
            no_op_blocked_budget: 43,
            no_op_priority_update_budget: 53,
            abuse_window: Duration::from_secs(7),
            inbound_control_frame_budget: 23,
            inbound_control_bytes_budget: Some(7_777),
            inbound_ext_frame_budget: 29,
            inbound_ext_bytes_budget: Some(8_888),
            inbound_mixed_frame_budget: Some(31),
            inbound_mixed_bytes_budget: Some(9_999),
            group_rebucket_churn_budget: 59,
            hidden_abort_churn_window: Duration::from_millis(555),
            hidden_abort_churn_budget: 13,
            visible_terminal_churn_window: Duration::from_millis(666),
            visible_terminal_churn_budget: 17,
            close_drain_timeout: Duration::from_millis(333),
            go_away_drain_interval: Duration::from_millis(44),
            stop_sending_graceful_drain_window: Some(Duration::from_millis(444)),
            stop_sending_graceful_tail_cap: Some(6_666),
            keepalive_interval: Duration::from_secs(3),
            keepalive_max_ping_interval: Duration::from_secs(11),
            keepalive_timeout: Duration::from_secs(5),
            accept_backlog_limit: Some(67),
            accept_backlog_bytes_limit: Some(10_101),
            retained_open_info_bytes_budget: Some(11_111),
            retained_peer_reason_bytes_budget: Some(12_121),
            event_handler: Some(handler),
        }
    }

    fn assert_config_components_eq(expected: &Config, actual: &Config, ignored: &[&str]) {
        let ignored = |field: &str| ignored.contains(&field);

        if !ignored("role") {
            assert_eq!(expected.role, actual.role);
        }
        if !ignored("tie_breaker_nonce") {
            assert_eq!(expected.tie_breaker_nonce, actual.tie_breaker_nonce);
        }
        assert_eq!(expected.min_proto, actual.min_proto);
        assert_eq!(expected.max_proto, actual.max_proto);
        assert_eq!(expected.capabilities, actual.capabilities);
        assert_eq!(expected.settings, actual.settings);
        assert_eq!(expected.preface_padding, actual.preface_padding);
        assert_eq!(
            expected.preface_padding_min_bytes,
            actual.preface_padding_min_bytes
        );
        assert_eq!(
            expected.preface_padding_max_bytes,
            actual.preface_padding_max_bytes
        );
        assert_eq!(expected.ping_padding, actual.ping_padding);
        assert_eq!(
            expected.ping_padding_min_bytes,
            actual.ping_padding_min_bytes
        );
        assert_eq!(
            expected.ping_padding_max_bytes,
            actual.ping_padding_max_bytes
        );
        assert_eq!(expected.write_queue_max_bytes, actual.write_queue_max_bytes);
        assert_eq!(expected.session_memory_cap, actual.session_memory_cap);
        assert_eq!(
            expected.urgent_queue_max_bytes,
            actual.urgent_queue_max_bytes
        );
        assert_eq!(
            expected.per_stream_queued_data_high_watermark,
            actual.per_stream_queued_data_high_watermark
        );
        assert_eq!(
            expected.session_queued_data_high_watermark,
            actual.session_queued_data_high_watermark
        );
        assert_eq!(
            expected.pending_control_bytes_budget,
            actual.pending_control_bytes_budget
        );
        assert_eq!(
            expected.pending_priority_bytes_budget,
            actual.pending_priority_bytes_budget
        );
        assert_eq!(
            expected.write_batch_max_frames,
            actual.write_batch_max_frames
        );
        assert_eq!(
            expected.max_provisional_streams_bidi,
            actual.max_provisional_streams_bidi
        );
        assert_eq!(
            expected.max_provisional_streams_uni,
            actual.max_provisional_streams_uni
        );
        assert_eq!(expected.tombstone_limit, actual.tombstone_limit);
        assert_eq!(
            expected.hidden_control_opened_limit,
            actual.hidden_control_opened_limit
        );
        assert_eq!(
            expected.marker_only_used_stream_limit,
            actual.marker_only_used_stream_limit
        );
        assert_eq!(expected.used_marker_limit, actual.used_marker_limit);
        assert_eq!(
            expected.late_data_per_stream_cap,
            actual.late_data_per_stream_cap
        );
        assert_eq!(
            expected.late_data_aggregate_cap,
            actual.late_data_aggregate_cap
        );
        assert_eq!(
            expected.ignored_control_budget,
            actual.ignored_control_budget
        );
        assert_eq!(
            expected.no_op_zero_data_budget,
            actual.no_op_zero_data_budget
        );
        assert_eq!(expected.inbound_ping_budget, actual.inbound_ping_budget);
        assert_eq!(expected.no_op_max_data_budget, actual.no_op_max_data_budget);
        assert_eq!(expected.no_op_blocked_budget, actual.no_op_blocked_budget);
        assert_eq!(
            expected.no_op_priority_update_budget,
            actual.no_op_priority_update_budget
        );
        assert_eq!(expected.abuse_window, actual.abuse_window);
        assert_eq!(
            expected.inbound_control_frame_budget,
            actual.inbound_control_frame_budget
        );
        assert_eq!(
            expected.inbound_control_bytes_budget,
            actual.inbound_control_bytes_budget
        );
        assert_eq!(
            expected.inbound_ext_frame_budget,
            actual.inbound_ext_frame_budget
        );
        assert_eq!(
            expected.inbound_ext_bytes_budget,
            actual.inbound_ext_bytes_budget
        );
        assert_eq!(
            expected.inbound_mixed_frame_budget,
            actual.inbound_mixed_frame_budget
        );
        assert_eq!(
            expected.inbound_mixed_bytes_budget,
            actual.inbound_mixed_bytes_budget
        );
        assert_eq!(
            expected.group_rebucket_churn_budget,
            actual.group_rebucket_churn_budget
        );
        assert_eq!(
            expected.hidden_abort_churn_window,
            actual.hidden_abort_churn_window
        );
        assert_eq!(
            expected.hidden_abort_churn_budget,
            actual.hidden_abort_churn_budget
        );
        assert_eq!(
            expected.visible_terminal_churn_window,
            actual.visible_terminal_churn_window
        );
        assert_eq!(
            expected.visible_terminal_churn_budget,
            actual.visible_terminal_churn_budget
        );
        assert_eq!(expected.close_drain_timeout, actual.close_drain_timeout);
        assert_eq!(
            expected.go_away_drain_interval,
            actual.go_away_drain_interval
        );
        assert_eq!(
            expected.stop_sending_graceful_drain_window,
            actual.stop_sending_graceful_drain_window
        );
        assert_eq!(
            expected.stop_sending_graceful_tail_cap,
            actual.stop_sending_graceful_tail_cap
        );
        assert_eq!(expected.keepalive_interval, actual.keepalive_interval);
        assert_eq!(
            expected.keepalive_max_ping_interval,
            actual.keepalive_max_ping_interval
        );
        assert_eq!(expected.keepalive_timeout, actual.keepalive_timeout);
        assert_eq!(expected.accept_backlog_limit, actual.accept_backlog_limit);
        assert_eq!(
            expected.accept_backlog_bytes_limit,
            actual.accept_backlog_bytes_limit
        );
        assert_eq!(
            expected.retained_open_info_bytes_budget,
            actual.retained_open_info_bytes_budget
        );
        assert_eq!(
            expected.retained_peer_reason_bytes_budget,
            actual.retained_peer_reason_bytes_budget
        );
        match (&expected.event_handler, &actual.event_handler) {
            (Some(expected), Some(actual)) => assert!(Arc::ptr_eq(expected, actual)),
            (None, None) => {}
            _ => panic!("event_handler presence differs"),
        }
    }

    #[test]
    fn config_clone_round_trips_all_components() {
        let config = sample_config();

        assert_config_components_eq(&config, &config.clone(), &[]);
    }

    #[test]
    fn role_preserves_components_and_handles_nonce_like_builder() {
        let original = sample_config();

        let explicit = original.clone().role(Role::Initiator);
        assert_eq!(explicit.role, Role::Initiator);
        assert_eq!(explicit.tie_breaker_nonce, 0);
        assert_config_components_eq(&original, &explicit, &["role", "tie_breaker_nonce"]);

        let auto = original.clone().role(Role::Auto);
        assert_eq!(auto.role, Role::Auto);
        assert_eq!(auto.tie_breaker_nonce, original.tie_breaker_nonce);
        assert_config_components_eq(&original, &auto, &["role"]);
    }

    #[test]
    fn config_common_builders_set_fields_without_struct_literal() {
        let settings = Settings {
            max_frame_payload: 32 * 1024,
            ..Settings::default()
        };
        let cfg = Config::default()
            .capabilities(crate::protocol::CAPABILITY_OPEN_METADATA)
            .enable_capabilities(crate::protocol::CAPABILITY_PRIORITY_HINTS)
            .settings(settings);

        assert_eq!(
            cfg.capabilities,
            crate::protocol::CAPABILITY_OPEN_METADATA | crate::protocol::CAPABILITY_PRIORITY_HINTS
        );
        assert_eq!(cfg.settings.max_frame_payload, 32 * 1024);
    }

    #[test]
    fn local_preface_normalizes_protocol_and_payload_limit_settings() {
        let cfg = Config {
            min_proto: 0,
            max_proto: 0,
            settings: Settings {
                initial_max_data: 123,
                max_frame_payload: 0,
                max_control_payload_bytes: 0,
                max_extension_payload_bytes: 0,
                ..Settings::default()
            },
            ..Config::default()
        };

        let normalized = cfg.normalized().unwrap();
        let preface = cfg.local_preface().unwrap();

        assert_eq!(normalized.settings.initial_max_data, 123);
        assert_eq!(
            normalized.settings.max_frame_payload,
            Settings::default().max_frame_payload
        );
        assert_eq!(
            normalized.settings.max_control_payload_bytes,
            Settings::default().max_control_payload_bytes
        );
        assert_eq!(
            normalized.settings.max_extension_payload_bytes,
            Settings::default().max_extension_payload_bytes
        );
        assert_eq!(preface.min_proto, PROTO_VERSION);
        assert_eq!(preface.max_proto, PROTO_VERSION);
        assert_eq!(preface.settings, normalized.settings);
    }

    #[test]
    fn derived_default_byte_caps_match_receive_runtime_policy() {
        assert_eq!(default_accept_backlog_bytes_limit(0), 4 * 1024 * 1024);
        assert_eq!(
            default_accept_backlog_bytes_limit(16 * 1024),
            4 * 1024 * 1024
        );
        assert_eq!(
            default_accept_backlog_bytes_limit(128 * 1024),
            8 * 1024 * 1024
        );

        assert_eq!(default_late_data_aggregate_cap(0), 64 * 1024);
        assert_eq!(default_late_data_aggregate_cap(16 * 1024), 64 * 1024);
        assert_eq!(default_late_data_aggregate_cap(32 * 1024), 128 * 1024);
    }

    #[test]
    fn local_preface_rejects_invalid_config_ranges() {
        let mut cfg = Config {
            min_proto: 2,
            max_proto: 1,
            ..Config::default()
        };
        assert!(cfg.local_preface().is_err());

        cfg = Config {
            capabilities: MAX_VARINT62 + 1,
            ..Config::default()
        };
        assert!(cfg.local_preface().is_err());

        cfg = Config {
            tie_breaker_nonce: MAX_VARINT62 + 1,
            ..Config::default()
        };
        assert!(cfg.local_preface().is_err());

        cfg = Config {
            max_proto: MAX_VARINT62 + 1,
            ..Config::default()
        };
        assert!(cfg.local_preface().is_err());

        cfg = Config {
            settings: Settings {
                initial_max_data: MAX_VARINT62 + 1,
                ..Settings::default()
            },
            ..Config::default()
        };
        assert!(cfg.local_preface().is_err());
    }

    #[test]
    fn explicit_role_clears_tie_breaker_nonce() {
        let cfg = Config::default().role(Role::Initiator);
        assert_eq!(cfg.role, Role::Initiator);
        assert_eq!(cfg.tie_breaker_nonce, 0);
    }

    #[test]
    fn config_default_uses_repository_template_before_global_updates() {
        let cfg = Config::default();

        assert_eq!(cfg.role, Role::Auto);
        assert_eq!(cfg.tie_breaker_nonce, 0);
        assert_eq!(cfg.min_proto, PROTO_VERSION);
        assert_eq!(cfg.max_proto, PROTO_VERSION);
        assert_eq!(cfg.settings, Settings::DEFAULT);
        assert!(!cfg.preface_padding);
        assert!(!cfg.ping_padding);
    }

    #[test]
    fn default_config_template_sanitizes_random_fields() {
        let cfg = sanitize_default_config_template(Config {
            write_batch_max_frames: 64,
            preface_padding: true,
            ping_padding: true,
            ping_padding_min_bytes: 33,
            ping_padding_max_bytes: 44,
            tie_breaker_nonce: 123,
            min_proto: 0,
            max_proto: 0,
            settings: Settings {
                max_control_payload_bytes: 8_192,
                ping_padding_key: 456,
                ..Settings::DEFAULT
            },
            ..builtin_default_config()
        });

        assert_eq!(cfg.write_batch_max_frames, 64);
        assert!(cfg.preface_padding);
        assert!(cfg.ping_padding);
        assert_eq!(cfg.ping_padding_min_bytes, 33);
        assert_eq!(cfg.ping_padding_max_bytes, 44);
        assert_eq!(cfg.tie_breaker_nonce, 0);
        assert_eq!(cfg.min_proto, PROTO_VERSION);
        assert_eq!(cfg.max_proto, PROTO_VERSION);
        assert_eq!(cfg.settings.max_control_payload_bytes, 8_192);
        assert_eq!(
            cfg.settings.max_frame_payload,
            Settings::DEFAULT.max_frame_payload
        );
        assert_eq!(cfg.settings.ping_padding_key, 0);
    }

    #[test]
    fn all_zero_settings_normalize_to_repository_defaults() {
        let cfg = Config {
            settings: ZERO_SETTINGS,
            ..Config::default()
        }
        .normalized()
        .unwrap();

        assert_eq!(cfg.settings, Settings::default());
    }

    #[test]
    fn open_options_builder_sets_fields_without_struct_literal() {
        let opts = OpenOptions::new().priority(7).group(3).open_info(b"info");

        assert_eq!(opts.initial_priority(), Some(7));
        assert_eq!(opts.initial_group(), Some(3));
        assert_eq!(opts.open_info_bytes(), b"info");
        assert_eq!(opts.open_info_bytes().len(), 4);
        assert!(opts.has_open_info());
        assert!(OpenOptions::new().is_empty());
        assert_eq!(OpenOptions::new().open_info_bytes().len(), 0);
        assert!(!OpenOptions::new().has_open_info());
        assert!(!opts.is_empty());
        assert_eq!(OpenOptions::new().priority(5).initial_priority(), Some(5));
        assert_eq!(OpenOptions::new().group(6).initial_group(), Some(6));
        assert_eq!(
            OpenOptions::new().open_info(b"borrowed").open_info_bytes(),
            b"borrowed"
        );
        assert_eq!(
            OpenOptions::new()
                .open_info(vec![4, 5, 6])
                .open_info_bytes(),
            &[4, 5, 6]
        );
    }

    #[test]
    fn open_options_owned_open_info_uses_value_semantics() {
        let mut source = vec![1, 2, 3];
        let opts = OpenOptions::new().priority(7).group(9).open_info(&source);
        source[0] = 9;

        assert_eq!(opts.open_info_bytes(), &[1, 2, 3]);

        let mut exposed = opts.open_info_bytes().to_vec();
        exposed[1] = 8;
        assert_eq!(opts.open_info_bytes(), &[1, 2, 3]);
        assert_eq!(
            opts,
            OpenOptions::new()
                .priority(7)
                .group(9)
                .open_info(&[1, 2, 3])
        );
        assert_ne!(
            opts,
            OpenOptions::new()
                .priority(7)
                .group(9)
                .open_info(&[1, 2, 4])
        );
    }

    #[test]
    fn open_options_validate_varint_metadata_fields() {
        assert!(OpenOptions::new()
            .priority(MAX_VARINT62)
            .group(MAX_VARINT62)
            .validate()
            .is_ok());
        assert!(OpenOptions::new()
            .priority(MAX_VARINT62 + 1)
            .validate()
            .is_err());
        assert!(OpenOptions::new()
            .group(MAX_VARINT62 + 1)
            .validate()
            .is_err());
    }

    #[test]
    fn random_uint64n_rejects_ranges_larger_than_random_source() {
        assert!(random_uint64n(MAX_VARINT62 + 2).is_err());
    }

    #[test]
    fn settings_default_is_stable_value_template() {
        assert_eq!(Settings::default(), Settings::default());
    }

    #[test]
    fn ping_padding_generates_session_key_and_disabled_clears_key() {
        let enabled = Config {
            ping_padding: true,
            ..Config::default()
        }
        .local_preface()
        .unwrap();
        assert_ne!(enabled.settings.ping_padding_key, 0);
        assert!(enabled.settings.ping_padding_key <= MAX_VARINT62);

        let disabled = Config {
            settings: Settings {
                ping_padding_key: 123,
                ..Settings::default()
            },
            ..Config::default()
        }
        .local_preface()
        .unwrap();
        assert_eq!(disabled.settings.ping_padding_key, 0);

        let configured_key = Config {
            ping_padding: true,
            settings: Settings {
                ping_padding_key: 77,
                ..Settings::default()
            },
            ..Config::default()
        }
        .local_preface()
        .unwrap();
        assert_eq!(configured_key.settings.ping_padding_key, 77);

        let disabled_dirty_key = Config {
            settings: Settings {
                ping_padding_key: MAX_VARINT62 + 1,
                ..Settings::default()
            },
            ..Config::default()
        }
        .local_preface()
        .unwrap();
        assert_eq!(disabled_dirty_key.settings.ping_padding_key, 0);
    }

    #[test]
    fn preface_padding_preserves_parsed_preface() {
        let cfg = Config {
            preface_padding: true,
            preface_padding_min_bytes: 32,
            preface_padding_max_bytes: 32,
            ..Config::default()
        };
        let preface = cfg.local_preface().unwrap();
        let base = preface.marshal().unwrap();
        let padded = cfg.local_preface_payload(&preface).unwrap();

        assert!(padded.len() > base.len());
        assert_eq!(Preface::parse(&padded).unwrap(), preface);
    }
}
