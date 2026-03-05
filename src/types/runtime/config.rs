use std::collections::HashSet;
use std::time::Duration;

use crate::error::{UniUdpError, ValidationContext};
use crate::types::PacketAuth;

use super::constants::{
    DEDUP_WINDOW, DEFAULT_MESSAGE_FRESHNESS_WINDOW, HEADER_LENGTH, MAX_COMPLETED_MESSAGES,
    MAX_PENDING_BYTES, MAX_PENDING_MESSAGES, MAX_RECEIVE_CHUNKS, MAX_RECEIVE_DATAGRAM_SIZE,
    MAX_RECEIVE_MESSAGE_LEN, MAX_TRACKED_SESSIONS_PER_SENDER, MAX_TRACKED_SESSIONS_TOTAL,
    PENDING_MAX_AGE, SESSION_FRESHNESS_RETENTION,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum AuthMode {
    /// Require valid packet authentication on all packets.
    Require,
    /// Accept unauthenticated packets and authenticated packets that verify.
    Optional,
    /// Disable authentication enforcement (auth metadata is ignored).
    #[default]
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReceiverCoreConfig {
    max_pending_messages: usize,
    /// Maximum aggregate estimated heap footprint for pending messages.
    ///
    /// The estimate includes declared payload bytes plus receiver bookkeeping
    /// state (chunk/parity metadata and tracking vectors).
    max_pending_bytes: usize,
    /// Maximum number of completed message keys retained for replay dedup.
    max_completed_messages: usize,
    /// Maximum number of authenticated sender/session entries retained across
    /// all senders for freshness/replay tracking.
    max_tracked_sessions_total: usize,
    /// Maximum number of authenticated session nonces tracked per sender.
    max_tracked_sessions_per_sender: usize,
    dedup_window: Duration,
    pending_max_age: Duration,
    max_receive_chunks: usize,
    max_receive_message_len: usize,
    max_receive_datagram_size: usize,
    /// Maximum backward distance from the highest seen message ID accepted for
    /// the current authenticated sender session.
    message_freshness_window: u64,
    /// If true, disables message freshness distance checks regardless of
    /// `message_freshness_window`.
    unbounded_message_freshness: bool,
    /// How long authenticated session state (`max_message_id` per session) is
    /// retained before cleanup evicts it.  Decoupled from `dedup_window` so
    /// that session freshness tracking can outlive the completed-message dedup
    /// cache.
    session_freshness_retention: Duration,
    /// When true, authenticated freshness checks require `message_id` to be
    /// strictly greater than the highest previously seen `message_id` for the
    /// session.  This closes a replay gap where a captured packet with
    /// `message_id == max_seen` could be re-accepted after its dedup cache
    /// entry expires.
    strict_message_ordering: bool,
    auth_mode: AuthMode,
}

impl Default for ReceiverCoreConfig {
    fn default() -> Self {
        Self {
            max_pending_messages: MAX_PENDING_MESSAGES,
            max_pending_bytes: MAX_PENDING_BYTES,
            max_completed_messages: MAX_COMPLETED_MESSAGES,
            max_tracked_sessions_total: MAX_TRACKED_SESSIONS_TOTAL,
            max_tracked_sessions_per_sender: MAX_TRACKED_SESSIONS_PER_SENDER,
            dedup_window: DEDUP_WINDOW,
            pending_max_age: PENDING_MAX_AGE,
            max_receive_chunks: MAX_RECEIVE_CHUNKS,
            max_receive_message_len: MAX_RECEIVE_MESSAGE_LEN,
            max_receive_datagram_size: MAX_RECEIVE_DATAGRAM_SIZE,
            message_freshness_window: DEFAULT_MESSAGE_FRESHNESS_WINDOW,
            unbounded_message_freshness: false,
            session_freshness_retention: SESSION_FRESHNESS_RETENTION,
            strict_message_ordering: false,
            auth_mode: AuthMode::Disabled,
        }
    }
}

impl ReceiverCoreConfig {
    fn validate(&self) -> std::result::Result<(), UniUdpError> {
        if self.max_pending_messages == 0 {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "max_pending_messages must be positive",
                "max_pending_messages",
                "> 0",
                self.max_pending_messages.to_string(),
            ));
        }
        if self.max_pending_bytes == 0 {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "max_pending_bytes must be positive",
                "max_pending_bytes",
                "> 0",
                self.max_pending_bytes.to_string(),
            ));
        }
        if self.max_completed_messages == 0 {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "max_completed_messages must be positive",
                "max_completed_messages",
                "> 0",
                self.max_completed_messages.to_string(),
            ));
        }
        if self.max_tracked_sessions_total == 0 {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "max_tracked_sessions_total must be positive",
                "max_tracked_sessions_total",
                "> 0",
                self.max_tracked_sessions_total.to_string(),
            ));
        }
        if self.max_tracked_sessions_per_sender == 0 {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "max_tracked_sessions_per_sender must be positive",
                "max_tracked_sessions_per_sender",
                "> 0",
                self.max_tracked_sessions_per_sender.to_string(),
            ));
        }
        if self.dedup_window.is_zero() {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "dedup_window must be positive",
                "dedup_window",
                "> 0s",
                format!("{:?}", self.dedup_window),
            ));
        }
        if self.pending_max_age.is_zero() {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "pending_max_age must be positive",
                "pending_max_age",
                "> 0s",
                format!("{:?}", self.pending_max_age),
            ));
        }
        if self.max_receive_chunks == 0 {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "max_receive_chunks must be positive",
                "max_receive_chunks",
                "> 0",
                self.max_receive_chunks.to_string(),
            ));
        }
        if self.max_receive_message_len == 0 {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "max_receive_message_len must be positive",
                "max_receive_message_len",
                "> 0",
                self.max_receive_message_len.to_string(),
            ));
        }
        if self.max_receive_datagram_size < HEADER_LENGTH {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "max_receive_datagram_size must be at least HEADER_LENGTH",
                "max_receive_datagram_size",
                format!(">= {HEADER_LENGTH}"),
                self.max_receive_datagram_size.to_string(),
            ));
        }
        if self.max_receive_datagram_size > MAX_RECEIVE_DATAGRAM_SIZE {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "max_receive_datagram_size exceeds UDP payload limit",
                "max_receive_datagram_size",
                format!("<= {MAX_RECEIVE_DATAGRAM_SIZE}"),
                self.max_receive_datagram_size.to_string(),
            ));
        }
        if self.session_freshness_retention.is_zero() {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "session_freshness_retention must be positive",
                "session_freshness_retention",
                "> 0s",
                format!("{:?}", self.session_freshness_retention),
            ));
        }
        if self.message_freshness_window == 0 && !self.unbounded_message_freshness {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "message_freshness_window must be positive unless unbounded_message_freshness is enabled",
                "message_freshness_window",
                "> 0 or with_unbounded_message_freshness(true)",
                self.message_freshness_window.to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// Read-only runtime receiver settings derived from validated
/// [`ReceiverConfig`].
///
/// We intentionally keep explicit getters on both `ReceiverRuntimeConfig` and
/// `ReceiverConfig` (rather than `Deref` or a shared trait) to keep type
/// boundaries and method resolution obvious, and to avoid expanding public API
/// semver surface with trait commitments.
pub struct ReceiverRuntimeConfig {
    core: ReceiverCoreConfig,
}

impl ReceiverRuntimeConfig {
    #[must_use]
    pub fn max_pending_messages(&self) -> usize {
        self.core.max_pending_messages
    }

    #[must_use]
    pub fn max_pending_bytes(&self) -> usize {
        self.core.max_pending_bytes
    }

    #[must_use]
    pub fn max_completed_messages(&self) -> usize {
        self.core.max_completed_messages
    }

    #[must_use]
    pub fn max_tracked_sessions_total(&self) -> usize {
        self.core.max_tracked_sessions_total
    }

    #[must_use]
    pub fn max_tracked_sessions_per_sender(&self) -> usize {
        self.core.max_tracked_sessions_per_sender
    }

    #[must_use]
    pub fn dedup_window(&self) -> Duration {
        self.core.dedup_window
    }

    #[must_use]
    pub fn pending_max_age(&self) -> Duration {
        self.core.pending_max_age
    }

    #[must_use]
    pub fn max_receive_chunks(&self) -> usize {
        self.core.max_receive_chunks
    }

    #[must_use]
    pub fn max_receive_message_len(&self) -> usize {
        self.core.max_receive_message_len
    }

    #[must_use]
    pub fn max_receive_datagram_size(&self) -> usize {
        self.core.max_receive_datagram_size
    }

    #[must_use]
    pub fn message_freshness_window(&self) -> u64 {
        self.core.message_freshness_window
    }

    #[must_use]
    pub fn unbounded_message_freshness(&self) -> bool {
        self.core.unbounded_message_freshness
    }

    #[must_use]
    pub fn session_freshness_retention(&self) -> Duration {
        self.core.session_freshness_retention
    }

    #[must_use]
    pub fn strict_message_ordering(&self) -> bool {
        self.core.strict_message_ordering
    }

    #[must_use]
    pub fn auth_mode(&self) -> AuthMode {
        self.core.auth_mode
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct ReceiverConfig {
    core: ReceiverCoreConfig,
    auth_keys: Vec<PacketAuth>,
    auth_mode_explicit: bool,
}

impl From<&ReceiverConfig> for ReceiverRuntimeConfig {
    fn from(value: &ReceiverConfig) -> Self {
        Self { core: value.core }
    }
}

impl ReceiverConfig {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn max_pending_messages(&self) -> usize {
        self.core.max_pending_messages
    }

    #[must_use]
    pub fn max_pending_bytes(&self) -> usize {
        self.core.max_pending_bytes
    }

    #[must_use]
    pub fn max_completed_messages(&self) -> usize {
        self.core.max_completed_messages
    }

    #[must_use]
    pub fn max_tracked_sessions_total(&self) -> usize {
        self.core.max_tracked_sessions_total
    }

    #[must_use]
    pub fn max_tracked_sessions_per_sender(&self) -> usize {
        self.core.max_tracked_sessions_per_sender
    }

    #[must_use]
    pub fn dedup_window(&self) -> Duration {
        self.core.dedup_window
    }

    #[must_use]
    pub fn pending_max_age(&self) -> Duration {
        self.core.pending_max_age
    }

    #[must_use]
    pub fn max_receive_chunks(&self) -> usize {
        self.core.max_receive_chunks
    }

    #[must_use]
    pub fn max_receive_message_len(&self) -> usize {
        self.core.max_receive_message_len
    }

    #[must_use]
    pub fn max_receive_datagram_size(&self) -> usize {
        self.core.max_receive_datagram_size
    }

    #[must_use]
    pub fn message_freshness_window(&self) -> u64 {
        self.core.message_freshness_window
    }

    #[must_use]
    pub fn unbounded_message_freshness(&self) -> bool {
        self.core.unbounded_message_freshness
    }

    #[must_use]
    pub fn session_freshness_retention(&self) -> Duration {
        self.core.session_freshness_retention
    }

    #[must_use]
    pub fn strict_message_ordering(&self) -> bool {
        self.core.strict_message_ordering
    }

    #[must_use]
    pub fn auth_keys(&self) -> &[PacketAuth] {
        &self.auth_keys
    }

    #[must_use]
    pub fn auth_mode(&self) -> AuthMode {
        self.core.auth_mode
    }

    #[must_use]
    pub fn with_max_pending_messages(mut self, max_pending_messages: usize) -> Self {
        self.core.max_pending_messages = max_pending_messages;
        self
    }

    #[must_use]
    pub fn with_max_pending_bytes(mut self, max_pending_bytes: usize) -> Self {
        self.core.max_pending_bytes = max_pending_bytes;
        self
    }

    #[must_use]
    pub fn with_max_completed_messages(mut self, max_completed_messages: usize) -> Self {
        self.core.max_completed_messages = max_completed_messages;
        self
    }

    #[must_use]
    pub fn with_max_tracked_sessions_total(mut self, max_tracked_sessions_total: usize) -> Self {
        self.core.max_tracked_sessions_total = max_tracked_sessions_total;
        self
    }

    #[must_use]
    pub fn with_max_tracked_sessions_per_sender(
        mut self,
        max_tracked_sessions_per_sender: usize,
    ) -> Self {
        self.core.max_tracked_sessions_per_sender = max_tracked_sessions_per_sender;
        self
    }

    #[must_use]
    pub fn with_dedup_window(mut self, dedup_window: Duration) -> Self {
        self.core.dedup_window = dedup_window;
        self
    }

    #[must_use]
    pub fn with_pending_max_age(mut self, pending_max_age: Duration) -> Self {
        self.core.pending_max_age = pending_max_age;
        self
    }

    #[must_use]
    pub fn with_max_receive_chunks(mut self, max_receive_chunks: usize) -> Self {
        self.core.max_receive_chunks = max_receive_chunks;
        self
    }

    #[must_use]
    pub fn with_max_receive_message_len(mut self, max_receive_message_len: usize) -> Self {
        self.core.max_receive_message_len = max_receive_message_len;
        self
    }

    #[must_use]
    pub fn with_max_receive_datagram_size(mut self, max_receive_datagram_size: usize) -> Self {
        self.core.max_receive_datagram_size = max_receive_datagram_size;
        self
    }

    #[must_use]
    pub fn with_message_freshness_window(mut self, message_freshness_window: u64) -> Self {
        self.core.message_freshness_window = message_freshness_window;
        self
    }

    /// Enables or disables unbounded message freshness checks.
    ///
    /// When enabled, older message IDs are not rejected due to freshness
    /// distance and `message_freshness_window` is ignored for that purpose.
    #[must_use]
    pub fn with_unbounded_message_freshness(mut self, enabled: bool) -> Self {
        self.core.unbounded_message_freshness = enabled;
        self
    }

    /// Sets how long authenticated session state is retained.
    ///
    /// Session state tracks the highest `message_id` per
    /// `(sender_id, session_nonce)` pair. Retaining it longer than
    /// `dedup_window` ensures that replayed authenticated packets are rejected
    /// by the freshness check even after their dedup cache entries expire.
    ///
    /// Default: 1 hour.
    #[must_use]
    pub fn with_session_freshness_retention(
        mut self,
        session_freshness_retention: Duration,
    ) -> Self {
        self.core.session_freshness_retention = session_freshness_retention;
        self
    }

    /// Enables or disables strict message ordering for authenticated sessions.
    ///
    /// When enabled, each authenticated `message_id` must be strictly greater
    /// than the highest previously seen `message_id` for that session.  This
    /// closes a replay gap where a captured packet with `message_id ==
    /// max_seen` could otherwise be re-accepted after its dedup cache entry
    /// expires.
    ///
    /// Only affects authenticated traffic.  Default: `false`.
    #[must_use]
    pub fn with_strict_message_ordering(mut self, enabled: bool) -> Self {
        self.core.strict_message_ordering = enabled;
        self
    }

    #[must_use]
    pub fn with_auth_mode(mut self, auth_mode: AuthMode) -> Self {
        self.core.auth_mode = auth_mode;
        self.auth_mode_explicit = true;
        self
    }

    #[must_use]
    pub fn with_auth_keys(mut self, auth_keys: Vec<PacketAuth>) -> Self {
        self.auth_keys = auth_keys;
        if !self.auth_mode_explicit {
            self.core.auth_mode = if self.auth_keys.is_empty() {
                AuthMode::Disabled
            } else {
                AuthMode::Require
            };
        }
        self
    }

    #[must_use]
    pub fn with_auth_key(mut self, auth_key: PacketAuth) -> Self {
        self.auth_keys.push(auth_key);
        if !self.auth_mode_explicit {
            self.core.auth_mode = AuthMode::Require;
        }
        self
    }

    pub fn runtime_config(&self) -> ReceiverRuntimeConfig {
        ReceiverRuntimeConfig::from(self)
    }

    pub(crate) fn into_parts(self) -> (ReceiverRuntimeConfig, Vec<PacketAuth>) {
        (ReceiverRuntimeConfig { core: self.core }, self.auth_keys)
    }

    pub fn validate(&self) -> std::result::Result<(), UniUdpError> {
        self.core.validate()?;

        if self.core.auth_mode == AuthMode::Require && self.auth_keys.is_empty() {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "auth_mode Require requires at least one auth key",
                "auth_mode",
                "Require with non-empty auth_keys",
                "Require with empty auth_keys",
            ));
        }

        if self.core.auth_mode == AuthMode::Optional && self.auth_keys.is_empty() {
            return Err(UniUdpError::validation_detail(
                ValidationContext::ReceiverConfig,
                "auth_mode Optional requires at least one auth key; use Disabled if no keys are available",
                "auth_mode",
                "Optional with non-empty auth_keys, or Disabled",
                "Optional with empty auth_keys",
            ));
        }

        let mut key_ids = HashSet::with_capacity(self.auth_keys.len());
        for auth in &self.auth_keys {
            if !key_ids.insert(auth.key_id()) {
                return Err(UniUdpError::validation_detail(
                    ValidationContext::ReceiverConfig,
                    "auth_keys contains duplicate key_id",
                    "auth_keys.key_id",
                    "unique values",
                    auth.key_id().to_string(),
                ));
            }
        }
        Ok(())
    }
}
