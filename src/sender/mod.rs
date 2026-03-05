use std::sync::Mutex;

use crate::error::{Result, UniUdpError, ValidationContext};
use crate::fec::pack_fec_field_from_mode;
use crate::types::{MessageKey, SendIdentityOverrides, SendOptions, SenderId};

mod builder;
mod emit;
mod plan;
mod request;
mod send_paths;
#[cfg(test)]
mod tests;
mod tracking;

pub use builder::{MessageIdStart, SenderBuilder};
pub use emit::SendScratch;
pub use request::SendRequest;

use plan::SendPlan;
use tracking::SenderMessageTracking;

/// Default number of sender/session identities for which explicit message-id
/// monotonicity is tracked. When this capacity is reached, new
/// sender/session identities are rejected (fail-closed) for both explicit and
/// automatic allocation instead of evicting older entries.
pub const DEFAULT_MAX_TRACKED_SENDERS: usize = 4096;

#[derive(Debug)]
#[non_exhaustive]
pub enum SendFailure {
    Preflight(Box<UniUdpError>),
    Emission {
        key: MessageKey,
        packets_sent: usize,
        error: Box<UniUdpError>,
    },
}

impl SendFailure {
    fn preflight(error: UniUdpError) -> Self {
        Self::Preflight(Box::new(error))
    }

    fn emission_from_emit(emit_failure: emit::EmitFailure) -> Self {
        Self::Emission {
            key: emit_failure.key,
            packets_sent: emit_failure.packets_sent,
            error: emit_failure.error,
        }
    }

    #[must_use]
    pub fn key(&self) -> Option<MessageKey> {
        match self {
            Self::Preflight(_) => None,
            Self::Emission { key, .. } => Some(*key),
        }
    }

    #[must_use]
    pub fn packets_sent(&self) -> usize {
        match self {
            Self::Preflight(_) => 0,
            Self::Emission { packets_sent, .. } => *packets_sent,
        }
    }

    #[must_use]
    pub fn error(&self) -> &UniUdpError {
        match self {
            Self::Preflight(error) => error,
            Self::Emission { error, .. } => error,
        }
    }

    #[must_use]
    pub fn into_error(self) -> UniUdpError {
        match self {
            Self::Preflight(error) | Self::Emission { error, .. } => *error,
        }
    }
}

impl std::fmt::Display for SendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Preflight(error) => write!(f, "send preflight failed: {error}"),
            Self::Emission {
                key,
                packets_sent,
                error,
            } => write!(
                f,
                "send emission failed for key={key} after {packets_sent} packet(s): {error}"
            ),
        }
    }
}

impl std::error::Error for SendFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error())
    }
}

/// Converts to the underlying [`UniUdpError`], discarding send-specific
/// context ([`SendFailure::key`], [`SendFailure::packets_sent`]).
///
/// If you need to know whether packets were partially sent, match on
/// [`SendFailure`] directly instead of using `?` into a `UniUdpError`.
impl From<SendFailure> for UniUdpError {
    fn from(value: SendFailure) -> Self {
        value.into_error()
    }
}

/// Stateful sender identity/sequence manager.
///
/// `Sender` is intentionally shareable across threads: send/reservation methods
/// take `&self`, and internal monotonic ID/session tracking is synchronized via
/// a mutex. This supports a single `Arc<Sender>` coordinating message IDs
/// across concurrent producers while preserving monotonic guarantees.
/// `Sender` is `Send + Sync`.
///
/// Session nonces are opaque session identifiers. `Sender::new()` seeds a
/// random default; callers can still set explicit values when deterministic
/// session boundaries are needed.
///
/// If the internal mutex is poisoned by a panic while locked, `Sender` recovers
/// the inner tracking state and continues operation. This is intentional to
/// avoid permanently disabling a sender in panic-recovery scenarios
/// (`catch_unwind`), but callers should treat post-panic behavior as
/// application-specific.
#[derive(Debug)]
pub struct Sender {
    sender_id: SenderId,
    session_nonce: u64,
    creator_pid: u32,
    highest_sent_message_by_sender: Mutex<SenderMessageTracking>,
    max_tracked_senders: usize,
}

impl Sender {
    fn automatic_message_id_exhausted_error() -> UniUdpError {
        UniUdpError::validation_detail(
            ValidationContext::SendOptions,
            "automatic message_id space exhausted for current session",
            "message_id",
            "< u64::MAX or reset_session(different_nonce)",
            "u64::MAX",
        )
    }

    fn counter_state_for_first_message_id(first_message_id: u64) -> (u64, bool) {
        if first_message_id == 0 {
            (u64::MAX, true)
        } else {
            (first_message_id - 1, false)
        }
    }

    #[must_use]
    pub fn builder() -> SenderBuilder {
        SenderBuilder::new()
    }

    pub fn new() -> Self {
        // Builder defaults are always valid.
        Self::builder()
            .build()
            .expect("default SenderBuilder is always valid")
    }

    pub fn with_identity(sender_id: SenderId, session_nonce: u64) -> Self {
        Self::with_identity_and_limits(
            sender_id,
            session_nonce,
            DEFAULT_MAX_TRACKED_SENDERS,
            MessageIdStart::Zero,
        )
    }

    #[cfg(test)]
    fn try_with_identity_and_limits(
        sender_id: SenderId,
        session_nonce: u64,
        max_tracked_senders: usize,
    ) -> Result<Self> {
        Self::try_with_identity_and_limits_and_start(
            sender_id,
            session_nonce,
            max_tracked_senders,
            MessageIdStart::Zero,
        )
    }

    fn try_with_identity_and_limits_and_start(
        sender_id: SenderId,
        session_nonce: u64,
        max_tracked_senders: usize,
        message_id_start: MessageIdStart,
    ) -> Result<Self> {
        if max_tracked_senders == 0 {
            return Err(UniUdpError::validation_detail(
                ValidationContext::SendOptions,
                "max_tracked_senders must be positive",
                "max_tracked_senders",
                "> 0",
                max_tracked_senders.to_string(),
            ));
        }
        Ok(Self::with_identity_and_limits(
            sender_id,
            session_nonce,
            max_tracked_senders,
            message_id_start,
        ))
    }

    fn with_identity_and_limits(
        sender_id: SenderId,
        session_nonce: u64,
        max_tracked_senders: usize,
        message_id_start: MessageIdStart,
    ) -> Self {
        let (counter_seed, post_reset_counter_pending) = match message_id_start {
            MessageIdStart::Zero => Self::counter_state_for_first_message_id(0),
            MessageIdStart::Random => {
                Self::counter_state_for_first_message_id(rand::random::<u64>())
            }
            MessageIdStart::Next(next) => Self::counter_state_for_first_message_id(next),
        };
        Self {
            sender_id,
            session_nonce,
            creator_pid: std::process::id(),
            highest_sent_message_by_sender: Mutex::new(SenderMessageTracking::with_counter_state(
                counter_seed,
                post_reset_counter_pending,
            )),
            max_tracked_senders,
        }
    }

    pub fn sender_id(&self) -> SenderId {
        self.sender_id
    }

    pub fn session_nonce(&self) -> u64 {
        self.session_nonce
    }

    pub fn max_tracked_senders(&self) -> usize {
        self.max_tracked_senders
    }

    pub fn creator_pid(&self) -> u32 {
        self.creator_pid
    }

    pub fn reset_session(&mut self, new_session_nonce: u64) -> Result<()> {
        if new_session_nonce == self.session_nonce {
            return Err(UniUdpError::validation_detail(
                ValidationContext::SendOptions,
                "new session_nonce must differ from current session_nonce",
                "session_nonce",
                format!("!= {}", self.session_nonce),
                new_session_nonce.to_string(),
            ));
        }

        let previous_session_nonce = self.session_nonce;
        self.session_nonce = new_session_nonce;
        // Restart automatic IDs for the new session.
        let mut tracking = match self.highest_sent_message_by_sender.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        tracking.reset_counter_for_new_session();
        // Reset only this sender's default-session identities. Keep unrelated
        // override identities so explicit-ID monotonicity is not weakened.
        tracking.remove_identity(self.sender_id, previous_session_nonce);
        tracking.remove_identity(self.sender_id, new_session_nonce);
        Ok(())
    }

    #[cfg(test)]
    fn next_message_id(&self) -> u64 {
        let mut tracking = match self.highest_sent_message_by_sender.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        tracking
            .next_message_id()
            .expect("automatic message_id space exhausted in test helper")
    }

    fn reserve_message_id(
        &self,
        sender_id: SenderId,
        session_nonce: u64,
        explicit_message_id: Option<u64>,
    ) -> Result<u64> {
        let mut tracking = match self.highest_sent_message_by_sender.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let tracked_identities = tracking.tracked_identities();
        let highest_seen = tracking.current_highest(sender_id, session_nonce);
        let new_identity = highest_seen.is_none();

        let message_id = match explicit_message_id {
            Some(message_id) => {
                if new_identity && tracked_identities >= self.max_tracked_senders {
                    return Err(UniUdpError::validation_detail(
                        ValidationContext::SendOptions,
                        "max_tracked_senders exceeded; refusing to weaken explicit message_id monotonicity",
                        "max_tracked_senders",
                        format!("> {tracked_identities}"),
                        self.max_tracked_senders.to_string(),
                    ));
                }
                if let Some(highest_seen) = highest_seen.filter(|&seen| message_id <= seen) {
                    return Err(UniUdpError::validation_detail(
                        ValidationContext::SendOptions,
                        "explicit message_id must be > highest previously sent message_id for sender/session",
                        "message_id",
                        format!("> {highest_seen}"),
                        message_id.to_string(),
                    ));
                }
                tracking.raise_message_counter_for_explicit(message_id);
                message_id
            }
            None => {
                if new_identity && tracked_identities >= self.max_tracked_senders {
                    return Err(UniUdpError::validation_detail(
                        ValidationContext::SendOptions,
                        "max_tracked_senders exceeded; refusing to weaken message_id monotonicity",
                        "max_tracked_senders",
                        format!("> {tracked_identities}"),
                        self.max_tracked_senders.to_string(),
                    ));
                }
                let mut message_id = tracking
                    .next_message_id()
                    .ok_or_else(Self::automatic_message_id_exhausted_error)?;
                if let Some(highest_seen) = highest_seen.filter(|&seen| message_id <= seen) {
                    message_id = highest_seen
                        .checked_add(1)
                        .ok_or_else(Self::automatic_message_id_exhausted_error)?;
                    // Keep global automatic allocation monotonic with the
                    // floor applied for this tracked sender/session identity.
                    tracking.raise_message_counter_for_explicit(message_id);
                }
                message_id
            }
        };

        let should_track_identity = !new_identity || tracked_identities < self.max_tracked_senders;
        if should_track_identity {
            tracking.record(sender_id, session_nonce, message_id);
        }
        Ok(message_id)
    }

    fn resolve_sender_id(&self, identity: &SendIdentityOverrides) -> SenderId {
        identity.sender_id().unwrap_or(self.sender_id)
    }

    fn resolve_session_nonce(&self, identity: &SendIdentityOverrides) -> u64 {
        identity.session_nonce().unwrap_or(self.session_nonce)
    }

    fn prepare_send_plan(
        &self,
        data: &[u8],
        options: &SendOptions,
        identity: &SendIdentityOverrides,
    ) -> Result<SendPlan> {
        options.validate()?;

        let redundancy_u16 = options.redundancy();
        let chunk_size_u16 = options.chunk_size();
        let fec_mode = *options.fec_mode();
        let chunk_size = usize::from(chunk_size_u16);
        let fec_group_size = fec_mode.effective_group_size();
        let delay = options.delay();
        let message_length = data.len();
        let total_chunks = if data.is_empty() {
            1
        } else {
            data.len().div_ceil(chunk_size)
        };

        if total_chunks > (u32::MAX as usize) || message_length > (u32::MAX as usize) {
            return Err(UniUdpError::validation(
                ValidationContext::SendOptions,
                "payload too large",
            ));
        }
        debug_assert!(message_length <= chunk_size.saturating_mul(total_chunks));

        let key = self.reserve_message_key_with_identity(identity)?;
        let data_field = pack_fec_field_from_mode(&fec_mode, false, 0)?;

        Ok(SendPlan {
            key,
            redundancy_u16,
            chunk_size_u16,
            chunk_size,
            fec_mode,
            fec_group_size,
            delay,
            message_length,
            total_chunks,
            data_field,
        })
    }

    fn ensure_origin_process(&self) -> Result<()> {
        let current_pid = std::process::id();
        if current_pid != self.creator_pid {
            return Err(UniUdpError::validation_detail(
                ValidationContext::SendOptions,
                "sender instance cannot be used across process boundaries; construct a new Sender",
                "creator_pid",
                self.creator_pid.to_string(),
                current_pid.to_string(),
            ));
        }
        Ok(())
    }

    /// Reserves a message key using the sender's configured identity.
    ///
    /// The returned `MessageKey` is permanently consumed — there is no way to
    /// "unreserve" an ID. If you reserve a key but never send the message, the
    /// ID is skipped and the next reservation will use the following ID. The
    /// receiver tolerates such gaps via its freshness window.
    ///
    /// For per-message identity overrides, use
    /// [`Sender::reserve_message_key_with_identity`].
    pub fn reserve_message_key(&self) -> Result<MessageKey> {
        self.reserve_message_key_with_identity(&SendIdentityOverrides::default())
    }

    /// Reserves a message key using explicit per-message identity overrides.
    ///
    /// This is the canonical message-id reservation API:
    /// - explicit IDs (`SendIdentityOverrides::with_message_id`) must be
    ///   strictly increasing per `(sender_id, session_nonce)`
    /// - automatic IDs (`message_id == None`) are allocated from the sender's
    ///   sequence and stay monotonic with explicit reservations
    pub fn reserve_message_key_with_identity(
        &self,
        identity: &SendIdentityOverrides,
    ) -> Result<MessageKey> {
        self.ensure_origin_process()?;
        let sender_id = self.resolve_sender_id(identity);
        let session_nonce = self.resolve_session_nonce(identity);
        let message_id =
            self.reserve_message_id(sender_id, session_nonce, identity.message_id())?;
        Ok(Self::message_key(sender_id, session_nonce, message_id))
    }

    fn message_key(sender_id: SenderId, session_nonce: u64, message_id: u64) -> MessageKey {
        MessageKey {
            sender_id,
            session_nonce,
            message_id,
        }
    }
}

impl Default for Sender {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) fn default_session_nonce() -> u64 {
    // Random default avoids nonce reuse under clock rollback/snapshot restore.
    rand::random::<u64>()
}
