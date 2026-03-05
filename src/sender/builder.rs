use std::fmt;

use crate::error::Result;
use crate::types::SenderId;

use super::{default_session_nonce, Sender, DEFAULT_MAX_TRACKED_SENDERS};

/// Strategy used to choose the first automatically-assigned `message_id` for a
/// sender instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MessageIdStart {
    /// Start automatic allocation at `0`.
    #[default]
    Zero,
    /// Start automatic allocation at a random `u64` value.
    Random,
    /// Start automatic allocation at the provided `message_id`.
    Next(u64),
}

/// Builder for [`Sender`].
#[derive(Clone)]
pub struct SenderBuilder {
    sender_id: SenderId,
    session_nonce_strategy: SessionNonceStrategy,
    max_tracked_senders: usize,
    message_id_start: MessageIdStart,
}

impl Default for SenderBuilder {
    fn default() -> Self {
        Self {
            sender_id: SenderId(rand::random::<u128>()),
            session_nonce_strategy: SessionNonceStrategy::RandomDefault,
            max_tracked_senders: DEFAULT_MAX_TRACKED_SENDERS,
            message_id_start: MessageIdStart::Zero,
        }
    }
}

impl SenderBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_sender_id(mut self, sender_id: SenderId) -> Self {
        self.sender_id = sender_id;
        self
    }

    #[must_use]
    pub fn with_session_nonce(mut self, session_nonce: u64) -> Self {
        self.session_nonce_strategy = SessionNonceStrategy::Explicit(session_nonce);
        self
    }

    #[must_use]
    pub fn with_max_tracked_senders(mut self, max_tracked_senders: usize) -> Self {
        self.max_tracked_senders = max_tracked_senders;
        self
    }

    #[must_use]
    pub fn with_message_id_start(mut self, message_id_start: MessageIdStart) -> Self {
        self.message_id_start = message_id_start;
        self
    }

    pub fn build(self) -> Result<Sender> {
        let session_nonce = match &self.session_nonce_strategy {
            SessionNonceStrategy::RandomDefault => default_session_nonce(),
            SessionNonceStrategy::Explicit(session_nonce) => *session_nonce,
        };
        Sender::try_with_identity_and_limits_and_start(
            self.sender_id,
            session_nonce,
            self.max_tracked_senders,
            self.message_id_start,
        )
    }
}

#[derive(Clone)]
enum SessionNonceStrategy {
    RandomDefault,
    Explicit(u64),
}

impl fmt::Debug for SessionNonceStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionNonceStrategy::RandomDefault => f.write_str("RandomDefault"),
            SessionNonceStrategy::Explicit(session_nonce) => {
                f.debug_tuple("Explicit").field(session_nonce).finish()
            }
        }
    }
}

impl fmt::Debug for SenderBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SenderBuilder")
            .field("sender_id", &self.sender_id)
            .field("session_nonce_strategy", &self.session_nonce_strategy)
            .field("max_tracked_senders", &self.max_tracked_senders)
            .field("message_id_start", &self.message_id_start)
            .finish()
    }
}
