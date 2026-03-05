use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SenderId(pub u128);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageKey {
    /// Logical sender identity from the wire header.
    pub sender_id: SenderId,
    /// Sender session nonce from the wire header.
    ///
    /// Messages with the same sender/message id in different sessions have
    /// distinct keys.
    pub session_nonce: u64,
    /// Sender-scoped message sequence id from the wire header.
    pub message_id: u64,
}

impl fmt::Display for SenderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

impl fmt::Display for MessageKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}",
            self.sender_id, self.session_nonce, self.message_id
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{MessageKey, SenderId};

    #[test]
    fn display_formats_are_compact_and_stable() {
        let sender = SenderId(0x12AB);
        let key = MessageKey {
            sender_id: sender,
            session_nonce: 7,
            message_id: 42,
        };
        assert_eq!(sender.to_string(), "000000000000000000000000000012ab");
        assert_eq!(key.to_string(), "000000000000000000000000000012ab:7:42");
    }
}
