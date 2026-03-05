use std::time::Instant;

#[derive(Debug, Clone, Copy)]
pub(super) struct SenderSessionState {
    pub(super) max_message_id: u64,
    pub(super) last_seen: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionNonceOutcome {
    /// First session observed for a sender.
    Initialize,
    /// Session nonce already observed for this sender.
    Current,
    /// New session nonce observed for an existing sender.
    Advance,
}
