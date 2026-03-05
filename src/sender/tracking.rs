use std::collections::HashMap;

use crate::types::SenderId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SenderSessionIdentity {
    sender_id: SenderId,
    session_nonce: u64,
}

#[derive(Debug)]
pub(super) struct SenderMessageTracking {
    highest_by_sender_session: HashMap<SenderSessionIdentity, u64>,
    message_counter: u64,
    post_reset_counter_pending: bool,
}

impl Default for SenderMessageTracking {
    fn default() -> Self {
        Self::with_counter_state(u64::MAX, true)
    }
}

impl SenderMessageTracking {
    pub(super) fn with_counter_state(
        message_counter: u64,
        post_reset_counter_pending: bool,
    ) -> Self {
        Self {
            highest_by_sender_session: HashMap::new(),
            message_counter,
            post_reset_counter_pending,
        }
    }

    fn identity(sender_id: SenderId, session_nonce: u64) -> SenderSessionIdentity {
        SenderSessionIdentity {
            sender_id,
            session_nonce,
        }
    }

    pub(super) fn current_highest(&self, sender_id: SenderId, session_nonce: u64) -> Option<u64> {
        self.highest_by_sender_session
            .get(&Self::identity(sender_id, session_nonce))
            .copied()
    }

    pub(super) fn tracked_identities(&self) -> usize {
        self.highest_by_sender_session.len()
    }

    pub(super) fn record(&mut self, sender_id: SenderId, session_nonce: u64, message_id: u64) {
        let identity = Self::identity(sender_id, session_nonce);
        if let Some(entry) = self.highest_by_sender_session.get_mut(&identity) {
            *entry = (*entry).max(message_id);
            return;
        }
        self.highest_by_sender_session.insert(identity, message_id);
    }

    pub(super) fn remove_identity(&mut self, sender_id: SenderId, session_nonce: u64) {
        let identity = Self::identity(sender_id, session_nonce);
        self.highest_by_sender_session.remove(&identity);
    }

    pub(super) fn reset_counter_for_new_session(&mut self) {
        self.message_counter = u64::MAX;
        self.post_reset_counter_pending = true;
    }

    pub(super) fn next_message_id(&mut self) -> Option<u64> {
        // Any automatic reservation consumes the post-reset seed state. This
        // path intentionally emits 0 when the counter is seeded to u64::MAX.
        if self.post_reset_counter_pending {
            self.post_reset_counter_pending = false;
            self.message_counter = 0;
            return Some(0);
        }
        let next = self.message_counter.checked_add(1)?;
        self.message_counter = next;
        Some(next)
    }

    pub(super) fn raise_message_counter_for_explicit(&mut self, message_id: u64) {
        // After reset_session(), the counter is seeded to u64::MAX so the first
        // automatic ID can be 0. If an explicit ID is reserved first, seed from
        // that explicit ID instead so later automatic IDs remain monotonic.
        if self.post_reset_counter_pending {
            self.post_reset_counter_pending = false;
            self.message_counter = message_id;
        } else {
            self.message_counter = self.message_counter.max(message_id);
        }
    }
}
