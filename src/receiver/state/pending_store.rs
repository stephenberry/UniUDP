use std::mem::size_of;

use crate::types::{MessageKey, ReceiverRuntimeConfig, SourcePolicy};

use super::{MessageState, ReceiverState};

impl ReceiverState {
    pub(super) fn pending_cost(state: &MessageState) -> usize {
        state
            .pending_bytes_estimate()
            .saturating_add(size_of::<MessageKey>())
    }

    pub(super) fn insert_pending(&mut self, key: MessageKey, state: MessageState) {
        let is_complete = state.is_complete();
        let created_at = state.created_at;
        if self.pending.contains_key(&key) {
            self.remove_pending(&key);
        }
        self.pending_estimated_bytes = self
            .pending_estimated_bytes
            .saturating_add(Self::pending_cost(&state));
        self.pending.insert(key, state);
        self.pending_index.insert(key, created_at);
        if is_complete {
            self.enqueue_complete(key);
        }
        self.assert_index_invariants();
    }

    pub(super) fn remove_pending(&mut self, key: &MessageKey) -> Option<MessageState> {
        let state = self.pending.remove(key)?;
        self.pending_estimated_bytes = self
            .pending_estimated_bytes
            .saturating_sub(Self::pending_cost(&state));
        self.pending_index.remove(key);
        self.remove_completion_tracking(*key);
        self.assert_index_invariants();
        Some(state)
    }

    pub(super) fn enqueue_complete(&mut self, key: MessageKey) {
        self.completion_index.insert_if_absent(key);
        self.assert_index_invariants();
    }

    fn remove_completion_tracking(&mut self, key: MessageKey) {
        self.completion_index.remove(&key);
    }

    fn evict_least_active(&mut self, protected_key: Option<MessageKey>) -> bool {
        let victim = self
            .pending
            .iter()
            .filter(|&(k, _)| Some(*k) != protected_key)
            .min_by_key(|(_, state)| state.last_activity_at)
            .map(|(k, _)| *k);
        let Some(key) = victim else {
            return false;
        };
        self.remove_pending(&key);
        true
    }

    pub(in crate::receiver) fn remove_pending_if_allowed(
        &mut self,
        key: MessageKey,
        policy: SourcePolicy,
    ) -> Option<MessageState> {
        let allowed = self
            .pending
            .get(&key)
            .is_some_and(|state| policy.allows_buffered(state.first_source));
        if !allowed {
            return None;
        }
        self.remove_pending(&key)
    }

    pub(super) fn evict_oldest_if_needed(
        &mut self,
        incoming_message_bytes: usize,
        config: &ReceiverRuntimeConfig,
        protected_key: Option<MessageKey>,
    ) -> bool {
        if incoming_message_bytes > config.max_pending_bytes() {
            return false;
        }

        while self.pending.len() >= config.max_pending_messages()
            || self
                .pending_estimated_bytes
                .saturating_add(incoming_message_bytes)
                > config.max_pending_bytes()
        {
            if !self.evict_least_active(protected_key) {
                return false;
            }
        }
        self.assert_index_invariants();
        true
    }

    pub(in crate::receiver) fn find_complete_message(
        &mut self,
        filter_key: Option<MessageKey>,
        policy: SourcePolicy,
    ) -> Option<MessageState> {
        if let Some(key) = filter_key {
            if self.pending.get(&key).is_some_and(|state| {
                state.is_complete() && policy.allows_buffered(state.first_source)
            }) {
                return self.remove_pending(&key);
            }
            return None;
        }

        let mut stale: Vec<(u64, MessageKey)> = Vec::new();
        let mut selected_key: Option<MessageKey> = None;
        for (seq, key) in self.completion_index.entries() {
            let Some(state) = self.pending.get(&key) else {
                stale.push((seq, key));
                continue;
            };
            if !state.is_complete() {
                stale.push((seq, key));
                continue;
            }
            if !policy.allows_buffered(state.first_source) {
                continue;
            }
            selected_key = Some(key);
            break;
        }

        for (seq, key) in stale {
            self.completion_index.remove_exact(seq, key);
        }

        if let Some(key) = selected_key {
            return self.remove_pending(&key);
        }
        self.assert_index_invariants();
        None
    }

    pub(in crate::receiver) fn is_pending_complete(&self, key: MessageKey) -> bool {
        self.pending
            .get(&key)
            .is_some_and(MessageState::is_complete)
    }
}
