use std::time::Instant;

use crate::types::{MessageKey, ReceiverRuntimeConfig};

use super::ReceiverState;

impl ReceiverState {
    pub(super) fn remove_completed(&mut self, key: &MessageKey) -> bool {
        let removed = self.completed.remove(key).is_some();
        self.completed_index.remove(key);
        self.assert_index_invariants();
        removed
    }

    fn evict_oldest_completed(&mut self) -> bool {
        let Some((_, oldest_key)) = self.completed_index.oldest() else {
            return false;
        };
        self.remove_completed(&oldest_key)
    }

    pub(super) fn enforce_completed_capacity(&mut self, config: &ReceiverRuntimeConfig) {
        while self.completed.len() > config.max_completed_messages() {
            if !self.evict_oldest_completed() {
                break;
            }
        }
    }

    pub(in crate::receiver) fn is_duplicate(&self, key: MessageKey) -> bool {
        self.completed.contains_key(&key)
    }

    pub(in crate::receiver) fn mark_completed(
        &mut self,
        key: MessageKey,
        now: Instant,
        config: &ReceiverRuntimeConfig,
    ) {
        self.remove_completed(&key);
        self.completed.insert(key, now);
        self.completed_index.insert(key, now);
        self.enforce_completed_capacity(config);
        self.assert_index_invariants();
    }
}
