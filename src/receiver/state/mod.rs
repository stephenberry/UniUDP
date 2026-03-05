use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Instant;

use crate::types::{MessageKey, PacketHeader, ReceiverRuntimeConfig, SenderId, SourcePolicy};

use super::message_state::{MessageState, PacketUpdateOutcome};
use super::session::SenderSessionState;

mod completed_cache;
mod index;
mod pending_store;
mod session_replay;

use index::{SequenceKeyIndex, TimestampKeyIndex};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpsertOutcome {
    Accepted,
    RejectedReplay,
    RejectedSourcePolicy,
    RejectedMessageMetadata,
    RejectedPendingBudget,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct UpsertContext<'a> {
    pub source: SocketAddr,
    pub policy: SourcePolicy,
    pub config: &'a ReceiverRuntimeConfig,
    pub protected_key: Option<MessageKey>,
}

#[derive(Debug, Default)]
pub(super) struct ReceiverState {
    completed: HashMap<MessageKey, Instant>,
    completed_index: TimestampKeyIndex,
    pending: HashMap<MessageKey, MessageState>,
    pending_estimated_bytes: usize,
    pending_index: TimestampKeyIndex,
    completion_index: SequenceKeyIndex,
    sender_sessions: HashMap<SenderId, HashMap<u64, SenderSessionState>>,
    tracked_sessions: usize,
}

impl ReceiverState {
    pub(super) fn clear(&mut self) {
        self.completed.clear();
        self.completed_index.clear();
        self.pending.clear();
        self.pending_estimated_bytes = 0;
        self.pending_index.clear();
        self.completion_index.clear();
        self.sender_sessions.clear();
        self.tracked_sessions = 0;
        self.assert_index_invariants();
    }

    pub(super) fn cleanup(&mut self, now: Instant, config: &ReceiverRuntimeConfig) {
        loop {
            let Some((completed_at, key)) = self.completed_index.oldest() else {
                break;
            };
            let stale = !self.completed.contains_key(&key);
            if !stale && now.duration_since(completed_at) <= config.dedup_window() {
                break;
            }
            self.remove_completed(&key);
        }
        self.enforce_completed_capacity(config);
        loop {
            let Some((created_at, key)) = self.pending_index.oldest() else {
                break;
            };
            if now.duration_since(created_at) <= config.pending_max_age() {
                break;
            }
            self.remove_pending(&key);
        }
        self.sender_sessions.retain(|_, sessions| {
            sessions.retain(|_, state| {
                now.duration_since(state.last_seen) <= config.session_freshness_retention()
            });
            !sessions.is_empty()
        });
        self.tracked_sessions = self
            .sender_sessions
            .values()
            .map(std::collections::HashMap::len)
            .sum();
        self.assert_index_invariants();
    }

    pub(super) fn upsert_from_packet(
        &mut self,
        header: &PacketHeader,
        payload: &[u8],
        upsert_context: UpsertContext<'_>,
    ) -> UpsertOutcome {
        let UpsertContext {
            source,
            policy,
            config,
            protected_key,
        } = upsert_context;
        let key = header.key();

        let mut updated_existing = false;
        let mut existing_complete = false;
        if let Some(state) = self.pending.get_mut(&key) {
            if !policy.allows_existing(state.first_source, source) {
                return UpsertOutcome::RejectedSourcePolicy;
            }
            match state.update(header, payload) {
                PacketUpdateOutcome::Accepted => {
                    state.last_activity_at = Instant::now();
                    updated_existing = true;
                    existing_complete = state.is_complete();
                }
                PacketUpdateOutcome::Replayed => return UpsertOutcome::RejectedReplay,
                PacketUpdateOutcome::InvalidMetadata => {
                    return UpsertOutcome::RejectedMessageMetadata;
                }
            }
        }
        if updated_existing {
            if existing_complete {
                self.enqueue_complete(key);
            }
            return UpsertOutcome::Accepted;
        }

        if !policy.allows_first(source) {
            return UpsertOutcome::RejectedSourcePolicy;
        }

        let Ok(state) = MessageState::new(header, payload, key, source, config) else {
            return UpsertOutcome::RejectedMessageMetadata;
        };
        let incoming_message_bytes = Self::pending_cost(&state);
        if !self.evict_oldest_if_needed(incoming_message_bytes, config, protected_key) {
            return UpsertOutcome::RejectedPendingBudget;
        }
        self.insert_pending(key, state);
        UpsertOutcome::Accepted
    }

    #[cfg(debug_assertions)]
    fn assert_index_invariants(&self) {
        self.completed_index.debug_assert_invariants();
        self.pending_index.debug_assert_invariants();
        self.completion_index.debug_assert_invariants();

        debug_assert_eq!(self.completed.len(), self.completed_index.len());
        for key in self.completed.keys() {
            debug_assert!(self.completed_index.contains_key(key));
        }

        debug_assert_eq!(self.pending.len(), self.pending_index.len());
        for key in self.pending.keys() {
            debug_assert!(self.pending_index.contains_key(key));
        }

        debug_assert_eq!(
            self.pending_estimated_bytes,
            self.pending.values().map(Self::pending_cost).sum::<usize>()
        );

        debug_assert!(self.completion_index.len() <= self.pending.len());
        for (_, key) in self.completion_index.entries() {
            debug_assert!(
                self.pending.contains_key(&key),
                "completion index contains non-pending key: {:?}",
                key
            );
        }

        debug_assert_eq!(
            self.tracked_sessions,
            self.sender_sessions
                .values()
                .map(std::collections::HashMap::len)
                .sum::<usize>()
        );
    }

    #[cfg(not(debug_assertions))]
    fn assert_index_invariants(&self) {}
}
