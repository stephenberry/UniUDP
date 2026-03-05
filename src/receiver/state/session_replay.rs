use std::time::Instant;

use crate::receiver::session::SessionNonceOutcome;
use crate::types::{MessageKey, ReceiverRuntimeConfig, SenderId};

use super::{ReceiverState, SenderSessionState};

impl ReceiverState {
    pub(in crate::receiver) fn can_track_session(
        &self,
        sender_id: SenderId,
        session_nonce: u64,
        config: &ReceiverRuntimeConfig,
    ) -> bool {
        let sender_sessions = self.sender_sessions.get(&sender_id);
        if sender_sessions.is_some_and(|sessions| sessions.contains_key(&session_nonce)) {
            return true;
        }
        let tracked_for_sender = sender_sessions.map_or(0, std::collections::HashMap::len);
        self.tracked_sessions < config.max_tracked_sessions_total()
            && tracked_for_sender < config.max_tracked_sessions_per_sender()
    }

    pub(in crate::receiver) fn check_session_nonce(
        &self,
        sender_id: SenderId,
        session_nonce: u64,
    ) -> SessionNonceOutcome {
        let Some(existing_sessions) = self.sender_sessions.get(&sender_id) else {
            return SessionNonceOutcome::Initialize;
        };
        if existing_sessions.contains_key(&session_nonce) {
            SessionNonceOutcome::Current
        } else {
            SessionNonceOutcome::Advance
        }
    }

    pub(in crate::receiver) fn is_message_fresh(
        &self,
        key: MessageKey,
        config: &ReceiverRuntimeConfig,
        session_outcome: SessionNonceOutcome,
    ) -> bool {
        match session_outcome {
            SessionNonceOutcome::Initialize | SessionNonceOutcome::Advance => true,
            SessionNonceOutcome::Current => {
                let Some(session) = self
                    .sender_sessions
                    .get(&key.sender_id)
                    .and_then(|sessions| sessions.get(&key.session_nonce))
                else {
                    return true;
                };
                if config.strict_message_ordering() {
                    return key.message_id > session.max_message_id;
                }
                if key.message_id >= session.max_message_id {
                    return true;
                }
                config.unbounded_message_freshness()
                    || session.max_message_id.saturating_sub(key.message_id)
                        <= config.message_freshness_window()
            }
        }
    }

    pub(in crate::receiver) fn note_message_seen(
        &mut self,
        key: MessageKey,
        now: Instant,
        session_outcome: SessionNonceOutcome,
    ) {
        match session_outcome {
            SessionNonceOutcome::Advance | SessionNonceOutcome::Initialize => {
                let inserted = self
                    .sender_sessions
                    .entry(key.sender_id)
                    .or_default()
                    .insert(
                        key.session_nonce,
                        SenderSessionState {
                            max_message_id: key.message_id,
                            last_seen: now,
                        },
                    );
                if inserted.is_none() {
                    self.tracked_sessions = self.tracked_sessions.saturating_add(1);
                }
            }
            SessionNonceOutcome::Current => {
                let sender_sessions = self.sender_sessions.entry(key.sender_id).or_default();
                let session = sender_sessions
                    .get_mut(&key.session_nonce)
                    .expect("current session outcome requires existing sender/session state");
                session.max_message_id = session.max_message_id.max(key.message_id);
                session.last_seen = now;
            }
        }
    }
}
