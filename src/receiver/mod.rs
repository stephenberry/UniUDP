use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::error::{ReceiveRejectReason, Result, UniUdpError};
use crate::header_validation::validate_header_invariants;
use crate::packet::{parse_packet_view_with_wire_security_parts, verify_packet_auth};
use crate::types::{
    AuthMode, CompletionReason, MessageReport, PacketAuthKey, ReceiveDiagnostics, ReceiveOptions,
    ReceiverConfig, ReceiverRuntimeConfig,
};

mod loop_logic;
mod message_state;
mod session;
mod socket;
mod state;

use state::{ReceiverState, UpsertContext, UpsertOutcome};

enum ReceiveLoopDecision {
    ReturnReport(MessageReport),
    AwaitPacket {
        cleanup_at: Instant,
        wait_time: Duration,
    },
    Timeout(CompletionReason),
}

enum ReceivePacketOutcome {
    Continue,
    Complete(Box<MessageReport>),
    InactivityTimeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
/// Controls whether [`Receiver::receive_loop`] continues after a message.
pub enum ReceiveLoopControl {
    Continue,
    Stop,
}

/// Stateful receive/reassembly engine.
///
/// `Receiver` is `Send + Sync`, but receive APIs require `&mut self` to
/// serialize state-machine progress and preserve deterministic mutation order.
#[derive(Debug)]
pub struct Receiver {
    state: ReceiverState,
    config: ReceiverRuntimeConfig,
    cleanup_recheck_interval: Duration,
    auth_keys_by_id: HashMap<u32, PacketAuthKey>,
    last_receive_diagnostics: ReceiveDiagnostics,
    recv_buffer: Vec<u8>,
}

impl Default for Receiver {
    fn default() -> Self {
        let config = ReceiverRuntimeConfig::default();
        Self {
            state: ReceiverState::default(),
            cleanup_recheck_interval: config.dedup_window().min(config.pending_max_age()),
            config,
            auth_keys_by_id: HashMap::new(),
            last_receive_diagnostics: ReceiveDiagnostics::default(),
            recv_buffer: Vec::new(),
        }
    }
}

impl Receiver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn try_with_config(config: ReceiverConfig) -> Result<Self> {
        config.validate()?;
        let (runtime_config, auth_keys) = config.into_parts();
        let auth_keys_by_id: HashMap<u32, PacketAuthKey> = auth_keys
            .into_iter()
            .map(|auth| (auth.key_id(), auth.key().clone()))
            .collect();
        Ok(Self {
            state: ReceiverState::default(),
            config: runtime_config,
            cleanup_recheck_interval: runtime_config
                .dedup_window()
                .min(runtime_config.pending_max_age()),
            auth_keys_by_id,
            last_receive_diagnostics: ReceiveDiagnostics::default(),
            recv_buffer: Vec::new(),
        })
    }

    /// Returns receiver runtime settings.
    ///
    /// This is a read-only runtime view with no authentication key material.
    /// Values are derived from validated [`ReceiverConfig`].
    pub fn config(&self) -> &ReceiverRuntimeConfig {
        &self.config
    }

    pub fn last_receive_diagnostics(&self) -> ReceiveDiagnostics {
        self.last_receive_diagnostics
    }

    pub fn clear_state(&mut self) {
        self.state.clear();
        self.last_receive_diagnostics = ReceiveDiagnostics::default();
    }

    /// Clears receiver protocol state and releases internal receive-buffer
    /// allocation back to the allocator.
    ///
    /// Prefer [`Receiver::clear_state`] in hot paths to keep the buffer warmed.
    /// Use this method when reclaiming memory is more important than avoiding
    /// future reallocation.
    pub fn clear_state_and_shrink(&mut self) {
        self.clear_state();
        self.recv_buffer.clear();
        self.recv_buffer.shrink_to_fit();
    }

    fn ensure_recv_buffer(&mut self) {
        let target = self.config.max_receive_datagram_size();
        if self.recv_buffer.len() != target {
            self.recv_buffer.resize(target, 0_u8);
        }
    }

    fn finish_with_report(
        &mut self,
        diagnostics: ReceiveDiagnostics,
        report: MessageReport,
    ) -> Result<MessageReport> {
        self.last_receive_diagnostics = diagnostics;
        Ok(report)
    }

    fn finish_with_error<T>(
        &mut self,
        diagnostics: ReceiveDiagnostics,
        err: UniUdpError,
    ) -> Result<T> {
        self.last_receive_diagnostics = diagnostics;
        Err(err)
    }

    fn increment_rejection(diagnostics: &mut ReceiveDiagnostics, reason: ReceiveRejectReason) {
        match reason {
            ReceiveRejectReason::Authentication => {
                diagnostics.auth_rejections = diagnostics.auth_rejections.saturating_add(1);
            }
            ReceiveRejectReason::Replay => {
                diagnostics.replay_rejections = diagnostics.replay_rejections.saturating_add(1);
            }
            ReceiveRejectReason::SourcePolicy => {
                diagnostics.source_rejections = diagnostics.source_rejections.saturating_add(1);
            }
            ReceiveRejectReason::MessageMetadata => {
                diagnostics.metadata_rejections = diagnostics.metadata_rejections.saturating_add(1);
            }
            ReceiveRejectReason::PendingBudget => {
                diagnostics.pending_budget_rejections =
                    diagnostics.pending_budget_rejections.saturating_add(1);
            }
            ReceiveRejectReason::SessionBudget => {
                diagnostics.session_budget_rejections =
                    diagnostics.session_budget_rejections.saturating_add(1);
            }
        }
    }

    fn handle_decode_error(
        &mut self,
        diagnostics: &mut ReceiveDiagnostics,
        options: &ReceiveOptions,
        err: UniUdpError,
    ) -> Result<()> {
        diagnostics.decode_errors = diagnostics.decode_errors.saturating_add(1);
        if options.strict_rejections() {
            return self.finish_with_error(*diagnostics, err);
        }
        Ok(())
    }

    fn handle_rejection(
        &mut self,
        diagnostics: &mut ReceiveDiagnostics,
        options: &ReceiveOptions,
        reason: ReceiveRejectReason,
    ) -> Result<()> {
        Self::increment_rejection(diagnostics, reason);
        if options.strict_rejections() {
            return self.finish_with_error(*diagnostics, UniUdpError::RejectedPacket { reason });
        }
        Ok(())
    }

    fn upsert_reject_reason(outcome: UpsertOutcome) -> ReceiveRejectReason {
        match outcome {
            UpsertOutcome::Accepted => unreachable!("accepted outcome is not a rejection"),
            UpsertOutcome::RejectedReplay => ReceiveRejectReason::Replay,
            UpsertOutcome::RejectedSourcePolicy => ReceiveRejectReason::SourcePolicy,
            UpsertOutcome::RejectedMessageMetadata => ReceiveRejectReason::MessageMetadata,
            UpsertOutcome::RejectedPendingBudget => ReceiveRejectReason::PendingBudget,
        }
    }

    fn handle_packet(
        &mut self,
        packet_len: usize,
        source: SocketAddr,
        cleanup_at: Instant,
        options: &ReceiveOptions,
        diagnostics: &mut ReceiveDiagnostics,
    ) -> Result<Option<MessageReport>> {
        let packet = &self.recv_buffer[..packet_len];
        let (header, payload, security) = match parse_packet_view_with_wire_security_parts(packet) {
            Ok(parsed) => parsed,
            Err(err @ UniUdpError::Decode { .. }) => {
                self.handle_decode_error(diagnostics, options, err)?;
                return Ok(None);
            }
            Err(err) => return self.finish_with_error(*diagnostics, err),
        };

        let is_authenticated =
            match self.config.auth_mode() {
                AuthMode::Disabled => false,
                AuthMode::Optional => {
                    if !security.authenticated {
                        false
                    } else {
                        let valid = self.auth_keys_by_id.get(&security.auth_key_id).is_some_and(
                            |auth_key| verify_packet_auth(packet, payload, security, auth_key),
                        );
                        if !valid {
                            self.handle_rejection(
                                diagnostics,
                                options,
                                ReceiveRejectReason::Authentication,
                            )?;
                            return Ok(None);
                        }
                        true
                    }
                }
                AuthMode::Require => {
                    let valid = security.authenticated
                        && self.auth_keys_by_id.get(&security.auth_key_id).is_some_and(
                            |auth_key| verify_packet_auth(packet, payload, security, auth_key),
                        );
                    if !valid {
                        self.handle_rejection(
                            diagnostics,
                            options,
                            ReceiveRejectReason::Authentication,
                        )?;
                        return Ok(None);
                    }
                    true
                }
            };
        let key = header.key();
        let now = Instant::now();
        // Skip duplicate cleanup in the hot path when nothing could have become
        // stale since the loop cleanup. Re-run only if enough time elapsed.
        if now.duration_since(cleanup_at) >= self.cleanup_recheck_interval {
            self.state.cleanup(now, &self.config);
        }
        let session_outcome = self
            .state
            .check_session_nonce(key.sender_id, header.session_nonce);
        if is_authenticated
            && !self
                .state
                .can_track_session(key.sender_id, key.session_nonce, &self.config)
        {
            self.handle_rejection(diagnostics, options, ReceiveRejectReason::SessionBudget)?;
            return Ok(None);
        }
        if is_authenticated
            && !self
                .state
                .is_message_fresh(key, &self.config, session_outcome)
        {
            self.handle_rejection(diagnostics, options, ReceiveRejectReason::Replay)?;
            return Ok(None);
        }
        if self.state.is_duplicate(key) {
            diagnostics.duplicate_packets = diagnostics.duplicate_packets.saturating_add(1);
            if options.strict_rejections() {
                self.handle_rejection(diagnostics, options, ReceiveRejectReason::Replay)?;
            }
            return Ok(None);
        }
        if validate_header_invariants(&header, payload.len()).is_err() {
            self.handle_rejection(diagnostics, options, ReceiveRejectReason::MessageMetadata)?;
            return Ok(None);
        }

        let upsert_outcome = self.state.upsert_from_packet(
            &header,
            payload,
            UpsertContext {
                source,
                policy: options.source_policy(),
                config: &self.config,
                protected_key: options.key(),
            },
        );
        if upsert_outcome != UpsertOutcome::Accepted {
            let reason = Self::upsert_reject_reason(upsert_outcome);
            self.handle_rejection(diagnostics, options, reason)?;
            return Ok(None);
        }

        diagnostics.packets_accepted = diagnostics.packets_accepted.saturating_add(1);
        if is_authenticated {
            self.state.note_message_seen(key, now, session_outcome);
        }

        if !self.state.is_pending_complete(key) {
            return Ok(None);
        }
        if options.key().is_some_and(|filter_key| filter_key != key) {
            return Ok(None);
        }

        let Some(complete) = self
            .state
            .remove_pending_if_allowed(key, options.source_policy())
        else {
            return Ok(None);
        };
        if self.state.is_duplicate(complete.key) {
            return Ok(None);
        }

        self.state.mark_completed(complete.key, now, &self.config);
        Ok(Some(complete.build_report(CompletionReason::Completed)))
    }
}
