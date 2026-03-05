use std::mem::size_of;
use std::net::SocketAddr;
use std::time::Instant;

use crate::error::{Result, UniUdpError, ValidationContext};
use crate::fec::{
    fec_group_size_from_field, fec_is_parity, fec_is_rs, fec_mode_from_field, rs_params_from_field,
    FecMode,
};
use crate::types::{
    CompletionReason, MessageChunk, MessageKey, MessageReport, PacketHeader, ReceiverRuntimeConfig,
};

struct CachedRsEncoder(reed_solomon_erasure::galois_8::ReedSolomon);

impl std::fmt::Debug for CachedRsEncoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReedSolomon({}+{})",
            self.0.data_shard_count(),
            self.0.parity_shard_count()
        )
    }
}

#[derive(Debug)]
pub(super) struct MessageState {
    pub(super) key: MessageKey,
    total_chunks: usize,
    received_count: usize,
    chunk_size: usize,
    pub(super) message_length: usize,
    redundancy: usize,
    fec_mode: FecMode,
    fec_group_size: usize,
    parity_shards_per_group: usize,
    chunks: Vec<Option<Vec<u8>>>,
    chunk_lengths: Vec<usize>,
    min_attempt: Vec<usize>,
    // Indexed by (group_index * parity_shards_per_group + parity_shard_index).
    parity_chunks: Vec<Option<Vec<u8>>>,
    parity_attempts: Vec<usize>,
    fec_recovered: Option<Vec<usize>>,
    fec_recovered_flags: Option<Vec<u8>>,
    rs_encoder: Option<CachedRsEncoder>,
    rs_shard_buf: Vec<Option<Vec<u8>>>,
    pending_bytes_estimate: usize,
    pub(super) first_source: SocketAddr,
    pub(super) created_at: Instant,
    pub(super) last_activity_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PacketUpdateOutcome {
    Accepted,
    Replayed,
    InvalidMetadata,
}

impl MessageState {
    pub(super) fn new(
        header: &PacketHeader,
        payload: &[u8],
        key: MessageKey,
        source: SocketAddr,
        config: &ReceiverRuntimeConfig,
    ) -> Result<Self> {
        let total_chunks = usize::try_from(header.total_chunks).map_err(|_| {
            UniUdpError::validation(
                ValidationContext::MessageMetadata,
                "total_chunks exceeds platform size",
            )
        })?;
        if total_chunks > config.max_receive_chunks() {
            return Err(UniUdpError::validation(
                ValidationContext::MessageMetadata,
                "total_chunks exceeds receiver limit",
            ));
        }

        let message_length = usize::try_from(header.message_length).map_err(|_| {
            UniUdpError::validation(
                ValidationContext::MessageMetadata,
                "message_length exceeds platform size",
            )
        })?;
        if message_length > config.max_receive_message_len() {
            return Err(UniUdpError::validation(
                ValidationContext::MessageMetadata,
                "message_length exceeds receiver limit",
            ));
        }
        let chunk_size = usize::from(header.chunk_size);
        let redundancy = usize::from(header.redundancy);

        let fec_mode = fec_mode_from_field(header.fec_field);
        let fec_group_size = fec_mode.effective_group_size();
        let parity_shards_per_group = fec_mode.parity_packets_per_group();

        let num_groups = if fec_mode.is_enabled() {
            total_chunks.div_ceil(fec_group_size)
        } else {
            0
        };
        let parity_slots = num_groups.saturating_mul(parity_shards_per_group);
        let fec_enabled = fec_mode.is_enabled();

        let rs_encoder = match fec_mode {
            FecMode::ReedSolomon {
                data_shards,
                parity_shards,
            } => reed_solomon_erasure::galois_8::ReedSolomon::new(
                usize::from(data_shards),
                usize::from(parity_shards),
            )
            .ok()
            .map(CachedRsEncoder),
            _ => None,
        };

        let pending_bytes_estimate = Self::estimate_pending_footprint(
            total_chunks,
            parity_slots,
            message_length,
            chunk_size,
        );
        let mut state = Self {
            key,
            total_chunks,
            received_count: 0,
            chunk_size,
            message_length,
            redundancy,
            fec_mode,
            fec_group_size,
            parity_shards_per_group,
            chunks: vec![None; total_chunks],
            chunk_lengths: vec![0; total_chunks],
            min_attempt: vec![redundancy + 1; total_chunks],
            parity_chunks: vec![None; parity_slots],
            parity_attempts: vec![redundancy + 1; parity_slots],
            fec_recovered: fec_enabled.then(Vec::new),
            fec_recovered_flags: fec_enabled.then(|| vec![0_u8; total_chunks]),
            rs_encoder,
            rs_shard_buf: Vec::new(),
            pending_bytes_estimate,
            first_source: source,
            created_at: Instant::now(),
            last_activity_at: Instant::now(),
        };
        if state.update(header, payload) != PacketUpdateOutcome::Accepted {
            return Err(UniUdpError::validation(
                ValidationContext::MessageMetadata,
                "initial packet rejected",
            ));
        }
        Ok(state)
    }

    pub(super) fn is_complete(&self) -> bool {
        self.received_count == self.total_chunks
    }

    pub(super) fn pending_bytes_estimate(&self) -> usize {
        self.pending_bytes_estimate
    }

    fn clear_fec_recovered_marker(&mut self, chunk_index: usize) {
        let Some(flags) = self.fec_recovered_flags.as_mut() else {
            return;
        };
        if flags[chunk_index] == 0 {
            return;
        }
        flags[chunk_index] = 0;
        if let Some(recovered) = self.fec_recovered.as_mut() {
            recovered.retain(|&idx| idx != chunk_index);
        }
    }

    fn expected_chunk_length_for_index(&self, chunk_index: usize) -> usize {
        if chunk_index >= self.total_chunks {
            return 0;
        }
        if chunk_index + 1 == self.total_chunks {
            return self
                .message_length
                .saturating_sub(self.chunk_size * (self.total_chunks - 1));
        }
        self.chunk_size
    }

    pub(super) fn update(&mut self, header: &PacketHeader, payload: &[u8]) -> PacketUpdateOutcome {
        if header.key() != self.key {
            return PacketUpdateOutcome::InvalidMetadata;
        }

        let payload_len_declared = usize::from(header.payload_len);
        if payload_len_declared != payload.len() {
            return PacketUpdateOutcome::InvalidMetadata;
        }
        if payload_len_declared > self.chunk_size {
            return PacketUpdateOutcome::InvalidMetadata;
        }

        if usize::try_from(header.total_chunks).ok() != Some(self.total_chunks) {
            return PacketUpdateOutcome::InvalidMetadata;
        }
        if usize::from(header.chunk_size) != self.chunk_size {
            return PacketUpdateOutcome::InvalidMetadata;
        }
        if usize::try_from(header.message_length).ok() != Some(self.message_length) {
            return PacketUpdateOutcome::InvalidMetadata;
        }

        let redundancy = usize::from(header.redundancy);
        if redundancy < 1 || redundancy != self.redundancy {
            return PacketUpdateOutcome::InvalidMetadata;
        }

        let attempt = usize::from(header.attempt);
        if attempt < 1 || attempt > self.redundancy {
            return PacketUpdateOutcome::InvalidMetadata;
        }

        // Validate FEC mode consistency
        let fec_group_size = fec_group_size_from_field(header.fec_field);
        if fec_group_size < 1 || fec_group_size != self.fec_group_size {
            return PacketUpdateOutcome::InvalidMetadata;
        }
        // Check RS mode consistency
        if fec_is_rs(header.fec_field) != matches!(self.fec_mode, FecMode::ReedSolomon { .. }) {
            return PacketUpdateOutcome::InvalidMetadata;
        }
        // For RS, validate that data_shards and parity_shards match
        if let FecMode::ReedSolomon {
            data_shards,
            parity_shards,
        } = self.fec_mode
        {
            let (hdr_ds, hdr_ps, _) = rs_params_from_field(header.fec_field);
            if hdr_ds != data_shards || hdr_ps != parity_shards {
                return PacketUpdateOutcome::InvalidMetadata;
            }
        }

        let is_parity = fec_is_parity(header.fec_field);

        if is_parity {
            return self.handle_parity_packet(header, payload, attempt);
        }

        let chunk_index = match usize::try_from(header.chunk_index) {
            Ok(idx) => idx,
            Err(_) => return PacketUpdateOutcome::InvalidMetadata,
        };
        if chunk_index >= self.total_chunks {
            return PacketUpdateOutcome::InvalidMetadata;
        }

        let expected_len = self.expected_chunk_length_for_index(chunk_index);
        if payload_len_declared != expected_len {
            return PacketUpdateOutcome::InvalidMetadata;
        }

        if self.chunks[chunk_index].is_none() {
            self.chunks[chunk_index] = Some(payload.to_vec());
            self.received_count = self.received_count.saturating_add(1);
            self.chunk_lengths[chunk_index] = payload_len_declared;
            self.min_attempt[chunk_index] = attempt;
        } else {
            let payload_matches = self.chunks[chunk_index]
                .as_ref()
                .is_some_and(|existing| existing.as_slice() == payload);
            let lower_attempt = attempt < self.min_attempt[chunk_index];
            let was_fec_recovered = self
                .fec_recovered_flags
                .as_ref()
                .and_then(|flags| flags.get(chunk_index))
                .is_some_and(|&flag| flag != 0);

            if !payload_matches {
                if !was_fec_recovered || !lower_attempt {
                    return PacketUpdateOutcome::InvalidMetadata;
                }
                self.chunks[chunk_index] = Some(payload.to_vec());
                self.chunk_lengths[chunk_index] = payload_len_declared;
                self.min_attempt[chunk_index] = attempt;
                self.clear_fec_recovered_marker(chunk_index);
            } else if lower_attempt {
                self.min_attempt[chunk_index] = attempt;
                self.clear_fec_recovered_marker(chunk_index);
            } else {
                return PacketUpdateOutcome::Replayed;
            }
        }

        if self.fec_mode.is_enabled() {
            let group_index = chunk_index / self.fec_group_size;
            self.try_recover_group(group_index);
        }
        PacketUpdateOutcome::Accepted
    }

    fn handle_parity_packet(
        &mut self,
        header: &PacketHeader,
        payload: &[u8],
        attempt: usize,
    ) -> PacketUpdateOutcome {
        let payload_len_declared = usize::from(header.payload_len);
        if payload_len_declared != self.chunk_size {
            return PacketUpdateOutcome::InvalidMetadata;
        }
        let group_start = match usize::try_from(header.chunk_index) {
            Ok(idx) => idx,
            Err(_) => return PacketUpdateOutcome::InvalidMetadata,
        };
        if group_start >= self.total_chunks {
            return PacketUpdateOutcome::InvalidMetadata;
        }
        if !self.fec_mode.is_enabled() {
            return PacketUpdateOutcome::InvalidMetadata;
        }
        if group_start % self.fec_group_size != 0 {
            return PacketUpdateOutcome::InvalidMetadata;
        }
        let group_index = group_start / self.fec_group_size;

        // Determine parity slot index
        let parity_shard_index = if fec_is_rs(header.fec_field) {
            let (_, _, psi) = rs_params_from_field(header.fec_field);
            let psi = usize::from(psi);
            if psi >= self.parity_shards_per_group {
                return PacketUpdateOutcome::InvalidMetadata;
            }
            psi
        } else {
            0
        };

        let slot = group_index * self.parity_shards_per_group + parity_shard_index;
        if slot >= self.parity_chunks.len() {
            return PacketUpdateOutcome::InvalidMetadata;
        }

        if let Some(existing_parity) = self.parity_chunks[slot].as_ref() {
            if existing_parity.as_slice() != payload {
                return PacketUpdateOutcome::InvalidMetadata;
            }
            if attempt >= self.parity_attempts[slot] {
                return PacketUpdateOutcome::Replayed;
            }
        }
        self.parity_chunks[slot] = Some(payload.to_vec());
        self.parity_attempts[slot] = attempt;

        self.try_recover_group(group_index);
        PacketUpdateOutcome::Accepted
    }

    fn try_recover_group(&mut self, group_index: usize) {
        if let FecMode::ReedSolomon {
            data_shards,
            parity_shards,
        } = self.fec_mode
        {
            self.try_recover_group_rs(group_index, data_shards, parity_shards);
        }
    }

    fn try_recover_group_rs(&mut self, group_index: usize, data_shards: u8, parity_shards: u8) {
        let ds = usize::from(data_shards);
        let ps = usize::from(parity_shards);
        let start_pos = group_index * ds;
        let end_pos = (start_pos + ds).min(self.total_chunks);
        let actual_data_in_group = end_pos - start_pos;

        // Count available data shards
        let mut data_present = 0_usize;
        let mut data_missing = 0_usize;
        for pos in start_pos..end_pos {
            if self.chunks[pos].is_some() {
                data_present += 1;
            } else {
                data_missing += 1;
            }
        }

        // If all data present, nothing to recover
        if data_missing == 0 {
            return;
        }

        // Count available parity shards
        let parity_base = group_index * ps;
        let mut parity_present = 0_usize;
        for pi in 0..ps {
            if parity_base + pi < self.parity_chunks.len()
                && self.parity_chunks[parity_base + pi].is_some()
            {
                parity_present += 1;
            }
        }

        // RS requires at least ds total shards to reconstruct.
        // In a partial final group, implicit zero-filled padding shards are
        // always available and count toward the total.
        let implicit_zero_shards = ds - actual_data_in_group;
        let total_available = data_present + implicit_zero_shards + parity_present;
        if total_available < ds {
            return;
        }

        let encoder = match self.rs_encoder.as_ref() {
            Some(e) => &e.0,
            None => return,
        };

        // Reuse the shard buffer across recovery attempts.
        self.rs_shard_buf.clear();

        // Data shards
        for pos in start_pos..end_pos {
            match &self.chunks[pos] {
                Some(chunk) => {
                    let mut padded = vec![0_u8; self.chunk_size];
                    padded[..chunk.len()].copy_from_slice(chunk);
                    self.rs_shard_buf.push(Some(padded));
                }
                None => self.rs_shard_buf.push(None),
            }
        }
        // Pad with present zero shards for partial final group
        for _ in actual_data_in_group..ds {
            self.rs_shard_buf.push(Some(vec![0_u8; self.chunk_size]));
        }
        // Parity shards
        for pi in 0..ps {
            let slot = parity_base + pi;
            if slot < self.parity_chunks.len() {
                self.rs_shard_buf.push(self.parity_chunks[slot].clone());
            } else {
                self.rs_shard_buf.push(None);
            }
        }

        // Reconstruct
        if encoder.reconstruct(&mut self.rs_shard_buf).is_err() {
            return;
        }

        // Extract recovered data shards
        for (i, pos) in (start_pos..end_pos).enumerate() {
            if self.chunks[pos].is_none() {
                if let Some(Some(recovered_padded)) = self.rs_shard_buf.get(i) {
                    let expected_len = self.expected_chunk_length_for_index(pos);
                    let recovered = recovered_padded[..expected_len].to_vec();
                    if self.chunks[pos].is_none() {
                        self.received_count = self.received_count.saturating_add(1);
                    }
                    self.chunks[pos] = Some(recovered);
                    self.chunk_lengths[pos] = expected_len;
                    // Use max parity attempt + 1
                    let max_parity_attempt = (0..ps)
                        .map(|pi| {
                            let slot = parity_base + pi;
                            if slot < self.parity_attempts.len() {
                                self.parity_attempts[slot]
                            } else {
                                0
                            }
                        })
                        .filter(|&a| a <= self.redundancy)
                        .max()
                        .unwrap_or(0);
                    self.min_attempt[pos] = max_parity_attempt.saturating_add(1);
                    if let (Some(flags), Some(recovered_list)) = (
                        self.fec_recovered_flags.as_mut(),
                        self.fec_recovered.as_mut(),
                    ) {
                        if flags[pos] == 0 {
                            flags[pos] = 1;
                            recovered_list.push(pos);
                        }
                    }
                }
            }
        }
    }

    fn estimate_pending_footprint(
        total_chunks: usize,
        parity_slots: usize,
        message_length: usize,
        chunk_size: usize,
    ) -> usize {
        let chunk_slots = total_chunks.saturating_mul(size_of::<Option<Vec<u8>>>());
        let chunk_lengths = total_chunks.saturating_mul(size_of::<usize>());
        let chunk_attempts = total_chunks.saturating_mul(size_of::<usize>());
        let recovered_tracking = if parity_slots > 0 {
            total_chunks.saturating_mul(size_of::<usize>())
        } else {
            0
        };
        let recovered_flags = if parity_slots > 0 { total_chunks } else { 0 };
        let parity_slots_meta = parity_slots.saturating_mul(size_of::<Option<Vec<u8>>>());
        let parity_attempts = parity_slots.saturating_mul(size_of::<usize>());
        let parity_payload = parity_slots.saturating_mul(chunk_size);

        size_of::<Self>()
            .saturating_add(chunk_slots)
            .saturating_add(chunk_lengths)
            .saturating_add(chunk_attempts)
            .saturating_add(recovered_tracking)
            .saturating_add(recovered_flags)
            .saturating_add(parity_slots_meta)
            .saturating_add(parity_attempts)
            .saturating_add(message_length)
            .saturating_add(parity_payload)
    }

    pub(super) fn build_report(self, reason: CompletionReason) -> MessageReport {
        let fec_mode = self.fec_mode;
        let MessageState {
            key,
            total_chunks,
            chunk_size,
            message_length,
            redundancy,
            chunks,
            min_attempt,
            fec_recovered,
            first_source,
            ..
        } = self;
        let fec_recovered = fec_recovered.unwrap_or_default();

        let mut received_chunks = Vec::with_capacity(total_chunks);
        let mut lost_chunks = Vec::new();
        for (idx, chunk) in chunks.into_iter().enumerate() {
            match chunk {
                Some(payload) => received_chunks.push(MessageChunk {
                    index: idx,
                    payload,
                }),
                None => lost_chunks.push(idx),
            }
        }

        let chunks_received = received_chunks.len();
        let redundancy_required = if lost_chunks.is_empty() {
            min_attempt.into_iter().max().unwrap_or(0)
        } else {
            redundancy + 1
        };
        MessageReport {
            key,
            message_length,
            chunk_size,
            received_chunks,
            chunks_expected: total_chunks,
            chunks_received,
            lost_chunks,
            redundancy_requested: redundancy,
            redundancy_required,
            fec_mode,
            fec_recovered_chunks: fec_recovered,
            source: first_source,
            completion_reason: reason,
        }
    }
}
