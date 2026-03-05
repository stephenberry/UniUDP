use crate::fec::FecMode;
use crate::types::{MessageKey, PacketHeader, SenderId};

#[derive(Debug, Clone, Copy)]
pub(super) struct ParityContext {
    pub(super) sender_id: SenderId,
    pub(super) message_id: u64,
    pub(super) session_nonce: u64,
    pub(super) total_chunks: usize,
    pub(super) message_length: usize,
    pub(super) chunk_size_u16: u16,
    pub(super) redundancy_u16: u16,
    pub(super) fec_mode: FecMode,
    pub(super) fec_group_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct SendPlan {
    pub(super) key: MessageKey,
    pub(super) redundancy_u16: u16,
    pub(super) chunk_size_u16: u16,
    pub(super) chunk_size: usize,
    pub(super) fec_mode: FecMode,
    pub(super) fec_group_size: usize,
    pub(super) delay: std::time::Duration,
    pub(super) message_length: usize,
    pub(super) total_chunks: usize,
    pub(super) data_field: u16,
}

impl SendPlan {
    pub(super) fn parity_context(self) -> ParityContext {
        ParityContext {
            sender_id: self.key.sender_id,
            message_id: self.key.message_id,
            session_nonce: self.key.session_nonce,
            total_chunks: self.total_chunks,
            message_length: self.message_length,
            chunk_size_u16: self.chunk_size_u16,
            redundancy_u16: self.redundancy_u16,
            fec_mode: self.fec_mode,
            fec_group_size: self.fec_group_size,
        }
    }

    pub(super) fn chunk_bounds(self, chunk_index: usize) -> (usize, usize) {
        let start_idx = chunk_index * self.chunk_size;
        let stop_idx = (start_idx + self.chunk_size).min(self.message_length);
        (start_idx, stop_idx)
    }

    pub(super) fn data_header(self, chunk_index: usize, payload_len: usize) -> PacketHeader {
        let chunk_index = u32::try_from(chunk_index).expect("chunk_index validated in send plan");
        let total_chunks =
            u32::try_from(self.total_chunks).expect("total_chunks validated in send plan");
        let message_length =
            u32::try_from(self.message_length).expect("message_length validated in send plan");
        let payload_len = u16::try_from(payload_len).expect("payload_len is bounded by chunk_size");
        PacketHeader {
            sender_id: self.key.sender_id,
            message_id: self.key.message_id,
            session_nonce: self.key.session_nonce,
            chunk_index,
            total_chunks,
            message_length,
            chunk_size: self.chunk_size_u16,
            payload_len,
            redundancy: self.redundancy_u16,
            attempt: 0,
            fec_field: self.data_field,
        }
    }
}
