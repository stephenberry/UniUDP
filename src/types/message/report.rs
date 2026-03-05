use std::net::SocketAddr;

use crate::fec::FecMode;
use crate::types::{CompletionReason, MessageKey};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageChunk {
    pub index: usize,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MessageReport {
    pub key: MessageKey,
    /// Declared message length from packet metadata.
    pub message_length: usize,
    /// Declared chunk size from packet metadata.
    pub chunk_size: usize,
    /// Chunks that were received (including FEC-recovered chunks), keyed by
    /// zero-based chunk index.
    ///
    /// Missing chunk ranges are omitted to avoid materializing a large
    /// zero-filled payload for partial reports.
    pub received_chunks: Vec<MessageChunk>,
    pub chunks_expected: usize,
    pub chunks_received: usize,
    /// Zero-based indices of chunks that were not available in the report.
    pub lost_chunks: Vec<usize>,
    pub redundancy_requested: usize,
    pub redundancy_required: usize,
    pub fec_mode: FecMode,
    pub fec_recovered_chunks: Vec<usize>,
    pub source: SocketAddr,
    pub completion_reason: CompletionReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum IncompletePayloadError {
    /// The report does not contain every expected chunk.
    MissingChunks {
        lost_chunks: Vec<usize>,
        chunks_received: usize,
        chunks_expected: usize,
        completion_reason: CompletionReason,
    },
}

impl std::fmt::Display for IncompletePayloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingChunks {
                lost_chunks,
                chunks_received,
                chunks_expected,
                completion_reason,
            } => write!(
                f,
                "message is incomplete (received {chunks_received}/{chunks_expected} chunks, lost={lost_chunks:?}, completion={completion_reason:?})"
            ),
        }
    }
}

impl std::error::Error for IncompletePayloadError {}

impl MessageReport {
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.lost_chunks.is_empty()
    }

    /// Materialize a dense payload only when all chunks are present.
    ///
    /// Returns an error for partial reports so callers do not accidentally
    /// treat zero-filled holes as valid application data.
    pub fn try_materialize_complete(&self) -> std::result::Result<Vec<u8>, IncompletePayloadError> {
        if !self.is_complete() {
            return Err(IncompletePayloadError::MissingChunks {
                lost_chunks: self.lost_chunks.clone(),
                chunks_received: self.chunks_received,
                chunks_expected: self.chunks_expected,
                completion_reason: self.completion_reason,
            });
        }
        Ok(self.materialize_payload_lossy())
    }

    /// Materialize a dense payload view where missing chunks are represented as
    /// zero-filled placeholders at their original offsets.
    #[must_use]
    pub fn materialize_payload_lossy(&self) -> Vec<u8> {
        let mut out = vec![0_u8; self.message_length];
        for chunk in &self.received_chunks {
            if chunk.index >= self.chunks_expected {
                continue;
            }
            let start = chunk.index.saturating_mul(self.chunk_size);
            if start >= self.message_length {
                continue;
            }
            let max_copy = (self.message_length - start).min(self.chunk_size);
            let copy_len = max_copy.min(chunk.payload.len());
            if copy_len > 0 {
                out[start..start + copy_len].copy_from_slice(&chunk.payload[..copy_len]);
            }
        }
        out
    }

    /// Materialize a dense payload if `message_length <= max_len`.
    ///
    /// Returns `None` when the declared payload is larger than `max_len`.
    #[must_use]
    pub fn materialize_payload_bounded(&self, max_len: usize) -> Option<Vec<u8>> {
        if self.message_length > max_len {
            return None;
        }
        Some(self.materialize_payload_lossy())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::error::UniUdpError;
    use crate::fec::FecMode;
    use crate::types::{
        CompletionReason, IncompletePayloadError, MessageChunk, MessageKey, MessageReport, SenderId,
    };

    fn sample_report() -> MessageReport {
        MessageReport {
            key: MessageKey {
                sender_id: SenderId(7),
                session_nonce: 1,
                message_id: 2,
            },
            message_length: 5,
            chunk_size: 5,
            received_chunks: vec![MessageChunk {
                index: 0,
                payload: b"hello".to_vec(),
            }],
            chunks_expected: 1,
            chunks_received: 1,
            lost_chunks: Vec::new(),
            redundancy_requested: 1,
            redundancy_required: 1,
            fec_mode: FecMode::None,
            fec_recovered_chunks: Vec::new(),
            source: "127.0.0.1:9999"
                .parse::<SocketAddr>()
                .expect("valid socket addr"),
            completion_reason: CompletionReason::Completed,
        }
    }

    #[test]
    fn materialize_payload_bounded_rejects_large_message_length() {
        let report = sample_report();
        assert_eq!(report.materialize_payload_bounded(4), None);
    }

    #[test]
    fn materialize_payload_bounded_returns_payload_within_limit() {
        let report = sample_report();
        assert_eq!(
            report.materialize_payload_bounded(5),
            Some(b"hello".to_vec())
        );
    }

    #[test]
    fn try_materialize_complete_returns_payload_for_complete_report() {
        let report = sample_report();
        assert_eq!(
            report.try_materialize_complete().unwrap(),
            b"hello".to_vec()
        );
    }

    #[test]
    fn try_materialize_complete_rejects_partial_report() {
        let mut report = sample_report();
        report.chunks_expected = 2;
        report.chunks_received = 1;
        report.lost_chunks = vec![1];
        report.completion_reason = CompletionReason::InactivityTimeout;

        let err = report.try_materialize_complete().unwrap_err();
        assert!(matches!(
            err,
            IncompletePayloadError::MissingChunks {
                chunks_received: 1,
                chunks_expected: 2,
                completion_reason: CompletionReason::InactivityTimeout,
                ..
            }
        ));
    }

    #[test]
    fn incomplete_payload_error_converts_to_uniudp_error() {
        let mut report = sample_report();
        report.chunks_expected = 2;
        report.chunks_received = 1;
        report.lost_chunks = vec![1];
        let err = report
            .try_materialize_complete()
            .expect_err("partial report should return incomplete-payload error");
        let uniudp: UniUdpError = err.into();
        assert!(matches!(
            uniudp,
            UniUdpError::IncompletePayload(IncompletePayloadError::MissingChunks {
                chunks_received: 1,
                chunks_expected: 2,
                ..
            })
        ));
    }

    #[test]
    fn materialize_payload_lossy_zero_fills_missing_chunks() {
        let mut report = sample_report();
        report.message_length = 10;
        report.chunk_size = 5;
        report.chunks_expected = 2;
        report.chunks_received = 1;
        report.lost_chunks = vec![1];

        assert_eq!(
            report.materialize_payload_lossy(),
            b"hello\0\0\0\0\0".to_vec()
        );
    }
}
