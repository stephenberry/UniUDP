use crate::fec::{fec_group_size_from_field, fec_is_parity, fec_is_rs, rs_params_from_field};
use crate::types::{PacketHeader, HEADER_LENGTH, MAX_UDP_PAYLOAD_HARD_LIMIT};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HeaderInvariantViolation {
    pub(crate) message: &'static str,
    pub(crate) field: &'static str,
    pub(crate) expected: String,
    pub(crate) actual: String,
}

impl HeaderInvariantViolation {
    fn new(
        message: &'static str,
        field: &'static str,
        expected: impl Into<String>,
        actual: impl Into<String>,
    ) -> Self {
        Self {
            message,
            field,
            expected: expected.into(),
            actual: actual.into(),
        }
    }
}

pub(crate) fn validate_header_invariants(
    header: &PacketHeader,
    payload_len: usize,
) -> std::result::Result<(), HeaderInvariantViolation> {
    if payload_len != usize::from(header.payload_len) {
        return Err(HeaderInvariantViolation::new(
            "payload_len does not match payload bytes",
            "payload_len",
            payload_len.to_string(),
            header.payload_len.to_string(),
        ));
    }

    let chunk_size = usize::from(header.chunk_size);
    if chunk_size == 0 {
        return Err(HeaderInvariantViolation::new(
            "chunk_size must be positive",
            "chunk_size",
            "> 0",
            header.chunk_size.to_string(),
        ));
    }
    if chunk_size.saturating_add(HEADER_LENGTH) > MAX_UDP_PAYLOAD_HARD_LIMIT {
        return Err(HeaderInvariantViolation::new(
            "chunk_size exceeds UDP datagram payload limit",
            "chunk_size",
            format!(
                "<= {}",
                MAX_UDP_PAYLOAD_HARD_LIMIT.saturating_sub(HEADER_LENGTH)
            ),
            header.chunk_size.to_string(),
        ));
    }
    if payload_len > chunk_size {
        return Err(HeaderInvariantViolation::new(
            "payload length exceeds chunk_size declared in header",
            "payload_len",
            format!("<= {}", header.chunk_size),
            payload_len.to_string(),
        ));
    }

    if header.total_chunks == 0 {
        return Err(HeaderInvariantViolation::new(
            "total_chunks must be positive",
            "total_chunks",
            "> 0",
            header.total_chunks.to_string(),
        ));
    }
    if header.chunk_index >= header.total_chunks {
        return Err(HeaderInvariantViolation::new(
            "chunk_index is out of bounds for total_chunks",
            "chunk_index",
            format!("< {}", header.total_chunks),
            header.chunk_index.to_string(),
        ));
    }

    if header.redundancy == 0 {
        return Err(HeaderInvariantViolation::new(
            "redundancy must be at least 1",
            "redundancy",
            ">= 1",
            header.redundancy.to_string(),
        ));
    }
    if header.attempt == 0 || header.attempt > header.redundancy {
        return Err(HeaderInvariantViolation::new(
            "attempt must be within redundancy range",
            "attempt",
            format!("1..={}", header.redundancy),
            header.attempt.to_string(),
        ));
    }

    if fec_is_rs(header.fec_field) {
        let (data_shards, parity_shards, parity_shard_index) =
            rs_params_from_field(header.fec_field);
        if data_shards == 0 || parity_shards == 0 {
            return Err(HeaderInvariantViolation::new(
                "RS data_shards and parity_shards must be positive",
                "fec_field",
                "data_shards >= 1, parity_shards >= 1",
                header.fec_field.to_string(),
            ));
        }
        if fec_is_parity(header.fec_field) && parity_shard_index >= parity_shards {
            return Err(HeaderInvariantViolation::new(
                "RS parity_shard_index out of range",
                "fec_field",
                format!("parity_shard_index < {parity_shards}"),
                parity_shard_index.to_string(),
            ));
        }
    } else {
        let fec_group_size = fec_group_size_from_field(header.fec_field);
        if fec_group_size != 1 {
            return Err(HeaderInvariantViolation::new(
                "invalid fec field encoding",
                "fec_field",
                "non-RS fec_field must encode group_size = 1",
                header.fec_field.to_string(),
            ));
        }
    }

    let expected_chunks = if header.message_length == 0 {
        1_u64
    } else {
        u64::from(header.message_length).div_ceil(u64::from(header.chunk_size))
    };
    if u64::from(header.total_chunks) != expected_chunks {
        return Err(HeaderInvariantViolation::new(
            "message metadata has inconsistent chunk geometry",
            "total_chunks",
            expected_chunks.to_string(),
            header.total_chunks.to_string(),
        ));
    }

    Ok(())
}
