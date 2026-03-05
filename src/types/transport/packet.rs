use crate::error::{Result, UniUdpError, ValidationContext};
use crate::fec::pack_fec_field;
use crate::header_validation::validate_header_invariants;
use crate::types::{MessageKey, SenderId};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub(crate) sender_id: SenderId,
    pub(crate) message_id: u64,
    pub(crate) session_nonce: u64,
    pub(crate) chunk_index: u32,
    pub(crate) total_chunks: u32,
    pub(crate) message_length: u32,
    pub(crate) chunk_size: u16,
    pub(crate) payload_len: u16,
    pub(crate) redundancy: u16,
    pub(crate) attempt: u16,
    pub(crate) fec_field: u16,
}

impl PacketHeader {
    #[must_use]
    pub fn builder() -> PacketHeaderBuilder {
        PacketHeaderBuilder::new()
    }

    /// Internal low-level constructor that skips semantic validation.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub(crate) const fn new_unchecked(
        sender_id: SenderId,
        message_id: u64,
        session_nonce: u64,
        chunk_index: u32,
        total_chunks: u32,
        message_length: u32,
        chunk_size: u16,
        payload_len: u16,
        redundancy: u16,
        attempt: u16,
        fec_field: u16,
    ) -> Self {
        Self {
            sender_id,
            message_id,
            session_nonce,
            chunk_index,
            total_chunks,
            message_length,
            chunk_size,
            payload_len,
            redundancy,
            attempt,
            fec_field,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender_id: SenderId,
        message_id: u64,
        session_nonce: u64,
        chunk_index: u32,
        total_chunks: u32,
        message_length: u32,
        chunk_size: u16,
        payload_len: u16,
        redundancy: u16,
        attempt: u16,
        fec_field: u16,
    ) -> Result<Self> {
        let header = Self::new_unchecked(
            sender_id,
            message_id,
            session_nonce,
            chunk_index,
            total_chunks,
            message_length,
            chunk_size,
            payload_len,
            redundancy,
            attempt,
            fec_field,
        );
        header.validate_for_payload(usize::from(payload_len))?;
        Ok(header)
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_for_payload(usize::from(self.payload_len))
    }

    pub fn validate_for_payload(&self, payload_len: usize) -> Result<()> {
        if let Err(violation) = validate_header_invariants(self, payload_len) {
            return Err(UniUdpError::validation_detail(
                ValidationContext::HeaderWrite,
                violation.message,
                violation.field,
                violation.expected,
                violation.actual,
            ));
        }
        Ok(())
    }

    pub const fn sender_id(&self) -> SenderId {
        self.sender_id
    }

    pub const fn message_id(&self) -> u64 {
        self.message_id
    }

    pub const fn session_nonce(&self) -> u64 {
        self.session_nonce
    }

    pub const fn chunk_index(&self) -> u32 {
        self.chunk_index
    }

    pub const fn total_chunks(&self) -> u32 {
        self.total_chunks
    }

    pub const fn message_length(&self) -> u32 {
        self.message_length
    }

    pub const fn chunk_size(&self) -> u16 {
        self.chunk_size
    }

    pub const fn payload_len(&self) -> u16 {
        self.payload_len
    }

    pub const fn redundancy(&self) -> u16 {
        self.redundancy
    }

    pub const fn attempt(&self) -> u16 {
        self.attempt
    }

    pub const fn fec_field(&self) -> u16 {
        self.fec_field
    }

    pub fn key(&self) -> MessageKey {
        MessageKey {
            sender_id: self.sender_id,
            session_nonce: self.session_nonce,
            message_id: self.message_id,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PacketHeaderBuilder {
    sender_id: Option<SenderId>,
    message_id: Option<u64>,
    session_nonce: Option<u64>,
    chunk_index: Option<u32>,
    total_chunks: Option<u32>,
    message_length: Option<u32>,
    chunk_size: Option<u16>,
    payload_len: u16,
    redundancy: u16,
    attempt: u16,
    fec_field: u16,
}

impl Default for PacketHeaderBuilder {
    fn default() -> Self {
        Self {
            sender_id: None,
            message_id: None,
            session_nonce: None,
            chunk_index: None,
            total_chunks: None,
            message_length: None,
            chunk_size: None,
            payload_len: 0,
            redundancy: 1,
            attempt: 1,
            // group_size=1, parity=false => FEC disabled for data packets
            fec_field: pack_fec_field(1, false).expect("pack_fec_field(1, false) is always valid"),
        }
    }
}

impl PacketHeaderBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_key(mut self, key: MessageKey) -> Self {
        self.sender_id = Some(key.sender_id);
        self.session_nonce = Some(key.session_nonce);
        self.message_id = Some(key.message_id);
        self
    }

    #[must_use]
    pub fn with_sender_id(mut self, sender_id: SenderId) -> Self {
        self.sender_id = Some(sender_id);
        self
    }

    #[must_use]
    pub fn with_message_id(mut self, message_id: u64) -> Self {
        self.message_id = Some(message_id);
        self
    }

    #[must_use]
    pub fn with_session_nonce(mut self, session_nonce: u64) -> Self {
        self.session_nonce = Some(session_nonce);
        self
    }

    #[must_use]
    pub fn with_chunk_index(mut self, chunk_index: u32) -> Self {
        self.chunk_index = Some(chunk_index);
        self
    }

    #[must_use]
    pub fn with_total_chunks(mut self, total_chunks: u32) -> Self {
        self.total_chunks = Some(total_chunks);
        self
    }

    #[must_use]
    pub fn with_message_length(mut self, message_length: u32) -> Self {
        self.message_length = Some(message_length);
        self
    }

    #[must_use]
    pub fn with_chunk_size(mut self, chunk_size: u16) -> Self {
        self.chunk_size = Some(chunk_size);
        self
    }

    #[must_use]
    pub fn with_payload_len(mut self, payload_len: u16) -> Self {
        self.payload_len = payload_len;
        self
    }

    #[must_use]
    pub fn with_redundancy(mut self, redundancy: u16) -> Self {
        self.redundancy = redundancy;
        self
    }

    #[must_use]
    pub fn with_attempt(mut self, attempt: u16) -> Self {
        self.attempt = attempt;
        self
    }

    #[must_use]
    pub fn with_fec_field(mut self, fec_field: u16) -> Self {
        self.fec_field = fec_field;
        self
    }

    pub fn build(self) -> Result<PacketHeader> {
        PacketHeader::new(
            require_builder(self.sender_id, "sender_id")?,
            require_builder(self.message_id, "message_id")?,
            require_builder(self.session_nonce, "session_nonce")?,
            require_builder(self.chunk_index, "chunk_index")?,
            require_builder(self.total_chunks, "total_chunks")?,
            require_builder(self.message_length, "message_length")?,
            require_builder(self.chunk_size, "chunk_size")?,
            self.payload_len,
            self.redundancy,
            self.attempt,
            self.fec_field,
        )
    }
}

fn require_builder<T>(value: Option<T>, field: &'static str) -> Result<T> {
    value.ok_or_else(|| {
        UniUdpError::validation_detail(
            ValidationContext::HeaderWrite,
            "missing required packet header field",
            field,
            "set via PacketHeader::builder()",
            "missing",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::PacketHeader;
    use crate::error::ValidationContext;
    use crate::fec::pack_fec_field;
    use crate::types::SenderId;
    use crate::UniUdpError;

    #[test]
    fn new_rejects_invalid_chunk_geometry() {
        let err = PacketHeader::new(
            SenderId(7),
            11,
            13,
            0,
            0,
            1,
            1,
            1,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        )
        .unwrap_err();

        assert!(matches!(
            err,
            UniUdpError::Validation {
                context: ValidationContext::HeaderWrite,
                message: "total_chunks must be positive",
                ..
            }
        ));
    }

    #[test]
    fn new_accepts_valid_header() {
        let header = PacketHeader::new(
            SenderId(0xAB),
            21,
            34,
            0,
            2,
            8,
            4,
            4,
            2,
            1,
            pack_fec_field(1, false).unwrap(),
        )
        .unwrap();
        assert_eq!(header.key().sender_id, SenderId(0xAB));
    }

    #[test]
    fn builder_accepts_valid_header() {
        let header = PacketHeader::builder()
            .with_sender_id(SenderId(0xCD))
            .with_message_id(22)
            .with_session_nonce(35)
            .with_chunk_index(0)
            .with_total_chunks(2)
            .with_message_length(8)
            .with_chunk_size(4)
            .build()
            .unwrap();
        assert_eq!(header.key().sender_id, SenderId(0xCD));
        assert_eq!(header.payload_len(), 0);
        assert_eq!(header.redundancy(), 1);
        assert_eq!(header.attempt(), 1);
        assert_eq!(header.fec_field(), pack_fec_field(1, false).unwrap());
    }

    #[test]
    fn builder_rejects_missing_required_field() {
        let err = PacketHeader::builder()
            .with_message_id(1)
            .with_session_nonce(0)
            .with_chunk_index(0)
            .with_total_chunks(1)
            .with_message_length(1)
            .with_chunk_size(1)
            .build()
            .unwrap_err();

        assert!(matches!(
            err,
            UniUdpError::Validation {
                context: ValidationContext::HeaderWrite,
                message: "missing required packet header field",
                ..
            }
        ));
    }
}
