mod message;
mod runtime;
mod transport;

pub use message::{
    CompletionReason, IncompletePayloadError, MessageChunk, MessageKey, MessageReport, SenderId,
    SourcePolicy,
};
pub(crate) use runtime::MAX_UDP_PAYLOAD_HARD_LIMIT;
pub use runtime::{
    AuthMode, ReceiveDiagnostics, ReceiveOptions, ReceiverConfig, ReceiverRuntimeConfig,
    SendIdentityOverrides, SendOptions,
};
pub use runtime::{
    DEDUP_WINDOW, DEFAULT_CHUNK_SIZE, DEFAULT_MESSAGE_FRESHNESS_WINDOW, HEADER_LENGTH,
    MAX_COMPLETED_MESSAGES, MAX_PENDING_BYTES, MAX_PENDING_MESSAGES, MAX_RECEIVE_CHUNKS,
    MAX_RECEIVE_DATAGRAM_SIZE, MAX_RECEIVE_MESSAGE_LEN, MAX_TRACKED_SESSIONS_PER_SENDER,
    MAX_TRACKED_SESSIONS_TOTAL, PACKET_AUTH_KEY_LENGTH, PACKET_AUTH_TAG_LENGTH,
    PACKET_CHECKSUM_OFFSET, PENDING_MAX_AGE, SAFE_UDP_PAYLOAD, SESSION_FRESHNESS_RETENTION,
};
pub use transport::{PacketAuth, PacketAuthKey, PacketHeader, PacketHeaderBuilder};
