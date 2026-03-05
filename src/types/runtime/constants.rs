use std::time::Duration;

pub const DEFAULT_CHUNK_SIZE: usize = 1024;
pub const HEADER_LENGTH: usize = 84;
pub const SAFE_UDP_PAYLOAD: usize = 1452;
/// Upper bound for UDP payload bytes accepted by this library on wire paths.
///
/// This uses the conservative IPv4-safe payload ceiling
/// (`65_535 - 20 byte IPv4 header - 8 byte UDP header`).
pub(crate) const MAX_UDP_PAYLOAD_HARD_LIMIT: usize = 65_507;
pub const PACKET_AUTH_KEY_LENGTH: usize = 32;
pub const PACKET_AUTH_TAG_LENGTH: usize = 16;
pub const PACKET_CHECKSUM_OFFSET: usize = 64;
pub const DEFAULT_MESSAGE_FRESHNESS_WINDOW: u64 = 16_384;

pub const MAX_PENDING_MESSAGES: usize = 100;
pub const MAX_PENDING_BYTES: usize = 128 * 1024 * 1024;
pub const MAX_COMPLETED_MESSAGES: usize = 100_000;
pub const MAX_TRACKED_SESSIONS_TOTAL: usize = 100_000;
pub const MAX_TRACKED_SESSIONS_PER_SENDER: usize = 1_024;
pub const DEDUP_WINDOW: Duration = Duration::from_secs(10);
pub const SESSION_FRESHNESS_RETENTION: Duration = Duration::from_secs(3600);
pub const PENDING_MAX_AGE: Duration = Duration::from_secs(30);
pub const MAX_RECEIVE_CHUNKS: usize = 4_096;
pub const MAX_RECEIVE_MESSAGE_LEN: usize = 16 * 1024 * 1024;
/// Maximum UDP payload bytes accepted from a single `recv_from` call.
///
/// This intentionally matches [`MAX_UDP_PAYLOAD_HARD_LIMIT`] so send/receive
/// paths enforce a single wire-size ceiling.
pub const MAX_RECEIVE_DATAGRAM_SIZE: usize = MAX_UDP_PAYLOAD_HARD_LIMIT;
