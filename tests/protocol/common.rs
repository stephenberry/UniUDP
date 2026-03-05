pub(super) use std::collections::{BTreeSet, HashSet};
pub(super) use std::net::{SocketAddr, UdpSocket};
pub(super) use std::thread;
pub(super) use std::time::Duration;

pub(super) use uniudp::auth::{PacketAuth, PacketAuthKey};
pub(super) use uniudp::config::{
    AuthMode, ReceiverConfig, HEADER_LENGTH, MAX_PENDING_MESSAGES, MAX_RECEIVE_CHUNKS,
    MAX_RECEIVE_DATAGRAM_SIZE, MAX_RECEIVE_MESSAGE_LEN, PACKET_AUTH_KEY_LENGTH,
    PACKET_AUTH_TAG_LENGTH, PACKET_CHECKSUM_OFFSET,
};
pub(super) use uniudp::fec::{
    fec_is_parity, pack_fec_field, pack_rs_data_field, pack_rs_parity_field, FecMode,
};
pub(super) use uniudp::message::{CompletionReason, MessageKey, SenderId, SourcePolicy};
pub(super) use uniudp::options::{
    ReceiveDiagnostics, ReceiveOptions, SendIdentityOverrides, SendOptions,
};
pub(super) use uniudp::packet::{
    encode_packet, encode_packet_with_auth, packet_crc32c, parse_packet, parse_packet_view,
    parse_packet_view_with_wire_security, PacketHeader,
};
pub(super) use uniudp::receiver::{ReceiveLoopControl, Receiver};
pub(super) use uniudp::sender::{SendRequest, SendScratch, Sender};
pub(super) use uniudp::{ReceiveRejectReason, UniUdpError};

macro_rules! send_options {
    (@set $options:ident;) => {};
    (@set $options:ident; ..SendOptions::default() $(,)?) => {};
    (@set $options:ident; redundancy : $value:expr $(, $($rest:tt)*)?) => {
        $options = $options.with_redundancy($value);
        send_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; chunk_size : $value:expr $(, $($rest:tt)*)?) => {
        $options = $options.with_chunk_size($value);
        send_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; fec_mode : $value:expr $(, $($rest:tt)*)?) => {
        $options = $options.with_fec_mode($value);
        send_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; message_id : Some($value:expr) $(, $($rest:tt)*)?) => {
        $options = $options.with_message_id($value);
        send_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; sender_id : Some($value:expr) $(, $($rest:tt)*)?) => {
        $options = $options.with_sender_id($value);
        send_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; session_nonce : Some($value:expr) $(, $($rest:tt)*)?) => {
        $options = $options.with_session_nonce($value);
        send_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; packet_auth : Some($value:expr) $(, $($rest:tt)*)?) => {
        $options = $options.with_packet_auth($value);
        send_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; $($rest:tt)+) => {
        compile_error!("unsupported send_options! field");
    };
    ($($tokens:tt)*) => {{
        let mut options = TestSendOptions::new();
        send_options!(@set options; $($tokens)*);
        options
    }};
}
pub(super) use send_options;

#[derive(Debug, Clone)]
pub(super) struct TestSendOptions {
    transport: SendOptions,
    identity: SendIdentityOverrides,
}

impl Default for TestSendOptions {
    fn default() -> Self {
        Self {
            transport: SendOptions::new(),
            identity: SendIdentityOverrides::new(),
        }
    }
}

impl TestSendOptions {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn with_redundancy(mut self, redundancy: u16) -> Self {
        self.transport = self.transport.with_redundancy(redundancy);
        self
    }

    pub(super) fn with_chunk_size(mut self, chunk_size: u16) -> Self {
        self.transport = self.transport.with_chunk_size(chunk_size);
        self
    }

    #[allow(dead_code)]
    pub(super) fn with_fec_mode(mut self, fec_mode: FecMode) -> Self {
        self.transport = self.transport.with_fec_mode(fec_mode);
        self
    }

    pub(super) fn with_message_id(mut self, message_id: u64) -> Self {
        self.identity = self.identity.with_message_id(message_id);
        self
    }

    pub(super) fn with_sender_id(mut self, sender_id: SenderId) -> Self {
        self.identity = self.identity.with_sender_id(sender_id);
        self
    }

    pub(super) fn with_session_nonce(mut self, session_nonce: u64) -> Self {
        self.identity = self.identity.with_session_nonce(session_nonce);
        self
    }

    pub(super) fn with_packet_auth(mut self, packet_auth: PacketAuth) -> Self {
        self.identity = self.identity.with_packet_auth(packet_auth);
        self
    }

    pub(super) fn sender_id(&self) -> Option<SenderId> {
        self.identity.sender_id()
    }

    pub(super) fn session_nonce(&self) -> Option<u64> {
        self.identity.session_nonce()
    }

    pub(super) fn into_parts(self) -> (SendOptions, SendIdentityOverrides) {
        (self.transport, self.identity)
    }
}

macro_rules! receive_options {
    (@set $options:ident;) => {};
    (@set $options:ident; ..ReceiveOptions::default() $(,)?) => {};
    (@set $options:ident; key : Some($value:expr) $(, $($rest:tt)*)?) => {
        $options = $options.with_key($value);
        receive_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; key : None $(, $($rest:tt)*)?) => {
        $options = $options.with_key_opt(None);
        receive_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; key : $value:expr $(, $($rest:tt)*)?) => {
        $options = $options.with_key_opt($value);
        receive_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; source_policy : $value:expr $(, $($rest:tt)*)?) => {
        $options = $options.with_source_policy($value);
        receive_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; strict_rejections : $value:expr $(, $($rest:tt)*)?) => {
        $options = $options.with_strict_rejections($value);
        receive_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; inactivity_timeout : $value:expr $(, $($rest:tt)*)?) => {
        $options = $options.with_inactivity_timeout($value);
        receive_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; overall_timeout : $value:expr $(, $($rest:tt)*)?) => {
        $options = $options.with_overall_timeout($value);
        receive_options!(@set $options; $($($rest)*)?);
    };
    (@set $options:ident; $($rest:tt)+) => {
        compile_error!("unsupported receive_options! field");
    };
    ($($tokens:tt)*) => {{
        let mut options = ReceiveOptions::new();
        receive_options!(@set options; $($tokens)*);
        options
    }};
}
pub(super) use receive_options;

macro_rules! receiver_config {
    (@set $config:ident;) => {};
    (@set $config:ident; ..ReceiverConfig::default() $(,)?) => {};
    (@set $config:ident; max_pending_messages : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_max_pending_messages($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; max_pending_bytes : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_max_pending_bytes($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; max_completed_messages : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_max_completed_messages($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; max_tracked_sessions_total : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_max_tracked_sessions_total($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; max_tracked_sessions_per_sender : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_max_tracked_sessions_per_sender($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; dedup_window : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_dedup_window($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; pending_max_age : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_pending_max_age($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; max_receive_chunks : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_max_receive_chunks($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; max_receive_message_len : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_max_receive_message_len($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; max_receive_datagram_size : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_max_receive_datagram_size($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; message_freshness_window : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_message_freshness_window($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; unbounded_message_freshness : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_unbounded_message_freshness($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; session_freshness_retention : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_session_freshness_retention($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; strict_message_ordering : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_strict_message_ordering($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; auth_keys : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_auth_keys($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; auth_mode : $value:expr $(, $($rest:tt)*)?) => {
        $config = $config.with_auth_mode($value);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; $field:ident $(, $($rest:tt)*)?) => {
        $config = $config.$field($field);
        receiver_config!(@set $config; $($($rest)*)?);
    };
    (@set $config:ident; $($rest:tt)+) => {
        compile_error!("unsupported receiver_config! field");
    };
    ($($tokens:tt)*) => {{
        let mut config = ReceiverConfig::new();
        receiver_config!(@set config; $($tokens)*);
        config
    }};
}
pub(super) use receiver_config;

pub(super) fn bind_local() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").expect("bind local udp socket")
}

pub(super) fn key(sender_id: SenderId, message_id: u64) -> MessageKey {
    key_with_session(sender_id, 0, message_id)
}

pub(super) fn key_with_session(
    sender_id: SenderId,
    session_nonce: u64,
    message_id: u64,
) -> MessageKey {
    MessageKey {
        sender_id,
        session_nonce,
        message_id,
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn packet_header(
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
) -> PacketHeader {
    PacketHeader::new(
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
    )
    .expect("test packet header should be valid")
}

pub(super) fn send_message_with_socket(
    socket: &UdpSocket,
    destination: SocketAddr,
    data: &[u8],
    options: TestSendOptions,
) -> Result<MessageKey, UniUdpError> {
    const DEFAULT_HELPER_SENDER_ID: SenderId = SenderId(0xD00D_CAFE_BAAD_F00D_1122_3344_5566_7788);
    const DEFAULT_HELPER_SESSION_NONCE: u64 = 0x0102_0304_0506_0708;

    let sender_id = options.sender_id().unwrap_or(DEFAULT_HELPER_SENDER_ID);
    let session_nonce = options
        .session_nonce()
        .unwrap_or(DEFAULT_HELPER_SESSION_NONCE);
    let (transport, identity) = options.into_parts();
    Sender::with_identity(sender_id, session_nonce)
        .send_with_socket(
            socket,
            SendRequest::new(destination, data)
                .with_options(transport)
                .with_identity(identity),
        )
        .map_err(Into::into)
}

pub(super) fn auth_key(seed: u8) -> PacketAuthKey {
    let mut bytes = [0_u8; PACKET_AUTH_KEY_LENGTH];
    for (idx, byte) in bytes.iter_mut().enumerate() {
        *byte = seed.wrapping_add(idx as u8);
    }
    PacketAuthKey::from(bytes)
}

pub(super) fn packet_auth(key_id: u32, seed: u8) -> PacketAuth {
    PacketAuth::new(key_id, auth_key(seed))
}

pub(super) fn rejected_timeout_diagnostics(err: UniUdpError) -> ReceiveDiagnostics {
    match err {
        UniUdpError::TimeoutAfterRejectedTraffic { diagnostics } => diagnostics,
        other => panic!("expected TimeoutAfterRejectedTraffic, got {other:?}"),
    }
}

const TEST_CHECKSUM_OFFSET: usize = PACKET_CHECKSUM_OFFSET;
pub(super) const TEST_TOTAL_CHUNKS_OFFSET: usize = 46;
pub(super) const TEST_ATTEMPT_OFFSET: usize = 60;

pub(super) fn rewrite_packet_checksum(packet: &mut [u8]) {
    assert!(packet.len() >= HEADER_LENGTH);
    let payload = &packet[HEADER_LENGTH..];
    let checksum = packet_crc32c(&packet[..TEST_CHECKSUM_OFFSET], payload);
    packet[TEST_CHECKSUM_OFFSET..TEST_CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_be_bytes());
}
