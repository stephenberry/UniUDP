#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod checksum;
mod error;
pub mod fec;
mod header_validation;
pub mod packet;
pub mod receiver;
pub mod sender;
mod types;

pub use error::{
    DecodeContext, EncodeContext, ErrorDetail, ReceiveRejectReason, Result, UniUdpError,
    ValidationContext,
};

pub mod auth {
    pub use crate::types::{PacketAuth, PacketAuthKey};
}

pub mod config {
    pub use crate::types::{
        AuthMode, ReceiverConfig, ReceiverRuntimeConfig, DEDUP_WINDOW, DEFAULT_CHUNK_SIZE,
        DEFAULT_MESSAGE_FRESHNESS_WINDOW, HEADER_LENGTH, MAX_COMPLETED_MESSAGES, MAX_PENDING_BYTES,
        MAX_PENDING_MESSAGES, MAX_RECEIVE_CHUNKS, MAX_RECEIVE_DATAGRAM_SIZE,
        MAX_RECEIVE_MESSAGE_LEN, MAX_TRACKED_SESSIONS_PER_SENDER, MAX_TRACKED_SESSIONS_TOTAL,
        PACKET_AUTH_KEY_LENGTH, PACKET_AUTH_TAG_LENGTH, PACKET_CHECKSUM_OFFSET, PENDING_MAX_AGE,
        SAFE_UDP_PAYLOAD, SESSION_FRESHNESS_RETENTION,
    };
}

pub mod message {
    pub use crate::types::{
        CompletionReason, IncompletePayloadError, MessageChunk, MessageKey, MessageReport,
        SenderId, SourcePolicy,
    };
}

pub mod options {
    pub use crate::fec::FecMode;
    pub use crate::types::{
        ReceiveDiagnostics, ReceiveOptions, SendIdentityOverrides, SendOptions,
    };
}

pub mod prelude {
    pub use crate::auth::{PacketAuth, PacketAuthKey};
    pub use crate::config::{AuthMode, ReceiverConfig, ReceiverRuntimeConfig};
    pub use crate::message::{
        CompletionReason, IncompletePayloadError, MessageKey, MessageReport, SenderId, SourcePolicy,
    };
    pub use crate::options::{
        FecMode, ReceiveDiagnostics, ReceiveOptions, SendIdentityOverrides, SendOptions,
    };
    pub use crate::receiver::{ReceiveLoopControl, Receiver};
    pub use crate::sender::{
        MessageIdStart, SendFailure, SendRequest, SendScratch, Sender, SenderBuilder,
    };
    pub use crate::{Result, UniUdpError};
}

// Compile-time assertions for documented threading guarantees.
#[doc(hidden)]
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<crate::sender::Sender>();
    assert_send_sync::<crate::receiver::Receiver>();
};
