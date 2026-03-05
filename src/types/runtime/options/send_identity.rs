use crate::types::{PacketAuth, SenderId};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
/// Optional per-message identity/auth overrides for a [`crate::sender::Sender`].
///
/// Prefer stable sender identity (`Sender::with_identity(...)`) in hot paths.
/// Use this only when a call must intentionally override sender/session/message
/// identity or packet auth metadata.
pub struct SendIdentityOverrides {
    message_id: Option<u64>,
    sender_id: Option<SenderId>,
    session_nonce: Option<u64>,
    packet_auth: Option<PacketAuth>,
}

impl SendIdentityOverrides {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn message_id(&self) -> Option<u64> {
        self.message_id
    }

    #[must_use]
    pub fn sender_id(&self) -> Option<SenderId> {
        self.sender_id
    }

    #[must_use]
    pub fn session_nonce(&self) -> Option<u64> {
        self.session_nonce
    }

    #[must_use]
    pub fn packet_auth(&self) -> Option<&PacketAuth> {
        self.packet_auth.as_ref()
    }

    #[must_use]
    pub fn with_message_id(mut self, message_id: u64) -> Self {
        self.message_id = Some(message_id);
        self
    }

    #[must_use]
    pub fn with_message_id_opt(mut self, message_id: Option<u64>) -> Self {
        self.message_id = message_id;
        self
    }

    #[must_use]
    pub fn with_sender_id(mut self, sender_id: SenderId) -> Self {
        self.sender_id = Some(sender_id);
        self
    }

    #[must_use]
    pub fn with_sender_id_opt(mut self, sender_id: Option<SenderId>) -> Self {
        self.sender_id = sender_id;
        self
    }

    #[must_use]
    pub fn with_session_nonce(mut self, session_nonce: u64) -> Self {
        self.session_nonce = Some(session_nonce);
        self
    }

    #[must_use]
    pub fn with_session_nonce_opt(mut self, session_nonce: Option<u64>) -> Self {
        self.session_nonce = session_nonce;
        self
    }

    #[must_use]
    pub fn with_packet_auth(mut self, packet_auth: PacketAuth) -> Self {
        self.packet_auth = Some(packet_auth);
        self
    }

    #[must_use]
    pub fn with_packet_auth_opt(mut self, packet_auth: Option<PacketAuth>) -> Self {
        self.packet_auth = packet_auth;
        self
    }
}
