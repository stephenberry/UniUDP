use std::fmt;

use zeroize::Zeroize;

use crate::types::PACKET_AUTH_KEY_LENGTH;

#[derive(Clone, PartialEq, Eq)]
pub struct PacketAuthKey([u8; PACKET_AUTH_KEY_LENGTH]);

impl PacketAuthKey {
    pub const fn new(bytes: [u8; PACKET_AUTH_KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; PACKET_AUTH_KEY_LENGTH] {
        &self.0
    }
}

impl From<[u8; PACKET_AUTH_KEY_LENGTH]> for PacketAuthKey {
    fn from(value: [u8; PACKET_AUTH_KEY_LENGTH]) -> Self {
        Self::new(value)
    }
}

impl fmt::Debug for PacketAuthKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PacketAuthKey([REDACTED])")
    }
}

impl Drop for PacketAuthKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketAuth {
    key_id: u32,
    key: PacketAuthKey,
}

impl PacketAuth {
    pub const fn new(key_id: u32, key: PacketAuthKey) -> Self {
        Self { key_id, key }
    }

    pub const fn key_id(&self) -> u32 {
        self.key_id
    }

    pub const fn key(&self) -> &PacketAuthKey {
        &self.key
    }
}
