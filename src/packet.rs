use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub use crate::checksum::packet_crc32c;
use crate::error::{DecodeContext, EncodeContext, Result, UniUdpError, ValidationContext};
use crate::header_validation::validate_header_invariants;
use crate::types::{PacketAuth, PacketAuthKey, SenderId};
pub use crate::types::{
    PacketHeader, PacketHeaderBuilder, HEADER_LENGTH, PACKET_AUTH_TAG_LENGTH,
    PACKET_CHECKSUM_OFFSET,
};

const PROTOCOL_MAGIC: [u8; 4] = *b"UUDP";
const PROTOCOL_VERSION: u8 = 1;

const PACKET_FLAG_AUTH_PRESENT: u8 = 0b0000_0001;
const SUPPORTED_PACKET_FLAGS: u8 = PACKET_FLAG_AUTH_PRESENT;

const MAGIC_OFFSET: usize = 0;
const VERSION_OFFSET: usize = 4;
const FLAGS_OFFSET: usize = 5;
const AUTH_KEY_ID_OFFSET: usize = 6;
const SESSION_NONCE_OFFSET: usize = 10;
const SENDER_ID_OFFSET: usize = 18;
const MESSAGE_ID_OFFSET: usize = 34;
const CHUNK_INDEX_OFFSET: usize = 42;
const TOTAL_CHUNKS_OFFSET: usize = 46;
const MESSAGE_LENGTH_OFFSET: usize = 50;
const CHUNK_SIZE_OFFSET: usize = 54;
const PAYLOAD_LEN_OFFSET: usize = 56;
const REDUNDANCY_OFFSET: usize = 58;
const ATTEMPT_OFFSET: usize = 60;
const FEC_FIELD_OFFSET: usize = 62;
const CHECKSUM_OFFSET: usize = PACKET_CHECKSUM_OFFSET;
const AUTH_TAG_OFFSET: usize = 68;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedPacket<'a> {
    pub header: PacketHeader,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedPacketWithSecurity<'a> {
    pub header: PacketHeader,
    pub payload: &'a [u8],
    pub security: PacketSecurity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketSecurity {
    pub flags: u8,
    pub authenticated: bool,
    pub auth_key_id: u32,
    pub checksum: u32,
    pub auth_tag: [u8; PACKET_AUTH_TAG_LENGTH],
}

/// Encodes a packet without authentication (`auth_key_id = 0`).
pub fn encode_packet(header: PacketHeader, payload: &[u8]) -> Result<Vec<u8>> {
    encode_packet_with_security(header, payload, PacketEncodeSecurity::unauthenticated())
}

/// Encodes a packet, optionally including packet authentication metadata.
///
/// - `packet_auth = Some(...)` writes auth flag/key-id and HMAC tag.
/// - `packet_auth = None` writes an unauthenticated packet.
pub fn encode_packet_with_auth(
    header: PacketHeader,
    payload: &[u8],
    packet_auth: Option<&PacketAuth>,
) -> Result<Vec<u8>> {
    encode_packet_with_security(header, payload, PacketEncodeSecurity { packet_auth })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PacketEncodeSecurity<'a> {
    pub packet_auth: Option<&'a PacketAuth>,
}

impl<'a> PacketEncodeSecurity<'a> {
    #[must_use]
    pub const fn unauthenticated() -> Self {
        Self { packet_auth: None }
    }
}

pub fn encode_packet_with_security(
    header: PacketHeader,
    payload: &[u8],
    security: PacketEncodeSecurity<'_>,
) -> Result<Vec<u8>> {
    let mut header = header;
    header.payload_len = u16::try_from(payload.len()).map_err(|_| {
        UniUdpError::encode(EncodeContext::Packet, "payload length exceeds u16 range")
    })?;
    if let Err(violation) = validate_header_invariants(&header, payload.len()) {
        return Err(UniUdpError::encode(
            EncodeContext::Packet,
            violation.message,
        ));
    }

    let mut out = vec![0_u8; HEADER_LENGTH + payload.len()];
    write_header(&mut out[..HEADER_LENGTH], &header, payload, security)?;
    out[HEADER_LENGTH..].copy_from_slice(payload);
    Ok(out)
}

pub fn parse_packet(packet: &[u8]) -> Result<(PacketHeader, Vec<u8>)> {
    let parsed = parse_packet_view(packet)?;
    Ok((parsed.header, parsed.payload.to_vec()))
}

pub fn parse_packet_view(packet: &[u8]) -> Result<ParsedPacket<'_>> {
    let parsed = parse_packet_view_with_wire_security(packet)?;
    let header = parsed.header;
    let payload = parsed.payload;
    Ok(ParsedPacket { header, payload })
}

/// Parses packet framing/header/checksum and returns wire security fields.
///
/// This parses/exposes auth-related metadata (`flags`, `auth_key_id`,
/// `auth_tag`), but it does not verify packet authentication tags against any
/// key. Use receiver auth mode or custom verification for authenticity checks.
pub fn parse_packet_view_with_wire_security(packet: &[u8]) -> Result<ParsedPacketWithSecurity<'_>> {
    let (header, payload, security) = parse_packet_view_with_wire_security_parts(packet)?;
    if let Err(violation) = validate_header_invariants(&header, payload.len()) {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Packet,
            violation.message,
            violation.field,
            violation.expected,
            violation.actual,
        ));
    }
    Ok(ParsedPacketWithSecurity {
        header,
        payload,
        security,
    })
}

pub(crate) fn parse_packet_view_with_wire_security_parts(
    packet: &[u8],
) -> Result<(PacketHeader, &[u8], PacketSecurity)> {
    if packet.len() < HEADER_LENGTH {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Packet,
            "packet shorter than expected",
            "packet_len",
            format!(">= {HEADER_LENGTH}"),
            packet.len().to_string(),
        ));
    }
    let (header, security) = read_header(&packet[..HEADER_LENGTH])?;
    let payload_len = usize::from(header.payload_len);
    let total_len = HEADER_LENGTH + payload_len;
    if packet.len() < total_len {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Packet,
            "packet shorter than declared payload length",
            "packet_len",
            format!(">= {total_len}"),
            packet.len().to_string(),
        ));
    }
    if packet.len() > total_len {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Packet,
            "packet length exceeds declared payload length",
            "packet_len",
            format!("{total_len}"),
            packet.len().to_string(),
        ));
    }
    if payload_len > usize::from(header.chunk_size) {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Packet,
            "payload length exceeds chunk_size declared in header",
            "payload_len",
            format!("<= {}", header.chunk_size),
            payload_len.to_string(),
        ));
    }
    let payload = &packet[HEADER_LENGTH..total_len];
    let actual_checksum = packet_crc32c(&packet[..CHECKSUM_OFFSET], payload);
    if actual_checksum != security.checksum {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Packet,
            "invalid packet checksum",
            "checksum",
            format!("{:#010x}", security.checksum),
            format!("{actual_checksum:#010x}"),
        ));
    }
    Ok((header, payload, security))
}

pub(crate) fn verify_packet_auth(
    packet: &[u8],
    payload: &[u8],
    security: PacketSecurity,
    auth_key: &PacketAuthKey,
) -> bool {
    if !security.authenticated || packet.len() < AUTH_TAG_OFFSET {
        return false;
    }
    let expected = packet_auth_tag(&packet[..AUTH_TAG_OFFSET], payload, auth_key);
    bool::from(expected.ct_eq(&security.auth_tag))
}

pub(crate) fn write_header(
    out: &mut [u8],
    header: &PacketHeader,
    payload: &[u8],
    security: PacketEncodeSecurity<'_>,
) -> Result<()> {
    if out.len() < HEADER_LENGTH {
        return Err(UniUdpError::validation(
            ValidationContext::HeaderWrite,
            "header buffer too small",
        ));
    }

    let mut flags = 0_u8;
    if security.packet_auth.is_some() {
        flags |= PACKET_FLAG_AUTH_PRESENT;
    }
    let auth_key_id = security.packet_auth.map_or(0_u32, PacketAuth::key_id);

    out[MAGIC_OFFSET..MAGIC_OFFSET + 4].copy_from_slice(&PROTOCOL_MAGIC);
    out[VERSION_OFFSET] = PROTOCOL_VERSION;
    out[FLAGS_OFFSET] = flags;
    out[AUTH_KEY_ID_OFFSET..AUTH_KEY_ID_OFFSET + 4].copy_from_slice(&auth_key_id.to_be_bytes());
    out[SESSION_NONCE_OFFSET..SESSION_NONCE_OFFSET + 8]
        .copy_from_slice(&header.session_nonce.to_be_bytes());
    out[SENDER_ID_OFFSET..SENDER_ID_OFFSET + 16].copy_from_slice(&header.sender_id.0.to_be_bytes());
    out[MESSAGE_ID_OFFSET..MESSAGE_ID_OFFSET + 8].copy_from_slice(&header.message_id.to_be_bytes());
    out[CHUNK_INDEX_OFFSET..CHUNK_INDEX_OFFSET + 4]
        .copy_from_slice(&header.chunk_index.to_be_bytes());
    out[TOTAL_CHUNKS_OFFSET..TOTAL_CHUNKS_OFFSET + 4]
        .copy_from_slice(&header.total_chunks.to_be_bytes());
    out[MESSAGE_LENGTH_OFFSET..MESSAGE_LENGTH_OFFSET + 4]
        .copy_from_slice(&header.message_length.to_be_bytes());
    out[CHUNK_SIZE_OFFSET..CHUNK_SIZE_OFFSET + 2].copy_from_slice(&header.chunk_size.to_be_bytes());
    out[PAYLOAD_LEN_OFFSET..PAYLOAD_LEN_OFFSET + 2]
        .copy_from_slice(&header.payload_len.to_be_bytes());
    out[REDUNDANCY_OFFSET..REDUNDANCY_OFFSET + 2].copy_from_slice(&header.redundancy.to_be_bytes());
    out[ATTEMPT_OFFSET..ATTEMPT_OFFSET + 2].copy_from_slice(&header.attempt.to_be_bytes());
    out[FEC_FIELD_OFFSET..FEC_FIELD_OFFSET + 2].copy_from_slice(&header.fec_field.to_be_bytes());

    let checksum = packet_crc32c(&out[..CHECKSUM_OFFSET], payload);
    out[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&checksum.to_be_bytes());

    if let Some(auth) = security.packet_auth {
        let key = auth.key();
        let tag = packet_auth_tag(&out[..AUTH_TAG_OFFSET], payload, key);
        out[AUTH_TAG_OFFSET..AUTH_TAG_OFFSET + PACKET_AUTH_TAG_LENGTH].copy_from_slice(&tag);
    } else {
        out[AUTH_TAG_OFFSET..AUTH_TAG_OFFSET + PACKET_AUTH_TAG_LENGTH].fill(0_u8);
    }
    Ok(())
}

fn read_field_bytes<const N: usize>(
    input: &[u8],
    offset: usize,
    field_name: &'static str,
) -> Result<[u8; N]> {
    input[offset..offset + N].try_into().map_err(|_| {
        UniUdpError::decode(
            DecodeContext::HeaderField(field_name),
            "invalid header field",
        )
    })
}

fn read_header(input: &[u8]) -> Result<(PacketHeader, PacketSecurity)> {
    if input.len() < HEADER_LENGTH {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Header,
            "header shorter than expected",
            "header_len",
            format!(">= {HEADER_LENGTH}"),
            input.len().to_string(),
        ));
    }
    if input[MAGIC_OFFSET..MAGIC_OFFSET + 4] != PROTOCOL_MAGIC {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Packet,
            "invalid protocol magic",
            "magic",
            String::from_utf8_lossy(&PROTOCOL_MAGIC).to_string(),
            format!("{:02X?}", &input[MAGIC_OFFSET..MAGIC_OFFSET + 4]),
        ));
    }
    if input[VERSION_OFFSET] != PROTOCOL_VERSION {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Packet,
            "unsupported protocol version",
            "version",
            PROTOCOL_VERSION.to_string(),
            input[VERSION_OFFSET].to_string(),
        ));
    }

    let flags = input[FLAGS_OFFSET];
    if (flags & !SUPPORTED_PACKET_FLAGS) != 0 {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Packet,
            "unsupported packet flags",
            "flags",
            format!("{SUPPORTED_PACKET_FLAGS:#010b}"),
            format!("{flags:#010b}"),
        ));
    }
    let auth_key_id =
        u32::from_be_bytes(read_field_bytes(input, AUTH_KEY_ID_OFFSET, "auth_key_id")?);
    let session_nonce = u64::from_be_bytes(read_field_bytes(
        input,
        SESSION_NONCE_OFFSET,
        "session_nonce",
    )?);

    let header = PacketHeader {
        sender_id: SenderId(u128::from_be_bytes(read_field_bytes(
            input,
            SENDER_ID_OFFSET,
            "sender_id",
        )?)),
        message_id: u64::from_be_bytes(read_field_bytes(input, MESSAGE_ID_OFFSET, "message_id")?),
        session_nonce,
        chunk_index: u32::from_be_bytes(read_field_bytes(
            input,
            CHUNK_INDEX_OFFSET,
            "chunk_index",
        )?),
        total_chunks: u32::from_be_bytes(read_field_bytes(
            input,
            TOTAL_CHUNKS_OFFSET,
            "total_chunks",
        )?),
        message_length: u32::from_be_bytes(read_field_bytes(
            input,
            MESSAGE_LENGTH_OFFSET,
            "message_length",
        )?),
        chunk_size: u16::from_be_bytes(read_field_bytes(input, CHUNK_SIZE_OFFSET, "chunk_size")?),
        payload_len: u16::from_be_bytes(read_field_bytes(
            input,
            PAYLOAD_LEN_OFFSET,
            "payload_len",
        )?),
        redundancy: u16::from_be_bytes(read_field_bytes(input, REDUNDANCY_OFFSET, "redundancy")?),
        attempt: u16::from_be_bytes(read_field_bytes(input, ATTEMPT_OFFSET, "attempt")?),
        fec_field: u16::from_be_bytes(read_field_bytes(input, FEC_FIELD_OFFSET, "fec_field")?),
    };
    if crate::fec::fec_is_rs(header.fec_field) {
        let (data_shards, parity_shards, _) = crate::fec::rs_params_from_field(header.fec_field);
        if data_shards == 0 || parity_shards == 0 {
            return Err(UniUdpError::decode_detail(
                DecodeContext::Packet,
                "invalid RS fec field encoding",
                "fec_field",
                "data_shards >= 1, parity_shards >= 1",
                header.fec_field.to_string(),
            ));
        }
    } else if (header.fec_field >> 1) == 0 {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Packet,
            "invalid fec field encoding",
            "fec_field",
            "encoded group size >= 1",
            header.fec_field.to_string(),
        ));
    }
    let checksum = u32::from_be_bytes(read_field_bytes(input, CHECKSUM_OFFSET, "checksum")?);

    let mut auth_tag = [0_u8; PACKET_AUTH_TAG_LENGTH];
    auth_tag.copy_from_slice(&input[AUTH_TAG_OFFSET..AUTH_TAG_OFFSET + PACKET_AUTH_TAG_LENGTH]);
    let authenticated = (flags & PACKET_FLAG_AUTH_PRESENT) != 0;
    if !authenticated && auth_tag != [0_u8; PACKET_AUTH_TAG_LENGTH] {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Packet,
            "packet auth tag present without auth flag",
            "auth_tag",
            "all zeros when auth flag absent",
            format!("{:02X?}", auth_tag),
        ));
    }
    if !authenticated && auth_key_id != 0 {
        return Err(UniUdpError::decode_detail(
            DecodeContext::Packet,
            "packet auth key_id present without auth flag",
            "auth_key_id",
            "0 when auth flag absent",
            auth_key_id.to_string(),
        ));
    }

    Ok((
        header,
        PacketSecurity {
            flags,
            authenticated,
            auth_key_id,
            checksum,
            auth_tag,
        },
    ))
}

fn packet_auth_tag(
    header_without_auth: &[u8],
    payload: &[u8],
    auth_key: &PacketAuthKey,
) -> [u8; PACKET_AUTH_TAG_LENGTH] {
    let mut mac = HmacSha256::new_from_slice(auth_key.as_bytes())
        .expect("HMAC-SHA256 accepts arbitrary key lengths");
    mac.update(header_without_auth);
    mac.update(payload);

    let digest = mac.finalize().into_bytes();
    let mut tag = [0_u8; PACKET_AUTH_TAG_LENGTH];
    tag.copy_from_slice(&digest[..PACKET_AUTH_TAG_LENGTH]);
    tag
}
