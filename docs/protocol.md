# Protocol

UniUDP is a unidirectional message transport built on UDP. Each message is split into chunks, wrapped in a fixed-width header, and sent as individual datagrams. The receiver reassembles chunks into complete messages without ever sending packets back to the sender.

## Packet Structure

Every UniUDP packet consists of a fixed **84-byte header** followed by a variable-length payload.

All multi-byte fields are **big-endian** (network byte order).

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          magic ("UUDP")       |    version    |     flags     |  0-5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         auth_key_id                           |  6-9
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                       session_nonce                           | 10-17
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                                                               |
|                          sender_id                            | 18-33
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                         message_id                            | 34-41
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        chunk_index                            | 42-45
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        total_chunks                           | 46-49
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       message_length                          | 50-53
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         chunk_size            |         payload_len           | 54-57
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         redundancy            |           attempt             | 58-61
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          fec_field            |          checksum             | 62-67
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                          auth_tag                             | 68-83
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        payload (variable)                     | 84+
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Header Fields

| Field | Offset | Size | Description |
|-------|--------|------|-------------|
| `magic` | 0 | 4 bytes | Fixed ASCII `"UUDP"` (`0x55554450`). Identifies the protocol. |
| `version` | 4 | 1 byte | Protocol version. Currently `1`. |
| `flags` | 5 | 1 byte | Bit 0: authentication present. Remaining bits reserved. |
| `auth_key_id` | 6 | 4 bytes | Identifies which key was used for authentication. `0` if unauthenticated. |
| `session_nonce` | 10 | 8 bytes | Opaque session identifier. Distinguishes sender sessions for replay protection. |
| `sender_id` | 18 | 16 bytes | 128-bit unique sender identifier. |
| `message_id` | 34 | 8 bytes | Monotonically increasing message sequence number, scoped to `(sender_id, session_nonce)`. |
| `chunk_index` | 42 | 4 bytes | Zero-based index of this chunk within the message. |
| `total_chunks` | 46 | 4 bytes | Total number of data chunks in the message. |
| `message_length` | 50 | 4 bytes | Total message payload size in bytes (across all chunks). |
| `chunk_size` | 54 | 2 bytes | Maximum bytes per chunk. The last chunk may be shorter. |
| `payload_len` | 56 | 2 bytes | Actual number of payload bytes in this specific packet. |
| `redundancy` | 58 | 2 bytes | Redundancy level the sender used (how many times each packet is sent). |
| `attempt` | 60 | 2 bytes | Which transmission attempt this packet represents (`1..=redundancy`). |
| `fec_field` | 62 | 2 bytes | FEC group size and parity flag (see [FEC Encoding](#fec-field-encoding)). |
| `checksum` | 64 | 4 bytes | CRC32C over `header[0..64] + payload`. Detects corruption. |
| `auth_tag` | 68 | 16 bytes | Truncated HMAC-SHA256 tag over `header[0..68] + payload`. All zeros if unauthenticated. |

### FEC Field Encoding

The 16-bit `fec_field` supports two encodings, distinguished by bit 15:

#### No FEC (bit 15 = 0)

When FEC is disabled, the field encodes `group_size = 1`:

```
fec_field = (1 << 1) | 0 = 0x0002
```

Non-RS fields with `group_size != 1` are rejected as invalid.

#### Reed-Solomon Mode (bit 15 = 1)

- **Bit 0** — parity flag: `1` = parity shard, `0` = data shard
- **Bits 1-6** — `data_shards - 1` (6 bits, 1-64 data shards)
- **Bits 7-10** — `parity_shards - 1` (4 bits, 1-16 parity shards)
- **Bits 11-14** — `parity_shard_index` (4 bits, meaningful only on parity packets)
- **Bit 15** — `1` (RS mode flag)

```
RS data:   0x8000 | ((data_shards-1) << 1) | ((parity_shards-1) << 7) | 0
RS parity: 0x8000 | ((data_shards-1) << 1) | ((parity_shards-1) << 7) | (parity_index << 11) | 1
```

RS mode can recover up to `parity_shards` missing data chunks per group.

#### Helper functions

```rust
use uniudp::fec::{pack_rs_data_field, pack_rs_parity_field, rs_params_from_field, fec_is_rs, fec_is_parity};

let rs_data = pack_rs_data_field(4, 2)?;      // RS(4,2) data shard
let rs_parity = pack_rs_parity_field(4, 2, 0)?; // RS(4,2) parity shard 0

assert!(fec_is_rs(rs_data));
let (ds, ps, _idx) = rs_params_from_field(rs_data);
assert_eq!((ds, ps), (4, 2));
```

### Message Identity

Every message is uniquely identified by a `MessageKey`, which combines three fields from the header:

```
MessageKey = (sender_id, session_nonce, message_id)
```

The receiver uses this triple for deduplication, replay detection, and message reassembly.

## Parsing

UniUDP provides three parse functions with increasing levels of detail:

| Function | Returns | Use Case |
|----------|---------|----------|
| `parse_packet(buf)` | `(PacketHeader, Vec<u8>)` | Simple parsing with payload copy |
| `parse_packet_view(buf)` | `ParsedPacket` (borrowed) | Zero-copy parsing for high-rate paths |
| `parse_packet_view_with_wire_security(buf)` | `ParsedPacketWithSecurity` | Exposes auth flags, key ID, checksum, and auth tag |

All three perform full validation:

1. **Framing** — minimum length, canonical size checks
2. **Magic and version** — rejects unknown protocols
3. **Checksum** — CRC32C integrity verification
4. **Header invariants** — chunk geometry, ranges, and field consistency

These checks are **stronger than wire decoding alone**. A successfully parsed packet has been validated for structural correctness.

### What parsing does NOT check

Parsing validates the packet in isolation. The receiver applies additional **runtime policy checks** when accepting packets into reassembly state:

- Authentication key verification (HMAC-SHA256)
- Session nonce tracking
- Message ID freshness
- Deduplication / replay rejection
- Source address policy
- Pending message budget admission

## Encoding

Three encoding functions are available:

```rust
use uniudp::packet::{encode_packet, encode_packet_with_auth, encode_packet_with_security};

// No authentication
let bytes = encode_packet(header, &payload)?;

// With HMAC-SHA256 authentication
let bytes = encode_packet_with_auth(header, &payload, Some(&auth))?;

// With a PacketEncodeSecurity struct
let bytes = encode_packet_with_security(header, &payload, security)?;
```

All encoding functions validate header geometry before writing. It is not possible to encode a packet that violates receiver-side invariants — invalid headers are rejected at encode time.

### Building Headers

Use the builder pattern to construct headers:

```rust
use uniudp::packet::PacketHeader;

let header = PacketHeader::builder()
    .with_sender_id(sender_id)
    .with_message_id(0)
    .with_session_nonce(42)
    .with_chunk_index(0)
    .with_total_chunks(1)
    .with_message_length(payload.len() as u32)
    .with_chunk_size(1024)
    .build()?;
```

The builder validates all fields and their relationships, returning an error if any invariant is violated.

## Reassembly

The receiver tracks per-message state as chunks arrive:

1. **Admission** — the packet passes runtime policy checks (auth, source, budget, freshness)
2. **Deduplication** — duplicate chunk indices within the same message are discarded
3. **FEC recovery** — Reed-Solomon: when enough data + parity shards are present (at least `data_shards` total), missing data chunks are reconstructed
4. **Completion** — when all `total_chunks` data chunks are present (received or recovered), the message is complete

A receive call returns a `MessageReport` with:

- All received and recovered chunks
- Lists of lost and FEC-recovered chunk indices
- The `CompletionReason` (`Completed`, `InactivityTimeout`, or `OverallTimeout`)
- Source address, declared message metadata, and redundancy statistics

## API Reference

### Packet encoding/decoding

- `uniudp::packet::encode_packet` — encode without authentication
- `uniudp::packet::encode_packet_with_auth` — encode with optional HMAC-SHA256
- `uniudp::packet::encode_packet_with_security` — encode with `PacketEncodeSecurity`
- `uniudp::packet::parse_packet` — parse with payload copy
- `uniudp::packet::parse_packet_view` — zero-copy parse
- `uniudp::packet::parse_packet_view_with_wire_security` — parse with security metadata

### Types

- `uniudp::packet::PacketHeader` — decoded header fields
- `uniudp::packet::PacketHeaderBuilder` — fluent header construction
- `uniudp::packet::ParsedPacket` — borrowed parse result
- `uniudp::packet::ParsedPacketWithSecurity` — parse result with wire security fields
- `uniudp::packet::PacketSecurity` — flags, auth key ID, checksum, auth tag
- `uniudp::packet::PacketEncodeSecurity` — auth configuration for encoding

### FEC helpers

- `uniudp::fec::FecMode` — enum: `None`, `ReedSolomon { data_shards, parity_shards }`
- `uniudp::fec::pack_fec_field` — encode group size + parity flag into `u16` (used internally for no-FEC sentinel)
- `uniudp::fec::pack_rs_data_field` — encode RS data shard fec_field
- `uniudp::fec::pack_rs_parity_field` — encode RS parity shard fec_field
- `uniudp::fec::fec_is_parity` — test whether a packet is a parity packet
- `uniudp::fec::fec_is_rs` — test whether a fec_field uses Reed-Solomon mode
- `uniudp::fec::fec_group_size_from_field` — extract group size from encoded field
- `uniudp::fec::rs_params_from_field` — extract `(data_shards, parity_shards, parity_index)` from RS field

### Constants

- `uniudp::packet::HEADER_LENGTH` — `84` bytes
- `uniudp::packet::PACKET_AUTH_TAG_LENGTH` — `16` bytes
- `uniudp::packet::PACKET_CHECKSUM_OFFSET` — `64`
- `uniudp::fec::MAX_RS_DATA_SHARDS` — `64`
- `uniudp::fec::MAX_RS_PARITY_SHARDS` — `16`
