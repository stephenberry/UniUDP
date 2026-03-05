# Security

This document covers UniUDP's threat model, authentication mechanisms, replay protection, and operational security considerations.

## Threat Model

UDP traffic is inherently spoofable — any host on the network path can forge source addresses and inject packets. UniUDP is designed to operate safely across a spectrum of trust levels:

| Environment | Recommendation |
|-------------|----------------|
| Trusted localhost / loopback | Authentication optional. CRC32C catches corruption. |
| Trusted LAN (no hostile actors) | Authentication recommended but not strictly required. |
| Untrusted network / internet | Authentication required. Enable `AuthMode::Require`. |

**Without authentication**, UniUDP provides:
- Data integrity via CRC32C checksums (detects accidental corruption)
- Message deduplication
- Source policy controls (address pinning)

**With authentication**, UniUDP additionally provides:
- Sender identity verification (HMAC-SHA256)
- Tamper detection (any modification invalidates the auth tag)
- Replay protection via session tracking and message freshness windows
- Fail-closed session budgets to bound state from authenticated senders

## Packet Authentication

### How It Works

UniUDP uses **HMAC-SHA256** with a 32-byte key to authenticate each packet. The authentication tag is computed over the header (excluding the tag itself) and the payload, then truncated to 16 bytes and stored in the `auth_tag` header field.

The `auth_key_id` header field identifies which key was used, enabling key rotation without downtime.

Authentication is verified using constant-time comparison (`subtle` crate) to prevent timing side-channel attacks.

### Sender Configuration

Attach authentication credentials to outgoing messages:

```rust
use uniudp::auth::{PacketAuth, PacketAuthKey};
use uniudp::options::SendIdentityOverrides;
use uniudp::sender::SendRequest;

let auth = PacketAuth::new(
    1,                                    // key_id for rotation
    PacketAuthKey::from([0xAB; 32]),      // 32-byte shared secret
);

let request = SendRequest::new(destination, &payload)
    .with_identity(
        SendIdentityOverrides::new().with_packet_auth(auth)
    );
```

### Receiver Configuration

Configure which keys the receiver accepts and how strictly to enforce authentication:

```rust
use uniudp::auth::{PacketAuth, PacketAuthKey};
use uniudp::config::{AuthMode, ReceiverConfig};

let key_v1 = PacketAuth::new(1, PacketAuthKey::from([0xAB; 32]));
let key_v2 = PacketAuth::new(2, PacketAuthKey::from([0xCD; 32]));

let config = ReceiverConfig::new()
    .with_auth_mode(AuthMode::Require)
    .with_auth_keys(vec![key_v1, key_v2]);
```

### Auth Modes

| Mode | Behavior |
|------|----------|
| `AuthMode::Require` | Every packet must carry a valid auth tag matching a configured key. Unauthenticated packets are rejected. |
| `AuthMode::Optional` | Unauthenticated packets are accepted. Authenticated packets must verify against a configured key — invalid tags are still rejected. |
| `AuthMode::Disabled` | No authentication checks are performed. This is the default when no keys are configured. |

**Auto-selection**: if you add auth keys without explicitly setting the mode, UniUDP auto-selects `Require`.

### Key Rotation

The receiver can hold multiple keys simultaneously, identified by `key_id`. To rotate keys:

1. Add the new key to both sender and receiver
2. Switch the sender to use the new `key_id`
3. Remove the old key from the receiver after a grace period

During the transition, the receiver accepts packets signed with either key.

### Key Security

`PacketAuthKey` wraps a `[u8; 32]` and implements `Zeroize` — the key material is securely erased from memory when the value is dropped. This prevents key leakage through freed memory.

## Integrity vs. Authenticity

UniUDP distinguishes between two levels of protection:

| Mechanism | Protects Against | Limitation |
|-----------|-----------------|------------|
| **CRC32C checksum** | Accidental corruption (bit flips, truncation) | Not cryptographic — trivially forgeable by an attacker |
| **HMAC-SHA256 auth tag** | Spoofing, tampering, and replay | Requires shared secret distribution |

The CRC32C checksum is always present and always verified. It catches corruption but provides **no authentication**. For adversarial environments, enable packet authentication.

## Replay Protection

UniUDP implements multiple layers of replay defense. These are most effective when combined with packet authentication (without auth, an attacker can forge arbitrary packets regardless of replay controls).

### Session Nonce Tracking

Each sender has a `session_nonce` — an opaque identifier that distinguishes independent sessions. The receiver tracks sessions per `sender_id`:

- Different `session_nonce` values represent distinct sessions
- Nonce values are **not ordered** — they are treated as opaque identifiers
- `Sender::new()` generates a random nonce by default
- Use explicit nonces only when you need deterministic session boundaries

### Message Freshness Window

For authenticated traffic, the receiver enforces a **freshness window** on `message_id` values within each `(sender_id, session_nonce)` pair:

- Default window size: 16,384
- Messages with IDs more than `freshness_window` behind the highest seen ID are rejected
- This prevents replay of old messages while allowing some reordering

To disable freshness checks (accept any message ID regardless of distance):

```rust
let config = ReceiverConfig::new()
    .with_unbounded_message_freshness(true);
```

### Session Freshness Retention

Session state (`max_message_id` per `(sender_id, session_nonce)`) is retained independently of the deduplication cache.  By default, session state is kept for **1 hour** (`session_freshness_retention`), while the dedup cache uses a shorter `dedup_window` (default 10 seconds).

This decoupling ensures that replayed authenticated packets are rejected by the freshness check even after their dedup cache entries expire.

```rust
let config = ReceiverConfig::new()
    .with_session_freshness_retention(Duration::from_secs(7200)); // 2 hours
```

### Strict Message Ordering

For maximum replay protection with authenticated traffic, enable strict message ordering:

```rust
let config = ReceiverConfig::new()
    .with_strict_message_ordering(true)
    .with_auth_keys(vec![key]);
```

When enabled, each authenticated `message_id` must be **strictly greater** than the highest previously seen `message_id` for that session.  This closes a gap where a captured packet with `message_id == max_seen` could otherwise be re-accepted after its dedup cache entry expires.

**Tradeoff**: strict ordering forbids out-of-order delivery within the freshness window.  This is compatible with the default `Sender` behavior (monotonically increasing IDs) but not with workloads that intentionally send non-sequential IDs.

### Deduplication Cache

Completed messages are cached for a configurable window (default 10 seconds) to reject duplicate deliveries:

- Configurable via `with_dedup_window(Duration)` and `with_max_completed_messages(usize)`
- Default cache size: 100,000 entries
- Duplicate packets for already-completed messages are silently dropped (or rejected in strict mode)

### Per-Chunk Replay

Within an in-flight message, duplicate chunk indices are discarded. Each chunk index can only be accepted once per message.

## Session Budget Controls

To prevent state exhaustion from authenticated senders, the receiver enforces configurable caps:

| Limit | Default | Purpose |
|-------|---------|---------|
| `max_tracked_sessions_total` | 100,000 | Maximum total authenticated sessions across all senders |
| `max_tracked_sessions_per_sender` | 1,024 | Maximum sessions per individual `sender_id` |

When either limit is reached, packets from **new** sessions are rejected. Existing sessions continue to work. This is a **fail-closed** policy — UniUDP never evicts tracked sessions to make room for new ones.

```rust
let config = ReceiverConfig::new()
    .with_max_tracked_sessions_total(50_000)
    .with_max_tracked_sessions_per_sender(256);
```

## Operational Notes

### Strict Rejection Mode

By default, the receiver silently discards invalid packets and continues waiting for valid ones. With strict rejections enabled, the receive call fails immediately on the first rejected packet:

```rust
let options = ReceiveOptions::new()
    .with_strict_rejections(true);
```

This is useful for testing and debugging but generally too aggressive for production, where sporadic invalid packets are expected.

### Diagnostics

After each receive, inspect rejection counters to understand traffic patterns:

```rust
let diag = rx.last_receive_diagnostics();
// diag.auth_rejections      — packets with invalid or missing auth tags
// diag.replay_rejections    — duplicate or stale message IDs
// diag.source_rejections    — packets from disallowed source addresses
// diag.metadata_rejections  — packets with invalid header metadata
// diag.decode_errors        — packets that failed parsing
// diag.duplicate_packets    — duplicate chunk indices within a message
// diag.pending_budget_rejections  — exceeded pending message/byte limits
// diag.session_budget_rejections  — exceeded session tracking limits
```

High rejection counts in specific categories indicate configuration issues, attack traffic, or network problems.

### Socket Modes

- **Blocking sockets** (recommended): `Receiver::receive_message` uses `mio` polling on unix and windows to wait for data without mutating socket state. On other platforms it falls back to `set_read_timeout`. The socket's previous read timeout is always saved and restored.
- **Tokio async**: `Receiver::receive_message_async` uses Tokio's async I/O primitives and never mutates socket state.

### Process Boundaries

`Sender` instances are bound to the process that created them (tracked by PID). Using a sender across `fork()` or other process boundaries is detected and rejected at send time. Always construct a new `Sender` in child processes.

### What UniUDP Does Not Provide

- **Confidentiality** — payloads are not encrypted. Use an application-layer encryption scheme if needed.
- **Key exchange** — shared secrets must be distributed out of band.
- **Nonce persistence** — session nonces are not persisted across process restarts. Applications must manage their own session continuity if needed.
- **Ordering guarantees** — messages may arrive out of order. Use `message_id` at the application layer to reorder if needed.
