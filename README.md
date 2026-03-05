# UniUDP

**Unidirectional UDP transport for Rust** — send messages reliably over UDP without requiring a back-channel. UniUDP handles chunking, reassembly, redundancy, forward error correction, packet authentication, and replay protection so you can focus on your application.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.74%2B-orange.svg)](https://www.rust-lang.org)

## Why UniUDP?

Standard UDP gives you raw datagrams with no delivery guarantees. TCP gives you reliable streams but requires a bidirectional connection. UniUDP sits in between: it adds reliability mechanisms to UDP while remaining fully **unidirectional** — the receiver never sends packets back to the sender.

This makes UniUDP ideal for:

- **Broadcast/multicast data distribution** — one sender, many receivers
- **Telemetry and sensor streaming** — fire-and-forget with recovery
- **Log shipping and event forwarding** — reliable delivery without back-pressure
- **Network-constrained environments** — where return paths are unavailable or undesirable

## Features

| Feature | Description |
|---------|-------------|
| **Chunked transport** | Automatically splits messages up to 16 MB into configurable chunks (default 1024 bytes) |
| **Packet redundancy** | Retransmit each packet N times to survive packet loss |
| **Forward error correction** | Reed-Solomon erasure coding for multi-chunk recovery per group |
| **Packet authentication** | Optional HMAC-SHA256 per-packet auth with key ID rotation |
| **Replay protection** | Session tracking, message freshness windows, and deduplication |
| **Source policy controls** | Pin receivers to specific source addresses or IPs |
| **Resource budgets** | Configurable limits on pending messages, bytes, and sessions |
| **Async support** | Optional Tokio integration for non-blocking I/O |
| **Thread-safe sender** | `Arc<Sender>` sharing across threads with `&self` send methods |
| **Diagnostics** | Per-receive counters for packets, rejections, duplicates, and recoveries |

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
uniudp = "1"
```

For async/Tokio support:

```toml
[dependencies]
uniudp = { version = "1", features = ["tokio"] }
tokio = { version = "1", features = ["macros", "rt", "net"] }
```

`uniudp`'s `tokio` feature enables async APIs in this crate. Add a direct
`tokio` dependency when your application uses `tokio::net::UdpSocket` and
`#[tokio::main]` (as in the async example below).

## Quick Start

### Send and receive a message

```rust
use std::net::UdpSocket;
use std::time::Duration;
use uniudp::message::SourcePolicy;
use uniudp::options::{ReceiveOptions, SendOptions};
use uniudp::receiver::Receiver;
use uniudp::sender::{SendRequest, Sender};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Bind sockets
    let send_socket = UdpSocket::bind("127.0.0.1:0")?;
    let mut recv_socket = UdpSocket::bind("127.0.0.1:5000")?;

    // Create sender and receiver
    let tx = Sender::new();
    let mut rx = Receiver::new();

    // Send a message with 2x redundancy and RS FEC
    let payload = b"hello uniudp".to_vec();
    let key = tx.send_with_socket(
        &send_socket,
        SendRequest::new(recv_socket.local_addr()?, &payload)
            .with_options(
                SendOptions::new()
                    .with_redundancy(2)
                    .with_chunk_size(1024)
                    .with_fec_mode(uniudp::fec::FecMode::ReedSolomon {
                        data_shards: 4,
                        parity_shards: 2,
                    }),
            ),
    )?;

    // Receive and reassemble
    let report = rx.receive_message(
        &mut recv_socket,
        ReceiveOptions::new()
            .with_key(key)
            .with_source_policy(SourcePolicy::AnyFirstSource)
            .with_overall_timeout(Duration::from_secs(2)),
    )?;

    let data = report.try_materialize_complete()?;
    assert_eq!(data, payload);
    Ok(())
}
```

### Async with Tokio

```rust,ignore
use tokio::net::UdpSocket;
use std::time::Duration;
use uniudp::message::SourcePolicy;
use uniudp::options::{ReceiveOptions, SendOptions};
use uniudp::receiver::Receiver;
use uniudp::sender::{SendRequest, Sender};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let send_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let recv_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let destination = recv_socket.local_addr()?;

    let tx = Sender::new();
    let mut rx = Receiver::new();
    let payload = b"hello async uniudp".to_vec();

    let key = tx.send_with_tokio_socket(
        &send_socket,
        SendRequest::new(destination, &payload)
            .with_options(SendOptions::new().with_redundancy(2)),
    ).await?;

    let report = rx.receive_message_async(
        &recv_socket,
        ReceiveOptions::new()
            .with_key(key)
            .with_source_policy(SourcePolicy::AnyFirstSource)
            .with_overall_timeout(Duration::from_secs(2)),
    ).await?;

    assert_eq!(report.try_materialize_complete()?, payload);
    Ok(())
}
```

### Authenticated messages

```rust,no_run
use std::net::UdpSocket;
use uniudp::auth::{PacketAuth, PacketAuthKey};
use uniudp::config::ReceiverConfig;
use uniudp::options::SendIdentityOverrides;
use uniudp::receiver::Receiver;
use uniudp::sender::{SendRequest, Sender};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let send_socket = UdpSocket::bind("127.0.0.1:0")?;
# let destination: std::net::SocketAddr = "127.0.0.1:5000".parse()?;
# let payload = b"hello".to_vec();
# let tx = Sender::new();

// Define a shared key (32 bytes) with a key ID for rotation
let auth = PacketAuth::new(1, PacketAuthKey::from([0xAB; 32]));

// Sender: attach auth to each message
let key = tx.send_with_socket(
    &send_socket,
    SendRequest::new(destination, &payload)
        .with_identity(SendIdentityOverrides::new().with_packet_auth(auth.clone())),
)?;

// Receiver: require authentication
let mut rx = Receiver::try_with_config(
    ReceiverConfig::new().with_auth_key(auth)
)?;
# Ok(())
# }
```

The receiver can hold multiple keys simultaneously for seamless key rotation.

## Core Concepts

### Messages and Chunks

UniUDP splits each message into fixed-size **chunks** (default 1024 bytes), wraps each in an 84-byte header, and sends them as individual UDP datagrams. The receiver reassembles chunks back into the original message.

### Reliability Without a Back-Channel

Since there is no return path, UniUDP provides two mechanisms to handle packet loss:

- **Redundancy** (`with_redundancy(n)`) — sends each packet `n` times. Simple and effective for uniform loss.
- **Reed-Solomon FEC** (`with_fec_mode(FecMode::ReedSolomon { data_shards, parity_shards })`) — generates parity shards per group, recovering up to `parity_shards` missing data chunks per group.

Both can be combined. The `MessageReport` tells you exactly which chunks were received, lost, or recovered via FEC.

### Choosing FEC Parameters

Reed-Solomon FEC is configured with `data_shards` (chunks per group) and `parity_shards` (recovery chunks per group). More parity shards improve loss tolerance at the cost of bandwidth.

| Scenario | Config | Overhead | Recovers |
|----------|--------|----------|----------|
| **General purpose** | `data_shards: 4, parity_shards: 2` | 50% | Up to 2 lost chunks per group |
| Bandwidth-constrained | `data_shards: 8, parity_shards: 1` | 12.5% | 1 per group |
| High loss (>15%) | `data_shards: 4, parity_shards: 4` | 100% | Up to 4 per group |
| Maximum resilience | `data_shards: 4, parity_shards: 2` + `redundancy: 2` | 3x total | FEC + full duplication |

For most workloads, **`data_shards: 4, parity_shards: 2`** is a good starting point. See [Performance](docs/perf.md) for detailed tuning guidance.

### Identity and Sessions

Each `Sender` has a 128-bit `SenderId` and a random `session_nonce`. Together with a monotonically increasing `message_id`, these form a `MessageKey` that uniquely identifies every message. The receiver uses this identity triple for deduplication, replay protection, and freshness checks.

### Source Policies

Control which network sources the receiver accepts packets from:

| Policy | Behavior |
|--------|----------|
| `AnyFirstSource` | Accept from any address; pin to the first source seen |
| `Exact(addr)` | Only accept from a specific `SocketAddr` |
| `SameIp` | Accept any port from the first source's IP |

### Timeouts and Completion

Receive operations use two timeouts:

- **Inactivity timeout** (default 500ms) — how long to wait with no new packets before giving up
- **Overall timeout** (default 5s) — maximum total wait time

The `MessageReport` includes a `CompletionReason` (`Completed`, `InactivityTimeout`, or `OverallTimeout`) so your application can distinguish full delivery from partial results.

## Send Options

```rust,no_run
use std::time::Duration;
use uniudp::fec::FecMode;
use uniudp::options::SendOptions;

# fn main() {
let options = SendOptions::new()
    .with_chunk_size(1024)      // Bytes per chunk (default: 1024)
    .with_redundancy(2)         // Send each packet 2x (default: 1)
    .with_fec_mode(FecMode::ReedSolomon { data_shards: 4, parity_shards: 2 }) // RS FEC
    .with_delay(Duration::from_micros(100));  // Inter-packet pacing delay
# }
```

## Receive Options

```rust,no_run
use std::time::Duration;
use uniudp::message::SourcePolicy;
use uniudp::options::ReceiveOptions;
# use uniudp::message::MessageKey;

# fn main() {
# let key: MessageKey = todo!();
let options = ReceiveOptions::new()
    .with_key(key)                          // Wait for a specific message
    .with_source_policy(SourcePolicy::AnyFirstSource)
    .with_inactivity_timeout(Duration::from_millis(500))
    .with_overall_timeout(Duration::from_secs(5))
    .with_strict_rejections(false);         // true = fail-fast on bad packets
# }
```

## Receiver Configuration

For advanced deployments, tune receiver resource budgets and security policies:

```rust,no_run
use std::time::Duration;
use uniudp::auth::{PacketAuth, PacketAuthKey};
use uniudp::config::{AuthMode, ReceiverConfig};
use uniudp::receiver::Receiver;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let key_v1 = PacketAuth::new(1, PacketAuthKey::from([0xAB; 32]));
let key_v2 = PacketAuth::new(2, PacketAuthKey::from([0xCD; 32]));

let config = ReceiverConfig::new()
    .with_max_pending_messages(100)            // Max concurrent incomplete messages
    .with_max_pending_bytes(128 * 1024 * 1024) // Max heap for pending state
    .with_max_receive_message_len(16 * 1024 * 1024) // Max message size (16 MB)
    .with_max_receive_chunks(4096)             // Max chunks per message
    .with_dedup_window(Duration::from_secs(10))
    .with_message_freshness_window(16_384)     // Message ID freshness distance
    .with_session_freshness_retention(Duration::from_secs(3600)) // Session state TTL
    .with_strict_message_ordering(true)        // Require message_id > max_seen
    .with_auth_mode(AuthMode::Require)         // Require packet authentication
    .with_auth_keys(vec![key_v1, key_v2]);     // Accept multiple key IDs

let mut rx = Receiver::try_with_config(config)?;
# Ok(())
# }
```

## Working with Results

```rust,no_run
use std::time::Duration;
use uniudp::message::SourcePolicy;
use uniudp::options::ReceiveOptions;
use uniudp::receiver::Receiver;
# use uniudp::message::MessageKey;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let mut rx = Receiver::new();
# let mut socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
# let key: MessageKey = todo!();
# let options = ReceiveOptions::new()
#     .with_key(key)
#     .with_source_policy(SourcePolicy::AnyFirstSource)
#     .with_overall_timeout(Duration::from_secs(2));
let report = rx.receive_message(&mut socket, options)?;

if report.is_complete() {
    // All chunks received — safe to materialize
    let data = report.try_materialize_complete()?;
} else {
    // Partial delivery — inspect what happened
    println!("received {}/{} chunks", report.chunks_received, report.chunks_expected);
    println!("lost chunks: {:?}", report.lost_chunks);
    println!("FEC recovered: {:?}", report.fec_recovered_chunks);
    println!("reason: {:?}", report.completion_reason);

    // Zero-fill missing chunks (lossy)
    let partial = report.materialize_payload_lossy();
}
# Ok(())
# }
```

## Diagnostics

After each receive, inspect packet-level counters:

```rust,no_run
use uniudp::receiver::Receiver;

# fn main() {
# let rx = Receiver::new();
let diag = rx.last_receive_diagnostics();
// diag.packets_received, diag.packets_accepted,
// diag.auth_rejections, diag.replay_rejections,
// diag.source_rejections, diag.duplicate_packets, ...
# }
```

## API Modules

| Module | Contents |
|--------|----------|
| `uniudp::sender` | `Sender`, `SenderBuilder`, `SendRequest`, `SendFailure`, `MessageIdStart` |
| `uniudp::receiver` | `Receiver`, `ReceiveLoopControl` |
| `uniudp::options` | `SendOptions`, `ReceiveOptions`, `SendIdentityOverrides`, `ReceiveDiagnostics` |
| `uniudp::message` | `MessageKey`, `SenderId`, `SourcePolicy`, `MessageReport`, `CompletionReason` |
| `uniudp::config` | `ReceiverConfig`, `AuthMode`, protocol constants |
| `uniudp::auth` | `PacketAuth`, `PacketAuthKey` |
| `uniudp::packet` | `PacketHeader`, encoding/decoding, `ParsedPacket` |
| `uniudp::fec` | `FecMode`, Reed-Solomon field encoding/decoding |
| `uniudp::prelude` | Common imports for quick setup |

## Examples

Run the included examples:

```sh
cargo run --example basic_send_receive
cargo run --example fec_recovery
cargo run --example auth_key_rotation
cargo run --example multi_sender
cargo run --example tokio_send_receive --features tokio
```

## Detailed Documentation

- [Protocol](docs/protocol.md) — packet layout, header fields, encoding invariants
- [Security](docs/security.md) — threat model, authentication, replay protection
- [Performance](docs/perf.md) — tuning chunking, redundancy, FEC, and receiver budgets

## Benchmarks

```sh
cargo bench --bench performance
```

Benchmarks cover packet encode/decode, FEC recovery, and end-to-end loopback throughput.

## License

MIT
