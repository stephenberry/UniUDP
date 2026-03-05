# Performance

This guide covers how to tune UniUDP for your workload — optimizing throughput, latency, reliability, and memory usage.

## Chunk Size

The `chunk_size` parameter controls how messages are split into packets. Each packet carries one chunk plus an 84-byte header.

```rust
SendOptions::new().with_chunk_size(1024)  // default
```

### Choosing a chunk size

| Chunk Size | Header Overhead | Packets per 1 MB | Best For |
|------------|----------------|-------------------|----------|
| 512 bytes | 14% | ~2,048 | High-loss networks (smaller blast radius per lost packet) |
| 1,024 bytes | 7.6% | ~1,024 | General purpose (default) |
| 1,400 bytes | 5.7% | ~749 | LAN / low-loss networks (near MTU) |

**Key constraint**: `chunk_size + HEADER_LENGTH` (84 bytes) must fit within the network's UDP payload limit. For standard Ethernet (1500-byte MTU), the safe UDP payload is approximately 1,452 bytes, giving a maximum chunk size of ~1,368 bytes. UniUDP defines `SAFE_UDP_PAYLOAD = 1452` as a reference.

**Tradeoff**: larger chunks reduce the total packet count and header overhead but increase the impact of losing any single packet. Smaller chunks are more resilient to per-packet loss.

## Redundancy

Redundancy sends each packet multiple times to survive loss without requiring a back-channel:

```rust
SendOptions::new().with_redundancy(2)  // send everything twice
```

| Redundancy | Bandwidth Multiplier | Survives | Best For |
|------------|---------------------|----------|----------|
| 1 | 1x | No loss | Trusted networks, LAN |
| 2 | 2x | ~50% uniform loss | General purpose |
| 3 | 3x | ~67% uniform loss | Hostile networks |

Higher redundancy linearly increases bandwidth usage. For isolated (non-uniform) loss patterns, FEC is often more efficient.

## Forward Error Correction (FEC)

UniUDP uses Reed-Solomon erasure coding for forward error correction. RS generates parity shards per group, recovering up to `parity_shards` missing data chunks:

```rust
use uniudp::fec::FecMode;

SendOptions::new().with_fec_mode(FecMode::ReedSolomon {
    data_shards: 4,
    parity_shards: 2,
})
```

### FEC comparison

| Approach | Extra Packets | Recovery Capability |
|----------|---------------|---------------------|
| Redundancy = 2 | 100% overhead | Survives any pattern where at least one copy arrives |
| RS(4, 1) | 25% overhead | Recovers 1 missing chunk per group of 4 |
| RS(8, 1) | 12.5% overhead | Recovers 1 missing chunk per group of 8 |
| RS(4, 2) | 50% overhead | Recovers up to 2 missing chunks per group of 4 |
| RS(8, 2) | 25% overhead | Recovers up to 2 missing chunks per group of 8 |
| RS(8, 4) | 50% overhead | Recovers up to 4 missing chunks per group of 8 |

**Combine with redundancy** for maximum reliability: redundancy handles burst loss; FEC handles isolated drops.

```rust
use uniudp::fec::FecMode;

SendOptions::new()
    .with_redundancy(2)
    .with_fec_mode(FecMode::ReedSolomon { data_shards: 4, parity_shards: 2 })
```

### When to use which

| Scenario | Recommendation |
|----------|---------------|
| Low loss, bandwidth constrained | RS with 1 parity shard and large data_shards |
| Moderate loss (5-15%) | RS with 2-4 parity shards |
| High loss (>15%) | RS + redundancy |
| Messages with few chunks (1-3) | Redundancy only (FEC needs groups to be effective) |

### Limits

| Parameter | Reed-Solomon |
|-----------|-------------|
| Max data shards per group | 64 |
| Max parity shards per group | 16 |
| Max total shards per group | 80 (64 + 16) |

FEC recovered chunks are reported in `MessageReport::fec_recovered_chunks`. The `MessageReport::fec_mode` field indicates which FEC mode was used.

## Sender Pacing

Inter-packet delay prevents overwhelming the receiver or network buffers:

```rust
SendOptions::new().with_delay(Duration::from_micros(100))
```

The delay is applied between each packet send (data and parity). No delay is applied after the final packet, avoiding unnecessary tail latency.

### Pacing modes

| API | Pacing Method | Use Case |
|-----|---------------|----------|
| `send_with_socket` | `std::thread::sleep` | Blocking I/O |
| `send_with_socket_with_pacer` | Custom callback | Custom pacing logic |
| `send_with_tokio_socket` | `tokio::time::sleep` | Async I/O (Tokio) |
| `send_async_oneshot` | `tokio::time::sleep` | Async one-shot sends |

The async APIs avoid blocking the Tokio runtime worker thread during pacing delays.

## Receiver Memory Budgets

The receiver enforces resource limits to prevent unbounded memory growth:

```rust
use uniudp::config::ReceiverConfig;

let config = ReceiverConfig::new()
    .with_max_pending_messages(100)              // concurrent incomplete messages
    .with_max_pending_bytes(128 * 1024 * 1024)   // 128 MB pending heap budget
    .with_max_completed_messages(100_000)         // dedup cache entries
    .with_max_receive_chunks(4096)               // max chunks per message
    .with_max_receive_message_len(16 * 1024 * 1024); // max 16 MB per message
```

### Tuning guidance

| Workload | Adjustment |
|----------|------------|
| Many concurrent senders | Increase `max_pending_messages` |
| Large messages (>16 MB) | Increase `max_receive_message_len` and `max_receive_chunks` |
| Memory-constrained receiver | Lower `max_pending_bytes` and `max_pending_messages` |
| High-throughput dedup | Increase `max_completed_messages` and `dedup_window` |
| Long-lived receivers | Lower `pending_max_age` to evict stale incomplete messages faster |
| Authenticated replay protection | Increase `session_freshness_retention` and enable `strict_message_ordering` |

Packets that exceed any budget are rejected with a budget rejection reason, visible in `ReceiveDiagnostics`.

## Sender Tracking Capacity

The `Sender` tracks the highest `message_id` per `(sender_id, session_nonce)` pair to enforce strict monotonicity. This tracking is bounded:

- Default capacity: 4,096 identity pairs (`DEFAULT_MAX_TRACKED_SENDERS`)
- When full, sends for **new** identity pairs are rejected (fail-closed)
- Existing identity pairs continue to work

```rust
use uniudp::sender::Sender;

// Increase capacity for multi-identity workloads
let sender = Sender::builder()
    .with_sender_id(sender_id)
    .with_session_nonce(session_nonce)
    .with_max_tracked_senders(8192)
    .build()?;
```

## Message ID Allocation

Automatic `message_id` assignment is per-sender-instance and strictly monotonic:

```rust
use uniudp::sender::{SenderBuilder, MessageIdStart};

let sender = Sender::builder()
    .with_message_id_start(MessageIdStart::Zero)       // start from 0 (default)
    .with_message_id_start(MessageIdStart::Random)     // random starting point
    .with_message_id_start(MessageIdStart::Next(1000)) // resume from persisted state
    .build()?;
```

Use `MessageIdStart::Next(n)` to resume a sender's sequence after a process restart, avoiding freshness window conflicts on the receiver.

## Timeouts

Receive timeouts control how long the receiver waits before returning:

```rust
ReceiveOptions::new()
    .with_inactivity_timeout(Duration::from_millis(500))  // no-packet gap (default: 500ms)
    .with_overall_timeout(Duration::from_secs(5))          // total wait (default: 5s)
```

### Tuning guidance

| Scenario | Adjustment |
|----------|------------|
| Localhost / loopback | Lower inactivity to 10-50ms for faster completion |
| High-latency WAN | Increase both timeouts to accommodate RTT |
| Burst traffic | Increase inactivity timeout to tolerate gaps between bursts |
| Real-time applications | Lower overall timeout to bound worst-case latency |

The `MessageReport::completion_reason` tells you whether the message completed fully or timed out, so your application can react accordingly.

## Parsing Performance

Two parse paths are available with different performance characteristics:

| Function | Payload Handling | Use Case |
|----------|-----------------|----------|
| `parse_packet(buf)` | Copies payload into `Vec<u8>` | Simple usage, moderate rate |
| `parse_packet_view(buf)` | Borrows from input buffer | Zero-copy, high-rate packet inspection |

For custom packet processing pipelines (outside the `Receiver`), prefer `parse_packet_view` to avoid allocation overhead.

## Diagnostics

Use `Receiver::last_receive_diagnostics()` after each receive to identify bottlenecks:

```rust
let diag = rx.last_receive_diagnostics();
```

| Counter | Indicates |
|---------|-----------|
| High `decode_errors` | Malformed traffic or protocol mismatch |
| High `auth_rejections` | Key mismatch, expired keys, or spoofed traffic |
| High `replay_rejections` | Duplicate or stale messages (may indicate retransmit storms) |
| High `source_rejections` | Traffic from unexpected source addresses |
| High `pending_budget_rejections` | Receiver overwhelmed — increase budgets or reduce sender rate |
| High `session_budget_rejections` | Too many distinct sessions — increase session limits or investigate |
| High `duplicate_packets` | Redundancy working as intended, or network-level duplication |

## Benchmarks

Criterion benchmarks are provided in `benches/performance.rs`:

```sh
cargo bench --bench performance
```

### Benchmark groups

| Group | What It Measures |
|-------|-----------------|
| `packet` | Encode/decode throughput for plain and authenticated packets |
| `fec_recovery` | Reed-Solomon recovery latency |
| `end_to_end_loopback` | Full send/receive throughput over localhost |
