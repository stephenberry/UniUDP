use std::net::UdpSocket;
use std::time::Duration;

use uniudp::config::HEADER_LENGTH;
use uniudp::fec::{fec_is_parity, pack_rs_data_field, pack_rs_parity_field, FecMode};
use uniudp::message::{CompletionReason, MessageKey, SenderId};
use uniudp::options::{ReceiveOptions, SendIdentityOverrides, SendOptions};
use uniudp::packet::{encode_packet, parse_packet, PacketHeader};
use uniudp::receiver::Receiver;
use uniudp::sender::{SendRequest, Sender};

#[derive(Clone, Debug)]
struct LcgRng(u64);

impl LcgRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0
    }

    fn next_u128(&mut self) -> u128 {
        (u128::from(self.next_u64()) << 64) | u128::from(self.next_u64())
    }

    fn next_usize(&mut self, upper: usize) -> usize {
        if upper == 0 {
            0
        } else {
            (self.next_u64() as usize) % upper
        }
    }

    fn gen_bool_ratio(&mut self, numerator: u64, denominator: u64) -> bool {
        if denominator == 0 {
            return false;
        }
        (self.next_u64() % denominator) < numerator
    }

    fn fill_bytes(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            *byte = self.next_u64() as u8;
        }
    }
}

fn shuffle<T>(items: &mut [T], rng: &mut LcgRng) {
    for i in (1..items.len()).rev() {
        let j = rng.next_usize(i + 1);
        items.swap(i, j);
    }
}

#[derive(Clone)]
struct GeneratedPacket {
    header: PacketHeader,
    payload: Vec<u8>,
}

fn generate_packets(
    key: MessageKey,
    payload: &[u8],
    chunk_size: u16,
    redundancy: u16,
    data_shards: u8,
    parity_shards: u8,
) -> Vec<GeneratedPacket> {
    let chunk_size_usize = usize::from(chunk_size);
    let total_chunks = if payload.is_empty() {
        1_usize
    } else {
        payload.len().div_ceil(chunk_size_usize)
    };
    let total_chunks_u32 = total_chunks as u32;
    let message_len_u32 = payload.len() as u32;

    let data_field = pack_rs_data_field(data_shards, parity_shards).unwrap();
    let fec_group_size = usize::from(data_shards);

    let encoder = reed_solomon_erasure::galois_8::ReedSolomon::new(
        usize::from(data_shards),
        usize::from(parity_shards),
    )
    .unwrap();

    // Collect all chunk payloads
    let mut chunk_payloads: Vec<Vec<u8>> = Vec::with_capacity(total_chunks);
    for chunk_idx in 0..total_chunks {
        let start = chunk_idx * chunk_size_usize;
        let end = (start + chunk_size_usize).min(payload.len());
        chunk_payloads.push(payload[start..end].to_vec());
    }

    let mut packets = Vec::new();

    for chunk_idx in 0..total_chunks {
        for attempt in 1..=redundancy {
            packets.push(GeneratedPacket {
                header: PacketHeader::new(
                    key.sender_id,
                    key.message_id,
                    0,
                    chunk_idx as u32,
                    total_chunks_u32,
                    message_len_u32,
                    chunk_size,
                    chunk_payloads[chunk_idx].len() as u16,
                    redundancy,
                    attempt,
                    data_field,
                )
                .expect("generated data header should be valid"),
                payload: chunk_payloads[chunk_idx].clone(),
            });
        }

        let group_offset = chunk_idx % fec_group_size;
        if group_offset == (fec_group_size - 1) || chunk_idx == (total_chunks - 1) {
            let group_start = chunk_idx - group_offset;

            // Pad chunks to chunk_size for RS encoding
            let mut data_bufs: Vec<Vec<u8>> = Vec::with_capacity(fec_group_size);
            for i in 0..fec_group_size {
                let gidx = group_start + i;
                if gidx < total_chunks {
                    let mut padded = chunk_payloads[gidx].clone();
                    padded.resize(chunk_size_usize, 0);
                    data_bufs.push(padded);
                } else {
                    data_bufs.push(vec![0u8; chunk_size_usize]);
                }
            }

            let mut parity_bufs: Vec<Vec<u8>> = (0..usize::from(parity_shards))
                .map(|_| vec![0u8; chunk_size_usize])
                .collect();

            let data_refs: Vec<&[u8]> = data_bufs.iter().map(|b| b.as_slice()).collect();
            let mut parity_refs: Vec<&mut [u8]> =
                parity_bufs.iter_mut().map(|b| b.as_mut_slice()).collect();
            encoder.encode_sep(&data_refs, &mut parity_refs).unwrap();

            for (pi, parity_buf) in parity_bufs.iter().enumerate() {
                let parity_field =
                    pack_rs_parity_field(data_shards, parity_shards, pi as u8).unwrap();
                for attempt in 1..=redundancy {
                    packets.push(GeneratedPacket {
                        header: PacketHeader::new(
                            key.sender_id,
                            key.message_id,
                            0,
                            group_start as u32,
                            total_chunks_u32,
                            message_len_u32,
                            chunk_size,
                            chunk_size,
                            redundancy,
                            attempt,
                            parity_field,
                        )
                        .expect("generated parity header should be valid"),
                        payload: parity_buf.clone(),
                    });
                }
            }
        }
    }

    packets
}

#[test]
fn randomized_packet_parse_fuzzing() {
    let mut rng = LcgRng::new(0xF00D_CAFE_DEAD_BEEF);

    for _ in 0..5_000 {
        let len = rng.next_usize(256);
        let mut bytes = vec![0_u8; len];
        rng.fill_bytes(&mut bytes);

        if let Ok((header, payload)) = parse_packet(&bytes) {
            assert_eq!(payload.len(), usize::from(header.payload_len()));
            assert!(payload.len() <= usize::from(header.chunk_size()));
            assert!(len >= HEADER_LENGTH + payload.len());
        }
    }
}

#[test]
fn randomized_end_to_end_matrix() {
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination = receiver_socket.local_addr().unwrap();
    let mut rng = LcgRng::new(0x1234_5678_9ABC_DEF0);
    let tx = Sender::new();

    let mut receiver = Receiver::new();
    for case_index in 0..120_u64 {
        receiver.clear_state();

        let payload_len = rng.next_usize(4096);
        let mut payload = vec![0_u8; payload_len];
        rng.fill_bytes(&mut payload);

        let chunk_size = (rng.next_usize(224) + 32) as u16;
        let redundancy = (rng.next_usize(3) + 1) as u16;
        let fec_mode = if rng.gen_bool_ratio(1, 3) {
            FecMode::None
        } else {
            FecMode::ReedSolomon {
                data_shards: (rng.next_usize(8) + 2) as u8,
                parity_shards: 1,
            }
        };
        let sender_id = SenderId(rng.next_u128());
        let message_id = 100_000 + case_index;

        let sent_key = tx
            .send_with_socket(
                &sender,
                SendRequest::new(destination, &payload)
                    .with_options(
                        SendOptions::new()
                            .with_redundancy(redundancy)
                            .with_chunk_size(chunk_size)
                            .with_fec_mode(fec_mode),
                    )
                    .with_identity(
                        SendIdentityOverrides::new()
                            .with_sender_id(sender_id)
                            .with_message_id(message_id),
                    ),
            )
            .unwrap();
        assert_eq!(
            sent_key,
            MessageKey {
                sender_id,
                session_nonce: tx.session_nonce(),
                message_id,
            }
        );

        let report = receiver
            .receive_message(
                &mut receiver_socket,
                ReceiveOptions::new()
                    .with_key(sent_key)
                    .with_inactivity_timeout(Duration::from_millis(60))
                    .with_overall_timeout(Duration::from_secs(2)),
            )
            .unwrap();

        assert_eq!(report.key, sent_key);
        assert_eq!(report.materialize_payload_lossy(), payload);
        assert!(report.lost_chunks.is_empty());
        assert_eq!(report.completion_reason, CompletionReason::Completed);
    }
}

#[test]
fn randomized_reassembly_with_drops_duplicates_and_shuffle() {
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut receiver_socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let destination = receiver_socket.local_addr().unwrap();
    let mut rng = LcgRng::new(0xA5A5_5A5A_0123_4567);

    let mut receiver = Receiver::new();
    for case_index in 0..80_u64 {
        receiver.clear_state();

        let payload_len = 1 + rng.next_usize(1200);
        let mut payload = vec![0_u8; payload_len];
        rng.fill_bytes(&mut payload);

        let chunk_size = (8 + rng.next_usize(88)) as u16;
        let data_shards = (2 + rng.next_usize(5)) as u8;
        let parity_shards = 1_u8;
        let key = MessageKey {
            sender_id: SenderId(0xA000 + u128::from(case_index)),
            session_nonce: 0,
            message_id: 200_000 + case_index,
        };

        let packets = generate_packets(key, &payload, chunk_size, 1, data_shards, parity_shards);
        let mut outbound: Vec<Vec<u8>> = Vec::with_capacity(packets.len() * 2);
        let mut dropped_data_packets = 0_usize;
        let mut dropped_in_group = std::collections::HashSet::<usize>::new();
        let group_size = usize::from(data_shards);

        for packet in packets {
            let is_parity = fec_is_parity(packet.header.fec_field());
            let group_index = (packet.header.chunk_index() as usize) / group_size;

            let drop_this =
                !is_parity && !dropped_in_group.contains(&group_index) && rng.gen_bool_ratio(1, 2);

            if drop_this {
                dropped_in_group.insert(group_index);
                dropped_data_packets += 1;
                continue;
            }

            let encoded = encode_packet(packet.header, &packet.payload).unwrap();
            outbound.push(encoded.clone());

            if rng.gen_bool_ratio(1, 3) {
                outbound.push(encoded);
            }
        }

        shuffle(&mut outbound, &mut rng);

        for datagram in outbound {
            sender.send_to(&datagram, destination).unwrap();
        }

        let report = receiver
            .receive_message(
                &mut receiver_socket,
                ReceiveOptions::new()
                    .with_key(key)
                    .with_inactivity_timeout(Duration::from_millis(80))
                    .with_overall_timeout(Duration::from_secs(2)),
            )
            .unwrap();

        assert_eq!(report.materialize_payload_lossy(), payload);
        assert!(report.lost_chunks.is_empty());
        assert_eq!(report.completion_reason, CompletionReason::Completed);
        assert!(report.fec_recovered_chunks.len() >= dropped_data_packets);
    }
}
