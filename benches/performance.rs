use std::net::UdpSocket;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use uniudp::auth::{PacketAuth, PacketAuthKey};
use uniudp::fec::{pack_fec_field, pack_rs_data_field, pack_rs_parity_field, FecMode};
use uniudp::message::{MessageKey, SenderId};
use uniudp::options::{ReceiveOptions, SendOptions};
use uniudp::packet::{
    encode_packet, encode_packet_with_auth, parse_packet, parse_packet_view, PacketHeader,
};
use uniudp::receiver::Receiver;
use uniudp::sender::{SendRequest, SendScratch, Sender};

#[allow(clippy::too_many_arguments)]
fn make_header(
    sender_id: SenderId,
    session_nonce: u64,
    message_id: u64,
    chunk_index: u32,
    total_chunks: u32,
    message_length: u32,
    chunk_size: u16,
    payload_len: u16,
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
        1,
        1,
        fec_field,
    )
    .expect("benchmark packet header should be valid")
}

fn bench_packet_encode_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet");
    let sender_id = SenderId(0x0123_4567_89AB_CDEF_0011_2233_4455_6677);
    let session_nonce = 0xBEEF_CAFE_F00D_1234;
    let auth = PacketAuth::new(7, PacketAuthKey::from([0x5A; 32]));
    let fec_field = pack_fec_field(1, false).expect("fec=1 should encode");

    for size in [256_usize, 1024, 4096] {
        let payload = vec![0xAB; size];
        let header = make_header(
            sender_id,
            session_nonce,
            42,
            0,
            1,
            size as u32,
            size as u16,
            size as u16,
            fec_field,
        );
        let packet = encode_packet(header, &payload).expect("encode packet");
        let auth_packet =
            encode_packet_with_auth(header, &payload, Some(&auth)).expect("encode auth packet");

        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("encode_plain", size), &size, |b, _| {
            b.iter(|| {
                let encoded =
                    encode_packet(black_box(header), black_box(&payload)).expect("encode");
                black_box(encoded.len());
            });
        });
        group.bench_with_input(BenchmarkId::new("encode_auth", size), &size, |b, _| {
            b.iter(|| {
                let encoded =
                    encode_packet_with_auth(black_box(header), black_box(&payload), Some(&auth))
                        .expect("encode auth");
                black_box(encoded.len());
            });
        });
        group.bench_with_input(BenchmarkId::new("parse_view_plain", size), &size, |b, _| {
            b.iter(|| {
                let parsed = parse_packet_view(black_box(&packet)).expect("parse view");
                black_box(parsed.payload.len());
            });
        });
        group.bench_with_input(
            BenchmarkId::new("parse_owned_plain", size),
            &size,
            |b, _| {
                b.iter(|| {
                    let (_, parsed_payload) =
                        parse_packet(black_box(&packet)).expect("parse owned");
                    black_box(parsed_payload.len());
                });
            },
        );
        group.bench_with_input(BenchmarkId::new("parse_view_auth", size), &size, |b, _| {
            b.iter(|| {
                let parsed = parse_packet_view(black_box(&auth_packet)).expect("parse auth view");
                black_box(parsed.payload.len());
            });
        });
    }
    group.finish();
}

fn bench_fec_recovery(c: &mut Criterion) {
    let mut group = c.benchmark_group("fec_recovery");
    let inject_socket = UdpSocket::bind("127.0.0.1:0").expect("bind injector");
    let mut recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    let destination = recv_socket.local_addr().expect("receiver addr");

    let mut receiver = Receiver::new();
    let receive_options = ReceiveOptions::new()
        .with_inactivity_timeout(Duration::from_millis(50))
        .with_overall_timeout(Duration::from_millis(500));

    let sender_id = SenderId(0xA1A2_A3A4_A5A6_A7A8_B1B2_B3B4_B5B6_B7B8);
    let session_nonce = 0x0102_0304_0506_0708;
    let chunk_size = 1024_usize;
    let data_shards: u8 = 4;
    let parity_shards: u8 = 1;
    let total_chunks = u32::from(data_shards);
    let message_length = (chunk_size as u32) * total_chunks;
    let data_field = pack_rs_data_field(data_shards, parity_shards).expect("rs data field");
    let chunk_size_u16 = chunk_size as u16;

    let data_chunks: Vec<Vec<u8>> = (0..data_shards as usize)
        .map(|idx| vec![(idx as u8).wrapping_add(1); chunk_size])
        .collect();

    // Build RS parity using the encoder
    let encoder =
        reed_solomon_erasure::galois_8::ReedSolomon::new(data_shards.into(), parity_shards.into())
            .expect("rs encoder");
    let data_refs: Vec<&[u8]> = data_chunks.iter().map(|c| c.as_slice()).collect();
    let mut parity_chunk = vec![0_u8; chunk_size];
    let mut parity_refs: Vec<&mut [u8]> = vec![parity_chunk.as_mut_slice()];
    encoder
        .encode_sep(&data_refs, &mut parity_refs)
        .expect("rs encode");

    let mut message_id = 0_u64;
    group.throughput(Throughput::Bytes(
        (message_length + chunk_size as u32) as u64,
    ));
    group.bench_function("single_missing_chunk", |b| {
        b.iter(|| {
            let current_message_id = message_id;
            message_id = message_id.wrapping_add(1);

            // Deliver chunks 0, 2, 3 (skip chunk 1) plus one RS parity packet.
            for chunk_index in [0_u32, 2_u32, 3_u32] {
                let header = make_header(
                    sender_id,
                    session_nonce,
                    current_message_id,
                    chunk_index,
                    total_chunks,
                    message_length,
                    chunk_size_u16,
                    chunk_size_u16,
                    data_field,
                );
                let packet =
                    encode_packet(header, &data_chunks[chunk_index as usize]).expect("encode data");
                inject_socket
                    .send_to(&packet, destination)
                    .expect("send data packet");
            }

            let parity_field =
                pack_rs_parity_field(data_shards, parity_shards, 0).expect("rs parity field");
            let parity_header = make_header(
                sender_id,
                session_nonce,
                current_message_id,
                0,
                total_chunks,
                message_length,
                chunk_size_u16,
                chunk_size_u16,
                parity_field,
            );
            let parity_packet =
                encode_packet(parity_header, &parity_chunk).expect("encode parity packet");
            inject_socket
                .send_to(&parity_packet, destination)
                .expect("send parity packet");

            let key = MessageKey {
                sender_id,
                session_nonce,
                message_id: current_message_id,
            };
            let report = receiver
                .receive_message(&mut recv_socket, receive_options.with_key(key))
                .expect("receive recovered message");
            black_box(report.fec_recovered_chunks.len());
        });
    });
    group.finish();
}

fn bench_end_to_end_loopback(c: &mut Criterion) {
    let mut group = c.benchmark_group("end_to_end_loopback");
    let send_socket = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    let mut recv_socket = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
    let destination = recv_socket.local_addr().expect("receiver addr");
    let payload = vec![0xCD; 4096];

    let sender = Sender::new();
    let mut receiver = Receiver::new();
    let mut scratch = SendScratch::new();
    let receive_options = ReceiveOptions::new()
        .with_inactivity_timeout(Duration::from_millis(50))
        .with_overall_timeout(Duration::from_millis(500));

    for (name, send_options) in [
        ("chunk1024_no_fec", SendOptions::new().with_chunk_size(1024)),
        (
            "chunk1024_rs4_1",
            SendOptions::new()
                .with_chunk_size(1024)
                .with_fec_mode(FecMode::ReedSolomon {
                    data_shards: 4,
                    parity_shards: 1,
                }),
        ),
    ] {
        group.throughput(Throughput::Bytes(payload.len() as u64));
        group.bench_function(name, |b| {
            b.iter(|| {
                let key = sender
                    .send_with_socket_with_scratch(
                        &send_socket,
                        SendRequest::new(destination, black_box(&payload))
                            .with_options(send_options.clone()),
                        &mut scratch,
                    )
                    .expect("send message");
                let report = receiver
                    .receive_message(&mut recv_socket, receive_options.with_key(key))
                    .expect("receive message");
                black_box(report.chunks_received);
            });
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_packet_encode_decode,
    bench_fec_recovery,
    bench_end_to_end_loopback
);
criterion_main!(benches);
