use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;

use uniudp::fec::FecMode;
use uniudp::message::{SenderId, SourcePolicy};
use uniudp::options::{ReceiveOptions, SendOptions};
use uniudp::receiver::Receiver;
use uniudp::sender::{SendRequest, Sender};

fn main() -> Result<(), Box<dyn Error>> {
    // --- Reed-Solomon FEC recovery ---
    // RS can recover multiple missing chunks per group (up to parity_shards).
    println!("--- Reed-Solomon FEC recovery ---");

    let sender_socket = UdpSocket::bind("127.0.0.1:0")?;
    let mut receiver_socket = UdpSocket::bind("127.0.0.1:0")?;
    let destination = receiver_socket.local_addr()?;
    let capture_socket = UdpSocket::bind("127.0.0.1:0")?;
    let capture_addr = capture_socket.local_addr()?;
    capture_socket.set_read_timeout(Some(Duration::from_millis(500)))?;

    let payload: Vec<u8> = (0..32).collect();
    let sender_id = SenderId(0xFEC);
    let session_nonce = 42_u64;
    let sender = Sender::with_identity(sender_id, session_nonce);

    let key = sender.send_with_socket(
        &sender_socket,
        SendRequest::new(capture_addr, &payload).with_options(
            SendOptions::new()
                .with_redundancy(1)
                .with_chunk_size(8)
                .with_fec_mode(FecMode::ReedSolomon {
                    data_shards: 4,
                    parity_shards: 2,
                }),
        ),
    )?;

    // Capture all 6 packets (4 data + 2 parity).
    let mut packets = Vec::new();
    for _ in 0..6 {
        let mut buf = vec![0_u8; 2048];
        let (len, _) = capture_socket.recv_from(&mut buf)?;
        packets.push(buf[..len].to_vec());
    }

    // Drop 2 data chunks (indices 0 and 2) — RS(4,2) can recover them.
    let mut filtered = Vec::new();
    for pkt in &packets {
        let (header, _) = uniudp::packet::parse_packet(pkt)?;
        if !uniudp::fec::fec_is_parity(header.fec_field())
            && (header.chunk_index() == 0 || header.chunk_index() == 2)
        {
            println!("  Dropping data chunk {}", header.chunk_index());
            continue;
        }
        filtered.push(pkt.clone());
    }

    // Replay remaining packets to receiver.
    for pkt in &filtered {
        sender_socket.send_to(pkt, destination)?;
    }

    let mut receiver = Receiver::new();
    let report = receiver.receive_message(
        &mut receiver_socket,
        ReceiveOptions::new()
            .with_key(key)
            .with_source_policy(SourcePolicy::AnyFirstSource)
            .with_overall_timeout(Duration::from_secs(2)),
    )?;

    assert_eq!(
        report.try_materialize_complete()?,
        (0..32).collect::<Vec<u8>>()
    );
    println!("RS FEC recovered chunks: {:?}", report.fec_recovered_chunks);
    println!(
        "RS FEC mode: {:?}, lost: {:?}",
        report.fec_mode, report.lost_chunks
    );

    Ok(())
}
