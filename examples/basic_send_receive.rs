use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;

use uniudp::fec::FecMode;
use uniudp::message::SourcePolicy;
use uniudp::options::{ReceiveOptions, SendOptions};
use uniudp::receiver::Receiver;
use uniudp::sender::{SendRequest, Sender};

fn main() -> Result<(), Box<dyn Error>> {
    let sender_socket = UdpSocket::bind("127.0.0.1:0")?;
    let mut receiver_socket = UdpSocket::bind("127.0.0.1:0")?;
    let destination = receiver_socket.local_addr()?;

    let sender = Sender::new();
    let mut receiver = Receiver::new();
    let payload = b"hello from UniUDP".to_vec();

    let key = sender.send_with_socket(
        &sender_socket,
        SendRequest::new(destination, &payload).with_options(
            SendOptions::new()
                .with_redundancy(2)
                .with_chunk_size(1024)
                .with_fec_mode(FecMode::ReedSolomon {
                    data_shards: 4,
                    parity_shards: 1,
                }),
        ),
    )?;

    let report = receiver.receive_message(
        &mut receiver_socket,
        ReceiveOptions::new()
            .with_key(key)
            .with_source_policy(SourcePolicy::AnyFirstSource)
            .with_overall_timeout(Duration::from_secs(2)),
    )?;

    println!("received key={}", report.key);
    println!(
        "chunks={}/{} reason={:?}",
        report.chunks_received, report.chunks_expected, report.completion_reason
    );
    assert_eq!(report.try_materialize_complete()?, payload);
    Ok(())
}
