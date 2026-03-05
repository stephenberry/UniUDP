#[cfg(feature = "tokio")]
use std::error::Error;
#[cfg(feature = "tokio")]
use std::time::Duration;

#[cfg(feature = "tokio")]
use tokio::net::UdpSocket;
#[cfg(feature = "tokio")]
use uniudp::fec::FecMode;
#[cfg(feature = "tokio")]
use uniudp::message::SourcePolicy;
#[cfg(feature = "tokio")]
use uniudp::options::{ReceiveOptions, SendOptions};
#[cfg(feature = "tokio")]
use uniudp::receiver::Receiver;
#[cfg(feature = "tokio")]
use uniudp::sender::{SendRequest, Sender};

#[cfg(feature = "tokio")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let sender_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let receiver_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let destination = receiver_socket.local_addr()?;

    let sender = Sender::new();
    let mut receiver = Receiver::new();
    let payload = b"hello from tokio uniudp".to_vec();

    let key = sender
        .send_with_tokio_socket(
            &sender_socket,
            SendRequest::new(destination, &payload).with_options(
                SendOptions::new()
                    .with_redundancy(2)
                    .with_chunk_size(1024)
                    .with_fec_mode(FecMode::ReedSolomon {
                        data_shards: 2,
                        parity_shards: 1,
                    }),
            ),
        )
        .await?;

    let report = receiver
        .receive_message_async(
            &receiver_socket,
            ReceiveOptions::new()
                .with_key(key)
                .with_source_policy(SourcePolicy::AnyFirstSource)
                .with_overall_timeout(Duration::from_secs(2)),
        )
        .await?;

    assert_eq!(report.try_materialize_complete()?, payload);
    println!("received key={} (async)", report.key);
    Ok(())
}

#[cfg(not(feature = "tokio"))]
fn main() {
    eprintln!("Enable tokio feature: cargo run --example tokio_send_receive --features tokio");
}
