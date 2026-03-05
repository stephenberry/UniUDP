use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;

use uniudp::message::{SenderId, SourcePolicy};
use uniudp::options::{ReceiveOptions, SendIdentityOverrides, SendOptions};
use uniudp::receiver::Receiver;
use uniudp::sender::{SendRequest, Sender};

fn main() -> Result<(), Box<dyn Error>> {
    let sender_socket = UdpSocket::bind("127.0.0.1:0")?;
    let mut receiver_socket = UdpSocket::bind("127.0.0.1:0")?;
    let destination = receiver_socket.local_addr()?;

    let sender = Sender::new();
    let mut receiver = Receiver::new();

    let identity_a = SendIdentityOverrides::new()
        .with_sender_id(SenderId(0xA11CE))
        .with_session_nonce(100)
        .with_message_id(0);
    let identity_b = SendIdentityOverrides::new()
        .with_sender_id(SenderId(0xB0B))
        .with_session_nonce(200)
        .with_message_id(0);

    let payload_a = b"from logical sender A".to_vec();
    let payload_b = b"from logical sender B".to_vec();

    let key_a = sender.send_with_socket(
        &sender_socket,
        SendRequest::new(destination, &payload_a)
            .with_options(SendOptions::new())
            .with_identity(identity_a),
    )?;
    let key_b = sender.send_with_socket(
        &sender_socket,
        SendRequest::new(destination, &payload_b)
            .with_options(SendOptions::new())
            .with_identity(identity_b),
    )?;

    let report_a = receiver.receive_message(
        &mut receiver_socket,
        ReceiveOptions::new()
            .with_key(key_a)
            .with_source_policy(SourcePolicy::AnyFirstSource)
            .with_overall_timeout(Duration::from_secs(2)),
    )?;
    let report_b = receiver.receive_message(
        &mut receiver_socket,
        ReceiveOptions::new()
            .with_key(key_b)
            .with_source_policy(SourcePolicy::AnyFirstSource)
            .with_overall_timeout(Duration::from_secs(2)),
    )?;

    assert_ne!(key_a.sender_id, key_b.sender_id);
    assert_ne!(key_a.session_nonce, key_b.session_nonce);
    assert_eq!(report_a.try_materialize_complete()?, payload_a);
    assert_eq!(report_b.try_materialize_complete()?, payload_b);

    println!("sender A key: {}", report_a.key);
    println!("sender B key: {}", report_b.key);
    Ok(())
}
