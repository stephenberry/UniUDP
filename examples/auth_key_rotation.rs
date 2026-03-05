use std::error::Error;
use std::net::UdpSocket;
use std::time::Duration;

use uniudp::auth::{PacketAuth, PacketAuthKey};
use uniudp::config::{ReceiverConfig, PACKET_AUTH_KEY_LENGTH};
use uniudp::message::SourcePolicy;
use uniudp::options::{ReceiveOptions, SendIdentityOverrides, SendOptions};
use uniudp::receiver::Receiver;
use uniudp::sender::{SendRequest, Sender};

fn main() -> Result<(), Box<dyn Error>> {
    let sender_socket = UdpSocket::bind("127.0.0.1:0")?;
    let mut receiver_socket = UdpSocket::bind("127.0.0.1:0")?;
    let destination = receiver_socket.local_addr()?;

    let auth_v1 = PacketAuth::new(1, PacketAuthKey::from([0x11; PACKET_AUTH_KEY_LENGTH]));
    let auth_v2 = PacketAuth::new(2, PacketAuthKey::from([0x22; PACKET_AUTH_KEY_LENGTH]));

    let config = ReceiverConfig::new().with_auth_keys(vec![auth_v1.clone(), auth_v2.clone()]);
    let mut receiver = Receiver::try_with_config(config)?;
    let sender = Sender::new();

    let payload_v1 = b"message authenticated with key_id=1".to_vec();
    let payload_v2 = b"message authenticated with key_id=2".to_vec();

    let key_v1 = sender.send_with_socket(
        &sender_socket,
        SendRequest::new(destination, &payload_v1)
            .with_options(SendOptions::new())
            .with_identity(SendIdentityOverrides::new().with_packet_auth(auth_v1)),
    )?;
    let key_v2 = sender.send_with_socket(
        &sender_socket,
        SendRequest::new(destination, &payload_v2)
            .with_options(SendOptions::new())
            .with_identity(SendIdentityOverrides::new().with_packet_auth(auth_v2)),
    )?;

    let report_v1 = receiver.receive_message(
        &mut receiver_socket,
        ReceiveOptions::new()
            .with_key(key_v1)
            .with_source_policy(SourcePolicy::AnyFirstSource)
            .with_overall_timeout(Duration::from_secs(2)),
    )?;
    let report_v2 = receiver.receive_message(
        &mut receiver_socket,
        ReceiveOptions::new()
            .with_key(key_v2)
            .with_source_policy(SourcePolicy::AnyFirstSource)
            .with_overall_timeout(Duration::from_secs(2)),
    )?;

    assert_eq!(report_v1.try_materialize_complete()?, payload_v1);
    assert_eq!(report_v2.try_materialize_complete()?, payload_v2);
    println!("received with rotated auth keys: {key_v1} then {key_v2}");
    Ok(())
}
