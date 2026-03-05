#![cfg(feature = "tokio")]

use std::collections::BTreeSet;
use std::time::Duration;

use tokio::net::UdpSocket;
use uniudp::options::{ReceiveOptions, SendIdentityOverrides, SendOptions};
use uniudp::receiver::{ReceiveLoopControl, Receiver};
use uniudp::sender::{SendRequest, SendScratch, Sender};

#[tokio::test(flavor = "current_thread")]
async fn tokio_socket_send_receive_end_to_end() {
    let sender_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender socket");
    let receiver_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind receiver socket");
    let destination = receiver_socket.local_addr().expect("receiver local addr");

    let tx = Sender::new();
    let mut rx = Receiver::new();
    let payload = b"hello async uniudp".to_vec();

    let key = tx
        .send_with_tokio_socket(
            &sender_socket,
            SendRequest::new(destination, &payload)
                .with_options(SendOptions::new().with_chunk_size(512).with_redundancy(1)),
        )
        .await
        .expect("async send should succeed");

    let report = rx
        .receive_message_async(
            &receiver_socket,
            ReceiveOptions::new()
                .with_key(key)
                .with_inactivity_timeout(Duration::from_millis(200))
                .with_overall_timeout(Duration::from_secs(2)),
        )
        .await
        .expect("async receive should succeed");

    assert_eq!(report.materialize_payload_lossy(), payload);
}

#[tokio::test(flavor = "current_thread")]
async fn tokio_convenience_send_with_identity_roundtrip() {
    let receiver_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind receiver socket");
    let destination = receiver_socket.local_addr().expect("receiver local addr");

    let tx = Sender::new();
    let mut rx = Receiver::new();
    let payload = b"identity override async send".to_vec();
    let identity = SendIdentityOverrides::new().with_message_id(42);

    let key = tx
        .send_async_oneshot(
            SendRequest::new(destination, &payload)
                .with_options(SendOptions::new().with_chunk_size(256).with_redundancy(1))
                .with_identity(identity),
        )
        .await
        .expect("async convenience send should succeed");

    let report = rx
        .receive_message_async(
            &receiver_socket,
            ReceiveOptions::new()
                .with_key(key)
                .with_inactivity_timeout(Duration::from_millis(200))
                .with_overall_timeout(Duration::from_secs(2)),
        )
        .await
        .expect("async receive should succeed");

    assert_eq!(report.materialize_payload_lossy(), payload);
}

#[tokio::test(flavor = "current_thread")]
async fn tokio_receive_loop_streams_messages_until_callback_stops() {
    let sender_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender socket");
    let receiver_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind receiver socket");
    let destination = receiver_socket.local_addr().expect("receiver local addr");

    let tx = Sender::new();
    let mut rx = Receiver::new();
    let payload_a = vec![0x10, 0x11, 0x12];
    let payload_b = vec![0x90, 0x91];

    tx.send_with_tokio_socket(
        &sender_socket,
        SendRequest::new(destination, &payload_a)
            .with_options(SendOptions::new().with_chunk_size(256).with_redundancy(1)),
    )
    .await
    .expect("first async send should succeed");
    tx.send_with_tokio_socket(
        &sender_socket,
        SendRequest::new(destination, &payload_b)
            .with_options(SendOptions::new().with_chunk_size(256).with_redundancy(1)),
    )
    .await
    .expect("second async send should succeed");

    let payloads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let delivered = rx
        .receive_loop_async(
            &receiver_socket,
            ReceiveOptions::new()
                .with_inactivity_timeout(Duration::from_millis(200))
                .with_overall_timeout(Duration::from_secs(2)),
            |report| {
                let payloads = std::sync::Arc::clone(&payloads);
                async move {
                    let mut payloads = payloads
                        .lock()
                        .expect("payload lock should not be poisoned");
                    payloads.push(report.materialize_payload_lossy());
                    if payloads.len() >= 2 {
                        ReceiveLoopControl::Stop
                    } else {
                        ReceiveLoopControl::Continue
                    }
                }
            },
        )
        .await
        .expect("async receive loop should succeed");

    assert_eq!(delivered, 2);
    let got: BTreeSet<Vec<u8>> = payloads
        .lock()
        .expect("payload lock should not be poisoned")
        .clone()
        .into_iter()
        .collect();
    let expected: BTreeSet<Vec<u8>> = [payload_a, payload_b].into_iter().collect();
    assert_eq!(got, expected);
}

#[tokio::test(flavor = "current_thread")]
async fn tokio_receive_loop_rejects_keyed_receive_options() {
    let receiver_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind receiver socket");
    let mut rx = Receiver::new();

    let err = rx
        .receive_loop_async(
            &receiver_socket,
            ReceiveOptions::new()
                .with_key(uniudp::message::MessageKey {
                    sender_id: uniudp::message::SenderId(0xB01),
                    session_nonce: 0,
                    message_id: 0x201,
                })
                .with_inactivity_timeout(Duration::from_millis(200))
                .with_overall_timeout(Duration::from_secs(2)),
            |_| async { ReceiveLoopControl::Stop },
        )
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        uniudp::UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiveOptions,
            message: "receive_loop does not support keyed ReceiveOptions; use receive_message for keyed receive",
            ..
        }
    ));
}

#[tokio::test(flavor = "current_thread")]
async fn tokio_send_with_scratch_reuses_sender_buffers() {
    let sender_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender socket");
    let receiver_socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind receiver socket");
    let destination = receiver_socket.local_addr().expect("receiver local addr");

    let tx = Sender::new();
    let mut rx = Receiver::new();
    let mut scratch = SendScratch::new();

    let key1 = tx
        .send_with_tokio_socket_with_scratch(
            &sender_socket,
            SendRequest::new(destination, b"first").with_options(SendOptions::default()),
            &mut scratch,
        )
        .await
        .expect("first async send with scratch should succeed");
    let key2 = tx
        .send_with_tokio_socket_with_scratch(
            &sender_socket,
            SendRequest::new(destination, b"second").with_options(SendOptions::default()),
            &mut scratch,
        )
        .await
        .expect("second async send with scratch should succeed");

    let report1 = rx
        .receive_message_async(
            &receiver_socket,
            ReceiveOptions::new()
                .with_key(key1)
                .with_inactivity_timeout(Duration::from_millis(200))
                .with_overall_timeout(Duration::from_secs(2)),
        )
        .await
        .expect("first async receive should succeed");
    let report2 = rx
        .receive_message_async(
            &receiver_socket,
            ReceiveOptions::new()
                .with_key(key2)
                .with_inactivity_timeout(Duration::from_millis(200))
                .with_overall_timeout(Duration::from_secs(2)),
        )
        .await
        .expect("second async receive should succeed");

    assert_eq!(report1.materialize_payload_lossy(), b"first");
    assert_eq!(report2.materialize_payload_lossy(), b"second");
}
