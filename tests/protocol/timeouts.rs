use super::common::*;

#[test]
fn timeout_before_first_packet_errors() {
    let mut receiver_socket = bind_local();
    let mut receiver = Receiver::new();

    let err = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(100),
                ..ReceiveOptions::default()
            },
        )
        .unwrap_err();

    match err {
        UniUdpError::TimeoutBeforeFirstPacket { .. } => {}
        other => panic!("expected timeout-before-first-packet, got {other:?}"),
    }
}

#[test]
fn nonblocking_socket_is_treated_as_timeout_when_idle() {
    let mut receiver_socket = bind_local();
    receiver_socket.set_nonblocking(true).unwrap();
    let mut receiver = Receiver::new();

    let err = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(100),
                ..ReceiveOptions::default()
            },
        )
        .unwrap_err();

    assert!(matches!(err, UniUdpError::TimeoutBeforeFirstPacket { .. }));
    receiver_socket.set_nonblocking(false).unwrap();
}

#[test]
fn receive_message_restores_socket_read_timeout_after_timeout() {
    let mut receiver_socket = bind_local();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(650)))
        .unwrap();
    let original_timeout = receiver_socket.read_timeout().unwrap();

    let mut receiver = Receiver::new();
    let err = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(100),
                ..ReceiveOptions::default()
            },
        )
        .unwrap_err();

    assert!(matches!(err, UniUdpError::TimeoutBeforeFirstPacket { .. }));
    assert_eq!(receiver_socket.read_timeout().unwrap(), original_timeout);
}

#[test]
fn unfiltered_timeout_after_traffic_when_no_message_completes() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination: SocketAddr = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0x3456);
    let message_id = 0x4567_u64;

    let first_chunk_only = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            2,
            8,
            4,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &[0xAA, 0xBB, 0xCC, 0xDD],
    )
    .unwrap();
    sender.send_to(&first_chunk_only, destination).unwrap();

    let mut receiver = Receiver::new();
    let err = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: None,
                inactivity_timeout: Duration::from_millis(80),
                overall_timeout: Duration::from_millis(300),
                ..ReceiveOptions::default()
            },
        )
        .unwrap_err();

    match err {
        UniUdpError::TimeoutAfterTraffic { .. } => {}
        other => panic!("expected timeout-after-traffic, got {other:?}"),
    }
}

#[test]
fn filtered_timeout_before_matching_message_includes_diagnostics() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination: SocketAddr = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0x4567);
    let message_id = 0x5678_u64;

    let first_chunk_only = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            2,
            8,
            4,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &[0x10, 0x20, 0x30, 0x40],
    )
    .unwrap();
    sender.send_to(&first_chunk_only, destination).unwrap();

    let mut receiver = Receiver::new();
    let err = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, message_id + 1)),
                inactivity_timeout: Duration::from_millis(80),
                overall_timeout: Duration::from_millis(300),
                ..ReceiveOptions::default()
            },
        )
        .unwrap_err();

    match err {
        UniUdpError::TimeoutBeforeMatchingMessage { diagnostics } => {
            assert!(diagnostics.packets_received > 0);
            assert!(diagnostics.packets_accepted > 0);
        }
        other => panic!("expected timeout-before-matching-message, got {other:?}"),
    }
}

#[test]
fn partial_message_report_on_filtered_inactivity() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination: SocketAddr = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0x3333);
    let message_id = 0x1234_u64;
    let fec_field = pack_fec_field(1, false).unwrap();

    let first_chunk = encode_packet(
        packet_header(sender_id, message_id, 0, 0, 2, 8, 4, 0, 1, 1, fec_field),
        &[0xAA, 0xBB, 0xCC, 0xDD],
    )
    .unwrap();
    sender.send_to(&first_chunk, destination).unwrap();

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, message_id)),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(report.key, key(sender_id, message_id));
    assert_eq!(report.received_chunks.len(), 1);
    assert_eq!(report.received_chunks[0].index, 0);
    assert_eq!(
        report.received_chunks[0].payload,
        vec![0xAA, 0xBB, 0xCC, 0xDD]
    );
    assert_eq!(report.lost_chunks, vec![1]);
    assert_eq!(
        report.completion_reason,
        CompletionReason::InactivityTimeout
    );
}

#[test]
fn partial_payload_preserves_offsets_when_middle_chunk_missing() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination: SocketAddr = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0x4444);
    let message_id = 0x2233_u64;
    let fec_field = pack_fec_field(1, false).unwrap();

    let chunk0 = encode_packet(
        packet_header(sender_id, message_id, 0, 0, 3, 12, 4, 0, 1, 1, fec_field),
        &[0x01, 0x02, 0x03, 0x04],
    )
    .unwrap();
    let chunk2 = encode_packet(
        packet_header(sender_id, message_id, 0, 2, 3, 12, 4, 0, 1, 1, fec_field),
        &[0xA1, 0xA2, 0xA3, 0xA4],
    )
    .unwrap();

    sender.send_to(&chunk0, destination).unwrap();
    sender.send_to(&chunk2, destination).unwrap();

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, message_id)),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(report.key, key(sender_id, message_id));
    assert_eq!(report.materialize_payload_lossy().len(), 12);
    assert_eq!(
        report.materialize_payload_lossy(),
        vec![0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0xA1, 0xA2, 0xA3, 0xA4]
    );
    assert_eq!(report.received_chunks.len(), 2);
    assert_eq!(report.received_chunks[0].index, 0);
    assert_eq!(
        report.received_chunks[0].payload,
        vec![0x01, 0x02, 0x03, 0x04]
    );
    assert_eq!(report.received_chunks[1].index, 2);
    assert_eq!(
        report.received_chunks[1].payload,
        vec![0xA1, 0xA2, 0xA3, 0xA4]
    );
    assert_eq!(report.lost_chunks, vec![1]);
    assert_eq!(
        report.completion_reason,
        CompletionReason::InactivityTimeout
    );
}

#[test]
fn unfiltered_receive_returns_messages_one_by_one() {
    let sender1 = bind_local();
    let sender2 = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    thread::spawn(move || {
        send_message_with_socket(
            &sender1,
            destination,
            &[0x01, 0x02, 0x03],
            send_options! {
                sender_id: Some(SenderId(0xA01)),
                message_id: Some(0x101),
                redundancy: 2,
                chunk_size: 64,
                ..SendOptions::default()
            },
        )
        .unwrap();
    });
    thread::spawn(move || {
        send_message_with_socket(
            &sender2,
            destination,
            &[0xAA, 0xBB, 0xCC, 0xDD],
            send_options! {
                sender_id: Some(SenderId(0xA02)),
                message_id: Some(0x102),
                redundancy: 2,
                chunk_size: 64,
                ..SendOptions::default()
            },
        )
        .unwrap();
    });

    let mut receiver = Receiver::new();
    let r1 = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: None,
                inactivity_timeout: Duration::from_millis(300),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    let r2 = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: None,
                inactivity_timeout: Duration::from_millis(300),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    let got: BTreeSet<Vec<u8>> = [
        r1.materialize_payload_lossy(),
        r2.materialize_payload_lossy(),
    ]
    .into_iter()
    .collect();
    let expected: BTreeSet<Vec<u8>> = [vec![0x01, 0x02, 0x03], vec![0xAA, 0xBB, 0xCC, 0xDD]]
        .into_iter()
        .collect();
    assert_eq!(got, expected);
}

#[test]
fn receive_loop_streams_messages_until_callback_stops() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_thread = thread::spawn(move || {
        send_message_with_socket(
            &sender,
            destination,
            &[0x11, 0x22, 0x33],
            send_options! {
                sender_id: Some(SenderId(0xB01)),
                message_id: Some(0x201),
                redundancy: 1,
                chunk_size: 64,
                ..SendOptions::default()
            },
        )
        .unwrap();
        send_message_with_socket(
            &sender,
            destination,
            &[0xAA, 0xBB],
            send_options! {
                sender_id: Some(SenderId(0xB01)),
                message_id: Some(0x202),
                redundancy: 1,
                chunk_size: 64,
                ..SendOptions::default()
            },
        )
        .unwrap();
    });

    let mut receiver = Receiver::new();
    let mut payloads = Vec::new();
    let delivered = receiver
        .receive_loop(
            &mut receiver_socket,
            receive_options! {
                key: None,
                inactivity_timeout: Duration::from_millis(300),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
            |report| {
                payloads.push(report.materialize_payload_lossy());
                if payloads.len() >= 2 {
                    ReceiveLoopControl::Stop
                } else {
                    ReceiveLoopControl::Continue
                }
            },
        )
        .unwrap();

    sender_thread.join().unwrap();

    assert_eq!(delivered, 2);
    let got: BTreeSet<Vec<u8>> = payloads.into_iter().collect();
    let expected: BTreeSet<Vec<u8>> = [vec![0x11, 0x22, 0x33], vec![0xAA, 0xBB]]
        .into_iter()
        .collect();
    assert_eq!(got, expected);
}

#[test]
fn receive_loop_rejects_keyed_receive_options() {
    let mut receiver_socket = bind_local();
    let mut receiver = Receiver::new();

    let err = receiver
        .receive_loop(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(SenderId(0xB01), 0x201)),
                inactivity_timeout: Duration::from_millis(300),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
            |_| ReceiveLoopControl::Stop,
        )
        .unwrap_err();

    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiveOptions,
            message: "receive_loop does not support keyed ReceiveOptions; use receive_message for keyed receive",
            ..
        }
    ));
}

#[test]
fn unfiltered_buffered_completion_order_is_deterministic() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination: SocketAddr = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xA55A);
    let message_a = 0x991_u64;
    let message_b = 0x992_u64;
    let fec_field = pack_fec_field(1, false).unwrap();

    let a_chunk_0 = encode_packet(
        packet_header(sender_id, message_a, 0, 0, 2, 2, 1, 0, 1, 1, fec_field),
        &[0xA0],
    )
    .unwrap();
    let b_single = encode_packet(
        packet_header(sender_id, message_b, 0, 0, 1, 1, 1, 0, 1, 1, fec_field),
        &[0xB0],
    )
    .unwrap();
    let a_chunk_1 = encode_packet(
        packet_header(sender_id, message_a, 0, 1, 2, 2, 1, 0, 1, 1, fec_field),
        &[0xA1],
    )
    .unwrap();

    sender.send_to(&a_chunk_0, destination).unwrap();
    sender.send_to(&b_single, destination).unwrap();
    sender.send_to(&a_chunk_1, destination).unwrap();

    let mut receiver = Receiver::new();
    let priming = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, 0xFFFF_FFFF)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(250),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        priming,
        Err(UniUdpError::TimeoutBeforeMatchingMessage { .. })
    ));

    let first = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: None,
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(250),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    let second = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: None,
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(250),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(first.key, key(sender_id, message_b));
    assert_eq!(first.materialize_payload_lossy(), vec![0xB0]);
    assert_eq!(second.key, key(sender_id, message_a));
    assert_eq!(second.materialize_payload_lossy(), vec![0xA0, 0xA1]);
}
