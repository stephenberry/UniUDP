use super::common::*;

#[test]
fn source_policy_any_first_source_pins_first_source() {
    let sender1 = bind_local();
    let sender2 = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0x111);
    let message_id = 0xA1;
    let common = packet_header(
        sender_id,
        message_id,
        0,
        0,
        2,
        2,
        1,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );

    let first = encode_packet(common, &[0xAA]).unwrap();
    let second = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            1,
            2,
            2,
            1,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &[0xBB],
    )
    .unwrap();

    sender1.send_to(&first, destination).unwrap();
    sender2.send_to(&second, destination).unwrap();

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, message_id)),
                source_policy: SourcePolicy::AnyFirstSource,
                strict_rejections: false,
                inactivity_timeout: Duration::from_millis(80),
                overall_timeout: Duration::from_millis(300),
            },
        )
        .unwrap();

    assert_eq!(
        report.completion_reason,
        CompletionReason::InactivityTimeout
    );
    assert_eq!(report.lost_chunks, vec![1]);
}

#[test]
fn source_policy_exact_requires_configured_source() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let key = send_message_with_socket(
        &sender,
        destination,
        b"exact",
        send_options! {
            sender_id: Some(SenderId(0x333)),
            message_id: Some(0x44),
            chunk_size: 16,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let wrong_source = SocketAddr::from(([127, 0, 0, 1], 65_000));

    let mut receiver = Receiver::new();
    let err = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key),
                source_policy: SourcePolicy::Exact(wrong_source),
                strict_rejections: false,
                inactivity_timeout: Duration::from_millis(60),
                overall_timeout: Duration::from_millis(200),
            },
        )
        .unwrap_err();

    let diagnostics = rejected_timeout_diagnostics(err);
    assert!(diagnostics.source_rejections > 0);
}

#[test]
fn strict_rejections_returns_rejected_packet_on_source_mismatch() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let key = send_message_with_socket(
        &sender,
        destination,
        b"strict-source",
        send_options! {
            sender_id: Some(SenderId(0x334)),
            message_id: Some(0x45),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let wrong_source = SocketAddr::from(([127, 0, 0, 1], 65_001));

    let mut receiver = Receiver::new();
    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key),
            source_policy: SourcePolicy::Exact(wrong_source),
            strict_rejections: true,
            inactivity_timeout: Duration::from_millis(60),
            overall_timeout: Duration::from_millis(200),
        },
    );
    assert!(matches!(
        err,
        Err(UniUdpError::RejectedPacket {
            reason: ReceiveRejectReason::SourcePolicy
        })
    ));

    let diagnostics = receiver.last_receive_diagnostics();
    assert_eq!(diagnostics.packets_received, 1);
    assert_eq!(diagnostics.source_rejections, 1);
}

#[test]
fn source_policy_same_ip_allows_port_change() {
    let sender1 = bind_local();
    let sender2 = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0x9191);
    let message_id = 0x77;
    let header0 = packet_header(
        sender_id,
        message_id,
        0,
        0,
        2,
        2,
        1,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );
    let header1 = packet_header(
        sender_id,
        message_id,
        0,
        1,
        2,
        2,
        1,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );

    sender1
        .send_to(&encode_packet(header0, &[0x10]).unwrap(), destination)
        .unwrap();
    sender2
        .send_to(&encode_packet(header1, &[0x20]).unwrap(), destination)
        .unwrap();

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, message_id)),
                source_policy: SourcePolicy::SameIp,
                strict_rejections: false,
                inactivity_timeout: Duration::from_millis(80),
                overall_timeout: Duration::from_millis(400),
            },
        )
        .unwrap();

    assert_eq!(report.materialize_payload_lossy(), vec![0x10, 0x20]);
    assert_eq!(report.completion_reason, CompletionReason::Completed);
}

#[test]
fn source_policy_exact_does_not_consume_buffered_complete_from_other_source() {
    let sender1 = bind_local();
    let sender2 = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let target_key = send_message_with_socket(
        &sender1,
        destination,
        b"buffered-complete",
        send_options! {
            sender_id: Some(SenderId(0xE001)),
            message_id: Some(0x2001),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let unrelated_key = key(SenderId(0xFF00), 0xFF00);
    let mut receiver = Receiver::new();
    let priming = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(unrelated_key),
            source_policy: SourcePolicy::AnyFirstSource,
            strict_rejections: false,
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
        },
    );
    assert!(matches!(
        priming,
        Err(UniUdpError::TimeoutBeforeMatchingMessage { .. })
    ));

    let strict_wrong = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(target_key),
            source_policy: SourcePolicy::Exact(sender2.local_addr().unwrap()),
            strict_rejections: false,
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
        },
    );
    assert!(matches!(
        strict_wrong,
        Err(UniUdpError::TimeoutBeforeFirstPacket { .. })
    ));

    let strict_right = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(target_key),
                source_policy: SourcePolicy::Exact(sender1.local_addr().unwrap()),
                strict_rejections: false,
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(200),
            },
        )
        .unwrap();
    assert_eq!(
        strict_right.materialize_payload_lossy(),
        b"buffered-complete"
    );
    assert_eq!(strict_right.completion_reason, CompletionReason::Completed);
}

#[test]
fn source_policy_exact_does_not_consume_buffered_partial_from_other_source() {
    let sender1 = bind_local();
    let sender2 = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xE101);
    let message_id = 0x2101_u64;
    let target_key = key(sender_id, message_id);

    let first_chunk = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            2,
            2,
            1,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &[0xAB],
    )
    .unwrap();
    sender1.send_to(&first_chunk, destination).unwrap();

    let unrelated_key = key(SenderId(0xFE00), 0xFE00);
    let mut receiver = Receiver::new();
    let priming = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(unrelated_key),
            source_policy: SourcePolicy::AnyFirstSource,
            strict_rejections: false,
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
        },
    );
    assert!(matches!(
        priming,
        Err(UniUdpError::TimeoutBeforeMatchingMessage { .. })
    ));

    let strict_wrong = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(target_key),
            source_policy: SourcePolicy::Exact(sender2.local_addr().unwrap()),
            strict_rejections: false,
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
        },
    );
    assert!(matches!(
        strict_wrong,
        Err(UniUdpError::TimeoutBeforeFirstPacket { .. })
    ));

    let strict_right = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(target_key),
                source_policy: SourcePolicy::Exact(sender1.local_addr().unwrap()),
                strict_rejections: false,
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(200),
            },
        )
        .unwrap();
    assert_eq!(strict_right.lost_chunks, vec![1]);
    assert_eq!(
        strict_right.completion_reason,
        CompletionReason::InactivityTimeout
    );
}
