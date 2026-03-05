use super::common::*;

#[test]
fn pending_eviction_drops_oldest_partial_message() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xD1);
    let first_id = 70_000_u64;
    let last_id = first_id + (MAX_PENDING_MESSAGES as u64);

    for i in 0..=MAX_PENDING_MESSAGES {
        let message_id = first_id + (i as u64);
        let packet = encode_packet(
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
            &[0xCC],
        )
        .unwrap();
        sender.send_to(&packet, destination).unwrap();
    }

    let mut receiver = Receiver::new();
    let prime = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, 999_999_999)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(300),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        prime,
        Err(UniUdpError::TimeoutBeforeMatchingMessage { .. })
    ));

    let oldest = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, first_id)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(150),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        oldest,
        Err(UniUdpError::TimeoutBeforeFirstPacket { .. })
    ));

    let newest = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, last_id)),
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(150),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(newest.key, key(sender_id, last_id));
    assert_eq!(newest.lost_chunks, vec![1]);
}

#[test]
fn pending_byte_budget_evicts_oldest_partial_message() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xD2);
    let first_id = 71_000_u64;
    let middle_id = first_id + 1;
    let last_id = first_id + 2;

    let first_chunk = vec![0xDD; 1024];
    for message_id in [first_id, middle_id, last_id] {
        let packet = encode_packet(
            packet_header(
                sender_id,
                message_id,
                0,
                0,
                2,
                2048,
                1024,
                0,
                1,
                1,
                pack_fec_field(1, false).unwrap(),
            ),
            &first_chunk,
        )
        .unwrap();
        sender.send_to(&packet, destination).unwrap();
    }

    let mut receiver = Receiver::try_with_config(receiver_config! {
        max_pending_bytes: 9000,
        ..ReceiverConfig::default()
    })
    .unwrap();
    let prime = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, 999_999_998)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(300),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        prime,
        Err(UniUdpError::TimeoutBeforeMatchingMessage { .. })
    ));

    let oldest = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, first_id)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(150),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        oldest,
        Err(UniUdpError::TimeoutBeforeFirstPacket { .. })
    ));

    let middle = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, middle_id)),
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(150),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(middle.key, key(sender_id, middle_id));
    assert_eq!(middle.lost_chunks, vec![1]);

    let newest = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, last_id)),
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(150),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(newest.key, key(sender_id, last_id));
    assert_eq!(newest.lost_chunks, vec![1]);
}

#[test]
fn oversized_pending_message_is_dropped_without_evicting_fit_message() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xD3);
    let fit_id = 72_000_u64;
    let oversized_id = fit_id + 1;
    let fit_chunk = vec![0xA1; 1024];
    let oversized_chunk = vec![0xB2; 1024];

    let fit_packet = encode_packet(
        packet_header(
            sender_id,
            fit_id,
            0,
            0,
            2,
            2048,
            1024,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &fit_chunk,
    )
    .unwrap();
    sender.send_to(&fit_packet, destination).unwrap();

    let oversized_packet = encode_packet(
        packet_header(
            sender_id,
            oversized_id,
            0,
            0,
            3,
            3072,
            1024,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &oversized_chunk,
    )
    .unwrap();
    sender.send_to(&oversized_packet, destination).unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        max_pending_bytes: 4500,
        ..ReceiverConfig::default()
    })
    .unwrap();
    let prime = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, 999_999_997)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(300),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        prime,
        Err(UniUdpError::TimeoutBeforeMatchingMessage { .. })
    ));

    let fit = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, fit_id)),
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(150),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(fit.key, key(sender_id, fit_id));
    assert_eq!(fit.lost_chunks, vec![1]);

    let oversized = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, oversized_id)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(150),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        oversized,
        Err(UniUdpError::TimeoutBeforeFirstPacket { .. })
    ));
}

#[test]
fn metadata_heavy_message_is_rejected_by_pending_byte_budget() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xD4);
    let message_id = 73_000_u64;
    let packet = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            4096,
            4096,
            1,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &[0xEF],
    )
    .unwrap();
    sender.send_to(&packet, destination).unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        max_pending_bytes: 10_000,
        ..ReceiverConfig::default()
    })
    .unwrap();
    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, message_id)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );

    let diagnostics = rejected_timeout_diagnostics(err.unwrap_err());
    assert_eq!(diagnostics.packets_accepted, 0);
    assert!(diagnostics.pending_budget_rejections > 0);
}

#[test]
fn malformed_packets_do_not_crash_or_complete_false_message() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let malformed = vec![
        vec![0xAA; 5],
        vec![0xBB; 12],
        {
            let mut pkt = vec![0_u8; HEADER_LENGTH + 2];
            pkt[0..16].copy_from_slice(&SenderId(0x1234).0.to_be_bytes());
            pkt[16..24].copy_from_slice(&0x1234_u64.to_be_bytes());
            pkt[24..28].copy_from_slice(&0_u32.to_be_bytes());
            pkt[28..32].copy_from_slice(&1_u32.to_be_bytes());
            pkt[32..36].copy_from_slice(&2_u32.to_be_bytes());
            pkt[36..38].copy_from_slice(&2_u16.to_be_bytes());
            pkt[38..40].copy_from_slice(&20_u16.to_be_bytes());
            pkt[40..42].copy_from_slice(&1_u16.to_be_bytes());
            pkt[42..44].copy_from_slice(&1_u16.to_be_bytes());
            pkt[44..46].copy_from_slice(&pack_fec_field(1, false).unwrap().to_be_bytes());
            pkt
        },
        {
            let mut packet = encode_packet(
                packet_header(
                    SenderId(0x9999),
                    0x9999,
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
                &[0x11],
            )
            .unwrap();
            packet[TEST_ATTEMPT_OFFSET..TEST_ATTEMPT_OFFSET + 2]
                .copy_from_slice(&0_u16.to_be_bytes());
            rewrite_packet_checksum(&mut packet);
            packet
        },
    ];

    for pkt in malformed {
        sender.send_to(&pkt, destination).unwrap();
    }

    let mut receiver = Receiver::new();
    let no_false_complete = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(SenderId(0xFFFF), 0xFFFF_FFFF_FFFF_FFFF)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );
    let diagnostics = rejected_timeout_diagnostics(no_false_complete.unwrap_err());
    assert!(diagnostics.decode_errors > 0);

    let valid_key = send_message_with_socket(
        &sender,
        destination,
        &[0x10, 0x20, 0x30],
        send_options! {
            sender_id: Some(SenderId(0xABCD)),
            message_id: Some(0xABCD),
            chunk_size: 16,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(valid_key),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(600),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(report.materialize_payload_lossy(), vec![0x10, 0x20, 0x30]);
    assert_eq!(report.completion_reason, CompletionReason::Completed);
}

#[test]
fn malformed_first_packet_does_not_create_pending_state() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xDD11);
    let message_id = 0xAA11_u64;
    let mut malformed_first = encode_packet(
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
    malformed_first[TEST_ATTEMPT_OFFSET..TEST_ATTEMPT_OFFSET + 2]
        .copy_from_slice(&0_u16.to_be_bytes());
    rewrite_packet_checksum(&mut malformed_first);
    sender.send_to(&malformed_first, destination).unwrap();

    let mut receiver = Receiver::new();
    let result = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, message_id)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );

    let diagnostics = rejected_timeout_diagnostics(result.unwrap_err());
    assert!(diagnostics.metadata_rejections > 0);
}

#[test]
fn inconsistent_chunk_geometry_first_packet_does_not_create_pending_state() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xE1E1);
    let message_id = 0xB1B1_u64;
    let mut malformed_first = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            1,
            1,
            1,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &[0xAB],
    )
    .unwrap();
    malformed_first[TEST_TOTAL_CHUNKS_OFFSET..TEST_TOTAL_CHUNKS_OFFSET + 4]
        .copy_from_slice(&64_u32.to_be_bytes());
    rewrite_packet_checksum(&mut malformed_first);
    sender.send_to(&malformed_first, destination).unwrap();

    let mut receiver = Receiver::new();
    let ignored = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, message_id)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );
    let diagnostics = rejected_timeout_diagnostics(ignored.unwrap_err());
    assert!(diagnostics.metadata_rejections > 0);

    let valid_key = send_message_with_socket(
        &sender,
        destination,
        &[0x7E],
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(message_id),
            chunk_size: 1,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(valid_key),
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(300),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(report.materialize_payload_lossy(), vec![0x7E]);
    assert_eq!(report.completion_reason, CompletionReason::Completed);
}

#[test]
fn oversized_message_len_first_packet_does_not_create_pending_state() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xE2E2);
    let message_id = 0xB2B2_u64;
    let chunk_size = 8_192_u16;
    let message_length = (MAX_RECEIVE_MESSAGE_LEN as u32) + 1;
    let total_chunks = usize::try_from(message_length)
        .unwrap()
        .div_ceil(usize::from(chunk_size));
    assert!(total_chunks <= MAX_RECEIVE_CHUNKS);

    let oversized_first = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            total_chunks as u32,
            message_length,
            chunk_size,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &vec![0x11; usize::from(chunk_size)],
    )
    .unwrap();
    sender.send_to(&oversized_first, destination).unwrap();

    let mut receiver = Receiver::new();
    let ignored = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, message_id)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );
    let diagnostics = rejected_timeout_diagnostics(ignored.unwrap_err());
    assert!(diagnostics.metadata_rejections > 0);
}

#[test]
fn max_message_len_first_packet_is_accepted() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xE2E3);
    let message_id = 0xB2B3_u64;
    let message_length = MAX_RECEIVE_MESSAGE_LEN;
    let chunk_size = u16::try_from(MAX_RECEIVE_MESSAGE_LEN / MAX_RECEIVE_CHUNKS).unwrap();
    let total_chunks = message_length.div_ceil(usize::from(chunk_size));
    assert!(total_chunks <= MAX_RECEIVE_CHUNKS);
    let message_length_u32 = u32::try_from(message_length).unwrap();

    let first = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            u32::try_from(total_chunks).unwrap(),
            message_length_u32,
            chunk_size,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &vec![0x21; usize::from(chunk_size)],
    )
    .unwrap();
    sender.send_to(&first, destination).unwrap();

    let mut receiver = Receiver::new();
    let partial = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, message_id)),
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(250),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(partial.key, key(sender_id, message_id));
    assert_eq!(partial.message_length, message_length);
    assert_eq!(partial.chunks_expected, total_chunks);
    assert_eq!(partial.chunks_received, 1);
    assert_eq!(
        partial.completion_reason,
        CompletionReason::InactivityTimeout
    );
}

#[test]
fn max_receive_chunks_first_packet_is_accepted() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xE2E4);
    let message_id = 0xB2B4_u64;
    let total_chunks = MAX_RECEIVE_CHUNKS;
    let message_length = total_chunks;

    let first = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            u32::try_from(total_chunks).unwrap(),
            u32::try_from(message_length).unwrap(),
            1,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &[0x22],
    )
    .unwrap();
    sender.send_to(&first, destination).unwrap();

    let mut receiver = Receiver::new();
    let partial = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, message_id)),
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(250),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(partial.key, key(sender_id, message_id));
    assert_eq!(partial.message_length, message_length);
    assert_eq!(partial.chunks_expected, total_chunks);
    assert_eq!(partial.chunks_received, 1);
    assert_eq!(
        partial.completion_reason,
        CompletionReason::InactivityTimeout
    );
}

#[test]
fn rejected_first_packet_does_not_evict_existing_pending_message() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xE3E3);
    let first_id = 91_000_u64;

    for i in 0..MAX_PENDING_MESSAGES {
        let message_id = first_id + (i as u64);
        let packet = encode_packet(
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
            &[0xA0],
        )
        .unwrap();
        sender.send_to(&packet, destination).unwrap();
    }

    let mut receiver = Receiver::new();
    let prime = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, 9_999_999)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(300),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        prime,
        Err(UniUdpError::TimeoutBeforeMatchingMessage { .. })
    ));

    let rejected_packet = encode_packet(
        packet_header(
            sender_id,
            first_id + (MAX_PENDING_MESSAGES as u64) + 5,
            0,
            0,
            (MAX_RECEIVE_CHUNKS as u32) + 1,
            (MAX_RECEIVE_CHUNKS as u32) + 1,
            1,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &[0xCC],
    )
    .unwrap();
    sender.send_to(&rejected_packet, destination).unwrap();

    let prime_rejected = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, 9_999_998)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(300),
            ..ReceiveOptions::default()
        },
    );
    let diagnostics = rejected_timeout_diagnostics(prime_rejected.unwrap_err());
    assert!(diagnostics.metadata_rejections > 0);

    let completion = encode_packet(
        packet_header(
            sender_id,
            first_id,
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
        &[0xB0],
    )
    .unwrap();
    sender.send_to(&completion, destination).unwrap();

    let completed = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, first_id)),
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(300),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(completed.completion_reason, CompletionReason::Completed);
    assert_eq!(completed.materialize_payload_lossy(), vec![0xA0, 0xB0]);
}

#[test]
fn filtered_receive_ignores_unrelated_pending_budget_pressure() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xE4E4);
    let target_id = 92_000_u64;
    let unrelated_start = 120_000_u64;

    let target_first = encode_packet(
        packet_header(
            sender_id,
            target_id,
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
        &[0xA1],
    )
    .unwrap();
    sender.send_to(&target_first, destination).unwrap();

    for i in 0..MAX_PENDING_MESSAGES {
        let message_id = unrelated_start + (i as u64);
        let unrelated = encode_packet(
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
            &[0xCC],
        )
        .unwrap();
        sender.send_to(&unrelated, destination).unwrap();
    }

    let target_second = encode_packet(
        packet_header(
            sender_id,
            target_id,
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
        &[0xB2],
    )
    .unwrap();
    sender.send_to(&target_second, destination).unwrap();

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, target_id)),
                inactivity_timeout: Duration::from_millis(80),
                overall_timeout: Duration::from_millis(700),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(report.key, key(sender_id, target_id));
    assert_eq!(report.completion_reason, CompletionReason::Completed);
    assert_eq!(report.materialize_payload_lossy(), vec![0xA1, 0xB2]);
}
