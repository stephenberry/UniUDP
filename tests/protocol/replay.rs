use super::common::*;

#[test]
fn strict_rejections_returns_rejected_packet_on_replayed_chunk_attempt() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0x9012);
    let message_id = 0x7777_u64;

    let repeated = encode_packet(
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
    sender.send_to(&repeated, destination).unwrap();
    sender.send_to(&repeated, destination).unwrap();

    let mut receiver = Receiver::new();
    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(sender_id, message_id)),
            strict_rejections: true,
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        err,
        Err(UniUdpError::RejectedPacket {
            reason: ReceiveRejectReason::Replay
        })
    ));
    assert_eq!(receiver.last_receive_diagnostics().replay_rejections, 1);
}

#[test]
fn strict_rejections_returns_rejected_packet_on_duplicate_completed_message() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0x9013);
    let message_id = 0x7778_u64;
    let session_nonce = 77_u64;

    let sent_key = send_message_with_socket(
        &sender,
        destination,
        b"dup-complete",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(message_id),
            session_nonce: Some(session_nonce),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::new();
    let first = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(sent_key),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(first.materialize_payload_lossy(), b"dup-complete");

    let duplicate_key = send_message_with_socket(
        &sender,
        destination,
        b"dup-complete",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(message_id),
            session_nonce: Some(session_nonce),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    assert_eq!(duplicate_key, sent_key);

    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(sent_key),
            strict_rejections: true,
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        err,
        Err(UniUdpError::RejectedPacket {
            reason: ReceiveRejectReason::Replay
        })
    ));
    let diagnostics = receiver.last_receive_diagnostics();
    assert_eq!(diagnostics.duplicate_packets, 1);
    assert_eq!(diagnostics.replay_rejections, 1);
}

#[test]
fn older_session_nonce_packet_is_accepted_as_distinct_session() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let auth = packet_auth(0xCAFE, 0x44);
    let sender_id = SenderId(0xCAFE);
    let newer_nonce = 50_u64;
    let older_nonce = 49_u64;

    let first_key = send_message_with_socket(
        &sender,
        destination,
        b"newer-session",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(700),
            session_nonce: Some(newer_nonce),
            packet_auth: Some(auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![auth.clone()],
        ..ReceiverConfig::default()
    })
    .unwrap();
    receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(first_key),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    let older_key = send_message_with_socket(
        &sender,
        destination,
        b"older-session",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(701),
            session_nonce: Some(older_nonce),
            packet_auth: Some(auth),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(older_key),
                strict_rejections: true,
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(200),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(report.key, older_key);
    assert_eq!(report.completion_reason, CompletionReason::Completed);
    assert_eq!(report.materialize_payload_lossy(), b"older-session");
    assert_eq!(receiver.last_receive_diagnostics().replay_rejections, 0);
}

#[test]
fn authenticated_new_session_rejected_when_global_session_budget_full() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let auth = packet_auth(0xCAE0, 0x45);

    let key_a = send_message_with_socket(
        &sender,
        destination,
        b"session-a",
        send_options! {
            sender_id: Some(SenderId(0xCAE1)),
            message_id: Some(800),
            session_nonce: Some(1),
            packet_auth: Some(auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let key_b = send_message_with_socket(
        &sender,
        destination,
        b"session-b",
        send_options! {
            sender_id: Some(SenderId(0xCAE2)),
            message_id: Some(801),
            session_nonce: Some(1),
            packet_auth: Some(auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![auth],
        max_tracked_sessions_total: 1,
        max_tracked_sessions_per_sender: 4,
        ..ReceiverConfig::default()
    })
    .unwrap();

    receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_a),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key_b),
            strict_rejections: true,
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        err,
        Err(UniUdpError::RejectedPacket {
            reason: ReceiveRejectReason::SessionBudget
        })
    ));
    assert_eq!(
        receiver
            .last_receive_diagnostics()
            .session_budget_rejections,
        1
    );
}

#[test]
fn authenticated_new_session_rejected_when_per_sender_session_budget_full() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let auth = packet_auth(0xCAE3, 0x46);
    let sender_id = SenderId(0xCAE4);

    let key_a = send_message_with_socket(
        &sender,
        destination,
        b"session-a",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(810),
            session_nonce: Some(1),
            packet_auth: Some(auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let key_b = send_message_with_socket(
        &sender,
        destination,
        b"session-b",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(811),
            session_nonce: Some(2),
            packet_auth: Some(auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![auth],
        max_tracked_sessions_total: 10,
        max_tracked_sessions_per_sender: 1,
        ..ReceiverConfig::default()
    })
    .unwrap();

    receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_a),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key_b),
            strict_rejections: true,
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        err,
        Err(UniUdpError::RejectedPacket {
            reason: ReceiveRejectReason::SessionBudget
        })
    ));
    assert_eq!(
        receiver
            .last_receive_diagnostics()
            .session_budget_rejections,
        1
    );
}

#[test]
fn higher_nonce_invalid_metadata_does_not_evict_existing_pending_message() {
    let sender = bind_local();
    let relay = bind_local();
    relay
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut receiver_socket = bind_local();
    let relay_destination = relay.local_addr().unwrap();
    let receiver_destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xEE11);
    let old_key = key_with_session(sender_id, 10, 10_000);

    send_message_with_socket(
        &sender,
        relay_destination,
        b"AB",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(old_key.message_id),
            session_nonce: Some(10),
            chunk_size: 1,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut buf = vec![0_u8; 1024];
    let mut old_chunk0 = None;
    let mut old_chunk1 = None;
    for _ in 0..8 {
        let (len, _) = relay.recv_from(&mut buf).unwrap();
        let packet = buf[..len].to_vec();
        let (header, _payload) = parse_packet(&packet).unwrap();
        if header.message_id() != old_key.message_id || fec_is_parity(header.fec_field()) {
            continue;
        }
        if header.chunk_index() == 0 {
            old_chunk0 = Some(packet);
        } else if header.chunk_index() == 1 {
            old_chunk1 = Some(packet);
        }
        if old_chunk0.is_some() && old_chunk1.is_some() {
            break;
        }
    }
    let old_chunk0 = old_chunk0.expect("missing data chunk 0");
    let old_chunk1 = old_chunk1.expect("missing data chunk 1");
    relay.send_to(&old_chunk0, receiver_destination).unwrap();

    send_message_with_socket(
        &sender,
        relay_destination,
        b"Z",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(10_001),
            session_nonce: Some(11),
            chunk_size: 1,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let (higher_len, _) = relay.recv_from(&mut buf).unwrap();
    let mut higher_nonce_invalid = buf[..higher_len].to_vec();
    higher_nonce_invalid[TEST_ATTEMPT_OFFSET..TEST_ATTEMPT_OFFSET + 2]
        .copy_from_slice(&0_u16.to_be_bytes());
    rewrite_packet_checksum(&mut higher_nonce_invalid);
    relay
        .send_to(&higher_nonce_invalid, receiver_destination)
        .unwrap();

    relay.send_to(&old_chunk1, receiver_destination).unwrap();

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(old_key),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(600),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(report.materialize_payload_lossy(), b"AB");
    let diagnostics = receiver.last_receive_diagnostics();
    assert!(diagnostics.metadata_rejections > 0);
    assert_eq!(diagnostics.replay_rejections, 0);
}

#[test]
fn unauthenticated_higher_nonce_does_not_reset_existing_pending_message() {
    let sender = bind_local();
    let relay = bind_local();
    relay
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut receiver_socket = bind_local();
    let relay_destination = relay.local_addr().unwrap();
    let receiver_destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xEE12);
    let old_key = key_with_session(sender_id, 10, 20_000);

    send_message_with_socket(
        &sender,
        relay_destination,
        b"AB",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(old_key.message_id),
            session_nonce: Some(10),
            chunk_size: 1,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut buf = vec![0_u8; 1024];
    let mut old_chunk0 = None;
    let mut old_chunk1 = None;
    for _ in 0..8 {
        let (len, _) = relay.recv_from(&mut buf).unwrap();
        let packet = buf[..len].to_vec();
        let (header, _payload) = parse_packet(&packet).unwrap();
        if header.message_id() != old_key.message_id || fec_is_parity(header.fec_field()) {
            continue;
        }
        if header.chunk_index() == 0 {
            old_chunk0 = Some(packet);
        } else if header.chunk_index() == 1 {
            old_chunk1 = Some(packet);
        }
        if old_chunk0.is_some() && old_chunk1.is_some() {
            break;
        }
    }
    let old_chunk0 = old_chunk0.expect("missing data chunk 0");
    let old_chunk1 = old_chunk1.expect("missing data chunk 1");
    relay.send_to(&old_chunk0, receiver_destination).unwrap();

    send_message_with_socket(
        &sender,
        relay_destination,
        b"Z",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(20_001),
            session_nonce: Some(11),
            chunk_size: 1,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let mut higher_nonce_valid = None;
    for _ in 0..6 {
        let (len, _) = relay.recv_from(&mut buf).unwrap();
        let packet = buf[..len].to_vec();
        let (header, _payload) = parse_packet(&packet).unwrap();
        if header.message_id() == 20_001 && !fec_is_parity(header.fec_field()) {
            higher_nonce_valid = Some(packet);
            break;
        }
    }
    let higher_nonce_valid = higher_nonce_valid.expect("missing higher-nonce data packet");
    relay
        .send_to(&higher_nonce_valid, receiver_destination)
        .unwrap();

    relay.send_to(&old_chunk1, receiver_destination).unwrap();

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(old_key),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(600),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(report.materialize_payload_lossy(), b"AB");
}

#[test]
fn authenticated_higher_nonce_does_not_purge_existing_pending_message() {
    let sender = bind_local();
    let relay = bind_local();
    relay
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut receiver_socket = bind_local();
    let relay_destination = relay.local_addr().unwrap();
    let receiver_destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xEE13);
    let auth = packet_auth(0xAA13, 0x5A);
    let old_session_nonce = 10_u64;
    let new_session_nonce = 11_u64;
    let old_key = key_with_session(sender_id, old_session_nonce, 30_000);

    send_message_with_socket(
        &sender,
        relay_destination,
        b"AB",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(old_key.message_id),
            session_nonce: Some(old_session_nonce),
            packet_auth: Some(auth.clone()),
            chunk_size: 1,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut buf = vec![0_u8; 1024];
    let mut old_chunk0 = None;
    let mut old_chunk1 = None;
    for _ in 0..8 {
        let (len, _) = relay.recv_from(&mut buf).unwrap();
        let packet = buf[..len].to_vec();
        let (header, _payload) = parse_packet(&packet).unwrap();
        if header.message_id() != old_key.message_id || fec_is_parity(header.fec_field()) {
            continue;
        }
        if header.chunk_index() == 0 {
            old_chunk0 = Some(packet);
        } else if header.chunk_index() == 1 {
            old_chunk1 = Some(packet);
        }
        if old_chunk0.is_some() && old_chunk1.is_some() {
            break;
        }
    }
    let old_chunk0 = old_chunk0.expect("missing data chunk 0");
    let old_chunk1 = old_chunk1.expect("missing data chunk 1");
    relay.send_to(&old_chunk0, receiver_destination).unwrap();

    let new_key = send_message_with_socket(
        &sender,
        receiver_destination,
        b"N",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(30_001),
            session_nonce: Some(new_session_nonce),
            packet_auth: Some(auth.clone()),
            chunk_size: 1,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![auth],
        ..ReceiverConfig::default()
    })
    .unwrap();
    let new_report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(new_key),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(600),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(new_report.materialize_payload_lossy(), b"N");

    // Older-session packets remain valid and should complete the buffered
    // partial message for that session.
    relay.send_to(&old_chunk1, receiver_destination).unwrap();

    let old_report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(old_key),
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(200),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(old_report.key, old_key);
    assert_eq!(old_report.chunks_received, 2);
    assert!(old_report.lost_chunks.is_empty());
    assert_eq!(old_report.completion_reason, CompletionReason::Completed);
    assert_eq!(receiver.last_receive_diagnostics().replay_rejections, 0);
}

#[test]
fn stale_message_id_outside_freshness_window_is_rejected() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0xF00D);
    let session_nonce = 88_u64;

    let mut receiver = Receiver::try_with_config(receiver_config! {
        message_freshness_window: 2,
        ..ReceiverConfig::default()
    })
    .unwrap();

    let key_100 = send_message_with_socket(
        &sender,
        destination,
        b"m100",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(100),
            session_nonce: Some(session_nonce),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_100),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    let key_104 = send_message_with_socket(
        &sender,
        destination,
        b"m104",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(104),
            session_nonce: Some(session_nonce),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_104),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    let stale_key = send_message_with_socket(
        &sender,
        destination,
        b"m100-replay",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(100),
            session_nonce: Some(session_nonce),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(stale_key),
            strict_rejections: true,
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );

    assert!(matches!(
        err,
        Err(UniUdpError::RejectedPacket {
            reason: ReceiveRejectReason::Replay
        })
    ));
    assert_eq!(receiver.last_receive_diagnostics().replay_rejections, 1);
}

#[test]
fn authenticated_unbounded_freshness_accepts_older_message_ids() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0xF00F);
    let session_nonce = 90_u64;
    let auth = packet_auth(42, 0x42);

    let mut receiver = Receiver::try_with_config(receiver_config! {
        message_freshness_window: 0,
        unbounded_message_freshness: true,
        auth_keys: vec![auth.clone()],
        ..ReceiverConfig::default()
    })
    .unwrap();

    let key_100 = send_message_with_socket(
        &sender,
        destination,
        b"m100",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(100),
            session_nonce: Some(session_nonce),
            packet_auth: Some(auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_100),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    let key_104 = send_message_with_socket(
        &sender,
        destination,
        b"m104",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(104),
            session_nonce: Some(session_nonce),
            packet_auth: Some(auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_104),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    let key_101 = send_message_with_socket(
        &sender,
        destination,
        b"m101",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(101),
            session_nonce: Some(session_nonce),
            packet_auth: Some(auth),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_101),
                strict_rejections: true,
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(report.materialize_payload_lossy(), b"m101");
}

#[test]
fn unauthenticated_high_message_id_does_not_poison_freshness_window() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0xF00E);

    // Tight window to expose poisoning regressions quickly.
    let mut receiver = Receiver::try_with_config(receiver_config! {
        message_freshness_window: 2,
        ..ReceiverConfig::default()
    })
    .unwrap();

    let high_key = send_message_with_socket(
        &sender,
        destination,
        b"high",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(1_000_000),
            session_nonce: Some(1),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let high_report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(high_key),
                strict_rejections: true,
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(high_report.materialize_payload_lossy(), b"high");

    // Without the fix, this lower ID was rejected as stale replay after high ID
    // updated freshness state in unauthenticated mode.
    let low_key = send_message_with_socket(
        &sender,
        destination,
        b"low",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(10),
            session_nonce: Some(1),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let low_report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(low_key),
                strict_rejections: true,
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(low_report.materialize_payload_lossy(), b"low");
}

#[test]
fn dedup_is_scoped_to_full_message_key() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id_a = SenderId(0xCAFE);
    let sender_id_b = SenderId(0xBEEF);
    let message_id = 0x55_u64;

    let key_a = send_message_with_socket(
        &sender,
        destination,
        b"hello",
        send_options! {
            sender_id: Some(sender_id_a),
            message_id: Some(message_id),
            chunk_size: 16,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::new();
    let first = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_a),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(500),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(first.materialize_payload_lossy(), b"hello");

    send_message_with_socket(
        &sender,
        destination,
        b"hello",
        send_options! {
            sender_id: Some(sender_id_a),
            message_id: Some(message_id),
            chunk_size: 16,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let duplicate = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key_a),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        duplicate,
        Err(UniUdpError::TimeoutBeforeMatchingMessage { .. })
    ));

    let key_b = send_message_with_socket(
        &sender,
        destination,
        b"world",
        send_options! {
            sender_id: Some(sender_id_b),
            message_id: Some(message_id),
            chunk_size: 16,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let second = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_b),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(500),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(second.materialize_payload_lossy(), b"world");
}

#[test]
fn same_sender_message_id_is_distinct_across_session_nonce() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0xABCD_EF01);
    let message_id = 0x55_u64;
    let auth = packet_auth(515, 0x33);

    let key_session_1 = send_message_with_socket(
        &sender,
        destination,
        b"s1",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(message_id),
            session_nonce: Some(1),
            packet_auth: Some(auth.clone()),
            chunk_size: 16,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![auth.clone()],
        ..ReceiverConfig::default()
    })
    .unwrap();
    let first = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_session_1),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(500),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(first.materialize_payload_lossy(), b"s1");

    let key_session_2 = send_message_with_socket(
        &sender,
        destination,
        b"s2",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(message_id),
            session_nonce: Some(2),
            packet_auth: Some(auth),
            chunk_size: 16,
            ..SendOptions::default()
        },
    )
    .unwrap();

    assert_ne!(key_session_1, key_session_2);

    let second = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_session_2),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(500),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(second.materialize_payload_lossy(), b"s2");
}

#[test]
fn completed_dedup_cache_respects_max_completed_messages_cap() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0xD00D);
    let session_nonce = 123_u64;

    let mut receiver = Receiver::try_with_config(receiver_config! {
        max_completed_messages: 2,
        dedup_window: Duration::from_secs(30),
        ..ReceiverConfig::default()
    })
    .unwrap();

    let key_100 = send_message_with_socket(
        &sender,
        destination,
        b"m100",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(100),
            session_nonce: Some(session_nonce),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let report_100 = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_100),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(500),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(report_100.materialize_payload_lossy(), b"m100");

    let key_101 = send_message_with_socket(
        &sender,
        destination,
        b"m101",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(101),
            session_nonce: Some(session_nonce),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let report_101 = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_101),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(500),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(report_101.materialize_payload_lossy(), b"m101");

    let key_102 = send_message_with_socket(
        &sender,
        destination,
        b"m102",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(102),
            session_nonce: Some(session_nonce),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let report_102 = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_102),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(500),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(report_102.materialize_payload_lossy(), b"m102");

    // The oldest completed key (message 100) should be evicted by the cap.
    let replayed_key_100 = send_message_with_socket(
        &sender,
        destination,
        b"m100-replayed",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(100),
            session_nonce: Some(session_nonce),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    assert_eq!(replayed_key_100, key_100);
    let replayed_report_100 = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_100),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(500),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(
        replayed_report_100.materialize_payload_lossy(),
        b"m100-replayed"
    );

    // More recent completion key (message 102) should still be deduped.
    send_message_with_socket(
        &sender,
        destination,
        b"m102-replayed",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(102),
            session_nonce: Some(session_nonce),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let still_deduped = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key_102),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        still_deduped,
        Err(UniUdpError::TimeoutBeforeMatchingMessage { .. })
    ));
}

#[test]
fn strict_message_ordering_rejects_replayed_max_message_id() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0xF100);
    let session_nonce = 200_u64;
    let auth = packet_auth(0xF100, 0x71);

    let mut receiver = Receiver::try_with_config(receiver_config! {
        strict_message_ordering: true,
        auth_keys: vec![auth.clone()],
        ..ReceiverConfig::default()
    })
    .unwrap();

    // Send and receive message 100.
    let key_100 = send_message_with_socket(
        &sender,
        destination,
        b"m100",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(100),
            session_nonce: Some(session_nonce),
            packet_auth: Some(auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_100),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(report.materialize_payload_lossy(), b"m100");

    // Re-send message 100 (same message_id == max_seen).  With strict
    // ordering, the freshness check requires message_id > max_seen, so this
    // is rejected even though the dedup cache also has the entry.
    send_message_with_socket(
        &sender,
        destination,
        b"m100-replay",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(100),
            session_nonce: Some(session_nonce),
            packet_auth: Some(auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key_100),
            strict_rejections: true,
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        err,
        Err(UniUdpError::RejectedPacket {
            reason: ReceiveRejectReason::Replay
        })
    ));
    assert!(receiver.last_receive_diagnostics().replay_rejections >= 1);

    // A genuinely new message_id (101 > 100) is accepted.
    let key_101 = send_message_with_socket(
        &sender,
        destination,
        b"m101",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(101),
            session_nonce: Some(session_nonce),
            packet_auth: Some(auth),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let report_101 = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_101),
                strict_rejections: true,
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(report_101.materialize_payload_lossy(), b"m101");
}

#[test]
fn session_freshness_rejects_replay_after_dedup_cache_eviction() {
    // This test demonstrates the fix for the replay vulnerability: with a
    // tiny dedup cache (max_completed_messages=1), dedup entries are evicted
    // quickly.  Without session_freshness_retention + strict_message_ordering
    // the evicted message would be re-accepted.  With both enabled, the
    // session state still remembers max_message_id and rejects the replay.
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0xF200);
    let session_nonce = 300_u64;
    let auth = packet_auth(0xF200, 0x72);

    let mut receiver = Receiver::try_with_config(receiver_config! {
        max_completed_messages: 1,
        dedup_window: Duration::from_secs(30),
        session_freshness_retention: Duration::from_secs(3600),
        strict_message_ordering: true,
        auth_keys: vec![auth.clone()],
        ..ReceiverConfig::default()
    })
    .unwrap();

    // Complete message 100.
    let key_100 = send_message_with_socket(
        &sender,
        destination,
        b"m100",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(100),
            session_nonce: Some(session_nonce),
            packet_auth: Some(auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_100),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    // Complete message 101.  This evicts key_100 from the dedup cache
    // (max_completed_messages=1).
    let key_101 = send_message_with_socket(
        &sender,
        destination,
        b"m101",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(101),
            session_nonce: Some(session_nonce),
            packet_auth: Some(auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_101),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    // Replay message 100.  The dedup cache no longer has key_100, but the
    // session state remembers max_message_id=101.  Strict ordering rejects
    // message_id=100 because 100 is not > 101.
    send_message_with_socket(
        &sender,
        destination,
        b"m100-replay",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(100),
            session_nonce: Some(session_nonce),
            packet_auth: Some(auth),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key_100),
            strict_rejections: true,
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        err,
        Err(UniUdpError::RejectedPacket {
            reason: ReceiveRejectReason::Replay
        })
    ));
    assert!(receiver.last_receive_diagnostics().replay_rejections >= 1);
}
