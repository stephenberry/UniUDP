use super::common::*;

#[test]
fn packet_encoding_and_parsing_roundtrip() {
    let sender_id = SenderId(0x0102_0304_0506_0708_1112_1314_1516_1718);
    let header = packet_header(
        sender_id,
        0xABCD_EF01_0203_0405,
        0,
        3,
        5,
        40,
        8,
        0,
        2,
        1,
        pack_fec_field(1, false).unwrap(),
    );
    let payload = vec![0x10, 0x20, 0x30, 0x40];
    let packet = encode_packet(header, &payload).unwrap();
    let (decoded_header, decoded_payload) = parse_packet(&packet).unwrap();

    assert_eq!(decoded_payload, payload);
    assert_eq!(decoded_header.sender_id(), sender_id);
    assert_eq!(decoded_header.message_id(), header.message_id());
    assert_eq!(decoded_header.chunk_index(), header.chunk_index());
    assert_eq!(decoded_header.total_chunks(), header.total_chunks());
    assert_eq!(decoded_header.redundancy(), header.redundancy());
    assert_eq!(decoded_header.attempt(), header.attempt());

    let borrowed = parse_packet_view(&packet).unwrap();
    assert_eq!(borrowed.header.sender_id(), header.sender_id());
    assert_eq!(borrowed.header.message_id(), header.message_id());
    assert_eq!(borrowed.header.session_nonce(), header.session_nonce());
    assert_eq!(borrowed.header.chunk_index(), header.chunk_index());
    assert_eq!(borrowed.header.total_chunks(), header.total_chunks());
    assert_eq!(borrowed.header.message_length(), header.message_length());
    assert_eq!(borrowed.header.chunk_size(), header.chunk_size());
    assert_eq!(borrowed.header.redundancy(), header.redundancy());
    assert_eq!(borrowed.header.attempt(), header.attempt());
    assert_eq!(borrowed.header.fec_field(), header.fec_field());
    assert_eq!(borrowed.header.payload_len(), payload.len() as u16);
    assert_eq!(borrowed.payload, payload.as_slice());
}

#[test]
fn send_receive_end_to_end() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let payload: Vec<u8> = (0..2048).map(|i| (i % 256) as u8).collect();
    let payload_for_send = payload.clone();

    let sender_thread = thread::spawn(move || {
        send_message_with_socket(
            &sender,
            destination,
            &payload_for_send,
            send_options! {
                redundancy: 3,
                chunk_size: 256,
                ..SendOptions::default()
            },
        )
        .unwrap()
    });

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(5),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    let sent_key = sender_thread.join().unwrap();
    assert_eq!(report.key, sent_key);
    assert_eq!(report.materialize_payload_lossy(), payload);
    assert!(report.lost_chunks.is_empty());
    assert_eq!(report.chunks_expected, report.chunks_received);
    assert_eq!(report.redundancy_requested, 3);
    assert_eq!(report.redundancy_required, 1);
    assert_eq!(report.completion_reason, CompletionReason::Completed);
}

#[test]
fn sender_reserved_message_ids_are_monotonic_per_instance() {
    let sender = Sender::with_identity(SenderId(0xA0A0), 0xB0B0);
    let id1 = sender.reserve_message_key().unwrap().message_id;
    let id2 = sender.reserve_message_key().unwrap().message_id;
    let id3 = sender.reserve_message_key().unwrap().message_id;
    assert_eq!(id2, id1.wrapping_add(1));
    assert_eq!(id3, id2.wrapping_add(1));
}

#[test]
fn sender_explicit_message_id_advances_automatic_sequence() {
    let sender_socket = bind_local();
    let receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender = Sender::with_identity(SenderId(0x1A2B), 0x3C4D);

    let baseline = sender.reserve_message_key().unwrap().message_id;
    let explicit_message_id = if baseline > (u64::MAX - 10) {
        baseline
    } else {
        baseline + 10
    };
    sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"manual")
                .with_options(SendOptions::default())
                .with_identity(SendIdentityOverrides::new().with_message_id(explicit_message_id)),
        )
        .unwrap();

    let auto_key = sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"auto").with_options(SendOptions::default()),
        )
        .unwrap();
    assert_eq!(auto_key.message_id, explicit_message_id.wrapping_add(1));
}

#[test]
fn sender_rejects_non_increasing_explicit_message_id() {
    let sender_socket = bind_local();
    let receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender = Sender::with_identity(SenderId(0x1A2C), 0x3C4E);

    sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"first")
                .with_options(SendOptions::default())
                .with_identity(SendIdentityOverrides::new().with_message_id(1_000)),
        )
        .unwrap();

    let err = sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"backward")
                .with_options(SendOptions::default())
                .with_identity(SendIdentityOverrides::new().with_message_id(999)),
        )
        .unwrap_err();
    assert!(matches!(
        err.error(),
        UniUdpError::Validation {
            context: uniudp::ValidationContext::SendOptions,
            message:
                "explicit message_id must be > highest previously sent message_id for sender/session",
            ..
        }
    ));
    let duplicate_err = sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"duplicate")
                .with_options(SendOptions::default())
                .with_identity(SendIdentityOverrides::new().with_message_id(1_000)),
        )
        .unwrap_err();
    assert!(matches!(
        duplicate_err.error(),
        UniUdpError::Validation {
            context: uniudp::ValidationContext::SendOptions,
            message:
                "explicit message_id must be > highest previously sent message_id for sender/session",
            ..
        }
    ));
}

#[test]
fn sender_reset_session_requires_different_nonce_even_when_current_is_max() {
    let mut sender = Sender::with_identity(SenderId(0x1A2F), u64::MAX);
    assert!(sender.reset_session(0).is_ok());
    let err = sender.reset_session(0).unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::SendOptions,
            message: "new session_nonce must differ from current session_nonce",
            ..
        }
    ));
}

#[test]
fn concurrent_senders_with_conflicting_message_key_reject_duplicate() {
    let sender_a = bind_local();
    let sender_b = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0x1B2C);
    let session_nonce = 0xAA55_u64;
    let message_id = 0x55AA_u64;
    let key = key_with_session(sender_id, session_nonce, message_id);

    let t1 = thread::spawn(move || {
        send_message_with_socket(
            &sender_a,
            destination,
            b"from-a",
            send_options! {
                sender_id: Some(sender_id),
                session_nonce: Some(session_nonce),
                message_id: Some(message_id),
                redundancy: 2,
                chunk_size: 64,
                ..SendOptions::default()
            },
        )
        .unwrap()
    });
    let t2 = thread::spawn(move || {
        send_message_with_socket(
            &sender_b,
            destination,
            b"from-b",
            send_options! {
                sender_id: Some(sender_id),
                session_nonce: Some(session_nonce),
                message_id: Some(message_id),
                redundancy: 2,
                chunk_size: 64,
                ..SendOptions::default()
            },
        )
        .unwrap()
    });

    assert_eq!(t1.join().unwrap(), key);
    assert_eq!(t2.join().unwrap(), key);

    let mut receiver = Receiver::new();
    let first = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key),
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert!(matches!(
        first.materialize_payload_lossy().as_slice(),
        b"from-a" | b"from-b"
    ));

    let duplicate = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key),
            strict_rejections: true,
            inactivity_timeout: Duration::from_millis(200),
            overall_timeout: Duration::from_secs(2),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        duplicate,
        Err(UniUdpError::RejectedPacket {
            reason: ReceiveRejectReason::Replay
        })
    ));
}

#[test]
fn sender_session_nonce_override_scopes_explicit_monotonicity() {
    let sender_socket = bind_local();
    let receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender = Sender::with_identity(SenderId(0x1A2E), 0x3C51);

    let first_key = sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"session-10")
                .with_options(SendOptions::default())
                .with_identity(
                    SendIdentityOverrides::new()
                        .with_session_nonce(10)
                        .with_message_id(100),
                ),
        )
        .unwrap();
    assert_eq!(first_key.message_id, 100);

    let second_key = sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"session-11")
                .with_options(SendOptions::default())
                .with_identity(
                    SendIdentityOverrides::new()
                        .with_session_nonce(11)
                        .with_message_id(0),
                ),
        )
        .unwrap();
    assert_eq!(second_key.message_id, 0);
}

#[test]
fn sender_reset_session_allows_message_id_restart_from_zero() {
    let sender_socket = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let mut sender = Sender::with_identity(SenderId(0x1A2D), 0x3C4F);

    let first_key = sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"first-session")
                .with_options(SendOptions::default())
                .with_identity(SendIdentityOverrides::new().with_message_id(100)),
        )
        .unwrap();
    assert_eq!(first_key.message_id, 100);

    sender.reset_session(0x3C50).unwrap();

    let second_key = sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"new-session")
                .with_options(SendOptions::default())
                .with_identity(SendIdentityOverrides::new().with_message_id(0)),
        )
        .unwrap();
    assert_eq!(second_key.message_id, 0);

    let mut receiver = Receiver::new();
    let first = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(first_key),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(500),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(first.materialize_payload_lossy(), b"first-session");

    let second = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(second_key),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(500),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(second.materialize_payload_lossy(), b"new-session");
}

#[test]
fn sender_reset_session_mixed_explicit_and_auto_ids_remain_monotonic() {
    let sender_socket = bind_local();
    let receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let mut sender = Sender::with_identity(SenderId(0x1A2F), 0x3C52);

    sender.reset_session(0x3C53).unwrap();
    let explicit_one = sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"explicit-one")
                .with_options(SendOptions::default())
                .with_identity(SendIdentityOverrides::new().with_message_id(1)),
        )
        .unwrap();
    let auto_after_one = sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"auto-after-one").with_options(SendOptions::default()),
        )
        .unwrap();
    assert_eq!(explicit_one.message_id, 1);
    assert_eq!(auto_after_one.message_id, 2);

    sender.reset_session(0x3C54).unwrap();
    let explicit_zero = sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"explicit-zero")
                .with_options(SendOptions::default())
                .with_identity(SendIdentityOverrides::new().with_message_id(0)),
        )
        .unwrap();
    let auto_after_zero = sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"auto-after-zero").with_options(SendOptions::default()),
        )
        .unwrap();
    assert_eq!(explicit_zero.message_id, 0);
    assert_eq!(auto_after_zero.message_id, 1);
}

#[test]
fn sender_instances_track_independent_message_sequences() {
    let sender_a = Sender::with_identity(SenderId(0xAA01), 0xAA10);
    let sender_b = Sender::with_identity(SenderId(0xBB01), 0xBB10);

    let a1 = sender_a.reserve_message_key().unwrap().message_id;
    let b1 = sender_b.reserve_message_key().unwrap().message_id;
    let a2 = sender_a.reserve_message_key().unwrap().message_id;
    let b2 = sender_b.reserve_message_key().unwrap().message_id;

    assert_eq!(a2, a1.wrapping_add(1));
    assert_eq!(b2, b1.wrapping_add(1));
}

#[test]
fn send_with_custom_pacer_invokes_inter_packet_delay_callback() {
    let sender_socket = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender = Sender::with_identity(SenderId(0x5A5A), 0x6B6B);
    let payload = vec![0xCD; 512];
    let delay = Duration::from_millis(1);
    let mut pace_calls = 0usize;

    let key = sender
        .send_with_socket_with_pacer(
            &sender_socket,
            SendRequest::new(destination, &payload).with_options(
                SendOptions::new()
                    .with_redundancy(1)
                    .with_chunk_size(256)
                    .with_delay(delay),
            ),
            |paced_delay| {
                assert_eq!(paced_delay, delay);
                pace_calls += 1;
            },
        )
        .unwrap();

    // Two chunks with redundancy=1 and no parity => one inter-packet delay.
    assert_eq!(pace_calls, 1);

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key),
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(report.materialize_payload_lossy(), payload);
}

#[test]
fn option_builders_set_expected_fields() {
    let auth = packet_auth(42, 0xAB);
    let sender_id = SenderId(0x1234);
    let message_key = key(sender_id, 0xDEAD_BEEF);

    let send_transport = SendOptions::new()
        .with_redundancy(3)
        .with_chunk_size(256)
        .with_fec_mode(FecMode::ReedSolomon {
            data_shards: 4,
            parity_shards: 1,
        })
        .with_delay(Duration::from_millis(2));
    assert_eq!(send_transport.redundancy(), 3);
    assert_eq!(send_transport.chunk_size(), 256);
    assert_eq!(
        *send_transport.fec_mode(),
        FecMode::ReedSolomon {
            data_shards: 4,
            parity_shards: 1
        }
    );
    assert_eq!(send_transport.delay(), Duration::from_millis(2));
    assert!(send_transport.validate().is_ok());

    let send_identity = SendIdentityOverrides::new()
        .with_message_id(message_key.message_id)
        .with_sender_id(sender_id)
        .with_session_nonce(99)
        .with_packet_auth(auth.clone());
    assert_eq!(send_identity.message_id(), Some(message_key.message_id));
    assert_eq!(send_identity.sender_id(), Some(sender_id));
    assert_eq!(send_identity.session_nonce(), Some(99));
    assert_eq!(send_identity.packet_auth().cloned(), Some(auth.clone()));

    let receive = ReceiveOptions::new()
        .with_key(message_key)
        .with_source_policy(SourcePolicy::Exact("127.0.0.1:9000".parse().unwrap()))
        .with_strict_rejections(true)
        .with_inactivity_timeout(Duration::from_millis(10))
        .with_overall_timeout(Duration::from_millis(50));
    assert_eq!(receive.key(), Some(message_key));
    assert!(receive.strict_rejections());
    assert_eq!(receive.inactivity_timeout(), Duration::from_millis(10));
    assert_eq!(receive.overall_timeout(), Duration::from_millis(50));
    assert!(receive.validate().is_ok());

    let receiver_config = ReceiverConfig::new()
        .with_max_pending_messages(8)
        .with_max_pending_bytes(4096)
        .with_max_completed_messages(32)
        .with_dedup_window(Duration::from_millis(250))
        .with_pending_max_age(Duration::from_secs(1))
        .with_max_receive_chunks(128)
        .with_max_receive_message_len(2048)
        .with_max_receive_datagram_size(4096)
        .with_message_freshness_window(10)
        .with_unbounded_message_freshness(true)
        .with_session_freshness_retention(Duration::from_secs(7200))
        .with_strict_message_ordering(true)
        .with_auth_key(auth.clone());
    assert_eq!(receiver_config.max_pending_messages(), 8);
    assert_eq!(receiver_config.max_pending_bytes(), 4096);
    assert_eq!(receiver_config.max_completed_messages(), 32);
    assert_eq!(receiver_config.dedup_window(), Duration::from_millis(250));
    assert_eq!(receiver_config.pending_max_age(), Duration::from_secs(1));
    assert_eq!(receiver_config.max_receive_chunks(), 128);
    assert_eq!(receiver_config.max_receive_message_len(), 2048);
    assert_eq!(receiver_config.max_receive_datagram_size(), 4096);
    assert_eq!(receiver_config.message_freshness_window(), 10);
    assert!(receiver_config.unbounded_message_freshness());
    assert_eq!(
        receiver_config.session_freshness_retention(),
        Duration::from_secs(7200)
    );
    assert!(receiver_config.strict_message_ordering());
    assert_eq!(receiver_config.auth_keys(), &[auth]);
    assert_eq!(receiver_config.auth_mode(), AuthMode::Require);
}

#[test]
fn send_options_validate_rejects_invalid_values() {
    let err = SendOptions::new()
        .with_redundancy(0)
        .validate()
        .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::SendOptions,
            message: "redundancy must be at least 1",
            ..
        }
    ));

    let err = SendOptions::new()
        .with_chunk_size(0)
        .validate()
        .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::SendOptions,
            message: "chunk_size must be positive",
            ..
        }
    ));

    // RS FEC mode validates shard counts
    assert!(SendOptions::new()
        .with_fec_mode(FecMode::ReedSolomon {
            data_shards: 4,
            parity_shards: 2
        })
        .validate()
        .is_ok());
    assert!(SendOptions::new()
        .with_fec_mode(FecMode::ReedSolomon {
            data_shards: 0,
            parity_shards: 1
        })
        .validate()
        .is_err());
    assert!(SendOptions::new()
        .with_fec_mode(FecMode::ReedSolomon {
            data_shards: 1,
            parity_shards: 0
        })
        .validate()
        .is_err());
}

#[test]
fn receive_options_validate_rejects_invalid_values() {
    let err = ReceiveOptions::new()
        .with_overall_timeout(Duration::ZERO)
        .validate()
        .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiveOptions,
            message: "overall_timeout must be positive",
            ..
        }
    ));

    let err = ReceiveOptions::new()
        .with_inactivity_timeout(Duration::ZERO)
        .validate()
        .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiveOptions,
            message: "inactivity_timeout must be positive",
            ..
        }
    ));
}

#[test]
fn sender_struct_send_uses_owned_sender_identity_by_default() {
    let sender_socket = bind_local();
    let receiver_socket = bind_local();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let destination = receiver_socket.local_addr().unwrap();

    let sender = Sender::with_identity(SenderId(0xCCDD), 0xEEFF);
    let key = sender
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, b"sender-struct")
                .with_options(SendOptions::new().with_chunk_size(64)),
        )
        .unwrap();

    let mut packet = vec![0_u8; 2048];
    let (packet_len, _source) = receiver_socket.recv_from(&mut packet).unwrap();
    let (header, payload) = parse_packet(&packet[..packet_len]).unwrap();

    assert_eq!(header.sender_id(), sender.sender_id());
    assert_eq!(header.message_id(), key.message_id);
    assert_eq!(payload, b"sender-struct");
}

#[test]
fn sender_send_with_socket_with_scratch_reuses_hot_path_buffers() {
    let sender_socket = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender = Sender::with_identity(SenderId(0xCCEE), 0xEE11);
    let mut scratch = SendScratch::new();

    let key1 = sender
        .send_with_socket_with_scratch(
            &sender_socket,
            SendRequest::new(destination, b"first").with_options(SendOptions::default()),
            &mut scratch,
        )
        .unwrap();
    let key2 = sender
        .send_with_socket_with_scratch(
            &sender_socket,
            SendRequest::new(destination, b"second").with_options(SendOptions::default()),
            &mut scratch,
        )
        .unwrap();

    let mut receiver = Receiver::new();
    let report1 = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key1),
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    let report2 = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key2),
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(report1.materialize_payload_lossy(), b"first");
    assert_eq!(report2.materialize_payload_lossy(), b"second");
}

#[test]
fn receiver_config_limits_max_message_length() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let key = send_message_with_socket(
        &sender,
        destination,
        b"too-long",
        send_options! {
            chunk_size: 16,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        max_receive_message_len: 3,
        ..ReceiverConfig::default()
    })
    .unwrap();
    let result = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );

    let diagnostics = rejected_timeout_diagnostics(result.unwrap_err());
    assert!(diagnostics.metadata_rejections > 0);
}

#[test]
fn receiver_config_limits_max_receive_chunks() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let key = send_message_with_socket(
        &sender,
        destination,
        b"four",
        send_options! {
            chunk_size: 2,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        max_receive_chunks: 1,
        ..ReceiverConfig::default()
    })
    .unwrap();
    let result = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );

    let diagnostics = rejected_timeout_diagnostics(result.unwrap_err());
    assert!(diagnostics.metadata_rejections > 0);
}

#[test]
fn receiver_config_validate_rejects_invalid_values() {
    let err = receiver_config! {
        max_pending_messages: 0,
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "max_pending_messages must be positive",
            ..
        }
    ));
    if let UniUdpError::Validation {
        detail: Some(detail),
        ..
    } = err
    {
        assert_eq!(detail.field, "max_pending_messages");
        assert_eq!(detail.expected, "> 0");
        assert_eq!(detail.actual, "0");
    } else {
        panic!("expected validation detail for max_pending_messages");
    }

    let err = receiver_config! {
        max_pending_bytes: 0,
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "max_pending_bytes must be positive",
            ..
        }
    ));

    let err = receiver_config! {
        max_completed_messages: 0,
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "max_completed_messages must be positive",
            ..
        }
    ));

    let err = receiver_config! {
        max_tracked_sessions_total: 0,
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "max_tracked_sessions_total must be positive",
            ..
        }
    ));

    let err = receiver_config! {
        max_tracked_sessions_per_sender: 0,
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "max_tracked_sessions_per_sender must be positive",
            ..
        }
    ));

    let err = receiver_config! {
        dedup_window: Duration::ZERO,
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "dedup_window must be positive",
            ..
        }
    ));

    let err = receiver_config! {
        session_freshness_retention: Duration::ZERO,
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "session_freshness_retention must be positive",
            ..
        }
    ));

    let err = receiver_config! {
        message_freshness_window: 0,
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "message_freshness_window must be positive unless unbounded_message_freshness is enabled",
            ..
        }
    ));
    if let UniUdpError::Validation {
        detail: Some(detail),
        ..
    } = err
    {
        assert_eq!(detail.field, "message_freshness_window");
        assert_eq!(
            detail.expected,
            "> 0 or with_unbounded_message_freshness(true)"
        );
        assert_eq!(detail.actual, "0");
    } else {
        panic!("expected validation detail for message_freshness_window");
    }

    assert!(receiver_config! {
        message_freshness_window: 0,
        unbounded_message_freshness: true,
        ..ReceiverConfig::default()
    }
    .validate()
    .is_ok());

    let err = receiver_config! {
        max_receive_datagram_size: HEADER_LENGTH - 1,
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "max_receive_datagram_size must be at least HEADER_LENGTH",
            ..
        }
    ));

    let err = receiver_config! {
        max_receive_datagram_size: MAX_RECEIVE_DATAGRAM_SIZE + 1,
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "max_receive_datagram_size exceeds UDP payload limit",
            ..
        }
    ));

    let err = receiver_config! {
        auth_keys: vec![packet_auth(1, 0x10), packet_auth(1, 0x20)],
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "auth_keys contains duplicate key_id",
            ..
        }
    ));

    let err = receiver_config! {
        auth_mode: AuthMode::Require,
        auth_keys: Vec::new(),
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "auth_mode Require requires at least one auth key",
            ..
        }
    ));

    let err = receiver_config! {
        auth_mode: AuthMode::Optional,
        auth_keys: Vec::new(),
        ..ReceiverConfig::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "auth_mode Optional requires at least one auth key; use Disabled if no keys are available",
            ..
        }
    ));
}

#[test]
fn receiver_try_with_config_rejects_invalid_config() {
    let err = Receiver::try_with_config(receiver_config! {
        max_receive_chunks: 0,
        ..ReceiverConfig::default()
    })
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::ReceiverConfig,
            message: "max_receive_chunks must be positive",
            ..
        }
    ));
}

#[test]
fn receive_message_restores_socket_read_timeout_after_success() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let original_timeout = receiver_socket.read_timeout().unwrap();

    let sender_thread = thread::spawn(move || {
        send_message_with_socket(
            &sender,
            destination,
            b"hello",
            send_options! {
                redundancy: 1,
                chunk_size: 8,
                ..SendOptions::default()
            },
        )
        .unwrap()
    });

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_secs(1),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    let sent_key = sender_thread.join().unwrap();
    assert_eq!(report.key, sent_key);
    assert_eq!(report.materialize_payload_lossy(), b"hello");
    assert_eq!(receiver_socket.read_timeout().unwrap(), original_timeout);
}

#[test]
fn zero_length_payload_delivery() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_thread = thread::spawn(move || {
        send_message_with_socket(
            &sender,
            destination,
            &[],
            send_options! {
                redundancy: 2,
                chunk_size: 64,
                ..SendOptions::default()
            },
        )
        .unwrap()
    });

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    let sent_key = sender_thread.join().unwrap();
    assert_eq!(report.key, sent_key);
    assert!(report.materialize_payload_lossy().is_empty());
    assert_eq!(report.received_chunks.len(), 1);
    assert_eq!(report.received_chunks[0].index, 0);
    assert!(report.received_chunks[0].payload.is_empty());
    assert!(report.lost_chunks.is_empty());
    assert_eq!(report.chunks_expected, 1);
    assert_eq!(report.chunks_received, 1);
    assert_eq!(report.redundancy_requested, 2);
    assert_eq!(report.redundancy_required, 1);
    assert_eq!(report.completion_reason, CompletionReason::Completed);
}

#[test]
fn send_message_validates_udp_datagram_payload_limit() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let max_chunk_size = (65_507_usize - HEADER_LENGTH) as u16;
    let too_large_chunk_size = max_chunk_size + 1;

    let invalid = send_message_with_socket(
        &sender,
        destination,
        &[0xAB],
        send_options! {
            chunk_size: too_large_chunk_size,
            ..SendOptions::default()
        },
    );
    assert!(matches!(
        invalid,
        Err(UniUdpError::Validation {
            context: uniudp::ValidationContext::SendOptions,
            ..
        })
    ));

    let key = send_message_with_socket(
        &sender,
        destination,
        &[0xAB],
        send_options! {
            chunk_size: max_chunk_size,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(500),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(report.materialize_payload_lossy(), vec![0xAB]);
}

#[test]
fn same_message_id_different_sender_ids_are_independent() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id_a = SenderId(0xA);
    let sender_id_b = SenderId(0xB);
    let message_id = 77_u64;

    let key_a = send_message_with_socket(
        &sender,
        destination,
        b"from-a",
        send_options! {
            sender_id: Some(sender_id_a),
            message_id: Some(message_id),
            chunk_size: 32,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let key_b = send_message_with_socket(
        &sender,
        destination,
        b"from-b",
        send_options! {
            sender_id: Some(sender_id_b),
            message_id: Some(message_id),
            chunk_size: 32,
            ..SendOptions::default()
        },
    )
    .unwrap();

    assert_ne!(key_a, key_b);

    let mut receiver = Receiver::new();
    let report_a = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_a),
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    let report_b = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_b),
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(report_a.materialize_payload_lossy(), b"from-a");
    assert_eq!(report_b.materialize_payload_lossy(), b"from-b");
}

#[test]
fn receiver_instances_do_not_share_dedup_state() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let shared_key = send_message_with_socket(
        &sender,
        destination,
        b"one",
        send_options! {
            sender_id: Some(SenderId(0x66)),
            message_id: Some(0x66),
            chunk_size: 8,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut r1 = Receiver::new();
    let first = r1
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(shared_key),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(first.materialize_payload_lossy(), b"one");

    send_message_with_socket(
        &sender,
        destination,
        b"one",
        send_options! {
            sender_id: Some(SenderId(0x66)),
            message_id: Some(0x66),
            chunk_size: 8,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let deduped_in_r1 = r1.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(shared_key),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(150),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        deduped_in_r1,
        Err(UniUdpError::TimeoutBeforeMatchingMessage { .. })
    ));

    send_message_with_socket(
        &sender,
        destination,
        b"one",
        send_options! {
            sender_id: Some(SenderId(0x66)),
            message_id: Some(0x66),
            chunk_size: 8,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut r2 = Receiver::new();
    let accepted_in_r2 = r2
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(shared_key),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(accepted_in_r2.materialize_payload_lossy(), b"one");
}

#[test]
fn same_message_id_can_complete_from_many_senders() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let base_message_id = 0x2222_u64;
    let mut expected = HashSet::new();
    for sender_num in 0..8_u128 {
        let sender_id = SenderId(0x7000 + sender_num);
        let payload = vec![sender_num as u8, 0xAA, 0xBB];
        let key = send_message_with_socket(
            &sender,
            destination,
            &payload,
            send_options! {
                sender_id: Some(sender_id),
                message_id: Some(base_message_id),
                chunk_size: 16,
                ..SendOptions::default()
            },
        )
        .unwrap();
        expected.insert((key, payload));
    }

    let mut receiver = Receiver::new();
    let mut got = HashSet::new();
    for _ in 0..expected.len() {
        let report = receiver
            .receive_message(
                &mut receiver_socket,
                receive_options! {
                    key: None,
                    inactivity_timeout: Duration::from_millis(100),
                    overall_timeout: Duration::from_secs(2),
                    ..ReceiveOptions::default()
                },
            )
            .unwrap();
        got.insert((report.key, report.materialize_payload_lossy()));
    }

    assert_eq!(got, expected);
}
