use super::common::*;

#[test]
fn send_receive_end_to_end_with_packet_auth() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let payload = b"auth-roundtrip".to_vec();
    let auth = packet_auth(7, 0x10);

    let sent_key = send_message_with_socket(
        &sender,
        destination,
        &payload,
        send_options! {
            chunk_size: 64,
            packet_auth: Some(auth.clone()),
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![auth],
        ..ReceiverConfig::default()
    })
    .unwrap();
    let report = receiver
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

    assert_eq!(report.materialize_payload_lossy(), payload);
    assert_eq!(report.key, sent_key);
    assert_eq!(report.completion_reason, CompletionReason::Completed);
    assert_eq!(
        receiver.config().max_pending_messages(),
        ReceiverConfig::default().max_pending_messages()
    );
}

#[test]
fn encode_packet_with_auth_roundtrip_via_receiver() {
    let sender_socket = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xFEED_BEEF);
    let message_id = 0x1020_3040_5060_7080;
    let payload = b"manual-auth-encode";
    let auth = packet_auth(313, 0x66);
    let session_nonce = 0xAA55_AA55_1122_3344;

    let header = packet_header(
        sender_id,
        message_id,
        session_nonce,
        0,
        1,
        payload.len() as u32,
        payload.len() as u16,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );
    let packet = encode_packet_with_auth(header, payload, Some(&auth)).unwrap();
    sender_socket.send_to(&packet, destination).unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![auth],
        ..ReceiverConfig::default()
    })
    .unwrap();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_with_session(sender_id, session_nonce, message_id)),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(
        report.key,
        key_with_session(sender_id, session_nonce, message_id)
    );
    assert_eq!(report.materialize_payload_lossy(), payload);
}

#[test]
fn send_receive_with_rotating_auth_keys_by_key_id() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xABCD);
    let session_nonce = 0xDEAD_BEEF_u64;
    let old_auth = packet_auth(100, 0x61);
    let new_auth = packet_auth(101, 0x62);

    let key_old = send_message_with_socket(
        &sender,
        destination,
        b"old-key",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(1000),
            session_nonce: Some(session_nonce),
            packet_auth: Some(old_auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();
    let key_new = send_message_with_socket(
        &sender,
        destination,
        b"new-key",
        send_options! {
            sender_id: Some(sender_id),
            message_id: Some(1001),
            session_nonce: Some(session_nonce),
            packet_auth: Some(new_auth.clone()),
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![old_auth, new_auth],
        ..ReceiverConfig::default()
    })
    .unwrap();
    let old_report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_old),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    let new_report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_new),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(old_report.materialize_payload_lossy(), b"old-key");
    assert_eq!(new_report.materialize_payload_lossy(), b"new-key");
}

#[test]
fn stable_sender_id_with_manual_session_nonce_survives_restart() {
    let sender_socket = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender_id = SenderId(0xABCDEF01);
    let auth = packet_auth(600, 0x4A);
    let first_session_nonce = 1_u64;
    let second_session_nonce = 2_u64;

    let sender_before_restart = Sender::builder()
        .with_sender_id(sender_id)
        .with_session_nonce(first_session_nonce)
        .build()
        .unwrap();
    let payload_a = b"before-restart".to_vec();
    let key_a = sender_before_restart
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, &payload_a)
                .with_identity(SendIdentityOverrides::new().with_packet_auth(auth.clone())),
        )
        .unwrap();

    let sender_after_restart = Sender::builder()
        .with_sender_id(sender_id)
        .with_session_nonce(second_session_nonce)
        .build()
        .unwrap();
    let payload_b = b"after-restart".to_vec();
    let key_b = sender_after_restart
        .send_with_socket(
            &sender_socket,
            SendRequest::new(destination, &payload_b)
                .with_identity(SendIdentityOverrides::new().with_packet_auth(auth.clone())),
        )
        .unwrap();

    assert_ne!(key_b.session_nonce, key_a.session_nonce);

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![auth],
        ..ReceiverConfig::default()
    })
    .unwrap();

    let report_a = receiver
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
    let report_b = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key_b),
                inactivity_timeout: Duration::from_millis(100),
                overall_timeout: Duration::from_millis(400),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(report_a.materialize_payload_lossy(), payload_a);
    assert_eq!(report_b.materialize_payload_lossy(), payload_b);
}

#[test]
fn optional_auth_mode_accepts_unauthenticated_packets_with_configured_keys() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let payload = b"optional-unauth".to_vec();

    let sent_key = send_message_with_socket(
        &sender,
        destination,
        &payload,
        send_options! {
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_mode: AuthMode::Optional,
        auth_keys: vec![packet_auth(41, 0x21)],
        ..ReceiverConfig::default()
    })
    .unwrap();
    let report = receiver
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

    assert_eq!(report.materialize_payload_lossy(), payload);
}

#[test]
fn optional_auth_mode_rejects_invalid_authenticated_packets() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sent_key = send_message_with_socket(
        &sender,
        destination,
        b"optional-auth-invalid",
        send_options! {
            chunk_size: 64,
            packet_auth: Some(packet_auth(77, 0x30)),
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_mode: AuthMode::Optional,
        auth_keys: vec![packet_auth(78, 0x30)],
        ..ReceiverConfig::default()
    })
    .unwrap();
    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(sent_key),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );

    let diagnostics = rejected_timeout_diagnostics(err.unwrap_err());
    assert!(diagnostics.auth_rejections > 0);
    assert_eq!(diagnostics.packets_accepted, 0);
}

#[test]
fn disabled_auth_mode_accepts_authenticated_packets_without_matching_key() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let payload = b"disabled-auth-mode".to_vec();

    let sent_key = send_message_with_socket(
        &sender,
        destination,
        &payload,
        send_options! {
            chunk_size: 64,
            packet_auth: Some(packet_auth(70, 0x44)),
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_mode: AuthMode::Disabled,
        auth_keys: vec![packet_auth(71, 0x44)],
        ..ReceiverConfig::default()
    })
    .unwrap();
    let report = receiver
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

    assert_eq!(report.materialize_payload_lossy(), payload);
}

#[test]
fn receiver_rejects_unauthenticated_packet_when_auth_required() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sent_key = send_message_with_socket(
        &sender,
        destination,
        b"unauth",
        send_options! {
            chunk_size: 64,
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![packet_auth(11, 0x21)],
        ..ReceiverConfig::default()
    })
    .unwrap();
    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(sent_key),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );

    let diagnostics = rejected_timeout_diagnostics(err.unwrap_err());
    assert!(diagnostics.auth_rejections > 0);
    assert_eq!(diagnostics.packets_accepted, 0);
}

#[test]
fn receiver_rejects_authenticated_packet_with_unknown_key_id() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let sender_auth = packet_auth(77, 0x30);

    let sent_key = send_message_with_socket(
        &sender,
        destination,
        b"auth-key-id",
        send_options! {
            chunk_size: 64,
            packet_auth: Some(sender_auth),
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![packet_auth(78, 0x30)],
        ..ReceiverConfig::default()
    })
    .unwrap();
    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(sent_key),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );

    let diagnostics = rejected_timeout_diagnostics(err.unwrap_err());
    assert!(diagnostics.auth_rejections > 0);
    assert_eq!(diagnostics.packets_accepted, 0);
}

#[test]
fn receiver_default_disabled_accepts_authenticated_packet_without_configured_auth_key() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();
    let auth = packet_auth(3, 0x30);

    let sent_key = send_message_with_socket(
        &sender,
        destination,
        b"auth-no-receiver-key",
        send_options! {
            chunk_size: 64,
            packet_auth: Some(auth),
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(sent_key),
                inactivity_timeout: Duration::from_millis(50),
                overall_timeout: Duration::from_millis(200),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();
    assert_eq!(report.materialize_payload_lossy(), b"auth-no-receiver-key");
}

#[test]
fn strict_rejections_returns_rejected_packet_on_auth_failure() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sent_key = send_message_with_socket(
        &sender,
        destination,
        b"strict-auth",
        send_options! {
            chunk_size: 64,
            packet_auth: Some(packet_auth(1, 0x40)),
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![packet_auth(1, 0x41)],
        ..ReceiverConfig::default()
    })
    .unwrap();
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
            reason: ReceiveRejectReason::Authentication
        })
    ));

    let diagnostics = receiver.last_receive_diagnostics();
    assert_eq!(diagnostics.packets_received, 1);
    assert_eq!(diagnostics.auth_rejections, 1);
}

#[test]
fn tampered_authenticated_packet_is_rejected() {
    let sender = bind_local();
    let relay = bind_local();
    let mut receiver_socket = bind_local();
    relay
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let relay_destination = relay.local_addr().unwrap();
    let receiver_destination = receiver_socket.local_addr().unwrap();
    let auth = packet_auth(9, 0x52);

    let sent_key = send_message_with_socket(
        &sender,
        relay_destination,
        b"tamper-tag",
        send_options! {
            sender_id: Some(SenderId(0x4040)),
            message_id: Some(0x5151),
            chunk_size: 64,
            packet_auth: Some(auth.clone()),
            ..SendOptions::default()
        },
    )
    .unwrap();

    let mut packet = vec![0_u8; 1024];
    let (packet_len, _source) = relay.recv_from(&mut packet).unwrap();
    let mut tampered = packet[..packet_len].to_vec();
    tampered[HEADER_LENGTH - 1] ^= 0x5A;
    assert!(parse_packet(&tampered).is_ok());
    relay.send_to(&tampered, receiver_destination).unwrap();

    let mut receiver = Receiver::try_with_config(receiver_config! {
        auth_keys: vec![auth],
        ..ReceiverConfig::default()
    })
    .unwrap();
    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(sent_key),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );

    let diagnostics = rejected_timeout_diagnostics(err.unwrap_err());
    assert!(diagnostics.auth_rejections > 0);
    assert_eq!(diagnostics.packets_accepted, 0);
}
