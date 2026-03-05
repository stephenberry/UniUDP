use super::common::*;

#[test]
fn parse_packet_view_with_wire_security_exposes_wire_fields() {
    let header = packet_header(
        SenderId(0x4242),
        0x9090,
        0xAA55_33CC_7788_9911,
        0,
        1,
        3,
        3,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );
    let payload = [0x10, 0x20, 0x30];
    let auth = packet_auth(77, 0x31);

    let packet = encode_packet_with_auth(header, &payload, Some(&auth)).unwrap();
    let parsed = parse_packet_view_with_wire_security(&packet).unwrap();

    assert_eq!(parsed.header.sender_id(), header.sender_id());
    assert_eq!(parsed.header.message_id(), header.message_id());
    assert_eq!(parsed.payload, payload.as_slice());
    assert!(parsed.security.authenticated);
    assert_ne!(parsed.security.flags, 0);
    assert_eq!(parsed.security.auth_key_id, auth.key_id());
    assert_eq!(parsed.header.session_nonce(), header.session_nonce());
    assert_ne!(parsed.security.auth_tag, [0_u8; PACKET_AUTH_TAG_LENGTH]);

    let checksum = u32::from_be_bytes(
        packet[PACKET_CHECKSUM_OFFSET..PACKET_CHECKSUM_OFFSET + 4]
            .try_into()
            .unwrap(),
    );
    assert_eq!(parsed.security.checksum, checksum);
}

#[test]
fn parse_packet_rejects_payload_len_larger_than_chunk_size() {
    let mut bytes = encode_packet(
        packet_header(
            SenderId(7),
            1,
            0,
            0,
            1,
            2,
            2,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &[1, 2],
    )
    .unwrap();
    bytes.extend_from_slice(&[3, 4]);
    let payload_len_offset = 4 + 1 + 1 + 4 + 8 + 16 + 8 + 4 + 4 + 4 + 2;
    bytes[payload_len_offset..payload_len_offset + 2].copy_from_slice(&4_u16.to_be_bytes());

    let err = parse_packet(&bytes).unwrap_err();
    match err {
        UniUdpError::Decode {
            context: uniudp::DecodeContext::Packet,
            ..
        } => {}
        other => panic!("expected packet parse error, got {other:?}"),
    }
}

#[test]
fn parse_packet_rejects_invalid_magic_or_version() {
    let header = packet_header(
        SenderId(0x55),
        0x66,
        0,
        0,
        1,
        2,
        2,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );

    let mut bad_magic = encode_packet(header, &[0xAA, 0xBB]).unwrap();
    bad_magic[0..4].copy_from_slice(b"NOPE");
    let err = parse_packet(&bad_magic).unwrap_err();
    match err {
        UniUdpError::Decode {
            context: uniudp::DecodeContext::Packet,
            message: "invalid protocol magic",
            detail: Some(detail),
        } => {
            assert_eq!(detail.field, "magic");
            assert_eq!(detail.expected, "UUDP");
        }
        other => panic!("expected invalid protocol magic decode error, got {other:?}"),
    }

    let mut bad_version = encode_packet(header, &[0xAA, 0xBB]).unwrap();
    bad_version[4] = 0xFF;
    let err = parse_packet(&bad_version).unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Decode {
            context: uniudp::DecodeContext::Packet,
            message: "unsupported protocol version",
            ..
        }
    ));
}

#[test]
fn parse_packet_rejects_unsupported_flags() {
    let header = packet_header(
        SenderId(0x56),
        0x67,
        0,
        0,
        1,
        2,
        2,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );

    let mut packet = encode_packet(header, &[0xAA, 0xBB]).unwrap();
    packet[5] = 0x80;
    let err = parse_packet(&packet).unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Decode {
            context: uniudp::DecodeContext::Packet,
            message: "unsupported packet flags",
            ..
        }
    ));
}

#[test]
fn parse_packet_rejects_non_canonical_zero_group_fec_encoding() {
    let header = packet_header(
        SenderId(0x5601),
        0x6701,
        0,
        0,
        1,
        2,
        2,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );

    for invalid in [0_u16, 1_u16] {
        let mut packet = encode_packet(header, &[0xAA, 0xBB]).unwrap();
        packet[62..64].copy_from_slice(&invalid.to_be_bytes());
        let err = parse_packet(&packet).unwrap_err();
        assert!(matches!(
            err,
            UniUdpError::Decode {
                context: uniudp::DecodeContext::Packet,
                message: "invalid fec field encoding",
                ..
            }
        ));
    }
}

#[test]
fn parse_packet_rejects_auth_tag_without_flag() {
    let header = packet_header(
        SenderId(0x57),
        0x68,
        0,
        0,
        1,
        2,
        2,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );

    let mut packet = encode_packet(header, &[0xAA, 0xBB]).unwrap();
    packet[HEADER_LENGTH - 1] = 0x01;
    let err = parse_packet(&packet).unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Decode {
            context: uniudp::DecodeContext::Packet,
            message: "packet auth tag present without auth flag",
            ..
        }
    ));
}

#[test]
fn parse_packet_rejects_auth_key_id_without_flag() {
    let header = packet_header(
        SenderId(0x58),
        0x69,
        0,
        0,
        1,
        2,
        2,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );

    let mut packet = encode_packet(header, &[0xAA, 0xBB]).unwrap();
    packet[6..10].copy_from_slice(&1_u32.to_be_bytes());
    let err = parse_packet(&packet).unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Decode {
            context: uniudp::DecodeContext::Packet,
            message: "packet auth key_id present without auth flag",
            ..
        }
    ));
}

#[test]
fn parse_packet_rejects_corrupted_payload_checksum() {
    let header = packet_header(
        SenderId(0xAA),
        0xBB,
        0,
        0,
        1,
        2,
        2,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );
    let mut packet = encode_packet(header, &[0x10, 0x20]).unwrap();
    packet[HEADER_LENGTH] ^= 0xFF;

    let err = parse_packet(&packet).unwrap_err();
    match err {
        UniUdpError::Decode {
            context: uniudp::DecodeContext::Packet,
            message: "invalid packet checksum",
            detail: Some(detail),
        } => {
            assert_eq!(detail.field, "checksum");
        }
        other => panic!("expected checksum decode error, got {other:?}"),
    }
}

#[test]
fn parse_packet_rejects_trailing_bytes_beyond_declared_payload() {
    let header = packet_header(
        SenderId(0xAB),
        0xCD,
        0,
        0,
        1,
        2,
        2,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );

    let mut packet = encode_packet(header, &[0x10, 0x20]).unwrap();
    packet.push(0x99);
    let err = parse_packet(&packet).unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Decode {
            context: uniudp::DecodeContext::Packet,
            message: "packet length exceeds declared payload length",
            ..
        }
    ));
}

#[test]
fn parse_packet_rejects_invalid_attempt_metadata() {
    let header = packet_header(
        SenderId(0xAC01),
        0xCE01,
        0,
        0,
        1,
        2,
        2,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );

    let mut packet = encode_packet(header, &[0x10, 0x20]).unwrap();
    packet[TEST_ATTEMPT_OFFSET..TEST_ATTEMPT_OFFSET + 2].copy_from_slice(&2_u16.to_be_bytes());
    rewrite_packet_checksum(&mut packet);

    let err = parse_packet(&packet).unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Decode {
            context: uniudp::DecodeContext::Packet,
            message: "attempt must be within redundancy range",
            ..
        }
    ));
}

#[test]
fn parse_packet_rejects_chunk_index_out_of_bounds() {
    let header = packet_header(
        SenderId(0xAC02),
        0xCE02,
        0,
        0,
        1,
        2,
        2,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );

    let mut packet = encode_packet(header, &[0x10, 0x20]).unwrap();
    packet[42..46].copy_from_slice(&1_u32.to_be_bytes());
    rewrite_packet_checksum(&mut packet);

    let err = parse_packet(&packet).unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Decode {
            context: uniudp::DecodeContext::Packet,
            message: "chunk_index is out of bounds for total_chunks",
            ..
        }
    ));
}

#[test]
fn parse_packet_view_rejects_inconsistent_chunk_geometry() {
    let header = packet_header(
        SenderId(0xAC03),
        0xCE03,
        0,
        0,
        1,
        2,
        2,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );

    let mut packet = encode_packet(header, &[0x10, 0x20]).unwrap();
    packet[TEST_TOTAL_CHUNKS_OFFSET..TEST_TOTAL_CHUNKS_OFFSET + 4]
        .copy_from_slice(&2_u32.to_be_bytes());
    rewrite_packet_checksum(&mut packet);

    let err = parse_packet_view(&packet).unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Decode {
            context: uniudp::DecodeContext::Packet,
            message: "message metadata has inconsistent chunk geometry",
            ..
        }
    ));
}

#[test]
fn encode_packet_reports_encode_error_for_invalid_payload_geometry() {
    let header = packet_header(
        SenderId(0x77),
        9,
        0,
        0,
        2,
        3,
        2,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    );

    let err = encode_packet(header, &[0x01, 0x02, 0x03]).unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Encode {
            context: uniudp::EncodeContext::Packet,
            ..
        }
    ));
}

#[test]
fn encode_packet_rejects_invalid_attempt_metadata() {
    let err = PacketHeader::new(
        SenderId(0x7701),
        10,
        0,
        0,
        1,
        2,
        2,
        0,
        1,
        0,
        pack_fec_field(1, false).unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::HeaderWrite,
            message: "attempt must be within redundancy range",
            ..
        }
    ));
}

#[test]
fn encode_packet_rejects_inconsistent_chunk_geometry() {
    let err = PacketHeader::new(
        SenderId(0x7702),
        11,
        0,
        0,
        3,
        2,
        2,
        0,
        1,
        1,
        pack_fec_field(1, false).unwrap(),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: uniudp::ValidationContext::HeaderWrite,
            message: "message metadata has inconsistent chunk geometry",
            ..
        }
    ));
}

#[test]
fn strict_rejections_returns_decode_error_immediately() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    sender.send_to(&[0xAA; 5], destination).unwrap();

    let mut receiver = Receiver::new();
    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(SenderId(0xDEAD), 0xBEEF)),
            strict_rejections: true,
            inactivity_timeout: Duration::from_millis(60),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );
    assert!(matches!(
        err,
        Err(UniUdpError::Decode {
            context: uniudp::DecodeContext::Packet,
            ..
        })
    ));

    let diagnostics = receiver.last_receive_diagnostics();
    assert_eq!(diagnostics.packets_received, 1);
    assert_eq!(diagnostics.decode_errors, 1);
}

#[test]
fn trailing_bytes_packet_is_treated_as_decode_rejection() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let mut packet = encode_packet(
        packet_header(
            SenderId(0xAB10),
            0xCD20,
            0,
            0,
            1,
            2,
            2,
            0,
            1,
            1,
            pack_fec_field(1, false).unwrap(),
        ),
        &[0x11, 0x22],
    )
    .unwrap();
    packet.push(0x77);
    sender.send_to(&packet, destination).unwrap();

    let mut receiver = Receiver::new();
    let err = receiver.receive_message(
        &mut receiver_socket,
        receive_options! {
            key: Some(key(SenderId(0xAB10), 0xCD20)),
            inactivity_timeout: Duration::from_millis(50),
            overall_timeout: Duration::from_millis(200),
            ..ReceiveOptions::default()
        },
    );

    let diagnostics = rejected_timeout_diagnostics(err.unwrap_err());
    assert_eq!(diagnostics.packets_received, 1);
    assert_eq!(diagnostics.decode_errors, 1);
}
