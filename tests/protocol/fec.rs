use super::common::*;

#[test]
fn conflicting_lower_attempt_chunk_payload_is_rejected() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xA3);
    let message_id = 0xFEC0_0003_u64;
    let chunk_size = 4_u16;
    let total_chunks = 2_u32;
    let message_length = 8_u32;
    let data_fec = pack_fec_field(1, false).unwrap();

    let attempt_two = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            total_chunks,
            message_length,
            chunk_size,
            0,
            2,
            2,
            data_fec,
        ),
        &[0x01, 0x02, 0x03, 0x04],
    )
    .unwrap();
    let conflicting_lower_attempt = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            total_chunks,
            message_length,
            chunk_size,
            0,
            2,
            1,
            data_fec,
        ),
        &[0xFF, 0xEE, 0xDD, 0xCC],
    )
    .unwrap();

    sender.send_to(&attempt_two, destination).unwrap();
    sender
        .send_to(&conflicting_lower_attempt, destination)
        .unwrap();

    let mut receiver = Receiver::new();
    let err = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, message_id)),
                strict_rejections: true,
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::RejectedPacket {
            reason: ReceiveRejectReason::MessageMetadata
        }
    ));
    assert_eq!(receiver.last_receive_diagnostics().metadata_rejections, 1);
}

#[test]
fn conflicting_lower_attempt_parity_payload_is_rejected() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xA4);
    let message_id = 0xFEC0_0004_u64;
    let chunk_size = 4_u16;
    let total_chunks = 2_u32;
    let message_length = 8_u32;
    let parity_fec = pack_rs_parity_field(2, 1, 0).unwrap();

    let parity_attempt_two = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            total_chunks,
            message_length,
            chunk_size,
            0,
            2,
            2,
            parity_fec,
        ),
        &[0x10, 0x11, 0x12, 0x13],
    )
    .unwrap();
    let parity_conflicting_lower_attempt = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            total_chunks,
            message_length,
            chunk_size,
            0,
            2,
            1,
            parity_fec,
        ),
        &[0x20, 0x21, 0x22, 0x23],
    )
    .unwrap();

    sender.send_to(&parity_attempt_two, destination).unwrap();
    sender
        .send_to(&parity_conflicting_lower_attempt, destination)
        .unwrap();

    let mut receiver = Receiver::new();
    let err = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, message_id)),
                strict_rejections: true,
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::RejectedPacket {
            reason: ReceiveRejectReason::MessageMetadata
        }
    ));
    assert_eq!(receiver.last_receive_diagnostics().metadata_rejections, 1);
}

#[test]
fn lower_attempt_direct_chunk_replaces_fec_recovery() {
    let sender = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let sender_id = SenderId(0xA5);
    let message_id = 0xFEC0_0005_u64;
    let chunk_size = 4_u16;
    let total_chunks = 3_u32;
    let message_length = 10_u32;

    let chunk0 = vec![0x01, 0x02, 0x03, 0x04];
    let chunk1 = vec![0x10, 0x11, 0x12, 0x13];
    let chunk2 = vec![0xAA, 0xBB];

    let data_fec = pack_rs_data_field(2, 1).unwrap();
    let parity_fec = pack_rs_parity_field(2, 1, 0).unwrap();

    // RS(2,1) parity for group 0 (chunk0, chunk1)
    let encoder = reed_solomon_erasure::galois_8::ReedSolomon::new(2, 1).unwrap();
    let data_refs: Vec<&[u8]> = vec![&chunk0, &chunk1];
    let mut parity_group_0 = vec![0u8; usize::from(chunk_size)];
    let mut parity_refs: Vec<&mut [u8]> = vec![parity_group_0.as_mut_slice()];
    encoder.encode_sep(&data_refs, &mut parity_refs).unwrap();

    let packet0 = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            total_chunks,
            message_length,
            chunk_size,
            0,
            1,
            1,
            data_fec,
        ),
        &chunk0,
    )
    .unwrap();
    let parity_packet = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            0,
            total_chunks,
            message_length,
            chunk_size,
            0,
            1,
            1,
            parity_fec,
        ),
        &parity_group_0,
    )
    .unwrap();
    let direct_chunk1 = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            1,
            total_chunks,
            message_length,
            chunk_size,
            0,
            1,
            1,
            data_fec,
        ),
        &chunk1,
    )
    .unwrap();
    let packet2 = encode_packet(
        packet_header(
            sender_id,
            message_id,
            0,
            2,
            total_chunks,
            message_length,
            chunk_size,
            0,
            1,
            1,
            data_fec,
        ),
        &chunk2,
    )
    .unwrap();

    // Order matters: parity recovers chunk 1 first, then direct chunk 1 should
    // replace recovered data and clear recovery markers.
    sender.send_to(&packet0, destination).unwrap();
    sender.send_to(&parity_packet, destination).unwrap();
    sender.send_to(&direct_chunk1, destination).unwrap();
    sender.send_to(&packet2, destination).unwrap();

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut receiver_socket,
            receive_options! {
                key: Some(key(sender_id, message_id)),
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(
        report.materialize_payload_lossy(),
        vec![0x01, 0x02, 0x03, 0x04, 0x10, 0x11, 0x12, 0x13, 0xAA, 0xBB]
    );
    assert!(report.fec_recovered_chunks.is_empty());
    assert_eq!(report.redundancy_required, 1);
}

// --- Reed-Solomon tests ---

#[test]
fn rs_send_receive_recovers_single_missing_chunk() {
    let sender_socket = bind_local();
    let receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let payload: Vec<u8> = (0..32).collect();
    let chunk_size = 8_u16;
    let data_shards = 4_u8;
    let parity_shards = 2_u8;

    let sender_id = SenderId(0xB501);
    let session_nonce = 0x0102_0304_0506_0708_u64;
    let tx = Sender::with_identity(sender_id, session_nonce);

    let send_opts = SendOptions::new()
        .with_redundancy(1)
        .with_chunk_size(chunk_size)
        .with_fec_mode(FecMode::ReedSolomon {
            data_shards,
            parity_shards,
        });

    // Capture all packets.
    let destination2 = destination;
    let sender_thread = thread::spawn(move || {
        tx.send_with_socket(
            &sender_socket,
            SendRequest::new(destination2, &payload).with_options(send_opts),
        )
        .unwrap()
    });

    // 4 data + 2 parity = 6 packets
    let mut packets = Vec::new();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    for _ in 0..6 {
        let mut buf = vec![0_u8; 2048];
        let (len, _) = receiver_socket.recv_from(&mut buf).unwrap();
        packets.push(buf[..len].to_vec());
    }
    let key = sender_thread.join().unwrap();

    // Drop chunk index 1 (the second data packet)
    // Identify it: non-parity packet with chunk_index == 1
    let mut filtered: Vec<Vec<u8>> = Vec::new();
    for pkt in &packets {
        let (header, _) = parse_packet(pkt).unwrap();
        if !fec_is_parity(header.fec_field()) && header.chunk_index() == 1 {
            continue; // drop this chunk
        }
        filtered.push(pkt.clone());
    }
    assert_eq!(filtered.len(), 5); // 3 data + 2 parity

    // Replay to a new receiver socket
    let mut rx_socket2 = bind_local();
    let dest2 = rx_socket2.local_addr().unwrap();
    let replay_socket = bind_local();
    for pkt in &filtered {
        replay_socket.send_to(pkt, dest2).unwrap();
    }

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut rx_socket2,
            receive_options! {
                key: Some(key),
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(
        report.materialize_payload_lossy(),
        (0..32).collect::<Vec<u8>>()
    );
    assert!(report.fec_recovered_chunks.contains(&1));
    assert!(report.lost_chunks.is_empty());
    assert_eq!(report.completion_reason, CompletionReason::Completed);
}

#[test]
fn rs_send_receive_recovers_two_missing_chunks() {
    let sender_socket = bind_local();
    let receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let payload: Vec<u8> = (0..32).collect();
    let chunk_size = 8_u16;
    let data_shards = 4_u8;
    let parity_shards = 2_u8;

    let sender_id = SenderId(0xB502);
    let session_nonce = 0x0102_0304_0506_0708_u64;
    let tx = Sender::with_identity(sender_id, session_nonce);

    let send_opts = SendOptions::new()
        .with_redundancy(1)
        .with_chunk_size(chunk_size)
        .with_fec_mode(FecMode::ReedSolomon {
            data_shards,
            parity_shards,
        });

    let destination2 = destination;
    let sender_thread = thread::spawn(move || {
        tx.send_with_socket(
            &sender_socket,
            SendRequest::new(destination2, &payload).with_options(send_opts),
        )
        .unwrap()
    });

    let mut packets = Vec::new();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    for _ in 0..6 {
        let mut buf = vec![0_u8; 2048];
        let (len, _) = receiver_socket.recv_from(&mut buf).unwrap();
        packets.push(buf[..len].to_vec());
    }
    let key = sender_thread.join().unwrap();

    // Drop chunk indices 0 and 2
    let mut filtered: Vec<Vec<u8>> = Vec::new();
    for pkt in &packets {
        let (header, _) = parse_packet(pkt).unwrap();
        if !fec_is_parity(header.fec_field())
            && (header.chunk_index() == 0 || header.chunk_index() == 2)
        {
            continue;
        }
        filtered.push(pkt.clone());
    }
    assert_eq!(filtered.len(), 4); // 2 data + 2 parity

    let mut rx_socket2 = bind_local();
    let dest2 = rx_socket2.local_addr().unwrap();
    let replay_socket = bind_local();
    for pkt in &filtered {
        replay_socket.send_to(pkt, dest2).unwrap();
    }

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut rx_socket2,
            receive_options! {
                key: Some(key),
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(
        report.materialize_payload_lossy(),
        (0..32).collect::<Vec<u8>>()
    );
    assert!(report.fec_recovered_chunks.contains(&0));
    assert!(report.fec_recovered_chunks.contains(&2));
    assert!(report.lost_chunks.is_empty());
    assert_eq!(report.completion_reason, CompletionReason::Completed);
}

#[test]
fn rs_too_many_missing_chunks_fails() {
    let sender_socket = bind_local();
    let receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let payload: Vec<u8> = (0..32).collect();
    let chunk_size = 8_u16;
    let data_shards = 4_u8;
    let parity_shards = 2_u8;

    let sender_id = SenderId(0xB503);
    let session_nonce = 0x0102_0304_0506_0708_u64;
    let tx = Sender::with_identity(sender_id, session_nonce);

    let send_opts = SendOptions::new()
        .with_redundancy(1)
        .with_chunk_size(chunk_size)
        .with_fec_mode(FecMode::ReedSolomon {
            data_shards,
            parity_shards,
        });

    let destination2 = destination;
    let sender_thread = thread::spawn(move || {
        tx.send_with_socket(
            &sender_socket,
            SendRequest::new(destination2, &payload).with_options(send_opts),
        )
        .unwrap()
    });

    let mut packets = Vec::new();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    for _ in 0..6 {
        let mut buf = vec![0_u8; 2048];
        let (len, _) = receiver_socket.recv_from(&mut buf).unwrap();
        packets.push(buf[..len].to_vec());
    }
    let key = sender_thread.join().unwrap();

    // Drop 3 chunks (0, 1, 2) — exceeds parity_shards=2 recovery capacity
    let mut filtered: Vec<Vec<u8>> = Vec::new();
    for pkt in &packets {
        let (header, _) = parse_packet(pkt).unwrap();
        if !fec_is_parity(header.fec_field())
            && (header.chunk_index() == 0 || header.chunk_index() == 1 || header.chunk_index() == 2)
        {
            continue;
        }
        filtered.push(pkt.clone());
    }
    assert_eq!(filtered.len(), 3); // 1 data + 2 parity

    let mut rx_socket2 = bind_local();
    let dest2 = rx_socket2.local_addr().unwrap();
    let replay_socket = bind_local();
    for pkt in &filtered {
        replay_socket.send_to(pkt, dest2).unwrap();
    }

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut rx_socket2,
            receive_options! {
                key: Some(key),
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    // Should NOT fully recover — 3 missing > 2 parity shards
    assert!(!report.lost_chunks.is_empty());
    assert_eq!(
        report.completion_reason,
        CompletionReason::InactivityTimeout
    );
}

#[test]
fn rs_send_emits_expected_parity_packet_count() {
    let sender_socket = bind_local();
    let receiver_socket = bind_local();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let destination = receiver_socket.local_addr().unwrap();

    let payload: Vec<u8> = (0..48).collect();
    let chunk_size = 8_u16;
    let data_shards = 4_u8;
    let parity_shards = 3_u8;

    let total_chunks = payload.len().div_ceil(usize::from(chunk_size)); // 6
    let num_groups = total_chunks.div_ceil(usize::from(data_shards)); // 2
    let expected_parity = num_groups * usize::from(parity_shards); // 6
    let expected_total = total_chunks + expected_parity; // 12

    let sender_id = SenderId(0xB504);
    let session_nonce = 0x0102_0304_0506_0708_u64;
    let tx = Sender::with_identity(sender_id, session_nonce);

    let send_opts = SendOptions::new()
        .with_redundancy(1)
        .with_chunk_size(chunk_size)
        .with_fec_mode(FecMode::ReedSolomon {
            data_shards,
            parity_shards,
        });

    let sender_thread = thread::spawn(move || {
        tx.send_with_socket(
            &sender_socket,
            SendRequest::new(destination, &payload).with_options(send_opts),
        )
        .unwrap()
    });

    let mut data_seen = 0_usize;
    let mut parity_seen = 0_usize;
    for _ in 0..expected_total {
        let mut buf = vec![0_u8; 2048];
        let (len, _) = receiver_socket.recv_from(&mut buf).unwrap();
        let (header, _) = parse_packet(&buf[..len]).unwrap();
        if fec_is_parity(header.fec_field()) {
            parity_seen += 1;
        } else {
            data_seen += 1;
        }
    }

    sender_thread.join().unwrap();
    assert_eq!(data_seen, total_chunks);
    assert_eq!(parity_seen, expected_parity);
}

#[test]
fn rs_partial_final_group_recovery() {
    // Test with a payload that doesn't fill the last RS group completely.
    let sender_socket = bind_local();
    let receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    // 5 chunks with data_shards=4: group0 = [0,1,2,3], group1 = [4] (partial)
    let payload: Vec<u8> = (0..40).collect();
    let chunk_size = 8_u16;
    let data_shards = 4_u8;
    let parity_shards = 2_u8;

    let sender_id = SenderId(0xB505);
    let session_nonce = 0x0102_0304_0506_0708_u64;
    let tx = Sender::with_identity(sender_id, session_nonce);

    let send_opts = SendOptions::new()
        .with_redundancy(1)
        .with_chunk_size(chunk_size)
        .with_fec_mode(FecMode::ReedSolomon {
            data_shards,
            parity_shards,
        });

    let destination2 = destination;
    let sender_thread = thread::spawn(move || {
        tx.send_with_socket(
            &sender_socket,
            SendRequest::new(destination2, &payload).with_options(send_opts),
        )
        .unwrap()
    });

    // 5 data + 2 parity(group0) + 2 parity(group1) = 9 packets
    let mut packets = Vec::new();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    for _ in 0..9 {
        let mut buf = vec![0_u8; 2048];
        let (len, _) = receiver_socket.recv_from(&mut buf).unwrap();
        packets.push(buf[..len].to_vec());
    }
    let key = sender_thread.join().unwrap();

    // Drop chunk 1 from group 0
    let mut filtered: Vec<Vec<u8>> = Vec::new();
    for pkt in &packets {
        let (header, _) = parse_packet(pkt).unwrap();
        if !fec_is_parity(header.fec_field()) && header.chunk_index() == 1 {
            continue;
        }
        filtered.push(pkt.clone());
    }
    assert_eq!(filtered.len(), 8);

    let mut rx_socket2 = bind_local();
    let dest2 = rx_socket2.local_addr().unwrap();
    let replay_socket = bind_local();
    for pkt in &filtered {
        replay_socket.send_to(pkt, dest2).unwrap();
    }

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut rx_socket2,
            receive_options! {
                key: Some(key),
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(
        report.materialize_payload_lossy(),
        (0..40).collect::<Vec<u8>>()
    );
    assert!(report.fec_recovered_chunks.contains(&1));
    assert!(report.lost_chunks.is_empty());
    assert_eq!(report.completion_reason, CompletionReason::Completed);
}

#[test]
fn rs_fec_mode_reported_in_message_report() {
    let sender_socket = bind_local();
    let mut receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let payload = vec![0xAA; 16];
    let data_shards = 2_u8;
    let parity_shards = 1_u8;

    let sender_id = SenderId(0xB506);
    let session_nonce = 0x0102_0304_0506_0708_u64;
    let tx = Sender::with_identity(sender_id, session_nonce);

    let send_opts = SendOptions::new()
        .with_redundancy(1)
        .with_chunk_size(8)
        .with_fec_mode(FecMode::ReedSolomon {
            data_shards,
            parity_shards,
        });

    let destination2 = destination;
    let sender_thread = thread::spawn(move || {
        tx.send_with_socket(
            &sender_socket,
            SendRequest::new(destination2, &payload).with_options(send_opts),
        )
        .unwrap()
    });

    let key = sender_thread.join().unwrap();

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

    assert!(matches!(
        report.fec_mode,
        FecMode::ReedSolomon {
            data_shards: 2,
            parity_shards: 1
        }
    ));
    assert_eq!(report.fec_mode.effective_group_size(), 2);
}

#[test]
fn rs_partial_final_group_recovers_sole_real_chunk() {
    // Regression: partial final group where the only real data chunk is missing.
    // The implicit zero-filled padding shards must count toward RS availability,
    // otherwise the availability check incorrectly skips reconstruction.
    //
    // RS(4,2): 5 chunks total → group0 = [0,1,2,3], group1 = [4] (+ 3 zero pads).
    // Drop chunk 4. Available for group1: 0 data + 3 implicit zeros + 2 parity = 5 >= 4.
    let sender_socket = bind_local();
    let receiver_socket = bind_local();
    let destination = receiver_socket.local_addr().unwrap();

    let payload: Vec<u8> = (0..40).collect();
    let chunk_size = 8_u16;
    let data_shards = 4_u8;
    let parity_shards = 2_u8;

    let sender_id = SenderId(0xB507);
    let session_nonce = 0x0102_0304_0506_0708_u64;
    let tx = Sender::with_identity(sender_id, session_nonce);

    let send_opts = SendOptions::new()
        .with_redundancy(1)
        .with_chunk_size(chunk_size)
        .with_fec_mode(FecMode::ReedSolomon {
            data_shards,
            parity_shards,
        });

    let destination2 = destination;
    let sender_thread = thread::spawn(move || {
        tx.send_with_socket(
            &sender_socket,
            SendRequest::new(destination2, &payload).with_options(send_opts),
        )
        .unwrap()
    });

    // 5 data + 2 parity(group0) + 2 parity(group1) = 9 packets
    let mut packets = Vec::new();
    receiver_socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    for _ in 0..9 {
        let mut buf = vec![0_u8; 2048];
        let (len, _) = receiver_socket.recv_from(&mut buf).unwrap();
        packets.push(buf[..len].to_vec());
    }
    let key = sender_thread.join().unwrap();

    // Drop chunk 4 (the sole real data chunk in the partial final group)
    let mut filtered: Vec<Vec<u8>> = Vec::new();
    for pkt in &packets {
        let (header, _) = parse_packet(pkt).unwrap();
        if !fec_is_parity(header.fec_field()) && header.chunk_index() == 4 {
            continue;
        }
        filtered.push(pkt.clone());
    }
    assert_eq!(filtered.len(), 8);

    let mut rx_socket2 = bind_local();
    let dest2 = rx_socket2.local_addr().unwrap();
    let replay_socket = bind_local();
    for pkt in &filtered {
        replay_socket.send_to(pkt, dest2).unwrap();
    }

    let mut receiver = Receiver::new();
    let report = receiver
        .receive_message(
            &mut rx_socket2,
            receive_options! {
                key: Some(key),
                inactivity_timeout: Duration::from_millis(200),
                overall_timeout: Duration::from_secs(2),
                ..ReceiveOptions::default()
            },
        )
        .unwrap();

    assert_eq!(
        report.materialize_payload_lossy(),
        (0..40).collect::<Vec<u8>>()
    );
    assert!(report.fec_recovered_chunks.contains(&4));
    assert!(report.lost_chunks.is_empty());
    assert_eq!(report.completion_reason, CompletionReason::Completed);
}
