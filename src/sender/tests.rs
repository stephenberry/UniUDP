use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};

use super::{MessageIdStart, SendFailure, SendRequest, Sender, SenderId};
use crate::types::{SendIdentityOverrides, SendOptions};
use crate::{UniUdpError, ValidationContext};

#[test]
fn sender_tracking_fails_closed_when_capacity_is_reached() {
    let sender = Sender::try_with_identity_and_limits(SenderId(0xAA), 0x11, 2).unwrap();
    assert_eq!(sender.max_tracked_senders(), 2);
    let session_nonce = 0x11;

    sender
        .reserve_message_id(SenderId(1), session_nonce, Some(100))
        .unwrap();
    sender
        .reserve_message_id(SenderId(2), session_nonce, Some(200))
        .unwrap();
    sender
        .reserve_message_id(SenderId(1), session_nonce, Some(101))
        .unwrap();

    let overflow = sender
        .reserve_message_id(SenderId(3), session_nonce, Some(300))
        .unwrap_err();
    assert!(matches!(
        overflow,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message:
                "max_tracked_senders exceeded; refusing to weaken explicit message_id monotonicity",
            ..
        }
    ));

    let retained_sender_err = sender
        .reserve_message_id(SenderId(2), session_nonce, Some(50))
        .unwrap_err();
    assert!(matches!(
        retained_sender_err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message:
                "explicit message_id must be > highest previously sent message_id for sender/session",
            ..
        }
    ));

    sender
        .reserve_message_id(SenderId(2), session_nonce, Some(201))
        .unwrap();
}

#[test]
fn sender_tracking_capacity_is_bounded() {
    let sender = Sender::try_with_identity_and_limits(SenderId(0xAB), 0x22, 3).unwrap();
    let session_nonce = 0x22;

    sender
        .reserve_message_id(SenderId(1), session_nonce, Some(1))
        .unwrap();
    sender
        .reserve_message_id(SenderId(2), session_nonce, Some(2))
        .unwrap();
    sender
        .reserve_message_id(SenderId(3), session_nonce, Some(3))
        .unwrap();
    let err = sender
        .reserve_message_id(SenderId(4), session_nonce, Some(4))
        .unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message:
                "max_tracked_senders exceeded; refusing to weaken explicit message_id monotonicity",
            ..
        }
    ));

    let tracking = match sender.highest_sent_message_by_sender.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert_eq!(tracking.tracked_identities(), 3);
}

#[test]
fn auto_message_id_for_new_sender_fails_closed_when_tracking_is_full() {
    let sender = Sender::try_with_identity_and_limits(SenderId(0xAF), 0x55, 1).unwrap();
    let session_nonce = 0x55;
    sender
        .reserve_message_id(SenderId(1), session_nonce, Some(10))
        .expect("initial tracked sender should be accepted");

    let auto_err = sender
        .reserve_message_id(SenderId(2), session_nonce, None)
        .expect_err("automatic message id should fail-closed for untracked sender at capacity");
    assert!(matches!(
        auto_err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message: "max_tracked_senders exceeded; refusing to weaken message_id monotonicity",
            ..
        }
    ));

    let explicit_err = sender
        .reserve_message_id(SenderId(2), session_nonce, Some(11))
        .expect_err("explicit message id should fail-closed when tracking is full");
    assert!(matches!(
        explicit_err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message:
                "max_tracked_senders exceeded; refusing to weaken explicit message_id monotonicity",
            ..
        }
    ));

    let tracking = match sender.highest_sent_message_by_sender.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    assert_eq!(tracking.tracked_identities(), 1);
    assert_eq!(
        tracking.current_highest(SenderId(1), session_nonce),
        Some(10)
    );
    assert_eq!(tracking.current_highest(SenderId(2), session_nonce), None);
}

#[test]
fn auto_message_id_updates_monotonicity_for_tracked_sender() {
    let sender = Sender::try_with_identity_and_limits(SenderId(0xB0), 0x66, 1).unwrap();
    let session_nonce = 0x66;
    let auto_id = sender
        .reserve_message_id(SenderId(7), session_nonce, None)
        .expect("automatic message id should be generated");

    let err = sender
        .reserve_message_id(SenderId(7), session_nonce, Some(auto_id))
        .expect_err("explicit id equal to tracked auto id must be rejected");
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message:
                "explicit message_id must be > highest previously sent message_id for sender/session",
            ..
        }
    ));
}

#[test]
fn explicit_message_id_monotonicity_is_scoped_by_session_nonce() {
    let sender = Sender::try_with_identity_and_limits(SenderId(0xB1), 0x10, 4).unwrap();
    let sender_id = SenderId(0x90);

    sender
        .reserve_message_id(sender_id, 10, Some(100))
        .expect("first explicit id in session 10 should be accepted");
    sender
        .reserve_message_id(sender_id, 11, Some(0))
        .expect("newer session nonce should have independent explicit monotonic tracking");

    let same_session_err = sender
        .reserve_message_id(sender_id, 10, Some(99))
        .expect_err("lower explicit id in same session should be rejected");
    assert!(matches!(
        same_session_err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message:
                "explicit message_id must be > highest previously sent message_id for sender/session",
            ..
        }
    ));
}

#[test]
fn try_with_identity_and_limits_rejects_zero_capacity() {
    let err = Sender::try_with_identity_and_limits(SenderId(0xA0), 0x10, 0).unwrap_err();
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message: "max_tracked_senders must be positive",
            ..
        }
    ));
}

#[test]
fn reserve_message_id_rejects_equal_explicit_id() {
    let sender = Sender::try_with_identity_and_limits(SenderId(0xAC), 0x33, 3).unwrap();
    let session_nonce = 0x33;
    sender
        .reserve_message_id(SenderId(0x77), session_nonce, Some(42))
        .expect("first explicit message id should be accepted");

    let err = sender
        .reserve_message_id(SenderId(0x77), session_nonce, Some(42))
        .expect_err("equal explicit message id must be rejected");
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message:
                "explicit message_id must be > highest previously sent message_id for sender/session",
            ..
        }
    ));
}

#[test]
fn reset_session_allows_message_id_restart_from_zero() {
    let mut sender = Sender::try_with_identity_and_limits(SenderId(0xAD), 0x44, 3).unwrap();
    sender
        .reserve_message_id(SenderId(0x66), 0x44, Some(100))
        .expect("first explicit id should be accepted");
    sender
        .reset_session(0x45)
        .expect("higher session nonce reset should succeed");
    sender
        .reserve_message_id(SenderId(0x66), 0x45, Some(0))
        .expect("reset must clear strict monotonic cache for new session");
    assert_eq!(sender.next_message_id(), 1);
}

#[test]
fn reset_session_explicit_one_then_auto_stays_monotonic() {
    let mut sender = Sender::try_with_identity_and_limits(SenderId(0xB2), 0x50, 3).unwrap();
    sender
        .reset_session(0x51)
        .expect("reset should succeed for higher nonce");
    sender
        .reserve_message_id(SenderId(0xA1), 0x51, Some(1))
        .expect("explicit id should be accepted");
    assert_eq!(sender.next_message_id(), 2);
}

#[test]
fn reset_session_explicit_zero_then_auto_is_non_duplicate() {
    let mut sender = Sender::try_with_identity_and_limits(SenderId(0xB3), 0x60, 3).unwrap();
    sender
        .reset_session(0x61)
        .expect("reset should succeed for higher nonce");
    sender
        .reserve_message_id(SenderId(0xA2), 0x61, Some(0))
        .expect("explicit zero should be accepted");
    assert_eq!(sender.next_message_id(), 1);
}

#[test]
fn reset_session_preserves_monotonicity_for_unrelated_override_identity() {
    let mut sender = Sender::try_with_identity_and_limits(SenderId(0xB4), 0x70, 8).unwrap();
    let override_sender = SenderId(0xE1);
    let override_session = 0xABC;

    sender
        .reserve_message_id(override_sender, override_session, Some(100))
        .expect("first explicit id for override identity should be accepted");

    sender
        .reset_session(0x71)
        .expect("reset should succeed for higher nonce");

    let err = sender
        .reserve_message_id(override_sender, override_session, Some(50))
        .expect_err("lower explicit id should remain rejected for unrelated identity");
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message:
                "explicit message_id must be > highest previously sent message_id for sender/session",
            ..
        }
    ));
}

#[test]
fn reset_session_preserves_auto_monotonicity_for_unrelated_override_identity() {
    let mut sender = Sender::try_with_identity_and_limits(SenderId(0xB5), 0x80, 8).unwrap();
    let override_sender = SenderId(0xE2);
    let override_session = 0xABD;

    let first_auto = sender
        .reserve_message_id(override_sender, override_session, None)
        .expect("first auto id for override identity should be accepted");
    sender
        .reset_session(0x81)
        .expect("reset should succeed for different nonce");
    let second_auto = sender
        .reserve_message_id(override_sender, override_session, None)
        .expect("second auto id for override identity should be accepted");

    assert!(
        second_auto > first_auto,
        "automatic ids for unrelated override identities must remain monotonic across reset_session"
    );
}

#[test]
fn reset_session_auto_override_fails_when_identity_is_at_u64_max() {
    let mut sender = Sender::try_with_identity_and_limits(SenderId(0xB6), 0x90, 8).unwrap();
    let override_sender = SenderId(0xE3);
    let override_session = 0xABE;

    sender
        .reserve_message_id(override_sender, override_session, Some(u64::MAX))
        .expect("explicit max id should be accepted for new override identity");
    sender
        .reset_session(0x91)
        .expect("reset should succeed for different nonce");

    let err = sender
        .reserve_message_id(override_sender, override_session, None)
        .expect_err("automatic id must fail when monotonic floor would overflow");
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message: "automatic message_id space exhausted for current session",
            ..
        }
    ));
}

#[test]
fn reset_session_with_tracking_full_rejects_auto_for_untracked_override_identity() {
    let mut sender = Sender::try_with_identity_and_limits(SenderId(0xB7), 0xA0, 1).unwrap();
    let tracked_sender = SenderId(0xE4);
    let tracked_session = 0xABF;
    let override_sender = SenderId(0xE5);
    let override_session = 0xAC0;

    sender
        .reserve_message_id(tracked_sender, tracked_session, Some(1))
        .expect("initial tracked identity should be accepted");
    sender
        .reset_session(0xA1)
        .expect("reset should succeed for different nonce");

    let err = sender
        .reserve_message_id(override_sender, override_session, None)
        .expect_err("auto ids for untracked identities must fail-closed when full");
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message: "max_tracked_senders exceeded; refusing to weaken message_id monotonicity",
            ..
        }
    ));
}

#[test]
fn reset_session_requires_different_nonce() {
    let mut sender = Sender::try_with_identity_and_limits(SenderId(0xAE), 0x10, 3).unwrap();
    let same_nonce = sender
        .reset_session(0x10)
        .expect_err("same nonce must be rejected");
    assert!(matches!(
        same_nonce,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message: "new session_nonce must differ from current session_nonce",
            ..
        }
    ));
    assert!(sender.reset_session(0x09).is_ok());
    assert!(sender.reset_session(0x11).is_ok());
}

#[test]
fn sender_builder_default_starts_message_id_from_zero() {
    let sender = Sender::builder()
        .with_sender_id(SenderId(0xAA00))
        .with_session_nonce(0xBB00)
        .build()
        .expect("builder defaults should be valid");
    let first = sender
        .reserve_message_key()
        .expect("first reservation should succeed");
    let second = sender
        .reserve_message_key()
        .expect("second reservation should succeed");
    assert_eq!(first.message_id, 0);
    assert_eq!(second.message_id, 1);
}

#[test]
fn sender_builder_allows_explicit_sender_id_with_random_default_nonce() {
    let sender = Sender::builder()
        .with_sender_id(SenderId(0xAA12))
        .build()
        .expect("explicit sender_id should work with random default nonce");
    assert_eq!(sender.sender_id(), SenderId(0xAA12));
}

#[test]
fn sender_builder_can_start_from_explicit_next_message_id() {
    let sender = Sender::builder()
        .with_sender_id(SenderId(0xAA11))
        .with_session_nonce(0xBB11)
        .with_message_id_start(MessageIdStart::Next(42))
        .build()
        .expect("builder configuration should be valid");
    let first = sender
        .reserve_message_key()
        .expect("first reservation should succeed");
    let second = sender
        .reserve_message_key()
        .expect("second reservation should succeed");
    assert_eq!(first.message_id, 42);
    assert_eq!(second.message_id, 43);
}

#[test]
fn sender_builder_next_zero_starts_from_zero() {
    let sender = Sender::builder()
        .with_sender_id(SenderId(0xAA13))
        .with_session_nonce(0xBB13)
        .with_message_id_start(MessageIdStart::Next(0))
        .build()
        .expect("builder configuration should be valid");
    let first = sender
        .reserve_message_key()
        .expect("first reservation should succeed");
    let second = sender
        .reserve_message_key()
        .expect("second reservation should succeed");
    assert_eq!(first.message_id, 0);
    assert_eq!(second.message_id, 1);
}

#[test]
fn automatic_message_id_exhaustion_fails_closed() {
    let sender = Sender::builder()
        .with_sender_id(SenderId(0xAA14))
        .with_session_nonce(0xBB14)
        .with_message_id_start(MessageIdStart::Next(u64::MAX))
        .build()
        .expect("builder configuration should be valid");
    let first = sender
        .reserve_message_key()
        .expect("first reservation should succeed");
    assert_eq!(first.message_id, u64::MAX);

    let err = sender
        .reserve_message_key()
        .expect_err("automatic allocation must fail closed at u64::MAX exhaustion");
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message: "automatic message_id space exhausted for current session",
            ..
        }
    ));
}

#[test]
fn sender_rejects_cross_process_usage() {
    let mut sender = Sender::with_identity(SenderId(0xAA22), 0xBB22);
    sender.creator_pid = sender.creator_pid.wrapping_add(1);

    let err = sender
        .reserve_message_key()
        .expect_err("cross-process sender usage must fail closed");
    assert!(matches!(
        err,
        UniUdpError::Validation {
            context: ValidationContext::SendOptions,
            message:
                "sender instance cannot be used across process boundaries; construct a new Sender",
            ..
        }
    ));
}

#[test]
fn reserve_message_key_with_identity_overrides_sender_and_session() {
    let sender = Sender::with_identity(SenderId(0xAA22), 0xBB22);
    let key = sender
        .reserve_message_key_with_identity(
            &SendIdentityOverrides::new()
                .with_sender_id(SenderId(0xCC33))
                .with_session_nonce(0xDD44)
                .with_message_id(7),
        )
        .expect("identity overrides should be applied to reservation");
    assert_eq!(key.sender_id, SenderId(0xCC33));
    assert_eq!(key.session_nonce, 0xDD44);
    assert_eq!(key.message_id, 7);
}

#[test]
fn send_with_socket_preflight_error_has_no_key_context() {
    let sender = Sender::with_identity(SenderId(0xAA30), 0xBB30);
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind sender socket");
    let destination = socket.local_addr().expect("local addr");
    let invalid_options = SendOptions::new().with_chunk_size(0);

    let err = sender
        .send_with_socket(
            &socket,
            SendRequest::new(destination, b"payload").with_options(invalid_options),
        )
        .expect_err("invalid options should fail during preflight");

    assert!(matches!(err, SendFailure::Preflight(_)));
    assert_eq!(err.key(), None);
    assert_eq!(err.packets_sent(), 0);
}

#[test]
fn send_with_socket_emission_error_exposes_reserved_key_and_progress() {
    let sender = Sender::with_identity(SenderId(0xAA31), 0xBB31);
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind ipv4 sender socket");
    let ipv6_destination = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 9999, 0, 0));

    let err = sender
        .send_with_socket(&socket, SendRequest::new(ipv6_destination, b"payload"))
        .expect_err("ipv4 socket sending to ipv6 destination should fail");

    let reserved_key = err
        .key()
        .expect("emission failure should expose reserved key");
    assert_eq!(reserved_key.sender_id, sender.sender_id());
    assert_eq!(reserved_key.session_nonce, sender.session_nonce());
    assert_eq!(reserved_key.message_id, 0);
    assert_eq!(err.packets_sent(), 0);
    assert!(matches!(err, SendFailure::Emission { .. }));

    let next = sender
        .reserve_message_key()
        .expect("failed emission should still consume reserved message_id");
    assert_eq!(next.message_id, 1);
}
