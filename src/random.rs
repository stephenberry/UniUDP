//! Operating-system entropy used to seed sender identities and session nonces.
//!
//! These values must be unpredictable: a repeated `SenderId` or session nonce
//! lets a receiver conflate two senders, and nonce reuse weakens replay
//! rejection. There is no meaningful fallback if the OS cannot supply entropy,
//! so failure aborts rather than silently degrading to a predictable value.

pub(crate) fn random_u64() -> u64 {
    getrandom::u64().expect("operating system entropy source is unavailable")
}

pub(crate) fn random_u128() -> u128 {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).expect("operating system entropy source is unavailable");
    u128::from_ne_bytes(bytes)
}
