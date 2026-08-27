//! HMAC-SHA256 (RFC 2104) over the `sha2` crate's SHA-256 implementation.
//!
//! This is a direct implementation of the ipad/opad construction rather than a
//! dependency on the `hmac` crate. The reason is dependency weight, not speed:
//! `hmac` pulls `digest/mac`, which in turn pulls `ctutils` and `cmov`. All of
//! the actual hashing still runs through `sha2`, so the hardware SHA-256
//! backends (ARMv8 crypto extensions, x86 SHA-NI) are used exactly as before.
//!
//! Correctness is pinned to the RFC 4231 test vectors in the tests below.

use std::hint::black_box;

use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// SHA-256 block size in bytes; the width of the HMAC pads.
const BLOCK_LENGTH: usize = 64;

const IPAD_BYTE: u8 = 0x36;
const OPAD_BYTE: u8 = 0x5c;

/// An in-progress HMAC-SHA256 computation.
///
/// Feed the message with [`update`](Self::update), then finish with either
/// [`finalize_truncated`](Self::finalize_truncated) to produce a tag or
/// [`verify_truncated_left`](Self::verify_truncated_left) to check one.
pub(crate) struct HmacSha256 {
    inner: Sha256,
    /// Retained until finalization so the outer digest can be started then.
    opad: [u8; BLOCK_LENGTH],
}

impl HmacSha256 {
    /// Starts an HMAC keyed with `key`, which may be any length.
    ///
    /// Per RFC 2104, keys longer than the block size are replaced by their
    /// SHA-256 digest, and shorter keys are zero-padded to the block size.
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut padded_key = [0_u8; BLOCK_LENGTH];
        if key.len() > BLOCK_LENGTH {
            padded_key[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            padded_key[..key.len()].copy_from_slice(key);
        }

        let mut ipad = [0_u8; BLOCK_LENGTH];
        let mut opad = [0_u8; BLOCK_LENGTH];
        for index in 0..BLOCK_LENGTH {
            ipad[index] = padded_key[index] ^ IPAD_BYTE;
            opad[index] = padded_key[index] ^ OPAD_BYTE;
        }
        padded_key.zeroize();

        // Passed as a slice, not as the array: `update` takes `impl AsRef<[u8]>`
        // by value, so handing it the array would copy the pad into the callee's
        // frame, where the `zeroize` below cannot reach it.
        let mut inner = Sha256::new();
        inner.update(ipad.as_slice());
        ipad.zeroize();

        Self { inner, opad }
    }

    /// Appends `data` to the message being authenticated.
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finishes the MAC and returns its leading `N` bytes.
    ///
    /// `N` is checked at compile time. The upper bound is the 32-byte SHA-256
    /// output. The lower bound matters more than it looks: a zero-length tag
    /// would make [`verify_truncated_left`](Self::verify_truncated_left) accept
    /// everything, so shrinking `PACKET_AUTH_TAG_LENGTH` to nothing fails to
    /// build rather than silently disabling authentication.
    pub(crate) fn finalize_truncated<const N: usize>(self) -> [u8; N] {
        const { assert!(N > 0 && N <= 32, "tag must be 1..=32 bytes") };
        let full = self.finalize();
        let mut truncated = [0_u8; N];
        truncated.copy_from_slice(&full[..N]);
        truncated
    }

    /// Checks `tag` against the leading `N` bytes of the MAC in constant time.
    ///
    /// Truncation matches [`finalize_truncated`](Self::finalize_truncated), so
    /// the two are symmetric. Comparison time depends only on `N`, never on
    /// where or whether the bytes differ, so a forgery attempt learns nothing
    /// from how long rejection took.
    pub(crate) fn verify_truncated_left<const N: usize>(self, tag: &[u8; N]) -> bool {
        let expected = self.finalize_truncated::<N>();
        constant_time_eq(&expected, tag)
    }

    fn finalize(mut self) -> [u8; 32] {
        // `Self` implements `Drop` to clear `opad`, so the inner state has to be
        // taken by replacement rather than moved out.
        let inner = std::mem::take(&mut self.inner).finalize();
        let mut outer = Sha256::new();
        outer.update(self.opad.as_slice());
        outer.update(inner);
        outer.finalize().into()
    }
}

impl Drop for HmacSha256 {
    fn drop(&mut self) {
        // `opad` is the key XOR a constant, so it is key-equivalent material.
        // The digest states absorbed the pads too, and the chaining values they
        // hold are forgery-equivalent for this key; those clear themselves
        // because `sha2` is built with its `zeroize` feature. Between the two,
        // no key-derived bytes we own outlive this value.
        self.opad.zeroize();
    }
}

/// Compares two equal-length byte strings without an input-dependent branch.
///
/// The difference is accumulated with `|` so every byte is always examined,
/// and the accumulator passes through [`black_box`] so the optimizer cannot
/// recover an early exit from it.
fn constant_time_eq<const N: usize>(left: &[u8; N], right: &[u8; N]) -> bool {
    let mut difference = 0_u8;
    for index in 0..N {
        difference |= left[index] ^ right[index];
    }
    black_box(difference) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mac(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new(key);
        mac.update(data);
        mac.finalize()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    // RFC 4231, section 4.2.
    #[test]
    fn rfc4231_case_1() {
        assert_eq!(
            hex(&mac(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    // RFC 4231, section 4.3. Key shorter than one block.
    #[test]
    fn rfc4231_case_2() {
        assert_eq!(
            hex(&mac(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    // RFC 4231, section 4.4. Data spanning multiple blocks.
    #[test]
    fn rfc4231_case_3() {
        assert_eq!(
            hex(&mac(&[0xaa; 20], &[0xdd; 50])),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    // RFC 4231, section 4.5.
    #[test]
    fn rfc4231_case_4() {
        let key: [u8; 25] = core::array::from_fn(|index| index as u8 + 1);
        assert_eq!(
            hex(&mac(&key, &[0xcd; 50])),
            "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
        );
    }

    // RFC 4231, section 4.6. Truncation to 128 bits, which is exactly the
    // `PACKET_AUTH_TAG_LENGTH` this crate puts on the wire.
    #[test]
    fn rfc4231_case_5_truncated_to_128_bits() {
        let mut mac = HmacSha256::new(&[0x0c; 20]);
        mac.update(b"Test With Truncation");
        assert_eq!(
            hex(&mac.finalize_truncated::<16>()),
            "a3b6167473100ee06e0c796c2955552b"
        );
    }

    // RFC 4231, section 4.7. Key longer than one block, so it is hashed first.
    #[test]
    fn rfc4231_case_6_oversized_key() {
        assert_eq!(
            hex(&mac(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    // RFC 4231, section 4.8. Oversized key and multi-block data.
    #[test]
    fn rfc4231_case_7_oversized_key_and_data() {
        assert_eq!(
            hex(&mac(
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a larger \
                  than block-size data. The key needs to be hashed before being \
                  used by the HMAC algorithm."
            )),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    #[test]
    fn key_of_exactly_one_block_is_not_hashed() {
        // A 64-byte key sits on the boundary: RFC 2104 hashes only keys
        // *longer* than the block size, so this one is used verbatim.
        let key = [0x5a_u8; BLOCK_LENGTH];
        let direct = mac(&key, b"boundary");
        let hashed = mac(&Sha256::digest(key), b"boundary");
        assert_ne!(direct, hashed);
    }

    #[test]
    fn update_is_incremental() {
        let split = {
            let mut mac = HmacSha256::new(&[0x11; 32]);
            mac.update(b"header bytes");
            mac.update(b"payload bytes");
            mac.finalize()
        };
        assert_eq!(split, mac(&[0x11; 32], b"header bytespayload bytes"));
    }

    #[test]
    fn verify_accepts_the_matching_tag_and_rejects_others() {
        let key = [0x24_u8; 32];
        let tag = {
            let mut mac = HmacSha256::new(&key);
            mac.update(b"authentic");
            mac.finalize_truncated::<16>()
        };

        let mut good = HmacSha256::new(&key);
        good.update(b"authentic");
        assert!(good.verify_truncated_left(&tag));

        // Wrong message.
        let mut wrong_message = HmacSha256::new(&key);
        wrong_message.update(b"tampered");
        assert!(!wrong_message.verify_truncated_left(&tag));

        // Wrong key.
        let mut wrong_key = HmacSha256::new(&[0x25_u8; 32]);
        wrong_key.update(b"authentic");
        assert!(!wrong_key.verify_truncated_left(&tag));

        // Every single-byte corruption of the tag is rejected, at every
        // position. This checks rejection only; the constant-time property of
        // the comparison is not something a test can observe.
        for index in 0..tag.len() {
            let mut corrupted = tag;
            corrupted[index] ^= 0x01;
            let mut mac = HmacSha256::new(&key);
            mac.update(b"authentic");
            assert!(
                !mac.verify_truncated_left(&corrupted),
                "corruption at byte {index} was accepted"
            );
        }
    }
}
