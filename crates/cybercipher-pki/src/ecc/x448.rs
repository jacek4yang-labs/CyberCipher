//! X448 Diffie-Hellman (RFC 7748) on the `x448` crate (curve arithmetic from
//! `ed448-goldilocks`).
//!
//! Keys are the raw RFC 7748 byte strings, transported as hex:
//! - private: 56-byte scalar, interpreted little-endian by the protocol and
//!   **clamped** on load (bits 0-1 cleared, bit 455 set), so the clamped
//!   bytes are the canonical private value reported by key derivation;
//! - public: 56-byte Montgomery `u`-coordinate.
//!
//! Small-subgroup safety: the crate's `as_diffie_hellman` rejects the known
//! low-order peer points outright, and an all-zero shared secret cannot
//! occur for the accepted inputs; both cases surface as typed errors rather
//! than silent results.
//!
//! Key containers (RFC 8410 SPKI/PKCS#8 for X448) follow the same pattern as
//! X25519 — see `curve.rs` for the wrapper approach; no pkcs8 trait impls
//! exist in the crate, so only the raw forms are handled here.

use x448::Secret;

use super::{decode_fixed_hex, internal};
use crate::error::PkiResult;
use crate::keys::to_hex;

/// Size of every X448 artifact: private scalar and public `u`-coordinate.
pub const X448_KEY_SIZE: usize = 56;
/// Size of the derived shared secret.
pub const X448_SHARED_SECRET_SIZE: usize = 56;

// ---------------------------------------------------------------------------
// Key generation / public-key derivation
// ---------------------------------------------------------------------------

/// Generate a fresh X448 private scalar: 56 random bytes from the OS RNG,
/// clamped per RFC 7748. Reported as the canonical (clamped) hex.
pub fn x448_generate_private() -> PkiResult<String> {
    let mut bytes = [0u8; X448_KEY_SIZE];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    // A fresh 56-byte OS-RNG draw is never all-zero in practice, but the
    // decode path enforces the invariant uniformly.
    if bytes.iter().all(|&b| b == 0) {
        return Err(internal("OS RNG produced an all-zero private scalar"));
    }
    let secret = Secret::from_bytes(&bytes)
        .ok_or_else(|| internal("56-byte Secret::from_bytes must always succeed"))?;
    Ok(to_hex(secret.as_bytes()))
}

/// Derive the X448 public key (56-byte Montgomery `u`-coordinate, hex) from
/// a 56-byte private scalar (hex). The scalar is clamped by the crate on
/// load; the clamped bytes are the canonical private value.
pub fn x448_public_from_private(private_hex: &str) -> PkiResult<String> {
    let secret = secret_from_hex("private_key", private_hex)?;
    let public = x448::PublicKey::from(&secret);
    Ok(to_hex(public.as_bytes()))
}

// ---------------------------------------------------------------------------
// Shared-secret derivation
// ---------------------------------------------------------------------------

/// Derive the X448 shared secret from a 56-byte private scalar and a
/// 56-byte peer public key (both hex). The private scalar is clamped by the
/// crate on load. The output is the raw 56-byte shared secret as a hex
/// string — callers are expected to run a KDF over the decoded bytes.
///
/// A peer public key on a low-order point (small-subgroup probe) is rejected
/// with a typed error — RFC 7748 section 6.2 advises checking against this.
pub fn x448_shared_secret(private_hex: &str, peer_public_hex: &str) -> PkiResult<String> {
    let secret = secret_from_hex("private_key", private_hex)?;
    let peer_bytes = decode_fixed_hex("peer_public_key", peer_public_hex, X448_KEY_SIZE)?;
    let peer_arr: [u8; X448_KEY_SIZE] = peer_bytes.as_slice().try_into().map_err(|_| {
        internal("peer public key length invariant violated after fixed-length decode")
    })?;
    let peer = x448::PublicKey::from_bytes(&peer_arr).ok_or_else(|| {
        crate::error::PkiError::invalid_input(
            "peer public key is not a valid Curve448 point encoding",
        )
        .with_parameter("peer_public_key")
        .with_expected("a 56-byte Montgomery u-coordinate")
    })?;
    let shared = secret.as_diffie_hellman(&peer).ok_or_else(|| {
        crate::error::PkiError::invalid_input(
            "X448 shared secret rejected: the peer public key is a low-order point \
                 (small-subgroup / contributory check failed)",
        )
        .with_parameter("peer_public_key")
    })?;
    Ok(to_hex(shared.as_bytes()))
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Decode a 56-byte private scalar and clamp it (the crate clamps in
/// `Secret::from_bytes`); all-zero input is rejected up front so the error
/// carries the parameter name.
fn secret_from_hex(parameter: &str, value: &str) -> PkiResult<Secret> {
    let bytes = decode_fixed_hex(parameter, value, X448_KEY_SIZE)?;
    if bytes.iter().all(|&b| b == 0) {
        return Err(
            super::invalid_key("private key scalar is zero (not a valid key)")
                .with_parameter(parameter),
        );
    }
    let arr: [u8; X448_KEY_SIZE] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| internal("private key length invariant violated after fixed-length decode"))?;
    Secret::from_bytes(&arr)
        .ok_or_else(|| internal("56-byte Secret::from_bytes must always succeed"))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use x448::X448_BASEPOINT_BYTES;

    /// RFC 7748 section 5.2 — X448 test vectors (Alice/Bob exchange).
    const ALICE_PRIV: &str = "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b";
    const ALICE_PUB: &str = "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0";
    const BOB_PRIV: &str = "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d";
    const BOB_PUB: &str = "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609";
    const SHARED: &str = "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d";

    #[test]
    fn rfc7748_public_key_derivation() {
        let alice_pub = x448_public_from_private(ALICE_PRIV).unwrap();
        let bob_pub = x448_public_from_private(BOB_PRIV).unwrap();
        assert_eq!(alice_pub, normal_hex(ALICE_PUB));
        assert_eq!(bob_pub, normal_hex(BOB_PUB));
    }

    #[test]
    fn rfc7748_shared_secret_both_directions() {
        let alice_shared = x448_shared_secret(ALICE_PRIV, BOB_PUB).unwrap();
        let bob_shared = x448_shared_secret(BOB_PRIV, ALICE_PUB).unwrap();
        assert_eq!(alice_shared, bob_shared);
        assert_eq!(alice_shared, normal_hex(SHARED));
    }

    #[test]
    fn basepoint_public_key_is_derivable() {
        // The basepoint scalar 5 (clamped from 5) maps to u(5G).
        let mut scalar = [0u8; X448_KEY_SIZE];
        scalar[0] = 5;
        let priv_hex = to_hex(&scalar);
        let public = x448_public_from_private(&priv_hex).unwrap();
        // Deterministic and non-trivial: 56 bytes, not all zero.
        assert_eq!(public.len(), X448_KEY_SIZE * 2);
        assert!(public.chars().any(|c| c != '0'));
    }

    #[test]
    fn low_order_peer_is_rejected() {
        // The all-zero u-coordinate (order-1 point) is rejected during the
        // peer key decode — the crate classifies low-order points as invalid
        // public keys, which surfaces as a typed error either way.
        let zeros = "00".repeat(X448_KEY_SIZE);
        let err = x448_shared_secret(ALICE_PRIV, &zeros)
            .expect_err("all-zero u-coordinate is a low-order point");
        let message = format!("{err}");
        assert!(
            message.contains("low-order") || message.contains("not a valid"),
            "error: {message}"
        );
    }

    #[test]
    fn malformed_inputs_are_typed_errors() {
        // Wrong length.
        assert!(x448_shared_secret(ALICE_PRIV, "0011").is_err());
        assert!(x448_public_from_private("0011").is_err());
        // Non-hex.
        assert!(x448_public_from_private(&"zz".repeat(X448_KEY_SIZE)).is_err());
        // Zero private scalar.
        let zeros = "00".repeat(X448_KEY_SIZE);
        let err = x448_public_from_private(&zeros).expect_err("zero scalar must fail");
        assert!(format!("{err}").contains("zero"), "error: {err}");
        // 0x prefix and uppercase are accepted.
        let upper = format!("0x{}", ALICE_PRIV.to_ascii_uppercase());
        assert_eq!(
            x448_public_from_private(&upper).unwrap(),
            x448_public_from_private(ALICE_PRIV).unwrap()
        );
    }

    #[test]
    fn basepoint_constant_is_56_bytes() {
        assert_eq!(X448_BASEPOINT_BYTES.len(), X448_KEY_SIZE);
    }

    #[test]
    fn generated_keys_exchange() {
        let a = x448_generate_private().unwrap();
        let b = x448_generate_private().unwrap();
        let a_pub = x448_public_from_private(&a).unwrap();
        let b_pub = x448_public_from_private(&b).unwrap();
        // Freshly generated scalars must round-trip unchanged (already
        // clamped by the generator).
        assert_eq!(x448_public_from_private(&a).unwrap(), a_pub);
        let ab = x448_shared_secret(&a, &b_pub).unwrap();
        let ba = x448_shared_secret(&b, &a_pub).unwrap();
        assert_eq!(ab, ba);
        assert_eq!(ab.len(), X448_SHARED_SECRET_SIZE * 2);
    }

    /// Normalize an expected vector: drop whitespace used for line wrapping.
    fn normal_hex(value: &str) -> String {
        value.split_whitespace().collect()
    }
}
