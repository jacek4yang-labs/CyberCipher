//! X25519 Diffie-Hellman (RFC 7748) on `x25519-dalek` 2.
//!
//! Keys are the raw RFC 7748 byte strings, transported as hex:
//! - private: 32-byte scalar, interpreted little-endian by the protocol and
//!   **clamped** on load (bits 0-2 cleared, bit 255 set, bit 254 cleared), so
//!   the clamped bytes are the canonical private value reported by keygen;
//! - public: 32-byte Montgomery `u`-coordinate.
//!
//! Small-subgroup safety: `x25519-dalek` clamps the private scalar, which
//! neutralizes the low-order bits an attacker could otherwise probe, and the
//! derived shared secret is checked for the all-zero output that a
//! low-order-point (small-subgroup) peer produces. An all-zero result is
//! rejected with a typed error (`was_contributory` check) — RFC 7748
//! section 6.1 strongly advises rejecting non-contributory exchanges.
//!
//! SPKI/PKCS#8 containers (RFC 8410) are handled by `curve.rs` via the
//! `pkcs8`/`spki` crates; `x25519-dalek` itself only works on the raw forms.

use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

use super::curve::{EccCurve, EccKeyPair, EccPublicKeyMaterial};
use super::{decode_fixed_hex, internal};
use crate::error::PkiResult;
use crate::keys::to_hex;

/// Size of every X25519 artifact: private scalar and public `u`-coordinate.
pub const X25519_KEY_SIZE: usize = 32;
/// Size of the derived shared secret.
pub const X25519_SHARED_SECRET_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Shared-secret derivation
// ---------------------------------------------------------------------------

/// Derive the X25519 shared secret from a 32-byte private scalar and a
/// 32-byte peer public key (both hex). The private scalar is clamped by the
/// crate on load. The output is the raw 32-byte shared secret as a hex
/// string — callers are expected to run a KDF over the decoded bytes.
///
/// The all-zero output produced when the peer public key is a low-order
/// point (small-subgroup attack) is rejected with a typed error.
pub fn x25519_shared_secret(private_hex: &str, peer_public_hex: &str) -> PkiResult<String> {
    let private_bytes = decode_fixed_hex("private_key", private_hex, X25519_KEY_SIZE)?;
    let peer_bytes = decode_fixed_hex("peer_public_key", peer_public_hex, X25519_KEY_SIZE)?;
    let private_arr: [u8; X25519_KEY_SIZE] = private_bytes
        .as_slice()
        .try_into()
        .map_err(|_| internal("private key length invariant violated after fixed-length decode"))?;
    let peer_arr: [u8; X25519_KEY_SIZE] = peer_bytes
        .as_slice()
        .try_into()
        .map_err(|_| internal("peer key length invariant violated after fixed-length decode"))?;
    let secret = StaticSecret::from(private_arr);
    let shared = secret.diffie_hellman(&PublicKey::from(peer_arr));
    if !shared.was_contributory() {
        return Err(crate::error::PkiError::invalid_input(
            "X25519 shared secret is all-zero: the peer public key is a low-order point \
             (small-subgroup / contributory check failed)",
        )
        .with_parameter("peer_public_key")
        .with_details(
            "RFC 7748 section 6.1: non-contributory exchanges must be rejected; \
             every party contributing a low-order point yields the same useless secret",
        ));
    }
    Ok(to_hex(shared.as_bytes()))
}

// ---------------------------------------------------------------------------
// Key handling (pub(crate) hooks used by `curve.rs`)
// ---------------------------------------------------------------------------

/// Generate an X25519 keypair (fresh random bytes from the OS RNG, clamped by
/// the crate on load).
pub(crate) fn generate() -> PkiResult<EccKeyPair> {
    let mut seed = [0u8; X25519_KEY_SIZE];
    OsRng.fill_bytes(&mut seed);
    Ok(keypair_from_private(seed))
}

/// Parse a 32-byte private scalar into a keypair with the derived public
/// key. The scalar is clamped on load; the clamped bytes are reported as the
/// canonical `private_hex`.
pub(crate) fn parse_private(private_hex: &str) -> PkiResult<EccKeyPair> {
    let bytes = decode_fixed_hex("private_key", private_hex, X25519_KEY_SIZE)?;
    let arr: [u8; X25519_KEY_SIZE] = bytes.as_slice().try_into().map_err(|_| {
        internal("private key length invariant violated after fixed-length decode")
    })?;
    Ok(keypair_from_private(arr))
}

/// Parse a 32-byte public `u`-coordinate into public-key material. Every
/// 32-byte string is a valid Montgomery `u`-coordinate (validation happens
/// implicitly during the DH computation).
pub(crate) fn public_material(public_hex: &str) -> PkiResult<EccPublicKeyMaterial> {
    let bytes = decode_fixed_hex("public_key", public_hex, X25519_KEY_SIZE)?;
    let hex = to_hex(&bytes);
    Ok(EccPublicKeyMaterial {
        curve: EccCurve::X25519,
        public_compressed_hex: hex.clone(),
        public_uncompressed_hex: hex,
    })
}

/// Raw 32-byte public key (SPKI bit-string payload) into public-key material.
pub(crate) fn public_from_raw_bytes(bytes: &[u8]) -> PkiResult<EccPublicKeyMaterial> {
    let arr: [u8; X25519_KEY_SIZE] = bytes
        .try_into()
        .map_err(|_| super::wrong_length("public_key", format!("{X25519_KEY_SIZE} bytes"), format!("{} bytes", bytes.len())))?;
    let hex = to_hex(&arr);
    Ok(EccPublicKeyMaterial {
        curve: EccCurve::X25519,
        public_compressed_hex: hex.clone(),
        public_uncompressed_hex: hex,
    })
}

/// PKCS#8 `privateKey` OCTET STRING payload (RFC 8410: the raw scalar) into
/// a keypair. The scalar is clamped on load.
pub(crate) fn private_from_pkcs8_octets(octets: &[u8]) -> PkiResult<EccKeyPair> {
    let arr: [u8; X25519_KEY_SIZE] = octets
        .try_into()
        .map_err(|_| super::wrong_length("private_key", format!("{X25519_KEY_SIZE} bytes"), format!("{} bytes", octets.len())))?;
    Ok(keypair_from_private(arr))
}

/// Build a keypair, clamping the private scalar on load (the clamped bytes
/// are the canonical private value).
fn keypair_from_private(private: [u8; X25519_KEY_SIZE]) -> EccKeyPair {
    let secret = StaticSecret::from(private);
    let public = PublicKey::from(&secret);
    let public_hex = to_hex(public.as_bytes());
    EccKeyPair {
        curve: EccCurve::X25519,
        private_hex: to_hex(secret.as_bytes()),
        public_compressed_hex: public_hex.clone(),
        public_uncompressed_hex: public_hex,
    }
}
