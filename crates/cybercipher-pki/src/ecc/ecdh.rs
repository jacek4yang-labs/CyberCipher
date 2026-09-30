//! ECDH shared-secret derivation for the NIST curves (SEC 1 v2 section 3.3,
//! elliptic-curve scalar multiplication of the peer public point by the local
//! private scalar).
//!
//! - The peer public key is hex-encoded SEC1 (compressed or uncompressed) and
//!   is validated to be on the curve before use — an off-curve, non-canonical,
//!   or identity point is a typed `KeyError` ("point is not on the curve").
//! - The output is the raw X-coordinate of the shared point (`x`), the
//!   canonical ECDH shared secret. Callers are expected to run a KDF
//!   (HKDF etc.) over the decoded bytes; this function only derives the raw
//!   secret, mirroring `x25519_shared_secret`.
//! - The local private scalar is checked for zero and the group order range
//!   by the underlying crates.

use super::curve::EccCurve;
use super::{decode_hex, decode_scalar_hex, invalid_key, invalid_point, wrong_curve, wrong_length};
use crate::error::PkiResult;
use crate::keys::to_hex;

/// ECDH shared-secret derivation on P-256 or P-384: `x`-coordinate of
/// `private * peer_public`, as a lowercase hex string of raw bytes
/// (32 bytes on P-256, 48 on P-384). Any other curve is a typed error.
pub fn ecdh_shared_secret(
    curve: EccCurve,
    private_hex: &str,
    peer_public_hex: &str,
) -> PkiResult<String> {
    match curve {
        EccCurve::P256 => {
            let scalar = decode_scalar_hex("private_key", private_hex, 32)?;
            nist_ecdh::<p256::NistP256>(curve, &scalar, peer_public_hex)
        }
        EccCurve::P384 => {
            let scalar = decode_scalar_hex("private_key", private_hex, 48)?;
            nist_ecdh::<p384::NistP384>(curve, &scalar, peer_public_hex)
        }
        other => Err(wrong_curve("p256 or p384", other.label())
            .with_details("ECDH is only defined here for the NIST curves P-256 and P-384")),
    }
}

fn nist_ecdh<C>(curve: EccCurve, scalar: &[u8], peer_public_hex: &str) -> PkiResult<String>
where
    C: elliptic_curve::CurveArithmetic,
    elliptic_curve::AffinePoint<C>:
        elliptic_curve::sec1::FromEncodedPoint<C> + elliptic_curve::sec1::ToEncodedPoint<C>,
    elliptic_curve::FieldBytesSize<C>: elliptic_curve::sec1::ModulusSize,
{
    let field = elliptic_curve::FieldBytes::<C>::clone_from_slice(scalar);
    let secret = elliptic_curve::SecretKey::<C>::from_bytes(&field).map_err(|_| {
        invalid_key("invalid private key scalar: not in the curve group order range")
            .with_parameter("private_key")
    })?;
    let peer_bytes = decode_hex("peer_public_key", peer_public_hex)?;
    let compressed_len = curve.public_key_compressed_size();
    let uncompressed_len = curve.public_key_uncompressed_size();
    if peer_bytes.len() != compressed_len && peer_bytes.len() != uncompressed_len {
        return Err(wrong_length(
            "peer_public_key",
            format!(
                "{compressed_len} bytes (compressed) or {uncompressed_len} bytes (uncompressed)"
            ),
            format!("{} bytes", peer_bytes.len()),
        ));
    }
    let peer = elliptic_curve::PublicKey::<C>::from_sec1_bytes(&peer_bytes).map_err(|_| {
        invalid_point(
            curve.label(),
            "peer public key is not a valid point on the curve (off-curve, non-canonical, \
             or point at infinity)",
        )
    })?;
    let shared = elliptic_curve::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer.as_affine());
    Ok(to_hex(shared.raw_secret_bytes().as_slice()))
}
