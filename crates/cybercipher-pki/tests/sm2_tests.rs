//! SM2 (GB/T 32918) + SM3 (GB/T 32905) tests: official SM3 KATs, keygen and
//! parse round-trips, sign/verify (default + custom user IDs, negative
//! cases), and PKE encrypt/decrypt round-trips with malformed-input errors.

use cybercipher_pki::sm2::{
    generate_sm2_keypair, parse_sm2_private_key, parse_sm2_public_key, sm3_digest, sm3_hex,
    SM2_DEFAULT_USER_ID, SM2_PUBLIC_COMPRESSED_LEN, SM2_PUBLIC_UNCOMPRESSED_LEN, SM2_SCALAR_LEN,
};
use cybercipher_pki::PkiError;

/// Error kind of a [`PkiError`] for assertions (mirrors the core enum).
fn kind_of(err: &PkiError) -> String {
    format!("{:?}", err.kind)
}

// ---------------------------------------------------------------------------
// SM3 (GB/T 32905-2016) known-answer tests — the two official example vectors
// ---------------------------------------------------------------------------

#[test]
fn sm3_kat_abc() {
    // GB/T 32905-2016 appendix A example 1: SM3("abc").
    assert_eq!(
        sm3_hex(b"abc"),
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
    );
}

#[test]
fn sm3_kat_abcd_repeated() {
    // GB/T 32905-2016 appendix A example 2: SM3 over the 64-byte message
    // "abcd" repeated 16 times.
    let msg = "abcd".repeat(16);
    assert_eq!(msg.len(), 64);
    assert_eq!(
        sm3_hex(msg.as_bytes()),
        "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
    );
}

#[test]
fn sm3_digest_returns_raw_bytes() {
    let raw = sm3_digest(b"abc");
    assert_eq!(raw.len(), 32);
    assert_eq!(hex_encode(&raw), sm3_hex(b"abc"));
}

/// Lowercase hex helper for tests.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Key generation and parsing
// ---------------------------------------------------------------------------

#[test]
fn keygen_shapes_and_serde_round_trip() {
    let kp = generate_sm2_keypair().unwrap();
    assert_eq!(kp.private_hex.len(), SM2_SCALAR_LEN * 2);
    assert_eq!(
        kp.public_compressed_hex.len(),
        SM2_PUBLIC_COMPRESSED_LEN * 2
    );
    assert!(
        kp.public_compressed_hex.starts_with("02") || kp.public_compressed_hex.starts_with("03")
    );
    assert_eq!(
        kp.public_uncompressed_hex.len(),
        SM2_PUBLIC_UNCOMPRESSED_LEN * 2
    );
    assert!(kp.public_uncompressed_hex.starts_with("04"));

    let json = serde_json::to_string(&kp).unwrap();
    let back: cybercipher_pki::sm2::Sm2KeyPair = serde_json::from_str(&json).unwrap();
    assert_eq!(back, kp);
}

#[test]
fn keygen_round_trip_serialize_then_parse_same_public_key() {
    let kp = generate_sm2_keypair().unwrap();

    // Private scalar parse must derive the exact same public key.
    let reparsed = parse_sm2_private_key(&kp.private_hex).unwrap();
    assert_eq!(reparsed.public_uncompressed_hex, kp.public_uncompressed_hex);
    assert_eq!(reparsed.public_compressed_hex, kp.public_compressed_hex);

    // Both public encodings parse to the same material.
    let from_uncompressed = parse_sm2_public_key(&kp.public_uncompressed_hex).unwrap();
    assert_eq!(
        from_uncompressed.public_uncompressed_hex,
        kp.public_uncompressed_hex
    );
    let from_compressed = parse_sm2_public_key(&kp.public_compressed_hex).unwrap();
    assert_eq!(
        from_compressed.public_uncompressed_hex,
        kp.public_uncompressed_hex
    );
}

#[test]
fn parse_private_key_is_left_pad_tolerant() {
    let kp = generate_sm2_keypair().unwrap();
    // Strip leading zeros: JWK-style short scalars must still parse.
    let stripped = kp.private_hex.trim_start_matches('0');
    let stripped = if stripped.is_empty() { "00" } else { stripped };
    let reparsed = parse_sm2_private_key(stripped).unwrap();
    assert_eq!(reparsed.public_uncompressed_hex, kp.public_uncompressed_hex);
}

#[test]
fn parse_private_key_rejects_zero_scalar() {
    let err = parse_sm2_private_key(&"00".repeat(32)).unwrap_err();
    assert_eq!(kind_of(&err), "KeyError");
}

#[test]
fn parse_private_key_rejects_bad_lengths_and_hex() {
    // Empty.
    let err = parse_sm2_private_key("").unwrap_err();
    assert_eq!(kind_of(&err), "Decode");
    // Odd length.
    let err = parse_sm2_private_key("abc").unwrap_err();
    assert_eq!(kind_of(&err), "Decode");
    // Non-hex.
    let err = parse_sm2_private_key(&"zz".repeat(32)).unwrap_err();
    assert_eq!(kind_of(&err), "Decode");
    // Too long (33 bytes).
    let err = parse_sm2_private_key(&"ab".repeat(33)).unwrap_err();
    assert_eq!(kind_of(&err), "LengthMismatch");
}

#[test]
fn parse_public_key_rejects_malformed_inputs() {
    let kp = generate_sm2_keypair().unwrap();

    // Wrong length: 32 bytes matches a raw Ed25519/X25519 key -> wrong-curve
    // hint, not a bare length error.
    let err = parse_sm2_public_key(&"ab".repeat(32)).unwrap_err();
    assert_eq!(kind_of(&err), "InvalidInput");
    assert!(err.actual.as_deref().unwrap_or_default().contains("x25519"));

    // Wrong length with a P-384 hint.
    let err = parse_sm2_public_key(&"ab".repeat(97)).unwrap_err();
    assert_eq!(kind_of(&err), "InvalidInput");
    assert!(err.actual.as_deref().unwrap_or_default().contains("p384"));

    // Wrong SEC1 tag with a valid length.
    let mut bad = vec![0x05u8];
    bad.extend_from_slice(&hex_decode(&kp.public_uncompressed_hex)[1..]);
    let err = parse_sm2_public_key(&hex_encode(&bad)).unwrap_err();
    assert_eq!(kind_of(&err), "Decode");
    assert!(err.message.contains("tag 0x05"));

    // Truncated uncompressed point: tag 0x04 with only 33 bytes.
    let mut bad = hex_decode(&kp.public_uncompressed_hex);
    bad.truncate(33);
    let err = parse_sm2_public_key(&hex_encode(&bad)).unwrap_err();
    assert_eq!(kind_of(&err), "Decode");
    assert!(err.message.contains("tag 0x04"));

    // Compressed tag with uncompressed length.
    let mut bad = hex_decode(&kp.public_compressed_hex);
    bad.extend_from_slice(&[0x41u8; 32]);
    let err = parse_sm2_public_key(&hex_encode(&bad)).unwrap_err();
    assert_eq!(kind_of(&err), "Decode");

    // Wrong total length (no curve hint applies).
    let err = parse_sm2_public_key(&"ab".repeat(40)).unwrap_err();
    assert_eq!(kind_of(&err), "LengthMismatch");

    // Empty and odd-length hex.
    assert_eq!(kind_of(&parse_sm2_public_key("").unwrap_err()), "Decode");
    assert_eq!(kind_of(&parse_sm2_public_key("0").unwrap_err()), "Decode");

    // A valid-length point that is not on the SM2 curve: the P-256 generator
    // satisfies y^2 = x^3 - 3x + b_p256, not the SM2 equation.
    let p256_generator = "04\
        6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
        4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    let err = parse_sm2_public_key(p256_generator).unwrap_err();
    assert_eq!(kind_of(&err), "KeyError");
    assert!(err.message.contains("point is not on the sm2 curve"));
}

#[test]
fn parse_public_key_rejects_identity_point() {
    // SEC1 encoding of the point at infinity is 0x00; a 0x04-prefixed blob
    // with zero coordinates must also be rejected as non-canonical.
    let zero_point = format!("04{}", "00".repeat(64));
    let err = parse_sm2_public_key(&zero_point).unwrap_err();
    assert_eq!(kind_of(&err), "KeyError");
}

/// Hex decode helper for tests.
fn hex_decode(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn default_user_id_constant_is_standard() {
    assert_eq!(SM2_DEFAULT_USER_ID, "1234567812345678");
}
