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

// ---------------------------------------------------------------------------
// SM2 sign / verify
// ---------------------------------------------------------------------------

use cybercipher_pki::sm2::{
    sm2_sign, sm2_signature_from_bytes, sm2_signature_to_bytes, sm2_verify, SM2_SIGNATURE_LEN,
};

#[test]
fn sign_verify_round_trip_default_user_id() {
    let kp = generate_sm2_keypair().unwrap();
    let msg = b"attack at dawn";

    let sig_hex = sm2_sign(&kp.private_hex, msg, None).unwrap();
    assert_eq!(sig_hex.len(), SM2_SIGNATURE_LEN * 2);

    let result = sm2_verify(&kp.public_uncompressed_hex, msg, &sig_hex, None).unwrap();
    assert!(
        result.valid,
        "default-ID verify failed: {:?}",
        result.reason
    );
    assert_eq!(result.user_id, SM2_DEFAULT_USER_ID);
    assert_eq!(result.reason, None);

    // The compressed public encoding must verify identically.
    let result = sm2_verify(&kp.public_compressed_hex, msg, &sig_hex, None).unwrap();
    assert!(result.valid);

    // `Some("")` selects the default ID as well.
    let result = sm2_verify(&kp.public_uncompressed_hex, msg, &sig_hex, Some("")).unwrap();
    assert!(result.valid);
}

#[test]
fn sign_verify_round_trip_custom_user_id() {
    // The GB/T 32918.2-2016 A.2 example ID.
    let user_id = "ALICE123@YAHOO.COM";
    let kp = generate_sm2_keypair().unwrap();
    let msg = b"message digest";

    let sig_hex = sm2_sign(&kp.private_hex, msg, Some(user_id)).unwrap();
    let result = sm2_verify(&kp.public_uncompressed_hex, msg, &sig_hex, Some(user_id)).unwrap();
    assert!(result.valid, "custom-ID verify failed: {:?}", result.reason);
    assert_eq!(result.user_id, user_id);
}

#[test]
fn signing_is_deterministic_rfc6979() {
    let kp = generate_sm2_keypair().unwrap();
    let a = sm2_sign(&kp.private_hex, b"deterministic", None).unwrap();
    let b = sm2_sign(&kp.private_hex, b"deterministic", None).unwrap();
    assert_eq!(a, b, "same key + same message must repeat the signature");
}

#[test]
fn default_and_explicit_default_id_agree() {
    let kp = generate_sm2_keypair().unwrap();
    let implicit = sm2_sign(&kp.private_hex, b"id check", None).unwrap();
    let explicit = sm2_sign(&kp.private_hex, b"id check", Some(SM2_DEFAULT_USER_ID)).unwrap();
    assert_eq!(implicit, explicit);
}

#[test]
fn sign_wrong_user_id_verify_fails() {
    let kp = generate_sm2_keypair().unwrap();
    let msg = b"ZA depends on the ID";
    let sig_hex = sm2_sign(&kp.private_hex, msg, Some("signer@example.com")).unwrap();

    let result = sm2_verify(
        &kp.public_uncompressed_hex,
        msg,
        &sig_hex,
        Some("other@example.com"),
    )
    .unwrap();
    assert!(!result.valid);
    assert!(result
        .reason
        .as_deref()
        .unwrap_or_default()
        .contains("user ID"));

    // The default ID must not verify a custom-ID signature either.
    let result = sm2_verify(&kp.public_uncompressed_hex, msg, &sig_hex, None).unwrap();
    assert!(!result.valid);
}

#[test]
fn verify_wrong_key_and_tampered_message_fail() {
    let kp = generate_sm2_keypair().unwrap();
    let other = generate_sm2_keypair().unwrap();
    let msg = b"authenticated content";
    let sig_hex = sm2_sign(&kp.private_hex, msg, None).unwrap();

    // Wrong public key: valid: false, not an error.
    let result = sm2_verify(&other.public_uncompressed_hex, msg, &sig_hex, None).unwrap();
    assert!(!result.valid);

    // Tampered message.
    let result = sm2_verify(
        &kp.public_uncompressed_hex,
        b"authenticated contenT",
        &sig_hex,
        None,
    )
    .unwrap();
    assert!(!result.valid);

    // Tampered signature: flip one hex char of r.
    let mut tampered = sig_hex.clone();
    let flip = if tampered.starts_with('0') { '1' } else { '0' };
    tampered.replace_range(0..1, flip.to_string().as_str());
    let result = sm2_verify(&kp.public_uncompressed_hex, msg, &tampered, None).unwrap();
    assert!(!result.valid);
}

#[test]
fn sign_rejects_bad_private_key() {
    let err = sm2_sign(&"00".repeat(32), b"x", None).unwrap_err();
    assert_eq!(kind_of(&err), "KeyError");
    let err = sm2_sign("nothex", b"x", None).unwrap_err();
    assert_eq!(kind_of(&err), "Decode");
}

#[test]
fn verify_malformed_signature_inputs_are_typed_errors() {
    let kp = generate_sm2_keypair().unwrap();
    let msg = b"typed errors";

    // Wrong length (63 and 65 bytes).
    let err = sm2_verify(&kp.public_uncompressed_hex, msg, &"ab".repeat(63), None).unwrap_err();
    assert_eq!(kind_of(&err), "LengthMismatch");
    let err = sm2_verify(&kp.public_uncompressed_hex, msg, &"ab".repeat(65), None).unwrap_err();
    assert_eq!(kind_of(&err), "LengthMismatch");

    // r = 0 is outside 1..n.
    let mut zero_r = vec![0u8; 32];
    zero_r.extend_from_slice(&[1u8; 32]);
    let err = sm2_verify(&kp.public_uncompressed_hex, msg, &hex_encode(&zero_r), None).unwrap_err();
    assert_eq!(kind_of(&err), "Decode");

    // s = n is non-canonical.
    let mut sig = vec![1u8; 32];
    sig.extend_from_slice(&hex_decode(
        "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
    ));
    let err = sm2_verify(&kp.public_uncompressed_hex, msg, &hex_encode(&sig), None).unwrap_err();
    assert_eq!(kind_of(&err), "Decode");

    // Off-curve public key (P-256 generator): KeyError at parse time.
    let p256_generator = "04\
        6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
        4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    let err = sm2_verify(p256_generator, msg, &"ab".repeat(64), None).unwrap_err();
    assert_eq!(kind_of(&err), "KeyError");
}

#[test]
fn oversized_user_id_is_a_typed_error() {
    let kp = generate_sm2_keypair().unwrap();
    // 8192 bytes would overflow the 16-bit ENTLa bit-length field.
    let too_long = "A".repeat(8192);
    let err = sm2_sign(&kp.private_hex, b"x", Some(too_long.as_str())).unwrap_err();
    assert_eq!(kind_of(&err), "InvalidParam");
    assert!(err.message.contains("ENTLa"));
}

#[test]
fn signature_byte_conversions_round_trip() {
    let kp = generate_sm2_keypair().unwrap();
    let sig_hex = sm2_sign(&kp.private_hex, b"bytes round trip", None).unwrap();

    let bytes = sm2_signature_to_bytes(&sig_hex).unwrap();
    assert_eq!(bytes.len(), SM2_SIGNATURE_LEN);
    assert_eq!(hex_encode(&bytes), sig_hex);
    assert_eq!(sm2_signature_from_bytes(&bytes).unwrap(), sig_hex);

    // Wrong length and non-canonical components are typed errors.
    assert_eq!(
        kind_of(&sm2_signature_from_bytes(&[0u8; 63]).unwrap_err()),
        "LengthMismatch"
    );
    assert_eq!(
        kind_of(&sm2_signature_to_bytes(&"00".repeat(64)).unwrap_err()),
        "Decode"
    );
}

// ---------------------------------------------------------------------------
// SM2 encrypt / decrypt (GB/T 32918.4, C1||C3||C2 layout)
// ---------------------------------------------------------------------------

use cybercipher_pki::sm2::{sm2_decrypt, sm2_encrypt, SM2_C1_LEN, SM2_C3_LEN};

#[test]
fn encrypt_decrypt_round_trip_various_sizes() {
    let kp = generate_sm2_keypair().unwrap();
    for size in [0usize, 1, 15, 31, 32, 33, 64, 255, 1000] {
        let plaintext: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let ciphertext = sm2_encrypt(&kp.public_uncompressed_hex, &plaintext).unwrap();
        assert_eq!(ciphertext.len(), SM2_C1_LEN + SM2_C3_LEN + plaintext.len());
        let decrypted = sm2_decrypt(&kp.private_hex, &ciphertext).unwrap();
        assert_eq!(decrypted, plaintext, "round-trip failed for {size} bytes");
    }
}

#[test]
fn ciphertext_layout_and_each_encryption_is_fresh() {
    let kp = generate_sm2_keypair().unwrap();
    let msg = b"layout check".repeat(3);

    let ct = sm2_encrypt(&kp.public_uncompressed_hex, &msg).unwrap();
    // Layout: 0x04 || x1 || y1 || C3 || C2.
    assert_eq!(ct[0], 0x04);
    assert_eq!(ct.len(), SM2_C1_LEN + SM2_C3_LEN + msg.len());

    // C1 must be a valid, on-curve SM2 point (it is [k]G).
    let c1 = parse_sm2_public_key(&hex_encode(&ct[..SM2_C1_LEN])).unwrap();
    assert_eq!(c1.public_uncompressed_hex, hex_encode(&ct[..SM2_C1_LEN]));

    // Fresh randomness: two encryptions of the same message share no C1/C2.
    let ct2 = sm2_encrypt(&kp.public_uncompressed_hex, &msg).unwrap();
    assert_ne!(ct, ct2, "C1 must be random per encryption");
    assert_ne!(
        &ct[SM2_C1_LEN + SM2_C3_LEN..],
        &ct2[SM2_C1_LEN + SM2_C3_LEN..]
    );

    // Both decrypt back to the message.
    assert_eq!(sm2_decrypt(&kp.private_hex, &ct).unwrap(), msg);
    assert_eq!(sm2_decrypt(&kp.private_hex, &ct2).unwrap(), msg);
}

#[test]
fn decrypt_wrong_key_or_tampered_c3_is_a_typed_error() {
    let kp = generate_sm2_keypair().unwrap();
    let other = generate_sm2_keypair().unwrap();
    let msg = b"integrity matters";

    // Wrong private key: well-formed ciphertext, C3 mismatch -> KeyError.
    let ct = sm2_encrypt(&kp.public_uncompressed_hex, msg).unwrap();
    let err = sm2_decrypt(&other.private_hex, &ct).unwrap_err();
    assert_eq!(kind_of(&err), "KeyError");
    assert!(err.message.contains("C3 integrity hash mismatch"));

    // Flip one byte of C3.
    let mut tampered = ct.clone();
    let i = SM2_C1_LEN;
    tampered[i] ^= 0x01;
    let err = sm2_decrypt(&kp.private_hex, &tampered).unwrap_err();
    assert_eq!(kind_of(&err), "KeyError");

    // Flip one byte of C2 (masked message).
    let mut tampered = ct.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0xff;
    let err = sm2_decrypt(&kp.private_hex, &tampered).unwrap_err();
    assert_eq!(kind_of(&err), "KeyError");

    // Flip one byte of C1 x-coordinate: usually off-curve or wrong shared
    // point; either way it must be a typed error, never a panic.
    let mut tampered = ct.clone();
    tampered[1] ^= 0x01;
    assert!(sm2_decrypt(&kp.private_hex, &tampered).is_err());
}

#[test]
fn decrypt_structural_errors_are_typed() {
    let kp = generate_sm2_keypair().unwrap();
    let ct = sm2_encrypt(&kp.public_uncompressed_hex, b"x").unwrap();

    // Truncated: below the 97-byte C1||C3 minimum.
    for cut in [0, 1, 64, 96] {
        let err = sm2_decrypt(&kp.private_hex, &ct[..cut]).unwrap_err();
        assert_eq!(kind_of(&err), "LengthMismatch", "cut={cut}");
    }

    // Wrong C1 tag (compressed-point confusion).
    let mut bad = ct.clone();
    bad[0] = 0x03;
    let err = sm2_decrypt(&kp.private_hex, &bad).unwrap_err();
    assert_eq!(kind_of(&err), "Decode");
    assert!(err.message.contains("tag 0x04"));

    // C1 coordinates not on the curve.
    let mut bad = ct.clone();
    bad[1] = 0xff;
    bad[2] = 0xff;
    let err = sm2_decrypt(&kp.private_hex, &bad).unwrap_err();
    assert!(matches!(kind_of(&err).as_str(), "KeyError" | "Decode"));

    // Empty ciphertext.
    let err = sm2_decrypt(&kp.private_hex, &[]).unwrap_err();
    assert_eq!(kind_of(&err), "LengthMismatch");

    // Bad private key before any ciphertext work.
    let err = sm2_decrypt(&"00".repeat(32), &ct).unwrap_err();
    assert_eq!(kind_of(&err), "KeyError");
}

#[test]
fn encrypt_rejects_malformed_public_key() {
    let err = sm2_encrypt(&"ab".repeat(65), b"x").unwrap_err();
    assert_eq!(kind_of(&err), "Decode");
    // Off-curve point (P-256 generator).
    let p256_generator = "04\
        6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296\
        4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    let err = sm2_encrypt(p256_generator, b"x").unwrap_err();
    assert_eq!(kind_of(&err), "KeyError");
    // Compressed public keys encrypt fine too.
    let kp = generate_sm2_keypair().unwrap();
    let ct = sm2_encrypt(&kp.public_compressed_hex, b"compressed").unwrap();
    assert_eq!(sm2_decrypt(&kp.private_hex, &ct).unwrap(), b"compressed");
}

#[test]
fn encrypt_decrypt_binary_safety() {
    // All byte values, including zeros and 0xff, must survive round-trips.
    let kp = generate_sm2_keypair().unwrap();
    let plaintext: Vec<u8> = (0..=255u8).chain([0x00, 0x04, 0xff]).collect();
    let ct = sm2_encrypt(&kp.public_uncompressed_hex, &plaintext).unwrap();
    assert_eq!(sm2_decrypt(&kp.private_hex, &ct).unwrap(), plaintext);
}
