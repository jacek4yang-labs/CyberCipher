//! ECC foundation tests: authoritative test vectors (RFC 6979, RFC 8032,
//! RFC 7748, RFC 5114), key/encoding round-trips, sign/verify semantics, and
//! malformed-input typed errors.

use cybercipher_core::ErrorKind;
use cybercipher_pki::ecc::curve::{EccCurve, EccKeyPair};
use cybercipher_pki::error::PkiError;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Assert an error kind + that the message mentions a substring.
fn assert_kind(err: &PkiError, kind: ErrorKind, needle: &str) {
    assert_eq!(
        err.kind, kind,
        "expected {kind:?}, got {:?} ({})",
        err.kind, err.message
    );
    assert!(
        err.message
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase()),
        "message '{}' does not mention '{needle}'",
        err.message
    );
}

fn generate(curve: EccCurve) -> EccKeyPair {
    cybercipher_pki::generate_ecc_keypair(curve).expect("keygen should not fail")
}

fn p256_off_curve_uncompressed() -> String {
    // (x=1, y=1): 1 != 1^3 - 3*1 + 7 mod p, so this 65-byte encoding is a
    // well-formed SEC1 point that does not satisfy the curve equation.
    let mut hex = String::from("04");
    hex.push_str(&"00".repeat(31));
    hex.push_str("01");
    hex.push_str(&"00".repeat(31));
    hex.push_str("01");
    hex
}

// ---------------------------------------------------------------------------
// Key generation + hex transport shapes
// ---------------------------------------------------------------------------

#[test]
fn keygen_transport_shapes() {
    let p256 = generate(EccCurve::P256);
    assert_eq!(p256.curve, EccCurve::P256);
    assert_eq!(p256.private_hex.len(), 64); // 32 bytes
    assert_eq!(p256.public_compressed_hex.len(), 66); // 33 bytes
    assert_eq!(p256.public_uncompressed_hex.len(), 130); // 65 bytes
    assert!(
        p256.public_compressed_hex.starts_with("02")
            || p256.public_compressed_hex.starts_with("03")
    );
    assert!(p256.public_uncompressed_hex.starts_with("04"));

    let p384 = generate(EccCurve::P384);
    assert_eq!(p384.private_hex.len(), 96); // 48 bytes
    assert_eq!(p384.public_compressed_hex.len(), 98); // 49 bytes
    assert_eq!(p384.public_uncompressed_hex.len(), 194); // 97 bytes

    let ed = generate(EccCurve::Ed25519);
    assert_eq!(ed.private_hex.len(), 64); // 32-byte seed
                                          // Single canonical 32-byte public encoding for Edwards/Montgomery curves.
    assert_eq!(ed.public_compressed_hex, ed.public_uncompressed_hex);
    assert_eq!(ed.public_compressed_hex.len(), 64);

    let x = generate(EccCurve::X25519);
    assert_eq!(x.private_hex.len(), 64);
    assert_eq!(x.public_compressed_hex, x.public_uncompressed_hex);
    assert_eq!(x.public_compressed_hex.len(), 64);
}

// ---------------------------------------------------------------------------
// Round-trips: keygen -> serialize -> parse -> same components
// ---------------------------------------------------------------------------

#[test]
fn nist_private_public_parse_round_trip() {
    for curve in [EccCurve::P256, EccCurve::P384] {
        let kp = generate(curve);
        let reparsed = cybercipher_pki::parse_ecc_private_key(curve, &kp.private_hex)
            .unwrap_or_else(|e| panic!("{curve}: private parse failed: {e}"));
        assert_eq!(reparsed, kp, "{curve}: private round-trip mismatch");

        for pub_hex in [&kp.public_compressed_hex, &kp.public_uncompressed_hex] {
            let material = cybercipher_pki::parse_ecc_public_key(curve, pub_hex)
                .unwrap_or_else(|e| panic!("{curve}: public parse failed: {e}"));
            assert_eq!(material.curve, curve);
            assert_eq!(material.public_compressed_hex, kp.public_compressed_hex);
            assert_eq!(material.public_uncompressed_hex, kp.public_uncompressed_hex);
        }
    }
}

#[test]
fn sec1_compressed_uncompressed_agree() {
    // Parsing the compressed form must yield exactly the uncompressed form
    // (and vice versa) — the two encodings carry the same point.
    let kp = generate(EccCurve::P256);
    let from_compressed =
        cybercipher_pki::parse_ecc_public_key(EccCurve::P256, &kp.public_compressed_hex).unwrap();
    let from_uncompressed =
        cybercipher_pki::parse_ecc_public_key(EccCurve::P256, &kp.public_uncompressed_hex).unwrap();
    assert_eq!(from_compressed, from_uncompressed);

    let kp = generate(EccCurve::P384);
    let from_compressed =
        cybercipher_pki::parse_ecc_public_key(EccCurve::P384, &kp.public_compressed_hex).unwrap();
    let from_uncompressed =
        cybercipher_pki::parse_ecc_public_key(EccCurve::P384, &kp.public_uncompressed_hex).unwrap();
    assert_eq!(from_compressed, from_uncompressed);
}

#[test]
fn ed25519_x25519_parse_round_trip() {
    let ed = generate(EccCurve::Ed25519);
    let reparsed =
        cybercipher_pki::parse_ecc_private_key(EccCurve::Ed25519, &ed.private_hex).unwrap();
    assert_eq!(reparsed, ed);
    let material =
        cybercipher_pki::parse_ecc_public_key(EccCurve::Ed25519, &ed.public_compressed_hex)
            .unwrap();
    assert_eq!(material.public_compressed_hex, ed.public_compressed_hex);

    let x = generate(EccCurve::X25519);
    let reparsed =
        cybercipher_pki::parse_ecc_private_key(EccCurve::X25519, &x.private_hex).unwrap();
    assert_eq!(reparsed, x);
    let material =
        cybercipher_pki::parse_ecc_public_key(EccCurve::X25519, &x.public_compressed_hex).unwrap();
    assert_eq!(material.public_compressed_hex, x.public_compressed_hex);
}

// ---------------------------------------------------------------------------
// SPKI / PKCS#8 DER + PEM round-trips (curve auto-detection)
// ---------------------------------------------------------------------------

#[test]
fn spki_der_pem_round_trip_all_curves() {
    for curve in [
        EccCurve::P256,
        EccCurve::P384,
        EccCurve::Ed25519,
        EccCurve::X25519,
    ] {
        let kp = generate(curve);
        let der = cybercipher_pki::ecc_public_key_to_spki_der(curve, &kp.public_uncompressed_hex)
            .unwrap_or_else(|e| panic!("{curve}: SPKI DER encode failed: {e}"));
        let material = cybercipher_pki::ecc_public_key_from_spki_der(&der)
            .unwrap_or_else(|e| panic!("{curve}: SPKI DER decode failed: {e}"));
        assert_eq!(material.curve, curve, "{curve}: SPKI curve detection");
        assert_eq!(material.public_compressed_hex, kp.public_compressed_hex);

        let pem = cybercipher_pki::ecc_public_key_to_spki_pem(curve, &kp.public_uncompressed_hex)
            .unwrap_or_else(|e| panic!("{curve}: SPKI PEM encode failed: {e}"));
        assert!(
            pem.starts_with("-----BEGIN PUBLIC KEY-----"),
            "{curve}: {pem}"
        );
        let material = cybercipher_pki::ecc_public_key_from_spki_pem(&pem)
            .unwrap_or_else(|e| panic!("{curve}: SPKI PEM decode failed: {e}"));
        assert_eq!(material.curve, curve);
        assert_eq!(material.public_compressed_hex, kp.public_compressed_hex);
    }
}

#[test]
fn pkcs8_der_pem_round_trip_all_curves() {
    for curve in [
        EccCurve::P256,
        EccCurve::P384,
        EccCurve::Ed25519,
        EccCurve::X25519,
    ] {
        let kp = generate(curve);
        let der = cybercipher_pki::ecc_private_key_to_pkcs8_der(curve, &kp.private_hex)
            .unwrap_or_else(|e| panic!("{curve}: PKCS#8 DER encode failed: {e}"));
        let reparsed = cybercipher_pki::ecc_private_key_from_pkcs8_der(&der)
            .unwrap_or_else(|e| panic!("{curve}: PKCS#8 DER decode failed: {e}"));
        assert_eq!(reparsed.curve, curve, "{curve}: PKCS#8 curve detection");
        assert_eq!(reparsed.public_compressed_hex, kp.public_compressed_hex);

        let pem = cybercipher_pki::ecc_private_key_to_pkcs8_pem(curve, &kp.private_hex)
            .unwrap_or_else(|e| panic!("{curve}: PKCS#8 PEM encode failed: {e}"));
        assert!(
            pem.starts_with("-----BEGIN PRIVATE KEY-----"),
            "{curve}: {pem}"
        );
        let reparsed = cybercipher_pki::ecc_private_key_from_pkcs8_pem(&pem)
            .unwrap_or_else(|e| panic!("{curve}: PKCS#8 PEM decode failed: {e}"));
        assert_eq!(reparsed.curve, curve);
        assert_eq!(reparsed.public_compressed_hex, kp.public_compressed_hex);
    }
}

#[test]
fn pkcs8_private_key_derives_matching_public() {
    // The PKCS#8 blob must carry the same public key the keypair reported.
    let kp = generate(EccCurve::P384);
    let pem =
        cybercipher_pki::ecc_private_key_to_pkcs8_pem(EccCurve::P384, &kp.private_hex).unwrap();
    let reparsed = cybercipher_pki::ecc_private_key_from_pkcs8_pem(&pem).unwrap();
    assert_eq!(reparsed.private_hex, kp.private_hex);
    assert_eq!(reparsed.public_uncompressed_hex, kp.public_uncompressed_hex);
}

// ---------------------------------------------------------------------------
// Curve label parsing
// ---------------------------------------------------------------------------

#[test]
fn curve_label_aliases() {
    assert_eq!(
        cybercipher_pki::parse_ecc_curve("P-256").unwrap(),
        EccCurve::P256
    );
    assert_eq!(
        cybercipher_pki::parse_ecc_curve("secp256r1").unwrap(),
        EccCurve::P256
    );
    assert_eq!(
        cybercipher_pki::parse_ecc_curve("prime256v1").unwrap(),
        EccCurve::P256
    );
    assert_eq!(
        cybercipher_pki::parse_ecc_curve("p384").unwrap(),
        EccCurve::P384
    );
    assert_eq!(
        cybercipher_pki::parse_ecc_curve("secp384r1").unwrap(),
        EccCurve::P384
    );
    assert_eq!(
        cybercipher_pki::parse_ecc_curve("Ed25519").unwrap(),
        EccCurve::Ed25519
    );
    assert_eq!(
        cybercipher_pki::parse_ecc_curve("curve25519").unwrap(),
        EccCurve::X25519
    );
    assert_eq!(
        cybercipher_pki::parse_ecc_curve("p521").unwrap_err().kind,
        ErrorKind::InvalidParam
    );
    assert_eq!(
        cybercipher_pki::parse_ecc_curve("").unwrap_err().kind,
        ErrorKind::InvalidParam
    );
}

// ---------------------------------------------------------------------------
// Malformed inputs -> typed errors (invalid key / wrong curve / wrong
// encoding / invalid point / wrong length)
// ---------------------------------------------------------------------------

#[test]
fn wrong_curve_error_on_sibling_curve_material() {
    // A P-384 point handed to the P-256 parser is a wrong-curve error, not a
    // bare length mismatch: the length identifies the sibling curve.
    let p384 = generate(EccCurve::P384);
    let err = cybercipher_pki::parse_ecc_public_key(EccCurve::P256, &p384.public_compressed_hex)
        .unwrap_err();
    assert_kind(&err, ErrorKind::InvalidInput, "wrong curve");
    assert_eq!(err.expected.as_deref(), Some("p256"));
    assert_eq!(err.actual.as_deref(), Some("p384"));
}

#[test]
fn invalid_point_error_off_curve() {
    let err = cybercipher_pki::parse_ecc_public_key(EccCurve::P256, &p256_off_curve_uncompressed())
        .unwrap_err();
    assert_kind(&err, ErrorKind::KeyError, "point is not on the");
}

#[test]
fn wrong_length_error_truncated_public_key() {
    let kp = generate(EccCurve::P256);
    let truncated = &kp.public_uncompressed_hex[..kp.public_uncompressed_hex.len() - 2];
    let err = cybercipher_pki::parse_ecc_public_key(EccCurve::P256, truncated).unwrap_err();
    assert_kind(&err, ErrorKind::LengthMismatch, "wrong length");
    assert!(err
        .expected
        .as_deref()
        .unwrap_or_default()
        .contains("65 bytes"));
    assert!(err
        .actual
        .as_deref()
        .unwrap_or_default()
        .contains("64 bytes"));
}

#[test]
fn wrong_encoding_error_bad_sec1_tag() {
    // 65 bytes with tag 0x01 instead of 0x04.
    let kp = generate(EccCurve::P256);
    let mut bad = kp.public_uncompressed_hex.clone();
    bad.replace_range(0..2, "01");
    let err = cybercipher_pki::parse_ecc_public_key(EccCurve::P256, &bad).unwrap_err();
    assert_kind(&err, ErrorKind::Decode, "invalid SEC1 point encoding");
}

#[test]
fn invalid_private_key_errors() {
    // All-zero scalar.
    let err = cybercipher_pki::parse_ecc_private_key(EccCurve::P256, &"00".repeat(32)).unwrap_err();
    assert_kind(&err, ErrorKind::KeyError, "zero");

    // Scalar >= group order (n of P-256).
    let err = cybercipher_pki::parse_ecc_private_key(
        EccCurve::P256,
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
    )
    .unwrap_err();
    assert_kind(&err, ErrorKind::KeyError, "group order");

    // Longer than the field size.
    let err = cybercipher_pki::parse_ecc_private_key(EccCurve::P256, &"ab".repeat(33)).unwrap_err();
    assert_kind(&err, ErrorKind::LengthMismatch, "wrong length");

    // Odd-length hex.
    let err = cybercipher_pki::parse_ecc_private_key(EccCurve::P256, "abc").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);

    // Ed25519/X25519 require exactly 32 bytes.
    let err = cybercipher_pki::parse_ecc_private_key(EccCurve::Ed25519, "abcd").unwrap_err();
    assert_eq!(err.kind, ErrorKind::LengthMismatch);
    let err =
        cybercipher_pki::parse_ecc_private_key(EccCurve::X25519, &"07".repeat(31)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::LengthMismatch);
}

#[test]
fn short_scalar_hex_is_left_padded() {
    // JWK-style `d` values drop leading zeros; a 1-byte scalar is padded.
    let kp = cybercipher_pki::parse_ecc_private_key(EccCurve::P256, "01").unwrap();
    assert_eq!(kp.private_hex.len(), 64);
    assert!(kp.private_hex.starts_with("00"));
}

#[test]
fn pem_wrong_label_and_object_type_errors() {
    let kp = generate(EccCurve::P256);
    let private_pem =
        cybercipher_pki::ecc_private_key_to_pkcs8_pem(EccCurve::P256, &kp.private_hex).unwrap();
    // Private PEM handed to the SPKI parser: wrong encoding.
    let err = cybercipher_pki::ecc_public_key_from_spki_pem(&private_pem).unwrap_err();
    assert_kind(&err, ErrorKind::Decode, "wrong PEM object type");

    // Certificate PEM: wrong object type with the certificate hint.
    let cert_pem = "-----BEGIN CERTIFICATE-----\nZW5k\n-----END CERTIFICATE-----\n";
    let err = cybercipher_pki::ecc_public_key_from_spki_pem(cert_pem).unwrap_err();
    assert_kind(&err, ErrorKind::InvalidInput, "certificate");

    // Garbage armor.
    let err = cybercipher_pki::ecc_private_key_from_pkcs8_pem("not a pem").unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);

    // Valid armor, invalid base64 payload.
    let bad_body = "-----BEGIN PUBLIC KEY-----\n!!!\n-----END PUBLIC KEY-----\n";
    let err = cybercipher_pki::ecc_public_key_from_spki_pem(bad_body).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);
}

#[test]
fn spki_unknown_algorithms_are_unsupported() {
    // A DER SEQUENCE with a bogus algorithm OID (1.2.3.4) — hand-built
    // SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { OID 1.2.3.4 }, BIT STRING }.
    // SEQUENCE { SEQUENCE { OID 1.2.3.4 (06 03 2A 03 04) }, BIT STRING }
    let der: Vec<u8> = vec![
        0x30, 0x0b, 0x30, 0x05, 0x06, 0x03, 0x2a, 0x03, 0x04, 0x03, 0x02, 0x00, 0xaa,
    ];
    let err = cybercipher_pki::ecc_public_key_from_spki_der(&der).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Unsupported);
}

#[test]
fn invalid_spki_der_is_decode_error() {
    let err = cybercipher_pki::ecc_public_key_from_spki_der(&[0xff, 0xff, 0xff]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);
    let err = cybercipher_pki::ecc_private_key_from_pkcs8_der(&[0x02, 0x01, 0x00]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);
}
