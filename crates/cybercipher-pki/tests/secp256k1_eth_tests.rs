//! secp256k1 (Bitcoin/Ethereum) tests: Wycheproof ECDSA SHA-256 verification
//! vectors, sign/verify roundtrips, key-format roundtrips, EIP-55 checksum
//! vectors (from the EIP-55 specification), and the canonical private-key-1
//! Ethereum address.

use cybercipher_core::ErrorKind;
use cybercipher_pki::ecc::curve::EccCurve;
use cybercipher_pki::error::PkiError;
use cybercipher_pki::{
    ecdsa_sign, ecdsa_signature_der_to_fixed, ecdsa_verify, eth_address_check,
    eth_address_from_private, eth_address_from_public, generate_ecc_keypair, parse_ecc_curve,
    parse_ecc_private_key, parse_ecc_public_key, EcdsaDigest, EcdsaNonceMode, EcdsaSignatureFormat,
};

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

// ---------------------------------------------------------------------------
// Key generation, parsing, key formats
// ---------------------------------------------------------------------------

#[test]
fn keygen_transport_shapes() {
    let kp = generate_ecc_keypair(EccCurve::Secp256k1).unwrap();
    assert_eq!(kp.curve, EccCurve::Secp256k1);
    assert_eq!(kp.private_hex.len(), 64); // 32-byte scalar
    assert_eq!(kp.public_compressed_hex.len(), 66); // 33-byte SEC1
    assert_eq!(kp.public_uncompressed_hex.len(), 130); // 65-byte SEC1
    assert!(
        kp.public_compressed_hex.starts_with("02") || kp.public_compressed_hex.starts_with("03")
    );
    assert!(kp.public_uncompressed_hex.starts_with("04"));
}

#[test]
fn private_key_1_public_key_is_the_generator() {
    // The secp256k1 generator (SEC 2 v2 section 2.4.1):
    // Gx = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
    let kp = parse_ecc_private_key(EccCurve::Secp256k1, "01").unwrap();
    assert_eq!(
        kp.public_uncompressed_hex.to_ascii_lowercase(),
        "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
    );
}

#[test]
fn parse_rejects_bad_scalars() {
    // Zero scalar.
    let err = parse_ecc_private_key(EccCurve::Secp256k1, "00").unwrap_err();
    assert_kind(&err, ErrorKind::KeyError, "zero");
    // Group order n is not a valid scalar.
    let err = parse_ecc_private_key(
        EccCurve::Secp256k1,
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
    )
    .unwrap_err();
    assert_kind(&err, ErrorKind::KeyError, "range");
    // 33-byte input is too long (length errors carry expected/actual as
    // structured fields; the message is a generic "wrong length").
    let err = parse_ecc_private_key(EccCurve::Secp256k1, &format!("01{:0>64}", "")).unwrap_err();
    assert_eq!(err.kind, ErrorKind::LengthMismatch);
}

#[test]
fn spki_pkcs8_roundtrips() {
    let kp = generate_ecc_keypair(EccCurve::Secp256k1).unwrap();

    let spki_der =
        cybercipher_pki::ecc_public_key_to_spki_der(EccCurve::Secp256k1, &kp.public_compressed_hex)
            .unwrap();
    let parsed = cybercipher_pki::ecc_public_key_from_spki_der(&spki_der).unwrap();
    assert_eq!(parsed.curve, EccCurve::Secp256k1);
    assert_eq!(parsed.public_compressed_hex, kp.public_compressed_hex);
    assert_eq!(parsed.public_uncompressed_hex, kp.public_uncompressed_hex);

    let pkcs8_der =
        cybercipher_pki::ecc_private_key_to_pkcs8_der(EccCurve::Secp256k1, &kp.private_hex)
            .unwrap();
    let parsed = cybercipher_pki::ecc_private_key_from_pkcs8_der(&pkcs8_der).unwrap();
    assert_eq!(parsed.curve, EccCurve::Secp256k1);
    assert_eq!(parsed.private_hex, kp.private_hex);
    assert_eq!(parsed.public_uncompressed_hex, kp.public_uncompressed_hex);

    let pem = cybercipher_pki::ecc_private_key_to_pkcs8_pem(EccCurve::Secp256k1, &kp.private_hex)
        .unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
    let parsed = cybercipher_pki::ecc_private_key_from_pkcs8_pem(&pem).unwrap();
    assert_eq!(parsed.private_hex, kp.private_hex);
}

// ---------------------------------------------------------------------------
// ECDSA sign/verify
// ---------------------------------------------------------------------------

#[test]
fn ecdsa_sign_verify_roundtrip() {
    let kp = generate_ecc_keypair(EccCurve::Secp256k1).unwrap();
    let msg = b"attack at dawn";

    let sig_der = ecdsa_sign(
        EccCurve::Secp256k1,
        &kp.private_hex,
        msg,
        EcdsaDigest::Sha256,
        EcdsaNonceMode::Deterministic,
        EcdsaSignatureFormat::Der,
    )
    .unwrap();
    // secp256k1 DER signatures are 70-72 bytes.
    assert!((sig_der.len() == 140) || (sig_der.len() == 142) || (sig_der.len() == 144));

    let verdict = ecdsa_verify(
        EccCurve::Secp256k1,
        &kp.public_compressed_hex,
        msg,
        EcdsaDigest::Sha256,
        EcdsaSignatureFormat::Der,
        &sig_der,
    )
    .unwrap();
    assert!(verdict.valid, "deterministic signature must verify");

    // Fixed-size form: 64 bytes r||s.
    let sig_fixed = ecdsa_sign(
        EccCurve::Secp256k1,
        &kp.private_hex,
        msg,
        EcdsaDigest::Sha256,
        EcdsaNonceMode::Deterministic,
        EcdsaSignatureFormat::Fixed,
    )
    .unwrap();
    assert_eq!(sig_fixed.len(), 128);
    let verdict = ecdsa_verify(
        EccCurve::Secp256k1,
        &kp.public_uncompressed_hex,
        msg,
        EcdsaDigest::Sha256,
        EcdsaSignatureFormat::Fixed,
        &sig_fixed,
    )
    .unwrap();
    assert!(verdict.valid);

    // DER <-> fixed conversion agrees.
    let fixed_from_der = ecdsa_signature_der_to_fixed(EccCurve::Secp256k1, &sig_der).unwrap();
    assert_eq!(fixed_from_der, sig_fixed);
}

#[test]
fn ecdsa_deterministic_signing_is_stable() {
    let kp = generate_ecc_keypair(EccCurve::Secp256k1).unwrap();
    let msg = b"stable";
    let s1 = ecdsa_sign(
        EccCurve::Secp256k1,
        &kp.private_hex,
        msg,
        EcdsaDigest::Sha256,
        EcdsaNonceMode::Deterministic,
        EcdsaSignatureFormat::Fixed,
    )
    .unwrap();
    let s2 = ecdsa_sign(
        EccCurve::Secp256k1,
        &kp.private_hex,
        msg,
        EcdsaDigest::Sha256,
        EcdsaNonceMode::Deterministic,
        EcdsaSignatureFormat::Fixed,
    )
    .unwrap();
    assert_eq!(s1, s2);
}

#[test]
fn ecdsa_tampered_signature_is_invalid() {
    let kp = generate_ecc_keypair(EccCurve::Secp256k1).unwrap();
    let msg = b"tamper test";
    let sig = ecdsa_sign(
        EccCurve::Secp256k1,
        &kp.private_hex,
        msg,
        EcdsaDigest::Sha256,
        EcdsaNonceMode::Deterministic,
        EcdsaSignatureFormat::Fixed,
    )
    .unwrap();
    // Flip one nibble in s.
    let mut tampered = sig.clone();
    tampered.replace_range(126..128, if &sig[126..128] == "00" { "11" } else { "00" });
    let verdict = ecdsa_verify(
        EccCurve::Secp256k1,
        &kp.public_uncompressed_hex,
        msg,
        EcdsaDigest::Sha256,
        EcdsaSignatureFormat::Fixed,
        &tampered,
    )
    .unwrap();
    assert!(!verdict.valid);
    assert!(verdict.reason.is_some());

    // Wrong message.
    let verdict = ecdsa_verify(
        EccCurve::Secp256k1,
        &kp.public_uncompressed_hex,
        b"other message",
        EcdsaDigest::Sha256,
        EcdsaSignatureFormat::Fixed,
        &sig,
    )
    .unwrap();
    assert!(!verdict.valid);
}

/// Project Wycheproof `ecdsa_secp256k1_sha256_test.json`, test group 0
/// (fetched 2026-10-03): valid low-s verification vectors. The high-s
/// variants of the same vectors are rejected by the underlying `ecdsa`
/// crate (normalized low-s policy), covered by the dedicated test below.
#[test]
fn ecdsa_wycheproof_secp256k1_sha256_vectors() {
    const PUBLIC: &str = "04782c8ed17e3b2a783b5464f33b09652a71c678e05ec51e84e2bcfc663a3de96\
         3af9acb4280b8c7f7c42f4ef9aba6245ec1ec1712fd38a0fa96418d8cd6aa6152";
    let cases: &[(&[u8], &str)] = &[
        // tcId 3: msg "123400".
        (
            b"123400",
            "3045022100d035ee1f17fdb0b2681b163e33c359932659990af77dca632012b30b27a057b302201939d9f3b2858bc13e3474cb50e6a82be44faa71940f876c1cba4c3e989202b6",
        ),
        // tcId 4: msg of 20 zero bytes.
        (
            &[0u8; 20],
            "304402204f053f563ad34b74fd8c9934ce59e79c2eb8e6eca0fef5b323ca67d5ac7ed23802204d4b05daa0719e773d8617dce5631c5fd6f59c9bdc748e4b55c970040af01be5",
        ),
    ];
    for (msg, sig) in cases {
        let verdict = ecdsa_verify(
            EccCurve::Secp256k1,
            PUBLIC,
            msg,
            EcdsaDigest::Sha256,
            EcdsaSignatureFormat::Der,
            sig,
        )
        .unwrap();
        assert!(verdict.valid, "wycheproof vector must verify: {sig}");
    }
}

/// Wycheproof tcId 1 (same group): a mathematically valid but *high-s*
/// signature is rejected — the `ecdsa` crate enforces the low-s convention,
/// so the verify result is `valid == false` rather than an error.
#[test]
fn ecdsa_rejects_high_s_signatures() {
    const PUBLIC: &str = "04782c8ed17e3b2a783b5464f33b09652a71c678e05ec51e84e2bcfc663a3de96\
         3af9acb4280b8c7f7c42f4ef9aba6245ec1ec1712fd38a0fa96418d8cd6aa6152";
    let verdict = ecdsa_verify(
        EccCurve::Secp256k1,
        PUBLIC,
        b"",
        EcdsaDigest::Sha256,
        EcdsaSignatureFormat::Der,
        "3046022100f80ae4f96cdbc9d853f83d47aae225bf407d51c56b7776cd67d0dc195d99a9dc022100b303e26be1f73465315221f0b331528807a1a9b6eb068ede6eebeaaa49af8a36",
    )
    .unwrap();
    assert!(!verdict.valid);
}

#[test]
fn ecdsa_rejects_mismatched_pairings() {
    let kp = generate_ecc_keypair(EccCurve::Secp256k1).unwrap();
    // SHA-384 is not a secp256k1 pairing.
    let err = ecdsa_sign(
        EccCurve::Secp256k1,
        &kp.private_hex,
        b"x",
        EcdsaDigest::Sha384,
        EcdsaNonceMode::Deterministic,
        EcdsaSignatureFormat::Fixed,
    )
    .unwrap_err();
    assert_kind(&err, ErrorKind::InvalidParam, "sha256");
    // P-384 keys are not secp256k1 keys.
    let p384 = generate_ecc_keypair(EccCurve::P384).unwrap();
    let err = ecdsa_sign(
        EccCurve::Secp256k1,
        &p384.private_hex,
        b"x",
        EcdsaDigest::Sha256,
        EcdsaNonceMode::Deterministic,
        EcdsaSignatureFormat::Fixed,
    )
    .unwrap_err();
    assert_eq!(err.kind, ErrorKind::LengthMismatch);
}

// ---------------------------------------------------------------------------
// ECDH
// ---------------------------------------------------------------------------

#[test]
fn ecdh_shared_secret_agreement() {
    let a = generate_ecc_keypair(EccCurve::Secp256k1).unwrap();
    let b = generate_ecc_keypair(EccCurve::Secp256k1).unwrap();
    let ab = cybercipher_pki::ecdh_shared_secret(
        EccCurve::Secp256k1,
        &a.private_hex,
        &b.public_uncompressed_hex,
    )
    .unwrap();
    let ba = cybercipher_pki::ecdh_shared_secret(
        EccCurve::Secp256k1,
        &b.private_hex,
        &a.public_compressed_hex,
    )
    .unwrap();
    assert_eq!(ab, ba);
    assert_eq!(ab.len(), 64);
}

// ---------------------------------------------------------------------------
// ETH addresses (EIP-55)
// ---------------------------------------------------------------------------

/// EIP-55 test vectors, quoted verbatim from the EIP-55 specification
/// (https://eips.ethereum.org/EIPS/eip-55).
#[test]
fn eth_eip55_spec_vectors() {
    let vectors = [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ];
    for vector in vectors {
        let check = eth_address_check(vector).unwrap();
        assert!(check.checksum_valid, "{vector} must carry a valid checksum");
        assert!(check.has_checksum, "{vector} must be mixed-case");
        // Re-encoding the checksum reproduces the input exactly.
        assert_eq!(check.address, vector);
        assert_eq!(check.address_lowercase, vector.to_ascii_lowercase());
    }
}

/// The canonical weak-key vector: private key 0x…01 derives the well-known
/// address 0x7E5F…5Bdf (see e.g. ISE "Ethercombing" case study).
#[test]
fn eth_private_key_one_address() {
    let address = eth_address_from_private(
        "0000000000000000000000000000000000000000000000000000000000000001",
    )
    .unwrap();
    assert_eq!(address, "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");

    // Same address derived from the generator public key.
    let kp = parse_ecc_private_key(EccCurve::Secp256k1, "01").unwrap();
    let from_public = eth_address_from_public(&kp.public_uncompressed_hex).unwrap();
    assert_eq!(from_public, address);
    let from_compressed = eth_address_from_public(&kp.public_compressed_hex).unwrap();
    assert_eq!(from_compressed, address);
}

#[test]
fn eth_address_roundtrip_and_case_checks() {
    let kp = generate_ecc_keypair(EccCurve::Secp256k1).unwrap();
    let address = eth_address_from_private(&kp.private_hex).unwrap();
    assert_eq!(address.len(), 42);
    assert!(address.starts_with("0x"));

    // The derived address verifies against itself.
    let check = eth_address_check(&address).unwrap();
    assert!(check.checksum_valid && check.has_checksum);
    assert_eq!(check.address, address);
    assert_eq!(check.address_lowercase, address.to_ascii_lowercase());

    // Lowercase / uppercase forms carry no checksum info and are accepted.
    let check = eth_address_check(&address.to_ascii_lowercase()).unwrap();
    assert!(check.checksum_valid && !check.has_checksum);
    let check = eth_address_check(&address.to_ascii_uppercase()).unwrap();
    assert!(check.checksum_valid && !check.has_checksum);

    // A broken mixed-case checksum is a result (valid == false), not an error.
    // Flip the case of the first alphabetic character after 0x; when that
    // breaks EIP-55 the check must report it.
    let chars: Vec<char> = address.chars().collect();
    let mut broken = chars.clone();
    for i in 2..chars.len() {
        if chars[i].is_ascii_alphabetic() {
            broken[i] = if chars[i].is_ascii_uppercase() {
                chars[i].to_ascii_lowercase()
            } else {
                chars[i].to_ascii_uppercase()
            };
            break;
        }
    }
    let broken: String = broken.into_iter().collect();
    let check = eth_address_check(&broken).unwrap();
    if broken == address {
        // The flipped character carries no checksum information for this
        // address; nothing to assert.
    } else {
        assert!(check.has_checksum);
        assert!(!check.checksum_valid, "broken checksum must be reported");
    }
}

#[test]
fn eth_address_malformed_inputs_are_typed_errors() {
    let err = eth_address_check("0x1234").unwrap_err();
    assert_eq!(err.kind, ErrorKind::LengthMismatch);
    let err = eth_address_check("0xzz").unwrap_err();
    assert_kind(&err, ErrorKind::Decode, "hex");
    let err = eth_address_check("").unwrap_err();
    assert_kind(&err, ErrorKind::Decode, "empty");
    let err = eth_address_from_private("00").unwrap_err();
    assert_kind(&err, ErrorKind::KeyError, "zero");
}

// ---------------------------------------------------------------------------
// Curve labels / registry helpers
// ---------------------------------------------------------------------------

#[test]
fn curve_label_aliases() {
    assert_eq!(parse_ecc_curve("secp256k1").unwrap(), EccCurve::Secp256k1);
    assert_eq!(parse_ecc_curve("K256").unwrap(), EccCurve::Secp256k1);
    assert_eq!(
        parse_ecc_public_key(EccCurve::Secp256k1, "zz").is_err(),
        true
    );
}
