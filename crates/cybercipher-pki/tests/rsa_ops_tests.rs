//! RSA operations acceptance tests (M8-PKI-B/C): OAEP/PKCS#1 v1.5
//! encryption, PKCS#1 v1.5/PSS signatures, PEM-level wrappers, negatives.
//! Keys are generated in-test (2048-bit, fast enough for CI).

#![allow(clippy::result_large_err)]

use cybercipher_pki::keys::{generate_rsa_keypair, parse_pem, RsaKeypair};
use cybercipher_pki::ops::encrypt::{
    rsa_decrypt_oaep, rsa_decrypt_pkcs1v15, rsa_encrypt_oaep, rsa_encrypt_pkcs1v15,
};
use cybercipher_pki::ops::pem::{
    rsa_decrypt_oaep_pem, rsa_encrypt_oaep_pem, rsa_sign_pkcs1v15_pem, rsa_verify_pkcs1v15_pem,
};
use cybercipher_pki::ops::sign::{
    rsa_sign_pkcs1v15, rsa_sign_pss, rsa_verify_pkcs1v15, rsa_verify_pss,
};
use cybercipher_pki::RsaDigest;

fn keypair_2048() -> RsaKeypair {
    generate_rsa_keypair(2048, "010001").unwrap()
}

const MSG: &[u8] = b"PKI operations acceptance test message";

#[test]
fn oaep_sha256_round_trip() {
    let kp = keypair_2048();
    let public = kp.public_material();
    let private = kp.material();
    let ct = rsa_encrypt_oaep(&public, MSG, RsaDigest::Sha256, None).unwrap();
    assert_eq!(ct.len(), 256, "2048-bit ciphertext is 256 bytes");
    let pt = rsa_decrypt_oaep(&private, &ct, RsaDigest::Sha256, None).unwrap();
    assert_eq!(pt, MSG);
}

#[test]
fn oaep_label_round_trip_and_hash_variants() {
    let kp = keypair_2048();
    let public = kp.public_material();
    let private = kp.material();
    let label = Some(b"ctf-context".as_slice());
    for hash in [RsaDigest::Sha1, RsaDigest::Sha256, RsaDigest::Sha512] {
        let ct = rsa_encrypt_oaep(&public, MSG, hash, label).unwrap();
        let pt = rsa_decrypt_oaep(&private, &ct, hash, label).unwrap();
        assert_eq!(pt, MSG, "{:?}", hash.label());
    }
    // Wrong label must fail decryption (typed error, not garbage).
    let ct = rsa_encrypt_oaep(&public, MSG, RsaDigest::Sha256, label).unwrap();
    assert!(rsa_decrypt_oaep(&private, &ct, RsaDigest::Sha256, Some(b"other")).is_err());
}

#[test]
fn oaep_plaintext_too_long_rejected() {
    let kp = keypair_2048();
    let public = kp.public_material();
    // 200 bytes > k - 2*32 - 2 = 190 for OAEP-SHA256 at 2048 bits.
    let err = rsa_encrypt_oaep(&public, &[0u8; 200], RsaDigest::Sha256, None).unwrap_err();
    assert_eq!(
        err.expected.as_deref(),
        Some("at most 190 bytes (k - 2*32 - 2)")
    );
}

#[test]
fn pkcs1v15_encrypt_round_trip_and_short_ct() {
    let kp = keypair_2048();
    let public = kp.public_material();
    let private = kp.material();
    let ct = rsa_encrypt_pkcs1v15(&public, MSG).unwrap();
    let pt = rsa_decrypt_pkcs1v15(&private, &ct).unwrap();
    assert_eq!(pt, MSG);
    // Decrypting a too-short ciphertext is a typed length error.
    let err = rsa_decrypt_pkcs1v15(&private, &[0u8; 8]).unwrap_err();
    assert_eq!(err.kind, cybercipher_core::ErrorKind::LengthMismatch);
}

#[test]
fn pkcs1v15_signature_sign_verify_and_tamper() {
    let kp = keypair_2048();
    let public = kp.public_material();
    let private = kp.material();
    let sig = rsa_sign_pkcs1v15(&private, RsaDigest::Sha256, MSG).unwrap();
    assert_eq!(sig.len(), 256);
    let verdict = rsa_verify_pkcs1v15(&public, RsaDigest::Sha256, MSG, &sig).unwrap();
    assert!(verdict.valid, "correct signature must verify");
    // Tampered data → invalid, not an error.
    let verdict = rsa_verify_pkcs1v15(&public, RsaDigest::Sha256, b"tampered", &sig).unwrap();
    assert!(!verdict.valid);
    assert!(verdict.reason.is_some());
}

#[test]
fn pss_signature_round_trips() {
    let kp = keypair_2048();
    let public = kp.public_material();
    let private = kp.material();
    for salt in pss_salts() {
        let sig = rsa_sign_pss(&private, RsaDigest::Sha256, MSG, salt).unwrap();
        let verdict = rsa_verify_pss(&public, RsaDigest::Sha256, MSG, &sig, salt).unwrap();
        assert!(verdict.valid, "salt {salt:?}");
        // PSS with a random salt: a second signature differs but still verifies.
        let sig2 = rsa_sign_pss(&private, RsaDigest::Sha256, MSG, salt).unwrap();
        assert_ne!(sig, sig2, "random salt must produce distinct signatures");
        let verdict2 = rsa_verify_pss(&public, RsaDigest::Sha256, MSG, &sig2, salt).unwrap();
        assert!(verdict2.valid);
    }
    // Tampered signature → invalid.
    let sig = rsa_sign_pss(&private, RsaDigest::Sha256, MSG, default_salt()).unwrap();
    let mut bad = sig.clone();
    bad[0] ^= 0xff;
    let verdict = rsa_verify_pss(&public, RsaDigest::Sha256, MSG, &bad, default_salt()).unwrap();
    assert!(!verdict.valid);
}

#[test]
fn pem_level_wrappers_round_trip() {
    let kp = keypair_2048();
    let pem = kp.to_pkcs8_pem().unwrap();
    // Parse back to sanity-check the PEM wrapper path uses the same parse
    // machinery as the keys module.
    let parsed = parse_pem(&pem).unwrap();
    assert!(matches!(
        parsed,
        cybercipher_pki::keys::pem::ParsedKey::Private { .. }
    ));

    let public_pem = kp.to_public_spki_pem().unwrap();
    let ct = rsa_encrypt_oaep_pem(&public_pem, MSG, RsaDigest::Sha256, None).unwrap();
    let pt = rsa_decrypt_oaep_pem(&pem, &ct, RsaDigest::Sha256, None).unwrap();
    assert_eq!(pt, MSG);

    let sig = rsa_sign_pkcs1v15_pem(&pem, "sha256", MSG).unwrap();
    let verdict = rsa_verify_pkcs1v15_pem(&public_pem, "sha256", MSG, &hex_str(&sig)).unwrap();
    assert!(verdict.valid);
}

#[test]
fn wrong_key_decrypt_is_typed_error() {
    let kp1 = keypair_2048();
    let kp2 = generate_rsa_keypair(2048, "010001").unwrap();
    let ct = rsa_encrypt_oaep(&kp1.public_material(), MSG, RsaDigest::Sha256, None).unwrap();
    // kp2 cannot decrypt kp1's ciphertext: typed error, not a panic.
    assert!(rsa_decrypt_oaep(&kp2.material(), &ct, RsaDigest::Sha256, None).is_err());
}

fn pss_salts() -> Vec<cybercipher_pki::PssSaltLength> {
    vec![
        cybercipher_pki::PssSaltLength::Digest,
        cybercipher_pki::PssSaltLength::Fixed(32),
    ]
}

fn default_salt() -> cybercipher_pki::PssSaltLength {
    cybercipher_pki::PssSaltLength::Digest
}

fn hex_str(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
