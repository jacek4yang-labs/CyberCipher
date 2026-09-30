//! Integration tests for the X.509 certificate / CSR / CRL inspectors.
//!
//! Fixtures are a small PKI generated at test-write time with OpenSSL 3.x
//! (a self-signed RSA-2048 root CA, an RSA leaf certificate issued by it, an
//! RSA and a P-256 CSR, and a CRL revoking the leaf serial). They are
//! committed as PEM constants; the DER-path test decodes the leaf certificate
//! from a base64 blob. Expected values (serials, validity instants, key
//! identifiers) were read from `openssl x509/crl -text` when the fixtures
//! were generated.

use base64ct::Encoding as _;
use cybercipher_core::{ErrorKind, OperationError};
use cybercipher_pki::x509::{
    identify_pem, inspect_certificate, inspect_crl, inspect_csr, PemObjectType,
};

// ---------------------------------------------------------------------------
// Static fixtures (generated with OpenSSL 3.5.7)
// ---------------------------------------------------------------------------

const FIXTURE_CA_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDiTCCAnGgAwIBAgIUYxEzsk2jl4+VmmrSRgUXoqbhPX8wDQYJKoZIhvcNAQEL
BQAwTDELMAkGA1UEBhMCVVMxGjAYBgNVBAoMEUN5YmVyQ2lwaGVyIFRlc3RzMSEw
HwYDVQQDDBhDeWJlckNpcGhlciBUZXN0IFJvb3QgQ0EwHhcNMjYwOTMwMDU1MTA2
WhcNMzYwOTI3MDU1MTA2WjBMMQswCQYDVQQGEwJVUzEaMBgGA1UECgwRQ3liZXJD
aXBoZXIgVGVzdHMxITAfBgNVBAMMGEN5YmVyQ2lwaGVyIFRlc3QgUm9vdCBDQTCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALvElSr43goHNJcdGHAb3Dn6
xl4zpZ3XdBsNlLRUt7JOykmPL23FnjlvmzgnoH/VliFqdOnMDkPAcoPrfVEnA1u8
62CFQHr63aIS77yWacf9BDZRbTlzWcZGsXWtjEH684D0y7M42IuBEPZKsbbw1bux
kUEyuOzwYAY/kp41YIq+CSQTdZObA5EQSnn36iEo0iQ+mw0FW1VhU5DnOHK1OQOf
beDx8vucI3M9qIC/NAoCTmaA2LZZhz4xjkNwRix4Vbl1Ys9SKcKPJIoRK0vUjfwB
y70OwgCEPsluacb85w+brJG3Nwbmuz2azv7wjhx33kviI37+MoM3+XOJ2RBen1sC
AwEAAaNjMGEwHwYDVR0jBBgwFoAULUfONRDgYx1a+b6onAIvybVPVC4wDwYDVR0T
AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFC1HzjUQ4GMdWvm+
qJwCL8m1T1QuMA0GCSqGSIb3DQEBCwUAA4IBAQBJR+2Dhug5HxKgsNnFpxCsJonw
eBGgfhp5Grfzuuee+dKrlH8aAd/SUunC8tqQX2lxyziXyoLshTkcVOEEJ5q1nncG
S8L/q96Ydkf8k7IW9QG6j5NHfzscyZ6AnKtlm9nTWMNTnowflhvxx78oRF1/ALNI
jeOoLUUYPTR8DqcslBQIjTZX/Ft7vafZZ/ZDTvge5KXoYAEEC0XddqVf1qEUdlNu
qj236vBnRMmwSkVuPGxR+KCPOAKZ60ZF3PQ4ABo0NXNu5VCWVSbigdSs88aww6+x
AsTTNsv9HUkT9hSOWUsUuJVe3V5tsNfjUeGmfn6lY+vyjChB6DW9B+abyeFN
-----END CERTIFICATE-----
";

const FIXTURE_LEAF_CERT_PEM: &str = "\
-----BEGIN CERTIFICATE-----
MIIDqTCCApGgAwIBAgIBKjANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJVUzEa
MBgGA1UECgwRQ3liZXJDaXBoZXIgVGVzdHMxITAfBgNVBAMMGEN5YmVyQ2lwaGVy
IFRlc3QgUm9vdCBDQTAeFw0yNjA5MzAwNTUxMDdaFw0yNzA5MzAwNTUxMDdaMEQx
CzAJBgNVBAYTAlVTMRowGAYDVQQKDBFDeWJlckNpcGhlciBUZXN0czEZMBcGA1UE
AwwQbGVhZi5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAOXc/S7i9AKhoRycHNqtja5MEL9jiN8n4oCVD/zZHnoJTaQQMQbPIZALlrej
J1YuZ1LDw3pasQ3bH55lMkIPZcChsoZRxS8EiP4hgOuk9q3bHqqnIGfhvRyQ4cs/
SyUiwSoyI/v832NsYITjL7cBWk9UWYXm1CPCTCE59ju+QPOKh21rev9bYK4XS7rv
MPtIiF0xP5Cyj3fblVd6m2zaZl7cbBw24fa/1yB6+ZlFca2s26p+w1RAKwUxqytY
rZLTOox0Il6swiFOabKcXwh95yS5S+wO4KVTdtxrHKM2QEtAQvOF51cC/FtdZuco
Ah1Ez8Iz73w/bsOOYE7jXgN8ccECAwEAAaOBnTCBmjAJBgNVHRMEAjAAMAsGA1Ud
DwQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwIQYDVR0RBBow
GIIQbGVhZi5leGFtcGxlLmNvbYcEfwAAATAdBgNVHQ4EFgQUQ3tIE4Mfh1JB6sZx
8WEhheOFqZswHwYDVR0jBBgwFoAULUfONRDgYx1a+b6onAIvybVPVC4wDQYJKoZI
hvcNAQELBQADggEBAAfONLs53V2WoOUaFDMAFaSlbDdhJY9nO+Qq/M+dgtQjWeAW
5sl5wxwubuV/O/MOEAHCOmp/+9RLqO7YjopbPNkfJ9DauQCB0cyvgObQokzysD6a
5x7zCuptU6fhwxHRirLnYUBG4N+xRsg9rM6VJn3KjCauLerRwP3SdmzBmS6fKcu1
37fw8rNVnA1+lb0RNxQLM0+I7ycM3FW6m+JvU3HgLrYZoSzRiR2SsZ8K9kIZDZgV
BPsCb1uNCvvw8eozrN4oqTNG24CAN1Rf5ykOSqzqyWlQ0W/tnVlffgMMsKFFS0Iv
NVxUsg9Hb1+kS4fy2RJivAzIr9UFgqLTRcCrOUo=
-----END CERTIFICATE-----
";

/// Raw DER of `FIXTURE_LEAF_CERT_PEM` (base64 of the DER bytes).
const FIXTURE_LEAF_CERT_DER_B64: &str = "\
MIIDqTCCApGgAwIBAgIBKjANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJVUzEa\
MBgGA1UECgwRQ3liZXJDaXBoZXIgVGVzdHMxITAfBgNVBAMMGEN5YmVyQ2lwaGVy\
IFRlc3QgUm9vdCBDQTAeFw0yNjA5MzAwNTUxMDdaFw0yNzA5MzAwNTUxMDdaMEQx\
CzAJBgNVBAYTAlVTMRowGAYDVQQKDBFDeWJlckNpcGhlciBUZXN0czEZMBcGA1UE\
AwwQbGVhZi5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\
ggEBAOXc/S7i9AKhoRycHNqtja5MEL9jiN8n4oCVD/zZHnoJTaQQMQbPIZALlrej\
J1YuZ1LDw3pasQ3bH55lMkIPZcChsoZRxS8EiP4hgOuk9q3bHqqnIGfhvRyQ4cs/\
SyUiwSoyI/v832NsYITjL7cBWk9UWYXm1CPCTCE59ju+QPOKh21rev9bYK4XS7rv\
MPtIiF0xP5Cyj3fblVd6m2zaZl7cbBw24fa/1yB6+ZlFca2s26p+w1RAKwUxqytY\
rZLTOox0Il6swiFOabKcXwh95yS5S+wO4KVTdtxrHKM2QEtAQvOF51cC/FtdZuco\
Ah1Ez8Iz73w/bsOOYE7jXgN8ccECAwEAAaOBnTCBmjAJBgNVHRMEAjAAMAsGA1Ud\
DwQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwIQYDVR0RBBow\
GIIQbGVhZi5leGFtcGxlLmNvbYcEfwAAATAdBgNVHQ4EFgQUQ3tIE4Mfh1JB6sZx\
8WEhheOFqZswHwYDVR0jBBgwFoAULUfONRDgYx1a+b6onAIvybVPVC4wDQYJKoZI\
hvcNAQELBQADggEBAAfONLs53V2WoOUaFDMAFaSlbDdhJY9nO+Qq/M+dgtQjWeAW\
5sl5wxwubuV/O/MOEAHCOmp/+9RLqO7YjopbPNkfJ9DauQCB0cyvgObQokzysD6a\
5x7zCuptU6fhwxHRirLnYUBG4N+xRsg9rM6VJn3KjCauLerRwP3SdmzBmS6fKcu1\
37fw8rNVnA1+lb0RNxQLM0+I7ycM3FW6m+JvU3HgLrYZoSzRiR2SsZ8K9kIZDZgV\
BPsCb1uNCvvw8eozrN4oqTNG24CAN1Rf5ykOSqzqyWlQ0W/tnVlffgMMsKFFS0Iv\
NVxUsg9Hb1+kS4fy2RJivAzIr9UFgqLTRcCrOUo=";

const FIXTURE_RSA_CSR_PEM: &str = "\
-----BEGIN CERTIFICATE REQUEST-----
MIICvTCCAaUCAQAwRDELMAkGA1UEBhMCVVMxGjAYBgNVBAoMEUN5YmVyQ2lwaGVy
IFRlc3RzMRkwFwYDVQQDDBBsZWFmLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0B
AQEFAAOCAQ8AMIIBCgKCAQEA5dz9LuL0AqGhHJwc2q2NrkwQv2OI3yfigJUP/Nke
eglNpBAxBs8hkAuWt6MnVi5nUsPDelqxDdsfnmUyQg9lwKGyhlHFLwSI/iGA66T2
rdseqqcgZ+G9HJDhyz9LJSLBKjIj+/zfY2xghOMvtwFaT1RZhebUI8JMITn2O75A
84qHbWt6/1tgrhdLuu8w+0iIXTE/kLKPd9uVV3qbbNpmXtxsHDbh9r/XIHr5mUVx
razbqn7DVEArBTGrK1itktM6jHQiXqzCIU5pspxfCH3nJLlL7A7gpVN23GscozZA
S0BC84XnVwL8W11m5ygCHUTPwjPvfD9uw45gTuNeA3xxwQIDAQABoDQwMgYJKoZI
hvcNAQkOMSUwIzAhBgNVHREEGjAYghBsZWFmLmV4YW1wbGUuY29thwR/AAABMA0G
CSqGSIb3DQEBCwUAA4IBAQBIpLOnGtx9R3yLRDuR7NMP8hYQSJMcmXJoEwYfju8l
yVYXTywTBlQyTQSBTUJC9moxKKBg4Ysiz6P94C6f152EwPKFmIkUpiKtTq1dvioq
jyGYwEfgDeLmNRn+9+Fe6KXlA4klNyJyE4ZqPaJHxXZxUO5CFhK4/Y0m7AMvCgb6
mPwcInVdiU22UvcWk/qIkgL77MSQsA/61BpgGSuktgzXIrAwp+TaoRwlV88yBhqW
JmCXVxAgL6Yg88hFBlWJQAruwburVDrJYYtwWxOof3DtDOK8kBnDw8/v7MPd7rS2
9XSZnkm7ER/DpB5f3uGu8Nfz1tk48FHGBShNFH5Ytatp
-----END CERTIFICATE REQUEST-----
";

const FIXTURE_EC_CSR_PEM: &str = "\
-----BEGIN CERTIFICATE REQUEST-----
MIH9MIGkAgEAMEIxCzAJBgNVBAYTAlVTMRowGAYDVQQKDBFDeWJlckNpcGhlciBU
ZXN0czEXMBUGA1UEAwwOZWMuZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQMGqNokrl3uwxijDJLPgdgQt0sibUKFaeNdYStQ23+dTYJ43SXylpW
ZdLTLZc+ImJRoknGlzrhyjAa5vYi90RsoAAwCgYIKoZIzj0EAwIDSAAwRQIgff4r
lJNZyVkPsPmHWiKan9UZGdr1SEUjpxAsvNJr8rACIQDHkUUAjnJkitSnS1xN3NUZ
gwAL/VVJ4h4VccLAwe3rlg==
-----END CERTIFICATE REQUEST-----
";

const FIXTURE_CRL_PEM: &str = "\
-----BEGIN X509 CRL-----
MIIBqDCBkTANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJVUzEaMBgGA1UECgwR
Q3liZXJDaXBoZXIgVGVzdHMxITAfBgNVBAMMGEN5YmVyQ2lwaGVyIFRlc3QgUm9v
dCBDQRcNMjYwOTMwMDU1MTM1WhcNMjYxMDMwMDU1MTM1WjAUMBICASoXDTI2MDkz
MDA1NTEzNVowDQYJKoZIhvcNAQELBQADggEBAJ0N04pyMgBgF8RZjy0/hgT39G8k
V/mWbQIMFmrpkDjU3pH7Cri77t31foUvNSqLTOwlHU6qbJ5Fm3QFxrXGDJXO4nju
GpKIAOP4XGyLpTpHTZ/VZXlivsPSzPJPaqn1i4UmylA/n/Yt848mwrsoPj4/DRxJ
5OIcavIDGn8EGppNm/TwrdFmwPsq/F/jD/Wr54raNh8UF9LSK0x0qWVOC44xB+D3
8Not7UsR2Q0wRwibnaIQxC6icsS2ZJjPx7cOdFnqJupqGLR9ONW20Ww6apT+6QaN
VYdP7YHv/P1mtHlOytRROXPTuk24owxbvuhdwT54YSzjlM7cGz5BAZlgN6c=
-----END X509 CRL-----
";

/// Legacy RFC 1421-style encrypted PEM (Proc-Type + DEK-Info headers).
const FIXTURE_LEGACY_ENCRYPTED_PEM: &str = "\
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,A55A2B4C1F2D3E4F

YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWZnaGlqa2xtbm9w
-----END RSA PRIVATE KEY-----
";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn assert_kind(err: &OperationError, kind: ErrorKind) {
    assert_eq!(err.kind, kind, "unexpected error: {err}");
}

fn der_of(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .skip(1)
        .take_while(|line| !line.starts_with("-----END"))
        .collect();
    base64ct::Base64::decode_vec(&body).expect("fixture base64 must decode")
}

// ---------------------------------------------------------------------------
// Generic PEM identification
// ---------------------------------------------------------------------------

#[test]
fn identify_pem_classifies_object_types() {
    for (pem, expected) in [
        (FIXTURE_CA_CERT_PEM, PemObjectType::Certificate),
        (FIXTURE_LEAF_CERT_PEM, PemObjectType::Certificate),
        (FIXTURE_RSA_CSR_PEM, PemObjectType::CertificateRequest),
        (FIXTURE_EC_CSR_PEM, PemObjectType::CertificateRequest),
        (FIXTURE_CRL_PEM, PemObjectType::Crl),
    ] {
        let id = identify_pem(pem.as_bytes()).unwrap_or_else(|e| panic!("{pem}: {e}"));
        assert_eq!(id.object_type, expected);
        assert_eq!(
            id.label,
            pem.lines().next().unwrap()[11..].trim_end_matches('-')
        );
        assert_eq!(id.der_len, der_of(pem).len(), "DER length mismatch");
    }
}

#[test]
fn identify_pem_rejects_non_pem_and_reports_encrypted() {
    // Raw DER is not PEM.
    let err = identify_pem(&der_of(FIXTURE_LEAF_CERT_PEM)).unwrap_err();
    assert_kind(&err, ErrorKind::Decode);

    // Modern encrypted PKCS#8 label.
    let encrypted =
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nYWJj\n-----END ENCRYPTED PRIVATE KEY-----\n";
    let id = identify_pem(encrypted.as_bytes()).unwrap();
    assert_eq!(id.object_type, PemObjectType::EncryptedPrivateKey);

    // Legacy RFC 1421 headers are rejected outright as unsupported.
    let err = identify_pem(FIXTURE_LEGACY_ENCRYPTED_PEM.as_bytes()).unwrap_err();
    assert_kind(&err, ErrorKind::Unsupported);
    assert!(err.message.contains("encrypted"), "got: {err:?}");

    // Broken armor: missing END line.
    let err = identify_pem(b"-----BEGIN CERTIFICATE-----\nYWJj\n".as_slice()).unwrap_err();
    assert_kind(&err, ErrorKind::Decode);
}

#[test]
fn inspectors_reject_wrong_object_types() {
    // A CRL is not a certificate...
    let err = inspect_certificate(FIXTURE_CRL_PEM.as_bytes()).unwrap_err();
    assert_kind(&err, ErrorKind::InvalidInput);
    assert!(
        err.message.contains("wrong PEM object type"),
        "got: {err:?}"
    );
    assert_eq!(err.actual.as_deref(), Some("X509 CRL"));

    // ...and a CSR is not a CRL.
    let err = inspect_crl(FIXTURE_RSA_CSR_PEM.as_bytes()).unwrap_err();
    assert_kind(&err, ErrorKind::InvalidInput);

    // Public keys / private keys are not certificates here either.
    let err = inspect_certificate(b"-----BEGIN PUBLIC KEY-----\nYWJj\n-----END PUBLIC KEY-----\n")
        .unwrap_err();
    assert_kind(&err, ErrorKind::InvalidInput);

    // Encrypted objects are explicitly unsupported.
    let err = inspect_certificate(
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nYWJj\n-----END ENCRYPTED PRIVATE KEY-----\n"
            .as_bytes(),
    )
    .unwrap_err();
    assert_kind(&err, ErrorKind::Unsupported);
}

// ---------------------------------------------------------------------------
// Certificate inspection
// ---------------------------------------------------------------------------

#[test]
fn inspect_leaf_certificate_from_pem() {
    let insp = inspect_certificate(FIXTURE_LEAF_CERT_PEM.as_bytes()).unwrap();

    assert_eq!(insp.version, 2);
    assert_eq!(insp.version_label, "v3");
    assert_eq!(insp.serial_hex, "2a");
    assert_eq!(insp.signature_algorithm, "sha256WithRSAEncryption");
    assert_eq!(insp.signature_algorithm_oid, "1.2.840.113549.1.1.11");
    assert_eq!(insp.not_before, "2026-09-30T05:51:07Z");
    assert_eq!(insp.not_after, "2027-09-30T05:51:07Z");

    let cn = |list: &[cybercipher_pki::x509::RdnEntry]| {
        list.iter()
            .find(|e| e.oid == "2.5.4.3")
            .map(|e| e.value.clone())
            .unwrap()
    };
    assert_eq!(cn(&insp.subject), "leaf.example.com");
    assert_eq!(cn(&insp.issuer), "CyberCipher Test Root CA");
    // OIDs carry well-known names from the asn1 table.
    assert!(insp
        .subject
        .iter()
        .any(|e| e.name.as_deref() == Some("commonName")));
    assert!(insp
        .issuer
        .iter()
        .any(|e| e.oid == "2.5.4.10" && e.value == "CyberCipher Tests"));

    // Public key: RSA-2048.
    assert_eq!(insp.public_key.key_type, "rsa");
    assert_eq!(insp.public_key.algorithm_oid, "1.2.840.113549.1.1.1");
    assert_eq!(insp.public_key.bit_length, Some(2048));

    // Fingerprints are hex of the right lengths and stable.
    assert_eq!(insp.fingerprint_sha256.len(), 64);
    assert_eq!(insp.fingerprint_sha1.len(), 40);
    assert!(insp
        .fingerprint_sha256
        .chars()
        .all(|c| c.is_ascii_hexdigit()));

    // Extensions: decoded SAN, key usage, EKU, basic constraints, SKI, AKI.
    assert!(insp.extensions.iter().any(|e| e.oid == "2.5.29.17"));
    assert_eq!(
        insp.subject_alt_names,
        vec![
            "DNS:leaf.example.com".to_string(),
            "IP:127.0.0.1".to_string()
        ]
    );
    assert!(insp.key_usage.contains(&"digitalSignature".to_string()));
    assert!(insp.key_usage.contains(&"keyEncipherment".to_string()));
    assert!(!insp.key_usage.contains(&"keyCertSign".to_string()));
    assert_eq!(
        insp.extended_key_usage,
        vec!["serverAuth".to_string(), "clientAuth".to_string()]
    );
    let bc = insp.basic_constraints.unwrap();
    assert!(!bc.ca);
    assert_eq!(bc.path_len, None);
    assert_eq!(
        insp.subject_key_identifier.as_deref(),
        Some("437b4813831f875241eac671f1612185e385a99b")
    );
    assert_eq!(
        insp.authority_key_identifier.as_deref(),
        Some("2d47ce3510e0631d5af9bea89c022fc9b54f542e")
    );

    assert!(insp.summary.contains("v3"), "summary: {}", insp.summary);
    assert!(
        insp.summary.contains("RSA 2048-bit"),
        "summary: {}",
        insp.summary
    );

    // Result is serde-serializable for the IPC boundary.
    let json = serde_json::to_value(&insp).unwrap();
    assert_eq!(json["serial_hex"], "2a");
    assert_eq!(json["public_key"]["key_type"], "rsa");
}

#[test]
fn inspect_ca_certificate_from_pem() {
    let insp = inspect_certificate(FIXTURE_CA_CERT_PEM.as_bytes()).unwrap();
    assert_eq!(insp.version, 2);
    assert_eq!(insp.not_before, "2026-09-30T05:51:06Z");
    assert_eq!(insp.not_after, "2036-09-27T05:51:06Z");
    // Self-signed: issuer == subject.
    assert_eq!(insp.issuer, insp.subject);
    // CA:TRUE (critical) with keyCertSign + cRLSign.
    let bc = insp.basic_constraints.unwrap();
    assert!(bc.ca);
    let bc_ext = insp
        .extensions
        .iter()
        .find(|e| e.oid == "2.5.29.19")
        .expect("basicConstraints present");
    assert!(bc_ext.critical);
    assert!(insp.key_usage.contains(&"keyCertSign".to_string()));
    assert!(insp.key_usage.contains(&"cRLSign".to_string()));
    // The CA has no SAN.
    assert!(insp.subject_alt_names.is_empty());
}

#[test]
fn inspect_certificate_accepts_raw_der() {
    let der = base64ct::Base64::decode_vec(FIXTURE_LEAF_CERT_DER_B64).unwrap();
    let from_der = inspect_certificate(&der).unwrap();
    let from_pem = inspect_certificate(FIXTURE_LEAF_CERT_PEM.as_bytes()).unwrap();
    assert_eq!(from_der, from_pem, "DER and PEM paths must agree");

    // Garbage DER is a typed decode error, not a panic.
    let err = inspect_certificate(&[0x30, 0x03, 0x01, 0x02, 0x03]).unwrap_err();
    assert_kind(&err, ErrorKind::Decode);
    assert!(err.message.contains("invalid DER"), "got: {err:?}");

    let err = inspect_certificate(&[]).unwrap_err();
    assert_kind(&err, ErrorKind::Decode);
}

// ---------------------------------------------------------------------------
// CSR inspection (with best-effort self-signature verification)
// ---------------------------------------------------------------------------

#[test]
fn inspect_rsa_csr_and_verify_self_signature() {
    let insp = inspect_csr(FIXTURE_RSA_CSR_PEM.as_bytes()).unwrap();
    assert_eq!(insp.version, 0);
    assert_eq!(insp.signature_algorithm, "sha256WithRSAEncryption");
    let cn = insp
        .subject
        .iter()
        .find(|e| e.oid == "2.5.4.3")
        .map(|e| e.value.clone())
        .unwrap();
    assert_eq!(cn, "leaf.example.com");
    assert_eq!(insp.public_key.key_type, "rsa");
    assert_eq!(insp.public_key.bit_length, Some(2048));
    // The CSR carries a single extensionRequest attribute (SAN).
    let ext_req = insp
        .attributes
        .iter()
        .find(|a| a.oid == "1.2.840.113549.1.9.14")
        .expect("extensionRequest present");
    assert_eq!(ext_req.value_count, 1);
    assert_eq!(ext_req.name.as_deref(), Some("extensionRequest"));

    assert_eq!(
        insp.signature_verified,
        Some(true),
        "note: {}",
        insp.verification_note
    );
    assert!(
        insp.summary.contains("self-signature verified"),
        "summary: {}",
        insp.summary
    );
}

#[test]
fn inspect_ec_csr_and_verify_self_signature() {
    let insp = inspect_csr(FIXTURE_EC_CSR_PEM.as_bytes()).unwrap();
    assert_eq!(insp.signature_algorithm, "ecdsa-with-SHA256");
    assert_eq!(insp.public_key.key_type, "ec");
    assert_eq!(insp.public_key.bit_length, Some(256));
    assert_eq!(insp.public_key.curve.as_deref(), Some("prime256v1 (P-256)"));
    assert_eq!(
        insp.signature_verified,
        Some(true),
        "note: {}",
        insp.verification_note
    );
}

#[test]
fn tampered_csr_reports_invalid_signature() {
    // Flip the last byte of the CN text inside certificationRequestInfo:
    // the structure still parses but the self-signature must fail.
    let mut der = der_of(FIXTURE_RSA_CSR_PEM);
    let needle = b"leaf.example.com";
    let pos = der
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("CN literal present in DER");
    der[pos + needle.len() - 1] ^= 0x01;
    let insp = inspect_csr(&der).unwrap();
    assert_eq!(
        insp.signature_verified,
        Some(false),
        "note: {}",
        insp.verification_note
    );
    assert!(
        insp.summary.contains("INVALID"),
        "summary: {}",
        insp.summary
    );
}

#[test]
fn unsupported_csr_signature_algorithm_is_marked_not_verified() {
    // Rewrite the outer signatureAlgorithm OID from
    // sha256WithRSAEncryption (…1.1.11) to rsassaPss (…1.1.10): same DER
    // length, so the structure still parses but verification is out of
    // scope here -> signature_verified must be None.
    let mut der = der_of(FIXTURE_RSA_CSR_PEM);
    let from = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    let to = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
    let positions: Vec<usize> = der
        .windows(from.len())
        .enumerate()
        .filter(|(_, window)| *window == from.as_slice())
        .map(|(index, _)| index)
        .collect();
    // PKCS#10 carries the signature algorithm exactly once (outer);
    // unlike certificates there is no inner copy.
    assert_eq!(
        positions.len(),
        1,
        "expected to rewrite the outer algorithm identifier"
    );
    for start in positions {
        der[start..start + from.len()].copy_from_slice(to);
    }
    let insp = inspect_csr(&der).unwrap();
    assert_eq!(insp.signature_algorithm_oid, "1.2.840.113549.1.1.10");
    assert_eq!(insp.signature_verified, None);
    assert!(
        insp.verification_note.contains("not verifiable"),
        "note: {}",
        insp.verification_note
    );
}

#[test]
fn malformed_csr_is_a_typed_error() {
    let mut der = der_of(FIXTURE_RSA_CSR_PEM);
    der.truncate(der.len() - 16);
    let err = inspect_csr(&der).unwrap_err();
    assert_kind(&err, ErrorKind::Decode);
}

// ---------------------------------------------------------------------------
// CRL inspection
// ---------------------------------------------------------------------------

#[test]
fn inspect_crl_lists_revoked_serials() {
    let insp = inspect_crl(FIXTURE_CRL_PEM.as_bytes()).unwrap();
    let cn = insp
        .issuer
        .iter()
        .find(|e| e.oid == "2.5.4.3")
        .map(|e| e.value.clone())
        .unwrap();
    assert_eq!(cn, "CyberCipher Test Root CA");
    assert_eq!(insp.this_update, "2026-09-30T05:51:35Z");
    assert_eq!(insp.next_update.as_deref(), Some("2026-10-30T05:51:35Z"));
    assert_eq!(insp.signature_algorithm, "sha256WithRSAEncryption");
    assert_eq!(insp.revoked_count, 1);
    assert_eq!(insp.revoked.len(), 1);
    assert_eq!(insp.revoked[0].serial_hex, "2a");
    assert_eq!(insp.revoked[0].revocation_date, "2026-09-30T05:51:35Z");
    assert!(
        insp.summary.contains("1 revoked serial(s)"),
        "summary: {}",
        insp.summary
    );

    let json = serde_json::to_value(&insp).unwrap();
    assert_eq!(json["revoked"][0]["serial_hex"], "2a");
}

#[test]
fn inspect_crl_rejects_certificates_and_garbage() {
    let err = inspect_crl(FIXTURE_LEAF_CERT_PEM.as_bytes()).unwrap_err();
    assert_kind(&err, ErrorKind::InvalidInput);

    let err = inspect_crl(&[0x02, 0x01, 0x00]).unwrap_err();
    assert_kind(&err, ErrorKind::Decode);
}
