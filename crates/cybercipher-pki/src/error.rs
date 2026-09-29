//! PKI error model. CyberCipher reuses the core `OperationError` directly
//! (rather than wrapping it in a newtype) so errors cross the IPC boundary as
//! the same structured JSON every other operation produces — the `PkiError`
//! name is an alias kept for call-site readability.

use cybercipher_core::OperationError;

/// Typed PKI error. Same structure as `cybercipher_core::OperationError`:
/// `kind` + `message` with optional `parameter` / `expected` / `actual` /
/// `details`.
pub type PkiError = OperationError;

/// Typed result alias used throughout the PKI crate.
pub type PkiResult<T> = Result<T, PkiError>;

/// PEM armor could not be located or was malformed.
pub(crate) fn invalid_armor(message: impl Into<String>) -> PkiError {
    PkiError::decode(message)
}

/// PEM was well-formed but the contained DER failed to parse.
pub(crate) fn invalid_der(context: &str, source: impl std::fmt::Display) -> PkiError {
    PkiError::decode(format!("invalid DER while parsing {context}"))
        .with_details(source.to_string())
}

/// The PEM object is not a key at all (e.g. a certificate).
pub(crate) fn wrong_object_type(actual_label: &str) -> PkiError {
    let mut err = PkiError::invalid_input(format!(
        "wrong PEM object type: '{actual_label}' is not a public or private key"
    ))
    .with_expected("a key PEM: PUBLIC KEY, PRIVATE KEY, RSA PUBLIC KEY, or RSA PRIVATE KEY")
    .with_actual(actual_label);
    if actual_label.contains("CERTIFICATE") {
        err = err.with_details(
            "this looks like a certificate; CyberCipher does not parse certificates yet — \
             extract the public key with an external tool first",
        );
    }
    err
}

/// The PEM object is a key but of an algorithm CyberCipher does not support
/// (e.g. an EC key inside a PKCS#8 wrapper).
pub(crate) fn unsupported_key_type(context: &str, actual: &str) -> PkiError {
    PkiError::unsupported(format!("unsupported key type: {context}")).with_actual(actual)
}

/// The key material itself is well-formed but self-inconsistent (bad sizes,
/// p*q != n, d*e != 1, ...).
pub(crate) fn inconsistent_key(message: impl Into<String>) -> PkiError {
    PkiError::key(message)
}
