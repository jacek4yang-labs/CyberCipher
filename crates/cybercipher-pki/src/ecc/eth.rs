//! Ethereum address derivation (EIP-55 / EIP-2 conventions over secp256k1).
//!
//! The address is keccak256 of the 64-byte uncompressed public key *without*
//! the SEC1 `0x04` prefix, truncated to the last 20 bytes — the rightmost
//! 160 bits of the Keccak-256 digest (Ethereum Yellow Paper, Eq. 249). The
//! checksum form is EIP-55: the address hex is written lowercase, Keccak-256
//! is applied to the ASCII bytes of that string, and each alphabetic hex
//! character is uppercased when the corresponding hash nibble is >= 8.
//!
//! Keccak-256 (original Keccak padding, NOT SHA3-256) comes from the RustCrypto
//! `sha3` crate, already in the dependency tree.

use serde::{Deserialize, Serialize};
use sha3::Digest;

use super::curve::{parse_ecc_private_key, parse_ecc_public_key, EccCurve};
use super::{decode_hex, wrong_encoding, wrong_length};
use crate::error::PkiResult;

/// Length of an Ethereum address in bytes.
pub const ETH_ADDRESS_SIZE: usize = 20;

/// Result of checking an address string against EIP-55.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthAddressCheck {
    /// The address re-encoded in EIP-55 mixed-case checksum form
    /// (`0x`-prefixed).
    pub address: String,
    /// The canonical lowercase `0x`-prefixed form (the 20-byte value itself).
    pub address_lowercase: String,
    /// Whether the input's letter casing is consistent with the EIP-55
    /// checksum. All-lowercase and all-uppercase inputs carry no checksum
    /// information and are reported as valid (`has_checksum == false`).
    pub checksum_valid: bool,
    /// Whether the input carried any checksum information at all (i.e. it
    /// was neither all-lowercase nor all-uppercase).
    pub has_checksum: bool,
}

/// Keccak-256 (the legacy Keccak padding used by Ethereum, not SHA3-256).
pub(crate) fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Derive the EIP-55 checksummed Ethereum address of the secp256k1 private
/// key (`32`-byte hex scalar). Equivalent to deriving the public key and
/// calling [`eth_address_from_public`].
pub fn eth_address_from_private(private_hex: &str) -> PkiResult<String> {
    let keypair = parse_ecc_private_key(EccCurve::Secp256k1, private_hex)?;
    eth_address_from_public(&keypair.public_uncompressed_hex)
}

/// Derive the EIP-55 checksummed Ethereum address of a secp256k1 public key
/// (SEC1 hex, compressed or uncompressed).
pub fn eth_address_from_public(public_hex: &str) -> PkiResult<String> {
    let material = parse_ecc_public_key(EccCurve::Secp256k1, public_hex)?;
    let uncompressed = decode_hex("public_key", &material.public_uncompressed_hex)?;
    // Strip the SEC1 0x04 tag: the digest runs over the raw (x, y) only.
    let payload = &uncompressed[1..];
    let digest = keccak256(payload);
    let addr_bytes: [u8; ETH_ADDRESS_SIZE] = digest[32 - ETH_ADDRESS_SIZE..]
        .try_into()
        .map_err(|_| super::internal("keccak digest slice invariant violated"))?;
    Ok(format!(
        "0x{}",
        eip55_encode(&crate::keys::to_hex(&addr_bytes))
    ))
}

/// Check an `0x`-prefixed Ethereum address string against EIP-55: re-encodes
/// the checksum and compares the casing. A malformed address (wrong length,
/// non-hex) is a typed error; a wrong checksum is a *result*
/// (`checksum_valid == false`), not an error.
pub fn eth_address_check(address: &str) -> PkiResult<EthAddressCheck> {
    let bytes = parse_address(address)?;
    let lowercase = crate::keys::to_hex(&bytes);
    let has_checksum = {
        let letters = address
            .trim()
            .strip_prefix("0x")
            .or_else(|| address.trim().strip_prefix("0X"))
            .unwrap_or(address.trim());
        let any_upper = letters.chars().any(|c| c.is_ascii_uppercase());
        let any_lower = letters.chars().any(|c| c.is_ascii_lowercase());
        any_upper && any_lower
    };
    let expected = eip55_encode(&lowercase);
    let input_letters = letters_of(address);
    let checksum_valid = if has_checksum {
        input_letters == expected
    } else {
        true
    };
    Ok(EthAddressCheck {
        address: format!("0x{expected}"),
        address_lowercase: format!("0x{lowercase}"),
        checksum_valid,
        has_checksum,
    })
}

/// EIP-55 checksum encoding of a lowercase 40-character address hex string.
fn eip55_encode(lowercase_hex: &str) -> String {
    debug_assert_eq!(lowercase_hex.len(), 2 * ETH_ADDRESS_SIZE);
    let hash = keccak256(lowercase_hex.as_bytes());
    lowercase_hex
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if c.is_ascii_digit() {
                c
            } else {
                let nibble = if i % 2 == 0 {
                    hash[i / 2] >> 4
                } else {
                    hash[i / 2] & 0x0f
                };
                if nibble >= 8 {
                    c.to_ascii_uppercase()
                } else {
                    c
                }
            }
        })
        .collect()
}

/// Parse an `0x`-prefixed 20-byte address into its raw bytes.
fn parse_address(address: &str) -> PkiResult<[u8; ETH_ADDRESS_SIZE]> {
    let trimmed = address.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if stripped.is_empty() {
        return Err(wrong_encoding("empty Ethereum address")
            .with_parameter("address")
            .with_expected("0x-prefixed 40-hex-digit address"));
    }
    if !stripped.len().is_multiple_of(2) || stripped.bytes().any(|b| !b.is_ascii_hexdigit()) {
        return Err(wrong_encoding("Ethereum address is not a hex string")
            .with_parameter("address")
            .with_expected("hex characters [0-9a-fA-F]")
            .with_actual(crate::keys::preview(address, 24)));
    }
    if stripped.len() != 2 * ETH_ADDRESS_SIZE {
        return Err(wrong_length(
            "address",
            format!("{} hex digits (20 bytes)", 2 * ETH_ADDRESS_SIZE),
            format!("{} hex digits", stripped.len()),
        ));
    }
    let bytes = decode_hex("address", stripped)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| super::internal("address length invariant violated after check"))
}

/// The letters of the address's hex payload as written (for checksum
/// comparison), lowercased digits untouched.
fn letters_of(address: &str) -> String {
    let trimmed = address.trim();
    let stripped = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    stripped.to_string()
}
