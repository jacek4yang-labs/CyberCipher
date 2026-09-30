//! SM3 hashing (GB/T 32905-2016): the 256-bit Chinese national-standard hash.
//! Also the digest inside SM2 signatures (ZA || M) and SM2 ciphertexts (C3).

use crate::keys::to_hex;

/// SM3 digest output size in bytes.
pub const SM3_DIGEST_LEN: usize = 32;

/// Compute the SM3 digest of `data` (GB/T 32905-2016).
pub fn sm3_digest(data: &[u8]) -> [u8; SM3_DIGEST_LEN] {
    use sm3::digest::Digest as _;
    sm3::Sm3::digest(data).into()
}

/// Compute the SM3 digest of `data` as a lowercase hex string (the
/// CyberCipher transport format for hashes).
pub fn sm3_hex(data: &[u8]) -> String {
    to_hex(&sm3_digest(data))
}
