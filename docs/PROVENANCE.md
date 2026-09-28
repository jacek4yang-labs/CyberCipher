# Provenance

Every algorithm in CyberCipher records where its definition, implementation,
and test vectors come from. This is machine-readable metadata on each
operation (visible in the UI via the `info` control) plus the notes here.

Principles:

1. Standardized algorithms: authoritative standards and official test vectors
   take precedence over third-party tool behavior.
2. CyberChef / ToolsFx / auto-ctf are interoperability and UX references,
   never authoritative specifications.
3. Prefer maintained Rust implementations (RustCrypto where appropriate) over
   hand-rolling; hand-written code must cite its spec and vectors.
4. Third-party code is only borrowed after license inspection, with notices
   preserved. CyberCipher is MIT OR Apache-2.0; incompatible code is not used.

## Current operations

| Operation group | Standard / source | Implementation | Test vectors |
|---|---|---|---|
| Hex encode/decode | Common convention (CyberChef-compatible behavior) | CyberCipher native | Round-trip + known-answer tests |
| Base64 (std/URL) | RFC 4648 | CyberCipher on `base64` crate 0.22 | RFC 4648 §10 |
| Base32 (std/hex) | RFC 4648 | CyberCipher native | RFC 4648 §7 |
| URL percent-encoding | RFC 3986 | CyberCipher on `percent-encoding` | Round-trip tests |
| Binary/Octal/Decimal | Common convention | CyberCipher native | Round-trip tests |
| UTF-8 | The Unicode Standard / RFC 3629 | Rust `std` | Malformed-input tests |
| XOR family, AND/OR/NOT, rotate, endianness, split/join | CyberCipher convention (documented per-op) | CyberCipher native | Known-answer tests |
| Entropy | Shannon (1948) | CyberCipher native | Analytic cases (uniform = 8 bits/byte) |
| Strings | Modeled on POSIX `strings` behavior | CyberCipher native | Hand-checked cases |

| AES | NIST FIPS 197; modes: SP 800-38 | RustCrypto `aes` + `ecb`/`cbc`/`ctr`/`ofb` crates; CyberCipher native CFB-128 | NIST SP 800-38A vectors |
| DES / 3DES | FIPS 46-3 (withdrawn); SP 800-67 | RustCrypto `des` crate | Classic known-answer vectors |
| SM4 | GB/T 32907-2016 | RustCrypto `sm4` crate | GB/T 32907 standard example |
| RC4 | Rivest's original RC4; RFC 6229 vectors | CyberCipher native Rust (variable-key KSA/PRGA) | Classic "Key"/"Plaintext" vector |
| TEA/XTEA/XXTEA | Wheeler/Needham/Jones original definitions (unstandardized) | CyberCipher native Rust | Zero-vector KAT cross-verified against an independent implementation + round-trips |
| MD5 | RFC 1321 (legacy/broken) | RustCrypto `md-5` | RFC 1321 suite |
| SHA-1/SHA-2 | FIPS 180-4 | RustCrypto `sha1`/`sha2` | FIPS 180-4 examples |
| SHA-3/SHAKE/Keccak | FIPS 202 | RustCrypto `sha3` | NIST KAT |
| SM3 | GB/T 32905-2016 | RustCrypto `sm3` | GB/T 32905 standard examples |
| HMAC | RFC 2104 / FIPS 198-1 | RustCrypto `hmac` | RFC 4231 test vectors |

## Upcoming (planned provenance targets)

- AES: NIST FIPS 197; modes: NIST SP 800-38 family; vectors: NIST AESAVS.
- SHA-2: FIPS 180-4. SHA-3/SHAKE: FIPS 202. MD5: RFC 1321 (legacy, broken).
- ChaCha20-Poly1305: RFC 8439. HKDF: RFC 5869. PBKDF2: RFC 8018.
- RSA primitives/schemes: RFC 8017 (PKCS #1 v2.2).
- Argon2: RFC 9106. SM2/SM3/SM4: GB/T 32918 / GB/T 32905 / GB/T 32907.
- TEA/XTEA/XXTEA: Wheeler et al. original definitions; vectors from reference
  implementations and interop testing.

Dependency inventory is tracked in the crate manifests; licenses are reviewed
against the MIT OR Apache-2.0 dual license before adoption.
