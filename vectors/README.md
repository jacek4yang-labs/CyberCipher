# Test vectors

Known-answer vectors for CyberCipher operations and attack modules.

- `rsa.md` — small textbook RSA instances (key material + plaintext/ciphertext
  round-trip fixtures for the attack lab).
- `prng.md` — MT19937 (reference + CPython-compatible), glibc `rand`, MSVC
  `rand` output sequences for the PRNG recovery modules.
- `aead.md` — ChaCha20-Poly1305, AES-GCM, HKDF, PBKDF2 and scrypt KATs for the
  AEAD/KDF operations.

## Status and licensing

Vectors reproduced from public standards (NIST FIPS/SP, IETF RFCs, the
MT19937 reference paper) and the public specifications of the emulated libc /
CRT `rand` functions are unencumbered; the RFC and NIST texts permit
reproduction and reuse. The RSA fixtures in `rsa.md` were generated for this
project and are released under the repository license (MIT OR Apache-2.0).

Every value in these files was computed and re-checked by an independent
Python reference implementation at generation time (2026-09-28); the RSA
entries additionally assert `pow(m, e, n) == c` and `pow(c, d, n) == m`, and
the PRNG entries were cross-checked against live CPython output where
applicable. If a vector in this directory ever disagrees with an
implementation, both are wrong until proven otherwise.

## Provenance policy

Each vector cites its source. When adding vectors:

1. Prefer citing an RFC/NIST section over inventing fixtures.
2. Re-verify any transcribed value by computing it — transcription errors in
   hex are the single most common vector bug.
3. Record the generator script or the command used in the file itself.
