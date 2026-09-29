# Compatibility

Upstream capability baselines. Per-feature tracking lives in
`compatibility/*.toml` (statuses: covered, superset, partial, missing,
intentional-out-of-scope, same-capability). CI generates coverage reports as
the matrices mature.

CyberCipher is an independent project; these baselines guide capability and
UX coverage, not architecture or code. Success is not raw operation count —
features a baseline has that are irrelevant to a CTF-oriented crypto
workbench are marked `intentional-out-of-scope` with a reason.

Entries reflect implemented reality only. They were verified against the
code and tests on `main` (commit `5d5ab8e`, 2026-09-28: 59 recipe-registry
operations + the attack engine, 154 tests green), not against names or
plans. Work that exists on a reviewed feature branch is marked
"PR in flight" rather than counted as landed.

| Baseline | Matrix | Why it is tracked |
|---|---|---|
| [CyberChef](https://github.com/gchq/CyberChef) | `compatibility/cyberchef.toml` (76 entries + 5 superset) | Interoperability and UX reference for the Workbench |
| [ToolsFx](https://github.com/Leon406/ToolsFx) | `compatibility/toolsfx.toml` (25 entries + 3 superset) | Closest CTF-toolbox analogue (BouncyCastle surface, CN CTF encodings) |
| [auto-ctf](https://github.com/jacek4yang-labs/auto-ctf) | `compatibility/auto-ctf-crypto.toml` (30 entries + 2 superset) | Pure-Rust CTF crypto toolchain; reference baseline for the attack engine |

## cyberchef.toml — summary

| Area | Ours | Status |
|---|---|---|
| Hex / base64 / base32 / URL / binary / octal / decimal / integer converter | from/to ops | covered |
| Hexdump | to-hexdump | partial (fixed 16-byte rows); hexdump *parsing* missing |
| Reverse / Join | reverse / join | covered |
| Split | split | partial (literal delimiters; no regex) |
| XOR | xor | partial (standard/rolling/incrementing; no differential schemes, no brute force) |
| AND / OR / NOT / rotate / swap-endianness | bitwise-* ops | covered |
| Entropy / Strings | entropy / strings | partial (no chunked entropy; ASCII-only strings) |
| Magic / auto decode | auto_decode engine | partial (bounded + explainable, fewer wrappers) |
| Compression | from-gzip/from-zlib/from-raw-deflate/to-gzip | inflate covered; zlib/raw-deflate compress + bzip2/lzma missing |
| AES | aes-encrypt/decrypt | partial (ECB/CBC/CTR/CFB/OFB, PKCS7/Zero/ISO7816/None; GCM ships as separate AEAD ops) |
| DES / 3DES | des-encrypt/decrypt | partial (ECB/CBC; upstream adds CFB/OFB/CTR) |
| RC4 + RC4 Drop | rc4 (drop parameter) | covered |
| SM4 | sm4-encrypt/decrypt | covered (mode set matches upstream) |
| TEA / XTEA / XXTEA | tea/xtea/xxtea | partial (classic ECB-style; upstream adds block modes) |
| MD5 / SHA-1 / SHA-2 / SHA-3 / SHAKE | md5, sha1, sha224/256/384/512, sha3 | covered |
| Keccak | sha3 | partial (implemented internally, not yet exposed as variants) |
| SM3 | sm3 | covered |
| HMAC | hmac | partial (8 variants; no CMAC/GMAC) |
| AEAD (GCM, CCM, ChaCha20-Poly1305, XChaCha20-Poly1305, GCM-SIV) | aead-* ops | covered (PR #9 merged; RFC-vector-tested) |
| KDFs (PBKDF2, HKDF, scrypt, EVP_BytesToKey) | pbkdf2/hkdf/scrypt/evp-bytestokey | covered (PR #9 merged) |
| RSA ops (encrypt/decrypt/sign/verify/keygen) | — | missing (M8) |
| PRNG/RSA attack tooling | attack engine (CLI + GUI labs) | superset — no upstream counterpart |

## toolsfx.toml — summary

| ToolsFx capability | Ours | Status |
|---|---|---|
| Symmetric core (AES/DES/SM4/TEA family/RC4) | same ops | covered/partial — ToolsFx exposes more modes (CTS, EAX/OCB, more paddings) via BouncyCastle |
| ChaCha20-Poly1305 | aead-chacha20poly1305 | covered (PR #9 merged); Salsa20/HC-256/Rabbit/ZUC missing (M5 lane queued) |
| Broad block ciphers (Serpent/Twofish/Camellia/ARIA/CAST/IDEA/RC2/5/6/Blowfish/SEED/Threefish/GOST) | — | missing (M5) |
| RSA / SM2 / DSA / ECDSA / EdDSA | attack engine only | missing as key ops (M8) |
| Hash family + HMAC/CMAC/GMAC/Poly1305 | md/sha/sm3/hmac | partial (CMAC/GMAC missing) |
| Base families / classical ciphers / Chinese CTF encodings (佛曰， 新佛曰， 兽音， 熊曰) / Brainfuck-Ook / aa-jjencode | — | missing (M6/M9) |
| QR/OCR, big-integer calculator, network utilities | — | missing / intentional-out-of-scope |
| PRNG recovery, provenance metadata | attack engine + registry | superset |

Where the upstream README does not name a feature precisely, the matrix says
"verify feature list" instead of guessing.

## auto-ctf-crypto.toml — summary

| auto-ctf capability | Ours | Status |
|---|---|---|
| RSA attacks (known p/q, d, phi; dp-leak; Wiener; Fermat; low-e; common modulus; Hastad; shared prime; Pollard rho/p-1) | 12-attack engine + analyzer | covered |
| RSA dp-dq joint leak, Rabin, yafu-style large factorization | — | missing |
| Lattice (LLL, Coppersmith small roots) | — | covered (PR #15 merged: exact integer LLL + Coppersmith small roots) |
| PRNG: LCG recovery (known m, blind 6-output, seed) | lcg module | covered |
| PRNG: MT19937 recovery + CPython compat | mt19937 module | covered |
| PRNG: Java/glibc/MSVC runtime PRNGs | prng module | covered (PR #10 merged); superset vs baseline |
| Classical / XOR solvers | — | partial (XOR lab covered, PR #18 merged; classical ciphers missing — M6 lane queued) |
| Encoding auto-chain | auto_decode | partial (explainable, narrower vocabulary) |
| NTLM (MD4/NT/NetNTLMv2), ECC/ETH addresses | — | missing |
| Explainability, typed outcomes, resource bounds | engine-wide | superset |

## Gap report

Missing high-value capabilities, ordered by milestone target (per
`docs/ROADMAP.md`):

- **Merge-ready (no new code required):**
  - AEAD set (AES-GCM/CCM, ChaCha20-Poly1305, XChaCha20-Poly1305, GCM-SIV)
    and KDF set (PBKDF2/HKDF/scrypt/EVP_BytesToKey) — implemented and
    RFC-vector-tested on `agent/crypto/m5-aead`; needs merge.
  - Java Random / glibc / MSVC rand recovery — implemented on
    `feat/runtime-prngs`; needs merge.
- **Milestone 5 (broad symmetric):** Serpent/Twofish/Camellia/ARIA/CAST5-6/
  IDEA/RC2/RC5/RC6/Blowfish/SEED/Threefish/GOST via RustCrypto; EAX/OCB/CTS
  modes; Keccak variant exposure (small); CMAC/GMAC.
- **Milestone 6 (classical / XOR cracking):** Caesar→ADFGVX solver suite,
  XOR brute force + differential XOR schemes, frequency/IOC/n-gram scoring —
  closes the auto-ctf classical row and the CyberChef `XOR_Brute_Force` row.
- **Milestone 7 (Crypto Assist):** parameter-space search for cipher ops
  (mitigates the mode/padding parity gaps vs ToolsFx/CyberChef by finding
  the right parameters automatically).
- **Milestone 8 (public-key ecosystem):** RSA encrypt/sign/verify/keygen,
  PEM/DER key parsing, SM2, ECDSA/Ed25519, certificates — currently the
  largest single "missing" block in both the CyberChef and ToolsFx matrices.
- **Milestone 9 (compression / CTF helpers):** to-zlib / to-raw-deflate,
  bzip2/LZMA, Chinese CTF encodings (与佛论禅/新佛曰/兽音/熊曰)， JSFuck/
  AAEncode/JJEncode, Brainfuck/Ook, base58/62/85, QR/image helpers.
- **Smaller parity polish (fold into nearby milestones):** hexdump width
  options + From Hexdump parser, Split regex delimiter, UTF-16 strings,
  chunked/conditional entropy, non-UTF-8 text encodings (GBK especially,
  relevant to the CN CTF scene), compression-level parameter.
