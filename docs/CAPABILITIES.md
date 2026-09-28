# Capabilities

Statuses: **done** (implemented + tested + exposed in UI), **partial**
(usable but incomplete), **planned** (on the roadmap), **out-of-scope**
(deliberately excluded — documented why).

This file states actual status. Features are marked done only when the
implementation, UI/CLI exposure, tests, and documentation all exist.

## Milestone 1 — Workbench foundation (current)

| Area | Item | Status |
|---|---|---|
| Encoding | To/From Hex (strict + relaxed, diagnostics) | done |
| Encoding | To/From Base64 (standard + URL-safe, strict + relaxed) | done |
| Encoding | To/From Base32 (standard + extended hex) | done |
| Encoding | To/From URL (percent-encoding, `+` as space) | done |
| Encoding | To/From Binary, Octal, Decimal | done |
| Encoding | To Hexdump | done |
| Encoding | Encode/Decode Text (UTF-8, lossy option, byte-offset errors) | done |
| Byte ops | XOR (standard/rolling/incrementing, null-preserving) | done |
| Byte ops | AND / OR / NOT | done |
| Byte ops | Rotate Left / Right | done |
| Byte ops | Reverse (bytes/chars) | done |
| Byte ops | Swap Endianness | done |
| Byte ops | Split / Join | done |
| Analysis | Entropy report (bits/byte, printable ratio, top bytes) | done |
| Utility | Strings extraction | done |
| Engine | Linear recipes, versioned public format | done |
| Engine | Incremental stage cache with chained keys | done |
| Engine | Cost-class gating for Auto Bake | done |
| Engine | Cancellation, deadline, panic isolation | done |
| Engine | Structured typed errors surfaced in UI | done |
| UI | Operation search with aliases/tags | done |
| UI | Drag-and-drop recipe editing, reorder, duplicate, enable/disable | done |
| UI | Registry-driven parameter forms | done |
| UI | Auto Bake (debounced) + manual Bake | done |
| UI | Recipe save/load/import/export | done |
| UI | Copy as hex / Base64 / Python bytes / C array / decimal / integer | done |
| UI | Input↔output send/swap, hexdump view, entropy/size status | done |
| UI | Dark/light themes, keyboard shortcuts (`/`, Ctrl+Enter, Ctrl+S) | done |
| UI | Flag-pattern highlighting in status bar | done |

## Milestone 2 — practical CTF crypto baseline (current)

| Area | Item | Status |
|---|---|---|
| Crypto | AES encrypt/decrypt — ECB/CBC/CTR/CFB/OFB, keys 128/192/256 | done |
| Crypto | DES / 3DES encrypt/decrypt — ECB/CBC (labeled Broken) | done |
| Crypto | SM4 encrypt/decrypt — ECB/CBC/CTR/CFB/OFB | done |
| Crypto | RC4 with RC4-drop[n] (labeled Broken) | done |
| Crypto | TEA / XTEA / XXTEA encrypt/decrypt | done |
| Crypto | Padding policies: PKCS7/None/Zero/ISO 7816-4, validated unpad with typed errors | done |
| Crypto | Orthogonal mode/IV validation (block alignment, IV lengths, ECB rejects IV) | done |
| Hash | MD5, SHA-1, SHA-224/256/384/512, SHA-3 family + SHAKE128/256, Keccak, SM3 | done |
| MAC | HMAC (MD5/SHA-1/SHA-2/SHA-3-256/SM3) | done |
| CLI | `cybercipher ops` / `run` / `recipe` sharing the engine | done |

Known gaps vs the full Milestone 2 charter (follow-up PR): GCM/CCM/EAX AEAD
modes, CTS/XTS, and a dedicated key-encoding live-length display in the UI
parameter rows.

## Milestone 4 — CTF cryptanalysis core (in progress)

| Area | Item | Status |
|---|---|---|
| Core | BigInt plumbing: to-integer/from-integer ops (bytes/text ⇄ bigint, endianness, two's complement, min-length padding), exact transport (strings, never JS numbers) | done |
| Attack | Number theory: gcd, xgcd, modinv, iroot, CRT, Miller-Rabin, Pollard rho (Brent), Pollard p−1, trial division | done |
| Attack | RSA attack primitives + analyzer — 12 attacks (known p/q/d/φ, dp leak, Wiener, Fermat, low-e, common modulus, Håstad, shared prime, rho, p−1), verified successes, 40 tests | done |
| Attack | CLI `cybercipher rsa [--solve]` | done |
| Attack | RSA Lab GUI — dedicated page, BigInt field validation (bits/bytes ✓), analyze & solve, recovered-key round-trip | done |
| Attack | LCG recovery (known/unknown m/a/b, prediction, reverse step, seed recovery) — 34 tests incl. 3-source-verified MT vectors | done |
| Attack | MT19937 (temper/untemper, 624-output state cloning, prediction, CPython getrandbits compatibility) | done |
| Attack | CLI `cybercipher prng {lcg-recover, lcg-predict, mt-clone, mt-bits}` | done |
| Attack | LLL lattice core (exact rational-free Gram-Schmidt, unimodular transform, dimension caps) | done |
| Attack | Coppersmith univariate small roots (Howgrave-Graham, β-divisor regime, certified bounds, verified candidates) | done |
| Attack | RSA analyzer Coppersmith escalation — stereotyped messages via known prefix (`hint`) | done |
| Crypto | AEAD: AES-GCM, AES-CCM, ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM-SIV (combined ct‖tag, AAD, verified tags) | done |
| Crypto | KDFs: PBKDF2, HKDF, scrypt (memory-capped), EVP_BytesToKey (OpenSSL-compatible) | done |
| Analysis | Auto Decode single-byte XOR exploration (bounded sweep, honest scoring penalty, beam-protected) | done |
| Perf | Criterion benches: codec/crypto/recipe hot paths at 64 KiB incl. cold-vs-warm cache comparison | done |

## Later milestones (planned, not started)
- **Milestone 3 — Auto Decode:** bounded explainable recursive decoding with
  candidate scoring and recipe reconstruction. *(planned)*
- **Milestone 4 — attack labs:** RSA (Wiener, Fermat, Håstad, dp leak,
  Coppersmith, ...), PRNG (LCG, MT19937), lattice layer. *(planned)*
- **Milestone 5 — broad symmetric coverage:** RustCrypto-backed Serpent,
  Twofish, Camellia, ARIA, CAST, IDEA, RC2/5/6, GOST family, AEAD, KDFs.
  *(planned)*
- **Milestone 6 — classical + XOR cracking:** frequency/IOC/Kasiski/chi-square
  scoring layers. *(planned)*
- **Milestone 7 — Crypto Assist** (AES Assist first). *(planned)*
- **Milestone 8 — public-key ecosystem** (RSA schemes, ECDSA, SM2, ASN.1,
  JWT). *(planned)*
- **Milestone 9 — compression/file/CTF helpers.** *(planned)*
- **Milestone 10 — compatibility closure** vs CyberChef/ToolsFx/auto-ctf
  baselines before 1.0. *(planned)*

## Deliberate exclusions

- No embedded Python/SageMath/Java runtime in the distributed app.
- No plugin marketplace, accounts, cloud backend, telemetry, or LLM deps.
- No generic visual node editor in v1 (linear recipes + specialized labs).
- Deep forensics suite parity is out of scope; CyberCipher covers useful
  file/CTF helpers, not everything forensic tools do.
