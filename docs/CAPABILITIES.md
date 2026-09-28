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

## Later milestones (planned, not started)

- **Milestone 2 — crypto baseline:** AES, DES/3DES, SM4, RC4, TEA/XTEA/XXTEA,
  MD5/SHA-1/SHA-2/SHA-3/SM3, HMAC. *(planned)*
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
