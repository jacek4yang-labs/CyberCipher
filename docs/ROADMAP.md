# Roadmap

Milestones follow the project charter. Order is deliberate: correctness and
architecture before breadth. Each milestone lands as one or more reviewed PRs
with tests, docs, and honest capability status.

- **Milestone 0 — repository & architecture.** ✅ Rust workspace, Tauri 2 app,
  React frontend, CI, typed Value/DataRef, operation registry, execution
  context, error model, provenance model.
- **Milestone 1 — working Workbench.** ✅ Search, drag/drop recipe, input/output,
  intermediate results, manual + auto bake, recipe save/load, 29 codec/byte
  operations.
- **Milestone 2 — practical CTF crypto baseline.** ✅ AES (ECB/CBC/CTR/CFB/OFB,
  PKCS7/Zero/ISO 7816 padding with validated unpad), DES/3DES, SM4, RC4(+drop),
  TEA/XTEA/XXTEA, MD5/SHA-1/SHA-2/SHA-3/SHAKE/Keccak/SM3, HMAC, official NIST /
  GB/T / RFC vectors. Shared-engine CLI binary (`cybercipher`) ships here.
  Remaining polish: AEAD modes (GCM/CCM/EAX), CTS/XTS.
- **Milestone 3 — Auto Decode.** ✅ Bounded, explainable decoding: cheap
  detectors → candidate generation → execution → scoring → beam search
  (depth 6 / width 16 / 3s deadline), evidence output, recipe reconstruction,
  corpus tests (multi-layer, traps, random data), Auto Analyze page, `auto`
  CLI command. Extensions (XOR exploration, Unicode-escape wrappers) follow.
- **Milestone 4 — RSA / PRNG attack labs.** Known p/q, dp/dq leaks, Wiener,
  Fermat, low-e, common modulus, Håstad, shared prime, Pollard rho/p−1,
  LCG recovery, MT19937 state cloning; lattice/LLL layer and Coppersmith next.
- **Milestone 5 — broad symmetric coverage.** RustCrypto-backed Serpent,
  Twofish, Blowfish, Camellia, ARIA, CAST5/6, IDEA, RC2/5/6, Threefish, SEED,
  GOST family; MAC/KDF/AEAD set.
- **Milestone 6 — classical / XOR cracking.** Caesar→ADFGVX set, frequency,
  IOC, Kasiski, chi-square, n-gram language scoring, crib dragging, MTP
  helpers.
- **Milestone 7 — Crypto Assist.** AES Assist parameter-space search with
  explainable ranking and "apply as recipe"; generalize to SM4/DES/3DES/RC4.
- **Milestone 8 — public-key ecosystem.** RSA standard schemes, ECDSA/Ed25519,
  SM2, certificate/key parsing, JWT/JWK, ASN.1.
- **Milestone 9 — compression / file / CTF helpers.** gzip/zlib/deflate and
  friends, structured data (JSON/YAML/XML/CBOR/MsgPack/TLV/ASN.1), magic
  detection, embedded file scanning, image/QR/LSB helpers.
- **Milestone 10 — compatibility closure.** Drive CyberChef/ToolsFx relevant
  gaps to zero and auto-ctf crypto baseline to matched/exceeded, then 1.0.

Infrastructure spread across milestones: Linux AppImage + signed updates,
property/fuzz testing, Criterion benchmarks, external-tool adapters (YAFU,
hashcat, John) as explicit optional sidecars.
