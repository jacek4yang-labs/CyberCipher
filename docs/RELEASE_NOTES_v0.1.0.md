# CyberCipher v0.1.0 — release notes

First packaged release of CyberCipher, a local-first cryptography and CTF
workbench (Rust engine + Tauri 2 GUI + CLI sharing the same engine).

## Highlights

- **Workbench**: recipe composition over 215+ typed operations with
  incremental execution, stage caching, Auto Bake (cost-gated), copy-as
  formats, recipe import/export.
- **Auto Decode v3**: bounded, explainable multi-layer decoding (beam depth
  6, width 16, 3s budget) over the full wrapper vocabulary — base families,
  HTML entities, quoted-printable, punycode, UU/XX/yEnc, compression and
  structured wrappers, specialty codecs.
- **Crypto Assist**: constrained parameter search for AES, SM4, DES, 3DES,
  Serpent, Twofish, Camellia and RC4 — structural pruning, ranked candidates
  with evidence, Apply as Recipe.
- **Attack labs**: RSA analyzer (known-pq/d/phi, dp-leak, Wiener, Fermat,
  low-e, common modulus, Håstad, shared prime, Coppersmith, Pollard rho/p−1),
  PRNG recovery (LCG, MT19937, Java, glibc, MSVC), XOR solving, classical
  cracking, lattice layer, ECDSA nonce attacks, crypto signature scanner.
- **PKI Lab**: RSA keygen + OAEP/PKCS#1 v1.5/PSS, ECDSA P-256/P-384, ECDH,
  Ed25519, X25519, SM2 + SM3, X.509/CSR/CRL/ASN.1 inspection, JWT/JWS
  (HS/RS/ES/EdDSA, alg=none rejection, claims validation).
- **Stego Lab**: bounded image decode, 42 StegSolve-compatible transforms
  (bit-exact), manual bit extraction, bounded Auto LSB scan, PNG/JPEG/GIF/BMP
  structure analysis with appended-data carving, QR/barcode (bytes-first),
  stereogram solver, 13-mode combiner, GIF frame access.
- **SSTV Lab**: automatic mode detection (Martin/Scottie/Robot/PD), VIS and
  blind sync-period recovery, frequency/clock correction, inverse-model
  candidate ranking — pure Rust in-tree (sstv-auto lineage), no subprocess.
- **Cross-tool composition**: Auto LSB bytes → Auto Decode, appended bytes →
  Workbench, QR payloads → Auto Decode, SSTV frames → Stego Lab, Crypto
  Assist → Apply as Recipe.
- **Safety posture**: typed errors with expected/actual, provenance metadata
  per operation, resource caps before allocation, hostile-input fuzzing on
  the parsers, honest cost classes (Heavy/Solver operations never auto-bake).

## Package

`CyberCipher-v0.1.0-linux-x86_64.tar.gz` — extract under `~/Applications`
(no sudo, no package manager, no build tools at runtime):

```bash
mkdir -p ~/Applications
tar -xzf CyberCipher-v0.1.0-linux-x86_64.tar.gz -C ~/Applications
```

Layout: `CyberCipher/` (GUI), `cybercipher` (CLI), desktop-install scripts,
share/, licenses, README.txt. Mutable state stays in `~/.config/cybercipher`,
`~/.cache/cybercipher`, `~/.local/share/cybercipher`. The archive contains no
Java, Python or Node runtime — everything is statically linked Rust.

Verify: `sha256sum -c CyberCipher-v0.1.0-linux-x86_64.tar.gz.sha256`

## Known limitations

- PKI residual parity (secp256k1/ETH, DSA, Ed448/X448) not yet implemented.
- File/data long-tail (YAML, XML, BSON, protobuf wire inspection) pending.
- APNG / animated WebP frame support pending.
- Pixel inspector needs a per-pixel readback op (GUI tab omitted rather than
  faked).

## Provenance

StegSolver (c14bfa9) and sstv-auto (f626d50) are behavioral parity references
used under MIT; see PROVENANCE.md and the in-crate NOTICE files. Full
capability matrices live under `compatibility/`.
