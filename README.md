# CyberCipher

> Crypto, decode, analyze, solve.

CyberCipher is a high-performance, local-first cryptography and CTF workbench.
It combines a CyberChef-style recipe workbench (operations → recipe → input →
output) with a Rust engine built for real cryptanalysis work. Everything runs
on your machine: no telemetry, no remote processing, no accounts.

**Status: pre-1.0 development.** The Workbench, the full codec/crypto/PKI
engine, the attack labs (RSA, PRNG, XOR, classical, lattice), PKI Lab, Stego
Lab (StegSolve-compatible transforms, bit extraction, Auto LSB, structure
analysis, carving, QR/barcode, stereogram, combine, GIF frames), SSTV Lab
(automatic mode detection, blind recovery, inverse-model ranking), JWT/JWS,
Crypto Assist (AES/SM4/DES/3DES/Serpent/Twofish/Camellia/RC4 profiles), the
signature scanner and Auto Decode v3 are all functional, with a CLI sharing
the same engine. See [docs/CAPABILITIES.md](docs/CAPABILITIES.md) and
[docs/ROADMAP.md](docs/ROADMAP.md) for the honest current state.

## Key properties

- **Rust engine, typed data model.** The engine is not `String -> String`;
  values are typed (bytes, text, integers, JSON, lists) and operations declare
  what they accept. The frontend is a replaceable presentation layer.
- **Incremental recipe execution.** Changing operation 5 of 10 re-runs only
  stages 5–10; earlier stages are served from a keyed stage cache.
- **Explainability.** Structured errors (expected vs actual), provenance
  metadata per operation (standard, implementation, test vectors), and honest
  cost classes: Auto Bake never silently runs expensive or solver operations.
- **Offline by construction.** No network code in the core engine.

## Architecture summary

```text
Tauri 2 GUI (React + TypeScript)  ← presentation only
        │  IPC: commands, metadata, previews
Rust engine (cybercipher-engine)
  ├─ recipe model (versioned public JSON format)
  ├─ incremental executor with stage cache
  └─ operation registry (drives the GUI)
        │
crates: cybercipher-core · cybercipher-codec · cybercipher-crypto
        · cybercipher-attack · cybercipher-pki · cybercipher-engine
        · cybercipher-media · cybercipher-steg · cybercipher-sstv
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Current capabilities

- **215+ registered operations** across ten crates, each with typed inputs,
  provenance metadata (standard, implementation, test vectors) and honest cost
  classes. Highlights:
  - Crypto: AES/DES/3DES/SM4/RC4/TEA family, Serpent/Twofish/Camellia/ARIA/
    CAST5/IDEA/RC2/RC5/RC6/Threefish/Magma/Kuznyechik, AEAD (GCM/CCM/
    ChaCha20-Poly1305/XChaCha20-Poly1305/GCM-SIV), KDFs (PBKDF2/HKDF/scrypt/
    Argon2id/EVP_BytesToKey), MACs (HMAC/CMAC/GMAC/Poly1305), hashes (MD5,
    SHA-1/2/3, SHAKE, Keccak, SM3), stream ciphers (Salsa20/XSalsa20/RC4).
  - PKI: RSA keygen + OAEP/PKCS#1 v1.5/PSS, ECDSA P-256/P-384/secp256k1
    (+ ETH addresses), ECDH, Ed25519, X25519, X448, DSA, SM2 + SM3,
    X.509/CSR/CRL/ASN.1 inspection, JWT/JWS
    (HS/RS/ES/EdDSA, alg=none rejection, claims validation).
  - Attacks: RSA analyzer (known-pq/d/phi, rabin, dp-leak, dp+dq joint leak,
    Wiener, Fermat, low-e, common modulus, Håstad, shared prime, Coppersmith,
    Pollard rho/p−1),
    PRNG recovery (LCG/MT19937/Java/glibc/MSVC), XOR solving, classical
    cipher cracking (IOC/Kasiski), ECDSA nonce attacks, Crypto Assist
    profiles, crypto signature scanner.
  - Steg/media: bounded image decode, 42 StegSolve-compatible transforms
    (bit-exact), bit extraction, bounded Auto LSB scanner, PNG/JPEG/GIF/BMP
    structure analysis + appended-data carving, QR/barcode (bytes-first),
    stereogram solver, 13-mode combiner, GIF frames.
  - SSTV: automatic mode detection (Martin/Scottie/Robot/PD), VIS + blind
    sync-period recovery, frequency/clock correction, inverse-model ranking,
    in-tree Rust (sstv-auto lineage, no subprocess).
  - Data: gzip/zlib/deflate/bzip2/xz/zstd/lz4/brotli, tar/zip, CBOR/
    MessagePack/VarInt/TLV, file magic, UTF-16, specialty CTF codecs
    (Brainfuck/Ook, Buddha, beast/bear, core values, AA/JJ), Auto Decode v3
    wrapper vocabulary (HTML entities, quoted-printable, punycode, UU/XX/yEnc,
    compression/structured wrappers).
- **Labs, not silos.** Results flow between tools: Auto LSB bytes → Auto
  Decode, appended bytes → Workbench, QR payloads → Auto Decode, SSTV frames
  → Stego Lab, Crypto Assist → Apply as Recipe.
- **Auto Decode v3**: bounded explainable beam search (depth 6, width 16, 3s
  budget) over the full wrapper vocabulary, with adversarial negative corpus.
- **CLI** (`cybercipher`) shares the same engine: ops, run, recipe, auto,
  rsa, prng, jwt, sstv, sigscan and more.

## Linux installation

The canonical Linux release is a tarball extracted under `~/Applications`
(no sudo, no package manager, no build tools at runtime):

```bash
mkdir -p ~/Applications
tar -xzf CyberCipher-vX.Y.Z-linux-x86_64.tar.gz -C ~/Applications
~/Applications/CyberCipher/CyberCipher      # GUI
~/Applications/CyberCipher/cybercipher --help  # CLI
```

Optional desktop integration: run `~/Applications/CyberCipher/install-desktop.sh`.
User data lives in XDG directories (`~/.config/cybercipher`, `~/.cache/cybercipher`,
`~/.local/share/cybercipher`), so upgrading is a simple folder replacement.
See [docs/RELEASING.md](docs/RELEASING.md) for the release process and the
honestly-documented dynamic runtime libraries (WebKitGTK/GTK3).

## Development

Prerequisites: Rust 1.85+, Node 20+, and Tauri 2 system dependencies
(on Linux: `libwebkit2gtk-4.1-dev`, `libgtk-3-dev`, `libayatana-appindicator3-dev`,
`librsvg2-dev`).

```bash
# backend
cargo test --workspace

# CLI (after cargo build)
cargo run -p cybercipher-cli -- run --op sha256 -- README.md
cargo run -p cybercipher-cli -- auto "ZmxhZ3tleGFtcGxlfQ=="

# frontend
cd ui && npm install && npm run typecheck && npm run build

# run the desktop app (dev)
npm --prefix ui run tauri dev
```

Linux distribution is a `tar.gz` release extracted under `~/Applications/` (canonical; AppImage may follow later); see [docs/ROADMAP.md](docs/ROADMAP.md).

## Security model

CyberCipher handles sensitive material. It works fully offline, has no
telemetry, and never persists inputs unless you explicitly save a recipe.
Legacy/broken algorithms are labeled, never hidden — CTF work needs them.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option.
