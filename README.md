# CyberCipher

> Crypto, decode, analyze, solve.

CyberCipher is a high-performance, local-first cryptography and CTF workbench.
It combines a CyberChef-style recipe workbench (operations → recipe → input →
output) with a Rust engine built for real cryptanalysis work. Everything runs
on your machine: no telemetry, no remote processing, no accounts.

**Status: pre-1.0 development.** The Workbench UI, the codec/byte-operation
foundation, the practical crypto baseline (AES, DES/3DES, SM4, RC4,
TEA/XTEA/XXTEA, MD5/SHA-1/SHA-2/SHA-3/SM3, HMAC), and the Auto Decode engine
(bounded, explainable multi-layer decoding) are functional, with a CLI sharing
the same engine. The attack labs are the next milestones — see
[docs/CAPABILITIES.md](docs/CAPABILITIES.md) and [docs/ROADMAP.md](docs/ROADMAP.md)
for the honest current state.

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
crates: cybercipher-core · cybercipher-codec · cybercipher-crypto (next)
        · cybercipher-analysis (next) · cybercipher-attack (next)
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.

## Current capabilities (Milestones 1–2)

- 51 working operations. Crypto baseline: AES (ECB/CBC/CTR/CFB/OFB,
  128/192/256-bit keys, validated PKCS7/Zero/ISO7816 padding), DES/3DES, SM4,
  RC4(+drop), TEA/XTEA/XXTEA, hashes (MD5, SHA-1/2/3, SHAKE, Keccak, SM3), and
  HMAC — all with official test vectors and provenance metadata. Legacy/broken
  primitives are labeled, never hidden.
- 18 codec/inspection operations: hex, Base64/URL-safe, Base32/Base32hex, URL percent
  encoding, binary/octal/decimal, hexdump, UTF-8 encode/decode, reverse,
  split/join, XOR (standard/rolling/incrementing, null-preserving), AND/OR/NOT,
  rotate left/right, swap endianness, entropy report, strings extraction.
- Workbench: operation search (aliases + tags), drag-and-drop recipe editing,
  parameter forms generated from the registry, enable/disable/duplicate,
  intermediate stage previews, Auto Bake (debounced, cost-gated), manual Bake,
  per-stage caching, structured error rendering, save/load/import/export
  recipes, dark/light themes, copy-as (hex / Base64 / Python bytes / C array /
  decimal / integer), input↔output swap, flag-pattern highlighting.
- **Auto Decode**: bounded explainable analysis (beam depth 6, width 16, 3s
  budget) that recovers multi-layer encodings — hex → Base64 → gzip — and
  shows its evidence instead of claiming certainty. Available as the Auto
  Analyze page and `cybercipher auto <input>`.
- CLI (`cybercipher`) shares the same engine: `cybercipher ops`,
  `cybercipher run --op from-base64 <input>`, `cybercipher auto <input>`,
  `cybercipher recipe <file> <input>`.

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
