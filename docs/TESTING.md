# Testing

## How to run

```bash
cargo test --workspace          # all backend tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cd ui && npm run typecheck && npm run build   # frontend
```

CI runs all of the above plus a Linux Tauri build smoke test.

## Current test inventory (Milestone 1)

- **core** (11 tests): value coercion, param validation + canonical JSON,
  registry search ranking, error serialization round-trip, entropy bounds,
  cancellation context.
- **codec** (12 test functions): RFC 4648 Base64/Base32 known-answer vectors
  (both directions), hex strict/relaxed diagnostics (odd length, invalid char
  naming), URL round-trips, radix round-trips + range validation, XOR known
  answers (single-byte, repeating, rolling-inverse, incrementing, empty-key
  error), bitwise/rotation/endianness constants, reverse/split/join
  round-trips, entropy + strings, UTF-8 invalid-sequence offset reporting,
  input-encoding helpers.
- **engine** (12 tests): ordered execution, cache hits on re-run, downstream
  invalidation on parameter change, disabled-node skip semantics, auto-mode
  cost gating, cancellation, operation error capture, panic isolation,
  execution-count cache proof, recipe JSON round-trip + validation.

- **crypto** (15 tests): AES-128 ECB/CBC + AES-256 NIST SP 800-38A vectors,
  stream-mode round-trips (CTR/CFB/OFB, non-aligned tails), PKCS7 round-trip +
  corrupted-ciphertext typed error, key-length validation with expected/actual,
  missing-IV diagnostics, SM4 GB/T standard vector, DES classic vector + 3DES
  round-trips, RC4 classic vector + involution, TEA zero-vector KAT
  (cross-verified against an independent implementation), family round-trips,
  block/word validation, hash KATs (MD5/SHA-1/SHA-256/SHA-512/SHA3-256/SM3),
  HMAC RFC 4231 case 1, engine-level integration of crypto ops.

## Requirements for later milestones

Every standardized crypto implementation ships with:

- official known-answer vectors,
- round-trip tests,
- differential tests against a second implementation where practical,
- malformed-input and edge-case tests.

Attack code additionally ships with: synthetic vulnerable instances, negative
instances (attack must *not* fire), and resource bounds. Auto Decode gets a
corpus: single-layer, multi-layer, compressed, binary, false-positive traps,
random data, CTF-like chains.

Property testing (`proptest`) and fuzzing (`cargo-fuzz`) targets for parsers,
codecs, padding, and recipe serialization are planned; the architecture
already keeps parsers pure functions to make this straightforward.
Benchmarks (Criterion) for Base64/hex/XOR/AES/hash/recipe execution/auto
analysis land with Milestone 2+; performance work is evidence-driven.
