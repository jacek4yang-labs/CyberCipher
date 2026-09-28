# Durable engineering decisions

- **Crate layout**: five crates (core, codec, crypto, engine, attack) — not one
  per concept. `attack` was added at M4 for number theory / RSA / PRNG /
  lattice; it stays out of the recipe registry (attacks are Solver-class,
  exposed via Labs + CLI) except where an operation genuinely belongs in a
  pipeline.
- **ParamValue is plain JSON** (untagged serde): recipe files carry ordinary
  JSON values. Big cryptographic integers are transported as strings and
  parsed Rust-side — never as JS numbers.
- **Error model**: `OperationError { kind, message, parameter, expected,
  actual, details }` serialized to the UI; no string parsing in the frontend.
  `#![allow(clippy::result_large_err)]` is documented in core/lib.rs (cold
  failure paths; boxing everywhere was judged not worth the churn).
- **CFB-128 is native** (ciphers.rs): RustCrypto's padded block-mode API
  cannot express a partial final block; our CFB matches OpenSSL semantics.
- **RC4 is native**: the `rc4` crate's compile-time key-size generics cannot
  take runtime-variable key lengths (classic CTF vectors use 3–16 byte keys).
- **TEA endianness**: TEA/XTEA use big-endian words; XXTEA uses little-endian
  words (canonical C reference on LE machines — matches CTF material).
- **Relaxed decoders are explicit**: strict mode is default; relaxed modes are
  separate parameter choices with diagnostics, never silent reinterpretation.
- **RustCrypto for standardized crypto**; hand-written only where the crate
  ecosystem cannot express CTF-required behavior (CFB partial blocks, RC4
  variable keys, TEA family) or where the attack itself is the product.
- **Cache keys**: xxh3-64 chained stage keys including node id + canonical
  params + IMPL_VERSION; disabled nodes inject a skip marker so downstream
  results cannot be reused across enable toggles.
- **CFB/CTR/OFB stream modes ignore padding**; ECB/CBC own the padding policy
  (PKCS7 default, validated unpad with a "check your key first" hint).
