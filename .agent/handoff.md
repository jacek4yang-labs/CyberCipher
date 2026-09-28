# Handoff

## In flight
- Branch `feat/rsa-attack-lab` → PR #4 (open once pushed): M4-CORE-01 +
  M4-RSA-01/02/03 — BigInt ops, `cybercipher-attack` crate (math foundation,
  RSA attack primitives, analyzer), CLI `rsa analyze`.

## Next concrete action
- Implement `crates/cybercipher-attack` (math.rs, rsa/attacks.rs,
  rsa/analyzer.rs), BigInt ops in codec, CLI wiring, tests; validate; push;
  open PR; green CI; squash merge; update `.agent`.

## After that
- M4-RSA-04 (RSA Lab GUI) and M4-PRNG-01/02 (LCG, MT19937) → PR #5.
- Then M5-AEAD-01 (AEAD) and M4-LAT-01/02 (LLL + Coppersmith).

## Blocked
- None.

## Environment notes for a fresh agent
- Windows host, Git Bash. Node + Rust stable present. `gh` authenticated as
  `jacek4yang` (admin of jacek4yang-labs).
- Frontend lives in `ui/` (npm). Tauri app: `apps/cybercipher-gui`.
- CI required checks: Rust / Frontend / TauriLinuxSmoke (strict).
- Clippy is `-D warnings`; `clippy::result_large_err` is allowed per-crate
  with rationale (see `.agent/decisions.md`).
-cargo workspace: 6 crates; tests: `cargo test --workspace` (~60 tests).
