# Handoff

## In flight
- Branch `feat/rsa-attack-lab` (integration branch for PR #4):
  - coordinator commits: attack-crate skeleton, BigInt codec ops (done, tested), CLI `rsa` (done), `rsa_analyze` Tauri command (done), docs/state.
  - Agent A (worktree ../cc-agent-rsa, branch agent/rsa/m4-rsa): hardening + tests for RSA attacks + math lints.
  - Agent B (worktree ../cc-agent-prng, branch agent/prng/m4-prng): LCG + MT19937 under src/prng.
- Queued (concurrency limit 2): Agent C (AEAD, worktree ../cc-agent-crypto exists), Agent D (QA, worktree ../cc-agent-qa exists). Relaunch as soon as a slot frees.

## Next concrete actions
1. When Agent A reports: merge agent/rsa/m4-rsa into feat/rsa-attack-lab, full validation, open PR #4, CI green, squash merge.
2. Relaunch Agent C (AEAD) on the free slot; then Agent D (QA).
3. PR #5 = agent/prng/m4-prng (+ GUI RSA Lab as Agent E lane afterwards).

## Blocked
- Nothing external. Subagent concurrency limit = 2 (two failures observed).

## Environment notes for a fresh agent
- Windows host, Git Bash. `gh` authenticated as jacek4yang (org admin).
- Required CI checks on main: Rust / Frontend / TauriLinuxSmoke (strict).
- clippy -D warnings; result_large_err allowed per-crate with rationale comment.
- `cargo test --workspace` currently 17 suites / ~77 tests green on this branch.
