# Handoff

## In flight
- Agent A2: LLL/Coppersmith -> agent/lattice/m4-coppersmith (worktree ../cc-agent-lattice), continued from WIP checkpoint after an infra crash.
- Agent D: QA/compatibility -> agent/qa/m4-coverage (worktree ../cc-agent-qa).

## Merged (PRs #1-#12)
bootstrap; crypto baseline+CLI; Auto Decode; RSA attack engine; PRNG recovery; prng CLI; RSA Lab GUI; agent state; AEAD/KDF; runtime PRNGs (Java/glibc/MSVC); runtime-PRNG CLI; criterion benches.

## Next concrete actions
1. Integrate lattice branch -> PR; then the XOR lab lane (M6-XOR-01) on the freed slot.
2. Integrate QA branch -> PR (docs/matrix coverage closure).
3. After lattice: M7 Auto Decode expansion (XOR candidates), Crypto Assist (AES Assist), classical ciphers.

## Blocked
- Subagent concurrency limit = 2. One infra failure mode seen twice: "Captcha instance timed out" kills background agents — always checkpoint worktrees before relaunching.
