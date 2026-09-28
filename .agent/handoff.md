# Handoff

## In flight
- Agent C: AEAD/KDF -> agent/crypto/m5-aead (worktree ../cc-agent-crypto)
- Agent A2: LLL/Coppersmith -> agent/lattice/m4-coppersmith (worktree ../cc-agent-lattice)

## Merged (PRs #1-#7)
bootstrap, crypto baseline+CLI, Auto Decode, RSA attack engine, PRNG recovery, prng CLI, RSA Lab GUI.

## Next concrete actions
1. Integrate Agent C's AEAD branch -> PR #8; then relaunch Agent D (QA, worktree ../cc-agent-qa exists).
2. Integrate lattice branch -> PR #9.
3. Next lanes after those: XOR lab (M6), Auto Decode expansion (M7), Java Random/glibc/MSVC rand.

## Blocked
- Subagent concurrency limit = 2.
