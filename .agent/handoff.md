# Handoff

## In flight
- Agent C: AEAD/KDF -> branch agent/crypto/m5-aead (worktree ../cc-agent-crypto)
- Agent E: RSA Lab GUI -> branch agent/gui/m4-attack-lab (worktree ../cc-agent-rsa-gui)
- Coordinator branch feat/prng-cli: CLI prng commands (this PR)

## Merged
- #1 bootstrap, #2 crypto baseline, #3 Auto Decode, #4 RSA attack engine (12 attacks + analyzer + BigInt ops), #5 PRNG recovery (LCG + MT19937)

## Next concrete actions
1. Merge feat/prng-cli when CI green.
2. Integrate Agent C's AEAD branch -> PR; then relaunch Agent D (QA) on the free slot.
3. Integrate Agent E's GUI branch -> PR.
4. Next lanes: LLL/Coppersmith (worktree from post-#5 main), Java Random/glibc/MSVC rand, then M7 Auto Decode expansion.

## Blocked
- Subagent concurrency limit = 2 (queue lanes accordingly).
