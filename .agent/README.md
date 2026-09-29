# CyberCipher agent state

This directory is the durable coordination state for autonomous development
sessions. Any fresh agent must be able to resume work from this directory
plus GitHub state alone — never from chat history.

- `state.json` — compact machine-readable snapshot (phase, current task, validation). `last_reconciled_sha` records the main HEAD at reconciliation time and must remain an ancestor of current main — it is NOT expected to equal HEAD, because state-update commits themselves land after it
- `queue.yaml` — the authoritative work queue
- `decisions.md` — durable engineering decisions only (no diary)
- `handoff.md` — ≤100 lines: what's in flight, next action, blockers

Rules:

- Only the primary coordinator modifies `.agent/*`; subagents never do.
- Statuses: pending | ready | running | review | blocked | done | superseded.
- GitHub (PRs, branches, CI) outranks these files when they disagree.
- Never store secrets, tokens, or private challenge material here.
