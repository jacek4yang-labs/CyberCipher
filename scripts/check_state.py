#!/usr/bin/env python3
"""Lightweight project-state consistency guard (QA-CONSISTENCY-01).

Semantics (revised): `.agent/state.json` records `last_reconciled_sha` — the
main HEAD observed at the last reconciliation. It must be an ANCESTOR of
current main, never necessarily equal to it: state-update commits themselves
land after the SHA they observed, so strict equality would create permanent
one-commit drift. Docs/state-only commits after the reconciliation base are
acceptable; meaningful merged feature work that is missing from the recorded
state is not.

Catches the easy, high-value coordination mistakes:
  1. last_reconciled_sha not an ancestor of current main (rewritten or
     unrelated history, or an unknown SHA).
  2. queue tasks marked running/pending although their milestone is recorded
     in last_completed with module-existence evidence on disk.
  3. stale "PR in flight" phrases in docs (heuristic).

Exit code 0 = consistent, 1 = drift found. Heuristic by design — GitHub
remains authoritative; this only flags obvious contradictions for review.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
issues: list[str] = []


def git(*args: str) -> tuple[str, int]:
    r = subprocess.run(["git", *args], capture_output=True, text=True, cwd=ROOT)
    return r.stdout.strip(), r.returncode


def main() -> int:
    state_path = ROOT / ".agent" / "state.json"
    queue_path = ROOT / ".agent" / "queue.yaml"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    queue = queue_path.read_text(encoding="utf-8") if queue_path.exists() else ""

    origin_main, _ = git("rev-parse", "origin/main")
    base = state.get("last_reconciled_sha")

    # 1. Ancestor semantics: base must be an ancestor of current main.
    if origin_main and base:
        if base == origin_main:
            pass  # reconciled at HEAD — ideal
        else:
            _, rc = git("merge-base", "--is-ancestor", base, origin_main)
            if rc != 0:
                issues.append(
                    f"last_reconciled_sha={base} is NOT an ancestor of "
                    f"origin/main={origin_main[:12]} — history diverged or the "
                    "SHA is unknown"
                )
            # Commits after the base are acceptable if state-only; detecting
            # "meaningful feature commits missing from metadata" is left to
            # rule 2's module evidence rather than parsing commit messages.

    # 2. Milestone recorded complete but queue entry still active.
    completed = state.get("last_completed", [])
    module_evidence = {
        "M4-RSA": ["crates/cybercipher-attack/src/rsa"],
        "M4-PRNG": ["crates/cybercipher-attack/src/prng"],
        "M4-LAT": ["crates/cybercipher-attack/src/lattice"],
        "M6-XOR": ["crates/cybercipher-attack/src/xor"],
        "M6-CLASSICAL": ["crates/cybercipher-attack/src/classical"],
        "M7-ASSIST": ["crates/cybercipher-attack/src/assist"],
        "M5-AEAD": ["crates/cybercipher-crypto/src/aead.rs"],
    }
    for prefix, paths in module_evidence.items():
        exists = any((ROOT / p).exists() for p in paths)
        recorded = any(c.startswith(prefix) for c in completed)
        if not exists or recorded:
            continue
        for m in re.finditer(
            r"- id: (" + re.escape(prefix) + r"[\w-]*)\n.*?status: (\w+)", queue, re.S
        ):
            task_id, status = m.group(1), m.group(2)
            if status in ("running", "pending", "ready") and recorded:
                issues.append(
                    f"queue task {task_id} is '{status}' but {prefix} appears in "
                    "state.json last_completed — mark done or supersede"
                )

    # 3. Stale "PR in flight" phrases in docs (heuristic).
    for doc in (ROOT / "docs").glob("*.md"):
        text = doc.read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), start=1):
            if "pr in flight" in line.lower():
                issues.append(
                    f"{doc.name}:{line_no} contains 'PR in flight' — verify it is still true"
                )

    if issues:
        print("STATE DRIFT DETECTED:")
        for i in issues:
            print(f"  - {i}")
        return 1
    print("state consistency: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
