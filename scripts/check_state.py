#!/usr/bin/env python3
"""Lightweight project-state consistency guard (QA-CONSISTENCY-01).

Catches the easy, high-value coordination mistakes:
  1. .agent/state.json main_sha stale vs origin/main.
  2. .agent/queue.yaml marks a task running/pending although its module
     exists on main AND .agent/state.json lists the milestone as completed.
  3. Docs contain "PR in flight" phrases for branches that were merged.

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


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, cwd=ROOT
    ).stdout.strip()


def main() -> int:
    state_path = ROOT / ".agent" / "state.json"
    queue_path = ROOT / ".agent" / "queue.yaml"
    state = json.loads(state_path.read_text(encoding="utf-8")) if state_path.exists() else {}
    queue = queue_path.read_text(encoding="utf-8") if queue_path.exists() else ""

    # 1. Stale main SHA in state.json.
    origin_main = git("rev-parse", "origin/main")
    if origin_main and state.get("main_sha") and origin_main.startswith(state["main_sha"]):
        pass  # exact or prefix match is fine
    elif origin_main and state.get("main_sha"):
        issues.append(
            f"state.json main_sha={state['main_sha']} is stale; origin/main={origin_main[:12]}"
        )

    # 2. Milestone listed completed but queue says running, or vice versa.
    completed = state.get("last_completed", [])
    module_evidence = {
        "M4-RSA": ["crates/cybercipher-attack/src/rsa"],
        "M4-PRNG": ["crates/cybercipher-attack/src/prng"],
        "M4-LAT": ["crates/cybercipher-attack/src/lattice"],
        "M6-XOR": ["crates/cybercipher-attack/src/xor"],
        "M5-AEAD": ["crates/cybercipher-crypto/src/aead.rs"],
        "M5-BLOCK": ["crates/cybercipher-crypto/src/ciphers.rs"],
    }
    for prefix, paths in module_evidence.items():
        exists = any((ROOT / p).exists() for p in paths)
        if not exists:
            continue
        # queue entries with this milestone id that are still running/pending
        for m in re.finditer(
            r"- id: (" + re.escape(prefix) + r"[\w-]*)\n.*?status: (\w+)", queue, re.S
        ):
            task_id, status = m.group(1), m.group(2)
            if status in ("running", "pending") and not any(
                c.startswith(prefix) for c in completed
            ):
                continue  # genuinely not completed — fine
            if status in ("running", "pending") and any(
                c.startswith(prefix) for c in completed
            ):
                issues.append(
                    f"queue task {task_id} is '{status}' but {prefix} is in "
                    "state.json last_completed — mark done or supersede"
                )

    # 3. "PR in flight" phrases in docs (usually stale after merge).
    for doc in (ROOT / "docs").glob("*.md"):
        text = doc.read_text(encoding="utf-8", errors="replace")
        for line_no, line in enumerate(
            text.splitlines(), start=1
        ):
            if "PR in flight" in line.lower() or "pr in flight" in line:
                issues.append(f"{doc.name}:{line_no} contains 'PR in flight' — verify it is still true")

    if issues:
        print("STATE DRIFT DETECTED:")
        for i in issues:
            print(f"  - {i}")
        return 1
    print("state consistency: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
