# Contributing

## Workflow

All development happens through pull requests; `main` is protected and always
releasable.

```text
main → feat/… | fix/… | refactor/… | docs/… branch → PR → CI green → squash merge
```

- One PR = one coherent engineering unit (a subsystem or milestone slice).
  Not one PR per edit, not the whole project in one PR.
- Conventional commit messages: `feat:`, `fix:`, `perf:`, `test:`, `docs:`.
- Do not bypass branch protection; if CI fails, fix the branch.

## Local validation before every PR

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cd ui && npm run typecheck && npm run build
```

## Quality bar

A feature is done when implementation, UI/CLI exposure, tests, edge cases,
useful error messages, provenance metadata, and docs all exist. Compile-only
is not done.

Additional rules (see README and docs/ARCHITECTURE.md):

- Never process user data remotely; no telemetry.
- No `.unwrap()` on user-controlled input in production paths.
- Never claim cipher detection without evidence; heuristics report evidence
  and confidence, never false certainty.
- Don't duplicate engine logic in TypeScript — the frontend is a
  presentation layer.
- Never commit secrets, keys, or private challenge material.
