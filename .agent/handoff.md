# Handoff

## main = 3962642 (v0.1.0) — 72 PRs merged, ~215+ registry ops, 1200+ tests.
## RELEASE: https://github.com/jacek4yang-labs/CyberCipher/releases/tag/v0.1.0
## Validation: GitHub Actions CI ONLY (machine policy: no local cargo/npm).

## RELEASE v0.1.0 (published)
- CyberCipher-v0.1.0-linux-x86_64.tar.gz (12.7 MB) + .sha256 attached.
- Package job: tar.gz from scripts/package-linux.sh (exec bit fixed in #72).
- Smoke job: layout verified, CLI --help OK, sha256("abc") KAT OK, GUI linkage recorded.
- sha256 verified on the downloaded artifact; canonical layout confirmed (12 entries).

## Merged this session (#58-#72)
stereogram/combine/frames (#58) · queue reconcile (#61) · QR/barcode (#62) ·
Auto Decode v3 (#63) · signature scanner (#64) · matrices reconcile (#65) ·
GUI composition (#66) · Assist profiles (#67) · docs truth (#68) ·
parity mop-up (#69) · release notes (#70) · ECDSA attacks (#71) ·
release exec-bit fix (#72).

## Remaining (tracked in queue.yaml, all P2/P3)
- PKI residual: secp256k1/ETH address, DSA, Ed448/X448.
- File/data: YAML, XML, BSON, protobuf wire inspection.
- Crypto long-tail: KMAC, bcrypt, HC-256/Rabbit/ZUC, CTS/XTS/EAX/OCB/SIV.
- Pixel inspector op + GUI tab; APNG/animated-WebP frames.

## Lessons (regression pins + process)
- Conflicting PRs get NO CI runs — keep branches merge-clean (cost a QR-lane debug cycle).
- rustfmt CI diffs apply mechanically line-anchored (apply_fmt.py pattern in session log).
- JJ tail/run boundary, base64url canonical trailing bits, Java Random LCG,
  uu/xx per-line budgets, punycode adapt-after-emit + delta increments —
  all pinned by tests; do not regress.
- Workers die at quota; checkpoint-push per coherent block means zero lost work
  (proven repeatedly this session).
