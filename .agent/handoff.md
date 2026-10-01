# Handoff

## main = d7b40b9 — 53 PRs, ~200 ops, ~830 tests. CI green. Validation: GitHub Actions ONLY (no local cargo per user policy).

## Session 8 merged (13 PRs)
#44 steg/sstv parity matrices + design doc | #45 PKI Lab GUI | #46 JWT/JWS
#47 SSTV core migration | #48 steg core (media+transforms+extract) | #49 CI timeout 60m
#50 state | #51 Auto LSB scanner | #52 SSTV op+Tauri/CLI bridge | #53 SSTV Lab GUI
#54 structure/carving | #55 CTF specialty (provenance-first) | #56 Stego Lab GUI

## In flight (CI-only loops)
- agent/qr: image_scan_qr op (rxing/rqrr, bytes-first payloads, inverted/rotated/rescaled fallbacks)
- agent/stereo: image_stereo_shift/auto, image_combine (13 modes), image_gif_info/frame

## Next
1. Auto Decode v3 expansion (wrap existing ops)
2. Crypto signature scanner (M7-SIG-01)
3. Crypto Assist profiles (SM4/DES/Serpent/RC4...)
4. ECDSA attacks (nonce reuse, duplicate-r)
5. Crypto parity mop-up (SEED/KMAC/HC-256/...)
6. Prerelease v0.1.0-alpha + tar dogfooding
7. Stego Lab: wire structure/QR tabs once ops land; pixel inspector op

## Coordination notes
- Worker quota deaths: finish WIP as coordinator from checkpoints (checkpoint policy held: zero lost work)
- JJ decode lesson: payload-tail boundary drift between encoders; walker accepts unterminated final run
- Rust CI job is 60m; full workspace test on CI ~40m — do not add heavy work without need
