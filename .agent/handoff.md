# Handoff

## main = 378a8e7 — 48 PRs, ~190 ops, ~734 tests. CI green (Rust job now 60m).

## Session 8 merged
- #44 StegSolver + sstv-auto capability matrices + docs/design-steg-sstv.md
- #45 PKI Lab GUI (Keys/RSA/ECC/SM2/Certificate tabs, 19 Tauri commands)
- #46 JWT/JWS engine (HS/RS/ES/EdDSA, alg=none rejection, claims validation, CLI + ops)
- #49 CI Rust job timeout 30m -> 60m (SSTV e2e suite needs it)
- #48 steg core: cybercipher-media (RgbaImage/bounded decode/encode/Roi) +
  cybercipher-steg (42 transforms bit-exact + DataExtractor + 3 registry ops)
- #47 SSTV core: sstv-auto f626d50 migrated in-tree (13 modules, 150 tests,
  bytes boundary, slowrx pinned, NOTICE/ML restribution notes)

## In flight (Wave 3)
- agent/autolsb: Auto LSB bounded scanner (steg PR-2) — Fast/Deep enumeration,
  verbatim scoring table, dedup/rank, auto_lsb_scan op
- agent/sstv-bridge: sstv_decode Heavy op + Tauri/CLI bridge (SSTV PR-2)

## Next lanes
1. Lane C: PNG/JPEG/GIF/BMP structure + appended-data carving + frames
2. Lane D: QR/barcode (rxing) + Stego Lab GUI
3. SSTV Lab GUI + Stego handoff
4. Lane F: stereo + combine + pixel/ROI
5. CTF specialty codecs (provenance first), Auto Decode v3, signature scanner,
   Assist profiles, ECDSA attacks, crypto parity mop-up

## Regression pins (never regress)
CTR/CFB/OFB unaligned input; Trifid 27-symbol; Hill cofactor signs; ADFGX/VX
ragged columns; XOR crib/keylen semantics; RFC 8410 OCTET STRING; X25519
all-zero rejection; SM2 scalar left-pad; Java Random LCG + full-alpha >>>8
quirk; base64url canonical trailing bits (JWT decode); ROI clamp origin.
