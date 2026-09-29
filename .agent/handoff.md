# Handoff

## In flight
- Nothing. All lanes integrated and merged; worktrees cleaned up.

## Merged (PRs #1-#19)
bootstrap; crypto baseline+CLI; Auto Decode; RSA attack engine; PRNG recovery; prng CLI; RSA Lab GUI; agent state; AEAD/KDF; runtime PRNGs (Java/glibc/MSVC); runtime-PRNG CLI; criterion benches; M4-complete docs; Auto Decode XOR exploration; lattice LLL+Coppersmith; RSA analyzer Coppersmith escalation; XOR Lab; QA compatibility matrices+vectors.

## Next concrete actions (in priority order)
1. M5 block-cipher breadth: Serpent, Twofish, Blowfish, Camellia, ARIA, CAST5/6, IDEA, RC2/5/6, SEED, Threefish, GOST family (RustCrypto crates; lane-ready).
2. M5 MACs: CMAC, GMAC, Poly1305, KMAC; Argon2id; bcrypt compat.
3. M6 classical ciphers + cracking (Caesar..ADFGVX, IOC/Kasiski/chi-square/n-grams).
4. M7 Crypto Assist (AES Assist first) + Auto Decode wrappers (Unicode escapes, quoted-printable).
5. M8 PKI: RSA standard schemes, ECDSA/Ed25519/X25519, SM2, PEM/DER/ASN.1, JWT.
6. Wire vectors/ fixtures into automated differential tests.

## Blocked
- Subagent concurrency limit = 2; background agents can die on infra errors ("Captcha instance timed out", "exceed quota limit") — always checkpoint worktrees and finish orphaned WIP as coordinator (done twice this session).
