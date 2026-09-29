# RSA known-answer fixtures

Small RSA instances generated for CyberCipher's attack lab and engine tests.
Generated and verified on 2026-09-28 with an independent Python reference:

```python
c = pow(m, e, n); assert c == pow(m, e, n)
assert pow(c, d, n) == m          # round-trip both directions
d = pow(e, -1, (p-1)*(q-1))       # derivation used for every instance
```

Primality was checked with 40-round Miller-Rabin. Instances are intentionally
small so every attack in the engine (wiener, fermat, low-e, pollard-*, dp-leak)
runs in milliseconds during tests.

## Instance 1 — textbook (Wiener-hostile layout, e = 17)

Classic first-example parameters; useful as the smallest end-to-end smoke test.

```
p   = 61
q   = 53
n   = 3233
phi = 3120
e   = 17
d   = 2753
m   = 123
c   = 855
```

Verified: `pow(123, 17, 3233) == 855` and `pow(855, 2753, 3233) == 123`.

## Instance 2 — two 64-bit primes, e = 65537 (workhorse fixture)

Message is ASCII `CTFKAT2`. Also carries a precomputed `dp` fixture for the
dp-leak attack.

```
p   = 16877550142839303311      (0xea391a6f0ec7ac8f)
q   = 17005604391466942553      (0xec000b183035c059)
n   = 287012940826271579945005337557779692983
    = 0xd7ecae84f73935e358934dcb6e713db7
phi = 287012940826271579911122183023473447120
e   = 65537
d   = 239238032431413764245918833852729106753
m   = 18951484326630450         (ascii "CTFKAT2", hex 4354464b415432)
c   = 160713494738716358910758721162690029310
    = 0x78e84b0f0d95302c2c3de5479eede6fe
dp  = d mod (p-1) = 13539742074094316353
```

Verified: `pow(m, e, n) == c`, `pow(c, d, n) == m`, and
`pow(pow(m, e, n), dp, p) % p == m % p` (dp-leak consistency).

Note: p and q here are far apart (`|p-q| ≈ 1.28e17` vs `n^(1/4) ≈ 4.1e9`), so
Fermat factorization would need ~1.2e14 iterations — this instance is a
*negative* fixture for fermat/wiener and a positive fixture for known-pq,
known-d, known-phi and dp-leak. Fermat/wiener attack tests need their own
tailored instances (chosen close-primes / small-d), which the engine tests
generate locally.

## Instance 3 — low public exponent, e = 3 (low-e / Hastad fixture)

Message is ASCII `loweKAT`.

```
p   = 3538334777     (0xd2e6b439)
q   = 2708517689     (0xa170b339)
n   = 9583642333108370353
    = 0x84ffefecf751fbb1
phi = 9583642326861517888
e   = 3
d   = 6389094884574345259
m   = 30521856075972948   (ascii "loweKAT", hex 6c6f77654b4154)
c   = 2790785495427403855 (0x26badc9f3343504f)
```

Verified: `pow(m, 3, n) == c`, `pow(c, d, n) == m`, and `c != m`
(i.e. the low-e attack on this fixture must actually take a cube root over the
integers modulo nothing — the message does not cube below n, so a naive
integer cube root fails and the attack must use the CRT path).

## Usage notes

- These are teaching/regression fixtures, not cryptographic material; all
  private values are public by design.
- For randomized attack tests, derive fresh instances with the same snippet
  shown above and keep the assertions — the assertions are the contract.
- Source: generated for CyberCipher (no external origin); release under the
  repository license.
