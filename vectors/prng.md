# PRNG known-answer vectors

Reference output sequences for the PRNG recovery modules. All sequences were
computed on 2026-09-28 with independent Python emulations and cross-checked:

- the MT19937 emulation reproduces the canonical reference sequence for
  `init_genrand(5489)` (Matsumoto & Nishimura, ACM TOMS 31:2, 1998 — the
  sequence published with the reference C code),
- the CPython rows were verified against live `random.Random` output and
  against an independent `init_by_array` emulation,
- the glibc and MSVC emulations implement the published algorithms
  (glibc `random.c` TYPE_3 additive feedback; MSVC LCG from the CRT sources)
  and reproduce the well-known `srand(1)` / `srand(0)` sequences quoted in
  numerous public references.

## MT19937 — `init_genrand(5489)`, first 5 outputs

Source: Matsumoto & Nishimura, "Mersenne Twister: A 623-Dimensionally
Equidistributed Uniform Pseudo-Random Number Generator", ACM TOMS 31:2 (1998);
also reproduced by the reference C implementation (`init_genrand(5489)` +
`genrand_int32()`).

```
3499211612  (0xd091bb5c)
 581869302  (0x22ae9ef6)
3890346734  (0xe7e1faee)
3586334585  (0xd5c31f79)
 545404204  (0x2082352c)
```

## CPython `random.seed(0)` — first 3 `getrandbits(32)`

Source: CPython `Modules/_randommodule.c` (int seed 0 → `init_by_array([0])`),
stable across CPython versions. Verified against live `random.Random(0)`.

```
3626764237  (0xd82c07cd)
1654615998  (0x629f6fbe)
3255389356  (0xc2094cac)
```

Semantics cross-checks (used by the CPython-compat reconstruction layer):

- `getrandbits(k)` for `k <= 32` equals `genrand_uint32() >> (32 - k)` —
  verified for `k = 1` and `k = 16` against live CPython;
- `random.seed(int)` for a non-negative int uses `init_by_array` over the
  little-endian 32-bit word decomposition of the seed (seed `0` → key `[0]`,
  *not* `init_genrand(0)`).

## glibc `rand` — `srand(1)`, first 3 outputs

Source: glibc `stdlib/random.c` (TYPE_3, 128-byte state, the default
`random()`): LCG warm-up `r[i] = (16807*lo - 2836*hi) mod 2^31-1`, additive
feedback `r[i] = r[i-3] + r[i-31] mod 2^32`, output `r[i] >> 1`, with 310
discarded outputs. Seed `0` is treated as `1`.

```
1804289383
 846930886
1681692777
```

## MSVC `rand` — `srand(0)`, first 4 outputs

Source: Microsoft CRT `rand.c`: 32-bit state updated by
`state = state * 214013 + 2531011 (mod 2^32)`, output `(state >> 16) & 0x7fff`.
The multiplier is odd, hence the step is invertible mod 2^32 (this is what the
MSVC state-recovery module exploits).

```
   38  (0x0026)
 7719  (0x1e27)
21238  (0x52f6)
 2437  (0x0985)
```
