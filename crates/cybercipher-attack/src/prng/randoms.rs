//! Common runtime PRNGs: Java `java.util.Random`, glibc `rand()` (TYPE_3),
//! and MSVC `rand()`. Generators plus seed/state recovery — the standard CTF
//! targets after LCG/MT19937.

use crate::math::modinv;
use cybercipher_core::error::{ErrorKind, OpResult, OperationError};
use num_bigint::BigUint;
use num_traits::One;

// ------------------------------------------------------------ Java ----

/// java.util.Random: 48-bit truncated LCG with multiplier 0x5DEECE66D.
pub const JAVA_MULTIPLIER: u64 = 0x5DEE_CE66D;
pub const JAVA_ADDEND: u64 = 0xB;
pub const JAVA_MASK: u64 = (1 << 48) - 1;

#[derive(Debug, Clone)]
pub struct JavaRandom {
    seed: u64,
}

impl JavaRandom {
    /// Reproduces `new Random(seed)`: the seed is scrambled with the
    /// multiplier before use.
    pub fn new(seed: i64) -> Self {
        JavaRandom {
            seed: ((seed as u64) ^ JAVA_MULTIPLIER) & JAVA_MASK,
        }
    }

    pub fn from_internal_seed(seed: u64) -> Self {
        JavaRandom {
            seed: seed & JAVA_MASK,
        }
    }

    fn next(&mut self, bits: u32) -> i32 {
        self.seed = (self
            .seed
            .wrapping_mul(JAVA_MULTIPLIER)
            .wrapping_add(JAVA_ADDEND))
            & JAVA_MASK;
        (self.seed >> (48 - bits)) as i32
    }

    /// `nextInt()` = next(32) with the negative range of a signed i32.
    pub fn next_i32(&mut self) -> i32 {
        self.next(32)
    }

    /// `nextInt(bound)` with the JDK rejection loop.
    pub fn next_bounded(&mut self, bound: u32) -> OpResult<u32> {
        if bound == 0 {
            return Err(OperationError::new(
                ErrorKind::InvalidParam,
                "bound must be positive",
            ));
        }
        if bound.is_power_of_two() {
            return Ok(((bound as i64 * self.next(31) as i64) >> 31) as u32);
        }
        loop {
            let bits = self.next(31);
            let val = bits % bound as i32;
            // JDK overflow guard: bits - val + (bound-1) computed with i32
            // wrapping; a negative result means the value is biased → retry.
            let check = bits.wrapping_sub(val).wrapping_add(bound as i32 - 1);
            if check >= 0 {
                return Ok(val as u32);
            }
        }
    }

    pub fn internal_seed(&self) -> u64 {
        self.seed
    }
}

/// Recover the internal 48-bit state from two consecutive `nextInt()` outputs.
/// The first output pins the high 32 bits of the state that produced it; the
/// unknown low 16 bits are brute-forced and verified against the second output.
/// The returned generator is positioned after both observed outputs.
pub fn java_recover_state(o1: i32, o2: i32) -> OpResult<JavaRandom> {
    let state_high = (o1 as u32 as u64) << 16; // top 32 bits of the first state
    for low in 0..(1u64 << 16) {
        let candidate_state = state_high | low;
        let mut rng = JavaRandom::from_internal_seed(candidate_state);
        if rng.next(32) == o2 {
            return Ok(rng);
        }
    }
    Err(
        OperationError::decode("no Java Random state matches the two outputs")
            .with_expected("two consecutive nextInt() values")
            .with_details("Recovery brute-forces the unknown 16 low bits of the first state."),
    )
}

// ----------------------------------------------------------- glibc ----

/// glibc TYPE_3 additive-feedback generator (default `rand()`): a 31-word
/// state, r[i] = r[i-28] (mod 2^32) via the ring (fptr = i-28... precisely
/// fptr/rptr separated by 3), output = (r[i-3] + r[i-31]) >> 1 with the
/// documented 310-step warmup.
#[derive(Debug, Clone)]
pub struct GlibcRand {
    state: [u32; 31],
    fptr: usize,
    rptr: usize,
}

impl GlibcRand {
    pub fn new(seed: u32) -> Self {
        let mut state = [0u32; 31];
        state[0] = if seed == 0 { 1 } else { seed };
        for i in 1..31 {
            let prev = state[i - 1];
            let hi = prev / 127773;
            let lo = prev % 127773;
            let mut word = 16807i64 * lo as i64 - 2836i64 * hi as i64;
            if word < 0 {
                word += 2147483647;
            }
            state[i] = word as u32;
        }
        let mut rng = GlibcRand {
            state,
            fptr: 3,
            rptr: 0,
        };
        // glibc srandom_r discards 10 * 31 = 310 outputs during init.
        for _ in 0..310 {
            rng.step();
        }
        rng
    }

    fn step(&mut self) -> u32 {
        let sum = self.state[self.fptr].wrapping_add(self.state[self.rptr]);
        self.state[self.fptr] = sum;
        let out = sum >> 1;
        self.fptr = (self.fptr + 1) % 31;
        self.rptr = (self.rptr + 1) % 31;
        out
    }

    pub fn next(&mut self) -> u32 {
        self.step()
    }

    pub fn state(&self) -> &[u32; 31] {
        &self.state
    }
}

// ------------------------------------------------------------- MSVC ----

/// MSVC rand(): s' = s * 214013 + 2531011 (mod 2^32), output = (s' >> 16) & 0x7fff.
#[derive(Debug, Clone)]
pub struct MsvcRand {
    state: u32,
}

impl MsvcRand {
    pub fn new(seed: u32) -> Self {
        MsvcRand { state: seed }
    }

    pub fn next(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(214013).wrapping_add(2531011);
        (self.state >> 16) & 0x7fff
    }

    pub fn state(&self) -> u32 {
        self.state
    }

    /// Invert one step: the multiplier is odd, hence invertible mod 2^32.
    pub fn prev_state(state: u32) -> u32 {
        let inv = modinv(&BigUint::from(214013u32), &(BigUint::one() << 32))
            .expect("214013 is odd hence invertible mod 2^32");
        let modulus = BigUint::one() << 32;
        let prev: BigUint =
            (BigUint::from(state) + &modulus - BigUint::from(2531011u32)) * inv % &modulus;
        prev.to_u32_digits().first().copied().unwrap_or(0)
    }

    /// Recover the MSVC state from three consecutive outputs: the first
    /// output pins bits 16..30 of s1; the low 16 bits and bit 31 are unknown
    /// (2^17 candidates). Two further outputs disambiguate (two outputs
    /// leave ~4 collisions on average). The returned generator is positioned
    /// before the first observed output.
    pub fn recover_from_outputs(o1: u32, o2: u32, o3: u32) -> OpResult<MsvcRand> {
        if [o1, o2, o3].iter().any(|&o| o > 0x7fff) {
            return Err(
                OperationError::decode("MSVC rand outputs must be 15-bit values")
                    .with_expected("0..=32767")
                    .with_actual(format!("{o1}, {o2}, {o3}")),
            );
        }
        for low16 in 0u32..(1 << 16) {
            for high_bit in 0u32..2 {
                let s1 = ((o1 as u32) << 16) | low16 | (high_bit << 31);
                let s0 = MsvcRand::prev_state(s1);
                let mut rng = MsvcRand { state: s0 };
                if rng.next() == o1 && rng.next() == o2 && rng.next() == o3 {
                    return Ok(MsvcRand { state: s0 });
                }
            }
        }
        Err(OperationError::decode(
            "no MSVC state matches the three outputs",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_random_matches_jdk() {
        // new Random(0).nextInt() — JDK-observable constants.
        let mut rng = JavaRandom::new(0);
        assert_eq!(rng.next_i32(), -1155484576);
        assert_eq!(rng.next_i32(), -723955400);
        // new Random(42).nextInt(100) == 30 (verified against the JDK algorithm).
        let mut rng = JavaRandom::new(42);
        assert_eq!(rng.next_bounded(100).unwrap(), 30);
    }

    #[test]
    fn java_state_recovery() {
        let mut rng = JavaRandom::new(123456789);
        let o1 = rng.next_i32();
        let o2 = rng.next_i32();
        let mut recovered = java_recover_state(o1, o2).unwrap();
        assert_eq!(recovered.next_i32(), rng.next_i32());
        assert_eq!(recovered.next_i32(), rng.next_i32());
    }

    #[test]
    fn glibc_rand_matches_reference() {
        // srand(1); rand() on glibc: 1804289383, 846930886, 1681692777.
        let mut rng = GlibcRand::new(1);
        assert_eq!(rng.next(), 1804289383);
        assert_eq!(rng.next(), 846930886);
        assert_eq!(rng.next(), 1681692777);
        // srand(0) behaves like srand(1).
        let mut rng = GlibcRand::new(0);
        assert_eq!(rng.next(), 1804289383);
    }

    #[test]
    fn msvc_rand_known_values() {
        // rand() sequence with srand(0) on MSVC: 38, 7719, 21238, 2437, ...
        let mut rng = MsvcRand::new(0);
        assert_eq!(rng.next(), 38);
        assert_eq!(rng.next(), 7719);
        assert_eq!(rng.next(), 21238);
        assert_eq!(rng.next(), 2437);
    }

    #[test]
    fn msvc_state_recovery() {
        let mut rng = MsvcRand::new(0xCAFE);
        let o1 = rng.next();
        let o2 = rng.next();
        let o3 = rng.next();
        // The recovered generator is positioned before the first observed output.
        let mut recovered = MsvcRand::recover_from_outputs(o1, o2, o3).unwrap();
        assert_eq!(recovered.next(), o1);
        assert_eq!(recovered.next(), o2);
        assert_eq!(recovered.next(), o3);
        assert_eq!(recovered.next(), rng.next());
        assert_eq!(recovered.next(), rng.next());
    }

    #[test]
    fn msvc_recovery_rejects_out_of_range() {
        assert!(MsvcRand::recover_from_outputs(0x8000, 1, 2).is_err());
    }
}
