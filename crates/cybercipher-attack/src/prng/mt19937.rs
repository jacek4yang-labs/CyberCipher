//! MT19937 Mersenne Twister: the full generator, untempering, state cloning
//! from 624 consecutive outputs, and CPython `random.getrandbits(k)`
//! compatibility.
//!
//! Everything follows the reference implementation of Matsumoto & Nishimura
//! (mt19937ar.c): `init_genrand` / `init_by_array` seeding, the standard
//! twist, and the standard tempering. CPython's `random.seed(int)` uses
//! `init_by_array` with the integer's 32-bit little-endian words as the key.
//!
//! State cloning assumption: the 624 observed outputs must be consecutive.
//! They are untempered into a full state block, which predicts the future
//! correctly when the window starts at a block boundary — true for the first
//! 624 outputs after seeding, the usual CTF capture. A window cut mid-block
//! cannot be distinguished from an aligned one from the outputs alone.

use cybercipher_core::error::OperationError;
use num_bigint::BigUint;
use num_traits::Zero;

/// State size of MT19937 (624 32-bit words).
pub const MT_N: usize = 624;
/// Twist offset.
pub const MT_M: usize = 397;
const MATRIX_A: u32 = 0x9908_b0df;
const UPPER_MASK: u32 = 0x8000_0000;
const LOWER_MASK: u32 = 0x7fff_ffff;

const INIT_GENRAND_MULT: u32 = 1812433253;
const INIT_BY_ARRAY_MULT1: u32 = 1664525;
const INIT_BY_ARRAY_MULT2: u32 = 1566083941;

/// Upper bound on words produced per generation call.
pub const MT_MAX_WORDS: usize = 1 << 20;
/// Upper bound on the bit width accepted by `getrandbits`.
pub const MT_MAX_GETRANDBITS: u32 = 1 << 20;

// ------------------------------------------------------ initialization ----

/// The reference `init_genrand` seeding: returns the untempered state array
/// for a 32-bit seed.
pub fn init_genrand(seed: u32) -> [u32; MT_N] {
    let mut state = [0u32; MT_N];
    state[0] = seed;
    for i in 1..MT_N {
        state[i] = INIT_GENRAND_MULT
            .wrapping_mul(state[i - 1] ^ (state[i - 1] >> 30))
            .wrapping_add(i as u32);
    }
    state
}

/// The reference `init_by_array` seeding (what CPython's `random.seed(int)`
/// uses). Returns the untempered state array for a non-empty key of 32-bit
/// words.
pub fn init_by_array(key: &[u32]) -> Result<[u32; MT_N], OperationError> {
    if key.is_empty() {
        return Err(OperationError::invalid_param(
            "key",
            "init_by_array requires a non-empty key (CPython uses the key [0] for seed 0)",
        )
        .with_expected("at least 1 word")
        .with_actual("0 words"));
    }
    let mut state = init_genrand(19650218);
    let mut i = 1usize;
    let mut j = 0usize;
    for _ in 0..MT_N.max(key.len()) {
        state[i] = (state[i]
            ^ ((state[i - 1] ^ (state[i - 1] >> 30)).wrapping_mul(INIT_BY_ARRAY_MULT1)))
        .wrapping_add(key[j])
        .wrapping_add(j as u32);
        i += 1;
        j += 1;
        if i >= MT_N {
            state[0] = state[MT_N - 1];
            i = 1;
        }
        if j >= key.len() {
            j = 0;
        }
    }
    for _ in 0..MT_N - 1 {
        state[i] = (state[i]
            ^ ((state[i - 1] ^ (state[i - 1] >> 30)).wrapping_mul(INIT_BY_ARRAY_MULT2)))
        .wrapping_sub(i as u32);
        i += 1;
        if i >= MT_N {
            state[0] = state[MT_N - 1];
            i = 1;
        }
    }
    state[0] = 0x8000_0000;
    Ok(state)
}

/// The `init_by_array` key CPython builds for `random.seed(int)`: the 32-bit
/// little-endian words of the (absolute) value, with the degenerate key `[0]`
/// for zero.
pub fn cpython_key(n: &BigUint) -> Vec<u32> {
    if n.is_zero() {
        return vec![0];
    }
    n.to_u32_digits()
}

// ------------------------------------------------- temper / untemper ----

/// The MT19937 tempering transform (state word -> output word).
pub fn temper(y: u32) -> u32 {
    let mut y = y;
    y ^= y >> 11;
    y ^= (y << 7) & 0x9d2c_5680;
    y ^= (y << 15) & 0xefc6_0000;
    y ^= y >> 18;
    y
}

/// Inverse of [`temper`]: recovers the state word behind an output word.
pub fn untemper(y: u32) -> u32 {
    // Undo the tempering steps in reverse order. Each is a shift-xor chain
    // with a constructive inverse (see `unxor_shift_right` / `_left`).
    let x = unxor_shift_right(y, 18);
    let x = unxor_shift_left(x, 15, 0xefc6_0000);
    let x = unxor_shift_left(x, 7, 0x9d2c_5680);
    unxor_shift_right(x, 11)
}

/// Inverse of `x -> x ^ (x >> shift)` for `shift >= 1`: each round fixes
/// `shift` more high bits.
fn unxor_shift_right(y: u32, shift: u32) -> u32 {
    debug_assert!((1..32).contains(&shift));
    let mut x = y;
    let mut i = 1u32;
    while i * shift < 32 {
        x = y ^ (x >> shift);
        i += 1;
    }
    x
}

/// Inverse of `x -> x ^ ((x << shift) & mask)` for `shift >= 1`: each round
/// fixes `shift` more low bits.
fn unxor_shift_left(y: u32, shift: u32, mask: u32) -> u32 {
    debug_assert!((1..32).contains(&shift));
    let mut x = y;
    let mut i = 1u32;
    while i * shift < 32 {
        x = y ^ ((x << shift) & mask);
        i += 1;
    }
    x
}

// --------------------------------------------------------------- twist ----

/// The MT19937 twist, with the exact in-place semantics of the reference C
/// (indices below the current position read already-updated values).
pub fn twist(state: &[u32; MT_N]) -> [u32; MT_N] {
    let mut s = *state;
    for i in 0..MT_N {
        let y = (s[i] & UPPER_MASK) | (s[(i + 1) % MT_N] & LOWER_MASK);
        let mut next = s[(i + MT_M) % MT_N] ^ (y >> 1);
        if y & 1 == 1 {
            next ^= MATRIX_A;
        }
        s[i] = next;
    }
    s
}

// ------------------------------------------------------------ generator ----

/// A full MT19937 generator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mt19937 {
    state: [u32; MT_N],
    /// Words served from the current block; `MT_N` means the block is
    /// exhausted and the next draw triggers a twist.
    index: usize,
}

impl Mt19937 {
    /// Generator seeded like the reference `init_genrand`.
    pub fn from_seed(seed: u32) -> Self {
        Self {
            state: init_genrand(seed),
            index: MT_N,
        }
    }

    /// Generator seeded like CPython's `random.seed(int)`:
    /// `init_by_array` over the integer's 32-bit little-endian words.
    pub fn from_cpython_seed(n: &BigUint) -> Result<Self, OperationError> {
        let state = init_by_array(&cpython_key(n))?;
        Ok(Self { state, index: MT_N })
    }

    /// Generator from an arbitrary key via `init_by_array`.
    pub fn from_key(key: &[u32]) -> Result<Self, OperationError> {
        let state = init_by_array(key)?;
        Ok(Self { state, index: MT_N })
    }

    /// Generator from an explicit 624-word state; the block is treated as
    /// exhausted, so the first draw twists it (the standard behavior after a
    /// full block has been served).
    pub fn from_state(state: [u32; MT_N]) -> Self {
        Self { state, index: MT_N }
    }

    /// Clone a generator from at least [`MT_N`] consecutive 32-bit outputs:
    /// the first 624 are untempered into the state block. Fewer than 624
    /// outputs is a typed [`OperationError`] (`LengthMismatch`).
    ///
    /// Extra outputs beyond 624 are ignored (the caller may pass a longer
    /// capture; only the leading full block is consumed).
    pub fn from_outputs(outputs: &[u32]) -> Result<Self, OperationError> {
        if outputs.len() < MT_N {
            return Err(OperationError::length(
                format!("{MT_N} consecutive 32-bit outputs"),
                format!("{} outputs", outputs.len()),
                "need 624 consecutive outputs to clone the MT19937 state",
            )
            .with_parameter("outputs"));
        }
        let mut state = [0u32; MT_N];
        for (slot, &out) in state.iter_mut().zip(outputs.iter().take(MT_N)) {
            *slot = untemper(out);
        }
        Ok(Self { state, index: MT_N })
    }

    /// Next 32-bit output (twisting first when the block is exhausted).
    pub fn next_u32(&mut self) -> u32 {
        if self.index >= MT_N {
            self.state = twist(&self.state);
            self.index = 0;
        }
        let y = temper(self.state[self.index]);
        self.index += 1;
        y
    }

    /// The next `count` 32-bit outputs (bounded by [`MT_MAX_WORDS`]).
    pub fn next_words(&mut self, count: usize) -> Result<Vec<u32>, OperationError> {
        if count > MT_MAX_WORDS {
            return Err(OperationError::invalid_param(
                "count",
                format!("word count exceeds the bound of {MT_MAX_WORDS}"),
            )
            .with_expected(MT_MAX_WORDS.to_string())
            .with_actual(count.to_string()));
        }
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(self.next_u32());
        }
        Ok(out)
    }

    /// CPython `random.getrandbits(k)` semantics (see [`getrandbits_from`]).
    pub fn getrandbits(&mut self, bits: u32) -> Result<BigUint, OperationError> {
        if bits > MT_MAX_GETRANDBITS {
            return Err(getrandbits_bound_error(bits));
        }
        if bits == 0 {
            return Ok(BigUint::zero()); // CPython returns 0 without drawing
        }
        let words = words_for_bits(bits);
        let mut drawn = Vec::with_capacity(words);
        for _ in 0..words {
            drawn.push(self.next_u32());
        }
        getrandbits_from(&drawn, bits)
    }

    /// The untempered state block.
    pub fn state(&self) -> &[u32; MT_N] {
        &self.state
    }

    /// Words already served from the current block (`0..=MT_N`).
    pub fn index(&self) -> usize {
        self.index
    }
}

fn getrandbits_bound_error(bits: u32) -> OperationError {
    OperationError::invalid_param(
        "bits",
        format!("bit count exceeds the supported bound of {MT_MAX_GETRANDBITS}"),
    )
    .with_expected(MT_MAX_GETRANDBITS.to_string())
    .with_actual(bits.to_string())
}

fn words_for_bits(bits: u32) -> usize {
    // bits <= MT_MAX_GETRANDBITS, so this is at most 2^15 + 1 words.
    (bits as u64).div_ceil(32) as usize
}

// ---------------------------------------------------- getrandbits ----

/// Reconstruct the value CPython's `random.getrandbits(bits)` returns from
/// `words` consecutive raw 32-bit outputs (the leading words of the stream).
///
/// CPython semantics: `ceil(bits / 32)` words are consumed; the first
/// generated word becomes the least significant word; the final (most
/// significant) word contributes only its top `bits - 32 * floor(bits / 32)`
/// bits, i.e. it is shifted right by `32 - remaining`. `bits = 0` returns 0
/// and consumes nothing, matching CPython.
pub fn getrandbits_from(outputs: &[u32], bits: u32) -> Result<BigUint, OperationError> {
    if bits > MT_MAX_GETRANDBITS {
        return Err(getrandbits_bound_error(bits));
    }
    if bits == 0 {
        return Ok(BigUint::zero());
    }
    let words = words_for_bits(bits);
    if outputs.len() < words {
        return Err(OperationError::length(
            format!("{words} consecutive 32-bit outputs"),
            format!("{} outputs", outputs.len()),
            format!("need {words} words to reconstruct getrandbits({bits})"),
        )
        .with_parameter("outputs"));
    }
    let mut value = BigUint::zero();
    for (i, &word) in outputs.iter().take(words).enumerate() {
        let remaining = bits - (i as u32) * 32; // 1..=32 for every consumed word
        let contribution = if remaining < 32 {
            word >> (32 - remaining)
        } else {
            word
        };
        value |= BigUint::from(contribution) << (32 * i);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn temper_is_invertible_on_edge_values() {
        for y in [0u32, 1, 0x7fff_ffff, 0x8000_0000, 0x9908_b0df, u32::MAX] {
            assert_eq!(untemper(temper(y)), y);
        }
    }

    #[test]
    fn reference_seed_5489_first_output() {
        let mut mt = Mt19937::from_seed(5489);
        assert_eq!(mt.next_u32(), 3_499_211_612);
    }

    #[test]
    fn getrandbits_from_basic_shapes() {
        // One full word.
        assert_eq!(
            getrandbits_from(&[0xdead_beef], 32).unwrap(),
            BigUint::from(0xdead_beefu32)
        );
        // Top bit only.
        assert_eq!(
            getrandbits_from(&[0xdead_beef], 1).unwrap(),
            BigUint::from(1u32)
        );
        // Zero bits consume nothing.
        assert_eq!(getrandbits_from(&[], 0).unwrap(), BigUint::zero());
    }
}
