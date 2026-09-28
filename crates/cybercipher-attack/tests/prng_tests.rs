//! PRNG recovery attack tests: LCG (forward/backward, parameter recovery with
//! known and unknown modulus, seed recovery) and MT19937 (reference vectors,
//! CPython `random.seed`/`getrandbits` compatibility, state cloning,
//! untempering) plus the serde result types.
//!
//! Reference vectors were cross-verified against three independent sources:
//! a direct port of the Matsumoto & Nishimura reference C, CPython 3.14
//! `random.seed(0)` / `random.getrandbits`, and numpy `RandomState(5489)`.

use cybercipher_attack::math::{big, lcg_u64};
use cybercipher_attack::prng::{
    getrandbits_from, init_by_array, recover_params_known_m, recover_params_unknown, temper, twist,
    untemper, LcgParams, LcgPredictionResult, Mt19937, Mt19937StateRecovery, MtRandBitsResult,
    PredictionDirection, MT_N,
};
use cybercipher_core::error::ErrorKind;
use num_bigint::BigUint;

// ------------------------------------------------------------ helpers ----

fn u64_big(n: u64) -> BigUint {
    BigUint::from(n)
}

/// Build a stream of `n` consecutive outputs (states) from a start state.
fn stream(params: &LcgParams, start: u64, n: usize) -> Vec<BigUint> {
    let mut s = u64_big(start);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(s.clone());
        s = params.next(&s);
    }
    out
}

fn big_from_dec(s: &str) -> BigUint {
    s.parse::<BigUint>().expect("valid decimal literal")
}

fn err_kind(e: &cybercipher_core::error::OperationError) -> ErrorKind {
    e.kind
}

// ---------------------------------------------------------------- LCG ----

#[test]
fn lcg_next_follows_the_recurrence() {
    let params = LcgParams::new(big(1103515245), big(12345), u64_big(1) << 31).unwrap();
    // First states of the glibc-style LCG from seed 1, hand-checked with the
    // recurrence: s1 = (1103515245 + 12345) mod 2^31 = 1103527590.
    assert_eq!(params.next(&u64_big(1)), u64_big(1103527590));
    let s = stream(&params, 1, 3);
    assert_eq!(s[1], u64_big(1103527590));
}

#[test]
fn lcg_prev_inverts_next() {
    let params = LcgParams::new(big(1103515245), big(12345), u64_big(1) << 31).unwrap();
    for s in [0u64, 1, 12345, 0x7fff_ffff] {
        let state = u64_big(s);
        assert_eq!(
            params.prev(&params.next(&state)).unwrap(),
            state % params.m()
        );
    }
    // Random walk: forward 40, then back 40, must return to the start.
    let start = u64_big(987_654_321);
    let forward = params.predict(&start, 40).unwrap();
    let back = params.step_back(forward.last().unwrap(), 40).unwrap();
    assert_eq!(back.last().unwrap(), &start);
}

#[test]
fn lcg_prev_fails_when_a_not_invertible() {
    let params = LcgParams::new(big(2), big(1), u64_big(1) << 32).unwrap();
    let e = params.prev(&big(7)).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidInput);
    assert!(
        e.message.contains("not invertible"),
        "message: {}",
        e.message
    );
}

#[test]
fn lcg_params_validates_and_reduces() {
    assert!(LcgParams::new(big(1), big(0), big(0)).is_err());
    assert!(LcgParams::new(big(1), big(0), big(1)).is_err());
    let params = LcgParams::new(u64_big(1) << 40, u64_big(1) << 33, u64_big(1) << 32).unwrap();
    assert_eq!(*params.a(), big(0)); // 2^40 mod 2^32
    assert_eq!(*params.b(), big(0)); // 2^33 mod 2^32
}

#[test]
fn lcg_known_m_recovers_parameters_and_predicts() {
    let params = LcgParams::new(big(1103515245), big(12345), u64_big(1) << 31).unwrap();
    let outputs = stream(&params, 1, 12);
    let recovery = recover_params_known_m(&outputs, &(u64_big(1) << 31)).unwrap();
    assert_eq!(recovery.params, params);
    assert_eq!(recovery.outputs_used, 12);

    // Prediction continues the stream.
    let predicted = recovery.params.predict(outputs.last().unwrap(), 7).unwrap();
    let mut s = outputs.last().unwrap().clone();
    for p in &predicted {
        s = params.next(&s);
        assert_eq!(&s, p);
    }

    // Backward prediction returns to the first observed output.
    let back = recovery
        .params
        .step_back(outputs.last().unwrap(), 11)
        .unwrap();
    assert_eq!(back.last().unwrap(), &outputs[0]);
}

#[test]
fn lcg_known_m_needs_three_outputs() {
    let params = LcgParams::new(big(3), big(5), big(97)).unwrap();
    let outputs = stream(&params, 7, 2);
    let e = recover_params_known_m(&outputs, &big(97)).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidInput);
    assert!(e.expected.as_deref().unwrap_or("").contains("3"));
}

#[test]
fn lcg_known_m_constant_outputs_are_underdetermined() {
    let outputs = vec![big(42); 5];
    let e = recover_params_known_m(&outputs, &big(97)).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidInput);
    assert!(e.message.contains("constant"), "message: {}", e.message);
}

#[test]
fn lcg_known_m_non_coprime_differences_fail_gracefully() {
    // a odd, b even, start even => every difference t_i = a^i * 2 shares a
    // factor of 2 with m = 2^32, so `a` is not identifiable from differences.
    let m: BigUint = u64_big(1) << 32;
    let params = LcgParams::new(big(1664525), big(2), m.clone()).unwrap();
    let outputs = stream(&params, 0, 6);
    let e = recover_params_known_m(&outputs, &m).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidInput);
    assert!(
        e.message.contains("common factor"),
        "message: {}",
        e.message
    );
}

#[test]
fn lcg_unknown_m_recovers_all_parameters() {
    // Mersenne prime modulus: the gcd of the difference products is exact.
    let m = (u64_big(1) << 61) - u64_big(1);
    let params = LcgParams::new(big(48271), big(987654321), m).unwrap();
    let outputs = stream(&params, 123456789, 10);
    let recovery = recover_params_unknown(&outputs).unwrap();
    assert_eq!(recovery.params, params, "exact recovery expected");
    assert_eq!(recovery.outputs_used, 10);

    let predicted = recovery.params.predict(outputs.last().unwrap(), 5).unwrap();
    let mut s = outputs.last().unwrap().clone();
    for p in &predicted {
        s = params.next(&s);
        assert_eq!(&s, p);
    }
}

#[test]
fn lcg_unknown_m_recovers_large_parameters() {
    let mut st = 0xC0FFEEu64;
    let m = (u64_big(1) << 127) - u64_big(1); // 2^127 - 1 is prime
    let a = cybercipher_attack::math::weak_random_odd(127, &mut st) % &m;
    let b = cybercipher_attack::math::weak_random_odd(127, &mut st) % &m;
    let params = LcgParams::new(a, b, m).unwrap();
    let outputs = stream(&params, 42, 10);
    let recovery = recover_params_unknown(&outputs).unwrap();
    assert_eq!(
        recovery.params, params,
        "exact recovery expected for a prime modulus"
    );
}

#[test]
fn lcg_unknown_m_needs_six_outputs() {
    let params = LcgParams::new(big(48271), big(1), big(97)).unwrap();
    let outputs = stream(&params, 3, 5);
    let e = recover_params_unknown(&outputs).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidInput);
    assert!(e.expected.as_deref().unwrap_or("").contains("6"));
}

#[test]
fn lcg_unknown_m_linear_stream_is_underdetermined() {
    // a = 1: differences are constant, all difference products vanish, and
    // the modulus is not identifiable (any m works).
    let params = LcgParams::new(big(1), big(7), u64_big(1) << 32).unwrap();
    let outputs = stream(&params, 0, 6);
    let e = recover_params_unknown(&outputs).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidInput);
    assert!(
        e.message.contains("could not determine the modulus"),
        "message: {}",
        e.message
    );
}

#[test]
fn lcg_unknown_m_non_coprime_differences_fail_gracefully() {
    // Even multiplier and even start: all differences and the recovered
    // modulus stay even, so no difference is invertible modulo m.
    let m = u64_big(1) << 32;
    let params = LcgParams::new(big(3329050), big(1), m).unwrap();
    let outputs = stream(&params, 1, 8);
    let e = recover_params_unknown(&outputs).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidInput);
    assert!(
        e.message.contains("common factor"),
        "message: {}",
        e.message
    );
}

#[test]
fn lcg_unknown_m_rejects_out_of_range_outputs() {
    // Almost-constant stream: the products collapse to modulus 1, so the
    // observed value 1 is out of range and recovery fails with a diagnostic
    // instead of panicking.
    let outputs: Vec<BigUint> = [0u64, 0, 0, 0, 1, 0].iter().map(|&v| big(v)).collect();
    let e = recover_params_unknown(&outputs).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidInput);
    assert!(
        e.message.contains("recovered modulus"),
        "message: {}",
        e.message
    );
}

#[test]
fn lcg_seed_recovery_walks_back_to_the_origin() {
    let params = LcgParams::new(
        big(6364136223846793005),
        big(1442695040888963407),
        u64_big(1) << 63,
    )
    .unwrap();
    let outputs = stream(&params, 777, 11);
    // The 8th observed output (index 7) steps back exactly to the seed.
    let seed = params.recover_seed(&outputs[7], 7).unwrap();
    assert_eq!(seed, u64_big(777));
    // Index 0: the output itself is the seed.
    assert_eq!(params.recover_seed(&outputs[0], 0).unwrap(), u64_big(777));
    // From the last output, 10 steps back.
    let seed = params.recover_seed(outputs.last().unwrap(), 10).unwrap();
    assert_eq!(seed, u64_big(777));
}

#[test]
fn lcg_seed_recovery_respects_bounds() {
    let params = LcgParams::new(big(3), big(5), big(97)).unwrap();
    let e = params
        .recover_seed(&big(1), cybercipher_attack::prng::MAX_STEPS_BACK + 1)
        .unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidParam);
}

#[test]
fn lcg_prediction_respects_bounds() {
    let params = LcgParams::new(big(3), big(5), big(97)).unwrap();
    let e = params
        .predict(&big(1), cybercipher_attack::prng::MAX_PREDICT + 1)
        .unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidParam);
    let e = params
        .step_back(&big(1), cybercipher_attack::prng::MAX_PREDICT + 1)
        .unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidParam);
}

#[test]
fn lcg_prediction_result_serializes_snake_case() {
    let params = LcgParams::new(big(3), big(5), big(97)).unwrap();
    let outs = params.predict(&big(2), 3).unwrap();
    let forward = LcgPredictionResult::forward(&params, &big(2), &outs);
    assert_eq!(forward.direction, PredictionDirection::Forward);
    let json = serde_json::to_string(&forward).unwrap();
    assert!(json.contains("\"direction\":\"forward\""), "json: {json}");
    assert!(json.contains("\"multiplier\":\"3\""), "json: {json}");
    let back: LcgPredictionResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, forward);

    let rev = params.step_back(&big(60), 2).unwrap();
    let backward = LcgPredictionResult::backward(&params, &big(60), &rev);
    let json = serde_json::to_string(&backward).unwrap();
    assert!(json.contains("\"direction\":\"backward\""), "json: {json}");
}

#[test]
fn lcg_recovery_serializes_as_decimal_strings() {
    let params = LcgParams::new(big(1103515245), big(12345), u64_big(1) << 31).unwrap();
    let outputs = stream(&params, 1, 5);
    let recovery = recover_params_known_m(&outputs, &(u64_big(1) << 31)).unwrap();
    let json = serde_json::to_string(&recovery).unwrap();
    assert!(
        json.contains("\"multiplier\":\"1103515245\""),
        "json: {json}"
    );
    assert!(json.contains("\"increment\":\"12345\""), "json: {json}");
    assert!(json.contains("\"modulus\":\"2147483648\""), "json: {json}");
    let back: cybercipher_attack::prng::LcgRecovery = serde_json::from_str(&json).unwrap();
    assert_eq!(back, recovery);
}

// ------------------------------------------------------------- MT19937 ----

#[test]
fn mt19937_reference_seed_5489_matches_reference_c() {
    // init_genrand(5489): cross-verified against the reference C semantics,
    // numpy RandomState(5489) and an independent Python port.
    let mut mt = Mt19937::from_seed(5489);
    let words = mt.next_words(6).unwrap();
    assert_eq!(
        words,
        vec![3499211612, 581869302, 3890346734, 3586334585, 545404204, 4161255391]
    );
}

#[test]
fn mt19937_cpython_seed0_reproduces_getrandbits32_stream() {
    // random.seed(0); [random.getrandbits(32) for _ in range(6)]
    let mut mt = Mt19937::from_cpython_seed(&BigUint::ZERO).unwrap();
    let words = mt.next_words(6).unwrap();
    assert_eq!(
        words,
        vec![3626764237, 1654615998, 3255389356, 3823568514, 1806341205, 173879092]
    );
}

#[test]
fn mt19937_init_by_array_matches_reference_vector() {
    // Reference C test key {0x123, 0x234, 0x345, 0x456}: first output is the
    // canonical 1067595299 (also produced by CPython random.seed of the
    // integer whose LE 32-bit words are the key).
    let mut mt = Mt19937::from_key(&[0x123, 0x234, 0x345, 0x456]).unwrap();
    let words = mt.next_words(4).unwrap();
    assert_eq!(words, vec![1067595299, 955945823, 477289528, 4107218783]);
}

#[test]
fn mt19937_init_by_array_rejects_empty_key() {
    let e = init_by_array(&[]).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidParam);
    assert!(e.message.contains("non-empty"), "message: {}", e.message);
}

#[test]
fn mt19937_cpython_getrandbits_shapes() {
    // Each shape uses a fresh generator (consumption differs per bit width),
    // mirroring `random.seed(0); random.getrandbits(k)` in CPython 3.14.
    let draw = |bits: u32| -> BigUint {
        let mut mt = Mt19937::from_cpython_seed(&BigUint::ZERO).unwrap();
        mt.getrandbits(bits).unwrap()
    };
    assert_eq!(draw(32), u64_big(3626764237));
    assert_eq!(draw(64), u64_big(7106521602475165645));
    assert_eq!(draw(63), u64_big(3553260803050964941));
    assert_eq!(draw(33), u64_big(3626764237)); // w1's top bit is 0 here
    assert_eq!(draw(1), u64_big(1));
    assert_eq!(draw(0), BigUint::ZERO);
    assert_eq!(draw(96), big_from_dec("60051334317516675368734164941"));
}

#[test]
fn mt19937_getrandbits_from_assembles_words_little_endian() {
    // First word = least significant; the final word contributes only its top
    // `remaining` bits.
    let (w0, w1, w2) = (0xd82c07cd_u32, 0x629f6fbe_u32, 0xc2094cac_u32);
    let full = u64_big(w0 as u64) | (u64_big(w1 as u64) << 32) | (BigUint::from(w2) << 64);
    assert_eq!(getrandbits_from(&[w0, w1, w2], 96).unwrap(), full);
    let b63 = u64_big(w0 as u64) | (u64_big((w1 >> 1) as u64) << 32);
    assert_eq!(getrandbits_from(&[w0, w1], 63).unwrap(), b63);
    assert_eq!(getrandbits_from(&[w0], 32).unwrap(), u64_big(w0 as u64));
    assert_eq!(
        getrandbits_from(&[w0], 12).unwrap(),
        u64_big((w0 >> 20) as u64)
    );
}

#[test]
fn mt19937_getrandbits_from_needs_enough_words() {
    let e = getrandbits_from(&[1, 2, 3], 128).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::LengthMismatch);
    assert!(e.message.contains("need 4 words"), "message: {}", e.message);
    // Zero bits consume nothing, even from an empty slice.
    assert_eq!(getrandbits_from(&[], 0).unwrap(), BigUint::ZERO);
}

#[test]
fn mt19937_untemper_inverts_temper() {
    for y in [
        0u32,
        1,
        0x7fff_ffff,
        0x8000_0000,
        0x9908_b0df,
        0x9d2c_5680,
        u32::MAX,
    ] {
        assert_eq!(untemper(temper(y)), y, "edge value {y:#010x}");
    }
    let mut st = 0xBEEFu64;
    for _ in 0..4096 {
        let y = (lcg_u64(&mut st) & 0xFFFF_FFFF) as u32;
        assert_eq!(untemper(temper(y)), y);
    }
}

#[test]
fn mt19937_clone_from_624_outputs_predicts_the_future() {
    let mut original = Mt19937::from_seed(2026);
    let captured = original.next_words(700).unwrap();

    let mut clone = Mt19937::from_outputs(&captured[..MT_N]).unwrap();
    let predicted = clone.next_words(76).unwrap();
    assert_eq!(predicted, captured[MT_N..]);

    // Mixed word/bit consumption stays in lockstep after cloning.
    let mut original = Mt19937::from_seed(7);
    let words = original.next_words(MT_N).unwrap();
    let value = original.getrandbits(64).unwrap();
    let mut clone = Mt19937::from_outputs(&words).unwrap();
    assert_eq!(clone.getrandbits(64).unwrap(), value);
}

#[test]
fn mt19937_from_outputs_needs_624_outputs() {
    let mut mt = Mt19937::from_seed(1);
    let words = mt.next_words(623).unwrap();
    let e = Mt19937::from_outputs(&words).unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::LengthMismatch);
    assert!(e.message.contains("624"), "message: {}", e.message);
    assert_eq!(
        e.expected.as_deref(),
        Some("624 consecutive 32-bit outputs")
    );
    assert_eq!(e.actual.as_deref(), Some("623 outputs"));
}

#[test]
fn mt19937_first_draw_after_explicit_state_twists() {
    let state: [u32; MT_N] = std::array::from_fn(|i| (i as u32) ^ 0x1357_9bdf);
    let mut mt = Mt19937::from_state(state);
    let expected = temper(twist(&state)[0]);
    assert_eq!(mt.next_u32(), expected);
    assert_eq!(mt.index(), 1);
}

#[test]
fn mt19937_generation_respects_bounds() {
    let mut mt = Mt19937::from_seed(1);
    let e = mt
        .next_words(cybercipher_attack::prng::MT_MAX_WORDS + 1)
        .unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidParam);
    let e = mt
        .getrandbits(cybercipher_attack::prng::MT_MAX_GETRANDBITS + 1)
        .unwrap_err();
    assert_eq!(err_kind(&e), ErrorKind::InvalidParam);
}

#[test]
fn mt19937_state_recovery_dto_serializes() {
    let mut mt = Mt19937::from_seed(99);
    let words = mt.next_words(MT_N).unwrap();
    let recovery = Mt19937StateRecovery::from_outputs(&words).unwrap();
    assert_eq!(recovery.state.len(), MT_N);
    assert_eq!(recovery.index, 624);
    assert_eq!(recovery.outputs_used, MT_N);
    assert_eq!(recovery.state[0], format!("{:08x}", untemper(words[0])));
    let json = serde_json::to_string(&recovery).unwrap();
    let back: Mt19937StateRecovery = serde_json::from_str(&json).unwrap();
    assert_eq!(back, recovery);
}

#[test]
fn mt19937_randbits_dto_serializes() {
    let mut mt = Mt19937::from_cpython_seed(&BigUint::ZERO).unwrap();
    let value = mt.getrandbits(64).unwrap();
    let dto = MtRandBitsResult::new(64, value);
    assert_eq!(dto.words_consumed, 2);
    assert_eq!(dto.value, "7106521602475165645");
    let json = serde_json::to_string(&dto).unwrap();
    assert!(
        json.contains("\"value\":\"7106521602475165645\""),
        "json: {json}"
    );
    let back: MtRandBitsResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, dto);
}

#[test]
fn mt19937_twist_is_deterministic_and_bounded() {
    let state: [u32; MT_N] = std::array::from_fn(|i| (i as u32).wrapping_mul(0x9e37_79b1));
    let once = twist(&state);
    let twice = twist(&once);
    assert_ne!(once, state);
    assert_ne!(twice, once);
    // Twisting is a bijection on 624-word blocks: re-twisting never reverts.
    assert_ne!(twice, state);
}
