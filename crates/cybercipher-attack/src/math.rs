//! Number-theory primitives for cryptanalysis. Implemented on `num-bigint`;
//! only what CTF attacks actually need, with explicit resource bounds.

use num_bigint::{BigInt, BigUint};
use num_traits::{One, Signed, Zero};
use std::cmp::Ordering;

pub fn big(n: u64) -> BigUint {
    BigUint::from(n)
}

/// Euclidean GCD.
pub fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let (mut a, mut b) = (a.clone(), b.clone());
    while !b.is_zero() {
        let r = &a % &b;
        a = b;
        b = r;
    }
    a
}

/// Extended GCD over signed integers: returns (g, x, y) with a*x + b*y = g.
pub fn extended_gcd(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut old_r, mut r) = (a.clone(), b.clone());
    let (mut old_s, mut s) = (BigInt::one(), BigInt::zero());
    let (mut old_t, mut t) = (BigInt::zero(), BigInt::one());
    while !r.is_zero() {
        let q = &old_r / &r;
        let tmp = &old_r - &q * &r;
        old_r = r.clone();
        r = tmp;
        let tmp = &old_s - &q * &s;
        old_s = s.clone();
        s = tmp;
        let tmp = &old_t - &q * &t;
        old_t = t.clone();
        t = tmp;
    }
    (old_r, old_s, old_t)
}

/// Modular inverse of a modulo m. Returns `None` when a is not invertible.
pub fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    if m.is_zero() {
        return None;
    }
    if m.is_one() {
        return Some(BigUint::zero());
    }
    let a_signed = BigInt::from(a.clone());
    let m_signed = BigInt::from(m.clone());
    let (g, x, _) = extended_gcd(&a_signed, &m_signed);
    if g != BigInt::one() {
        return None;
    }
    let m_big = m_signed.clone();
    let inv = x.mod_floor_impl(&m_big);
    Some(inv.to_biguint().unwrap())
}

trait ModFloor {
    fn mod_floor_impl(&self, m: &BigInt) -> BigInt;
}

impl ModFloor for BigInt {
    fn mod_floor_impl(&self, m: &BigInt) -> BigInt {
        let r = self % m;
        if r.is_negative() {
            r + m.abs()
        } else {
            r
        }
    }
}

/// Integer k-th root (floor) via Newton's method. Root of 0 is 0.
pub fn iroot(n: &BigUint, k: u32) -> BigUint {
    if k == 0 {
        panic!("iroot: k must be >= 1");
    }
    if k == 1 || n.is_zero() || n.is_one() {
        return n.clone();
    }
    let kn = big(k as u64);
    // Initial guess: 2^(ceil(bits/k)).
    let bits = n.bits();
    let mut x: BigUint = BigUint::one() << (bits / (k as u64) + 1);
    loop {
        // x_next = ((k-1)*x + n / x^(k-1)) / k
        let xk1 = pow_mod_free(&x, k - 1);
        if xk1.is_zero() {
            x = BigUint::one();
            continue;
        }
        let next = (((&kn - 1u32) * &x) + (n / &xk1)) / &kn;
        if next >= x {
            break;
        }
        x = next;
    }
    // Newton may overshoot by construction of the initial guess; verify down.
    while pow_mod_free(&x, k) > *n {
        x -= 1u32;
    }
    x
}

fn pow_mod_free(x: &BigUint, k: u32) -> BigUint {
    let mut result = BigUint::one();
    let mut base = x.clone();
    let mut e = k;
    while e > 0 {
        if e & 1 == 1 {
            result *= &base;
        }
        base = &base * &base;
        e >>= 1;
    }
    result
}

/// If n is a perfect square, returns its root.
pub fn isqrt_exact(n: &BigUint) -> Option<BigUint> {
    let r = iroot(n, 2);
    if &r * &r == *n {
        Some(r)
        } else {
        None
    }
}

/// CRT: combine remainders with pairwise-coprime moduli.
/// Returns (x, product_of_moduli) or None on inconsistent input.
pub fn crt(remainders: &[BigUint], moduli: &[BigUint]) -> Option<(BigUint, BigUint)> {
    if remainders.len() != moduli.len() || moduli.is_empty() {
        return None;
    }
    let mut x = BigUint::zero();
    let mut product = BigUint::one();
    for (r, m) in remainders.iter().zip(moduli.iter()) {
        if m.is_zero() {
            return None;
        }
        let mi = modinv(&(&product % m), m)?;
        // Solve x' = x + t*product ≡ r (mod m): t = (r - x) * product^-1 (mod m).
        let rm = r % m;
        let xm = &x % m;
        let diff = if rm >= xm { &rm - &xm } else { &rm + m - &xm };
        let t = (diff * mi) % m;
        x += t * &product;
        product *= m;
    }
    Some((x % &product, product))
}

/// Small primes for trial division (first 2048 primes).
pub fn small_primes() -> &'static [u64] {
    &SMALL_PRIMES
}

const SMALL_PRIMES: &[u64] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039,
    1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
    1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279,
    1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409,
    1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
    1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613,
    1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741,
    1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873,
    1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999,
    2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113,
    2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251,
    2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371,
    2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477,
    2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647,
    2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731,
    2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857,
    2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001,
    3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119, 3121, 3137, 3163,
    3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229, 3251, 3253, 3257, 3259, 3271, 3299,
    3301, 3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407,
    3413, 3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539,
    3541, 3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637, 3643, 3659,
    3671, 3673, 3677, 3691, 3697, 3701, 3709, 3719, 3727, 3733, 3739, 3761, 3767, 3769, 3779, 3793,
    3797, 3803, 3821, 3823, 3833, 3847, 3851, 3853, 3863, 3877, 3881, 3889, 3907, 3911, 3917, 3919,
    3923, 3929, 3931, 3943, 3947, 3967, 3989, 4001, 4003, 4007, 4013, 4019, 4021, 4027, 4049, 4051,
    4057, 4073, 4079, 4091, 4093, 4099, 4111, 4127, 4129, 4133, 4139, 4153, 4157, 4159, 4177, 4201,
    4211, 4217, 4219, 4229, 4231, 4241, 4243, 4253, 4259, 4261, 4271, 4273, 4283, 4289, 4297, 4327,
    4337, 4339, 4349, 4357, 4363, 4373, 4391, 4397, 4409, 4421, 4423, 4441, 4447, 4451, 4457, 4463,
    4481, 4483, 4493, 4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583, 4591, 4597, 4603,
    4621, 4637, 4639, 4643, 4649, 4651, 4657, 4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733,
    4751, 4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831, 4861, 4871, 4877, 4889, 4903,
    4909, 4919, 4931, 4933, 4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003, 5009, 5011,
    5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087, 5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167,
    5171, 5179, 5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279, 5281, 5297, 5303, 5309,
    5323, 5333, 5347, 5351, 5381, 5387, 5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443,
    5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521, 5527, 5531, 5557, 5563, 5569, 5573,
    5581, 5591, 5623, 5639, 5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693, 5701, 5711,
    5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791, 5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849,
    5851, 5857, 5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939, 5953, 5981, 5987, 6007,
    6011, 6029, 6037, 6043, 6047, 6053, 6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,
    6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221, 6229, 6247, 6257, 6263, 6269, 6271,
    6277, 6287, 6299, 6301, 6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367, 6373, 6379,
    6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473, 6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563,
    6569, 6571, 6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673, 6679, 6689, 6691, 6701,
    6703, 6709, 6719, 6733, 6737, 6761, 6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833,
    6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917, 6947, 6949, 6959, 6961, 6967, 6971,
    6977, 6983, 6991, 6997, 7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103, 7109, 7121,
    7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207, 7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253,
    7283, 7297, 7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411, 7417, 7433, 7451, 7457,
    7459, 7477, 7481, 7487, 7489, 7499, 7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561,
    7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643, 7649, 7669, 7673, 7681, 7687, 7691,
    7699, 7703, 7717, 7723, 7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829, 7841, 7853,
    7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919, 7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009,
    8011, 8017, 8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111, 8117, 8123, 8147, 8161,
    8167, 8171, 8179, 8191, 8209, 8219, 8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291,
    8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387, 8389, 8419, 8423, 8429, 8431, 8443,
    8447, 8461, 8467, 8501, 8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597, 8599, 8609,
    8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677, 8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731,
    8737, 8741, 8747, 8753, 8761, 8779, 8783, 8803, 8821, 8831, 8837, 8839, 8849, 8861, 8863, 8867,
    8887, 8893, 8923, 8929, 8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011, 9013, 9029,
    9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109, 9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181,
    9187, 9199, 9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283, 9293, 9311, 9319, 9323,
    9337, 9341, 9343, 9349, 9371, 9377, 9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439,
    9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533, 9539, 9547, 9551, 9587, 9601, 9613,
    9619, 9623, 9629, 9631, 9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733, 9739, 9743,
    9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811, 9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871,
    9883, 9887, 9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973,
];

/// Miller-Rabin probable-prime test. Deterministic for n < 3.3e24 using the
/// first 13 prime bases; for larger n uses a fixed set of witness bases
/// (deterministic per call, probabilistic in the mathematical sense).
pub fn is_probable_prime(n: &BigUint) -> bool {
    is_probable_prime_with_rounds(n, 16)
}

pub fn is_probable_prime_with_rounds(n: &BigUint, rounds: u32) -> bool {
    if *n < big(2) {
        return false;
    }
    for &p in SMALL_PRIMES.iter().take(64) {
        let p = big(p);
        if *n == p {
            return true;
        }
        if n % &p == BigUint::zero() {
            return false;
        }
    }
    let one = BigUint::one();
    let two = &one + &one;
    if *n == two {
        return true;
    }
    // n - 1 = d * 2^s
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut s = 0u64;
    while (&d & &one) == BigUint::zero() {
        d >>= 1;
        s += 1;
    }

    let deterministic_bound = BigUint::from(3317044064679887385961981u128);
    let witnesses: Vec<BigUint> = if *n < deterministic_bound {
        SMALL_PRIMES
            .iter()
            .take(13)
            .map(|&b| big(b))
            .filter(|b| b < n)
            .collect()
    } else {
        (0..rounds)
            .map(|i| big(WITNESS_BASES[(i as usize) % WITNESS_BASES.len()]))
            .collect()
    };

    for a in witnesses {
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue;
        }
        let mut composite = true;
        for _ in 0..s {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                composite = false;
                break;
            }
            if x.is_one() {
                break;
            }
        }
        if composite {
            return false;
        }
    }
    true
}

const WITNESS_BASES: &[u64] = &[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];

/// Pollard's rho with Brent's cycle detection. Bounded by `max_steps`.
/// Returns a non-trivial factor or None. Best for factors up to ~2^60.
pub fn pollard_rho(n: &BigUint, max_steps: u64) -> Option<BigUint> {
    pollard_rho_bounded(n, max_steps, None)
}

/// Deadline-aware Pollard rho. `deadline` cuts the search short; the step
/// bound still applies. Returns a non-trivial factor or None.
pub fn pollard_rho_bounded(
    n: &BigUint,
    max_steps: u64,
    deadline: Option<std::time::Instant>,
) -> Option<BigUint> {
    let two = big(2);
    if n % &two == BigUint::zero() {
        return Some(two);
    }
    if *n < big(4) {
        return None;
    }
    for c in 1u64..=8 {
        let c = big(c);
        if let Some(f) = brent_round(n, &c, max_steps, deadline) {
            if f != *n {
                return Some(f);
            }
        }
        if let Some(d) = deadline {
            if std::time::Instant::now() >= d {
                return None;
            }
        }
    }
    None
}

fn deadline_hit(deadline: Option<std::time::Instant>, steps: u64) -> bool {
    match deadline {
        Some(d) => steps % 1024 == 0 && std::time::Instant::now() >= d,
        None => false,
    }
}

fn brent_round(
    n: &BigUint,
    c: &BigUint,
    max_steps: u64,
    deadline: Option<std::time::Instant>,
) -> Option<BigUint> {
    let f = |x: &BigUint| (&(x * x) + c) % n;
    let mut y = big(2);
    let mut x = big(2);
    let mut r: u64 = 1;
    let mut q = BigUint::one();
    let mut steps = 0u64;
    let mut g = BigUint::one();
    let mut ys = y.clone();
    while g.is_one() {
        x = y.clone();
        for _ in 0..r {
            y = f(&y);
            steps += 1;
            if steps > max_steps || deadline_hit(deadline, steps) {
                return None;
            }
        }
        let mut k = 0u64;
        while k < r && g.is_one() {
            ys = y.clone();
            let batch = (r - k).min(32);
            for _ in 0..batch {
                y = f(&y);
                let diff = if x > y { &x - &y } else { &y - &x };
                q = (&q * diff) % n;
                steps += 1;
                if steps > max_steps || deadline_hit(deadline, steps) {
                    return None;
                }
            }
            g = gcd(&q, n);
            k += batch;
        }
        r *= 2;
        if r > max_steps {
            return None;
        }
    }
    if g == *n {
        // Backtrack one step at a time.
        g = BigUint::one();
        y = ys;
        while g.is_one() {
            y = f(&y);
            let diff = if x > y { &x - &y } else { &y - &x };
            g = gcd(&diff, n);
            steps += 1;
            if steps > max_steps || deadline_hit(deadline, steps) {
                return None;
            }
        }
    }
    if g == *n || g.is_one() {
        None
    } else {
        Some(g)
    }
}

/// Pollard's p-1 (stage 1) with smoothness bound B. Returns a non-trivial
/// factor when p-1 (or q-1) is B-smooth.
pub fn pollard_pm1(n: &BigUint, bound: u64) -> Option<BigUint> {
    pollard_pm1_bounded(n, bound, None)
}

/// Deadline-aware Pollard p-1 stage 1.
pub fn pollard_pm1_bounded(
    n: &BigUint,
    bound: u64,
    deadline: Option<std::time::Instant>,
) -> Option<BigUint> {
    let mut a: BigUint = big(2);
    for &p in SMALL_PRIMES {
        if p > bound {
            break;
        }
        if let Some(d) = deadline {
            if std::time::Instant::now() >= d {
                return None;
            }
        }
        // a = a^(p^e) mod n where p^e <= bound
        let mut pe = p as u128;
        while pe * (p as u128) <= bound as u128 {
            pe *= p as u128;
        }
        let e = big(pe as u64);
        a = a.modpow(&e, n);
        let d = gcd(&(&a - BigUint::one()), n);
        if d != BigUint::one() {
            if d != *n {
                return Some(d);
            }
            return None; // full cycle hit; bail
        }
    }
    None
}

/// Trial division by small primes.
pub fn trial_division(n: &BigUint, limit: u64) -> Option<BigUint> {
    for &p in SMALL_PRIMES {
        if p > limit {
            break;
        }
        let p = big(p);
        if n % &p == BigUint::zero() {
            return Some(p);
        }
    }
    None
}

/// Simple deterministic LCG for reproducible test instance generation.
pub fn lcg_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state >> 33
}

/// Generate a random odd BigUint of `bits` bits from an LCG stream
/// (test/dev use only — not a security RNG).
pub fn weak_random_odd(bits: u64, state: &mut u64) -> BigUint {
    let mut n = BigUint::zero();
    let mut produced = 0u64;
    while produced < bits {
        let word = lcg_u64(state);
        let take = (bits - produced).min(31);
        n |= BigUint::from(word & ((1u64 << take) - 1)) << produced;
        produced += take;
    }
    n |= BigUint::one() << (bits - 1); // force top bit
    n |= BigUint::one(); // force odd
    n
}

/// Generate a probable prime of `bits` bits (LCG-driven; test/dev only).
pub fn weak_prime(bits: u64, state: &mut u64) -> BigUint {
    loop {
        let candidate = weak_random_odd(bits, state);
        if is_probable_prime(&candidate) {
            return candidate;
        }
    }
}

/// Compare helper used by tests and diagnostics.
pub fn bits(n: &BigUint) -> u64 {
    n.bits()
}

/// Order two big integers (for sorting factor pairs).
pub fn cmp_big(a: &BigUint, b: &BigUint) -> Ordering {
    a.cmp(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcd_basics() {
        assert_eq!(gcd(&big(48), &big(18)), big(6));
        assert_eq!(gcd(&big(17), &big(5)), big(1));
        assert_eq!(gcd(&big(0), &big(7)), big(7));
    }

    #[test]
    fn modular_inverse() {
        // 3^-1 mod 11 = 4
        assert_eq!(modinv(&big(3), &big(11)), Some(big(4)));
        // Non-invertible
        assert_eq!(modinv(&big(2), &big(4)), None);
        // Big case: e=65537 inverse mod small prime
        let p = big(1000000007);
        let inv = modinv(&big(65537), &p).unwrap();
        assert_eq!((big(65537) * inv) % &p, big(1));
    }

    #[test]
    fn integer_roots() {
        assert_eq!(iroot(&big(27), 3), big(3));
        assert_eq!(iroot(&big(26), 3), big(2));
        assert_eq!(iroot(&big(16), 2), big(4));
        assert_eq!(iroot(&big(15), 2), big(3));
        // Large: 1234567890123456789^3
        let m = big(1234567890123456789);
        let cube = &m * &m * &m;
        assert_eq!(iroot(&cube, 3), m);
    }

    #[test]
    fn perfect_square() {
        assert_eq!(isqrt_exact(&big(49)), Some(big(7)));
        assert_eq!(isqrt_exact(&big(48)), None);
    }

    #[test]
    fn crt_combines() {
        // x ≡ 2 mod 3, x ≡ 3 mod 5, x ≡ 2 mod 7 → 23
        let (x, m) = crt(&[big(2), big(3), big(2)], &[big(3), big(5), big(7)]).unwrap();
        assert_eq!(m, big(105));
        assert_eq!(x, big(23));
        // Non-coprime moduli may still work when consistent; inconsistent must fail.
        assert!(crt(&[big(1), big(2)], &[big(4), big(6)]).is_none());
    }

    #[test]
    fn primality() {
        assert!(is_probable_prime(&big(2)));
        assert!(is_probable_prime(&big(997)));
        assert!(!is_probable_prime(&big(998)));
        assert!(is_probable_prime(&((big(1) << 61u32) - big(1)))); // 2^61-1 Mersenne
        assert!(!is_probable_prime(&(big(1) << 61u32)));
        // Carmichael number 561
        assert!(!is_probable_prime(&big(561)));
    }

    #[test]
    fn rho_finds_factor() {
        let n = big(10403); // 101 * 103
        let f = pollard_rho(&n, 100_000).unwrap();
        assert!(f == big(101) || f == big(103));
        // Prime input must not "factor".
        assert!(pollard_rho(&big(9973), 10_000).is_none());
    }

    #[test]
    fn pm1_finds_smooth_factor() {
        // 769 is prime and 769-1 = 768 = 2^8 * 3 is 1000-smooth.
        let p = big(769);
        // 1000000007 is prime; p-1 = 2 * 500000003 is not 1000-smooth.
        let q = big(1000000007);
        let n = &p * &q;
        let f = pollard_pm1(&n, 1000).unwrap();
        assert_eq!(f, p, "must recover the smooth-prime factor");
    }

    #[test]
    fn weak_primes_generate() {
        let mut state = 0xC0FFEEu64;
        let p = weak_prime(64, &mut state);
        let q = weak_prime(64, &mut state);
        assert!(p.bits() == 64 && q.bits() == 64);
        assert!(is_probable_prime(&p) && is_probable_prime(&q));
    }
}
