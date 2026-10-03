//! RSA cryptanalysis: parameter model, attack primitives, analyzer, and the
//! Rabin (e = 2) decryption path.

pub mod attacks;
pub mod params;
pub mod rabin;

pub use attacks::{
    analyze, attack_common_modulus, attack_dp_leak, attack_dpdq_recover, attack_fermat,
    attack_hastad, attack_known_d, attack_known_phi, attack_known_pq, attack_low_e,
    attack_pollard_pm1, attack_pollard_rho, attack_shared_prime, attack_wiener, AnalyzerReport,
    AttackCost, AttackOutcome, AttackStatus, PlaintextResult,
};
pub use params::{parse_big_value, RsaParams, RsaSet};
pub use rabin::{attack_rabin, rabin_decrypt, RabinDecryptResult};
