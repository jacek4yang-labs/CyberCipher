//! CyberCipher CLI. Shares the engine (and therefore every operation) with
//! the GUI; no algorithm code is duplicated.

use clap::{Parser, Subcommand};
use cybercipher_core::{ExecutionContext, OperationRegistry, ParamMap, ParamValue, Value};
use cybercipher_engine::{RecipeEngine, RecipeV1, RunMode};
use std::io::Read;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "cybercipher",
    version,
    about = "CyberCipher — crypto, decode, analyze, solve (local-first CTF workbench)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List registered operations.
    Ops,
    /// Run one operation on input.
    Run {
        /// Operation id, e.g. from-base64.
        #[arg(short, long)]
        op: String,
        /// Parameters as key=value (repeated). Values parse as bool/int then fall back to string.
        #[arg(short, long = "param")]
        params: Vec<String>,
        /// Input file path, `-` for stdin, or a literal string.
        input: String,
    },
    /// PRNG recovery: LCG parameter/state recovery and MT19937 cloning.
    Prng {
        #[command(subcommand)]
        cmd: PrngCmd,
    },
    /// RSA parameter analysis and solving (JSON with n/e/c/d/p/q/phi/dp/dq/qinv/sets/ns).
    Rsa {
        /// Run attacks in order until the plaintext is recovered.
        #[arg(long)]
        solve: bool,
        /// Time budget per run in milliseconds.
        #[arg(long, default_value = "10000")]
        budget_ms: u64,
        /// JSON file path or `-` for stdin.
        input: String,
    },
    /// JWT/JWS: decode, verify, or sign compact tokens (RFC 7519/7515).
    Jwt {
        #[command(subcommand)]
        cmd: JwtCmd,
    },
    /// ECDSA attacks: duplicate-r detection and nonce-reuse / known-k /
    /// small-k private-key recovery (JSON input; every recovered key is
    /// verified against the provided public key).
    EcdsaAttack {
        #[command(subcommand)]
        cmd: EcdsaAttackCmd,
    },
    /// SSTV decode: automatic mode detection + image recovery from audio.
    Sstv {
        #[command(subcommand)]
        cmd: SstvCmd,
    },
    /// Bounded explainable automatic decoding.
    Auto {
        /// Input file path, `-` for stdin, or a literal string.
        input: String,
    },
    /// Scan input for cryptographic algorithm signatures (constant tables,
    /// code shapes). Evidence-backed candidates with confidence.
    Sigscan {
        /// Input file path, `-` for stdin, or a literal string.
        input: String,
        /// Detection mode: auto | text | bytes.
        #[arg(long, default_value = "auto")]
        mode: String,
        /// Interpret the input as a hex string / hex dump (decode first).
        #[arg(long)]
        hex: bool,
        /// Minimum confidence to report: low | medium | high.
        #[arg(long, default_value = "low")]
        min_confidence: String,
    },
    /// Execute a recipe file (JSON, format v1) on input.
    Recipe {
        /// Recipe JSON file path.
        recipe: String,
        /// Input file path, `-` for stdin, or a literal string.
        input: String,
    },
}

#[derive(Subcommand)]
enum PrngCmd {
    /// Recover LCG parameters (a, b, m) from consecutive outputs.
    LcgRecover {
        /// Consecutive outputs, comma/space separated, or a file path / '-' for stdin.
        outputs: String,
    },
    /// Predict LCG outputs forward/backward from a known state.
    LcgPredict {
        #[arg(long)]
        a: String,
        #[arg(long)]
        b: String,
        #[arg(long)]
        modulus: String,
        #[arg(long)]
        state: String,
        #[arg(long, default_value = "10")]
        count: u64,
        #[arg(long, default_value = "0")]
        back: u64,
    },
    /// Clone MT19937 state from 624 consecutive 32-bit outputs and predict ahead.
    MtClone {
        /// File with 624 outputs (whitespace/comma separated) or '-' for stdin.
        outputs: String,
        #[arg(long, default_value = "10")]
        predict: u64,
    },
    /// Java java.util.Random stream: new Random(SEED).nextInt().
    Java {
        #[arg(long)]
        seed: i64,
        #[arg(long, default_value = "5")]
        count: u32,
    },
    /// Recover Java Random state from two consecutive nextInt() outputs.
    JavaRecover {
        /// Two consecutive nextInt() outputs.
        outputs: String,
    },
    /// glibc rand() stream (TYPE_3 additive feedback).
    Glibc {
        #[arg(long)]
        seed: u32,
        #[arg(long, default_value = "5")]
        count: u32,
    },
    /// MSVC rand() stream.
    Msvc {
        #[arg(long)]
        seed: u32,
        #[arg(long, default_value = "5")]
        count: u32,
    },
    /// Recover MSVC rand state from three consecutive outputs.
    MsvcRecover {
        /// Three consecutive outputs.
        outputs: String,
    },
    /// CPython-compatible getrandbits stream: random.seed(SEED).getrandbits(BITS).
    MtBits {
        #[arg(long)]
        seed: String,
        #[arg(long, default_value = "32")]
        bits: u32,
        #[arg(long, default_value = "5")]
        count: u64,
    },
}

#[derive(Subcommand)]
enum EcdsaAttackCmd {
    /// Detect duplicate r values across a list of signatures (nonce-reuse
    /// fingerprint). Input: JSON array of {message | digest, r, s} objects,
    /// or an object with a `signatures` array.
    Detect {
        /// JSON file path, `-` for stdin, or a literal JSON string.
        input: String,
        /// Curve: p256 | p384.
        #[arg(long, default_value = "p256")]
        curve: String,
        /// Hash: auto | sha256 | sha384.
        #[arg(long, default_value = "auto")]
        hash: String,
    },
    /// Recover the private key from two signatures sharing a nonce (same r):
    /// k = (h1-h2)/(s1-s2) mod n, d = (s1*k-h1)/r mod n.
    /// Input: {"msg1"|"digest1", "msg2"|"digest2", "r", "s1", "s2"} (hex).
    Reuse {
        /// JSON file path, `-` for stdin, or a literal JSON string.
        input: String,
        /// Curve: p256 | p384.
        #[arg(long, default_value = "p256")]
        curve: String,
        /// Hash: auto | sha256 | sha384.
        #[arg(long, default_value = "auto")]
        hash: String,
        /// Signer public key: SEC1 hex, a file path, or `-` for stdin.
        #[arg(long)]
        public_key: String,
    },
    /// Recover the private key from one signature with a known nonce k:
    /// d = (s*k-h)/r mod n. Input: {"message"|"digest", "r", "s", "k"} (hex).
    Knownk {
        /// JSON file path, `-` for stdin, or a literal JSON string.
        input: String,
        /// Curve: p256 | p384.
        #[arg(long, default_value = "p256")]
        curve: String,
        /// Hash: auto | sha256 | sha384.
        #[arg(long, default_value = "auto")]
        hash: String,
        /// Signer public key: SEC1 hex, a file path, or `-` for stdin.
        #[arg(long)]
        public_key: String,
    },
    /// Brute-force small nonces k in 1..=max_k against one signature (the
    /// first candidate whose derived public key matches is reported).
    /// Input: {"message"|"digest", "r", "s"} (hex).
    Smallk {
        /// JSON file path, `-` for stdin, or a literal JSON string.
        input: String,
        /// Curve: p256 | p384.
        #[arg(long, default_value = "p256")]
        curve: String,
        /// Hash: auto | sha256 | sha384.
        #[arg(long, default_value = "auto")]
        hash: String,
        /// Signer public key: SEC1 hex, a file path, or `-` for stdin.
        #[arg(long)]
        public_key: String,
        /// Upper nonce bound (default 100000, hard cap 10000000).
        #[arg(long, default_value = "100000")]
        max_k: u64,
        /// Time budget in milliseconds (0 = no deadline).
        #[arg(long, default_value = "0")]
        budget_ms: u64,
    },
}

fn main() {
    let cli = Cli::parse();
    // Default registry plus the PKI JWT and SSTV operations (the extra crates
    // are wired here rather than inside `default_registry` so library
    // consumers opt in).
    let mut reg = cybercipher_engine::default_registry();
    cybercipher_pki::jwt::register(&mut reg);
    cybercipher_pki::ecc::register(&mut reg);
    cybercipher_sstv::register_all(&mut reg);
    let registry = Arc::new(reg);
    let engine = RecipeEngine::new(registry.clone());

    match cli.command {
        Command::Prng { cmd } => run_prng(cmd),
        Command::Jwt { cmd } => run_jwt(cmd),
        Command::EcdsaAttack { cmd } => run_ecdsa_attack(cmd, &registry),
        Command::Sstv { cmd } => run_sstv(cmd),
        Command::Ops => {
            for info in registry.info() {
                println!("{:<22} {:<16} {}", info.id, info.category.name(), info.name);
            }
        }
        Command::Run { op, params, input } => {
            let operation = registry.get(&op).unwrap_or_else(|| {
                eprintln!("error: unknown operation `{op}` — use `cybercipher ops` to list");
                std::process::exit(2);
            });
            let mut map = ParamMap::new();
            for p in &params {
                let (k, v) = p.split_once('=').unwrap_or_else(|| {
                    eprintln!("error: parameter `{p}` is not key=value");
                    std::process::exit(2);
                });
                map.insert(k, parse_param(v));
            }
            let data = read_input(&input);
            let value = Value::from_bytes(data);
            match operation.execute(&value, &map, &ExecutionContext::new()) {
                Ok(out) => print_value(&out),
                Err(e) => {
                    eprintln!(
                        "error [{}]: {e}",
                        serde_json::to_string(&e.kind).unwrap_or_default()
                    );
                    if let Some(d) = &e.details {
                        eprintln!("details: {d}");
                    }
                    std::process::exit(1);
                }
            }
        }
        Command::Rsa {
            solve,
            budget_ms,
            input,
        } => {
            let text = read_input(&input);
            let value: serde_json::Value = serde_json::from_slice(&text).unwrap_or_else(|e| {
                eprintln!("error: RSA parameter file is not valid JSON: {e}");
                std::process::exit(2);
            });
            let params = cybercipher_attack::RsaParams::from_json(&value).unwrap_or_else(|e| {
                eprintln!("error: {e}");
                std::process::exit(2);
            });
            let report = cybercipher_attack::analyze(&params, solve, budget_ms);
            println!("== Applicable findings ==");
            for f in &report.findings {
                let status = serde_json::to_string(&f.status).unwrap_or_default();
                let status = status.trim_matches('"');
                println!("[{status:<14}] {:<28} ({:?}) {}", f.name, f.cost, f.message);
                if let Some(d) = &f.details {
                    println!("                {d}");
                }
            }
            match &report.plaintext {
                Some(pt) => {
                    println!(
                        "
== Plaintext =="
                    );
                    println!("hex:     {}", pt.m_hex);
                    println!("decimal: {}", pt.m_decimal);
                    if let Some(utf8) = &pt.utf8 {
                        println!("utf8:    {utf8:?}");
                    }
                    if let Some(flag) = &pt.flag_like {
                        println!("flag:    {flag}");
                    }
                }
                None => println!(
                    "
no plaintext recovered (see findings)"
                ),
            }
        }
        Command::Auto { input } => {
            let data = read_input(&input);
            let candidates = cybercipher_engine::auto_decode(
                &registry,
                &data,
                &cybercipher_core::ExecutionContext::new(),
            );
            if candidates.is_empty() {
                println!("no plausible decoding found");
            }
            for (i, c) in candidates.iter().enumerate() {
                println!(
                    "#{} score {:.2}{} path: {}",
                    i + 1,
                    c.score,
                    if c.confident { " (confident)" } else { "" },
                    c.path.join(" -> ")
                );
                for e in &c.evidence {
                    println!("    + {e}");
                }
                let head: String = c.preview.chars().take(120).collect();
                println!("    preview: {head:?}");
            }
        }
        Command::Sigscan {
            input,
            mode,
            hex,
            min_confidence,
        } => {
            let value = sigscan_value(&registry, &input, &mode, hex, &min_confidence);
            print_value(&value);
        }
        Command::Recipe { recipe, input } => {
            let text = read_input(&recipe);
            let recipe: RecipeV1 = serde_json::from_slice(&text).unwrap_or_else(|e| {
                eprintln!("error: recipe file is not valid JSON: {e}");
                std::process::exit(2);
            });
            let data = read_input(&input);
            let report = engine.execute(
                &recipe,
                Value::from_bytes(data),
                RunMode::Manual,
                &ExecutionContext::new(),
            );
            match report {
                Ok(report) => {
                    for stage in &report.stages {
                        let status = format!("{:?}", stage.status).to_lowercase();
                        println!(
                            "[{status}] {:<18} {} · {} µs",
                            stage.op_id, stage.kind, stage.duration_us
                        );
                    }
                    if let Some(e) = &report.error {
                        eprintln!(
                            "error [{}]: {e}",
                            serde_json::to_string(&e.kind).unwrap_or_default()
                        );
                        if let Some(d) = &e.details {
                            eprintln!("details: {d}");
                        }
                        std::process::exit(1);
                    }
                    if let Some(out) = &report.output {
                        print_value(out);
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(2);
                }
            }
        }
    }
}

#[derive(Subcommand)]
enum JwtCmd {
    /// Decode a token into header/payload/signature — output is UNVERIFIED.
    Decode {
        /// Token file path, `-` for stdin, or a literal token string.
        input: String,
    },
    /// Verify a token's signature (and optionally its claims).
    Verify {
        /// Token file path, `-` for stdin, or a literal token string.
        input: String,
        /// JWS algorithm: HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|EdDSA.
        #[arg(short, long)]
        alg: String,
        /// Key: shared secret (HS*), key PEM/hex (RS*/ES*/EdDSA), a file
        /// path, or `-` for stdin.
        #[arg(short, long)]
        key: String,
        /// How to read the HS* shared secret: utf8 | hex.
        #[arg(long, default_value = "utf8")]
        secret_encoding: String,
        /// How to read ES*/EdDSA keys: pem | hex.
        #[arg(long, default_value = "pem")]
        key_encoding: String,
        /// Validate exp/nbf/iat/iss/aud claims after the signature check.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        validate_claims: bool,
        /// Clock-skew tolerance for temporal claims, in seconds.
        #[arg(long, default_value_t = 60)]
        leeway: i64,
        /// Exact-match issuer check.
        #[arg(long)]
        expected_iss: Option<String>,
        /// Exact-match audience check (string or array member).
        #[arg(long)]
        expected_aud: Option<String>,
        /// Freeze the verification clock (unix seconds) for reproducibility.
        #[arg(long)]
        now_unix: Option<i64>,
    },
    /// Sign JSON claims into a compact JWS.
    Sign {
        /// Claims JSON file path, `-` for stdin, or a literal JSON string.
        input: String,
        /// JWS algorithm: HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|EdDSA.
        #[arg(short, long)]
        alg: String,
        /// Key: shared secret (HS*), private key PEM/hex (RS*/ES*/EdDSA), a
        /// file path, or `-` for stdin.
        #[arg(short, long)]
        key: String,
        /// How to read the HS* shared secret: utf8 | hex.
        #[arg(long, default_value = "utf8")]
        secret_encoding: String,
        /// How to read ES*/EdDSA keys: pem | hex.
        #[arg(long, default_value = "pem")]
        key_encoding: String,
        /// Extra JOSE header members as a JSON object (never overrides alg).
        #[arg(long)]
        header_extra: Option<String>,
    },
}

fn run_jwt(cmd: JwtCmd) {
    use cybercipher_pki::jwt::{
        jwt_decode, jwt_sign, jwt_verify, jwt_verify_at, JwtAlg, JwtSignParams, JwtVerifyParams,
        KeyEncoding, SecretEncoding,
    };

    match cmd {
        JwtCmd::Decode { input } => {
            let token = String::from_utf8_lossy(&read_input(&input)).into_owned();
            match jwt_decode(&token) {
                Ok(decoded) => print_value(&Value::Json(
                    serde_json::to_value(&decoded).unwrap_or_default(),
                )),
                Err(e) => fail(&e),
            }
        }
        JwtCmd::Verify {
            input,
            alg,
            key,
            secret_encoding,
            key_encoding,
            validate_claims,
            leeway,
            expected_iss,
            expected_aud,
            now_unix,
        } => {
            let token = String::from_utf8_lossy(&read_input(&input)).into_owned();
            let alg = JwtAlg::parse(&alg).unwrap_or_else(|e| fail(&e));
            let key = String::from_utf8_lossy(&read_input(&key)).into_owned();
            let params = JwtVerifyParams {
                secret_encoding: SecretEncoding::parse(&secret_encoding)
                    .unwrap_or_else(|e| fail(&e)),
                key_encoding: KeyEncoding::parse(&key_encoding).unwrap_or_else(|e| fail(&e)),
                validate_claims,
                leeway_secs: leeway,
                expected_iss,
                expected_aud,
            };
            let result = match now_unix {
                Some(now) => jwt_verify_at(&token, alg, &key, &params, now),
                None => jwt_verify(&token, alg, &key, &params),
            };
            match result {
                Ok(verified) => {
                    print_value(&Value::Json(
                        serde_json::to_value(&verified).unwrap_or_default(),
                    ));
                    if !verified.valid {
                        eprintln!("error: JWT verification failed");
                        std::process::exit(1);
                    }
                }
                Err(e) => fail(&e),
            }
        }
        JwtCmd::Sign {
            input,
            alg,
            key,
            secret_encoding,
            key_encoding,
            header_extra,
        } => {
            let claims_text = String::from_utf8_lossy(&read_input(&input)).into_owned();
            let claims: serde_json::Value =
                serde_json::from_str(&claims_text).unwrap_or_else(|e| {
                    eprintln!("error: claims input is not valid JSON: {e}");
                    std::process::exit(2);
                });
            let alg = JwtAlg::parse(&alg).unwrap_or_else(|e| fail(&e));
            let key = String::from_utf8_lossy(&read_input(&key)).into_owned();
            let header_extra = match header_extra {
                None => serde_json::Value::Null,
                Some(text) => serde_json::from_str(&text).unwrap_or_else(|e| {
                    eprintln!("error: --header-extra is not valid JSON: {e}");
                    std::process::exit(2);
                }),
            };
            let params = JwtSignParams {
                secret_encoding: SecretEncoding::parse(&secret_encoding)
                    .unwrap_or_else(|e| fail(&e)),
                key_encoding: KeyEncoding::parse(&key_encoding).unwrap_or_else(|e| fail(&e)),
            };
            match jwt_sign(claims, header_extra, alg, &key, &params) {
                Ok(token) => println!("{token}"),
                Err(e) => fail(&e),
            }
        }
    }
}

/// Run one ECDSA attack subaction through the registry (shared with tests).
fn run_ecdsa_attack(cmd: EcdsaAttackCmd, registry: &OperationRegistry) {
    match cmd {
        EcdsaAttackCmd::Detect { input, curve, hash } => {
            let data = read_input(&input);
            let value = ecdsa_attack_value(
                registry,
                "ecdsa-duplicate-r-detect",
                &data,
                &curve,
                &hash,
                None,
                cybercipher_pki::SMALL_K_DEFAULT,
                &ExecutionContext::new(),
            );
            print_value(&value);
        }
        EcdsaAttackCmd::Reuse {
            input,
            curve,
            hash,
            public_key,
        } => {
            let key = read_key_arg(&public_key);
            let data = read_input(&input);
            let value = ecdsa_attack_value(
                registry,
                "ecdsa-nonce-reuse-recover",
                &data,
                &curve,
                &hash,
                Some(&key),
                cybercipher_pki::SMALL_K_DEFAULT,
                &ExecutionContext::new(),
            );
            print_value(&value);
        }
        EcdsaAttackCmd::Knownk {
            input,
            curve,
            hash,
            public_key,
        } => {
            let key = read_key_arg(&public_key);
            let data = read_input(&input);
            let value = ecdsa_attack_value(
                registry,
                "ecdsa-known-k-recover",
                &data,
                &curve,
                &hash,
                Some(&key),
                cybercipher_pki::SMALL_K_DEFAULT,
                &ExecutionContext::new(),
            );
            print_value(&value);
        }
        EcdsaAttackCmd::Smallk {
            input,
            curve,
            hash,
            public_key,
            max_k,
            budget_ms,
        } => {
            let key = read_key_arg(&public_key);
            let data = read_input(&input);
            let ctx = deadline_ctx(budget_ms);
            let value = ecdsa_attack_value(
                registry,
                "ecdsa-small-k-recover",
                &data,
                &curve,
                &hash,
                Some(&key),
                max_k,
                &ctx,
            );
            print_value(&value);
        }
    }
}

/// Execute an ECDSA attack operation by id with the common parameter shape.
#[allow(clippy::too_many_arguments)]
fn ecdsa_attack_value(
    registry: &OperationRegistry,
    op_id: &str,
    input: &[u8],
    curve: &str,
    hash: &str,
    public_key: Option<&str>,
    max_k: u64,
    ctx: &ExecutionContext,
) -> Value {
    let op = registry.get(op_id).unwrap_or_else(|| {
        eprintln!("error: `{op_id}` is not registered");
        std::process::exit(2);
    });
    let mut map = ParamMap::new();
    map.insert("curve", curve);
    map.insert("hash", hash);
    if let Some(key) = public_key {
        map.insert("public_key", key);
    }
    map.insert(
        "max_k",
        ParamValue::Int(i64::try_from(max_k).unwrap_or(i64::MAX)),
    );
    let value = Value::from_bytes(input.to_vec());
    match op.execute(&value, &map, ctx) {
        Ok(out) => out,
        Err(e) => fail(&e),
    }
}

/// Public-key argument: hex text, a file path, or `-` for stdin.
fn read_key_arg(spec: &str) -> String {
    String::from_utf8_lossy(&read_input(spec))
        .trim()
        .to_string()
}

/// Deadline context for bounded subcommands; 0 means no deadline.
fn deadline_ctx(budget_ms: u64) -> ExecutionContext {
    if budget_ms > 0 {
        ExecutionContext::new()
            .with_deadline(std::time::Instant::now() + std::time::Duration::from_millis(budget_ms))
    } else {
        ExecutionContext::new()
    }
}

#[derive(Subcommand)]
enum SstvCmd {
    /// Decode an SSTV transmission from an audio file (WAV/FLAC/MP3/...).
    Decode {
        /// Audio file path, or `-` for stdin.
        file: String,
        /// Channel: auto | mono | left | right | zero-based index.
        #[arg(long, default_value = "auto")]
        channel: String,
        /// Force a specific mode (e.g. robot36, martin1) instead of detecting.
        #[arg(long)]
        mode: Option<String>,
        /// Allow blind sync-period inference when the VIS header is absent.
        /// On by default; pass `--blind false` to require a valid header.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        blind: bool,
        /// Reject audio longer than this many seconds before any decode work.
        #[arg(long, default_value_t = 90)]
        max_seconds: i64,
        /// Write the JSON report to this path instead of stdout.
        #[arg(long)]
        out: Option<String>,
        /// Write decoded images as PNG files with this path prefix
        /// (`out/frame` -> `out/frame-001-robot36.png`).
        #[arg(long)]
        png: Option<String>,
    },
}

fn run_sstv(cmd: SstvCmd) {
    let SstvCmd::Decode {
        file,
        channel,
        mode,
        blind,
        max_seconds,
        out,
        png,
    } = cmd;
    let bytes = read_input(&file);
    let request = cybercipher_sstv::ops::DecodeRequest {
        channel,
        forced_mode: mode,
        blind,
        max_duration_seconds: max_seconds,
        max_candidates: cybercipher_sstv::ops::DEFAULT_MAX_CANDIDATES,
    };
    let decoded = cybercipher_sstv::ops::decode_bounded(&bytes, &request, &ExecutionContext::new())
        .unwrap_or_else(|e| fail(&e));

    // PNGs are written first so the report can name the files that were
    // actually created. Paths come only from the explicit `--png` argument.
    let mut written: Vec<String> = Vec::new();
    if let Some(prefix) = &png {
        for (index, image) in decoded.images.iter().enumerate() {
            let path = format!("{prefix}-{:03}-{}.png", index + 1, image.mode_slug);
            write_bytes(&path, &image.png);
            println!(
                "wrote {path} ({}x{}, {} bytes)",
                image.width,
                image.height,
                image.png.len()
            );
            written.push(path);
        }
    }

    let mut report = decoded.report;
    for (index, path) in written.iter().enumerate() {
        if let Some(detection) = report.get_mut("detections").and_then(|d| d.get_mut(index)) {
            detection["output_png"] = serde_json::Value::String(path.clone());
        }
    }
    let text = serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
        eprintln!("error serialising report: {e}");
        std::process::exit(1);
    });
    match &out {
        Some(path) => {
            write_bytes(path, text.as_bytes());
            println!("report: {path}");
        }
        None => println!("{text}"),
    }

    for warning in report
        .get("warnings")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(text) = warning.as_str() {
            eprintln!("warning: {text}");
        }
    }
    if decoded.images.is_empty() {
        eprintln!("no SSTV image was decoded (see warnings)");
    }
}

/// Write bytes to an explicit user-specified path, creating the parent
/// directory when needed.
fn write_bytes(path: &str, bytes: &[u8]) {
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).unwrap_or_else(|e| {
                eprintln!("error creating directory for `{path}`: {e}");
                std::process::exit(1);
            });
        }
    }
    std::fs::write(path, bytes).unwrap_or_else(|e| {
        eprintln!("error writing `{path}`: {e}");
        std::process::exit(1);
    });
}

fn run_prng(cmd: PrngCmd) {
    use cybercipher_attack::prng;
    match cmd {
        PrngCmd::LcgRecover { outputs } => {
            let outs = read_biguint_list(&outputs);
            match prng::recover_params_unknown(&outs) {
                Ok(rec) => {
                    println!("m = {}", rec.params.m());
                    println!("a = {}", rec.params.a());
                    println!("b = {}", rec.params.b());
                    println!("verified against all {} outputs", rec.outputs_used);
                }
                Err(e) => fail(&e),
            }
        }
        PrngCmd::LcgPredict {
            a,
            b,
            modulus,
            state,
            count,
            back,
        } => {
            let parse = |v: &str| {
                let t = v.trim();
                let (radix, digits) = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    Some(h) => (16u32, h),
                    None => (10, t),
                };
                num_bigint::BigUint::parse_bytes(digits.as_bytes(), radix).unwrap_or_else(|| {
                    eprintln!("error: `{v}` is not a valid integer");
                    std::process::exit(2);
                })
            };
            let params = prng::LcgParams::new(parse(&a), parse(&b), parse(&modulus))
                .unwrap_or_else(|e| fail(&e));
            let s0 = parse(&state);
            if back > 0 {
                println!("backward:");
                for v in params
                    .step_back(&s0, back.min(1 << 20) as usize)
                    .unwrap_or_else(|e| fail(&e))
                {
                    println!("  {v}");
                }
            }
            println!("forward:");
            for v in params
                .predict(&s0, count.max(1) as usize)
                .unwrap_or_else(|e| fail(&e))
            {
                println!("  {v}");
            }
        }
        PrngCmd::Java { seed, count } => {
            let mut rng = prng::JavaRandom::new(seed);
            for i in 0..count.max(1) {
                println!("nextInt[{i}] = {}", rng.next_i32());
            }
        }
        PrngCmd::JavaRecover { outputs } => {
            let outs = read_u32_list(&outputs);
            if outs.len() != 2 {
                fail(&cybercipher_core::OperationError::invalid_input(
                    "java-recover needs exactly two outputs",
                ));
            }
            let mut rng = prng::java_recover_state(outs[0] as i32, outs[1] as i32)
                .unwrap_or_else(|e| fail(&e));
            println!("internal seed = {}", rng.internal_seed());
            println!("next = {}", rng.next_i32());
        }
        PrngCmd::Glibc { seed, count } => {
            let mut rng = prng::GlibcRand::new(seed);
            for i in 0..count.max(1) {
                println!("rand[{i}] = {}", rng.rand());
            }
        }
        PrngCmd::Msvc { seed, count } => {
            let mut rng = prng::MsvcRand::new(seed);
            for i in 0..count.max(1) {
                println!("rand[{i}] = {}", rng.rand());
            }
        }
        PrngCmd::MsvcRecover { outputs } => {
            let outs = read_u32_list(&outputs);
            if outs.len() != 3 {
                fail(&cybercipher_core::OperationError::invalid_input(
                    "msvc-recover needs exactly three outputs",
                ));
            }
            let mut rng = prng::MsvcRand::recover_from_outputs(outs[0], outs[1], outs[2])
                .unwrap_or_else(|e| fail(&e));
            println!("state = {}", rng.state());
            println!("next = {}", rng.rand());
        }
        PrngCmd::MtClone { outputs, predict } => {
            let outs = read_u32_list(&outputs);
            let mut gen = prng::Mt19937::from_outputs(&outs).unwrap_or_else(|e| fail(&e));
            println!("state cloned from {} outputs", outs.len());
            for i in 0..predict.max(1) {
                println!("next[{i}] = {}", gen.next_u32());
            }
        }
        PrngCmd::MtBits { seed, bits, count } => {
            let parse = |v: &str| {
                let t = v.trim();
                let (radix, digits) = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                    Some(h) => (16, h),
                    None => (10, t),
                };
                num_bigint::BigUint::parse_bytes(digits.as_bytes(), radix).unwrap_or_else(|| {
                    eprintln!("error: `{v}` is not a valid integer");
                    std::process::exit(2);
                })
            };
            let mut gen =
                prng::Mt19937::from_cpython_seed(&parse(&seed)).unwrap_or_else(|e| fail(&e));
            for i in 0..count.max(1) {
                println!(
                    "getrandbits({bits})[{i}] = {}",
                    gen.getrandbits(bits).unwrap_or_else(|e| fail(&e))
                );
            }
        }
    }
}

/// Execute the crypto-signature-scan operation (shared with tests).
fn sigscan_value(
    registry: &OperationRegistry,
    input: &str,
    mode: &str,
    hex: bool,
    min_confidence: &str,
) -> Value {
    let op = registry.get("crypto-signature-scan").unwrap_or_else(|| {
        eprintln!("error: `crypto-signature-scan` is not registered");
        std::process::exit(2);
    });
    let mut map = ParamMap::new();
    map.insert("mode", mode);
    map.insert("input_is_hex", hex);
    map.insert("min_confidence", min_confidence);
    let data = read_input(input);
    let value = Value::from_bytes(data);
    match op.execute(&value, &map, &ExecutionContext::new()) {
        Ok(out) => out,
        Err(e) => fail(&e),
    }
}

fn fail(e: &cybercipher_core::OperationError) -> ! {
    eprintln!("error: {e}");
    if let Some(d) = &e.details {
        eprintln!("details: {d}");
    }
    std::process::exit(1)
}

fn read_biguint_list(spec: &str) -> Vec<num_bigint::BigUint> {
    let text = read_input(spec);
    let joined = String::from_utf8_lossy(&text);
    joined
        .split(|c: char| c == ',' || c.is_whitespace() || c == ';')
        .filter(|t| !t.trim().is_empty())
        .map(|t| {
            let t = t.trim();
            let (radix, digits) = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(h) => (16u32, h),
                None => (10, t),
            };
            num_bigint::BigUint::parse_bytes(digits.as_bytes(), radix).unwrap_or_else(|| {
                eprintln!("error: `{t}` is not a valid integer");
                std::process::exit(2);
            })
        })
        .collect()
}

fn read_u32_list(spec: &str) -> Vec<u32> {
    read_biguint_list(spec)
        .into_iter()
        .map(|v| {
            let t: String = v.to_string();
            t.parse::<u32>().unwrap_or_else(|_| {
                eprintln!("error: `{t}` does not fit in 32 bits");
                std::process::exit(2);
            })
        })
        .collect()
}

fn parse_param(v: &str) -> ParamValue {
    if v == "true" {
        return ParamValue::Bool(true);
    }
    if v == "false" {
        return ParamValue::Bool(false);
    }
    if let Ok(i) = v.parse::<i64>() {
        return ParamValue::Int(i);
    }
    if let Ok(f) = v.parse::<f64>() {
        if v.contains('.') {
            return ParamValue::Float(f);
        }
    }
    ParamValue::Str(v.to_string())
}

/// Read input: `-` is stdin, an existing path is a file, anything else is a
/// literal string.
fn read_input(spec: &str) -> Vec<u8> {
    if spec == "-" {
        let mut buf = Vec::new();
        std::io::stdin().read_to_end(&mut buf).unwrap_or_else(|e| {
            eprintln!("error reading stdin: {e}");
            std::process::exit(2);
        });
        return buf;
    }
    let path = std::path::Path::new(spec);
    if path.is_file() {
        return std::fs::read(path).unwrap_or_else(|e| {
            eprintln!("error reading `{spec}`: {e}");
            std::process::exit(2);
        });
    }
    spec.as_bytes().to_vec()
}

fn print_value(v: &Value) {
    match v {
        Value::Text(t) => println!("{t}"),
        Value::Bytes(b) => {
            // Bytes print as lowercase hex on one line — pipe-friendly.
            let mut out = String::with_capacity(b.len() * 2);
            for byte in b {
                out.push_str(&format!("{byte:02x}"));
            }
            println!("{out}");
        }
        Value::Json(j) => println!("{j:#}"),
        Value::Integer(i) => println!("{i}"),
        Value::IntegerList(l) => println!(
            "{}",
            l.iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ),
        Value::List(items) => {
            for item in items {
                println!("{item:?}");
            }
        }
        Value::Null => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> Arc<OperationRegistry> {
        let mut reg = cybercipher_engine::default_registry();
        cybercipher_pki::jwt::register(&mut reg);
        cybercipher_pki::ecc::register(&mut reg);
        cybercipher_sstv::register_all(&mut reg);
        Arc::new(reg)
    }

    /// Deterministic P-256 nonce-reuse fixture built from the public pki API
    /// plus plain big-integer math: r = x(k*G) comes from parsing the nonce
    /// k = 12345 as a private key, and s = k^-1 * (h + r*d) mod n over the
    /// FIPS 186-4 group order (a test-only constant). Digests are supplied
    /// directly ("01"*32 / "02"*32), so no hashing is needed here.
    fn p256_nonce_fixture() -> (String, String, String, String, String) {
        // (private_key_hex, public_key_hex, r_hex, s1_hex, s2_hex)
        let d_hex = "2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe";
        let keypair =
            cybercipher_pki::parse_ecc_private_key(cybercipher_pki::EccCurve::P256, d_hex).unwrap();
        let n = num_bigint::BigUint::parse_bytes(
            b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            16,
        )
        .unwrap();
        let d = num_bigint::BigUint::parse_bytes(d_hex.as_bytes(), 16).unwrap();
        let k = num_bigint::BigUint::from(12345u32);
        let nonce_key =
            cybercipher_pki::parse_ecc_private_key(cybercipher_pki::EccCurve::P256, "3039")
                .unwrap();
        let compressed = nonce_key.public_compressed_hex;
        let r = num_bigint::BigUint::parse_bytes(&compressed.as_bytes()[2..], 16).unwrap();
        let k_inv = k.modpow(&(&n - 2u32), &n);
        let sign = |h_hex: String| {
            let h = num_bigint::BigUint::parse_bytes(h_hex.as_bytes(), 16).unwrap();
            let s = (&k_inv * &((&h + &(&r * &d)) % &n)) % &n;
            format!("{:0>64}", format!("{s:x}"))
        };
        (
            d_hex.to_string(),
            keypair.public_uncompressed_hex,
            format!("{:0>64}", format!("{r:x}")),
            sign("01".repeat(32)),
            sign("02".repeat(32)),
        )
    }

    #[test]
    fn ecdsa_attack_cli_detect_reports_duplicate_r() {
        let registry = test_registry();
        let (_d_hex, _public_hex, r_hex, s1_hex, s2_hex) = p256_nonce_fixture();
        let input = serde_json::json!([
            {"digest": "01".repeat(32), "r": r_hex, "s": s1_hex},
            {"digest": "02".repeat(32), "r": r_hex, "s": s2_hex},
        ]);
        let value = ecdsa_attack_value(
            &registry,
            "ecdsa-duplicate-r-detect",
            serde_json::to_vec(&input).unwrap().as_slice(),
            "p256",
            "auto",
            None,
            100_000,
            &ExecutionContext::new(),
        );
        match value {
            Value::Json(report) => {
                assert_eq!(report["duplicates_found"], serde_json::json!(true));
                assert_eq!(report["total_signatures"], serde_json::json!(2));
                assert_eq!(report["pairs"].as_array().unwrap().len(), 1);
            }
            other => panic!("expected JSON output, got {other:?}"),
        }
    }

    #[test]
    fn ecdsa_attack_cli_nonce_reuse_recovers_and_verifies() {
        let registry = test_registry();
        let (d_hex, public_hex, r_hex, s1_hex, s2_hex) = p256_nonce_fixture();
        let input = serde_json::json!({
            "digest1": "01".repeat(32),
            "digest2": "02".repeat(32),
            "r": r_hex,
            "s1": s1_hex,
            "s2": s2_hex,
        });
        let value = ecdsa_attack_value(
            &registry,
            "ecdsa-nonce-reuse-recover",
            serde_json::to_vec(&input).unwrap().as_slice(),
            "p256",
            "auto",
            Some(&public_hex),
            100_000,
            &ExecutionContext::new(),
        );
        match value {
            Value::Json(report) => {
                assert_eq!(report["verified"], serde_json::json!(true));
                assert_eq!(report["method"], serde_json::json!("nonce-reuse"));
                assert_eq!(report["private_key_hex"], serde_json::json!(d_hex));
                assert_eq!(report["nonce_r_matches"], serde_json::json!(true));
            }
            other => panic!("expected JSON output, got {other:?}"),
        }
    }

    #[test]
    fn ecdsa_attack_cli_small_k_recovers_with_candidate_count() {
        let registry = test_registry();
        let (d_hex, public_hex, r_hex, s1_hex, _s2_hex) = p256_nonce_fixture();
        let input = serde_json::json!({
            "digest": "01".repeat(32),
            "r": r_hex,
            "s": s1_hex,
        });
        let value = ecdsa_attack_value(
            &registry,
            "ecdsa-small-k-recover",
            serde_json::to_vec(&input).unwrap().as_slice(),
            "p256",
            "auto",
            Some(&public_hex),
            12345,
            &ExecutionContext::new(),
        );
        match value {
            Value::Json(report) => {
                assert_eq!(report["method"], serde_json::json!("small-k"));
                assert_eq!(report["candidates_tried"], serde_json::json!(12345));
                assert_eq!(report["private_key_hex"], serde_json::json!(d_hex));
            }
            other => panic!("expected JSON output, got {other:?}"),
        }
    }

    #[test]
    fn sigscan_cli_roundtrip_text_input() {
        let registry = test_registry();
        let value = sigscan_value(&registry, "sum += 0x9E3779B9;", "auto", false, "low");
        match value {
            Value::Json(json) => {
                assert_eq!(json["mode"], "text");
                let candidates = json["candidates"].as_array().unwrap();
                let tea = candidates
                    .iter()
                    .find(|c| c["algorithm"] == "tea")
                    .expect("tea candidate");
                assert_eq!(tea["confidence"], "low");
                assert!(tea["explanation"].as_str().unwrap().contains("weak"));
            }
            other => panic!("expected JSON output, got {other:?}"),
        }
    }

    #[test]
    fn sigscan_cli_roundtrip_hex_input() {
        let registry = test_registry();
        // 40 junk bytes, then the first 32 bytes of the AES S-box: a prefix
        // anchor, so Medium confidence.
        let mut blob = vec![0xA5u8; 40];
        blob.extend_from_slice(&[
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7,
            0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf,
            0x9c, 0xa4, 0x72, 0xc0,
        ]);
        let hex: String = blob.iter().map(|b| format!("{b:02x}")).collect();
        let value = sigscan_value(&registry, &hex, "auto", true, "medium");
        match value {
            Value::Json(json) => {
                assert_eq!(json["mode"], "bytes");
                let candidates = json["candidates"].as_array().unwrap();
                let aes = candidates
                    .iter()
                    .find(|c| c["algorithm"] == "aes")
                    .expect("aes candidate");
                assert_eq!(aes["confidence"], "medium");
                assert_eq!(aes["locations"][0]["offset"].as_u64(), Some(40));
            }
            other => panic!("expected JSON output, got {other:?}"),
        }
    }
}
