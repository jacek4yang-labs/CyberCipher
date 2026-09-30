//! Auto Decode corpus tests: single-layer, multi-layer, compressed, binary,
//! false-positive traps, and random data. These encode the charter's corpus
//! requirements for Milestone 3.

#![allow(clippy::result_large_err)]

use cybercipher_core::{ExecutionContext, OperationRegistry, ParamMap, Value};
use cybercipher_engine::{
    auto_decode, default_registry, RecipeEngine, RecipeNodeV1, RecipeV1, RunMode,
};
use std::io::Write;

fn registry() -> OperationRegistry {
    default_registry()
}

/// Encode `data` through a registered encoder op (e.g. "to-base58") so the
/// round-trip tests exercise exactly the alphabets the engine must detect.
fn encode_with_op(reg: &OperationRegistry, op_id: &str, data: &[u8]) -> String {
    let op = reg
        .get(op_id)
        .unwrap_or_else(|| panic!("{op_id} must be registered"));
    match op
        .execute(
            &Value::Bytes(data.to_vec()),
            &ParamMap::new(),
            &ExecutionContext::new(),
        )
        .expect("{op_id} must encode")
    {
        Value::Text(text) => text,
        other => panic!("{op_id} must produce text, got {}", other.kind().name()),
    }
}

fn top_candidate(
    reg: &OperationRegistry,
    input: &[u8],
) -> Option<cybercipher_engine::AutoCandidate> {
    let candidates = auto_decode(reg, input, &ExecutionContext::new());
    candidates.into_iter().next()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn single_layer_hex() {
    let reg = registry();
    let input = hex_encode(b"flag{just_hex}");
    let c = top_candidate(&reg, input.as_bytes()).expect("should find hex candidate");
    assert!(c.path.first().unwrap() == "from-hex");
    assert_eq!(c.preview, "flag{just_hex}");
    assert!(c.confident);
}

#[test]
fn single_layer_base64() {
    let reg = registry();
    let input = b"VGhpcyBpcyBwbGFpbiB0ZXh0IGluIEJhc2U2NC4=";
    let c = top_candidate(&reg, input).expect("should find base64 candidate");
    assert_eq!(c.path.first().unwrap(), "from-base64");
    assert!(c.preview.starts_with("This is plain text in Base64."));
    assert!(c.confident);
}

#[test]
fn multi_layer_hex_base64_xor_utf8() {
    let reg = registry();
    // Build the charter's vertical-slice chain: From Hex -> From Base64 -> XOR(0x20) -> UTF-8.
    let inner = b"flag{multi_layer}";
    let xored: Vec<u8> = inner.iter().map(|b| b ^ 0x20).collect();
    let b64 = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(&xored)
    };
    let hex = hex_encode(b64.as_bytes());
    let candidates = auto_decode(&reg, hex.as_bytes(), &ExecutionContext::new());
    assert!(!candidates.is_empty(), "must recover the chain");
    // The engine recovers hex -> base64 and stops there honestly: XOR with an
    // unknown key belongs to the XOR lab, so no confident claim is made about
    // the binary tail. (0x20 on '_' produces a 0x7f control byte, which the
    // scorer correctly refuses to call confident.)
    let layered = candidates
        .iter()
        .find(|c| c.path == vec!["from-hex", "from-base64"])
        .expect("hex->base64 prefix must be discovered");
    assert!(
        !layered.confident,
        "must not fake certainty about the XOR tail"
    );
    assert_eq!(layered.size, xored.len());

    // The recovered path must replay to the same result through the engine.
    let recipe = RecipeV1::new(
        layered
            .recipe_ops()
            .iter()
            .enumerate()
            .map(|(i, op)| RecipeNodeV1 {
                id: format!("n{i}"),
                op: op.clone(),
                enabled: true,
                params: Default::default(),
            })
            .collect(),
    );
    let engine = RecipeEngine::new(std::sync::Arc::new(registry()));
    let report = engine
        .execute(
            &recipe,
            Value::Bytes(hex.as_bytes().to_vec()),
            RunMode::Manual,
            &ExecutionContext::new(),
        )
        .unwrap();
    assert!(report.error.is_none());
    assert_eq!(
        report.output.unwrap(),
        Value::Bytes(xored.clone()),
        "recipe reconstruction must replay the candidate path"
    );
}

#[test]
fn multi_layer_base64_gzip_text() {
    let reg = registry();
    // Base64(gzip(flag text)).
    let gzipped = {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"flag{compressed_layers}").unwrap();
        encoder.finish().unwrap()
    };
    use base64::Engine as _;
    let input = base64::engine::general_purpose::STANDARD.encode(&gzipped);
    let candidates = auto_decode(&reg, input.as_bytes(), &ExecutionContext::new());
    let best = candidates
        .iter()
        .find(|c| c.path.contains(&"from-gzip".to_string()))
        .expect("gzip layer must be discovered");
    assert_eq!(
        best.path,
        vec!["from-base64", "from-gzip"],
        "{:?}",
        best.path
    );
    assert_eq!(best.preview, "flag{compressed_layers}");
    assert!(best.confident, "score {}", best.score);
    assert_eq!(best.flag_like.as_deref(), Some("flag{compressed_layers}"));
}

#[test]
fn url_encoded_input() {
    let reg = registry();
    let input = b"flag%7Burl_decoded%7D%20tail";
    let c = top_candidate(&reg, input).expect("url candidate");
    assert_eq!(c.path.first().unwrap(), "from-url");
    assert_eq!(c.preview, "flag{url_decoded} tail");
}

#[test]
fn json_payload_scores_high() {
    let reg = registry();
    use base64::Engine as _;
    let json = br#"{"user":"ctf","token":"a1b2c3","n":42}"#;
    let input = base64::engine::general_purpose::STANDARD.encode(json);
    let candidates = auto_decode(&reg, input.as_bytes(), &ExecutionContext::new());
    let best = &candidates[0];
    assert!(best.path == vec!["from-base64"], "{:?}", best.path);
    assert!(best.evidence.iter().any(|e| e.contains("JSON")));
}

#[test]
fn binary_input_reports_honestly() {
    let reg = registry();
    // A PNG header wrapped in nothing: magic detection should surface it.
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    png.extend_from_slice(&[0x00, 0x00, 0x00, 0x0d, b'I', b'H', b'D', b'R']);
    let candidates = auto_decode(&reg, &png, &ExecutionContext::new());
    // Magic-only data may produce a low-confidence candidate or none — but
    // never a confident claim of a wrong decoding.
    for c in &candidates {
        if c.path
            .first()
            .map(|p| p == "from-gzip" || p == "from-zlib")
            .unwrap_or(false)
        {
            panic!("binary data must not be force-decoded as compression: {c:?}");
        }
    }
}

#[test]
fn random_data_is_bounded_and_honest() {
    let reg = registry();
    // 64 KiB of pseudo-random high-entropy data.
    let mut seed = 0x12345678u64;
    let mut data = Vec::with_capacity(64 * 1024);
    for _ in 0..64 * 1024 {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        data.push((seed >> 33) as u8);
    }
    let started = std::time::Instant::now();
    let candidates = auto_decode(&reg, &data, &ExecutionContext::new());
    let elapsed = started.elapsed();
    assert!(elapsed.as_secs() < 10, "auto decode must stay bounded");
    // No confident claims on random data.
    for c in &candidates {
        assert!(
            !c.confident,
            "random data produced a confident candidate: {c:?}"
        );
    }
}

#[test]
fn false_positive_trap_whitespace_decimal() {
    let reg = registry();
    // A decimal byte list must not be decoded as base64/hex.
    let input = b"72 101 108 108 111 44 32 119 111 114 108 100 33";
    let candidates = auto_decode(&reg, input, &ExecutionContext::new());
    for c in &candidates {
        let first = c.path.first().unwrap();
        assert!(
            *first != "from-hex" && *first != "from-base64",
            "decimal list misread as {first}: {c:?}"
        );
    }
}

fn encode_and_repeat(data: &[u8], rounds: usize) -> String {
    use base64::Engine as _;
    let mut current = data.to_vec();
    for _ in 0..rounds {
        current = base64::engine::general_purpose::STANDARD
            .encode(&current)
            .into_bytes();
    }
    String::from_utf8(current).unwrap()
}

#[test]
fn deep_base64_nesting_recovers_at_depth() {
    let reg = registry();
    let input = encode_and_repeat(b"flag{deep}", 3);
    let candidates = auto_decode(&reg, input.as_bytes(), &ExecutionContext::new());
    let best = &candidates[0];
    assert_eq!(best.path.len(), 3, "expected three layers: {:?}", best.path);
    assert!(best.path.iter().all(|p| p == "from-base64"));
    assert_eq!(best.preview, "flag{deep}");
}

#[test]
fn single_byte_xor_recovered_from_raw_input() {
    let reg = registry();
    let inner = b"flag{xor_is_fun}";
    let xored: Vec<u8> = inner.iter().map(|b| b ^ 0x5a).collect();
    let candidates = auto_decode(&reg, &xored, &ExecutionContext::new());
    let best = candidates
        .iter()
        .find(|c| {
            c.path
                .first()
                .map(|p| p == "xor-single-byte")
                .unwrap_or(false)
        })
        .expect("xor layer must be discovered");
    assert_eq!(best.preview, "flag{xor_is_fun}");
    assert!(best.confident, "score {}", best.score);
    assert!(best.evidence.iter().any(|e| e.contains("0x5a")));
}

#[test]
fn base64_then_xor_chain_recovered() {
    let reg = registry();
    // This is the charter vertical slice the bootstrap had to punt on:
    // From Base64 -> XOR(0x20) -> UTF-8, all recovered automatically.
    // Inner uses letters/digits so XOR 0x20 stays printable (case flip).
    let inner = b"flag{AUTOXOR42}";
    let xored: Vec<u8> = inner.iter().map(|b| b ^ 0x20).collect();
    use base64::Engine as _;
    let input = base64::engine::general_purpose::STANDARD.encode(&xored);
    let candidates = auto_decode(&reg, input.as_bytes(), &ExecutionContext::new());
    let chained = candidates
        .iter()
        .find(|c| c.path == vec!["from-base64", "xor-single-byte"])
        .expect("base64->xor chain must be discovered");
    // XOR is an involution: the decode recovers the original inner text.
    assert_eq!(chained.preview, "flag{AUTOXOR42}");
    assert!(chained.confident, "score {}", chained.score);
}

#[test]
fn random_data_xor_exploration_stays_bounded() {
    let reg = registry();
    let mut seed = 0xDEADBEEFu64;
    let data: Vec<u8> = (0..32 * 1024)
        .map(|_| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        })
        .collect();
    let started = std::time::Instant::now();
    let candidates = auto_decode(&reg, &data, &ExecutionContext::new());
    let elapsed = started.elapsed();
    assert!(elapsed.as_secs() < 10, "xor exploration must stay bounded");
    // XOR of random data is still random: no confident candidate may emerge.
    for c in &candidates {
        assert!(
            !c.confident,
            "random data produced a confident candidate: {:?}",
            c.path
        );
    }
}

// ------------------------------------------------- base-family coverage ----

#[test]
fn single_layer_base58() {
    let reg = registry();
    let input = encode_with_op(&reg, "to-base58", b"flag{base58_roundtrip}");
    let candidates = auto_decode(&reg, input.as_bytes(), &ExecutionContext::new());
    let best = candidates
        .iter()
        .find(|c| c.path == vec!["from-base58"])
        .expect("base58 layer must be discovered");
    assert!(
        best.preview.contains("flag{base58_roundtrip}"),
        "preview {}",
        best.preview
    );
    assert!(best.confident, "score {}", best.score);
    assert!(
        best.evidence.iter().any(|e| e.contains("Base58")),
        "evidence must name the base58 gate: {:?}",
        best.evidence
    );
}

#[test]
fn single_layer_ascii85() {
    let reg = registry();
    let input = encode_with_op(&reg, "to-ascii85", b"flag{ascii85_roundtrip}");
    let candidates = auto_decode(&reg, input.as_bytes(), &ExecutionContext::new());
    let best = candidates
        .iter()
        .find(|c| c.path == vec!["from-ascii85"])
        .expect("ascii85 layer must be discovered");
    assert!(
        best.preview.contains("flag{ascii85_roundtrip}"),
        "preview {}",
        best.preview
    );
    assert!(best.confident, "score {}", best.score);
}

#[test]
fn multi_layer_base58_base64() {
    let reg = registry();
    // Base58(Base64(flag)): the outer layer hides the Base64 padding, so the
    // engine must fall back to the alphabet gates to open it.
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(b"flag{b58_over_b64}");
    let input = encode_with_op(&reg, "to-base58", b64.as_bytes());
    let candidates = auto_decode(&reg, input.as_bytes(), &ExecutionContext::new());
    let chained = candidates
        .iter()
        .find(|c| c.path == vec!["from-base58", "from-base64"])
        .expect("base58->base64 chain must be discovered");
    assert_eq!(chained.preview, "flag{b58_over_b64}");
    assert!(chained.confident, "score {}", chained.score);
}

#[test]
fn base58_rejected_when_zero_o_i_l_present() {
    let reg = registry();
    // Digits only with a '0' inside: 0/O/I/l are the base58 disqualifiers.
    // The gate must refuse to fire no matter how the ratios look.
    let input = b"1234567890123456";
    let candidates = auto_decode(&reg, input, &ExecutionContext::new());
    for c in &candidates {
        assert!(
            !c.path.iter().any(|p| p == "from-base58"),
            "data containing '0' must not be decoded as base58: {c:?}"
        );
    }
}

#[test]
fn single_layer_base36() {
    let reg = registry();
    let input = encode_with_op(&reg, "to-base36", b"flag{base36_roundtrip}");
    let candidates = auto_decode(&reg, input.as_bytes(), &ExecutionContext::new());
    let best = candidates
        .iter()
        .find(|c| c.path == vec!["from-base36"])
        .expect("base36 layer must be discovered");
    assert!(
        best.preview.contains("flag{base36_roundtrip}"),
        "preview {}",
        best.preview
    );
    assert!(best.confident, "score {}", best.score);
}

#[test]
fn random_alnum_data_is_not_confident() {
    let reg = registry();
    // Random alphanumeric text: the new alphabet gates (base62/91/64, ...)
    // all fire, but their decodes are arbitrary bytes — none may be called
    // confident, because these alphabets are weaker evidence than Base64.
    let mut seed = 0x5EEDC0DEu64;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let data: Vec<u8> = (0..512)
        .map(|_| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            alphabet[((seed >> 33) as usize) % alphabet.len()]
        })
        .collect();
    let candidates = auto_decode(&reg, &data, &ExecutionContext::new());
    for c in &candidates {
        assert!(
            !c.confident,
            "random alnum data produced a confident candidate: {c:?}"
        );
    }
}

#[test]
fn large_random_alnum_stays_bounded() {
    let reg = registry();
    // 16 KiB of random alnum text exceeds the bignum exploration cap, so the
    // O(n^2) base58/62/36 decodes must be skipped: bounded time, no confident
    // claims.
    let mut seed = 0xBADC0DEu64;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let data: Vec<u8> = (0..16 * 1024)
        .map(|_| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            alphabet[((seed >> 33) as usize) % alphabet.len()]
        })
        .collect();
    let started = std::time::Instant::now();
    let candidates = auto_decode(&reg, &data, &ExecutionContext::new());
    let elapsed = started.elapsed();
    assert!(elapsed.as_secs() < 10, "auto decode must stay bounded");
    for c in &candidates {
        assert!(
            !c.confident,
            "random data produced a confident candidate: {c:?}"
        );
    }
}
