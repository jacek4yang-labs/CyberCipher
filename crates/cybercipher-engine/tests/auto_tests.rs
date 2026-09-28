//! Auto Decode corpus tests: single-layer, multi-layer, compressed, binary,
//! false-positive traps, and random data. These encode the charter's corpus
//! requirements for Milestone 3.

#![allow(clippy::result_large_err)]

use cybercipher_core::{ExecutionContext, OperationRegistry, Value};
use cybercipher_engine::{
    auto_decode, default_registry, RecipeEngine, RecipeNodeV1, RecipeV1, RunMode,
};
use std::io::Write;

fn registry() -> OperationRegistry {
    default_registry()
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
