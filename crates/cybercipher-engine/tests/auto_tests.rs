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
    // Text-oriented encoder ops reject bytes; feed Text when the payload is
    // valid UTF-8 and Bytes otherwise.
    let input = match std::str::from_utf8(data) {
        Ok(text) => Value::Text(text.to_owned()),
        Err(_) => Value::Bytes(data.to_vec()),
    };
    match op
        .execute(&input, &ParamMap::new(), &ExecutionContext::new())
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

// ================================================ v3 wrapper vocabulary ----

/// Like `encode_with_op`, for ops whose output is bytes (to-yenc, to-cbor,
/// to-msgpack, the compression encoders).
fn encode_bytes_with_op(reg: &OperationRegistry, op_id: &str, data: &[u8]) -> Vec<u8> {
    let op = reg
        .get(op_id)
        .unwrap_or_else(|| panic!("{op_id} must be registered"));
    // Text-oriented encoder ops reject bytes; feed Text when the payload is
    // valid UTF-8 and Bytes otherwise.
    let input = match std::str::from_utf8(data) {
        Ok(text) => Value::Text(text.to_owned()),
        Err(_) => Value::Bytes(data.to_vec()),
    };
    match op
        .execute(&input, &ParamMap::new(), &ExecutionContext::new())
        .expect("{op_id} must encode")
    {
        Value::Bytes(bytes) => bytes,
        other => panic!("{op_id} must produce bytes, got {}", other.kind().name()),
    }
}

fn find_candidate(
    reg: &OperationRegistry,
    input: &[u8],
    needle: &str,
) -> Option<cybercipher_engine::AutoCandidate> {
    let candidates = auto_decode(reg, input, &ExecutionContext::new());
    candidates
        .into_iter()
        .find(|c| c.path.iter().any(|p| p == needle))
}

fn assert_no_candidate_with(reg: &OperationRegistry, input: &[u8], needle: &str) {
    let candidates = auto_decode(reg, input, &ExecutionContext::new());
    for c in &candidates {
        assert!(
            !c.path.iter().any(|p| p == needle),
            "must not produce a `{needle}` candidate: {c:?}"
        );
    }
}

// ------------------------------------------------------ unicode escapes ----

#[test]
fn single_layer_unicode_escapes_u4() {
    let reg = registry();
    let input = br"flag{\u0061\u0062\u0063\u0064}";
    let c = find_candidate(&reg, input, "from-unicode-escapes").expect("unicode candidate");
    assert_eq!(c.path.first().unwrap(), "from-unicode-escapes");
    assert!(c.preview.contains("flag{abcd}"), "preview {}", c.preview);
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn single_layer_unicode_escapes_braced_and_x() {
    let reg = registry();
    let braced = br"flag{\u{61}\u{62}\u{63}\u{64}}";
    let c = find_candidate(&reg, braced, "from-unicode-escapes").expect("braced candidate");
    assert!(c.preview.contains("flag{abcd}"), "preview {}", c.preview);

    let x2 = br"flag{\x61\x62\x63\x64}";
    let c = find_candidate(&reg, x2, "from-unicode-escapes").expect("x2 candidate");
    assert!(c.preview.contains("flag{abcd}"), "preview {}", c.preview);
}

#[test]
fn unicode_escapes_inside_multilayer_chain() {
    let reg = registry();
    use base64::Engine as _;
    let inner = br"flag{\u00e9\u00e8\u00ea\u00e0}";
    let input = base64::engine::general_purpose::STANDARD.encode(inner);
    let candidates = auto_decode(&reg, input.as_bytes(), &ExecutionContext::new());
    let chained = candidates
        .iter()
        .find(|c| c.path == vec!["from-base64", "from-unicode-escapes"])
        .expect("base64->unicode chain must be discovered");
    assert!(
        chained.preview.contains("flag{éèêà}"),
        "preview {}",
        chained.preview
    );
    assert!(chained.confident, "score {}", chained.score);
}

#[test]
fn lone_unicode_escapes_do_not_fire() {
    let reg = registry();
    let input = br"Read \u0041 in the docs and compare with \u0042 there.";
    assert_no_candidate_with(&reg, input, "from-unicode-escapes");
}

// --------------------------------------------------------- html entities ----

#[test]
fn single_layer_html_named_entities() {
    let reg = registry();
    let input = b"flag{&amp;&lt;entities&gt;}";
    let c = find_candidate(&reg, input, "from-html-entities").expect("html candidate");
    assert_eq!(c.path.first().unwrap(), "from-html-entities");
    // &amp; decodes to a literal &, so the preview keeps it.
    assert!(
        c.preview.contains("flag{&<entities>}"),
        "preview {}",
        c.preview
    );
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn single_layer_html_numeric_entities() {
    let reg = registry();
    let input = b"&#72;&#101;&#108;&#108;&#111; &#x77;o&#x72;ld";
    let c = find_candidate(&reg, input, "from-html-entities").expect("html numeric candidate");
    assert!(c.preview.contains("Hello world"), "preview {}", c.preview);
}

#[test]
fn html_entities_inside_multilayer_chain() {
    let reg = registry();
    use base64::Engine as _;
    let inner = b"flag{&amp;ctf&amp;}";
    let input = base64::engine::general_purpose::STANDARD.encode(inner);
    let candidates = auto_decode(&reg, input.as_bytes(), &ExecutionContext::new());
    let chained = candidates
        .iter()
        .find(|c| c.path == vec!["from-base64", "from-html-entities"])
        .expect("base64->html chain must be discovered");
    assert!(
        chained.preview.contains("flag{&ctf&}"),
        "preview {}",
        chained.preview
    );
    assert!(chained.confident, "score {}", chained.score);
}

#[test]
fn lone_amp_entity_does_not_fire() {
    let reg = registry();
    assert_no_candidate_with(&reg, b"Fish &amp; Chips", "from-html-entities");
    assert_no_candidate_with(&reg, b"R&D and Q&A", "from-html-entities");
}

// ------------------------------------------------------ quoted printable ----

#[test]
fn single_layer_quoted_printable() {
    let reg = registry();
    let encoded = encode_with_op(&reg, "to-quoted-printable", b"flag{quoted}=FF=\xFE tail");
    let c =
        find_candidate(&reg, encoded.as_bytes(), "from-quoted-printable").expect("qp candidate");
    assert_eq!(c.path.first().unwrap(), "from-quoted-printable");
    assert!(c.preview.contains("flag{quoted}"), "preview {}", c.preview);
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn quoted_printable_soft_breaks() {
    let reg = registry();
    let input = b"flag{soft=\r\nbreaks} A=3D=42=43=44";
    let c = find_candidate(&reg, input, "from-quoted-printable").expect("qp soft break candidate");
    assert!(
        c.preview.contains("flag{softbreaks}"),
        "preview {}",
        c.preview
    );
}

#[test]
fn plain_equals_signs_do_not_fire_qp() {
    let reg = registry();
    assert_no_candidate_with(&reg, b"x=1 y=2 z=3 w=4", "from-quoted-printable");
    assert_no_candidate_with(&reg, b"a=b=c=d", "from-quoted-printable");
}

// ============================================================== punycode ----

#[test]
fn single_layer_punycode_ace() {
    let reg = registry();
    let input = b"xn--bcher-kva";
    let c = find_candidate(&reg, input, "from-punycode").expect("punycode candidate");
    assert_eq!(c.path.first().unwrap(), "from-punycode");
    assert!(c.preview.contains("bücher"), "preview {}", c.preview);
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn single_layer_punycode_domain() {
    let reg = registry();
    let input = b"xn--fiqs8s.cn";
    let c = find_candidate(&reg, input, "from-punycode").expect("punycode domain candidate");
    assert!(c.preview.contains("中国.cn"), "preview {}", c.preview);
}

#[test]
fn short_xn_prefix_does_not_fire_punycode() {
    let reg = registry();
    assert_no_candidate_with(&reg, b"see xn--ab online", "from-punycode");
    assert_no_candidate_with(&reg, b"nothing here at all", "from-punycode");
}

// ============================================================== uu / xx ----

#[test]
fn single_layer_uuencode() {
    let reg = registry();
    let input = encode_with_op(&reg, "to-uuencode", b"flag{uuencode_auto}");
    let c = find_candidate(&reg, input.as_bytes(), "from-uuencode").expect("uu candidate");
    assert_eq!(c.path.first().unwrap(), "from-uuencode");
    assert!(
        c.preview.contains("flag{uuencode_auto}"),
        "preview {}",
        c.preview
    );
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn uuencode_inside_multilayer_chain() {
    let reg = registry();
    use base64::Engine as _;
    let uu = encode_with_op(&reg, "to-uuencode", b"flag{uu_over_b64}");
    let input = base64::engine::general_purpose::STANDARD.encode(uu.as_bytes());
    let candidates = auto_decode(&reg, input.as_bytes(), &ExecutionContext::new());
    let chained = candidates
        .iter()
        .find(|c| c.path == vec!["from-base64", "from-uuencode"])
        .expect("base64->uu chain must be discovered");
    assert!(
        chained.preview.contains("flag{uu_over_b64}"),
        "preview {}",
        chained.preview
    );
    assert!(chained.confident, "score {}", chained.score);
    // The candidate path must replay through the recipe engine.
    let recipe = RecipeV1::new(
        chained
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
            Value::Bytes(input.as_bytes().to_vec()),
            RunMode::Manual,
            &ExecutionContext::new(),
        )
        .unwrap();
    assert!(report.error.is_none());
    // from-uuencode declares a Bytes output; the payload must roundtrip
    // byte-exact either way.
    let replayed = match report.output.unwrap() {
        Value::Text(text) => text.into_bytes(),
        Value::Bytes(bytes) => bytes,
        other => panic!("uu replay must produce text/bytes, {}", other.kind().name()),
    };
    assert!(String::from_utf8_lossy(&replayed).contains("flag{uu_over_b64}"));
}

#[test]
fn incomplete_uu_envelope_produces_no_candidate() {
    let reg = registry();
    // begin without end: the gate must not fire, the op must not be reached.
    assert_no_candidate_with(&reg, b"begin 644 f\n%9F]O\n", "from-uuencode");
    assert_no_candidate_with(&reg, b"begin 644 f\n%9F]O\n", "from-xxencode");
}

#[test]
fn single_layer_xxencode() {
    let reg = registry();
    let input = encode_with_op(&reg, "to-xxencode", b"flag{xxencode_auto}");
    let c = find_candidate(&reg, input.as_bytes(), "from-xxencode").expect("xx candidate");
    assert_eq!(c.path.first().unwrap(), "from-xxencode");
    assert!(
        c.preview.contains("flag{xxencode_auto}"),
        "preview {}",
        c.preview
    );
    assert!(c.confident, "score {}", c.score);
}

// ================================================================= yEnc ----

#[test]
fn single_layer_yenc() {
    let reg = registry();
    let input = encode_bytes_with_op(&reg, "to-yenc", b"flag{yenc_auto}");
    let c = find_candidate(&reg, &input, "from-yenc").expect("yenc candidate");
    assert_eq!(c.path.first().unwrap(), "from-yenc");
    assert!(
        c.preview.contains("flag{yenc_auto}"),
        "preview {}",
        c.preview
    );
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn incomplete_yenc_produces_no_candidate() {
    let reg = registry();
    // Header without the =yend trailer: gate fires, strict op fails, and no
    // relaxed guessing may produce a candidate.
    assert_no_candidate_with(
        &reg,
        b"=ybegin line=128 size=4 name=f\r\nJ;IJ\r\n",
        "from-yenc",
    );
}

// ============================================================ compression ----

#[test]
fn magic_gated_compression_layers() {
    let reg = registry();
    for (op, needle, marker) in [
        ("to-bzip2", "from-bzip2", "flag{bzip2_auto}"),
        ("to-xz", "from-xz", "flag{xz_auto}"),
        ("to-zstd", "from-zstd", "flag{zstd_auto}"),
        ("to-lz4", "from-lz4", "flag{lz4_auto}"),
    ] {
        let input = encode_bytes_with_op(&reg, op, marker.as_bytes());
        let c = find_candidate(&reg, &input, needle)
            .unwrap_or_else(|| panic!("{needle} candidate must be discovered"));
        assert!(c.preview.contains(marker), "{needle} preview {}", c.preview);
    }
}

#[test]
fn bzip2_inside_multilayer_chain() {
    let reg = registry();
    use base64::Engine as _;
    let bz2 = encode_bytes_with_op(&reg, "to-bzip2", b"flag{b64_over_bzip2}");
    let input = base64::engine::general_purpose::STANDARD.encode(&bz2);
    let candidates = auto_decode(&reg, input.as_bytes(), &ExecutionContext::new());
    let chained = candidates
        .iter()
        .find(|c| c.path == vec!["from-base64", "from-bzip2"])
        .expect("base64->bzip2 chain must be discovered");
    assert_eq!(chained.preview, "flag{b64_over_bzip2}");
    assert!(chained.confident, "score {}", chained.score);
}

// ============================================================= structured ----

#[test]
fn cbor_layer_detected_structurally() {
    let reg = registry();
    let input = encode_bytes_with_op(&reg, "to-cbor", br#"{"flag":"cbor_auto_layer"}"#);
    let c = find_candidate(&reg, &input, "from-cbor").expect("cbor candidate");
    assert_eq!(c.path.first().unwrap(), "from-cbor");
    assert!(
        c.preview.contains("cbor_auto_layer"),
        "preview {}",
        c.preview
    );
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn msgpack_layer_detected_structurally() {
    let reg = registry();
    let input = encode_bytes_with_op(&reg, "to-msgpack", br#"{"k":"flag{msgpack_auto}"}"#);
    let c = find_candidate(&reg, &input, "from-msgpack").expect("msgpack candidate");
    assert!(
        c.preview.contains("flag{msgpack_auto}"),
        "preview {}",
        c.preview
    );
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn random_binary_never_claimed_as_structured() {
    let reg = registry();
    let mut seed = 0xC0FFEEu64;
    let data: Vec<u8> = (0..4096)
        .map(|_| {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 33) as u8
        })
        .collect();
    let candidates = auto_decode(&reg, &data, &ExecutionContext::new());
    for c in &candidates {
        for op in [
            "from-cbor",
            "from-msgpack",
            "from-uuencode",
            "from-xxencode",
            "from-yenc",
            "from-unicode-escapes",
            "from-html-entities",
            "from-quoted-printable",
            "from-punycode",
            "run-brainfuck",
        ] {
            assert!(
                !c.path.contains(&op.to_string()),
                "random binary claimed as {op}: {c:?}"
            );
        }
        assert!(
            !c.confident,
            "random binary produced a confident claim: {c:?}"
        );
    }
}

// ============================================================== specialty ----

#[test]
fn buddha_layer_detected() {
    let reg = registry();
    let input = encode_with_op(&reg, "to-buddha", "flag{buddha_auto}".as_bytes());
    let c = find_candidate(&reg, input.as_bytes(), "from-buddha").expect("buddha candidate");
    assert!(
        c.preview.contains("flag{buddha_auto}"),
        "preview {}",
        c.preview
    );
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn bear_layer_detected() {
    let reg = registry();
    let input = encode_with_op(&reg, "to-bear", "flag{bear_auto}".as_bytes());
    let c = find_candidate(&reg, input.as_bytes(), "from-bear").expect("bear candidate");
    assert!(
        c.preview.contains("flag{bear_auto}"),
        "preview {}",
        c.preview
    );
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn core_values_layer_detected() {
    let reg = registry();
    let input = encode_with_op(&reg, "to-core-values", "flag{core_auto}".as_bytes());
    let c = find_candidate(&reg, input.as_bytes(), "from-core-values").expect("core candidate");
    assert!(
        c.preview.contains("flag{core_auto}"),
        "preview {}",
        c.preview
    );
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn brainfuck_layer_detected() {
    let reg = registry();
    let input = encode_with_op(&reg, "to-brainfuck", "flag{bf_auto}".as_bytes());
    let c = find_candidate(&reg, input.as_bytes(), "run-brainfuck").expect("bf candidate");
    assert!(c.preview.contains("flag{bf_auto}"), "preview {}", c.preview);
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn ook_layer_detected() {
    let reg = registry();
    let input = encode_with_op(&reg, "to-ook", "flag{ook_auto}".as_bytes());
    let c = find_candidate(&reg, input.as_bytes(), "from-ook").expect("ook candidate");
    assert!(
        c.preview.contains("flag{ook_auto}"),
        "preview {}",
        c.preview
    );
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn beast_layer_detected() {
    let reg = registry();
    let input = encode_with_op(&reg, "to-beast", "flag{beast_auto}".as_bytes());
    let c = find_candidate(&reg, input.as_bytes(), "from-beast").expect("beast candidate");
    assert!(
        c.preview.contains("flag{beast_auto}"),
        "preview {}",
        c.preview
    );
    assert!(c.confident, "score {}", c.score);
}

// ============================================================== classical ----

#[test]
fn rot13_flag_recovered() {
    let reg = registry();
    let input = b"synt{pnrfne_pvcure}";
    let c = find_candidate(&reg, input, "rot13").expect("rot13 candidate");
    assert_eq!(c.path.first().unwrap(), "rot13");
    assert_eq!(c.preview, "flag{caesar_cipher}");
    assert!(c.confident, "score {}", c.score);
    assert_eq!(c.flag_like.as_deref(), Some("flag{caesar_cipher}"));
}

#[test]
fn rot13_plain_english_not_proposed() {
    let reg = registry();
    assert_no_candidate_with(
        &reg,
        b"the quick brown fox jumps over the lazy dog again and again",
        "rot13",
    );
}

#[test]
fn atbash_flag_recovered() {
    let reg = registry();
    // banana atbash-encodes to yzmzmz (n <-> m, not n <-> n).
    let input = b"uozt{yzmzmz}";
    let c = find_candidate(&reg, input, "atbash").expect("atbash candidate");
    assert_eq!(c.preview, "flag{banana}");
    assert!(c.confident, "score {}", c.score);
}

#[test]
fn reversed_flag_recovered() {
    let reg = registry();
    let input = b"}otua_desrever{galf";
    let c = find_candidate(&reg, input, "reverse").expect("reverse candidate");
    assert_eq!(c.preview, "flag{reversed_auto}");
    assert!(c.confident, "score {}", c.score);
    assert_eq!(c.flag_like.as_deref(), Some("flag{reversed_auto}"));
}

#[test]
fn plain_reversed_prose_does_not_fire_reverse() {
    let reg = registry();
    assert_no_candidate_with(&reg, b"}dlrow olleh", "reverse");
}

// ============================================== bounds & pathological ----

#[test]
fn nested_html_layers_recover_at_depth() {
    let reg = registry();
    // Five successive HTML-escaping layers; each keeps two entity groups.
    let mut current = b"flag{&&}".to_vec();
    for _ in 0..5 {
        current = encode_with_op(&reg, "to-html-entities", &current).into_bytes();
    }
    let started = std::time::Instant::now();
    let candidates = auto_decode(&reg, &current, &ExecutionContext::new());
    assert!(started.elapsed().as_secs() < 10, "must stay bounded");
    let best = candidates
        .iter()
        .find(|c| c.path.len() == 5 && c.path.iter().all(|p| p == "from-html-entities"))
        .expect("the five-layer decode must be among the candidates");
    assert_eq!(best.preview, "flag{&&}");
}

#[test]
fn pathological_unicode_escape_wall_stays_bounded() {
    let reg = registry();
    // 64 KiB of \u0041 escapes: the gate fires on ~10k escapes and the
    // decode must complete within the deadline budget without exploding.
    let mut input = Vec::with_capacity(64 * 1024);
    for _ in 0..64 * 1024 / 6 {
        input.extend_from_slice(b"\\u0041");
    }
    let started = std::time::Instant::now();
    let candidates = auto_decode(&reg, &input, &ExecutionContext::new());
    assert!(started.elapsed().as_secs() < 10, "must stay bounded");
    assert!(
        candidates
            .iter()
            .any(|c| c.path.contains(&"from-unicode-escapes".to_string())),
        "the escape wall must decode"
    );
}

// ---------------------------------------------------- polluted hex tail ----

/// Regression (user-reported bake failure): b64 -> b64 -> hex whose tail
/// carries ONE junk character ('J' after the "==" padding, encoded as 3d3d).
/// The strict hex gate refuses it; the relaxed step must recover the chain:
/// b64 -> b64 -> from-hex(relaxed) -> from-base64 -> payload text.
#[test]
fn polluted_hex_tail_recovers_via_relaxed_step() {
    let reg = registry();
    let input = b"TlRRME5EWTROR1ExTnpVMk5EWXpORFUzTlRRMU1qVXhOR1UyWkRaak4yRTJNalU0Tm1Jek1UVXpObVUwWlRSak5UVTFOVFEyTmprMk16WmpOalEyWkRVeU5tVTBOak16TlRFek1UWmpOemsyTXpVM05UWTJZVFJsTkRZMFlUUmpOalUwTlRVeE16VTFNalpsTm1NME16VTNObVF6T1RVeU5XRTFOVE0wTXpJMk1UVTFORFkwTWpWaE5EVTNPRFExTlRZek1ETTFOMkUxTlRVNE5HRXpOVFJsTXpNMVlUUmtOalUwTnpVMk16STFORFUxTXpFMk9EVmhORFUxTWpjMU5qSXpNamMwTlRVMU1UWmxORFV6TVRVMU16QTBOalUzTlRJMU56VXlOemMyTVRkaE5qZzBPVFJsTlRVek1UTXlOakkxTmpaaU16STFNak16Tm1Zek1qVXpORGcyT0RabE5UYzFOalppTjJFMk1UWmtOamcwWlRVek16RTJZamM0TlRVek1EY3dOekUxTmpRM05URTNPRFl4Tm1VMk5EUTNOR1kxT0Raak5qZzFOelUyTlRZM01qVXhOVGcyTXpkaE5qTTJZalk0TmpFMFpUWmtOalEyWWpVMU5EYzFZVFUzTmpNek1qY3dObUkyTVRaaU5USTFOVFUxTnpjelpETks=";
    let candidates = auto_decode(&reg, input, &ExecutionContext::new());
    let relaxed = candidates
        .iter()
        .find(|c| c.path.contains(&"from-hex".to_string()) && c.path.len() >= 3)
        .expect("relaxed-hex must continue the chain past the junk tail");
    // The relaxed step's evidence must say what was ignored — no silent fixes.
    let relaxed_idx = relaxed
        .path
        .iter()
        .position(|p| p == "from-hex")
        .unwrap();
    assert!(
        relaxed.evidence.iter().any(|e| e.contains("trailing junk")),
        "evidence must name the relaxed handling: {:?}",
        relaxed.evidence
    );
    let _ = relaxed_idx;
    // The chain continues past the hex layer into another base64 layer.
    assert!(
        relaxed.path.len() >= 4,
        "chain must continue: {:?}",
        relaxed.path
    );
    // The final payload is printable text (the recovered answer).
    assert!(relaxed.is_utf8, "payload {}", relaxed.preview);
}
