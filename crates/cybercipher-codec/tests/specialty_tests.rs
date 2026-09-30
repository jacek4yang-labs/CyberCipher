//! Registry-level round-trip and known-answer tests for the CTF specialty
//! codecs (Brainfuck/Ook!, Buddha, new Buddha, beast speak, bear, socialist
//! core values, AAEncode, JJEncode).
//!
//! Provenance for every pinned vector is cited in the test comments and in
//! the op metadata (see crates/cybercipher-codec/src/specialty.rs).

// See cybercipher-core/src/lib.rs for the rationale.
#![allow(clippy::result_large_err)]

use cybercipher_core::prelude::*;
use cybercipher_core::OperationRegistry;

fn reg() -> OperationRegistry {
    let mut r = OperationRegistry::new();
    cybercipher_codec::register_all(&mut r);
    r
}

fn run(
    reg: &OperationRegistry,
    id: &str,
    input: Value,
    params: &[(&'static str, ParamValue)],
) -> OpResult<Value> {
    let op = reg.get(id).unwrap_or_else(|| panic!("missing op {id}"));
    let mut map = ParamMap::new();
    for (k, v) in params {
        map.insert(*k, v.clone());
    }
    op.execute(&input, &map, &ExecutionContext::new())
}

fn run_text(reg: &OperationRegistry, id: &str, input: &str) -> OpResult<Value> {
    run(reg, id, Value::Text(input.to_string()), &[])
}

fn text_of(out: Value) -> String {
    match out {
        Value::Text(t) => t,
        Value::Bytes(b) => String::from_utf8(b).expect("output is not UTF-8"),
        other => panic!("expected text-like output, got {other:?}"),
    }
}

fn expect_err(out: OpResult<Value>, needle: &str) -> OperationError {
    let err = out.expect_err("expected an error");
    assert!(
        err.message.contains(needle),
        "error `{}` does not contain `{needle}`",
        err.message
    );
    err
}

// -------------------------------------------------------- registry ----

#[test]
fn specialty_ops_are_registered() {
    let r = reg();
    for id in [
        "run-brainfuck",
        "to-brainfuck",
        "from-ook",
        "to-ook",
        "to-buddha",
        "from-buddha",
        "to-buddha-pbe",
        "from-buddha-pbe",
        "to-beast",
        "from-beast",
        "to-bear",
        "from-bear",
        "to-core-values",
        "from-core-values",
        "from-aaencode",
        "from-jjencode",
    ] {
        let op = r.get(id).unwrap_or_else(|| panic!("missing op {id}"));
        assert_eq!(op.spec().cost, CostClass::Instant);
        assert_eq!(op.spec().category, Category::Classical);
        assert!(op.spec().tags.contains(&"ctf"), "{id} missing ctf tag");
        assert!(
            op.spec().tags.contains(&"specialty"),
            "{id} missing specialty tag"
        );
    }
}

// ------------------------------------------------------ brainfuck ----

#[test]
fn brainfuck_registry_roundtrip() {
    let r = reg();
    let program = text_of(run_text(&r, "to-brainfuck", "registry round trip!").unwrap());
    let out = run(
        &r,
        "run-brainfuck",
        Value::Text(program),
        &[("input", ParamValue::Str(String::new()))],
    )
    .unwrap();
    assert_eq!(text_of(out.unwrap()), "registry round trip!");
}

#[test]
fn brainfuck_hello_world_via_registry() {
    let r = reg();
    let program = "++++++++[>++++[>++>+++>+++>+<<<<-]>+>+>->>+[<]<-]>>.>---.+++++++\
                   ..+++.>>.<-.<.+++.------.--------.>>+.>++.";
    let out = run_text(&r, "run-brainfuck", program).unwrap();
    assert_eq!(text_of(out.unwrap()), "Hello World!\n");
}

#[test]
fn brainfuck_step_limit_via_registry() {
    let r = reg();
    let err = run_text(&r, "run-brainfuck", "+[]").unwrap_err();
    assert_eq!(err.kind, ErrorKind::BudgetExceeded);
}

#[test]
fn ook_registry_roundtrip() {
    let r = reg();
    let ook = text_of(run_text(&r, "to-ook", "Ook round trip\n").unwrap());
    let out = run_text(&r, "from-ook", &ook).unwrap();
    assert_eq!(text_of(out.unwrap()), "Ook round trip\n");
}

// -------------------------------------------------------- buddha ----

#[test]
fn buddha_registry_roundtrip() {
    let r = reg();
    for text in ["与佛论禅", "Buddha says: 佛曰 123"] {
        let enc = run_text(&r, "to-buddha", text).unwrap();
        let dec = run_text(&r, "from-buddha", &text_of(enc.unwrap())).unwrap();
        assert_eq!(text_of(dec), *text);
    }
}

#[test]
fn buddha_reference_vector_via_registry() {
    let r = reg();
    // ToolsFx BuddhaTest.kt: github.com/Leon406/ToolsFx
    let out = run_text(
        &r,
        "from-buddha",
        "佛曰：冥耶以缽醯以梵蘇心缽參哆能哆他多罰姪實悉那遮奢三",
    )
    .unwrap();
    assert_eq!(text_of(out), "与佛论禅666");
}

#[test]
fn buddha_pbe_registry_roundtrip() {
    let r = reg();
    let enc = run(
        &r,
        "to-buddha-pbe",
        Value::Text("新佛曰 pbe".into()),
        &[
            ("password", ParamValue::Str("takuron.top".into())),
            ("salt", ParamValue::Str("0102030405060708".into())),
        ],
    )
    .unwrap();
    let dec = run(
        &r,
        "from-buddha-pbe",
        enc,
        &[("password", ParamValue::Str("takuron.top".into()))],
    )
    .unwrap();
    assert_eq!(text_of(dec), "新佛曰 pbe");
}

// ---------------------------------------------------------- beast ----

#[test]
fn beast_registry_roundtrip() {
    let r = reg();
    let enc = run_text(&r, "to-beast", "兽音译者 beast").unwrap();
    let dec = run_text(&r, "from-beast", &text_of(enc.unwrap())).unwrap();
    assert_eq!(text_of(dec), "兽音译者 beast");
}

#[test]
fn beast_custom_codec() {
    let r = reg();
    let codec = [("codec", ParamValue::Str("叮咚嘟锵".into()))];
    let enc = run(&r, "to-beast", Value::Text("音音".into()), &codec).unwrap();
    let dec = run(&r, "from-beast", enc, &codec).unwrap();
    assert_eq!(text_of(dec), "音音");
}

// ----------------------------------------------------------- bear ----

#[test]
fn bear_registry_roundtrip() {
    let r = reg();
    let enc = text_of(run_text(&r, "to-bear", "熊曰 round trip").unwrap());
    assert!(enc.starts_with("熊曰：呋"));
    let dec = run_text(&r, "from-bear", &enc).unwrap();
    assert_eq!(text_of(dec), "熊曰 round trip");
}

#[test]
fn bear_reference_vector_via_registry() {
    let r = reg();
    // ToolsFx wiki CTF.md 熊曰 sample (a greasyfork userscript link).
    let out = run_text(
        &r,
        "from-bear",
        "熊曰：呋性呱吖萌盜性森破捕訴嗒喜冬呱唬嗡盜偶哈魚嗥麼噔囑襲達嗥取喜捕嘿家咬嗡性既洞喜達嗒嘿沒類嚁麼常哈現襲啽樣動你嗅嘍嗚爾現氏蜜動眠常嗡嗥破住啽嗥囑更沒常破嘍森唬偶嗅人氏拙怎噔雜很誒",
    )
    .unwrap();
    assert_eq!(
        text_of(out),
        "https://greasyfork.org/zh-CN/scripts/439266-网盘有效性检查"
    );
}

// --------------------------------------------------- core values ----

#[test]
fn core_values_registry_roundtrip() {
    let r = reg();
    let enc = run_text(&r, "to-core-values", "core values 42").unwrap();
    let dec = run_text(&r, "from-core-values", &text_of(enc.unwrap())).unwrap();
    assert_eq!(text_of(dec), "core values 42");
}

#[test]
fn core_values_reference_vector_via_registry() {
    let r = reg();
    // ToolsFx wiki CTF.md socialCoreValue sample.
    let out = run_text(
        &r,
        "from-core-values",
        "公正爱国公正平等公正诚信文明公正诚信文明公正诚信平等友善爱国平等诚信民主诚信文明爱国富强友善爱国平等爱国诚信平等敬业民主诚信自由平等友善平等法治诚信富强平等友善爱国平等爱国平等诚信民主法治诚信自由法治友善自由友善爱国友善平等民主",
    )
    .unwrap();
    assert_eq!(text_of(out), "hello开发工具箱");
}

// -------------------------------------------------------- aaencode ----

#[test]
fn aaencode_reference_sample_via_registry() {
    let r = reg();
    let sample = include_str!("../vectors/specialty/aa_sample_alert.txt");
    let out = run_text(&r, "from-aaencode", sample).unwrap();
    assert_eq!(text_of(out), "alert(\"Hello, JavaScript\")");
}

#[test]
fn aaencode_rejects_plain_js() {
    let r = reg();
    expect_err(run_text(&r, "from-aaencode", "alert(1);"), "not AAEncode");
}

// -------------------------------------------------------- jjencode ----

#[test]
fn jjencode_reference_sample_via_registry() {
    let r = reg();
    let sample = include_str!("../vectors/specialty/jj_sample_alert.txt");
    let out = run_text(&r, "from-jjencode", sample).unwrap();
    assert_eq!(text_of(out), "alert(\"Hello, JavaScript\")");
}

#[test]
fn jjencode_rejects_plain_js() {
    let r = reg();
    expect_err(run_text(&r, "from-jjencode", "alert(1);"), "not JJEncode");
}

#[test]
fn specialty_no_duplicate_op_ids() {
    // register_all panics on duplicates by design; a second registration of
    // the full set into a fresh registry must succeed.
    let mut r = OperationRegistry::new();
    cybercipher_codec::register_all(&mut r);
    assert!(r.len() > 100);
}
