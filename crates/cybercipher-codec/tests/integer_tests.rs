//! BigInt operation tests (M4-CORE-01 acceptance).

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

fn pv(params: &[(&'static str, &str)]) -> Vec<(&'static str, ParamValue)> {
    params
        .iter()
        .map(|(k, v)| (*k, ParamValue::Str(v.to_string())))
        .collect()
}

#[test]
fn text_decimal_and_hex_roundtrip() {
    let reg = reg();
    // 256-bit value must survive exactly (no f64 involvement).
    let dec = "115792089237316195423570985008687907853269984665640564039457584007913129639936"; // 2^256
    let out = run(&reg, "to-integer", Value::Text(dec.to_string()), &[]).unwrap();
    match &out {
        Value::Integer(i) => {
            assert_eq!(i.to_string(), dec);
            assert_eq!(i.bits(), 257);
        }
        other => panic!("expected integer, got {other:?}"),
    }
    let back = run(&reg, "from-integer", out, &pv(&[("output", "decimal")])).unwrap();
    assert_eq!(back, Value::Text(dec.to_string()));

    let out = run(
        &reg,
        "to-integer",
        Value::Text("0xdeadbeef".to_string()),
        &[],
    )
    .unwrap();
    let hex = run(&reg, "from-integer", out, &pv(&[("output", "hex")])).unwrap();
    assert_eq!(hex, Value::Text("deadbeef".to_string()));
}

#[test]
fn bytes_roundtrip_endianness_and_sign() {
    let reg = reg();
    let bytes = vec![0x01, 0x02, 0x03, 0x04];
    let out = run(&reg, "to-integer", Value::Bytes(bytes.clone()), &[]).unwrap();
    let back = run(&reg, "from-integer", out, &pv(&[("output", "bytes")])).unwrap();
    assert_eq!(back, Value::Bytes(bytes));

    // Little endian: byte order flips.
    let out = run(
        &reg,
        "to-integer",
        Value::Bytes(vec![1, 0]),
        &[("byteorder", ParamValue::Str("little".into()))],
    )
    .unwrap();
    assert!(matches!(&out, Value::Integer(i) if *i == 1.into()));

    // Signed negative: -1 as one signed byte = 0xff.
    let out = run(
        &reg,
        "to-integer",
        Value::Bytes(vec![0xff]),
        &[("signed", ParamValue::Bool(true))],
    )
    .unwrap();
    assert!(matches!(&out, Value::Integer(i) if i.to_string() == "-1"));
    let back = run(
        &reg,
        "from-integer",
        out,
        &[
            ("output", ParamValue::Str("bytes".into())),
            ("signed", ParamValue::Bool(true)),
        ],
    )
    .unwrap();
    assert_eq!(back, Value::Bytes(vec![0xff]));
}

#[test]
fn min_length_padding() {
    let reg = reg();
    let out = run(&reg, "to-integer", Value::Text("255".to_string()), &[]).unwrap();
    let back = run(
        &reg,
        "from-integer",
        out,
        &[
            ("output", ParamValue::Str("bytes".into())),
            ("min_length", ParamValue::Int(4)),
        ],
    )
    .unwrap();
    assert_eq!(back, Value::Bytes(vec![0, 0, 0, 0xff]));
}

#[test]
fn invalid_integers_report_diagnostics() {
    let reg = reg();
    let err = run(&reg, "to-integer", Value::Text("12x4".to_string()), &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Decode);

    // from-integer on non-integer input is a typed InvalidInput.
    let err = run(&reg, "from-integer", Value::Text("5".to_string()), &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidInput);
    assert_eq!(err.expected.as_deref(), Some("integer"));
}

#[test]
fn engine_transports_big_ints_without_precision_loss() {
    // Recipe: to-integer → from-integer (decimal) on a 300-bit number.
    let engine = cybercipher_engine::RecipeEngine::new(std::sync::Arc::new(
        cybercipher_engine::default_registry(),
    ));
    let mk = |op: &str| cybercipher_engine::RecipeNodeV1 {
        id: op.replace('-', "_"),
        op: op.to_string(),
        enabled: true,
        params: ParamMap::new(),
    };
    let mut from = mk("from-integer");
    from.params
        .insert("output", ParamValue::Str("decimal".into()));
    let recipe = cybercipher_engine::RecipeV1::new(vec![mk("to-integer"), from]);
    let input = "123456789012345678901234567890123456789012345678901234567890".to_string();
    let report = engine
        .execute(
            &recipe,
            Value::Text(input.clone()),
            cybercipher_engine::RunMode::Manual,
            &ExecutionContext::new(),
        )
        .unwrap();
    assert!(report.error.is_none(), "{:?}", report.error);
    match report.output {
        Some(Value::Text(t)) => assert_eq!(t, input),
        other => panic!("unexpected output {other:?}"),
    }
}
