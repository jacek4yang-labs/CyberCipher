//! Registry-level coverage for the batch D digest ops: every id is
//! registered with the shared hash factory, Text input matches Bytes input,
//! and unknown hash ids surface typed errors.

// See cybercipher-core/src/lib.rs for the rationale.
#![allow(clippy::result_large_err)]

use cybercipher_core::prelude::*;
use cybercipher_core::OperationRegistry;

const BATCH_D_IDS: &[&str] = &[
    "md2",
    "tiger",
    "streebog-256",
    "streebog-512",
    "gost94",
    "shabal",
    "groestl-256",
    "groestl-512",
];

fn reg() -> OperationRegistry {
    let mut r = OperationRegistry::new();
    cybercipher_crypto::register_all(&mut r);
    r
}

fn run(
    reg: &OperationRegistry,
    id: &str,
    input: &Value,
    params: &[(&'static str, ParamValue)],
) -> OpResult<Value> {
    let op = reg.get(id).unwrap_or_else(|| panic!("missing op {id}"));
    let mut map = ParamMap::new();
    for (k, v) in params {
        map.insert(*k, v.clone());
    }
    op.execute(input, &map, &ExecutionContext::new())
}

fn s(v: &Value) -> String {
    match v {
        Value::Text(t) => t.clone(),
        Value::Bytes(b) => b.iter().map(|x| format!("{x:02x}")).collect(),
        other => panic!("unexpected value {other:?}"),
    }
}

#[test]
fn batch_d_hashes_registered_and_kat_on_abc() {
    // The "abc" digest of each family must equal the value produced by the
    // shared digest_bytes path (exercised with official vectors in the lib
    // tests); here we pin the registry wiring itself.
    let r = reg();
    let abc = Value::Bytes(b"abc".to_vec());
    for id in BATCH_D_IDS {
        let op = r
            .get(id)
            .unwrap_or_else(|| panic!("missing batch D hash op {id}"));
        assert_eq!(op.spec().category, Category::Hash, "{id}");
        let out = run(&r, id, &abc, &[]).unwrap();
        assert!(!s(&out).is_empty(), "{id} empty digest");
    }
    // Spot-check two official vectors end-to-end through the registry.
    let md2_abc = run(&r, "md2", &abc, &[]).unwrap();
    assert_eq!(
        s(&md2_abc),
        "da853b0d3f88d99b30283a69e6ded6bb",
        "RFC 1319 test suite MD2(abc)"
    );
    let gost94_empty = run(&r, "gost94", &Value::Bytes(Vec::new()), &[]).unwrap();
    assert_eq!(
        s(&gost94_empty),
        "ce85b99cc46752fffee35cab9a7b0278abb4c2d2055cff685af4912c49490f8d",
        "GOST R 34.11-94 test-parameter empty vector"
    );
}

#[test]
fn batch_d_hashes_text_and_bytes_agree() {
    let r = reg();
    for id in BATCH_D_IDS {
        let as_bytes = run(&r, id, &Value::Bytes(b"message".to_vec()), &[]).unwrap();
        let as_text = run(&r, id, &Value::Text("message".to_string()), &[]).unwrap();
        assert_eq!(as_bytes, as_text, "{id} Text == Bytes");
    }
}

#[test]
fn batch_d_hash_security_labels_and_provenance() {
    // Broken digests must be labeled Broken so the UI can warn; modern
    // national-standard digests must cite their standard.
    let r = reg();
    let md2 = r.get("md2").unwrap();
    assert_eq!(md2.spec().security, Security::Broken);
    let gost94 = r.get("gost94").unwrap();
    assert_eq!(gost94.spec().security, Security::Broken);
    for id in ["streebog-256", "streebog-512", "groestl-256", "groestl-512"] {
        let op = r.get(id).unwrap();
        assert_eq!(op.spec().security, Security::Modern, "{id}");
        assert!(
            !op.spec().provenance.test_vectors.is_empty(),
            "{id} must cite test vectors"
        );
    }
}

#[test]
fn batch_d_hashes_reject_non_byte_inputs() {
    let r = reg();
    let err = run(&r, "md2", &Value::Integer(5.into()), &[]).unwrap_err();
    assert_eq!(err.kind, ErrorKind::InvalidInput);
    assert!(err
        .expected
        .as_deref()
        .unwrap_or_default()
        .contains("bytes"));
}
