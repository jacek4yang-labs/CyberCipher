//! Hot-path benchmarks for crypto operations (64 KiB payload).

use criterion::{criterion_group, criterion_main, Criterion};
use cybercipher_core::{ExecutionContext, OperationRegistry, ParamMap, ParamValue, Value};

fn bench_op(reg: &OperationRegistry, id: &str, input: &Value, params: &[(&str, ParamValue)]) {
    let op = reg.get(id).unwrap();
    let mut map = ParamMap::new();
    for (k, v) in params {
        map.insert(*k, v.clone());
    }
    op.execute(input, &map, &ExecutionContext::new()).unwrap();
}

fn pv(params: &[(&'static str, &str)]) -> Vec<(&'static str, ParamValue)> {
    params
        .iter()
        .map(|(k, v)| (*k, ParamValue::Str(v.to_string())))
        .collect()
}

fn bench_crypto(c: &mut Criterion) {
    let mut reg = OperationRegistry::new();
    cybercipher_crypto::register_all(&mut reg);
    let data: Vec<u8> = (0..=255u8).cycle().take(64 * 1024).collect();

    let mut group = c.benchmark_group("crypto_64k");
    group.throughput(criterion::Throughput::Bytes(data.len() as u64));
    group.bench_function("aes128_cbc_encrypt", |b| {
        b.iter(|| {
            bench_op(
                &reg,
                "aes-encrypt",
                &Value::Bytes(data.clone()),
                &pv(&[
                    ("key", "2b7e151628aed2a6abf7158809cf4f3c"),
                    ("key_encoding", "hex"),
                    ("mode", "cbc"),
                    ("iv", "000102030405060708090a0b0c0d0e0f"),
                    ("padding", "pkcs7"),
                ]),
            )
        })
    });
    group.bench_function("sha256", |b| {
        b.iter(|| bench_op(&reg, "sha256", &Value::Bytes(data.clone()), &[]))
    });
    group.bench_function("hmac_sha256", |b| {
        b.iter(|| {
            bench_op(
                &reg,
                "hmac",
                &Value::Bytes(data.clone()),
                &pv(&[
                    ("key", "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                    ("algorithm", "sha256"),
                ]),
            )
        })
    });
    group.bench_function("rc4", |b| {
        b.iter(|| {
            bench_op(
                &reg,
                "rc4",
                &Value::Bytes(data.clone()),
                &pv(&[("key", "0102030405")]),
            )
        })
    });
    group.finish();
}

criterion_group!(benches, bench_crypto);
criterion_main!(benches);
