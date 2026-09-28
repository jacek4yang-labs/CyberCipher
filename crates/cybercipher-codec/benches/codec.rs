//! Hot-path benchmarks for codec operations (64 KiB payload).

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

fn bench_codec(c: &mut Criterion) {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);
    let data: Vec<u8> = (0..=255u8).cycle().take(64 * 1024).collect();
    let hex_text: String = data.iter().map(|b| format!("{b:02x}")).collect();

    let mut group = c.benchmark_group("codec_64k");
    group.throughput(criterion::Throughput::Bytes(data.len() as u64));
    group.bench_function("to_hex", |b| {
        b.iter(|| bench_op(&reg, "to-hex", &Value::Bytes(data.clone()), &[]))
    });
    group.bench_function("from_hex", |b| {
        b.iter(|| bench_op(&reg, "from-hex", &Value::Text(hex_text.clone()), &[]))
    });
    group.bench_function("to_base64", |b| {
        b.iter(|| bench_op(&reg, "to-base64", &Value::Bytes(data.clone()), &[]))
    });
    group.bench_function("xor_single_byte", |b| {
        b.iter(|| {
            bench_op(
                &reg,
                "xor",
                &Value::Bytes(data.clone()),
                &[
                    ("key", ParamValue::Str("5a".into())),
                    ("key_encoding", ParamValue::Str("hex".into())),
                ],
            )
        })
    });
    group.bench_function("entropy", |b| {
        b.iter(|| bench_op(&reg, "entropy", &Value::Bytes(data.clone()), &[]))
    });
    group.finish();
}

criterion_group!(benches, bench_codec);
criterion_main!(benches);
