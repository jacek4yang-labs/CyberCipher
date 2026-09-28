//! Recipe-execution benchmarks: cold vs warm (incremental cache) runs.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cybercipher_core::{ExecutionContext, OperationRegistry, ParamMap, Value};
use cybercipher_engine::{RecipeEngine, RecipeNodeV1, RecipeV1, RunMode};

fn node(id: &str, op: &str, params: &[(&str, &str)]) -> RecipeNodeV1 {
    let mut p = ParamMap::new();
    for (k, v) in params {
        p.insert(*k, *v);
    }
    RecipeNodeV1 {
        id: id.to_string(),
        op: op.to_string(),
        enabled: true,
        params: p,
    }
}

fn bench_recipe(c: &mut Criterion) {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);
    let reg = std::sync::Arc::new(reg);
    let engine = RecipeEngine::new(reg);
    let data: Vec<u8> = (0..=255u8).cycle().take(64 * 1024).collect();

    let recipe = RecipeV1::new(vec![
        node("s1", "to-base64", &[]),
        node("s2", "from-base64", &[]),
        node("s3", "to-hex", &[]),
        node("s4", "xor", &[("key", "37"), ("key_encoding", "hex")]),
    ]);
    let input = Value::Bytes(data.clone());

    let mut group = c.benchmark_group("recipe_64k");
    group.throughput(criterion::Throughput::Bytes(data.len() as u64));
    group.bench_function("four_stage_cold", |b| {
        b.iter(|| {
            let engine = RecipeEngine::new(cybercipher_engine::default_registry().into());
            engine.execute(
                black_box(&recipe),
                input.clone(),
                RunMode::Manual,
                &ExecutionContext::new(),
            )
        })
    });
    group.bench_function("four_stage_warm", |b| {
        b.iter(|| {
            engine.execute(
                black_box(&recipe),
                input.clone(),
                RunMode::Manual,
                &ExecutionContext::new(),
            )
        })
    });
    group.finish();
}

criterion_group!(benches, bench_recipe);
criterion_main!(benches);
