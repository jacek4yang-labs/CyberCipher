//! Engine behavior tests: incremental caching, cost gating, cancellation,
//! panic isolation, and end-to-end recipe execution.

// See cybercipher-core/src/lib.rs for the rationale.
#![allow(clippy::result_large_err)]

use cybercipher_core::prelude::*;
use cybercipher_core::{ExecutionContext, OperationRegistry, ParamMap, Value};
use cybercipher_engine::{RecipeEngine, RecipeNodeV1, RecipeV1, RunMode};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

fn node(id: &str, op: &str) -> RecipeNodeV1 {
    RecipeNodeV1 {
        id: id.to_string(),
        op: op.to_string(),
        enabled: true,
        params: ParamMap::new(),
    }
}

fn node_with(id: &str, op: &str, params: &[(&str, ParamValue)]) -> RecipeNodeV1 {
    RecipeNodeV1 {
        id: id.to_string(),
        op: op.to_string(),
        enabled: true,
        params: params
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
    }
}

fn engine() -> RecipeEngine {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);
    RecipeEngine::new(Arc::new(reg))
}

fn run(
    engine: &RecipeEngine,
    recipe: &RecipeV1,
    input: Value,
    mode: RunMode,
    cancel: Option<Arc<AtomicBool>>,
) -> cybercipher_engine::ExecutionReport {
    let ctx = match cancel {
        Some(flag) => ExecutionContext::new().with_cancel(flag),
        None => ExecutionContext::new(),
    };
    engine
        .execute(recipe, input, mode, &ctx)
        .expect("structural error")
}

#[test]
fn executes_linear_recipe_in_order() {
    let engine = engine();
    // "hi" -> to-hex -> from-hex -> to-base64
    let recipe = RecipeV1::new(vec![
        node("s1", "to-hex"),
        node("s2", "from-hex"),
        node("s3", "to-base64"),
    ]);
    let report = run(
        &engine,
        &recipe,
        Value::Text("hi".into()),
        RunMode::Manual,
        None,
    );
    assert!(report.error.is_none(), "{:?}", report.error);
    assert_eq!(report.output, Some(Value::Text("aGk=".into())));
    assert_eq!(report.stages.len(), 3);
    assert!(report
        .stages
        .iter()
        .all(|s| s.status == cybercipher_engine::StageStatus::Ok));
}

#[test]
fn second_run_hits_cache() {
    let engine = engine();
    let recipe = RecipeV1::new(vec![node("s1", "to-hex"), node("s2", "to-base64")]);
    let input = Value::Text("cache me".into());

    let r1 = run(&engine, &recipe, input.clone(), RunMode::Manual, None);
    assert_eq!(r1.cached_stages, 0);

    let r2 = run(&engine, &recipe, input, RunMode::Manual, None);
    assert_eq!(r2.cached_stages, 2, "all stages should be cached");
    assert!(r2
        .stages
        .iter()
        .all(|s| s.status == cybercipher_engine::StageStatus::Cached));
}

#[test]
fn param_change_invalidates_only_downstream() {
    let engine = engine();
    let mk = |xor_key: &str| {
        RecipeV1::new(vec![
            node("s1", "to-hex"),
            node_with(
                "s2",
                "xor",
                &[
                    ("key", ParamValue::Str(xor_key.into())),
                    ("key_encoding", ParamValue::Str("hex".into())),
                ],
            ),
            node("s3", "to-base64"),
        ])
    };
    let input = Value::Text("abc".into());

    let _ = run(&engine, &mk("00"), input.clone(), RunMode::Manual, None);
    // Change only the middle stage: s1 stays cached, s2/s3 recompute.
    let r2 = run(&engine, &mk("ff"), input, RunMode::Manual, None);
    assert_eq!(r2.cached_stages, 1, "first stage should be cached");
    assert_eq!(r2.stages[0].status, cybercipher_engine::StageStatus::Cached);
    assert_eq!(r2.stages[1].status, cybercipher_engine::StageStatus::Ok);
    assert_eq!(r2.stages[2].status, cybercipher_engine::StageStatus::Ok);
}

#[test]
fn disabled_nodes_pass_through_and_invalidate_downstream() {
    let engine = engine();
    let mut recipe = RecipeV1::new(vec![node("s1", "to-hex"), node("s2", "to-base64")]);
    let input = Value::Text("xyz".into());
    let _ = run(&engine, &recipe, input.clone(), RunMode::Manual, None);

    recipe.nodes[0].enabled = false;
    let r2 = run(&engine, &recipe, input, RunMode::Manual, None);
    assert_eq!(
        r2.stages[0].status,
        cybercipher_engine::StageStatus::Skipped
    );
    // Downstream stage must not be served from the previous (enabled) run.
    assert_eq!(r2.stages[1].status, cybercipher_engine::StageStatus::Ok);
    // Output equals base64 of raw "xyz" (hex stage skipped).
    assert_eq!(report_output_text(&r2), "eHl6");
}

fn report_output_text(report: &cybercipher_engine::ExecutionReport) -> String {
    match &report.output {
        Some(Value::Text(t)) => t.clone(),
        other => panic!("expected text output, got {other:?}"),
    }
}

#[test]
fn auto_mode_blocks_heavy_operations() {
    // Build a registry with a Heavy test-only op.
    static HEAVY_SPEC: OperationSpec = OperationSpec {
        id: "test-heavy",
        name: "Test Heavy",
        description: "cost class test",
        category: Category::Utility,
        input_kinds: &[ValueKind::Bytes, ValueKind::Text],
        output_kind: ValueKind::Bytes,
        params: &[],
        cost: CostClass::Heavy,
        security: Security::Neutral,
        deterministic: true,
        reversible: false,
        aliases: &[],
        tags: &[],
        provenance: Provenance::PROJECT,
    };
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);
    reg.add_simple(&HEAVY_SPEC, |v, _, _| {
        Ok(Value::Bytes(
            v.as_bytes().map(|c| c.to_vec()).unwrap_or_default(),
        ))
    });
    let engine = RecipeEngine::new(Arc::new(reg));

    let recipe = RecipeV1::new(vec![node("s1", "to-hex"), node("s2", "test-heavy")]);
    let report = run(
        &engine,
        &recipe,
        Value::Text("abc".into()),
        RunMode::Auto,
        None,
    );
    assert_eq!(report.blocked_at.as_deref(), Some("s2"));
    assert!(report.error.is_none());
    // Stage 1 executed, heavy stage did not.
    assert_eq!(report.stages.len(), 1);

    // Manual mode runs it.
    let report = run(
        &engine,
        &recipe,
        Value::Text("abc".into()),
        RunMode::Manual,
        None,
    );
    assert!(report.blocked_at.is_none());
    assert_eq!(report.stages.len(), 2);
}

#[test]
fn cancellation_stops_execution() {
    let engine = engine();
    let recipe = RecipeV1::new(vec![node("s1", "to-hex"), node("s2", "to-base64")]);
    let flag = Arc::new(AtomicBool::new(false));
    flag.store(true, Ordering::Relaxed);
    let report = run(
        &engine,
        &recipe,
        Value::Text("abc".into()),
        RunMode::Manual,
        Some(flag),
    );
    let err = report.error.expect("expected cancellation error");
    assert_eq!(err.kind, ErrorKind::Cancelled);
    assert!(report.stages.is_empty());
}

#[test]
fn operation_errors_are_captured_in_report() {
    let engine = engine();
    // from-hex on non-hex text fails inside stage 1.
    let recipe = RecipeV1::new(vec![node("s1", "from-hex"), node("s2", "to-base64")]);
    let report = run(
        &engine,
        &recipe,
        Value::Text("zzz-not-hex".into()),
        RunMode::Manual,
        None,
    );
    let err = report.error.expect("expected decode error");
    assert_eq!(err.kind, ErrorKind::Decode);
    assert_eq!(report.stages.len(), 1);
    assert_eq!(
        report.stages[0].status,
        cybercipher_engine::StageStatus::Error
    );
    assert!(report.output.is_none());
}

#[test]
fn panicking_operations_become_internal_errors() {
    static PANIC_SPEC: OperationSpec = OperationSpec {
        id: "test-panic",
        name: "Test Panic",
        description: "always panics",
        category: Category::Utility,
        input_kinds: &[ValueKind::Bytes, ValueKind::Text],
        output_kind: ValueKind::Null,
        params: &[],
        cost: CostClass::Instant,
        security: Security::Neutral,
        deterministic: true,
        reversible: false,
        aliases: &[],
        tags: &[],
        provenance: Provenance::PROJECT,
    };
    let mut reg = OperationRegistry::new();
    reg.add_simple(&PANIC_SPEC, |_, _, _| panic!("boom for test"));
    let engine = RecipeEngine::new(Arc::new(reg));

    let recipe = RecipeV1::new(vec![node("s1", "test-panic")]);
    let report = run(
        &engine,
        &recipe,
        Value::Text("x".into()),
        RunMode::Manual,
        None,
    );
    let err = report.error.expect("expected internal error");
    assert_eq!(err.kind, ErrorKind::Internal);
    assert!(err.message.contains("panicked"), "{}", err.message);
}

#[test]
fn operation_execution_count_tracks_cache() {
    // Count actual executions of to-hex via a counting wrapper op.
    static COUNT: AtomicU32 = AtomicU32::new(0);
    static COUNT_SPEC: OperationSpec = OperationSpec {
        id: "test-count",
        name: "Test Count",
        description: "counts executions",
        category: Category::Utility,
        input_kinds: &[ValueKind::Bytes, ValueKind::Text],
        output_kind: ValueKind::Text,
        params: &[],
        cost: CostClass::Instant,
        security: Security::Neutral,
        deterministic: true,
        reversible: false,
        aliases: &[],
        tags: &[],
        provenance: Provenance::PROJECT,
    };
    let mut reg = OperationRegistry::new();
    reg.add_simple(&COUNT_SPEC, |v, _, _| {
        COUNT.fetch_add(1, Ordering::Relaxed);
        Ok(match v {
            Value::Text(t) => Value::Text(t.clone()),
            other => Value::Text(format!("{other:?}")),
        })
    });
    let engine = RecipeEngine::new(Arc::new(reg));
    let recipe = RecipeV1::new(vec![node("s1", "test-count")]);
    let input = Value::Text("same".into());

    run(&engine, &recipe, input.clone(), RunMode::Manual, None);
    run(&engine, &recipe, input, RunMode::Manual, None);
    assert_eq!(
        COUNT.load(Ordering::Relaxed),
        1,
        "second run must be cached"
    );
}
