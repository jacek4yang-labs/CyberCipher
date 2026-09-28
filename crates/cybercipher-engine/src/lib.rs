// OperationError is ~128 bytes (five string fields). Failure paths are cold,
// so boxing the error at every call site is not worth the churn; silence the
// size lint until profiling says otherwise.
#![allow(clippy::result_large_err)]
//! CyberCipher engine: the versioned recipe format, the incremental recipe
//! executor, and the default operation registry aggregation.
//!
//! The public recipe format is stable JSON (version 1). Rust internals are
//! never serialized into it.

mod auto;
mod executor;
mod payload;
mod recipe;

pub use auto::{auto_decode, AutoCandidate};
pub use executor::{ExecutionReport, RunMode, StageStatus};
pub use payload::{ValuePayload, ValueSummary};
pub use recipe::{RecipeEdge, RecipeNodeV1, RecipeV1};

use cybercipher_core::{ExecutionContext, OperationRegistry};
use parking_lot::Mutex;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

/// Bumped whenever operation implementation semantics change in a way that
/// invalidates cached stage results.
pub const IMPL_VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"), ".1");

/// FIFO-bounded cache of stage results keyed by chained stage hashes.
struct StageCache {
    map: HashMap<u64, Arc<cybercipher_core::Value>>,
    order: VecDeque<u64>,
    capacity: usize,
}

impl StageCache {
    fn new(capacity: usize) -> Self {
        StageCache {
            map: HashMap::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    fn get(&mut self, key: u64) -> Option<Arc<cybercipher_core::Value>> {
        if let Some(v) = self.map.get(&key) {
            let v = v.clone();
            // Move to front for LRU-ish behavior.
            if let Some(pos) = self.order.iter().position(|&k| k == key) {
                self.order.remove(pos);
                self.order.push_front(key);
            }
            Some(v)
        } else {
            None
        }
    }

    fn put(&mut self, key: u64, value: Arc<cybercipher_core::Value>) {
        if self.map.insert(key, value).is_none() {
            self.order.push_front(key);
            while self.order.len() > self.capacity {
                if let Some(evict) = self.order.pop_back() {
                    self.map.remove(&evict);
                }
            }
        }
    }
}

/// The recipe engine: validates and executes recipes with incremental
/// caching. Shared between GUI, CLI, and any future frontend.
pub struct RecipeEngine {
    registry: Arc<OperationRegistry>,
    cache: Mutex<StageCache>,
}

impl RecipeEngine {
    pub fn new(registry: Arc<OperationRegistry>) -> Self {
        RecipeEngine {
            registry,
            cache: Mutex::new(StageCache::new(512)),
        }
    }

    pub fn registry(&self) -> &Arc<OperationRegistry> {
        &self.registry
    }

    /// Clear all cached stage results (used by an explicit "rebake").
    pub fn clear_cache(&self) {
        self.cache.lock().map.clear();
        self.cache.lock().order.clear();
    }

    /// Execute a recipe. Structural errors are reported via `Err`; operation
    /// errors are captured inside the returned report.
    pub fn execute(
        &self,
        recipe: &RecipeV1,
        input: cybercipher_core::Value,
        mode: RunMode,
        ctx: &ExecutionContext,
    ) -> Result<ExecutionReport, String> {
        recipe.validate(&self.registry)?;

        let root_key = xxhash_rust::xxh3::xxh3_64(&payload::value_cache_bytes(&input));
        let mut current = Arc::new(input);
        let mut chain_key = root_key;
        let mut report = ExecutionReport::new();
        let started = std::time::Instant::now();

        for node in recipe.nodes.iter() {
            if ctx.is_cancelled() {
                report.error = Some(cybercipher_core::OperationError::cancelled());
                break;
            }

            let op = match self.registry.get(&node.op) {
                Some(op) => op,
                None => {
                    report.error = Some(cybercipher_core::OperationError::unsupported(format!(
                        "unknown operation `{}`",
                        node.op
                    )));
                    break;
                }
            };
            let spec = op.spec();

            // Cost gating: Auto Bake never runs Heavy/Solver/External ops.
            if mode == RunMode::Auto {
                use cybercipher_core::CostClass::{External, Heavy, Solver};
                if matches!(spec.cost, Heavy | Solver | External) {
                    report.blocked_at = Some(node.id.clone());
                    break;
                }
            }

            // Chain the stage key: input identity + op id + params + version.
            let params_json = node.params.canonical_json();
            let stage_material = format!(
                "{}\u{1f}{}\u{1f}{}\u{1f}{}",
                node.id, node.op, params_json, IMPL_VERSION
            );
            let stage_key =
                xxhash_rust::xxh3::xxh3_64_with_seed(stage_material.as_bytes(), chain_key);

            let stage_start = std::time::Instant::now();
            let cached = self.cache.lock().get(stage_key);

            let value: Arc<cybercipher_core::Value> = if !node.enabled {
                // Disabled nodes pass through; the chain key records the skip
                // so downstream results differ from an enabled run.
                chain_key = xxhash_rust::xxh3::xxh3_64_with_seed(b"\x1fdisabled", chain_key);
                report.push_stage(
                    node,
                    spec.name,
                    StageStatus::Skipped,
                    &current,
                    Duration::ZERO,
                );
                continue;
            } else if let Some(hit) = cached {
                report.cached_stages += 1;
                report.push_stage(
                    node,
                    spec.name,
                    StageStatus::Cached,
                    &hit,
                    stage_start.elapsed(),
                );
                hit
            } else {
                // Coerce the value losslessly into one of the operation's
                // declared input kinds (Text <-> Bytes when reversible).
                let coerced = match coerce_input(spec, &current) {
                    Ok(v) => v,
                    Err(e) => {
                        report.error = Some(e);
                        report.push_stage(
                            node,
                            spec.name,
                            StageStatus::Error,
                            &current,
                            stage_start.elapsed(),
                        );
                        break;
                    }
                };
                let result = {
                    // Panic isolation: a bug in one operation must not take
                    // down the process.
                    let input_ref = coerced;
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        op.execute(&input_ref, &node.params, ctx)
                    }))
                };
                match result {
                    Ok(Ok(v)) => {
                        let arc = Arc::new(v);
                        self.cache.lock().put(stage_key, arc.clone());
                        report.push_stage(
                            node,
                            spec.name,
                            StageStatus::Ok,
                            &arc,
                            stage_start.elapsed(),
                        );
                        arc
                    }
                    Ok(Err(e)) => {
                        report.error = Some(e);
                        report.push_stage(
                            node,
                            spec.name,
                            StageStatus::Error,
                            &current,
                            stage_start.elapsed(),
                        );
                        break;
                    }
                    Err(panic) => {
                        let msg = panic_message(panic);
                        report.error = Some(cybercipher_core::OperationError::internal(format!(
                            "operation `{}` panicked: {msg}",
                            node.op
                        )));
                        report.push_stage(
                            node,
                            spec.name,
                            StageStatus::Error,
                            &current,
                            stage_start.elapsed(),
                        );
                        break;
                    }
                }
            };

            chain_key = stage_key;
            current = value;
        }

        report.duration_us = started.elapsed().as_micros() as u64;
        if report.error.is_none() {
            report.output = Some(cybercipher_core::Value::clone(&current));
        }
        Ok(report)
    }
}

fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".to_string()
    }
}

/// Losslessly adapt a value to one of an operation's declared input kinds.
/// Bytes become Text only when they are valid UTF-8; Text is passed through
/// for byte-oriented operations (operations borrow via `as_bytes`).
fn coerce_input(
    spec: &cybercipher_core::OperationSpec,
    value: &cybercipher_core::Value,
) -> Result<cybercipher_core::Value, cybercipher_core::OperationError> {
    use cybercipher_core::{OperationError, Value, ValueKind};
    if spec.input_kinds.contains(&value.kind()) {
        return Ok(value.clone());
    }
    if value.as_bytes().is_some() {
        // Bytes or Text feeding an operation that can handle either.
        if spec.input_kinds.contains(&ValueKind::Text) {
            match value {
                Value::Bytes(b) => match std::str::from_utf8(b) {
                    Ok(text) => return Ok(Value::Text(text.to_string())),
                    Err(_) => {
                        return Err(OperationError::invalid_input(format!(
                            "`{}` expects text input, but the bytes are not valid UTF-8",
                            spec.name
                        ))
                        .with_expected("valid UTF-8 text")
                        .with_actual("non-UTF-8 bytes"));
                    }
                },
                _ => return Ok(value.clone()),
            }
        }
        if spec.input_kinds.contains(&ValueKind::Bytes) {
            return Ok(value.clone());
        }
    }
    Err(OperationError::invalid_input(format!(
        "`{}` expects {}, but received {}",
        spec.name,
        spec.input_kinds
            .iter()
            .map(|k| k.name())
            .collect::<Vec<_>>()
            .join(" or "),
        value.kind().name()
    ))
    .with_expected(
        spec.input_kinds
            .iter()
            .map(|k| k.name())
            .collect::<Vec<_>>()
            .join(" or "),
    )
    .with_actual(value.kind().name()))
}

/// Convenience: build the default registry with all known operation sets.
pub fn default_registry() -> OperationRegistry {
    let mut reg = OperationRegistry::new();
    cybercipher_codec::register_all(&mut reg);
    cybercipher_crypto::register_all(&mut reg);
    reg
}
