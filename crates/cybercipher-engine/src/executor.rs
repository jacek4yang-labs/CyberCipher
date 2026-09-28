//! Execution reports: per-stage status, timing, and error capture.

use crate::recipe::RecipeNodeV1;
use cybercipher_core::{OperationError, Value};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;

/// How a run was requested. `Auto` stops before Heavy/Solver/External ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunMode {
    Auto,
    Manual,
}

/// Outcome of a single recipe stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageStatus {
    Ok,
    /// Served from the incremental cache.
    Cached,
    /// Node disabled; data passed through unchanged.
    Skipped,
    Error,
}

/// Report for one stage of the recipe.
#[derive(Debug, Clone, Serialize)]
pub struct StageReport {
    pub node_id: String,
    pub op_id: String,
    pub op_name: String,
    pub status: StageStatus,
    pub kind: String,
    pub size: usize,
    pub duration_us: u64,
    pub error: Option<OperationError>,
}

/// Full report of one execution.
#[derive(Debug, Clone, Serialize)]
pub struct ExecutionReport {
    pub stages: Vec<StageReport>,
    /// Final value when execution reached the end (or was blocked).
    /// Not serialized: the IPC layer projects it into a `ValuePayload`.
    #[serde(skip_serializing)]
    pub output: Option<Value>,
    pub error: Option<OperationError>,
    /// Node id where Auto Bake stopped due to a cost gate.
    pub blocked_at: Option<String>,
    pub cached_stages: usize,
    pub duration_us: u64,
}

impl ExecutionReport {
    pub fn new() -> Self {
        ExecutionReport {
            stages: Vec::new(),
            output: None,
            error: None,
            blocked_at: None,
            cached_stages: 0,
            duration_us: 0,
        }
    }

    pub(crate) fn push_stage(
        &mut self,
        node: &RecipeNodeV1,
        op_name: &str,
        status: StageStatus,
        value: &Arc<Value>,
        elapsed: Duration,
    ) {
        self.stages.push(StageReport {
            node_id: node.id.clone(),
            op_id: node.op.clone(),
            op_name: op_name.to_string(),
            status,
            kind: value.kind().name().to_string(),
            size: value.size_hint(),
            duration_us: elapsed.as_micros() as u64,
            error: None,
        });
    }
}

impl Default for ExecutionReport {
    fn default() -> Self {
        Self::new()
    }
}
