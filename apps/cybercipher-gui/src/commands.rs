//! Tauri IPC commands. The command layer is a thin adapter: all real work
//! happens in the engine so the same API can back the CLI and MCP later.

use crate::state::AppState;
use cybercipher_codec::decode_input;
use cybercipher_core::{ExecutionContext, OperationError};
use cybercipher_engine::{RecipeV1, RunMode, ValuePayload};
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tauri::State;

/// Structured error crossing the IPC boundary.
#[derive(Debug, Serialize)]
pub struct CmdError {
    pub kind: String,
    pub message: String,
}

impl From<OperationError> for CmdError {
    fn from(e: OperationError) -> Self {
        CmdError {
            kind: serde_json::to_string(&e.kind).unwrap_or_else(|_| "\"internal\"".to_string()),
            message: e.to_string(),
        }
    }
}

impl From<std::io::Error> for CmdError {
    fn from(e: std::io::Error) -> Self {
        CmdError {
            kind: "\"io\"".to_string(),
            message: e.to_string(),
        }
    }
}

impl CmdError {
    fn internal(message: impl Into<String>) -> Self {
        CmdError {
            kind: "\"internal\"".to_string(),
            message: message.into(),
        }
    }
}

#[tauri::command]
pub fn list_operations(
    state: State<'_, AppState>,
) -> Vec<cybercipher_core::registry::OperationInfo> {
    state.registry.info()
}

#[derive(Debug, Deserialize)]
pub struct BakeRequest {
    pub recipe: RecipeV1,
    #[serde(default)]
    pub input_text: String,
    #[serde(default = "default_input_encoding")]
    pub input_encoding: String,
    #[serde(default)]
    pub auto_bake: bool,
    pub run_id: String,
}

fn default_input_encoding() -> String {
    "utf8".to_string()
}

#[derive(Debug, Serialize)]
pub struct BakeResponse {
    pub report: cybercipher_engine::ExecutionReport,
    pub output: Option<ValuePayload>,
    pub blocked_at: Option<String>,
}

#[tauri::command]
pub async fn bake(
    state: State<'_, AppState>,
    request: BakeRequest,
) -> Result<BakeResponse, CmdError> {
    let flag = Arc::new(AtomicBool::new(false));
    state
        .runs
        .lock()
        .insert(request.run_id.clone(), flag.clone());

    let engine = state.engine.clone();
    let recipe = request.recipe;
    let auto = request.auto_bake;
    let run_id = request.run_id.clone();

    let input_bytes =
        decode_input(&request.input_encoding, &request.input_text).map_err(CmdError::from)?;
    let input = cybercipher_core::Value::from_bytes(input_bytes);

    let mode = if auto { RunMode::Auto } else { RunMode::Manual };
    let ctx = ExecutionContext::new()
        .with_cancel(flag)
        .with_start(std::time::Instant::now());

    let handle =
        tauri::async_runtime::spawn_blocking(move || engine.execute(&recipe, input, mode, &ctx));

    let result = handle
        .await
        .map_err(|e| CmdError::internal(format!("execution task failed: {e}")))?;

    state.runs.lock().remove(&run_id);

    let report = result.map_err(CmdError::internal)?;
    let output = report.output.as_ref().map(ValuePayload::from_value);
    let blocked_at = report.blocked_at.clone();
    Ok(BakeResponse {
        report,
        output,
        blocked_at,
    })
}

#[derive(Debug, Deserialize)]
pub struct RsaAnalyzeRequest {
    pub params: serde_json::Value,
    #[serde(default)]
    pub solve: bool,
    #[serde(default = "default_rsa_budget")]
    pub budget_ms: u64,
}

fn default_rsa_budget() -> u64 {
    10000
}

#[tauri::command]
pub async fn rsa_analyze(
    state: State<'_, AppState>,
    request: RsaAnalyzeRequest,
) -> Result<cybercipher_attack::AnalyzerReport, CmdError> {
    // Reject unknown/invalid parameter keys before running anything.
    let params = cybercipher_attack::RsaParams::from_json(&request.params)
        .map_err(|e| CmdError {
            kind: "\"invalid_param\"".to_string(),
            message: e,
        })?;
    let _ = state;
    let handle = tauri::async_runtime::spawn_blocking(move || {
        cybercipher_attack::analyze(&params, request.solve, request.budget_ms)
    });
    handle
        .await
        .map_err(|e| CmdError::internal(format!("rsa analysis task failed: {e}")))
}

#[derive(Debug, Deserialize)]
pub struct AutoRequest {
    #[serde(default)]
    pub input_text: String,
    #[serde(default = "default_input_encoding")]
    pub input_encoding: String,
}

#[tauri::command]
pub async fn auto_analyze(
    state: State<'_, AppState>,
    request: AutoRequest,
) -> Result<Vec<cybercipher_engine::AutoCandidate>, CmdError> {
    let bytes =
        decode_input(&request.input_encoding, &request.input_text).map_err(CmdError::from)?;
    let registry = state.registry.clone();
    let handle = tauri::async_runtime::spawn_blocking(move || {
        cybercipher_engine::auto_decode(&registry, &bytes, &ExecutionContext::new())
    });
    handle
        .await
        .map_err(|e| CmdError::internal(format!("auto decode task failed: {e}")))
}

#[tauri::command]
pub fn cancel_run(state: State<'_, AppState>, run_id: String) {
    if let Some(flag) = state.runs.lock().get(&run_id) {
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

#[derive(Debug, Deserialize)]
pub struct InputRef {
    #[serde(default)]
    pub text: String,
    #[serde(default = "default_input_encoding")]
    pub encoding: String,
}

#[derive(Debug, Serialize)]
pub struct InputStats {
    pub size: usize,
    pub entropy: f64,
    pub printable_ratio: f64,
}

#[tauri::command]
pub fn input_stats(input: InputRef) -> Result<InputStats, CmdError> {
    let bytes = decode_input(&input.encoding, &input.text).map_err(CmdError::from)?;
    Ok(InputStats {
        size: bytes.len(),
        entropy: cybercipher_core::util::shannon_entropy(&bytes),
        printable_ratio: cybercipher_core::util::printable_ratio(&bytes),
    })
}

// ------------------------------------------------------------- recipes ----

fn sanitize_name(name: &str) -> Result<String, CmdError> {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == ' ' || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cleaned = cleaned.trim().replace(' ', "_");
    if cleaned.is_empty() {
        return Err(CmdError {
            kind: "\"invalid_param\"".to_string(),
            message: "recipe name must contain visible characters".to_string(),
        });
    }
    if cleaned.len() > 80 {
        return Err(CmdError {
            kind: "\"invalid_param\"".to_string(),
            message: "recipe name is too long (max 80 characters)".to_string(),
        });
    }
    Ok(cleaned)
}

#[derive(Debug, Deserialize)]
pub struct SaveRecipeRequest {
    pub name: String,
    pub recipe: RecipeV1,
}

#[derive(Debug, Serialize)]
pub struct RecipeMeta {
    pub name: String,
    pub op_count: usize,
    pub modified: String,
}

#[tauri::command]
pub fn save_recipe(
    state: State<'_, AppState>,
    request: SaveRecipeRequest,
) -> Result<RecipeMeta, CmdError> {
    let name = sanitize_name(&request.name)?;
    if let Err(e) = request.recipe.validate(&state.registry) {
        return Err(CmdError {
            kind: "\"invalid_recipe\"".to_string(),
            message: e,
        });
    }
    let doc = serde_json::json!({
        "name": request.name.trim(),
        "saved_at": utc_timestamp_now(),
        "recipe": request.recipe,
    });
    let path = state.recipes_dir.join(format!("{name}.json"));
    std::fs::create_dir_all(&state.recipes_dir)?;
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&doc).unwrap_or_default(),
    )?;
    Ok(RecipeMeta {
        name: request.name.trim().to_string(),
        op_count: request.recipe.nodes.len(),
        modified: doc["saved_at"].as_str().unwrap_or_default().to_string(),
    })
}

#[tauri::command]
pub fn load_recipe(state: State<'_, AppState>, name: String) -> Result<RecipeV1, CmdError> {
    let file = sanitize_name(&name)?;
    let path = state.recipes_dir.join(format!("{file}.json"));
    let content = std::fs::read_to_string(&path).map_err(|e| CmdError {
        kind: "\"not_found\"".to_string(),
        message: format!("recipe `{name}` could not be read: {e}"),
    })?;
    let doc: serde_json::Value = serde_json::from_str(&content).map_err(|e| CmdError {
        kind: "\"corrupt\"".to_string(),
        message: format!("recipe file is corrupt: {e}"),
    })?;
    let recipe: RecipeV1 =
        serde_json::from_value(doc.get("recipe").cloned().unwrap_or(doc.clone())).map_err(|e| {
            CmdError {
                kind: "\"corrupt\"".to_string(),
                message: format!("recipe structure is invalid: {e}"),
            }
        })?;
    recipe.validate(&state.registry).map_err(|e| CmdError {
        kind: "\"invalid_recipe\"".to_string(),
        message: e,
    })?;
    Ok(recipe)
}

#[tauri::command]
pub fn list_saved_recipes(state: State<'_, AppState>) -> Result<Vec<RecipeMeta>, CmdError> {
    let mut metas = Vec::new();
    let dir = &state.recipes_dir;
    if !dir.exists() {
        return Ok(metas);
    }
    let entries = std::fs::read_dir(dir)?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let doc: serde_json::Value = match serde_json::from_str(&content) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let name = doc["name"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unnamed")
                    .to_string()
            });
        let op_count = doc["recipe"]["nodes"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(0);
        let modified = doc["saved_at"].as_str().unwrap_or_default().to_string();
        metas.push(RecipeMeta {
            name,
            op_count,
            modified,
        });
    }
    metas.sort_by(|a, b| b.modified.cmp(&a.modified));
    Ok(metas)
}

#[tauri::command]
pub fn delete_recipe(state: State<'_, AppState>, name: String) -> Result<(), CmdError> {
    let file = sanitize_name(&name)?;
    let path = state.recipes_dir.join(format!("{file}.json"));
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

fn utc_timestamp_now() -> String {
    // Local-time ISO-ish timestamp without pulling a date library; ordering
    // by this string is what matters for the recipes list.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    // Convert to UTC date-time (Y-M-D h:m:s).
    let days = secs / 86400;
    let (y, m, d) = civil_from_days(days as i64);
    let rem = secs % 86400;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}
