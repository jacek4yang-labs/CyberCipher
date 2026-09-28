//! The operation registry: every recipe-compatible capability registers here,
//! and the registry drives the GUI (forms, search, categories).

use crate::context::ExecutionContext;
use crate::error::OpResult;
use crate::param::ParamMap;
use crate::spec::{Category, OperationSpec};
use crate::value::{Value, ValueKind};
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A recipe-compatible operation.
pub trait Operation: Send + Sync {
    fn spec(&self) -> &'static OperationSpec;

    fn execute(&self, input: &Value, params: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value>;
}

/// Adapter for stateless operations implemented as plain functions or
/// closures. Runs are wrapped in an `Arc` so the wrapper stays `Send + Sync`.
pub struct SimpleOp {
    spec: &'static OperationSpec,
    run: RunFn,
}

pub type RunFn = Arc<dyn Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> + Send + Sync>;

impl SimpleOp {
    pub fn new(
        spec: &'static OperationSpec,
        run: impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> + Send + Sync + 'static,
    ) -> Self {
        SimpleOp {
            spec,
            run: Arc::new(run),
        }
    }
}

impl Operation for SimpleOp {
    fn spec(&self) -> &'static OperationSpec {
        self.spec
    }

    fn execute(&self, input: &Value, params: &ParamMap, ctx: &ExecutionContext) -> OpResult<Value> {
        (self.run)(input, params, ctx)
    }
}

/// One search result.
#[derive(Debug, Clone, Serialize)]
pub struct SearchHit {
    pub op_id: String,
    pub score: u32,
}

/// Search-relevant projection of an operation (serialized to the frontend).
#[derive(Debug, Clone, Serialize)]
pub struct OperationInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: Category,
    pub input_kinds: Vec<ValueKind>,
    pub output_kind: ValueKind,
    pub params: Vec<crate::spec::ParamSpec>,
    pub cost: crate::spec::CostClass,
    pub security: crate::spec::Security,
    pub deterministic: bool,
    pub reversible: bool,
    pub aliases: Vec<String>,
    pub tags: Vec<String>,
    pub provenance: crate::spec::Provenance,
}

/// Registry of all known operations.
pub struct OperationRegistry {
    ops: BTreeMap<String, Arc<dyn Operation>>,
}

impl OperationRegistry {
    pub fn new() -> Self {
        OperationRegistry {
            ops: BTreeMap::new(),
        }
    }

    /// Register an operation. Panics on duplicate IDs: operation IDs are
    /// compile-time constants and duplicates are a programming error.
    pub fn add(&mut self, op: Arc<dyn Operation>) {
        let id = op.spec().id;
        assert!(
            self.ops.insert(id.to_string(), op).is_none(),
            "duplicate operation id: {id}"
        );
    }

    pub fn add_simple(
        &mut self,
        spec: &'static OperationSpec,
        run: impl Fn(&Value, &ParamMap, &ExecutionContext) -> OpResult<Value> + Send + Sync + 'static,
    ) {
        self.add(Arc::new(SimpleOp::new(spec, run)));
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Operation>> {
        self.ops.get(id).cloned()
    }

    pub fn len(&self) -> usize {
        self.ops.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    pub fn all(&self) -> impl Iterator<Item = Arc<dyn Operation>> + '_ {
        self.ops.values().cloned()
    }

    pub fn info(&self) -> Vec<OperationInfo> {
        self.all().map(operation_info).collect()
    }

    /// Search operations by query with alias/tag/description awareness.
    /// Empty query returns everything ordered by name within category.
    pub fn search(
        &self,
        query: &str,
        category: Option<Category>,
    ) -> Vec<(Arc<dyn Operation>, u32)> {
        let q = query.trim().to_lowercase();
        let mut hits: Vec<(Arc<dyn Operation>, u32)> = self
            .ops
            .values()
            .filter(|op| category.is_none_or(|c| op.spec().category == c))
            .filter_map(|op| {
                let score = if q.is_empty() {
                    1
                } else {
                    score_op(op.spec(), &q)?
                };
                Some((op.clone(), score))
            })
            .collect();
        hits.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| a.0.spec().name.cmp(b.0.spec().name))
        });
        hits
    }
}

impl Default for OperationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Score one operation against a lowercased query. Returns `None` when the
/// operation is not a match at all.
fn score_op(spec: &OperationSpec, q: &str) -> Option<u32> {
    let name = spec.name.to_lowercase();
    let id = spec.id;
    if name == q || id == q {
        return Some(100);
    }
    if spec.aliases.iter().any(|a| a.eq_ignore_ascii_case(q)) {
        return Some(95);
    }
    if name.starts_with(q) {
        return Some(80);
    }
    if name.contains(q) {
        return Some(65);
    }
    if spec.aliases.iter().any(|a| a.to_lowercase().contains(q)) {
        return Some(55);
    }
    if spec.tags.iter().any(|t| t.to_lowercase().contains(q)) {
        return Some(40);
    }
    if spec.description.to_lowercase().contains(q) {
        return Some(25);
    }
    None
}

/// Build the serializable [`OperationInfo`] for an operation.
pub fn operation_info(op: Arc<dyn Operation>) -> OperationInfo {
    let s = op.spec();
    OperationInfo {
        id: s.id.to_string(),
        name: s.name.to_string(),
        description: s.description.to_string(),
        category: s.category,
        input_kinds: s.input_kinds.to_vec(),
        output_kind: s.output_kind,
        params: s.params.to_vec(),
        cost: s.cost,
        security: s.security,
        deterministic: s.deterministic,
        reversible: s.reversible,
        aliases: s.aliases.iter().map(|a| a.to_string()).collect(),
        tags: s.tags.iter().map(|t| t.to_string()).collect(),
        provenance: s.provenance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{CostClass, Provenance, Security};

    static SPEC_A: OperationSpec = OperationSpec {
        id: "from-hex",
        name: "From Hex",
        description: "Decodes hexadecimal",
        category: Category::Encoding,
        input_kinds: &[ValueKind::Text],
        output_kind: ValueKind::Bytes,
        params: &[],
        cost: CostClass::Instant,
        security: Security::Neutral,
        deterministic: true,
        reversible: true,
        aliases: &["hex decode"],
        tags: &["encoding"],
        provenance: Provenance::PROJECT,
    };

    fn noop(_: &Value, _: &ParamMap, _: &ExecutionContext) -> OpResult<Value> {
        Ok(Value::Null)
    }

    #[test]
    fn search_ranks_exact_match_first() {
        let mut reg = OperationRegistry::new();
        reg.add_simple(&SPEC_A, noop);
        let hits = reg.search("hex", None);
        assert!(!hits.is_empty());
        assert_eq!(hits[0].0.spec().id, "from-hex");

        let hits = reg.search("hex decode", None);
        assert_eq!(hits[0].0.spec().id, "from-hex");

        assert!(reg.search("aes", None).is_empty());
    }

    #[test]
    fn category_filter_and_info() {
        let mut reg = OperationRegistry::new();
        reg.add_simple(&SPEC_A, noop);
        assert_eq!(reg.search("", Some(Category::Crypto)).len(), 0);
        assert_eq!(reg.search("", Some(Category::Encoding)).len(), 1);
        let info = reg.info();
        assert_eq!(info[0].id, "from-hex");
        assert_eq!(info[0].provenance.standard, "CyberCipher project");
    }
}
