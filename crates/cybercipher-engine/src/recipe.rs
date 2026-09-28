//! Public recipe format (version 1). Linear chains are expressed as an
//! ordered node list; edges make the data flow explicit and will generalize
//! to DAGs (fork/merge/conditions) without a format break.

use cybercipher_core::{OperationRegistry, ParamMap};
use serde::{Deserialize, Serialize};

pub const RECIPE_FORMAT_VERSION: u32 = 1;
pub const MAX_RECIPE_NODES: usize = 256;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecipeNodeV1 {
    pub id: String,
    pub op: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub params: ParamMap,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecipeEdge {
    pub from: String,
    pub to: String,
}

/// A versioned recipe document. This is the stable, public interchange
/// format — safe to persist and share.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecipeV1 {
    pub version: u32,
    pub nodes: Vec<RecipeNodeV1>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<RecipeEdge>,
}

impl RecipeV1 {
    pub fn new(nodes: Vec<RecipeNodeV1>) -> Self {
        let mut recipe = RecipeV1 {
            version: RECIPE_FORMAT_VERSION,
            nodes,
            edges: Vec::new(),
        };
        recipe.edges = recipe.linear_edges();
        recipe
    }

    /// The linear edge chain `input -> n0 -> n1 -> ... -> output`.
    pub fn linear_edges(&self) -> Vec<RecipeEdge> {
        let mut edges = Vec::new();
        let mut prev = "input".to_string();
        for node in &self.nodes {
            edges.push(RecipeEdge {
                from: prev,
                to: node.id.clone(),
            });
            prev = node.id.clone();
        }
        if !self.nodes.is_empty() {
            edges.push(RecipeEdge {
                from: prev,
                to: "output".to_string(),
            });
        }
        edges
    }

    /// Structural validation against a registry.
    pub fn validate(&self, registry: &OperationRegistry) -> Result<(), String> {
        if self.version != RECIPE_FORMAT_VERSION {
            return Err(format!(
                "unsupported recipe format version {} (expected {RECIPE_FORMAT_VERSION})",
                self.version
            ));
        }
        if self.nodes.len() > MAX_RECIPE_NODES {
            return Err(format!(
                "recipe has {} nodes, maximum is {MAX_RECIPE_NODES}",
                self.nodes.len()
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for node in &self.nodes {
            if node.id.is_empty() {
                return Err("recipe nodes must have non-empty ids".to_string());
            }
            if !seen.insert(&node.id) {
                return Err(format!("duplicate node id `{}`", node.id));
            }
            if registry.get(&node.op).is_none() {
                return Err(format!(
                    "unknown operation `{}` — the operation may have been renamed",
                    node.op
                ));
            }
        }
        if !self.edges.is_empty() && self.edges != self.linear_edges() {
            return Err(
                "recipe edges must form a single linear chain in node order (DAG recipes are not supported yet)"
                    .to_string(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_json() {
        let mut params = ParamMap::new();
        params.insert("key", "secret");
        params.insert("strict", true);
        let recipe = RecipeV1::new(vec![RecipeNodeV1 {
            id: "n1".to_string(),
            op: "xor".to_string(),
            enabled: true,
            params,
        }]);
        let json = serde_json::to_string(&recipe).unwrap();
        assert!(json.contains("\"version\":1"));
        let back: RecipeV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, recipe);
        assert_eq!(back.nodes[0].params.get_str("key"), Some("secret"));
    }

    #[test]
    fn missing_enabled_defaults_true() {
        let recipe: RecipeV1 =
            serde_json::from_str(r#"{"version":1,"nodes":[{"id":"a","op":"to-hex"}]}"#).unwrap();
        assert!(recipe.nodes[0].enabled);
        assert_eq!(recipe.linear_edges().len(), 2);
    }

    #[test]
    fn validation_rejects_bad_structures() {
        let mut reg = OperationRegistry::new();
        cybercipher_codec::register_all(&mut reg);

        let recipe: RecipeV1 =
            serde_json::from_str(r#"{"version":1,"nodes":[{"id":"a","op":"not-an-op"}]}"#).unwrap();
        assert!(recipe.validate(&reg).is_err());

        let recipe: RecipeV1 = serde_json::from_str(r#"{"version":2,"nodes":[]}"#).unwrap();
        assert!(recipe.validate(&reg).is_err());

        let recipe: RecipeV1 = serde_json::from_str(
            r#"{"version":1,"nodes":[{"id":"a","op":"to-hex"},{"id":"a","op":"from-hex"}]}"#,
        )
        .unwrap();
        assert!(recipe.validate(&reg).is_err());
    }
}
