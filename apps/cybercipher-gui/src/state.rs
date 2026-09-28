//! Shared application state for the CyberCipher GUI.

use cybercipher_core::OperationRegistry;
use cybercipher_engine::RecipeEngine;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

pub struct AppState {
    pub registry: Arc<OperationRegistry>,
    pub engine: Arc<RecipeEngine>,
    /// Active runs keyed by run id, holding their cancellation flags.
    pub runs: Mutex<HashMap<String, Arc<AtomicBool>>>,
    pub recipes_dir: PathBuf,
}

impl AppState {
    pub fn new(
        registry: Arc<OperationRegistry>,
        engine: Arc<RecipeEngine>,
        recipes_dir: PathBuf,
    ) -> Self {
        AppState {
            registry,
            engine,
            runs: Mutex::new(HashMap::new()),
            recipes_dir,
        }
    }
}
