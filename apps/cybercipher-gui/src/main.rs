//! CyberCipher desktop application entry point.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// See cybercipher-core/src/lib.rs for the rationale.
#![allow(clippy::result_large_err)]

mod commands;
mod state;

use std::sync::Arc;

fn main() {
    let registry = Arc::new(cybercipher_engine::default_registry());
    let engine = Arc::new(cybercipher_engine::RecipeEngine::new(registry.clone()));

    let recipes_dir = dirs::config_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("cybercipher")
        .join("recipes");
    if let Err(e) = std::fs::create_dir_all(&recipes_dir) {
        eprintln!("warning: could not create recipes directory: {e}");
    }

    tauri::Builder::default()
        .manage(state::AppState::new(registry, engine, recipes_dir))
        .invoke_handler(tauri::generate_handler![
            commands::list_operations,
            commands::bake,
            commands::cancel_run,
            commands::input_stats,
            commands::save_recipe,
            commands::load_recipe,
            commands::list_saved_recipes,
            commands::delete_recipe,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CyberCipher");
}
