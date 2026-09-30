//! CyberCipher desktop application entry point.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
// See cybercipher-core/src/lib.rs for the rationale.
#![allow(clippy::result_large_err)]

mod commands;
mod pki_commands;
mod sstv_commands;
mod state;

use std::sync::Arc;

fn main() {
    // Default registry plus the SSTV operation (the sstv crate is wired here
    // rather than inside `default_registry` so library consumers opt in).
    let mut registry = cybercipher_engine::default_registry();
    cybercipher_sstv::register_all(&mut registry);
    let registry = Arc::new(registry);
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
            commands::auto_analyze,
            commands::crypto_assist,
            commands::rsa_analyze,
            commands::cancel_run,
            commands::input_stats,
            commands::save_recipe,
            commands::load_recipe,
            commands::list_saved_recipes,
            commands::delete_recipe,
            pki_commands::pki_inspect_key,
            pki_commands::pki_rsa_keygen,
            pki_commands::pki_rsa_encrypt,
            pki_commands::pki_rsa_decrypt,
            pki_commands::pki_rsa_sign,
            pki_commands::pki_rsa_verify,
            pki_commands::pki_ecc_keygen,
            pki_commands::pki_ecdsa_sign,
            pki_commands::pki_ecdsa_verify,
            pki_commands::pki_ecdh,
            pki_commands::pki_ed25519_sign,
            pki_commands::pki_ed25519_verify,
            pki_commands::pki_x25519,
            pki_commands::pki_sm2_keygen,
            pki_commands::pki_sm2_sign,
            pki_commands::pki_sm2_verify,
            pki_commands::pki_sm2_encrypt,
            pki_commands::pki_sm2_decrypt,
            pki_commands::pki_cert_inspect,
            sstv_commands::sstv_decode_audio,
            sstv_commands::sstv_modes,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CyberCipher");
}
