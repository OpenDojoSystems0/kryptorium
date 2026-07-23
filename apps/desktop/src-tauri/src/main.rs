#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod state;

use state::AppState;

fn main() {
    tauri::Builder::default()
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::home_dir,
            commands::default_vault_dir,
            commands::vault_exists,
            commands::create_vault,
            commands::unlock_vault,
            commands::lock_vault,
            commands::is_unlocked,
            commands::vault_info,
            commands::list_entries,
            commands::add_files,
            commands::export_file,
            commands::get_preview,
            commands::delete_entry,
            commands::set_tags,
            commands::change_passphrase,
            commands::create_decoy_vault,
            commands::set_duress,
            commands::clear_duress,
            commands::set_auto_wipe,
            commands::panic_wipe,
        ])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de l'application Tauri");
}
