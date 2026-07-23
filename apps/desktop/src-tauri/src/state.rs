use std::sync::Mutex;

use vault_core::UnlockedVault;

/// État partagé de l'application. `vault` vaut `None` tant qu'aucun
/// coffre n'est déverrouillé ; la clé maître ne réside en mémoire que
/// pendant cette fenêtre, et [`UnlockedVault`] l'efface (zeroize) à sa
/// destruction (verrouillage explicite ou fermeture de l'application).
#[derive(Default)]
pub struct AppState {
    pub vault: Mutex<Option<UnlockedVault>>,
}
