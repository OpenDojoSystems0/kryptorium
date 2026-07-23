use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::Serialize;
use tauri::State;
use uuid::Uuid;

use crate::state::AppState;

#[derive(Debug, Serialize)]
pub struct CmdError {
    pub kind: String,
    pub message: String,
}

impl From<vault_core::VaultError> for CmdError {
    fn from(e: vault_core::VaultError) -> Self {
        use vault_core::VaultError as E;
        let kind = match &e {
            E::WrongPassphrase => "wrong_passphrase",
            E::TamperedOrCorrupt => "tampered",
            E::NotFound => "not_found",
            E::AlreadyExists => "already_exists",
            E::VaultNotFound => "vault_not_found",
            E::Locked => "locked",
            E::TooLarge => "too_large",
            E::Wiped => "wiped",
            _ => "internal",
        };
        CmdError {
            kind: kind.to_string(),
            message: e.to_string(),
        }
    }
}

fn locked_err() -> CmdError {
    CmdError {
        kind: "locked".into(),
        message: "le coffre est verrouillé".into(),
    }
}

fn internal_err(message: impl Into<String>) -> CmdError {
    CmdError {
        kind: "internal".into(),
        message: message.into(),
    }
}

fn parse_uuid(id: &str) -> Result<Uuid, CmdError> {
    Uuid::parse_str(id).map_err(|_| internal_err("identifiant invalide"))
}

fn parse_cipher(s: &str) -> Result<vault_core::Cipher, CmdError> {
    match s {
        "xchacha20poly1305" => Ok(vault_core::Cipher::XChaCha20Poly1305),
        "aes256gcm" => Ok(vault_core::Cipher::Aes256Gcm),
        _ => Err(internal_err("algorithme de chiffrement inconnu")),
    }
}

/// Parcourt récursivement `path` (fichier ou dossier) et accumule dans
/// `out` la liste des fichiers trouvés avec un nom d'affichage relatif
/// (ex: `"Photos/vacances/img.png"` pour un fichier situé dans un dossier
/// glissé-déposé). Les liens symboliques sont ignorés par prudence
/// (évite les boucles et l'évasion hors de l'arborescence attendue).
fn collect_files_recursive(
    path: &Path,
    base_label: Option<&str>,
    out: &mut Vec<(PathBuf, String)>,
) -> Result<(), CmdError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|e| internal_err(format!("{path:?}: {e}")))?;

    if metadata.is_dir() {
        let folder_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("dossier")
            .to_string();
        let label = match base_label {
            Some(b) => format!("{b}/{folder_name}"),
            None => folder_name,
        };
        let mut children: Vec<_> = std::fs::read_dir(path)
            .map_err(|e| internal_err(e.to_string()))?
            .filter_map(|e| e.ok())
            .collect();
        children.sort_by_key(|e| e.file_name());
        for child in children {
            collect_files_recursive(&child.path(), Some(&label), out)?;
        }
    } else if metadata.is_file() {
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("fichier")
            .to_string();
        let label = match base_label {
            Some(b) => format!("{b}/{file_name}"),
            None => file_name,
        };
        out.push((path.to_path_buf(), label));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct EntryView {
    pub id: String,
    pub original_name: String,
    pub size: u64,
    pub added_at: String,
    pub tags: Vec<String>,
    pub content_type: Option<String>,
}

impl From<&vault_core::Entry> for EntryView {
    fn from(e: &vault_core::Entry) -> Self {
        EntryView {
            id: e.id.to_string(),
            original_name: e.original_name.clone(),
            size: e.size,
            added_at: e.added_at.to_rfc3339(),
            tags: e.tags.clone(),
            content_type: e.content_type.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct PreviewDto {
    pub content_type: String,
    pub data_base64: String,
}

#[derive(Debug, Serialize)]
pub struct VaultInfoDto {
    pub cipher_label: String,
    pub kdf_memory_mib: f64,
    pub kdf_iterations: u32,
    pub created_at: String,
    pub entry_count: usize,
    pub duress_configured: bool,
    pub auto_wipe_after: Option<u32>,
}

#[tauri::command]
pub fn home_dir() -> String {
    std::env::var("HOME").unwrap_or_default()
}

#[tauri::command]
pub fn default_vault_dir() -> String {
    format!("{}/Kryptorium", home_dir())
}

#[tauri::command]
pub fn vault_exists(path: String) -> bool {
    vault_core::looks_like_vault(Path::new(&path))
}

#[tauri::command]
pub fn create_vault(
    state: State<AppState>,
    path: String,
    passphrase: String,
    cipher: String,
) -> Result<(), CmdError> {
    let cipher = parse_cipher(&cipher)?;
    let vault =
        vault_core::UnlockedVault::create(PathBuf::from(path).as_path(), &passphrase, cipher)?;
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    *guard = Some(vault);
    Ok(())
}

/// Déverrouille le coffre à `path`. Reconnaît de façon transparente un
/// éventuel mot de passe de contrainte AtomasDestruct : dans ce cas,
/// ouvre silencieusement le coffre-leurre associé à la place — rien dans
/// la réponse ne permet de distinguer les deux cas. Comptabilise aussi
/// les échecs pour la purge automatique si elle est activée.
#[tauri::command]
pub fn unlock_vault(
    state: State<AppState>,
    path: String,
    passphrase: String,
) -> Result<(), CmdError> {
    let outcome = vault_core::unlock_checked(PathBuf::from(&path).as_path(), &passphrase)?;
    let vault = match outcome {
        vault_core::UnlockOutcome::Real(vault) => vault,
        vault_core::UnlockOutcome::Duress { decoy_path } => {
            vault_core::UnlockedVault::unlock(&decoy_path, &passphrase)?
        }
    };
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    *guard = Some(vault);
    Ok(())
}

#[tauri::command]
pub fn lock_vault(state: State<AppState>) -> Result<(), CmdError> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    *guard = None;
    Ok(())
}

#[tauri::command]
pub fn is_unlocked(state: State<AppState>) -> bool {
    state.vault.lock().map(|g| g.is_some()).unwrap_or(false)
}

#[tauri::command]
pub fn list_entries(state: State<AppState>) -> Result<Vec<EntryView>, CmdError> {
    let guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    let vault = guard.as_ref().ok_or_else(locked_err)?;
    Ok(vault.list().iter().map(EntryView::from).collect())
}

/// Ajoute des fichiers et/ou des dossiers entiers (parcourus
/// récursivement) au coffre. Pour un dossier, l'arborescence relative est
/// préservée dans le nom affiché (ex: `"Photos/vacances/img.png"`).
#[tauri::command]
pub fn add_files(
    state: State<AppState>,
    paths: Vec<String>,
    tags: Vec<String>,
) -> Result<Vec<EntryView>, CmdError> {
    let mut collected = Vec::new();
    for p in &paths {
        collect_files_recursive(Path::new(p), None, &mut collected)?;
    }

    let mut guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    let vault = guard.as_mut().ok_or_else(locked_err)?;

    let mut added = Vec::with_capacity(collected.len());
    for (source, display_name) in collected {
        let id = vault.add_file_named(&source, display_name, tags.clone())?;
        if let Some(entry) = vault.get_entry(id) {
            added.push(EntryView::from(entry));
        }
    }
    Ok(added)
}

#[tauri::command]
pub fn vault_info(state: State<AppState>) -> Result<VaultInfoDto, CmdError> {
    let guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    let vault = guard.as_ref().ok_or_else(locked_err)?;
    let info = vault.info();
    Ok(VaultInfoDto {
        cipher_label: info.cipher_label.to_string(),
        kdf_memory_mib: info.kdf_memory_kib as f64 / 1024.0,
        kdf_iterations: info.kdf_iterations,
        created_at: info.created_at,
        entry_count: info.entry_count,
        duress_configured: info.duress_configured,
        auto_wipe_after: info.auto_wipe_after,
    })
}

#[tauri::command]
pub fn export_file(state: State<AppState>, id: String, dest: String) -> Result<(), CmdError> {
    let guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    let vault = guard.as_ref().ok_or_else(locked_err)?;
    let uuid = parse_uuid(&id)?;
    vault.export_file(uuid, Path::new(&dest))?;
    Ok(())
}

#[tauri::command]
pub fn get_preview(state: State<AppState>, id: String) -> Result<PreviewDto, CmdError> {
    let guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    let vault = guard.as_ref().ok_or_else(locked_err)?;
    let uuid = parse_uuid(&id)?;

    let entry = vault
        .get_entry(uuid)
        .ok_or_else(|| internal_err("entrée introuvable"))?;
    let content_type = entry
        .content_type
        .clone()
        .filter(|ct| ct.starts_with("image/"))
        .ok_or_else(|| CmdError {
            kind: "unsupported".into(),
            message: "aperçu non disponible pour ce type de fichier".into(),
        })?;

    let bytes = vault.decrypt_to_memory(uuid, vault_core::MAX_PREVIEW_BYTES)?;
    Ok(PreviewDto {
        content_type,
        data_base64: B64.encode(bytes),
    })
}

#[tauri::command]
pub fn delete_entry(state: State<AppState>, id: String) -> Result<(), CmdError> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    let vault = guard.as_mut().ok_or_else(locked_err)?;
    let uuid = parse_uuid(&id)?;
    vault.delete_file(uuid)?;
    Ok(())
}

#[tauri::command]
pub fn set_tags(state: State<AppState>, id: String, tags: Vec<String>) -> Result<(), CmdError> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    let vault = guard.as_mut().ok_or_else(locked_err)?;
    let uuid = parse_uuid(&id)?;
    vault.set_tags(uuid, tags)?;
    Ok(())
}

#[tauri::command]
pub fn change_passphrase(
    state: State<AppState>,
    old: String,
    new: String,
) -> Result<(), CmdError> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    let vault = guard.as_mut().ok_or_else(locked_err)?;
    vault.change_passphrase(&old, &new)?;
    Ok(())
}

// ---------- AtomasDestruct ----------

/// Crée un coffre-leurre à `path` (indépendant, sans toucher au coffre
/// actuellement déverrouillé) — étape préparatoire avant
/// [`set_duress`]. N'affecte pas l'état de session en cours.
#[tauri::command]
pub fn create_decoy_vault(path: String, passphrase: String, cipher: String) -> Result<(), CmdError> {
    let cipher = parse_cipher(&cipher)?;
    vault_core::UnlockedVault::create(PathBuf::from(path).as_path(), &passphrase, cipher)?
        .lock();
    Ok(())
}

/// Configure le mot de passe de contrainte AtomasDestruct sur le coffre
/// actuellement déverrouillé : `decoy_path` doit être un coffre déjà
/// existant, ouvrable avec `duress_passphrase` (voir
/// [`create_decoy_vault`] pour en créer un au préalable).
#[tauri::command]
pub fn set_duress(
    state: State<AppState>,
    decoy_path: String,
    duress_passphrase: String,
) -> Result<(), CmdError> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    let vault = guard.as_mut().ok_or_else(locked_err)?;
    vault.set_duress(Path::new(&decoy_path), &duress_passphrase)?;
    Ok(())
}

#[tauri::command]
pub fn clear_duress(state: State<AppState>) -> Result<(), CmdError> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    let vault = guard.as_mut().ok_or_else(locked_err)?;
    vault.clear_duress()?;
    Ok(())
}

/// Active (`Some(seuil)`) ou désactive (`None`) la purge automatique
/// après un nombre de tentatives de déverrouillage échouées consécutives.
#[tauri::command]
pub fn set_auto_wipe(state: State<AppState>, threshold: Option<u32>) -> Result<(), CmdError> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| internal_err("état interne inaccessible"))?;
    let vault = guard.as_mut().ok_or_else(locked_err)?;
    vault.set_auto_wipe(threshold)?;
    Ok(())
}

/// Détruit immédiatement et irréversiblement le coffre actuellement
/// déverrouillé (bouton panique). Consomme le coffre de l'état de
/// session : après cet appel, l'app repasse à l'écran de verrouillage.
#[tauri::command]
pub fn panic_wipe(state: State<AppState>) -> Result<(), CmdError> {
    let vault = {
        let mut guard = state
            .vault
            .lock()
            .map_err(|_| internal_err("état interne inaccessible"))?;
        guard.take().ok_or_else(locked_err)?
    };
    vault.panic_wipe()?;
    Ok(())
}
