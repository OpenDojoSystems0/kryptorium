//! API haut niveau du coffre-fort : création, déverrouillage, ajout,
//! export, suppression, rotation de passphrase.
//!
//! Disposition sur disque :
//! ```text
//! mon-coffre.vault/
//!   vault.json     en-tête en clair : version, algorithme choisi,
//!                  paramètres Argon2id, clé maître enveloppée (chiffrée
//!                  par la clé dérivée de la passphrase)
//!   index.enc      nonce || (métadonnées JSON chiffrées par la clé
//!                  maître)
//!   objects/
//!     <uuid>.enc   contenu de chaque fichier, chiffré en flux par une
//!                  sous-clé dérivée (HKDF) de la clé maître
//! ```

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, Cipher, Key};
use crate::error::{Result, VaultError};
use crate::file_crypto;
use crate::index::{Entry, Index};
use crate::kdf::KdfParams;
use crate::mime::guess_content_type;
use crate::util;

const FORMAT_VERSION: u32 = 2;
const HEADER_FILE: &str = "vault.json";
const INDEX_FILE: &str = "index.enc";
const OBJECTS_DIR: &str = "objects";

const WRAP_AAD: &[u8] = b"vault-master-key-wrap-v1";
const INDEX_AAD: &[u8] = b"vault-index-v1";
const FILE_KEY_INFO: &[u8] = b"vault-file-key-v1";
const DURESS_AAD: &[u8] = b"vault-duress-decoy-path-v1";
const ATTEMPTS_FILE: &str = "attempts.json";

/// Taille maximale acceptée pour un déchiffrement en mémoire (aperçu),
/// afin d'éviter qu'un fichier énorme ne sature la RAM du process GUI.
pub const MAX_PREVIEW_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB

#[derive(Debug, Serialize, Deserialize)]
struct VaultHeader {
    version: u32,
    created_at: chrono::DateTime<Utc>,
    #[serde(default)]
    cipher: Cipher,
    kdf: KdfParams,
    #[serde(with = "util::b64_vec")]
    wrapped_master_key: Vec<u8>,
    #[serde(with = "util::b64_vec")]
    wrap_nonce: Vec<u8>,
    /// AtomasDestruct : mot de passe de contrainte (leurre). Absent si
    /// non configuré.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duress: Option<DuressConfig>,
    /// AtomasDestruct : nombre de tentatives de déverrouillage échouées
    /// consécutives au-delà duquel le coffre est détruit. `None` ou `0`
    /// = désactivé (comportement par défaut).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    auto_wipe_after: Option<u32>,
}

/// AtomasDestruct — mot de passe de contrainte : dérive une KEK distincte
/// de celle du vrai mot de passe et enveloppe le chemin d'un coffre
/// "leurre" totalement séparé. Voir [`try_duress`].
#[derive(Debug, Serialize, Deserialize)]
struct DuressConfig {
    kdf: KdfParams,
    #[serde(with = "util::b64_vec")]
    wrap_nonce: Vec<u8>,
    #[serde(with = "util::b64_vec")]
    wrapped_decoy_path: Vec<u8>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Attempts {
    failed_count: u32,
}

fn header_path(root: &Path) -> PathBuf {
    root.join(HEADER_FILE)
}
fn index_path(root: &Path) -> PathBuf {
    root.join(INDEX_FILE)
}
fn objects_dir(root: &Path) -> PathBuf {
    root.join(OBJECTS_DIR)
}
fn object_path(root: &Path, id: Uuid) -> PathBuf {
    objects_dir(root).join(format!("{id}.enc"))
}
fn attempts_path(root: &Path) -> PathBuf {
    root.join(ATTEMPTS_FILE)
}

fn read_header(root: &Path) -> Result<VaultHeader> {
    let header_bytes = fs::read(header_path(root)).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            VaultError::VaultNotFound
        } else {
            VaultError::Io(e)
        }
    })?;
    Ok(serde_json::from_slice(&header_bytes)?)
}

fn write_header(root: &Path, header: &VaultHeader) -> Result<()> {
    util::atomic_write(
        &header_path(root),
        serde_json::to_string_pretty(header)?.as_bytes(),
    )
}

/// Essaie `passphrase` comme mot de passe de contrainte pour le coffre
/// `root`. Retourne le chemin du coffre-leurre associé si ça correspond.
fn try_duress(header: &VaultHeader, passphrase: &str) -> Option<PathBuf> {
    let duress = header.duress.as_ref()?;
    let kek = duress.kdf.derive(passphrase).ok()?;
    let bytes = crypto::open(
        header.cipher,
        &kek,
        &duress.wrap_nonce,
        DURESS_AAD,
        &duress.wrapped_decoy_path,
    )
    .ok()?;
    Some(PathBuf::from(String::from_utf8_lossy(&bytes).into_owned()))
}

fn read_attempts(root: &Path) -> u32 {
    fs::read(attempts_path(root))
        .ok()
        .and_then(|b| serde_json::from_slice::<Attempts>(&b).ok())
        .map(|a| a.failed_count)
        .unwrap_or(0)
}

fn reset_attempts(root: &Path) {
    let _ = fs::remove_file(attempts_path(root));
}

/// Enregistre une tentative de déverrouillage échouée. Si le seuil
/// AtomasDestruct configuré est atteint, détruit immédiatement le coffre
/// et retourne `true`.
fn record_failed_attempt(root: &Path, header: &VaultHeader) -> Result<bool> {
    let threshold = match header.auto_wipe_after {
        Some(t) if t > 0 => t,
        _ => return Ok(false),
    };

    let count = read_attempts(root) + 1;
    if count >= threshold {
        panic_wipe_path(root)?;
        return Ok(true);
    }

    util::atomic_write(
        &attempts_path(root),
        serde_json::to_vec(&Attempts { failed_count: count })?.as_slice(),
    )?;
    Ok(false)
}

/// AtomasDestruct — destruction immédiate et irréversible d'un coffre à
/// `root` : écrase chaque objet chiffré, l'index, l'en-tête et le
/// compteur de tentatives avant suppression (voir les limites
/// documentées dans [`util::secure_overwrite_and_remove`]), puis retire
/// les répertoires devenus vides. N'a besoin d'aucune clé — fonctionne
/// même après un mot de passe erroné.
fn panic_wipe_path(root: &Path) -> Result<()> {
    if let Ok(entries) = fs::read_dir(objects_dir(root)) {
        for entry in entries.flatten() {
            let _ = util::secure_overwrite_and_remove(&entry.path());
        }
    }
    let _ = util::secure_overwrite_and_remove(&index_path(root));
    let _ = util::secure_overwrite_and_remove(&header_path(root));
    let _ = util::secure_overwrite_and_remove(&attempts_path(root));
    let _ = fs::remove_dir(objects_dir(root));
    let _ = fs::remove_dir(root);
    Ok(())
}

/// Résultat d'un déverrouillage passant par [`unlock_checked`] : soit le
/// vrai coffre, soit — si le mot de passe de contrainte AtomasDestruct a
/// été saisi — le chemin du coffre-leurre à ouvrir à la place (avec la
/// même passphrase).
pub enum UnlockOutcome {
    Real(UnlockedVault),
    Duress { decoy_path: PathBuf },
}

/// Déverrouille `root` en tenant compte d'AtomasDestruct : reconnaît un
/// éventuel mot de passe de contrainte, et comptabilise les échecs pour
/// déclencher la purge automatique si elle est activée. À utiliser à la
/// place de [`UnlockedVault::unlock`] partout où la saisie vient d'un
/// utilisateur (GUI/CLI) plutôt que d'un appel interne au moteur.
pub fn unlock_checked(root: &Path, passphrase: &str) -> Result<UnlockOutcome> {
    match UnlockedVault::unlock(root, passphrase) {
        Ok(vault) => {
            reset_attempts(root);
            Ok(UnlockOutcome::Real(vault))
        }
        Err(VaultError::WrongPassphrase) => {
            let header = read_header(root)?;
            if let Some(decoy_path) = try_duress(&header, passphrase) {
                reset_attempts(root);
                return Ok(UnlockOutcome::Duress { decoy_path });
            }
            if record_failed_attempt(root, &header)? {
                return Err(VaultError::Wiped);
            }
            Err(VaultError::WrongPassphrase)
        }
        Err(e) => Err(e),
    }
}

/// Informations publiques (non secrètes) sur un coffre déverrouillé,
/// destinées à l'affichage dans l'UI (panneau réglages).
#[derive(Debug, Clone, Serialize)]
pub struct VaultInfo {
    pub cipher_label: &'static str,
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub created_at: String,
    pub entry_count: usize,
    pub duress_configured: bool,
    pub auto_wipe_after: Option<u32>,
}

/// Un coffre déverrouillé. La clé maître ne vit qu'en mémoire, dans un
/// buffer `Zeroizing` remis à zéro à la destruction (drop) de la
/// structure — que ce soit via [`UnlockedVault::lock`] ou simplement en
/// sortant de portée.
pub struct UnlockedVault {
    root: PathBuf,
    master_key: Zeroizing<Key>,
    cipher: Cipher,
    created_at: chrono::DateTime<Utc>,
    kdf_memory_kib: u32,
    kdf_iterations: u32,
    index: Index,
}

impl UnlockedVault {
    /// Crée un nouveau coffre à l'emplacement `root` (qui doit être vide
    /// ou inexistant) protégé par `passphrase`, chiffré avec `cipher`.
    pub fn create(root: &Path, passphrase: &str, cipher: Cipher) -> Result<Self> {
        if root.exists() && fs::read_dir(root)?.next().is_some() {
            return Err(VaultError::AlreadyExists);
        }
        fs::create_dir_all(objects_dir(root))?;

        let master_key = crypto::random_key();
        let kdf = KdfParams::generate_default();
        let kek = kdf.derive(passphrase)?;
        let wrap_nonce = crypto::random_nonce(cipher);
        let wrapped = crypto::seal(cipher, &kek, &wrap_nonce, WRAP_AAD, master_key.as_slice())?;
        let created_at = Utc::now();

        let header = VaultHeader {
            version: FORMAT_VERSION,
            created_at,
            cipher,
            kdf: kdf.clone(),
            wrapped_master_key: wrapped,
            wrap_nonce,
            duress: None,
            auto_wipe_after: None,
        };
        util::atomic_write(
            &header_path(root),
            serde_json::to_string_pretty(&header)?.as_bytes(),
        )?;

        let vault = UnlockedVault {
            root: root.to_path_buf(),
            master_key,
            cipher,
            created_at,
            kdf_memory_kib: kdf.m_cost_kib,
            kdf_iterations: kdf.t_cost,
            index: Index::new(),
        };
        vault.save_index()?;
        Ok(vault)
    }

    /// Déverrouille un coffre existant. Retourne
    /// [`VaultError::WrongPassphrase`] si la passphrase ne correspond
    /// pas, sans distinguer davantage (pour ne pas donner d'indice à un
    /// attaquant).
    pub fn unlock(root: &Path, passphrase: &str) -> Result<Self> {
        let header_bytes = fs::read(header_path(root)).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VaultError::VaultNotFound
            } else {
                VaultError::Io(e)
            }
        })?;
        let header: VaultHeader = serde_json::from_slice(&header_bytes)?;

        let kek = header.kdf.derive(passphrase)?;
        let master_key_vec = crypto::open(
            header.cipher,
            &kek,
            &header.wrap_nonce,
            WRAP_AAD,
            &header.wrapped_master_key,
        )
        .map_err(|_| VaultError::WrongPassphrase)?;
        let master_key: Key = master_key_vec
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Crypto("clé maître de taille invalide".into()))?;
        let master_key = Zeroizing::new(master_key);

        let index = Self::load_index(root, header.cipher, &master_key)?;

        Ok(UnlockedVault {
            root: root.to_path_buf(),
            master_key,
            cipher: header.cipher,
            created_at: header.created_at,
            kdf_memory_kib: header.kdf.m_cost_kib,
            kdf_iterations: header.kdf.t_cost,
            index,
        })
    }

    /// Verrouille explicitement le coffre (efface la clé maître de la
    /// mémoire immédiatement plutôt que d'attendre le drop implicite).
    pub fn lock(self) {
        drop(self);
    }

    pub fn info(&self) -> VaultInfo {
        let header = read_header(&self.root).ok();
        VaultInfo {
            cipher_label: self.cipher.label(),
            kdf_memory_kib: self.kdf_memory_kib,
            kdf_iterations: self.kdf_iterations,
            created_at: self.created_at.to_rfc3339(),
            entry_count: self.index.entries.len(),
            duress_configured: header.as_ref().is_some_and(|h| h.duress.is_some()),
            auto_wipe_after: header.and_then(|h| h.auto_wipe_after),
        }
    }

    fn load_index(root: &Path, cipher: Cipher, master_key: &Key) -> Result<Index> {
        let raw = fs::read(index_path(root))?;
        let nonce_len = cipher.nonce_len();
        if raw.len() < nonce_len {
            return Err(VaultError::TamperedOrCorrupt);
        }
        let (nonce, ct) = raw.split_at(nonce_len);
        let plain = crypto::open(cipher, master_key, nonce, INDEX_AAD, ct)?;
        let index: Index = serde_json::from_slice(&plain)?;
        Ok(index)
    }

    fn save_index(&self) -> Result<()> {
        let plain = serde_json::to_vec(&self.index)?;
        let nonce = crypto::random_nonce(self.cipher);
        let ct = crypto::seal(self.cipher, &self.master_key, &nonce, INDEX_AAD, &plain)?;
        let mut out = Vec::with_capacity(nonce.len() + ct.len());
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        util::atomic_write(&index_path(&self.root), &out)
    }

    /// Liste les entrées du coffre, triées par date d'ajout.
    pub fn list(&self) -> Vec<Entry> {
        let mut v: Vec<_> = self.index.entries.values().cloned().collect();
        v.sort_by(|a, b| a.added_at.cmp(&b.added_at));
        v
    }

    pub fn get_entry(&self, id: Uuid) -> Option<&Entry> {
        self.index.entries.get(&id)
    }

    /// Chiffre `source` et l'ajoute au coffre sous son propre nom de
    /// fichier. Le fichier en clair d'origine n'est jamais modifié ni
    /// supprimé par cette fonction.
    pub fn add_file(&mut self, source: &Path, tags: Vec<String>) -> Result<Uuid> {
        let name = source
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("fichier")
            .to_string();
        self.add_file_named(source, name, tags)
    }

    /// Comme [`Self::add_file`], mais avec un nom d'affichage explicite
    /// (utilisé pour préserver l'arborescence lors de l'ajout d'un
    /// dossier entier : `display_name` peut alors contenir des `/`).
    pub fn add_file_named(
        &mut self,
        source: &Path,
        display_name: String,
        tags: Vec<String>,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let content_type = guess_content_type(&display_name);

        let file_key = crypto::derive_subkey(&self.master_key, id.as_bytes(), FILE_KEY_INFO);
        let in_file = fs::File::open(source)?;
        let obj_path = object_path(&self.root, id);
        let tmp_path = util::temp_sibling(&obj_path, "write");

        let (base_nonce, size) = {
            let out_file = fs::File::create(&tmp_path)?;
            let mut writer = std::io::BufWriter::new(out_file);
            let result = file_crypto::encrypt_stream(self.cipher, in_file, &mut writer, &file_key);
            match result {
                Ok(v) => v,
                Err(e) => {
                    let _ = fs::remove_file(&tmp_path);
                    return Err(e);
                }
            }
        };
        fs::rename(&tmp_path, &obj_path)?;

        let entry = Entry {
            id,
            original_name: display_name,
            size,
            added_at: Utc::now(),
            tags,
            content_type,
            base_nonce,
        };
        self.index.entries.insert(id, entry);

        if let Err(e) = self.save_index() {
            self.index.entries.remove(&id);
            let _ = fs::remove_file(&obj_path);
            return Err(e);
        }
        Ok(id)
    }

    /// Déchiffre l'entrée `id` vers le fichier `dest` (écriture atomique).
    pub fn export_file(&self, id: Uuid, dest: &Path) -> Result<()> {
        let entry = self.index.entries.get(&id).ok_or(VaultError::NotFound)?;
        let file_key = crypto::derive_subkey(&self.master_key, id.as_bytes(), FILE_KEY_INFO);
        let in_file = fs::File::open(object_path(&self.root, id))?;
        let tmp_dest = util::temp_sibling(dest, "export");

        {
            let out_file = fs::File::create(&tmp_dest)?;
            let mut writer = std::io::BufWriter::new(out_file);
            if let Err(e) = file_crypto::decrypt_stream(
                self.cipher,
                in_file,
                &mut writer,
                &file_key,
                &entry.base_nonce,
                entry.size,
            ) {
                let _ = fs::remove_file(&tmp_dest);
                return Err(e);
            }
        }
        fs::rename(&tmp_dest, dest)?;
        Ok(())
    }

    /// Déchiffre l'entrée `id` entièrement en mémoire (pour un aperçu
    /// dans l'UI, typiquement une image). Refuse les fichiers de plus de
    /// `max_bytes`.
    pub fn decrypt_to_memory(&self, id: Uuid, max_bytes: u64) -> Result<Vec<u8>> {
        let entry = self.index.entries.get(&id).ok_or(VaultError::NotFound)?;
        if entry.size > max_bytes {
            return Err(VaultError::TooLarge);
        }
        let file_key = crypto::derive_subkey(&self.master_key, id.as_bytes(), FILE_KEY_INFO);
        let in_file = fs::File::open(object_path(&self.root, id))?;
        let mut out = Vec::with_capacity(entry.size as usize);
        file_crypto::decrypt_stream(
            self.cipher,
            in_file,
            &mut out,
            &file_key,
            &entry.base_nonce,
            entry.size,
        )?;
        Ok(out)
    }

    /// Supprime une entrée : écrase l'objet chiffré sur disque avant de
    /// le retirer (voir les limites documentées dans
    /// [`util::secure_overwrite_and_remove`]), puis met à jour l'index.
    pub fn delete_file(&mut self, id: Uuid) -> Result<()> {
        if !self.index.entries.contains_key(&id) {
            return Err(VaultError::NotFound);
        }
        let path = object_path(&self.root, id);
        util::secure_overwrite_and_remove(&path)?;
        self.index.entries.remove(&id);
        self.save_index()
    }

    pub fn set_tags(&mut self, id: Uuid, tags: Vec<String>) -> Result<()> {
        let entry = self.index.entries.get_mut(&id).ok_or(VaultError::NotFound)?;
        entry.tags = tags;
        self.save_index()
    }

    /// Change la passphrase du coffre : re-dérive une nouvelle KEK avec
    /// de nouveaux paramètres/sel Argon2id et ré-enveloppe la même clé
    /// maître. Les fichiers déjà chiffrés ne sont PAS ré-écrits (ils
    /// dépendent de la clé maître, pas directement de la passphrase),
    /// et l'algorithme de chiffrement du coffre ne change pas.
    pub fn change_passphrase(&mut self, old: &str, new: &str) -> Result<()> {
        let header_bytes = fs::read(header_path(&self.root))?;
        let mut header: VaultHeader = serde_json::from_slice(&header_bytes)?;

        let old_kek = header.kdf.derive(old)?;
        let unwrapped = crypto::open(
            header.cipher,
            &old_kek,
            &header.wrap_nonce,
            WRAP_AAD,
            &header.wrapped_master_key,
        )
        .map_err(|_| VaultError::WrongPassphrase)?;
        if unwrapped.as_slice() != self.master_key.as_slice() {
            return Err(VaultError::WrongPassphrase);
        }

        let new_kdf = KdfParams::generate_default();
        let new_kek = new_kdf.derive(new)?;
        let new_wrap_nonce = crypto::random_nonce(header.cipher);
        let new_wrapped = crypto::seal(
            header.cipher,
            &new_kek,
            &new_wrap_nonce,
            WRAP_AAD,
            self.master_key.as_slice(),
        )?;

        header.kdf = new_kdf;
        header.wrapped_master_key = new_wrapped;
        header.wrap_nonce = new_wrap_nonce;

        util::atomic_write(
            &header_path(&self.root),
            serde_json::to_string_pretty(&header)?.as_bytes(),
        )
    }

    /// AtomasDestruct — configure un mot de passe de contrainte : saisi à
    /// l'écran de verrouillage, il ouvrira `decoy_vault_path` (un coffre
    /// entièrement distinct, normal, déjà protégé par ce même
    /// `duress_passphrase`) au lieu de ce coffre-ci. Ne modifie ni ne
    /// touche au coffre-leurre lui-même : il doit déjà exister et être
    /// déverrouillable avec `duress_passphrase` (vérifié avant
    /// d'enregistrer la configuration).
    ///
    /// Limite importante : ceci n'est qu'un leurre logiciel — le vrai
    /// coffre reste présent sur le disque à son propre emplacement. Ce
    /// n'est pas un volume caché façon VeraCrypt ; une analyse forensique
    /// du disque peut révéler son existence même si son contenu reste
    /// illisible sans la vraie passphrase.
    pub fn set_duress(&mut self, decoy_vault_path: &Path, duress_passphrase: &str) -> Result<()> {
        if duress_passphrase.is_empty() {
            return Err(VaultError::Crypto(
                "le mot de passe de contrainte ne peut pas être vide".into(),
            ));
        }
        // Vérifie que le coffre-leurre existe bel et bien et s'ouvre avec
        // ce mot de passe, pour ne pas enregistrer une configuration
        // cassée qui laisserait l'utilisateur sans porte de sortie sous
        // contrainte.
        UnlockedVault::unlock(decoy_vault_path, duress_passphrase)?.lock();

        let kdf = KdfParams::generate_default();
        let kek = kdf.derive(duress_passphrase)?;
        let wrap_nonce = crypto::random_nonce(self.cipher);
        let path_bytes = decoy_vault_path.to_string_lossy().into_owned().into_bytes();
        let wrapped = crypto::seal(self.cipher, &kek, &wrap_nonce, DURESS_AAD, &path_bytes)?;

        let mut header = read_header(&self.root)?;
        header.duress = Some(DuressConfig {
            kdf,
            wrap_nonce,
            wrapped_decoy_path: wrapped,
        });
        write_header(&self.root, &header)
    }

    /// Désactive le mot de passe de contrainte AtomasDestruct.
    pub fn clear_duress(&mut self) -> Result<()> {
        let mut header = read_header(&self.root)?;
        header.duress = None;
        write_header(&self.root, &header)
    }

    /// AtomasDestruct — active/désactive la purge automatique après
    /// `threshold` tentatives de déverrouillage échouées consécutives.
    /// `None` ou `Some(0)` désactive. Réinitialise le compteur en cours.
    ///
    /// Limite importante : ce compteur est un fichier en clair sur
    /// disque, pas un compteur matériel inviolable. Quelqu'un ayant déjà
    /// un accès en écriture au dossier du coffre peut le remettre à zéro
    /// ou copier le coffre ailleurs pour retenter le déverrouillage hors
    /// ligne sans limite. Cette protection vise les tentatives répétées
    /// depuis l'interface elle-même, pas un attaquant disposant déjà
    /// d'une copie complète du coffre — c'est Argon2id qui protège contre
    /// ce dernier cas.
    pub fn set_auto_wipe(&mut self, threshold: Option<u32>) -> Result<()> {
        let mut header = read_header(&self.root)?;
        header.auto_wipe_after = threshold.filter(|t| *t > 0);
        write_header(&self.root, &header)?;
        reset_attempts(&self.root);
        Ok(())
    }

    /// AtomasDestruct — destruction immédiate et irréversible de CE
    /// coffre, déclenchée volontairement (bouton panique). Écrase et
    /// supprime tous les fichiers chiffrés, l'index et l'en-tête. Ne
    /// peut pas être annulée.
    pub fn panic_wipe(self) -> Result<()> {
        let root = self.root.clone();
        drop(self);
        panic_wipe_path(&root)
    }
}

/// Vérifie sans déverrouiller si un dossier ressemble à un coffre valide.
pub fn looks_like_vault(root: &Path) -> bool {
    header_path(root).is_file() && index_path(root).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const ALL_CIPHERS: [Cipher; 2] = [Cipher::XChaCha20Poly1305, Cipher::Aes256Gcm];

    #[test]
    fn create_unlock_roundtrip() {
        for cipher in ALL_CIPHERS {
            let dir = tempdir().unwrap();
            let vault_path = dir.path().join("test.vault");

            let vault =
                UnlockedVault::create(&vault_path, "correct horse battery staple", cipher).unwrap();
            vault.lock();

            let vault = UnlockedVault::unlock(&vault_path, "correct horse battery staple").unwrap();
            assert!(vault.list().is_empty());
            assert_eq!(vault.info().cipher_label, cipher.label());
        }
    }

    #[test]
    fn wrong_passphrase_rejected() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");

        UnlockedVault::create(&vault_path, "right-passphrase", Cipher::default())
            .unwrap()
            .lock();

        match UnlockedVault::unlock(&vault_path, "wrong-passphrase") {
            Err(VaultError::WrongPassphrase) => {}
            Err(other) => panic!("attendu WrongPassphrase, obtenu une autre erreur: {other}"),
            Ok(_) => panic!("le déverrouillage aurait dû échouer avec une mauvaise passphrase"),
        }
    }

    #[test]
    fn add_export_file_roundtrip() {
        for cipher in ALL_CIPHERS {
            let dir = tempdir().unwrap();
            let vault_path = dir.path().join("test.vault");
            let src_path = dir.path().join("secret.txt");
            std::fs::write(&src_path, b"contenu tres secret").unwrap();

            let mut vault = UnlockedVault::create(&vault_path, "pw", cipher).unwrap();
            let id = vault.add_file(&src_path, vec!["perso".into()]).unwrap();

            let entries = vault.list();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].original_name, "secret.txt");
            assert_eq!(entries[0].tags, vec!["perso".to_string()]);

            let dest_path = dir.path().join("recovered.txt");
            vault.export_file(id, &dest_path).unwrap();
            let recovered = std::fs::read(&dest_path).unwrap();
            assert_eq!(recovered, b"contenu tres secret");
        }
    }

    #[test]
    fn add_file_named_preserves_relative_path() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");
        let src_path = dir.path().join("img.png");
        std::fs::write(&src_path, b"donnees-image").unwrap();

        let mut vault = UnlockedVault::create(&vault_path, "pw", Cipher::default()).unwrap();
        let id = vault
            .add_file_named(&src_path, "Photos/vacances/img.png".to_string(), vec![])
            .unwrap();

        let entry = vault.get_entry(id).unwrap();
        assert_eq!(entry.original_name, "Photos/vacances/img.png");
        assert_eq!(entry.content_type.as_deref(), Some("image/png"));
    }

    #[test]
    fn deleted_file_is_gone_and_object_removed() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");
        let src_path = dir.path().join("secret.txt");
        std::fs::write(&src_path, b"a effacer").unwrap();

        let mut vault = UnlockedVault::create(&vault_path, "pw", Cipher::default()).unwrap();
        let id = vault.add_file(&src_path, vec![]).unwrap();
        let obj_path = object_path(&vault_path, id);
        assert!(obj_path.exists());

        vault.delete_file(id).unwrap();
        assert!(!obj_path.exists());
        assert!(vault.list().is_empty());
        assert!(matches!(
            vault.export_file(id, &dir.path().join("out.txt")).unwrap_err(),
            VaultError::NotFound
        ));
    }

    #[test]
    fn tampered_object_fails_export() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");
        let src_path = dir.path().join("secret.txt");
        std::fs::write(&src_path, b"donnees integres").unwrap();

        let mut vault = UnlockedVault::create(&vault_path, "pw", Cipher::default()).unwrap();
        let id = vault.add_file(&src_path, vec![]).unwrap();

        let obj_path = object_path(&vault_path, id);
        let mut bytes = std::fs::read(&obj_path).unwrap();
        bytes[0] ^= 0xFF;
        std::fs::write(&obj_path, bytes).unwrap();

        let dest_path = dir.path().join("out.txt");
        let err = vault.export_file(id, &dest_path).unwrap_err();
        assert!(matches!(err, VaultError::TamperedOrCorrupt));
    }

    #[test]
    fn change_passphrase_then_unlock_with_new() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");

        let mut vault = UnlockedVault::create(&vault_path, "old-pw", Cipher::default()).unwrap();
        vault.change_passphrase("old-pw", "new-pw").unwrap();
        drop(vault);

        assert!(UnlockedVault::unlock(&vault_path, "old-pw").is_err());
        assert!(UnlockedVault::unlock(&vault_path, "new-pw").is_ok());
    }

    #[test]
    fn change_passphrase_preserves_files() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");
        let src_path = dir.path().join("secret.txt");
        std::fs::write(&src_path, b"toujours la").unwrap();

        let mut vault = UnlockedVault::create(&vault_path, "old-pw", Cipher::default()).unwrap();
        let id = vault.add_file(&src_path, vec![]).unwrap();
        vault.change_passphrase("old-pw", "new-pw").unwrap();
        drop(vault);

        let vault = UnlockedVault::unlock(&vault_path, "new-pw").unwrap();
        let dest = dir.path().join("out.txt");
        vault.export_file(id, &dest).unwrap();
        assert_eq!(std::fs::read(dest).unwrap(), b"toujours la");
    }

    // ---------- AtomasDestruct ----------

    #[test]
    fn duress_passphrase_redirects_to_decoy_vault() {
        let dir = tempdir().unwrap();
        let real_path = dir.path().join("real.vault");
        let decoy_path = dir.path().join("decoy.vault");

        let mut real_vault =
            UnlockedVault::create(&real_path, "vrai-mot-de-passe", Cipher::default()).unwrap();
        UnlockedVault::create(&decoy_path, "mot-de-passe-leurre", Cipher::default())
            .unwrap()
            .lock();

        real_vault
            .set_duress(&decoy_path, "mot-de-passe-leurre")
            .unwrap();
        drop(real_vault);

        match unlock_checked(&real_path, "mot-de-passe-leurre").unwrap() {
            UnlockOutcome::Duress { decoy_path: got } => assert_eq!(got, decoy_path),
            UnlockOutcome::Real(_) => panic!("attendu une redirection vers le coffre-leurre"),
        }

        // Le vrai mot de passe continue de fonctionner normalement.
        match unlock_checked(&real_path, "vrai-mot-de-passe").unwrap() {
            UnlockOutcome::Real(_) => {}
            UnlockOutcome::Duress { .. } => panic!("le vrai mot de passe n'aurait pas dû être pris pour le leurre"),
        }
    }

    #[test]
    fn unlock_checked_propagates_vault_not_found() {
        let dir = tempdir().unwrap();
        let real_path = dir.path().join("does-not-exist.vault");

        match unlock_checked(&real_path, "n'importe quoi") {
            Err(VaultError::VaultNotFound) => {}
            Err(other) => panic!("attendu VaultNotFound, obtenu une autre erreur: {other}"),
            Ok(_) => panic!("un coffre inexistant ne devrait jamais s'ouvrir"),
        }
    }

    #[test]
    fn wrong_passphrase_without_duress_configured_is_plain_wrong_passphrase() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");
        UnlockedVault::create(&vault_path, "pw", Cipher::default())
            .unwrap()
            .lock();

        match unlock_checked(&vault_path, "pas-le-bon-mdp") {
            Err(VaultError::WrongPassphrase) => {}
            Err(other) => panic!("attendu WrongPassphrase, obtenu une autre erreur: {other}"),
            Ok(_) => panic!("un mauvais mot de passe n'aurait pas dû fonctionner"),
        }
    }

    #[test]
    fn auto_wipe_triggers_after_threshold_failed_attempts() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");
        let mut vault = UnlockedVault::create(&vault_path, "pw", Cipher::default()).unwrap();
        vault.set_auto_wipe(Some(3)).unwrap();
        drop(vault);

        assert!(matches!(
            unlock_checked(&vault_path, "mauvais-1"),
            Err(VaultError::WrongPassphrase)
        ));
        assert!(matches!(
            unlock_checked(&vault_path, "mauvais-2"),
            Err(VaultError::WrongPassphrase)
        ));
        // 3e échec consécutif : purge.
        assert!(matches!(unlock_checked(&vault_path, "mauvais-3"), Err(VaultError::Wiped)));

        assert!(!looks_like_vault(&vault_path));
    }

    #[test]
    fn successful_unlock_resets_the_failed_attempt_counter() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");
        let mut vault = UnlockedVault::create(&vault_path, "pw", Cipher::default()).unwrap();
        vault.set_auto_wipe(Some(3)).unwrap();
        drop(vault);

        assert!(matches!(
            unlock_checked(&vault_path, "mauvais-1"),
            Err(VaultError::WrongPassphrase)
        ));
        assert!(matches!(
            unlock_checked(&vault_path, "mauvais-2"),
            Err(VaultError::WrongPassphrase)
        ));
        // Déverrouillage correct : remet le compteur à zéro.
        match unlock_checked(&vault_path, "pw").unwrap() {
            UnlockOutcome::Real(v) => v.lock(),
            UnlockOutcome::Duress { .. } => panic!("inattendu"),
        }

        // Deux nouveaux échecs ne doivent pas déclencher la purge
        // (le compteur repartait de zéro, pas de 2).
        assert!(matches!(
            unlock_checked(&vault_path, "mauvais-3"),
            Err(VaultError::WrongPassphrase)
        ));
        assert!(matches!(
            unlock_checked(&vault_path, "mauvais-4"),
            Err(VaultError::WrongPassphrase)
        ));
        assert!(looks_like_vault(&vault_path));
    }

    #[test]
    fn auto_wipe_disabled_by_default() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");
        UnlockedVault::create(&vault_path, "pw", Cipher::default())
            .unwrap()
            .lock();

        for i in 0..20 {
            assert!(matches!(
                unlock_checked(&vault_path, &format!("mauvais-{i}")),
                Err(VaultError::WrongPassphrase)
            ));
        }
        assert!(looks_like_vault(&vault_path));
    }

    #[test]
    fn panic_wipe_destroys_everything() {
        let dir = tempdir().unwrap();
        let vault_path = dir.path().join("test.vault");
        let src_path = dir.path().join("secret.txt");
        std::fs::write(&src_path, b"a supprimer").unwrap();

        let mut vault = UnlockedVault::create(&vault_path, "pw", Cipher::default()).unwrap();
        vault.add_file(&src_path, vec![]).unwrap();

        vault.panic_wipe().unwrap();

        assert!(!looks_like_vault(&vault_path));
        assert!(!vault_path.join("index.enc").exists());
        assert!(!vault_path.join("vault.json").exists());
    }

    #[test]
    fn set_duress_rejects_unreachable_decoy() {
        let dir = tempdir().unwrap();
        let real_path = dir.path().join("real.vault");
        let decoy_path = dir.path().join("decoy.vault");

        let mut real_vault = UnlockedVault::create(&real_path, "pw", Cipher::default()).unwrap();
        UnlockedVault::create(&decoy_path, "leurre-pw", Cipher::default())
            .unwrap()
            .lock();

        // Mauvais mot de passe de contrainte par rapport à celui du
        // coffre-leurre : la configuration doit être refusée, pas
        // enregistrée à moitié.
        let err = real_vault.set_duress(&decoy_path, "mauvais-mdp-leurre");
        assert!(err.is_err());

        drop(real_vault);
        // Le coffre réel doit toujours s'ouvrir normalement, sans leurre
        // configuré.
        match unlock_checked(&real_path, "pw").unwrap() {
            UnlockOutcome::Real(v) => assert!(!v.info().duress_configured),
            UnlockOutcome::Duress { .. } => panic!("inattendu"),
        }
    }
}
