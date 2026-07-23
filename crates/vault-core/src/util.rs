//! Petits utilitaires partagés (encodage base64 pour serde, écriture atomique).

use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::RngCore;

use crate::error::{Result, VaultError};

/// (Dé)sérialise un `Vec<u8>` en base64 standard pour serde.
pub mod b64_vec {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Écrit `data` dans `path` de façon atomique : écriture dans un fichier
/// temporaire du même répertoire, `fsync`, puis renommage. Évite qu'un
/// crash ou une coupure de courant laisse un fichier d'index ou d'en-tête
/// à moitié écrit.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or_else(|| {
        VaultError::Crypto("chemin de destination sans répertoire parent".into())
    })?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| VaultError::Crypto("nom de fichier invalide".into()))?;
    let tmp_path = dir.join(format!(".{file_name}.tmp-{}", std::process::id()));

    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Construit un chemin de fichier temporaire "voisin" de `path`, dans le
/// même répertoire (pour permettre un `rename` atomique sur le même
/// système de fichiers), avec un `tag` et le PID pour éviter les
/// collisions entre opérations concurrentes.
pub fn temp_sibling(path: &Path, tag: &str) -> PathBuf {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("fichier");
    dir.join(format!(".{name}.{tag}-{}.tmp", std::process::id()))
}

/// Écrase le contenu d'un fichier avec des octets aléatoires avant de le
/// supprimer, puis supprime le fichier.
///
/// Limite honnête : sur un SSD moderne (wear leveling) ou un système de
/// fichiers journalisé/copy-on-write (Btrfs, ZFS, APFS...), cette
/// opération ne garantit PAS l'effacement physique des données sur le
/// support — le firmware ou le système de fichiers peuvent avoir déplacé
/// les blocs originaux ailleurs. C'est un durcissement best-effort, pas
/// une garantie cryptographique. La seule garantie forte contre la
/// récupération de données supprimées est de ne jamais perdre le
/// contrôle de la clé de chiffrement du coffre (voir README).
pub fn secure_overwrite_and_remove(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let len = fs::metadata(path)?.len();
    {
        let mut f = fs::OpenOptions::new().write(true).open(path)?;
        const BUF_LEN: usize = 64 * 1024;
        let mut buf = vec![0u8; BUF_LEN.min(len.max(1) as usize)];
        let mut remaining = len;
        f.seek(SeekFrom::Start(0))?;
        while remaining > 0 {
            let n = buf.len().min(remaining as usize);
            OsRng.fill_bytes(&mut buf[..n]);
            f.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        f.sync_all()?;
    }
    fs::remove_file(path)?;
    Ok(())
}
