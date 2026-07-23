//! Structure de l'index du coffre : métadonnées de chaque fichier stocké.
//!
//! L'index entier est sérialisé en JSON puis chiffré comme un unique
//! blob (voir `vault.rs`). Il n'existe donc jamais en clair sur disque.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: Uuid,
    pub original_name: String,
    pub size: u64,
    pub added_at: chrono::DateTime<chrono::Utc>,
    pub tags: Vec<String>,
    pub content_type: Option<String>,
    #[serde(with = "crate::util::b64_vec")]
    pub base_nonce: crate::crypto::Nonce,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Index {
    pub entries: HashMap<Uuid, Entry>,
}

impl Index {
    pub fn new() -> Self {
        Self::default()
    }
}
