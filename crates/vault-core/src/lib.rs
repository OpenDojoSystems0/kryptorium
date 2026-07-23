//! `vault-core` : moteur de chiffrement et de coffre-fort de fichiers,
//! indépendant de toute UI.
//!
//! Voir [`vault::UnlockedVault`] pour l'API principale, et les
//! commentaires en tête de `vault.rs` pour le format sur disque.

pub mod crypto;
pub mod error;
pub mod file_crypto;
pub mod index;
pub mod kdf;
pub mod mime;
pub mod util;
pub mod vault;

pub use crypto::Cipher;
pub use error::{Result, VaultError};
pub use index::Entry;
pub use vault::{
    looks_like_vault, unlock_checked, UnlockOutcome, UnlockedVault, VaultInfo, MAX_PREVIEW_BYTES,
};
