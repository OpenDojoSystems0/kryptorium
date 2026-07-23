//! Primitives AEAD et dérivation de sous-clés (HKDF-SHA256).
//!
//! Deux algorithmes de chiffrement authentifié sont proposés, choisis
//! une fois pour toutes à la création d'un coffre (voir [`Cipher`]) :
//!
//! - **XChaCha20-Poly1305** (recommandé, par défaut) : nonce de 24 octets,
//!   ce qui élimine tout risque de collision de nonce même généré
//!   aléatoirement à grande échelle. Implémentation en logiciel pur,
//!   résistante par construction aux attaques par canal auxiliaire liées
//!   au cache (contrairement à une implémentation AES non accélérée).
//! - **AES-256-GCM** : standard largement audité et accéléré matériellement
//!   (AES-NI) sur la quasi-totalité des CPU récents, donc potentiellement
//!   plus rapide sur de gros volumes. Nonce de 12 octets ; la sécurité
//!   contre les collisions repose ici sur la dérivation d'une sous-clé
//!   unique par fichier (voir `derive_subkey`), qui rend un nonce
//!   aléatoire de 12 octets acceptable (les nonces ne doivent être
//!   uniques que par clé, jamais réutilisés à l'échelle du coffre entier).
//!
//! Dans les deux cas, l'étiquette d'authentification fait 16 octets.

use aes_gcm::Aes256Gcm;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

pub const KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

pub type Key = [u8; KEY_LEN];
/// Nonce de taille variable : 24 octets pour XChaCha20-Poly1305, 12 pour
/// AES-256-GCM (voir [`Cipher::nonce_len`]).
pub type Nonce = Vec<u8>;

/// Algorithme de chiffrement authentifié utilisé par un coffre. Choisi à
/// la création et immuable ensuite (change de mot de passe ≠ change
/// d'algorithme : ce dernier nécessiterait de rechiffrer tous les
/// fichiers, ce qui n'est pas fait automatiquement).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cipher {
    #[serde(rename = "xchacha20poly1305")]
    XChaCha20Poly1305,
    #[serde(rename = "aes256gcm")]
    Aes256Gcm,
}

impl Cipher {
    pub fn nonce_len(self) -> usize {
        match self {
            Cipher::XChaCha20Poly1305 => 24,
            Cipher::Aes256Gcm => 12,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Cipher::XChaCha20Poly1305 => "XChaCha20-Poly1305",
            Cipher::Aes256Gcm => "AES-256-GCM",
        }
    }
}

impl Default for Cipher {
    fn default() -> Self {
        Cipher::XChaCha20Poly1305
    }
}

pub fn random_nonce(cipher: Cipher) -> Nonce {
    let mut n = vec![0u8; cipher.nonce_len()];
    OsRng.fill_bytes(&mut n);
    n
}

pub fn random_key() -> Zeroizing<Key> {
    let mut k = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(k.as_mut());
    k
}

/// Chiffre `plaintext` avec AAD lié (authentifié mais non chiffré).
pub fn seal(cipher: Cipher, key: &Key, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match cipher {
        Cipher::XChaCha20Poly1305 => {
            let c = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| VaultError::Crypto("clé de taille invalide".into()))?;
            c.encrypt(XNonce::from_slice(nonce), payload)
                .map_err(|_| VaultError::Crypto("échec du chiffrement AEAD".into()))
        }
        Cipher::Aes256Gcm => {
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|_| VaultError::Crypto("clé de taille invalide".into()))?;
            c.encrypt(aes_gcm::Nonce::from_slice(nonce), payload)
                .map_err(|_| VaultError::Crypto("échec du chiffrement AEAD".into()))
        }
    }
}

/// Déchiffre et vérifie l'intégrité/l'authenticité. Toute altération du
/// ciphertext, du nonce ou de l'AAD fait échouer cette fonction.
pub fn open(cipher: Cipher, key: &Key, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    match cipher {
        Cipher::XChaCha20Poly1305 => {
            let c = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| VaultError::Crypto("clé de taille invalide".into()))?;
            c.decrypt(XNonce::from_slice(nonce), payload)
                .map_err(|_| VaultError::TamperedOrCorrupt)
        }
        Cipher::Aes256Gcm => {
            let c = Aes256Gcm::new_from_slice(key)
                .map_err(|_| VaultError::Crypto("clé de taille invalide".into()))?;
            c.decrypt(aes_gcm::Nonce::from_slice(nonce), payload)
                .map_err(|_| VaultError::TamperedOrCorrupt)
        }
    }
}

/// Dérive une sous-clé de 32 octets à partir d'une clé maître, avec un
/// sel (typiquement l'identifiant de l'objet) et une info contextuelle
/// (domain separation). Permet d'éviter que deux objets du coffre
/// partagent la même clé de chiffrement, et prépare le terrain pour un
/// "crypto-shredding" ciblé si nécessaire.
pub fn derive_subkey(master_key: &Key, salt: &[u8], info: &[u8]) -> Zeroizing<Key> {
    let hk = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    // hk.expand ne peut échouer que si la longueur demandée est
    // absurdement grande (> 255 * taille de hash) ; 32 octets est
    // toujours valide, donc on peut dérouler l'erreur en toute sécurité.
    hk.expand(info, okm.as_mut())
        .expect("HKDF expand vers 32 octets ne peut pas échouer");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip_for(cipher: Cipher) {
        let key = *random_key();
        let nonce = random_nonce(cipher);
        let aad = b"contexte";
        let pt = b"donnees secretes";

        let ct = seal(cipher, &key, &nonce, aad, pt).unwrap();
        let recovered = open(cipher, &key, &nonce, aad, &ct).unwrap();
        assert_eq!(recovered, pt);
    }

    #[test]
    fn seal_open_roundtrip_xchacha() {
        roundtrip_for(Cipher::XChaCha20Poly1305);
    }

    #[test]
    fn seal_open_roundtrip_aes_gcm() {
        roundtrip_for(Cipher::Aes256Gcm);
    }

    #[test]
    fn tampering_ciphertext_is_detected() {
        for cipher in [Cipher::XChaCha20Poly1305, Cipher::Aes256Gcm] {
            let key = *random_key();
            let nonce = random_nonce(cipher);
            let aad = b"contexte";
            let mut ct = seal(cipher, &key, &nonce, aad, b"donnees secretes").unwrap();
            ct[0] ^= 0xFF;
            assert!(open(cipher, &key, &nonce, aad, &ct).is_err());
        }
    }

    #[test]
    fn tampering_aad_is_detected() {
        for cipher in [Cipher::XChaCha20Poly1305, Cipher::Aes256Gcm] {
            let key = *random_key();
            let nonce = random_nonce(cipher);
            let ct = seal(cipher, &key, &nonce, b"aad-1", b"donnees").unwrap();
            assert!(open(cipher, &key, &nonce, b"aad-2", &ct).is_err());
        }
    }

    #[test]
    fn wrong_key_fails() {
        for cipher in [Cipher::XChaCha20Poly1305, Cipher::Aes256Gcm] {
            let key1 = *random_key();
            let key2 = *random_key();
            let nonce = random_nonce(cipher);
            let ct = seal(cipher, &key1, &nonce, b"", b"donnees").unwrap();
            assert!(open(cipher, &key2, &nonce, b"", &ct).is_err());
        }
    }

    #[test]
    fn subkeys_are_distinct_per_salt() {
        let master = *random_key();
        let k1 = derive_subkey(&master, b"id-1", b"vault-file-key");
        let k2 = derive_subkey(&master, b"id-2", b"vault-file-key");
        assert_ne!(*k1, *k2);
    }
}
