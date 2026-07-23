//! Dérivation de clé à partir de la passphrase (Argon2id).
//!
//! Argon2id est utilisé car il résiste à la fois aux attaques par
//! canal auxiliaire (side-channel) et aux attaques par matériel dédié
//! (GPU/ASIC), contrairement à Argon2i ou Argon2d pris isolément.

use argon2::{Algorithm, Argon2, Params, Version};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};

pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// Paramètres Argon2id persistés dans l'en-tête du coffre (non secrets).
///
/// Les valeurs par défaut visent ~0.5-2s de dérivation sur une machine
/// de bureau récente, avec une empreinte mémoire volontairement élevée
/// pour renchérir les attaques massivement parallèles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    #[serde(with = "crate::util::b64_vec")]
    pub salt: Vec<u8>,
}

impl KdfParams {
    pub fn generate_default() -> Self {
        let mut salt = vec![0u8; SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        KdfParams {
            // Mesuré à ~1s en debug / largement sous la seconde en
            // release sur un CPU de bureau récent (voir README). La
            // crate `argon2` ne parallélise pas p_cost en threads OS
            // réels ici, donc p_cost=1 : monter p_cost n'accélère rien
            // et ne fait qu'allonger le calcul.
            m_cost_kib: 131_072, // 128 MiB
            t_cost: 2,
            p_cost: 1,
            salt,
        }
    }

    fn to_argon2(&self) -> Result<Argon2<'static>> {
        let params = Params::new(self.m_cost_kib, self.t_cost, self.p_cost, Some(KEY_LEN))
            .map_err(|e| VaultError::InvalidKdfParams(e.to_string()))?;
        Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
    }

    /// Dérive une clé de 32 octets à partir de la passphrase. Le résultat
    /// est enveloppé dans `Zeroizing` pour être effacé de la mémoire dès
    /// qu'il sort de portée.
    pub fn derive(&self, passphrase: &str) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let argon2 = self.to_argon2()?;
        let mut out = Zeroizing::new([0u8; KEY_LEN]);
        argon2
            .hash_password_into(passphrase.as_bytes(), &self.salt, out.as_mut())
            .map_err(|e| VaultError::Crypto(format!("argon2: {e}")))?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_is_deterministic_for_same_params() {
        let mut params = KdfParams::generate_default();
        params.m_cost_kib = 8192; // léger pour test rapide
        params.t_cost = 1;
        params.p_cost = 1;

        let k1 = params.derive("correct horse battery staple").unwrap();
        let k2 = params.derive("correct horse battery staple").unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn derive_differs_for_different_passphrase() {
        let mut params = KdfParams::generate_default();
        params.m_cost_kib = 8192;
        params.t_cost = 1;
        params.p_cost = 1;

        let k1 = params.derive("passphrase A").unwrap();
        let k2 = params.derive("passphrase B").unwrap();
        assert_ne!(*k1, *k2);
    }
}
