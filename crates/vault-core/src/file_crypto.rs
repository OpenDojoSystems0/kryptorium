//! Chiffrement/déchiffrement de fichiers en flux (streaming), par blocs.
//!
//! Un fichier est découpé en blocs de taille fixe `CHUNK_SIZE` (le
//! dernier bloc pouvant être plus court). Chaque bloc est chiffré
//! individuellement avec l'algorithme choisi pour le coffre (voir
//! [`crate::crypto::Cipher`]) :
//!
//! - le nonce du bloc = nonce de base aléatoire (unique par fichier, de
//!   la taille requise par l'algorithme) dont les 4 derniers octets sont
//!   XORés avec le compteur de bloc en big-endian. Le nonce de base étant
//!   unique par fichier (généré aléatoirement) et le compteur ne se
//!   répétant jamais au sein d'un même fichier, l'unicité (clé, nonce)
//!   est garantie ;
//! - l'AAD de chaque bloc contient le compteur de bloc et un booléen
//!   "dernier bloc" (`is_last`). Ces deux valeurs sont recalculées de
//!   façon identique et indépendante par l'émetteur et le récepteur en
//!   observant simplement la position dans le flux (EOF ou non) : elles
//!   ne sont donc jamais stockées en clair. Un attaquant qui tronque ou
//!   ajoute des blocs au fichier chiffré change la position d'EOF perçue
//!   par le déchiffreur, ce qui fait diverger l'AAD recalculé de celui
//!   utilisé au chiffrement -> échec d'authentification.
//! - en complément, la taille totale déchiffrée est comparée à la taille
//!   originale (authentifiée séparément, dans l'index chiffré) : toute
//!   troncature de blocs complets est ainsi détectée même dans les cas
//!   limites.

use std::io::{BufRead, BufReader, Read, Write};

use crate::crypto::{self, Cipher, Key, Nonce};
use crate::error::{Result, VaultError};

pub const CHUNK_SIZE: usize = 1024 * 1024; // 1 MiB de texte clair par bloc

fn derive_chunk_nonce(base: &Nonce, counter: u32) -> Nonce {
    let mut n = base.clone();
    let ctr_bytes = counter.to_be_bytes();
    let start = n.len() - 4;
    for i in 0..4 {
        n[start + i] ^= ctr_bytes[i];
    }
    n
}

fn build_aad(counter: u32, is_last: bool) -> [u8; 5] {
    let mut aad = [0u8; 5];
    aad[0..4].copy_from_slice(&counter.to_be_bytes());
    aad[4] = is_last as u8;
    aad
}

/// Remplit `buf` en lisant `reader` de façon répétée jusqu'à ce qu'il
/// soit plein ou que le flux atteigne EOF. Retourne le nombre d'octets
/// effectivement lus (peut être < buf.len() uniquement en cas d'EOF).
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

/// Chiffre le contenu de `reader` vers `writer`. Retourne le nonce de
/// base (à conserver dans l'index) et la taille totale en clair.
pub fn encrypt_stream<R: Read, W: Write>(
    cipher: Cipher,
    reader: R,
    mut writer: W,
    key: &Key,
) -> Result<(Nonce, u64)> {
    let base_nonce = crypto::random_nonce(cipher);
    let mut reader = BufReader::with_capacity(CHUNK_SIZE + 1, reader);
    let mut buf = vec![0u8; CHUNK_SIZE];
    let mut counter: u32 = 0;
    let mut total: u64 = 0;

    loop {
        let n = read_full(&mut reader, &mut buf)?;
        total += n as u64;

        let more_after = !reader.fill_buf()?.is_empty();
        let is_last = !more_after;

        let nonce = derive_chunk_nonce(&base_nonce, counter);
        let aad = build_aad(counter, is_last);
        let ct = crypto::seal(cipher, key, &nonce, &aad, &buf[..n])?;
        writer.write_all(&ct)?;

        counter = counter
            .checked_add(1)
            .ok_or_else(|| VaultError::Crypto("fichier trop volumineux (trop de blocs)".into()))?;

        if is_last {
            break;
        }
    }

    writer.flush()?;
    Ok((base_nonce, total))
}

/// Déchiffre le flux produit par [`encrypt_stream`]. `expected_len` doit
/// provenir d'une source authentifiée (l'index chiffré) : elle sert de
/// garde-fou contre la troncature de blocs complets en fin de fichier.
pub fn decrypt_stream<R: Read, W: Write>(
    cipher: Cipher,
    reader: R,
    mut writer: W,
    key: &Key,
    base_nonce: &Nonce,
    expected_len: u64,
) -> Result<()> {
    let ct_chunk_size: usize = CHUNK_SIZE + crypto::TAG_LEN;

    let mut reader = BufReader::with_capacity(ct_chunk_size + 1, reader);
    let mut buf = vec![0u8; ct_chunk_size];
    let mut counter: u32 = 0;
    let mut total: u64 = 0;

    loop {
        let n = read_full(&mut reader, &mut buf)?;
        if n < crypto::TAG_LEN {
            // Il ne reste même pas assez d'octets pour un tag valide :
            // flux tronqué de façon incohérente.
            return Err(VaultError::TamperedOrCorrupt);
        }

        let more_after = !reader.fill_buf()?.is_empty();
        let is_last = !more_after;

        let nonce = derive_chunk_nonce(base_nonce, counter);
        let aad = build_aad(counter, is_last);
        let pt = crypto::open(cipher, key, &nonce, &aad, &buf[..n])?;
        writer.write_all(&pt)?;
        total += pt.len() as u64;

        counter = counter
            .checked_add(1)
            .ok_or(VaultError::TamperedOrCorrupt)?;

        if is_last {
            break;
        }
    }

    writer.flush()?;

    if total != expected_len {
        return Err(VaultError::TamperedOrCorrupt);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::random_key;
    use std::io::Cursor;

    fn roundtrip(cipher: Cipher, plaintext: &[u8]) {
        let key = *random_key();
        let mut ciphertext = Vec::new();
        let (nonce, len) =
            encrypt_stream(cipher, Cursor::new(plaintext), &mut ciphertext, &key).unwrap();
        assert_eq!(len, plaintext.len() as u64);

        let mut out = Vec::new();
        decrypt_stream(cipher, Cursor::new(&ciphertext), &mut out, &key, &nonce, len).unwrap();
        assert_eq!(out, plaintext);
    }

    const CIPHERS: [Cipher; 2] = [Cipher::XChaCha20Poly1305, Cipher::Aes256Gcm];

    #[test]
    fn empty_file() {
        for c in CIPHERS {
            roundtrip(c, b"");
        }
    }

    #[test]
    fn small_file() {
        for c in CIPHERS {
            roundtrip(c, b"hello, world!");
        }
    }

    #[test]
    fn exact_multiple_of_chunk_size() {
        let data = vec![0x42u8; CHUNK_SIZE * 2];
        for c in CIPHERS {
            roundtrip(c, &data);
        }
    }

    #[test]
    fn multi_chunk_with_remainder() {
        let mut data = vec![0u8; CHUNK_SIZE * 2 + 137];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        for c in CIPHERS {
            roundtrip(c, &data);
        }
    }

    #[test]
    fn truncation_is_detected() {
        for cipher in CIPHERS {
            let key = *random_key();
            let data = vec![0x11u8; CHUNK_SIZE + 500];
            let mut ciphertext = Vec::new();
            let (nonce, len) =
                encrypt_stream(cipher, Cursor::new(&data), &mut ciphertext, &key).unwrap();

            // Tronque après le premier bloc complet : il ne reste plus le
            // dernier bloc.
            ciphertext.truncate(CHUNK_SIZE + crypto::TAG_LEN);

            let mut out = Vec::new();
            let err = decrypt_stream(cipher, Cursor::new(&ciphertext), &mut out, &key, &nonce, len);
            assert!(err.is_err());
        }
    }

    #[test]
    fn appended_garbage_is_detected() {
        for cipher in CIPHERS {
            let key = *random_key();
            let data = vec![0x22u8; 100];
            let mut ciphertext = Vec::new();
            let (nonce, len) =
                encrypt_stream(cipher, Cursor::new(&data), &mut ciphertext, &key).unwrap();

            ciphertext.extend_from_slice(b"garbage-appended-data");

            let mut out = Vec::new();
            let err = decrypt_stream(cipher, Cursor::new(&ciphertext), &mut out, &key, &nonce, len);
            assert!(err.is_err());
        }
    }

    #[test]
    fn bit_flip_is_detected() {
        for cipher in CIPHERS {
            let key = *random_key();
            let data = vec![0x33u8; 100];
            let mut ciphertext = Vec::new();
            let (nonce, len) =
                encrypt_stream(cipher, Cursor::new(&data), &mut ciphertext, &key).unwrap();

            ciphertext[10] ^= 0x01;

            let mut out = Vec::new();
            let err = decrypt_stream(cipher, Cursor::new(&ciphertext), &mut out, &key, &nonce, len);
            assert!(err.is_err());
        }
    }

    #[test]
    fn wrong_expected_len_is_detected() {
        for cipher in CIPHERS {
            let key = *random_key();
            let data = vec![0x44u8; 100];
            let mut ciphertext = Vec::new();
            let (nonce, _len) =
                encrypt_stream(cipher, Cursor::new(&data), &mut ciphertext, &key).unwrap();

            let mut out = Vec::new();
            let err = decrypt_stream(cipher, Cursor::new(&ciphertext), &mut out, &key, &nonce, 99);
            assert!(err.is_err());
        }
    }
}
