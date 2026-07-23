# Changelog

Toutes les modifications notables de ce projet sont documentées ici.
Format inspiré de [Keep a Changelog](https://keepachangelog.com/fr/1.1.0/).

## [0.1.0] - Première version

### Ajouté

- Moteur de chiffrement (`vault-core`) : Argon2id, XChaCha20-Poly1305 et
  AES-256-GCM au choix, chiffrement en flux par blocs avec détection
  d'altération, écritures atomiques.
- Application desktop (Tauri) pour Linux et macOS : création/déverrouillage
  de coffre, glisser-déposer de fichiers et de dossiers entiers, aperçu
  d'images, export, recherche, tags.
- Réglages : informations de sécurité du coffre, changement de mot de
  passe, verrouillage automatique après inactivité.
- **AtomasDestruct** : mot de passe de contrainte (coffre-leurre), purge
  automatique après un nombre configurable d'échecs, destruction manuelle
  immédiate.
- Interface claire/sombre automatique selon le thème système.
