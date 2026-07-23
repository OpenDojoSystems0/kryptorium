<div align="center">
<img src="apps/desktop/src-tauri/icons/128x128.png" width="88" height="88" alt="Kryptorium" />

# Kryptorium

**Gestionnaire de chiffrement de fichiers et d'images, local et open-source.**
XChaCha20-Poly1305 · AES-256-GCM · Argon2id · Linux & macOS

[![CI](https://github.com/OpenDojoSystems0/kryptorium/actions/workflows/ci.yml/badge.svg)](https://github.com/OpenDojoSystems0/kryptorium/actions/workflows/ci.yml)
[![Release](https://github.com/OpenDojoSystems0/kryptorium/actions/workflows/release.yml/badge.svg)](https://github.com/OpenDojoSystems0/kryptorium/actions/workflows/release.yml)
[![License: GPL v3](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-informational)](#compiler-et-lancer)

</div>

---

Kryptorium chiffre vos fichiers et dossiers (documents, images, tout type)
localement, sans dépendance réseau, sous forme d'application desktop pour
**Linux et macOS** — écrite en Rust ([Tauri](https://tauri.app) pour
l'interface, moteur crypto interne sans dépendance UI, entièrement
testable et auditable séparément).

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Architecture](#architecture)
- [Choix cryptographiques](#choix-cryptographiques)
- [Compiler et lancer](#compiler-et-lancer)
- [Utilisation](#utilisation)
- [AtomasDestruct](#atomasdestruct)
- [Limites et avertissements](#limites-et-avertissements)
- [Tests](#tests)
- [Licence](#licence)

## Fonctionnalités

- Chiffrement de fichiers individuels **ou de dossiers entiers** (glisser-déposer, arborescence préservée)
- Choix de l'algorithme à la création du coffre : **XChaCha20-Poly1305** ou **AES-256-GCM**
- Dérivation de clé **Argon2id**, résistante GPU/ASIC
- Aperçu d'images déchiffrées en mémoire, sans fichier temporaire en clair
- Recherche, tags, export sélectif
- Verrouillage automatique après inactivité
- **AtomasDestruct** — mot de passe de contrainte (coffre-leurre), purge après échecs répétés, destruction manuelle immédiate
- Interface claire/sombre automatique, sans Node.js ni bundler côté frontend
- Aucune télémétrie, aucun compte, aucune dépendance réseau

> **Statut** : le moteur crypto (`vault-core`) et le backend Tauri
> compilent et passent tous leurs tests dans cet environnement
> (`cargo test -p vault-core` : 32/32 ; `cargo build -p vault-desktop` :
> sans erreur ; l'écran de verrouillage a été vérifié visuellement). Le
> parcours complet dans l'interface (création → glisser-déposer →
> réglages → export) n'a en revanche pas pu être validé par un clic-à-clic
> automatisé de bout en bout — testez-le vous-même avant de vous fier au
> logiciel pour des données sensibles, et idéalement faites relire le code
> crypto par un tiers compétent. Voir
> [Limites et avertissements](#limites-et-avertissements).

## Architecture

```
kryptorium/
  crates/vault-core/     Moteur de chiffrement + logique de coffre-fort.
                          Pas de dépendance UI : testable et auditable
                          indépendamment de l'application desktop.
  apps/desktop/
    src-tauri/            Backend Tauri (Rust) : expose vault-core via
                           des commandes IPC.
    src/                  Frontend statique (HTML/CSS/JS vanilla, sans
                           bundler ni npm) : window.__TAURI__.core.invoke
                           appelle directement les commandes Rust.
```

### Format du coffre sur disque

```
mon-coffre.vault/
  vault.json     en-tête en clair : version, paramètres Argon2id, sel,
                 clé maître "enveloppée" (chiffrée par la clé dérivée
                 de la passphrase)
  index.enc      nonce (24o) || métadonnées JSON chiffrées par la clé
                 maître (noms de fichiers, tags, dates, tailles...)
  objects/
    <uuid>.enc   contenu de chaque fichier, chiffré par blocs avec une
                 sous-clé dérivée (HKDF-SHA256) de la clé maître
```

### Choix cryptographiques

- **Argon2id** (via la crate `argon2`) pour dériver une clé de
  déverrouillage à partir de la passphrase — résistant aux attaques GPU/ASIC
  et aux canaux auxiliaires. Paramètres par défaut : 128 Mio de mémoire,
  2 itérations (mesuré ~1s en build debug, nettement moins en release sur
  un CPU de bureau récent ; ajustable dans `kdf.rs`).
- **Algorithme de chiffrement au choix**, fixé à la création du coffre
  (bouton « Options avancées » sur l'écran de verrouillage) et immuable
  ensuite :
  - **XChaCha20-Poly1305** (par défaut, recommandé) : nonce de 24 octets,
    ce qui élimine tout risque de collision même généré aléatoirement à
    grande échelle ; implémentation logicielle pure.
  - **AES-256-GCM** : standard largement audité, accéléré matériellement
    (AES-NI) sur la quasi-totalité des CPU récents. Nonce de 12 octets ;
    la sécurité contre les collisions repose sur la sous-clé unique par
    fichier (voir ci-dessous), qui rend un nonce aléatoire de 12 octets
    acceptable.
- La **clé maître** est générée aléatoirement à la création du coffre, puis
  "enveloppée" (chiffrée) par la clé dérivée de la passphrase. Changer de
  passphrase ne nécessite donc pas de re-chiffrer tous les fichiers.
- Chaque fichier est chiffré avec une **sous-clé dérivée par HKDF**
  (clé maître + UUID du fichier), pas directement avec la clé maître — pour
  la séparation de domaine et limiter la portée d'un `crypto-shredding`
  ciblé si nécessaire.
- Chiffrement **en flux, par blocs de 1 Mio**, avec nonce dérivé du
  compteur de bloc et AAD authentifiant la position/dernier-bloc : toute
  troncature ou ajout de données au fichier chiffré est détecté (voir les
  tests dans `file_crypto.rs`).
- Toute clé/passphrase en mémoire est enveloppée dans `zeroize::Zeroizing`,
  effacée dès qu'elle sort de portée (verrouillage du coffre ou fermeture
  de l'app).
- Écritures **atomiques** (fichier temporaire + `fsync` + `rename`) pour
  l'en-tête et l'index, afin qu'un crash ne corrompe jamais ces fichiers.

## Compiler et lancer

### Pré-requis communs

- [Rust](https://rustup.rs) (édition 2021, toolchain stable récente)
- L'outil `tauri-cli` :
  ```bash
  cargo install tauri-cli --version "^2"
  ```
- **Aucun Node.js/npm n'est requis** : le frontend est en HTML/CSS/JS
  statique, servi directement (`frontendDist: "../src"` dans
  `tauri.conf.json`).

### Linux

Dépendances système (exemple Debian/Ubuntu) :
```bash
sudo apt update
sudo apt install -y libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev patchelf build-essential curl wget file
```
(Sur Fedora/Arch, voir la [doc officielle Tauri](https://tauri.app/start/prerequisites/) pour les paquets équivalents.)

### macOS

```bash
xcode-select --install
```
(Xcode Command Line Tools suffisent, pas besoin de l'IDE complet.)

### Lancer en développement

D'abord, valider le moteur crypto seul (rapide, ne nécessite aucune
dépendance GUI) :
```bash
cd kryptorium
cargo test -p vault-core
```

Puis lancer l'application :
```bash
cd apps/desktop
cargo tauri dev
```

### Construire un binaire distribuable

```bash
cd apps/desktop
cargo tauri build
```
Les paquets générés (AppImage/.deb sur Linux, .app/.dmg sur macOS) se
trouvent sous `apps/desktop/src-tauri/target/release/bundle/`.

> Un jeu d'icônes basique (cadenas) est déjà fourni dans
> `apps/desktop/src-tauri/icons/`. Pour le remplacer par votre propre
> design, régénérez-le avec :
> ```bash
> cargo tauri icon /chemin/vers/une-image-1024x1024.png
> ```

## Utilisation

1. Au premier lancement, choisissez un emplacement de coffre (un dossier,
   par défaut `~/Kryptorium`) et un mot de passe (8 caractères minimum,
   privilégiez une phrase longue plutôt qu'un mot complexe court). Le lien
   « Options avancées » permet de choisir l'algorithme de chiffrement
   (XChaCha20-Poly1305 ou AES-256-GCM) — uniquement pertinent pour la
   création d'un nouveau coffre.
2. « Créer un nouveau coffre » l'initialise ; « Déverrouiller » ouvre un
   coffre existant.
3. Glissez-déposez des **fichiers ou des dossiers entiers** dans la zone
   dédiée pour les chiffrer et les ajouter au coffre. Pour un dossier,
   l'arborescence relative est préservée dans le nom affiché (ex.
   `Photos/vacances/img.png`). Les fichiers/dossiers d'origine ne sont ni
   modifiés ni supprimés.
4. « Aperçu » affiche les images directement déchiffrées en mémoire (sans
   écrire de fichier temporaire en clair sur disque).
5. « Exporter » déchiffre un fichier vers un chemin choisi.
6. « Supprimer » écrase puis retire l'objet chiffré du coffre.
7. Le bouton **Réglages** (icône engrenage) affiche les informations de
   sécurité du coffre (algorithme, paramètres Argon2id, date de création,
   nombre de fichiers), permet de changer le mot de passe et de configurer
   le **verrouillage automatique** après inactivité (jamais / 1 / 5 / 15 /
   30 minutes, réglage conservé localement dans le navigateur intégré).
8. « Verrouiller » efface la clé maître de la mémoire du process.

## AtomasDestruct

Section « AtomasDestruct » du panneau Réglages : protections contre la
contrainte, conçues pour ne **jamais** se déclencher automatiquement sur
une simple détection d'altération/corruption (voir la discussion de
conception ci-dessous — c'est un choix délibéré, pas un oubli).

- **Mot de passe de contrainte** : un second mot de passe qui, saisi à
  l'écran de déverrouillage, ouvre silencieusement un coffre-leurre
  entièrement distinct à la place du vrai — rien à l'écran ne permet de
  faire la différence. Le coffre-leurre est un coffre Kryptorium normal
  (à créer/pointer vers un coffre existant, à peupler vous-même avec du
  contenu plausible). **Limite** : ce n'est pas un volume caché façon
  VeraCrypt — le vrai coffre reste présent sur le disque à son propre
  emplacement, et une analyse forensique du support peut révéler son
  existence même si son contenu reste illisible sans la vraie passphrase.
- **Purge après échecs répétés** (désactivée par défaut) : détruit
  irréversiblement le coffre après un nombre configurable de mots de
  passe incorrects consécutifs saisis *dans cette application*.
  **Limite** : le compteur est un simple fichier en clair sur disque, pas
  un compteur matériel inviolable — quelqu'un ayant déjà un accès en
  écriture au dossier du coffre peut le remettre à zéro, ou copier le
  coffre ailleurs pour retenter le déverrouillage hors ligne sans limite.
  C'est Argon2id, pas ce compteur, qui protège contre un attaquant
  disposant déjà d'une copie complète du coffre.
- **Destruction immédiate** : bouton panique manuel, confirmation par
  saisie d'une phrase exacte, irréversible.

**Pourquoi pas d'auto-destruction sur simple détection d'altération ?**
C'était la demande initiale, et le choix de conception mérite d'être
documenté : le chiffrement authentifié utilisé par Kryptorium détecte
*toute* altération d'un octet, qu'elle vienne d'une attaque réelle ou
d'un accident (secteur disque défaillant, coupure de courant, bug d'un
outil de synchronisation). Détruire automatiquement sur ce seul signal
aurait deux effets pervers : (1) n'importe qui ayant un accès en écriture
à un seul octet de vos fichiers chiffrés — une clé USB, une synchro
cloud, un accès physique bref — pourrait détruire tout votre coffre sans
jamais casser le chiffrement, simplement en modifiant ce bit ; (2) un
accident matériel banal ferait perdre les données définitivement, sans
recours. Les protections ci-dessus visent la même intention (résister à
la contrainte, façon Snowden) sans ce risque d'auto-sabotage.

## Limites et avertissements

Pour être honnête sur ce que cet outil protège réellement :

- **Confidentialité au repos** : oui, un attaquant qui copie le dossier du
  coffre sans connaître la passphrase ne peut pas en extraire le contenu
  (Argon2id + XChaCha20-Poly1305, tests d'altération inclus).
- **Ce que ça ne protège PAS** :
  - Un attaquant qui compromet la machine *pendant que le coffre est
    déverrouillé* (malware, accès physique avec session active) peut lire
    la clé en mémoire ou les fichiers déchiffrés que vous exportez.
  - Un keylogger capturant votre passphrase à la saisie.
  - La suppression "sécurisée" (`delete_file`) écrase le contenu du
    fichier chiffré avant de le retirer, mais sur SSD (wear leveling) ou
    systèmes de fichiers copy-on-write (Btrfs, ZFS, APFS), ceci ne garantit
    **pas** l'effacement physique des blocs d'origine. La seule garantie
    forte reste de ne jamais perdre le contrôle de la clé/passphrase.
  - Ce logiciel n'a pas fait l'objet d'un audit de sécurité externe. Ne
    l'utilisez pas tel quel pour des données à très fort enjeu (accusations
    pénales, journalisme à haut risque, etc.) sans faire réaliser un audit
    indépendant du code cryptographique au préalable.
- La mémoire du process n'est pas verrouillée (`mlock`) contre le swap :
  sur une machine avec swap actif et sans chiffrement de disque, des clés
  pourraient théoriquement transiter par le fichier d'échange. Activer le
  chiffrement de disque complet (LUKS sur Linux, FileVault sur macOS) est
  recommandé en complément.

## Tests

```bash
cargo test -p vault-core
```
Couvre notamment : aller-retour chiffrement/déchiffrement (deux
algorithmes), rejet d'une mauvaise passphrase, détection d'altération
(bit-flip, troncature, ajout de données), changement de passphrase
préservant l'accès aux fichiers, et AtomasDestruct (redirection vers le
coffre-leurre, purge après seuil atteint, remise à zéro du compteur sur
succès, désactivation par défaut, destruction manuelle complète).

## Contribuer

Les *issues* et *pull requests* sont bienvenues. Avant de proposer un
changement touchant à `crates/vault-core` (le moteur crypto), merci
d'inclure des tests couvrant le nouveau comportement — voir les fichiers
`#[cfg(test)]` existants pour le style attendu.

## Licence

Distribué sous licence **GPL-3.0-or-later** — voir [LICENSE](LICENSE).

---

<div align="center">
<sub>Développé par <a href="https://github.com/OpenDojoSystems0">OpenDojoSystems0</a></sub>
</div>
