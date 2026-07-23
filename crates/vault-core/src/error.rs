use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("erreur d'entrée/sortie: {0}")]
    Io(#[from] std::io::Error),

    #[error("mot de passe incorrect")]
    WrongPassphrase,

    #[error("données altérées ou corrompues (échec d'authentification)")]
    TamperedOrCorrupt,

    #[error("erreur de (dé)sérialisation: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("entrée introuvable dans le coffre")]
    NotFound,

    #[error("un coffre existe déjà à cet emplacement")]
    AlreadyExists,

    #[error("aucun coffre trouvé à cet emplacement")]
    VaultNotFound,

    #[error("paramètres KDF invalides: {0}")]
    InvalidKdfParams(String),

    #[error("erreur cryptographique: {0}")]
    Crypto(String),

    #[error("le coffre est verrouillé")]
    Locked,

    #[error("fichier trop volumineux pour cette opération")]
    TooLarge,

    #[error("le coffre a été détruit (seuil de tentatives échouées atteint)")]
    Wiped,
}

pub type Result<T> = std::result::Result<T, VaultError>;
