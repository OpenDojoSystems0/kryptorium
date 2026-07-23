//! Devine un type de contenu approximatif à partir de l'extension du nom
//! de fichier d'origine. Sert uniquement à décider si l'UI peut proposer
//! un aperçu (image) — ce n'est jamais utilisé pour une décision de
//! sécurité.

pub fn guess_content_type(file_name: &str) -> Option<String> {
    let ext = file_name.rsplit('.').next()?.to_ascii_lowercase();
    let mime = match ext.as_str() {
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "svg" => "image/svg+xml",
        "pdf" => "application/pdf",
        "txt" | "md" => "text/plain",
        "zip" => "application/zip",
        _ => return None,
    };
    Some(mime.to_string())
}
