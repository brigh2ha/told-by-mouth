//! The server's signing key: loaded from a file, created on first start.

use std::io::Write;
use std::path::Path;

use tbm_core::crypto::SoftwareSigner;

/// Loads the 32-byte private key, or creates one (readable only by this
/// user) if the file does not exist yet.
pub fn load_or_create(path: &Path) -> Result<SoftwareSigner, String> {
    if path.exists() {
        let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        return SoftwareSigner::from_secret_bytes(&bytes)
            .map_err(|_| format!("{} is not a valid server key", path.display()));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    }
    let key = SoftwareSigner::generate();
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| format!("creating {}: {e}", path.display()))?;
    f.write_all(&key.secret_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|e| format!("writing {}: {e}", path.display()))?;
    tracing::warn!(path = %path.display(), "created a new server key; back it up, every certificate depends on it");
    Ok(key)
}
