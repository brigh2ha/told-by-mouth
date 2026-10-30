//! Server configuration, read from a TOML file. See `deploy/tbm-server.toml.example`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on, for example "0.0.0.0:8443".
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// SQLite database (users and revocations only; no reviews).
    pub database: PathBuf,
    /// The server's P-256 private key (32 raw bytes). Created on first start
    /// if missing. Never commit it.
    pub server_key: PathBuf,
    /// Id of that key, carried in every certificate and stamp (1 to 255).
    #[serde(default = "default_key_id")]
    pub server_key_id: u8,
    /// File holding the admin token. If it is missing, admin endpoints are off.
    pub admin_token_file: Option<PathBuf>,
    /// DEVELOPMENT ONLY. Turns on the stub identity check and the stub
    /// device attestation, which accept anything. Never enable in production.
    #[serde(default)]
    pub dev_mode: bool,
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}

fn default_key_id() -> u8 {
    1
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).map_err(|e| format!("parsing {}: {e}", path.display()))?;
        if cfg.server_key_id == 0 {
            return Err("server_key_id must be 1 to 255".into());
        }
        // Relative paths are relative to the config file.
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [&mut cfg.database, &mut cfg.server_key] {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        if let Some(p) = cfg.admin_token_file.as_mut() {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        Ok(cfg)
    }
}
