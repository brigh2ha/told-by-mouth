//! SQLite storage: people (as a hash of the identity provider's reference),
//! issued certificates and revocations. No names, no reviews, no visits.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use tbm_core::crypto::{sha256, PublicKey};
use tbm_core::model::{RevokedKey, UserId};

pub struct Db {
    conn: Connection,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS users (
    user_id     BLOB PRIMARY KEY,
    person_hash BLOB NOT NULL UNIQUE,
    created_at  INTEGER NOT NULL,
    revoked_at  INTEGER
);
CREATE TABLE IF NOT EXISTS certificates (
    device_key  BLOB NOT NULL,
    user_id     BLOB NOT NULL REFERENCES users(user_id),
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    revoked_at  INTEGER
);
CREATE INDEX IF NOT EXISTS certificates_key ON certificates(device_key);
CREATE INDEX IF NOT EXISTS certificates_user ON certificates(user_id);
";

fn sql_err(e: rusqlite::Error) -> String {
    format!("database: {e}")
}

/// The stored form of a provider's person reference.
pub fn person_hash(provider: &str, person_ref: &str) -> [u8; 32] {
    sha256(format!("tbm/person/1\0{provider}\0{person_ref}").as_bytes())
}

impl Db {
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
        }
        Self::init(Connection::open(path).map_err(sql_err)?)
    }

    pub fn open_in_memory() -> Result<Self, String> {
        Self::init(Connection::open_in_memory().map_err(sql_err)?)
    }

    fn init(conn: Connection) -> Result<Self, String> {
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(sql_err)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(sql_err)?;
        conn.execute_batch(SCHEMA).map_err(sql_err)?;
        Ok(Self { conn })
    }

    /// The user id for this person, created on first sight. Also returns
    /// whether the person is revoked.
    pub fn user_for_person(
        &self,
        person_hash: &[u8; 32],
        now: u64,
    ) -> Result<(UserId, bool), String> {
        let found: Option<(Vec<u8>, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT user_id, revoked_at FROM users WHERE person_hash = ?1",
                params![&person_hash[..]],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(sql_err)?;
        if let Some((id, revoked)) = found {
            let id: UserId = id
                .try_into()
                .map_err(|_| "bad user id in database".to_string())?;
            return Ok((id, revoked.is_some()));
        }
        let id: UserId = tbm_core::crypto::random_bytes();
        self.conn
            .execute(
                "INSERT INTO users (user_id, person_hash, created_at) VALUES (?1, ?2, ?3)",
                params![&id[..], &person_hash[..], now as i64],
            )
            .map_err(sql_err)?;
        Ok((id, false))
    }

    pub fn user_revoked(&self, user: &UserId) -> Result<Option<bool>, String> {
        self.conn
            .query_row(
                "SELECT revoked_at FROM users WHERE user_id = ?1",
                params![&user[..]],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()
            .map(|o| o.map(|r| r.is_some()))
            .map_err(sql_err)
    }

    pub fn record_certificate(
        &self,
        user: &UserId,
        key: &PublicKey,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT INTO certificates (device_key, user_id, issued_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
                params![&key.0[..], &user[..], issued_at as i64, expires_at as i64],
            )
            .map_err(sql_err)?;
        Ok(())
    }

    /// Revokes every key of this user except `keep`, from `now` on (the
    /// person moved to a new phone). Returns how many keys were revoked.
    pub fn revoke_other_keys(
        &self,
        user: &UserId,
        keep: &PublicKey,
        now: u64,
    ) -> Result<usize, String> {
        self.conn
            .execute(
                "UPDATE certificates SET revoked_at = ?3
                 WHERE user_id = ?1 AND device_key != ?2 AND revoked_at IS NULL",
                params![&user[..], &keep.0[..], now as i64],
            )
            .map_err(sql_err)
    }

    /// The user a key was certified for, if the key is known and not revoked.
    pub fn active_key_owner(&self, key: &PublicKey) -> Result<Option<UserId>, String> {
        let row: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT user_id FROM certificates WHERE device_key = ?1 AND revoked_at IS NULL LIMIT 1",
                params![&key.0[..]],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql_err)?;
        row.map(|v| {
            v.try_into()
                .map_err(|_| "bad user id in database".to_string())
        })
        .transpose()
    }

    pub fn revoke_user(&self, user: &UserId, now: u64) -> Result<bool, String> {
        let n = self
            .conn
            .execute(
                "UPDATE users SET revoked_at = ?2 WHERE user_id = ?1 AND revoked_at IS NULL",
                params![&user[..], now as i64],
            )
            .map_err(sql_err)?;
        Ok(n > 0)
    }

    pub fn revoke_key(&self, key: &PublicKey, now: u64) -> Result<bool, String> {
        let n = self
            .conn
            .execute(
                "UPDATE certificates SET revoked_at = ?2 WHERE device_key = ?1 AND revoked_at IS NULL",
                params![&key.0[..], now as i64],
            )
            .map_err(sql_err)?;
        Ok(n > 0)
    }

    /// Everything that goes into the signed revocation list.
    pub fn revocations(&self) -> Result<(Vec<UserId>, Vec<RevokedKey>), String> {
        let mut users = Vec::new();
        let mut stmt = self
            .conn
            .prepare("SELECT user_id FROM users WHERE revoked_at IS NOT NULL")
            .map_err(sql_err)?;
        for row in stmt
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map_err(sql_err)?
        {
            let id: UserId = row
                .map_err(sql_err)?
                .try_into()
                .map_err(|_| "bad user id in database".to_string())?;
            users.push(id);
        }
        let mut keys = Vec::new();
        let mut stmt = self
            .conn
            .prepare(
                "SELECT device_key, MIN(revoked_at) FROM certificates
                 WHERE revoked_at IS NOT NULL GROUP BY device_key",
            )
            .map_err(sql_err)?;
        for row in stmt
            .query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?)))
            .map_err(sql_err)?
        {
            let (key, since) = row.map_err(sql_err)?;
            keys.push(RevokedKey {
                key: PublicKey::from_sec1(&key).map_err(|_| "bad key in database".to_string())?,
                since: since as u64,
            });
        }
        Ok((users, keys))
    }
}
