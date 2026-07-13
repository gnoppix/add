//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------

use sqlx::{Pool, Row, Sqlite, sqlite::SqlitePoolOptions};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::DhtResult;

/// Default value for max encrypted blob size.
const MAX_VALUE_SIZE: usize = 4096;

/// Retention window for the DHT nonce-replay log (seconds). Entries older than
/// this are pruned by the background task (SECURITY FIX L5). 7 days keeps a
/// wide-enough window for legitimate replay detection across restarts without
/// unbounded SQLite growth.
pub const NONCE_RETENTION_SECS: u64 = 7 * 24 * 3600;

/// A single DHT key-value record.
#[derive(Debug, Clone)]
pub struct KvRecord {
    pub value: String,
    pub salt: String,
    pub seq: i64,
    pub publisher_fp: String,
    pub stored_at: f64,
    pub expires_at: f64,
    pub sig: String,
}

/// SQLite-backed persistent DHT storage.
///
/// SECURITY: Keys are stored as-is (they are null IDs which are public).
/// Values are encrypted blobs -- the storage layer never sees plaintext.
#[derive(Clone)]
pub struct DhtStore {
    pool: Pool<Sqlite>,
}

impl DhtStore {
    /// Open or create a DHT store at the given path.
    /// If no path is given, defaults to `~/.add/dht_store.db`.
    pub async fn open(db_path: Option<&str>) -> DhtResult<Self> {
        let path = match db_path {
            Some(p) => p.to_string(),
            None => {
                let mut p = dirs::home_dir().unwrap_or_else(|| std::path::PathBuf::from("."));
                p.push(".add");
                p.push("dht_store.db");
                p.to_string_lossy().to_string()
            }
        };

        // Ensure directory exists
        if let Some(parent) = std::path::Path::new(&path).parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // mode=rwc => open read-write, creating the file if it does not exist.
        // Without this, sqlx only opens an existing db and returns
        // SQLITE_CANTOPEN (code 14) on a fresh host with no pre-created file.
        let url = format!("sqlite://{}?mode=rwc", path);
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await?;

        let store = Self { pool };
        store.init_tables().await?;
        Ok(store)
    }

    /// Open an in-memory store (useful for testing).
    pub async fn open_in_memory() -> DhtResult<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;

        let store = Self { pool };
        store.init_tables().await?;
        Ok(store)
    }

    async fn init_tables(&self) -> DhtResult<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS kv_store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                salt TEXT NOT NULL DEFAULT '',
                seq INTEGER NOT NULL DEFAULT 0,
                publisher_fp TEXT NOT NULL DEFAULT '',
                stored_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                sig TEXT NOT NULL DEFAULT ''
            )
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_expires ON kv_store(expires_at)")
            .execute(&self.pool)
            .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_publisher ON kv_store(publisher_fp)")
            .execute(&self.pool)
            .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS nonce_log (
                key TEXT,
                nonce INTEGER,
                recorded_at INTEGER DEFAULT (strftime('%s','now')),
                PRIMARY KEY(key, nonce)
            ) WITHOUT ROWID
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_nonce_log_recorded ON nonce_log(recorded_at)")
            .execute(&self.pool)
            .await?;

        // WAL mode and foreign keys are set per-connection in SQLite.
        // We set WAL via pragma on each new connection by executing it.
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&self.pool)
            .await?;
        sqlx::query("PRAGMA foreign_keys=ON")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Retrieve a value by key. Returns None if expired or not found.
    pub async fn get(&self, key: &str) -> DhtResult<Option<KvRecord>> {
        let now = now_unix();
        let row = sqlx::query(
            "SELECT value, salt, seq, publisher_fp, stored_at, expires_at, sig \
             FROM kv_store WHERE key = ? AND expires_at > ?",
        )
        .bind(key)
        .bind(now)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => Ok(Some(KvRecord {
                value: r.get::<String, _>("value"),
                salt: r.get::<String, _>("salt"),
                seq: r.get::<i64, _>("seq"),
                publisher_fp: r.get::<String, _>("publisher_fp"),
                stored_at: r.get::<f64, _>("stored_at"),
                expires_at: r.get::<f64, _>("expires_at"),
                sig: r.get::<String, _>("sig"),
            })),
            None => Ok(None),
        }
    }

    /// Store a value. Returns true if stored, false if rejected.
    ///
    /// SECURITY: Only stores if:
    /// - The new seq is higher than existing (prevents replay)
    /// - The value size is within limits
    /// - The nonce has not been seen before for this key (prevents replay across restarts)
    #[allow(clippy::too_many_arguments)]
    pub async fn put(
        &self,
        key: &str,
        value: &str,
        salt: &str,
        seq: i64,
        publisher_fp: &str,
        ttl: i64,
        sig: &str,
        nonce: i64,
    ) -> DhtResult<bool> {
        if value.len() > MAX_VALUE_SIZE {
            tracing::warn!("value too large: {} bytes", value.len());
            return Ok(false);
        }

        // Check nonce for replay protection (persistent across restarts)
        if self.is_nonce_seen(key, nonce).await? {
            tracing::debug!("nonce {} already seen for key {}, rejecting", nonce, key);
            return Ok(false);
        }

        let now = now_unix();
        let expires = now + ttl as f64;

        // Check existing seq for replay protection
        let existing: Option<i64> = sqlx::query_scalar("SELECT seq FROM kv_store WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;

        if let Some(existing_seq) = existing
            && existing_seq >= seq
        {
            tracing::debug!(
                "stale seq {} < existing {} for key {}",
                seq,
                existing_seq,
                key
            );
            return Ok(false);
        }

        // Record nonce and store value in a transaction
        let mut tx = self.pool.begin().await?;

        sqlx::query("INSERT OR IGNORE INTO nonce_log (key, nonce) VALUES (?, ?)")
            .bind(key)
            .bind(nonce)
            .execute(&mut *tx)
            .await?;

        sqlx::query(
            "INSERT OR REPLACE INTO kv_store \
             (key, value, salt, seq, publisher_fp, stored_at, expires_at, sig) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(key)
        .bind(value)
        .bind(salt)
        .bind(seq)
        .bind(publisher_fp)
        .bind(now)
        .bind(expires)
        .bind(sig)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(true)
    }

    /// Delete all expired records. Returns the number of deleted rows.
    pub async fn delete_expired(&self) -> DhtResult<u64> {
        let now = now_unix();
        let result = sqlx::query("DELETE FROM kv_store WHERE expires_at <= ?")
            .bind(now)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// Count non-expired keys.
    pub async fn count_keys(&self) -> DhtResult<i64> {
        let now = now_unix();
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kv_store WHERE expires_at > ?")
            .bind(now)
            .fetch_one(&self.pool)
            .await?;
        Ok(count)
    }

    /// Check if we already have the same (key, or key+nonce) recorded.
    pub async fn has_key(&self, key: &str) -> DhtResult<bool> {
        let row: Option<i64> = sqlx::query_scalar("SELECT 1 FROM kv_store WHERE key = ?")
            .bind(key)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some())
    }

    /// Check if a nonce has already been recorded for the given key.
    /// Provides persistent replay protection across node restarts.
    pub async fn is_nonce_seen(&self, key: &str, nonce: i64) -> DhtResult<bool> {
        let row: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM nonce_log WHERE key = ? AND nonce = ?")
                .bind(key)
                .bind(nonce)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.is_some())
    }

    /// Record a nonce for the given key. Called after successful put.
    /// INSERT OR IGNORE makes this idempotent — re-recording is a no-op.
    pub async fn record_nonce(&self, key: &str, nonce: i64) -> DhtResult<()> {
        sqlx::query("INSERT OR IGNORE INTO nonce_log (key, nonce) VALUES (?, ?)")
            .bind(key)
            .bind(nonce)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Prune nonce log entries older than the given cutoff timestamp (unix epoch seconds).
    /// Call periodically to prevent unbounded growth.
    /// Default retention: 7 days (604800 seconds).
    pub async fn prune_old_nonces(&self, cutoff_timestamp: i64) -> DhtResult<u64> {
        let result = sqlx::query("DELETE FROM nonce_log WHERE recorded_at < ?")
            .bind(cutoff_timestamp)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let store = DhtStore::open_in_memory().await.unwrap();

        let result = store.get("NN-TEST-0001").await.unwrap();
        assert!(result.is_none());

        let stored = store
            .put(
                "NN-TEST-0001",
                "base64blob",
                "somesalt",
                1,
                "AABB",
                3600,
                "b64sig",
                1001,
            )
            .await
            .unwrap();
        assert!(stored);

        let record = store.get("NN-TEST-0001").await.unwrap().unwrap();
        assert_eq!(record.value, "base64blob");
        assert_eq!(record.salt, "somesalt");
        assert_eq!(record.seq, 1);
        assert_eq!(record.publisher_fp, "AABB");
    }

    #[tokio::test]
    async fn test_replay_protection() {
        let store = DhtStore::open_in_memory().await.unwrap();

        store
            .put(
                "NN-TEST-0002",
                "blob1",
                "salt1",
                5,
                "FP1",
                3600,
                "sig1",
                2001,
            )
            .await
            .unwrap();

        // Same seq should be rejected
        let stored = store
            .put(
                "NN-TEST-0002",
                "blob2",
                "salt2",
                5,
                "FP1",
                3600,
                "sig2",
                2002,
            )
            .await
            .unwrap();
        assert!(!stored);

        // Lower seq should be rejected
        let stored = store
            .put(
                "NN-TEST-0002",
                "blob3",
                "salt3",
                3,
                "FP1",
                3600,
                "sig3",
                2003,
            )
            .await
            .unwrap();
        assert!(!stored);

        // Higher seq should be accepted
        let stored = store
            .put(
                "NN-TEST-0002",
                "blob4",
                "salt4",
                6,
                "FP1",
                3600,
                "sig4",
                2004,
            )
            .await
            .unwrap();
        assert!(stored);
    }

    #[tokio::test]
    async fn test_nonce_replay_protection() {
        let store = DhtStore::open_in_memory().await.unwrap();

        // First put with nonce 3001 should succeed
        let stored = store
            .put(
                "NN-TEST-NONCE",
                "blob1",
                "salt1",
                1,
                "FP1",
                3600,
                "sig1",
                3001,
            )
            .await
            .unwrap();
        assert!(stored);

        // Same key, same nonce, higher seq should be rejected (nonce replay)
        let stored = store
            .put(
                "NN-TEST-NONCE",
                "blob2",
                "salt2",
                2,
                "FP1",
                3600,
                "sig2",
                3001,
            )
            .await
            .unwrap();
        assert!(!stored);

        // Same key, different nonce should succeed
        let stored = store
            .put(
                "NN-TEST-NONCE",
                "blob3",
                "salt3",
                2,
                "FP1",
                3600,
                "sig3",
                3002,
            )
            .await
            .unwrap();
        assert!(stored);

        // Verify is_nonce_seen works
        assert!(store.is_nonce_seen("NN-TEST-NONCE", 3001).await.unwrap());
        assert!(store.is_nonce_seen("NN-TEST-NONCE", 3002).await.unwrap());
        assert!(!store.is_nonce_seen("NN-TEST-NONCE", 3003).await.unwrap());
    }

    #[tokio::test]
    async fn test_nonce_persistence_across_restart() {
        // Use a temp file to simulate persistence across restart
        let tmp_dir = std::env::temp_dir();
        let db_path = tmp_dir.join("dht_nonce_test.db");
        let path_str = db_path.to_string_lossy().to_string();

        // Clean up any previous test file
        let _ = std::fs::remove_file(&path_str);

        // First "run": store a nonce
        {
            let store = DhtStore::open(Some(&path_str)).await.unwrap();
            let stored = store
                .put(
                    "NN-TEST-PERSIST",
                    "blob1",
                    "salt1",
                    1,
                    "FP1",
                    3600,
                    "sig1",
                    4001,
                )
                .await
                .unwrap();
            assert!(stored);
        }

        // Second "run": reopen the same DB, nonce should still be seen
        {
            let store = DhtStore::open(Some(&path_str)).await.unwrap();
            assert!(store.is_nonce_seen("NN-TEST-PERSIST", 4001).await.unwrap());

            // Attempt replay with same nonce should be rejected
            let stored = store
                .put(
                    "NN-TEST-PERSIST",
                    "blob2",
                    "salt2",
                    2,
                    "FP1",
                    3600,
                    "sig2",
                    4001,
                )
                .await
                .unwrap();
            assert!(!stored);

            // Different nonce should work
            let stored = store
                .put(
                    "NN-TEST-PERSIST",
                    "blob3",
                    "salt3",
                    2,
                    "FP1",
                    3600,
                    "sig3",
                    4002,
                )
                .await
                .unwrap();
            assert!(stored);
        }

        // Clean up
        let _ = std::fs::remove_file(&path_str);
    }

    #[tokio::test]
    async fn test_prune_old_nonces() {
        let store = DhtStore::open_in_memory().await.unwrap();

        // Record some nonces directly
        store.record_nonce("key1", 1).await.unwrap();
        store.record_nonce("key1", 2).await.unwrap();
        store.record_nonce("key2", 3).await.unwrap();

        // All should be seen
        assert!(store.is_nonce_seen("key1", 1).await.unwrap());
        assert!(store.is_nonce_seen("key1", 2).await.unwrap());
        assert!(store.is_nonce_seen("key2", 3).await.unwrap());

        // Prune with a far-future cutoff (everything is old)
        let pruned = store.prune_old_nonces(i64::MAX).await.unwrap();
        assert_eq!(pruned, 3);

        // Nonces should be gone
        assert!(!store.is_nonce_seen("key1", 1).await.unwrap());
        assert!(!store.is_nonce_seen("key1", 2).await.unwrap());
        assert!(!store.is_nonce_seen("key2", 3).await.unwrap());
    }

    #[tokio::test]
    async fn test_delete_expired() {
        let store = DhtStore::open_in_memory().await.unwrap();

        // Store with 0 TTL so it's immediately expired
        store
            .put("NN-TEST-0003", "blob", "salt", 1, "FP1", 0, "sig", 5001)
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        let deleted = store.delete_expired().await.unwrap();
        assert!(deleted >= 1);

        let result = store.get("NN-TEST-0003").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_count_keys() {
        let store = DhtStore::open_in_memory().await.unwrap();
        assert_eq!(store.count_keys().await.unwrap(), 0);

        store
            .put(
                "NN-TEST-0004",
                "blob1",
                "salt1",
                1,
                "FP1",
                3600,
                "sig1",
                6001,
            )
            .await
            .unwrap();
        assert_eq!(store.count_keys().await.unwrap(), 1);
    }
}
