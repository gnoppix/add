//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// Add P2P Messenger Client
//
// G1: Send command — DHT lookup + P2P delivery
// G2: Read command — relay mailbox fetch + decrypt
// G3: Listen command — WebSocket listener for incoming P2P connections
// G4: Kademlia DHT routing — documented as intentional (centralized seed model)
// G5: Message persistence — local SQLite message store
//-------------------------------------------------------------------------------

use std::collections::HashMap;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::io::Read;
use std::sync::Arc;

use base64::Engine;
use clap::Parser;
use futures::{SinkExt as _, StreamExt as _};
use hickory_resolver::Resolver;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::domain::IntoName;
use serde::{Deserialize, Serialize};
use sqlx::Pool;
use sqlx::sqlite::SqlitePoolOptions;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;
use tracing_subscriber::EnvFilter;
use zeroize::ZeroizeOnDrop;

// Privacy-first per-contact presence (PART VII V2.2).
mod presence;

// ------------------------------------------------------------------ //
//  Configuration                                                     //
// ------------------------------------------------------------------ //

const GPG_HOME: &str = ".add/gnupg";
const CONTACTS_PATH: &str = ".add/contacts.json";
const ALIASES_PATH: &str = ".add/aliases.json";
const DELIVERY_SECRETS_PATH: &str = ".add/delivery_secrets.json";
const IDENTITY_PATH: &str = ".add/identity.json";
const VAULT_PATH: &str = ".add/vault.json";
const BOOTSTRAP_PATH: &str = ".add/bootstrap_pin_cache.json";
const MESSAGES_DB: &str = ".add/messages.db";
const DB_KEY_PATH: &str = ".add/db_key.json";

/// Read receipt sent to relays for cross-relay sync.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayReadReceipt {
    message_id: String,    // SHA-256 hash of the message payload
    recipient_nid: String, // The recipient who read the message
    recipient_fp: String,  // Fingerprint of the recipient
    signature: String,     // GPG signature over message_id + recipient_nid + timestamp
    timestamp: f64,        // Unix timestamp
    nonce: String,         // Unique nonce for replay protection
    /// Recipient's ML-DSA-87 verifying key (base64) — required by the relay to
    /// verify the read-receipt signature (TOFU). Without it the receipt is
    /// rejected and the message stays undelivered (re-fetched → echo loop).
    recipient_verifying_key: String,
    /// Optional: list of other relay URLs that should also delete this message
    other_relays: Vec<String>,
}
// Local development defaults
const SEED_URL: &str = "ws://127.0.0.1:9001";
const RELAY_URL: &str = "ws://127.0.0.1:8765";

// Default bootstrap servers (multi-bootstrap setup) - with /ws path
const BOOTSTRAP_US: &str = "wss://bootstrap-us.gnoppix.org/ws";
const BOOTSTRAP_EU: &str = "wss://bootstrap-eu.gnoppix.org/ws";
const BOOTSTRAP_ASIA: &str = "wss://bootstrap-asia.gnoppix.org/ws";
// ------------------------------------------------------------------ //
//  Server Discovery (DNS SRV)                                         //
// ------------------------------------------------------------------ //

/// Hardcoded fallback servers used when DNS SRV lookup fails.
const FALLBACK_BOOTSTRAP: &str = "wss://bootstrap-eu.gnoppix.org/ws";
const FALLBACK_RELAY_US: &str = "wss://relay-us.gnoppix.org/ws";
const FALLBACK_RELAY_EU: &str = "wss://relay-eu.gnoppix.org/ws";
const FALLBACK_RELAY_ASIA: &str = "wss://relay-asia.gnoppix.org/ws";

/// SRV record service prefixes for auto-discovery.
const BOOTSTRAP_SRV: &str = "_add-bootstrap._tcp.gnoppix.org";
const RELAY_SRV: &str = "_add-relay._tcp.gnoppix.org";

/// Well-known public service: the Add Reflector (echo) bot.
/// A public service is reachable WITHOUT being in the user's contact list
/// (DESIGN.md §6 exception). Clients fetch its cert+address bundle from the
/// public cert store and pin the verifying key, so no contact entry is needed
/// and the reflector never holds anyone in its (non-existent) address book.
const REFLECTOR_NULL_ID: &str = "NN-1ae2-e797-1e6b-fff8-9e79-f936-0627-d10f";
const REFLECTOR_FINGERPRINT: &str = "3957378550B111F2678DC1B4A58C27B22091D5CF";

/// Well-known public services exempt from the mutual-consent inbound gate
/// (DESIGN.md §6 exception). Reachable without a contact entry. Add new
/// public bots/services here as an explicit allow-list rather than hardcoding
/// a single constant deeper in the logic. Matched by fingerprint.
const PUBLIC_SERVICE_FINGERPRINTS: &[&str] = &[
    REFLECTOR_FINGERPRINT,
];

/// True for a well-known public service (reflector, future bots). Public
/// services are exempt from the mutual-consent gate so they can initiate
/// without a contact entry.
fn is_public_service_fingerprint(fp: &str) -> bool {
    PUBLIC_SERVICE_FINGERPRINTS.contains(&fp)
}
/// True for a well-known public service (reflector, future bots). Public
/// services are exempt from the mutual-consent contact-list gate but are still
/// pinned to their published cert — see `fetch_public_service`.
fn is_public_service(null_id: &str) -> bool {
    null_id == REFLECTOR_NULL_ID
}

/// Discover bootstrap and relay server URLs via DNS SRV records.
///
/// Queries `_add-bootstrap._tcp.gnoppix.org` and
/// `_add-relay._tcp.gnoppix.org` for SRV records, selects the
/// highest-priority (lowest number) / highest-weight entry, and returns
/// a `wss://<target>:<port>` URL for each.
///
/// Falls back to hardcoded defaults if the SRV lookup fails for any reason.
pub async fn discover_servers() -> (String, Vec<String>) {
    let resolver = TokioResolver::builder_tokio()
        .unwrap_or_else(|_| {
            Resolver::builder_with_config(
                ResolverConfig::default(),
                TokioRuntimeProvider::default(),
            )
        })
        .build()
        .unwrap();

    let seed = query_srv(&resolver, BOOTSTRAP_SRV)
        .await
        .map(|url| format!("{}/ws", url.trim_end_matches('/')))
        .unwrap_or_else(|| {
            tracing::warn!(
                "SRV lookup for {} failed, using fallback {}",
                BOOTSTRAP_SRV,
                FALLBACK_BOOTSTRAP
            );
            FALLBACK_BOOTSTRAP.to_string()
        });

    // Query all relays via SRV, fall back to default list
    let relays_raw = query_all_srv(&resolver, RELAY_SRV)
        .await
        .unwrap_or_else(|| {
            tracing::warn!(
                "SRV lookup for {} failed, using default relay list",
                RELAY_SRV
            );
            vec![FALLBACK_RELAY_US, FALLBACK_RELAY_EU, FALLBACK_RELAY_ASIA]
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        });

    // Add /ws suffix if not present
    let relays = relays_raw
        .into_iter()
        .map(|url| {
            if url.ends_with("/ws") {
                url
            } else {
                format!("{}/ws", url.trim_end_matches('/'))
            }
        })
        .collect();

    (seed, relays)
}

/// Discover all bootstrap and relay server URLs via DNS SRV records.
/// Returns (primary_bootstrap, all_bootstraps, all_relays).
pub async fn discover_all_servers() -> (String, Vec<String>, Vec<String>) {
    let resolver = TokioResolver::builder_tokio()
        .unwrap_or_else(|_| {
            Resolver::builder_with_config(
                ResolverConfig::default(),
                TokioRuntimeProvider::default(),
            )
        })
        .build()
        .unwrap();

    // Primary bootstrap (single best SRV record)
    let seed = query_srv(&resolver, BOOTSTRAP_SRV)
        .await
        .map(|url| format!("{}/ws", url.trim_end_matches('/')))
        .unwrap_or_else(|| {
            tracing::warn!(
                "SRV lookup for {} failed, using fallback {}",
                BOOTSTRAP_SRV,
                FALLBACK_BOOTSTRAP
            );
            FALLBACK_BOOTSTRAP.to_string()
        });

    // ALL bootstrap servers from SRV (for multi-bootstrap registration) - ADD /ws path
    let bootstraps_raw = query_all_srv(&resolver, BOOTSTRAP_SRV)
        .await
        .unwrap_or_else(|| {
            tracing::warn!(
                "SRV lookup for {} failed, using default bootstrap list",
                BOOTSTRAP_SRV
            );
            vec![BOOTSTRAP_US, BOOTSTRAP_EU, BOOTSTRAP_ASIA]
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        });

    // Add /ws suffix to bootstrap URLs if not present
    let bootstraps = bootstraps_raw
        .into_iter()
        .map(|url| {
            if url.ends_with("/ws") {
                url
            } else {
                format!("{}/ws", url.trim_end_matches('/'))
            }
        })
        .collect();

    // ALL relays from SRV - ADD /ws suffix
    let relays_raw = query_all_srv(&resolver, RELAY_SRV)
        .await
        .unwrap_or_else(|| {
            tracing::warn!(
                "SRV lookup for {} failed, using default relay list",
                RELAY_SRV
            );
            vec![FALLBACK_RELAY_US, FALLBACK_RELAY_EU, FALLBACK_RELAY_ASIA]
                .into_iter()
                .map(|s| s.to_string())
                .collect()
        });

    // Add /ws suffix if not present (relays use /ws endpoint)
    let relays = relays_raw
        .into_iter()
        .map(|url| {
            if url.ends_with("/ws") {
                url
            } else {
                format!("{}/ws", url.trim_end_matches('/'))
            }
        })
        .collect();

    (seed, bootstraps, relays)
}

/// Query ALL SRV records (not just the first) and return URLs.
/// Returns all discovered URLs (sorted by priority/weight).
async fn query_all_srv<N: IntoName>(resolver: &TokioResolver, name: N) -> Option<Vec<String>> {
    let response = resolver.srv_lookup(name).await.ok()?;

    let records = response.answers();
    if records.is_empty() {
        return None;
    }

    let mut srv_records: Vec<_> = records
        .iter()
        .filter_map(|r| r.try_borrow::<hickory_resolver::proto::rr::rdata::SRV>())
        .collect();

    if srv_records.is_empty() {
        return None;
    }

    // Sort by priority (lower = preferred), then weight (higher = preferred)
    srv_records.sort_by(|a, b| {
        a.data()
            .priority
            .cmp(&b.data().priority)
            .then_with(|| b.data().weight.cmp(&a.data().weight))
    });

    Some(
        srv_records
            .into_iter()
            .map(|r| {
                let target = r.data().target.to_string();
                let target = target.trim_end_matches('.');
                format!("wss://{}:{}", target, r.data().port)
            })
            .collect(),
    )
}

/// Query a single SRV record and return the best `wss://host:port` URL.
///
/// Records are sorted by priority (ascending), then by weight (descending)
/// within the same priority group. The first record is selected.
async fn query_srv<N: IntoName>(resolver: &TokioResolver, name: N) -> Option<String> {
    let response = resolver.srv_lookup(name).await.ok()?;

    let records = response.answers();
    if records.is_empty() {
        return None;
    }

    let mut srv_records: Vec<_> = records
        .iter()
        .filter_map(|r| r.try_borrow::<hickory_resolver::proto::rr::rdata::SRV>())
        .collect();

    if srv_records.is_empty() {
        return None;
    }

    // Sort by priority (lower = preferred), then weight (higher = preferred)
    srv_records.sort_by(|a, b| {
        a.data()
            .priority
            .cmp(&b.data().priority)
            .then_with(|| b.data().weight.cmp(&a.data().weight))
    });

    let r = srv_records.first()?;
    let target = r.data().target.to_string();
    let target = target.trim_end_matches('.');
    Some(format!("wss://{}:{}", target, r.data().port))
}

// ------------------------------------------------------------------ //
//  Database Encryption (AES-256-GCM)                                  //
// ------------------------------------------------------------------ //

/// Database encryption key for message-at-rest protection.
///
/// Uses AES-256-GCM with a random 96-bit nonce per encryption.
/// The key is stored on disk encrypted with a key derived from the
/// user's identity key (first app: derived from Kyber public key hash).
///
/// ACS2.6 Part III.2: AEAD enforcement for local data-at-rest.
/// SECURITY FIX (C2): Zeroize key material on drop.
#[derive(ZeroizeOnDrop)]
pub(crate) struct DbEncryptionKey {
    #[zeroize(drop)]
    key: [u8; 32],
}

impl DbEncryptionKey {
    /// Get a reference to the raw key bytes (for Kyber key encryption).
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Promote a legacy plaintext-hex key file to age-encrypted form using
    /// `passphrase`. Called once at identity init when a passphrase is set.
    /// If `passphrase` is None the key file stays plaintext (legacy/headless)
    /// but callers should warn — a plaintext key file means local root can
    /// decrypt the message store (F-7).
    pub fn save(&self, passphrase: Option<&str>) -> std::io::Result<()> {
        let path = home_dir().join(DB_KEY_PATH);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        #[cfg(unix)]
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        match passphrase {
            Some(pass) => {
                let armored = encrypt_cert_armored(&hex::encode(self.key), pass)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
                std::fs::write(&path, armored)
            }
            None => {
                eprintln!(
                    "WARNING: DB key written as PLAINTEXT (no passphrase). Local root can decrypt the message store."
                );
                std::fs::write(&path, hex::encode(self.key))
            }
        }
    }

    /// Load the DB key. Accepts an optional `passphrase` used to unwrap an
    /// age-encrypted key file (F-7 hardening). Resolution order:
    ///   1. file is age-armored → decrypt with `passphrase` (error if None)
    ///   2. file is plaintext hex (legacy) → use as-is
    ///   3. file absent → generate random, write via `save(passphrase)`
    pub fn load(passphrase: Option<&str>) -> std::io::Result<Self> {
        let path = home_dir().join(DB_KEY_PATH);
        if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            let trimmed = raw.trim();
            if trimmed.starts_with("-----BEGIN AGE ENCRYPTED FILE-----") {
                let pass = passphrase.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "DB key is passphrase-encrypted; set ADD_DB_PASSPHRASE or run interactively",
                    )
                })?;
                let decrypted = decrypt_cert_armored(
                    trimmed,
                    pass,
                )
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
                let bytes = hex::decode(decrypted.trim())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                if bytes.len() != 32 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid db key length",
                    ));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(Self { key })
            } else {
                // Legacy plaintext hex
                let bytes = hex::decode(trimmed)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                if bytes.len() != 32 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid db key length",
                    ));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                Ok(Self { key })
            }
        } else {
            use rand::RngCore;
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            let k = Self { key };
            k.save(passphrase)?;
            Ok(k)
        }
    }

    /// Load or create the database encryption key (async context).
    ///
    /// SECURITY FIX (F-7): the key file is no longer stored as plaintext hex by
    /// default — when `passphrase` is provided it is written age-encrypted; a
    /// plaintext-hex file is only produced in legacy/headless mode and warned.
    /// Synchronous load-or-create for non-async contexts (e.g. cmd_init,
    /// publish_cert). Delegates to the passphrase-aware loader so a wrapped
    /// key is unlocked via `ADD_DB_PASSPHRASE` / interactive prompt instead of
    /// silently creating a *new* plaintext key (which would desync from the
    /// age-wrapped one).
    pub fn load_or_create_sync() -> Self {
        load_db_key_interactive(read_db_passphrase().as_deref())
            .expect("failed to load/create db key")
    }

    /// Generate a fresh random 32-byte AES-256 key without persistent storage.
    /// Used for in-memory databases that should never be written to disk.
    #[allow(dead_code)]
    fn generate_random() -> Self {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Self { key }
    }

    /// Deterministic blind index over a value, keyed by the DB key.
    /// Lets SQLite filter/lookup by an otherwise-encrypted column without
    /// leaking the plaintext (HMAC-SHA256, truncated to 32 hex chars).
    fn blind_index(&self, value: &str) -> String {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        type HmacSha256 = Hmac<Sha256>;
        let mut mac =
            HmacSha256::new_from_slice(&self.key).expect("32-byte key for HMAC");
        mac.update(value.as_bytes());
        let out = mac.finalize().into_bytes();
        hex::encode(&out[..16])
    }

    /// Encrypt an optional string (None → None).
    fn encrypt_opt(&self, plaintext: &Option<String>) -> Result<Option<String>, Box<dyn std::error::Error>> {
        match plaintext {
            Some(s) => Ok(Some(self.encrypt(s)?)),
            None => Ok(None),
        }
    }

    /// Decrypt an optional string (None → None).
    fn decrypt_opt(&self, encrypted: &Option<String>) -> Option<String> {
        encrypted.as_ref().and_then(|e| self.decrypt(e).ok())
    }

    /// Encrypt plaintext using AES-256-GCM.
    ///
    /// Output format: [nonce (12 bytes)] [ciphertext + tag]
    fn encrypt(&self, plaintext: &str) -> Result<String, Box<dyn std::error::Error>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);

        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|e| format!("encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(base64::engine::general_purpose::STANDARD.encode(&output))
    }

    /// Decrypt ciphertext using AES-256-GCM.
    ///
    /// Expects format: [nonce (12 bytes)] [ciphertext + tag]
    fn decrypt(&self, encrypted_b64: &str) -> Result<String, Box<dyn std::error::Error>> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        let data = base64::engine::general_purpose::STANDARD.decode(encrypted_b64)?;
        if data.len() < 12 + 16 {
            // nonce + minimum tag
            return Err("ciphertext too short".into());
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let key = Key::<Aes256Gcm>::from_slice(&self.key);
        let cipher = Aes256Gcm::new(key);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("decryption failed: {}", e))?;

        Ok(String::from_utf8(plaintext)?)
    }
}

// ------------------------------------------------------------------ //
//  Identity                                                          //
// ------------------------------------------------------------------ //

/// Path to persistent Kyber keypair
const KYBER_KEY_PATH: &str = ".add/kyber_key.json";

/// Read the DB key passphrase for headless/daemon operation.
///
/// Interactive (`add`) prompts are handled at init; for systemd daemons that
/// cannot prompt, the operator supplies `ADD_DB_PASSPHRASE` (a service
/// credential). Returns None when unset (legacy plaintext key tolerated).
fn read_db_passphrase() -> Option<String> {
    std::env::var("ADD_DB_PASSPHRASE").ok().filter(|s| !s.is_empty())
}

/// TIER-0 (metadata hardening): compute the blind relay routing tag for a
/// recipient null_id. When `ADD_RELAY_SHARED_SECRET` is configured (the same
/// secret the operator sets on the relay), the client addresses the relay
/// mailbox by `HMAC(secret, nid||epoch)` instead of the raw null_id, so the
/// relay never sees/persists the plaintext recipient identity. The tag
/// rotates hourly (epoch = unix_secs / 3600) and MUST match the relay's
/// `recipient_tag()`. Returns None when no secret is configured (the client
/// then falls back to sending the plaintext null_id, preserving compat).
fn relay_routing_tag(recipient_nid: &str) -> Option<String> {
    let secret = std::env::var("ADD_RELAY_SHARED_SECRET").ok().filter(|s| !s.is_empty())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let epoch = now / 3600;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key any size");
    mac.update(format!("{}|{}", recipient_nid, epoch).as_bytes());
    Some(hex::encode(mac.finalize().into_bytes()))
}

/// Load the DB key, trying (in order): the env passphrase, then a plaintext
/// (legacy) key file, then an interactive no-echo prompt when stdin is a tty
/// and the key file is age-wrapped. This keeps headless daemons working via
/// `ADD_DB_PASSPHRASE` while interactive `add` can still open a wrapped key
/// without forcing the operator to export the passphrase to the environment.
fn load_db_key_interactive(
    pass_env: Option<&str>,
) -> Result<DbEncryptionKey, Box<dyn std::error::Error>> {
    use std::io::IsTerminal;
    if let Some(p) = pass_env {
        return Ok(DbEncryptionKey::load(Some(p))?);
    }
    // No env passphrase: try legacy plaintext, else prompt on a tty.
    let loaded: std::io::Result<DbEncryptionKey> = DbEncryptionKey::load(None);
    match loaded {
        Ok(k) => Ok(k),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // No key file yet — create one (plaintext, with warning, in
            // legacy/headless mode; interactive init re-wraps with a passphrase).
            Ok(DbEncryptionKey::load(None)?)
        }
        Err(_) => {
            // Key file exists but is age-wrapped and no env passphrase was set.
            if std::io::stdin().is_terminal() {
                match prompt_passphrase() {
                    Ok(p) if !p.is_empty() => return Ok(DbEncryptionKey::load(Some(&p))?),
                    _ => {}
                }
            }
            Err("DB key is passphrase-encrypted; set ADD_DB_PASSPHRASE or run interactively".into())
        }
    }
}

/// Prompt for the GPG passphrase (from stdin, no echo).
///
/// SECURITY FIX (F-8): never fall back to a plain (echoed) `read_line` on an
/// interactive terminal — that would leak the passphrase to the screen and any
/// shoulder-surfer / scrollback. If `rpassword` is unavailable we only fall
/// back to echoed input when stdin is NOT a tty (e.g. piped/pinned from a
/// secret manager), and we warn loudly in that case.
fn prompt_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    use std::io::IsTerminal;
    use std::io::Write;

    print!("Enter GPG key passphrase (leave empty for none): ");
    std::io::stdout().flush()?;

    #[cfg(unix)]
    {
        // Interactive terminal: require no-echo. rpassword uses termios RAW so
        // the passphrase is never echoed.
        if std::io::stdin().is_terminal() {
            match rpassword::read_password() {
                Ok(pass) => return Ok(pass),
                Err(e) => {
                    // No-echo genuinely unavailable on this tty — refuse rather
                    // than leak the secret.
                    return Err(format!(
                        "could not read passphrase without echo (refusing to echo on a terminal): {e}"
                    )
                    .into());
                }
            }
        }
    }
    // Non-tty stdin (piped secrets): echo is acceptable/expected here.
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    if std::io::stdin().is_terminal() {
        eprintln!("WARNING: GPG passphrase was read with echo enabled (no-echo unavailable).");
    }
    Ok(buf.trim_end().to_string())
}

/// Load the Sequoia certificate for signing operations.
/// Returns the user's own certificate as ASCII-armored text (the same bytes
/// stored in `own_cert.age` / `own_cert.asc`). Used by the cert-store publish
/// path (DESIGN.md §4.2) which uploads the armored cert to the opaque blob store.
/// Tries the age-encrypted `own_cert.age` first, falls back to plaintext `own_cert.asc`.
fn load_cert() -> Result<sequoia_openpgp::Cert, Box<dyn std::error::Error>> {
    use sequoia_openpgp::parse::Parse;

    let cert_dir = home_dir().join(GPG_HOME);
    let enc_path = cert_dir.join("own_cert.age");
    let plain_path = cert_dir.join("own_cert.asc");

    // Try age-encrypted cert first
    if enc_path.exists() {
        let armored = std::fs::read_to_string(&enc_path)?;
        let password = prompt_passphrase()?;
        if password.is_empty() {
            return Err("encrypted own_cert.age requires a passphrase".into());
        }
        let plaintext = decrypt_cert_armored(&armored, &password)?;
        return sequoia_openpgp::Cert::from_bytes(plaintext.as_bytes())
            .map_err(|e| format!("parse decrypted cert: {}", e).into());
    }

    // Fallback to plaintext legacy format
    if !plain_path.exists() {
        return Err("no identity found — run 'add init' first".into());
    }
    let armored = std::fs::read_to_string(&plain_path)?;
    // Detect corrupt binary data (old bug: serialize wrote binary to .asc file)
    let bytes = armored.as_bytes();
    if !bytes.is_empty()
        && (bytes[0] == 0xEF && bytes.get(1..3) == Some(&[0xBF, 0xBD]) || bytes[0] == 0x00)
    {
        return Err(
            "corrupt identity file detected — run 'rm -rf ~/.add/gnupg && add init' to recreate"
                .into(),
        );
    }
    sequoia_openpgp::Cert::from_bytes(armored.as_bytes())
        .map_err(|e| format!("parse cert: {}", e).into())
}

/// Encrypt the GPG secret key cert using age passphrase encryption.
/// Output format: age ASCII-armored (-----BEGIN AGE ENCRYPTED FILE-----).
fn encrypt_cert_armored(
    plaintext: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use age::secrecy::SecretString;
    use std::io::Write;

    let passphrase = SecretString::from(password.to_string());
    let encryptor = age::Encryptor::with_user_passphrase(passphrase);
    let mut buf = Vec::new();
    {
        let mut armored_writer =
            age::armor::ArmoredWriter::wrap_output(&mut buf, age::armor::Format::AsciiArmor)
                .map_err(|e| format!("age armor wrap: {}", e))?;
        let mut writer = encryptor
            .wrap_output(&mut armored_writer)
            .map_err(|e| format!("age encrypt: {}", e))?;
        writer
            .write_all(plaintext.as_bytes())
            .map_err(|e| format!("age write: {}", e))?;
        writer.finish().map_err(|e| format!("age finish: {}", e))?;
        armored_writer
            .finish()
            .map_err(|e| format!("age armor finish: {}", e))?;
    }
    String::from_utf8(buf).map_err(|e| format!("age output utf8: {}", e).into())
}

/// Decrypt an age-encrypted cert.
fn decrypt_cert_armored(
    armored: &str,
    password: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use age::secrecy::SecretString;

    let passphrase = SecretString::from(password.to_string());
    let identity = age::scrypt::Identity::new(passphrase);
    let plaintext =
        age::decrypt(&identity, armored.as_bytes()).map_err(|e| format!("age decrypt: {}", e))?;
    String::from_utf8(plaintext).map_err(|e| format!("decrypted cert utf8: {}", e).into())
}

/// Change the passphrase protecting the GPG secret key (own_cert.age)
/// Decrypts with old passphrase, re-encrypts with new passphrase.
/// If encrypt=true and only plaintext exists, encrypt it without prompting for old password.
fn change_passphrase(
    current_pass: Option<String>,
    new_pass_in: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let cert_dir = home_dir().join(GPG_HOME);
    let enc_path = cert_dir.join("own_cert.age");
    let plain_path = cert_dir.join("own_cert.asc");

    // IPC mode from Electron: both passphrases provided as args
    if let Some(old_pass) = current_pass {
        let new_pass = new_pass_in.ok_or("new passphrase required with --current")?;
        if new_pass.is_empty() {
            return Err("new passphrase cannot be empty".into());
        }

        // Load and decrypt existing cert with old passphrase
        let armored = std::fs::read_to_string(&enc_path)?;
        let cert_armored = decrypt_cert_armored(&armored, &old_pass)?;

        // Re-encrypt with new passphrase
        let encrypted = encrypt_cert_armored(&cert_armored, &new_pass)?;
        std::fs::write(&enc_path, &encrypted)?;
        println!("Passphrase changed successfully");
        return Ok(());
    }

    // CLI mode: prompt for passphrases
    // If --encrypt flag and plaintext cert exists, encrypt it without old password
    if plain_path.exists() {
        let armored = std::fs::read_to_string(&plain_path)?;
        println!("Enter passphrase to encrypt with (empty to cancel):");
        let new_pass = rpassword::read_password().unwrap_or_default();
        if new_pass.is_empty() {
            return Ok(());
        }
        let encrypted = encrypt_cert_armored(&armored, &new_pass)?;
        std::fs::write(&enc_path, &encrypted)?;
        std::fs::remove_file(&plain_path)?;
        println!("Cert encrypted successfully");
        return Ok(());
    }

    // Normal flow: decrypt + re-encrypt
    if !enc_path.exists() {
        return Err(
            "No encrypted cert found (run 'add init' with a passphrase to create one)".into(),
        );
    }

    // Prompt for current passphrase
    let old_pass = prompt_passphrase()?;
    if old_pass.is_empty() {
        return Err("Current passphrase cannot be empty for encrypted cert".into());
    }

    // Load and decrypt existing cert
    let armored = std::fs::read_to_string(&enc_path)?;
    let cert_armored = decrypt_cert_armored(&armored, &old_pass)?;

    // Prompt for new passphrase (twice to confirm)
    println!("Enter new passphrase (empty for no encryption):");
    let new_pass = rpassword::read_password().unwrap_or_default();
    println!("Confirm new passphrase:");
    let confirm_pass = rpassword::read_password().unwrap_or_default();

    if new_pass != confirm_pass {
        return Err("Passphrases do not match".into());
    }

    if new_pass.is_empty() {
        // Save as plaintext, remove encrypted version
        std::fs::write(&plain_path, &cert_armored)?;
        std::fs::remove_file(&enc_path)?;
        println!("Cert saved as plaintext (not encrypted)");
    } else {
        // Re-encrypt with new passphrase
        let encrypted = encrypt_cert_armored(&cert_armored, &new_pass)?;
        std::fs::write(&enc_path, &encrypted)?;
        let _ = std::fs::remove_file(&plain_path);
    }

    println!("Passphrase changed successfully");
    Ok(())
}

/// Sign data with our ML-DSA-87 key for P2P/relay authentication.
fn sign_for_transport(data: &str) -> Result<String, String> {
    let identity = Identity::load().map_err(|e| format!("Failed to load identity: {}", e))?;
    let sk_b64 = identity
        .ml_dsa87_signing_key
        .ok_or("ML-DSA-87 signing key not found - re-run 'add init'")?;
    let sk_bytes = base64::engine::general_purpose::STANDARD
        .decode(sk_b64)
        .map_err(|e| format!("Failed to decode signing key: {}", e))?;
    // Reconstruct the signing key from bytes
    use ml_dsa::KeyInit;
    let sk = add_crypto_pq::MlDsa87SigningKey::new_from_slice(&sk_bytes)
        .map_err(|e| format!("ML-DSA-87 key reconstruction failed: {}", e))?;
    add_dht_core::sign_data(data, &sk).map_err(|e| format!("sign failed: {}", e))
}

/// Return this identity's ML-DSA-87 verifying key as base64, for embedding in
/// P2P hello/ack payloads so the peer can verify the signature without a DHT
/// round-trip (the bootstrap `dht-found` response is sanitized and omits it).
fn my_verifying_key_b64() -> Result<String, String> {
    let identity = Identity::load().map_err(|e| format!("load identity: {}", e))?;
    let sk_b64 = identity
        .ml_dsa87_signing_key
        .ok_or("ML-DSA-87 signing key not found")?;
    let sk_bytes = base64::engine::general_purpose::STANDARD
        .decode(sk_b64)
        .map_err(|e| format!("decode: {}", e))?;
    use ml_dsa::{KeyExport, KeyInit, Keypair};
    let sk = add_crypto_pq::MlDsa87SigningKey::new_from_slice(&sk_bytes)
        .map_err(|e| format!("recon: {}", e))?;
    let vk = Keypair::verifying_key(&sk).clone();
    Ok(base64::engine::general_purpose::STANDARD.encode(vk.to_bytes()))
}

/// Load armored cert string for TOFU verification at relay.
#[allow(dead_code)]
fn load_armored_cert() -> Result<String, Box<dyn std::error::Error>> {
    use sequoia_openpgp::serialize::Serialize;
    let cert = load_cert()?;
    let mut buf = Vec::new();
    cert.as_tsk()
        .armored()
        .serialize(&mut buf)
        .map_err(|e| format!("cert armored serialize failed: {}", e))?;
    String::from_utf8(buf).map_err(|e| format!("cert armored utf8 error: {}", e).into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Identity {
    fingerprint: String,
    null_id: String,
    ml_dsa87_signing_key: Option<String>, // base64-encoded ML-DSA-87 signing key (PKCS8)
}

impl Identity {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let path = home_dir().join(IDENTITY_PATH);
        if !path.exists() {
            return Err("no identity found — run 'add init' first".into());
        }
        let content = std::fs::read_to_string(&path)?;
        let mut identity: Identity = serde_json::from_str(&content)?;
        // Backfill: identities created before ML-DSA-87 keys existed have
        // `None`. Generate one now (deterministically tied to this identity)
        // so relay transport signatures (purge/fetch) work without re-init.
        if identity.ml_dsa87_signing_key.is_none() {
            use ml_dsa::KeyExport;
            let (sk, _vk) = add_crypto_pq::generate_keypair()
                .map_err(|e| format!("ML-DSA-87 backfill generation failed: {}", e))?;
            identity.ml_dsa87_signing_key =
                Some(base64::engine::general_purpose::STANDARD.encode(sk.to_bytes()));
            identity.save()?;
        }
        Ok(identity)
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = home_dir().join(IDENTITY_PATH);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(self)?)?;
        // Set 0o600 permissions for security
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Get the stored certificate for signing
    fn cert(&self) -> Result<sequoia_openpgp::Cert, Box<dyn std::error::Error>> {
        load_cert()
    }
}

// ------------------------------------------------------------------ //
//  Contacts                                                          //
// ------------------------------------------------------------------ //

type Contacts = HashMap<String, String>; // null_id -> fingerprint

pub(crate) fn load_contacts() -> Contacts {
    let path = home_dir().join(CONTACTS_PATH);
    if !path.exists() {
        return HashMap::new();
    }
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

fn save_contacts(contacts: &Contacts) -> Result<(), Box<dyn std::error::Error>> {
    let path = home_dir().join(CONTACTS_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(contacts)?)?;
    // SECURITY FIX (HIGH-5): Set 0o600 permissions for contacts file
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ------------------------------------------------------------------ //
//  Aliases                                                          //
// ------------------------------------------------------------------ //

type Aliases = HashMap<String, String>; // alias -> null_id

fn load_aliases() -> Aliases {
    let path = home_dir().join(ALIASES_PATH);
    if !path.exists() {
        return HashMap::new();
    }
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

fn save_aliases(aliases: &Aliases) -> Result<(), Box<dyn std::error::Error>> {
    let path = home_dir().join(ALIASES_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(aliases)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Resolve a user-provided recipient string to a Null ID.
/// If the input matches a known alias, return the mapped null_id.
/// Otherwise return the input unchanged (assumed to be a raw null_id).
fn resolve_recipient(input: &str, aliases: &Aliases) -> String {
    aliases
        .get(input)
        .cloned()
        .unwrap_or_else(|| input.to_string())
}

// ------------------------------------------------------------------ //
//  WebSocket Transport (ws:// + wss://)                              //
// ------------------------------------------------------------------ //

/// Connect a WebSocket, supporting both ws:// and wss:// URLs.
/// For wss://, tokio-tungstenite handles TLS automatically via rustls-native-tls
/// with WebPKI certificate verification.
/// Returns a WebSocket stream over MaybeTlsStream (TLS when scheme is wss://).
#[allow(clippy::type_complexity)]
async fn ws_connect(
    url: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Box<dyn std::error::Error>,
> {
    // Route every connection through TOFU cert pinning (relay + bootstrap).
    ws_connect_pinned(url).await
}

// ------------------------------------------------------------------ //
//  TLS Certificate Pinning (item 11)                                 //
// ------------------------------------------------------------------ //
//
// TOFU (trust-on-first-use) SPKI/cert pinning for relay + bootstrap
// WebSocket TLS. On first connect to a host we record the SHA-256 of the
// presented end-entity certificate; thereafter any cert that does NOT match
// the pinned hash is rejected, defeating a MITM that presents a valid-but-
// different certificate (e.g. a compromised CA or a rogue proxy). Chain +
// expiry are still validated by WebPKI first, then the pin is enforced.
//
// Pin cache: `.add/tls_pin_cache.json`  { "<host>": "<hex sha256>" }
// To rotate a server cert, delete the offending entry (or the whole file) —
// the next connect re-pins (TOFU).

const TLS_PIN_CACHE_PATH: &str = ".add/tls_pin_cache.json";

use sha2::{Sha256, Digest as _};
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::Error as TlsError;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

#[derive(Debug)]
struct PinnedCertVerifier {
    inner: Arc<WebPkiServerVerifier>,
}

impl PinnedCertVerifier {
    fn new(root_store: rustls::RootCertStore) -> Arc<Self> {
        // WebPKI verifier seeded with the OS trust store; the pin check is
        // applied on top in `verify_server_cert`.
        let inner = WebPkiServerVerifier::builder(root_store.into())
            .build()
            .expect("webpki verifier");
        Arc::new(Self { inner })
    }

    fn pin_path() -> std::path::PathBuf {
        home_dir().join(TLS_PIN_CACHE_PATH)
    }

    fn load_pins() -> HashMap<String, String> {
        let p = Self::pin_path();
        if !p.exists() {
            return HashMap::new();
        }
        serde_json::from_str(&std::fs::read_to_string(&p).unwrap_or_default()).unwrap_or_default()
    }

    fn save_pins(pins: &HashMap<String, String>) {
        let p = Self::pin_path();
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(s) = serde_json::to_string_pretty(pins) {
            let _ = std::fs::write(&p, s);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        // 1) Normal WebPKI chain + expiry validation first.
        self.inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

        // 2) Pin check (TOFU). Pin the ISSUER CA's SPKI, not the leaf cert:
        //   leaf certs rotate every 75-90 days, so pinning the leaf would break
        //   connectivity on every renewal. The issuing CA (e.g. Let's Encrypt R3/
        //   ISRG X1) is stable for years, so pinning its public key survives
        //   routine leaf rotation while still rejecting a MITM cert from a
        //   different CA. Falls back to the leaf SPKI if no intermediates exist.
        let issuer_der = intermediates
            .first()
            .or(Some(end_entity))
            .map(|c| c.as_ref())
            .unwrap_or(&[]);
        let spki_raw = x509_parser::parse_x509_certificate(issuer_der)
            .map(|(_, cert)| cert.public_key().raw.to_vec())
            .map_err(|e| {
                tracing::error!("TLS pin: failed to parse issuer cert: {}", e);
                TlsError::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
            })?;
        let digest = Sha256::digest(&spki_raw);
        let hex = hex::encode(digest);
        let host = server_name.to_str().to_string();
        let mut pins = Self::load_pins();
        match pins.get(&host) {
            Some(pinned) if pinned == &hex => Ok(ServerCertVerified::assertion()),
            Some(pinned) => {
                tracing::error!(
                    "TLS cert pin mismatch for {}: pinned={} presented={}",
                    host,
                    pinned,
                    hex
                );
                Err(TlsError::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ))
            }
            None => {
                // First sighting of this host — pin it (TOFU).
                pins.insert(host.clone(), hex);
                Self::save_pins(&pins);
                tracing::info!("TLS cert pinned (TOFU) for {}", host);
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Connect with TOFU cert pinning. The `host` is the TLS SNI / server name
/// (e.g. "relay-eu.gnoppix.org"). Falls back to plain `connect_async` for
/// non-TLS (`ws://`) URLs.
async fn ws_connect_pinned(
    url: &str,
) -> Result<
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Box<dyn std::error::Error>,
> {
    if !url.starts_with("wss://") {
        // Plaintext (local dev) — no TLS, no pinning.
        return tokio_tungstenite::connect_async(url)
            .await
            .map(|(ws, _)| ws)
            .map_err(|e| format!("WebSocket connect failed: {}", e).into());
    }

    let request = url.into_client_request()?;

    let mut root_store = rustls::RootCertStore::empty();
    // Seed OS trust roots so WebPKI validation still works for legit certs.
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = root_store.add(cert);
    }
    let verifier = PinnedCertVerifier::new(root_store);
    let mut client_config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let authority = request
        .uri()
        .authority()
        .ok_or("missing authority")?
        .to_string();
    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(client_config));
    tokio_tungstenite::client_async_tls_with_config(
        request,
        tokio::net::TcpStream::connect(authority).await?,
        None,
        Some(connector),
    )
    .await
    .map(|(ws, _)| ws)
    .map_err(|e| format!("WebSocket (pinned TLS) connect failed: {}", e).into())
}

// ------------------------------------------------------------------ //
//  Delivery Token Secrets (ACS2.6 Part I.2)                          //
// ------------------------------------------------------------------ //

/// Load or create per-contact delivery master secrets.
/// Each contact gets a unique HMAC master secret for token derivation.
fn load_delivery_secrets() -> HashMap<String, String> {
    let path = home_dir().join(DELIVERY_SECRETS_PATH);
    if !path.exists() {
        return HashMap::new();
    }
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    serde_json::from_str(&content).unwrap_or_default()
}

fn save_delivery_secrets(
    secrets: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = home_dir().join(DELIVERY_SECRETS_PATH);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, serde_json::to_string_pretty(secrets)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Get or create a delivery master secret for a contact.
/// The secret is stored as hex on disk; in production it should be derived
/// from the Kyber shared secret during contact initialization.
fn get_or_create_delivery_secret(
    contact_nid: &str,
) -> Result<add_crypto::delivery_tokens::DeliveryMasterSecret, Box<dyn std::error::Error>> {
    let mut secrets = load_delivery_secrets();

    if let Some(hex) = secrets.get(contact_nid) {
        let bytes = hex::decode(hex)?;
        if bytes.len() != 64 {
            return Err("invalid delivery secret length".into());
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        let master = add_crypto::delivery_tokens::DeliveryMasterSecret::from_bytes(arr);
        Ok(master)
    } else {
        let master = add_crypto::delivery_tokens::DeliveryMasterSecret::generate();
        let bytes = *master.as_bytes();
        secrets.insert(contact_nid.to_string(), hex::encode(bytes));
        save_delivery_secrets(&secrets)?;
        Ok(master)
    }
}

/// Generate a delivery token message for a recipient.
/// ACS2.6 Part I.2: Anonymous delivery token for sealed sender.
fn generate_delivery_token(
    recipient_nid: &str,
    message_id: u64,
) -> Result<add_crypto::delivery_tokens::DeliveryTokenMessage, Box<dyn std::error::Error>> {
    let master = get_or_create_delivery_secret(recipient_nid)?;
    let token = master.derive_token(recipient_nid, message_id)?;

    // Hash the sender's public key (fingerprint) for recipient identification
    let identity = Identity::load()?;
    let pk_hash = sha256_hex(&identity.fingerprint);
    let sender_key_hash = format!("{}:{}", &pk_hash[..16], &pk_hash[16..32]);

    Ok(add_crypto::delivery_tokens::DeliveryTokenMessage {
        token: token.to_hex(),
        sender_key_hash,
        timestamp: chrono::Utc::now().timestamp() as u64,
    })
}

// ------------------------------------------------------------------ //
//  PIR Local Contact Discovery (ACS2.6 Part I.3)                     //
// ------------------------------------------------------------------ //

/// Local PIR-based contact registry for privacy-preserving contact lookup.
/// Prevents forensic analysis of the contact list by using cuckoo-hashed bins.
#[allow(dead_code)]
struct PirContactCache {
    registry: add_crypto::pir::PirRegistry,
}

impl PirContactCache {
    /// Build a PIR cache from the local contacts file.
    #[allow(dead_code)]
    fn build() -> Result<Self, Box<dyn std::error::Error>> {
        let contacts = load_contacts();
        let mut registry = add_crypto::pir::PirRegistry::new();

        for (nid, fingerprint) in &contacts {
            let fp_hash = sha256_hex(fingerprint);
            let hash_bytes = hex::decode(&fp_hash)?;
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&hash_bytes);
            // Store the NID as metadata (contact identifier)
            let entry = add_crypto::pir::PirContactEntry::new(hash, nid.as_bytes())?;
            // Use cuckoo hashing to determine bin placement
            let client = add_crypto::pir::PirClient::new();
            let (bin_idx, _) = client.prepare_registration(&hash)?;
            registry.add_entry(bin_idx, &entry)?;
        }

        Ok(Self { registry })
    }

    /// Look up a contact by fingerprint hash using PIR blind retrieval.
    /// Returns the contact NID if found.
    #[allow(dead_code)]
    fn lookup(&self, fingerprint: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let fp_hash = sha256_hex(fingerprint);
        let hash_bytes = hex::decode(&fp_hash)?;
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);

        let client = add_crypto::pir::PirClient::new();
        let tokens = client.query_contact(&hash)?;

        // Query each candidate bin
        for token in &tokens {
            if let Some(response) = self.registry.handle_query(token) {
                // Process response: XOR mask + scan for matching entry
                if let Some(entry) = client.process_response(&response, &token.xor_mask, &hash)? {
                    // Extract NID from metadata (bytes 32.. of the entry)
                    let raw = entry.to_bytes();
                    let nid = String::from_utf8_lossy(&raw[32..])
                        .trim_end_matches('\0')
                        .to_string();
                    if !nid.is_empty() {
                        return Ok(Some(nid));
                    }
                }
            }
        }

        Ok(None)
    }
}

// ------------------------------------------------------------------ //
//  Message Store (G5)                                                //
// ------------------------------------------------------------------ //

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMessage {
    id: i64,
    from_nid: String,
    to_nid: String,
    ciphertext: String,
    timestamp: String,
    delivered: bool,
    /// Delivery status: 0=sent, 1=relayed, 2=delivered, 3=read
    status: u8,
    /// Timestamp when status was last updated
    status_updated_at: String,
    /// Read receipt timestamp (if status=3)
    read_receipt_at: Option<String>,
    /// Message ID (SHA-256 of ciphertext for deduplication)
    message_id: String,
}

struct MessageStore {
    pool: Pool<sqlx::Sqlite>,
    db_key: DbEncryptionKey,
}

impl MessageStore {
    /// Get a reference to the database encryption key (for encrypting Kyber keys at rest).
    pub fn db_key(&self) -> &[u8; 32] {
        &self.db_key.key
    }
}

impl MessageStore {
    async fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let path = home_dir().join(MESSAGES_DB);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // SECURITY FIX (HIGH-4): Set restrictive file permissions on database
        // Note: SQLite doesn't respect permissions on newly-created DB, so we set them after connect
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&url)
            .await?;

        // Set permissions on the database file (may need to retry on race condition)
        #[cfg(unix)]
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

        // SECURITY (metadata encryption, 2026-07-18): sender/recipient nids,
        // timestamps and message_id are stored AES-256-GCM (db_key); equality
        // lookups use a keyed HMAC blind index so the plaintext never hits disk
        // or is queryable in the clear. Only operational columns (id, status,
        // delivered, status_updated_at) stay plaintext.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_nid_enc TEXT NOT NULL,
                to_nid_enc TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                timestamp_enc TEXT NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0,
                status INTEGER NOT NULL DEFAULT 0,
                status_updated_at TEXT NOT NULL,
                read_receipt_at_enc TEXT,
                message_id_enc TEXT NOT NULL,
                message_id_idx TEXT NOT NULL UNIQUE
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_id ON messages(id)")
            .execute(&pool)
            .await?;

        // Message State History Ledger - tracks all state transitions for audit trail.
        // Never queried back by nid; collapsed to an encrypted record blob keyed
        // by a blind index on message_id.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS message_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id_idx TEXT NOT NULL,
                record_enc TEXT NOT NULL,
                created_at TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        // DoubleRatchet sessions: peer_nid queried for equality (load/delete on
        // every send/handle). Replaced with a blind index + encrypted value.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ratchet_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_nid_idx TEXT NOT NULL UNIQUE,
                peer_nid_enc TEXT NOT NULL,
                session_data TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        let db_key = load_db_key_interactive(read_db_passphrase().as_deref())?;

        // Backward-compat migration (2026-07-18): if this store was created by a
        // build before metadata-encryption, the messages/ratchet_sessions columns
        // are still plaintext. Re-encrypt any legacy rows into the new *_enc
        // columns + blind indexes. No-op for a fresh DB. Best-effort: a row that
        // fails decryption is left as-is (it was already corrupt).
        Self::migrate_legacy_plaintext_store(&pool, &db_key).await?;

        Ok(Self { pool, db_key })
    }

    /// Re-encrypt legacy plaintext metadata columns into the encrypted schema.
    async fn migrate_legacy_plaintext_store(
        pool: &sqlx::SqlitePool,
        db_key: &DbEncryptionKey,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use sqlx::Row;

        // 1) Ensure the new columns exist. An existing DB created before this
        //    migration already has `messages`/`ratchet_sessions` WITHOUT the
        //    *_enc columns (CREATE TABLE IF NOT EXISTS is a no-op there), so we
        //    add them. SQLite has no "ADD COLUMN IF NOT EXISTS", so we probe
        //    PRAGMA table_info and ALTER only the missing ones.
        if !Self::table_has_column(pool, "messages", "from_nid_enc").await {
            sqlx::query("ALTER TABLE messages ADD COLUMN from_nid_enc TEXT")
                .execute(pool).await?;
            sqlx::query("ALTER TABLE messages ADD COLUMN to_nid_enc TEXT")
                .execute(pool).await?;
            sqlx::query("ALTER TABLE messages ADD COLUMN timestamp_enc TEXT")
                .execute(pool).await?;
            sqlx::query("ALTER TABLE messages ADD COLUMN read_receipt_at_enc TEXT")
                .execute(pool).await?;
            sqlx::query("ALTER TABLE messages ADD COLUMN message_id_enc TEXT")
                .execute(pool).await?;
            sqlx::query("ALTER TABLE messages ADD COLUMN message_id_idx TEXT")
                .execute(pool).await?;
        }
        if !Self::table_has_column(pool, "ratchet_sessions", "peer_nid_enc").await {
            sqlx::query("ALTER TABLE ratchet_sessions ADD COLUMN peer_nid_idx TEXT")
                .execute(pool).await?;
            sqlx::query("ALTER TABLE ratchet_sessions ADD COLUMN peer_nid_enc TEXT")
                .execute(pool).await?;
        }

        // 2) Re-encrypt any legacy plaintext rows (those whose *_enc is still
        //    NULL). No-op for a fresh DB. Best-effort: a row that fails is left
        //    as-is (it was already corrupt).
        if let Ok(rows) = sqlx::query(
            "SELECT id, from_nid, to_nid, timestamp, message_id, read_receipt_at, ciphertext \
             FROM messages WHERE from_nid_enc IS NULL",
        )
        .fetch_all(pool)
        .await
        {
            for r in rows {
                let id: i64 = r.try_get("id")?;
                let from_nid: String = r.try_get("from_nid")?;
                let to_nid: String = r.try_get("to_nid")?;
                let timestamp: String = r.try_get("timestamp")?;
                let message_id: String = r.try_get("message_id")?;
                let read_receipt_at: Option<String> = r.try_get("read_receipt_at").unwrap_or(None);
                // Legacy builds stored the message body in `ciphertext` in
                // PLAINTEXT; re-encrypt it too, else get_messages()'s decrypt
                // would reject the row.
                let body: String = r.try_get("ciphertext")?;
                let body_enc = db_key.encrypt(&body)?;
                let from_enc = db_key.encrypt(&from_nid)?;
                let to_enc = db_key.encrypt(&to_nid)?;
                let ts_enc = db_key.encrypt(&timestamp)?;
                let mid_enc = db_key.encrypt(&message_id)?;
                let mid_idx = db_key.blind_index(&message_id);
                let rra_enc = match read_receipt_at {
                    Some(v) => Some(db_key.encrypt(&v)?),
                    None => None,
                };
                sqlx::query(
                    "UPDATE messages SET from_nid_enc=?, to_nid_enc=?, timestamp_enc=?, \
                     message_id_enc=?, message_id_idx=?, read_receipt_at_enc=?, ciphertext=? WHERE id=?",
                )
                .bind(&from_enc)
                .bind(&to_enc)
                .bind(&ts_enc)
                .bind(&mid_enc)
                .bind(&mid_idx)
                .bind(rra_enc)
                .bind(&body_enc)
                .bind(id)
                .execute(pool)
                .await?;
            }
        }

        // ratchet_sessions: peer_nid + session_data -> *_enc + peer_nid_idx.
        if let Ok(rows) = sqlx::query("SELECT id, peer_nid, session_data FROM ratchet_sessions WHERE peer_nid_enc IS NULL")
            .fetch_all(pool)
            .await
        {
            for r in rows {
                let id: i64 = r.try_get("id")?;
                let peer_nid: String = r.try_get("peer_nid")?;
                let session_data: String = r.try_get("session_data")?;
                let nid_idx = db_key.blind_index(&peer_nid);
                let nid_enc = db_key.encrypt(&peer_nid)?;
                // Legacy builds stored session_data in PLAINTEXT; re-encrypt it
                // too, else load_session()'s decrypt would reject the row.
                let data_enc = db_key.encrypt(&session_data)?;
                sqlx::query("UPDATE ratchet_sessions SET peer_nid_idx=?, peer_nid_enc=?, session_data=? WHERE id=?")
                    .bind(&nid_idx)
                    .bind(&nid_enc)
                    .bind(&data_enc)
                    .bind(id)
                    .execute(pool)
                    .await?;
            }
        }

        Ok(())
    }

    /// Probe whether a column exists in a table (SQLite has no
    /// "ADD COLUMN IF NOT EXISTS", so the migration uses this to decide).
    async fn table_has_column(
        pool: &sqlx::SqlitePool,
        table: &str,
        col: &str,
    ) -> bool {
        use sqlx::Row;
        let rows = sqlx::query(&format!("PRAGMA table_info({})", table))
            .fetch_all(pool)
            .await
            .unwrap_or_default();
        rows.iter().any(|r| r.get::<String, _>("name") == col)
    }

    /// Create an in-memory SQLite database for ephemeral KEM handshake state.
    /// No data is written to disk — all state is lost on process exit.
    /// Uses a fresh random encryption key (no persistence needed).
    #[allow(dead_code)]
    async fn open_in_memory() -> Result<Self, Box<dyn std::error::Error>> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS kem_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_nid TEXT NOT NULL,
                session_key BLOB NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        let db_key = DbEncryptionKey::generate_random();

        Ok(Self { pool, db_key })
    }

    async fn store_message(
        &self,
        from_nid: &str,
        to_nid: &str,
        ciphertext: &str,
        status: u8,
        message_id: &str,
    ) -> Result<i64, Box<dyn std::error::Error>> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let status_updated_at = timestamp.clone();
        // ACS2.6 Part III.2: Encrypt ciphertext + all metadata before writing.
        let encrypted_ct = self.db_key.encrypt(ciphertext)?;
        let from_enc = self.db_key.encrypt(from_nid)?;
        let to_enc = self.db_key.encrypt(to_nid)?;
        let ts_enc = self.db_key.encrypt(&timestamp)?;
        let mid_enc = self.db_key.encrypt(message_id)?;
        let mid_idx = self.db_key.blind_index(message_id);
        let result = sqlx::query(
            "INSERT OR IGNORE INTO messages (from_nid_enc, to_nid_enc, ciphertext, timestamp_enc, delivered, status, status_updated_at, read_receipt_at_enc, message_id_enc, message_id_idx)\n             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&from_enc)
        .bind(&to_enc)
        .bind(&encrypted_ct)
        .bind(&ts_enc)
        .bind(if status >= 2 { 1 } else { 0 })
        .bind(status as i64)
        .bind(&status_updated_at)
        .bind(None::<String>)
        .bind(&mid_enc)
        .bind(&mid_idx)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    async fn get_messages(
        &self,
        limit: i64,
    ) -> Result<Vec<StoredMessage>, Box<dyn std::error::Error>> {
        let rows = sqlx::query_as::<_, MessageRow>(
            "SELECT id, from_nid_enc, to_nid_enc, ciphertext, timestamp_enc, delivered, status, status_updated_at, read_receipt_at_enc, message_id_enc\n             FROM messages ORDER BY id DESC LIMIT ?"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        // Decrypt ciphertext + metadata on read.
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let pt = self.db_key.decrypt(&r.ciphertext).ok()?;
                let m = StoredMessage {
                    id: r.id,
                    from_nid: self.db_key.decrypt(&r.from_nid_enc).ok()?,
                    to_nid: self.db_key.decrypt(&r.to_nid_enc).ok()?,
                    ciphertext: pt,
                    timestamp: self.db_key.decrypt(&r.timestamp_enc).ok()?,
                    delivered: r.delivered != 0,
                    status: r.status as u8,
                    status_updated_at: r.status_updated_at,
                    read_receipt_at: self.db_key.decrypt_opt(&r.read_receipt_at_enc),
                    message_id: self.db_key.decrypt(&r.message_id_enc).ok()?,
                };
                Some(m)
            })
            .collect())
    }

    /// Save or update a DoubleRatchet session for a peer.
    /// The session JSON is encrypted with db_key before writing to disk;
    /// peer_nid is stored only as an encrypted value + blind index.
    async fn save_session(
        &self,
        peer_nid: &str,
        session_json: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let encrypted_data = self.db_key.encrypt(session_json)?;
        let nid_idx = self.db_key.blind_index(peer_nid);
        let nid_enc = self.db_key.encrypt(peer_nid)?;
        sqlx::query(
            "INSERT INTO ratchet_sessions (peer_nid_idx, peer_nid_enc, session_data, updated_at)\n             VALUES (?, ?, ?, ?)\n             ON CONFLICT(peer_nid_idx) DO UPDATE SET\n                peer_nid_enc = excluded.peer_nid_enc,\n                session_data = excluded.session_data,\n                updated_at = excluded.updated_at",
        )
        .bind(&nid_idx)
        .bind(&nid_enc)
        .bind(&encrypted_data)
        .bind(&timestamp)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Load a DoubleRatchet session for a peer.
    /// Returns None if no session exists for this peer.
    async fn load_session(
        &self,
        peer_nid: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        let nid_idx = self.db_key.blind_index(peer_nid);
        let row: Option<(String,)> =
            sqlx::query_as("SELECT session_data FROM ratchet_sessions WHERE peer_nid_idx = ?")
                .bind(&nid_idx)
                .fetch_optional(&self.pool)
                .await?;

        row.map(|(data,)| self.db_key.decrypt(&data)).transpose()
    }

    /// Delete a DoubleRatchet session for a peer.
    async fn delete_session(&self, peer_nid: &str) -> Result<(), Box<dyn std::error::Error>> {
        let nid_idx = self.db_key.blind_index(peer_nid);
        sqlx::query("DELETE FROM ratchet_sessions WHERE peer_nid_idx = ?")
            .bind(&nid_idx)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    #[allow(dead_code)]
    async fn get_messages_from(
        &self,
        from_nid: &str,
        limit: i64,
    ) -> Result<Vec<StoredMessage>, Box<dyn std::error::Error>> {
        // Scan-and-decrypt: from_nid is encrypted (no plaintext index). Bounded
        // by `limit` after filtering; acceptable for a local store.
        let rows = sqlx::query_as::<_, MessageRow>(
            "SELECT id, from_nid_enc, to_nid_enc, ciphertext, timestamp_enc, delivered, status, status_updated_at, read_receipt_at_enc, message_id_enc\n             FROM messages ORDER BY id DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|r| {
                let pt = self.db_key.decrypt(&r.ciphertext).ok()?;
                let f = self.db_key.decrypt(&r.from_nid_enc).ok()?;
                if f != from_nid {
                    return None;
                }
                Some(StoredMessage {
                    id: r.id,
                    from_nid: f,
                    to_nid: self.db_key.decrypt(&r.to_nid_enc).ok()?,
                    ciphertext: pt,
                    timestamp: self.db_key.decrypt(&r.timestamp_enc).ok()?,
                    delivered: r.delivered != 0,
                    status: r.status as u8,
                    status_updated_at: r.status_updated_at,
                    read_receipt_at: self.db_key.decrypt_opt(&r.read_receipt_at_enc),
                    message_id: self.db_key.decrypt(&r.message_id_enc).ok()?,
                })
            })
            .take(limit as usize)
            .collect())
    }

    /// Delete a message by its database ID.
    /// Returns true if a message was found and deleted, false otherwise.
    async fn delete_message(&self, id: i64) -> Result<bool, Box<dyn std::error::Error>> {
        let result = sqlx::query("DELETE FROM messages WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    /// Update message delivery status by message_id.
    async fn update_message_status(
        &self,
        message_id: &str,
        status: u8,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let delivered = if status >= 2 { 1 } else { 0 };
        let mid_idx = self.db_key.blind_index(message_id);

        // First get the current message info for history (decrypt metadata).
        let current = sqlx::query_as::<_, MessageRow>(
                    "SELECT id, from_nid_enc, to_nid_enc, ciphertext, timestamp_enc, delivered, status, status_updated_at, read_receipt_at_enc, message_id_enc\n                     FROM messages WHERE message_id_idx = ?"
                )
                .bind(&mid_idx)
                .fetch_optional(&self.pool)
                .await?;

        let (from_nid, to_nid, old_status) = if let Some(ref msg) = current {
            (
                self.db_key.decrypt(&msg.from_nid_enc).unwrap_or_default(),
                self.db_key.decrypt(&msg.to_nid_enc).unwrap_or_default(),
                msg.status as u8,
            )
        } else {
            return Ok(false);
        };

        let result = sqlx::query(
                    "UPDATE messages SET status = ?, status_updated_at = ?, delivered = ? WHERE message_id_idx = ?"
                )
                .bind(status as i64)
                .bind(&timestamp)
                .bind(delivered)
                .bind(&mid_idx)
                .execute(&self.pool)
                .await?;

        // Record in history ledger (encrypted blob; never queried back by nid).
        if result.rows_affected() > 0 {
            let reason = match status {
                1 => "relay_ack",
                2 => "delivered",
                3 => "read_receipt",
                _ => "status_change",
            };
            let record = serde_json::json!({
                "message_id": message_id,
                "from_nid": from_nid,
                "to_nid": to_nid,
                "old_status": old_status,
                "new_status": status,
                "status_updated_at": timestamp,
                "transition_reason": reason,
            }).to_string();
            let record_enc = self.db_key.encrypt(&record)?;
            sqlx::query(
                        "INSERT INTO message_history (message_id_idx, record_enc, created_at)\n                         VALUES (?, ?, ?)"
                    )
                    .bind(&mid_idx)
                    .bind(&record_enc)
                    .bind(&timestamp)
                    .execute(&self.pool)
                    .await?;
        }

        Ok(result.rows_affected() > 0)
    }
}

#[derive(sqlx::FromRow)]
struct MessageRow {
    id: i64,
    from_nid_enc: String,
    to_nid_enc: String,
    ciphertext: String,
    timestamp_enc: String,
    delivered: i64,
    status: i64,
    status_updated_at: String,
    read_receipt_at_enc: Option<String>,
    message_id_enc: String,
}

impl StoredMessage {
    // Built inline in the store methods (decryption happens at read time).
}

// ------------------------------------------------------------------ //
//  Helpers                                                           //
// ------------------------------------------------------------------ //

fn home_dir() -> PathBuf {
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

fn null_id_from_fingerprint(fp: &str) -> String {
    add_dht_core::compute_null_id(fp)
}

fn generate_identity() -> Result<Identity, Box<dyn std::error::Error>> {
    use rand::Rng;
    use sequoia_openpgp::cert::prelude::*;

    let suffix: String = (0..4)
        .map(|_| format!("{:02x}", rand::thread_rng().r#gen::<u8>()))
        .collect();
    let uid = format!("nn-{} <nn-{}@add.local>", suffix, suffix);

    // Generate keypair using Sequoia (Cv25519 EdDSA)
    let (cert, _sig) = CertBuilder::general_purpose(Some(uid.as_str()))
        .set_cipher_suite(sequoia_openpgp::cert::CipherSuite::Cv25519)
        .set_creation_time(std::time::SystemTime::now())
        .generate()
        .map_err(|e| format!("key generation failed: {}", e))?;

    let fingerprint = cert.fingerprint().to_hex().to_uppercase();
    let null_id = null_id_from_fingerprint(&fingerprint);

    // Serialize the cert (secret key) to ASCII-armored text
    let armored = {
        use sequoia_openpgp::serialize::Serialize;
        let mut buf = Vec::new();
        cert.as_tsk()
            .armored()
            .serialize(&mut buf)
            .map_err(|e| format!("serialize armored cert: {}", e))?;
        String::from_utf8(buf).map_err(|e| format!("armored cert contains invalid UTF-8: {}", e))?
    };

    // Prompt for passphrase to protect the GPG secret key
    let cert_dir = home_dir().join(".add/gnupg");
    std::fs::create_dir_all(&cert_dir)?;
    let password = prompt_passphrase()?;

    if password.is_empty() {
        // No passphrase: save as plaintext (legacy behavior). SECURITY: the
        // GPG secret key is then stored unencrypted on disk. We allow it for
        // backward compatibility but warn loudly — prefer a passphrase (age-
        // encrypted) in any real deployment.
        eprintln!("WARNING: saving GPG secret key WITHOUT a passphrase (plaintext on disk).");
        let cert_path = cert_dir.join("own_cert.asc");
        std::fs::write(&cert_path, &armored)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cert_path, std::fs::Permissions::from_mode(0o600))?;
        }
    } else {
        // Encrypt with age passphrase encryption
        let enc_path = cert_dir.join("own_cert.age");
        let encrypted = encrypt_cert_armored(&armored, &password)?;
        std::fs::write(&enc_path, &encrypted)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&enc_path, std::fs::Permissions::from_mode(0o600))?;
        }
        // Optionally remove old plaintext file if exists
        let old_plain = cert_dir.join("own_cert.asc");
        if old_plain.exists() {
            let _ = std::fs::remove_file(&old_plain);
        }
    }

    // SECURITY FIX (C1): Generate Kyber-1024 keypair RANDOMLY (post-quantum
    // encryption). The KEM keypair is NO LONGER derived from null_id — that
    // made the decapsulation key reconstructable from the public cert. We
    // generate it with OS randomness, save it encrypted at rest, and publish
    // only the encapsulation (public) key inside the cert bundle. See F-1/F-2/F-3.
    let db_key = DbEncryptionKey::load_or_create_sync();
    // F-7: wrap the DB key with the user passphrase so the message store key
    // is not recoverable by local root from a plaintext key file.
    db_key.save(Some(password.as_str()))?;
    let kyber_path = home_dir().join(KYBER_KEY_PATH);
    let kyber_kp = add_crypto::kyber::KyberKeypair::load_or_generate(&kyber_path, db_key.key())
        .map_err(|e| format!("kyber keypair load/generate: {e}"))?;
    // Print Kyber public key for debugging (can be removed later)
    let kyber_enc_b64 = add_crypto::kyber::encode_enc_key(&kyber_kp.enc);
    println!("Kyber public key generated ({} bytes)", kyber_enc_b64.len());

    // Generate ML-DSA-87 keypair for post-quantum signatures
    let (ml_dsa87_sk, ml_dsa87_vk) = add_crypto_pq::generate_keypair()
        .map_err(|e| format!("ML-DSA-87 keypair generation failed: {}", e))?;

    // Serialize the signing key
    use ml_dsa::KeyExport;
    let ml_dsa87_sk_bytes = ml_dsa87_sk.to_bytes();
    let ml_dsa87_sk_b64 = base64::engine::general_purpose::STANDARD.encode(ml_dsa87_sk_bytes);

    // Also save the verifying key fingerprint for DHT registration
    let ml_dsa87_fp = add_crypto_pq::fingerprint_from_verifying_key(&ml_dsa87_vk);
    println!("ML-DSA-87 fingerprint: {}", ml_dsa87_fp);

    let identity = Identity {
        fingerprint,
        null_id,
        ml_dsa87_signing_key: Some(ml_dsa87_sk_b64),
    };
    identity.save()?;

    Ok(identity)
}

// ------------------------------------------------------------------ //
//  DHT Client (for G1 Send)                                         //
// ------------------------------------------------------------------ //

/// Connect to the seed DHT node and look up a recipient's address.
/// This uses the centralized seed DHT model (G4: no Kademlia routing).
/// Fetch a peer's ML-DSA-87 verifying key from the DHT and cache it for
/// signature verification. The bootstrap `dht-found` response carries the
/// publisher's verifying key alongside the value. Returns true if cached.
async fn fetch_peer_verifying_key(seed_url: &str, peer_fp: &str) -> bool {
    use add_protocol::envelope::WireEnvelope;
    let null_id = null_id_from_fingerprint(peer_fp);
    let ws_url = seed_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let mut ws = match ws_connect(&ws_url).await {
        Ok(w) => w,
        Err(_) => return false,
    };
    let sig_data = format!("dht-get:{}\n", serde_json::json!({"key": null_id}));
    let sig = match sign_for_transport(&sig_data) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let req = WireEnvelope {
        msg_type: "dht-get".to_string(),
        msg_id: uuid_hex(),
        ts: chrono::Utc::now().timestamp() as f64,
        sig,
        payload: {
            let mut m = serde_json::Map::new();
            m.insert("key".to_string(), serde_json::Value::String(null_id));
            serde_json::Value::Object(m)
        },
    };
    if ws
        .send(Message::Text(serde_json::to_string(&req).unwrap().into()))
        .await
        .is_err()
    {
        return false;
    }
    if let Some(Ok(Message::Text(resp_text))) = ws.next().await
        && let Ok(resp) = serde_json::from_str::<WireEnvelope>(&resp_text)
        && let Some(vk_b64) = resp.payload_str("publisher_verifying_key")
        && let Ok(vk_bytes) = base64::engine::general_purpose::STANDARD.decode(vk_b64)
        && let Ok(vk) = add_crypto_pq::decode_verifying_key(&vk_bytes)
    {
        add_dht_core::crypto_helpers::cache_verifying_key(peer_fp, &vk);
        return true;
    }
    false
}
/// Returns Ok(Some(value)) if found, Ok(None) if not found, Err on error.
async fn dht_get(
    seed_url: &str,
    null_id: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    use add_protocol::envelope::WireEnvelope;

    // Bootstrap servers use root path, not /ws
    let ws_url = seed_url;

    let mut ws = ws_connect(ws_url)
        .await
        .map_err(|e| format!("DHT connect failed: {}", e))?;

    // Send dht-get request (no signature needed for query)
    let req = WireEnvelope {
        msg_type: "dht-get".to_string(),
        msg_id: uuid_hex(),
        ts: chrono::Utc::now().timestamp() as f64,
        sig: String::new(),
        payload: {
            let mut m = serde_json::Map::new();
            m.insert(
                "key".to_string(),
                serde_json::Value::String(null_id.to_string()),
            );
            serde_json::Value::Object(m)
        },
    };
    let req_json = serde_json::to_string(&req)?;
    ws.send(Message::Text(req_json.into()))
        .await
        .map_err(|e| format!("DHT send failed: {}", e))?;

    // Read response
    if let Some(Ok(Message::Text(resp_text))) = ws.next().await {
        let resp: WireEnvelope = serde_json::from_str(&resp_text)?;
        if resp.msg_type == "dht-found" {
            let value = resp.payload_str("value").unwrap_or("");
            if !value.is_empty() {
                return Ok(Some(value.to_string()));
            }
        }
    }

    Ok(None)
}

/// Register identity with the DHT bootstrap server.
/// Sends a `dht-put` message with the Null ID as key and the fingerprint as value.
/// Must include proof-of-work, nonce, salt, seq, publisher_fp, and signature.
async fn dht_register(
    seed_url: &str,
    identity: &Identity,
) -> Result<(), Box<dyn std::error::Error>> {
    use add_protocol::envelope::WireEnvelope;

    let ws_url = seed_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");

    let mut ws = ws_connect(&ws_url)
        .await
        .map_err(|e| format!("DHT connect failed: {}", e))?;

    // Check if already registered: do a dht-get first.
    // seq==0 → diff 8 (fast, ~2-10s). seq>0 → diff 16 (slow, ~1-2 min).
    // Only use diff-16 when re-registering an existing key.
    let already_registered = {
        use add_protocol::envelope::WireEnvelope;
        let check_req = WireEnvelope {
            msg_type: "dht-get".to_string(),
            msg_id: uuid_hex(),
            ts: chrono::Utc::now().timestamp() as f64,
            sig: String::new(),
            payload: {
                let mut m = serde_json::Map::new();
                m.insert(
                    "key".to_string(),
                    serde_json::Value::String(identity.null_id.clone()),
                );
                serde_json::Value::Object(m)
            },
        };
        ws.send(Message::Text(
            serde_json::to_string(&check_req).unwrap_or_default().into(),
        ))
        .await
        .map_err(|e| format!("DHT check send failed: {}", e))?;
        // Loop past Ping/Pong frames to find the Text response
        let mut found = false;
        for _ in 0..10 {
            if let Some(Ok(msg)) = ws.next().await {
                match msg {
                    Message::Text(resp_text) => {
                        if let Ok(resp) = serde_json::from_str::<WireEnvelope>(&resp_text)
                            && resp.msg_type == "dht-found"
                        {
                            found = true;
                        }
                        break;
                    }
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Close(_) => break,
                    _ => continue,
                }
            } else {
                break;
            }
        }
        found
    };

    if already_registered {
        tracing::info!(
            "Identity {} already registered — updating with higher seq",
            identity.null_id
        );
    }
    let seq: i64 = if already_registered {
        chrono::Utc::now().timestamp()
    } else {
        0
    };
    let pow_difficulty: u32 = if seq == 0 {
        8
    } else {
        add_protocol::constants::DHT_POW_DIFFICULTY
    };
    tracing::info!(
        "Solving PoW (difficulty {}, this may take {})...",
        pow_difficulty,
        if pow_difficulty <= 8 {
            "~2-10s"
        } else {
            "~1-2 min"
        }
    );

    let salt = uuid_hex();
    let value_b64 = identity.fingerprint.clone();
    // SECURITY FIX (M11): salt PoW with the publisher's own fingerprint so
    // the server (which validates with the same publisher_fp) can reproduce
    // the identical Argon2id salt. Must match dht-core/handle_put.
    let pow_data = format!("{}|{}|{}|{}", identity.null_id, value_b64, salt, seq);
    // Owned copy of the per-node secret for the spawned blocking task
    // (spawn_blocking requires 'static; `identity` is only borrowed here).
    let publisher_fp_secret = identity.fingerprint.clone();
    let start = std::time::Instant::now();
    let pow_nonce = match tokio::task::spawn_blocking(move || {
        add_dht_core::pow_solve(
            &pow_data,
            pow_difficulty,
            10_000_000,
            publisher_fp_secret.as_bytes(),
        )
    })
    .await
    {
        Ok(Ok(Some(n))) => {
            tracing::info!("PoW solved in {}s", start.elapsed().as_secs());
            n
        }
        Ok(Ok(None)) => {
            return Err("DHT register: could not solve PoW in time (exhausted attempts)".into());
        }
        Ok(Err(e)) => {
            return Err(format!("DHT register: PoW error: {}", e).into());
        }
        Err(e) => {
            return Err(format!("DHT register: task join error: {}", e).into());
        }
    };

    // Sign the put request with ML-DSA-87
    let sign_data = format!(
        "{}|{}|{}|{}|{}",
        identity.null_id, value_b64, salt, seq, pow_nonce
    );
    let sig = sign_for_transport(&sign_data)?;

    // Include ML-DSA-87 verifying key in the payload for the DHT to verify
    let identity = Identity::load()?;
    let vk_b64 = if let Some(sk_b64) = identity.ml_dsa87_signing_key {
        let sk_bytes = base64::engine::general_purpose::STANDARD.decode(sk_b64)?;
        use ml_dsa::{KeyInit, Keypair};
        let sk = add_crypto_pq::MlDsa87SigningKey::new_from_slice(&sk_bytes)
            .map_err(|e| format!("ML-DSA-87 key reconstruction failed: {}", e))?;
        let vk = Keypair::verifying_key(&sk).clone();
        use ml_dsa::KeyExport;
        let vk_bytes = vk.to_bytes();
        base64::engine::general_purpose::STANDARD.encode(vk_bytes)
    } else {
        String::new()
    };

    let req = WireEnvelope {
        msg_type: "dht-put".to_string(),
        msg_id: uuid_hex(),
        ts: chrono::Utc::now().timestamp() as f64,
        sig,
        payload: {
            let mut m = serde_json::Map::new();
            m.insert(
                "key".to_string(),
                serde_json::Value::String(identity.null_id.clone()),
            );
            m.insert("value".to_string(), serde_json::Value::String(value_b64));
            m.insert("salt".to_string(), serde_json::Value::String(salt));
            m.insert("seq".to_string(), serde_json::Value::Number(seq.into()));
            m.insert(
                "nonce".to_string(),
                serde_json::Value::Number(pow_nonce.into()),
            );
            m.insert(
                "publisher_fp".to_string(),
                serde_json::Value::String(identity.fingerprint.clone()),
            );
            m.insert(
                "publisher_verifying_key".to_string(),
                serde_json::Value::String(vk_b64),
            );
            serde_json::Value::Object(m)
        },
    };
    let req_json = serde_json::to_string(&req)?;
    ws.send(Message::Text(req_json.into()))
        .await
        .map_err(|e| format!("DHT send failed: {}", e))?;

    // Read response
    if let Some(Ok(Message::Text(resp_text))) = ws.next().await {
        let resp: WireEnvelope = serde_json::from_str(&resp_text)
            .map_err(|e| format!("DHT register: bad response: {}", e))?;
        if resp.msg_type == "dht-found" {
            return Ok(());
        } else {
            let payload = resp.payload.to_string();
            return Err(format!("DHT register failed: {} ({})", resp.msg_type, payload).into());
        }
    }

    Err("DHT register failed: server closed connection".into())
}

/// Content-addressing key for the cert store: SHA-256 of the fingerprint.
/// The fetcher computes this directly from the fingerprint Bob speaks
/// out-of-band (DESIGN.md §4.2), so no prior cert is needed to locate it.
fn cert_blob_key(fingerprint: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(fingerprint.as_bytes());
    format!("cert:{}", hex::encode(h))
}

/// Publish our certificate to the opaque blob store on ALL bootstrap servers
/// (DESIGN.md §4.2 Publish). The blob is addressed by `cert:<H(fingerprint)>`
/// and signed over `{cert_b64}|{fingerprint}` with our ML-DSA-87 key. The
/// server stores it opaquely — it learns the public cert + fingerprint but
/// gains no trusted ID↔key statement.
async fn dht_publish_cert(
    identity: &Identity,
) -> Result<(), Box<dyn std::error::Error>> {
    use add_protocol::envelope::WireEnvelope;

    // SECURITY: publish the PUBLIC cert only — strip all secret key material.
    let armored = {
        use sequoia_openpgp::serialize::Serialize;
        let cert = load_cert()
            .map_err(|e| e.to_string())?
            .strip_secret_key_material();
        let mut buf = Vec::new();
        cert.armored()
            .serialize(&mut buf)
            .map_err(|e| format!("serialize public cert: {}", e))?;
        String::from_utf8(buf).map_err(|e| format!("armored cert invalid UTF-8: {}", e))?
    };
    let cert_b64 = base64::engine::general_purpose::STANDARD.encode(armored.as_bytes());

    // ML-DSA-87 verifying key (for the fetcher to verify signatures later)
    let vk_b64 = if let Some(sk_b64) = &identity.ml_dsa87_signing_key {
        let sk_bytes = base64::engine::general_purpose::STANDARD.decode(sk_b64)?;
        use ml_dsa::{KeyExport, KeyInit, Keypair};
        let sk = add_crypto_pq::MlDsa87SigningKey::new_from_slice(&sk_bytes)
            .map_err(|e| format!("ML-DSA-87 key reconstruction failed: {}", e))?;
        let vk = Keypair::verifying_key(&sk).clone();
        base64::engine::general_purpose::STANDARD.encode(vk.to_bytes())
    } else {
        String::new()
    };

    // Cert-store identity is the ML-DSA-87 fingerprint (post-quantum), NOT the
    // OpenPGP cert fingerprint. The server binds the published VK to this fp,
    // so the blob key, bundle fp and publisher_fp must all be the PQ fp. Using
    // the GPG fp here would fail the VK→fp binding check and be rejected.
    let fp = if let Some(sk_b64) = &identity.ml_dsa87_signing_key {
        let sk_bytes = base64::engine::general_purpose::STANDARD.decode(sk_b64)?;
        use ml_dsa::{KeyInit, Keypair};
        let sk = add_crypto_pq::MlDsa87SigningKey::new_from_slice(&sk_bytes)
            .map_err(|e| format!("ML-DSA-87 key reconstruction failed: {}", e))?;
        add_crypto_pq::fingerprint_from_verifying_key(&Keypair::verifying_key(&sk).clone())
    } else {
        return Err("ML-DSA-87 signing key not found - re-run 'add init'".into());
    };

    // ML-KEM (Kyber) encapsulation key — PUBLISH our random on-disk key
    // (NOT derived from null_id). Loaded from disk so sender/receiver agree.
    let kyber_kp = load_or_generate_kyber(&identity.null_id, &DbEncryptionKey::load_or_create_sync().key().clone())?;
    let kyber_enc_b64 = add_crypto::kyber::encode_enc_key(&kyber_kp.enc);

    let key = cert_blob_key(&fp);
    // Bundle cert + keys into the opaque value blob (the generic store only
    // persists key/value/sig, so extra payload fields would be dropped on GET).
    let bundle = serde_json::json!({
        "cert": cert_b64,
        "vk": vk_b64,
        "kyber_enc": kyber_enc_b64,
        "fp": fp,
    })
    .to_string();
    let value_b64 = base64::engine::general_purpose::STANDARD.encode(bundle.as_bytes());
    // Canonical signed data matches the server's cert: blob verification
    // contract: "{key}|{value}|{publisher_fp}". The server binds the
    // self-asserted `publisher_verifying_key` to publisher_fp, so only the
    // holder of the matching ML-DSA-87 key can publish this cert blob.
    let sign_data = format!("{}|{}|{}", key, value_b64, fp);
    let sig = sign_for_transport(&sign_data)?;

    let (_, bootstraps, _) = discover_all_servers().await;
    let mut success_count = 0;
    let mut last_error = None;
    for seed_url in &bootstraps {
        let ws_url = seed_url
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        let mut ws = match ws_connect(&ws_url).await {
            Ok(w) => w,
            Err(e) => {
                last_error = Some(format!("DHT connect failed: {}", e));
                continue;
            }
        };
        let req = WireEnvelope {
            msg_type: "blob-put".to_string(),
            msg_id: uuid_hex(),
            ts: chrono::Utc::now().timestamp() as f64,
            sig: sig.clone(),
            payload: {
                let mut m = serde_json::Map::new();
                m.insert("key".to_string(), serde_json::Value::String(key.clone()));
                m.insert(
                    "value".to_string(),
                    serde_json::Value::String(value_b64.clone()),
                );
                m.insert("sig".to_string(), serde_json::Value::String(sig.clone()));
                m.insert(
                    "publisher_fp".to_string(),
                    serde_json::Value::String(fp.clone()),
                );
                // Self-asserted verifying key — the server binds it to
                // publisher_fp before accepting the cert blob (cert-store MITM defense).
                m.insert(
                    "publisher_verifying_key".to_string(),
                    serde_json::Value::String(vk_b64.clone()),
                );
                m.insert(
                    "ttl".to_string(),
                    serde_json::Value::Number(serde_json::Number::from(
                        add_protocol::constants::ADDR_TTL,
                    )),
                );
                m.insert(
                    "nonce".to_string(),
                    serde_json::Value::Number((uuid_hex().len() as i64).into()),
                );
                m.insert("vk".to_string(), serde_json::Value::String(vk_b64.clone()));
                m.insert(
                    "kyber_enc".to_string(),
                    serde_json::Value::String(kyber_enc_b64.clone()),
                );
                serde_json::Value::Object(m)
            },
        };
        let req_json = serde_json::to_string(&req)?;
        if let Err(e) = ws.send(Message::Text(req_json.into())).await {
            last_error = Some(format!("cert publish send failed: {}", e));
            continue;
        }
        if let Some(Ok(Message::Text(resp_text))) = ws.next().await
            && let Ok(resp) = serde_json::from_str::<WireEnvelope>(&resp_text)
        {
            if resp.msg_type == "dht-found" {
                success_count += 1;
            } else {
                last_error = Some(format!("cert publish rejected: {}", resp.msg_type));
            }
        }
    }
    if success_count > 0 {
        tracing::info!(
            "Certificate published on {}/{} bootstrap servers",
            success_count,
            bootstraps.len()
        );
        Ok(())
    } else {
        Err(last_error
            .map(|e| e.into())
            .unwrap_or_else(|| "No bootstrap servers available".into()))
    }
}

/// Fetch a contact's certificate blob from the opaque store, given the
/// fingerprint they spoke out-of-band (DESIGN.md §4.2 Onboarding). Returns the
/// armored cert + ML-DSA verifying key + ML-KEM enc key. The caller verifies
/// the cert hash matches the spoken fingerprint before trusting it.
pub(crate) async fn dht_fetch_cert(
    seed_url: &str,
    fingerprint: &str,
) -> Result<(String, String, String), Box<dyn std::error::Error + Send + Sync>> {
    use add_protocol::envelope::WireEnvelope;
    let ws_url = seed_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let mut ws = ws_connect(&ws_url)
        .await
        .map_err(|e| format!("DHT connect failed: {}", e))?;
    let key = cert_blob_key(fingerprint);
    let req = WireEnvelope {
        msg_type: "blob-get".to_string(),
        msg_id: uuid_hex(),
        ts: chrono::Utc::now().timestamp() as f64,
        sig: String::new(),
        payload: {
            let mut m = serde_json::Map::new();
            m.insert("key".to_string(), serde_json::Value::String(key));
            serde_json::Value::Object(m)
        },
    };
    ws.send(Message::Text(serde_json::to_string(&req)?.into()))
        .await
        .map_err(|e| format!("cert fetch send failed: {}", e))?;
    if let Some(Ok(Message::Text(resp_text))) = ws.next().await {
        let resp: WireEnvelope = serde_json::from_str(&resp_text)
            .map_err(|e| format!("cert fetch parse failed: {}", e))?;
        if resp.msg_type != "dht-found" {
            return Err(format!("cert not found: {}", resp.msg_type).into());
        }
        let value = resp.payload_str("value").ok_or("missing cert blob value")?;
        // value = base64(JSON bundle {cert, vk, kyber_enc, fp})
        let bundle_bytes = base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|e| format!("cert blob not base64: {}", e))?;
        let bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes)
            .map_err(|e| format!("cert bundle not JSON: {}", e))?;
        let cert_b64 = bundle.get("cert").and_then(|v| v.as_str()).unwrap_or("");
        let vk_b64 = bundle
            .get("vk")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let kyber_enc = bundle
            .get("kyber_enc")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let armored_bytes = base64::engine::general_purpose::STANDARD
            .decode(cert_b64)
            .map_err(|e| format!("cert not base64: {}", e))?;
        let armored =
            String::from_utf8(armored_bytes).map_err(|e| format!("cert blob not utf8: {}", e))?;
        Ok((armored, vk_b64, kyber_enc))
    } else {
        Err("no response from bootstrap".into())
    }
}

/// Resolve a well-known public service's listener address from the public
/// cert store, and pin its verifying key (DESIGN.md §6 exception).
///
/// Public services publish their `{cert, vk, kyber_enc, fp, address}` bundle to
/// the same opaque cert store as everyone else (key `cert:<H(fp)>`), so the
/// server stores only ciphertext + the public cert — no plaintext `addr:ip`
/// record. Any client may read it (the key is well-known), which is what makes
/// the service reachable without a contact entry. We pre-pin the VK from this
/// authoritative bundle so the later `p2p-hello-ack` MITM check (C3) can only
/// succeed if the responder proves possession of the published key.
///
/// Fail-closed: if the bundle is missing/unpublished, the send aborts — this is
/// the "reflector needs its cert in bootstrap" guarantee made explicit.
async fn fetch_public_service_addr(null_id: &str) -> Option<String> {
    let fp = if null_id == REFLECTOR_NULL_ID {
        REFLECTOR_FINGERPRINT
    } else {
        return None;
    };
    let (_, bootstraps, _) = discover_all_servers().await;
    for seed_url in &bootstraps {
        // Reuse the cert blob-get path; the bundle carries `address`.
        if let Ok((_cert, vk_b64, _kyber)) = dht_fetch_cert(seed_url, fp).await {
            // Pin the VK from the authoritative published bundle.
            if let Ok(vk_bytes) = base64::engine::general_purpose::STANDARD.decode(&vk_b64)
                && let Ok(vk) = add_crypto_pq::decode_verifying_key(&vk_bytes)
            {
                let _ = add_dht_core::crypto_helpers::pin_verifying_key(fp, &vk);
            }
            // The address field is carried in the same bundle; re-fetch the raw
            // bundle to read it (dht_fetch_cert elides it).
            if let Some(addr) = fetch_cert_address(seed_url, fp).await {
                return Some(addr);
            }
        }
    }
    None
}

/// Read just the `address` field from a published cert bundle (the public
/// service's advertised `ws://` endpoint). Returns None if unpublished.
async fn fetch_cert_address(seed_url: &str, fingerprint: &str) -> Option<String> {
    use add_protocol::envelope::WireEnvelope;
    let ws_url = seed_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let mut ws = ws_connect(&ws_url).await.ok()?;
    let key = cert_blob_key(fingerprint);
    let req = WireEnvelope {
        msg_type: "blob-get".to_string(),
        msg_id: uuid_hex(),
        ts: chrono::Utc::now().timestamp() as f64,
        sig: String::new(),
        payload: {
            let mut m = serde_json::Map::new();
            m.insert("key".to_string(), serde_json::Value::String(key));
            serde_json::Value::Object(m)
        },
    };
    ws.send(Message::Text(serde_json::to_string(&req).ok()?.into()))
        .await
        .ok()?;
    if let Some(Ok(Message::Text(resp_text))) = ws.next().await {
        if let Ok(resp) = serde_json::from_str::<WireEnvelope>(&resp_text) {
            if resp.msg_type != "dht-found" {
                return None;
            }
            let value = resp.payload_str("value")?;
            let bundle_bytes = base64::engine::general_purpose::STANDARD
                .decode(value)
                .ok()?;
            let bundle: serde_json::Value = serde_json::from_slice(&bundle_bytes).ok()?;
            let addr = bundle.get("address").and_then(|a| a.as_str())?.to_string();
            if addr.is_empty() { None } else { Some(addr) }
        } else {
            None
        }
    } else {
        None
    }
}

/// SECURITY FIX (L1): Privacy-enhanced DHT lookup using PIR (Private Information Retrieval).
/// Instead of sending the null_id in plaintext to the DHT server (which would reveal
/// WHO the user is looking up), this function uses XOR-based PIR with cuckoo hashing
/// to query blind bins. The server learns neither the queried contact nor whether
/// the lookup succeeded.
///
/// The DHT bootstrap server must expose a `/pir-query` WebSocket endpoint that
/// accepts PIR query tokens and returns bin contents. Falls back to standard
/// `dht_lookup` if the server doesn't support PIR.
// ------------------------------------------------------------------ //
//  Relay Client (for G2 Read)                                        //
// ------------------------------------------------------------------ //

/// SECURITY FIX (C2): Fetch messages from the relay mailbox for our null_id.
/// Uses relay-fetch protocol with GPG signature for authentication.
/// Fetch messages from relay mailbox and decrypt them using persisted
/// DoubleRatchet sessions.
/// SECURITY FIX (G9): Relay-fetched messages are now decrypted with the
/// DoubleRatchet session, not returned as raw ciphertext blobs.
/// Load or generate the Kyber keypair deterministically from null_id.
/// Both sender and recipient derive the SAME keypair from the recipient's null_id,
/// Load our local ML-KEM-1024 keypair, generating it RANDOMLY on first use.
///
/// SECURITY FIX (F-1/F-2/F-3): this MUST NOT derive the keypair from `null_id`.
/// A deterministic seed would let anyone who knows our public cert recompute
/// our decapsulation key. We generate with OS randomness, store it encrypted at
/// rest (AES-256-GCM via DbEncryptionKey), and publish only the encapsulation
/// (public) key inside our cert bundle. The `null_id` arg is retained for
/// call-site compatibility but is intentionally unused.
pub(crate) fn load_or_generate_kyber(
    _null_id: &str,
    enc_key: &[u8; 32],
) -> Result<add_crypto::kyber::KyberKeypair, Box<dyn std::error::Error>> {
    let kyber_path = home_dir().join(KYBER_KEY_PATH);
    // Try loading existing keypair first
    if kyber_path.exists() {
        return add_crypto::kyber::KyberKeypair::load(&kyber_path, enc_key)
            .map_err(|e| format!("kyber keypair load failed: {e}").into());
    }
    // Generate a fresh RANDOM keypair (never derived from null_id).
    let kp = add_crypto::kyber::KyberKeypair::generate()
        .map_err(|e| format!("kyber keypair generate failed: {e}"))?;
    std::fs::create_dir_all(kyber_path.parent().unwrap())?;
    kp.save(&kyber_path, enc_key)
        .map_err(|e| format!("kyber keypair save failed: {e}"))?;
    Ok(kp)
}

#[allow(dead_code)]
async fn relay_fetch(
    relay_url: &str,
    null_id: &str,
    store: &MessageStore,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let ws_url = relay_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let mut ws = ws_connect(&ws_url)
        .await
        .map_err(|e| format!("Relay connect failed: {}", e))?;

    // Load identity to get fingerprint for signing and cert for TOFU
    let identity = Identity::load()?;

    // Load armored cert for TOFU verification at relay
    let cert = identity.cert()?;
    let cert_armored = {
        use sequoia_openpgp::serialize::Serialize;
        let mut buf = Vec::new();
        cert.as_tsk()
            .armored()
            .serialize(&mut buf)
            .map_err(|e| format!("serialize armored cert: {}", e))?;
        String::from_utf8(buf).map_err(|e| format!("armored cert utf8: {}", e))?
    };

    // SECURITY FIX (C2): Sign the fetch request with our PGP key
    let timestamp = chrono::Utc::now().timestamp() as f64;
    let nonce = uuid_hex();
    let sig_data = format!("relay-fetch:{}:{}:{}", null_id, timestamp, nonce);
    let sig = sign_for_transport(&sig_data)?;

    // SECURITY FIX (C2): Use relay-fetch protocol with ALL required fields
    let req = serde_json::json!({
        "msg_type": "relay-fetch",
        "msg_id": uuid_hex(),
        "ts": timestamp,
        "sig": "",
        "payload": {
            "recipient_nid": null_id,
            "requester_fp": identity.fingerprint,
            "sender_sig": sig,
            "sender_cert": cert_armored,
            "timestamp": timestamp,
            "nonce": nonce,
            "auth_hmac": "",
        },
    });
    ws.send(Message::Text(req.to_string().into()))
        .await
        .map_err(|e| format!("Relay send failed: {}", e))?;

    // Load our Kyber keypair deterministically derived from null_id
    let our_kyber = load_or_generate_kyber(null_id, store.db_key())?;

    // Read response, skipping Ping/Pong heartbeats
    let resp_text = loop {
        match ws.next().await {
            Some(Ok(Message::Text(text))) => break text.to_string(),
            Some(Ok(Message::Ping(data))) => {
                let _ = ws.send(Message::Pong(data)).await;
                continue;
            }
            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Close(_))) => continue,
            Some(Err(e)) => return Err(format!("Relay websocket error: {}", e).into()),
            None => return Err("Relay closed connection without response".into()),
            _ => continue,
        }
    };
    let resp: serde_json::Value = serde_json::from_str(&resp_text)?;

    // Check for error response
    if let Some(error) = resp.get("error").and_then(|e| e.as_str()) {
        return Err(format!("Relay error: {}", error).into());
    }

    // Parse entries from relay-fetch response and decrypt
    let data = resp.get("data").and_then(|d| d.as_object());
    if let Some(entries) = data
        .and_then(|d| d.get("entries"))
        .and_then(|m| m.as_array())
    {
        let mut result = Vec::new();
        for entry in entries {
            if let Some(signed_blob) = entry.get("signed_blob").and_then(|b| b.as_str()) {
                // Extract sender info from the relay entry (not the blob)
                let entry_sender_nid = entry
                    .get("sender_nid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let entry_sender_fp = entry
                    .get("sender_fp")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let decrypted = match relay_decrypt_message(
                    signed_blob,
                    entry_sender_nid,
                    entry_sender_fp,
                    &identity.fingerprint,
                    store,
                    &our_kyber,
                )
                .await
                {
                    Ok(plaintext) => plaintext,
                    Err(e) => {
                        println!("Warning: failed to decrypt relay message: {}", e);
                        continue;
                    }
                };
                result.push(decrypted);
            }
        }
        return Ok(result);
    }

    Ok(Vec::new())
}

/// Select the fastest responding relay from a list.
/// Tries all relays in parallel with timeouts, returns the first to respond.
async fn select_fastest_relay(relay_urls: &[String]) -> Option<String> {
    use tokio::time::{Duration, timeout};

    let mut tasks = Vec::new();

    for url in relay_urls {
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let ws_url = url
                .replace("http://", "ws://")
                .replace("https://", "wss://");
            match timeout(Duration::from_secs(5), ws_connect(&ws_url)).await {
                Ok(Ok(_)) => Some(url),
                _ => None,
            }
        }));
    }

    // Return the first successful connection
    for task in tasks {
        if let Ok(Some(url)) = task.await {
            tracing::debug!("Fastest relay selected: {}", url);
            return Some(url);
        }
    }

    // If none responded, try them sequentially
    for url in relay_urls {
        let ws_url = url
            .replace("http://", "ws://")
            .replace("https://", "wss://");
        if ws_connect(&ws_url).await.is_ok() {
            return Some(url.clone());
        }
    }

    None
}

/// Parallel fetch from ALL relay servers - needed for multi-relay failover.
/// Returns messages with their source relay URLs for deduplication.
async fn relay_fetch_all(
    relay_urls: &[String],
    null_id: &str,
) -> Result<Vec<(String, String, String, String)>, Box<dyn std::error::Error>> {
    use tokio::time::{Duration, timeout};

    let mut tasks = Vec::new();
    for url in relay_urls {
        let url = url.clone();
        let null_id = null_id.to_string();
        tasks.push(tokio::spawn(async move {
            let ws_url = url
                .replace("http://", "ws://")
                .replace("https://", "wss://");
            let timeout_result = timeout(Duration::from_secs(10), async {
                let mut ws = ws_connect(&ws_url).await?;

                let identity = match Identity::load() {
                    Ok(id) => id,
                    Err(_) => {
                        return Ok::<Vec<(String, String, String)>, Box<dyn std::error::Error>>(
                            Vec::new(),
                        );
                    }
                };
                let cert = match identity.cert() {
                    Ok(c) => c,
                    Err(_) => {
                        return Ok::<Vec<(String, String, String)>, Box<dyn std::error::Error>>(
                            Vec::new(),
                        );
                    }
                };
                let cert_armored = {
                    use sequoia_openpgp::serialize::Serialize;
                    let mut buf = Vec::new();
                    match cert.as_tsk().armored().serialize(&mut buf) {
                        Ok(_) => String::from_utf8(buf).unwrap_or_default(),
                        Err(_) => String::new(),
                    }
                };

                let timestamp = chrono::Utc::now().timestamp() as f64;
                let nonce = uuid_hex();
                let sig_data = format!("relay-fetch:{}:{}:{}", null_id, timestamp, nonce);
                let sig = sign_for_transport(&sig_data)?;

                let req = serde_json::json!({
                    "msg_type": "relay-fetch",
                    "msg_id": uuid_hex(),
                    "ts": timestamp,
                    "sig": "",
                    "payload": {
                        "recipient_nid": null_id,
                        "requester_fp": identity.fingerprint,
                        "sender_sig": sig,
                        "sender_cert": cert_armored,
                        "timestamp": timestamp,
                        "nonce": nonce,
                        "auth_hmac": "",
                        "requester_verifying_key": my_verifying_key_b64().unwrap_or_default(),
                    },
                });
                ws.send(Message::Text(req.to_string().into())).await?;

                let mut messages: Vec<(String, String, String)> = Vec::new();
                loop {
                    match ws.next().await {
                        Some(Ok(Message::Text(text))) => {
                            let resp: serde_json::Value = serde_json::from_str(&text)?;
                            if let Some(error) = resp.get("error").and_then(|e| e.as_str()) {
                                tracing::warn!("relay-fetch rejected by {}: {}", url, error);
                                return Ok(Vec::new());
                            }
                            if let Some(entries) = resp
                                .get("data")
                                .and_then(|d| d.as_object())
                                .and_then(|d| d.get("entries"))
                                .and_then(|m| m.as_array())
                            {
                                for entry in entries {
                                    let blob = entry
                                        .get("signed_blob")
                                        .and_then(|b| b.as_str())
                                        .unwrap_or_default()
                                        .to_string();
                                    let snid = entry
                                        .get("sender_nid")
                                        .and_then(|b| b.as_str())
                                        .unwrap_or_default()
                                        .to_string();
                                    let sfp = entry
                                        .get("sender_fp")
                                        .and_then(|b| b.as_str())
                                        .unwrap_or_default()
                                        .to_string();
                                    messages.push((blob, snid, sfp));
                                }
                            }
                            break;
                        }
                        Some(Ok(Message::Ping(data))) => {
                            let _ = ws.send(Message::Pong(data)).await;
                            continue;
                        }
                        Some(Ok(Message::Close(_))) | Some(Err(_)) => break,
                        None => break,
                        _ => continue,
                    }
                }
                Ok(messages)
            })
            .await;

            match timeout_result {
                Ok(Ok(msgs)) => (url, msgs),
                Ok(Err(e)) => {
                    tracing::warn!("Relay {} fetch error: {}", url, e);
                    (url.clone(), Vec::new())
                }
                Err(_) => {
                    tracing::warn!("Relay {} fetch timeout", url);
                    (url.clone(), Vec::new())
                }
            }
        }));
    }

    // Wait for all tasks
    let mut all_results: Vec<(String, String, String, String)> = Vec::new();
    for task in tasks {
        if let Ok((url, messages)) = task.await {
            for (blob, snid, sfp) in messages {
                all_results.push((url.clone(), blob, snid, sfp));
            }
        }
    }
    Ok(all_results)
}

/// TIER-1 cover traffic. Spawns a background task that performs constant-rate
/// decoy relay fetches for random blind tags. This (a) keeps the relay
/// connection cadence + payload sizes indistinguishable from real fetches and
/// (b) breaks the "you connected at T, a message was delivered at ~T"
/// correlation an ISP+relay could otherwise build together. Decoy fetches
/// return nothing (random tags), so they never touch a real mailbox.
fn start_cover_traffic(relay_urls: Vec<String>) {
    if relay_urls.is_empty() {
        return;
    }
    tokio::spawn(async move {
        // Poisson-ish: randomized 20-60s interval, constant background chatter.
        // (Use stateless `rand::random` — `ThreadRng` is !Send and can't cross
        // the tokio::spawn boundary.)
        loop {
            let delay = 20u64 + (rand::random::<u64>() % 40);
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;

            // Random 16-byte tag — looks identical on the wire to a real
            // recipient_tag fetch, but matches no mailbox.
            let buf: [u8; 16] = rand::random();
            let fake_nid = hex::encode(buf);

            // Prefer a relay that has the shared secret deployed so the cover
            // fetch is indistinguishable from a real blind-tag fetch.
            let url = relay_urls
                .iter()
                .find(|u| relay_routing_tag(&fake_nid).is_some())
                .or_else(|| relay_urls.first())
                .cloned()
                .unwrap();
            let ws_url = url
                .replace("http://", "ws://")
                .replace("https://", "wss://");

            // Extract the stream and drop the (non-Send) error so the future
            // stays Send across the await points below.
            let mut ws = match ws_connect(&ws_url).await {
                Ok(w) => w,
                Err(_) => continue,
            };
            let identity = match Identity::load() {
                Ok(id) => id,
                Err(_) => continue,
            };
            let timestamp = chrono::Utc::now().timestamp() as f64;
            let nonce = uuid_hex();
            let sig_data = format!("relay-fetch:{}:{}:{}", fake_nid, timestamp, nonce);
            let sig = match sign_for_transport(&sig_data) {
                Ok(s) => s,
                Err(_) => continue,
            };
            let req = serde_json::json!({
                "msg_type": "relay-fetch",
                "msg_id": uuid_hex(),
                "ts": timestamp,
                "sig": "",
                "payload": {
                    "recipient_nid": fake_nid,
                    "recipient_tag": relay_routing_tag(&fake_nid).unwrap_or_default(),
                    "requester_fp": identity.fingerprint,
                    "sender_sig": sig,
                    "sender_cert": "",
                    "timestamp": timestamp,
                    "nonce": nonce,
                    "auth_hmac": "",
                },
            });
            let _ = ws.send(Message::Text(req.to_string().into())).await;
            // Drain the (empty) response so the socket stays healthy.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                ws.next(),
            ).await;
        }
    });
}

/// Send a relay-purge request after successful fetch+decrypt.
/// This tells the relay to delete all messages for our null_id,
/// preventing stale data accumulation (squelch).
async fn relay_purge(relay_url: &str, null_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let ws_url = relay_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let mut ws = ws_connect(&ws_url)
        .await
        .map_err(|e| format!("Relay connect failed for purge: {}", e))?;

    let identity = Identity::load()?;
    let sender_verifying_key_b64 = if let Some(sk_b64) = identity.ml_dsa87_signing_key {
        let sk_bytes = base64::engine::general_purpose::STANDARD.decode(sk_b64)?;
        use ml_dsa::{KeyExport, KeyInit, Keypair};
        let sk = add_crypto_pq::MlDsa87SigningKey::new_from_slice(&sk_bytes)
            .map_err(|e| format!("ML-DSA-87 key reconstruction failed: {}", e))?;
        let vk = Keypair::verifying_key(&sk).clone();
        base64::engine::general_purpose::STANDARD.encode(vk.to_bytes())
    } else {
        String::new()
    };
    let nonce = uuid_hex();
    let timestamp = chrono::Utc::now().timestamp() as f64;
    let sig_data = format!("relay-purge:{}:{}:{}", null_id, timestamp, nonce);
    let sig = sign_for_transport(&sig_data)?;

    let req = serde_json::json!({
        "msg_type": "relay-purge",
        "msg_id": uuid_hex(),
        "ts": timestamp,
        "sig": "",
        "payload": {
            "recipient_nid": null_id,
            "requester_fp": identity.fingerprint,
            "requester_verifying_key": sender_verifying_key_b64,
            "sender_sig": sig,
            "timestamp": timestamp,
            "nonce": nonce,
            "auth_hmac": "", // Optional: populated when client has relay shared_secret
        },
    });
    ws.send(Message::Text(req.to_string().into()))
        .await
        .map_err(|e| format!("Relay purge send failed: {}", e))?;

    // Wait for the relay's purge acknowledgement and surface it verbatim so
    // silent rejections are never hidden.
    match ws.next().await {
        Some(Ok(Message::Text(resp))) => {
            let resp_val: serde_json::Value =
                serde_json::from_str(&resp).unwrap_or(serde_json::Value::Null);
            let accepted = resp_val
                .get("payload")
                .and_then(|p| p.get("accepted"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if accepted {
                println!("  Relay mailbox purged successfully.");
            } else {
                // Print the raw relay response so the user can see WHY (e.g.
                // "purge denied: ML-DSA-87 signature verification failed").
                println!("  Relay purge response: {}", resp.trim());
            }
        }
        Some(Ok(Message::Binary(b))) => {
            println!("  Relay purge response: <binary {} bytes>", b.len());
        }
        Some(Err(e)) => {
            println!("  Relay purge error: {}", e);
        }
        None => {
            println!("  Relay purge: no response (connection closed).");
        }
        _ => {
            println!("  Relay purge: unexpected response frame.");
        }
    }

    ws.close(None).await.ok();
    Ok(())
}

/// Send a read receipt to a relay for cross-relay sync.
async fn send_read_receipt_to_relay(
    relay_url: &str,
    receipt: &RelayReadReceipt,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws_url = relay_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let mut ws = ws_connect(&ws_url)
        .await
        .map_err(|e| format!("Relay connect failed for read receipt: {}", e))?;

    let req = serde_json::json!({
        "msg_type": "relay-read-receipt",
        "payload": receipt,
        "msg_id": uuid_hex(),
        "ts": chrono::Utc::now().timestamp() as f64,
    });

    ws.send(Message::Text(req.to_string().into()))
        .await
        .map_err(|e| format!("Relay read receipt send failed: {}", e))?;

    // Wait for OK response
    if let Some(Ok(Message::Text(resp))) = ws.next().await {
        let resp_val: serde_json::Value = serde_json::from_str(&resp)?;
        if resp_val.get("ok").and_then(|v| v.as_bool()) == Some(true) {
            tracing::debug!("Read receipt accepted by relay");
        } else if let Some(err) = resp_val.get("error").and_then(|e| e.as_str()) {
            return Err(format!("Relay read receipt error: {}", err).into());
        }
    }

    ws.close(None).await.ok();
    Ok(())
}

/// The relay stores the message without knowing the sender's identity.
/// The sender identity is encapsulated under the recipient's Kyber public key
/// so only the recipient can learn who sent it.
#[allow(clippy::too_many_arguments)]
async fn send_via_relay(
    identity: &Identity,
    recipient_nid: &str,
    recipient_fp: &str,
    message: &str,
    store: &MessageStore,
    relay_url: &str,
    ttl: Option<&str>,
    force_first: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws_url = relay_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let mut ws = ws_connect(&ws_url)
        .await
        .map_err(|e| format!("Relay connect failed: {}", e))?;

    // Load our Kyber keypair deterministically derived from null_id
    let _our_kyber = load_or_generate_kyber(&identity.null_id, store.db_key())?;
    let _our_kyber_enc_b64 = add_crypto::kyber::encode_enc_key(&_our_kyber.enc);

    // Look up recipient's REAL Kyber public key from their published cert
    // (SECURITY FIX F-2: no longer derived from null_id).
    let recipient_kyber = lookup_kyber_for_nid(recipient_fp, store).await?;

    // Create or load DoubleRatchet session with recipient
    let is_self = recipient_nid == identity.null_id;
    // When force_first is set (reflector bounce), always start a fresh
    // first-message so the recipient can bootstrap independently — no
    // shared ratchet state to desync across repeated bounces.
    let session_json = if force_first {
        None
    } else {
        store.load_session(recipient_nid).await?
    };
    let (mut ratchet_session, kyber_ct_hex_opt, shared_secret_opt) = if is_self {
        // Self-message: a single fixed-key shared session (no per-message
        // Kyber re-encapsulation). Reuse the persisted self-session if present;
        // otherwise create it once. All self messages use the first-message
        // envelope format (nonce || AES-CT, no Kyber appended), so the reader
        // can always decrypt with the same key.
        let session = if let Some(json) = session_json {
            add_crypto::DoubleRatchetSession::deserialize(&json)
                .map_err(|e| format!("ratchet load self: {}", e))?
        } else {
            // First self message: derive a shared secret via Kyber to
            // self-encapsulation (recipient == self public key).
            let (_ct, shared_secret) =
                add_crypto::kyber::KyberKeypair::encapsulate(&recipient_kyber)
                    .map_err(|e| format!("kyber encapsulate: {}", e))?;
            add_crypto::DoubleRatchetSession::new_self(
                recipient_fp,
                recipient_nid,
                &identity.fingerprint,
                &shared_secret,
            )
            .map_err(|e| format!("ratchet init self: {}", e))?
        };
        (session, None, None)
    } else if let Some(json) = session_json {
        // Existing session: no Kyber ciphertext needed
        (
            add_crypto::DoubleRatchetSession::deserialize(&json)
                .map_err(|e| format!("ratchet load: {}", e))?,
            None,
            None,
        )
    } else {
        // First message: perform KEM exchange
        let (ct, shared_secret) = add_crypto::kyber::KyberKeypair::encapsulate(&recipient_kyber)
            .map_err(|e| format!("kyber encapsulate: {}", e))?;
        let ct_hex = hex::encode(ct);
        let shared_secret_hex = hex::encode(shared_secret);
        let session = add_crypto::DoubleRatchetSession::new(
            recipient_fp,
            recipient_nid,
            &identity.fingerprint,
            true,
            &shared_secret,
        )
        .map_err(|e| format!("ratchet init: {}", e))?;
        // New session: include Kyber ciphertext in envelope
        (session, Some(ct_hex), Some(shared_secret_hex))
    };

    // SECURITY FIX (M1): Pad message to constant-size bucket
    let padded = pad_message_bucket(message);

    // SECURITY FIX (C1): Encrypt message using Double Ratchet + Kyber-768
    let ciphertext = if is_self {
        // Self-message: fixed-key shared session, first-message envelope format.
        ratchet_session
            .encrypt_first(&padded, &[], &[])
            .map_err(|e| format!("ratchet encrypt_first (self): {}", e))?
    } else if let (Some(ref kyber_ct_hex), Some(ref shared_secret_hex)) =
        (kyber_ct_hex_opt.clone(), shared_secret_opt.clone())
    {
        // First message: use the shared secret we already have
        ratchet_session
            .encrypt_first(
                &padded,
                &hex::decode(kyber_ct_hex).unwrap_or_default(),
                &hex::decode(shared_secret_hex).unwrap_or_default(),
            )
            .map_err(|e| format!("ratchet encrypt_first: {}", e))?
    } else {
        // Subsequent messages: generate new Kyber encapsulation per message
        ratchet_session
            .encrypt_message(&padded, &recipient_kyber)
            .map_err(|e| format!("ratchet encrypt: {}", e))?
    };

    // SECURITY FIX (M2 / TIER-0 sender): sealed sender. The relay never sees
    // the real sender identity — `sender_nid` is sent as "anonymous" and the
    // true {sender_nid, sender_fp} travel INSIDE the KEM-encrypted blob, so
    // only the recipient (who decapsulates) can recover them post-decrypt.
    let sealed_sender_token = String::new();
    let nonce: i64 = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let ts: f64 = chrono::Utc::now().timestamp() as f64;

    // Build the signed blob (WireEnvelope). The sender identity is embedded in
    // the encrypted payload so the relay stores only "anonymous".
    let envelope = if let Some(ref kyber_ct) = kyber_ct_hex_opt {
        // First message: include Kyber ciphertext for recipient to initialize session
        serde_json::json!({
            "type": "p2p-message",
            "seq": 1,
            "sender_nid": identity.null_id,
            "sender_fp": identity.fingerprint,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(&ciphertext),
            "msg_hash": sha256_hex(&ciphertext),
            "kyber_ciphertext": kyber_ct,
        })
    } else {
        // Subsequent messages: no Kyber ciphertext needed
        serde_json::json!({
            "type": "p2p-message",
            "seq": 1,
            "sender_nid": identity.null_id,
            "sender_fp": identity.fingerprint,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(&ciphertext),
            "msg_hash": sha256_hex(&ciphertext),
        })
    };
    let sig_data = format!(
        "{}|{}|{}|{}|{}|{}",
        recipient_nid, identity.null_id, identity.fingerprint, 1i64, ts, nonce
    );
    let sig = sign_for_transport(&sig_data)?;

    // SECURITY FIX (M2): Sender identity required for decryption.
    // Future: implement sealed sender decapsulation to hide identity.
    // Load ML-DSA-87 verifying key for TOFU verification at relay
    let identity = Identity::load()?;
    let sender_verifying_key_b64 = if let Some(sk_b64) = identity.ml_dsa87_signing_key {
        let sk_bytes = base64::engine::general_purpose::STANDARD.decode(sk_b64)?;
        use ml_dsa::{KeyInit, Keypair};
        let sk = add_crypto_pq::MlDsa87SigningKey::new_from_slice(&sk_bytes)
            .map_err(|e| format!("ML-DSA-87 key reconstruction failed: {}", e))?;
        let vk = Keypair::verifying_key(&sk).clone();
        use ml_dsa::KeyExport;
        let vk_bytes = vk.to_bytes();
        base64::engine::general_purpose::STANDARD.encode(vk_bytes)
    } else {
        String::new()
    };
    let req = serde_json::json!({
        "msg_type": "relay-store",
        "msg_id": uuid_hex(),
        "ts": ts,
        "payload": {
            "recipient_nid": recipient_nid,
            "recipient_tag": relay_routing_tag(recipient_nid).unwrap_or_default(),
            "signed_blob": serde_json::to_string(&envelope)?,
            // TIER-0 sealed sender: the relay only ever sees "anonymous";
            // the real sender identity lives inside the KEM-encrypted blob.
            "sender_nid": "anonymous".to_string(),
            "sender_fp": "anonymous".to_string(),
            "sender_verifying_key": sender_verifying_key_b64,
            "seq": 1,
            "timestamp": ts,
            "nonce": nonce.to_string(),
            "sender_sig": sig,
            "sealed_sender": sealed_sender_token,
            "ttl": ttl,
        },
    });
    let req_json = serde_json::to_string(&req)?;
    let _sb = req
        .get("payload")
        .and_then(|p| p.get("signed_blob"))
        .and_then(|s| s.as_str())
        .unwrap_or("");
    tracing::info!(
        "DBG send blob_has_kc={} sb_len={}",
        _sb.contains("kyber_ciphertext"),
        _sb.len()
    );
    ws.send(Message::Text(req_json.into()))
        .await
        .map_err(|e| format!("relay-store send failed: {}", e))?;
    tracing::info!(
        "relay-store sent, waiting for response... (relay={})",
        ws_url
    );

    // Wait for relay-ok response, skipping Ping/Pong heartbeats
    loop {
        match ws.next().await {
            Some(Ok(Message::Text(resp))) => {
                let resp_val: serde_json::Value = serde_json::from_str(&resp)?;
                tracing::info!(
                    "DBG store resp: {}",
                    resp.chars().take(200).collect::<String>()
                );
                if resp_val.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                    // Persist updated ratchet session
                    let session_json = ratchet_session
                        .serialize()
                        .map_err(|e| format!("ratchet serialize: {}", e))?;
                    store
                        .save_session(recipient_nid, &session_json)
                        .await
                        .map_err(|e| format!("ratchet save: {}", e))?;
                    println!(
                        "Message delivered via relay (sealed sender) to {}",
                        recipient_nid
                    );
                    return Ok(());
                }
                return Err(format!("relay error: {}", resp).into());
            }
            Some(Ok(Message::Ping(data))) => {
                // Respond to heartbeat pings
                let _ = ws.send(Message::Pong(data)).await;
                continue;
            }
            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Close(_))) => continue,
            Some(Err(e)) => return Err(format!("relay websocket error: {}", e).into()),
            None => return Err("no response from relay".into()),
            _ => continue,
        }
    }
}

/// SECURITY FIX (G10): Onion-routed message delivery.
/// Wraps the message in two layers of encryption: outer for the entry relay
/// and inner for the exit relay. The entry relay peels the outer layer
/// and forwards the inner ciphertext to the exit relay. The exit relay
/// stores it in the recipient's mailbox.
///
/// This provides traffic analysis resistance: the entry relay knows
/// the sender but not the recipient; the exit relay knows the recipient
/// Send a message via onion routing (2-hop).
///
/// Requires two relay URLs: entry_relay_url and exit_relay_url.
#[allow(dead_code)]
async fn send_via_onion(
    identity: &Identity,
    recipient_nid: &str,
    message: &str,
    entry_relay_url: &str,
    exit_relay_url: &str,
    store: &MessageStore,
) -> Result<(), Box<dyn std::error::Error>> {
    use add_crypto::DoubleRatchetSession;

    // Load our Kyber keypair deterministically derived from null_id
    let _our_kyber = load_or_generate_kyber(&identity.null_id, store.db_key())?;

    // Derive exit relay's Kyber key (TOFU)
    let exit_kyber = lookup_kyber_for_nid(exit_relay_url, store).await?;

    // Create or load DoubleRatchet session with exit relay
    let session_json = store.load_session("__onion_exit__").await?;
    let mut ratchet_session = if let Some(json) = session_json {
        DoubleRatchetSession::deserialize(&json).map_err(|e| format!("ratchet load: {}", e))?
    } else {
        // First onion message to exit relay: KEM exchange
        let (_ct, shared_secret) = add_crypto::kyber::KyberKeypair::encapsulate(&exit_kyber)
            .map_err(|e| format!("onion exit kyber encapsulate: {}", e))?;
        DoubleRatchetSession::new(
            &identity.fingerprint,
            "__onion_exit__",
            &identity.fingerprint,
            true,
            &shared_secret,
        )
        .map_err(|e| format!("onion ratchet init: {}", e))?
    };

    // Encrypt message for exit relay (inner layer)
    let inner_ciphertext = ratchet_session
        .encrypt_message(message, &exit_kyber)
        .map_err(|e| format!("onion inner encrypt: {}", e))?;

    // Build the inner relay-store payload for the exit relay
    let inner_payload = serde_json::json!({
        "type": "relay-store",
        "recipient_nid": recipient_nid,
        "signed_blob": inner_ciphertext,
        "sender_nid": "anonymous",
        "sender_fp": "",
        "sender_sig": "",
        "sender_cert": "",
        "sealed_sender": base64::engine::general_purpose::STANDARD.encode(identity.null_id.as_bytes()),
    });

    // Now encrypt the entire inner payload for the entry relay
    // (outer layer — entry peers sees only "onion-wrap" destined for exit_relay)
    let padded = pad_message_bucket(&inner_payload.to_string());

    // Derive entry relay's key
    let entry_kyber = lookup_kyber_for_nid(entry_relay_url, store).await?;

    let entry_session_json = store.load_session("__onion_entry__").await?;
    let mut entry_ratchet = if let Some(json) = entry_session_json {
        DoubleRatchetSession::deserialize(&json).map_err(|e| format!("ratchet load: {}", e))?
    } else {
        // First onion message to entry relay: KEM exchange
        let (_ct, shared_secret) = add_crypto::kyber::KyberKeypair::encapsulate(&entry_kyber)
            .map_err(|e| format!("onion entry kyber encapsulate: {}", e))?;
        DoubleRatchetSession::new(
            &identity.fingerprint,
            "__onion_entry__",
            &identity.fingerprint,
            true,
            &shared_secret,
        )
        .map_err(|e| format!("entry ratchet init: {}", e))?
    };

    let outer_ciphertext = entry_ratchet
        .encrypt_message(
            &base64::engine::general_purpose::STANDARD.encode(&padded),
            &entry_kyber,
        )
        .map_err(|e| format!("onion outer encrypt: {}", e))?;

    // Build the outer relay-store payload for entry relay
    let outer_payload = serde_json::json!({
        "type": "onion-v1",
        "exit_relay_url": exit_relay_url,
        "ciphertext": outer_ciphertext,
    });

    // Send to entry relay
    let ws_url = entry_relay_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");
    let mut ws = ws_connect(&ws_url)
        .await
        .map_err(|e| format!("onion entry relay connect failed: {}", e))?;

    ws.send(Message::Text(outer_payload.to_string().into()))
        .await
        .map_err(|e| format!("onion entry relay send failed: {}", e))?;

    // Wait for relay-ok
    if let Some(Ok(Message::Text(resp))) = ws.next().await {
        let resp_val: serde_json::Value = serde_json::from_str(&resp)?;
        if resp_val.get("type").and_then(|t| t.as_str()) == Some("relay-ok") {
            // Persist ratchet sessions
            let entry_json = entry_ratchet
                .serialize()
                .map_err(|e| format!("entry ratchet serialize: {}", e))?;
            store
                .save_session("__onion_entry__", &entry_json)
                .await
                .map_err(|e| format!("entry ratchet save: {}", e))?;

            let exit_json = ratchet_session
                .serialize()
                .map_err(|e| format!("exit ratchet serialize: {}", e))?;
            store
                .save_session("__onion_exit__", &exit_json)
                .await
                .map_err(|e| format!("exit ratchet save: {}", e))?;

            println!(
                "Message routed via onion (entry={} exit={})",
                entry_relay_url, exit_relay_url
            );
            return Ok(());
        }
        return Err(format!("onion entry relay error: {}", resp).into());
    }
    Err("no response from entry relay".into())
}

/// Look up a recipient's Kyber public key from DHT.
/// SECURITY FIX (M2): In production, this would fetch from DHT records.
/// For now, derive deterministically from nid hash (TOFU on first contact).
/// Resolve a peer's REAL ML-KEM-1024 public (encapsulation) key by fetching
/// their published cert from the DHT and decoding the `kyber_enc` field.
///
/// SECURITY FIX (F-1/F-2/F-3): previously this DERIVED the key deterministically
/// from the Null ID, which let anyone who knew the public cert recompute the
/// recipient's decapsulation key. Now the KEM keypair is random + published in
/// the cert; we look up the real public key here.
///
/// `id` is the peer's 64-hex ML-DSA fingerprint. (Relay/onion callers that pass
/// a URL instead hit the error branch — that path is unused dead code and the
/// relay's sealed-sender key is not published as a cert.)
async fn lookup_kyber_for_nid(
    id: &str,
    _store: &MessageStore,
) -> Result<add_crypto::kyber::KyberEncapsulationKey, Box<dyn std::error::Error>> {
    let is_fp = id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit());
    if !is_fp {
        return Err(format!(
            "lookup_kyber_for_nid: '{id}' is not a peer fingerprint; relay sealed-sender KEM lookup is not supported"
        )
        .into());
    }
    let (_seed_url, bootstraps, _relays) = discover_all_servers().await;
    let mut last_err: Option<Box<dyn std::error::Error>> = None;
    for seed in bootstraps.iter().chain(std::iter::once(&_seed_url)) {
        match dht_fetch_cert(seed, id).await {
            Ok((_armored, _vk_b64, kyber_enc_b64)) => {
                return add_crypto::kyber::decode_enc_key(&kyber_enc_b64)
                    .map_err(|e| format!("decode peer kyber enc key: {e}").into());
            }
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| "no bootstrap reachable to fetch peer cert".into()))
}

/// Decrypt a relay-fetched signed_blob using the persisted DoubleRatchet session.
/// The signed_blob is a serialized WireEnvelope of type p2p-message.
/// `sender_nid` and `sender_fp` come from the relay entry metadata.
async fn relay_decrypt_message(
    signed_blob: &str,
    sender_nid: &str,
    sender_fp: &str,
    our_fingerprint: &str,
    store: &MessageStore,
    our_kyber: &add_crypto::kyber::KyberKeypair,
) -> Result<String, Box<dyn std::error::Error>> {
    // Parse signed_blob as a p2p-message envelope (generic JSON, not WireEnvelope)
    let env: serde_json::Value =
        serde_json::from_str(signed_blob).map_err(|e| format!("parse signed_blob: {}", e))?;

    // TIER-0 sealed sender: prefer the sender identity that was embedded
    // INSIDE the KEM-encrypted blob (so the relay never held it in plaintext).
    // Fall back to the relay-provided (or P2P-provided) args for backward
    // compatibility with messages stored before sealed sender was enabled.
    let blob_sender_nid = env.get("sender_nid").and_then(|v| v.as_str()).unwrap_or("");
    let blob_sender_fp = env.get("sender_fp").and_then(|v| v.as_str()).unwrap_or("");

    let (nid, _fp) = if !blob_sender_nid.is_empty() && !blob_sender_fp.is_empty() {
        (blob_sender_nid.to_string(), blob_sender_fp.to_string())
    } else if !sender_nid.is_empty() && sender_nid != "anonymous" {
        (sender_nid.to_string(), sender_fp.to_string())
    } else if !sender_fp.is_empty() && sender_fp != "anonymous" {
        (add_crypto::null_id(sender_fp), sender_fp.to_string())
    } else {
        return Err("relay message has no recoverable sender identification".into());
    };

    if nid.is_empty() {
        return Err("relay message has no sender identification".into());
    }

    // Extract ciphertext from the message envelope
    let ciphertext = env
        .get("ciphertext")
        .and_then(|c| c.as_str())
        .ok_or("no ciphertext in relay message")?;

    // SECURITY FIX (M1): message sequence number drives skipped-key handling.
    let seq = env.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);

    // Check if this is a first-message (contains kyber_ciphertext for session init)
    let kyber_ct_hex = env.get("kyber_ciphertext").and_then(|c| c.as_str());

    // Load any existing session (used for subsequent messages / self-messages).
    let session_json = store.load_session(&nid).await?;

    let is_self = nid == add_crypto::null_id(our_fingerprint);

    let (mut session, _is_new_session) = if is_self {
        // Self-message: ALWAYS reuse the persisted single-shared-chain session
        // created at send time (so send/recv chain counters stay in sync).
        // A fresh re-derivation from the enclosed Kyber would start a brand-new
        // chain and never match the encrypt side.
        if let Some(json) = session_json {
            (
                add_crypto::DoubleRatchetSession::deserialize(&json)
                    .map_err(|e| format!("ratchet deserialize: {}", e))?,
                false,
            )
        } else {
            return Err(format!("no self session for {} (send to yourself first)", nid).into());
        }
    } else if let Some(kyber_ct) = kyber_ct_hex {
        // First message from a peer: derive the recipient session from the
        // enclosed Kyber CT (authoritative shared secret). We ignore any stored
        // session because it would be the *outgoing* direction with a different
        // chain, and would fail to decrypt.
        let kyber_ct_bytes =
            hex::decode(kyber_ct).map_err(|e| format!("kyber_ct hex decode: {}", e))?;
        let kyber_ct = add_crypto::kyber::MlKem1024Ciphertext::try_from(&kyber_ct_bytes[..])
            .map_err(|e| format!("kyber_ct parse: {:?}", e))?;
        let shared_secret = our_kyber
            .decapsulate(&kyber_ct)
            .map_err(|e| format!("kyber decapsulate: {}", e))?;
        let session = add_crypto::DoubleRatchetSession::new(
            sender_fp,
            &nid,
            our_fingerprint,
            false, // We are the recipient of this first message
            &shared_secret,
        )
        .map_err(|e| format!("ratchet init: {}", e))?;
        (session, true)
    } else if let Some(json) = session_json {
        // Subsequent message from a peer: use the persisted session (advanced by
        // prior decrypts); the inline Kyber CT in the blob is handled by decrypt_message.
        (
            add_crypto::DoubleRatchetSession::deserialize(&json)
                .map_err(|e| format!("ratchet deserialize: {}", e))?,
            false,
        )
    } else {
        return Err(format!(
            "no ratchet session for sender {} (need first message with kyber_ciphertext)",
            nid
        )
        .into());
    };

    let padded_plaintext = if kyber_ct_hex.is_some() {
        // First message: blob is nonce || AES-CT (no Kyber appended).
        session
            .decrypt_first(ciphertext, our_kyber)
            .map_err(|e| format!("ratchet decrypt: {}", e))?
    } else {
        session
            .decrypt_message(ciphertext, our_kyber, seq)
            .map_err(|e| format!("ratchet decrypt: {}", e))?
    };

    // SECURITY FIX (M1): Strip message padding
    let plaintext = unpad_message_bucket(&padded_plaintext)?;

    // Update the persisted session (seq numbers advanced)
    let updated_json = session
        .serialize()
        .map_err(|e| format!("ratchet re-serialize: {}", e))?;
    store
        .save_session(&nid, &updated_json)
        .await
        .map_err(|e| format!("ratchet re-save: {}", e))?;

    Ok(plaintext)
}

// ------------------------------------------------------------------ //
//  P2P Send (G1)                                                     //
// ------------------------------------------------------------------ //

/// Send a message to a recipient via DHT lookup + direct P2P delivery.
/// SECURITY FIX (C1): Uses Kyber-768 KEM + Double Ratchet for post-quantum encryption.
/// SECURITY FIX (L1): When `use_pir` is true, uses PIR for privacy-enhanced DHT lookup.
#[allow(clippy::too_many_arguments)]
async fn send_message(
    identity: &Identity,
    recipient_nid: &str,
    message: &str,
    store: &MessageStore,
    _use_pir: bool,
    _seed_url: &str,
    relay_url: &str,
    ttl: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Mutual-consent gate (DESIGN.md §6): the recipient must be in the local
    // contact list, EXCEPT for well-known public services (reflector), which are
    // reachable by anyone without a contact entry. Public services are still
    // pinned to their published cert below — the gate is relaxed, not the trust.
    let recipient_fp: String = if is_public_service(recipient_nid) {
        REFLECTOR_FINGERPRINT.to_string()
    } else {
        let contacts = load_contacts();
        contacts
            .get(recipient_nid)
            .cloned()
            .ok_or("unknown contact — add with 'add-contact' first")?
    };
    // Borrow as &str for the rest of the function (downstream fns take &str).
    let recipient_fp = recipient_fp.as_str();

    println!("Looking up {} ...", recipient_nid);

    // Resolve the recipient's listener address.
    // - Normal contact: per-contact encrypted V2.2 presence blob (only a mutual
    //   contact can decrypt it; the server learns nothing).
    // - Public service: its address rides inside the public cert-store bundle
    //   (opaque to the server, readable by anyone who knows the well-known key).
    // Either way the server stores only ciphertext; no plaintext IP↔ID.
    let recipient_addr = if is_public_service(recipient_nid) {
        fetch_public_service_addr(recipient_nid).await
    } else {
        presence::fetch_presence(identity, recipient_fp).await
    };

    // Resolve the recipient's listener address. If DHT lookup failed, fall
    // back to relay delivery below.
    let ws_url = if let Some(ref addr) = recipient_addr {
        println!("Found at: {}", addr);
        addr.replace("http://", "ws://")
            .replace("https://", "wss://")
    } else {
        // Public services are reached only via the cert store (P2P), never the
        // relay — the reflector is stateless and never reads relay mail. A
        // missing bundle means it's unpublished/offline; say so instead of
        // fake-delivering to a relay it will never collect from.
        if is_public_service(recipient_nid) {
            return Err(format!(
                "{} is a public service but its address is not in the cert store \
                 (it may be offline or unpublished). Cannot deliver.",
                recipient_nid
            )
            .into());
        }
        println!("DHT lookup failed — using relay delivery...");
        relay_url
            .replace("http://", "ws://")
            .replace("https://", "wss://")
            .to_string()
    };

    // If DHT lookup failed, skip P2P and go straight to relay delivery
    if recipient_addr.is_none() {
        return send_via_relay(
            identity,
            recipient_nid,
            recipient_fp,
            message,
            store,
            relay_url,
            ttl,
            true,
        )
        .await;
    }

    println!("Establishing P2P connection...");

    // G1: Try direct P2P connection, fall back to relay delivery.
    // Wrap the connect in a timeout so an unreachable peer (offline / NAT
    // with no hole punch) fails fast and we fall back to relay instead of
    // hanging on a dead TCP endpoint (per architecture: relay is the fallback
    // when the peer is not directly reachable).
    //
    // Candidate order is LOCAL-FIRST: loopback, then our LAN IP, then the
    // presence (public) address. When sender and receiver share a host, the
    // loopback/LAN connect succeeds instantly without needing NAT hairpinning;
    // for remote peers the public address is what ultimately works. The
    // handshake authenticates the peer, so a local candidate can never
    // deliver to the wrong party — a refused/wrong peer just fails fast.
    //
    // Each candidate gets its OWN short timeout. Without this, a hung connect
    // to the public IP would consume the entire budget and the loopback
    // attempt (which would have succeeded) would never be reached.
    let port = ws_url
        .rsplit(':')
        .next()
        .and_then(|p| p.parse::<u16>().ok());
    let mut candidates: Vec<String> = Vec::new();
    if let Some(p) = port {
        // Local-first: loopback and LAN connect instantly on a co-located peer.
        candidates.push(format!("ws://127.0.0.1:{}", p));
        if let Some(lan) = primary_ipv4() {
            candidates.push(format!("ws://{}:{}", lan, p));
        }
    }
    candidates.push(ws_url.clone()); // presence / public address last
    // Deduplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|c| seen.insert(c.clone()));

    const CANDIDATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
    const P2P_TOTAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(8);

    let connect_result: Result<(tokio_tungstenite::WebSocketStream<_>, _), String> =
        tokio::time::timeout(P2P_TOTAL_TIMEOUT, async {
            let mut last_err = String::from("no candidate addresses");
            for cand in &candidates {
                match tokio::time::timeout(CANDIDATE_TIMEOUT, tokio_tungstenite::connect_async(cand))
                    .await
                {
                    Ok(Ok(result)) => return Ok(result),
                    Ok(Err(e)) => {
                        last_err = format!("{}", e);
                        continue;
                    }
                    Err(_) => {
                        // This candidate hung (e.g. public IP with no hairpin) —
                        // move on to the next without burning the whole budget.
                        last_err = format!("{} timed out", cand);
                        continue;
                    }
                }
            }
            Err(last_err)
        })
        .await
        .unwrap_or_else(|_| Err(String::from("timed out")));

    let (mut ws, _) = match connect_result {
        Ok(result) => result,
        Err(e) => {
            // If presence lookup failed entirely and this is a public service
            // (which never reads relay mail), say so instead of fake-delivering
            // to a relay it will never collect from.
            if recipient_addr.is_none() && is_public_service(recipient_nid) {
                return Err(format!(
                    "{} is a public service but its address is not in the cert store \
                     (it may be offline or unpublished). Cannot deliver.",
                    recipient_nid
                )
                .into());
            }
            println!("Direct P2P failed ({}), using relay delivery...", e);
            return send_via_relay(
                identity,
                recipient_nid,
                recipient_fp,
                message,
                store,
                relay_url,
                ttl,
                true,
            )
            .await;
        }
    };

    // SECURITY FIX (C1): Load our Kyber keypair deterministically derived from null_id
    let our_kyber = load_or_generate_kyber(&identity.null_id, store.db_key())?;
    let our_kyber_enc_b64 = add_crypto::kyber::encode_enc_key(&our_kyber.enc);

    // SECURITY FIX (C1): Perform handshake with Kyber key included
    let _my_vk_b64 = my_verifying_key_b64()?;

    // SECURITY FIX (C2): Sign the P2P hello with our ML-DSA-87 key
    let my_vk_b64 = my_verifying_key_b64()?;
    let mut hello = add_p2p::protocol::build_p2p_hello_signed(
        identity.fingerprint.as_str(),
        1,
        16,
        &our_kyber_enc_b64,
        "",
        "",
        &my_vk_b64,
    );
    // Sign over the SAME payload object (including sender_verifying_key) the
    // peer will verify — not a hand-built object that diverges from it.
    let hello_sig_data = format!("p2p-hello:{}\n", hello.payload);
    hello.sig = sign_for_transport(&hello_sig_data)?;
    ws.send(Message::Text(serde_json::to_string(&hello)?.into()))
        .await
        .map_err(|e| format!("P2P hello failed: {}", e))?;

    // Wait for hello-ack, verify signature, and extract peer's Kyber public key
    let mut peer_kyber_enc: Option<add_crypto::kyber::KyberEncapsulationKey> = None;
    if let Some(Ok(Message::Text(resp))) = ws.next().await {
        let ack: serde_json::Value = serde_json::from_str(&resp)?;
        // The reflector (and peers) send `msg_type` (WireEnvelope field);
        // be tolerant of a bare `type` key too, for compatibility.
        let ack_type = ack
            .get("msg_type")
            .or_else(|| ack.get("type"))
            .and_then(|t| t.as_str());
        if ack_type != Some("p2p-hello-ack") {
            return Err(format!("Unexpected response: {}", resp).into());
        }

        // SECURITY FIX (C3): Verify the hello-ack GPG signature from responder.
        // Without this, an active MITM could inject a fake hello-ack with their
        // own Kyber key, decrypting all subsequent messages.
        let ack_sig = ack.get("sig").and_then(|s| s.as_str()).unwrap_or("");
        if ack_sig.is_empty() {
            return Err("p2p-hello-ack has no signature — rejecting (MITM risk)".into());
        }
        let ack_payload = ack
            .get("payload")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let ack_fp = ack_payload
            .get("public_key")
            .and_then(|k| k.as_str())
            .unwrap_or("unknown");
        // Cache the peer's verifying key from the ack payload (sender embeds it)
        if add_dht_core::crypto_helpers::get_cached_verifying_key(ack_fp).is_none()
            && let Some(vk_b64) = ack_payload
                .get("sender_verifying_key")
                .and_then(|v| v.as_str())
            && let Ok(vk_bytes) = base64::engine::general_purpose::STANDARD.decode(vk_b64)
            && let Ok(vk) = add_crypto_pq::decode_verifying_key(&vk_bytes)
        {
            // SECURITY FIX (C3): pin the fingerprint→VK binding (hard-fail on
            // conflict) instead of silently overwriting via cache_verifying_key.
            if let Err(e) = add_dht_core::crypto_helpers::pin_verifying_key(ack_fp, &vk) {
                return Err(format!(
                    "p2p-hello-ack identity binding conflict for {}: {}",
                    ack_fp, e
                )
                .into());
            }
        }
        if ack_sig.is_empty() {
            return Err("p2p-hello-ack has no signature — rejecting (MITM risk)".into());
        } else {
            let ack_sig_data = format!("p2p-hello-ack:{}\n", ack_payload);
            if !add_dht_core::verify_signature(&ack_sig_data, ack_sig, ack_fp) {
                return Err(format!(
                    "p2p-hello-ack signature verification failed for {} — possible MITM",
                    ack_fp
                )
                .into());
            }
        }

        // SECURITY FIX (C1): Extract peer's Kyber public key for KEM exchange.
        // SPQR Braid: if the peer advertised braid capability, stream our EK as
        // braid chunks and reassemble the peer's EK from its chunks; otherwise
        // fall back to the inline kyber_enc_key (keeps old/relay peers working).
        let peer_braid = ack_payload
            .get("braid")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        // Authenticated inline Kyber public key from the ML-DSA-87-signed
        // hello-ack payload (signature verified above at C3). Used directly when
        // braid is NOT negotiated; used as the authentication binding when braid
        // IS negotiated.
        let inline_ek_b64 = ack_payload
            .get("kyber_enc_key")
            .and_then(|k| k.as_str())
            .unwrap_or("")
            .to_string();
        if peer_braid {
            let our_ek_b64 = add_crypto::kyber::encode_enc_key(&our_kyber.enc);
            let our_ek_bytes = base64::engine::general_purpose::STANDARD
                .decode(&our_ek_b64)
                .map_err(|e| format!("ek decode: {}", e))?;
            let peer_ek_bytes = add_p2p::braid_handshake::exchange_ek_braid(&mut ws, &our_ek_bytes)
                .await
                .map_err(|e| format!("braid EK exchange: {}", e))?;
            // SECURITY (C1): bind the reassembled EK to the authenticated inline
            // `kyber_enc_key` from the ML-DSA-87-signed hello-ack. The braid
            // stream is only integrity-protected, so without this binding an
            // active MITM could substitute their own EK during the stream.
            let inline_ek = base64::engine::general_purpose::STANDARD
                .decode(&inline_ek_b64)
                .map_err(|e| format!("inline kyber_enc_key decode: {}", e))?;
            let peer_ek_bytes =
                add_p2p::braid_handshake::verify_peer_ek_from_bytes(&peer_ek_bytes, &inline_ek)
                    .map_err(|e| {
                        format!("[braid] peer EK failed authentication ({}), aborting", e)
                    })?;
            let peer_ek_b64 = base64::engine::general_purpose::STANDARD.encode(&peer_ek_bytes);
            peer_kyber_enc = add_crypto::kyber::decode_enc_key(&peer_ek_b64).ok();
        } else if !inline_ek_b64.is_empty() {
            // Non-braid path: the inline kyber_enc_key is a field of the
            // ML-DSA-87-signed hello-ack payload, so it is authenticated by the
            // verified responder identity (C3). This is NOT a plaintext fallback
            // — it is the legitimate, signed key. Reject (fail-closed) if the key
            // is absent or undecodable.
            peer_kyber_enc = add_crypto::kyber::decode_enc_key(&inline_ek_b64).ok();
        }
        if peer_kyber_enc.is_none() {
            return Err(
                "No authenticated Kyber public key from peer, aborting (fail-closed)".into(),
            );
        }
    } else {
        return Err("No hello-ack received".into());
    }

    // SECURITY FIX (C1): Perform Kyber KEM exchange and create Double Ratchet session.
    // The initiator encapsulates to the peer and SHIPS the ciphertext so the
    // responder can decapsulate the SAME shared secret (symmetric ratchet seed).
    let peer_kyber = peer_kyber_enc.as_ref().ok_or("no peer Kyber key")?;
    let (init_ct, init_shared_secret) = add_crypto::kyber::KyberKeypair::encapsulate(peer_kyber)
        .map_err(|e| format!("kyber encapsulate: {}", e))?;
    let init_ct_b64 =
        base64::engine::general_purpose::STANDARD.encode(AsRef::<[u8]>::as_ref(&init_ct));

    let peer_nid = add_crypto::null_id(recipient_fp);
    let mut ratchet_session = add_crypto::DoubleRatchetSession::new(
        recipient_fp,
        &peer_nid,
        &identity.fingerprint,
        true, // is_initiator
        &init_shared_secret,
    )
    .map_err(|e| format!("ratchet init: {}", e))?;
    // SECURITY FIX (G9): Persist the ratchet session for this peer so
    // future relay-fetched messages (or re-connections) can decrypt.
    let session_json = ratchet_session
        .serialize()
        .map_err(|e| format!("ratchet serialize: {}", e))?;
    store
        .save_session(&peer_nid, &session_json)
        .await
        .map_err(|e| format!("ratchet save: {}", e))?;

    // SECURITY FIX (C1): Encrypt message using Double Ratchet + Kyber-768
    // SECURITY FIX (M1): Pad message to constant-size bucket before encryption
    // to prevent traffic analysis by message size
    let padded_message = pad_message_bucket(message);
    let encrypted_msg = ratchet_session.encrypt_message(&padded_message, peer_kyber)?;
    let encrypted_msg_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted_msg);
    let msg_hash = sha256_hex(&encrypted_msg);

    // SECURITY FIX (C2): Sign the P2P message payload
    let msg_sig_data = format!(
        "p2p-message:{}",
        serde_json::json!({
            "seq": 1,
            "ciphertext": &encrypted_msg_b64,
            "msg_hash": &msg_hash,
        })
    );
    let msg_sig = sign_for_transport(&msg_sig_data)?;

    // Send encrypted message (signed) with TTL
    let p2p_msg = add_p2p::protocol::build_p2p_message_signed(
        1,
        &encrypted_msg_b64,
        &msg_hash,
        &msg_sig,
        Some(&init_ct_b64),
        ttl,
    );

    // ACS2.6 Part I.2: Attach delivery token for sealed sender
    let delivery_token = generate_delivery_token(recipient_nid, 1)?;
    let token_msg = serde_json::to_string(&delivery_token)?;
    ws.send(Message::Text(token_msg.into())).await.ok();
    ws.send(Message::Text(serde_json::to_string(&p2p_msg)?.into()))
        .await
        .map_err(|e| format!("P2P send failed: {}", e))?;
    // Wait for ack (and optionally, p2p-receipt)
    let mut ack_received = false;
    let mut receipt_received = false;

    loop {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(10), ws.next()).await;

        match msg {
            Ok(Some(Ok(Message::Text(resp)))) => {
                let msg_val: serde_json::Value = serde_json::from_str(&resp)?;
                let msg_type = msg_val
                    .get("msg_type")
                    .or_else(|| msg_val.get("type"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");

                if msg_type == "p2p-ack" {
                    ack_received = true;
                    println!("Message delivered successfully!");
                } else if msg_type == "p2p-receipt" {
                    // ACS2.6: E2E delivery receipt — recipient has decrypted the message.
                    // Reflector sends receipt with top-level fields (not under payload)
                    let receipt_msg_hash = msg_val
                        .get("payload")
                        .and_then(|p| p.get("msg_hash"))
                        .and_then(|h| h.as_str())
                        .or_else(|| msg_val.get("msg_hash").and_then(|h| h.as_str()))
                        .unwrap_or("");
                    let received_at = msg_val
                        .get("payload")
                        .and_then(|p| p.get("received_at"))
                        .and_then(|t| t.as_f64())
                        .or_else(|| msg_val.get("received_at").and_then(|t| t.as_f64()))
                        .unwrap_or(0.0);

                    // Verify receipt signature (authenticity)
                    let receipt_sig = msg_val.get("sig").and_then(|s| s.as_str()).unwrap_or("");
                    if verify_receipt_signature(
                        receipt_msg_hash,
                        received_at,
                        receipt_sig,
                        recipient_fp,
                    ) {
                        // SECURITY FIX (M8): Verify hash matches our sent message to prevent
                        // forged receipts for different messages. The hash must match exactly.
                        if receipt_msg_hash == msg_hash {
                            let when = chrono::DateTime::from_timestamp(received_at as i64, 0)
                                .map(|dt| dt.format("%H:%M:%S").to_string())
                                .unwrap_or_else(|| format!("{:.0}", received_at));
                            println!("Message READ by peer at {} [E2E confirmed]", when);
                        } else {
                            println!(
                                "Warning: p2p-receipt hash mismatch (possible forged receipt)"
                            );
                            println!(
                                "  Sent: {}..., Received: {}...",
                                &msg_hash[..16],
                                &receipt_msg_hash[..16]
                            );
                        }
                    } else {
                        println!("Warning: p2p-receipt signature verification failed");
                    }
                    receipt_received = true;
                }

                if msg_type == "p2p-message" {
                    // Echoed message (e.g. reflector loopback). The reflector is a
                    // P2P-only echo bot: it bounced our *encrypted* frame straight
                    // back. It never decapsulates, so the returned `ciphertext` is
                    // opaque to us. In a loopback the sender already holds the
                    // plaintext, so display that instead of dumping base64 garbage.
                    // Reflector may send at top-level or under payload (WireEnvelope format)
                    let raw_ct = msg_val
                        .get("payload")
                        .and_then(|p| p.get("ciphertext"))
                        .and_then(|c| c.as_str())
                        .or_else(|| msg_val.get("ciphertext").and_then(|c| c.as_str()))
                        .unwrap_or("");
                    // Strip a cosmetic prefix the reflector may prepend (e.g. "/"
                    // or "🤖 [Reflector Echo]: ").
                    let stripped = raw_ct.rsplit_once(": ").map(|(_, b)| b).unwrap_or(raw_ct);
                    // If the returned body equals what we sent, or is just the
                    // opaque ciphertext (doesn't match our plaintext), show the
                    // plaintext we already have — that's the real loopback content.
                    let text = if stripped.is_empty() || stripped != message {
                        message.to_string()
                    } else {
                        stripped.to_string()
                    };
                    println!("Echo: {}", text);
                }

                if ack_received && receipt_received {
                    break;
                }
                if ack_received && !receipt_received {
                    // Don't break after ack alone — wait for receipt or timeout
                    continue;
                }
            }
            Ok(Some(Ok(_))) => {} // binary or other frame type
            Ok(None) => break,    // connection closed
            Err(_) => break,      // timeout
            Ok(Some(Err(e))) => {
                println!("Warning: websocket error: {}", e);
                break;
            }
        }
    }

    // G5: Store sent message locally (only ciphertext, no plaintext)
    // Status 0 = sent (🔘)
    let message_id = sha256_hex(encrypted_msg_b64.as_bytes());
    let _ = store
        .store_message(
            &identity.null_id,
            recipient_nid,
            &encrypted_msg_b64,
            0, // Sent
            &message_id,
        )
        .await;

    ws.close(None).await.ok();
    Ok(())
}

// ------------------------------------------------------------------ //
//  P2P Listener (G3)                                                 //
// ------------------------------------------------------------------ //

/// Best-effort discovery of the machine's primary outbound IPv4 address.
/// Used to advertise a peer-reachable P2P address instead of 0.0.0.0
/// (which is a valid bind address but not a valid connect target).
fn primary_ipv4() -> Option<std::net::Ipv4Addr> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    match sock.local_addr().ok()? {
        std::net::SocketAddr::V4(a) => {
            let ip = a.ip();
            if ip.is_unspecified() || ip.is_loopback() {
                None
            } else {
                Some(*ip)
            }
        }
        _ => None,
    }
}

/// Build the raw LAN advertise address (ws://LAN_IP:PORT). LAN-only; not
/// reachable from the internet, but used as the final fallback when NAT
/// traversal is disabled or unavailable.
fn lan_address(local_addr: std::net::SocketAddr) -> String {
    let advertise_ip = if local_addr.ip().is_unspecified() {
        primary_ipv4()
            .map(std::net::IpAddr::V4)
            .unwrap_or(local_addr.ip())
    } else {
        local_addr.ip()
    };
    format!("ws://{}:{}", advertise_ip, local_addr.port())
}

/// Extract the host portion of a `ws://host:port` (or bare `host:port`) address.
/// Used to detect a *real* address change (public IP) while ignoring the
/// ephemeral port churn that symmetric NATs produce on every STUN probe.
fn addr_host(addr: &str) -> String {
    let s = addr
        .strip_prefix("ws://")
        .or_else(|| addr.strip_prefix("wss://"))
        .unwrap_or(addr);
    // Strip any path, then split host:port on the last ':' (IPv6-safe enough
    // for our ws://ip:port form; bracketed IPv6 keeps its brackets as host).
    let hostport = s.split('/').next().unwrap_or(s);
    match hostport.rsplit_once(':') {
        Some((host, _port)) => host.to_string(),
        None => hostport.to_string(),
    }
}

/// Attempt NAT traversal so a remote peer can reach our LAN listener:
///   1. UPnP/IGD — ask the router to port-map external:internal (TCP),
///      then advertise the router's public IP:external_port.
///   2. STUN — learn the NAT's public IP:port and advertise that.
///
/// Returns Some(ws://PUBLIC_IP:PORT) on success, None if both fail.
async fn traverse_nat(bind_ip: std::net::IpAddr, bind_port: u16) -> Option<String> {
    // Only attempt UPnP when bound to an unspecified/all-interfaces address and we
    // have a usable LAN IP to map to.
    if bind_ip.is_unspecified()
        && let Some(lan) = primary_ipv4()
    {
        match add_p2p::upnp::Igd::discover(lan).await {
            Ok(igd) => match igd.add_tcp_mapping(bind_port, 0).await {
                Ok(ext_port) => match igd.external_ip().await {
                    Ok(pub_ip) => {
                        println!(
                            "NAT traversal: UPnP mapped {}:{} -> {}:{}",
                            pub_ip, ext_port, lan, bind_port
                        );
                        // UPnP's ext_port IS the inbound-mapped port → correct.
                        return Some(format!("ws://{}:{}", pub_ip, ext_port));
                    }
                    Err(e) => tracing::warn!("UPnP external-IP query failed: {e}"),
                },
                Err(e) => tracing::warn!("UPnP AddPortMapping failed: {e}"),
            },
            Err(e) => tracing::warn!("UPnP IGD discovery failed: {e}"),
        }
    }

    // Fallback: STUN. For a cone NAT (the common case) the binding the NAT
    // created for the *outbound probe socket* is the very endpoint that inbound
    // traffic is forwarded to — and it forwards to whatever internal socket sent
    // the probe (our listener). So we MUST advertise the STUN-discovered
    // `public_port`, not our LAN bind port; otherwise inbound connects hit a
    // port nothing is listening on publicly and P2P times out. (On a symmetric
    // NAT the mapping is per-destination and won't accept the peer's inbound
    // packet regardless — there P2P is expected to fail and relay covers it.)
    let nat = add_p2p::nat::NatManager::new();
    match nat.discover_public_address().await {
        Ok(res) => {
            println!(
                "NAT traversal: STUN discovered public {}{} (advertising this endpoint; listener bound on {})",
                res.public_ip, res.public_port, bind_port
            );
            Some(format!("ws://{}:{}", res.public_ip, res.public_port))
        }
        Err(e) => {
            tracing::warn!("STUN discovery failed: {e}");
            None
        }
    }
}

/// Start a WebSocket listener for incoming P2P connections.
/// Also registers the listener's address in the DHT as an addr_record
/// so other clients can discover this listener for direct P2P connections.
async fn run_listener(
    identity: Identity,
    store: MessageStore,
    _cert: sequoia_openpgp::Cert, // Our GPG cert for signing
    advertised_url: Option<String>,
    no_nat: bool,
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = std::net::SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        listen_port,
    );
    let listener = TcpListener::bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;
    // Advertised address, in priority order:
    //   1. explicit --advertised-url (reverse-proxy / relay-fronted wss://)
    //   2. automatic NAT traversal: UPnP/IGD port map first, then STUN discovery
    //   3. raw LAN bind address (LAN-only; unreachable from the internet)
    // 0.0.0.0 is never advertised — it is not a valid connect target.
    let listen_address = if let Some(url) = &advertised_url {
        url.clone()
    } else if !no_nat {
        match traverse_nat(local_addr.ip(), local_addr.port()).await {
            Some(addr) => addr,
            None => lan_address(local_addr),
        }
    } else {
        lan_address(local_addr)
    };

    println!("P2P listener on ws://{}", local_addr);
    println!("Your address for incoming connections: {}", listen_address);
    println!("Registering address in DHT for direct P2P discovery...");

    // Publish per-contact encrypted presence (V2.2) so mutual contacts can
    // discover our listener address without the server learning it.
    if let Err(e) = presence::publish_presence(&identity, &listen_address).await {
        tracing::warn!("Failed to publish presence: {}", e);
        println!(
            "Warning: Could not publish presence. Direct P2P may not work: {}",
            e
        );
    } else {
        println!("Presence published for direct P2P discovery.");
    }

    // Start background task to periodically refresh the address record (every 30 min).
    // If a fixed --advertised-url was given, keep re-registering that exact URL.
    // Otherwise re-detect the primary outbound IP (no socket rebind, stable port)
    // and only re-register if the advertised address actually changed.
    let identity_clone = identity.clone();
    let listen_port = local_addr.port();
    let advertised_url_clone = advertised_url.clone();
    let initial_address = listen_address.clone();
    let bind_ip = local_addr.ip();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30 * 60)); // 30 minutes
        // interval fires its first tick immediately; consume it so we don't
        // re-register seconds after the initial registration above.
        interval.tick().await;
        let mut last_registered_address = initial_address;
        loop {
            interval.tick().await;
            // Fixed URL mode: keep the same advertised address (no re-detection).
            // Auto mode: re-detect IP only; keep the listener's real port (no rebind -> no flap).
            let current_addr = match &advertised_url_clone {
                Some(u) => u.clone(),
                None => {
                    if no_nat {
                        lan_address(std::net::SocketAddr::new(bind_ip, listen_port))
                    } else {
                        match traverse_nat(bind_ip, listen_port).await {
                            Some(a) => a,
                            None => lan_address(std::net::SocketAddr::new(bind_ip, listen_port)),
                        }
                    }
                }
            };

            // Re-register only when the public HOST changes. Under symmetric NAT
            // STUN hands back a fresh ephemeral port on every probe; that port is
            // useless for inbound anyway, so treating a port-only delta as a
            // "change" just burns PoW. Compare host (IP) only.
            let host_changed = addr_host(&current_addr) != addr_host(&last_registered_address);
            if host_changed {
                tracing::info!(
                    "Address changed from {} to {}, re-registering...",
                    last_registered_address,
                    current_addr
                );
                if let Err(e) = presence::publish_presence(&identity_clone, &current_addr).await {
                    tracing::warn!("Failed to re-publish presence after IP change: {}", e);
                } else {
                    tracing::info!("Presence re-published after IP change: {}", current_addr);
                    last_registered_address = current_addr;
                }
            } else {
                // Host unchanged: refresh presence (re-encrypt + re-store under
                // the same opaque keys; keeps the record live for contacts).
                if let Err(e) =
                    presence::publish_presence(&identity_clone, &last_registered_address).await
                {
                    tracing::warn!("Failed to refresh presence: {}", e);
                } else {
                    tracing::debug!("Presence refreshed (no change): {}", identity_clone.null_id);
                }
            }
        }
    });

    println!("Waiting for connections...");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let store_pool = store.pool.clone();
        let id_clone = identity.clone();

        tokio::spawn(async move {
            // Each spawned task creates its own DbEncryptionKey from the file
            let db_key = match load_db_key_interactive(read_db_passphrase().as_deref()) {
                Ok(key) => key,
                Err(e) => {
                    tracing::error!("Failed to load db key: {}", e);
                    return;
                }
            };
            let store = MessageStore {
                pool: store_pool,
                db_key,
            };
            if let Err(_e) = handle_incoming_connection(stream, peer_addr, id_clone, store).await {}
        });
    }
}


async fn handle_incoming_connection(
    stream: TcpStream,
    _peer_addr: std::net::SocketAddr,
    identity: Identity,
    store: MessageStore,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws = tokio_tungstenite::accept_async(stream).await?;
    let (mut ws_tx, mut ws_rx) = ws.split();

    // Read hello
    let hello_text = match ws_rx.next().await {
        Some(Ok(Message::Text(t))) => t.to_string(),
        Some(Ok(Message::Binary(b))) => String::from_utf8_lossy(&b).to_string(),
        Some(Err(e)) => return Err(format!("ws read err: {}", e).into()),
        None => return Err("connection closed before hello".into()),
        _ => return Err("unexpected message type for hello".into()),
    };
    let hello: serde_json::Value = serde_json::from_str(&hello_text)?;
    // Peers send `msg_type` (WireEnvelope field); tolerate a bare `type` key too.
    let hello_type = hello
        .get("msg_type")
        .or_else(|| hello.get("type"))
        .and_then(|t| t.as_str());
    if hello_type != Some("p2p-hello") {
        return Err("expected p2p-hello".into());
    }

    // SECURITY FIX (C2): Verify peer's hello signature.
    // WireEnvelope nests public_key/braid/kyber_enc_key inside `payload`;
    // `sig` is a top-level field. The sender signs the `payload` object,
    // so verify the same string (not the full envelope).
    let payload = hello
        .get("payload")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let peer_sig = hello.get("sig").and_then(|s| s.as_str()).unwrap_or("");
    let peer_fp = payload
        .get("public_key")
        .and_then(|k| k.as_str())
        .unwrap_or("unknown");

    // Mutual-consent gate (DESIGN.md §6.1): drop any inbound peer that is not in
    // the local contact list BEFORE signature verification / ratchet work. This
    // blocks one-sided contact (Bob→Alice when Alice has not added Bob) and
    // stops a stranger from burning CPU or probing presence. The gate is
    // client-enforced, so it survives a hostile/modified server.
    // `peer_fp` here is the peer's *fingerprint* (it is carried in the hello's
    // `public_key` field), so match it against the contact fingerprints.
    // Well-known public services (reflector) are exempt — they are reachable
    // without a contact entry (DESIGN.md §6 exception), so they must also be
    // allowed to initiate.
    {
        let contacts = load_contacts();
        let known = contacts.values().any(|fp| fp == peer_fp);
        if !known && !is_public_service_fingerprint(peer_fp) {
            return Err(format!(
                "inbound hello from {} rejected — not in contact list (mutual-consent gate)",
                peer_fp
            )
            .into());
        }
    }

    if peer_sig.is_empty() {
        return Err("p2p-hello has no signature — rejecting (MITM risk)".into());
    } else {
        // SECURITY FIX (C2): Cache the peer's ML-DSA-87 verifying key from the
        // hello payload (the sender embeds it) so verify_signature can succeed
        // without a DHT round-trip. Fall back to a DHT fetch if absent.

        if add_dht_core::crypto_helpers::get_cached_verifying_key(peer_fp).is_none() {
            if let Some(vk_b64) = payload.get("sender_verifying_key").and_then(|v| v.as_str())
                && let Ok(vk_bytes) = base64::engine::general_purpose::STANDARD.decode(vk_b64)
                && let Ok(vk) = add_crypto_pq::decode_verifying_key(&vk_bytes)
            {
                // SECURITY FIX (C3): pin the fingerprint→VK binding (hard-fail
                // on conflict) instead of silently overwriting.
                if let Err(e) = add_dht_core::crypto_helpers::pin_verifying_key(peer_fp, &vk) {
                    return Err(format!(
                        "p2p-hello identity binding conflict for {}: {}",
                        peer_fp, e
                    )
                    .into());
                }
            }
            if add_dht_core::crypto_helpers::get_cached_verifying_key(peer_fp).is_none() {
                let (seed_url, _bootstraps, _relays) = discover_all_servers().await;
                fetch_peer_verifying_key(&seed_url, peer_fp).await;
            }
        }
        let hello_sig_payload = format!("p2p-hello:{}\n", payload);
        if !add_dht_core::verify_signature(&hello_sig_payload, peer_sig, peer_fp) {
            return Err(format!("p2p-hello signature verification failed for {}", peer_fp).into());
        }
        println!("Verified p2p-hello signature from {}", peer_fp);
    }

    // SECURITY FIX (C1): Extract peer's Kyber public key from hello.
    // SPQR Braid: if the initiator advertised braid, we reassemble its EK from
    // braid chunks after sending the ack (and stream our own in return).
    let peer_braid = payload
        .get("braid")
        .and_then(|b| b.as_bool())
        .unwrap_or(false);
    let mut peer_kyber_enc: Option<add_crypto::kyber::KyberEncapsulationKey> = None;
    if !peer_braid && let Some(kyber_b64) = payload.get("kyber_enc_key").and_then(|k| k.as_str()) {
        peer_kyber_enc = add_crypto::kyber::decode_enc_key(kyber_b64).ok();
    }

    // SECURITY FIX (C1): Load our Kyber keypair deterministically derived from null_id
    let our_kyber = load_or_generate_kyber(&identity.null_id, store.db_key())?;
    let our_kyber_enc_b64 = add_crypto::kyber::encode_enc_key(&our_kyber.enc);

    // Send hello-ack with our Kyber public key (signed).
    // Build the ack envelope embedding our verifying key so the peer can
    // verify the signature without a DHT round-trip. The signature is computed
    // over the SAME payload object (including sender_verifying_key) the peer
    // will verify — not a hand-built object that diverges from it.
    let server_challenge = uuid_hex();
    let my_vk_b64 = my_verifying_key_b64()?;
    let mut ack = add_p2p::protocol::build_p2p_hello_ack(
        identity.fingerprint.as_str(),
        1,
        16,
        &server_challenge,
        &our_kyber_enc_b64,
    );
    ack.payload["sender_verifying_key"] = serde_json::Value::String(my_vk_b64);
    let ack_sig_data = format!("p2p-hello-ack:{}\n", ack.payload);
    ack.sig = sign_for_transport(&ack_sig_data)?;
    ws_tx
        .send(Message::Text(serde_json::to_string(&ack)?.into()))
        .await?;

    // SPQR Braid: exchange EKs over the streamed braid channel.
    if peer_braid {
        let our_ek_bytes = base64::engine::general_purpose::STANDARD
            .decode(&our_kyber_enc_b64)
            .map_err(|e| format!("ek decode: {}", e))?;
        let (sink, rx, peer_ek_bytes) =
            add_p2p::braid_handshake::exchange_ek_braid_split(ws_tx, ws_rx, &our_ek_bytes)
                .await
                .map_err(|e| format!("braid EK exchange: {}", e))?;
        ws_tx = sink;
        ws_rx = rx;
        // SECURITY (C1): bind the reassembled EK to the authenticated inline
        // `kyber_enc_key` from the ML-DSA-87-signed hello. Fail-closed — no
        // plaintext fallback.
        let inline_ek_b64 = payload
            .get("kyber_enc_key")
            .and_then(|k| k.as_str())
            .unwrap_or("");
        let inline_ek = base64::engine::general_purpose::STANDARD
            .decode(inline_ek_b64)
            .map_err(|e| format!("inline kyber_enc_key decode: {}", e))?;
        let peer_ek_bytes =
            add_p2p::braid_handshake::verify_peer_ek_from_bytes(&peer_ek_bytes, &inline_ek)
                .map_err(|e| format!("[braid] peer EK failed authentication ({}), aborting", e))?;
        let peer_ek_b64 = base64::engine::general_purpose::STANDARD.encode(&peer_ek_bytes);
        peer_kyber_enc = add_crypto::kyber::decode_enc_key(&peer_ek_b64).ok();
        if peer_kyber_enc.is_none() {
            return Err(
                "[braid] reassembled peer EK invalid after authentication, aborting".into(),
            );
        }
    }

    // SECURITY FIX (C1): The initial shared secret is derived SYMMETRICALLY.
    // The initiator (Bob) encapsulates to Alice and ships the Kyber ciphertext
    // inside the p2p-message (`init_kyber_ct`). Here, after reading that
    // message, Alice decapsulates it with her own secret key to recover the
    // SAME shared secret. (If absent — e.g. relay/legacy path — fall back to
    // Alice independently encapsulating to Bob, preserving prior behaviour.)
    // -> ratchet session is created below, once init_kyber_ct is available.

    // Discover relays for read receipt forwarding
    let (_seed_url, _bootstraps, relay_urls) = discover_all_servers().await;

    // Read message — skip control frames (e.g. the sealed-sender delivery
    // token sent before the encrypted message) and wait for p2p-message.
    #[allow(unused_assignments)]
    let mut msg: serde_json::Value = serde_json::Value::Null;
    loop {
        match ws_rx.next().await {
            Some(Ok(Message::Text(t))) => {
                let v: serde_json::Value = match serde_json::from_str(&t) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if v.get("msg_type")
                    .or_else(|| v.get("type"))
                    .and_then(|x| x.as_str())
                    == Some("p2p-message")
                {
                    msg = v;
                    break;
                }
                // otherwise: delivery token or other control frame — skip
                continue;
            }
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
            Some(Err(e)) => return Err(format!("ws read err: {}", e).into()),
            None => return Err("connection closed before p2p-message".into()),
            _ => continue,
        }
    }
    if msg
        .get("msg_type")
        .or_else(|| msg.get("type"))
        .and_then(|t| t.as_str())
        == Some("p2p-message")
    {
        // SECURITY FIX (C2): Verify the peer's message signature — FAIL-CLOSED.
        // The message is rejected (never decrypted) if the signature is missing
        // or fails to verify against the verified peer identity established by
        // the signed hello (C3 binding). This closes the fail-open path that
        // previously let a MITM or malicious relay inject/forge p2p-message frames.
        let msg_sig = msg.get("sig").and_then(|s| s.as_str()).unwrap_or("");
        if msg_sig.is_empty() {
            return Err(format!(
                "p2p-message from {} has no signature — rejecting (MITM risk)",
                peer_fp
            )
            .into());
        }
        // Reconstruct the EXACT signed payload the initiator produced:
        //   "p2p-message:" + {"seq","ciphertext","msg_hash"}  (compact, no trailing newline)
        // (The full envelope also carries init_kyber_ct/ttl/sig, but those are
        // NOT part of the signed string.)
        let p = msg
            .get("payload")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let signed_inner = serde_json::json!({
            "seq": p.get("seq").cloned().unwrap_or(serde_json::Value::Null),
            "ciphertext": p.get("ciphertext").cloned().unwrap_or(serde_json::Value::Null),
            "msg_hash": p.get("msg_hash").cloned().unwrap_or(serde_json::Value::Null),
        });
        let msg_sig_payload = format!(
            "p2p-message:{}",
            serde_json::to_string(&signed_inner).unwrap_or_default()
        );
        // Use the verifying key bound during the signed hello (C3). If for some
        // reason it is not cached, fall back to the fingerprint-keyed cache, but
        // never accept an unverifiable message.
        let verified = match add_dht_core::crypto_helpers::get_cached_verifying_key(peer_fp) {
            Some(vk) => add_dht_core::crypto_helpers::verify_signature_with_verifying_key(
                &msg_sig_payload,
                msg_sig,
                &vk,
            ),
            None => add_dht_core::verify_signature(&msg_sig_payload, msg_sig, peer_fp),
        };
        if !verified {
            return Err(format!(
                "p2p-message signature verification failed for {} — possible MITM, rejecting",
                peer_fp
            )
            .into());
        }
        println!("Verified p2p-message signature from {}", peer_fp);

        let payload = msg
            .get("payload")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let ciphertext = payload
            .get("ciphertext")
            .and_then(|c| c.as_str())
            .unwrap_or("");

        // SECURITY FIX (C1): Derive the initial shared secret SYMMETRICALLY.
        // The initiator (Bob) encapsulates to Alice and ships the Kyber
        // ciphertext in `init_kyber_ct`; Alice decapsulates it with her own
        // secret key to recover the SAME shared secret Bob used to seed his
        // ratchet. Fallback: if absent, Alice independently encapsulates to
        // Bob (legacy/relay path) — keep prior behaviour.
        let peer_nid = add_crypto::null_id(peer_fp);
        let init_shared_secret: Vec<u8> =
            if let Some(init_ct_b64) = payload.get("init_kyber_ct").and_then(|v| v.as_str()) {
                let ct_bytes = base64::engine::general_purpose::STANDARD
                    .decode(init_ct_b64)
                    .map_err(|e| format!("init_kyber_ct decode: {}", e))?;
                let ct = add_crypto::kyber::MlKem1024Ciphertext::try_from(ct_bytes.as_slice())
                    .map_err(|e| format!("init_kyber_ct parse: {:?}", e))?;
                let ss = our_kyber
                    .decapsulate(&ct)
                    .map_err(|e| format!("init_kyber decapsulate: {}", e))?;
                AsRef::<[u8]>::as_ref(&ss).to_vec()
            } else {
                let peer_kyber = peer_kyber_enc.as_ref().ok_or("no peer Kyber key")?;
                let ss2 = add_crypto::kyber::KyberKeypair::encapsulate(peer_kyber)
                    .map_err(|e| format!("kyber encapsulate: {}", e))?
                    .1;
                AsRef::<[u8]>::as_ref(&ss2).to_vec()
            };
        let mut ratchet_session = add_crypto::DoubleRatchetSession::new(
            peer_fp,
            &peer_nid,
            &identity.fingerprint,
            false, // not initiator
            &init_shared_secret,
        )
        .map_err(|e| format!("ratchet init: {}", e))?;
        // SECURITY FIX (G9): Persist the ratchet session for this peer so
        // future messages (including relay-fetched) can decrypt.
        let session_json = ratchet_session
            .serialize()
            .map_err(|e| format!("ratchet serialize: {}", e))?;
        let _ = store.save_session(&peer_nid, &session_json).await;

        // SECURITY FIX (M1): thread the message sequence number into the
        // ratchet so skipped-key handling can recover out-of-order delivery.
        let p2p_seq = payload.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);

        // SECURITY FIX (C1): Decrypt using Double Ratchet + Kyber-768
        let padded_plaintext = ratchet_session
            .decrypt_message(ciphertext, &our_kyber, p2p_seq)
            .map_err(|e| format!("decrypt failed: {}", e))?;

        // SECURITY FIX (M1): Strip message padding
        let plaintext = unpad_message_bucket(&padded_plaintext)?;

        // Emit a machine-parseable line (Null ID + fingerprint) so the desktop
        // UI listener can attribute and display the message. Format:
        //   [HH:MM:SS] From: <NULL_ID> (<FP>) | <text>
        let sender_nid = add_crypto::null_id(peer_fp);
        println!(
            "[{}] From: {} ({}) | {}",
            chrono::Utc::now().format("%H:%M:%S"),
            sender_nid,
            peer_fp,
            plaintext
        );

        // G5: Store received message (only ciphertext, no plaintext)
        // Status 2 = delivered
        let message_id = sha256_hex(ciphertext.as_bytes());
        let _ = store
            .store_message(peer_fp, &identity.null_id, ciphertext, 2, &message_id)
            .await;

        // Send ack (signed)
        let ack_sig_data = format!(
            "p2p-ack:{}\n",
            serde_json::json!({
                "seq": 1,
                "msg_hash": sha256_hex(&plaintext),
            })
        );
        let ack_sig = sign_for_transport(&ack_sig_data)?;
        let p2p_ack = add_p2p::protocol::build_p2p_ack_signed(1, &sha256_hex(&plaintext), &ack_sig);
        ws_tx
            .send(Message::Text(serde_json::to_string(&p2p_ack)?.into()))
            .await?;

        // ACS2.6: Send p2p-receipt — cryptographic E2E delivery confirmation.
        // The receipt is signed by the recipient and proves the message was
        // successfully decrypted (delivered to the user) without revealing content.
        // Hash is of ciphertext to match sender's msg_hash for correlation verification.
        let receipt_sig_data = format!(
            "p2p-receipt:{}:{}:{}",
            sha256_hex(ciphertext),
            chrono::Utc::now().timestamp() as f64,
            1, // seq
        );
        let receipt_sig = sign_for_transport(&receipt_sig_data)?;
        let p2p_receipt = add_p2p::protocol::build_p2p_receipt(
            &sha256_hex(&plaintext),
            chrono::Utc::now().timestamp() as f64,
            1,
            &receipt_sig,
        );
        ws_tx
            .send(Message::Text(serde_json::to_string(&p2p_receipt)?.into()))
            .await?;

        // Also send read receipt to all known relays for cross-relay sync
        let receipt = RelayReadReceipt {
            message_id: sha256_hex(ciphertext.as_bytes()),
            recipient_nid: identity.null_id.clone(),
            recipient_fp: identity.fingerprint.clone(),
            signature: receipt_sig,
            timestamp: chrono::Utc::now().timestamp() as f64,
            nonce: uuid_hex(),
            recipient_verifying_key: my_verifying_key_b64()?,
            other_relays: relay_urls.clone(),
        };
        for url in &relay_urls {
            if let Err(e) = send_read_receipt_to_relay(url, &receipt).await {
                tracing::warn!(relay = %url, "failed to send read receipt: {}", e);
            }
        }

        // Update local message status to "read" (3)
        let message_id = sha256_hex(ciphertext.as_bytes());
        let _ = store.update_message_status(&message_id, 3).await;
    }

    ws_tx.close().await.ok();
    Ok(())
}

// ------------------------------------------------------------------ //
//  Crypto helpers (for client)                                       //
// ------------------------------------------------------------------ //

fn sha256_hex<T: AsRef<[u8]>>(data: T) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data.as_ref());
    hex::encode(hasher.finalize())
}

/// Verify a p2p-receipt signature from the recipient.
/// The receipt is signed over "p2p-receipt:{msg_hash}:{received_at}:{seq}"
/// using the recipient's PGP key. This proves they decrypted the message.
fn verify_receipt_signature(
    msg_hash: &str,
    received_at: f64,
    signature: &str,
    recipient_fp: &str,
) -> bool {
    if signature.is_empty() {
        return false;
    }
    let sig_data = format!("p2p-receipt:{}:{}:{}", msg_hash, received_at, 1);
    add_dht_core::verify_signature(&sig_data, signature, recipient_fp)
}

/// SECURITY FIX (M1): Pad message to constant-size bucket to prevent
/// traffic analysis by message size. Uses power-of-2 buckets with
/// random padding bytes. The first byte of the padded output indicates
/// the padding length so the receiver can strip it.
/// Bucket sizes: 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
fn pad_message_bucket(message: &str) -> String {
    let msg_bytes = message.as_bytes();
    let msg_len = msg_bytes.len();
    // 1 byte for padding-length header
    let total_len = msg_len + 1;

    // Find the next power-of-2 bucket >= total_len
    let bucket_size = if total_len <= 256 {
        256
    } else if total_len <= 512 {
        512
    } else if total_len <= 1024 {
        1024
    } else if total_len <= 2048 {
        2048
    } else if total_len <= 4096 {
        4096
    } else if total_len <= 8192 {
        8192
    } else if total_len <= 16384 {
        16384
    } else if total_len <= 32768 {
        32768
    } else {
        65536
    };

    let pad_len = bucket_size - msg_len - 1; // -1 for the header byte
    let mut result = Vec::with_capacity(bucket_size);
    // Header: padding length as a single byte (must fit; max 65535)
    result.push(pad_len as u8);
    result.extend_from_slice(msg_bytes);
    // Fill padding with random bytes
    use rand::RngCore;
    let mut padding = vec![0u8; pad_len];
    rand::thread_rng().fill_bytes(&mut padding);
    result.extend_from_slice(&padding);
    // Encode as hex for transport
    hex::encode(result)
}

/// SECURITY FIX (M1): Strip padding from a de-padded message.
/// Reads the first byte as padding length, then strips that many bytes + 1 header byte.
fn unpad_message_bucket(padded_hex: &str) -> Result<String, Box<dyn std::error::Error>> {
    let data = hex::decode(padded_hex)?;
    if data.is_empty() {
        return Err("empty padded message".into());
    }
    let pad_len = data[0] as usize;
    if data.len() < pad_len + 1 {
        return Err("invalid padding length".into());
    }
    let msg = &data[1..data.len() - pad_len];
    Ok(String::from_utf8_lossy(msg).to_string())
}

/// SECURITY FIX (G6): Compute a safety number from two fingerprints.
/// This is analogous to Signal's safety number — a deterministic value
/// that both parties can compute and compare out-of-band (voice call,
/// QR scan, etc.) to verify no man-in-the-middle has substituted keys.
///
/// The safety number is derived from both fingerprints in sorted order,
/// so both parties compute the same value regardless of who initiated.
fn safety_number(fp1: &str, fp2: &str) -> String {
    let mut fps = [fp1.to_uppercase(), fp2.to_uppercase()];
    fps.sort();
    let combined = format!("{}|{}", fps[0], fps[1]);
    let hash = sha256_hex(&combined);
    // Format as 8 groups of 8 hex chars for easy visual comparison
    format!(
        "{} {} {} {} {} {} {} {}",
        &hash[0..8],
        &hash[8..16],
        &hash[16..24],
        &hash[24..32],
        &hash[32..40],
        &hash[40..48],
        &hash[48..56],
        &hash[56..64]
    )
}

fn uuid_hex() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n: u128 = rng.r#gen();
    format!("{:032x}", n)[..16].to_string()
}

// ------------------------------------------------------------------ //
//  CLI                                                               //
// ------------------------------------------------------------------ //

/// Add P2P Messenger Client
#[derive(Parser, Debug)]
#[command(name = "add", version, about)]
struct Args {
    /// Subcommand
    #[command(subcommand)]
    cmd: Commands,

    /// DHT seed/bootstrap URL (auto-discovered via DNS SRV if omitted)
    #[arg(long, global = true)]
    seed: Option<String>,

    /// Relay URL (auto-discovered via DNS SRV if omitted)
    #[arg(long, global = true)]
    relay: Option<String>,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Initialize a new identity (creates MAK vault if TPM present)
    Init {
        /// 6-digit TPM PIN
        #[arg(long)]
        pin: Option<String>,
        /// 16-character passphrase (upper+lower+digit+special)
        #[arg(long)]
        password: Option<String>,
    },
    /// Unlock the MAK vault (loads into secure memory)
    Unlock {
        /// 6-digit TPM PIN (if TPM vault)
        #[arg(long)]
        pin: Option<String>,
        /// 16-character passphrase (if passphrase vault)
        #[arg(long)]
        password: Option<String>,
    },
    /// Show your Null ID
    Id,
    /// Send a message
    Send {
        /// Recipient Null ID
        to: String,
        /// Message text. Use "-" to read the message body from stdin
        /// (required for large payloads such as file attachments, which would
        /// otherwise exceed the OS command-line argument length limit).
        message: String,
        /// Use PIR for privacy-enhanced DHT lookup (hides query from DHT server)
        #[arg(long)]
        pir: bool,
        /// Auto-destruct timer (e.g., 2h, 12h, 24h, 48h, 5d, 7d, 14d)
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Read messages
    Read {
        /// Emit one JSON object per message ({"from":"<null_id>","text":"<msg>"}) for machine parsing
        #[arg(long)]
        json: bool,
        /// Hide the locally "Stored messages" section (relay mailbox only)
        #[arg(long)]
        no_stored: bool,
    },
    /// Always-online echo mode: fetch incoming messages and send back exactly
    /// the same text to the sender. Used by the Reflector Bot — reuses the
    /// normal receive + send paths (no bespoke crypto).
    Reflect {
        /// Auto-destruct timer for the returned echo (e.g. 2h, 24h)
        #[arg(long)]
        ttl: Option<String>,
        /// Poll interval in seconds between mailbox checks
        #[arg(long, default_value_t = 5)]
        interval: u64,
        /// Override relay servers to poll (repeatable). Defaults to discovered relays.
        #[arg(long)]
        relay: Option<Vec<String>>,
    },
    /// (TEMP DEBUG) one-shot relay fetch for self, print count + senders
    RawFetch {
        #[arg(long, default_value = "wss://relay-us.gnoppix.org/ws")]
        relay: String,
    },
    /// (TEMP DEBUG) purge own mailbox on all relays
    Purge,
    /// List contacts
    Contacts,
    /// Add a contact
    AddContact {
        /// Contact Null ID
        null_id: String,
        /// Contact fingerprint
        fingerprint: String,
    },
    /// Start P2P listener
    Listen {
        /// Publicly-reachable URL to advertise in the DHT (e.g. wss://your.domain/ws).
        /// Use this when the listener sits behind a reverse proxy / NAT so peers
        /// connect to your public endpoint instead of the LAN bind address.
        #[arg(long)]
        advertised_url: Option<String>,
        /// Disable automatic NAT traversal (UPnP port mapping, then STUN discovery).
        /// When set, the listener advertises the raw LAN bind address.
        #[arg(long)]
        no_nat: bool,
        /// Fixed local TCP port to bind the listener to. Binding a stable port
        /// (instead of an ephemeral one) keeps the advertised address consistent
        /// with the port NAT traversal maps to, so inbound P2P actually lands
        /// on this socket. Defaults to 42887.
        #[arg(long, default_value_t = 42887)]
        port: u16,
    },
    /// Show DHT status
    Status,
    /// Verify a contact's safety number (G6)
    Verify {
        /// Contact Null ID
        null_id: String,
    },
    /// Show your safety number for a contact (G6)
    SafetyNumber {
        /// Contact Null ID or alias
        null_id: String,
    },
    /// Assign a human-readable name to a Null ID
    Alias {
        /// Short alias name (e.g. "Bob-office")
        alias: String,
        /// The Null ID to map
        null_id: String,
    },
    /// List all aliases
    Aliases,
    /// Register identity with bootstrap DHT
    Register,
    /// Register identity with ALL bootstrap servers (background retry until all succeed)
    RegisterAllBootstraps,
    /// Check registration status across all bootstrap servers
    CheckRegister,
    /// Publish your certificate to the opaque blob store (DESIGN.md §4.2)
    PublishCert,
    /// Fetch a contact's certificate from the opaque store by fingerprint
    FetchCert {
        /// Contact fingerprint (spoken out-of-band)
        fingerprint: String,
    },
    /// Check online status of all contacts (query DHT addr_records)
    ContactStatus,
    /// Delete a message by its position number (shown in read output)
    Delete {
        /// Position number of message to delete (1 = first/newest in list)
        id: i64,
    },
    /// Change or set the passphrase protecting your GPG secret key
    Passwd {
        /// Current passphrase (for IPC from Electron)
        #[arg(long)]
        current: Option<String>,
        /// New passphrase (for IPC from Electron)
        #[arg(long)]
        new: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install rustls crypto provider (required since rustls 0.23)
    // Must be called before any TLS connection (wss:// URLs)
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Parse args FIRST to know what command we're running
    let args = Args::parse();

    // PID file: prevent multiple instances from racing on the same DB/GPG home
    let pid_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".add/add.pid");
    let listen_pid_path = dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(".add/add_listen.pid");

    // Check main PID file - only block if another process is running AND we're trying to run listen
    // For non-listen commands, just overwrite the PID file (commands run sequentially)
    if pid_path.exists() {
        // Check if the PID is still alive
        if let Ok(old_pid) = std::fs::read_to_string(&pid_path) {
            let old_pid: i32 = old_pid.trim().parse().unwrap_or(0);
            #[cfg(unix)]
            let pid_alive = old_pid > 0 && unsafe { libc::kill(old_pid, 0) } == 0;
            #[cfg(not(unix))]
            let pid_alive = false; // No POSIX kill on Windows; treat stale PID as not running.
            if pid_alive {
                // Only block if we're trying to run listen and there's another process
                if matches!(args.cmd, Commands::Listen { .. }) {
                    return Err(format!(
                        "Another add instance is already running (PID {}). Kill it first.",
                        old_pid
                    )
                    .into());
                }
                // For non-listen commands, just continue (we'll overwrite the PID)
            }
        }
        // Stale PID file — overwrite it
    } else if let Some(parent) = pid_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Only check listen PID if we're running the listen command
    // The listen PID file is written by the Electron app for background listen process
    let current_pid = std::process::id() as i32;
    if matches!(args.cmd, Commands::Listen { .. }) {
        let is_already_listen = listen_pid_path.exists()
            && std::fs::read_to_string(&listen_pid_path)
                .ok()
                .and_then(|p| p.trim().parse::<i32>().ok())
                == Some(current_pid);

        if !is_already_listen {
            // Check listen PID file (for background listen process from Electron app)
            if listen_pid_path.exists() {
                if let Ok(old_pid) = std::fs::read_to_string(&listen_pid_path) {
                    let old_pid: i32 = old_pid.trim().parse().unwrap_or(0);
                    #[cfg(unix)]
                    let pid_alive = old_pid > 0 && unsafe { libc::kill(old_pid, 0) } == 0;
                    #[cfg(not(unix))]
                    let pid_alive = false; // No POSIX kill on Windows; treat stale PID as not running.
                    if pid_alive {
                        return Err(format!(
                            "A add listen process is already running (PID {}). Kill it first or use 'add listen' from the Electron app.",
                            old_pid
                        )
                        .into());
                    }
                }
                // Stale listen PID file — remove it
                let _ = std::fs::remove_file(&listen_pid_path);
            }
        }
    }

    std::fs::write(&pid_path, format!("{}\n", current_pid))
        .map_err(|e| format!("Cannot write PID file {}: {}", pid_path.display(), e))?;
    struct PidDrop(std::path::PathBuf);
    impl Drop for PidDrop {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _pid_cleanup = PidDrop(pid_path);

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("add=info".parse()?))
        .init();

    // ACS2.6 Part III.2: Lifecycle memory hooks — zeroize on SIGINT/SIGTERM
    // SECURITY FIX (C2): Use graceful shutdown (not process::exit) so Drop
    // implementations run — ZeroizeOnDrop zeros all key material on scope exit.
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!(
            "received SIGINT, initiating graceful shutdown (zeroizing secure memory)..."
        );
        shutdown_clone.notify_one();
    });

    // Also handle SIGTERM for systemd/service manager
    #[cfg(unix)]
    {
        let shutdown_clone2 = Arc::clone(&shutdown);
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
            let _ = sigterm.recv().await;
            tracing::info!("received SIGTERM, initiating graceful shutdown...");
            shutdown_clone2.notify_one();
        });
    }

    // Resolve seed and relay URLs: CLI flag > SRV discovery > hardcoded defaults > localhost fallback
    let (srv_seed, srv_relays) = discover_servers().await;

    let seed_url = args
        .seed
        .clone()
        .or_else(|| {
            let url = srv_seed.clone();
            tracing::info!("Using discovered bootstrap server: {}", url);
            Some(url)
        })
        .unwrap_or_else(|| SEED_URL.to_string());

    // Handle relay URLs - CLI can specify single or comma-separated list
    let relay_urls: Vec<String> = if let Some(ref relay_arg) = args.relay {
        if relay_arg.contains(',') {
            relay_arg.split(',').map(|s| s.to_string()).collect()
        } else {
            vec![relay_arg.clone()]
        }
    } else {
        srv_relays.clone()
    };

    // Use first (primary) relay for single-relay ops
    let relay_url = relay_urls
        .first()
        .cloned()
        .unwrap_or_else(|| RELAY_URL.to_string());

    // Log relay configuration
    if relay_urls.len() > 1 {
        tracing::info!("Using {} relay servers:", relay_urls.len());
        for (i, url) in relay_urls.iter().enumerate() {
            tracing::info!("  [{}] {}", i + 1, url);
        }
    } else {
        tracing::info!("Using relay server: {}", relay_url);
    }

    match args.cmd {
        Commands::Init { pin, password } => {
            // Check if identity already exists — require confirmation to overwrite
            let identity_path = home_dir().join(IDENTITY_PATH);
            if identity_path.exists()
                && let Ok(existing) = Identity::load()
            {
                println!("An identity already exists!");
                println!("  Null ID:     {}", existing.null_id);
                println!("  Fingerprint: {}", existing.fingerprint);
                println!();
                println!("WARNING: Re-initializing will destroy your current identity.");
                println!("         You will NOT be able to read messages sent to this identity.");
                println!("         All contacts will need your new Null ID.");
                println!();
                println!("Type 'yes' to confirm and replace your identity:");

                let mut confirm = String::new();
                std::io::stdin().read_line(&mut confirm)?;
                if confirm.trim() != "yes" {
                    println!("Aborted. Your existing identity is unchanged.");
                    return Ok(());
                }
            }

            // Create MAK vault (TPM PIN or passphrase)
            let identity = generate_identity()?;
            println!("Identity created successfully!");
            println!("  Fingerprint: {}", identity.fingerprint);
            println!("  Null ID:     {}", identity.null_id);
            println!();

            // Create MAK vault (protect the ML-DSA seed)
            if let Some(ref pin) = pin {
                let mak = add_crypto::MasterAppKey::generate()?;
                #[cfg(feature = "tpm")]
                {
                    let vault = add_crypto::VaultFile::seal_to_tpm(&mak, pin.as_bytes())?;
                    add_crypto::cache_mak(mak);
                    vault.write_to(&home_dir().join(VAULT_PATH))?;
                    println!("Vault created at ~/.add/vault.json");
                }
                #[cfg(not(feature = "tpm"))]
                {
                    // No TPM: treat PIN as passphrase
                    let vault = add_crypto::seal_with_passphrase(&mak, pin.as_bytes())?;
                    add_crypto::cache_mak(mak);
                    vault.write_to(&home_dir().join(VAULT_PATH))?;
                    println!("Vault created at ~/.add/vault.json (passphrase mode, no TPM)");
                }
            } else if let Some(ref pw) = password {
                let mak = add_crypto::MasterAppKey::generate()?;
                let vault = add_crypto::seal_with_passphrase(&mak, pw.as_bytes())?;
                add_crypto::cache_mak(mak);
                vault.write_to(&home_dir().join(VAULT_PATH))?;
                println!("Vault created at ~/.add/vault.json");
            } else {
                // No auth provided — generate ephemeral MAK, no vault file
                println!("WARNING: No --pin or --password provided. MAK stored in memory only.");
                println!("         This identity is NOT protected at rest. Re-init with --pin/--password to secure it.");
            }

            println!("Share your Null ID with contacts to receive messages.");

            // NOTE: the Reflector Bot (NN-UFtv-8fHu) is a well-known PUBLIC
            // SERVICE, not a contact. It is reachable without being in the
            // contact list — `send_message` resolves it via the public cert
            // store (DESIGN.md §6 exception). We therefore do NOT insert it as
            // a contact here. The Reflector-ECHO alias is kept as a convenience
            // shortcut that resolves to its well-known null id.
            let mut aliases = load_aliases();
            if !aliases.contains_key("Reflector-ECHO") {
                aliases.insert("Reflector-ECHO".to_string(), "NN-UFtv-8fHu".to_string());
                save_aliases(&aliases)?;
            }
        }
        Commands::Id => {
            let identity = Identity::load()?;
            println!("Null ID:     {}", identity.null_id);
            println!("Fingerprint: {}", identity.fingerprint);
        }
        Commands::Unlock { pin, password } => {
            let vault_path = home_dir().join(VAULT_PATH);
            if !vault_path.exists() {
                println!("No vault found at ~/.add/vault.json");
                println!("Run 'add init --pin <PIN> or --password <pw>' to create one.");
                return Ok(());
            }
            let home = home_dir();
            let mak = (|| -> Result<add_crypto::MasterAppKey, Box<dyn std::error::Error>> {
                let vault: add_crypto::VaultFile =
                    add_crypto::VaultFile::read_from(&vault_path)?;
                #[cfg(feature = "tpm")]
                if let Some(ref pin) = pin {
                    vault.unseal_from_tpm(pin.as_bytes()).map_err(|e| e.into())
                } else {
                    Err(add_crypto::CryptoError::Io("Either --pin or --password required for unlock".to_string()).into())
                }
                #[cfg(not(feature = "tpm"))]
                if let Some(ref pw) = password {
                    add_crypto::unseal_with_passphrase(&vault, pw.as_bytes())
                        .map_err(|e| e.into())
                } else {
                    Err(add_crypto::CryptoError::Io("Either --pin or --password required for unlock".to_string()).into())
                }
            })();
            
            match mak {
                Ok(m) => {
                    add_crypto::reset_failed_attempts(&home)?;
                    add_crypto::cache_mak(m);
                    println!("Vault unlocked successfully.");
                }
                Err(e) => {
                    let should_destroy = add_crypto::check_failed_attempts(&home, true)?;
                    if should_destroy {
                        add_crypto::self_destruct(&home)?;
                        println!("WRONG PASSWORD ENTERED 10 TIMES - IDENTITY DESTROYED");
                        std::process::exit(1);
                    }
                    return Err(e);
                }
            }
        }
        Commands::Send {
            to,
            message,
            pir,
            ttl,
        } => {
            // `-` means read the message body from stdin. This is required for
            // large payloads (e.g. file attachments) because the OS imposes a
            // hard cap on command-line argument length (Linux/macOS ~128-256KB,
            // Windows ~32KB) that a base64 attachment would exceed.
            let message = if message == "-" {
                let mut buf = String::new();
                std::io::stdin().read_to_string(&mut buf)?;
                buf
            } else {
                message
            };
            let store = MessageStore::open().await?;
            let identity = Identity::load()?;
            let aliases = load_aliases();
            let resolved_to = resolve_recipient(&to, &aliases);
            // Try all relays, use the fastest responding one
            let best_relay = select_fastest_relay(&relay_urls).await;
            match best_relay {
                Some(url) => {
                    tracing::info!("Selected fastest relay: {}", url);
                    send_message(
                        &identity,
                        &resolved_to,
                        &message,
                        &store,
                        pir,
                        &seed_url,
                        &url,
                        ttl.as_deref(),
                    )
                    .await?;
                }
                None => {
                    return Err("No relay servers reachable".into());
                }
            }
        }
        Commands::Read { json, no_stored } => {
            let store = MessageStore::open().await?;
            let identity = Identity::load()?;

            // G2: Fetch from ALL relay mailboxes and decrypt via DoubleRatchet
            println!("Checking {} relay mailbox(s)...", relay_urls.len());
            let results = relay_fetch_all(&relay_urls, &identity.null_id).await?;

            if results.is_empty() {
                println!("No new messages.");
            } else {
                // Decrypt and deduplicate messages
                let our_kyber = load_or_generate_kyber(&identity.null_id, store.db_key())?;
                let mut seen_hashes = std::collections::HashSet::new();
                let mut decrypted_messages: Vec<(String, String)> = Vec::new();

                for (_source_url, signed_blob, entry_sender_nid, entry_sender_fp) in results {
                    match relay_decrypt_message(
                        &signed_blob,
                        &entry_sender_nid,
                        &entry_sender_fp,
                        &identity.fingerprint,
                        &store,
                        &our_kyber,
                    )
                    .await
                    {
                        Ok(decrypted) => {
                            let msg_hash = sha256_hex(decrypted.as_bytes());
                            if !seen_hashes.contains(&msg_hash) {
                                seen_hashes.insert(msg_hash);
                                decrypted_messages.push((entry_sender_nid, decrypted));
                            }
                        }
                        Err(_) => { /* undecryptable (e.g. stale pre-fix mailbox cruft) */ }
                    }
                }

                if !decrypted_messages.is_empty() {
                    // Build a null_id -> alias reverse map so messages show the
                    // sender's alias (or the raw Null ID when no alias exists).
                    let aliases = load_aliases();
                    let reverse_aliases: std::collections::HashMap<String, String> = aliases
                        .iter()
                        .map(|(a, n)| (n.clone(), a.clone()))
                        .collect();

                    if json {
                        // Machine-readable: one JSON object per line, so the UI
                        // can attribute each message to its sender conversation.
                        for (from, msg) in &decrypted_messages {
                            let line = serde_json::json!({ "from": from, "text": msg }).to_string();
                            println!("{}", line);
                        }
                    } else {
                        println!("Messages ({}):", decrypted_messages.len());
                        for (i, (from, msg)) in decrypted_messages.iter().enumerate() {
                            let label = reverse_aliases
                                .get(from)
                                .cloned()
                                .unwrap_or_else(|| from.clone());
                            println!("  [{}] [{}] [{}]", i + 1, label, msg);
                            // Store with status 2 (delivered) and message ID
                            let message_id = sha256_hex(msg.as_bytes());
                            let _ = store
                                .store_message(
                                    "relay",
                                    &identity.null_id,
                                    msg,
                                    2, // Delivered (✔️)
                                    &message_id,
                                )
                                .await;
                        }
                    }
                    // Purge from all connected relays
                    for url in &relay_urls {
                        let _ = relay_purge(url, &identity.null_id).await;
                    }
                }
            }

            // G5: Also show locally stored messages (unless --no-stored)
            let stored = store.get_messages(20).await?;
            if !no_stored && !stored.is_empty() {
                println!("\nStored messages (last 20):");
                for (idx, msg) in stored.iter().enumerate() {
                    // Messages are stored encrypted - display ciphertext preview
                    let preview = if msg.ciphertext.len() > 40 {
                        format!("{}...", &msg.ciphertext[..40])
                    } else {
                        msg.ciphertext.clone()
                    };
                    // Checkmark indicators based on status
                    let checkmark = match msg.status {
                        0 => "🔘",   // Sent
                        1 => "☑️",   // Relayed
                        2 => "✔️",   // Delivered
                        3 => "✔️✔️", // Read
                        _ => "?",
                    };
                    println!(
                        "  [{}] {} {} -> {}: {}",
                        idx + 1,
                        checkmark,
                        msg.from_nid,
                        msg.to_nid,
                        preview
                    );
                }
                println!("  (use 'add delete <position>' to delete a message)");
            }
        }
        Commands::Reflect {
            ttl,
            interval,
            relay,
        } => {
            // Always-online echo mode (Reflector Bot). Reuses the normal
            // receive + send paths — no bespoke crypto. For every message we
            // receive, we send back exactly the same text to its sender.
            let store = MessageStore::open().await?;
            let identity = Identity::load()?;
            // Honor the global --seed override (otherwise discover_servers()
            // falls back to DNS SRV / public bootstrap, which is wrong for a
            // locally-scoped reflector test or a non-default deployment).
            let seed_url = match args.seed.clone() {
                Some(s) => s,
                None => discover_servers().await.0,
            };
            // Allow scoping the reflector to a specific relay set (e.g. a single
            // healthy relay) for testing or to avoid broken peers.
            let relay_urls: Vec<String> = relay.clone().unwrap_or_else(|| relay_urls.clone());
            println!(
                "Reflector echo mode active as {} (poll every {}s). Sending back whatever arrives.",
                identity.null_id, interval
            );

            // Publish per-contact encrypted presence so mutual contacts can
            // discover us without the server learning our address.
            let advertised = match primary_ipv4() {
                Some(ip) => format!("ws://{}:8765", ip),
                None => format!("ws://{}:8765", "0.0.0.0"),
            };
            if let Err(e) = presence::publish_presence(&identity, &advertised).await {
                tracing::warn!("initial presence publish failed: {}", e);
            }
            // Refresh presence every 30 min (no IP re-detection churn).
            let identity_refresh = identity.clone();
            let advertised_refresh = advertised.clone();
            tokio::spawn(async move {
                let mut interval_timer =
                    tokio::time::interval(std::time::Duration::from_secs(30 * 60));
                interval_timer.tick().await; // consume immediate first tick
                loop {
                    interval_timer.tick().await;
                    if let Err(e) =
                        presence::publish_presence(&identity_refresh, &advertised_refresh).await
                    {
                        tracing::warn!("presence publish refresh failed: {}", e);
                    }
                }
            });

            // TIER-1 cover traffic: constant-rate decoy relay fetches so the
            // relay/ISP can't correlate "you connected ⇄ message delivered".
            start_cover_traffic(relay_urls.clone());

            loop {
                // G2: fetch from ALL relay mailboxes and decrypt.
                let results = match relay_fetch_all(&relay_urls, &identity.null_id).await {
                    Ok(r) => {
                        if !r.is_empty() {
                            tracing::info!("reflect fetch: {} message(s) retrieved", r.len());
                        }
                        r
                    }
                    Err(e) => {
                        tracing::warn!("relay fetch failed: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                        continue;
                    }
                };

                if !results.is_empty() {
                    let our_kyber = match load_or_generate_kyber(&identity.null_id, store.db_key()) {
                        Ok(k) => k,
                        Err(e) => {
                            tracing::warn!("kyber load failed: {}", e);
                            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                            continue;
                        }
                    };
                    let mut seen_hashes = std::collections::HashSet::new();
                    let my_vk_b64 = my_verifying_key_b64()?;

                    // Collect every fetched blob (whether we can decrypt it or not)
                    // so we can ACK all of them at the end of the poll. Marking them
                    // delivered (read-receipt) is what stops the reflector from
                    // re-fetching + re-processing the same message forever — including
                    // stale undecryptable cruft that has no kyber_ciphertext / session.
                    let mut ack_blobs: Vec<String> = Vec::new();
                    for (_source_url, signed_blob, entry_sender_nid, entry_sender_fp) in results {
                        ack_blobs.push(signed_blob.clone());
                        let decrypted = match relay_decrypt_message(
                            &signed_blob,
                            &entry_sender_nid,
                            &entry_sender_fp,
                            &identity.fingerprint,
                            &store,
                            &our_kyber,
                        )
                        .await
                        {
                            Ok(d) => d,
                            Err(_) => continue, // undecryptable (e.g. stale cruft): skip echo, but still ACK below
                        };
                        // Deduplicate within this poll cycle.
                        let msg_hash = sha256_hex(decrypted.as_bytes());
                        if !seen_hashes.insert(msg_hash) {
                            continue;
                        }
                        println!("echo -> {} : {}", entry_sender_nid, decrypted);
                        // Force a fresh ratchet session for this recipient so the
                        // bounce is always an independent first-message (Kyber-
                        // encapsulated). This prevents ratchet desync when the same
                        // peer is bounced repeatedly or at different fetch cadences.
                        let _ = store.delete_session(&entry_sender_nid).await;
                        // Send the echo back. Per architecture the reflector is always
                        // online and the original sender is online, so we try a direct
                        // P2P return first; only fall back to relay when the peer is
                        // unreachable (offline / NAT with no hole punch).
                        let echo_sent = if let Ok(()) = send_message(
                            &identity,
                            &entry_sender_nid,
                            &decrypted,
                            &store,
                            true,
                            &seed_url,
                            &select_fastest_relay(&relay_urls).await.unwrap_or_default(),
                            ttl.as_deref(),
                        )
                        .await
                        {
                            true
                        } else {
                            send_via_relay(
                                &identity,
                                &entry_sender_nid,
                                &entry_sender_fp,
                                &decrypted,
                                &store,
                                &select_fastest_relay(&relay_urls).await.unwrap_or_default(),
                                ttl.as_deref(),
                                true,
                            )
                            .await
                            .is_ok()
                        };
                        if echo_sent {
                            // ACK the source message on the relay (message_id == the
                            // signed_blob we just echoed) so it is marked delivered and
                            // will NOT be re-fetched on the next poll.
                            let rts = chrono::Utc::now().timestamp() as f64;
                            let rnonce = uuid_hex();
                            if let Ok(rsig) = sign_for_transport(&format!(
                                "{}|{}|{}",
                                signed_blob, identity.null_id, rts
                            )) {
                                let receipt = RelayReadReceipt {
                                    message_id: signed_blob.clone(),
                                    recipient_nid: identity.null_id.clone(),
                                    recipient_fp: identity.fingerprint.clone(),
                                    signature: rsig,
                                    timestamp: rts,
                                    nonce: rnonce,
                                    recipient_verifying_key: my_vk_b64.clone(),
                                    other_relays: relay_urls.clone(),
                                };
                                let _ = send_read_receipt_to_relay(
                                    &select_fastest_relay(&relay_urls).await.unwrap_or_default(),
                                    &receipt,
                                )
                                .await;
                            }
                        }
                    }
                    // ACK every fetched message (delivered=1) so nothing is re-fetched.
                    // This is the loop-stopper even for undecryptable stale entries.
                    for blob in &ack_blobs {
                        let rts = chrono::Utc::now().timestamp() as f64;
                        let rnonce = uuid_hex();
                        if let Ok(rsig) =
                            sign_for_transport(&format!("{}|{}|{}", blob, identity.null_id, rts))
                        {
                            let receipt = RelayReadReceipt {
                                message_id: blob.clone(),
                                recipient_nid: identity.null_id.clone(),
                                recipient_fp: identity.fingerprint.clone(),
                                signature: rsig,
                                timestamp: rts,
                                nonce: rnonce,
                                recipient_verifying_key: my_vk_b64.clone(),
                                other_relays: relay_urls.clone(),
                            };
                            let _ = send_read_receipt_to_relay(
                                &select_fastest_relay(&relay_urls).await.unwrap_or_default(),
                                &receipt,
                            )
                            .await;
                        }
                    }
                    // Purge delivered echoes from the mailbox so we don't loop.
                    for url in &relay_urls {
                        let _ = relay_purge(url, &identity.null_id).await;
                    }
                }

                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
            }
        }
        Commands::RawFetch { relay } => {
            let identity = Identity::load()?;
            let _store = MessageStore::open().await?;
            // Use the decrypting fetch path so we can confirm end-to-end
            // decryption of relay-stored (kyber_ciphertext) echoes.
            let mut all = relay_fetch_all(&relay_urls, &identity.null_id).await?;
            if !relay_urls.iter().any(|u| u == &relay) {
                match relay_fetch_all(std::slice::from_ref(&relay), &identity.null_id).await {
                    Ok(mut more) => all.append(&mut more),
                    Err(e) => println!("  (relay {} error: {})", relay, e),
                }
            }
            println!("RAWFETCH count={}", all.len());
            let store = MessageStore::open().await?;
            let our_kyber = load_or_generate_kyber(&identity.null_id, store.db_key())?;
            for (i, (_src, blob, snd, sfp)) in all.iter().enumerate() {
                match relay_decrypt_message(
                    blob,
                    snd,
                    sfp,
                    &identity.fingerprint,
                    &store,
                    &our_kyber,
                )
                .await
                {
                    Ok(plaintext) => println!("  [{}] from {}: {}", i, snd, plaintext),
                    Err(e) => println!(
                        "  [{}] from {}: <decrypt-failed: {}> blob={}",
                        i, snd, e, blob
                    ),
                }
            }
        }
        Commands::Purge => {
            let identity = Identity::load()?;
            for r in &relay_urls {
                match relay_purge(r, &identity.null_id).await {
                    Ok(()) => println!("purged {}", r),
                    Err(e) => println!("purge failed {}: {}", r, e),
                }
            }
        }
        Commands::Contacts => {
            let contacts = load_contacts();
            if contacts.is_empty() {
                println!("No contacts. Add one with: add add-contact <null_id> <fingerprint>");
            } else {
                println!("Contacts:");
                for (nid, fp) in &contacts {
                    println!("  {} -> {}", nid, fp);
                }
            }
        }
        Commands::AddContact {
            null_id,
            fingerprint,
        } => {
            if fingerprint.len() < 32 || !fingerprint.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("invalid fingerprint format — must be 32-40 hex chars".into());
            }
            let mut contacts = load_contacts();
            contacts.insert(null_id.clone(), fingerprint.to_uppercase());
            save_contacts(&contacts)?;
            println!(
                "Added contact: {} -> {}",
                null_id,
                fingerprint.to_uppercase()
            );
        }
        Commands::Listen {
            advertised_url,
            no_nat,
            port,
        } => {
            let store = MessageStore::open().await?;
            let identity = Identity::load()?;
            // Load our GPG cert for signing address records
            let cert = load_cert()?;
            println!("Starting P2P listener...");
            // Abort on SIGINT/SIGTERM so the listener exits cleanly (key material
            // zeroized via Drop) instead of being orphaned when its parent dies.
            tokio::select! {
                res = run_listener(identity, store, cert, advertised_url, no_nat, port) => {
                    res?;
                }
                _ = shutdown.notified() => {
                    tracing::info!("listener interrupted by signal, shutting down");
                }
            }
        }
        Commands::Status => {
            println!("Add Status:");
            println!("================");

            match Identity::load() {
                Ok(id) => {
                    println!("  Identity: {}", id.null_id);
                    println!("  Fingerprint: {}", id.fingerprint);
                }
                Err(_) => println!("  Identity: NOT INITIALIZED (run 'add init')"),
            }

            let contacts = load_contacts();
            println!("  Contacts: {}", contacts.len());

            let bootstrap_path = home_dir().join(BOOTSTRAP_PATH);
            if bootstrap_path.exists() {
                println!("  Bootstrap pin cache: present");
            } else {
                println!("  Bootstrap pin cache: none");
            }

            println!("  Key dir: {}", home_dir().join(GPG_HOME).display());
            println!("  Message DB: {}", home_dir().join(MESSAGES_DB).display());
            println!("  Seed URL: {}", seed_url);
            println!("  Relay URL: {}", relay_url);

            // G4: Document that the DHT is centralized (seed model)
            println!("\n  DHT model: Centralized seed (no Kademlia routing)");
            println!(
                "  The DHT seed node at {} stores all key-value pairs.",
                seed_url
            );
            println!("  Clients connect directly to the seed for lookups and writes.");
            println!("  P2P connections are established after DHT lookup for direct delivery.");
        }
        Commands::Verify { null_id } => {
            let contacts = load_contacts();
            let aliases = load_aliases();
            let resolved_nid = resolve_recipient(&null_id, &aliases);
            let fp = contacts
                .get(&resolved_nid)
                .ok_or("unknown contact — add with 'add-contact' first")?;
            let identity = Identity::load()?;
            let sn = safety_number(&identity.fingerprint, fp);
            println!("Safety number for {}:", resolved_nid);
            println!("  {}", sn);
            println!("\nVerify this matches your contact's safety number.");
            println!(
                "If it doesn't match, a man-in-the-middle may be intercepting your communication."
            );
        }
        Commands::SafetyNumber { null_id } => {
            let contacts = load_contacts();
            let aliases = load_aliases();
            let resolved_nid = resolve_recipient(&null_id, &aliases);
            let fp = contacts
                .get(&resolved_nid)
                .ok_or("unknown contact — add with 'add-contact' first")?;
            let identity = Identity::load()?;
            let sn = safety_number(&identity.fingerprint, fp);
            println!("Your safety number with {}:", resolved_nid);
            println!("  {}", sn);
        }
        Commands::Alias { alias, null_id } => {
            // Validate that the null_id exists in contacts
            let contacts = load_contacts();
            if !contacts.contains_key(&null_id) {
                return Err(format!(
                    "unknown Null ID: {} — add it first with 'add-contact {} <fingerprint>'",
                    null_id, null_id
                )
                .into());
            }
            let mut aliases = load_aliases();
            aliases.insert(alias.clone(), null_id.clone());
            save_aliases(&aliases)?;
            println!("Alias set: {} -> {}", alias, null_id);
        }
        Commands::Aliases => {
            let aliases = load_aliases();
            if aliases.is_empty() {
                println!("No aliases. Add one with: add alias <name> <null_id>");
            } else {
                println!("Aliases:");
                for (alias, nid) in &aliases {
                    println!("  {} -> {}", alias, nid);
                }
            }
        }
        Commands::Register => {
            let identity = Identity::load()?;
            let seed_url = discover_servers().await.0;
            dht_register(&seed_url, &identity).await?;
            println!("Registered identity {} with DHT.", identity.null_id);
        }
        Commands::RegisterAllBootstraps => {
            let identity = Identity::load()?;
            let (_seed_url, bootstraps, _relays) = discover_all_servers().await;
            println!(
                "Registering identity {} with {} bootstrap servers...",
                identity.null_id,
                bootstraps.len()
            );

            let mut tasks = Vec::new();
            for bootstrap_url in bootstraps.clone() {
                let ident = identity.clone();
                let url = bootstrap_url.clone();
                tasks.push(tokio::spawn(async move {
                    match dht_register(&url, &ident).await {
                        Ok(_) => (url, Ok(())),
                        Err(e) => (url, Err(e.to_string())),
                    }
                }));
            }

            // Wait for all to complete
            let mut results = Vec::new();
            for task in tasks {
                if let Ok((url, result)) = task.await {
                    results.push((url, result));
                }
            }

            // Print results
            let mut all_ok = true;
            for (url, result) in &results {
                match result {
                    Ok(_) => println!("  ✓ {}", url),
                    Err(e) => {
                        println!("  ✗ {} - {}", url, e);
                        all_ok = false;
                    }
                }
            }

            if all_ok {
                println!(
                    "\n✓ All {} bootstrap registrations successful.",
                    results.len()
                );
            } else {
                println!("\n⚠ Some registrations failed. Run 'add check-register' to verify.");
            }
        }
        Commands::CheckRegister => {
            let identity = Identity::load()?;
            let (_seed_url, bootstraps, _relays) = discover_all_servers().await;
            println!(
                "Checking registration for {} across {} bootstrap servers...",
                identity.null_id,
                bootstraps.len()
            );

            let mut tasks = Vec::new();
            for bootstrap_url in bootstraps.clone() {
                let ident = identity.clone();
                let url = bootstrap_url.clone();
                tasks.push(tokio::spawn(async move {
                    // Try to fetch our own record from each bootstrap
                    match dht_get(&url, &ident.null_id).await {
                        Ok(Some(_)) => (url, "online".to_string()),
                        Ok(None) => (url, "not-found".to_string()),
                        Err(e) => (url, format!("error: {}", e)),
                    }
                }));
            }

            let mut results = Vec::new();
            for task in tasks {
                if let Ok((url, status)) = task.await {
                    results.push((url, status.to_string()));
                }
            }

            // Print status table
            println!("\nBootstrap Registration Status:");
            println!("{:<50} Status", "Server");
            println!("{}", "-".repeat(70));
            let mut all_online = true;
            for (url, status) in &results {
                let icon = if status == "online" { "✓" } else { "✗" };
                println!("{:<50} {} {}", url, icon, status);
                if status != "online" {
                    all_online = false;
                }
            }

            println!(
                "\nSummary: {} online, {} incomplete",
                results.iter().filter(|(_, s)| s == "online").count(),
                results.iter().filter(|(_, s)| s != "online").count()
            );

            if all_online {
                println!("✓ All bootstrap servers have your identity registered.");
            } else {
                println!(
                    "⚠ Some servers missing registration. Run 'add register-all-bootstraps' to fix."
                );
            }
        }
        Commands::PublishCert => {
            let identity = Identity::load()?;
            match dht_publish_cert(&identity).await {
                Ok(()) => println!("✓ Certificate published to bootstrap servers."),
                Err(e) => {
                    eprintln!("✗ Failed to publish certificate: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Commands::FetchCert { fingerprint } => {
            let (_seed_url, bootstraps, _relays) = discover_all_servers().await;
            let mut fetched = None;
            for url in &bootstraps {
                match dht_fetch_cert(url, &fingerprint).await {
                    Ok((armored, vk, kyber_enc)) => {
                        fetched = Some((armored, vk, kyber_enc));
                        break;
                    }
                    Err(e) => tracing::warn!("cert fetch from {} failed: {}", url, e),
                }
            }
            match fetched {
                Some((armored, vk, kyber_enc)) => {
                    // Verify the fetched cert's fingerprint matches what Bob spoke.
                    use sequoia_openpgp::parse::Parse;
                    let cert = sequoia_openpgp::Cert::from_bytes(armored.as_bytes())
                        .map_err(|e| format!("parse cert: {}", e))?;
                    let got_fp = cert.fingerprint().to_hex().to_uppercase();
                    if got_fp != fingerprint.to_uppercase() {
                        eprintln!(
                            "✗ FINGERPRINT MISMATCH: spoke '{}' but cert hashes to '{}'",
                            fingerprint, got_fp
                        );
                        std::process::exit(1);
                    }
                    println!("✓ Certificate verified (fingerprint matches).");
                    println!("Fingerprint:   {}", got_fp);
                    println!("ML-DSA vk:     {}", vk);
                    println!("ML-KEM enc:    {}", kyber_enc);
                    println!();
                    println!("----- BEGIN ARMORDED CERT (share on request) -----");
                    println!("{}", armored);
                    println!("----- END ARMORDED CERT -----");
                }
                None => {
                    eprintln!("✗ Certificate not found for fingerprint {}", fingerprint);
                    std::process::exit(1);
                }
            }
        }
        Commands::ContactStatus => {
            let identity = Identity::load()?;
            let (_seed_url, bootstraps, _relays) = discover_all_servers().await;
            let contacts = load_contacts();

            if contacts.is_empty() {
                println!(
                    "No contacts found. Add contacts with 'add add-contact <null_id> <fingerprint>'"
                );
            } else {
                println!(
                    "Checking online status for {} contacts across {} bootstrap servers...",
                    contacts.len(),
                    bootstraps.len()
                );

                let mut contact_status = Vec::new();

                for (null_id, fingerprint) in &contacts {
                    let fp8 = fingerprint.chars().take(8).collect::<String>();
                    // Public services (e.g. the reflector) publish no per-contact
                    // presence — they're stateless. Reachability is the cert-store
                    // bundle (opaque address), so check that instead of presence.
                    let mut found_online = false;
                    if is_public_service(null_id) {
                        match fetch_public_service_addr(null_id).await {
                            Some(addr) => {
                                println!(
                                    "  ● {} ({}) - AVAILABLE (public service) at {}",
                                    fp8, null_id, addr
                                );
                                found_online = true;
                            }
                            None => {
                                println!("  ○ {} ({}) - UNAVAILABLE (cert store)", fp8, null_id);
                            }
                        }
                    } else if let Some(addr) =
                        presence::fetch_presence_live(&identity, fingerprint).await
                    {
                        println!("  ✓ {} ({}) - ONLINE at {}", fp8, null_id, addr);
                        found_online = true;
                    }

                    if !found_online && !is_public_service(null_id) {
                        println!("  ✗ {} ({}) - OFFLINE", fp8, null_id);
                    }
                    contact_status.push((null_id.clone(), fingerprint.clone(), found_online));
                }

                // Summary
                let online_count = contact_status
                    .iter()
                    .filter(|(_, _, online)| *online)
                    .count();
                let offline_count = contact_status.len() - online_count;
                println!(
                    "\nSummary: {} online, {} offline",
                    online_count, offline_count
                );
            }
        }
        Commands::Delete { id } => {
            // 'id' is a 1-indexed position from the message list
            let store = MessageStore::open().await?;
            // Get all messages to find the position
            let stored = store.get_messages(100).await?;
            let pos = id.max(1) as usize; // clamp to 1-indexed
            if pos > stored.len() {
                println!(
                    "No message found at position {}. ({} stored messages)",
                    pos,
                    stored.len()
                );
            } else {
                // messages are ordered DESC, position 1 = newest (first in list)
                let msg_id = stored[pos - 1].id;
                match store.delete_message(msg_id).await? {
                    true => println!("Message {} (ID {}) deleted.", pos, msg_id),
                    false => println!("No message found with ID {}.", msg_id),
                }
            }
        }
        Commands::Passwd { current, new } => match change_passphrase(current, new) {
            Ok(()) => println!("Passphrase changed successfully."),
            Err(e) => eprintln!("Failed to change passphrase: {}", e),
        },
    }

    Ok(())
}

#[cfg(test)]
mod db_key_tests {
    use super::*;
    use std::sync::Mutex;

    // Both tests below mutate the global HOME env var (key file + MessageStore
    // resolve their path from HOME). Cargo runs tests in parallel threads, so we
    // serialize them on a lock to avoid one test reading the other's key file.
    static HOME_LOCK: Mutex<()> = Mutex::new(());

    // F-7: the message-store key file must NOT sit on disk as recoverable
    // plaintext. It must be age-encrypted with the user's passphrase.
    #[test]
    fn db_key_file_is_age_encrypted_not_plaintext() {
        let _guard = HOME_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("add-dbkeytest-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        unsafe { std::env::set_var("HOME", &dir); }
        let path = dir.join(".add").join("db_key.json");
        let _ = std::fs::remove_file(&path);

        let mut raw = [0u8; 32];
        for (i, b) in raw.iter_mut().enumerate() { *b = (i as u8).wrapping_mul(7); }
        let key = DbEncryptionKey { key: raw };
        key.save(Some("hunter2")).expect("age-wrap test key");

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            contents.contains("BEGIN AGE ENCRYPTED FILE"),
            "key file must be age-encrypted, found plaintext: {contents}"
        );

        let loaded = DbEncryptionKey::load(Some("hunter2")).expect("load with passphrase");
        assert_eq!(loaded.key(), &raw, "round-trip key mismatch");
        assert!(DbEncryptionKey::load(Some("wrong")).is_err(), "wrong passphrase must fail");

        let _ = std::fs::remove_dir_all(&dir);
    }

    // F-7 metadata: sender/recipient nids, timestamps and message_id must be
    // stored encrypted (AES-256-GCM), with equality lookups served by a keyed
    // HMAC blind index — never the plaintext on disk or in the WHERE clause.
    #[tokio::test]
    async fn message_metadata_is_encrypted_at_rest() {
        let _guard = HOME_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("add-metatest-{}-{}", std::process::id(), chrono::Utc::now().timestamp()));
        let _ = std::fs::create_dir_all(&dir.join(".add"));
        unsafe { std::env::set_var("HOME", &dir); }
        unsafe { std::env::set_var("ADD_DB_PASSPHRASE", "hunter2"); }

        let store = MessageStore::open().await.expect("open store");

        let from = "NN-aaaa-bbbb-cccc";
        let to = "NN-dddd-eeee-ffff";
        let mid = "msg-0123-unique";
        store.store_message(from, to, "hello world", 0, mid).await.expect("store");

        // Round-trip: read back decrypts to the right metadata.
        let msgs = store.get_messages(10).await.expect("get");
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].from_nid, from);
        assert_eq!(msgs[0].to_nid, to);
        assert_eq!(msgs[0].message_id, mid);
        assert_eq!(msgs[0].ciphertext, "hello world");

        // Blind-index lookup for status update must hit the same row.
        assert!(store.update_message_status(mid, 2).await.expect("update"));

        // Raw on-disk inspection: the nid/timestamp/message_id columns must
        // NOT contain the plaintext values.
        let pool = &store.pool;
        let row: (String, String, String, String, String) = sqlx::query_as(
            "SELECT from_nid_enc, to_nid_enc, timestamp_enc, message_id_enc, message_id_idx FROM messages LIMIT 1",
        )
        .fetch_one(pool)
        .await
        .expect("raw read");
        for col in [row.0.clone(), row.1.clone(), row.2.clone(), row.3.clone()] {
            assert!(!col.contains(from) && !col.contains(to) && !col.contains(mid),
                "plaintext metadata leaked into encrypted column: {col}");
        }
        // Blind index is a 32-char hex HMAC, distinct from plaintext.
        assert_eq!(row.4.len(), 32, "blind index should be 32 hex chars");
        assert_ne!(row.4, mid, "blind index must not equal plaintext message_id");

        // Ratchet session: peer_nid must be encrypted + blind-indexed.
        store.save_session("NN-peer-x", "session-json").await.expect("save session");
        let loaded = store.load_session("NN-peer-x").await.expect("load session");
        assert_eq!(loaded.as_deref(), Some("session-json"));
        let srow: (String, String) = sqlx::query_as(
            "SELECT peer_nid_enc, peer_nid_idx FROM ratchet_sessions LIMIT 1",
        )
        .fetch_one(pool)
        .await
        .expect("raw session read");
        assert!(!srow.0.contains("NN-peer-x"), "peer_nid leaked: {}", srow.0);
        assert_ne!(srow.1, "NN-peer-x");

        unsafe { std::env::remove_var("ADD_DB_PASSPHRASE"); }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // F-7 metadata: an existing plaintext DB (pre-migration schema) must be
    // transparently re-encrypted on open — old rows survive and become ciphertext.
    #[tokio::test]
    async fn legacy_plaintext_db_is_migrated_on_open() {
        let _guard = HOME_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("add-legacytest-{}-{}", std::process::id(), chrono::Utc::now().timestamp()));
        let add_dir = dir.join(".add");
        let _ = std::fs::create_dir_all(&add_dir);
        unsafe { std::env::set_var("HOME", &dir); }
        unsafe { std::env::set_var("ADD_DB_PASSPHRASE", "hunter2"); }

        // Bootstrap a DB with the OLD plaintext schema, then drop a row in.
        let db_path = add_dir.join("messages.db");
        let pool = SqlitePoolOptions::new()
            .connect(&format!("sqlite://{}?mode=rwc", db_path.display()))
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE messages (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                from_nid TEXT NOT NULL,\n                to_nid TEXT NOT NULL,\n                ciphertext TEXT NOT NULL,\n                timestamp TEXT NOT NULL,\n                delivered INTEGER NOT NULL DEFAULT 0,\n                status INTEGER NOT NULL DEFAULT 0,\n                status_updated_at TEXT NOT NULL,\n                read_receipt_at TEXT,\n                message_id TEXT NOT NULL UNIQUE\n            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "CREATE TABLE ratchet_sessions (\n                id INTEGER PRIMARY KEY AUTOINCREMENT,\n                peer_nid TEXT NOT NULL UNIQUE,\n                session_data TEXT NOT NULL,\n                updated_at TEXT NOT NULL\n            )",
        )
        .execute(&pool)
        .await
        .unwrap();
        let legacy_from = "NN-old-from";
        let legacy_to = "NN-old-to";
        let legacy_mid = "legacy-mid-1";
        sqlx::query(
            "INSERT INTO messages (from_nid, to_nid, ciphertext, timestamp, delivered, status, status_updated_at, read_receipt_at, message_id)\n             VALUES (?, ?, ?, ?, 0, 0, ?, NULL, ?)",
        )
        .bind(legacy_from)
        .bind(legacy_to)
        .bind("cipher-blob")
        .bind("2026-01-01T00:00:00Z")
        .bind("2026-01-01T00:00:00Z")
        .bind(legacy_mid)
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("INSERT INTO ratchet_sessions (peer_nid, session_data, updated_at) VALUES (?, ?, ?)")
            .bind("NN-old-peer")
            .bind("old-session")
            .bind("2026-01-01T00:00:00Z")
            .execute(&pool)
            .await
            .unwrap();
        pool.close().await;

        // Now open via the real store: migration runs, re-encrypting legacy rows.
        let store = MessageStore::open().await.expect("open legacy db");

        let msgs = store.get_messages(10).await.expect("get migrated");
        assert_eq!(msgs.len(), 1, "legacy row must survive migration");
        assert_eq!(msgs[0].from_nid, legacy_from);
        assert_eq!(msgs[0].to_nid, legacy_to);
        assert_eq!(msgs[0].message_id, legacy_mid);

        let loaded = store.load_session("NN-old-peer").await.expect("load migrated session");
        assert_eq!(loaded.as_deref(), Some("old-session"));

        // And the on-disk columns must now be ciphertext, not the legacy plaintext.
        let pool = &store.pool;
        let row: (String, String) = sqlx::query_as(
            "SELECT from_nid_enc, to_nid_enc FROM messages LIMIT 1",
        )
        .fetch_one(pool)
        .await
        .expect("raw read");
        assert!(!row.0.contains(legacy_from) && !row.1.contains(legacy_to),
            "legacy plaintext not re-encrypted: {} / {}", row.0, row.1);

        unsafe { std::env::remove_var("ADD_DB_PASSPHRASE"); }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
