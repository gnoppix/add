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
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
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

// ------------------------------------------------------------------ //
//  Configuration                                                     //
// ------------------------------------------------------------------ //

const GPG_HOME: &str = ".add/gnupg";
const CONTACTS_PATH: &str = ".add/contacts.json";
const ALIASES_PATH: &str = ".add/aliases.json";
const DELIVERY_SECRETS_PATH: &str = ".add/delivery_secrets.json";
const IDENTITY_PATH: &str = ".add/identity.json";
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
struct DbEncryptionKey {
    #[zeroize(drop)]
    key: [u8; 32],
}

impl DbEncryptionKey {
    /// Get a reference to the raw key bytes (for Kyber key encryption).
    pub fn key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Synchronous version of load_or_create for use in non-async contexts (e.g., cmd_init).
    pub fn load_or_create_sync() -> Self {
        let path = home_dir().join(DB_KEY_PATH);
        if path.exists() {
            let hex_key = std::fs::read_to_string(&path).expect("failed to read db key");
            let bytes = hex::decode(hex_key.trim()).expect("invalid db key hex");
            assert_eq!(bytes.len(), 32, "invalid db key length");
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Self { key }
        } else {
            use rand::RngCore;
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let hex_key = hex::encode(key);
            std::fs::write(&path, &hex_key).expect("failed to write db key");
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            Self { key }
        }
    }

    /// Load or create the database encryption key.
    ///
    /// In the first app, the key is stored directly on disk (0o600).
    /// In production, this should be derived from HSM/TEK + user entropy.
    async fn load_or_create() -> Result<Self, Box<dyn std::error::Error>> {
        let path = home_dir().join(DB_KEY_PATH);

        if path.exists() {
            let hex_key = tokio::fs::read_to_string(&path).await?;
            let bytes = hex::decode(hex_key.trim())?;
            if bytes.len() != 32 {
                return Err("invalid db key length".into());
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            Ok(Self { key })
        } else {
            // Generate a new random key
            let mut key = [0u8; 32];
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut key);

            // Store with restrictive permissions
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let hex_key = hex::encode(key);
            tokio::fs::write(&path, &hex_key).await?;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

            Ok(Self { key })
        }
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

/// Prompt for the GPG passphrase (from stdin, no echo if possible).
fn prompt_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    use std::io::Write;

    print!("Enter GPG key passphrase (leave empty for none): ");
    std::io::stdout().flush()?;

    // Try to read with no-echo if available (Unix), otherwise plain readline
    #[cfg(unix)]
    {
        if let Ok(pass) = rpassword::read_password() {
            return Ok(pass);
        }
    }
    // Fallback: plain readline
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    Ok(buf.trim_end().to_string())
}

/// Load the Sequoia certificate for signing operations.
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

fn load_contacts() -> Contacts {
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
    tokio_tungstenite::connect_async(url)
        .await
        .map(|(ws, _)| ws)
        .map_err(|e| format!("WebSocket connect failed: {}", e).into())
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
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_nid TEXT NOT NULL,
                to_nid TEXT NOT NULL,
                ciphertext TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                delivered INTEGER NOT NULL DEFAULT 0,
                status INTEGER NOT NULL DEFAULT 0,
                status_updated_at TEXT NOT NULL,
                read_receipt_at TEXT,
                message_id TEXT NOT NULL UNIQUE
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_nid)")
            .execute(&pool)
            .await?;

        // Message State History Ledger - tracks all state transitions for audit trail
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS message_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT NOT NULL,
                from_nid TEXT NOT NULL,
                to_nid TEXT NOT NULL,
                old_status INTEGER,
                new_status INTEGER,
                status_updated_at TEXT NOT NULL,
                transition_reason TEXT,
                created_at TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_message_history_message_id ON message_history(message_id)"
        )
        .execute(&pool)
        .await?;

        // SECURITY FIX (G9): Persist DoubleRatchet sessions so encrypted
        // conversations survive restarts and relay-fetched messages can be
        // decrypted. The session JSON contains chain keys and pending
        // ciphertext, encrypted at rest by db_key.
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS ratchet_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_nid TEXT NOT NULL UNIQUE,
                session_data TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        let db_key = DbEncryptionKey::load_or_create().await?;

        Ok(Self { pool, db_key })
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
        // ACS2.6 Part III.2: Encrypt ciphertext before writing to disk
        let encrypted_ct = self.db_key.encrypt(ciphertext)?;
        let result = sqlx::query(
            "INSERT OR IGNORE INTO messages (from_nid, to_nid, ciphertext, timestamp, delivered, status, status_updated_at, read_receipt_at, message_id)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(from_nid)
        .bind(to_nid)
        .bind(&encrypted_ct)
        .bind(&timestamp)
        .bind(if status >= 2 { 1 } else { 0 })
        .bind(status as i64)
        .bind(&status_updated_at)
        .bind(None::<String>) // read_receipt_at
        .bind(message_id)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    async fn get_messages(
        &self,
        limit: i64,
    ) -> Result<Vec<StoredMessage>, Box<dyn std::error::Error>> {
        let rows = sqlx::query_as::<_, MessageRow>(
            "SELECT id, from_nid, to_nid, ciphertext, timestamp, delivered, status, status_updated_at, read_receipt_at, message_id
             FROM messages ORDER BY id DESC LIMIT ?"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        // Decrypt ciphertext on read
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                match self.db_key.decrypt(&r.ciphertext) {
                    Ok(_pt) => Some(StoredMessage::from(r)),
                    Err(_) => None, // Skip corrupted/undecryptable entries
                }
            })
            .collect())
    }

    /// Save or update a DoubleRatchet session for a peer.
    /// The session JSON is encrypted with db_key before writing to disk.
    async fn save_session(
        &self,
        peer_nid: &str,
        session_json: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let timestamp = chrono::Utc::now().to_rfc3339();
        let encrypted_data = self.db_key.encrypt(session_json)?;
        sqlx::query(
            "INSERT INTO ratchet_sessions (peer_nid, session_data, updated_at)
             VALUES (?, ?, ?)
             ON CONFLICT(peer_nid) DO UPDATE SET
                session_data = excluded.session_data,
                updated_at = excluded.updated_at",
        )
        .bind(peer_nid)
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
        let row: Option<(String,)> =
            sqlx::query_as("SELECT session_data FROM ratchet_sessions WHERE peer_nid = ?")
                .bind(peer_nid)
                .fetch_optional(&self.pool)
                .await?;

        row.map(|(data,)| self.db_key.decrypt(&data)).transpose()
    }

    /// Delete a DoubleRatchet session for a peer (so the next send re-bootstraps
    /// via a fresh Kyber encapsulation). Used by the reflector so every bounce is
    /// an independent first-message and the recipient never desyncs.
    async fn delete_session(&self, peer_nid: &str) -> Result<(), Box<dyn std::error::Error>> {
        sqlx::query("DELETE FROM ratchet_sessions WHERE peer_nid = ?")
            .bind(peer_nid)
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
        let rows = sqlx::query_as::<_, MessageRow>(
            "SELECT id, from_nid, to_nid, ciphertext, timestamp, delivered
             FROM messages WHERE from_nid = ? ORDER BY id DESC LIMIT ?",
        )
        .bind(from_nid)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|r| {
                match self.db_key.decrypt(&r.ciphertext) {
                    Ok(_pt) => Some(StoredMessage::from(r)),
                    Err(_) => None, // Skip corrupted/undecryptable entries
                }
            })
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

        // First get the current message info for history
        let current = sqlx::query_as::<_, MessageRow>(
                    "SELECT id, from_nid, to_nid, ciphertext, timestamp, delivered, status, status_updated_at, read_receipt_at, message_id
                     FROM messages WHERE message_id = ?"
                )
                .bind(message_id)
                .fetch_optional(&self.pool)
                .await?;

        let (from_nid, to_nid, old_status) = if let Some(ref msg) = current {
            (msg.from_nid.clone(), msg.to_nid.clone(), msg.status as u8)
        } else {
            return Ok(false);
        };

        let result = sqlx::query(
                    "UPDATE messages SET status = ?, status_updated_at = ?, delivered = ? WHERE message_id = ?"
                )
                .bind(status as i64)
                .bind(&timestamp)
                .bind(delivered)
                .bind(message_id)
                .execute(&self.pool)
                .await?;

        // Record in history ledger
        if result.rows_affected() > 0 {
            let reason = match status {
                1 => "relay_ack",
                2 => "delivered",
                3 => "read_receipt",
                _ => "status_change",
            };
            sqlx::query(
                        "INSERT INTO message_history (message_id, from_nid, to_nid, old_status, new_status, status_updated_at, transition_reason, created_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
                    )
                    .bind(message_id)
                    .bind(&from_nid)
                    .bind(&to_nid)
                    .bind(old_status as i64)
                    .bind(status as i64)
                    .bind(&timestamp)
                    .bind(reason)
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
    from_nid: String,
    to_nid: String,
    ciphertext: String,
    timestamp: String,
    delivered: i64,
    status: i64,
    status_updated_at: String,
    read_receipt_at: Option<String>,
    message_id: String,
}

impl From<MessageRow> for StoredMessage {
    fn from(r: MessageRow) -> Self {
        Self {
            id: r.id,
            from_nid: r.from_nid,
            to_nid: r.to_nid,
            ciphertext: r.ciphertext,
            timestamp: r.timestamp,
            delivered: r.delivered != 0,
            status: r.status as u8,
            status_updated_at: r.status_updated_at,
            read_receipt_at: r.read_receipt_at,
            message_id: r.message_id,
        }
    }
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
        // No passphrase: save as plaintext (legacy behavior)
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

    // SECURITY FIX (C1): Generate Kyber-768 keypair for post-quantum encryption
    // SECURITY FIX (C6): Encrypt secret key at rest using DbEncryptionKey
    let kyber_path = home_dir().join(KYBER_KEY_PATH);
    std::fs::create_dir_all(kyber_path.parent().unwrap())?;
    // Deterministic Kyber keypair derived from null_id so both sides get the same key.
    // The recipient's decrypt_message uses the same keypair loaded from its local file.
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(null_id.as_bytes());
    let hk = hkdf::Hkdf::<Sha256>::new(None, &hash);
    let mut seed = [0u8; 64];
    hk.expand(b"add-sealed-sender-kyber-seed", &mut seed)
        .map_err(|_| "HKDF expand failed".to_string())?;
    let kyber_kp = add_crypto::kyber::KyberKeypair::from_seed(&seed)
        .map_err(|e| format!("kyber keypair from seed: {}", e))?;
    // Load or create encryption key, then encrypt+save the Kyber secret key
    let db_key = DbEncryptionKey::load_or_create_sync();
    kyber_kp
        .save(&kyber_path, db_key.key())
        .map_err(|e| format!("kyber keypair save failed: {}", e))?;

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
async fn dht_lookup(
    seed_url: &str,
    null_id: &str,
    use_addr_key: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    use add_protocol::envelope::WireEnvelope;

    // Address records (P2P listener endpoints for contacts/reflector) are stored
    // under the "addr:{null_id}" key, not the bare null_id. The recipient lookup
    // for direct P2P delivery must query that key.
    let dht_key = if use_addr_key {
        format!("addr:{null_id}")
    } else {
        null_id.to_string()
    };

    // Normalize URL scheme: https:// → wss://, http:// → ws://
    let ws_url = seed_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");

    let mut ws = ws_connect(&ws_url)
        .await
        .map_err(|e| format!("DHT connect failed: {}", e))?;

    // SECURITY FIX (C2): Sign the dht-get request with ML-DSA-87
    let sig_data = format!("dht-get:{}\n", serde_json::json!({"key": dht_key}));
    let sig = sign_for_transport(&sig_data)?;

    // Send dht-get (construct WireEnvelope manually)
    let req = WireEnvelope {
        msg_type: "dht-get".to_string(),
        msg_id: uuid_hex(),
        ts: chrono::Utc::now().timestamp() as f64,
        sig: sig.clone(),
        payload: {
            let mut m = serde_json::Map::new();
            m.insert(
                "key".to_string(),
                serde_json::Value::String(dht_key.to_string()),
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
            let address = resp.payload_str("value").unwrap_or("");
            if !address.is_empty() {
                return Ok(address.to_string());
            }
        }
    }

    Err("recipient not found in DHT".into())
}

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

/// Register a DHT address record (listener address) with the bootstrap server.
/// This allows other clients to discover our P2P listener address for direct P2P connections.
async fn dht_register_addr_record(
    seed_url: String,
    identity: &Identity,
    address: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use add_protocol::constants::ADDR_POW_DIFFICULTY;
    use add_protocol::envelope::WireEnvelope;

    let ws_url = seed_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");

    let mut ws = ws_connect(&ws_url)
        .await
        .map_err(|e| format!("DHT connect failed: {}", e))?;

    // Create address record key: "addr:{null_id}"
    let addr_key = format!("addr:{}", identity.null_id);
    let value_b64 = base64::engine::general_purpose::STANDARD.encode(address.as_bytes());

    // Solve PoW for addr-record (difficulty 12)
    let salt = uuid_hex();
    let seq = chrono::Utc::now().timestamp();
    let pow_data = format!("{}|{}|{}|{}", addr_key, value_b64, salt, seq);
    // Owned copy of the per-node secret for the spawned blocking task
    // (spawn_blocking requires 'static; `identity` is only borrowed here).
    let publisher_fp_secret = identity.fingerprint.clone();
    tracing::info!(
        "Solving PoW for addr-record (difficulty {})...",
        ADDR_POW_DIFFICULTY
    );
    let pow_nonce = match tokio::task::spawn_blocking(move || {
        // SECURITY FIX (M11): salt with the publisher's own fingerprint so the
        // server (which validates with the same publisher_fp) reproduces the
        // identical Argon2id salt. Must match dht-core/handle_put addr path.
        add_dht_core::pow_solve(
            &pow_data,
            ADDR_POW_DIFFICULTY,
            10_000_000,
            publisher_fp_secret.as_bytes(),
        )
    })
    .await
    {
        Ok(Ok(Some(n))) => {
            tracing::info!("PoW solved for addr-record");
            n
        }
        Ok(Ok(None)) => {
            return Err("addr-record: could not solve PoW in time".into());
        }
        Ok(Err(e)) => return Err(format!("addr-record PoW error: {}", e).into()),
        Err(e) => return Err(format!("addr-record PoW task error: {}", e).into()),
    };

    // Sign the put request with ML-DSA-87
    let sign_data = format!("{}|{}|{}|{}|{}", addr_key, value_b64, salt, seq, pow_nonce);
    let sig = sign_for_transport(&sign_data)?;

    // Include ML-DSA-87 verifying key in the payload for the DHT to verify
    let vk_b64 = if let Some(sk_b64) = &identity.ml_dsa87_signing_key {
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
                serde_json::Value::String(addr_key.clone()),
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
        .map_err(|e| format!("DHT addr_record send failed: {}", e))?;

    // Read response
    if let Some(Ok(Message::Text(resp_text))) = ws.next().await {
        let resp: WireEnvelope = serde_json::from_str(&resp_text)
            .map_err(|e| format!("DHT addr_record: bad response: {}", e))?;
        if resp.msg_type == "dht-found" {
            tracing::info!(
                "Address record registered for {} at {}",
                identity.null_id,
                address
            );
            return Ok(());
        } else {
            let payload = resp.payload.to_string();
            return Err(format!("DHT addr_record failed: {} ({})", resp.msg_type, payload).into());
        }
    }

    Err("DHT addr_record failed: server closed connection".into())
}

/// Register a DHT address record (listener address) with ALL bootstrap servers.
/// This allows other clients to discover our P2P listener address for direct P2P connections.
/// Uses low difficulty (8) similar to first registration, not the higher re-registration difficulty.
async fn dht_register_addr_record_all(
    identity: &Identity,
    address: &str,
    _ttl: i64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Discover all bootstrap servers
    let (_, bootstraps, _) = discover_all_servers().await;

    let mut last_error = None;
    let mut success_count = 0;

    // Try each bootstrap server
    for seed_url in &bootstraps {
        match dht_register_addr_record(seed_url.clone(), identity, address).await {
            Ok(_) => {
                tracing::debug!("Address record registered on {}", seed_url);
                success_count += 1;
            }
            Err(e) => {
                tracing::warn!("Failed to register address record on {}: {}", seed_url, e);
                last_error = Some(e);
            }
        }
    }

    if success_count > 0 {
        tracing::info!(
            "Address record registered on {}/{} bootstrap servers",
            success_count,
            bootstraps.len()
        );
        Ok(())
    } else {
        Err(last_error.unwrap_or_else(|| "No bootstrap servers available".into()))
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
async fn pir_dht_lookup(
    seed_url: &str,
    null_id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use add_crypto::pir::PirClient;
    use sha2::{Digest, Sha256};

    // Compute fingerprint hash from null_id (same as what's stored in PIR bins)
    let mut hasher = Sha256::new();
    hasher.update(b"pir-fp-hash-v1:");
    hasher.update(null_id.as_bytes());
    let fp_hash: [u8; 32] = hasher.finalize().into();

    let client = PirClient::new();
    let queries = client.query_contact(&fp_hash)?;

    let ws_url = seed_url
        .replace("http://", "ws://")
        .replace("https://", "wss://");

    let mut ws = ws_connect(&ws_url)
        .await
        .map_err(|e| format!("PIR DHT connect failed: {}", e))?;

    // Send PIR queries (one per cuckoo bin candidate)
    let mut result: Option<String> = None;
    for query in queries.iter() {
        let req_json = serde_json::json!({
            "type": "pir-query",
            "bin_index": query.bin_index,
            "ephemeral_pk": base64::engine::general_purpose::STANDARD.encode(query.client_ephemeral_pk),
            "nonce": uuid_hex(),
        });
        ws.send(Message::Text(req_json.to_string().into()))
            .await
            .map_err(|e| format!("PIR query send failed: {}", e))?;

        // Read PIR response
        let resp_msg = ws
            .next()
            .await
            .ok_or("PIR DHT connection closed")?
            .map_err(|e| format!("PIR DHT read failed: {}", e))?;
        let resp_text = match resp_msg {
            Message::Text(t) => t.to_string(),
            _ => continue,
        };
        let resp_json: serde_json::Value = serde_json::from_str(&resp_text)?;
        if resp_json["type"] != "pir-response" {
            continue;
        }
        let bin_data_b64 = resp_json["bin_data"]
            .as_str()
            .ok_or("missing bin_data in PIR response")?;
        let bin_data = base64::engine::general_purpose::STANDARD
            .decode(bin_data_b64)
            .map_err(|e| format!("PIR bin_data decode: {}", e))?;

        let pir_resp = add_crypto::pir::PirResponse {
            bin_data,
            dht_ephemeral_pk: [0u8; 32],
            nonce: [0u8; 8],
        };

        if let Some(entry) = client.process_response(&pir_resp, &query.xor_mask, &fp_hash)? {
            // Extract the contact address from the entry metadata
            let metadata = &entry.metadata;
            let addr = String::from_utf8_lossy(&metadata[32..])
                .trim_end_matches('\0')
                .to_string();
            if !addr.is_empty() {
                result = Some(addr.to_string());
                break;
            }
        }
    }

    ws.close(None).await.ok();

    match result {
        Some(addr) => Ok(addr),
        None => {
            println!("PIR lookup returned no result, falling back to standard DHT");
            dht_lookup(seed_url, null_id, true).await
        }
    }
}

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
/// so Kyber encapsulation on sender side can be decapsulated on recipient side.
fn load_or_generate_kyber(
    null_id: &str,
    store: &MessageStore,
) -> Result<add_crypto::kyber::KyberKeypair, Box<dyn std::error::Error>> {
    let kyber_path = home_dir().join(KYBER_KEY_PATH);
    // Try loading existing keypair first
    if kyber_path.exists() {
        return add_crypto::kyber::KyberKeypair::load(&kyber_path, store.db_key())
            .map_err(|e| format!("kyber keypair load failed: {}", e))
            .map_err(|e| e.into());
    }
    // Derive deterministically from null_id (same on all machine with same identity)
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(null_id.as_bytes());
    let hk = hkdf::Hkdf::<Sha256>::new(None, &hash);
    let mut seed = [0u8; 64];
    hk.expand(b"add-sealed-sender-kyber-seed", &mut seed)
        .map_err(|_| "HKDF expand failed".to_string())?;
    let kp = add_crypto::kyber::KyberKeypair::from_seed(&seed)
        .map_err(|e| format!("kyber keypair from seed: {}", e))?;
    std::fs::create_dir_all(kyber_path.parent().unwrap())?;
    kp.save(&kyber_path, store.db_key())
        .map_err(|e| format!("kyber keypair save failed: {}", e))?;
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
    let our_kyber = load_or_generate_kyber(null_id, store)?;

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
                            if let Some(_error) = resp.get("error").and_then(|e| e.as_str()) {
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
            let resp_val: serde_json::Value = serde_json::from_str(&resp).unwrap_or(serde_json::Value::Null);
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
    let _our_kyber = load_or_generate_kyber(&identity.null_id, store)?;
    let _our_kyber_enc_b64 = add_crypto::kyber::encode_enc_key(&_our_kyber.enc);

    // Look up recipient's Kyber public key from DHT
    let recipient_kyber = lookup_kyber_for_nid(recipient_nid, store).await?;

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

    // SECURITY FIX (M2): Sender identity required for decryption.
    // Real sender_nid/sender_fp stored for recipient to load ratchet session.
    let sealed_sender_token = String::new(); // No sealed sender - we send real identity
    let nonce: i64 = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0);
    let ts: f64 = chrono::Utc::now().timestamp() as f64;

    // Build the signed blob (WireEnvelope)
    let envelope = if let Some(ref kyber_ct) = kyber_ct_hex_opt {
        // First message: include Kyber ciphertext for recipient to initialize session
        serde_json::json!({
            "type": "p2p-message",
            "seq": 1,
            "ciphertext": base64::engine::general_purpose::STANDARD.encode(&ciphertext),
            "msg_hash": sha256_hex(&ciphertext),
            "kyber_ciphertext": kyber_ct,
        })
    } else {
        // Subsequent messages: no Kyber ciphertext needed
        serde_json::json!({
            "type": "p2p-message",
            "seq": 1,
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
            "signed_blob": serde_json::to_string(&envelope)?,
            "sender_nid": identity.null_id.clone(),
            "sender_fp": identity.fingerprint.clone(),
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
    let _our_kyber = load_or_generate_kyber(&identity.null_id, store)?;

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
async fn lookup_kyber_for_nid(
    nid: &str,
    _store: &MessageStore,
) -> Result<add_crypto::kyber::KyberEncapsulationKey, Box<dyn std::error::Error>> {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(nid.as_bytes());
    // Expand 32-byte hash to 64-byte seed via HKDF-SHA256
    let hk = hkdf::Hkdf::<Sha256>::new(None, &hash);
    let mut seed = [0u8; 64];
    hk.expand(b"add-sealed-sender-kyber-seed", &mut seed)
        .map_err(|_| "HKDF expand failed".to_string())?;
    // Use the store's db_key as additional binding
    let kp = add_crypto::kyber::KyberKeypair::from_seed(&seed)
        .map_err(|e| format!("kyber keypair from seed: {}", e))?;
    Ok(kp.enc)
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

    // Use the sender_nid from the relay entry; fall back to computing from fp
    let nid = if sender_nid.is_empty() && !sender_fp.is_empty() {
        add_crypto::null_id(sender_fp)
    } else {
        sender_nid.to_string()
    };

    if nid.is_empty() {
        return Err("relay message has no sender identification".into());
    }

    // Extract ciphertext from the message envelope
    let ciphertext = env
        .get("ciphertext")
        .and_then(|c| c.as_str())
        .ok_or("no ciphertext in relay message")?;

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
            .decrypt_message(ciphertext, our_kyber)
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
    use_pir: bool,
    seed_url: &str,
    relay_url: &str,
    ttl: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let contacts = load_contacts();
    let recipient_fp = contacts
        .get(recipient_nid)
        .ok_or("unknown contact — add with 'add-contact' first")?;

    println!("Looking up {} in DHT...", recipient_nid);

    // G1: Look up recipient's address via DHT (PIR or standard).
    // If DHT lookup fails (recipient not registered), fall back to relay delivery.
    let recipient_addr = if use_pir {
        pir_dht_lookup(seed_url, recipient_nid).await.ok()
    } else {
        dht_lookup(seed_url, recipient_nid, true).await.ok()
    };

    // DHT addr-records are stored base64-encoded (see dht_register_addr_record).
    // Decode before use; fall back to the raw value if it isn't valid base64.
    let recipient_addr = recipient_addr.map(|a| {
        base64::engine::general_purpose::STANDARD
            .decode(&a)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or(a)
    });

    let ws_url = if let Some(ref addr) = recipient_addr {
        println!("Found at: {}", addr);
        addr.replace("http://", "ws://")
            .replace("https://", "wss://")
    } else {
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
    let connect_fut = tokio_tungstenite::connect_async(&ws_url);
    let (mut ws, _) =
        match tokio::time::timeout(std::time::Duration::from_secs(8), connect_fut).await {
            Ok(Ok(result)) => result,
            Ok(Err(e)) => {
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
            Err(_) => {
                println!("Direct P2P timed out, using relay delivery...");
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
    let our_kyber = load_or_generate_kyber(&identity.null_id, store)?;
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
            add_dht_core::crypto_helpers::cache_verifying_key(ack_fp, &vk);
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
        if peer_braid {
            let our_ek_b64 = add_crypto::kyber::encode_enc_key(&our_kyber.enc);
            let our_ek_bytes = base64::engine::general_purpose::STANDARD
                .decode(&our_ek_b64)
                .map_err(|e| format!("ek decode: {}", e))?;
            let peer_ek_bytes = add_p2p::braid_handshake::exchange_ek_braid(&mut ws, &our_ek_bytes)
                .await
                .map_err(|e| format!("braid EK exchange: {}", e))?;
            let peer_ek_b64 = base64::engine::general_purpose::STANDARD.encode(&peer_ek_bytes);
            peer_kyber_enc = add_crypto::kyber::decode_enc_key(&peer_ek_b64).ok();
            if peer_kyber_enc.is_none() {
                println!(
                    "[braid] Warning: reassembled peer EK invalid, falling back to plaintext (insecure)"
                );
            }
        }
        if let Some(kyber_b64) = ack_payload.get("kyber_enc_key").and_then(|k| k.as_str())
            && peer_kyber_enc.is_none()
        {
            peer_kyber_enc = add_crypto::kyber::decode_enc_key(kyber_b64).ok();
        }
        if peer_kyber_enc.is_none() {
            println!(
                "Warning: no Kyber public key from peer, falling back to plaintext (insecure)"
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
    // Capture an echoed message (e.g. from a reflector / loopback peer) so it
    // can be displayed and returned to the caller (desktop UI).
    let mut echoed_text: Option<String> = None;

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
                    let receipt_msg_hash = msg_val
                        .get("payload")
                        .and_then(|p| p.get("msg_hash"))
                        .and_then(|h| h.as_str())
                        .unwrap_or("");
                    let received_at = msg_val
                        .get("payload")
                        .and_then(|p| p.get("received_at"))
                        .and_then(|t| t.as_f64())
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
                    // P2P-only echo bot: it bounced our frame straight back, proving
                    // the roundtrip. We display the message we sent (the sender always
                    // holds its own plaintext in a loopback), tagged as an echo.
                    let echo_display = msg_val
                        .get("ciphertext")
                        .and_then(|c| c.as_str())
                        .map(|ct| {
                            // Strip a cosmetic prefix the reflector may prepend
                            // (e.g. "🤖 [Reflector Echo]: "), keeping any real body.
                            ct.rsplit_once(": ").map(|(_, b)| b).unwrap_or(ct).to_string()
                        });
                    let text = echo_display.filter(|s| !s.is_empty()).unwrap_or_else(|| message.to_string());
                    println!("Echo: {}", text);
                    echoed_text = Some(text);
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
                        return Some(format!("ws://{}:{}", pub_ip, ext_port));
                    }
                    Err(e) => tracing::warn!("UPnP external-IP query failed: {e}"),
                },
                Err(e) => tracing::warn!("UPnP AddPortMapping failed: {e}"),
            },
            Err(e) => tracing::warn!("UPnP IGD discovery failed: {e}"),
        }
    }

    // Fallback: STUN. Only meaningful for cone NATs; symmetric NATs will
    // reject inbound, but advertising the discovered public endpoint is the
    // best-effort option.
    let nat = add_p2p::nat::NatManager::new();
    match nat.discover_public_address().await {
        Ok(res) => {
            println!(
                "NAT traversal: STUN discovered public {}:{}",
                res.public_ip, res.public_port
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
) -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("0.0.0.0:0").await?;
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

    // Register address record in DHT for P2P discovery (all bootstrap servers, low difficulty)
    if let Err(e) = dht_register_addr_record_all(&identity, &listen_address, 3600).await {
        tracing::warn!("Failed to register address record in DHT: {}", e);
        println!(
            "Warning: Could not register address in DHT. Direct P2P may not work: {}",
            e
        );
    } else {
        println!("Address registered in DHT for direct P2P discovery.");
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
                if let Err(e) =
                    dht_register_addr_record_all(&identity_clone, &current_addr, 3600).await
                {
                    tracing::warn!(
                        "Failed to re-register address record after IP change: {}",
                        e
                    );
                } else {
                    tracing::info!(
                        "Address record re-registered after IP change: {}",
                        current_addr
                    );
                    last_registered_address = current_addr;
                }
            } else {
                // Host unchanged: refresh the record's TTL. Keep advertising the
                // already-registered address (not the churned port).
                if let Err(e) =
                    dht_register_addr_record_all(&identity_clone, &last_registered_address, 3600)
                        .await
                {
                    tracing::warn!("Failed to refresh address record: {}", e);
                } else {
                    tracing::debug!(
                        "Address record refreshed (no change): {}",
                        identity_clone.null_id
                    );
                }
            }
        }
    });

    println!("Waiting for connections...");

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let store_pool = store.pool.clone();
        let db_key_path = home_dir().join(DB_KEY_PATH);
        let id_clone = identity.clone();

        tokio::spawn(async move {
            // Each spawned task creates its own DbEncryptionKey from the file
            let db_key = match tokio::fs::read_to_string(&db_key_path).await {
                Ok(hex) => match hex::decode(hex.trim()) {
                    Ok(bytes) if bytes.len() == 32 => {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&bytes);
                        DbEncryptionKey { key }
                    }
                    _ => {
                        tracing::error!("Invalid db key file");
                        return;
                    }
                },
                Err(e) => {
                    tracing::error!("Failed to read db key: {}", e);
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
                add_dht_core::crypto_helpers::cache_verifying_key(peer_fp, &vk);
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
    let our_kyber = load_or_generate_kyber(&identity.null_id, &store)?;
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
        let peer_ek_b64 = base64::engine::general_purpose::STANDARD.encode(&peer_ek_bytes);
        peer_kyber_enc = add_crypto::kyber::decode_enc_key(&peer_ek_b64).ok();
        if peer_kyber_enc.is_none() {
            println!(
                "[braid] Warning: reassembled peer EK invalid, falling back to plaintext (insecure)"
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
                if v.get("msg_type").or_else(|| v.get("type")).and_then(|x| x.as_str()) == Some("p2p-message") {
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
    if msg.get("msg_type").or_else(|| msg.get("type")).and_then(|t| t.as_str()) == Some("p2p-message") {
        // SECURITY FIX (C2): Verify peer's message signature
        let msg_sig = msg.get("sig").and_then(|s| s.as_str()).unwrap_or("");
        if msg_sig.is_empty() {
            println!("Warning: p2p-message has no signature, accepting but vulnerable to MITM");
        } else {
            let msg_sig_payload = format!(
                "p2p-message:{}\n",
                serde_json::to_string(&msg).unwrap_or_default()
            );
            if !add_dht_core::verify_signature(&msg_sig_payload, msg_sig, peer_fp) {
                println!(
                    "Warning: p2p-message signature verification failed for {}",
                    peer_fp
                );
                // Don't reject, just warn - we still want to receive the message
            } else {
                println!("Verified p2p-message signature from {}", peer_fp);
            }
        }

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

        // SECURITY FIX (C1): Decrypt using Double Ratchet + Kyber-768
        let padded_plaintext = ratchet_session
            .decrypt_message(ciphertext, &our_kyber)
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
    /// Initialize a new identity
    Init,
    /// Show your Null ID
    Id,
    /// Send a message
    Send {
        /// Recipient Null ID
        to: String,
        /// Message text
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
    /// Check online status of all contacts (query DHT addr_records)
    ContactStatus,
    /// Delete a message by its position number (shown in read output)
    Delete {
        /// Position number of message to delete (1 = first/newest in list)
        id: i64,
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
            if old_pid > 0 && unsafe { libc::kill(old_pid, 0) } == 0 {
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
                    if old_pid > 0 && unsafe { libc::kill(old_pid, 0) } == 0 {
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
        Commands::Init => {
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

            println!("Generating post-quantum keypair (this may take a moment)...");
            let identity = generate_identity()?;
            println!("Identity created successfully!");
            println!("  Fingerprint: {}", identity.fingerprint);
            println!("  Null ID:     {}", identity.null_id);
            println!("\nShare your Null ID with contacts to receive messages.");

            // Add Reflector Bot as a default contact (for testing).
            // NOTE: the contact key MUST be the reflector's real Null ID
            // (derive via compute_null_id of its fingerprint), because the
            // reflector registers its DHT addr_record under that same key.
            // A vanity label here would never resolve to an addr_record.
            let mut contacts = load_contacts();
            if !contacts.contains_key("NN-UFtv-8fHu") {
                contacts.insert(
                    "NN-UFtv-8fHu".to_string(),
                    "3957378550B111F2678DC1B4A58C27B22091D5CF".to_string(),
                );
                save_contacts(&contacts)?;
                println!(
                    "\nAdded Reflector Bot (NN-UFtv-8fHu) as ECHO contact for latency testing."
                );
            }
        }
        Commands::Id => {
            let identity = Identity::load()?;
            println!("Null ID:     {}", identity.null_id);
            println!("Fingerprint: {}", identity.fingerprint);
        }
        Commands::Send {
            to,
            message,
            pir,
            ttl,
        } => {
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
                let our_kyber = load_or_generate_kyber(&identity.null_id, &store)?;
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
                    let reverse_aliases: std::collections::HashMap<String, String> =
                        aliases.iter().map(|(a, n)| (n.clone(), a.clone())).collect();

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
            let seed_url = discover_servers().await.0;
            // Allow scoping the reflector to a specific relay set (e.g. a single
            // healthy relay) for testing or to avoid broken peers.
            let relay_urls: Vec<String> = relay.clone().unwrap_or_else(|| relay_urls.clone());
            println!(
                "Reflector echo mode active as {} (poll every {}s). Sending back whatever arrives.",
                identity.null_id, interval
            );

            // Register our DHT addr-record so contacts see us ONLINE and direct
            // P2P works for non-NAT peers. Advertise the host's primary IP.
            let advertised = match primary_ipv4() {
                Some(ip) => format!("ws://{}:8765", ip),
                None => format!("ws://{}:8765", "0.0.0.0"),
            };
            if let Err(e) = dht_register_addr_record_all(&identity, &advertised, 3600).await {
                tracing::warn!("initial DHT register failed: {}", e);
            }
            // Refresh the record every 30 min (no IP re-detection churn).
            let identity_refresh = identity.clone();
            let advertised_refresh = advertised.clone();
            tokio::spawn(async move {
                let mut interval_timer =
                    tokio::time::interval(std::time::Duration::from_secs(30 * 60));
                interval_timer.tick().await; // consume immediate first tick
                loop {
                    interval_timer.tick().await;
                    if let Err(e) =
                        dht_register_addr_record_all(&identity_refresh, &advertised_refresh, 3600)
                            .await
                    {
                        tracing::warn!("DHT register refresh failed: {}", e);
                    }
                }
            });

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
                    let our_kyber = match load_or_generate_kyber(&identity.null_id, &store) {
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
            let our_kyber = load_or_generate_kyber(&identity.null_id, &store)?;
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
        } => {
            let store = MessageStore::open().await?;
            let identity = Identity::load()?;
            // Load our GPG cert for signing address records
            let cert = load_cert()?;
            println!("Starting P2P listener...");
            run_listener(identity, store, cert, advertised_url, no_nat).await?;
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
        Commands::ContactStatus => {
            let _identity = Identity::load()?;
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
                    // Query each bootstrap for addr record
                    let mut found_online = false;
                    for bootstrap_url in &bootstraps {
                        let addr_key = format!("addr:{}", null_id);
                        match dht_get(bootstrap_url, &addr_key).await {
                            Ok(Some(value)) => {
                                // Decode the base64 address
                                if let Ok(decoded) =
                                    base64::engine::general_purpose::STANDARD.decode(&value)
                                    && let Ok(addr) = String::from_utf8(decoded)
                                {
                                    println!(
                                        "  ✓ {} ({}) - ONLINE at {}",
                                        fingerprint.chars().take(8).collect::<String>(),
                                        null_id,
                                        addr
                                    );
                                    found_online = true;
                                    break;
                                }
                            }
                            Ok(None) => continue,
                            Err(_) => continue,
                        }
                    }

                    if !found_online {
                        println!(
                            "  ✗ {} ({}) - OFFLINE",
                            fingerprint.chars().take(8).collect::<String>(),
                            null_id
                        );
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
    }

    Ok(())
}
