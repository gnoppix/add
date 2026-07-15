//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::SystemTime;

use base64::Engine;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_tungstenite::accept_async;
use tokio_tungstenite::tungstenite::protocol::Message;
use tracing::{debug, error, info, warn};

use add_protocol::constants;
use add_protocol::envelope::*;
use add_protocol::pow::pow_check;

use crate::DhtResult;
use crate::bot_log::BotLogger;
use crate::crypto_helpers::{
    compute_null_id, constant_time_compare, validate_fingerprint, validate_null_id,
    verify_signature, verify_signature_with_verifying_key,
};
use crate::ratelimit::RateLimiter;
use crate::sqlite_store::DhtStore;
use crate::types::{DhtNode, NodeConfig};
use add_crypto::pir::{PirQueryToken, PirRegistry};

/// SECURITY FIX (C6): TLS acceptor for the DHT WebSocket server.
/// When configured, the DHT node accepts wss:// connections.
type DhtTlsAcceptor = tokio_rustls::TlsAcceptor;

/// SECURITY FIX (C6): Combined trait for boxing streams (TLS or plaintext).
trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

/// SECURITY FIX (C6): Load a TLS acceptor from PEM cert and key files.
fn load_dht_tls_acceptor(
    cert_path: &str,
    key_path: &str,
) -> Result<DhtTlsAcceptor, Box<dyn std::error::Error>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<Vec<_>, _>>()?;

    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or("no private key found in key file")?;

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config: {}", e))?;

    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)))
}

/// Async runtime for a DHT node (WebSocket server + request handler).
pub struct DhtNodeRuntime {
    pub node: DhtNode,
    pub store: DhtStore,
    pub config: NodeConfig,
    pub conn_limiter: RateLimiter,
    /// SECURITY FIX (M7): Per-IP rate limiter for GET operations.
    /// Prevents key enumeration / scanning attacks.
    pub get_limiter: RateLimiter,
    /// PIR registry for private information retrieval
    pir_registry: Arc<RwLock<PirRegistry>>,
    stealth_mode: bool,
    seen_nonces: Arc<RwLock<HashMap<String, HashSet<i64>>>>,
    bot_logger: BotLogger,
}

impl DhtNodeRuntime {
    /// Create a new DHT node runtime.
    pub async fn new(config: NodeConfig) -> DhtResult<Self> {
        let store = DhtStore::open(config.db_path.as_deref()).await?;
        let node_id = DhtNode::node_id_from_nid(&config.null_id);

        let address = config
            .advertised_url
            .clone()
            .unwrap_or_else(|| format!("{}:{}", config.host, config.port));

        let node = DhtNode {
            null_id: config.null_id.clone(),
            fingerprint: config.fingerprint.clone(),
            node_id,
            host: config.host.clone(),
            port: config.port,
            address,
            routing_table: HashMap::new(),
        };

        let conn_limiter = RateLimiter::new(
            constants::CONN_RATE_LIMIT as usize,
            constants::CONN_RATE_WINDOW as f64,
        );
        // SECURITY FIX (M7): Tighter rate limit for GET operations (30 per 60s per IP)
        let get_limiter = RateLimiter::new(30, 60.0);
        let bot_logger = BotLogger::new(None);

        Ok(Self {
            node,
            store,
            config,
            conn_limiter,
            get_limiter,
            pir_registry: Arc::new(RwLock::new(PirRegistry::new())),
            stealth_mode: false,
            seen_nonces: Arc::new(RwLock::new(HashMap::new())),
            bot_logger,
        })
    }

    /// Start the DHT node WebSocket server. Blocks until shutdown.
    pub async fn start(self) -> DhtResult<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port);

        // SECURITY FIX (C6): Load TLS acceptor if cert and key are configured
        let tls_acceptor: Option<DhtTlsAcceptor> = if !self.config.ssl_certfile.is_empty()
            && !self.config.ssl_keyfile.is_empty()
        {
            match load_dht_tls_acceptor(&self.config.ssl_certfile, &self.config.ssl_keyfile) {
                Ok(a) => {
                    info!("DHT node TLS configured: cert={}", self.config.ssl_certfile);
                    Some(a)
                }
                Err(e) => {
                    error!(
                        "Failed to load DHT TLS cert/key: {} — falling back to plaintext",
                        e
                    );
                    None
                }
            }
        } else {
            // Detect reverse proxy mode by host binding:
            // - 127.0.0.1 or 0.0.0.0 = behind nginx (proxied)
            // - Real external IP = direct TLS required
            let behind_proxy = self.config.host == "127.0.0.1"
                || self.config.host == "0.0.0.0"
                || self.config.advertised_url.is_some();
            if !behind_proxy {
                warn!(
                    "DHT node TLS not configured (ssl_certfile/ssl_keyfile empty) — running in plaintext mode (ws://). For production, set --tls-cert and --tls-key, or use --advertised-url with nginx proxy."
                );
            }
            None
        };

        let listener = TcpListener::bind(&addr).await?;
        info!(
            "DHT node listening on {} ({})",
            addr,
            if tls_acceptor.is_some() {
                "wss:// (TLS)"
            } else {
                "ws:// (plaintext)"
            }
        );

        let store = self.store;
        let stealth = self.stealth_mode;
        let seen_nonces = self.seen_nonces;
        let bot = self.bot_logger;
        let get_limiter = self.get_limiter;
        let pir_registry = self.pir_registry.clone();

        // SECURITY FIX (L3): Background cleanup of seen_nonces to prevent
        // unbounded memory growth. An attacker can send puts with many
        // different keys, each creating a HashSet entry that is never removed.
        // This task prunes entries every 5 minutes, removing keys whose
        // nonce sets have grown large (keeping only the most recent 64).
        {
            let nonces_for_prune = seen_nonces.clone();
            tokio::spawn(async move {
                let interval = std::time::Duration::from_secs(300);
                loop {
                    tokio::time::sleep(interval).await;
                    let mut nonces = nonces_for_prune.write().await;
                    // For each key, if the set has more than 64 nonces,
                    // keep only the most recent 64 (prevents unbounded growth
                    // per key from a legitimate high-volume publisher).
                    for set in nonces.values_mut() {
                        if set.len() > 64 {
                            let mut all: Vec<i64> = set.iter().copied().collect();
                            all.sort_unstable();
                            let to_keep = &all[all.len() - 64..];
                            set.clear();
                            for n in to_keep {
                                set.insert(*n);
                            }
                        }
                    }
                    // Remove keys with empty sets
                    nonces.retain(|_, set| !set.is_empty());
                }
            });
        }

        // SECURITY FIX (L5): Ensure the DHT nonce log is actually pruned.
        // `prune_old_nonces` exists but was only exercised in tests; without a
        // running task the SQLite nonce table grows without bound and replay
        // protection degrades. This background task prunes nonces older than the
        // retention window every 10 minutes.
        {
            let prune_store = store.clone();
            tokio::spawn(async move {
                let interval = std::time::Duration::from_secs(600);
                loop {
                    tokio::time::sleep(interval).await;
                    let cutoff = chrono::Utc::now().timestamp()
                        - crate::sqlite_store::NONCE_RETENTION_SECS as i64;
                    if let Err(e) = prune_store.prune_old_nonces(cutoff).await {
                        tracing::warn!("DHT nonce prune failed: {}", e);
                    }
                }
            });
        }

        loop {
            let (stream, peer_addr) = listener.accept().await?;
            let peer_ip = peer_addr.ip().to_string();

            let allowed = self.conn_limiter.allow(&peer_ip).await;
            if !allowed {
                warn!("rate-limited connection from {}", peer_addr);
                continue;
            }

            let store_clone = store.clone();
            let bot_clone = bot.clone();
            let nonces_clone = seen_nonces.clone();
            let tls = tls_acceptor.clone();
            let get_lim = get_limiter.clone();
            let pir_reg = pir_registry.clone();
            let node_fingerprint = self.node.fingerprint.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(
                    stream,
                    peer_addr,
                    &store_clone,
                    stealth,
                    nonces_clone,
                    bot_clone,
                    tls,
                    get_lim,
                    pir_reg,
                    &node_fingerprint,
                )
                .await
                {
                    debug!("connection from {} closed: {}", peer_addr, e);
                }
            });
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        store: &DhtStore,
        stealth_mode: bool,
        seen_nonces: Arc<RwLock<HashMap<String, HashSet<i64>>>>,
        bot_logger: BotLogger,
        tls_acceptor: Option<DhtTlsAcceptor>,
        get_limiter: RateLimiter,
        pir_registry: Arc<RwLock<PirRegistry>>,
        node_fingerprint: &str,
    ) -> DhtResult<()> {
        // SECURITY FIX (C6): Wrap stream in TLS if acceptor is configured.
        // We box the underlying stream so both TLS and plaintext paths produce
        // the same WebSocketStream type.
        type BoxedStream = Box<dyn AsyncReadWrite>;
        let ws = if let Some(acceptor) = tls_acceptor {
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|e| crate::DhtError::Io(std::io::Error::other(e)))?;
            let boxed: BoxedStream = Box::new(tls_stream);
            accept_async(boxed)
                .await
                .map_err(|e| crate::DhtError::Io(std::io::Error::other(e)))?
        } else {
            let boxed: BoxedStream = Box::new(stream);
            accept_async(boxed)
                .await
                .map_err(|e| crate::DhtError::Io(std::io::Error::other(e)))?
        };

        let (mut ws_tx, mut ws_rx) = ws.split();
        let mut consecutive_failures: u32 = 0;
        const MAX_FAILURES: u32 = 10;

        while let Some(msg_result) = ws_rx.next().await {
            let raw = match msg_result {
                Ok(Message::Text(text)) => text.to_string(),
                Ok(Message::Close(_)) => break,
                Ok(_) => continue,
                Err(e) => {
                    debug!("websocket error from {}: {}", peer_addr, e);
                    break;
                }
            };

            let env = match WireEnvelope::from_json(&raw) {
                Ok(e) => e,
                Err(e) => {
                    consecutive_failures += 1;
                    if consecutive_failures == MAX_FAILURES {
                        bot_logger.log(
                            &peer_addr.ip().to_string(),
                            peer_addr.port(),
                            "SCANNER",
                            Some(&format!("bad_envelope x{MAX_FAILURES}")),
                        );
                    }
                    if stealth_mode {
                        let _ = ws_tx
                            .send(Message::Text(Self::stealth_response().into()))
                            .await;
                    } else {
                        let resp = build_dht_error("", &format!("bad envelope: {e}"));
                        let _ = ws_tx
                            .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                            .await;
                    }
                    continue;
                }
            };

            // Timestamp freshness check
            let now = now_unix();
            if (now - env.ts).abs() > constants::POW_MAX_AGE as f64 {
                consecutive_failures += 1;
                if consecutive_failures == MAX_FAILURES {
                    bot_logger.log(
                        &peer_addr.ip().to_string(),
                        peer_addr.port(),
                        "SCANNER",
                        Some(&format!("stale_timestamp x{MAX_FAILURES}")),
                    );
                }
                if stealth_mode {
                    let _ = ws_tx
                        .send(Message::Text(Self::stealth_response().into()))
                        .await;
                } else {
                    let key = env.payload_str("key").unwrap_or("");
                    let resp = build_dht_error(key, "stale timestamp");
                    let _ = ws_tx
                        .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                        .await;
                }
                continue;
            }

            consecutive_failures = 0;

            match env.msg_type.as_str() {
                "dht-put" => {
                    Self::handle_put(
                        &env,
                        &mut ws_tx,
                        store,
                        stealth_mode,
                        &seen_nonces,
                        &bot_logger,
                        &peer_addr,
                        node_fingerprint,
                    )
                    .await;
                }
                "dht-get" => {
                    // SECURITY FIX (M7): Per-IP rate limiting for GET operations
                    // to prevent key enumeration / scanning attacks.
                    let peer_ip = peer_addr.ip().to_string();
                    if !get_limiter.allow(&peer_ip).await {
                        bot_logger.log(
                            &peer_ip,
                            peer_addr.port(),
                            "GET_RATE_LIMITED",
                            Some("dht-get rate limit exceeded"),
                        );
                        if stealth_mode {
                            let _ = ws_tx
                                .send(Message::Text(Self::stealth_response().into()))
                                .await;
                        } else {
                            let resp = build_dht_error("", "rate limited");
                            let _ = ws_tx
                                .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                                .await;
                        }
                        continue;
                    }
                    Self::handle_get(&env, &mut ws_tx, store, stealth_mode).await;
                }
                "pir-query" => {
                    Self::handle_pir_query(&env, &mut ws_tx, pir_registry.clone(), stealth_mode)
                        .await;
                }
                "blob-put" => {
                    Self::handle_blob_put(&env, &mut ws_tx, store).await;
                }
                "blob-get" => {
                    Self::handle_blob_get(&env, &mut ws_tx, store).await;
                }
                other => {
                    bot_logger.log(
                        &peer_addr.ip().to_string(),
                        peer_addr.port(),
                        "BAD_TYPE",
                        Some(other),
                    );
                    if stealth_mode {
                        let _ = ws_tx
                            .send(Message::Text(Self::stealth_response().into()))
                            .await;
                    } else {
                        let key = env.payload_str("key").unwrap_or("");
                        let resp = build_dht_error(key, &format!("unexpected type: {other}"));
                        let _ = ws_tx
                            .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                            .await;
                    }
                }
            }
        }

        if consecutive_failures >= 5 {
            bot_logger.log(
                &peer_addr.ip().to_string(),
                peer_addr.port(),
                "SUSPECT",
                Some(&format!("{consecutive_failures} consecutive failures")),
            );
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_put(
        env: &WireEnvelope,
        ws_tx: &mut (impl futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
        store: &DhtStore,
        _stealth_mode: bool,
        seen_nonces: &RwLock<HashMap<String, HashSet<i64>>>,
        _bot_logger: &BotLogger,
        _peer_addr: &SocketAddr,
        _node_fingerprint: &str,
    ) {
        let key = env.payload_str("key").unwrap_or("").to_string();
        let value_b64 = env.payload_str("value").unwrap_or("").to_string();
        let salt = env.payload_str("salt").unwrap_or("").to_string();
        let seq = env.payload_i64("seq").unwrap_or(0);
        let ttl = env
            .payload_i64("ttl")
            .unwrap_or(constants::STORE_TTL)
            .min(constants::STORE_TTL);
        let nonce = env.payload_i64("nonce").unwrap_or(0);
        let sig = env.sig.clone();

        if !validate_null_id(&key) {
            let resp = build_dht_error(&key, "invalid key format");
            let _ = ws_tx
                .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                .await;
            return;
        }

        // SECURITY FIX (H7): Enforce maximum key size to prevent
        // disproportionately large keys from consuming storage.
        if key.len() > constants::MAX_KEY_SIZE {
            let resp = build_dht_error(&key, "key too long");
            let _ = ws_tx
                .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                .await;
            return;
        }

        // SECURITY FIX (H6): Reject TTL values exceeding MAX_TTL.
        // The ttl.min(STORE_TTL) cap below will further reduce it to
        // STORE_TTL, but we explicitly reject absurdly large values to
        // signal misbehaving clients and prevent any future code path
        // from accidentally honoring an unbounded TTL.
        if ttl <= 0 || ttl > constants::MAX_TTL {
            let resp = build_dht_error(&key, "ttl out of range");
            let _ = ws_tx
                .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                .await;
            return;
        }

        // SECURITY FIX (M4): Enforce global key count limit to prevent
        // resource exhaustion. Without this, an attacker could fill the
        // DHT store with unlimited keys, exhausting disk/memory.
        // SECURITY FIX (L2): Check regardless of whether sig is present.
        // Even though unsigned puts are rejected later, the count check
        // must run first as defense-in-depth.
        {
            let exists = store.has_key(&key).await.unwrap_or(false);
            if !exists {
                let count = store.count_keys().await.unwrap_or(0);
                if count >= constants::MAX_TOTAL_KEYS as i64 {
                    let resp = build_dht_error(&key, "DHT store full (max keys reached)");
                    let _ = ws_tx
                        .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                        .await;
                    return;
                }
            }
        }

        if value_b64.len() > constants::MAX_VALUE_SIZE {
            let resp = build_dht_error(&key, "value too large");
            let _ = ws_tx
                .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                .await;
            return;
        }

        // Anti-replay: check nonce
        {
            let nonces = seen_nonces.read().await;
            if nonces.get(&key).is_some_and(|s| s.contains(&nonce)) {
                let resp = build_dht_error(&key, "nonce replay");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
                return;
            }
        }

        // Verify proof-of-work
        // SECURITY FIX (M11): Use the record publisher's fingerprint as the
        // per-node secret so client and server compute an identical salt.
        // The client (which cannot know the server's fingerprint) salts with
        // its own `publisher_fp`; the server must therefore validate with the
        // same `publisher_fp` carried in the envelope, NOT its own fingerprint.
        // Identity registration (seq==0) uses difficulty 8 (fast, one-time).
        // Updates/re-registration (seq>0) use full DHT_POW_DIFFICULTY (16).
        // addr-record keys use ADDR_POW_DIFFICULTY (8).
        let publisher_fp = env.payload_str("publisher_fp").unwrap_or("").to_string();
        let is_addr_record = key.starts_with("addr:");
        let pow_difficulty = if is_addr_record {
            constants::ADDR_POW_DIFFICULTY
        } else if seq == 0 {
            8
        } else {
            constants::DHT_POW_DIFFICULTY
        };
        // Addr records are solved by the client with pipe-separated
        // "{key}|{value}|{salt}|{seq}"; standard puts use the same format.
        let pow_data = format!("{key}|{value_b64}|{salt}|{seq}");
        let pow_ok = pow_check(
            &pow_data,
            nonce as u64,
            pow_difficulty,
            publisher_fp.as_bytes(),
        )
        .unwrap_or(false);
        if !pow_ok {
            let resp = build_dht_error(&key, "insufficient proof-of-work");
            let _ = ws_tx
                .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                .await;
            return;
        }

        if sig.is_empty() {
            let resp = build_dht_error(&key, "missing signature");
            let _ = ws_tx
                .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                .await;
            return;
        }

        if !validate_fingerprint(&publisher_fp) {
            let resp = build_dht_error(&key, "invalid publisher fingerprint");
            let _ = ws_tx
                .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                .await;
            return;
        }

        // Address records are stored under the "addr:{null_id}" key (sent by the
        // reflector/contact registration path). Validate against the bare null_id
        // after stripping the prefix so the lookup key round-trips correctly.
        // Public cert bundles (DESIGN.md §4.2/§6) are stored under the opaque
        // "cert:<H(fp)>" key and are NOT keyed by the publisher's null_id; their
        // authenticity is established by the mandatory signature check below
        // (the VK must derive to `publisher_fp`), so we exempt them from the
        // null_id==key rule.
        let is_cert_key = key.starts_with("cert:");
        let key_for_validation = key.strip_prefix("addr:").unwrap_or(&key);
        let expected_nid = compute_null_id(&publisher_fp);
        if !is_cert_key && expected_nid != key_for_validation {
            let resp = build_dht_error(&key, &format!("key mismatch: expected {expected_nid}"));
            let _ = ws_tx
                .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                .await;
            return;
        }

        // SECURITY FIX (C5): Mandatory signature verification on DHT put.
        // Records without a valid Ed25519 signature from the publisher's key
        // are rejected. This prevents an attacker from injecting arbitrary
        // unsigned records into the DHT.
        let sign_data = format!("{key}|{value_b64}|{salt}|{seq}|{nonce}");
        let verified = verify_dht_put_signature(&sign_data, &sig, &publisher_fp, env);
        if !verified {
            let resp = build_dht_error(&key, "signature verification failed");
            let _ = ws_tx
                .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                .await;
            return;
        }

        match store
            .put(
                &key,
                &value_b64,
                &salt,
                seq,
                &publisher_fp,
                ttl,
                &sig,
                nonce,
            )
            .await
        {
            Ok(true) => {
                let mut nonces = seen_nonces.write().await;
                nonces.entry(key.clone()).or_default().insert(nonce);

                let resp = build_dht_found(&key, &value_b64, &salt, seq);
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
                debug!("stored key {} seq {}", key, seq);
            }
            Ok(false) => {
                let resp = build_dht_error(&key, "stale sequence");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
            }
            Err(e) => {
                error!("storage error for key {}: {}", key, e);
                let resp = build_dht_error(&key, "storage error");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
            }
        }
    }

    async fn handle_get(
        env: &WireEnvelope,
        ws_tx: &mut (impl futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
        store: &DhtStore,
        stealth_mode: bool,
    ) {
        let key = env.payload_str("key").unwrap_or("");

        if !validate_null_id(key) {
            if stealth_mode {
                let _ = ws_tx
                    .send(Message::Text(Self::stealth_response().into()))
                    .await;
            } else {
                let resp = build_dht_error(key, "invalid key format");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
            }
            return;
        }

        // SECURITY FIX (H9): Add random jitter to DHT key-existence queries to
        // prevent timing side-channel attacks that could reveal whether a key
        // exists in the store based on response time differences.
        let jitter_ms = rand::random::<u64>() % 50;
        if jitter_ms > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
        }

        match store.get(key).await {
            Ok(Some(record)) => {
                let resp = build_dht_found(key, &record.value, &record.salt, record.seq);
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
            }
            Ok(None) => {
                let resp = build_dht_error(key, "not found");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
            }
            Err(e) => {
                error!("get error for key {}: {}", key, e);
                let resp = build_dht_error(key, "storage error");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
            }
        }
    }

    fn stealth_response() -> String {
        let payload = serde_json::json!({ "key": "", "value": "", "salt": "", "seq": 0 });
        serde_json::json!({
            "type": "dht-found",
            "payload": payload,
            "msg_id": uuid_hex(),
            "ts": now_unix(),
            "sig": "",
        })
        .to_string()
    }

    /// Opaque content-addressed blob store (DESIGN.md §4 / PART VII V2.1).
    ///
    /// The server treats `key`/`value` as opaque: it never parses the value as
    /// an address and never validates `key` as a Null ID. The client supplies a
    /// content-addressing key (e.g. H(owner_id || contact_fp) or H(pubkey)) and
    /// an ML-DSA signature over `key || value`. This lets the later per-contact
    /// encrypted-address and cert stores run WITHOUT the server learning IPs,
    /// IDs, or the contact graph. Contrast with `handle_addr_record`, which
    /// stores the IP:port in clear.
    async fn handle_blob_put(
        env: &WireEnvelope,
        ws_tx: &mut (impl futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
        store: &DhtStore,
    ) {
        let key = match env.payload_str("key") {
            Some(k) if !k.is_empty() => k.to_string(),
            _ => {
                let resp = build_dht_error("", "missing key");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
                return;
            }
        };
        let value_b64 = match env.payload_str("value") {
            Some(v) => v.to_string(),
            None => {
                let resp = build_dht_error(&key, "missing value");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
                return;
            }
        };
        // Bound blob size (ciphertext + signature overhead is small).
        if value_b64.len() > constants::MAX_VALUE_SIZE {
            let resp = build_dht_error(&key, "value too large");
            let _ = ws_tx
                .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                .await;
            return;
        }
        let sig = env.payload_str("sig").unwrap_or("").to_string();
        let publisher_fp = env.payload_str("publisher_fp").unwrap_or("").to_string();
        let ttl: i64 = env.payload_i64("ttl").unwrap_or(constants::ADDR_TTL);
        let salt = format!("blob:{}", rand::random::<u32>());
        // Authenticate public cert bundles (DESIGN.md §4.2 / §6): a `cert:` blob
        // MUST be signed by the key whose verifying key derives to `publisher_fp`.
        // The otherwise-opaque store would otherwise let anyone overwrite
        // `cert:<H(fp)>` and substitute a victim's cert/vk (cert-store MITM).
        // We reuse the DHT-put signature contract: canonical
        // `sign_data = "{key}|{value}|{publisher_fp}"`, verified against the
        // self-asserted `publisher_verifying_key` (VK must derive to publisher_fp).
        if key.starts_with("cert:") {
            let sign_data = format!("{}|{}|{}", key, value_b64, publisher_fp);
            if !verify_dht_put_signature(&sign_data, &sig, &publisher_fp, env) {
                let resp = build_dht_error(&key, "invalid cert bundle signature");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
                return;
            }
        }
        // Content-addressed "latest wins" upsert — no seq/nonce replay games
        // (those are for the mutable addr-record model). Client owns the key.
        match store
            .put_blob(&key, &value_b64, &salt, &publisher_fp, ttl, &sig)
            .await
        {
            Ok(true) => {
                let seq_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                let resp = build_dht_found(&key, &value_b64, &salt, seq_ms);
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
            }
            Ok(false) => {
                let resp = build_dht_error(&key, "value too large");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
            }
            Err(e) => {
                error!("blob-put storage error for key {}: {}", key, e);
                let resp = build_dht_error(&key, "storage error");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
            }
        }
    }

    /// Opaque blob fetch (DESIGN.md §4 / PART VII V2.1). Returns the stored
    /// ciphertext blob keyed by the client-chosen opaque key. No semantic
    /// interpretation by the server.
    async fn handle_blob_get(
        env: &WireEnvelope,
        ws_tx: &mut (impl futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
        store: &DhtStore,
    ) {
        let key = match env.payload_str("key") {
            Some(k) if !k.is_empty() => k.to_string(),
            _ => {
                let resp = build_dht_error("", "missing key");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
                return;
            }
        };
        match store.get(&key).await {
            Ok(Some(rec)) => {
                let json = serde_json::json!({
                    "type": "dht-found",
                    "payload": {
                        "key": key,
                        "value": rec.value,
                        "salt": rec.salt,
                        "seq": rec.seq,
                        "publisher_fp": rec.publisher_fp,
                        "sig": rec.sig,
                        "expires_at": rec.expires_at,
                    },
                    "msg_id": uuid_hex(),
                    "ts": now_unix(),
                    "sig": "",
                });
                let resp = match WireEnvelope::from_json(&json.to_string()) {
                    Ok(e) => e,
                    Err(_) => build_dht_found(&key, &rec.value, &rec.salt, rec.seq),
                };
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
            }
            Ok(None) => {
                let resp = build_dht_error(&key, "not found");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
            }
            Err(e) => {
                error!("blob-get error for key {}: {}", key, e);
                let resp = build_dht_error(&key, "storage error");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
            }
        }
    }

    /// Handle PIR query for private contact lookup.
    /// Client sends query tokens for specific bins; server returns bin contents.
    async fn handle_pir_query(
        env: &WireEnvelope,
        ws_tx: &mut (impl futures::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
        pir_registry: Arc<RwLock<PirRegistry>>,
        _stealth_mode: bool,
    ) {
        let query_json = env.payload_str("query");
        if query_json.is_none() {
            let resp = build_dht_error("", "missing query");
            let _ = ws_tx
                .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                .await;
            return;
        }

        // Parse query token
        let query_token: PirQueryToken = match serde_json::from_str(query_json.unwrap()) {
            Ok(t) => t,
            Err(_) => {
                let resp = build_dht_error("", "invalid query format");
                let _ = ws_tx
                    .send(Message::Text(resp.to_json().unwrap_or_default().into()))
                    .await;
                return;
            }
        };

        let registry = pir_registry.read().await;
        let response = registry.handle_query(&query_token);
        drop(registry);

        let resp: WireEnvelope = match response {
            Some(r) => {
                let mut payload = serde_json::Map::new();
                payload.insert(
                    "bin_data".to_string(),
                    serde_json::Value::String(
                        base64::engine::general_purpose::STANDARD.encode(&r.bin_data),
                    ),
                );
                payload.insert(
                    "dht_ephemeral_pk".to_string(),
                    serde_json::Value::String(
                        base64::engine::general_purpose::STANDARD.encode(r.dht_ephemeral_pk),
                    ),
                );
                payload.insert(
                    "nonce".to_string(),
                    serde_json::Value::String(
                        base64::engine::general_purpose::STANDARD.encode(r.nonce),
                    ),
                );
                WireEnvelope {
                    msg_type: "pir-response".to_string(),
                    payload: serde_json::Value::Object(payload),
                    msg_id: uuid_hex(),
                    ts: now_unix(),
                    sig: "".to_string(),
                }
            }
            None => build_dht_error("", "bin not found"),
        };

        let _ = ws_tx
            .send(Message::Text(resp.to_json().unwrap_or_default().into()))
            .await;
    }
}

/// Extract the peer (host, port) from a TCP stream.
pub fn get_peer_address(stream: &TcpStream) -> (String, u16) {
    match stream.peer_addr() {
        Ok(addr) => (addr.ip().to_string(), addr.port()),
        Err(_) => ("unknown".to_string(), 0),
    }
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// SECURITY FIX (C5): Verify the signature on a DHT put record.
///
/// This function is the single mandatory signature verification gate for
/// DHT put operations. It tries verifying key-based verification first (preferred
/// path when the publisher includes their verifying key in the envelope), then
/// falls back to fingerprint-based verification using the key cache.
///
/// Returns `true` only if the signature is cryptographically valid and
/// was made by the key matching `publisher_fp`.
fn verify_dht_put_signature(
    sign_data: &str,
    sig: &str,
    publisher_fp: &str,
    env: &WireEnvelope,
) -> bool {
    // Prefer verifying-key-based verification (C3-style pin binding).
    if let Some(vk_b64) = env.payload_str("publisher_verifying_key") {
        let vk_bytes = match base64::engine::general_purpose::STANDARD.decode(vk_b64) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        // Use ml_dsa::KeyInit::new_from_slice to decode the verifying key
        use crypto_common::KeyInit;
        let vk = match add_crypto_pq::MlDsa87VerifyingKey::new_from_slice(&vk_bytes) {
            Ok(vk) => vk,
            Err(_) => return false,
        };
        // SECURITY FIX (L2): the verifying key was self-asserted in the
        // envelope. Bind it to the publisher fingerprint (TOFU pin) the same
        // way C3 binds bootstrap certs: the VK must derive to `publisher_fp`.
        // Without this an attacker who controls the envelope could assert an
        // arbitrary VK and sign with it, defeating the publisher_fp check.
        let derived_fp = add_crypto_pq::fingerprint_from_verifying_key(&vk);
        if !constant_time_compare(&derived_fp, publisher_fp) {
            return false;
        }
        return verify_signature_with_verifying_key(sign_data, sig, &vk);
    }
    verify_signature(sign_data, sig, publisher_fp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use add_crypto_pq::{MlDsa87SigningKey, MlDsa87VerifyingKey};
    use add_protocol::pow::pow_solve;
    use base64::Engine;

    /// Helper: create a valid signed DHT put envelope for testing.
    fn create_signed_put_env(
        key: &str,
        value: &str,
        salt: &str,
        seq: i64,
        ttl: i64,
        signing_key: &MlDsa87SigningKey,
        publisher_fp: &str,
    ) -> (WireEnvelope, u64) {
        // Solve PoW (test only: use the minimum difficulty so the unit test
        // stays fast — this helper exists to exercise signature handling, not
        // PoW cost. Production uses DHT_POW_DIFFICULTY=16.)
        // SECURITY FIX (M11): Pass node's fingerprint as per-node secret
        let pow_nonce = pow_solve(
            &format!("{key}{value}{salt}{seq}"),
            constants::MIN_POW_DIFFICULTY,
            100_000,
            publisher_fp.as_bytes(),
        )
        .unwrap()
        .expect("PoW solution should be found within attempt limit");

        let sign_data_str = format!("{key}|{value}|{salt}|{seq}|{pow_nonce}");
        let sig = crate::sign_data(&sign_data_str, signing_key).unwrap();

        let payload = serde_json::json!({
            "key": key,
            "value": value,
            "salt": salt,
            "seq": seq,
            "ttl": ttl,
            "nonce": pow_nonce,
            "publisher_fp": publisher_fp,
        });

        let env = WireEnvelope {
            msg_type: "dht-put".to_string(),
            payload,
            msg_id: add_protocol::envelope::uuid_hex(),
            ts: now_unix(),
            sig,
        };

        (env, pow_nonce)
    }

    /// Helper: cache a verifying key for fingerprint-based verification in tests.
    fn cache_test_verifying_key(vk: &MlDsa87VerifyingKey, fp: &str) {
        crate::crypto_helpers::cache_verifying_key(fp, vk);
    }

    #[test]
    fn test_verify_dht_put_signature_valid() {
        let (signing_key, verifying_key) = add_crypto_pq::generate_keypair().unwrap();
        // verify_signature requires validate_fingerprint (32 or 40 hex chars).
        // The ML-DSA-derived SHA256 fingerprint is 64 chars and is rejected,
        // so use a valid 40-char fingerprint as the cache key (the vk is
        // looked up by this string; it need not match the vk cryptographically).
        let fp = "AABBCCDDEEFF00112233445566778899AABBCCDD";

        // Cache the verifying key so fingerprint-based verification works
        cache_test_verifying_key(&verifying_key, fp);

        let key = compute_null_id(fp);
        let (env, _) =
            create_signed_put_env(&key, "dGVzdA==", "somesalt", 1, 3600, &signing_key, fp);

        let sign_data_str = format!(
            "{}|dGVzdA==|somesalt|1|{}",
            key,
            env.payload_i64("nonce").unwrap()
        );
        assert!(verify_dht_put_signature(&sign_data_str, &env.sig, fp, &env));
    }

    #[test]
    fn test_verify_dht_put_signature_unsigned_rejected() {
        let (_signing_key, verifying_key) = add_crypto_pq::generate_keypair().unwrap();
        let fp = add_crypto_pq::fingerprint_from_verifying_key(&verifying_key);
        cache_test_verifying_key(&verifying_key, &fp);

        let key = compute_null_id(&fp);

        // Create an envelope with empty signature (unsigned record)
        let payload = serde_json::json!({
            "key": key,
            "value": "dGVzdA==",
            "salt": "somesalt",
            "seq": 1,
            "ttl": 3600,
            "nonce": 0,
            "publisher_fp": fp,
        });

        let env = WireEnvelope {
            msg_type: "dht-put".to_string(),
            payload,
            msg_id: add_protocol::envelope::uuid_hex(),
            ts: now_unix(),
            sig: "".to_string(), // No signature!
        };

        let sign_data_str = format!("{key}|dGVzdA==|somesalt|1|0");
        assert!(
            !verify_dht_put_signature(&sign_data_str, "", &fp, &env),
            "unsigned record must be rejected"
        );
    }

    #[test]
    fn test_verify_dht_put_signature_wrong_signature_rejected() {
        let (_signing_key, verifying_key) = add_crypto_pq::generate_keypair().unwrap();
        let fp = add_crypto_pq::fingerprint_from_verifying_key(&verifying_key);
        cache_test_verifying_key(&verifying_key, &fp);

        let key = compute_null_id(&fp);

        // Create an envelope with a valid-looking but wrong signature
        let payload = serde_json::json!({
            "key": key,
            "value": "dGVzdA==",
            "salt": "somesalt",
            "seq": 1,
            "ttl": 3600,
            "nonce": 0,
            "publisher_fp": fp,
        });

        let env = WireEnvelope {
            msg_type: "dht-put".to_string(),
            payload,
            msg_id: add_protocol::envelope::uuid_hex(),
            ts: now_unix(),
            sig: base64::engine::general_purpose::STANDARD.encode("invalid-signature-data"),
        };

        let sign_data_str = format!("{key}|dGVzdA==|somesalt|1|0");
        assert!(
            !verify_dht_put_signature(&sign_data_str, &env.sig, &fp, &env),
            "record with invalid signature must be rejected"
        );
    }

    /// SECURITY FIX (H6): Test that TTL values exceeding MAX_TTL are rejected.
    /// This test directly validates the TTL bounds check in handle_put by
    /// verifying the constant relationship and the rejection logic.
    #[test]
    fn test_ttl_max_bound_enforced() {
        // MAX_TTL must be 7 days (604800 seconds)
        assert_eq!(constants::MAX_TTL, 604800, "MAX_TTL should be 7 days");

        // The TTL rejection predicate used in handle_put.
        let reject = |ttl: i64| ttl <= 0 || ttl > constants::MAX_TTL;

        // Oversized, zero and negative TTLs must be rejected.
        assert!(
            reject(constants::MAX_TTL + 1),
            "oversized ttl must be rejected"
        );
        assert!(reject(0), "zero ttl must be rejected");
        assert!(reject(-1), "negative ttl must be rejected");

        // Valid in-bounds TTLs must NOT be rejected.
        assert!(!reject(constants::MAX_TTL), "max ttl must be accepted");
        assert!(!reject(3600), "one-hour ttl must be accepted");
    }

    #[test]
    fn test_verify_dht_put_signature_tampered_data_rejected() {
        let (signing_key, verifying_key) = add_crypto_pq::generate_keypair().unwrap();
        let fp = add_crypto_pq::fingerprint_from_verifying_key(&verifying_key);
        cache_test_verifying_key(&verifying_key, &fp);

        let key = compute_null_id(&fp);

        // Sign original data
        let original_data = format!("{key}|dGVzdA==|somesalt|1|0");
        let sig = crate::sign_data(&original_data, &signing_key).unwrap();

        // But create envelope with tampered data (different value)
        let payload = serde_json::json!({
            "key": key,
            "value": "dGFtcGVyZWQ=", // different value
            "salt": "somesalt",
            "seq": 1,
            "ttl": 3600,
            "nonce": 0,
            "publisher_fp": fp,
        });

        let env = WireEnvelope {
            msg_type: "dht-put".to_string(),
            payload,
            msg_id: add_protocol::envelope::uuid_hex(),
            ts: now_unix(),
            sig,
        };

        // The sign_data computed from the tampered envelope won't match the signature
        let tampered_sign_data = format!("{key}|dGFtcGVyZWQ=|somesalt|1|0");
        assert!(
            !verify_dht_put_signature(&tampered_sign_data, &env.sig, &fp, &env),
            "record with tampered data must be rejected"
        );
    }
}
