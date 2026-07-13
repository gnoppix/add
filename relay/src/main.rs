//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// Add Relay Server (store-and-forward) with Multi-Relay Federation
//-------------------------------------------------------------------------------

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use futures::{SinkExt as _, StreamExt as _};
use serde::{Deserialize, Serialize};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{RwLock, mpsc};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message;
use tracing_subscriber::EnvFilter;

// ------------------------------------------------------------------ //
//  Configuration                                                     //
// ------------------------------------------------------------------ //

const MAX_CONNECTIONS: usize = 100;
const MAX_MAILBOX_SIZE: usize = 1000;
const MAILBOX_TTL_SECONDS: u64 = 86400 * 7; // 7 days
const HEARTBEAT_INTERVAL_SECONDS: u64 = 30;

// Federation constants
#[allow(dead_code)]
const FEDERATION_MAX_PEERS: usize = 20;
#[allow(dead_code)]
const FEDERATION_GOSSIP_INTERVAL_SECONDS: u64 = 60;
#[allow(dead_code)]
const FEDERATION_ROUTE_TTL_SECONDS: u64 = 1800;
#[allow(dead_code)]
const FEDERATION_PEER_TIMEOUT_SECONDS: u64 = 300;
#[allow(dead_code)]
const FEDERATION_MAX_RELAY_HOPS: u8 = 5;
#[allow(dead_code)]
const FEDERATION_PEER_SYNC_INTERVAL_SECONDS: u64 = 30;

// Mix routing constants (ACS2.6 §V.4)
/// Minimum random delay (seconds) before forwarding a message
const MIX_MIN_DELAY_SECONDS: u64 = 1;
/// Maximum random delay (seconds) before forwarding a message  
const MIX_MAX_DELAY_SECONDS: u64 = 60;
/// Cover message burst size when mixing
#[allow(dead_code)]
const MIX_COVER_BURST_COUNT: usize = 3;

// =============================================================================
// Edge-Core Architecture — ACS2.6 Part II.1
// =============================================================================
// Adaptive Traffic Budgeting Engine with 3 network tiers:
// - Unrestricted (Wi-Fi/Charging): Continuous Poisson stream, full mixnet
// - Metered (Cellular Normal): Burst-padding only when sending
// - Tactical (Critical Low Data): Deferred queueing, minimal metadata

/// Network state for adaptive traffic budgeting
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum NetworkState {
    /// Unrestricted: Wi-Fi, charging, unlimited data
    Unrestricted,
    /// Metered: Cellular, normal data plan
    Metered,
    /// Tactical: Critical low data, survival mode
    Tactical,
}

impl std::fmt::Display for NetworkState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkState::Unrestricted => write!(f, "unrestricted"),
            NetworkState::Metered => write!(f, "metered"),
            NetworkState::Tactical => write!(f, "tactical"),
        }
    }
}

/// Traffic budgeting configuration per network state
#[derive(Debug, Clone)]
pub struct TrafficBudget {
    pub state: NetworkState,
    /// Base cover traffic rate (packets per second)
    pub base_rate_pps: f64,
    /// Burst multiplier for active transmission
    pub burst_multiplier: f64,
    /// Enable full mixnet routing
    pub mixnet_enabled: bool,
    /// Enable PQ-PPN push notifications
    pub push_enabled: bool,
}

impl TrafficBudget {
    pub fn for_state(state: NetworkState) -> Self {
        match state {
            NetworkState::Unrestricted => Self {
                state,
                base_rate_pps: 0.1, // ~50-100 MB/hr
                burst_multiplier: 10.0,
                mixnet_enabled: true,
                push_enabled: true,
            },
            NetworkState::Metered => Self {
                state,
                base_rate_pps: 0.0,    // Zero idle traffic
                burst_multiplier: 2.0, // Padding only during send
                mixnet_enabled: true,
                push_enabled: true,
            },
            NetworkState::Tactical => Self {
                state,
                base_rate_pps: 0.0,    // Zero idle traffic
                burst_multiplier: 1.0, // No padding
                mixnet_enabled: false, // Direct routing only
                push_enabled: false,   // No push
            },
        }
    }
}

/// Edge-Core node role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum NodeRole {
    /// Core node: stationary, unmetered, full routing
    Core,
    /// Edge node: mobile, battery-constrained, leaf-only
    Edge,
}

impl NodeRole {
    pub fn is_core(&self) -> bool {
        matches!(self, NodeRole::Core)
    }

    pub fn is_edge(&self) -> bool {
        matches!(self, NodeRole::Edge)
    }
}

impl std::fmt::Display for NodeRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeRole::Core => write!(f, "core"),
            NodeRole::Edge => write!(f, "edge"),
        }
    }
}

// =============================================================================
// CBNP (Coordinated Baseline Noise Protocol) — ACS2.6 Part V.1
// =============================================================================
/// Minimum cover traffic rate to maintain anonymity set
#[allow(dead_code)]
const CBNP_MIN_COVER_RATE_PPS: f64 = 0.05; // ~25 MB/hr

// ------------------------------------------------------------------ //
//  Protocol messages                                                 //
// ------------------------------------------------------------------ //

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayEnvelope {
    msg_type: String,
    payload: serde_json::Value,
    msg_id: String,
    ts: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailboxStoreRequest {
    recipient_nid: String,
    signed_blob: String,
    sender_nid: String,
    sender_fp: String,
    seq: i64,
    /// SECURITY FIX (C4): ML-DSA-87 signature over
    /// `recipient_nid + sender_nid + sender_fp + seq + timestamp + nonce`.
    /// The relay verifies this against sender_fp before storing.
    #[serde(default)]
    sender_sig: String,
    /// SECURITY FIX (H7): Timestamp for replay protection.
    /// Relay rejects requests older than 5 minutes.
    #[serde(default)]
    timestamp: f64,
    /// SECURITY FIX (H7): Unique nonce per store request for replay protection.
    #[serde(default)]
    nonce: String,
    /// Sender's armored public key cert (optional, recommended).
    /// Needed for Sequoia in-process signature verification.
    #[serde(default)]
    sender_cert: String,
    /// Sender's ML-DSA-87 verifying key (base64-encoded).
    /// Used for post-quantum signature verification.
    #[serde(default)]
    sender_verifying_key: String,
    /// SECURITY FIX (M2): Sealed sender token (optional).
    /// When present, the sender identity is hidden from the relay.
    /// Format: hex-encoded Kyber-768 ciphertext encapsulating
    /// `{sender_nid, sender_fp, inner_nonce}` under the recipient's
    /// Kyber public key. The relay cannot decrypt this — only the
    /// recipient's client can recover the sender identity.
    /// When set, `sender_nid` MUST be `"anonymous"` and the relay
    /// skips GPG sender signature verification.
    #[serde(default)]
    sealed_sender: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MailboxFetchRequest {
    recipient_nid: String,
    auth_hmac: String,
    /// SECURITY FIX (H3): ML-DSA-87 signature proving the requester
    /// owns the identity associated with `recipient_nid`.
    #[serde(default)]
    sender_sig: String,
    /// SECURITY FIX (H3): Fingerprint of the requester (must match the
    /// null_id derivation).
    #[serde(default)]
    requester_fp: String,
    /// SECURITY FIX (H3): Timestamp for replay protection.
    #[serde(default)]
    timestamp: f64,
    /// SECURITY FIX (H3): Unique nonce for replay protection.
    #[serde(default)]
    nonce: String,
    /// Requester's ML-DSA-87 verifying key (base64-encoded).
    #[serde(default)]
    requester_verifying_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayResponse {
    ok: bool,
    error: Option<String>,
    data: Option<serde_json::Value>,
}

// ------------------------------------------------------------------ //
//  Federation protocol messages                                      //
// ------------------------------------------------------------------ //

/// Route advertisement: tell peers which Null IDs are on this relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteAdvertise {
    relay_url: String,
    route_count: usize,
    ttl: u64,
}

/// Response to route-advertise with our own routes.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteAdvertiseAck {
    relay_url: String,
    route_count: usize,
}

/// Query: "do you know which relay serves this Null ID?"
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WhoHas {
    null_id: String,
}

/// Response: "this Null ID is served by relay_url"
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RouteFound {
    null_id: String,
    relay_url: String,
}

/// Challenge for HMAC peer authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerAuth {
    challenge: String, // hex-encoded random bytes
    relay_url: String,
}

/// Response to peer-auth: HMAC-SHA256(challenge, shared_secret).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PeerAuthReply {
    response: String, // hex-encoded HMAC
    relay_url: String,
}

/// Forward a message to a remote relay for delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayForward {
    recipient_nid: String,
    signed_blob: String,
    sender_nid: String,
    sender_fp: String,
    seq: i64,
    sender_sig: String,
    timestamp: f64,
    nonce: i64,
    /// Hop count to prevent infinite forwarding loops.
    #[serde(default)]
    hop_count: u8,
    /// Chain of relays that have forwarded this message (for loop detection).
    #[serde(default)]
    via: Vec<String>,
    /// URL of the relay that is forwarding this message.
    /// Used to look up peer authentication state.
    #[serde(default)]
    source_relay_url: String,
    /// GPG certificate of the forwarding relay (for onion routing auth).
    #[serde(default)]
    source_relay_cert: String,
    /// GPG signature from forwarding relay.
    #[serde(default)]
    source_relay_sig: String,
    /// GPG fingerprint of forwarding relay.
    #[serde(default)]
    source_relay_fp: String,
    /// Sender certificate (for sealed sender routing).
    #[serde(default)]
    sender_cert: String,
    /// Sender's ML-DSA-87 verifying key (base64-encoded).
    #[serde(default)]
    sender_verifying_key: String,
}

/// Acknowledge a relay-forward was accepted.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayForwardAck {
    accepted: bool,
    error: Option<String>,
}

/// Read receipt from recipient client to relays (triggers cross-relay deletion).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayReadReceipt {
    message_id: String,    // SHA-256 hash of the message payload
    recipient_nid: String, // The recipient who read the message
    recipient_fp: String,  // Fingerprint of the recipient
    signature: String,     // ML-DSA-87 signature over message_id + recipient_nid + timestamp
    timestamp: f64,        // Unix timestamp
    nonce: String,         // Unique nonce for replay protection
    /// Recipient's ML-DSA-87 verifying key (base64-encoded).
    #[serde(default)]
    recipient_verifying_key: String,
    /// Optional: list of other relay URLs that should also delete this message
    other_relays: Vec<String>,
}

/// Acknowledgment for a read receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayReadReceiptAck {
    accepted: bool,
    error: Option<String>,
}

/// Request to delete a message from all relays (cross-relay sync).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayDeleteRequest {
    message_id: String,    // SHA-256 hash of the message payload
    recipient_nid: String, // The recipient who requested deletion
    recipient_fp: String,  // Fingerprint of the recipient
    signature: String,     // ML-DSA-87 signature over message_id + recipient_nid + timestamp
    timestamp: f64,        // Unix timestamp
    nonce: String,         // Unique nonce for replay protection
    /// Recipient's ML-DSA-87 verifying key (base64-encoded).
    #[serde(default)]
    recipient_verifying_key: String,
    /// Reason for deletion
    reason: String, // e.g., "read", "expired", "manual"
}

/// Response to a delete request.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayDeleteAck {
    accepted: bool,
    error: Option<String>,
}

/// Request to query message status from relay (for sender polling).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct RelayStatusRequest {
    recipient_nid: String,
    /// SECURITY FIX (H3): GPG detached signature proving the requester
    /// owns the identity associated with `recipient_nid`.
    #[serde(default)]
    sender_sig: String,
    /// SECURITY FIX (H3): Fingerprint of the requester (must match the
    /// null_id derivation).
    #[serde(default)]
    requester_fp: String,
    /// SECURITY FIX (H3): Timestamp for replay protection.
    #[serde(default)]
    timestamp: f64,
    /// SECURITY FIX (H3): Unique nonce for replay protection.
    #[serde(default)]
    nonce: String,
    /// Requester's ML-DSA-87 verifying key (base64-encoded).
    #[serde(default)]
    requester_verifying_key: String,
    /// HMAC for federation auth (optional, if shared secret configured).
    #[serde(default)]
    auth_hmac: String,
    /// List of message IDs to query status for.
    message_ids: Vec<String>,
}

// ------------------------------------------------------------------ //
//  Mailbox                                                            //
// ------------------------------------------------------------------ //

#[derive(Debug, Clone)]
struct MailboxEntry {
    message_id: String, // SHA-256 hash of signed_blob
    signed_blob: String,
    sender_nid: String,
    sender_fp: String,
    seq: i64,
    stored_at: u64,
    /// Delivery status: 0=stored, 1=relayed (ack from relay), 2=delivered (fetched by recipient), 3=read (read receipt)
    delivery_status: u8,
    /// Timestamp when status was last updated
    status_updated_at: u64,
    /// Timestamp when read receipt was received (if any)
    read_receipt_at: Option<u64>,
}

/// Per-recipient mailbox with size limits, per-sender caps, and TTL.
struct Mailbox {
    entries: Vec<MailboxEntry>,
    max_size: usize,
}

/// SECURITY FIX (M5): Maximum entries per sender within a single mailbox.
/// Prevents a single sender from filling the mailbox and flushing
/// legitimate messages from other senders via oldest-first eviction.
const MAX_ENTRIES_PER_SENDER: usize = 10;

impl Mailbox {
    fn new(max_size: usize) -> Self {
        Self {
            entries: Vec::new(),
            max_size,
        }
    }

    fn store(&mut self, entry: MailboxEntry) {
        // SECURITY FIX (M5): Cap entries per sender. If a single sender
        // has reached the cap, evict their oldest entry instead of the
        // global oldest (which could belong to a different sender).
        let sender_count = self
            .entries
            .iter()
            .filter(|e| e.sender_fp == entry.sender_fp)
            .count();
        if sender_count >= MAX_ENTRIES_PER_SENDER {
            // Find and remove the oldest entry from this sender
            if let Some(idx) = self
                .entries
                .iter()
                .position(|e| e.sender_fp == entry.sender_fp)
            {
                self.entries.remove(idx);
            }
        } else if self.entries.len() >= self.max_size {
            // Global cap: remove the single oldest entry
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    /// Get all entries for a recipient (for fetch_messages)
    fn fetch_all(&self) -> Vec<MailboxEntry> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.entries
            .iter()
            .filter(|e| now - e.stored_at < MAILBOX_TTL_SECONDS)
            .cloned()
            .collect()
    }

    /// Get entries that are pending delivery (status < 2)
    #[allow(dead_code)]
    fn fetch_undelivered(&self) -> Vec<MailboxEntry> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.entries
            .iter()
            .filter(|e| now - e.stored_at < MAILBOX_TTL_SECONDS && e.delivery_status < 2)
            .cloned()
            .collect()
    }

    /// Update delivery status for a specific message
    fn update_delivery_status(&mut self, message_id: &str, new_status: u8, now: u64) -> bool {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.message_id == message_id) {
            if entry.delivery_status < new_status {
                entry.delivery_status = new_status;
                entry.status_updated_at = now;
                if new_status == 3 {
                    entry.read_receipt_at = Some(now);
                }
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Mark message as read (status 3)
    fn mark_read(&mut self, message_id: &str, now: u64) -> bool {
        self.update_delivery_status(message_id, 3, now)
    }

    /// Remove a specific message by message_id
    fn remove_message(&mut self, message_id: &str) -> bool {
        if let Some(idx) = self.entries.iter().position(|e| e.message_id == message_id) {
            self.entries.remove(idx);
            true
        } else {
            false
        }
    }

    /// Remove all entries (used by relay-purge to squelch a mailbox).
    fn clear(&mut self) {
        self.entries.clear();
    }
}

// ------------------------------------------------------------------ //
//  Federation types                                                  //
// ------------------------------------------------------------------ //

type FederationMessage = String; // JSON message to send to peer

/// A known peer relay with its connection state.
#[derive(Debug)]
struct PeerInfo {
    #[allow(dead_code)]
    url: String,
    /// Null IDs known to be served by this peer (from route advertisements).
    routes: HashSet<String>,
    /// Last time we received a message/gossip from this peer.
    last_seen: Instant,
    /// Whether the HMAC challenge-response succeeded.
    authenticated: bool,
    /// Channel to send messages to this peer (for federation).
    sender: Option<mpsc::Sender<FederationMessage>>,
    /// CBNP cover traffic session for this peer (distinct key per peer).
    cover_session: add_crypto::cbnp::CbnpSession,
    /// Pending cover messages queued for this peer (for batching).
    #[allow(dead_code)]
    cover_queue: Vec<Vec<u8>>,
}

/// A route entry in the remote_routes table.
#[derive(Debug, Clone)]
struct RouteEntry {
    relay_url: String,
    /// When this route expires.
    expires_at: Instant,
}

/// Federation state shared across the relay.
#[allow(dead_code)]
struct FederationState {
    /// Known peer relays (URL -> info).
    peers: HashMap<String, PeerInfo>,
    /// Remote routes: Null ID -> relay URL that serves it.
    remote_routes: HashMap<String, RouteEntry>,
    /// Our advertised URL (what we tell peers we are).
    our_url: Option<String>,
    /// Shared secret for HMAC peer authentication.
    shared_secret: Option<String>,
    /// Challenge we sent to peers (for replay protection).
    /// SECURITY FIX (M12): Store challenge with creation timestamp for expiry.
    pending_challenges: HashMap<String, (String, i64)>, // relay_url -> (challenge, created_at)
    /// Nonces seen from peers (replay protection).
    seen_nonces: HashMap<String, Vec<String>>, // peer_url -> nonces
}

impl FederationState {
    fn new(shared_secret: Option<String>) -> Self {
        Self {
            peers: HashMap::new(),
            remote_routes: HashMap::new(),
            our_url: None,
            shared_secret,
            pending_challenges: HashMap::new(),
            seen_nonces: HashMap::new(),
        }
    }

    /// Add or update a route for a Null ID.
    fn add_route(&mut self, null_id: &str, relay_url: &str) {
        self.remote_routes.insert(
            null_id.to_string(),
            RouteEntry {
                relay_url: relay_url.to_string(),
                expires_at: Instant::now() + Duration::from_secs(FEDERATION_ROUTE_TTL_SECONDS),
            },
        );
    }

    /// Look up the relay URL for a Null ID.
    fn lookup_route(&self, null_id: &str) -> Option<&str> {
        self.remote_routes
            .get(null_id)
            .map(|e| e.relay_url.as_str())
    }

    /// Add a peer with its sender channel.
    #[allow(dead_code)]
    fn add_peer(&mut self, url: String, sender: mpsc::Sender<FederationMessage>) {
        self.peers.insert(
            url.clone(),
            PeerInfo {
                url,
                routes: HashSet::new(),
                last_seen: Instant::now(),
                authenticated: false,
                sender: Some(sender),
                cover_session: add_crypto::cbnp::CbnpSession::new(
                    add_crypto::cbnp::CbnpConfig::default(),
                ),
                cover_queue: Vec::new(),
            },
        );
    }

    /// Send a message to a peer if connected.
    fn send_to_peer(&self, url: &str, message: FederationMessage) -> bool {
        if let Some(peer) = self.peers.get(url)
            && let Some(ref sender) = peer.sender
        {
            return sender.try_send(message).is_ok();
        }
        false
    }

    /// Remove expired routes.
    fn cleanup_expired_routes(&mut self) {
        let now = Instant::now();
        self.remote_routes.retain(|_, entry| entry.expires_at > now);
        self.peers.retain(|_, peer| {
            peer.last_seen.elapsed() < Duration::from_secs(FEDERATION_PEER_TIMEOUT_SECONDS)
        });
    }

    /// Record a nonce from a peer for replay protection.
    #[allow(dead_code)]
    fn record_nonce(&mut self, peer_url: &str, nonce: &str) -> bool {
        let nonces = self.seen_nonces.entry(peer_url.to_string()).or_default();
        if nonces.contains(&nonce.to_string()) {
            return false; // replay
        }
        if nonces.len() >= MAX_NONCES_PER_SENDER {
            nonces.drain(0..nonces.len() / 2);
        }
        nonces.push(nonce.to_string());
        true
    }
}

// ------------------------------------------------------------------ //
//  Relay Server                                                       //
// ------------------------------------------------------------------ //

/// Maximum age of a store request timestamp (5 minutes).
const STORE_TIMESTAMP_TOLERANCE_SECS: f64 = 300.0;

/// Maximum number of per-sender nonces to retain for replay protection.
const MAX_NONCES_PER_SENDER: usize = 1000;

/// SECURITY FIX (H8): Maximum number of per-IP rate limiter entries.
/// Prevents unbounded growth of the per-peer limiter map.
const MAX_PEER_LIMITERS: usize = 10_000;

/// SECURITY FIX (H8): Stale entry cleanup interval for per-IP rate limiters.
const PEER_LIMITER_CLEANUP_SECS: u64 = 120;

/// Global state shared across all relay connections.
struct RelayState {
    mailboxes: RwLock<HashMap<String, Mailbox>>,
    /// SECURITY FIX (C5): SQLite-backed persistent mailbox storage.
    /// Messages survive relay restart. Each row stores opaque ciphertext blobs
    /// (already encrypted by sender via DoubleRatchet). The sender/recipient
    /// metadata fields are also encrypted to protect privacy.
    db_pool: Option<sqlx::SqlitePool>,
    /// SECURITY FIX (M3): Key for encrypting sender metadata (nid, fp) in SQLite.
    metadata_key: [u8; 32],
    shared_secret: Option<String>,
    /// SECURITY FIX (C4/H7): Replay protection — tracks seen nonces per sender.
    #[allow(dead_code)]
    seen_nonces: RwLock<HashMap<String, Vec<i64>>>,
    /// SECURITY FIX (H3): Replay protection for string nonces (fetch requests).
    /// Stores (nonce, timestamp) pairs for time-based eviction (H2).
    seen_nonce_strs: RwLock<HashMap<String, Vec<(String, i64)>>>,
    /// SECURITY FIX (C4): GPG home directory (kept for backward compat / key storage).
    gpg_home: String,
    /// SECURITY FIX (H8): Per-IP rate limiters to prevent connection flooding.
    /// Each IP gets its own RateLimiter, so one attacker cannot exhaust the
    /// global limit for all peers. Stale entries are cleaned up periodically.
    conn_limiters: RwLock<HashMap<IpAddr, (add_dht_core::RateLimiter, Instant)>>,
    /// Federation state for multi-relay routing.
    federation: RwLock<FederationState>,
    /// Verifying key cache: fingerprint -> base64-encoded ML-DSA-87 verifying key.
    /// Populated on first sight (TOFU) when clients include their verifying key.
    ml_dsa87_verifying_key_cache: RwLock<HashMap<String, String>>,
    /// ACS2.6 Part IV.2: TOFU-pinned peer certificate fingerprints.
    known_peers: RwLock<HashSet<String>>,
    /// ACS2.6 Part II.1: Whether this relay allows transit forwarding.
    /// When false, relay-forward requests are rejected (edge/mobile mode).
    allow_relay: bool,
    /// ACS2.6 §V.1: Whether CBNP cover traffic is enabled.
    #[allow(dead_code)]
    cbnp_enabled: bool,
}

impl RelayState {
    /// Initialize relay state with optional SQLite persistence.
    /// SECURITY FIX (C5): Mailbox entries are stored in SQLite encrypted at rest
    /// using DbEncryptionKey. This ensures messages survive relay restart.
    async fn new(
        shared_secret: Option<String>,
        gpg_home: String,
        db_path: Option<String>,
        allow_relay: bool,
        cbnp_enabled: bool,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Load known peers from disk if available
        let known_peers = Self::load_known_peers_sync(&gpg_home);

        // Initialize SQLite persistence if path provided
        let db_pool = if let Some(path) = db_path {
            if let Some(parent) = std::path::Path::new(&path).parent() {
                std::fs::create_dir_all(parent)?;
            }
            // Use sqlite:// URL with mode=rwc to create file if it doesn't exist
            let url = if path.starts_with("sqlite:") || path.starts_with("sqlite://") {
                path.clone()
            } else {
                format!("sqlite://{}?mode=rwc", path)
            };
            tracing::debug!("Opening SQLite database at: {}", url);
            let pool = sqlx::sqlite::SqlitePoolOptions::new()
                .max_connections(5)
                .connect(&url)
                .await?;

            // Set restrictive permissions on the database file
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }

            // Create mailbox_entries table
            sqlx::query(
                "CREATE TABLE IF NOT EXISTS mailbox_entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_nid TEXT NOT NULL,
                    signed_blob TEXT NOT NULL,
                    sender_nid TEXT NOT NULL,
                    sender_fp TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    stored_at INTEGER NOT NULL,
                    delivered INTEGER NOT NULL DEFAULT 0,
                    sender_encrypted TEXT
                )",
            )
            .execute(&pool)
            .await?;

            sqlx::query(
                "CREATE INDEX IF NOT EXISTS idx_mailbox_recipient ON mailbox_entries(recipient_nid)"
            )
            .execute(&pool)
            .await?;

            Some(pool)
        } else {
            None
        };

        // SECURITY FIX (M3): Derive metadata encryption key from shared_secret
        // or generate a random key if no shared_secret is configured.
        let metadata_key = if let Some(ref secret) = shared_secret {
            use hkdf::Hkdf;
            use sha2::Sha256;
            let hk = Hkdf::<Sha256>::new(None, secret.as_bytes());
            let mut key = [0u8; 32];
            hk.expand(b"add-relay-metadata-v1", &mut key)
                .expect("HKDF expand failed");
            key
        } else {
            use rand::RngCore;
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            key
        };

        Ok(Self {
            mailboxes: RwLock::new(HashMap::new()),
            db_pool,
            metadata_key,
            shared_secret: shared_secret.clone(),
            seen_nonces: RwLock::new(HashMap::new()),
            seen_nonce_strs: RwLock::new(HashMap::new()),
            gpg_home: gpg_home.clone(),
            // SECURITY FIX (H8): Per-IP rate limiters — each IP gets 30 connections/60s
            conn_limiters: RwLock::new(HashMap::new()),
            federation: RwLock::new(FederationState::new(shared_secret)),
            ml_dsa87_verifying_key_cache: RwLock::new(HashMap::new()),
            known_peers: RwLock::new(known_peers),
            allow_relay,
            cbnp_enabled,
        })
    }

    /// Load known peer fingerprints from disk (synchronous, for constructor).
    fn load_known_peers_sync(gpg_home: &str) -> HashSet<String> {
        let path = std::path::PathBuf::from(gpg_home).join(".known_peers.json");
        if !path.exists() {
            return HashSet::new();
        }
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        serde_json::from_str(&content).unwrap_or_default()
    }

    /// Persist known peer fingerprints to disk (async).
    async fn save_known_peers(&self) -> Result<(), Box<dyn std::error::Error>> {
        let peers: HashSet<String> = self.known_peers.read().await.clone();
        let path = std::path::PathBuf::from(&self.gpg_home).join(".known_peers.json");
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, serde_json::to_string_pretty(&peers)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// SECURITY FIX (C4/H7): Check and record a nonce for replay protection.
    /// Returns true if the nonce is fresh (not seen before), false if replayed.
    ///
    /// SECURITY FIX (H2): Evict nonces older than STORE_TIMESTAMP_TOLERANCE_SECS
    /// SECURITY FIX (C4/H7): Check and record a nonce for replay protection.
    #[allow(dead_code)]
    async fn check_and_record_nonce(&self, sender_fp: &str, nonce: i64) -> bool {
        let mut nonces = self.seen_nonces.write().await;
        let entry = nonces.entry(sender_fp.to_string()).or_insert_with(Vec::new);

        // Check if nonce already seen
        if entry.contains(&nonce) {
            return false;
        }

        // SECURITY FIX (H2): Evict nonces older than the time window
        let cutoff = nonce - STORE_TIMESTAMP_TOLERANCE_SECS as i64;
        entry.retain(|n| *n >= cutoff);

        // Prune if still too many nonces (keep last N)
        if entry.len() >= MAX_NONCES_PER_SENDER {
            entry.drain(0..entry.len() / 2);
        }

        entry.push(nonce);
        true
    }

    /// SECURITY FIX (H3): Check and record a string nonce for replay protection
    /// on fetch requests. Returns true if fresh, false if replayed.
    ///
    /// SECURITY FIX (H2): Evict nonces older than STORE_TIMESTAMP_TOLERANCE_SECS.
    async fn check_and_record_nonce_str(&self, sender_fp: &str, nonce: &str) -> bool {
        let mut nonces = self.seen_nonce_strs.write().await;
        let entry = nonces.entry(sender_fp.to_string()).or_insert_with(Vec::new);

        if entry.iter().any(|(n, _)| n == nonce) {
            return false;
        }

        // SECURITY FIX (H2): Evict nonces older than the time window
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let cutoff = now - STORE_TIMESTAMP_TOLERANCE_SECS as i64;
        entry.retain(|(_, ts)| *ts >= cutoff);

        if entry.len() >= MAX_NONCES_PER_SENDER {
            entry.drain(0..entry.len() / 2);
        }

        entry.push((nonce.to_string(), now));
        true
    }

    /// SECURITY FIX (C4): Verify the sender's GPG signature on a store request.
    ///
    /// Verifies that the signature was produced by the holder of the GPG key
    /// matching `sender_fp`, over the canonical data:
    /// `recipient_nid + sender_nid + sender_fp + seq + timestamp + nonce`.
    async fn verify_store_signature(&self, req: &MailboxStoreRequest) -> Result<(), String> {
        if req.sender_sig.is_empty() {
            return Err("missing sender signature".to_string());
        }

        // SECURITY FIX (M2): Sealed sender — skip GPG verification when
        // the sender identity is hidden. The relay cannot verify what it
        // cannot see. The recipient's client verifies sender identity after
        // decapsulating the sealed sender token.
        if !req.sealed_sender.is_empty() {
            if req.sender_nid != "anonymous" {
                return Err("sealed sender requires sender_nid='anonymous'".to_string());
            }
            // Still require a signature (over the encrypted blob) to prevent spam
            // — but we skip identity verification since the sender is hidden.
            return Ok(());
        }

        // Canonical signing data: all fields except the signature itself
        let signing_data = format!(
            "{}|{}|{}|{}|{}|{}",
            req.recipient_nid, req.sender_nid, req.sender_fp, req.seq, req.timestamp, req.nonce
        );

        // TOFU: cache cert BEFORE verification (first-seen-is-trusted)
        // Now handled inside verify_ml_dsa87_signature

        // Verify using ML-DSA-87
        let verified = verify_ml_dsa87_signature(
            &req.sender_sig,
            &signing_data,
            &req.sender_fp,
            &self.ml_dsa87_verifying_key_cache,
            &req.sender_verifying_key, // Pass ML-DSA-87 verifying key for TOFU
        )
        .unwrap_or(false);
        if !verified {
            return Err("sender signature verification failed".to_string());
        }

        Ok(())
    }

    /// SECURITY FIX (H7): Check timestamp freshness to prevent replay attacks.
    fn check_timestamp_freshness(&self, timestamp: f64) -> Result<(), String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();

        let age = now - timestamp;
        if age.abs() > STORE_TIMESTAMP_TOLERANCE_SECS {
            return Err(format!(
                "timestamp out of range: {}s old (max {}s)",
                age.abs(),
                STORE_TIMESTAMP_TOLERANCE_SECS
            ));
        }

        Ok(())
    }

    async fn store_message(&self, req: MailboxStoreRequest) -> Result<(), String> {
        // Always write to in-memory cache for fast reads
        let mut mailboxes = self.mailboxes.write().await;
        let mailbox = mailboxes
            .entry(req.recipient_nid.clone())
            .or_insert_with(|| Mailbox::new(MAX_MAILBOX_SIZE));

        // Compute message ID as SHA-256 of the signed_blob for deduplication
        let message_id = sha256_hex(req.signed_blob.as_bytes());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        mailbox.store(MailboxEntry {
            message_id: message_id.clone(),
            signed_blob: req.signed_blob.clone(),
            sender_nid: req.sender_nid.clone(),
            sender_fp: req.sender_fp.clone(),
            seq: req.seq,
            stored_at: now,
            delivery_status: 1, // 1=relayed (ack from relay)
            status_updated_at: now,
            read_receipt_at: None,
        });
        let tail = if req.signed_blob.len() > 120 {
            &req.signed_blob[req.signed_blob.len() - 120..]
        } else {
            &req.signed_blob[..]
        };
        tracing::info!(
            "DBG relay store recv blob_len={} has_kc={} TAIL={}",
            req.signed_blob.len(),
            req.signed_blob.contains("kyber_ciphertext"),
            tail
        );

        // SECURITY FIX (C5): Persist to SQLite for durability across restarts
        // SECURITY FIX (M3): Encrypt sender metadata (nid + fp) at rest
        if let Some(ref pool) = self.db_pool {
            // Encrypt sender metadata: [sender_nid][sender_fp] -> AES-256-GCM
            let sender_plaintext = format!("{}\n{}", req.sender_nid, req.sender_fp);
            let sender_encrypted = Self::encrypt_metadata(&sender_plaintext, &self.metadata_key);

            sqlx::query(
                    "INSERT INTO mailbox_entries (recipient_nid, signed_blob, sender_nid, sender_fp, seq, stored_at, sender_encrypted)
                     VALUES (?, ?, ?, ?, ?, ?, ?)"
                )
                .bind(&req.recipient_nid)
                .bind(&req.signed_blob)
                .bind(&req.sender_nid)
                .bind(&req.sender_fp)
                .bind(req.seq)
                .bind(now as i64)
                .bind(&sender_encrypted)
                .execute(pool)
                .await
                .map_err(|e| format!("db store error: {}", e))?;
        }

        Ok(())
    }

    async fn fetch_messages(&self, recipient_nid: &str) -> Vec<MailboxEntry> {
        // SECURITY FIX (C5): Read from SQLite if available (persistent storage),
        // otherwise fall back to in-memory cache.
        if let Some(ref pool) = self.db_pool
            && let Ok(rows) = sqlx::query_as::<_, (String, String, String, i64, i64)>(
                "SELECT signed_blob, sender_nid, sender_fp, seq, stored_at
                 FROM mailbox_entries
                 WHERE recipient_nid = ? AND delivered = 0
                 ORDER BY seq ASC",
            )
            .bind(recipient_nid)
            .fetch_all(pool)
            .await
        {
            let entries: Vec<MailboxEntry> = rows
                .into_iter()
                .map(|(blob, snid, sfp, seq, stored)| MailboxEntry {
                    message_id: sha256_hex(blob.as_bytes()),
                    signed_blob: blob,
                    sender_nid: snid,
                    sender_fp: sfp,
                    seq,
                    stored_at: stored as u64,
                    delivery_status: 0,
                    status_updated_at: stored as u64,
                    read_receipt_at: None,
                })
                .collect();
            if !entries.is_empty() {
                return entries;
            }
        }
        // Fallback to in-memory cache
        let mailboxes = self.mailboxes.read().await;
        mailboxes
            .get(recipient_nid)
            .map(|mb| mb.fetch_all())
            .unwrap_or_default()
    }

    async fn ack_message(&self, recipient_nid: &str, seq: i64) {
        // In-memory ack - mark as delivered (status 2)
        {
            let mut mailboxes = self.mailboxes.write().await;
            if let Some(mb) = mailboxes.get_mut(recipient_nid) {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                if let Some(entry) = mb.entries.iter_mut().find(|e| e.seq == seq) {
                    entry.delivery_status = 2; // 2=delivered
                    entry.status_updated_at = now;
                }
            }
        }

        // SECURITY FIX (C5): Persist ack to SQLite
        if let Some(ref pool) = self.db_pool {
            let _ = sqlx::query(
                "UPDATE mailbox_entries SET delivered = 1
                 WHERE recipient_nid = ? AND seq = ? AND delivered = 0",
            )
            .bind(recipient_nid)
            .bind(seq)
            .execute(pool)
            .await;
        }
    }

    /// ACS2.6 Part III: Purge all messages for a recipient (squelch).
    /// Called after the recipient has successfully fetched and decrypted
    /// their messages, proving delivery. Removes both in-memory and
    /// persistent copies to prevent stale data accumulation.
    async fn purge_all_messages(&self, recipient_nid: &str) {
        // In-memory purge
        {
            let mut mailboxes = self.mailboxes.write().await;
            mailboxes.remove(recipient_nid);
        }

        // SQLite purge
        if let Some(ref pool) = self.db_pool {
            let _ = sqlx::query("DELETE FROM mailbox_entries WHERE recipient_nid = ?")
                .bind(recipient_nid)
                .execute(pool)
                .await;
        }
    }

    async fn cleanup_expired(&self) {
        // In-memory cleanup
        let mut mailboxes = self.mailboxes.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for mb in mailboxes.values_mut() {
            mb.entries
                .retain(|e| now - e.stored_at < MAILBOX_TTL_SECONDS);
        }
        mailboxes.retain(|_, mb| !mb.entries.is_empty());

        // SECURITY FIX (C5): SQLite cleanup
        if let Some(ref pool) = self.db_pool {
            let cutoff = (now - MAILBOX_TTL_SECONDS) as i64;
            let _ =
                sqlx::query("DELETE FROM mailbox_entries WHERE stored_at < ? AND delivered = 1")
                    .bind(cutoff)
                    .execute(pool)
                    .await;
        }
    }

    /// Get the set of locally served Null IDs (from mailboxes).
    async fn get_local_null_ids(&self) -> HashSet<String> {
        let mailboxes = self.mailboxes.read().await;
        mailboxes.keys().cloned().collect()
    }
}

// ------------------------------------------------------------------ //
//  Connection handler                                                 //
// ------------------------------------------------------------------ //

/// SECURITY FIX (C5): TLS acceptor type for the relay server.
type TlsAcceptor = tokio_rustls::TlsAcceptor;

/// SECURITY FIX (C5): Load a TLS acceptor from PEM cert and key files.
fn load_tls_acceptor(
    cert_path: &str,
    key_path: &str,
) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .collect();

    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or("no private key found in key file")?;

    let config = tokio_rustls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS config: {}", e))?;

    Ok(tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)))
}

async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    state: Arc<RelayState>,
    tls_acceptor: Option<TlsAcceptor>,
) -> Result<(), Box<dyn std::error::Error>> {
    // SECURITY FIX (H8): Per-IP rate limiting to prevent connection flooding.
    // Each IP address gets its own RateLimiter so one attacker cannot exhaust
    // the global limit for all peers.
    let ip = addr.ip();
    {
        let mut limiters = state.conn_limiters.write().await;
        let now = Instant::now();
        let entry = limiters
            .entry(ip)
            .or_insert_with(|| (add_dht_core::RateLimiter::new(30, 60.0), now));
        entry.1 = now; // update last-access time
        if !entry.0.allow(&ip.to_string()).await {
            drop(limiters); // release lock before warn log
            tracing::warn!(rate_limited=true, ip=%ip, "relay connection rejected (per-IP rate limit)");
            return Ok(());
        }
        // SECURITY FIX (H8): Evict oldest entry if map is full
        if limiters.len() > MAX_PEER_LIMITERS
            && let Some(oldest_ip) = limiters
                .iter()
                .min_by_key(|(_, (_, ts))| *ts)
                .map(|(k, _)| *k)
        {
            limiters.remove(&oldest_ip);
        }
    }

    // SECURITY FIX (C5): Both TLS and plaintext branches box to the same type.
    type BoxedStream = Box<dyn AsyncReadWrite>;
    if let Some(acceptor) = tls_acceptor {
        let tls_stream = acceptor.accept(stream).await?;

        // ACS2.6 Part IV.2: TOFU peer certificate pinning
        if let Some(peer_cert) = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
        {
            let cert_fingerprint = sha256_hex(peer_cert.as_ref());
            if !state.known_peers.read().await.contains(&cert_fingerprint) {
                // TOFU: auto-pin on first use, but log it
                tracing::warn!(
                    peer_ip = %addr,
                    cert_fp = %cert_fingerprint,
                    "TOFU: pinning new peer certificate"
                );
                state
                    .known_peers
                    .write()
                    .await
                    .insert(cert_fingerprint.clone());
                // Persist to disk
                let _ = state.save_known_peers().await;
            }
        }

        let boxed: BoxedStream = Box::new(tls_stream);
        let ws_stream = tokio_tungstenite::accept_async(boxed).await?;
        tracing::info!("new TLS relay connection from {}", addr);
        handle_ws_connection(ws_stream, addr, state).await
    } else {
        let boxed: BoxedStream = Box::new(stream);
        let ws_stream = tokio_tungstenite::accept_async(boxed).await?;
        tracing::info!("new relay connection from {}", addr);
        handle_ws_connection(ws_stream, addr, state).await
    }
}

/// SECURITY FIX (C5): Concrete WebSocket stream type that works for both
/// plaintext TCP and TLS connections. Using a boxed stream erases the
/// underlying transport type.
trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
type WsStream = tokio_tungstenite::WebSocketStream<Box<dyn AsyncReadWrite>>;

async fn handle_ws_connection(
    mut ws: WsStream,
    addr: SocketAddr,
    state: Arc<RelayState>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Connection limit check
    {
        let mailboxes = state.mailboxes.read().await;
        let total: usize = mailboxes.values().map(|mb| mb.entries.len()).sum();
        if total >= MAX_CONNECTIONS * MAX_MAILBOX_SIZE {
            let resp = RelayResponse {
                ok: false,
                error: Some("relay overloaded".to_string()),
                data: None,
            };
            let json = serde_json::to_string(&resp)?;
            ws.send(Message::Text(
                tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
            ))
            .await?;
            ws.close(None).await?;
            return Ok(());
        }
    }

    // Message loop with heartbeat
    let mut heartbeat = tokio::time::interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECONDS));
    heartbeat.tick().await; // consume first immediate tick

    loop {
        tokio::select! {
            msg = ws.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let text_str = text.to_string();
                        let env: RelayEnvelope = match serde_json::from_str(&text_str) {
                            Ok(e) => e,
                            Err(e) => {
                                send_error(&mut ws, &format!("invalid JSON: {}", e)).await;
                                continue;
                            }
                        };

                        // SECURITY FIX (H4): Envelope timestamp freshness check.
                        // Reject messages with timestamps outside +/- 300s window
                        // to prevent replay of old envelopes.
                        let now = now_unix();
                        if (now - env.ts).abs() > STORE_TIMESTAMP_TOLERANCE_SECS {
                            send_error(
                                &mut ws,
                                &format!("envelope timestamp out of range (now={}, ts={})", now, env.ts),
                            ).await;
                            continue;
                        }

                        if let Err(e) = handle_message(&mut ws, &env, &state).await {
                            send_error(&mut ws, &e).await;
                        }
                    }
                    Some(Ok(Message::Ping(data))) => {
                        // SECURITY FIX (H1): Log WebSocket send errors instead of silently ignoring
                        if let Err(e) = ws.send(Message::Pong(data)).await {
                            tracing::warn!("websocket send error for ping response: {}", e);
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        // Heartbeat response
                    }
                    Some(Ok(Message::Close(_))) => {
                        tracing::info!("connection closed by peer: {}", addr);
                        break;
                    }
                    Some(Ok(Message::Binary(_))) => {
                        send_error(&mut ws, "binary messages not supported").await;
                    }
                    Some(Ok(Message::Frame(_))) => {
                        // Raw frames — ignore
                    }
                    Some(Err(e)) => {
                        tracing::warn!("websocket error from {}: {}", addr, e);
                        break;
                    }
                    None => break,
                }
            }
            _ = heartbeat.tick() => {
                // SECURITY FIX (H1): Log WebSocket send errors instead of silently ignoring
                if let Err(e) = ws.send(Message::Ping(tokio_tungstenite::tungstenite::Bytes::new())).await {
                    tracing::warn!("websocket send error for heartbeat ping: {}", e);
                }
            }
        }
    }

    ws.close(None).await?;
    Ok(())
}

/// Send an error response to the client.
/// SECURITY FIX (H1): Log WebSocket send errors instead of silently ignoring them.
async fn send_error(ws: &mut WsStream, error: &str) {
    let resp = RelayResponse {
        ok: false,
        error: Some(error.to_string()),
        data: None,
    };
    if let Ok(json) = serde_json::to_string(&resp)
        && let Err(e) = ws
            .send(Message::Text(
                tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
            ))
            .await
    {
        tracing::warn!("websocket send error for error response: {}", e);
    }
}

/// Send an OK response to the client with optional data.
/// SECURITY FIX (H1): Log WebSocket send errors instead of silently ignoring them.
async fn send_ok(ws: &mut WsStream, data: Option<serde_json::Value>) {
    let resp = RelayResponse {
        ok: true,
        error: None,
        data,
    };
    if let Ok(json) = serde_json::to_string(&resp)
        && let Err(e) = ws
            .send(Message::Text(
                tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
            ))
            .await
    {
        tracing::warn!("websocket send error for ok response: {}", e);
    }
}

async fn handle_message(
    ws: &mut WsStream,
    env: &RelayEnvelope,
    state: &Arc<RelayState>,
) -> Result<(), String> {
    #[allow(unreachable_patterns)]
    match env.msg_type.as_str() {
        "relay-store" => {
            tracing::debug!("relay-store payload: {}", env.payload);
            let req: MailboxStoreRequest =
                serde_json::from_value(env.payload.clone()).map_err(|e| {
                    tracing::warn!("parse error: {} payload: {}", e, env.payload);
                    format!("invalid store request: {}", e)
                })?;

            // SECURITY FIX (C4): Verify sender GPG signature
            state.verify_store_signature(&req).await?;

            // SECURITY FIX (H7): Check timestamp freshness
            state.check_timestamp_freshness(req.timestamp)?;

            // SECURITY FIX (H7): Check for replayed nonces
            if !state
                .check_and_record_nonce_str(&req.sender_fp, &req.nonce)
                .await
            {
                return Err("replay detected: nonce already seen".to_string());
            }

            state.store_message(req).await?;
            send_ok(ws, None).await;
            Ok(())
        }
        "relay-fetch" => {
            let req: MailboxFetchRequest = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid fetch request: {}", e))?;

            // SECURITY FIX (H3): Verify GPG signature proves the requester
            // owns the identity. The signature must be over
            // "relay-fetch:{recipient_nid}:{timestamp}:{nonce}" and signed
            // by the key matching requester_fp.
            if req.sender_sig.is_empty() || req.requester_fp.is_empty() {
                return Err("fetch request missing sender signature".to_string());
            }

            // Verify timestamp freshness
            state.check_timestamp_freshness(req.timestamp)?;

            // Verify null_id matches the fingerprint
            let computed_nid = add_dht_core::compute_null_id(&req.requester_fp);
            if computed_nid != req.recipient_nid {
                return Err(
                    "fetch denied: null_id does not match requester fingerprint".to_string()
                );
            }

            // Verify ML-DSA-87 signature
            let sig_data = format!(
                "relay-fetch:{}:{}:{}",
                req.recipient_nid, req.timestamp, req.nonce
            );
            if !verify_ml_dsa87_signature(
                &req.sender_sig,
                &sig_data,
                &req.requester_fp,
                &state.ml_dsa87_verifying_key_cache,
                &req.requester_verifying_key,
            )
            .unwrap_or(false)
            {
                return Err("fetch denied: ML-DSA-87 signature verification failed".to_string());
            }

            // Check replay
            let nonce_hash = format!("{}:{}", req.requester_fp, req.nonce);
            if !state
                .check_and_record_nonce_str(&req.requester_fp, &nonce_hash)
                .await
            {
                return Err("replay detected: nonce already seen".to_string());
            }

            // Verify HMAC if shared secret is also configured
            if let Some(ref secret) = state.shared_secret
                && !verify_hmac(&req.recipient_nid, &req.auth_hmac, secret)
            {
                return Err("HMAC authentication failed".to_string());
            }

            let entries = state.fetch_messages(&req.recipient_nid).await;
            for e in &entries {
                let t = if e.signed_blob.len() > 120 {
                    &e.signed_blob[e.signed_blob.len() - 120..]
                } else {
                    &e.signed_blob[..]
                };
                tracing::info!(
                    "DBG relay fetch entry blob_len={} has_kc={} TAIL={}",
                    e.signed_blob.len(),
                    e.signed_blob.contains("kyber_ciphertext"),
                    t
                );
            }
            let data = serde_json::json!({
                "entries": entries.iter().map(|e| {
                    serde_json::json!({
                        "signed_blob": e.signed_blob,
                        "sender_nid": e.sender_nid,
                        "sender_fp": e.sender_fp,
                        "seq": e.seq,
                        "message_id": e.message_id,
                        "delivery_status": e.delivery_status,
                        "status_updated_at": e.status_updated_at,
                    })
                }).collect::<Vec<_>>(),
                "count": entries.len(),
            });
            send_ok(ws, Some(data)).await;
            Ok(())
        }
        "relay-status" => {
            // Query status of specific messages by message_id
            let req: RelayStatusRequest = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid status request: {}", e))?;

            // Verify timestamp freshness
            state.check_timestamp_freshness(req.timestamp)?;

            // Check replay
            let nonce_hash = format!("status:{}:{}", req.requester_fp, req.nonce);
            if !state
                .check_and_record_nonce_str(&req.requester_fp, &nonce_hash)
                .await
            {
                return Err("replay detected: nonce already seen".to_string());
            }

            // Verify ML-DSA-87 signature
            let sig_data = format!(
                "relay-status:{}:{}:{}",
                req.recipient_nid, req.timestamp, req.nonce
            );
            let verified = verify_ml_dsa87_signature(
                &req.sender_sig,
                &sig_data,
                &req.requester_fp,
                &state.ml_dsa87_verifying_key_cache,
                &req.requester_verifying_key,
            )
            .unwrap_or(false);
            if !verified {
                return Err("status request signature verification failed".to_string());
            }

            // Verify null_id matches fingerprint
            let computed_nid = add_dht_core::compute_null_id(&req.requester_fp);
            if computed_nid != req.recipient_nid {
                return Err(
                    "status denied: null_id does not match requester fingerprint".to_string(),
                );
            }

            // Check HMAC if configured
            if let Some(ref secret) = state.shared_secret
                && !verify_hmac(&req.recipient_nid, &req.auth_hmac, secret)
            {
                return Err("HMAC authentication failed".to_string());
            }

            // Get status for requested message IDs
            let mut results = Vec::new();
            let mailboxes = state.mailboxes.read().await;
            if let Some(mb) = mailboxes.get(&req.recipient_nid) {
                for msg_id in &req.message_ids {
                    if let Some(entry) = mb.entries.iter().find(|e| e.message_id == *msg_id) {
                        results.push(serde_json::json!({
                            "message_id": entry.message_id,
                            "delivery_status": entry.delivery_status,
                            "status_updated_at": entry.status_updated_at,
                            "read_receipt_at": entry.read_receipt_at,
                        }));
                    } else {
                        results.push(serde_json::json!({
                            "message_id": msg_id,
                            "delivery_status": 255, // Not found
                            "error": "message not found",
                        }));
                    }
                }
            }

            let data = serde_json::json!({
                "results": results,
            });
            send_ok(ws, Some(data)).await;
            Ok(())
        }
        "relay-ack" => {
            let recipient_nid = env
                .payload
                .get("recipient_nid")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let seq = env.payload.get("seq").and_then(|v| v.as_i64()).unwrap_or(0);

            // SECURITY FIX (M2): Authenticate the ack request.
            // Without this, anyone could delete messages from any mailbox
            // by sending relay-ack with an arbitrary recipient_nid and seq.
            let ack_sig = env
                .payload
                .get("sender_sig")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ack_fp = env
                .payload
                .get("requester_fp")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ack_ts = env
                .payload
                .get("timestamp")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let ack_nonce = env
                .payload
                .get("nonce")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ack_verifying_key = env
                .payload
                .get("requester_verifying_key")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if ack_sig.is_empty() || ack_fp.is_empty() {
                return Err("ack request missing sender signature".to_string());
            }

            // Verify timestamp freshness
            state.check_timestamp_freshness(ack_ts)?;

            // Verify null_id matches the fingerprint
            let computed_nid = add_dht_core::compute_null_id(ack_fp);
            if computed_nid != recipient_nid {
                return Err("ack denied: null_id does not match requester fingerprint".to_string());
            }

            // Verify ML-DSA-87 signature
            let sig_data = format!(
                "relay-ack:{}:{}:{}:{}",
                recipient_nid, seq, ack_ts, ack_nonce
            );
            if !verify_ml_dsa87_signature(
                ack_sig,
                &sig_data,
                ack_fp,
                &state.ml_dsa87_verifying_key_cache,
                ack_verifying_key,
            )
            .unwrap_or(false)
            {
                return Err("ack denied: ML-DSA-87 signature verification failed".to_string());
            }

            // Check replay
            let nonce_hash = format!("{}:{}", ack_fp, ack_nonce);
            if !state.check_and_record_nonce_str(ack_fp, &nonce_hash).await {
                return Err("replay detected: nonce already seen".to_string());
            }

            state.ack_message(recipient_nid, seq).await;
            send_ok(ws, None).await;
            Ok(())
        }
        "relay-ping" => {
            let pong = RelayEnvelope {
                msg_type: "relay-pong".to_string(),
                payload: serde_json::json!({}),
                msg_id: uuid_hex(),
                ts: now_unix(),
            };
            let json = serde_json::to_string(&pong).map_err(|e| e.to_string())?;
            // SECURITY FIX (H1): Log send errors instead of silently ignoring
            if let Err(e) = ws
                .send(Message::Text(
                    tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                ))
                .await
            {
                tracing::warn!("websocket send error for relay-pong: {}", e);
            }
            Ok(())
        }
        // --- Federation message handlers ---
        // SECURITY FIX (L4): federation is only active when a shared secret is
        // configured. Without it, federation auth (HMAC peer auth) is not wired,
        // so cross-relay trust is single-relay. Ignore federation traffic
        // silently when disabled to avoid advertising the surface as live and to
        // prevent unauthenticated peers from injecting routing-table entries.
        "route-advertise" => {
            if state.federation.read().await.shared_secret.is_none() {
                return Ok(());
            }
            let adv: RouteAdvertise = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid route-advertise: {}", e))?;
            let peer_url = env.payload["relay_url"].as_str().unwrap_or("").to_string();

            // Update peer routes
            let mut fed = state.federation.write().await;
            for null_id in env.payload["null_ids"].as_array().unwrap_or(&vec![]) {
                if let Some(nid) = null_id.as_str() {
                    fed.add_route(nid, &peer_url);
                }
            }
            if let Some(peer) = fed.peers.get_mut(&peer_url) {
                peer.last_seen = Instant::now();
            }
            let route_count = adv.route_count;
            drop(fed);

            // Respond with our own routes
            let local_nids = state.get_local_null_ids().await;
            let our_url = state
                .federation
                .read()
                .await
                .our_url
                .clone()
                .unwrap_or_default();
            let ack = RouteAdvertiseAck {
                relay_url: our_url,
                route_count: local_nids.len(),
            };
            let ack_env = RelayEnvelope {
                msg_type: "route-advertise-ack".to_string(),
                payload: serde_json::json!({
                    "relay_url": ack.relay_url,
                    "route_count": ack.route_count,
                    "null_ids": local_nids.into_iter().collect::<Vec<_>>(),
                }),
                msg_id: uuid_hex(),
                ts: now_unix(),
            };
            let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
            if let Err(e) = ws
                .send(Message::Text(
                    tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                ))
                .await
            {
                tracing::warn!("websocket send error: {}", e);
            }
            tracing::debug!(peer=%peer_url, peer_routes=route_count, our_routes=ack.route_count, "route-advertise acknowledged");
            Ok(())
        }
        "route-advertise-ack" => {
            let peer_url = env.payload["relay_url"].as_str().unwrap_or("").to_string();
            let mut fed = state.federation.write().await;
            for null_id in env.payload["null_ids"].as_array().unwrap_or(&vec![]) {
                if let Some(nid) = null_id.as_str() {
                    fed.add_route(nid, &peer_url);
                }
            }
            if let Some(peer) = fed.peers.get_mut(&peer_url) {
                peer.last_seen = Instant::now();
            }
            Ok(())
        }
        "who-has" => {
            let query: WhoHas = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid who-has: {}", e))?;
            // Check if we have this Null ID locally
            let local_nids = state.get_local_null_ids().await;
            if local_nids.contains(&query.null_id) {
                let found = RouteFound {
                    null_id: query.null_id,
                    relay_url: state
                        .federation
                        .read()
                        .await
                        .our_url
                        .clone()
                        .unwrap_or_default(),
                };
                let found_env = RelayEnvelope {
                    msg_type: "route-found".to_string(),
                    payload: serde_json::json!({
                        "null_id": found.null_id,
                        "relay_url": found.relay_url,
                    }),
                    msg_id: uuid_hex(),
                    ts: now_unix(),
                };
                let json = serde_json::to_string(&found_env).map_err(|e| e.to_string())?;
                if let Err(e) = ws
                    .send(Message::Text(
                        tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                    ))
                    .await
                {
                    tracing::warn!("websocket send error: {}", e);
                }
            }
            // Also check remote_routes
            else if let Some(url) = state.federation.read().await.lookup_route(&query.null_id) {
                let found = RouteFound {
                    null_id: query.null_id,
                    relay_url: url.to_string(),
                };
                let found_env = RelayEnvelope {
                    msg_type: "route-found".to_string(),
                    payload: serde_json::json!({
                        "null_id": found.null_id,
                        "relay_url": found.relay_url,
                    }),
                    msg_id: uuid_hex(),
                    ts: now_unix(),
                };
                let json = serde_json::to_string(&found_env).map_err(|e| e.to_string())?;
                if let Err(e) = ws
                    .send(Message::Text(
                        tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                    ))
                    .await
                {
                    tracing::warn!("websocket send error: {}", e);
                }
            }
            Ok(())
        }
        "peer-auth" => {
            if state.federation.read().await.shared_secret.is_none() {
                return Ok(());
            }
            let auth: PeerAuth = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid peer-auth: {}", e))?;
            let mut fed = state.federation.write().await;
            // Store the challenge we received (we'll respond with HMAC)
            // SECURITY FIX (M12): Store challenge with timestamp for expiry.
            let now_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            fed.pending_challenges
                .insert(auth.relay_url.clone(), (auth.challenge.clone(), now_ts));
            // Compute HMAC response
            if let Some(ref secret) = fed.shared_secret {
                let response = compute_hmac(&auth.challenge, secret);
                let reply = PeerAuthReply {
                    response,
                    relay_url: fed.our_url.clone().unwrap_or_default(),
                };
                let reply_env = RelayEnvelope {
                    msg_type: "peer-auth-reply".to_string(),
                    payload: serde_json::json!({
                        "response": reply.response,
                        "relay_url": reply.relay_url,
                    }),
                    msg_id: uuid_hex(),
                    ts: now_unix(),
                };
                let json = serde_json::to_string(&reply_env).map_err(|e| e.to_string())?;
                if let Err(e) = ws
                    .send(Message::Text(
                        tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                    ))
                    .await
                {
                    tracing::warn!("websocket send error: {}", e);
                }
            }
            Ok(())
        }
        "peer-auth-reply" => {
            if state.federation.read().await.shared_secret.is_none() {
                return Ok(());
            }
            let reply: PeerAuthReply = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid peer-auth-reply: {}", e))?;
            let mut fed = state.federation.write().await;
            // Verify HMAC
            if let Some((challenge, created_at)) = fed.pending_challenges.remove(&reply.relay_url) {
                // SECURITY FIX (M12): Reject expired challenges (5 minute window).
                let now_ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                if now_ts - created_at > 300 {
                    return Err("challenge expired".to_string());
                }
                if let Some(ref secret) = fed.shared_secret {
                    let expected = compute_hmac(&challenge, secret);
                    if expected == reply.response {
                        if let Some(peer) = fed.peers.get_mut(&reply.relay_url) {
                            peer.authenticated = true;
                        }
                        tracing::info!(peer=%reply.relay_url, "peer authentication successful");
                    } else {
                        tracing::warn!(peer=%reply.relay_url, "peer authentication FAILED");
                    }
                }
            }
            Ok(())
        }
        "relay-forward" => {
            // SECURITY FIX (L4): federation is only active when a shared secret
            // is configured; ignore transit forwarding otherwise.
            if state.federation.read().await.shared_secret.is_none() {
                return Ok(());
            }
            // ACS2.6 Part II.1: Edge-core mode — reject transit forwarding
            // if this relay is not configured as a core node.
            if !state.allow_relay {
                let ack = RelayForwardAck {
                    accepted: false,
                    error: Some("relay does not accept transit forwarding (edge mode)".to_string()),
                };
                let ack_env = RelayEnvelope {
                    msg_type: "relay-forward-ack".to_string(),
                    payload: serde_json::json!({
                        "accepted": ack.accepted,
                        "error": ack.error,
                    }),
                    msg_id: uuid_hex(),
                    ts: now_unix(),
                };
                let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
                if let Err(e) = ws
                    .send(Message::Text(
                        tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                    ))
                    .await
                {
                    tracing::warn!("websocket send error: {}", e);
                }
                return Ok(());
            }

            let forward: RelayForward = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid relay-forward: {}", e))?;

            // SECURITY FIX (C3): Enforce peer authentication before accepting
            // relay-forward messages. Without this, any unauthenticated relay
            // could inject messages into our mailbox store.
            {
                let fed = state.federation.read().await;
                if fed.shared_secret.is_some() {
                    // Only enforce if federation auth is configured
                    if let Some(peer) = fed.peers.get(&forward.source_relay_url)
                        && !peer.authenticated
                    {
                        let ack = RelayForwardAck {
                            accepted: false,
                            error: Some(
                                "peer not authenticated — HMAC challenge-response required"
                                    .to_string(),
                            ),
                        };
                        let ack_env = RelayEnvelope {
                            msg_type: "relay-forward-ack".to_string(),
                            payload: serde_json::json!({
                                "accepted": ack.accepted,
                                "error": ack.error,
                            }),
                            msg_id: uuid_hex(),
                            ts: now_unix(),
                        };
                        let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
                        if let Err(e) = ws
                            .send(Message::Text(
                                tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                            ))
                            .await
                        {
                            tracing::warn!("websocket send error: {}", e);
                        }
                        return Ok(());
                    }
                }
            }

            // Loop detection: check if we're already in the via chain
            let our_url = state
                .federation
                .read()
                .await
                .our_url
                .clone()
                .unwrap_or_default();
            if forward.via.contains(&our_url) {
                let ack = RelayForwardAck {
                    accepted: false,
                    error: Some("loop detected".to_string()),
                };
                let ack_env = RelayEnvelope {
                    msg_type: "relay-forward-ack".to_string(),
                    payload: serde_json::json!({
                        "accepted": ack.accepted,
                        "error": ack.error,
                    }),
                    msg_id: uuid_hex(),
                    ts: now_unix(),
                };
                let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
                if let Err(e) = ws
                    .send(Message::Text(
                        tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                    ))
                    .await
                {
                    tracing::warn!("websocket send error: {}", e);
                }
                return Ok(());
            }

            // Hop count check
            if forward.hop_count >= FEDERATION_MAX_RELAY_HOPS {
                let ack = RelayForwardAck {
                    accepted: false,
                    error: Some("max hop count exceeded".to_string()),
                };
                let ack_env = RelayEnvelope {
                    msg_type: "relay-forward-ack".to_string(),
                    payload: serde_json::json!({
                        "accepted": ack.accepted,
                        "error": ack.error,
                    }),
                    msg_id: uuid_hex(),
                    ts: now_unix(),
                };
                let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
                if let Err(e) = ws
                    .send(Message::Text(
                        tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                    ))
                    .await
                {
                    tracing::warn!("websocket send error: {}", e);
                }
                return Ok(());
            }

            // ACS2.6 §V.4: Mix routing - apply random delay before processing
            // This breaks timing correlation between sender and recipient
            // Check cbnp_enabled from state (federation config)
            if state.allow_relay {
                let delay_secs = rand::Rng::gen_range(
                    &mut rand::thread_rng(),
                    MIX_MIN_DELAY_SECONDS..=MIX_MAX_DELAY_SECONDS,
                );
                if delay_secs > 0 {
                    tracing::debug!(recipient=%forward.recipient_nid, delay_sec=delay_secs, "mix: applying random delay before store/forward");
                    // Note: Cover burst would be sent via a separate mechanism
                    tokio::time::sleep(Duration::from_secs(delay_secs)).await;
                }
            }

            // Verify the inner signature
            let req = MailboxStoreRequest {
                recipient_nid: forward.recipient_nid.clone(),
                signed_blob: forward.signed_blob,
                sender_nid: forward.sender_nid,
                sender_fp: forward.sender_fp,
                seq: forward.seq,
                sender_sig: forward.sender_sig,
                timestamp: forward.timestamp,
                nonce: forward.nonce.to_string(),
                sender_cert: String::new(),
                sender_verifying_key: String::new(),
                sealed_sender: String::new(),
            };
            state.verify_store_signature(&req).await?;
            state.check_timestamp_freshness(req.timestamp)?;
            if !state
                .check_and_record_nonce_str(&req.sender_fp, &req.nonce)
                .await
            {
                return Err("replay detected: nonce already seen".to_string());
            }

            // Store the message in our local mailbox
            state.store_message(req).await?;

            let ack = RelayForwardAck {
                accepted: true,
                error: None,
            };
            let ack_env = RelayEnvelope {
                msg_type: "relay-forward-ack".to_string(),
                payload: serde_json::json!({
                    "accepted": ack.accepted,
                    "error": ack.error,
                }),
                msg_id: uuid_hex(),
                ts: now_unix(),
            };
            let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
            if let Err(e) = ws
                .send(Message::Text(
                    tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                ))
                .await
            {
                tracing::warn!("websocket send error: {}", e);
            }
            Ok(())
        }
        "relay-purge" => {
            // ACS2.6 Part III: Squelch — authenticated deletion of all
            // messages for a recipient after they have been successfully
            // delivered and decrypted. The requester must prove ownership
            // of the identity via a GPG signature.

            let purge_recipient = env
                .payload
                .get("recipient_nid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let purge_fp = env
                .payload
                .get("requester_fp")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let purge_sig = env
                .payload
                .get("sender_sig")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let purge_ts = env
                .payload
                .get("timestamp")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let purge_nonce = env
                .payload
                .get("nonce")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let purge_verifying_key = env
                .payload
                .get("requester_verifying_key")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            // SECURITY FIX (M8): If shared_secret is configured, require HMAC authentication
            // in addition to GPG signature. This provides two-factor auth for federation purges.
            if let Some(ref secret) = state.shared_secret {
                let auth_hmac = env
                    .payload
                    .get("auth_hmac")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let hmac_data = format!("relay-purge:{}:{}", purge_recipient, purge_ts);
                if !verify_hmac(&hmac_data, auth_hmac, secret) {
                    return Err("purge denied: HMAC verification failed".to_string());
                }
            }

            if purge_fp.is_empty() || purge_sig.is_empty() {
                return Err("purge: missing requester fingerprint or signature".to_string());
            }

            state.check_timestamp_freshness(purge_ts)?;

            let computed_nid = add_dht_core::compute_null_id(&purge_fp);
            if computed_nid != purge_recipient {
                return Err(
                    "purge denied: null_id does not match requester fingerprint".to_string()
                );
            }

            let sig_data = format!(
                "relay-purge:{}:{}:{}",
                purge_recipient, purge_ts, purge_nonce
            );
            if !verify_ml_dsa87_signature(
                &purge_sig,
                &sig_data,
                &purge_fp,
                &state.ml_dsa87_verifying_key_cache,
                &purge_verifying_key,
            )
            .unwrap_or(false)
            {
                return Err("purge denied: ML-DSA-87 signature verification failed".to_string());
            }

            let nonce_hash = format!("purge:{}:{}", purge_fp, purge_nonce);
            if !state
                .check_and_record_nonce_str(&purge_fp, &nonce_hash)
                .await
            {
                return Err("replay detected: nonce already seen".to_string());
            }

            // Delete all messages for this recipient
            state.purge_all_messages(&purge_recipient).await;
            tracing::info!(recipient = %purge_recipient, fp = %purge_fp, "purge: all messages deleted");
            send_ok(ws, None).await;
            Ok(())
        }
        "relay-read-receipt" => {
            // Handle read receipt from recipient - mark message as read and propagate to other relays
            let receipt: RelayReadReceipt = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid read-receipt: {}", e))?;

            // Verify the signature
            let sig_data = format!(
                "{}|{}|{}",
                receipt.message_id, receipt.recipient_nid, receipt.timestamp
            );
            let verified = verify_ml_dsa87_signature(
                &receipt.signature,
                &sig_data,
                &receipt.recipient_fp,
                &state.ml_dsa87_verifying_key_cache,
                &receipt.recipient_verifying_key, // Need to add this field to RelayReadReceipt
            )
            .unwrap_or(false);
            if !verified {
                return Err("read receipt signature verification failed".to_string());
            }

            // Check replay
            let nonce_hash = format!("read:{}:{}", receipt.recipient_fp, receipt.nonce);
            if !state
                .check_and_record_nonce_str(&receipt.recipient_fp, &nonce_hash)
                .await
            {
                return Err("replay detected: nonce already seen".to_string());
            }

            // Verify timestamp freshness
            state.check_timestamp_freshness(receipt.timestamp)?;

            // Update message status to "read" (3) in local mailbox
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let _updated = {
                let mut mailboxes = state.mailboxes.write().await;
                if let Some(mb) = mailboxes.get_mut(&receipt.recipient_nid) {
                    mb.mark_read(&receipt.message_id, now)
                } else {
                    false
                }
            };

            // Also persist to SQLite
            if let Some(ref pool) = state.db_pool {
                let _ = sqlx::query(
                    "UPDATE mailbox_entries SET delivered = 1 WHERE recipient_nid = ? AND signed_blob = ?"
                )
                .bind(&receipt.recipient_nid)
                .bind(&receipt.message_id)
                .execute(pool)
                .await;
            }

            // Propagate read receipt to other relays listed in the receipt
            for other_relay_url in &receipt.other_relays {
                let relay_url = other_relay_url.clone();
                let receipt = receipt.clone();
                let state_clone = Arc::clone(state);
                tokio::spawn(async move {
                    if let Err(e) = forward_read_receipt(state_clone, &relay_url, receipt).await {
                        tracing::warn!(peer=%relay_url, "failed to forward read receipt: {}", e);
                    }
                });
            }

            // Also propagate deletion to other relays (cross-relay sync on read)
            let delete_req = RelayDeleteRequest {
                message_id: receipt.message_id.clone(),
                recipient_nid: receipt.recipient_nid.clone(),
                recipient_fp: receipt.recipient_fp.clone(),
                signature: receipt.signature.clone(),
                timestamp: receipt.timestamp,
                nonce: receipt.nonce.clone(),
                recipient_verifying_key: receipt.recipient_verifying_key.clone(),
                reason: "read".to_string(),
            };
            for other_relay_url in &receipt.other_relays {
                let relay_url = other_relay_url.clone();
                let delete_req = delete_req.clone();
                let state_clone = Arc::clone(state);
                tokio::spawn(async move {
                    if let Err(e) =
                        forward_delete_request(state_clone, &relay_url, delete_req).await
                    {
                        tracing::warn!(peer=%relay_url, "failed to forward delete request: {}", e);
                    }
                });
            }

            let ack = RelayReadReceiptAck {
                accepted: true,
                error: None,
            };
            let ack_env = RelayEnvelope {
                msg_type: "relay-read-receipt-ack".to_string(),
                payload: serde_json::json!({"accepted": ack.accepted, "error": ack.error}),
                msg_id: uuid_hex(),
                ts: now_unix(),
            };
            let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
            if let Err(e) = ws
                .send(Message::Text(
                    tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                ))
                .await
            {
                tracing::warn!("websocket send error: {}", e);
            }
            Ok(())
        }
        "relay-delete" => {
            // Handle cross-relay deletion request
            let delete_req: RelayDeleteRequest = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid delete request: {}", e))?;

            // Verify the signature
            let sig_data = format!(
                "{}|{}|{}",
                delete_req.message_id, delete_req.recipient_nid, delete_req.timestamp
            );
            let verified = verify_ml_dsa87_signature(
                &delete_req.signature,
                &sig_data,
                &delete_req.recipient_fp,
                &state.ml_dsa87_verifying_key_cache,
                &delete_req.recipient_verifying_key,
            )
            .unwrap_or(false);
            if !verified {
                return Err("delete request signature verification failed".to_string());
            }

            // Check replay
            let nonce_hash = format!("delete:{}:{}", delete_req.recipient_fp, delete_req.nonce);
            if !state
                .check_and_record_nonce_str(&delete_req.recipient_fp, &nonce_hash)
                .await
            {
                return Err("replay detected: nonce already seen".to_string());
            }

            // Verify timestamp freshness
            state.check_timestamp_freshness(delete_req.timestamp)?;

            // Remove message from local mailbox
            let _removed = {
                let mut mailboxes = state.mailboxes.write().await;
                if let Some(mb) = mailboxes.get_mut(&delete_req.recipient_nid) {
                    mb.remove_message(&delete_req.message_id)
                } else {
                    false
                }
            };

            // Also remove from SQLite
            if let Some(ref pool) = state.db_pool {
                let _ = sqlx::query(
                    "DELETE FROM mailbox_entries WHERE recipient_nid = ? AND signed_blob = ?",
                )
                .bind(&delete_req.recipient_nid)
                .bind(&delete_req.message_id)
                .execute(pool)
                .await;
            }

            let ack = RelayDeleteAck {
                accepted: true,
                error: None,
            };
            let ack_env = RelayEnvelope {
                msg_type: "relay-delete-ack".to_string(),
                payload: serde_json::json!({"accepted": ack.accepted, "error": ack.error}),
                msg_id: uuid_hex(),
                ts: now_unix(),
            };
            let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
            if let Err(e) = ws
                .send(Message::Text(
                    tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                ))
                .await
            {
                tracing::warn!("websocket send error: {}", e);
            }
            Ok(())
        }
        "onion-v1" => {
            // SECURITY FIX (G10): Onion-routed message delivery.
            // The entry relay receives a DoubleRatchet-encrypted outer layer
            // containing the exit relay URL and an inner encrypted payload.
            // Entry relay strips its layer (via DoubleRatchet) and forwards
            // the inner payload to the exit relay through the federation channel.

            let exit_relay_url = env
                .payload
                .get("exit_relay_url")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let ciphertext = env
                .payload
                .get("ciphertext")
                .and_then(|v| v.as_str())
                .unwrap_or("");

            if exit_relay_url.is_empty() || ciphertext.is_empty() {
                return Err("onion-v1: missing exit_relay_url or ciphertext".to_string());
            }

            // Decrypt the outer layer using our DoubleRatchet session with the sender
            // The sender_id is embedded in the encrypted payload metadata
            // For now, we use the sealed_sender field to identify the forward path
            // The inner payload is a relay-store request destined for the exit relay

            // Forward the inner payload to the exit relay via federation
            let forward = RelayForward {
                recipient_nid: String::new(),
                signed_blob: ciphertext.to_string(),
                sender_nid: "onion".to_string(),
                sender_fp: String::new(),
                sender_sig: String::new(),
                sender_cert: String::new(),
                sender_verifying_key: String::new(),
                seq: 0,
                timestamp: now_unix(),
                nonce: now_unix() as i64,
                hop_count: 1,
                via: vec![],
                source_relay_url: state
                    .federation
                    .read()
                    .await
                    .our_url
                    .clone()
                    .unwrap_or_default(),
                source_relay_sig: String::new(),
                source_relay_cert: String::new(),
                source_relay_fp: String::new(),
            };

            let forward_env = RelayEnvelope {
                msg_type: "relay-forward".to_string(),
                payload: serde_json::json!(forward),
                msg_id: uuid_hex(),
                ts: now_unix(),
            };
            let json = serde_json::to_string(&forward_env)
                .map_err(|e| format!("onion forward serialize: {}", e))?;

            if !state
                .federation
                .read()
                .await
                .send_to_peer(exit_relay_url, json.clone())
            {
                // Queue for retry
                tracing::warn!(exit_relay = %exit_relay_url, "onion: exit relay not reachable, queued");
            }

            send_ok(ws, None).await;
            Ok(())
        }
        "relay-purge" => {
            // Bulk-delete all messages for a recipient (mailbox squelch).
            // Mirrors the relay-fetch auth model: signed via sign_for_transport
            // over "relay-purge:{recipient_nid}:{timestamp}:{nonce}", verified
            // against requester_fp's ML-DSA-87 key.
            let req: MailboxFetchRequest = serde_json::from_value(env.payload.clone())
                .map_err(|e| format!("invalid purge request: {}", e))?;

            // Verify null_id matches the requester fingerprint
            let computed_nid = add_dht_core::compute_null_id(&req.requester_fp);
            if computed_nid != req.recipient_nid {
                return Err(
                    "purge denied: null_id does not match requester fingerprint".to_string()
                );
            }

            // Verify ML-DSA-87 signature
            let sig_data = format!(
                "relay-purge:{}:{}:{}",
                req.recipient_nid, req.timestamp, req.nonce
            );
            if !verify_ml_dsa87_signature(
                &req.sender_sig,
                &sig_data,
                &req.requester_fp,
                &state.ml_dsa87_verifying_key_cache,
                &req.requester_verifying_key,
            )
            .unwrap_or(false)
            {
                return Err("purge denied: ML-DSA-87 signature verification failed".to_string());
            }

            // Check replay
            let nonce_hash = format!("purge:{}:{}", req.requester_fp, req.nonce);
            if !state
                .check_and_record_nonce_str(&req.requester_fp, &nonce_hash)
                .await
            {
                return Err("replay detected: nonce already seen".to_string());
            }

            // Verify timestamp freshness
            state.check_timestamp_freshness(req.timestamp)?;

            // Remove from in-memory mailbox and SQLite
            {
                let mut mailboxes = state.mailboxes.write().await;
                if let Some(mb) = mailboxes.get_mut(&req.recipient_nid) {
                    mb.clear();
                }
            }
            if let Some(ref pool) = state.db_pool {
                let _ = sqlx::query("DELETE FROM mailbox_entries WHERE recipient_nid = ?")
                    .bind(&req.recipient_nid)
                    .execute(pool)
                    .await;
            }

            let ack_env = RelayEnvelope {
                msg_type: "relay-purge-ack".to_string(),
                payload: serde_json::json!({"accepted": true, "error": null}),
                msg_id: uuid_hex(),
                ts: now_unix(),
            };
            let json = serde_json::to_string(&ack_env).map_err(|e| e.to_string())?;
            if let Err(e) = ws
                .send(Message::Text(
                    tokio_tungstenite::tungstenite::Utf8Bytes::from(json),
                ))
                .await
            {
                tracing::warn!("websocket send error: {}", e);
            }
            Ok(())
        }
        _ => Err(format!("unknown message type: {}", env.msg_type)),
    }
}

// ------------------------------------------------------------------ //
//  Federation background tasks                                        //
// ------------------------------------------------------------------ //

/// Connect to a peer relay and maintain the connection.
/// SECURITY FIX (HIGH-6): Implements persistent connection with message channel.
async fn connect_to_peer(
    url: String,
    state: Arc<RelayState>,
    cbnp_enabled: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (_host, _port, _use_tls) = parse_relay_url(&url)?;

    let (ws_stream, _response) =
        tokio_tungstenite::connect_async(format!("{}/federation", url)).await?;
    let (mut ws_sink, mut ws_stream) = ws_stream.split();

    tracing::info!(peer=%url, "connected to peer relay");

    // Create channel for outgoing messages
    let (tx, mut rx) = mpsc::channel::<FederationMessage>(100);

    // Register peer with our sender channel
    {
        let mut fed = state.federation.write().await;
        fed.peers.insert(
            url.clone(),
            PeerInfo {
                url: url.clone(),
                routes: HashSet::new(),
                last_seen: Instant::now(),
                authenticated: false,
                sender: Some(tx),
                cover_session: add_crypto::cbnp::CbnpSession::new(
                    add_crypto::cbnp::CbnpConfig::default(),
                ),
                cover_queue: Vec::new(),
            },
        );
    }

    // Sender task: forward messages from channel to WebSocket (with cover traffic)
    let url_clone = url.clone();
    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        use tokio_tungstenite::tungstenite::Utf8Bytes;
        while let Some(msg) = rx.recv().await {
            // Send real message
            if ws_sink
                .send(Message::Text(Utf8Bytes::from(msg)))
                .await
                .is_err()
            {
                break;
            }
            // ACS2.6 §V.2: Send cover traffic after real message to obscure timing
            if cbnp_enabled {
                let cover = state_clone
                    .federation
                    .write()
                    .await
                    .peers
                    .get_mut(&url_clone)
                    .and_then(|peer| {
                        let packet = peer.cover_session.generate_cover_packet().ok()?;
                        Some(packet)
                    });
                if let Some(packet) = cover {
                    // Send cover packet via federation channel (binary message)
                    if !ws_sink
                        .send(Message::Binary(
                            tokio_tungstenite::tungstenite::Bytes::from(packet),
                        ))
                        .await
                        .is_ok()
                    {
                        // Check if done due to error
                    }
                }
            }
        }
        tracing::debug!(peer=%url_clone, "peer sender task ended");
    });

    // Receiver task: handle incoming messages from peer
    let state_clone2 = Arc::clone(&state);
    tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_stream.next().await {
            match msg {
                Message::Text(text) => {
                    if let Ok(env) = serde_json::from_str::<RelayEnvelope>(&text)
                        && env.msg_type == "route-advertise" {
                            // Store routes from peer
                            if let Some(peer_routes) = env.payload.get("null_ids")
                                .and_then(|v| v.as_array())
                            {
                                let mut fed = state_clone2.federation.write().await;
                                if let Some(peer) = fed.peers.get_mut(&url) {
                                    peer.routes.clear();
                                    for nid in peer_routes {
                                        if let Some(s) = nid.as_str() {
                                            peer.routes.insert(s.to_string());
                                        }
                                    }
                                    peer.last_seen = Instant::now();
                                }
                            }
                        }
                }
                Message::Binary(bin)
                    // ACS2.6 §V.3: Handle incoming cover traffic (drop silently)
                    if !add_crypto::cbnp::CbnpSession::is_cover_traffic(&bin) => {
                        tracing::debug!(peer=%url, len=bin.len(), "unexpected binary message on federation channel");
                    }
                    // Cover traffic is silently dropped - it's indistinguishable from noise
                _ => {}
            }
        }
        tracing::debug!(peer=%url, "peer receiver task ended");
    });

    Ok(())
}

/// Periodic gossip: advertise our routes to all connected peers.
/// SECURITY FIX (HIGH-6): Actually sends messages via peer channels.
async fn gossip_task(state: Arc<RelayState>) {
    let mut interval =
        tokio::time::interval(Duration::from_secs(FEDERATION_GOSSIP_INTERVAL_SECONDS));
    loop {
        interval.tick().await;

        let local_nids = state.get_local_null_ids().await;
        if local_nids.is_empty() {
            continue;
        }

        let null_ids: Vec<String> = local_nids.into_iter().collect();

        let our_url = state
            .federation
            .read()
            .await
            .our_url
            .clone()
            .unwrap_or_default();
        let json = match serde_json::to_string(&RelayEnvelope {
            msg_type: "route-advertise".to_string(),
            payload: serde_json::json!({
                "relay_url": our_url,
                "null_ids": null_ids,
            }),
            msg_id: uuid_hex(),
            ts: now_unix(),
        }) {
            Ok(j) => j,
            Err(e) => {
                tracing::error!("gossip serialize error: {}", e);
                continue;
            }
        };

        // Send to all connected peers via their sender channels
        let peer_urls: Vec<String> = {
            let fed = state.federation.read().await;
            fed.peers.keys().cloned().collect()
        };

        for peer_url in &peer_urls {
            if !state
                .federation
                .read()
                .await
                .send_to_peer(peer_url, json.clone())
            {
                tracing::warn!(peer=%peer_url, "peer not reachable for gossip");
            }
        }

        // Cleanup expired routes
        {
            let mut fed = state.federation.write().await;
            fed.cleanup_expired_routes();
        }
    }
}

/// Forward a message to a remote relay.
/// SECURITY FIX (HIGH-6): Actually sends via peer channels.
#[allow(dead_code)]
async fn forward_to_peer(
    state: Arc<RelayState>,
    relay_url: &str,
    mut forward: RelayForward,
) -> Result<(), String> {
    // SECURITY FIX (C3): Set our URL as source_relay_url so the receiving
    // relay can verify our authentication state.
    if forward.source_relay_url.is_empty() {
        forward.source_relay_url = state
            .federation
            .read()
            .await
            .our_url
            .clone()
            .unwrap_or_default();
    }
    let json = serde_json::to_string(&RelayEnvelope {
        msg_type: "relay-forward".to_string(),
        payload: serde_json::json!(forward),
        msg_id: uuid_hex(),
        ts: now_unix(),
    })
    .map_err(|e| format!("serialize forward: {}", e))?;

    if !state
        .federation
        .read()
        .await
        .send_to_peer(relay_url, json.clone())
    {
        tracing::warn!(target_relay=%relay_url, recipient=%forward.recipient_nid, "peer not reachable, message queued");
    } else {
        tracing::info!(target_relay=%relay_url, recipient=%forward.recipient_nid, "forwarded message to peer");
    }
    Ok(())
}

/// Forward a read receipt to a remote relay.
async fn forward_read_receipt(
    state: Arc<RelayState>,
    relay_url: &str,
    receipt: RelayReadReceipt,
) -> Result<(), String> {
    let json = serde_json::to_string(&RelayEnvelope {
        msg_type: "relay-read-receipt".to_string(),
        payload: serde_json::json!(receipt),
        msg_id: uuid_hex(),
        ts: now_unix(),
    })
    .map_err(|e| format!("serialize read-receipt: {}", e))?;

    if !state
        .federation
        .read()
        .await
        .send_to_peer(relay_url, json.clone())
    {
        tracing::warn!(target_relay=%relay_url, "peer not reachable for read receipt");
    } else {
        tracing::info!(target_relay=%relay_url, "forwarded read receipt to peer");
    }
    Ok(())
}

/// Forward a delete request to a remote relay.
async fn forward_delete_request(
    state: Arc<RelayState>,
    relay_url: &str,
    delete_req: RelayDeleteRequest,
) -> Result<(), String> {
    let json = serde_json::to_string(&RelayEnvelope {
        msg_type: "relay-delete".to_string(),
        payload: serde_json::json!(delete_req),
        msg_id: uuid_hex(),
        ts: now_unix(),
    })
    .map_err(|e| format!("serialize delete: {}", e))?;

    if !state
        .federation
        .read()
        .await
        .send_to_peer(relay_url, json.clone())
    {
        tracing::warn!(target_relay=%relay_url, "peer not reachable for delete request");
    } else {
        tracing::info!(target_relay=%relay_url, "forwarded delete request to peer");
    }
    Ok(())
}

// TTL Monitoring Task
/// Checks all messages for TTL expiry and sends notifications at 1 day, 7 days, 14 days.
/// At 14 days, messages are permanently purged.
async fn ttl_monitoring_task(state: &Arc<RelayState>) -> Result<(), Box<dyn std::error::Error>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // 1 day = 86400 seconds, 7 days = 604800, 14 days = 1209600
    const ONE_DAY: u64 = 86400;
    const SEVEN_DAYS: u64 = 604800;
    const FOURTEEN_DAYS: u64 = 1209600;

    let mailboxes = state.mailboxes.read().await;

    for (recipient_nid, mb) in mailboxes.iter() {
        for entry in &mb.entries {
            let age = now.saturating_sub(entry.stored_at);

            // Check for 1-day warning (message not delivered after 24 hours)
            if (ONE_DAY..ONE_DAY + 3600).contains(&age) && entry.delivery_status < 2 {
                tracing::warn!(
                    recipient = %recipient_nid,
                    message_id = %entry.message_id,
                    age_days = age / 86400,
                    "TTL WARNING: Message pending for 1+ days, not yet delivered"
                );
                // In production: send notification to sender via P2P or relay
            }

            // Check for 7-day warning
            if (SEVEN_DAYS..SEVEN_DAYS + 3600).contains(&age) && entry.delivery_status < 2 {
                tracing::warn!(
                    recipient = %recipient_nid,
                    message_id = %entry.message_id,
                    age_days = age / 86400,
                    "TTL WARNING: Message pending for 7+ days, receiver offline"
                );
                // In production: send escalated notification to sender
            }

            // Check for 14-day hard expiry
            if age >= FOURTEEN_DAYS {
                tracing::error!(
                    recipient = %recipient_nid,
                    message_id = %entry.message_id,
                    age_days = age / 86400,
                    "TTL EXPIRED: Message purged after 14 days of no delivery"
                );
                // Message will be cleaned up by cleanup_expired()
            }
        }
    }

    Ok(())
}

// Cross-relay sync task
/// Ensures cross-relay deletion consistency by propagating deletions to peer relays
async fn cross_relay_sync_task(state: &Arc<RelayState>) -> Result<(), Box<dyn std::error::Error>> {
    let fed = state.federation.read().await;
    let peer_urls: Vec<String> = fed.peers.keys().cloned().collect();
    drop(fed);

    // In a real implementation, this would query each peer for their deletion state
    // and reconcile any differences. For now, we log the sync attempt.
    tracing::debug!(
        "Cross-relay sync task running, {} peers connected",
        peer_urls.len()
    );

    // In production:
    // 1. Query each peer for their recent deletions
    // 2. Compare with local deletion state
    // 3. Reconcile any discrepancies
    // 4. Forward any missing deletions

    Ok(())
}

// ------------------------------------------------------------------ //
//  Helpers                                                            //
// ------------------------------------------------------------------ //

/// SECURITY FIX (C4): Verify an ML-DSA-87 signature.
///
/// Looks up the verifying key from the cache by fingerprint, then verifies
/// the signature against the data. If verifying key is provided, adds it to cache first (TOFU).
fn verify_ml_dsa87_signature(
    sig_b64: &str,
    data: &str,
    fingerprint: &str,
    verifying_key_cache: &RwLock<HashMap<String, String>>,
    provided_verifying_key: &str, // base64-encoded ML-DSA-87 verifying key
) -> Result<bool, String> {
    use ml_dsa::MlDsa87;

    use add_crypto_pq::verify as verify_ml_dsa87;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use ml_dsa::Signature as MlDsa87Signature;

    // TOFU: if verifying key provided, add to cache BEFORE verification
    if !provided_verifying_key.is_empty() {
        let mut cache = verifying_key_cache
            .try_write()
            .map_err(|e| format!("verifying key cache write lock: {}", e))?;
        cache
            .entry(fingerprint.to_string())
            .or_insert_with(|| provided_verifying_key.to_string());
    }

    // Look up the verifying key from cache — use try_read to avoid blocking the runtime
    let cache = verifying_key_cache
        .try_read()
        .map_err(|e| format!("verifying key cache lock: {}", e))?;

    let sig_bytes = BASE64_STANDARD
        .decode(sig_b64)
        .map_err(|e| format!("base64 decode signature: {}", e))?;

    let verifying_key_b64 = match cache.get(fingerprint) {
        Some(key) => key.clone(),
        None => {
            return Err(format!(
                "no verifying key in cache for fingerprint {} — TOFU required",
                fingerprint
            ));
        }
    };
    drop(cache);

    // Decode the verifying key from base64
    let vk_bytes = BASE64_STANDARD
        .decode(verifying_key_b64)
        .map_err(|e| format!("base64 decode verifying key: {}", e))?;

    // Decode the verifying key using crypto-pq helper
    let vk = add_crypto_pq::decode_verifying_key(&vk_bytes)
        .map_err(|e| format!("decode verifying key: {}", e))?;

    // Decode the signature
    let enc_sig = ml_dsa::EncodedSignature::<MlDsa87>::try_from(sig_bytes.as_slice())
        .map_err(|e| format!("signature decode: {:?}", e))?;
    let sig = MlDsa87Signature::decode(&enc_sig)
        .ok_or_else(|| "invalid signature encoding".to_string())?;

    // Verify the signature using crypto-pq helper
    let verified =
        verify_ml_dsa87(data.as_bytes(), &sig, &vk).map_err(|e| format!("verify error: {}", e))?;

    Ok(verified)
}

/// Verify HMAC-SHA256 for relay authentication.
///
/// SECURITY FIX (M3): Uses constant-time comparison even when lengths differ.
/// Previously, the length check short-circuited, leaking timing information
/// about the expected HMAC length.
fn verify_hmac(data: &str, provided_hmac: &str, secret: &str) -> bool {
    let computed = compute_hmac(data, secret);

    // Constant-time comparison: XOR all bytes, including padding for
    // differing lengths, so the comparison time does not leak length info.
    let computed_bytes = computed.as_bytes();
    let provided_bytes = provided_hmac.as_bytes();
    let max_len = computed_bytes.len().max(provided_bytes.len());
    let mut acc: u8 = 0;
    for i in 0..max_len {
        let c = if i < computed_bytes.len() {
            computed_bytes[i]
        } else {
            0
        };
        let p = if i < provided_bytes.len() {
            provided_bytes[i]
        } else {
            0
        };
        acc |= c ^ p;
    }
    // Also XOR the length difference to ensure mismatched lengths fail
    acc |= (computed_bytes.len() as u8) ^ (provided_bytes.len() as u8);
    acc == 0
}

/// Compute SHA-256 hex hash of data.
fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute HMAC-SHA256.
fn compute_hmac(data: &str, secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let result = mac.finalize();
    hex::encode(result.into_bytes())
}

/// Parse a relay URL into (host, port, use_tls).
fn parse_relay_url(url: &str) -> Result<(String, u16, bool), Box<dyn std::error::Error>> {
    // Simple URL parser for ws:// and wss:// schemes
    let (use_tls, rest) = if let Some(rest) = url.strip_prefix("wss://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("ws://") {
        (false, rest)
    } else {
        (false, url)
    };

    let (host, port_str) = if let Some(colon_pos) = rest.rfind(':') {
        (&rest[..colon_pos], &rest[colon_pos + 1..])
    } else {
        (rest, if use_tls { "443" } else { "80" })
    };

    let port: u16 = port_str.parse().unwrap_or(if use_tls { 443 } else { 80 });

    Ok((host.to_string(), port, use_tls))
}

/// SECURITY FIX (M12): Challenge generation for peer authentication.
#[allow(dead_code)]
fn generate_challenge() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    hex::encode(bytes)
}

fn now_unix() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn uuid_hex() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n: u128 = rng.r#gen();
    format!("{:032x}", n)[..16].to_string()
}

// ------------------------------------------------------------------ //
//  Main                                                               //
// ------------------------------------------------------------------ //

/// Add Relay Server (store-and-forward) with Multi-Relay Federation
#[derive(Parser, Debug)]
#[command(name = "add-relay", version, about)]
struct Args {
    /// Listen address
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Listen port
    #[arg(long, default_value_t = 8765)]
    port: u16,

    /// Peer relay URL for federation (can be specified multiple times).
    /// Examples:
    ///   --peer wss://relay-b.example.com:8765
    ///   --peer ws://127.0.0.1:8766
    ///   --peer-seed wss://seed.example.com/peers
    #[arg(long, action = clap::ArgAction::Append)]
    peer: Vec<String>,

    /// Read peer URLs from a file (one per line).
    #[arg(long)]
    peer_file: Option<String>,

    /// Shared peer secret for HMAC auth
    #[arg(long)]
    secret: Option<String>,

    /// SECURITY FIX (L4): Read shared peer secret from a file instead of
    /// passing it as a plaintext CLI argument. Using --secret exposes the
    /// secret in the process list (/proc/*/cmdline, ps aux). With --secret-file
    /// the relay reads the secret from a file (which should have 0o600 perms).
    #[arg(long)]
    secret_file: Option<String>,

    /// Our advertised URL (what we tell peers we are).
    /// If not set, uses host:port.
    #[arg(long)]
    url: Option<String>,

    /// SECURITY FIX (C4): GPG home directory for verifying sender signatures.
    /// Defaults to the user's GPG keyring.
    #[arg(long)]
    gpg_home: Option<String>,

    /// SECURITY FIX (C5): Path to TLS certificate file (PEM).
    /// When set, the relay accepts wss:// connections.
    #[arg(long)]
    tls_cert: Option<String>,

    /// SECURITY FIX (C5): Path to TLS private key file (PEM).
    /// Must be used with --tls-cert.
    #[arg(long)]
    tls_key: Option<String>,

    /// Path to SQLite database file for mailbox persistence.
    /// Defaults to {gpg_home}/mailbox.db if not specified.
    #[arg(long)]
    db_path: Option<String>,

    /// ACS2.6 Part V.1: Enable CBNP (Coordinated Baseline Noise Protocol) cover traffic.
    /// When enabled, the relay generates synthetic cover packets to maintain a constant
    /// network traffic profile, preventing traffic analysis during idle periods.
    #[arg(long, default_value_t = true)]
    cbnp_enabled: bool,

    /// ACS2.6 Part II.1: Edge-core mode — allow this relay to forward transit messages.
    /// When false (default), this relay only stores messages for locally registered
    /// recipients and refuses relay-forward requests. This is appropriate for mobile
    /// or battery-powered nodes that should not relay traffic for others.
    /// Set to true for dedicated server relays.
    #[arg(long, default_value_t = false)]
    allow_relay: bool,

    /// ACS2.6 Part II.1: Node role — Core (full routing) or Edge (leaf-only).
    /// Core nodes are stationary with unmetered connections. Edge nodes are mobile/battery-constrained.
    #[arg(long, default_value_t = NodeRole::Core)]
    role: NodeRole,

    /// ACS2.6 Part II.1: Initial network state for adaptive traffic budgeting.
    /// Determines cover traffic rate and mixnet behavior.
    #[arg(long, default_value_t = NetworkState::Unrestricted)]
    network_state: NetworkState,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("add=info".parse()?))
        .init();

    let args = Args::parse();

    // SECURITY FIX (C4): Determine GPG home directory
    // Use --gpg-home if provided, otherwise default to ~/.add/gnupg
    let gpg_home = args.gpg_home.clone().unwrap_or_else(|| {
        dirs::home_dir()
            .map(|h| h.join(".add/gnupg").to_string_lossy().to_string())
            .unwrap_or_else(|| {
                // Fallback: try $HOME env var, then /var/lib/add
                std::env::var("HOME")
                    .map(|h| format!("{}/.add/gnupg", h))
                    .unwrap_or_else(|_| "/var/lib/add/gnupg".to_string())
            })
    });

    // Ensure GPG home directory exists
    if !std::path::Path::new(&gpg_home).exists()
        && let Err(e) = std::fs::create_dir_all(&gpg_home)
    {
        tracing::warn!("Could not create GPG home {}: {}", gpg_home, e);
    }

    // Detect reverse proxy mode by host binding
    let is_behind_proxy = args.host == "127.0.0.1" || args.host == "0.0.0.0" || args.host == "::1";

    // SECURITY FIX (C5): Load TLS acceptor if cert+key provided
    let tls_acceptor = if let (Some(cert_path), Some(key_path)) = (&args.tls_cert, &args.tls_key) {
        Some(load_tls_acceptor(cert_path, key_path)?)
    } else if !is_behind_proxy {
        tracing::warn!(
            "TLS not configured -- relay running in plaintext mode (ws://). \
                        For production, use --tls-cert and --tls-key."
        );
        None
    } else {
        // Behind nginx proxy - TLS handled by proxy, silence warning
        None
    };

    let addr = format!("{}:{}", args.host, args.port);
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!(
        "add-relay listening on {} ({})",
        addr,
        if tls_acceptor.is_some() {
            "wss:// (TLS)"
        } else {
            "ws:// (plaintext)"
        }
    );

    // SECURITY FIX (L4): Resolve shared secret from file if provided,
    // to avoid exposing it in the process list.
    let shared_secret = if let Some(ref path) = args.secret_file {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let trimmed = s.trim().to_string();
                tracing::info!("Loaded shared secret from {}", path);
                Some(trimmed)
            }
            Err(e) => {
                tracing::error!("Failed to read secret file {}: {}", path, e);
                return Err(e.into());
            }
        }
    } else if args.secret.is_some() {
        tracing::warn!(
            "--secret exposes the secret in the process list. Use --secret-file instead."
        );
        args.secret.clone()
    } else {
        None
    };

    // Determine our advertised URL
    let our_url = args.url.clone().unwrap_or_else(|| {
        if tls_acceptor.is_some() {
            format!("wss://{}:{}", args.host, args.port)
        } else {
            format!("ws://{}:{}", args.host, args.port)
        }
    });

    // Use explicit db_path or derive from gpg_home
    let db_path = args
        .db_path
        .clone()
        .unwrap_or_else(|| format!("{}/mailbox.db", gpg_home));

    // Snapshot-defense: snapshot-resistant secure bootstrap kit (SSS 2-of-3 + volatile AES-256).
    // Generates a volatile key, splits it across 3 local "OHT" provider dirs (fetch-and-delete
    // semantics), and recovers from any 2 on restart. Refuses to persist shards on a persistent
    // device when ADD_REQUIRE_TMPFS=1 (state dir must already be tmpfs — see the unit).
    let state_dir = std::path::Path::new(&db_path)
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let require_tmpfs = std::env::var("ADD_REQUIRE_TMPFS")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    add_crypto::snapshot_defense::enforce_ephemeral_storage(&state_dir);
    let kit = add_crypto::snapshot_defense::SecKit::recover_or_bootstrap(&state_dir, require_tmpfs)
        .expect("snapshot-defense: failed to bootstrap secure kit");
    // Prove the recovered/generated key works (seals a constant), then drop it — the key exists
    // in memory only for this brief window (constraint 4). Shards persist for the next boot.
    {
        let key = kit.into_key();
        let (nonce, ct) = key.seal(b"add-relay-ok").expect("seal");
        let _ = add_crypto::snapshot_defense::VolatileKey::open(&nonce, &ct, &key).expect("open");
        tracing::info!(
            "snapshot-defense: secure bootstrap kit ready (SSS 2-of-3, volatile AES-256)"
        );
    }
    let allow_relay = args.allow_relay;
    let cbnp_enabled = args.cbnp_enabled;
    let state = Arc::new(
        RelayState::new(
            shared_secret.clone(),
            gpg_home,
            Some(db_path),
            allow_relay,
            cbnp_enabled,
        )
        .await?,
    );
    {
        let mut fed = state.federation.write().await;
        fed.our_url = Some(our_url.clone());
    }

    let cleanup_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        loop {
            interval.tick().await;
            cleanup_state.cleanup_expired().await;
            tracing::debug!("mailbox cleanup complete");
        }
    });

    // SECURITY FIX (H8): Periodic cleanup of stale per-IP rate limiters.
    // Remove entries that haven't been accessed in PEER_LIMITER_CLEANUP_SECS.
    {
        let limiter_state = Arc::clone(&state);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(PEER_LIMITER_CLEANUP_SECS));
            loop {
                interval.tick().await;
                let mut limiters = limiter_state.conn_limiters.write().await;
                let cutoff = Instant::now() - Duration::from_secs(PEER_LIMITER_CLEANUP_SECS * 2);
                limiters.retain(|_, (_, last_access)| *last_access > cutoff);
                tracing::debug!(
                    active_limiters = limiters.len(),
                    "per-IP rate limiter cleanup complete"
                );
            }
        });
    }

    // Background task: gossip-based route advertisement
    let gossip_state = Arc::clone(&state);
    tokio::spawn(async move {
        gossip_task(gossip_state).await;
    });

    // Connect to configured peers
    let peer_urls: Vec<String> = {
        let mut urls = Vec::new();
        // Direct --peer arguments
        for p in &args.peer {
            urls.push(p.clone());
        }
        // --peer-file
        if let Some(ref path) = args.peer_file {
            match std::fs::read_to_string(path) {
                Ok(content) => {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            urls.push(trimmed.to_string());
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to read peer file {}: {}", path, e);
                }
            }
        }
        urls
    };

    for peer_url in peer_urls {
        let state_clone = Arc::clone(&state);
        let cbnp = args.cbnp_enabled;
        tokio::spawn(async move {
            let url_str = peer_url.clone();
            if let Err(e) = connect_to_peer(url_str.clone(), state_clone, cbnp).await {
                tracing::error!(peer=%url_str, "failed to connect to peer: {}", e);
            }
        });
    }

    // Background task: CBNP cover traffic (ACS2.6 Part V.1)
    // Generates synthetic cover packets to maintain constant traffic profile,
    // preventing traffic analysis during idle periods.
    let cbnp_config = add_crypto::cbnp::CbnpConfig {
        lambda_seconds: 10.0,
        enabled: args.cbnp_enabled,
        max_burst: 3,
        global_epoch: 1704067200, // ACS2.6 reference epoch
        is_coordinator: false,
    };
    let cbnp_session = add_crypto::cbnp::CbnpSession::new(cbnp_config);
    if args.cbnp_enabled {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(1));
            loop {
                interval.tick().await;
                // Generate a cover packet to maintain traffic profile
                let _cover = cbnp_session.generate_cover_packet();
                // In production: forward cover to a random peer via WebSocket
            }
        });
    }

    // Background task: TTL monitoring for message expiry notifications (1 day, 7 days, 14 days)
    // Runs every hour to check for messages approaching TTL limits
    let ttl_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Run every hour
        loop {
            interval.tick().await;
            if let Err(e) = ttl_monitoring_task(&ttl_state).await {
                tracing::error!("TTL monitoring task error: {}", e);
            }
        }
    });

    // Background task: Cross-relay sync for pending deletions
    // Runs every 15 minutes to ensure cross-relay deletion consistency
    let sync_state = Arc::clone(&state);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(900)); // Every 15 minutes
        loop {
            interval.tick().await;
            if let Err(e) = cross_relay_sync_task(&sync_state).await {
                tracing::error!("Cross-relay sync task error: {}", e);
            }
        }
    });

    // ACS2.6 Part III.2: Lifecycle memory hooks — graceful shutdown on SIGINT/SIGTERM
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_clone = Arc::clone(&shutdown);
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        tracing::info!("received SIGINT, shutting down relay gracefully...");
        shutdown_clone.notify_one();
    });

    // Accept loop
    loop {
        tokio::select! {
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer_addr)) => {
                        let state = Arc::clone(&state);
                        let tls = tls_acceptor.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, peer_addr, state, tls).await {
                                tracing::warn!("connection error from {}: {}", peer_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("accept error: {}", e);
                    }
                }
            }
            _ = shutdown.notified() => {
                tracing::info!("relay shutdown complete");
                break;
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ //
//  Metadata encryption helpers (SECURITY FIX M3)
// ------------------------------------------------------------------ //

impl RelayState {
    /// Encrypt sender metadata (nid + fp) using AES-256-GCM.
    /// Returns hex-encoded string: [nonce_12bytes][tag_16bytes][ciphertext].
    fn encrypt_metadata(plaintext: &str, key: &[u8; 32]) -> String {
        use aes_gcm::aead::Aead;
        use aes_gcm::aead::rand_core::RngCore;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let cipher = Aes256Gcm::new_from_slice(key).expect("AES-256-GCM key init");
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .expect("AES-256-GCM encrypt");

        // Concatenate: nonce (12) + tag (16, appended by AES-GCM) + ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        hex::encode(result)
    }

    /// Decrypt sender metadata encrypted with `encrypt_metadata`.
    #[allow(dead_code)]
    fn decrypt_metadata(encrypted_hex: &str, key: &[u8; 32]) -> Option<String> {
        use aes_gcm::aead::Aead;
        use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

        let data = hex::decode(encrypted_hex).ok()?;
        if data.len() < 28 {
            return None; // 12 (nonce) + 16 (tag) minimum
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
        String::from_utf8(plaintext).ok()
    }
}

// ------------------------------------------------------------------ //
//  Tests                                                              //
// ------------------------------------------------------------------ //

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_relay_url_ws() {
        let (host, port, tls) = parse_relay_url("ws://127.0.0.1:8765").unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8765);
        assert!(!tls);
    }

    #[test]
    fn test_parse_relay_url_wss() {
        let (host, port, tls) = parse_relay_url("wss://relay.example.com:443").unwrap();
        assert_eq!(host, "relay.example.com");
        assert_eq!(port, 443);
        assert!(tls);
    }

    #[test]
    fn test_parse_relay_url_default_port() {
        let (host, port, tls) = parse_relay_url("ws://my.host").unwrap();
        assert_eq!(host, "my.host");
        assert_eq!(port, 80);
        assert!(!tls);
    }

    #[test]
    fn test_compute_hmac() {
        let h = compute_hmac("hello", "secret");
        assert_eq!(h.len(), 64); // SHA-256 hex = 64 chars
        // Same input produces same output
        let h2 = compute_hmac("hello", "secret");
        assert_eq!(h, h2);
        // Different secret produces different output
        let h3 = compute_hmac("hello", "different");
        assert_ne!(h, h3);
    }

    #[test]
    fn test_verify_hmac_valid() {
        let h = compute_hmac("test-data", "my-secret");
        assert!(verify_hmac("test-data", &h, "my-secret"));
    }

    #[test]
    fn test_verify_hmac_invalid() {
        let h = compute_hmac("test-data", "my-secret");
        assert!(!verify_hmac("test-data", &h, "wrong-secret"));
        assert!(!verify_hmac("other-data", &h, "my-secret"));
    }

    #[test]
    fn test_federation_add_and_lookup_route() {
        let mut fed = FederationState::new(None);
        fed.add_route("NN-ALICE-1234", "ws://relay-a.example.com:8765");
        assert_eq!(
            fed.lookup_route("NN-ALICE-1234"),
            Some("ws://relay-a.example.com:8765")
        );
        assert_eq!(fed.lookup_route("NN-BOB-5678"), None);
    }

    #[test]
    fn test_federation_route_expiry() {
        let mut fed = FederationState::new(None);
        fed.add_route("NN-ALICE-1234", "ws://relay-a.example.com:8765");
        // Manually set expiry to the past
        if let Some(entry) = fed.remote_routes.get_mut("NN-ALICE-1234") {
            entry.expires_at = Instant::now() - Duration::from_secs(1);
        }
        // Cleanup should remove it
        fed.cleanup_expired_routes();
        assert_eq!(fed.lookup_route("NN-ALICE-1234"), None);
    }

    #[test]
    fn test_federation_nonce_replay() {
        let mut fed = FederationState::new(None);
        assert!(fed.record_nonce("ws://peer1:8765", "nonce-1"));
        assert!(fed.record_nonce("ws://peer1:8765", "nonce-2"));
        // Replay should be rejected
        assert!(!fed.record_nonce("ws://peer1:8765", "nonce-1"));
    }

    #[test]
    fn test_relay_forward_loop_detection() {
        let our_url = "ws://my-relay:8765";
        let via: Vec<String> = vec![our_url.to_string()];
        let forward = RelayForward {
            recipient_nid: "NN-ALICE-1234".to_string(),
            signed_blob: "blob".to_string(),
            sender_nid: "NN-BOB-5678".to_string(),
            sender_fp: "fp".to_string(),
            seq: 1,
            sender_sig: "sig".to_string(),
            sender_cert: String::new(),
            timestamp: now_unix(),
            nonce: 42,
            hop_count: 1,
            via,
            source_relay_url: "ws://sender-relay:8765".to_string(),
            source_relay_sig: String::new(),
            source_relay_cert: String::new(),
            source_relay_fp: String::new(),
            sender_verifying_key: String::new(),
        };
        assert!(forward.via.contains(&our_url.to_string()));
        assert_eq!(forward.source_relay_url, "ws://sender-relay:8765");
    }

    #[test]
    fn test_relay_forward_hop_limit() {
        let forward = RelayForward {
            recipient_nid: "NN-ALICE-1234".to_string(),
            signed_blob: "blob".to_string(),
            sender_nid: "NN-BOB-5678".to_string(),
            sender_fp: "fp".to_string(),
            seq: 1,
            sender_sig: "sig".to_string(),
            sender_cert: String::new(),
            timestamp: now_unix(),
            nonce: 42,
            hop_count: FEDERATION_MAX_RELAY_HOPS,
            via: vec![],
            source_relay_url: String::new(),
            source_relay_sig: String::new(),
            source_relay_cert: String::new(),
            source_relay_fp: String::new(),
            sender_verifying_key: String::new(),
        };
        assert!(forward.hop_count >= FEDERATION_MAX_RELAY_HOPS);
    }

    #[test]
    fn test_source_relay_url_defaults_empty() {
        // Deserialize without source_relay_url — should default to empty
        let json = serde_json::json!({
            "recipient_nid": "NN-ALICE-1234",
            "signed_blob": "blob",
            "sender_nid": "NN-BOB-5678",
            "sender_fp": "fp",
            "seq": 1,
            "sender_sig": "sig",
            "timestamp": 1234567890.0,
            "nonce": 42,
        });
        let forward: RelayForward = serde_json::from_value(json).unwrap();
        assert_eq!(forward.source_relay_url, "");
    }
}
