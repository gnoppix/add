//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------

// --- DHT configuration constants matching Python dht.py ---

/// Default bootstrap seed addresses.
pub const BOOTSTRAP_SEEDS: &[&str] = &[
    "wss://bootstrap-eu.gnoppix.org:9001",
    "wss://bootstrap-us.gnoppix.org:9001",
    "wss://bootstrap-asia.gnoppix.org:9001",
];

pub const DHT_PORT: u16 = 6881;
pub const K_BUCKET_SIZE: usize = 8;
pub const MAX_STORE_PER_KEY: usize = 100;
pub const STORE_TTL: i64 = 86400; // 24 hours
/// SECURITY FIX (H6): Maximum allowed TTL for DHT records.
/// Prevents infinite-lived records that could bloat the DHT store.
pub const MAX_TTL: i64 = 604800; // 7 days
/// SECURITY FIX (H7): Maximum allowed key size in bytes/chars.
/// Prevents excessively long keys from consuming disproportionate storage.
pub const MAX_KEY_SIZE: usize = 256;
pub const ADDR_TTL: i64 = 7200; // 2 hours
pub const POW_MAX_AGE: i64 = 300; // 5 minutes
pub const MAX_VALUE_SIZE: usize = 4096; // 4 KB
pub const MAX_TOTAL_KEYS: usize = 1_000_000;

// --- Argon2id PoW parameters for DHT writes ---
pub const DHT_POW_MEMORY_COST: u32 = 16384; // 16 MB
pub const DHT_POW_TIME_COST: u32 = 3;
pub const DHT_POW_PARALLELISM: u32 = 1;
pub const DHT_POW_HASH_LEN: usize = 32;
pub const DHT_POW_DIFFICULTY: u32 = 16;

/// SECURITY FIX (M9): Minimum allowed PoW difficulty.
/// Prevents attackers from setting difficulty=0 to bypass PoW entirely.
pub const MIN_POW_DIFFICULTY: u32 = 8;

/// SECURITY FIX (L7): PoW difficulty for addr-record writes.
/// Lower than DHT_POW_DIFFICULTY since addr records are smaller and more
/// frequent, but still required to prevent spamming without computation.
pub const ADDR_POW_DIFFICULTY: u32 = 8;

// --- Argon2id PoW parameters for P2P hello ---
pub const P2P_POW_MEMORY_COST: u32 = 1024; // 1 MB
pub const P2P_POW_TIME_COST: u32 = 2;
pub const P2P_POW_PARALLELISM: u32 = 1;
pub const P2P_POW_HASH_LEN: usize = 32;
pub const P2P_POW_DIFFICULTY: u32 = 12;

/// Fixed salt for DHT PoW (deterministic verification).
pub const POW_SALT: &[u8] = b"add-dht-pow";

// --- Relay constants matching relay.py ---
pub const RELAY_MAX_QUEUE_PER_NID: usize = 100;
pub const RELAY_QUEUE_TTL: u64 = 300; // 5 minutes
pub const RELAY_MAX_TOTAL_QUEUED: usize = 10000;
pub const RELAY_MAX_SESSIONS_PER_NID: usize = 10;
pub const RELAY_MAX_MSG_SIZE: usize = 1_048_576; // 1 MB
pub const RELAY_IDLE_TIMEOUT: u64 = 300; // 5 minutes
pub const RELAY_GOSSIP_INTERVAL: u64 = 60;
pub const RELAY_ROUTE_TTL: u64 = 1800; // 30 minutes
pub const RELAY_MAX_CONCURRENT_PER_IP: usize = 10;
pub const CONN_RATE_LIMIT: u64 = 50; // connections per window
pub const CONN_RATE_WINDOW: u64 = 60; // seconds
pub const MSG_RATE_LIMIT: u64 = 120; // messages per window
pub const MSG_RATE_WINDOW: u64 = 60; // seconds

// --- Protocol message types ---
pub const MSG_DHT_PUT: &str = "dht-put";
pub const MSG_DHT_GET: &str = "dht-get";
pub const MSG_DHT_FOUND: &str = "dht-found";
pub const MSG_DHT_ERROR: &str = "dht-error";
pub const MSG_ADDR_RECORD: &str = "addr-record";
pub const MSG_P2P_HELLO: &str = "p2p-hello";
pub const MSG_P2P_HELLO_ACK: &str = "p2p-hello-ack";
pub const MSG_P2P_MESSAGE: &str = "p2p-message";
pub const MSG_P2P_ACK: &str = "p2p-ack";
pub const MSG_P2P_PING: &str = "p2p-ping";
pub const MSG_P2P_PONG: &str = "p2p-pong";
pub const MSG_P2P_BRAID_CHUNK: &str = "p2p-braid-chunk";
pub const MSG_P2P_BRAID_COMPLETE: &str = "p2p-braid-complete";
pub const MSG_P2P_DELIVERY_TOKEN: &str = "p2p-delivery-token";
pub const MSG_RELAY_REGISTER: &str = "register";
pub const MSG_RELAY_REGISTERED: &str = "registered";
pub const MSG_RELAY_SEND: &str = "send";
pub const MSG_RELAY_RECV: &str = "recv";
pub const MSG_RELAY_ACK: &str = "ack";
pub const MSG_RELAY_PURGE: &str = "relay-purge";
pub const MSG_P2P_RECEIPT: &str = "p2p-receipt";
