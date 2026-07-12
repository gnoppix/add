//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------

pub mod bootstrap_verify;
pub mod bot_log;
pub mod crypto_helpers;
pub mod dht_node;
pub mod pin_cache;
pub mod ratelimit;
pub mod sqlite_store;
pub mod types;
pub mod util;

// Re-exports for convenience
// SECURITY FIX (H3): dropped cert_issuer_is_trusted / cert_issuer_name_is_trusted
// (the redundant CA-substring check was removed — trust rests on WebPKI + pin).
pub use bootstrap_verify::{cert_has_trusted_domain, domain_matches};
pub use crypto_helpers::{
    compute_null_id, sign_data, validate_fingerprint, validate_null_id, verify_signature,
    verify_signature_with_verifying_key,
};
pub use dht_node::DhtNodeRuntime;
pub use dht_node::get_peer_address;
pub use pin_cache::{bootstrap_pin_check, pin_get, pin_update, pin_verify_address};
pub use ratelimit::RateLimiter;
pub use sqlite_store::DhtStore;
pub use types::{DhtNode, NodeConfig};

// Re-export constants from add-protocol
pub use add_protocol::constants;

// Re-export PoW functions from add-protocol
pub use add_protocol::pow::{pow_check, pow_solve};

// Re-export envelope types from add-protocol
pub use add_protocol::envelope::{
    WireEnvelope, build_dht_error, build_dht_found, parse_dht_addr_record, parse_dht_get,
    parse_dht_put,
};

pub use add_crypto::pir::{
    PIR_BIN_SIZE, PIR_CUCKOO_FANOUT, PIR_ENTRY_SIZE, PirClient, PirContactEntry, PirQueryToken,
    PirRegistry, PirResponse,
};

use thiserror::Error;

/// Top-level error type for the dht-core crate.
#[derive(Error, Debug)]
pub enum DhtError {
    #[error("storage error: {0}")]
    Storage(String),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("signature verification failed")]
    SignatureInvalid,

    #[error("proof-of-work verification failed")]
    PowInvalid,

    #[error("invalid key format")]
    InvalidKey,

    #[error("invalid fingerprint format")]
    InvalidFingerprint,

    #[error("value too large")]
    ValueTooLarge,

    #[error("stale sequence")]
    StaleSequence,

    #[error("nonce replay detected")]
    NonceReplay,

    #[error("stale timestamp")]
    StaleTimestamp,

    #[error("rate limited")]
    RateLimited,
}

/// Crate-wide result alias.
pub type DhtResult<T> = Result<T, DhtError>;
