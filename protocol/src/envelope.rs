//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
use serde::{Deserialize, Serialize};

use crate::constants;

/// DHT PUT envelope payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPut {
    pub key: String,
    pub value: String,
    pub salt: String,
    pub seq: i64,
    pub ttl: i64,
    pub nonce: i64,
    /// Publisher's armored public key cert (optional, recommended).
    /// Needed for Sequoia in-process signature verification.
    #[serde(default)]
    pub publisher_cert: String,
}

/// DHT GET request payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtGet {
    pub key: String,
}

/// DHT response: blob found.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtFound {
    pub key: String,
    pub value: String,
    pub salt: String,
    pub seq: i64,
}

/// DHT error response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtError {
    pub key: String,
    pub message: String,
}

/// DHT address record — proves ownership of a DHT key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtAddrRecord {
    pub null_id: String,
    pub address: String,
    pub ttl: i64,
    pub publisher_fp: String,
    /// Publisher's armored public key cert (optional, recommended).
    #[serde(default)]
    pub publisher_cert: String,
}

/// Generic JSON envelope for wire protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireEnvelope {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub payload: serde_json::Value,
    pub msg_id: String,
    pub ts: f64,
    pub sig: String,
}

/// SECURITY FIX (L1): Per-message-type domain-separation context string used
/// when signing/verifying a `WireEnvelope`. Prefixing the signed data with a
/// type-specific tag prevents cross-type signature replay (e.g. a `dht-put`
/// signature being replayed as a `dht-get`). Unknown types get a safe,
/// explicit "unknown" tag rather than an empty string, so they still cannot
/// collide with any known type.
pub fn signing_context(msg_type: &str) -> &'static str {
    match msg_type {
        "dht-put" => "add-dht-put-v1",
        "dht-get" => "add-dht-get-v1",
        "dht-found" => "add-dht-found-v1",
        "dht-error" => "add-dht-error-v1",
        "dht-addr-record" => "add-dht-addr-record-v1",
        "p2p-hello" => "add-p2p-hello-v1",
        "p2p-hello-ack" => "add-p2p-hello-ack-v1",
        "relay-store" => "add-relay-store-v1",
        "relay-fetch" => "add-relay-fetch-v1",
        "relay-ack" => "add-relay-ack-v1",
        "relay-delete" => "add-relay-delete-v1",
        "relay-purge" => "add-relay-purge-v1",
        "relay-read-receipt" => "add-relay-read-receipt-v1",
        "route-advertise" => "add-fed-route-advertise-v1",
        "peer-auth" => "add-fed-peer-auth-v1",
        "peer-auth-reply" => "add-fed-peer-auth-reply-v1",
        "relay-forward" => "add-fed-relay-forward-v1",
        "relay-forward-ack" => "add-fed-relay-forward-ack-v1",
        _ => "add-unknown-v1",
    }
}

impl WireEnvelope {
    /// Serialize to JSON string.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize from JSON string.
    pub fn from_json(raw: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(raw)
    }

    /// Extract a field from the payload.
    pub fn payload_field(&self, key: &str) -> Option<&serde_json::Value> {
        self.payload.as_object()?.get(key)
    }

    /// Extract a string field from the payload.
    pub fn payload_str(&self, key: &str) -> Option<&str> {
        self.payload_field(key)?.as_str()
    }

    /// Extract an integer field from the payload.
    pub fn payload_i64(&self, key: &str) -> Option<i64> {
        self.payload_field(key)?.as_i64()
    }

    /// Compute the canonical signing data for this envelope.
    ///
    /// SECURITY FIX (L1): A fixed, versioned context tag is prepended per
    /// message type so that a signature over one message type cannot be
    /// cross-replayed as a different type even if the payloads collide.
    /// (Previously the signature covered only `msg_type|payload|msg_id|ts`,
    /// where two different types with identical payloads would yield the same
    /// signed string.) The tag is stable across sign+verify, so this is a
    /// strict hardening with no wire-format change for legitimate peers.
    pub fn signing_data(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            signing_context(&self.msg_type),
            self.msg_type,
            self.payload,
            self.msg_id,
            self.ts
        )
    }

    /// Sign this envelope in-place using a detached OpenPGP signature.
    ///
    /// Uses the certificate's secret key for signing.
    /// On success, `self.sig` contains the ASCII-armored detached signature.
    pub fn sign_gpg(&mut self, cert: &sequoia_openpgp::Cert) -> Result<(), String> {
        let data = self.signing_data();
        let sig = crate::gpg::sign_detached(&data, cert)?;
        self.sig = sig;
        Ok(())
    }

    /// Set the signature field directly (for pre-computed signatures).
    pub fn set_signature(&mut self, sig: String) {
        self.sig = sig;
    }

    /// Verify the OpenPGP signature on this envelope.
    ///
    /// SECURITY FIX (C3): Verifies that the signature matches the canonical
    /// signing data (msg_type + payload + msg_id + ts) and was produced by
    /// the holder of the certificate's key.
    pub fn verify_gpg(&self, cert: &sequoia_openpgp::Cert) -> Result<bool, String> {
        if self.sig.is_empty() {
            return Ok(false);
        }
        let data = self.signing_data();
        crate::gpg::verify_detached(&self.sig, &data, cert)
    }

    /// Check if this envelope is signed.
    pub fn is_signed(&self) -> bool {
        !self.sig.is_empty()
    }
}

/// Parse a DHT PUT envelope from a wire envelope.
pub fn parse_dht_put(env: &WireEnvelope) -> Option<DhtPut> {
    Some(DhtPut {
        key: env.payload_str("key")?.to_string(),
        value: env.payload_str("value")?.to_string(),
        salt: env.payload_str("salt")?.to_string(),
        seq: env.payload_i64("seq").unwrap_or(0),
        ttl: env.payload_i64("ttl").unwrap_or(constants::STORE_TTL),
        nonce: env.payload_i64("nonce").unwrap_or(0),
        publisher_cert: env.payload_str("publisher_cert").unwrap_or("").to_string(),
    })
}

/// Parse a DHT GET envelope from a wire envelope.
pub fn parse_dht_get(env: &WireEnvelope) -> Option<DhtGet> {
    Some(DhtGet {
        key: env.payload_str("key")?.to_string(),
    })
}

/// Parse a DHT ADDR_RECORD envelope from a wire envelope.
pub fn parse_dht_addr_record(env: &WireEnvelope) -> Option<DhtAddrRecord> {
    Some(DhtAddrRecord {
        null_id: env.payload_str("null_id")?.to_string(),
        address: env.payload_str("address")?.to_string(),
        ttl: env.payload_i64("ttl").unwrap_or(constants::ADDR_TTL),
        publisher_fp: env.payload_str("publisher_fp")?.to_string(),
        publisher_cert: env.payload_str("publisher_cert").unwrap_or("").to_string(),
    })
}

/// Build a DHT FOUND response envelope.
pub fn build_dht_found(key: &str, value: &str, salt: &str, seq: i64) -> WireEnvelope {
    WireEnvelope {
        msg_type: "dht-found".to_string(),
        payload: serde_json::json!({
            "key": key,
            "value": value,
            "salt": salt,
            "seq": seq,
        }),
        msg_id: uuid_hex(),
        ts: now_unix(),
        sig: String::new(),
    }
}

/// Build a DHT ERROR response envelope.
pub fn build_dht_error(key: &str, message: &str) -> WireEnvelope {
    WireEnvelope {
        msg_type: "dht-error".to_string(),
        payload: serde_json::json!({
            "key": key,
            "message": message,
        }),
        msg_id: uuid_hex(),
        ts: now_unix(),
        sig: String::new(),
    }
}

/// Generate a 16-char hex message ID.
pub fn uuid_hex() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let n: u128 = rng.r#gen();
    format!("{:032x}", n)[..16].to_string()
}

/// Current Unix timestamp as f64.
pub fn now_unix() -> f64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wire_envelope_roundtrip() {
        let env = WireEnvelope {
            msg_type: "dht-put".to_string(),
            payload: serde_json::json!({
                "key": "test_key",
                "value": "test_value",
                "salt": "abc",
                "seq": 1,
                "ttl": 86400,
                "nonce": 42,
            }),
            msg_id: "abc123".to_string(),
            ts: 1234567890.0,
            sig: String::new(),
        };
        let json = env.to_json().unwrap();
        let parsed = WireEnvelope::from_json(&json).unwrap();
        assert_eq!(parsed.msg_type, "dht-put");
        assert_eq!(parsed.payload_str("key"), Some("test_key"));
    }

    #[test]
    fn test_parse_dht_put() {
        let env = WireEnvelope {
            msg_type: "dht-put".to_string(),
            payload: serde_json::json!({
                "key": "NN-test",
                "value": "blob",
                "salt": "salty",
                "seq": 5,
                "ttl": 3600,
                "nonce": 100,
            }),
            msg_id: "id".to_string(),
            ts: 0.0,
            sig: String::new(),
        };
        let put = parse_dht_put(&env).unwrap();
        assert_eq!(put.key, "NN-test");
        assert_eq!(put.nonce, 100);
    }
}
