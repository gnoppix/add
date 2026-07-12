//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// Delivery Tokens — Anonymous delivery receipts for Sealed Sender (ACS2.6 §3.4)
//
// Allows a sender to prove a message was delivered without revealing content.
// Token hierarchy: master_secret -> delivery_key -> delivery token (per message)
//
// Uses HMAC-SHA256 for token derivation. Tokens are 32 bytes, indistinguishable
// from random to anyone without the delivery_key.
//-------------------------------------------------------------------------------

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::ZeroizeOnDrop;

use crate::CryptoError;

/// SECURITY FIX (M4): single, audited constant-time equality for secret
/// material (delivery tokens / keys). Replaces the hand-rolled `fold` XOR
/// compares that could invite accidental early-exit regressions.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

type HmacSha256 = Hmac<Sha256>;

/// Size of a delivery token in bytes (256 bits of security)
pub const DELIVERY_TOKEN_SIZE: usize = 32;

/// Size of a delivery key in bytes
const DELIVERY_KEY_SIZE: usize = 32;

/// Size of a delivery seed used to derive keys
const DELIVERY_SEED_SIZE: usize = 64;

/// Master secret for delivery token derivation. Lives only in memory.
#[derive(ZeroizeOnDrop)]
pub struct DeliveryMasterSecret {
    bytes: [u8; DELIVERY_SEED_SIZE],
}

impl DeliveryMasterSecret {
    /// Generate a random delivery master secret
    pub fn generate() -> Self {
        let mut bytes = [0u8; DELIVERY_SEED_SIZE];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self { bytes }
    }

    /// Create from existing bytes (for persistence)
    pub fn from_bytes(bytes: [u8; DELIVERY_SEED_SIZE]) -> Self {
        Self { bytes }
    }

    /// Derive a per-contact delivery key using HKDF-like construction
    pub fn derive_key(&self, contact_id: &str) -> DeliveryKey {
        let mut mac = HmacSha256::new_from_slice(&self.bytes).expect("HMAC accepts any key size");
        mac.update(b"add-delivery-key-v1");
        mac.update(contact_id.as_bytes());
        let result = mac.finalize();
        let mut key_bytes = [0u8; DELIVERY_KEY_SIZE];
        key_bytes.copy_from_slice(&result.into_bytes()[..DELIVERY_KEY_SIZE]);
        DeliveryKey { bytes: key_bytes }
    }

    /// Derive a delivery token for a specific message.
    /// Tokens are unique per (contact, message_id) pair.
    pub fn derive_token(
        &self,
        contact_id: &str,
        message_id: u64,
    ) -> Result<DeliveryToken, CryptoError> {
        let key = self.derive_key(contact_id);
        derive_token_internal(&key, message_id)
    }

    /// Expose the secret bytes (for encrypted persistence)
    pub fn as_bytes(&self) -> &[u8; DELIVERY_SEED_SIZE] {
        &self.bytes
    }

    /// Verify that a token matches what we'd derive for this message.
    pub fn verify_token(
        &self,
        contact_id: &str,
        message_id: u64,
        token: &DeliveryToken,
    ) -> Result<bool, CryptoError> {
        let expected = self.derive_token(contact_id, message_id)?;
        // SECURITY FIX (M4): constant-time compare via `subtle`.
        Ok(ct_eq(&expected.bytes, &token.bytes))
    }
}

// ZeroizeOnDrop derive handles drop automatically
/// Per-contact delivery key. Safe to persist (not the master secret).
/// SECURITY FIX (H1): no `Debug` — holds an HMAC key; redact instead.
#[derive(Clone, ZeroizeOnDrop)]
pub struct DeliveryKey {
    bytes: [u8; DELIVERY_KEY_SIZE],
}

impl std::fmt::Debug for DeliveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeliveryKey")
            .field("bytes", &"<key redacted>")
            .finish()
    }
}

impl DeliveryKey {
    /// Derive a delivery token for a message ID
    pub fn derive_token(&self, message_id: u64) -> Result<DeliveryToken, CryptoError> {
        derive_token_internal(self, message_id)
    }

    /// Verify a token for a message
    pub fn verify(&self, message_id: u64, token: &DeliveryToken) -> Result<bool, CryptoError> {
        let expected = derive_token_internal(self, message_id)?;
        // SECURITY FIX (M4): constant-time compare via `subtle`.
        Ok(ct_eq(&expected.bytes, &token.bytes))
    }

    /// Get the raw key bytes (for serialization)
    pub fn as_bytes(&self) -> &[u8; DELIVERY_KEY_SIZE] {
        &self.bytes
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; DELIVERY_KEY_SIZE]) -> Self {
        Self { bytes }
    }
}

/// An anonymous delivery token. Sent by recipient to sender to confirm
/// delivery without revealing which message exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryToken {
    bytes: [u8; DELIVERY_TOKEN_SIZE],
}

impl DeliveryToken {
    /// Get the raw token bytes
    pub fn as_bytes(&self) -> &[u8; DELIVERY_TOKEN_SIZE] {
        &self.bytes
    }

    /// Create from raw bytes
    pub fn from_bytes(bytes: [u8; DELIVERY_TOKEN_SIZE]) -> Self {
        Self { bytes }
    }

    /// Encode as hex string for wire transport
    pub fn to_hex(&self) -> String {
        hex::encode(self.bytes)
    }

    /// Parse from hex string
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| CryptoError::DecryptFailed(format!("hex decode: {}", e)))?;
        if bytes.len() != DELIVERY_TOKEN_SIZE {
            return Err(CryptoError::DecryptFailed(format!(
                "wrong token size: {} != {}",
                bytes.len(),
                DELIVERY_TOKEN_SIZE
            )));
        }
        let mut out = [0u8; DELIVERY_TOKEN_SIZE];
        out.copy_from_slice(&bytes);
        Ok(Self { bytes: out })
    }
}

/// Internal: derive a token using HMAC-SHA256(key, message_id_be_bytes)
fn derive_token_internal(key: &DeliveryKey, message_id: u64) -> Result<DeliveryToken, CryptoError> {
    let mut mac = HmacSha256::new_from_slice(&key.bytes)
        .map_err(|_| CryptoError::EncryptFailed("HMAC init failed".into()))?;
    mac.update(b"add-delivery-token-v1");
    mac.update(&message_id.to_be_bytes());
    let result = mac.finalize();
    let mut token_bytes = [0u8; DELIVERY_TOKEN_SIZE];
    token_bytes.copy_from_slice(&result.into_bytes());
    Ok(DeliveryToken { bytes: token_bytes })
}

/// Wire format for a delivery token message
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct DeliveryTokenMessage {
    /// Anonymous delivery token
    pub token: String,
    /// Sender's public key hash (for sender to identify which message)
    pub sender_key_hash: String,
    /// Timestamp (seconds since epoch)
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delivery_master_secret_generate_and_derive() {
        let master = DeliveryMasterSecret::generate();
        let token = master.derive_token("contact-alice", 42).unwrap();
        // Token must be non-zero
        assert!(token.bytes.iter().any(|&b| b != 0));
        // Verify same token
        let derived = master.derive_token("contact-alice", 42).unwrap();
        assert_eq!(token.bytes, derived.bytes);
    }

    #[test]
    fn test_delivery_token_verification() {
        let master = DeliveryMasterSecret::generate();
        let token_a = master.derive_token("contact-bob", 100).unwrap();
        // Correct verification
        assert!(master.verify_token("contact-bob", 100, &token_a).unwrap());
        // Wrong message ID
        let token_b = master.derive_token("contact-bob", 101).unwrap();
        assert!(!master.verify_token("contact-bob", 100, &token_b).unwrap());
        // Different contact
        let token_c = master.derive_token("contact-charlie", 100).unwrap();
        assert!(!master.verify_token("contact-bob", 100, &token_c).unwrap());
    }

    #[test]
    fn test_delivery_key_from_bytes() {
        let master = DeliveryMasterSecret::generate();
        let key = master.derive_key("test-contact");
        let key_bytes = key.as_bytes();
        let recovered = DeliveryKey::from_bytes(*key_bytes);
        let token1 = key.derive_token(5).unwrap();
        let token2 = recovered.derive_token(5).unwrap();
        assert_eq!(token1.bytes, token2.bytes);
    }

    #[test]
    fn test_delivery_token_hex_encoding() {
        let master = DeliveryMasterSecret::generate();
        let token = master.derive_token("alice", 7).unwrap();
        let hex = token.to_hex();
        assert_eq!(hex.len(), DELIVERY_TOKEN_SIZE * 2);
        let parsed = DeliveryToken::from_hex(&hex).unwrap();
        assert_eq!(token.bytes, parsed.bytes);
    }

    #[test]
    fn test_delivery_token_from_invalid_hex() {
        let result = DeliveryToken::from_hex("deadbeef");
        assert!(result.is_err());
    }
}
