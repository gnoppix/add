//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
//-------------------------------------------------------------------------------
//! Post-quantum cryptographic primitives for the Gnoppix messenger.
//!
//! This crate provides:
//! - Hybrid X25519 + ML-KEM-768 key agreement (X-Wing combiner)
//! - Bidirectional PQXDH handshake protocol
//! - Post-quantum Double Ratchet extension

pub mod error;
pub mod keys;
pub mod hybrid_kem;
pub mod kem;
pub mod pqxdh;
pub mod ratchet_pq;
pub mod signature;

// Re-export key types
pub use error::PqError;
pub use keys::{MlDsa87KeyPair, MlDsa87SigningKey, MlDsa87VerifyingKey, MlDsa87Signature};
pub use signature::{sign, verify};
/// Alias for `sign` — used by bot, relay, and client.
pub fn sign_ml_dsa87(data: &[u8], sk: &MlDsa87SigningKey) -> Result<MlDsa87Signature, PqError> {
    sign(data, sk)
}
/// Decode a verifying key from raw bytes (ML-DSA-87).
pub fn decode_verifying_key(bytes: &[u8]) -> Result<MlDsa87VerifyingKey, PqError> {
    let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa87>::try_from(bytes)
        .map_err(|_| PqError::DecodingError("Invalid ML-DSA-87 encoded verifying key".into()))?;
    Ok(MlDsa87VerifyingKey::decode(&encoded))
}
pub use hybrid_kem::{
    HybridKeypair, HybridCiphertext, HybridSharedSecret,
    COMBINED_PK_SIZE, COMBINED_CT_SIZE, HYBRID_SS_SIZE,
    combine_shared_secrets, bidirectional_exchange,
    hybrid_encapsulate, hybrid_decapsulate, ratchet_step as hybrid_ratchet_step,
};
pub use kem::{
    KemRatchet, HybridKemRatchet,
    async_encapsulate, async_decapsulate, async_generate_keypair,
    make_kem_context, serialize_keypair, deserialize_keypair,
    MAX_KEM_CT_SIZE, MAX_KEM_PK_SIZE,
    MlKem1024Ciphertext, MlKem1024DecapsulationKey,
    MlKem1024EncapsulationKey, MlKem1024Keypair, MlKem1024SharedSecret,

};
pub use pqxdh::{
    PqxDhHandshake, PqxDhSessionKeys, PqxDhRatchetState,
    PQXDH_VERSION, NONCE_SIZE, SESSION_KEY_SIZE, IV_SIZE,
    execute_pqxdh_handshake,
};
pub use ratchet_pq::{
    KemRatchetState, EphemeralKeys, RatchetState,
    KemRatchetMessage, PqDoubleRatchet,
    advance_root_ratchet, verify_ratchet_properties,
};

// ML-DSA-87 helpers for examples
pub fn generate_keypair() -> Result<(MlDsa87SigningKey, MlDsa87VerifyingKey), PqError> {
    let kp = keys::MlDsa87KeyPair::generate()?;
    Ok((kp.signing_key(), kp.verifying_key()))
}

pub fn fingerprint_from_verifying_key(vk: &MlDsa87VerifyingKey) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use ml_dsa::KeyExport;
    use sha2::Digest;
    let hash = sha2::Sha256::digest(vk.to_bytes());
    let first8 = &hash[..8];
    STANDARD.encode(first8)
}
