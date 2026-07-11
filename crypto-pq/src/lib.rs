//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
//! Post-quantum cryptography for Add
//! ML-DSA-87 (FIPS 204) for signatures, ML-KEM-1024 (FIPS 203) for encryption

pub mod signature;
pub mod kem;
pub mod keys;
pub mod error;

pub use signature::{MlDsa87SigningKey, MlDsa87VerifyingKey, MlDsa87Signature, sign, verify};
pub use kem::{MlKem1024EncapsulationKey, MlKem1024DecapsulationKey, encapsulate, decapsulate, MlKem1024Keypair};
pub use keys::{PqKeyPair, MlDsa87KeyPair, MlKem1024KeyPair};
pub use error::PqError;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use ml_dsa::MlDsa87;

/// Generate ML-DSA-87 keypair
pub fn generate_keypair() -> Result<(MlDsa87SigningKey, MlDsa87VerifyingKey), crate::error::PqError> {
    use ml_dsa::{Generate, Keypair};
    let sk = MlDsa87SigningKey::generate();
    let vk = sk.verifying_key().clone();
    Ok((sk, vk))
}

/// Decode ML-DSA-87 verifying key from bytes (raw public key)
pub fn decode_verifying_key(bytes: &[u8]) -> Result<MlDsa87VerifyingKey, crate::error::PqError> {
    use ml_dsa::KeyInit;
    MlDsa87VerifyingKey::new_from_slice(bytes)
        .map_err(|e| crate::error::PqError::InvalidKeyLength { expected: 0, got: 0 })
}

/// Derive fingerprint from verifying key (SHA256 of public key bytes)
pub fn fingerprint_from_verifying_key(vk: &MlDsa87VerifyingKey) -> String {
    use ml_dsa::KeyExport;
    use sha2::{Digest, Sha256};
    let pk_bytes = vk.to_bytes();
    let hash = Sha256::digest(pk_bytes.as_slice());
    hex::encode(hash).to_uppercase()
}

/// Sign data with ML-DSA-87
pub fn sign_ml_dsa87(data: &[u8], sk: &MlDsa87SigningKey) -> Result<String, crate::error::PqError> {
    use ml_dsa::Signer;
    let sig = sk.sign(data);
    let encoded = sig.encode();
    Ok(BASE64_STANDARD.encode(encoded.as_slice()))
}

/// Verify ML-DSA-87 signature
pub fn verify_ml_dsa87(data: &[u8], base64_sig: &str, vk: &MlDsa87VerifyingKey) -> Result<bool, crate::error::PqError> {
    use ml_dsa::Verifier;
    let sig_bytes = BASE64_STANDARD.decode(base64_sig)?;
    let encoded = ml_dsa::EncodedSignature::<MlDsa87>::try_from(sig_bytes.as_slice())?;
    let sig = MlDsa87Signature::decode(&encoded).ok_or(crate::error::PqError::InvalidSignature)?;
    Ok(vk.verify(data, &sig).is_ok())
}