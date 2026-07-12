//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
//! Error types for post-quantum crypto operations

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PqError {
    #[error("Invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("Invalid signature format")]
    InvalidSignature,

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Encapsulation failed: {0}")]
    EncapsulationFailed(String),

    #[error("Decapsulation failed: {0}")]
    DecapsulationFailed(String),

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("ML-DSA error: {0}")]
    MlDsaError(#[from] ml_dsa::Error),

    #[error("ML-KEM error: {0}")]
    MlKemError(#[from] ml_kem::InvalidKey),

    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("Add crypto error: {0}")]
    CryptoError(#[from] add_crypto::CryptoError),
}

impl From<std::array::TryFromSliceError> for PqError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        PqError::InvalidKeyLength {
            expected: 0,
            got: 0,
        }
    }
}
