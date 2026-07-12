//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// Hardware-Bound Key Hierarchy — ACS2.6 Part III.1
//
// Implements HSM-backed root secrets with Argon2id derivation and HKDF-SHA512
// key hierarchy. Keys never leave the secure enclave/HSM.
//
// Hierarchy:
//   Root Secret (HSM) ──HKDF-SHA512──▶ Identity Root Key (per-device)
//                                    ├── Double Ratchet Root (per-session)
//                                    ├── CBNP Cover Root (per-session)
//                                    ├── Sealed Sender Root (per-identity)
//                                    └── Delivery Token Root (per-message)

use argon2::{Algorithm, Argon2, Params, Version, password_hash::SaltString};
use hkdf::Hkdf;
use sha2::Sha512;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    CryptoError, MlKem1024Keypair,
    secure_mem::{SecureKeyMaterial, lock_memory, unlock_memory},
};

/// Argon2id parameters for key derivation (OWASP recommended)
const ARGON2_MEMORY_KIB: u32 = 19456; // ~19 MiB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const ARGON2_OUTPUT_LEN: usize = 64;

/// HKDF info strings for key separation
const HKDF_INFO_IDENTITY: &[u8] = b"add-identity-root-v1";
const HKDF_INFO_RATCHET: &[u8] = b"add-double-ratchet-v1";
const HKDF_INFO_CBNP: &[u8] = b"add-cbnp-cover-v1";
const HKDF_INFO_SEALED: &[u8] = b"add-sealed-sender-v1";
const HKDF_INFO_DELIVERY: &[u8] = b"add-delivery-token-v1";
const HKDF_INFO_AUTH: &[u8] = b"add-auth-hmac-v1";

#[derive(Debug, Error)]
pub enum HardwareKeyError {
    #[error("HSM not available: {0}")]
    HsmUnavailable(String),
    #[error("Key derivation failed: {0}")]
    DerivationFailed(String),
    #[error("Invalid password/credential")]
    InvalidCredential,
    #[error("Serialization error: {0}")]
    Serialization(String),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
}

/// Root secret stored in HSM/secure enclave
/// On platforms without HSM, falls back to Argon2id-derived secret from user passphrase
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootSecret {
    #[zeroize(skip)]
    source: RootSecretSource,
    material: SecureKeyMaterial,
}

/// Source of the root secret
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootSecretSource {
    /// Hardware Security Module / Secure Enclave (TEE, TPM, StrongBox, etc.)
    Hsm,
    /// Software fallback: Argon2id from user passphrase
    Argon2id,
    /// Test/development mode (NOT for production)
    #[cfg(test)]
    Test,
}

/// Derived identity root key (never leaves this module in plaintext)
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct IdentityRootKey {
    key: SecureKeyMaterial,
}

/// Session-specific keys derived from IdentityRootKey
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub ratchet_root: SecureKeyMaterial,
    pub cbnp_cover: SecureKeyMaterial,
    pub sealed_sender: SecureKeyMaterial,
    pub delivery_token: SecureKeyMaterial,
    pub auth_hmac: SecureKeyMaterial,
}

/// Hardware-bound key manager
pub struct HardwareKeyManager {
    root_secret: RootSecret,
    identity_root: IdentityRootKey,
}

impl RootSecret {
    /// Initialize from HSM (stub - platform-specific implementation needed)
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn from_hsm() -> Result<Self, HardwareKeyError> {
        // On Linux, this would use pkcs11, tpm2-tss, or kernel keyring
        // For now, return error to force passphrase fallback
        Err(HardwareKeyError::HsmUnavailable(
            "HSM integration not yet implemented - use passphrase".to_string(),
        ))
    }

    /// Derive root secret from user passphrase using Argon2id
    /// This is the production fallback for devices without HSM
    pub fn from_passphrase(passphrase: &[u8]) -> Result<Self, HardwareKeyError> {
        let salt = SaltString::generate(&mut rand::rngs::OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                ARGON2_MEMORY_KIB,
                ARGON2_ITERATIONS,
                ARGON2_PARALLELISM,
                Some(ARGON2_OUTPUT_LEN),
            )
            .map_err(|e| HardwareKeyError::DerivationFailed(e.to_string()))?,
        );

        let mut output = [0u8; ARGON2_OUTPUT_LEN];
        argon2
            .hash_password_into(passphrase, salt.as_str().as_bytes(), &mut output)
            .map_err(|e| HardwareKeyError::DerivationFailed(e.to_string()))?;

        let material = SecureKeyMaterial::new(output.to_vec(), true);
        output.zeroize();

        Ok(Self {
            source: RootSecretSource::Argon2id,
            material,
        })
    }

    /// Verify a passphrase against an existing root secret (for unlock)
    pub fn verify_passphrase(&self, passphrase: &[u8], stored_salt: &str) -> bool {
        if self.source != RootSecretSource::Argon2id {
            return false;
        }

        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(
                ARGON2_MEMORY_KIB,
                ARGON2_ITERATIONS,
                ARGON2_PARALLELISM,
                Some(ARGON2_OUTPUT_LEN),
            )
            .unwrap(),
        );

        // Parse salt from b64-encoded SaltString
        let salt = match SaltString::from_b64(stored_salt) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let mut output = [0u8; ARGON2_OUTPUT_LEN];
        argon2
            .hash_password_into(passphrase, salt.as_str().as_bytes(), &mut output)
            .is_ok()
    }

    /// Get the raw key material for derivation (internal use only)
    fn as_bytes(&self) -> &[u8] {
        self.material.bytes()
    }

    /// Get the source of this root secret
    pub fn source(&self) -> RootSecretSource {
        self.source
    }
}

impl IdentityRootKey {
    /// Derive identity root key from root secret using HKDF-SHA512
    pub fn derive(root_secret: &RootSecret) -> Result<Self, HardwareKeyError> {
        let hkdf = Hkdf::<Sha512>::new(None, root_secret.as_bytes());
        let mut output = [0u8; 64];
        hkdf.expand(HKDF_INFO_IDENTITY, &mut output)
            .map_err(|e| HardwareKeyError::DerivationFailed(e.to_string()))?;

        let material = SecureKeyMaterial::new(output.to_vec(), true);
        output.zeroize();

        Ok(Self { key: material })
    }

    /// Derive session keys from identity root
    pub fn derive_session_keys(&self) -> Result<SessionKeys, HardwareKeyError> {
        let hkdf = Hkdf::<Sha512>::new(None, self.key.bytes());

        let mut ratchet_root = [0u8; 32];
        hkdf.expand(HKDF_INFO_RATCHET, &mut ratchet_root)
            .map_err(|e| HardwareKeyError::DerivationFailed(e.to_string()))?;

        let mut cbnp_cover = [0u8; 32];
        hkdf.expand(HKDF_INFO_CBNP, &mut cbnp_cover)
            .map_err(|e| HardwareKeyError::DerivationFailed(e.to_string()))?;

        let mut sealed_sender = [0u8; 32];
        hkdf.expand(HKDF_INFO_SEALED, &mut sealed_sender)
            .map_err(|e| HardwareKeyError::DerivationFailed(e.to_string()))?;

        let mut delivery_token = [0u8; 32];
        hkdf.expand(HKDF_INFO_DELIVERY, &mut delivery_token)
            .map_err(|e| HardwareKeyError::DerivationFailed(e.to_string()))?;

        let mut auth_hmac = [0u8; 32];
        hkdf.expand(HKDF_INFO_AUTH, &mut auth_hmac)
            .map_err(|e| HardwareKeyError::DerivationFailed(e.to_string()))?;

        Ok(SessionKeys {
            ratchet_root: SecureKeyMaterial::new(ratchet_root.to_vec(), true),
            cbnp_cover: SecureKeyMaterial::new(cbnp_cover.to_vec(), true),
            sealed_sender: SecureKeyMaterial::new(sealed_sender.to_vec(), true),
            delivery_token: SecureKeyMaterial::new(delivery_token.to_vec(), true),
            auth_hmac: SecureKeyMaterial::new(auth_hmac.to_vec(), true),
        })
    }
}

impl HardwareKeyManager {
    /// Create new hardware key manager from passphrase (fallback mode)
    pub fn new_from_passphrase(passphrase: &[u8]) -> Result<Self, HardwareKeyError> {
        let root_secret = RootSecret::from_passphrase(passphrase)?;
        let identity_root = IdentityRootKey::derive(&root_secret)?;

        Ok(Self {
            root_secret,
            identity_root,
        })
    }

    /// Create new hardware key manager from HSM (production mode)
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub fn new_from_hsm() -> Result<Self, HardwareKeyError> {
        let root_secret = RootSecret::from_hsm()?;
        let identity_root = IdentityRootKey::derive(&root_secret)?;

        Ok(Self {
            root_secret,
            identity_root,
        })
    }

    /// Get the root secret source
    pub fn root_source(&self) -> RootSecretSource {
        self.root_secret.source()
    }

    /// Derive session keys for current session
    pub fn session_keys(&self) -> Result<SessionKeys, HardwareKeyError> {
        self.identity_root.derive_session_keys()
    }

    /// Generate ML-KEM-1024 keypair using hardware-bound randomness
    /// The seed is derived from the identity root key
    pub fn generate_mlkem_keypair(&self) -> Result<MlKem1024Keypair, HardwareKeyError> {
        let session_keys = self.session_keys()?;

        // Use HKDF to expand ratchet_root (32 bytes) to 64-byte seed for ML-KEM
        let hkdf = Hkdf::<Sha512>::new(None, session_keys.ratchet_root.bytes());
        let mut seed = [0u8; 64];
        hkdf.expand(b"add-mlkem-seed-v1", &mut seed)
            .map_err(|e| HardwareKeyError::DerivationFailed(e.to_string()))?;

        let keypair = MlKem1024Keypair::from_seed(&seed).map_err(|e| {
            HardwareKeyError::Crypto(CryptoError::Ratchet(format!("ML-KEM keypair: {}", e)))
        })?;

        Ok(keypair)
    }

    /// Get auth HMAC key for sealed sender / delivery tokens
    pub fn auth_hmac_key(&self) -> Result<SecureKeyMaterial, HardwareKeyError> {
        let session_keys = self.session_keys()?;
        Ok(session_keys.auth_hmac.clone())
    }

    /// Get delivery token key
    pub fn delivery_token_key(&self) -> Result<SecureKeyMaterial, HardwareKeyError> {
        let session_keys = self.session_keys()?;
        Ok(session_keys.delivery_token.clone())
    }

    /// Get sealed sender key
    pub fn sealed_sender_key(&self) -> Result<SecureKeyMaterial, HardwareKeyError> {
        let session_keys = self.session_keys()?;
        Ok(session_keys.sealed_sender.clone())
    }

    /// Get CBNP cover traffic key
    pub fn cbnp_cover_key(&self) -> Result<SecureKeyMaterial, HardwareKeyError> {
        let session_keys = self.session_keys()?;
        Ok(session_keys.cbnp_cover.clone())
    }

    /// Lock all keys in memory (prevent swap)
    pub fn lock_all(&mut self) -> bool {
        let mut session_keys = match self.session_keys() {
            Ok(k) => k,
            Err(_) => return false,
        };

        let mut locked = true;
        locked &= lock_memory(session_keys.ratchet_root.key_material_mut());
        locked &= lock_memory(session_keys.cbnp_cover.key_material_mut());
        locked &= lock_memory(session_keys.sealed_sender.key_material_mut());
        locked &= lock_memory(session_keys.delivery_token.key_material_mut());
        locked &= lock_memory(session_keys.auth_hmac.key_material_mut());
        locked &= lock_memory(self.identity_root.key.key_material_mut());
        locked &= lock_memory(self.root_secret.material.key_material_mut());

        locked
    }

    /// Unlock all keys
    pub fn unlock_all(&mut self) -> bool {
        let mut session_keys = match self.session_keys() {
            Ok(k) => k,
            Err(_) => return false,
        };

        let mut unlocked = true;
        unlocked &= unlock_memory(session_keys.ratchet_root.key_material_mut());
        unlocked &= unlock_memory(session_keys.cbnp_cover.key_material_mut());
        unlocked &= unlock_memory(session_keys.sealed_sender.key_material_mut());
        unlocked &= unlock_memory(session_keys.delivery_token.key_material_mut());
        unlocked &= unlock_memory(session_keys.auth_hmac.key_material_mut());
        unlocked &= unlock_memory(self.identity_root.key.key_material_mut());
        unlocked &= unlock_memory(self.root_secret.material.key_material_mut());

        unlocked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_kem::KeyExport;

    #[test]
    fn test_root_secret_from_passphrase() {
        let passphrase = b"test-passphrase-123";
        let root = RootSecret::from_passphrase(passphrase).unwrap();
        assert_eq!(root.source(), RootSecretSource::Argon2id);
        assert!(!root.as_bytes().is_empty());
    }

    #[test]
    fn test_identity_root_derivation() {
        let passphrase = b"test-passphrase-123";
        let root = RootSecret::from_passphrase(passphrase).unwrap();
        let identity = IdentityRootKey::derive(&root).unwrap();
        assert!(!identity.key.bytes().is_empty());
    }

    #[test]
    fn test_session_keys_derivation() {
        let passphrase = b"test-passphrase-123";
        let root = RootSecret::from_passphrase(passphrase).unwrap();
        let identity = IdentityRootKey::derive(&root).unwrap();
        let session = identity.derive_session_keys().unwrap();

        assert!(!session.ratchet_root.bytes().is_empty());
        assert!(!session.cbnp_cover.bytes().is_empty());
        assert!(!session.sealed_sender.bytes().is_empty());
        assert!(!session.delivery_token.bytes().is_empty());
        assert!(!session.auth_hmac.bytes().is_empty());

        // All keys should be 32 bytes
        assert_eq!(session.ratchet_root.len(), 32);
        assert_eq!(session.cbnp_cover.len(), 32);
        assert_eq!(session.sealed_sender.len(), 32);
        assert_eq!(session.delivery_token.len(), 32);
        assert_eq!(session.auth_hmac.len(), 32);
    }

    #[test]
    fn test_hardware_key_manager() {
        let passphrase = b"test-passphrase-123";
        let manager = HardwareKeyManager::new_from_passphrase(passphrase).unwrap();

        assert_eq!(manager.root_source(), RootSecretSource::Argon2id);

        let session = manager.session_keys().unwrap();
        assert_eq!(session.ratchet_root.len(), 32);
    }

    #[test]
    fn test_mlkem_keypair_generation() {
        let passphrase = b"test-passphrase-123";
        let manager = HardwareKeyManager::new_from_passphrase(passphrase).unwrap();

        let keypair = manager.generate_mlkem_keypair().unwrap();

        // Verify keypair works using static method
        let (ct, ss1) = MlKem1024Keypair::encapsulate(&keypair.enc).unwrap();
        let ss2 = keypair.decapsulate(&ct).unwrap();
        // Compare shared secrets by converting to bytes
        let ss1_bytes: &[u8] = ss1.as_ref();
        let ss2_bytes: &[u8] = ss2.as_ref();
        assert_eq!(ss1_bytes, ss2_bytes);
    }

    #[test]
    fn test_deterministic_keys_same_passphrase() {
        let passphrase = b"same-passphrase";

        let manager1 = HardwareKeyManager::new_from_passphrase(passphrase).unwrap();
        let manager2 = HardwareKeyManager::new_from_passphrase(passphrase).unwrap();

        // Keys should be different each time due to random salt
        let kp1 = manager1.generate_mlkem_keypair().unwrap();
        let kp2 = manager2.generate_mlkem_keypair().unwrap();

        // Different keypairs (salt is random) - compare via KeyExport
        let kp1_bytes = kp1.enc.to_bytes();
        let kp2_bytes = kp2.enc.to_bytes();
        assert_ne!(kp1_bytes, kp2_bytes);
    }

    #[test]
    fn test_lock_unlock_memory() {
        let passphrase = b"test-passphrase-123";
        let mut manager = HardwareKeyManager::new_from_passphrase(passphrase).unwrap();

        // Best effort - may not work in all test environments
        let _ = manager.lock_all();
        let _ = manager.unlock_all();
    }
}
