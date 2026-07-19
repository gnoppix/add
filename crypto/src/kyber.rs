//-------------------------------------------------------------------------------
// Name: Gnoppix Linux - Services
// Architecture: all
// Date: 2002-2026 by Gnoppix Linux
// Author: Andreas Mueller
// Website: https://www.gnoppix.com
// Licence: Business Source License (BSL / BUSL)
// You can use the code for free if your company or organisation doesn't have more than 2 people.
//-------------------------------------------------------------------------------
// Add ML-KEM-1024 KEM — Post-quantum key exchange (NIST Level 5)
//
// Uses ml-kem crate (pure Rust, FIPS 203 compliant).
// ML-KEM-1024 provides NIST Level 5 quantum-resistant key encapsulation.
//
// SECURITY MODEL:
// - ML-KEM-1024 wraps a shared secret that encrypts a TEST payload only.
// - Pure (non-test) messages use AES-256-GCM via DoubleRatchetSession.
// - No one can decrypt pure messages via ML-KEM — they are separate cipher systems.
//-------------------------------------------------------------------------------

use ml_kem::KeyExport;
use ml_kem::MlKem768;
use ml_kem::MlKem1024;
use ml_kem::TryKeyInit;
use ml_kem::kem::{Decapsulate, Encapsulate, Kem};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use base64::Engine;

use crate::CryptoError;
/// ML-KEM-1024 encapsulation (public) key.
pub type MlKem1024EncapsulationKey = ml_kem::kem::EncapsulationKey<MlKem1024>;

/// ML-KEM-1024 decapsulation (secret) key.
pub type MlKem1024DecapsulationKey = ml_kem::kem::DecapsulationKey<MlKem1024>;

/// ML-KEM-1024 ciphertext (1504 bytes).
pub type MlKem1024Ciphertext = ml_kem::kem::Ciphertext<MlKem1024>;

/// ML-KEM-1024 shared secret (32 bytes).
pub type MlKem1024SharedSecret = ml_kem::kem::SharedKey<MlKem1024>;

/// Encode an ML-KEM-1024 encapsulation key as base64 for wire transport.
pub fn encode_enc_key(key: &MlKem1024EncapsulationKey) -> String {
    let bytes = key.to_bytes();
    base64::engine::general_purpose::STANDARD.encode(bytes.as_slice())
}

/// Decode a base64-encoded ML-KEM-1024 encapsulation key.
pub fn decode_enc_key(b64: &str) -> Result<MlKem1024EncapsulationKey, CryptoError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| CryptoError::KeyPersistence(format!("base64 decode: {}", e)))?;
    ml_kem::kem::EncapsulationKey::<MlKem1024>::new_from_slice(bytes.as_slice())
        .map_err(|_| CryptoError::KeyPersistence("invalid enc key bytes".into()))
}

/// An ML-KEM-1024 keypair for post-quantum key exchange.
/// SECURITY FIX (C2): decapsulation key is automatically zeroized on drop
/// (DecapsulationKey implements ZeroizeOnDrop from ml-kem crate).
/// No derive needed — drop glue clears dec when MlKem1024Keypair is dropped.
pub struct MlKem1024Keypair {
    pub enc: MlKem1024EncapsulationKey,
    pub dec: MlKem1024DecapsulationKey,
}

impl MlKem1024Keypair {
    /// Generate a new ML-KEM-1024 keypair using OS randomness.
    pub fn generate() -> Result<Self, CryptoError> {
        let (dec, enc) = MlKem1024::generate_keypair();
        Ok(Self { enc, dec })
    }

    /// Encapsulate a shared secret for the given public key.
    /// Returns (ciphertext, shared_secret).
    pub fn encapsulate(
        enc_key: &MlKem1024EncapsulationKey,
    ) -> Result<(MlKem1024Ciphertext, MlKem1024SharedSecret), CryptoError> {
        let (ct, ss) = enc_key.encapsulate();
        Ok((ct, ss))
    }

    /// Decapsulate a ciphertext using our secret key.
    /// Returns the shared secret.
    pub fn decapsulate(
        &self,
        ciphertext: &MlKem1024Ciphertext,
    ) -> Result<MlKem1024SharedSecret, CryptoError> {
        let ss = self.dec.decapsulate(ciphertext);
        Ok(ss)
    }

    /// Save the ML-KEM-1024 keypair to a file with AES-256-GCM encryption.
    /// SECURITY FIX (C6): The secret key (`dec`) is encrypted at rest using
    /// AES-256-GCM with a key derived from `encryption_key` via HKDF-SHA256.
    /// Format (hex JSON): [salt (32 bytes)][nonce (12 bytes)][ciphertext (variable)]
    /// The public key (`enc`) is stored in plaintext (it is not secret).
    pub fn save(
        &self,
        path: &std::path::Path,
        encryption_key: &[u8; 32],
    ) -> Result<(), CryptoError> {
        use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
        use aes_gcm::{Aes256Gcm, Key};
        use hkdf::Hkdf;
        use sha2::Sha256;

        let enc_bytes = self.enc.to_bytes();
        let dec_bytes = self.dec.to_bytes();

        // Derive AES-256-GCM key from encryption_key using HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(None, encryption_key);
        let mut aes_key = [0u8; 32];
        hk.expand(b"add-kyber-key-enc-v1", &mut aes_key)
            .map_err(|_| CryptoError::KeyPersistence("HKDF expand failed".into()))?;

        // Generate random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        // Encrypt dec_bytes with AES-256-GCM
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
        let ciphertext = cipher
            .encrypt(&nonce, dec_bytes.as_slice())
            .map_err(|e| CryptoError::KeyPersistence(format!("AES-GCM encrypt: {}", e)))?;

        // Assemble: enc_public (plaintext) + nonce + encrypted_dec
        let data = serde_json::json!({
            "enc": hex::encode(enc_bytes),
            "nonce": hex::encode(nonce.as_slice()),
            "dec_encrypted": hex::encode(ciphertext),
        });
        std::fs::write(path, data.to_string())
            .map_err(|e| CryptoError::KeyPersistence(format!("write failed: {}", e)))?;
        // Set restrictive permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Load an ML-KEM-1024 keypair from an encrypted file.
    /// SECURITY FIX (C6): Decrypts the secret key using AES-256-GCM.
    pub fn load(path: &std::path::Path, encryption_key: &[u8; 32]) -> Result<Self, CryptoError> {
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};
        use hkdf::Hkdf;
        use sha2::Sha256;

        let content = std::fs::read_to_string(path)
            .map_err(|e| CryptoError::KeyPersistence(format!("read failed: {}", e)))?;
        let data: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| CryptoError::KeyPersistence(format!("parse failed: {}", e)))?;
        let enc_hex = data["enc"]
            .as_str()
            .ok_or_else(|| CryptoError::KeyPersistence("missing enc field".into()))?;
        let nonce_hex = data["nonce"]
            .as_str()
            .ok_or_else(|| CryptoError::KeyPersistence("missing nonce field".into()))?;
        let dec_encrypted_hex = data["dec_encrypted"]
            .as_str()
            .ok_or_else(|| CryptoError::KeyPersistence("missing dec_encrypted field".into()))?;

        let enc_bytes = hex::decode(enc_hex)
            .map_err(|e| CryptoError::KeyPersistence(format!("enc hex decode: {}", e)))?;
        let nonce_bytes = hex::decode(nonce_hex)
            .map_err(|e| CryptoError::KeyPersistence(format!("nonce hex decode: {}", e)))?;
        let dec_ciphertext = hex::decode(dec_encrypted_hex)
            .map_err(|e| CryptoError::KeyPersistence(format!("dec_encrypted hex decode: {}", e)))?;

        // Derive AES-256-GCM key from encryption_key using HKDF-SHA256
        let hk = Hkdf::<Sha256>::new(None, encryption_key);
        let mut aes_key = [0u8; 32];
        hk.expand(b"add-kyber-key-enc-v1", &mut aes_key)
            .map_err(|_| CryptoError::KeyPersistence("HKDF expand failed".into()))?;

        // Decrypt dec_bytes with AES-256-GCM
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&aes_key));
        let nonce = Nonce::from_slice(&nonce_bytes);
        let dec_bytes = cipher
            .decrypt(nonce, dec_ciphertext.as_slice())
            .map_err(|e| CryptoError::KeyPersistence(format!("AES-GCM decrypt: {}", e)))?;

        // Reconstruct keys: enc uses KeyInit::new_from_slice, dec uses from_seed
        let enc_key =
            ml_kem::kem::EncapsulationKey::<MlKem1024>::new_from_slice(enc_bytes.as_slice())
                .map_err(|_| CryptoError::KeyPersistence("invalid enc key bytes".into()))?;
        // ml_kem 0.3.x from_seed expects seed as Array<u8, U64>
        let dec_key = ml_kem::kem::DecapsulationKey::<MlKem1024>::from_seed(
            dec_bytes
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::KeyPersistence("invalid seed length".into()))?,
        );
        Ok(Self {
            enc: enc_key,
            dec: dec_key,
        })
    }

    pub fn load_or_generate(
        path: &std::path::Path,
        encryption_key: &[u8; 32],
    ) -> Result<Self, CryptoError> {
        if path.exists() {
            Self::load(path, encryption_key)
        } else {
            let kp = Self::generate()?;
            kp.save(path, encryption_key)?;
            Ok(kp)
        }
    }

    /// Load or generate an unencrypted keypair (for bootstrap server identity).
    /// Stored in plaintext - NOT for user secrets, only for bootstrap/federation nodes.
    /// Admin can delete the file to force regeneration on next start.
    pub fn load_or_generate_unencrypted(path: &std::path::Path) -> Result<Self, CryptoError> {
        if path.exists() {
            Self::load_unencrypted(path)
        } else {
            let kp = Self::generate()?;
            Self::save_unencrypted(path, &kp)?;
            Ok(kp)
        }
    }

    /// Save keypair unencrypted (for bootstrap server identity).
    /// Sets 0o600 permissions for basic protection.
    pub fn save_unencrypted(path: &std::path::Path, kp: &Self) -> Result<(), CryptoError> {
        use ml_kem::KeyExport;
        let data = serde_json::json!({
            "enc": hex::encode(kp.enc.to_bytes()),
            "dec": hex::encode(kp.dec.to_bytes()),
        });
        std::fs::write(path, data.to_string())
            .map_err(|e| CryptoError::KeyPersistence(format!("write failed: {}", e)))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Load an unencrypted keypair (no encryption key required).
    pub fn load_unencrypted(path: &std::path::Path) -> Result<Self, CryptoError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| CryptoError::KeyPersistence(format!("read failed: {}", e)))?;
        let data: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| CryptoError::KeyPersistence(format!("parse failed: {}", e)))?;
        let enc_hex = data["enc"]
            .as_str()
            .ok_or_else(|| CryptoError::KeyPersistence("missing enc field".into()))?;
        let dec_hex = data["dec"]
            .as_str()
            .ok_or_else(|| CryptoError::KeyPersistence("missing dec field".into()))?;

        let enc_bytes = hex::decode(enc_hex)
            .map_err(|e| CryptoError::KeyPersistence(format!("enc hex decode: {}", e)))?;
        let dec_bytes = hex::decode(dec_hex)
            .map_err(|e| CryptoError::KeyPersistence(format!("dec hex decode: {}", e)))?;

        let enc_key =
            ml_kem::kem::EncapsulationKey::<MlKem1024>::new_from_slice(enc_bytes.as_slice())
                .map_err(|_| CryptoError::KeyPersistence("invalid enc key bytes".into()))?;
        let dec_key = ml_kem::kem::DecapsulationKey::<MlKem1024>::from_seed(
            dec_bytes
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::KeyPersistence("invalid seed length".into()))?,
        );
        Ok(Self {
            enc: enc_key,
            dec: dec_key,
        })
    }

    /// Derive an ML-KEM-1024 keypair from a 64-byte seed.
    /// Used for deterministic sealed sender identity derivation.
    pub fn from_seed(seed: &[u8; 64]) -> Result<Self, CryptoError> {
        use ml_kem::kem::DecapsulationKey;
        let dec = DecapsulationKey::<MlKem1024>::from_seed(
            seed.as_slice()
                .try_into()
                .map_err(|_| CryptoError::Serialization("invalid seed length".into()))?,
        );
        let enc = dec.encapsulation_key();
        Ok(Self {
            enc: enc.clone(),
            dec,
        })
    }
}

// Backward-compatible type aliases (alias old names to new types)
pub type KyberEncapsulationKey = MlKem1024EncapsulationKey;
pub type KyberDecapsulationKey = MlKem1024DecapsulationKey;
pub type KyberCiphertext = MlKem1024Ciphertext;
pub type KyberSharedSecret = MlKem1024SharedSecret;
pub type KyberKeypair = MlKem1024Keypair;

/// ML-KEM variant selection (NIST security level).
/// Determines key sizes and ciphertext sizes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlKemVariant {
    /// ML-KEM-768: NIST Level 3 (1184-byte pubkey, 1088-byte ciphertext)
    MlKem768,
    /// ML-KEM-1024: NIST Level 5 (1568-byte pubkey, 1568-byte ciphertext)
    MlKem1024,
}

impl MlKemVariant {
    /// Default variant: ML-KEM-1024 (NIST Level 5)
    pub const DEFAULT: Self = Self::MlKem1024;

    /// Encapsulation key size in bytes
    pub const fn enc_key_size(self) -> usize {
        match self {
            Self::MlKem768 => 1184,
            Self::MlKem1024 => 1568,
        }
    }

    /// Ciphertext size in bytes
    pub const fn ciphertext_size(self) -> usize {
        match self {
            Self::MlKem768 => 1088,
            Self::MlKem1024 => 1568,
        }
    }

    /// Shared secret size (always 32 bytes)
    pub const fn shared_secret_size(self) -> usize {
        32
    }

    /// NIST security level description
    pub const fn security_level(self) -> &'static str {
        match self {
            Self::MlKem768 => "NIST Level 3 (192-bit equivalent)",
            Self::MlKem1024 => "NIST Level 5 (256-bit equivalent)",
        }
    }

    /// Minimum ciphertext wire length for this variant (enc_key + ct + nonce + tag)
    pub fn min_ciphertext_len(self) -> usize {
        self.enc_key_size() + self.ciphertext_size() + 12 + 16
    }
}

/// A keypair that can be either ML-KEM-768 or ML-KEM-1024.
///
/// The variant is determined at key generation time and must be known
/// for correct deserialization.
/// SECURITY FIX (C2): Zeroize dec_bytes (private key seed) on drop.
/// `variant` and `enc_bytes` are public/non-sensitive — skipped.
/// SECURITY FIX (H1): no `Debug` — `dec_bytes` is the private key seed (redacted on drop).
#[derive(Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct VariantKeypair {
    #[zeroize(skip)]
    pub variant: MlKemVariant,
    #[zeroize(skip)]
    pub enc_bytes: Vec<u8>,
    pub dec_bytes: Vec<u8>,
}

#[allow(dead_code)]
impl VariantKeypair {
    /// Generate a keypair with the requested variant.
    pub fn generate(variant: MlKemVariant) -> Result<Self, CryptoError> {
        match variant {
            MlKemVariant::MlKem1024 => {
                let kp = MlKem1024Keypair::generate()?;
                let enc_bytes = kp.enc.to_bytes().to_vec();
                let dec_bytes = kp.dec.to_bytes().to_vec();
                Ok(Self {
                    variant,
                    enc_bytes,
                    dec_bytes,
                })
            }
            MlKemVariant::MlKem768 => {
                let (dec, enc) = MlKem768::generate_keypair();
                let enc_bytes = enc.to_bytes().to_vec();
                let dec_bytes = dec.to_bytes().to_vec();
                Ok(Self {
                    variant,
                    enc_bytes,
                    dec_bytes,
                })
            }
        }
    }

    /// Encapsulate a shared secret for the given public key variant.
    fn encapsulate_1024(
        enc_key: &ml_kem::kem::EncapsulationKey<MlKem1024>,
    ) -> Result<(MlKem1024Ciphertext, MlKem1024SharedSecret), CryptoError> {
        let (ct, ss) = enc_key.encapsulate();
        Ok((ct, ss))
    }

    fn encapsulate_768(
        enc_key: &ml_kem::kem::EncapsulationKey<MlKem768>,
    ) -> Result<
        (
            ml_kem::kem::Ciphertext<MlKem768>,
            ml_kem::kem::SharedKey<MlKem768>,
        ),
        CryptoError,
    > {
        let (ct, ss) = enc_key.encapsulate();
        Ok((ct, ss))
    }

    /// Decapsulate using the secret key for the given variant.
    fn decapsulate_1024(
        dec: &ml_kem::kem::DecapsulationKey<MlKem1024>,
        ct: &MlKem1024Ciphertext,
    ) -> MlKem1024SharedSecret {
        dec.decapsulate(ct)
    }

    fn decapsulate_768(
        dec: &ml_kem::kem::DecapsulationKey<MlKem768>,
        ct: &ml_kem::kem::Ciphertext<MlKem768>,
    ) -> ml_kem::kem::SharedKey<MlKem768> {
        dec.decapsulate(ct)
    }

    /// Get the public key bytes (encapsulation key).
    pub fn enc_bytes(&self) -> &[u8] {
        &self.enc_bytes
    }

    /// Get the secret key bytes (decapsulation key seed).
    pub fn dec_bytes(&self) -> &[u8] {
        &self.dec_bytes
    }

    /// Convert to a MlKem1024Keypair (only if variant matches)
    pub fn as_1024(&self) -> Result<MlKem1024Keypair, CryptoError> {
        if self.variant != MlKemVariant::MlKem1024 {
            return Err(CryptoError::KeyPersistence(
                "keypair is not ML-KEM-1024".into(),
            ));
        }
        let enc_key = ml_kem::kem::EncapsulationKey::<MlKem1024>::new_from_slice(&self.enc_bytes)
            .map_err(|_| CryptoError::KeyPersistence("invalid enc key".into()))?;
        let dec_key = ml_kem::kem::DecapsulationKey::<MlKem1024>::from_seed(
            self.dec_bytes
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::KeyPersistence("invalid dec key".into()))?,
        );
        Ok(MlKem1024Keypair {
            enc: enc_key,
            dec: dec_key,
        })
    }
}

// =============================================================================
// ML-KEM Braid Protocol (SPQR) — ACS2.6 Part I.1
